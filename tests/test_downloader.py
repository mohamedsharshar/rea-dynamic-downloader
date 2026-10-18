"""
Unit Tests for REA Dynamic Multi-Part Downloader & Scheduler
Validates filename sanitization, Content-Disposition RFC 5987, Magic Bytes sniffing,
dynamic chunk splitting math, thread-safety, lossless reassembly & SHA-256 integrity.
"""

import unittest
import os
import shutil
import hashlib
import tempfile
import threading
from rea_dynamic_downloader import (
    sanitize_filename,
    parse_content_disposition,
    sniff_extension_from_magic_bytes,
    SpeedLimitVar,
    DownloadChunk,
    DownloadTask,
    DynamicDownloadEngine,
)


class TestDownloaderUtils(unittest.TestCase):
    def test_sanitize_filename(self):
        # Invalid characters on Windows
        bad_name = 'my<cool>:file/with\\bad|chars?and*stars.exe'
        clean = sanitize_filename(bad_name)
        for char in '<>:"/\\|?*':
            self.assertNotIn(char, clean)
        self.assertTrue(clean.endswith('.exe'))

        # Empty or dots only
        self.assertEqual(sanitize_filename("..."), "downloaded_file")
        self.assertEqual(sanitize_filename("   "), "downloaded_file")

    def test_parse_content_disposition_standard(self):
        h1 = 'attachment; filename="setup_v1.0.exe"'
        self.assertEqual(parse_content_disposition(h1), "setup_v1.0.exe")

        h2 = 'attachment; filename=document.pdf'
        self.assertEqual(parse_content_disposition(h2), "document.pdf")

    def test_parse_content_disposition_rfc5987(self):
        # RFC 5987 UTF-8 encoded filename
        h = "attachment; filename*=UTF-8''%D9%85%D9%84%D9%81_%D8%AA%D8%AC%D8%B1%D8%A8%D8%A9.zip"
        parsed = parse_content_disposition(h)
        self.assertEqual(parsed, "ملف_تجربة.zip")

    def test_sniff_extension_from_magic_bytes(self):
        # Windows PE executable
        self.assertEqual(sniff_extension_from_magic_bytes(b"MZ\x90\x00\x03\x00"), ".exe")

        # PNG Image
        self.assertEqual(sniff_extension_from_magic_bytes(b"\x89PNG\r\n\x1a\n\x00\x00"), ".png")

        # PDF Document
        self.assertEqual(sniff_extension_from_magic_bytes(b"%PDF-1.7\r\n"), ".pdf")

        # ZIP Archive
        self.assertEqual(sniff_extension_from_magic_bytes(b"PK\x03\x04\x14\x00"), ".zip")

        # MP4 Video container
        mp4_hdr = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00"
        self.assertEqual(sniff_extension_from_magic_bytes(mp4_hdr), ".mp4")

        # Unknown / non-matching
        self.assertIsNone(sniff_extension_from_magic_bytes(b"HELLO_WORLD_1234"))


class TestConcurrencyAndChunks(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="rea_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_speed_limit_var_thread_safety(self):
        limit = SpeedLimitVar(100.0)
        self.assertEqual(limit.get(), 100.0)

        def worker(val):
            for _ in range(100):
                limit.set(val)
                _ = limit.get()

        threads = [
            threading.Thread(target=worker, args=(float(i),))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertIsInstance(limit.get(), float)

    def test_dynamic_chunk_split_math(self):
        total_size = 10 * 1024 * 1024  # 10 MB
        task = DownloadTask("https://example.com/testfile.bin", self.test_dir)
        task.total_bytes = total_size
        task.supports_range = True

        first_part = os.path.join(task.temp_dir, "part_0000.bin")
        chunk0 = DownloadChunk(0, 0, total_size - 1, first_part)
        task.chunks.append(chunk0)

        # Split 1: should divide chunk 0 into two halves
        chunk1 = task.split_largest_chunk()
        self.assertIsNotNone(chunk1)
        self.assertEqual(len(task.chunks), 2)

        # Check contiguous bounds with zero overlap and zero gaps
        self.assertEqual(chunk0.start, 0)
        self.assertEqual(chunk0.end, chunk1.start - 1)
        self.assertEqual(chunk1.end, total_size - 1)

        # Verify sum of ranges equals original total_bytes
        range0_len = chunk0.end - chunk0.start + 1
        range1_len = chunk1.end - chunk1.start + 1
        self.assertEqual(range0_len + range1_len, total_size)

        # Split 2: should divide the largest of chunk0 and chunk1
        chunk2 = task.split_largest_chunk()
        self.assertIsNotNone(chunk2)
        self.assertEqual(len(task.chunks), 3)

        # Sort all chunks by start and verify seamless coverage across the entire range
        sorted_chunks = sorted(task.chunks, key=lambda c: c.start)
        self.assertEqual(sorted_chunks[0].start, 0)
        for i in range(len(sorted_chunks) - 1):
            self.assertEqual(sorted_chunks[i].end + 1, sorted_chunks[i + 1].start)
        self.assertEqual(sorted_chunks[-1].end, total_size - 1)

    def test_lossless_assembly_and_sha256(self):
        total_bytes = 2 * 1024 * 1024  # 2 MB sample
        data = os.urandom(total_bytes)
        expected_sha = hashlib.sha256(data).hexdigest()

        task = DownloadTask("https://example.com/payload.dat", self.test_dir)
        task.total_bytes = total_bytes
        task.supports_range = True
        os.makedirs(task.temp_dir, exist_ok=True)

        # Create 4 parts manually simulating parallel downloaded segments
        part_size = total_bytes // 4
        for i in range(4):
            start = i * part_size
            end = (start + part_size - 1) if i < 3 else (total_bytes - 1)
            part_path = os.path.join(task.temp_dir, f"part_{i:04d}.bin")
            with open(part_path, "wb") as f:
                f.write(data[start:end + 1])
            task.chunks.append(DownloadChunk(i, start, end, part_path))

        # Reassemble
        logs = []
        DynamicDownloadEngine._assemble_lossless(
            task,
            on_update_ui=lambda t: None,
            on_log=lambda msg, lvl: logs.append((lvl, msg)),
        )

        self.assertTrue(task.is_verified)
        self.assertEqual(task.final_hash, expected_sha)
        self.assertTrue(os.path.exists(task.output_path))
        self.assertEqual(os.path.getsize(task.output_path), total_bytes)

        # Verify physical file contents match bit-for-bit
        with open(task.output_path, "rb") as f:
            assembled_data = f.read()
        self.assertEqual(assembled_data, data)


if __name__ == "__main__":
    unittest.main()
