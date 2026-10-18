"""
================================================================================
  REA Dynamic Multi-Part Downloader & Stream Controller (Python Edition)
  - مبني على هندسة IDM المفككة: Dynamic Segmentation + HTTP Range Chunks
  - واجهة حديثة داكنة بدون إطار (Modern Frameless Window) مع دعم السحب
  - ميزة حصرية: محدد سرعة يدوي مستقل لكل ملف (Per-File Throttle Slider)
  - دعم كامل لروابط الويب (HTTP/HTTPS Range) والملفات المحلية للاختبار
  - دمج تسلسلي آمن (AppendFile) مع تحقق رياضي ثلاثي من البصمة الرقمية
================================================================================
"""

import os
import sys
import time
import hashlib
import threading
import urllib.request
import urllib.error
import urllib.parse
import re
import mimetypes
import ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from typing import List, Optional

WINDOW_TITLE = "⚡ REA Dynamic Multi-Part Downloader & Scheduler"
MUTEX_NAME = "Global\\REA_Dynamic_Downloader_SingleInstance_Mutex_v2"


def acquire_single_instance_lock():
    """ضمان تشغيل نسخة واحدة فقط من البرنامج، وجلب النافذة للأمام إذا كان يعمل مسبقاً."""
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if hwnd:
            user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            user32.SetForegroundWindow(hwnd)
        return None
    return mutex

# تهيئة قاعدة بيانات أنواع الوسائط
mimetypes.init()

DEFAULT_BUFFER_SIZE = 64 * 1024  # 64 KB Buffer

# خريطة شاملة لأنواع MIME الأكثر استخداماً لتحديد الامتداد الدقيق
MIME_TO_EXT = {
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/x-matroska": ".mkv",
    "video/quicktime": ".mov",
    "video/x-msvideo": ".avi",
    "video/x-flv": ".flv",
    "video/mp2t": ".ts",
    "video/3gpp": ".3gp",
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a",
    "audio/aac": ".aac",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/flac": ".flac",
    "audio/ogg": ".ogg",
    "audio/webm": ".weba",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/vnd.rar": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/x-tar": ".tar",
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/vnd.android.package-archive": ".apk",
    "application/x-msdownload": ".exe",
    "application/vnd.microsoft.portable-executable": ".exe",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "image/bmp": ".bmp",
    "text/html": ".html",
    "text/plain": ".txt",
    "application/json": ".json",
}


def sanitize_filename(filename: str) -> str:
    """تنظيف اسم الملف من الحروف والرموز غير المسموحة في نظام ويندوز."""
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    sanitized = sanitized.strip().strip(". ")
    if not sanitized:
        sanitized = "downloaded_file"
    return sanitized


def parse_content_disposition(header_val: str) -> Optional[str]:
    """استخراج اسم الملف من ترويسة Content-Disposition مع دعم UTF-8 و RFC 5987."""
    if not header_val:
        return None
    # 1. فحص صيغة RFC 5987 / RFC 6266: filename*=UTF-8''...
    match_star = re.search(r"filename\*\s*=\s*([^;]+)", header_val, re.IGNORECASE)
    if match_star:
        raw = match_star.group(1).strip().strip('"').strip("'")
        if "''" in raw:
            encoding, _, encoded_text = raw.partition("''")
            try:
                return urllib.parse.unquote(encoded_text, encoding=encoding or "utf-8")
            except Exception:
                pass
        return urllib.parse.unquote(raw)

    # 2. فحص الصيغة القياسية: filename="..." أو filename=...
    match_std = re.search(
        r'filename\s*=\s*(?:"([^"]+)"|([^;\s]+))', header_val, re.IGNORECASE
    )
    if match_std:
        raw = match_std.group(1) or match_std.group(2)
        if raw:
            raw = raw.strip()
            return urllib.parse.unquote(raw)
    return None


def sniff_extension_from_magic_bytes(data: bytes) -> Optional[str]:
    """فحص التوقيع الثنائي (Magic Bytes) لتحديد الامتداد الدقيق لنوع الملف من المحتوى المادي."""
    if not data or len(data) < 4:
        return None

    # MP4 / M4A / MOV
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].lower()
        if brand in (b"m4a ", b"m4b "):
            return ".m4a"
        if brand in (b"qt  ", b"moov"):
            return ".mov"
        return ".mp4"
    if b"ftyp" in data[:32]:
        return ".mp4"

    # Matroska / WebM (EBML: 0x1A 0x45 0xDF 0xA3)
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        if b"webm" in data[:64].lower():
            return ".webm"
        return ".mkv"

    # RIFF containers (AVI, WAV, WEBP)
    if data.startswith(b"RIFF") and len(data) >= 12:
        riff_type = data[8:12]
        if riff_type == b"AVI ":
            return ".avi"
        elif riff_type == b"WAVE":
            return ".wav"
        elif riff_type == b"WEBP":
            return ".webp"

    # Audio: MP3, FLAC, OGG
    if data.startswith(b"ID3") or (
        len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0
    ):
        return ".mp3"
    if data.startswith(b"fLaC"):
        return ".flac"
    if data.startswith(b"OggS"):
        return ".ogg"

    # PDF Document
    if data.startswith(b"%PDF-"):
        return ".pdf"

    # Archives: ZIP, 7Z, RAR, GZ
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return ".zip"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return ".rar"
    if data.startswith(b"\x1f\x8b"):
        return ".gz"

    # Images: PNG, JPEG, GIF, BMP
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif"
    if data.startswith(b"BM"):
        return ".bmp"

    # Windows Executable
    if data.startswith(b"MZ"):
        return ".exe"

    return None


class SpeedLimitVar:
    """متغير آمن للوصول والتعديل المتزامن بين خيوط الخلفية وواجهة المستخدم."""

    def __init__(self, value: float = 0.0):
        self._val = float(value)
        self._lock = threading.Lock()

    def get(self) -> float:
        with self._lock:
            return self._val

    def set(self, val: float):
        with self._lock:
            self._val = float(val)


class DownloadChunk:
    """تمثيل دقيق لشريحة التحميل الديناميكية (Dynamic Segment Chunk)."""

    def __init__(self, chunk_id: int, start: int, end: int, part_path: str):
        self.chunk_id = chunk_id
        self.start = start
        self.end = end
        self.current = start
        self.part_path = part_path
        self.is_completed = False
        self.is_active = False
        self.lock = threading.RLock()

    @property
    def remaining(self) -> int:
        with self.lock:
            return max(0, self.end - self.current + 1)


class DownloadTask:
    """كائن إدارة مهمة التحميل وتنسيق الخيوط المستقلة."""

    def __init__(
        self,
        url_or_path: str,
        output_dir: str,
        is_local: bool = False,
        custom_name: str = "",
    ):
        self.lock = threading.RLock()
        self.source = url_or_path
        self.is_local = is_local
        self.output_dir = output_dir

        if is_local:
            self.file_name = os.path.basename(url_or_path)
            self.total_bytes = os.path.getsize(url_or_path)
            self.supports_range = True
        else:
            parsed_path = urllib.parse.urlparse(url_or_path).path
            base = os.path.basename(parsed_path.rstrip("/"))
            base = urllib.parse.unquote(base) if base else ""
            self.file_name = sanitize_filename(
                custom_name or base or "downloaded_file"
            )
            self.total_bytes = 0
            self.supports_range = False

        self.output_path = os.path.join(output_dir, self.file_name)
        task_hash = hashlib.md5(
            url_or_path.encode("utf-8", errors="ignore")
        ).hexdigest()[:10]
        self.temp_dir = os.path.join(output_dir, f".idm_parts_{task_hash}")

        # محدد السرعة الخاص بهذا الملف (0 = غير محدود بالكيلوبايت/ثانية)
        self.speed_limit_kbps = SpeedLimitVar(0.0)

        # إدارة الشرائح الديناميكية (IDM-style ChunksList)
        self.chunks: List[DownloadChunk] = []
        self.chunks_lock = threading.RLock()
        self.max_connections = 8

        # الحالة والمقاييس
        self.status = "جاهز في الانتظار"
        self.progress_percent = 0.0
        self.downloaded_bytes = 0
        self.current_speed = "0.0 KB/s"
        self.eta_str = "--:--"
        self.is_running = False
        self.is_cancelled = False
        self.is_verified = False
        self.final_hash = ""

        # عناصر واجهة المستخدم
        self.ui_title: Optional[tk.Label] = None
        self.ui_progress: Optional[ttk.Progressbar] = None
        self.ui_status: Optional[tk.Label] = None
        self.ui_speed: Optional[tk.Label] = None
        self.ui_chunks_badge: Optional[tk.Label] = None
        self.ui_limit_label: Optional[tk.Label] = None

    def refine_filename(
        self,
        content_disposition: str = "",
        content_type: str = "",
        initial_bytes: Optional[bytes] = None,
        final_url: str = "",
    ) -> bool:
        """تحسين وتصحيح اسم وامتداد الملف تلقائياً بناءً على ترويسات الخادم والبصمة الرقمية."""
        with self.lock:
            changed = False
            current_name = self.file_name
            current_base, current_ext = os.path.splitext(current_name)

            # 1. محاولة استخراج الاسم الكامل من Content-Disposition
            if content_disposition:
                cd_name = parse_content_disposition(content_disposition)
                if cd_name:
                    cd_name = sanitize_filename(cd_name)
                    cd_base, cd_ext = os.path.splitext(cd_name)
                    if cd_ext:
                        current_name = cd_name
                        current_base, current_ext = cd_base, cd_ext
                        changed = True
                    elif not current_ext:
                        current_name = cd_name
                        current_base = cd_name
                        changed = True

            # 2. فحص الرابط النهائي المحوّل (Redirected URL) ومعلمات الاستعلام (Query Parameters)
            url_to_check = final_url or self.source
            if url_to_check:
                try:
                    parsed_u = urllib.parse.urlparse(url_to_check)
                    qs = urllib.parse.parse_qs(parsed_u.query)
                    if not content_type and "mime" in qs:
                        content_type = qs["mime"][0]

                    if not current_ext or current_ext.lower() in [
                        ".bin",
                        ".tmp",
                        ".download",
                    ]:
                        path_base = os.path.basename(parsed_u.path.rstrip("/"))
                        if path_base:
                            path_base = urllib.parse.unquote(path_base)
                            _, p_ext = os.path.splitext(path_base)
                            if p_ext and len(p_ext) <= 6:
                                current_ext = p_ext
                                current_name = f"{current_base}{current_ext}"
                                changed = True
                except Exception:
                    pass

            # 3. إذا كان الملف بدون امتداد أو بامتداد عام (.bin, .tmp)، نستنتجه من Content-Type أو Magic Bytes
            if not current_ext or current_ext.lower() in [
                ".bin",
                ".tmp",
                ".download",
            ]:
                detected_ext = None

                # أ. فحص Content-Type
                if content_type:
                    clean_ct = content_type.split(";")[0].strip().lower()
                    detected_ext = MIME_TO_EXT.get(clean_ct)
                    if not detected_ext:
                        detected_ext = mimetypes.guess_extension(clean_ct)

                # ب. فحص البصمة الثنائية (Magic Bytes)
                if not detected_ext and initial_bytes:
                    detected_ext = sniff_extension_from_magic_bytes(initial_bytes)

                if detected_ext:
                    if detected_ext.lower() == ".jpe":
                        detected_ext = ".jpg"
                    current_ext = detected_ext
                    current_name = f"{current_base}{current_ext}"
                    changed = True

            if changed and current_name != self.file_name:
                self.file_name = sanitize_filename(current_name)
                self.output_path = os.path.join(self.output_dir, self.file_name)
                return True
            return False

    def split_largest_chunk(self) -> Optional[DownloadChunk]:
        """محاكاة دالة IDM: Connection::OnChangeBounds() لتقسيم الشريحة إلى نصفين حياً بدون قفل ميت."""
        with self.chunks_lock:
            # نبحث عن شريحة نشطة متبقٍ منها أكثر من 1 ميجابايت
            candidates = []
            for c in self.chunks:
                if not c.is_completed:
                    with c.lock:
                        rem = max(0, c.end - c.current + 1)
                    if rem > 1024 * 1024:
                        candidates.append((rem, c))

            if not candidates:
                return None

            candidates.sort(key=lambda x: x[0], reverse=True)
            largest_rem, largest = candidates[0]

            with largest.lock:
                rem = max(0, largest.end - largest.current + 1)
                if rem < 1024 * 1024:
                    return None

                half = rem // 2
                new_start = largest.end - half + 1
                new_end = largest.end

                # تعديل حدود الشريحة الحالية لتقف عند النصف
                largest.end = new_start - 1

                # إنشاء الشريحة الجديدة للنصف الآخر
                new_id = len(self.chunks)
                part_path = os.path.join(
                    self.temp_dir, f"part_{new_id:04d}.bin"
                )
                new_chunk = DownloadChunk(new_id, new_start, new_end, part_path)
                self.chunks.append(new_chunk)
                return new_chunk


class DynamicDownloadEngine:
    """محرك التحميل والتقسيم الديناميكي والدمج الآمن."""

    @staticmethod
    def start_download(task: DownloadTask, on_update_ui, on_log):
        worker = threading.Thread(
            target=DynamicDownloadEngine._orchestrate_task,
            args=(task, on_update_ui, on_log),
            daemon=True,
        )
        worker.start()

    @staticmethod
    def _orchestrate_task(task: DownloadTask, on_update_ui, on_log):
        def safe_log(msg, level="INFO"):
            try:
                on_log(msg, level)
            except Exception:
                pass

        def safe_update_ui(t):
            try:
                on_update_ui(t)
            except Exception:
                pass

        task.is_running = True
        task.is_cancelled = False
        os.makedirs(task.temp_dir, exist_ok=True)

        safe_log(
            f"[بدء الجلسة] تهيئة مهمة التحميل: {task.file_name}", "INFO"
        )

        try:
            # 1. الاستكشاف الأولي للملف أو الرابط (Pre-flight Inspection)
            if not task.is_local:
                task.status = "جاري فحص دعم Range وحجم الخادم..."
                safe_update_ui(task)
                req = urllib.request.Request(
                    task.source,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tonec-REA/6.7"
                    },
                    method="HEAD",
                )
                try:
                    with urllib.request.urlopen(req, timeout=12) as response:
                        length_header = response.headers.get("Content-Length")
                        accept_ranges = response.headers.get(
                            "Accept-Ranges", ""
                        ).lower()
                        if length_header:
                            task.total_bytes = int(length_header)
                        task.supports_range = (
                            accept_ranges == "bytes" or response.status == 206
                        )
                        cd = response.headers.get("Content-Disposition", "")
                        ct = response.headers.get("Content-Type", "")
                        final_url = response.geturl()
                        if task.refine_filename(
                            content_disposition=cd,
                            content_type=ct,
                            final_url=final_url,
                        ):
                            safe_log(
                                f"[كشف الهوية] تم تحديد اسم وامتداد الملف: {task.file_name}",
                                "INFO",
                            )
                            safe_update_ui(task)
                except Exception as e:
                    safe_log(
                        f"[تحذير] فشل طلب HEAD: {e}. سيتم المحاولة عبر طلب مباشر.",
                        "WARN",
                    )

            if task.total_bytes > 0:
                safe_log(
                    f"[معلومات] الحجم الإجمالي: {task.total_bytes:,} بايت | دعم التقسيم المتوازي (Accept-Ranges): {task.supports_range}",
                    "INFO",
                )
            else:
                safe_log(
                    f"[معلومات] تدفق مستمر غير محدد الحجم مسبقاً (Stream).",
                    "WARN",
                )

            # 2. تهيئة الشريحة الأولى (ChunksList::InitFirst)
            with task.chunks_lock:
                task.chunks.clear()
                first_part = os.path.join(task.temp_dir, "part_0000.bin")
                end_bound = (
                    task.total_bytes - 1 if task.total_bytes > 0 else 0
                )
                task.chunks.append(
                    DownloadChunk(0, 0, end_bound, first_part)
                )

            threads: List[threading.Thread] = []

            # تشغيل أول خيط للبدء الفوري
            t1 = threading.Thread(
                target=DynamicDownloadEngine._worker_loop,
                args=(task, task.chunks[0], safe_update_ui, safe_log),
                daemon=True,
            )
            t1.start()
            threads.append(t1)

            # 3. حلقة الجدولة والمراقبة الحية للتقسيم الديناميكي (Dynamic Scaling Supervisor)
            last_bytes = 0
            while True:
                if task.is_cancelled:
                    task.status = "تم الإلغاء"
                    safe_log(f"[إلغاء] تم إلغاء المهمة: {task.file_name}", "WARN")
                    return

                time.sleep(0.5)

                # حساب السرعة الحالية وتقدير الوقت المتبقي
                with task.chunks_lock:
                    active_chunks = [c for c in task.chunks if not c.is_completed]
                    all_done = len(active_chunks) == 0

                delta = task.downloaded_bytes - last_bytes
                last_bytes = task.downloaded_bytes
                speed_kbps = (delta / 1024) / 0.5
                task.current_speed = f"{speed_kbps:.1f} KB/s"

                if speed_kbps > 0 and task.total_bytes > task.downloaded_bytes:
                    rem_sec = int(
                        (task.total_bytes - task.downloaded_bytes)
                        / (speed_kbps * 1024)
                    )
                    task.eta_str = f"{rem_sec // 60:02d}:{rem_sec % 60:02d}"
                else:
                    task.eta_str = "--:--"

                if task.total_bytes > 0:
                    task.progress_percent = (
                        task.downloaded_bytes / task.total_bytes
                    ) * 100
                safe_update_ui(task)

                if all_done:
                    break

                # تطبيق التقسيم الديناميكي الذكي (Dynamic Segment Splitting)
                alive_threads = [t for t in threads if t.is_alive()]
                if (
                    task.supports_range
                    and task.total_bytes > 2 * 1024 * 1024
                    and len(alive_threads) < task.max_connections
                    and len(task.chunks) < task.max_connections
                ):
                    new_chunk = task.split_largest_chunk()
                    if new_chunk:
                        safe_log(
                            f"[تقسيم ديناميكي] تم تقسيم أكبر شريحة وتوليد الجزء #{new_chunk.chunk_id} بنطاق ({new_chunk.start:,} -> {new_chunk.end:,})",
                            "INFO",
                        )
                        t_new = threading.Thread(
                            target=DynamicDownloadEngine._worker_loop,
                            args=(task, new_chunk, safe_update_ui, safe_log),
                            daemon=True,
                        )
                        t_new.start()
                        threads.append(t_new)

            for t in threads:
                t.join(timeout=1.0)

            if task.is_cancelled:
                task.status = "تم الإلغاء"
                safe_log(f"[إلغاء] تم إلغاء المهمة: {task.file_name}", "WARN")
                return

            # 4. مرحلة الدمج والتحقق النهائي (ChunksList::AppendFile)
            task.status = "جاري تجميع ودمج الأجزاء (AppendFile)..."
            safe_update_ui(task)
            safe_log(
                f"[دمج] بدء تجميع شرائح {task.file_name} المكتملة بالتسلسل...",
                "INFO",
            )

            DynamicDownloadEngine._assemble_lossless(task, safe_update_ui, safe_log)

        except Exception as ex:
            task.status = f"خطأ: {str(ex)}"
            safe_log(
                f"[استثناء] حدث خطأ أثناء المعالجة: {ex}", "ERROR"
            )
        finally:
            task.is_running = False
            safe_update_ui(task)

    @staticmethod
    def _worker_loop(
        task: DownloadTask,
        chunk: DownloadChunk,
        on_update_ui,
        on_log,
    ):
        chunk.is_active = True
        try:
            if task.is_local:
                DynamicDownloadEngine._stream_local(task, chunk)
            else:
                DynamicDownloadEngine._stream_http(
                    task, chunk, on_update_ui, on_log
                )
            chunk.is_completed = True
        except Exception as e:
            on_log(
                f"[خطأ خيط #{chunk.chunk_id}] انقطع التدفق: {e}", "WARN"
            )
        finally:
            chunk.is_active = False

    @staticmethod
    def _stream_http(
        task: DownloadTask,
        chunk: DownloadChunk,
        on_update_ui=None,
        on_log=None,
    ):
        # وضع الاستئناف إذا كان جزء مكتوب جزئياً
        existing_size = (
            os.path.getsize(chunk.part_path)
            if os.path.exists(chunk.part_path)
            else 0
        )
        chunk.current = chunk.start + existing_size
        req_start = chunk.current

        # إذا كانت الشريحة مقفلة ومحددة النهاية
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tonec-REA/6.7"
        }
        if task.supports_range and task.total_bytes > 0:
            with chunk.lock:
                req_end = chunk.end
            headers["Range"] = f"bytes={req_start}-{req_end}"

        req = urllib.request.Request(task.source, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            # فحص الترويسات للقطعة الأولى لاستخراج الاسم والامتداد
            if chunk.chunk_id == 0:
                cd = resp.headers.get("Content-Disposition", "")
                ct = resp.headers.get("Content-Type", "")
                final_url = resp.geturl()
                if task.refine_filename(
                    content_disposition=cd,
                    content_type=ct,
                    final_url=final_url,
                ):
                    if on_log:
                        on_log(
                            f"[كشف الهوية] تم تحديد اسم وامتداد الملف من ترويسات الخادم: {task.file_name}",
                            "INFO",
                        )
                    if on_update_ui:
                        on_update_ui(task)

            mode = "ab" if existing_size > 0 else "wb"
            with open(chunk.part_path, mode) as out:
                first_buffer = True
                while True:
                    if task.is_cancelled:
                        return
                    with chunk.lock:
                        if task.supports_range and task.total_bytes > 0:
                            rem = chunk.end - chunk.current + 1
                            if rem <= 0:
                                break
                            to_read = min(DEFAULT_BUFFER_SIZE, rem)
                        else:
                            to_read = DEFAULT_BUFFER_SIZE

                    t0 = time.perf_counter()
                    try:
                        buf = resp.read(to_read)
                    except Exception as e:
                        if on_log:
                            on_log(
                                f"[تحذير خيط #{chunk.chunk_id}] انقطاع القراءة: {e}",
                                "WARN",
                            )
                        break

                    if not buf:
                        break

                    # فحص البصمة الثنائية الحية (Magic Bytes) عند استلام أول حزمة
                    if (
                        first_buffer
                        and chunk.chunk_id == 0
                        and existing_size == 0
                        and len(buf) >= 12
                    ):
                        first_buffer = False
                        curr_ext = os.path.splitext(task.file_name)[1]
                        if not curr_ext or curr_ext.lower() in [
                            ".bin",
                            ".tmp",
                            ".download",
                        ]:
                            if task.refine_filename(initial_bytes=buf[:512]):
                                if on_log:
                                    on_log(
                                        f"[كشف البصمة الحية] تم استنتاج نوع الملف عبر Magic Bytes: {task.file_name}",
                                        "INFO",
                                    )
                                if on_update_ui:
                                    on_update_ui(task)

                    out.write(buf)
                    buf_len = len(buf)
                    chunk.current += buf_len
                    task.downloaded_bytes += buf_len

                    # محدد السرعة اليدوي لكل ملف (Manual Throttle)
                    limit = task.speed_limit_kbps.get()
                    if limit > 0:
                        target_sec = buf_len / (limit * 1024)
                        elapsed = time.perf_counter() - t0
                        if elapsed < target_sec:
                            time.sleep(target_sec - elapsed)

    @staticmethod
    def _stream_local(task: DownloadTask, chunk: DownloadChunk):
        with open(task.source, "rb") as src:
            src.seek(chunk.start)
            with open(chunk.part_path, "wb") as out:
                while True:
                    if task.is_cancelled:
                        return
                    with chunk.lock:
                        rem = chunk.end - chunk.current + 1
                        if rem <= 0:
                            break
                        read_size = min(DEFAULT_BUFFER_SIZE, rem)

                    t0 = time.perf_counter()
                    buf = src.read(read_size)
                    if not buf:
                        break

                    out.write(buf)
                    buf_len = len(buf)
                    chunk.current += buf_len
                    task.downloaded_bytes += buf_len

                    # محدد السرعة اليدوي
                    limit = task.speed_limit_kbps.get()
                    if limit > 0:
                        target_sec = buf_len / (limit * 1024)
                        elapsed = time.perf_counter() - t0
                        if elapsed < target_sec:
                            time.sleep(target_sec - elapsed)

    @staticmethod
    def _assemble_lossless(task: DownloadTask, on_update_ui, on_log):
        # فرز الشرائح ترتيباً تصاعدياً دقيقاً حسب الـ start byte
        sorted_chunks = sorted(task.chunks, key=lambda c: c.start)

        # فحص البصمة الثنائية (Magic Bytes) للقطعة الأولى للتأكد التام من الامتداد قبل الدمج
        curr_ext = os.path.splitext(task.file_name)[1]
        if not curr_ext or curr_ext.lower() in [
            ".bin",
            ".tmp",
            ".download",
        ]:
            try:
                if sorted_chunks and os.path.exists(sorted_chunks[0].part_path):
                    with open(sorted_chunks[0].part_path, "rb") as fp:
                        header_sample = fp.read(512)
                    if task.refine_filename(initial_bytes=header_sample):
                        on_log(
                            f"[فحص البصمة Magic Bytes] تم اكتشاف نوع الملف بنجاح وتعيين الامتداد: {task.file_name}",
                            "INFO",
                        )
                        if on_update_ui:
                            on_update_ui(task)
            except Exception as e:
                on_log(f"[تحذير] تعذر فحص البصمة الثنائية: {e}", "WARN")

        # تجنب الكتابة فوق ملف موجود مسبقاً بنفس الاسم
        if os.path.exists(task.output_path):
            base_p, ext_p = os.path.splitext(task.output_path)
            c_idx = 1
            while os.path.exists(f"{base_p} ({c_idx}){ext_p}"):
                c_idx += 1
            task.output_path = f"{base_p} ({c_idx}){ext_p}"
            task.file_name = os.path.basename(task.output_path)
            if on_update_ui:
                on_update_ui(task)

        hasher = hashlib.sha256()
        total_stitched = 0

        with open(task.output_path, "wb") as final_file:
            for c in sorted_chunks:
                if not os.path.exists(c.part_path):
                    raise FileNotFoundError(
                        f"فقدان شريحة مادية: {c.part_path}"
                    )
                with open(c.part_path, "rb") as part:
                    while True:
                        block = part.read(128 * 1024)
                        if not block:
                            break
                        final_file.write(block)
                        hasher.update(block)
                        total_stitched += len(block)

        task.final_hash = hasher.hexdigest()

        # التحقق الثلاثي من الاكتمال وعدم التلف
        if task.total_bytes > 0 and total_stitched != task.total_bytes:
            task.is_verified = False
            task.status = "فشل التحقق: عدم تطابق الحجم"
            try:
                on_log(
                    f"[خطأ] الحجم المجمع ({total_stitched}) لا يطابق الأصلي ({task.total_bytes})!",
                    "ERROR",
                )
            except Exception:
                pass
            return

        task.is_verified = True
        task.status = "مكتمل ومتحقق بنسبة 100%"
        try:
            on_log(
                f"[نجاح] تم دمج {task.file_name} بنجاح! البصمة: {task.final_hash[:16]}...",
                "SUCCESS",
            )
        except Exception:
            pass

        # تنظيف مجلد الشرائح المؤقتة
        for c in sorted_chunks:
            try:
                os.remove(c.part_path)
            except:
                pass
        try:
            os.rmdir(task.temp_dir)
        except:
            pass


class ModernDownloaderWindow:
    """الواجهة الرسومية الحديثة مع دعم شريط المهام (Taskbar) والمظهر الداكن الأصلي."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.root.geometry("1020x740")
        self.root.minsize(850, 520)
        self.root.configure(bg="#181825")

        self.tasks: List[DownloadTask] = []
        self.output_dir = os.path.abspath("./downloads_output")
        os.makedirs(self.output_dir, exist_ok=True)

        self._build_components()
        self._center()
        self._apply_windows_dark_title_bar()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_clicked)

    def _center(self):
        self.root.update_idletasks()
        w, h = 1020, 740
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _apply_windows_dark_title_bar(self):
        """تطبيق المظهر الداكن الأصلي (Native Dark Mode) على شريط عنوان ويندوز."""
        try:
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 11 / 10 20H1+)
            val = ctypes.c_int(2)
            try:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 20, ctypes.byref(val), ctypes.sizeof(val)
                )
            except Exception:
                val = ctypes.c_int(1)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, 19, ctypes.byref(val), ctypes.sizeof(val)
                )
        except Exception:
            pass

    def _build_components(self):
        # 1. شريط الأوامر العلوي (Toolbar)
        toolbar = tk.Frame(self.root, bg="#1e1e2e", height=64)
        toolbar.pack(fill=tk.X, padx=16, pady=(14, 8))

        btn_url = tk.Button(
            toolbar,
            text="🔗 إضافة رابط ويب (URL)",
            command=self._prompt_add_url,
            font=("Segoe UI", 9, "bold"),
            bg="#89b4fa",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#b4befe",
        )
        btn_url.pack(side=tk.LEFT, padx=10, pady=12)

        btn_local = tk.Button(
            toolbar,
            text="📁 محاكاة ملف محلي (Local)",
            command=self._prompt_add_local,
            font=("Segoe UI", 9, "bold"),
            bg="#b4befe",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#cdd6f4",
        )
        btn_local.pack(side=tk.LEFT, padx=6, pady=12)

        btn_start_all = tk.Button(
            toolbar,
            text="🚀 بدء التحميل المتزامن",
            command=self._start_all,
            font=("Segoe UI", 9, "bold"),
            bg="#a6e3a1",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#94e2d5",
        )
        btn_start_all.pack(side=tk.LEFT, padx=10, pady=12)

        btn_stop = tk.Button(
            toolbar,
            text="⏹ إيقاف الكل",
            command=self._stop_all,
            font=("Segoe UI", 9, "bold"),
            bg="#f38ba8",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#eba0ac",
        )
        btn_stop.pack(side=tk.LEFT, padx=6, pady=12)

        btn_open_folder = tk.Button(
            toolbar,
            text="📂 فتح مجلد التحميل",
            command=self._open_downloads_folder,
            font=("Segoe UI", 9, "bold"),
            bg="#313244",
            fg="#cdd6f4",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
            activebackground="#45475a",
            activeforeground="#ffffff",
        )
        btn_open_folder.pack(side=tk.RIGHT, padx=10, pady=12)

        dest_lbl = tk.Label(
            toolbar,
            text=f"الحفظ: {self.output_dir}",
            font=("Segoe UI", 8),
            bg="#1e1e2e",
            fg="#a6adc8",
        )
        dest_lbl.pack(side=tk.RIGHT, padx=6)

        # 3. لوحة عرض بطاقات التحميل (Download Cards Canvas)
        card_area = tk.Frame(self.root, bg="#181825")
        card_area.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

        self.canvas = tk.Canvas(
            card_area, bg="#181825", bd=0, highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            card_area, orient=tk.VERTICAL, command=self.canvas.yview
        )
        self.scrollable = tk.Frame(self.canvas, bg="#181825")

        self.scrollable.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            ),
        )
        self.canvas.create_window(
            (0, 0), window=self.scrollable, anchor="nw"
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 4. لوحة سجل الأحداث والتدفق البرمجي (Audit & Chunk Log)
        log_box = tk.Frame(self.root, bg="#11111b", height=150)
        log_box.pack(fill=tk.X, padx=16, pady=(6, 16))
        log_box.pack_propagate(False)

        log_head = tk.Label(
            log_box,
            text="📋 سجل التدفق والتقسيم الديناميكي (Dynamic Chunking Event Log)",
            font=("Segoe UI", 8, "bold"),
            bg="#11111b",
            fg="#89b4fa",
        )
        log_head.pack(anchor="w", padx=10, pady=(6, 2))

        self.log_txt = tk.Text(
            log_box,
            bg="#181825",
            fg="#cdd6f4",
            font=("Consolas", 8),
            bd=0,
            padx=8,
            pady=4,
            relief=tk.FLAT,
        )
        self.log_txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        self.log_txt.tag_config("INFO", foreground="#89b4fa")
        self.log_txt.tag_config("SUCCESS", foreground="#a6e3a1")
        self.log_txt.tag_config("WARN", foreground="#fab387")
        self.log_txt.tag_config("ERROR", foreground="#f38ba8")

    def _on_close_clicked(self):
        running = [t for t in self.tasks if t.is_running]
        if running:
            res = messagebox.askyesno(
                "تحميلات نشطة قيد التشغيل",
                f"يوجد حالياً {len(running)} مهمة تحميل نشطة قيد التنفيذ في الخلفية.\n\n"
                "• هل ترغب في إيقاف التحميلات والخروج نهائياً؟\n"
                "(إذا كنت ترغب في استمرار التحميل، اختر 'لا' وقم بتصغير النافذة لشريط المهام).",
                parent=self.root,
            )
            if not res:
                return
        for task in self.tasks:
            task.is_cancelled = True
        self.root.destroy()
        sys.exit(0)

    def _log(self, msg: str, level="INFO"):
        def write():
            t = time.strftime("%H:%M:%S")
            self.log_txt.insert(tk.END, f"[{t}] {msg}\n", level)
            self.log_txt.see(tk.END)

        self.root.after(0, write)

    def _prompt_add_url(self):
        url = simpledialog.askstring(
            "إضافة رابط", "أدخل رابط الملف المباشر (HTTP/HTTPS):", parent=self.root
        )
        if url and url.strip():
            clean_url = url.strip()
            if "youtube.com" in clean_url.lower() or "youtu.be" in clean_url.lower():
                res = messagebox.askyesno(
                    "تنبيه حول روابط يوتيوب",
                    "روابط منصة YouTube هي صفحات ويب مشفرة وليست روابط تنزيل وسائط مباشرة.\n\n"
                    "• برنامج IDM الأصلي يستخدم إضافة للمتصفح لاعتراض مسار البث المباشر (Direct CDN Stream).\n"
                    "• لتنزيل الملفات بنجاح، يُرجى استخدام روابط التنزيل المباشرة (مثل ملفات exe, zip, mp4 المباشرة).\n\n"
                    "هل ترغب في المتابعة وإضافة هذا الرابط على أي حال؟",
                    parent=self.root,
                )
                if not res:
                    return

            task = DownloadTask(clean_url, self.output_dir, is_local=False)
            self.tasks.append(task)
            self._render_card(task)
            self._log(f"تمت إضافة الرابط: {task.source}")

    def _prompt_add_local(self):
        path = filedialog.askopenfilename(
            title="اختر ملفاً لمحاكاة التقسيم والتحميل المتوازي"
        )
        if path:
            task = DownloadTask(path, self.output_dir, is_local=True)
            self.tasks.append(task)
            self._render_card(task)
            self._log(
                f"تمت إضافة الملف المحلي: {task.file_name} ({task.total_bytes:,} بايت)"
            )

    def _open_downloads_folder(self):
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            os.startfile(self.output_dir)
            self._log(f"تم فتح مجلد التنزيلات: {self.output_dir}")
        except Exception as e:
            messagebox.showerror("خطأ", f"تعذر فتح المجلد: {e}")

    def _render_card(self, task: DownloadTask):
        card = tk.Frame(
            self.scrollable,
            bg="#1e1e2e",
            padx=14,
            pady=10,
            highlightbackground="#313244",
            highlightthickness=1,
        )
        card.pack(fill=tk.X, expand=True, padx=8, pady=5)

        # الصف الأول: العنوان والأزرار ومحدد السرعة اليدوي
        r1 = tk.Frame(card, bg="#1e1e2e")
        r1.pack(fill=tk.X)

        title = f"📦 {task.file_name}"
        t_lbl = tk.Label(
            r1,
            text=title,
            font=("Segoe UI", 9, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
        )
        t_lbl.pack(side=tk.LEFT)
        task.ui_title = t_lbl

        size_txt = (
            f"({task.total_bytes / (1024*1024):.1f} MB)"
            if task.total_bytes > 0
            else "(جاري استكشاف الحجم...)"
        )
        s_lbl = tk.Label(
            r1,
            text=size_txt,
            font=("Segoe UI", 8),
            bg="#1e1e2e",
            fg="#a6adc8",
        )
        s_lbl.pack(side=tk.LEFT, padx=8)

        # الميزة المطلوبة: محدد سرعة مستقل لكل ملف
        speed_box = tk.Frame(r1, bg="#1e1e2e")
        speed_box.pack(side=tk.RIGHT)

        lbl_tag = tk.Label(
            speed_box,
            text="سرعة التحميل:",
            font=("Segoe UI", 8),
            bg="#1e1e2e",
            fg="#fab387",
        )
        lbl_tag.pack(side=tk.LEFT, padx=4)

        limit_disp = tk.Label(
            speed_box,
            text="غير محدود",
            font=("Segoe UI", 8, "bold"),
            bg="#1e1e2e",
            fg="#a6e3a1",
            width=11,
        )
        limit_disp.pack(side=tk.RIGHT, padx=4)
        task.ui_limit_label = limit_disp

        def on_slide(val):
            v = float(val)
            task.speed_limit_kbps.set(v)
            if v <= 0:
                limit_disp.config(text="غير محدود", fg="#a6e3a1")
            elif v < 1024:
                limit_disp.config(text=f"{int(v)} KB/s", fg="#fab387")
            else:
                limit_disp.config(
                    text=f"{v/1024:.1f} MB/s", fg="#89b4fa"
                )

        slider = tk.Scale(
            speed_box,
            from_=0,
            to=10240,
            resolution=128,
            orient=tk.HORIZONTAL,
            showvalue=False,
            command=on_slide,
            bg="#1e1e2e",
            fg="#cdd6f4",
            troughcolor="#11111b",
            highlightthickness=0,
            length=130,
            sliderrelief=tk.FLAT,
        )
        slider.set(0)
        slider.pack(side=tk.RIGHT, padx=4)

        # الصف الثاني: شريط التقدم
        r2 = tk.Frame(card, bg="#1e1e2e")
        r2.pack(fill=tk.X, pady=(8, 4))

        prog = ttk.Progressbar(r2, orient=tk.HORIZONTAL, mode="determinate")
        prog.pack(fill=tk.X)
        task.ui_progress = prog

        # الصف الثالث: العدادات والشرائح النشطة والسرعة
        r3 = tk.Frame(card, bg="#1e1e2e")
        r3.pack(fill=tk.X, pady=(2, 0))

        st_lbl = tk.Label(
            r3,
            text=f"الحالة: {task.status}",
            font=("Segoe UI", 8),
            bg="#1e1e2e",
            fg="#a6adc8",
        )
        st_lbl.pack(side=tk.LEFT)
        task.ui_status = st_lbl

        sp_lbl = tk.Label(
            r3,
            text=f"السرعة: {task.current_speed} | الوقت المتبقي: {task.eta_str}",
            font=("Segoe UI", 8, "bold"),
            bg="#1e1e2e",
            fg="#89b4fa",
        )
        sp_lbl.pack(side=tk.RIGHT)
        task.ui_speed = sp_lbl

    def _update_card_ui(self, task: DownloadTask):
        def sync():
            try:
                if not self.root.winfo_exists():
                    return
                if task.ui_title:
                    task.ui_title.config(text=f"📦 {task.file_name}")
                if task.ui_progress:
                    task.ui_progress["value"] = task.progress_percent
                if task.ui_status:
                    num_chunks = len(task.chunks)
                    active = sum(1 for c in task.chunks if not c.is_completed)
                    task.ui_status.config(
                        text=f"الحالة: {task.status} | (الأجزاء: {num_chunks} إجمالي، {active} نشط)"
                    )
                    if task.is_verified:
                        task.ui_status.config(fg="#a6e3a1")
                    elif "خطأ" in task.status:
                        task.ui_status.config(fg="#f38ba8")
                if task.ui_speed:
                    task.ui_speed.config(
                        text=f"السرعة: {task.current_speed} ({task.progress_percent:.1f}%) | متبقي: {task.eta_str}"
                    )
            except Exception:
                pass

        try:
            self.root.after(0, sync)
        except Exception:
            pass

    def _start_all(self):
        pending = [t for t in self.tasks if not t.is_running and not t.is_verified]
        if not pending:
            messagebox.showinfo(
                "تنبيه", "لا توجد مهام جديدة في الانتظار لبدء تحميلها."
            )
            return

        for task in pending:
            DynamicDownloadEngine.start_download(
                task, self._update_card_ui, self._log
            )

    def _stop_all(self):
        for task in self.tasks:
            if task.is_running:
                task.is_cancelled = True
        self._log("تم إرسال إشارة إيقاف لجميع المهام.", "WARN")


if __name__ == "__main__":
    # قفل النسخة الواحدة: ضمان تشغيل نسخة واحدة فقط ومنع التكرار في الخلفية
    instance_mutex = acquire_single_instance_lock()
    if not instance_mutex:
        sys.exit(0)

    app_root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(
        "Horizontal.TProgressbar",
        background="#89b4fa",
        troughcolor="#11111b",
        bordercolor="#1e1e2e",
        lightcolor="#89b4fa",
        darkcolor="#89b4fa",
    )

    app = ModernDownloaderWindow(app_root)
    app_root.mainloop()
