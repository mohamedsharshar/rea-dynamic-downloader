"""
================================================================================
  REA Multi-Part Chunking & Lossless Stream Transfer Engine (Python Edition)
  - Frameless Modern Dark UI
  - Individual Per-File Speed Throttling (تحديد سرعة التدفق لكل ملف بشكل مستقل)
  - 64 KB Positional Chunking & Streaming
  - Three-Way Lossless Reassembly Verification (Bytes, Chunks, SHA-256 Digest)
================================================================================
"""

import os
import sys
import time
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Dict

CHUNK_SIZE = 64 * 1024  # 64 KB per chunk (مطابق لبروتوكول REA)


class FileTransferTask:
    """كائن يمثل مهمة نقل وتقسيم ودمج ملف واحد مع إعدادات السرعة والحالة الخاصة به."""

    def __init__(self, file_path: str, output_dir: str):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.total_bytes = os.path.getsize(file_path)
        self.output_dir = output_dir
        self.output_path = os.path.join(output_dir, f"verified_{self.file_name}")

        # محدد السرعة الخاص بهذا الملف (0 = غير محدود، أو قيمة بالكيلوبايت/ثانية)
        self.speed_limit_kbps = tk.DoubleVar(value=0.0)

        # بيانات المراقبة وتدفق الحالة
        self.status = "جاهز في الانتظار"
        self.progress_percent = 0.0
        self.transferred_bytes = 0
        self.current_speed = "0.0 KB/s"
        self.original_hash = ""
        self.reassembled_hash = ""
        self.is_verified = False
        self.is_running = False
        self.is_cancelled = False

        # عناصر واجهة المستخدم الخاصة بهذه المهمة
        self.ui_progress_bar: Optional[ttk.Progressbar] = None
        self.ui_status_label: Optional[tk.Label] = None
        self.ui_speed_label: Optional[tk.Label] = None
        self.ui_limit_label: Optional[tk.Label] = None


class ChunkTransferEngine:
    """محرك التقسيم التدفقي، خنق السرعة، والدمج الآمن مع التحقق الرياضي."""

    @staticmethod
    def process_task(task: FileTransferTask, on_update_ui, on_log):
        task.is_running = True
        task.is_cancelled = False
        task.status = "جاري التقسيم والضخ التدفقي..."
        task.transferred_bytes = 0

        hasher_original = hashlib.sha256()
        chunk_files = []
        chunks_temp_dir = os.path.join(task.output_dir, f".parts_{task.file_name}")
        os.makedirs(chunks_temp_dir, exist_ok=True)

        on_log(
            f"[بدء] بدء معالجة الملف: {task.file_name} (الحجم: {task.total_bytes:,} بايت)",
            "INFO",
        )

        try:
            # 1. مرحلة قراءة وتقسيم وتدفق الأجزاء (Chunking & Rate-Limiting)
            with open(task.file_path, "rb") as src:
                chunk_index = 0
                while True:
                    if task.is_cancelled:
                        task.status = "تم الإلغاء من قبل المستخدم"
                        on_log(f"[إلغاء] تم إيقاف نقل: {task.file_name}", "WARN")
                        return

                    t_start = time.perf_counter()
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # تحديث التجزئة التراكمية للبصمة الأصلية
                    hasher_original.update(chunk)

                    # كتابة الشريحة المستقلة (Chunk Part)
                    chunk_path = os.path.join(
                        chunks_temp_dir, f"part_{chunk_index:06d}.chunk"
                    )
                    with open(chunk_path, "wb") as cf:
                        cf.write(chunk)
                    chunk_files.append(chunk_path)

                    chunk_len = len(chunk)
                    task.transferred_bytes += chunk_len
                    chunk_index += 1

                    # خوارزمية تحديد سرعة التدفق المستقلة لكل ملف (Throttling)
                    limit_kb = task.speed_limit_kbps.get()
                    if limit_kb > 0:
                        target_bytes_per_sec = limit_kb * 1024
                        expected_duration = chunk_len / target_bytes_per_sec
                        elapsed = time.perf_counter() - t_start
                        if elapsed < expected_duration:
                            time.sleep(expected_duration - elapsed)

                    actual_elapsed = time.perf_counter() - t_start
                    if actual_elapsed > 0:
                        curr_kbps = (chunk_len / 1024) / actual_elapsed
                        task.current_speed = f"{curr_kbps:.1f} KB/s"

                    task.progress_percent = (
                        (task.transferred_bytes / task.total_bytes) * 100
                        if task.total_bytes > 0
                        else 100
                    )
                    on_update_ui(task)

            task.original_hash = hasher_original.hexdigest()
            on_log(
                f"[تقسيم] اكتمل تقسيم {task.file_name} إلى {len(chunk_files)} جزء. البصمة: {task.original_hash[:16]}...",
                "INFO",
            )

            # 2. مرحلة الدمج والتحقق الرياضي الصارم (Lossless Reassembly)
            task.status = "جاري التحقق والدمج النهائي..."
            on_update_ui(task)
            on_log(
                f"[دمج] جاري دمج الأجزاء والتحقق من سلامة البصمات والأحجام...",
                "INFO",
            )

            hasher_reassembled = hashlib.sha256()
            merged_bytes = 0

            with open(task.output_path, "wb") as dst:
                for cp in chunk_files:
                    if task.is_cancelled:
                        task.status = "تم الإلغاء"
                        return
                    with open(cp, "rb") as cf:
                        part = cf.read()
                        dst.write(part)
                        hasher_reassembled.update(part)
                        merged_bytes += len(part)

            task.reassembled_hash = hasher_reassembled.hexdigest()

            # مصفوفة التحقق الثلاثي: (البايتات + عدد الأجزاء + SHA-256)
            is_valid = (
                merged_bytes == task.total_bytes
                and task.original_hash == task.reassembled_hash
                and len(chunk_files) == chunk_index
            )

            if is_valid:
                task.is_verified = True
                task.status = "✅ مكتمل ومطابق 100% دون أي تلف"
                on_log(
                    f"[نجاح] ✅ تم دمج {task.file_name} بنجاح ومطابقته رياضياً 100%!",
                    "SUCCESS",
                )
            else:
                task.is_verified = False
                task.status = "❌ فشل التحقق (عدم تطابق البيانات)"
                on_log(
                    f"[خطأ] ❌ فشل التحقق من {task.file_name}. تم التراجع وحذف الملف المدمج!",
                    "ERROR",
                )
                if os.path.exists(task.output_path):
                    os.remove(task.output_path)

            # تنظيف مجلد الأجزاء المؤقتة
            for cp in chunk_files:
                try:
                    os.remove(cp)
                except:
                    pass
            try:
                os.rmdir(chunks_temp_dir)
            except:
                pass

        except Exception as ex:
            task.status = f"خطأ: {str(ex)}"
            on_log(f"[استثناء] خطأ أثناء معالجة {task.file_name}: {ex}", "ERROR")
        finally:
            task.is_running = False
            on_update_ui(task)


class FramelessApp:
    """الواجهة الرسومية الحديثة بدون إطار (Modern Frameless Window)."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("REA Chunk Transfer & Flow Controller")
        self.root.geometry("980x720")
        self.root.configure(bg="#1e1e2e")

        # تفعيل نمط النافذة بدون إطار خارجي (Frameless Window)
        self.root.overrideredirect(True)

        self.tasks: List[FileTransferTask] = []
        self.output_dir = os.path.abspath("./reassembled_output")
        os.makedirs(self.output_dir, exist_ok=True)

        # متغيرات سحب النافذة
        self.drag_start_x = 0
        self.drag_start_y = 0

        self._build_ui()
        self._center_window()

    def _center_window(self):
        self.root.update_idletasks()
        w = 980
        h = 720
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        # 1. شريط العنوان المخصص (Custom Modern Title Bar)
        self.title_bar = tk.Frame(self.root, bg="#181825", height=42)
        self.title_bar.pack(fill=tk.X, side=tk.TOP)
        self.title_bar.pack_propagate(False)

        # أحداث سحب النافذة
        self.title_bar.bind("<ButtonPress-1>", self._start_drag)
        self.title_bar.bind("<B1-Motion>", self._on_drag)

        title_lbl = tk.Label(
            self.title_bar,
            text="⚡ REA Stream Chunk Transfer & Rate Controller",
            font=("Segoe UI", 10, "bold"),
            bg="#181825",
            fg="#cdd6f4",
        )
        title_lbl.pack(side=tk.LEFT, padx=14)
        title_lbl.bind("<ButtonPress-1>", self._start_drag)
        title_lbl.bind("<B1-Motion>", self._on_drag)

        # أزرار الإغلاق والتصغير
        btn_close = tk.Button(
            self.title_bar,
            text="✕",
            command=self.root.destroy,
            font=("Segoe UI", 10, "bold"),
            bg="#181825",
            fg="#f38ba8",
            bd=0,
            relief=tk.FLAT,
            activebackground="#f38ba8",
            activeforeground="#181825",
            width=4,
            cursor="hand2",
        )
        btn_close.pack(side=tk.RIGHT, fill=tk.Y)

        btn_min = tk.Button(
            self.title_bar,
            text="—",
            command=self._minimize_window,
            font=("Segoe UI", 10, "bold"),
            bg="#181825",
            fg="#a6adc8",
            bd=0,
            relief=tk.FLAT,
            activebackground="#313244",
            activeforeground="#cdd6f4",
            width=4,
            cursor="hand2",
        )
        btn_min.pack(side=tk.RIGHT, fill=tk.Y)

        # 2. شريط الأدوات العلوي (Toolbar Controls)
        toolbar = tk.Frame(self.root, bg="#252538", height=60)
        toolbar.pack(fill=tk.X, padx=16, pady=(16, 8))

        btn_add = tk.Button(
            toolbar,
            text="📁 إضافة ملفات",
            command=self._add_files,
            font=("Segoe UI", 9, "bold"),
            bg="#89b4fa",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#b4befe",
        )
        btn_add.pack(side=tk.LEFT, padx=10, pady=10)

        btn_start = tk.Button(
            toolbar,
            text="🚀 بدء النقل والدمج الآمن",
            command=self._start_all_transfers,
            font=("Segoe UI", 9, "bold"),
            bg="#a6e3a1",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#94e2d5",
        )
        btn_start.pack(side=tk.LEFT, padx=10, pady=10)

        btn_cancel = tk.Button(
            toolbar,
            text="⏹ إيقاف الكل",
            command=self._cancel_all,
            font=("Segoe UI", 9, "bold"),
            bg="#f38ba8",
            fg="#11111b",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            activebackground="#eba0ac",
        )
        btn_cancel.pack(side=tk.LEFT, padx=10, pady=10)

        self.out_lbl = tk.Label(
            toolbar,
            text=f"📂 مجلد الإخراج: {self.output_dir}",
            font=("Segoe UI", 8),
            bg="#252538",
            fg="#a6adc8",
        )
        self.out_lbl.pack(side=tk.RIGHT, padx=14)

        # 3. لوحة عرض المهام وقائمة الملفات (Task List Container)
        list_container = tk.Frame(self.root, bg="#1e1e2e")
        list_container.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        # Canvas مع شريط تمرير لعرض بطاقات الملفات بسلاسة
        self.canvas = tk.Canvas(
            list_container, bg="#181825", bd=0, highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            list_container, orient=tk.VERTICAL, command=self.canvas.yview
        )
        self.scrollable_frame = tk.Frame(self.canvas, bg="#181825")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            ),
        )
        self.canvas.create_window(
            (0, 0), window=self.scrollable_frame, anchor="nw"
        )
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 4. لوحة سجل العمليات المباشر (Terminal Audit Log)
        log_frame = tk.Frame(self.root, bg="#181825", height=160)
        log_frame.pack(fill=tk.X, padx=16, pady=(8, 16))
        log_frame.pack_propagate(False)

        log_title = tk.Label(
            log_frame,
            text="📋 سجل تدفق البيانات والتحقق الرياضي (Live Audit & Integrity Log)",
            font=("Segoe UI", 8, "bold"),
            bg="#181825",
            fg="#89b4fa",
        )
        log_title.pack(anchor="w", padx=10, pady=(6, 2))

        self.log_text = tk.Text(
            log_frame,
            bg="#11111b",
            fg="#cdd6f4",
            font=("Consolas", 8),
            bd=0,
            padx=8,
            pady=4,
            relief=tk.FLAT,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        # ألوان أسطر السجل
        self.log_text.tag_config("INFO", foreground="#89b4fa")
        self.log_text.tag_config("SUCCESS", foreground="#a6e3a1")
        self.log_text.tag_config("WARN", foreground="#fab387")
        self.log_text.tag_config("ERROR", foreground="#f38ba8")

    def _start_drag(self, event):
        self.drag_start_x = event.x
        self.drag_start_y = event.y

    def _on_drag(self, event):
        x = self.root.winfo_pointerx() - self.drag_start_x
        y = self.root.winfo_pointery() - self.drag_start_y
        self.root.geometry(f"+{x}+{y}")

    def _minimize_window(self):
        self.root.update_idletasks()
        self.root.overrideredirect(False)
        self.root.iconify()
        self.root.bind("<FocusIn>", self._on_restore)

    def _on_restore(self, event):
        if self.root.state() == "normal":
            self.root.overrideredirect(True)
            self.root.unbind("<FocusIn>")

    def _log(self, message: str, level="INFO"):
        def append():
            timestamp = time.strftime("%H:%M:%S")
            self.log_text.insert(
                tk.END, f"[{timestamp}] {message}\n", level
            )
            self.log_text.see(tk.END)

        self.root.after(0, append)

    def _add_files(self):
        files = filedialog.askopenfilenames(title="اختر ملفات لنقلها وتقسيمها")
        if not files:
            return

        for fp in files:
            if any(t.file_path == fp for t in self.tasks):
                continue
            task = FileTransferTask(fp, self.output_dir)
            self.tasks.append(task)
            self._render_task_card(task)
            self._log(
                f"تمت إضافة الملف: {task.file_name} ({task.total_bytes:,} بايت)"
            )

    def _render_task_card(self, task: FileTransferTask):
        card = tk.Frame(
            self.scrollable_frame,
            bg="#252538",
            padx=12,
            pady=10,
            highlightbackground="#313244",
            highlightthickness=1,
        )
        card.pack(fill=tk.X, expand=True, padx=10, pady=6)

        # الصف الأول: الاسم والحجم ومحدد السرعة اليدوي
        row1 = tk.Frame(card, bg="#252538")
        row1.pack(fill=tk.X)

        name_lbl = tk.Label(
            row1,
            text=f"📄 {task.file_name}",
            font=("Segoe UI", 9, "bold"),
            bg="#252538",
            fg="#cdd6f4",
        )
        name_lbl.pack(side=tk.LEFT)

        size_lbl = tk.Label(
            row1,
            text=f"({task.total_bytes / (1024*1024):.2f} MB)",
            font=("Segoe UI", 8),
            bg="#252538",
            fg="#a6adc8",
        )
        size_lbl.pack(side=tk.LEFT, padx=6)

        # الميزة المطلوبة: إمكانية تحديد سرعة التدفق بشكل يدوي لكل ملف
        speed_control_frame = tk.Frame(row1, bg="#252538")
        speed_control_frame.pack(side=tk.RIGHT)

        speed_tag = tk.Label(
            speed_control_frame,
            text="تحديد السرعة:",
            font=("Segoe UI", 8),
            bg="#252538",
            fg="#fab387",
        )
        speed_tag.pack(side=tk.LEFT, padx=4)

        limit_val_label = tk.Label(
            speed_control_frame,
            text="غير محدود",
            font=("Segoe UI", 8, "bold"),
            bg="#252538",
            fg="#a6e3a1",
            width=12,
        )
        limit_val_label.pack(side=tk.RIGHT, padx=4)
        task.ui_limit_label = limit_val_label

        def on_speed_change(val):
            v = float(val)
            task.speed_limit_kbps.set(v)
            if v <= 0:
                limit_val_label.config(text="غير محدود", fg="#a6e3a1")
            elif v < 1024:
                limit_val_label.config(text=f"{int(v)} KB/s", fg="#fab387")
            else:
                limit_val_label.config(
                    text=f"{v/1024:.1f} MB/s", fg="#89b4fa"
                )

        slider = tk.Scale(
            speed_control_frame,
            from_=0,
            to=10240,
            resolution=128,
            orient=tk.HORIZONTAL,
            showvalue=False,
            command=on_speed_change,
            bg="#252538",
            fg="#cdd6f4",
            troughcolor="#181825",
            highlightthickness=0,
            length=140,
            sliderrelief=tk.FLAT,
        )
        slider.set(0)
        slider.pack(side=tk.RIGHT, padx=6)

        # الصف الثاني: شريط التقدم
        row2 = tk.Frame(card, bg="#252538")
        row2.pack(fill=tk.X, pady=(8, 4))

        progress_bar = ttk.Progressbar(
            row2, orient=tk.HORIZONTAL, mode="determinate"
        )
        progress_bar.pack(fill=tk.X)
        task.ui_progress_bar = progress_bar

        # الصف الثالث: تفاصيل الحالة والسرعة الحالية
        row3 = tk.Frame(card, bg="#252538")
        row3.pack(fill=tk.X, pady=(2, 0))

        status_lbl = tk.Label(
            row3,
            text=f"الحالة: {task.status}",
            font=("Segoe UI", 8),
            bg="#252538",
            fg="#a6adc8",
        )
        status_lbl.pack(side=tk.LEFT)
        task.ui_status_label = status_lbl

        speed_lbl = tk.Label(
            row3,
            text=f"معدل النقل: {task.current_speed}",
            font=("Segoe UI", 8, "bold"),
            bg="#252538",
            fg="#89b4fa",
        )
        speed_lbl.pack(side=tk.RIGHT)
        task.ui_speed_label = speed_lbl

    def _update_task_ui(self, task: FileTransferTask):
        def update():
            if task.ui_progress_bar:
                task.ui_progress_bar["value"] = task.progress_percent
            if task.ui_status_label:
                task.ui_status_label.config(text=f"الحالة: {task.status}")
                if task.is_verified:
                    task.ui_status_label.config(fg="#a6e3a1")
                elif "خطأ" in task.status:
                    task.ui_status_label.config(fg="#f38ba8")
            if task.ui_speed_label:
                task.ui_speed_label.config(
                    text=f"معدل النقل: {task.current_speed} ({task.progress_percent:.1f}%)"
                )

        self.root.after(0, update)

    def _start_all_transfers(self):
        pending = [t for t in self.tasks if not t.is_running and not t.is_verified]
        if not pending:
            messagebox.showinfo(
                "تنبيه", "لا توجد ملفات جديدة في الانتظار لبدء معالجتها."
            )
            return

        for task in pending:
            worker = threading.Thread(
                target=ChunkTransferEngine.process_task,
                args=(task, self._update_task_ui, self._log),
                daemon=True,
            )
            worker.start()

    def _cancel_all(self):
        for task in self.tasks:
            if task.is_running:
                task.is_cancelled = True
        self._log("تم إرسال إشارة إلغاء لجميع المهام الجارية.", "WARN")


if __name__ == "__main__":
    root = tk.Tk()
    # تخصيص سمة شريط التقدم ttk
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(
        "Horizontal.TProgressbar",
        background="#89b4fa",
        troughcolor="#181825",
        bordercolor="#252538",
        lightcolor="#89b4fa",
        darkcolor="#89b4fa",
    )

    app = FramelessApp(root)
    root.mainloop()
