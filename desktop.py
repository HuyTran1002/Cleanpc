"""
desktop.py - CleanPC Master Native Desktop Application
Runs CleanPC Master in a sleek native Windows desktop window using WebView2.
Provides direct in-memory Python APIs for lightning-fast scanning and zero network latency.
Includes native Windows System Tray with real-time RAM usage percentage display & instant clean.
"""

import os
import sys
import time
import ctypes
from ctypes import wintypes
import threading
from PIL import Image, ImageDraw, ImageFont
import pystray
from pystray import MenuItem as item
import webview
import cleaner_core
import app

# Ensure current directory and frozen assets are resolved correctly
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

# Global references for Tray and Window control
main_window = None
tray_icon = None
force_quit_flag = [False]
notified_hide_flag = [False]
last_tray_pct = [-1]

def make_dynamic_ram_icon(pct: int):
    """
    Generate dynamic 64x64 RGBA icon displaying real-time RAM percentage.
    Color coded: Green (<60%), Amber (60-80%), Red (>=80%).
    Optimized for perfect centering and large, high-contrast visibility on Windows Taskbar.
    """
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pct = max(1, min(99, int(pct)))

    if pct < 60:
        bg_color = (16, 185, 129, 255)      # Cool Emerald Green
        border_color = (52, 211, 153, 255)
    elif pct < 80:
        bg_color = (245, 158, 11, 255)     # Amber Orange
        border_color = (251, 191, 36, 255)
    else:
        bg_color = (239, 68, 68, 255)      # Crimson Red
        border_color = (248, 113, 113, 255)

    # Draw rounded badge with crisp outline
    draw.rounded_rectangle([1, 1, 62, 62], radius=13, fill=bg_color, outline=border_color, width=2)

    # Font selection: Size 44 bold font for high visibility in system tray
    font = None
    for name in ["segoeuib.ttf", "arialbd.ttf", "tahomabd.ttf"]:
        try:
            font = ImageFont.truetype(name, 44)
            break
        except Exception:
            pass
    if not font:
        font = ImageFont.load_default()

    text = str(pct)
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        ink_w = bbox[2] - bbox[0]
        ink_h = bbox[3] - bbox[1]
        # True ink bounding box centering: subtract font glyph bearing offsets
        x = (64.0 - ink_w) / 2.0 - bbox[0]
        y = (64.0 - ink_h) / 2.0 - bbox[1]
    except Exception:
        x, y = 14, 12

    # Drop shadow for readability against any Windows accent/theme
    draw.text((x + 1, y + 1), text, font=font, fill=(0, 0, 0, 180))
    # Crisp white text
    draw.text((x, y), text, font=font, fill=(255, 255, 255, 255))
    return img

def get_window_hwnd():
    """Retrieve the Windows HWND handle safely without type error."""
    global main_window
    if not main_window:
        return None
    try:
        native = getattr(main_window, 'native', None)
        if native and hasattr(native, 'Handle'):
            h = native.Handle
            if hasattr(h, 'ToInt64'):
                return int(h.ToInt64())
            elif hasattr(h, 'ToInt32'):
                return int(h.ToInt32())
            return int(str(h))
    except Exception:
        pass
    try:
        title = getattr(main_window, 'title', '')
        if title:
            hwnd = ctypes.windll.user32.FindWindowW(None, title)
            if hwnd:
                return hwnd
    except Exception:
        pass
    return None

def ensure_window_in_bounds(hwnd):
    """Ensure the window never sits shifted downwards, off-screen, or hidden behind taskbar."""
    try:
        user32 = ctypes.windll.user32
        class RECT(ctypes.Structure):
            _fields_ = [('left', wintypes.LONG), ('top', wintypes.LONG),
                        ('right', wintypes.LONG), ('bottom', wintypes.LONG)]
        wrect = RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(wrect))
        srect = RECT()
        user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(srect), 0)

        cur_w = wrect.right - wrect.left
        cur_h = wrect.bottom - wrect.top
        work_w = srect.right - srect.left
        work_h = srect.bottom - srect.top

        # Check if window is positioned outside comfortable bounds or shifted below taskbar
        is_outside = (
            wrect.top < srect.top or
            wrect.top > (srect.bottom - 120) or
            wrect.left < (srect.left - 40) or
            wrect.left > (srect.right - 100) or
            (wrect.bottom > srect.bottom and cur_h <= work_h)
        )
        if is_outside:
            target_x = srect.left + max(0, (work_w - cur_w) // 2)
            target_y = srect.top + max(0, (work_h - cur_h) // 2)
            # SWP_NOZORDER (0x0004) | SWP_SHOWWINDOW (0x0040)
            user32.SetWindowPos(hwnd, 0, target_x, target_y, cur_w, cur_h, 0x0044)
    except Exception:
        pass

def show_main_window(icon=None, item=None):
    """Restore and bring main window to the foreground, perfectly centered."""
    global main_window
    try:
        if main_window:
            try:
                main_window.show()
            except Exception:
                pass

            hwnd = get_window_hwnd()
            if hwnd:
                user32 = ctypes.windll.user32
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.ShowWindow(hwnd, 5)  # SW_SHOW
                ensure_window_in_bounds(hwnd)
                user32.SetForegroundWindow(hwnd)
    except Exception as e:
        print(f"[show_main_window error]: {e}")

def hide_main_window(icon=None, item=None):
    """Minimize main window to tray and trim working set to release idle memory."""
    global main_window
    try:
        hwnd = get_window_hwnd()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        elif main_window:
            main_window.hide()

        # Aggressively trim process working set on hide to minimize background RAM footprint
        try:
            h_proc = cleaner_core._kernel32.GetCurrentProcess()
            if cleaner_core._K32EmptyWorkingSet:
                cleaner_core._K32EmptyWorkingSet(h_proc)
        except Exception:
            pass
    except Exception as e:
        print(f"[hide_main_window error]: {e}")

def tray_clean_memory_now(icon=None, item=None):
    """Trigger background memory purge directly from Tray without opening UI."""
    try:
        res = cleaner_core.clean_memory(
            purge_standby=True,
            empty_working_sets=True,
            flush_modified=True,
            skip_foreground=True
        )
        freed_mb = res.get("freed_mb", 0)
        after_pct = res.get("after", {}).get("used_percent") or res.get("after", {}).get("usage_pct", 0)
        if tray_icon:
            tray_icon.notify(
                f"Đã giải phóng thành công {freed_mb:.1f} MB RAM!\nMức sử dụng hiện tại: {after_pct}%",
                "CleanPC Master - Dọn RAM Thành Công"
            )
        # Force refresh tray icon badge
        last_tray_pct[0] = -1
    except Exception as e:
        print(f"[tray_clean_memory_now error]: {e}")

def force_quit_application(icon=None, item=None):
    """Completely exit the application."""
    global tray_icon, main_window
    force_quit_flag[0] = True
    if tray_icon:
        try:
            tray_icon.stop()
        except Exception:
            pass
    try:
        if main_window:
            main_window.destroy()
    except Exception:
        pass
    threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0)), daemon=True).start()

def tray_monitor_loop():
    """Background daemon thread updating RAM percentage on the Tray icon every 2.5s."""
    global tray_icon
    while not force_quit_flag[0]:
        try:
            if tray_icon:
                mem = cleaner_core.get_memory_status()
                pct = int(mem.get("used_percent") or mem.get("usage_pct") or 0)
                used_gb = mem.get("used_gb") or round(mem.get("used_bytes", 0) / (1024**3), 1)
                total_gb = mem.get("total_gb") or round(mem.get("total_bytes", 0) / (1024**3), 1)

                if pct != last_tray_pct[0]:
                    new_img = make_dynamic_ram_icon(pct)
                    tray_icon.icon = new_img
                    tray_icon.title = (
                        f"CleanPC Master - RAM: {pct}% ({used_gb:.1f}/{total_gb:.1f} GB)\n"
                        f"Bấm đúp để mở | Chuột phải để dọn nhanh"
                    )
                    last_tray_pct[0] = pct
        except Exception:
            pass
        time.sleep(2.5)

def toggle_tray_autostart(icon=None, item=None):
    """Toggle autostart with Windows from the System Tray menu."""
    try:
        cur = cleaner_core.get_autostart_status()
        new_state = not cur
        cleaner_core.set_autostart(new_state)
        if tray_icon:
            msg = "Đã bật: Tự khởi động ngầm trong khay hệ thống khi mở máy." if new_state else "Đã tắt khởi động cùng Windows."
            tray_icon.notify(msg, "CleanPC Master - Khởi Động Cùng Windows")
    except Exception as e:
        print(f"[toggle_tray_autostart error]: {e}")

def setup_tray():
    """Initialize and run system tray in detached mode."""
    global tray_icon
    initial_mem = cleaner_core.get_memory_status()
    initial_pct = int(initial_mem.get("used_percent") or initial_mem.get("usage_pct") or 50)
    initial_used_gb = initial_mem.get("used_gb") or round(initial_mem.get("used_bytes", 0) / (1024**3), 1)
    initial_total_gb = initial_mem.get("total_gb") or round(initial_mem.get("total_bytes", 0) / (1024**3), 1)
    initial_icon = make_dynamic_ram_icon(initial_pct)
    last_tray_pct[0] = initial_pct

    menu = pystray.Menu(
        item('Mở CleanPC Master', show_main_window, default=True),
        item('⚡ Dọn RAM ngay (Mem Reduct)', tray_clean_memory_now),
        pystray.Menu.SEPARATOR,
        item('Khởi chạy cùng Windows', toggle_tray_autostart, checked=lambda item: cleaner_core.get_autostart_status()),
        item('Thu nhỏ vào khay', hide_main_window),
        pystray.Menu.SEPARATOR,
        item('❌ Thoát hoàn toàn', force_quit_application)
    )

    tray_icon = pystray.Icon(
        "CleanPC_Master",
        initial_icon,
        f"CleanPC Master - RAM: {initial_pct}% ({initial_used_gb:.1f}/{initial_total_gb:.1f} GB)\nBấm đúp để mở | Chuột phải để dọn nhanh",
        menu
    )
    tray_icon.run_detached()

    # Start monitor thread
    monitor_thread = threading.Thread(target=tray_monitor_loop, daemon=True)
    monitor_thread.start()


class CleanPCApi:
    """Native Python API exposed directly to the Desktop frontend."""

    def minimize_to_tray(self):
        """Minimize window to tray from Javascript."""
        hide_main_window()
        return {"success": True}

    def exit_app(self):
        """Completely exit application from Javascript."""
        force_quit_application()
        return {"success": True}

    def get_memory_status(self):
        try:
            return cleaner_core.get_memory_status()
        except Exception as e:
            return {"error": str(e)}

    def clean_memory(self, purge_standby=True, empty_working_sets=True, flush_modified=True, skip_foreground=True):
        try:
            res = cleaner_core.clean_memory(
                purge_standby=purge_standby,
                empty_working_sets=empty_working_sets,
                flush_modified=flush_modified,
                skip_foreground=skip_foreground
            )
            # Trigger immediate update of tray icon
            last_tray_pct[0] = -1
            return res
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_memory_daemon_config(self):
        try:
            return cleaner_core.memory_daemon.get_config()
        except Exception as e:
            return {"error": str(e)}

    def set_memory_daemon_config(self, enabled=None, threshold_pct=None, cooldown_sec=None, pause_in_game=None,
                                 purge_standby=None, empty_working_sets=None, flush_modified=None, skip_foreground=None):
        try:
            cfg = cleaner_core.memory_daemon.update_config(
                enabled=enabled,
                threshold_pct=threshold_pct,
                cooldown_sec=cooldown_sec,
                pause_in_game=pause_in_game,
                purge_standby=purge_standby,
                empty_working_sets=empty_working_sets,
                flush_modified=flush_modified,
                skip_foreground=skip_foreground
            )
            return {"success": True, "config": cfg}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_autostart_status(self):
        try:
            return {"enabled": cleaner_core.get_autostart_status()}
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def set_autostart(self, enabled):
        try:
            status = cleaner_core.set_autostart(bool(enabled))
            return {"success": True, "enabled": status}
        except Exception as e:
            return {"success": False, "enabled": False, "error": str(e)}

    def get_settings(self):
        try:
            return cleaner_core.load_settings()
        except Exception as e:
            return {"error": str(e)}

    def save_settings(self, settings):
        try:
            if isinstance(settings, dict):
                cleaner_core.save_settings(settings)
                return {"success": True, "settings": cleaner_core.load_settings()}
            return {"success": False, "error": "Invalid settings payload"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_disks_smart(self, force_refresh=False):
        try:
            return {"disks": cleaner_core.get_disks_health_smart(force_refresh=force_refresh)}
        except Exception as e:
            return {"disks": [], "error": str(e)}

    def get_system_overview(self):
        try:
            return cleaner_core.get_system_overview()
        except Exception as e:
            return {"error": str(e), "admin": cleaner_core.is_admin(), "drives": []}

    def get_junk_categories(self):
        return {"categories": cleaner_core.JUNK_CATEGORIES}

    def scan_junk(self):
        try:
            return cleaner_core.scan_all_junk_categories()
        except Exception as e:
            return {"categories": [], "total_bytes": 0, "total_formatted": "0 B", "error": str(e)}

    def clean_junk(self, category_ids, use_recycle_bin=False):
        try:
            clean_results = []
            total_freed = 0
            total_files = 0
            total_locked = 0
            all_locked_hints = []
            for cid in category_ids:
                res = cleaner_core.clean_junk_category(cid, use_recycle_bin)
                clean_results.append(res)
                total_freed += res.get("freed_bytes", 0)
                total_files += res.get("deleted_files", 0)
                total_locked += res.get("locked_bytes", 0)
                for h in res.get("locked_hints", []):
                    if h not in all_locked_hints:
                        all_locked_hints.append(h)
            return {
                "success": True,
                "total_freed_bytes": total_freed,
                "total_freed_formatted": cleaner_core.format_bytes(total_freed),
                "total_deleted_files": total_files,
                "total_locked_bytes": total_locked,
                "total_locked_formatted": cleaner_core.format_bytes(total_locked),
                "all_locked_hints": all_locked_hints,
                "details": clean_results
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def close_temp_blocking_processes(self):
        try:
            return cleaner_core.close_temp_blocking_processes()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def empty_recycle_bin(self, drive=None):
        try:
            if drive:
                drive = drive.rstrip(':\\/') + ':\\'
            success = cleaner_core.empty_recycle_bin(drive)
            return {"success": success}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_duplicate_scan(self, targets=None, min_size_mb=1.0, file_types=None):
        try:
            if isinstance(targets, str):
                targets = [t.strip() for t in targets.replace(';', ',').split(',') if t.strip()]
            if not targets:
                targets = ["C:\\", "D:\\"]
            min_size_bytes = int(float(min_size_mb) * 1024 * 1024)
            started = cleaner_core.duplicate_scanner.start_scan(targets, min_size_bytes, file_types)
            return {"success": started, "started": started}
        except Exception as e:
            return {"success": False, "started": False, "error": str(e)}

    def get_duplicate_status(self):
        return cleaner_core.duplicate_scanner.get_status()

    def get_duplicate_results(self):
        return {"groups": cleaner_core.duplicate_scanner.get_results()}

    def cancel_duplicate_scan(self):
        cleaner_core.duplicate_scanner.cancel()
        return {"success": True}

    def delete_duplicates(self, paths, use_recycle_bin=False):
        try:
            return cleaner_core.delete_files(paths, use_recycle_bin)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def scan_large_files(self, target_dir="C:\\", min_size_mb=100.0, limit=100):
        try:
            min_size_bytes = int(float(min_size_mb) * 1024 * 1024)
            return cleaner_core.scan_large_files(target_dir, min_size_bytes, int(limit))
        except Exception as e:
            return {"files": [], "total_formatted": "0 B", "error": str(e)}

    def optimize_trim(self, drive="C"):
        try:
            return cleaner_core.optimize_drive_trim(drive)
        except Exception as e:
            return {"success": False, "message": str(e)}

    def open_explorer(self, path):
        try:
            return {"success": cleaner_core.open_in_explorer(path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def choose_folder(self):
        """Open native Windows folder picker dialog."""
        try:
            if webview.windows:
                res = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
                if res and len(res) > 0:
                    return {"path": res[0], "success": True}
        except Exception as e:
            print(f"[choose_folder error]: {e}")
        return {"path": "", "success": False}

    def restart_admin(self):
        """Elevate process using native Windows ShellExecuteW."""
        try:
            script_path = os.path.abspath(__file__)
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script_path}"',
                BASE_DIR,
                1
            )
            threading.Thread(target=lambda: (time.sleep(1.0), os._exit(0)), daemon=True).start()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def start_embedded_server(port=8899):
    """Start local Threaded HTTP server in background daemon thread."""
    try:
        import run
        run.free_port(port)
    except Exception:
        pass

    try:
        httpd = app.ThreadedHTTPServer((app.HOST, port), app.CleanPCHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return port
    except Exception as e:
        print(f"[Warning] Failed to start embedded server on port {port}: {e}")
        try:
            httpd = app.ThreadedHTTPServer((app.HOST, 0), app.CleanPCHandler)
            assigned_port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            return assigned_port
        except Exception:
            return None

def get_optimal_window_geometry():
    """
    Calculate centered window geometry matching the user's active monitor work area.
    Ensures the window opens directly centered, doesn't overflow the taskbar,
    and is neither oversized nor shifted downwards.
    """
    try:
        class RECT(ctypes.Structure):
            _fields_ = [('left', wintypes.LONG), ('top', wintypes.LONG),
                        ('right', wintypes.LONG), ('bottom', wintypes.LONG)]
        rect = RECT()
        ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)
        work_w = rect.right - rect.left
        work_h = rect.bottom - rect.top
        left = rect.left
        top = rect.top
    except Exception:
        work_w, work_h = 1366, 768
        left, top = 0, 0

    # Default balanced dimensions for modern displays with DPI scaling (e.g. 1536x864, 1920x1080)
    target_w = 1100
    target_h = 700

    win_w = min(target_w, int(work_w * 0.90))
    win_h = min(target_h, int(work_h * 0.86))

    win_w = max(900, win_w)
    win_h = max(580, win_h)

    pos_x = left + max(0, (work_w - win_w) // 2)
    pos_y = top + max(0, (work_h - win_h) // 2)

    return win_w, win_h, pos_x, pos_y

_single_instance_mutex = None

def acquire_single_instance():
    """
    Ensure only one instance of CleanPC Master runs at a time using a Windows Named Mutex.
    If another instance is already running:
    - If launched with --tray or --minimized, exit silently.
    - If launched normally, find and restore the existing window to the foreground, then exit.
    """
    global _single_instance_mutex
    try:
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        mutex_name = "Global\\CleanPCMaster_App_SingleInstance_Mutex"
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        ERROR_ALREADY_EXISTS = 183
        if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            if handle:
                kernel32.CloseHandle(handle)

            # Another instance is already running!
            if "--tray" in sys.argv or "--minimized" in sys.argv:
                sys.exit(0)

            # Bring existing window to foreground
            target_titles = [
                "CleanPC Master - Tối Ưu & Dọn Dẹp Máy Tính [Administrator]",
                "CleanPC Master - Tối Ưu & Dọn Dẹp Máy Tính"
            ]
            for t in target_titles:
                hwnd = user32.FindWindowW(None, t)
                if hwnd:
                    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                    user32.SetForegroundWindow(hwnd)
                    sys.exit(0)
            sys.exit(0)

        _single_instance_mutex = handle
        return True
    except Exception as e:
        print(f"[SingleInstance Warning]: {e}")
        return True

def main():
    global main_window

    # 1. Enforce single instance across the system
    acquire_single_instance()

    # 2. Self-heal autostart configuration to match active executable
    try:
        cleaner_core.sync_autostart_target()
    except Exception:
        pass

    # If launched with --admin and not yet elevated, prompt UAC natively
    if "--admin" in sys.argv and not is_admin():
        script_path = os.path.abspath(__file__)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script_path}"',
            BASE_DIR,
            1
        )
        if ret > 32:
            sys.exit(0)

    # Setup System Tray with dynamic RAM icon
    setup_tray()

    # Start embedded HTTP server
    port = start_embedded_server(8899)
    if port:
        target_url = f"http://127.0.0.1:{port}"
    else:
        target_url = os.path.join(BASE_DIR, "web", "index.html")

    api = CleanPCApi()
    admin_title = " [Administrator]" if is_admin() else ""
    app_icon_path = os.path.join(BASE_DIR, "app.ico")
    is_tray_mode = "--tray" in sys.argv or "--minimized" in sys.argv

    # Calculate centered, taskbar-aware optimal window position
    win_w, win_h, pos_x, pos_y = get_optimal_window_geometry()

    main_window = webview.create_window(
        title=f"CleanPC Master - Tối Ưu & Dọn Dẹp Máy Tính{admin_title}",
        url=target_url,
        js_api=api,
        width=win_w,
        height=win_h,
        x=pos_x,
        y=pos_y,
        min_size=(900, 580),
        background_color='#070a13',
        hidden=is_tray_mode
    )

    # Intercept window close event to minimize to system tray instead of exiting!
    def on_window_closing(*args, **kwargs):
        if force_quit_flag[0]:
            return True  # Proceed with window destruction

        try:
            hide_main_window()
            if not notified_hide_flag[0] and tray_icon:
                tray_icon.notify(
                    "CleanPC Master đang tiếp tục chạy ngầm trong khay hệ thống.\nBấm đúp vào biểu tượng RAM để mở lại bất kỳ lúc nào.",
                    "CleanPC Master - Chạy Ngầm"
                )
                notified_hide_flag[0] = True
        except Exception as e:
            print(f"[on_window_closing error]: {e}")

        return False  # CANCEL window close event, keeping app alive in tray!

    main_window.events.closing += on_window_closing

    def on_window_shown(*args, **kwargs):
        if is_tray_mode:
            hide_main_window()
            return
        try:
            hwnd = get_window_hwnd()
            if hwnd:
                ensure_window_in_bounds(hwnd)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass

    main_window.events.shown += on_window_shown

    # Start WebView2 with custom window icon
    webview.start(icon=app_icon_path if os.path.exists(app_icon_path) else None, debug=False)

if __name__ == "__main__":
    main()
