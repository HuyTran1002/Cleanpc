"""
app.py - Web Server & REST API for CleanPC Master
Runs a lightweight, multi-threaded HTTP server using Python's standard library.
Provides responsive JSON APIs for scanning junk, duplicates, large files, and TRIM optimization.
"""

import os
import sys
import json
import time
import socket
import threading
import urllib.parse
import webbrowser
import subprocess
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import cleaner_core

PORT = 8899
HOST = "127.0.0.1"
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for high responsiveness."""
    daemon_threads = True
    allow_reuse_address = True

class CleanPCHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        """Suppress default verbose logging for clean console output."""
        pass

    def _send_json(self, data: dict, status_code: int = 200):
        """Helper to send JSON response with UTF-8 encoding."""
        try:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            pass

    def do_OPTIONS(self):
        """Handle pre-flight CORS requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _read_json_body(self) -> dict:
        """Parse incoming JSON payload from POST request."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                raw_data = self.rfile.read(content_length).decode('utf-8')
                return json.loads(raw_data)
        except Exception as e:
            print(f"[Error reading JSON body]: {e}")
        return {}

    def do_GET(self):
        """Route GET requests."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # REST APIs
        if path == "/api/system/overview":
            data = cleaner_core.get_system_overview()
            self._send_json(data)
        elif path == "/api/memory/status":
            self._send_json(cleaner_core.get_memory_status())
        elif path == "/api/memory/daemon_config":
            self._send_json(cleaner_core.memory_daemon.get_config())
        elif path == "/api/autostart":
            self._send_json({"enabled": cleaner_core.get_autostart_status()})
        elif path == "/api/settings":
            self._send_json(cleaner_core.load_settings())
        elif path == "/api/disks/smart":
            self._send_json({"disks": cleaner_core.get_disks_health_smart()})
        elif path == "/api/junk/categories":
            self._send_json({"categories": cleaner_core.JUNK_CATEGORIES})
        elif path == "/api/duplicates/status":
            self._send_json(cleaner_core.duplicate_scanner.get_status())
        elif path == "/api/duplicates/results":
            self._send_json({"groups": cleaner_core.duplicate_scanner.get_results()})
        elif path.startswith("/api/"):
            self._send_json({"error": "Endpoint not found"}, 404)
        else:
            # Static files handler (serves index.html, logo.png, favicon.ico, styles.css, app.js, etc.)
            clean_path = path.lstrip("/")
            if not clean_path or clean_path == "index.html":
                clean_path = "index.html"

            # Strip query params and hashes
            clean_path = clean_path.split("?")[0].split("#")[0]
            safe_path = os.path.normpath(os.path.join(WEB_DIR, clean_path))

            # Security check: ensure path is inside WEB_DIR and exists
            if safe_path.startswith(os.path.abspath(WEB_DIR)) and os.path.isfile(safe_path):
                import mimetypes
                content_type, _ = mimetypes.guess_type(safe_path)
                if not content_type:
                    if safe_path.endswith('.ico'):
                        content_type = 'image/x-icon'
                    else:
                        content_type = 'application/octet-stream'
                elif content_type.startswith('text/') or content_type == 'application/javascript':
                    content_type += '; charset=utf-8'

                try:
                    with open(safe_path, 'rb') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', content_type)
                    self.send_header('Content-Length', str(len(content)))
                    self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(content)
                    self.wfile.flush()
                    return
                except Exception as e:
                    self._send_json({"error": f"Failed reading file: {str(e)}"}, 500)
                    return

            self._send_json({"error": "Resource not found"}, 404)

    def do_POST(self):
        """Route POST requests."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        body = self._read_json_body()

        # 0. Real-Time Memory Operations (Mem Reduct Engine)
        if path == "/api/memory/clean":
            purge_standby = body.get("purge_standby", True)
            empty_working_sets = body.get("empty_working_sets", True)
            flush_modified = body.get("flush_modified", True)
            skip_foreground = body.get("skip_foreground", True)
            res = cleaner_core.clean_memory(
                purge_standby=purge_standby,
                empty_working_sets=empty_working_sets,
                flush_modified=flush_modified,
                skip_foreground=skip_foreground
            )
            self._send_json(res)

        elif path == "/api/memory/daemon_config":
            cfg = cleaner_core.memory_daemon.update_config(
                enabled=body.get("enabled"),
                threshold_pct=body.get("threshold_pct"),
                cooldown_sec=body.get("cooldown_sec"),
                pause_in_game=body.get("pause_in_game"),
                purge_standby=body.get("purge_standby"),
                empty_working_sets=body.get("empty_working_sets"),
                flush_modified=body.get("flush_modified"),
                skip_foreground=body.get("skip_foreground")
            )
            self._send_json({"success": True, "config": cfg})

        elif path == "/api/autostart":
            enabled = body.get("enabled", False)
            status = cleaner_core.set_autostart(enabled)
            self._send_json({"success": True, "enabled": status})

        elif path == "/api/settings":
            cleaner_core.save_settings(body)
            self._send_json({"success": True, "settings": cleaner_core.load_settings()})

        # 1. Junk Operations
        elif path == "/api/junk/scan":
            results = cleaner_core.scan_all_junk_categories()
            self._send_json(results)

        elif path == "/api/junk/clean":
            category_ids = body.get("category_ids", [])
            use_recycle_bin = body.get("use_recycle_bin", False)
            
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
                
            self._send_json({
                "success": True,
                "total_freed_bytes": total_freed,
                "total_freed_formatted": cleaner_core.format_bytes(total_freed),
                "total_deleted_files": total_files,
                "total_locked_bytes": total_locked,
                "total_locked_formatted": cleaner_core.format_bytes(total_locked),
                "all_locked_hints": all_locked_hints,
                "details": clean_results
            })

        elif path == "/api/junk/close_temp_lockers":
            res = cleaner_core.close_temp_blocking_processes()
            self._send_json(res)

        # 2. Recycle Bin Operations
        elif path == "/api/recycle_bin/empty":
            drive = body.get("drive") # e.g. 'C:\\' or None for all
            if drive:
                stripped = drive.rstrip(':\\/')
                drive = stripped + ':\\'
            success = cleaner_core.empty_recycle_bin(drive)
            self._send_json({"success": success})

        # 3. Duplicate Files Operations
        elif path == "/api/duplicates/start":
            targets = body.get("targets", [])
            if isinstance(targets, str):
                targets = [t.strip() for t in targets.replace(';', ',').split(',') if t.strip()]
            min_size_mb = float(body.get("min_size_mb", 1))
            min_size_bytes = int(min_size_mb * 1024 * 1024)
            file_types = body.get("file_types", None) # list of extensions or None
            
            # Default to both drives if none specified
            if not targets:
                targets = ["C:\\", "D:\\"]
                
            ok = cleaner_core.duplicate_scanner.start_scan(targets, min_size_bytes, file_types)
            self._send_json({"started": ok, "success": ok})

        elif path == "/api/duplicates/cancel":
            cleaner_core.duplicate_scanner.cancel()
            self._send_json({"cancelled": True})

        elif path == "/api/duplicates/delete":
            paths = body.get("paths", [])
            use_recycle_bin = body.get("use_recycle_bin", True)
            res = cleaner_core.delete_files(paths, use_recycle_bin)
            self._send_json(res)

        # 4. Large Files Operations
        elif path == "/api/large_files/scan":
            target_dir = body.get("target_dir", "C:\\")
            min_size_mb = float(body.get("min_size_mb", 100))
            min_size_bytes = int(min_size_mb * 1024 * 1024)
            limit = int(body.get("limit", 100))
            
            res = cleaner_core.scan_large_files(target_dir, min_size_bytes, limit)
            self._send_json(res)

        elif path == "/api/large_files/delete":
            paths = body.get("paths", [])
            use_recycle_bin = body.get("use_recycle_bin", True)
            
            deleted = 0
            freed = 0
            for p in paths:
                if os.path.exists(p):
                    try:
                        sz = os.path.getsize(p)
                        if use_recycle_bin:
                            ok = cleaner_core.send_to_recycle_bin(p)
                        else:
                            ok = cleaner_core.permanent_delete(p)
                        if ok:
                            deleted += 1
                            freed += sz
                    except Exception:
                        pass
            self._send_json({
                "success": True,
                "deleted_count": deleted,
                "freed_bytes": freed,
                "freed_formatted": cleaner_core.format_bytes(freed)
            })

        # 5. Drive Optimization
        elif path == "/api/optimize/trim":
            drive = body.get("drive", "C")
            res = cleaner_core.optimize_drive_trim(drive)
            self._send_json(res)

        # 6. Windows Explorer Highlight & Folder Picker
        elif path == "/api/system/open_explorer":
            target_path = body.get("path", "")
            ok = cleaner_core.open_in_explorer(target_path)
            self._send_json({"success": ok})

        elif path == "/api/system/choose_folder":
            folder = ""
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                root.attributes('-topmost', True)
                folder = filedialog.askdirectory()
                root.destroy()
            except Exception:
                pass
            self._send_json({"path": folder, "success": bool(folder)})

        # 7. Restart as Administrator
        elif path == "/api/system/restart_admin":
            try:
                import ctypes
                run_py_path = os.path.join(BASE_DIR, "run.py")
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    f'"{run_py_path}"',
                    BASE_DIR,
                    1
                )
                self._send_json({"success": True, "message": "Đang khởi động lại CleanPC với quyền Administrator..."})
                threading.Thread(target=lambda: (time.sleep(1.0), os._exit(0))).start()
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        # 8. Server Shutdown & Window Control
        elif path == "/api/app/minimize":
            try:
                import webview
                if webview.windows:
                    webview.windows[0].hide()
            except Exception:
                pass
            self._send_json({"success": True, "message": "Đã thu nhỏ xuống khay hệ thống"})

        elif path == "/api/app/exit" or path == "/api/system/shutdown":
            self._send_json({"success": True, "message": "Đang dừng CleanPC Master..."})
            import threading
            threading.Thread(target=lambda: (time.sleep(0.5), os._exit(0))).start()

        else:
            self._send_json({"error": "Endpoint not found"}, 404)

def run_server(port: int = PORT, open_browser: bool = True):
    """Start HTTP server and launch browser."""
    # Ensure web directory exists
    os.makedirs(WEB_DIR, exist_ok=True)
    
    httpd = None
    for attempt in range(10):
        server_address = (HOST, port)
        try:
            httpd = ThreadedHTTPServer(server_address, CleanPCHandler)
            break
        except (OSError, PermissionError) as e:
            err_msg = str(e).lower()
            err_args = getattr(e, 'args', ())
            if "already in use" in err_msg or 10048 in err_args or 10013 in err_args or "forbidden" in err_msg:
                port += 1
            else:
                raise

    if not httpd:
        raise RuntimeError(f"Không thể mở cổng mạng trong dải {PORT}-{port}")

    url = f"http://{HOST}:{port}"
    print("=" * 65)
    print(f"🚀 CleanPC Master Server đang hoạt động tại: {url}")
    print(f"🔒 Chế độ quyền: {'Administrator (Toàn quyền tối ưu TRIM)' if cleaner_core.is_admin() else 'Người dùng thông thường (Standard)'}")
    print("=" * 65)

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[CleanPC Master] Máy chủ đã dừng.")
        httpd.server_close()

if __name__ == "__main__":
    port = PORT
    open_browser = True
    if "--no-browser" in sys.argv:
        open_browser = False
    if "--port" in sys.argv:
        try:
            idx = sys.argv.index("--port")
            port = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass
    run_server(port=port, open_browser=open_browser)
