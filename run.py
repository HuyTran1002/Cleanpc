"""
run.py - CleanPC Master Launcher
Default: Launches the native Desktop Application (pywebview).
Pass --web to launch in Web Server mode on port 8899.
"""

import sys
import os
import ctypes
import subprocess

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def free_port(port: int = 8899):
    """Ensure port 8899 is free from any previous orphaned instances."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        output = subprocess.check_output(f'netstat -ano | findstr :{port}', shell=True, text=True, stderr=subprocess.DEVNULL, creationflags=flags)
        current_pid = os.getpid()
        for line in output.strip().splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and "LISTENING" in parts:
                pid = int(parts[-1])
                if pid != current_pid and pid > 4:
                    subprocess.run(f'taskkill /F /PID {pid}', shell=True, capture_output=True, creationflags=flags)
    except Exception:
        pass

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)
    os.chdir(base_dir)

    # Optional --admin flag to elevate natively via Windows ShellExecuteW
    if "--admin" in sys.argv and not is_admin():
        script_path = os.path.abspath(__file__)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script_path}"',
            base_dir,
            1
        )
        if ret > 32:
            sys.exit(0)
        print("[CleanPC Master] Yêu cầu quyền Admin bị từ chối hoặc hủy.")
        print("[CleanPC Master] Tiếp tục khởi chạy ở chế độ Tiêu chuẩn (Standard)...")

    if "--web" in sys.argv:
        free_port(8899)
        from app import run_server
        open_browser = "--no-browser" not in sys.argv
        run_server(port=8899, open_browser=open_browser)
    else:
        import desktop
        desktop.main()
