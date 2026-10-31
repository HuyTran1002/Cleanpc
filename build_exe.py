"""
build_exe.py - Automated Single-File EXE Builder for CleanPC Master
Builds a standalone, single-file executable with embedded assets, WebView2 GUI,
Windows UAC elevation, and zero external dependencies.
"""

import os
import sys
import shutil
import subprocess

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def build():
    print("=" * 65)
    print("🚀 Bắt đầu quá trình đóng gói CleanPC Master thành 1 file .EXE duy nhất")
    print("=" * 65)

    os.chdir(BASE_DIR)

    target_name = "CleanPC_Master"
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000

    # 1. Close any running instances so the target exe is unlocked
    print("🔍 Đang kiểm tra và đóng các tiến trình CleanPC Master đang chạy...")
    for proc_pattern in ["CleanPC_Master.exe", "CleanPC_Master_v1.1.exe", "CleanPC_Master_v1.2.exe"]:
        subprocess.run(f'taskkill /F /IM "{proc_pattern}" /T', shell=True, capture_output=True, creationflags=flags)

    import time
    time.sleep(1.0)

    # 2. Clean up obsolete versioned exes and spec files
    for old_file in ["CleanPC_Master_v1.1.spec", "CleanPC_Master_v1.2.spec"]:
        p = os.path.join(BASE_DIR, old_file)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    for old_exe in ["CleanPC_Master_v1.1.exe", "CleanPC_Master_v1.2.exe"]:
        p = os.path.join(BASE_DIR, "dist", old_exe)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    spec_file = f"{target_name}.spec"
    if os.path.exists(spec_file):
        try:
            os.remove(spec_file)
        except Exception:
            pass

    icon_path = os.path.join(BASE_DIR, "app.ico")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", target_name,
        "--onefile",
        "--noconsole",
        "--uac-admin",
        f"--icon={icon_path}",
        "--add-data", f"web{os.pathsep}web",
        "--add-data", f"app.ico{os.pathsep}.",
        "--hidden-import", "clr_loader",
        "--hidden-import", "pythonnet",
        "--hidden-import", "bottle",
        "--hidden-import", "webview",
        "--hidden-import", "cleaner_core",
        "--hidden-import", "app",
        "--hidden-import", "pystray",
        "--hidden-import", "pystray._win32",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL.Image",
        "--hidden-import", "PIL.ImageDraw",
        "--hidden-import", "PIL.ImageFont",
        "--hidden-import", "six",
        "--clean",
        "desktop.py"
    ]

    print("\n📦 Đang thực thi lệnh đóng gói PyInstaller...")
    print(" ".join(cmd))
    print("-" * 65)

    res = subprocess.run(cmd)

    if res.returncode == 0:
        exe_path = os.path.join(BASE_DIR, "dist", f"{target_name}.exe")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print("=" * 65)
            print("🎉 ĐÓNG GÓI THÀNH CÔNG RỰC RỠ!")
            print(f"📁 Tệp thực thi chuẩn: {exe_path}")
            print(f"📊 Dung lượng tệp: {size_mb:.2f} MB (Hoàn toàn Portable - 1 File duy nhất)")
            print("🔒 Tự động yêu cầu quyền Administrator khi mở (để mở khóa toàn quyền S.M.A.R.T, TRIM & Mem Reduct)")

            # Auto sync startup paths
            try:
                import cleaner_core
                cleaner_core.sync_autostart_target()
                print("🔄 Đã đồng bộ đường dẫn khởi động cùng Windows sang CleanPC_Master.exe mới nhất!")
            except Exception as e:
                print(f"⚠️ Lưu ý về autostart: {e}")

            print("=" * 65)
            return True

    print("\n❌ Có lỗi xảy ra trong quá trình đóng gói. Vui lòng kiểm tra log bên trên.")
    return False

if __name__ == "__main__":
    success = build()
    sys.exit(0 if success else 1)
