"""
cleaner_core.py - Core Engine for CleanPC Master
Provides system analysis, junk scanning, multi-stage duplicate detection,
large file discovery, and safe Windows deletion APIs.
"""

import os
import sys
import time
import json
import stat
import shutil
import hashlib
import ctypes
import datetime
import threading
import subprocess
from pathlib import Path
from ctypes import wintypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import glob
import fnmatch

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def run_powershell_hidden(script: str, timeout: int = 8) -> str:
    """Run PowerShell command completely hidden with NO console window flashing."""
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

        res = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=flags,
            startupinfo=startupinfo
        )
        return res.stdout.strip() if res.returncode == 0 else ""
    except Exception:
        return ""

# -----------------------------------------------------------------------------
# Windows API Definitions via ctypes
# -----------------------------------------------------------------------------

class SHFILEOPSTRUCT(ctypes.Structure):
    _fields_ = [
        ('hwnd', wintypes.HWND),
        ('wFunc', wintypes.UINT),
        ('pFrom', wintypes.LPCWSTR),
        ('pTo', wintypes.LPCWSTR),
        ('fFlags', wintypes.WORD),
        ('fAnyOperationsAborted', wintypes.BOOL),
        ('hNameMappings', wintypes.LPVOID),
        ('lpszProgressTitle', wintypes.LPCWSTR)
    ]

class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('i64Size', ctypes.c_int64),
        ('i64NumItems', ctypes.c_int64)
    ]

FO_DELETE = 0x0003
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004

def is_admin() -> bool:
    """Check if current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def format_bytes(bytes_num: int) -> str:
    """Format bytes into readable string (B, KB, MB, GB, TB)."""
    if bytes_num < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_num < 1024.0 or unit == 'PB':
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} B"

def send_to_recycle_bin(path: str) -> bool:
    """Send a file or folder to the Windows Recycle Bin."""
    if not os.path.exists(path):
        return True
    try:
        shfs = SHFILEOPSTRUCT()
        shfs.hwnd = None
        shfs.wFunc = FO_DELETE
        # pFrom must be double-null terminated
        abs_path = os.path.abspath(path)
        shfs.pFrom = abs_path + '\0\0'
        shfs.pTo = None
        shfs.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(shfs))
        return result == 0
    except Exception as e:
        print(f"[Error] send_to_recycle_bin for {path}: {e}")
        return False

def permanent_delete(path: str) -> bool:
    """Permanently delete a file or directory, handling read-only permissions on Windows."""
    try:
        if os.path.isfile(path) or os.path.islink(path):
            try:
                os.chmod(path, stat.S_IWRITE)
            except Exception:
                pass
            os.remove(path)
            return True
        elif os.path.isdir(path):
            def _remove_readonly(func, p, excinfo):
                try:
                    os.chmod(p, stat.S_IWRITE)
                    func(p)
                except Exception:
                    pass
            shutil.rmtree(path, onerror=_remove_readonly)
            return True
    except Exception as e:
        print(f"[Error] permanent_delete for {path}: {e}")
        return False
    return False

def delete_files(paths: list, use_recycle_bin: bool = True) -> dict:
    """Delete a list of files either permanently or via Recycle Bin."""
    deleted_count = 0
    freed_bytes = 0
    errors = []
    actually_deleted = []
    
    for p in paths:
        if not os.path.exists(p):
            # Already deleted or not found: track so UI removes it
            actually_deleted.append(p)
            continue
        try:
            sz = os.path.getsize(p) if os.path.isfile(p) else 0
            ok = False
            if use_recycle_bin:
                ok = send_to_recycle_bin(p)
                # Fallback to permanent delete if recycle bin failed (e.g. drive without recycle bin)
                if not ok:
                    ok = permanent_delete(p)
            else:
                ok = permanent_delete(p)

            if ok:
                deleted_count += 1
                freed_bytes += sz
                actually_deleted.append(p)
            else:
                errors.append(f"Không thể xóa: {p}")
        except Exception as e:
            errors.append(f"{p}: {str(e)}")
            
    # Automatically prune deleted files from active duplicate scanner results
    if actually_deleted:
        try:
            duplicate_scanner.remove_deleted_files(actually_deleted)
        except Exception as e:
            print(f"[Warning] Failed to prune duplicate scanner: {e}")

    return {
        "success": True,
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "freed_formatted": format_bytes(freed_bytes),
        "errors": errors,
        "actually_deleted": actually_deleted
    }

def empty_recycle_bin(drive_root: str = None) -> bool:
    """Empty the Windows Recycle Bin for a specific drive or all drives."""
    try:
        flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
        res = ctypes.windll.shell32.SHEmptyRecycleBinW(None, drive_root, flags)
        return res == 0
    except Exception as e:
        print(f"[Error] empty_recycle_bin: {e}")
        return False

def get_recycle_bin_info(drive_root: str) -> dict:
    """Query item count and total size in Recycle Bin for given drive root (e.g. 'C:\\')."""
    try:
        rbinfo = SHQUERYRBINFO()
        rbinfo.cbSize = ctypes.sizeof(SHQUERYRBINFO)
        res = ctypes.windll.shell32.SHQueryRecycleBinW(drive_root, ctypes.byref(rbinfo))
        if res == 0:
            return {
                "items": rbinfo.i64NumItems,
                "size_bytes": rbinfo.i64Size,
                "size_formatted": format_bytes(rbinfo.i64Size)
            }
    except Exception as e:
        print(f"[Warning] get_recycle_bin_info failed for {drive_root}: {e}")
    return {"items": 0, "size_bytes": 0, "size_formatted": "0 B"}

# -----------------------------------------------------------------------------
# System & Drive Information
# -----------------------------------------------------------------------------

_cached_drive_hardware = None

def get_drive_hardware_map() -> dict:
    """Accurately maps Drive Letters (C, D, etc.) to physical disk models & media types."""
    global _cached_drive_hardware
    if _cached_drive_hardware is not None:
        return _cached_drive_hardware

    mapping = {}
    try:
        out1 = run_powershell_hidden('Get-Partition | Where-Object DriveLetter | Select-Object DriveLetter, DiskNumber | ConvertTo-Json -Compress', timeout=5)
        parts = json.loads(out1) if out1 else []
        if isinstance(parts, dict): parts = [parts]

        out2 = run_powershell_hidden('Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType | ConvertTo-Json -Compress', timeout=5)
        disks = json.loads(out2) if out2 else []
        if isinstance(disks, dict): disks = [disks]

        disk_dict = {str(d['DeviceId']): d for d in disks}
        for p in parts:
            dl = str(p['DriveLetter']).upper()
            dnum = str(p.get('DiskNumber', ''))
            dinfo = disk_dict.get(dnum, {})
            model = dinfo.get('FriendlyName', '').strip() or f'Ổ đĩa {dl}:'
            mtype = dinfo.get('MediaType', '').strip() or 'SSD'
            btype = dinfo.get('BusType', '').strip()
            full_type = f"{btype} {mtype}".strip() if btype and btype != 'Unknown' else mtype

            mapping[dl] = {
                'name': model,
                'media_type': full_type,
                'disk_number': dnum
            }
    except Exception as e:
        print(f"[Warning] get_drive_hardware_map failed: {e}")

    _cached_drive_hardware = mapping
    return mapping

def get_system_drives() -> list:
    """Retrieve all fixed filesystem drives with storage statistics and physical disk info."""
    drives = []
    hw_map = get_drive_hardware_map()
    
    # Check drive letters from A to Z using Windows kernel32 GetDriveTypeW
    # 3 = DRIVE_FIXED, 2 = DRIVE_REMOVABLE
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        if drive_type in (3, 2):
            free_bytes = ctypes.c_ulonglong()
            total_bytes = ctypes.c_ulonglong()
            total_free_bytes = ctypes.c_ulonglong()
            ret = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                root,
                ctypes.byref(free_bytes),
                ctypes.byref(total_bytes),
                ctypes.byref(total_free_bytes)
            )
            if ret != 0 and total_bytes.value > 0:
                tot = total_bytes.value
                fre = free_bytes.value
                usd = tot - fre
                pct = round((usd / tot) * 100, 1)
                
                # Check recycle bin
                rb = get_recycle_bin_info(root)
                
                # Match physical disk name/type accurately from partition mapping
                hw_info = hw_map.get(letter, {})
                friendly_name = hw_info.get('name', f"Ổ đĩa {letter}:")
                media_type = hw_info.get('media_type', "SSD")

                drives.append({
                    "letter": letter,
                    "root": root,
                    "name": friendly_name,
                    "media_type": media_type,
                    "total_bytes": tot,
                    "free_bytes": fre,
                    "used_bytes": usd,
                    "used_percent": pct,
                    "total_formatted": format_bytes(tot),
                    "free_formatted": format_bytes(fre),
                    "used_formatted": format_bytes(usd),
                    "recycle_bin": rb
                })
    return drives

def get_system_overview() -> dict:
    """Compile comprehensive system hardware and storage overview."""
    drives = get_system_drives()
    total_space = sum(d["total_bytes"] for d in drives)
    used_space = sum(d["used_bytes"] for d in drives)
    free_space = sum(d["free_bytes"] for d in drives)
    total_rb_items = sum(d["recycle_bin"]["items"] for d in drives)
    total_rb_bytes = sum(d["recycle_bin"]["size_bytes"] for d in drives)
    
    return {
        "admin": is_admin(),
        "drives": drives,
        "total_space": total_space,
        "total_space_formatted": format_bytes(total_space),
        "used_space": used_space,
        "used_space_formatted": format_bytes(used_space),
        "free_space": free_space,
        "free_space_formatted": format_bytes(free_space),
        "overall_used_percent": round((used_space / total_space) * 100, 1) if total_space > 0 else 0,
        "recycle_bin": {
            "total_items": total_rb_items,
            "total_bytes": total_rb_bytes,
            "total_formatted": format_bytes(total_rb_bytes)
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# -----------------------------------------------------------------------------
# System Junk Scanner & Cleaner
# -----------------------------------------------------------------------------

_WINDIR = os.environ.get('WINDIR', os.environ.get('SystemRoot', r'C:\Windows'))
_LOCALAPPDATA = os.environ.get('LOCALAPPDATA', '')
_USERPROFILE = os.environ.get('USERPROFILE', '')
_PROGRAMDATA = os.environ.get('ProgramData', os.environ.get('ALLUSERSPROFILE', r'C:\ProgramData'))

JUNK_CATEGORIES = [
    {
        "id": "user_temp",
        "name": "Tệp tạm Người dùng (User Temp)",
        "description": "File tạm sinh ra từ các phần mềm đang hoặc đã chạy trong thư mục cá nhân (%TEMP%).",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(_LOCALAPPDATA, 'Temp') if _LOCALAPPDATA else ''
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "windows_temp",
        "name": "Tệp tạm Hệ thống (Windows Temp)",
        "description": "File tạm của dịch vụ hệ điều hành Windows (%WINDIR%\\Temp).",
        "safety": "medium",
        "default_checked": True,
        "paths": [os.path.join(_WINDIR, 'Temp')],
        "file_patterns": ["*"]
    },
    {
        "id": "crash_dumps",
        "name": "Báo cáo lỗi & Crash Dumps (*.dmp, WER)",
        "description": "Bản ghi sự cố phần mềm khi ứng dụng hoặc hệ thống bị sập (Minidump, WER).",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, 'CrashDumps') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Windows\WER\ReportArchive') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Windows\WER\ReportQueue') if _LOCALAPPDATA else '',
            os.path.join(_PROGRAMDATA, r'Microsoft\Windows\WER\ReportArchive') if _PROGRAMDATA else '',
            os.path.join(_PROGRAMDATA, r'Microsoft\Windows\WER\ReportQueue') if _PROGRAMDATA else '',
            os.path.join(_WINDIR, 'Minidump'),
        ],
        "file_patterns": ["*.dmp", "*.wer", "*.tmp", "*.hdmp", "*.mdmp"]
    },
    {
        "id": "thumbnail_cache",
        "name": "Bộ nhớ đệm Hình thu nhỏ (Thumbnail Cache)",
        "description": "Bộ nhớ đệm ảnh thumbnail của Windows Explorer (sẽ tự động tái tạo khi cần).",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'Microsoft\Windows\Explorer') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, 'IconCache.db') if _LOCALAPPDATA else ''
        ],
        "file_patterns": ["thumbcache_*.db", "iconcache_*.db", "IconCache.db"]
    },
    {
        "id": "chrome_cache",
        "name": "Bộ nhớ đệm Google Chrome",
        "description": "Tệp đệm hình ảnh, script duyệt web Google Chrome. Không xóa mật khẩu hay cookie.",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'Google\Chrome\User Data\*\Cache\Cache_Data') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Google\Chrome\User Data\*\Code Cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Google\Chrome\User Data\*\GPUCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Google\Chrome\User Data\*\DawnCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Google\Chrome\User Data\*\ShaderCache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "edge_cache",
        "name": "Bộ nhớ đệm Microsoft Edge",
        "description": "Tệp đệm duyệt web của trình duyệt Microsoft Edge. An toàn tuyệt đối cho tài khoản.",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'Microsoft\Edge\User Data\*\Cache\Cache_Data') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Edge\User Data\*\Code Cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Edge\User Data\*\GPUCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Edge\User Data\*\DawnCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Microsoft\Edge\User Data\*\ShaderCache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "coccoc_cache",
        "name": "Bộ nhớ đệm Trình duyệt Cốc Cốc",
        "description": "Tệp đệm hình ảnh và mã duyệt web của trình duyệt Cốc Cốc.",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'CocCoc\Browser\User Data\*\Cache\Cache_Data') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'CocCoc\Browser\User Data\*\Code Cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'CocCoc\Browser\User Data\*\GPUCache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "brave_cache",
        "name": "Bộ nhớ đệm Brave Browser",
        "description": "Tệp đệm duyệt web của Brave Browser.",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'BraveSoftware\Brave-Browser\User Data\*\Cache\Cache_Data') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'BraveSoftware\Brave-Browser\User Data\*\Code Cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'BraveSoftware\Brave-Browser\User Data\*\GPUCache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "directx_cache",
        "name": "Bộ nhớ đệm Đồ họa (DirectX & Shader Cache)",
        "description": "Bộ nhớ đệm shader đồ họa GPU (NVIDIA, AMD, Intel, D3D). Giúp làm sạch dữ liệu render cũ.",
        "safety": "high",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, 'D3DSCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'NVIDIA\DXCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'NVIDIA\GLCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'AMD\DxCache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Intel\ShaderCache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "windows_logs",
        "name": "Tệp Nhật ký Hệ thống (CBS & Windows Logs)",
        "description": "File nhật ký bảo trì hệ thống và bản ghi cấu hình cài đặt (CBS.log, DISM).",
        "safety": "medium",
        "default_checked": True,
        "paths": [
            os.path.join(_WINDIR, r'Logs\CBS'),
            os.path.join(_WINDIR, r'Logs\DISM'),
            os.path.join(_WINDIR, r'Logs\WindowsUpdate'),
        ],
        "file_patterns": ["*.log", "*.bak", "CbsPersist_*.cab", "CbsPersist_*.log"]
    },
    {
        "id": "dev_caches",
        "name": "Bộ nhớ đệm Lập trình (pip, npm, yarn, nuget)",
        "description": "File gói thư viện đã tải trong quá khứ của Python pip, Node.js npm, Yarn, NuGet.",
        "safety": "medium",
        "default_checked": True,
        "paths": [
            os.path.join(_LOCALAPPDATA, r'pip\cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, 'npm-cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'Yarn\Cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'pnpm\cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'NuGet\v3-cache') if _LOCALAPPDATA else '',
            os.path.join(_LOCALAPPDATA, r'NuGet\Cache') if _LOCALAPPDATA else '',
        ],
        "file_patterns": ["*"]
    },
    {
        "id": "windows_update_cache",
        "name": "Bộ nhớ đệm Tải về Windows Update",
        "description": "Các gói cập nhật Windows đã cài đặt xong lưu trong SoftwareDistribution\\Download.",
        "safety": "medium",
        "default_checked": True,
        "paths": [os.path.join(_WINDIR, r'SoftwareDistribution\Download')],
        "file_patterns": ["*"]
    },
    {
        "id": "delivery_optimization",
        "name": "Tệp Delivery Optimization",
        "description": "Tệp chia sẻ bản cập nhật giữa các máy tính trong mạng nội bộ.",
        "safety": "high",
        "default_checked": True,
        "paths": [os.path.join(_WINDIR, r'SoftwareDistribution\DeliveryOptimization')],
        "file_patterns": ["*"]
    }
]

def get_friendly_app_hint(folder_name: str) -> str:
    """Map temp folder or file prefix to a friendly human-readable application name."""
    f_lower = folder_name.lower()
    if '3kbnm' in f_lower or 'faceid' in f_lower or 'windows security service' in f_lower:
        return 'FaceID (Windows Security Service)'
    elif '_mei' in f_lower:
        return 'Ứng dụng FaceID Guard v2'
    elif 'pyrefly' in f_lower:
        return 'Antigravity IDE / Python Tools'
    elif f_lower.endswith('.sys'):
        return 'Driver phần cứng hệ thống'
    elif f_lower.endswith('.tmp'):
        return 'Tiến trình trình duyệt / WebView2'
    elif 'coccoc' in f_lower:
        return 'Trình duyệt Cốc Cốc'
    elif 'chrome' in f_lower:
        return 'Trình duyệt Google Chrome'
    elif 'edge' in f_lower:
        return 'Trình duyệt Microsoft Edge'
    elif 'discord' in f_lower:
        return 'Ứng dụng Discord'
    elif 'node' in f_lower:
        return 'Tiến trình Node.js'
    return folder_name

def expand_category_paths(cat: dict) -> list:
    """Expand paths with wildcards and deduplicate real folders."""
    expanded = []
    seen = set()
    for raw in cat.get("paths", []):
        if not raw:
            continue
        raw = os.path.expandvars(raw)
        if '*' in raw or '?' in raw:
            for p in glob.glob(raw):
                norm = os.path.normcase(os.path.abspath(p))
                if norm not in seen and os.path.exists(p):
                    seen.add(norm)
                    expanded.append(p)
        else:
            if os.path.exists(raw):
                norm = os.path.normcase(os.path.abspath(raw))
                if norm not in seen:
                    seen.add(norm)
                    expanded.append(raw)
    return expanded

def scan_single_junk_category(cat: dict) -> dict:
    """Scan all target paths for a specific junk category with maximum speed and accuracy."""
    files_sample = []
    total_files = 0
    total_bytes = 0
    errors = 0
    patterns = cat.get("file_patterns", ["*"])
    is_match_all = (patterns == ["*"] or not patterns)

    ext_set = set()
    regex = None
    if not is_match_all:
        if all(p.startswith('*.') and '*' not in p[2:] for p in patterns):
            ext_set = {p[1:].lower() for p in patterns}
        else:
            regex = re.compile('|'.join([fnmatch.translate(p) for p in patterns]), re.IGNORECASE)

    target_dirs = expand_category_paths(cat)

    for base_path in target_dirs:
        # If the target is a single file (e.g. IconCache.db)
        if os.path.isfile(base_path):
            try:
                st = os.stat(base_path)
                sz = st.st_size
                total_files += 1
                total_bytes += sz
                if len(files_sample) < 50:
                    files_sample.append({
                        "path": base_path,
                        "name": os.path.basename(base_path),
                        "size": sz,
                        "size_formatted": format_bytes(sz),
                        "is_locked": False,
                        "mtime": st.st_mtime,
                        "mtime_str": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                    })
            except (PermissionError, OSError):
                errors += 1
            continue

        stack = [base_path]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        try:
                            # Do not follow symlinks/junctions to prevent infinite recursion
                            if entry.is_file(follow_symlinks=False):
                                fname = entry.name
                                if not is_match_all:
                                    if ext_set:
                                        _, ext = os.path.splitext(fname)
                                        if ext.lower() not in ext_set:
                                            continue
                                    elif regex and not regex.match(fname):
                                        continue

                                st = entry.stat(follow_symlinks=False)
                                sz = st.st_size
                                total_files += 1
                                total_bytes += sz

                                # Lightweight check for files sample
                                if len(files_sample) < 50:
                                    is_locked = False
                                    if cat["id"] in ["user_temp", "windows_temp"]:
                                        try:
                                            with open(entry.path, 'r+b'):
                                                pass
                                        except (PermissionError, OSError):
                                            is_locked = True
                                    files_sample.append({
                                        "path": entry.path,
                                        "name": fname,
                                        "size": sz,
                                        "size_formatted": format_bytes(sz),
                                        "is_locked": is_locked,
                                        "mtime": st.st_mtime,
                                        "mtime_str": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
                                    })
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                        except (PermissionError, OSError):
                            errors += 1
            except (PermissionError, OSError):
                errors += 1

    return {
        "id": cat["id"],
        "name": cat["name"],
        "description": cat["description"],
        "safety": cat["safety"],
        "default_checked": cat["default_checked"],
        "total_files": total_files,
        "total_bytes": total_bytes,
        "total_formatted": format_bytes(total_bytes),
        "deletable_bytes": total_bytes,
        "deletable_formatted": format_bytes(total_bytes),
        "locked_bytes": 0,
        "locked_formatted": "0 B",
        "locked_files": 0,
        "locked_hints": [],
        "errors": errors,
        "files_sample": files_sample,
        "all_files_count": total_files
    }

def scan_all_junk_categories() -> dict:
    """Scan all junk categories using concurrent threads for maximum speed."""
    results = []
    max_workers = min(8, len(JUNK_CATEGORIES))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(scan_single_junk_category, cat): cat for cat in JUNK_CATEGORIES}
        for future in as_completed(future_map):
            try:
                cat_res = future.result()
                results.append(cat_res)
            except Exception as e:
                print(f"[Error] scan category failed: {e}")

    # Sort consistent with defined categories order
    cat_order = {cat["id"]: idx for idx, cat in enumerate(JUNK_CATEGORIES)}
    results.sort(key=lambda x: cat_order.get(x["id"], 99))

    total_bytes = sum(c["total_bytes"] for c in results)
    total_files = sum(c["total_files"] for c in results)

    return {
        "categories": results,
        "total_bytes": total_bytes,
        "total_formatted": format_bytes(total_bytes),
        "total_files": total_files
    }

def clean_junk_category(category_id: str, use_recycle_bin: bool = False) -> dict:
    """Clean all items in a specified junk category safely and effectively."""
    cat = next((c for c in JUNK_CATEGORIES if c["id"] == category_id), None)
    if not cat:
        return {"success": False, "error": f"Không tìm thấy danh mục {category_id}"}

    deleted_files = 0
    freed_bytes = 0
    failed_files = 0
    failed_bytes = 0
    locked_folders = {}
    patterns = cat.get("file_patterns", ["*"])
    is_match_all = (patterns == ["*"] or not patterns)

    ext_set = set()
    regex = None
    if not is_match_all:
        if all(p.startswith('*.') and '*' not in p[2:] for p in patterns):
            ext_set = {p[1:].lower() for p in patterns}
        else:
            regex = re.compile('|'.join([fnmatch.translate(p) for p in patterns]), re.IGNORECASE)

    target_dirs = expand_category_paths(cat)

    for base_path in target_dirs:
        if os.path.isfile(base_path):
            try:
                sz = os.path.getsize(base_path)
                ok = False
                if use_recycle_bin:
                    ok = send_to_recycle_bin(base_path)
                if not ok:
                    ok = permanent_delete(base_path)
                if ok:
                    deleted_files += 1
                    freed_bytes += sz
                else:
                    failed_files += 1
                    failed_bytes += sz
            except Exception:
                failed_files += 1
            continue

        try:
            # Walk bottom-up to allow directory cleanup after files are removed
            for root, dirs, files in os.walk(base_path, topdown=False):
                for f in files:
                    if not is_match_all:
                        if ext_set:
                            _, ext = os.path.splitext(f)
                            if ext.lower() not in ext_set:
                                continue
                        elif regex and not regex.match(f):
                            continue

                    file_path = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(file_path)
                    except Exception:
                        sz = 0

                    ok = False
                    try:
                        if use_recycle_bin:
                            ok = send_to_recycle_bin(file_path)
                        if not ok:
                            ok = permanent_delete(file_path)
                    except Exception:
                        ok = False

                    if ok:
                        deleted_files += 1
                        freed_bytes += sz
                    else:
                        failed_files += 1
                        failed_bytes += sz
                        try:
                            rel = os.path.relpath(file_path, base_path)
                            top = rel.split(os.sep)[0]
                            locked_folders[top] = locked_folders.get(top, 0) + sz
                        except Exception:
                            pass

                # Try to clean empty subdirectories (never remove the base_path itself)
                root_norm = os.path.normcase(os.path.abspath(root))
                base_norm = os.path.normcase(os.path.abspath(base_path))
                if root_norm != base_norm:
                    try:
                        os.rmdir(root)
                    except (PermissionError, OSError):
                        pass
        except Exception:
            pass

    locked_hints = []
    for top, sz in sorted(locked_folders.items(), key=lambda x: x[1], reverse=True)[:3]:
        app_name = get_friendly_app_hint(top)
        locked_hints.append(f"{app_name} ({format_bytes(sz)})")

    return {
        "success": True,
        "category_id": category_id,
        "deleted_files": deleted_files,
        "freed_bytes": freed_bytes,
        "freed_formatted": format_bytes(freed_bytes),
        "failed_files": failed_files,
        "locked_bytes": failed_bytes,
        "locked_formatted": format_bytes(failed_bytes),
        "locked_hints": locked_hints
    }

def close_temp_blocking_processes() -> dict:
    """Safely terminate background processes holding User Temp files locked."""
    import subprocess
    temp_dir = os.environ.get('TEMP', r'C:\Users\HuyBlink\AppData\Local\Temp').replace('\\', '\\\\')
    ps_script = f"""
    $temp = '{temp_dir}'.ToLower()
    $stopped = @()
    Get-CimInstance Win32_Process | Where-Object {{ $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith($temp) }} | ForEach-Object {{
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $stopped += $_.Name
    }}
    Get-CimInstance Win32_Process | Where-Object {{ $_.Name -like '*WinSecurityHealthGuard*' -or $_.Name -like '*WindowsSecurityService*' }} | ForEach-Object {{
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $stopped += $_.Name
    }}
    $stopped | Select-Object -Unique
    """
    try:
        out = run_powershell_hidden(ps_script, timeout=10)
        terminated = [line.strip() for line in out.splitlines() if line.strip()]
        return {"success": True, "terminated": terminated}
    except Exception as e:
        return {"success": False, "error": str(e)}

# -----------------------------------------------------------------------------
# Multi-Stage Fast Duplicate File Finder
# -----------------------------------------------------------------------------

class DuplicateFinderTask:
    def __init__(self):
        self.lock = threading.Lock()
        self.is_running = False
        self.should_cancel = False
        self.status = "idle"  # idle | scanning | grouping | hashing | completed | cancelled | error
        self.error_message = ""
        self.progress = {
            "phase": "",
            "scanned_files": 0,
            "candidate_files": 0,
            "hashed_files": 0,
            "total_to_hash": 0,
            "current_file": "",
            "duplicate_groups": 0,
            "wasted_bytes": 0,
            "percent": 0
        }
        self.results = []

    def cancel(self):
        with self.lock:
            self.should_cancel = True

    def get_status(self) -> dict:
        with self.lock:
            return {
                "is_running": self.is_running,
                "status": self.status,
                "error_message": self.error_message,
                "progress": dict(self.progress),
                "groups_count": len(self.results),
                "wasted_bytes": sum(g["wasted_bytes"] for g in self.results),
                "wasted_formatted": format_bytes(sum(g["wasted_bytes"] for g in self.results))
            }

    def get_results(self) -> list:
        with self.lock:
            return list(self.results)

    def remove_deleted_files(self, deleted_paths: list):
        """Prune deleted files from results and drop groups that no longer have duplicates."""
        if not deleted_paths:
            return
        deleted_set = {os.path.normcase(os.path.abspath(p)) for p in deleted_paths}
        with self.lock:
            new_results = []
            for grp in self.results:
                remaining_files = []
                for f in grp.get("files", []):
                    f_path_norm = os.path.normcase(os.path.abspath(f["path"]))
                    if f_path_norm not in deleted_set and os.path.exists(f["path"]):
                        remaining_files.append(f)

                # A duplicate group only makes sense if it has at least 2 copies!
                if len(remaining_files) >= 2:
                    remaining_files.sort(key=lambda x: x["mtime"])
                    for idx, f in enumerate(remaining_files):
                        f["is_oldest"] = (idx == 0)
                        f["selected"] = (idx > 0)
                    sz = grp["file_size"]
                    wasted = sz * (len(remaining_files) - 1)
                    grp["files"] = remaining_files
                    grp["total_copies"] = len(remaining_files)
                    grp["wasted_bytes"] = wasted
                    grp["wasted_formatted"] = format_bytes(wasted)
                    new_results.append(grp)

            self.results = new_results
            if isinstance(self.progress, dict):
                self.progress["duplicate_groups"] = len(new_results)
                self.progress["wasted_bytes"] = sum(g["wasted_bytes"] for g in new_results)

    def _quick_partial_hash(self, path: str, size: int) -> str:
        """Read 4KB from start and end of file for ultra-fast candidate filtering."""
        try:
            hasher = hashlib.md5()
            with open(path, 'rb') as f:
                # Read start
                hasher.update(f.read(4096))
                if size > 8192:
                    # Seek to end
                    f.seek(-4096, os.SEEK_END)
                    hasher.update(f.read(4096))
            return hasher.hexdigest()
        except Exception:
            return ""

    def _full_hash(self, path: str) -> str:
        """Stream full file through SHA-256 in 128KB blocks with instant cancellation support."""
        try:
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(131072):
                    if self.should_cancel:
                        return ""
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def start_scan(self, target_dirs: list, min_size_bytes: int = 1048576, file_types: list = None):
        """Start async scanning in a background worker thread."""
        with self.lock:
            if self.is_running:
                return False
            self.is_running = True
            self.should_cancel = False
            self.status = "scanning"
            self.error_message = ""
            self.results = []
            self.progress = {
                "phase": "Đang quét danh sách tệp...",
                "scanned_files": 0,
                "candidate_files": 0,
                "hashed_files": 0,
                "total_to_hash": 0,
                "current_file": "",
                "duplicate_groups": 0,
                "wasted_bytes": 0,
                "percent": 5
            }

        worker = threading.Thread(
            target=self._run_scan_thread,
            args=(target_dirs, min_size_bytes, file_types),
            daemon=True
        )
        worker.start()
        return True

    def _run_scan_thread(self, target_dirs: list, min_size_bytes: int, file_types: list):
        try:
            # Stage 1: Walk directories & gather files >= min_size_bytes
            files_by_size = {} # size -> [file_path, ...]
            scanned_count = 0
            FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
            
            # System directories and developer caches to skip from duplicate scanning
            SYSTEM_SKIP_NAMES = {
                '$recycle.bin', 'system volume information', 'windows',
                'recovery', '$winreagent', '$windows.~bt', '$windows.~ws',
                'appdata', '.git', 'node_modules', '__pycache__',
                '.gradle', '.nuget', '.vscode-shared', '.gemini', '.android'
            }

            stack = [os.path.abspath(d) for d in target_dirs if os.path.exists(d)]
            while stack:
                if self.should_cancel:
                    break
                curr = stack.pop()
                try:
                    with os.scandir(curr) as it:
                        for entry in it:
                            if self.should_cancel:
                                break
                            scanned_count += 1
                            try:
                                st = entry.stat(follow_symlinks=False)
                                # Never follow Windows junctions/reparse points (prevents infinite recursive loops)
                                if st.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                                    continue

                                if entry.is_dir(follow_symlinks=False):
                                    name_lower = entry.name.lower()
                                    if name_lower.startswith('$') or name_lower in SYSTEM_SKIP_NAMES:
                                        continue
                                    # On Windows system drive (C:), skip OS application install directories
                                    if curr.upper().startswith('C:') and name_lower in ('program files', 'program files (x86)', 'programdata'):
                                        continue
                                    stack.append(entry.path)
                                elif entry.is_file(follow_symlinks=False):
                                    if file_types:
                                        ext = os.path.splitext(entry.name)[1].lower().lstrip('.')
                                        if ext not in file_types:
                                            continue
                                    sz = st.st_size
                                    if sz >= min_size_bytes:
                                        files_by_size.setdefault(sz, []).append((entry.path, st.st_mtime))
                            except (PermissionError, OSError):
                                continue

                            if scanned_count % 200 == 0:
                                with self.lock:
                                    self.progress["scanned_files"] = scanned_count
                                    self.progress["current_file"] = entry.name
                                    self.progress["percent"] = min(25, 5 + int(scanned_count / 1000))
                except (PermissionError, OSError):
                    continue

            if self.should_cancel:
                with self.lock:
                    self.status = "cancelled"
                    self.is_running = False
                return

            # Stage 2: Filter sizes that have 2+ files
            potential_duplicate_groups = [(sz, group) for sz, group in files_by_size.items() if len(group) >= 2]
            total_candidate_files = sum(len(g) for _, g in potential_duplicate_groups)
            
            if total_candidate_files == 0:
                with self.lock:
                    self.results = []
                    self.status = "completed"
                    self.is_running = False
                    self.progress["phase"] = "Hoàn tất tìm kiếm! Không phát hiện tệp trùng lặp nào."
                    self.progress["percent"] = 100
                return

            with self.lock:
                self.status = "grouping"
                self.progress["phase"] = "Đối chiếu nhanh phần đầu & cuối tệp..."
                self.progress["scanned_files"] = scanned_count
                self.progress["candidate_files"] = total_candidate_files
                self.progress["percent"] = 30

            # Stage 3: Partial Hash filtering with continuous progress updates
            partial_groups = {} # (size, partial_hash) -> [(path, mtime), ...]
            processed_partial = 0
            for sz, group in potential_duplicate_groups:
                if self.should_cancel:
                    break
                for path, mtime in group:
                    if self.should_cancel:
                        break
                    phash = self._quick_partial_hash(path, sz)
                    if phash:
                        partial_groups.setdefault((sz, phash), []).append((path, mtime))
                    processed_partial += 1
                    if processed_partial % 20 == 0 or processed_partial == total_candidate_files:
                        with self.lock:
                            pct = 30 + int((processed_partial / max(1, total_candidate_files)) * 20)
                            self.progress["percent"] = min(50, pct)
                            self.progress["current_file"] = os.path.basename(path)

            if self.should_cancel:
                with self.lock:
                    self.status = "cancelled"
                    self.is_running = False
                return

            # Filter partial groups that have 2+ files
            full_hash_candidates = [(key[0], grp) for key, grp in partial_groups.items() if len(grp) >= 2]
            total_files_to_hash = sum(len(g) for _, g in full_hash_candidates)

            if total_files_to_hash == 0:
                with self.lock:
                    self.results = []
                    self.status = "completed"
                    self.is_running = False
                    self.progress["phase"] = "Hoàn tất tìm kiếm! Không phát hiện tệp trùng lặp nào."
                    self.progress["percent"] = 100
                return

            with self.lock:
                self.status = "hashing"
                self.progress["phase"] = "Đang băm SHA-256 chính xác các tệp nghi vấn..."
                self.progress["total_to_hash"] = total_files_to_hash
                self.progress["percent"] = 50

            # Stage 4: Full SHA-256 Hashing with ThreadPoolExecutor
            full_hash_groups = {} # (size, full_hash) -> [(path, mtime), ...]
            hashed_count = 0

            # Flatten list of files to hash
            files_to_process = []
            for sz, grp in full_hash_candidates:
                for path, mtime in grp:
                    files_to_process.append((path, sz, mtime))

            def hash_worker(item):
                p, sz, mt = item
                return p, sz, mt, self._full_hash(p)

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(hash_worker, item): item for item in files_to_process}
                for future in as_completed(futures):
                    if self.should_cancel:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    p, sz, mt, f_hash = future.result()
                    hashed_count += 1
                    if f_hash:
                        full_hash_groups.setdefault((sz, f_hash), []).append((p, mt))

                    with self.lock:
                        self.progress["hashed_files"] = hashed_count
                        pct = 50 + int((hashed_count / max(1, total_files_to_hash)) * 48)
                        self.progress["percent"] = min(98, pct)
                        self.progress["current_file"] = os.path.basename(p)

            if self.should_cancel:
                with self.lock:
                    self.status = "cancelled"
                    self.is_running = False
                return

            # Stage 5: Compile Final Groups
            final_groups = []
            group_idx = 1
            for (sz, f_hash), file_list in full_hash_groups.items():
                if len(file_list) >= 2:
                    # Sort files by modified time (oldest first)
                    file_list.sort(key=lambda x: x[1])
                    files_data = []
                    for idx, (p, mt) in enumerate(file_list):
                        # By default, select newer files for deletion (keep the oldest original)
                        is_selected = (idx > 0)
                        files_data.append({
                            "path": p,
                            "name": os.path.basename(p),
                            "directory": os.path.dirname(p),
                            "size": sz,
                            "size_formatted": format_bytes(sz),
                            "mtime": mt,
                            "mtime_str": datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M:%S"),
                            "is_oldest": (idx == 0),
                            "selected": is_selected
                        })
                    
                    wasted = sz * (len(file_list) - 1)
                    final_groups.append({
                        "id": f"dup_grp_{group_idx}",
                        "hash": f_hash,
                        "file_size": sz,
                        "size_formatted": format_bytes(sz),
                        "total_copies": len(file_list),
                        "wasted_bytes": wasted,
                        "wasted_formatted": format_bytes(wasted),
                        "files": files_data
                    })
                    group_idx += 1

            # Sort groups by wasted bytes descending (largest wasted space first)
            final_groups.sort(key=lambda g: g["wasted_bytes"], reverse=True)

            with self.lock:
                self.results = final_groups
                self.status = "completed"
                self.is_running = False
                self.progress["phase"] = "Hoàn tất tìm kiếm!"
                self.progress["percent"] = 100
                self.progress["duplicate_groups"] = len(final_groups)
                self.progress["wasted_bytes"] = sum(g["wasted_bytes"] for g in final_groups)

        except Exception as e:
            with self.lock:
                self.status = "error"
                self.is_running = False
                self.error_message = str(e)
            print(f"[Error in duplicate scan]: {e}")

# Global instance
duplicate_scanner = DuplicateFinderTask()

# -----------------------------------------------------------------------------
# Large Files Finder
# -----------------------------------------------------------------------------

def scan_large_files(target_dir: str, min_size_bytes: int = 104857600, limit: int = 100) -> dict:
    """Find top N largest files in target directory/drive using ultra-fast os.scandir (default >= 100MB)."""
    if not os.path.exists(target_dir):
        return {"error": f"Đường dẫn {target_dir} không tồn tại", "files": []}
        
    found_files = []
    scanned_count = 0
    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
    skip_folders = {
        '$recycle.bin', 'system volume information', 'windows',
        'recovery', '$winreagent', '$windows.~bt', '$windows.~ws'
    }

    stack = [os.path.abspath(target_dir)]
    try:
        while stack:
            curr = stack.pop()
            try:
                with os.scandir(curr) as it:
                    for entry in it:
                        scanned_count += 1
                        try:
                            st = entry.stat(follow_symlinks=False)
                            if st.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                name_lower = entry.name.lower()
                                if name_lower.startswith('$') or name_lower in skip_folders:
                                    continue
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                sz = st.st_size
                                if sz >= min_size_bytes:
                                    ext = os.path.splitext(entry.name)[1].lower().lstrip('.')
                                    mt = entry.stat(follow_symlinks=False).st_mtime
                                    found_files.append({
                                        "path": entry.path,
                                        "name": entry.name,
                                        "directory": curr,
                                        "extension": ext or "FILE",
                                        "size": sz,
                                        "size_formatted": format_bytes(sz),
                                        "mtime": mt,
                                        "mtime_str": datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M:%S")
                                    })
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue
    except Exception as e:
        print(f"[Warning] scan_large_files partial error: {e}")

    # Sort descending by size
    found_files.sort(key=lambda x: x["size"], reverse=True)
    top_files = found_files[:limit]
    total_large_bytes = sum(f["size"] for f in top_files)
    
    return {
        "target_dir": target_dir,
        "scanned_count": scanned_count,
        "total_found": len(found_files),
        "total_bytes": total_large_bytes,
        "total_formatted": format_bytes(total_large_bytes),
        "files": top_files
    }

# -----------------------------------------------------------------------------
# Drive Optimization (TRIM & Defrag)
# -----------------------------------------------------------------------------

def optimize_drive_trim(drive_letter: str) -> dict:
    """Run TRIM on SSD drive via PowerShell Optimize-Volume."""
    dl = drive_letter.rstrip(":\\/").upper()
    cmd = f"Optimize-Volume -DriveLetter {dl} -ReTrim -Verbose"
    
    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        res = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=flags
        )
        if res.returncode == 0:
            return {
                "success": True,
                "drive": dl,
                "message": f"Kích hoạt TRIM thành công cho ổ {dl}:\\! Các khối nhớ SSD đã được giải phóng tối ưu.",
                "output": res.stdout or res.stderr
            }
        else:
            err = res.stderr or res.stdout
            if "Access denied" in err or "PermissionDenied" in err:
                return {
                    "success": False,
                    "need_admin": True,
                    "drive": dl,
                    "message": f"Cần quyền Quản trị viên (Administrator) để chạy lệnh TRIM cho ổ {dl}:\\.",
                    "output": err
                }
            return {
                "success": False,
                "drive": dl,
                "message": f"Lệnh TRIM không thành công: {err}",
                "output": err
            }
    except Exception as e:
        return {
            "success": False,
            "drive": dl,
            "message": f"Lỗi thực thi lệnh: {e}"
        }

def open_in_explorer(path: str) -> bool:
    """Open Windows Explorer and highlight file or directory."""
    try:
        abs_p = os.path.abspath(path)
        if os.path.isfile(abs_p):
            subprocess.Popen(f'explorer /select,"{abs_p}"')
            return True
        elif os.path.isdir(abs_p):
            subprocess.Popen(f'explorer "{abs_p}"')
            return True
    except Exception as e:
        print(f"[Error] open_in_explorer: {e}")
    return False

# Compatibility Aliases
run_ssd_trim = optimize_drive_trim
open_file_in_explorer = open_in_explorer

# -----------------------------------------------------------------------------
# Real-Time Memory Management & Mem Reduct Engine
# -----------------------------------------------------------------------------

# Windows Token & Privilege Constants
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

class LUID(ctypes.Structure):
    _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ('dwLength', wintypes.DWORD),
        ('dwMemoryLoad', wintypes.DWORD),
        ('ullTotalPhys', ctypes.c_uint64),
        ('ullAvailPhys', ctypes.c_uint64),
        ('ullTotalPageFile', ctypes.c_uint64),
        ('ullAvailPageFile', ctypes.c_uint64),
        ('ullTotalVirtual', ctypes.c_uint64),
        ('ullAvailVirtual', ctypes.c_uint64),
        ('sullAvailExtendedVirtual', ctypes.c_uint64),
    ]

class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('CommitTotal', ctypes.c_size_t),
        ('CommitLimit', ctypes.c_size_t),
        ('CommitPeak', ctypes.c_size_t),
        ('PhysicalTotal', ctypes.c_size_t),
        ('PhysicalAvailable', ctypes.c_size_t),
        ('SystemCache', ctypes.c_size_t),
        ('KernelTotal', ctypes.c_size_t),
        ('KernelPaged', ctypes.c_size_t),
        ('KernelNonpaged', ctypes.c_size_t),
        ('PageSize', ctypes.c_size_t),
        ('HandleCount', wintypes.DWORD),
        ('ProcessCount', wintypes.DWORD),
        ('ThreadCount', wintypes.DWORD),
    ]

# Setup Windows API signatures
_kernel32 = ctypes.windll.kernel32
_advapi32 = ctypes.windll.advapi32
_ntdll = ctypes.windll.ntdll
_user32 = ctypes.windll.user32
_shell32 = ctypes.windll.shell32
_psapi = ctypes.windll.psapi

_K32EmptyWorkingSet = getattr(_kernel32, 'K32EmptyWorkingSet', None) or getattr(_psapi, 'EmptyWorkingSet', None)
if _K32EmptyWorkingSet:
    _K32EmptyWorkingSet.argtypes = [wintypes.HANDLE]
    _K32EmptyWorkingSet.restype = wintypes.BOOL

_NtSetSystemInformation = getattr(_ntdll, 'NtSetSystemInformation', None)
if _NtSetSystemInformation:
    _NtSetSystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
    _NtSetSystemInformation.restype = ctypes.c_long

def enable_privilege(privilege_name: str) -> bool:
    """Acquire specific Windows privilege in process token (e.g. SeProfileSingleProcessPrivilege)."""
    try:
        h_token = wintypes.HANDLE()
        h_proc = _kernel32.GetCurrentProcess()
        if not _advapi32.OpenProcessToken(h_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
            return False
        try:
            luid = LUID()
            if not _advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
                return False
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            _advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
            return _kernel32.GetLastError() == 0
        finally:
            _kernel32.CloseHandle(h_token)
    except Exception:
        return False

def get_foreground_process_id() -> int:
    """Retrieve the PID of the active foreground window to avoid flushing its working set."""
    try:
        hwnd = _user32.GetForegroundWindow()
        if hwnd:
            pid = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return pid.value
    except Exception:
        pass
    return 0

def is_gaming_or_fullscreen() -> bool:
    """Check if a DirectX/Vulkan game is running in fullscreen or user is in presentation mode."""
    try:
        state = wintypes.DWORD()
        res = _shell32.SHQueryUserNotificationState(ctypes.byref(state))
        if res == 0:
            # 2 = QUNS_BUSY, 3 = QUNS_RUNNING_D3D_FULL_SCREEN, 4 = QUNS_PRESENTATION_MODE
            return state.value in (2, 3, 4)
    except Exception:
        pass
    return False

def get_memory_status() -> dict:
    """Query current system memory metrics, standby cache, commit charges, and handle count."""
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    _kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))

    total_bytes = stat.ullTotalPhys
    avail_bytes = stat.ullAvailPhys
    used_bytes = max(0, total_bytes - avail_bytes)
    used_pct = stat.dwMemoryLoad

    total_pagefile = stat.ullTotalPageFile
    avail_pagefile = stat.ullAvailPageFile
    used_pagefile = max(0, total_pagefile - avail_pagefile)
    pagefile_pct = round((used_pagefile / total_pagefile * 100) if total_pagefile > 0 else 0, 1)

    # Performance Info for Standby/SystemCache and process count
    perf = PERFORMANCE_INFORMATION()
    perf.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
    system_cache_bytes = 0
    process_count = 0
    thread_count = 0
    handle_count = 0

    if _psapi.GetPerformanceInfo(ctypes.byref(perf), ctypes.sizeof(PERFORMANCE_INFORMATION)):
        page_size = perf.PageSize
        system_cache_bytes = perf.SystemCache * page_size
        process_count = perf.ProcessCount
        thread_count = perf.ThreadCount
        handle_count = perf.HandleCount

    used_gb = round(used_bytes / (1024**3), 1)
    total_gb = round(total_bytes / (1024**3), 1)
    avail_gb = round(avail_bytes / (1024**3), 1)

    return {
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "available_bytes": avail_bytes,
        "used_percent": used_pct,
        "usage_pct": used_pct,
        "total_gb": total_gb,
        "used_gb": used_gb,
        "available_gb": avail_gb,
        "total_formatted": format_bytes(total_bytes),
        "used_formatted": format_bytes(used_bytes),
        "available_formatted": format_bytes(avail_bytes),
        "system_cache_bytes": system_cache_bytes,
        "system_cache_formatted": format_bytes(system_cache_bytes),
        "pagefile_total": total_pagefile,
        "pagefile_used": used_pagefile,
        "pagefile_percent": pagefile_pct,
        "pagefile_total_formatted": format_bytes(total_pagefile),
        "pagefile_used_formatted": format_bytes(used_pagefile),
        "processes": process_count,
        "threads": thread_count,
        "handles": handle_count,
        "is_admin": is_admin(),
        "is_gaming": is_gaming_or_fullscreen()
    }

def clean_memory(
    purge_standby: bool = True,
    empty_working_sets: bool = True,
    flush_modified: bool = True,
    skip_foreground: bool = True
) -> dict:
    """
    Cleans system memory using Mem Reduct native algorithms.
    Protects foreground active process from being flushed to prevent lag/stutter.
    """
    before = get_memory_status()
    foreground_pid = get_foreground_process_id() if skip_foreground else 0
    current_pid = os.getpid()

    # Enable privileges required for ntdll system memory list commands
    enable_privilege('SeProfileSingleProcessPrivilege')
    enable_privilege('SeIncreaseQuotaPrivilege')

    nt_success = False
    working_sets_cleaned = 0

    # 1. Native NT System Memory List commands (Mem Reduct core)
    # SYSTEM_MEMORY_LIST_COMMAND:
    # 0 = MemoryEmptyWorkingSets
    # 1 = MemoryFlushModifiedList
    # 2 = MemoryPurgeStandbyList
    # 3 = MemoryPurgeLowPriorityStandbyList
    if _NtSetSystemInformation:
        try:
            if empty_working_sets:
                cmd_ws = ctypes.c_int(0)
                res = _NtSetSystemInformation(80, ctypes.byref(cmd_ws), ctypes.sizeof(cmd_ws))
                if res == 0:
                    nt_success = True

            if flush_modified:
                cmd_fm = ctypes.c_int(1)
                _NtSetSystemInformation(80, ctypes.byref(cmd_fm), ctypes.sizeof(cmd_fm))

            if purge_standby:
                cmd_ps = ctypes.c_int(2)
                res_ps = _NtSetSystemInformation(80, ctypes.byref(cmd_ps), ctypes.sizeof(cmd_ps))
                if res_ps == 0:
                    nt_success = True
                cmd_lp = ctypes.c_int(3)
                _NtSetSystemInformation(80, ctypes.byref(cmd_lp), ctypes.sizeof(cmd_lp))
        except Exception as e:
            print(f"[Warning] NtSetSystemInformation call: {e}")

    # 2. Targeted Working Set Trimming for running processes (with foreground protection)
    if empty_working_sets and _K32EmptyWorkingSet:
        try:
            # Query all process IDs
            pids = (wintypes.DWORD * 2048)()
            cb_needed = wintypes.DWORD()
            if _psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(cb_needed)):
                count = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
                PROCESS_QUERY_INFORMATION = 0x0400
                PROCESS_SET_QUOTA = 0x0100

                for i in range(count):
                    pid = pids[i]
                    if pid == 0 or pid == 4 or pid == current_pid or pid == foreground_pid:
                        # Skip system idle, system, self, and foreground app
                        continue
                    h_proc = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
                    if h_proc:
                        try:
                            if _K32EmptyWorkingSet(h_proc):
                                working_sets_cleaned += 1
                        finally:
                            _kernel32.CloseHandle(h_proc)
        except Exception as e:
            print(f"[Warning] EnumProcesses trim: {e}")

    # 3. Clear System File Cache Size if supported
    try:
        SetSystemFileCacheSize = getattr(_kernel32, 'SetSystemFileCacheSize', None)
        if SetSystemFileCacheSize:
            SetSystemFileCacheSize.argtypes = [ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD]
            SetSystemFileCacheSize(-1, -1, 0)
    except Exception:
        pass

    # Give OS a moment to update counters
    time.sleep(0.1)
    after = get_memory_status()

    freed_bytes = max(0, before["used_bytes"] - after["used_bytes"])
    cache_freed_bytes = max(0, before["system_cache_bytes"] - after["system_cache_bytes"])

    return {
        "success": True,
        "freed_bytes": freed_bytes,
        "freed_formatted": format_bytes(freed_bytes),
        "cache_freed_bytes": cache_freed_bytes,
        "cache_freed_formatted": format_bytes(cache_freed_bytes),
        "before": before,
        "after": after,
        "processes_trimmed": working_sets_cleaned,
        "nt_success": nt_success,
        "is_admin": is_admin(),
        "foreground_protected": foreground_pid > 0
    }

# -----------------------------------------------------------------------------
# Advanced Disk Health & S.M.A.R.T Metrics
# -----------------------------------------------------------------------------

_cached_disks_smart = None
_cached_disks_smart_time = 0

def get_disks_health_smart(force_refresh: bool = False) -> list:
    """
    Retrieve comprehensive S.M.A.R.T health data, temperature, wear level,
    and operational status for all physical disks.
    Cached for 10 seconds to eliminate redundant PowerShell overhead.
    """
    global _cached_disks_smart, _cached_disks_smart_time
    now = time.time()
    if not force_refresh and _cached_disks_smart is not None and (now - _cached_disks_smart_time < 10.0):
        return _cached_disks_smart

    results = []
    try:
        # 1. Fetch partition mapping (which drive letters belong to which disk)
        part_map = {}
        try:
            out_part = run_powershell_hidden('Get-Partition | Where-Object DriveLetter | Select-Object DriveLetter, DiskNumber | ConvertTo-Json -Compress', timeout=5)
            if out_part:
                parts = json.loads(out_part)
                if isinstance(parts, dict): parts = [parts]
                for p in parts:
                    dnum = str(p.get('DiskNumber', ''))
                    dl = str(p.get('DriveLetter', '')).upper()
                    if dnum:
                        part_map.setdefault(dnum, []).append(dl)
        except Exception:
            pass

        # 2. Fetch Physical Disks
        out_disk = run_powershell_hidden('Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, OperationalStatus, HealthStatus, Size | ConvertTo-Json -Compress', timeout=5)
        disks = []
        if out_disk:
            disks = json.loads(out_disk)
            if isinstance(disks, dict): disks = [disks]

        # 3. If Admin, query Storage Reliability Counters (Temperature, Wear, PowerOnHours, Errors)
        reliability = {}
        if is_admin():
            try:
                out_rel = run_powershell_hidden('Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId, Temperature, Wear, PowerOnHours, ReadErrorsTotal, WriteErrorsTotal | ConvertTo-Json -Compress', timeout=6)
                if out_rel:
                    rels = json.loads(out_rel)
                    if isinstance(rels, dict): rels = [rels]
                    for r in rels:
                        did = str(r.get('DeviceId', ''))
                        if did:
                            reliability[did] = r
            except Exception:
                pass

        # 4. Construct unified disk health objects
        for d in disks:
            did = str(d.get('DeviceId', ''))
            model = str(d.get('FriendlyName', f'Disk {did}')).strip()
            media = str(d.get('MediaType', 'SSD')).strip()
            bus = str(d.get('BusType', 'NVMe')).strip()
            full_type = f"{bus} {media}".strip() if bus and bus != 'Unknown' else media
            health = str(d.get('HealthStatus', 'Healthy')).strip()
            op_status = str(d.get('OperationalStatus', 'OK')).strip()
            sz = int(d.get('Size', 0) or 0)
            drives = part_map.get(did, [])

            rel_data = reliability.get(did, {})
            temp = rel_data.get('Temperature')
            wear = rel_data.get('Wear')
            power_hours = rel_data.get('PowerOnHours')
            read_errors = rel_data.get('ReadErrorsTotal')

            # Calculate remaining life %
            remaining_life = None
            if wear is not None:
                remaining_life = max(0, 100 - int(wear))

            # Temperature status
            temp_status = "normal"
            if temp is not None:
                if temp >= 70:
                    temp_status = "danger"
                elif temp >= 55:
                    temp_status = "warning"
                else:
                    temp_status = "good"

            results.append({
                "device_id": did,
                "name": model,
                "media_type": media,
                "bus_type": bus,
                "full_type": full_type,
                "health_status": health,
                "operational_status": op_status,
                "is_healthy": health.lower() in ("healthy", "ok"),
                "size_bytes": sz,
                "size_formatted": format_bytes(sz),
                "drives": drives,
                "can_trim": "ssd" in media.lower() or "nvme" in bus.lower(),
                "temperature": temp,
                "temperature_status": temp_status,
                "wear_percent": wear,
                "remaining_life_percent": remaining_life,
                "power_on_hours": power_hours,
                "read_errors": read_errors,
                "has_admin_metrics": bool(rel_data)
            })

    except Exception as e:
        print(f"[Warning] get_disks_health_smart failed: {e}")

    _cached_disks_smart = results
    _cached_disks_smart_time = now
    return results

# -----------------------------------------------------------------------------
# Persistent Settings & Windows Startup Management
# -----------------------------------------------------------------------------

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    _CORE_BASE_DIR = sys._MEIPASS
else:
    _CORE_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_DIR = os.path.join(os.getenv("APPDATA") or _CORE_BASE_DIR, "CleanPCMaster")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")

DEFAULT_SETTINGS = {
    "auto_clean_ram_enabled": False,
    "clean_threshold_pct": 80.0,
    "cooldown_sec": 180.0,
    "pause_in_game": True,
    "purge_standby": True,
    "empty_working_sets": True,
    "flush_modified": True,
    "skip_foreground": True,
    "start_with_windows": False
}

def load_settings() -> dict:
    """Load settings from persistent JSON file."""
    settings = dict(DEFAULT_SETTINGS)
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    settings.update(data)
    except Exception as e:
        print(f"[Settings Warning] Error reading settings: {e}")
    return settings

def save_settings(new_settings: dict) -> bool:
    """Save settings dictionary to persistent JSON file."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        current = load_settings()
        current.update(new_settings)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[Settings Warning] Error saving settings: {e}")
        return False

REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "CleanPCMaster"

def get_autostart_status() -> bool:
    """Check if CleanPC Master is configured to start with Windows."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_REG_NAME)
            if val:
                return True
    except Exception:
        pass

    try:
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        res = subprocess.run(
            ['schtasks', '/query', '/tn', APP_REG_NAME],
            capture_output=True,
            creationflags=flags
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    return False

def get_target_launch_command() -> str:
    """Returns the canonical command line string to launch CleanPC Master in tray mode."""
    if getattr(sys, 'frozen', False):
        exe_path = sys.executable
        return f'"{exe_path}" --tray'

    # If compiled standalone executable exists in dist/CleanPC_Master.exe, prefer it
    compiled_exe = os.path.join(_CORE_BASE_DIR, "dist", "CleanPC_Master.exe")
    if os.path.exists(compiled_exe):
        return f'"{compiled_exe}" --tray'

    python_exe = sys.executable
    pythonw = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
    runner = pythonw if os.path.exists(pythonw) else python_exe
    script_path = os.path.join(_CORE_BASE_DIR, "desktop.py")
    return f'"{runner}" "{script_path}" --tray'

def set_autostart(enable: bool) -> bool:
    """Register or unregister CleanPC Master from Windows startup."""
    try:
        import winreg
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        if enable:
            cmd = get_target_launch_command()

            # 1. Register in HKCU Run registry
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, cmd)
            except Exception:
                pass

            # 2. If running as Admin, also create Scheduled Task with highest privilege to ensure UAC bypass on logon
            if is_admin():
                try:
                    subprocess.run(
                        ['schtasks', '/create', '/tn', APP_REG_NAME, '/tr', cmd, '/sc', 'onlogon', '/rl', 'highest', '/f'],
                        capture_output=True,
                        creationflags=flags
                    )
                except Exception:
                    pass
        else:
            # 1. Delete from HKCU Run registry
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, APP_REG_NAME)
            except FileNotFoundError:
                pass
            except Exception:
                pass

            # 2. Delete schtasks if exists
            try:
                subprocess.run(
                    ['schtasks', '/delete', '/tn', APP_REG_NAME, '/f'],
                    capture_output=True,
                    creationflags=flags
                )
            except Exception:
                pass

        save_settings({"start_with_windows": enable})
        return get_autostart_status()
    except Exception as e:
        print(f"[Autostart Error]: {e}")
        return get_autostart_status()

def sync_autostart_target() -> None:
    """
    Self-healing startup synchronizer:
    Ensures that if 'start_with_windows' is enabled, both Registry and Task Scheduler
    point to the exact active executable (CleanPC_Master.exe) rather than obsolete versioned files.
    """
    try:
        settings = load_settings()
        if not settings.get("start_with_windows", False):
            return

        expected_cmd = get_target_launch_command()
        need_update = False

        # 1. Check HKCU Run registry value
        current_reg_val = None
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ) as key:
                current_reg_val, _ = winreg.QueryValueEx(key, APP_REG_NAME)
        except Exception:
            pass

        # 2. Check Task Scheduler
        flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0x08000000
        schtask_cmd = None
        try:
            res = subprocess.run(
                ['schtasks', '/query', '/tn', APP_REG_NAME, '/fo', 'LIST', '/v'],
                capture_output=True,
                text=True,
                creationflags=flags
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "Task To Run:" in line:
                        schtask_cmd = line.split("Task To Run:", 1)[1].strip()
                        break
        except Exception:
            pass

        # Check for discrepancies or obsolete versions (e.g., _v1.1.exe, _v1.2.exe)
        for check_cmd in [current_reg_val, schtask_cmd]:
            if check_cmd:
                if "_v1." in check_cmd:
                    need_update = True
                    break
                parts = check_cmd.split('"')
                raw_path = parts[1] if len(parts) > 1 else check_cmd.split()[0]
                if not os.path.exists(raw_path):
                    need_update = True
                    break

        if is_admin() and schtask_cmd and schtask_cmd.lower() != expected_cmd.lower():
            need_update = True
        elif current_reg_val and current_reg_val.lower() != expected_cmd.lower():
            need_update = True

        if need_update:
            print(f"[Autostart] Self-healing startup target -> {expected_cmd}")
            set_autostart(True)
    except Exception as e:
        print(f"[Autostart sync warning]: {e}")

# -----------------------------------------------------------------------------
# Zero-Lag Background Real-Time Memory Daemon
# -----------------------------------------------------------------------------

class MemoryAutoCleanDaemon:
    """
    Ultra-lightweight background thread that monitors RAM usage and auto-cleans
    when memory exceeds threshold, enforcing gaming mode and cooldown protection.
    Persists configuration across application restarts.
    """
    def __init__(self):
        settings = load_settings()
        self.enabled = bool(settings.get("auto_clean_ram_enabled", False))
        self.threshold_pct = float(settings.get("clean_threshold_pct", 80.0))
        self.interval_sec = 2.0
        self.cooldown_sec = float(settings.get("cooldown_sec", 180.0))
        self.pause_in_game = bool(settings.get("pause_in_game", True))
        self.purge_standby = bool(settings.get("purge_standby", True))
        self.empty_working_sets = bool(settings.get("empty_working_sets", True))
        self.flush_modified = bool(settings.get("flush_modified", True))
        self.skip_foreground = bool(settings.get("skip_foreground", True))
        self.last_clean_time = 0.0
        self.last_freed_formatted = "0 B"
        self.clean_count = 0
        self.is_running = True
        self.lock = threading.Lock()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self):
        # Set thread priority to IDLE to ensure ZERO impact on system/gaming
        try:
            THREAD_PRIORITY_IDLE = -15
            h_thread = _kernel32.GetCurrentThread()
            _kernel32.SetThreadPriority(h_thread, THREAD_PRIORITY_IDLE)
        except Exception:
            pass

        while self.is_running:
            time.sleep(self.interval_sec)
            with self.lock:
                if not self.enabled:
                    continue
                cooldown = self.cooldown_sec
                pause_game = self.pause_in_game
                threshold = self.threshold_pct
                last_time = self.last_clean_time
                purge_standby = self.purge_standby
                empty_working_sets = self.empty_working_sets
                flush_modified = self.flush_modified
                skip_foreground = self.skip_foreground

            # 1. Check if user is in gaming or fullscreen mode
            if pause_game and is_gaming_or_fullscreen():
                continue

            # 2. Check cooldown
            now = time.time()
            if now - last_time < cooldown:
                continue

            # 3. Check memory status
            try:
                mem = get_memory_status()
                if mem["used_percent"] >= threshold:
                    res = clean_memory(
                        purge_standby=purge_standby,
                        empty_working_sets=empty_working_sets,
                        flush_modified=flush_modified,
                        skip_foreground=skip_foreground
                    )
                    with self.lock:
                        self.last_clean_time = now
                        self.last_freed_formatted = res.get("freed_formatted", "0 B")
                        self.clean_count += 1
            except Exception as e:
                print(f"[MemoryDaemon Warning]: {e}")

    def get_config(self) -> dict:
        with self.lock:
            return {
                "enabled": self.enabled,
                "threshold_pct": self.threshold_pct,
                "cooldown_sec": self.cooldown_sec,
                "pause_in_game": self.pause_in_game,
                "purge_standby": self.purge_standby,
                "empty_working_sets": self.empty_working_sets,
                "flush_modified": self.flush_modified,
                "skip_foreground": self.skip_foreground,
                "last_clean_time": self.last_clean_time,
                "last_clean_str": datetime.datetime.fromtimestamp(self.last_clean_time).strftime("%H:%M:%S") if self.last_clean_time > 0 else "Chưa kích hoạt",
                "last_freed_formatted": self.last_freed_formatted,
                "clean_count": self.clean_count
            }

    def update_config(self, enabled=None, threshold_pct=None, cooldown_sec=None, pause_in_game=None,
                      purge_standby=None, empty_working_sets=None, flush_modified=None, skip_foreground=None):
        with self.lock:
            if enabled is not None:
                self.enabled = bool(enabled)
            if threshold_pct is not None:
                self.threshold_pct = float(threshold_pct)
            if cooldown_sec is not None:
                self.cooldown_sec = float(cooldown_sec)
            if pause_in_game is not None:
                self.pause_in_game = bool(pause_in_game)
            if purge_standby is not None:
                self.purge_standby = bool(purge_standby)
            if empty_working_sets is not None:
                self.empty_working_sets = bool(empty_working_sets)
            if flush_modified is not None:
                self.flush_modified = bool(flush_modified)
            if skip_foreground is not None:
                self.skip_foreground = bool(skip_foreground)

            # Persist to disk immediately
            save_settings({
                "auto_clean_ram_enabled": self.enabled,
                "clean_threshold_pct": self.threshold_pct,
                "cooldown_sec": self.cooldown_sec,
                "pause_in_game": self.pause_in_game,
                "purge_standby": self.purge_standby,
                "empty_working_sets": self.empty_working_sets,
                "flush_modified": self.flush_modified,
                "skip_foreground": self.skip_foreground
            })
        return self.get_config()

# Global memory daemon
memory_daemon = MemoryAutoCleanDaemon()


