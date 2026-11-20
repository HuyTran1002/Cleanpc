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

def _co_init_sta():
    """Initialize COM STA on the current worker thread for Shell APIs."""
    try:
        hr = ctypes.windll.ole32.CoInitializeEx(None, 0x2)
        return hr in (0, 1)
    except Exception:
        return False

def _co_uninit(need_uninit: bool):
    if need_uninit:
        try:
            ctypes.windll.ole32.CoUninitialize()
        except Exception:
            pass

def send_to_recycle_bin(path: str) -> bool:
    """Send a file or folder to the Windows Recycle Bin."""
    if not os.path.exists(path):
        return True
    need_uninit = _co_init_sta()
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
    finally:
        _co_uninit(need_uninit)

def send_to_recycle_bin_batch(paths: list) -> bool:
    """Send multiple files/folders to the Windows Recycle Bin in a single Shell call."""
    abs_paths = [os.path.abspath(p) for p in paths if os.path.exists(p)]
    if not abs_paths:
        return True
    need_uninit = _co_init_sta()
    try:
        joined = '\0'.join(abs_paths) + '\0\0'
        buf = ctypes.create_unicode_buffer(joined)
        shfs = SHFILEOPSTRUCT()
        shfs.hwnd = None
        shfs.wFunc = FO_DELETE
        shfs.pFrom = ctypes.cast(buf, wintypes.LPCWSTR)
        shfs.pTo = None
        shfs.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(shfs))
        return result == 0 and not shfs.fAnyOperationsAborted
    except Exception as e:
        print(f"[Error] send_to_recycle_bin_batch ({len(abs_paths)} items): {e}")
        return False
    finally:
        _co_uninit(need_uninit)

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

        def _record_failure(fp: str, sz: int):
            nonlocal failed_files, failed_bytes
            failed_files += 1
            failed_bytes += sz
            try:
                rel = os.path.relpath(fp, base_path)
                top = rel.split(os.sep)[0]
                locked_folders[top] = locked_folders.get(top, 0) + sz
            except Exception:
                pass

        def _flush_recycle_batch(batch: list):
            nonlocal deleted_files, freed_bytes
            if not batch:
                return
            if send_to_recycle_bin_batch([fp for fp, _ in batch]):
                deleted_files += len(batch)
                freed_bytes += sum(sz for _, sz in batch)
            else:
                for fp, sz in batch:
                    ok = False
                    try:
                        ok = send_to_recycle_bin(fp)
                        if not ok:
                            ok = permanent_delete(fp)
                    except Exception:
                        ok = False
                    if ok:
                        deleted_files += 1
                        freed_bytes += sz
                    else:
                        _record_failure(fp, sz)
            batch.clear()

        try:
            # Walk bottom-up to allow directory cleanup after files are removed
            recycle_batch = []
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

                    if use_recycle_bin:
                        recycle_batch.append((file_path, sz))
                        if len(recycle_batch) >= 100:
                            _flush_recycle_batch(recycle_batch)
                    else:
                        ok = False
                        try:
                            ok = permanent_delete(file_path)
                        except Exception:
                            ok = False
                        if ok:
                            deleted_files += 1
                            freed_bytes += sz
                        else:
                            _record_failure(file_path, sz)

                if use_recycle_bin and recycle_batch:
                    _flush_recycle_batch(recycle_batch)

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
    import tempfile
    temp_dir = (os.environ.get('TEMP') or tempfile.gettempdir()).replace('\\', '\\\\')
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

def _parse_target_paths(raw_targets) -> list:
    """Split comma/semicolon target strings, expand env vars, deduplicate, and keep existing paths."""
    items = [raw_targets] if isinstance(raw_targets, str) else list(raw_targets or [])
    parsed = []
    seen = set()
    for item in items:
        for part in re.split(r'[,;]+', str(item)):
            p = os.path.expandvars(part.strip())
            if p and os.path.exists(p):
                ap = os.path.abspath(p)
                key = os.path.normcase(ap)
                if key not in seen:
                    seen.add(key)
                    parsed.append(ap)
    return parsed

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
            normalized_types = (
                {str(t).strip().lower().lstrip('.') for t in file_types if str(t).strip()}
                if file_types else None
            )
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

            parsed_targets = _parse_target_paths(target_dirs)

            if not parsed_targets:
                with self.lock:
                    self.results = []
                    self.status = "error"
                    self.is_running = False
                    self.error_message = "Không tìm thấy thư mục hoặc ổ đĩa hợp lệ để quét."
                return

            stack = parsed_targets
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
                                    if normalized_types:
                                        ext = os.path.splitext(entry.name)[1].lower().lstrip('.')
                                        if ext not in normalized_types:
                                            continue
                                    sz = st.st_size
                                    if sz > 0 and sz >= min_size_bytes:
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
    """Find top N largest files in target directory/drive(s) using ultra-fast os.scandir (default >= 100MB)."""
    stack = _parse_target_paths(target_dir)

    if not stack:
        return {"error": f"Đường dẫn {target_dir} không tồn tại", "files": []}

    found_files = []
    scanned_count = 0
    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
    skip_folders = {
        '$recycle.bin', 'system volume information', 'windows',
        'recovery', '$winreagent', '$windows.~bt', '$windows.~ws'
    }
    skip_system_files = {'pagefile.sys', 'hiberfil.sys', 'swapfile.sys', 'dumpstack.log.tmp'}

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
                                if entry.name.lower() in skip_system_files:
                                    continue
                                sz = st.st_size
                                if sz >= min_size_bytes:
                                    ext = os.path.splitext(entry.name)[1].lower().lstrip('.')
                                    mt = st.st_mtime
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


# ==============================================================================
# MODULE 8: PERFORMANCE, GPU (NVIDIA NVAPI) & COOLING OPTIMIZER
# ==============================================================================

TUNING_BACKUP_FILE = os.path.join(CONFIG_DIR, "tuning_backup.json")

_NVAPI_INITIALIZE = 0x0150E828
_NVAPI_UNLOAD = 0xD22BDD7E
_NVAPI_DRS_CREATE_SESSION = 0x0694D52E
_NVAPI_DRS_DESTROY_SESSION = 0xDAD9CFF8
_NVAPI_DRS_LOAD_SETTINGS = 0x375DBD6B
_NVAPI_DRS_SAVE_SETTINGS = 0xFCBC7E14
_NVAPI_DRS_GET_BASE_PROFILE = 0xDA8466A0
_NVAPI_DRS_GET_SETTING = 0x73BF8338
_NVAPI_DRS_SET_SETTING = 0x577DD202
_NVAPI_DRS_DELETE_PROFILE_SETTING = 0xE4A26362
_NVAPI_SETTING_NOT_FOUND = -160


class _NVDRS_BINARY_SETTING(ctypes.Structure):
    _fields_ = [
        ("valueLength", ctypes.c_uint32),
        ("valueData", ctypes.c_uint8 * 4096),
    ]


class _NVDRS_VALUE_UNION(ctypes.Union):
    _fields_ = [
        ("dwordValue", ctypes.c_uint32),
        ("binaryValue", _NVDRS_BINARY_SETTING),
        ("wszValue", ctypes.c_wchar * 2048),
    ]


class _NVDRS_SETTING(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("settingName", ctypes.c_wchar * 2048),
        ("settingId", ctypes.c_uint32),
        ("settingType", ctypes.c_int),
        ("settingLocation", ctypes.c_int),
        ("isCurrentPredefined", ctypes.c_uint32),
        ("isPredefinedValid", ctypes.c_uint32),
        ("predefinedValue", _NVDRS_VALUE_UNION),
        ("currentValue", _NVDRS_VALUE_UNION),
    ]


_NVDRS_SETTING_VER = (1 << 16) | ctypes.sizeof(_NVDRS_SETTING)


class NvDrsClient:
    """Thin ctypes wrapper for NVIDIA nvapi64.dll Driver Settings (DRS) API."""

    def __init__(self):
        self.nvapi = ctypes.WinDLL("nvapi64.dll")
        self.qi = self.nvapi.nvapi_QueryInterface
        self.qi.restype = ctypes.c_void_p
        self.qi.argtypes = [ctypes.c_uint32]

        self._init = self._fn(_NVAPI_INITIALIZE, ctypes.c_int, [])
        self._unload = self._fn(_NVAPI_UNLOAD, ctypes.c_int, [])
        self._create_session = self._fn(_NVAPI_DRS_CREATE_SESSION, ctypes.c_int, [ctypes.POINTER(ctypes.c_void_p)])
        self._destroy_session = self._fn(_NVAPI_DRS_DESTROY_SESSION, ctypes.c_int, [ctypes.c_void_p])
        self._load_settings = self._fn(_NVAPI_DRS_LOAD_SETTINGS, ctypes.c_int, [ctypes.c_void_p])
        self._save_settings = self._fn(_NVAPI_DRS_SAVE_SETTINGS, ctypes.c_int, [ctypes.c_void_p])
        self._get_base_profile = self._fn(_NVAPI_DRS_GET_BASE_PROFILE, ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
        self._get_setting = self._fn(_NVAPI_DRS_GET_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_NVDRS_SETTING)])
        self._set_setting = self._fn(_NVAPI_DRS_SET_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_NVDRS_SETTING)])
        self._del_setting = self._fn(_NVAPI_DRS_DELETE_PROFILE_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32])
        self.session = ctypes.c_void_p()
        self.profile = ctypes.c_void_p()

    def _fn(self, fid: int, restype, argtypes):
        addr = self.qi(fid)
        if not addr:
            raise RuntimeError(f"NVAPI function {hex(fid)} not found")
        return ctypes.CFUNCTYPE(restype, *argtypes)(addr)

    def __enter__(self):
        if self._init() != 0:
            raise RuntimeError("NvAPI_Initialize failed")
        if self._create_session(ctypes.byref(self.session)) != 0:
            raise RuntimeError("NvAPI_DRS_CreateSession failed")
        if self._load_settings(self.session) != 0:
            raise RuntimeError("NvAPI_DRS_LoadSettings failed")
        if self._get_base_profile(self.session, ctypes.byref(self.profile)) != 0:
            raise RuntimeError("NvAPI_DRS_GetBaseProfile failed")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.session:
            self._destroy_session(self.session)
        try:
            self._unload()
        except Exception:
            pass

    def get_dword(self, sid: int):
        s = _NVDRS_SETTING()
        s.version = _NVDRS_SETTING_VER
        rc = self._get_setting(self.session, self.profile, sid, ctypes.byref(s))
        if rc == _NVAPI_SETTING_NOT_FOUND:
            return None
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_GetSetting({hex(sid)}) failed: {rc}")
        return {"value": int(s.currentValue.dwordValue), "location": int(s.settingLocation)}

    def set_dword(self, sid: int, value: int):
        s = _NVDRS_SETTING()
        s.version = _NVDRS_SETTING_VER
        s.settingId = sid
        s.settingType = 0
        s.settingLocation = 0
        s.currentValue.dwordValue = int(value)
        rc = self._set_setting(self.session, self.profile, ctypes.byref(s))
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_SetSetting({hex(sid)}, {value}) failed: {rc}")

    def delete_setting(self, sid: int):
        rc = self._del_setting(self.session, self.profile, sid)
        if rc not in (0, _NVAPI_SETTING_NOT_FOUND):
            raise RuntimeError(f"NvAPI_DRS_DeleteProfileSetting({hex(sid)}) failed: {rc}")

    def save(self):
        rc = self._save_settings(self.session)
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_SaveSettings failed: {rc}")


_NVIDIA_PROFILE_KEYS = {
    "nv_power_mode": 0x1057EB71,
    "nv_optimus": 0x10F9DC80,
    "nv_optimus_app": 0x10F9DC81,
    "nv_max_fps": 0x10835002,
    "nv_bg_fps": 0x10835016,
    "nv_low_latency": 0x007BA09E,
    "nv_tex_quality": 0x00CE2691,
    "nv_tex_aniso": 0x00E73211,
    "nv_tex_trilinear": 0x002ECAF2,
    "nv_refresh_rate": 0x0064B541,
    "nv_vsync": 0x00A879CF,
}

_POWER_SETTING_GUIDS = {
    "PROCTHROTTLEMIN": ("SUB_PROCESSOR", "893dee8e-2bef-41e0-89c6-b55d0929964c"),
    "PROCTHROTTLEMAX": ("SUB_PROCESSOR", "bc5038f7-23e0-4960-96da-33abaf5935ec"),
    "PERFBOOSTMODE": ("SUB_PROCESSOR", "be337238-0d82-4146-a960-4f3749d470c7"),
    "PROCFREQMAX": ("SUB_PROCESSOR", "75b0ae3f-bce0-45a7-8c89-c9611c25e100"),
    "PROCFREQMAX1": ("SUB_PROCESSOR", "75b0ae3f-bce0-45a7-8c89-c9611c25e101"),
    "ASPM": ("SUB_PCIEXPRESS", "ee12f906-d277-404b-b6da-e5fa1a576df5"),
    "INTEL_GFX": ("44f3beca-a7c0-460e-9df2-bb8b99e0cba6", "3619c3f2-afb2-4afc-b0e9-e7fef372de36"),
}

_REG_PATHS = {
    "gfx_drivers": (True, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"),
    "game_bar": (False, r"Software\Microsoft\GameBar"),
    "game_cfg": (False, r"System\GameConfigStore"),
    "game_dvr": (False, r"Software\Microsoft\Windows\CurrentVersion\GameDVR"),
    "gpu_pref": (False, r"Software\Microsoft\DirectX\UserGpuPreferences"),
    "personalize": (False, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
    "uwp_bg": (False, r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"),
    "edge_policy": (True, r"SOFTWARE\Policies\Microsoft\Edge"),
    "chrome_policy": (True, r"SOFTWARE\Policies\Google\Chrome"),
}

_TUNING_GROUPS = [
    {"id": "nvidia", "title": "Card Đồ Họa NVIDIA (Global Profile)", "subtitle": "Kiểm soát nguồn điện, FPS, Optimus và độ trễ ngay ở tầng driver NVAPI"},
    {"id": "power", "title": "CPU, PCIe & Intel iGPU Power Plan", "subtitle": "Tối ưu riêng cho lúc cắm sạc (mượt) và dùng pin (mát, bền pin)"},
    {"id": "windows", "title": "Windows Gaming & Tiết Kiệm Tài Nguyên Nền", "subtitle": "HAGS, Game Mode, VRR và tắt các tiến trình/hiệu ứng chạy ngầm"},
]


def _winreg_root(is_hklm: bool):
    import winreg
    return winreg.HKEY_LOCAL_MACHINE if is_hklm else winreg.HKEY_CURRENT_USER


def _reg_read(path_key: str, value_name: str, default=None):
    import winreg
    is_hklm, subkey = _REG_PATHS[path_key]
    try:
        with winreg.OpenKey(_winreg_root(is_hklm), subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
    except OSError:
        return default


def _reg_write_dword(path_key: str, value_name: str, value: int):
    import winreg
    is_hklm, subkey = _REG_PATHS[path_key]
    with winreg.CreateKeyEx(_winreg_root(is_hklm), subkey, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, int(value))


def _reg_write_str(path_key: str, value_name: str, value: str):
    import winreg
    is_hklm, subkey = _REG_PATHS[path_key]
    with winreg.CreateKeyEx(_winreg_root(is_hklm), subkey, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(value))


def _reg_delete_value(path_key: str, value_name: str):
    import winreg
    is_hklm, subkey = _REG_PATHS[path_key]
    try:
        with winreg.OpenKey(_winreg_root(is_hklm), subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
    except OSError:
        pass


def _merge_dx_global_settings(existing: str, enable_vrr: bool) -> str:
    """Update SwapEffectUpgradeEnable & VRROptimizeEnable without clobbering other DirectX flags."""
    pairs = {}
    if existing:
        for chunk in str(existing).split(";"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                k = k.strip()
                if k:
                    pairs[k] = v.strip()
    target = "1" if enable_vrr else "0"
    pairs["SwapEffectUpgradeEnable"] = "1" if enable_vrr else pairs.get("SwapEffectUpgradeEnable", "1")
    pairs["VRROptimizeEnable"] = target
    return ";".join(f"{k}={v}" for k, v in pairs.items()) + ";"


def _run_powercfg(args: list, timeout: int = 5) -> str:
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0x08000000
    res = subprocess.run(
        ["powercfg"] + args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=flags,
        timeout=timeout,
    )
    if res.returncode != 0 and args[:1] != ["-attributes"]:
        raise RuntimeError(res.stderr.strip() or res.stdout.strip() or f"powercfg {args[0]} failed")
    return res.stdout


def _query_powercfg_all() -> dict:
    """Parse current active scheme name and AC/DC values for tracked power settings in one call."""
    out = _run_powercfg(["/qh", "SCHEME_CURRENT"], timeout=6)
    scheme_name = "Balanced"
    m_scheme = re.search(r"Power Scheme GUID:\s*[0-9a-fA-F-]+\s*\((.+?)\)", out)
    if m_scheme:
        scheme_name = m_scheme.group(1).strip()

    guid_to_key = {guid.lower(): key for key, (_, guid) in _POWER_SETTING_GUIDS.items()}
    values = {key: {"ac": None, "dc": None} for key in _POWER_SETTING_GUIDS}
    current_key = None

    for line in out.splitlines():
        m_guid = re.search(r"Power Setting GUID:\s*([0-9a-fA-F-]{36})", line)
        if m_guid:
            current_key = guid_to_key.get(m_guid.group(1).lower())
            continue
        if not current_key:
            continue
        m_ac = re.search(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)", line)
        if m_ac:
            values[current_key]["ac"] = int(m_ac.group(1), 16)
            continue
        m_dc = re.search(r"Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)", line)
        if m_dc:
            values[current_key]["dc"] = int(m_dc.group(1), 16)
            current_key = None

    return {"scheme_name": scheme_name, "values": values}


def _set_powercfg_pair(setting_key: str, ac=None, dc=None):
    sub, guid = _POWER_SETTING_GUIDS[setting_key]
    if setting_key in ("PERFBOOSTMODE", "PROCFREQMAX", "PROCFREQMAX1"):
        try:
            _run_powercfg(["-attributes", "SUB_PROCESSOR", guid, "-ATTRIB_HIDE"])
        except Exception:
            pass
    if ac is not None:
        _run_powercfg(["/setacvalueindex", "SCHEME_CURRENT", sub, guid, str(int(ac))])
    if dc is not None:
        _run_powercfg(["/setdcvalueindex", "SCHEME_CURRENT", sub, guid, str(int(dc))])
    _run_powercfg(["/setactive", "SCHEME_CURRENT"])


_SAFE_IGPU_OFFLOAD_EXES = {
    "chrome.exe", "msedge.exe", "browser.exe", "brave.exe", "opera.exe",
    "code.exe", "antigravity.exe", "idman.exe", "idmlite.exe",
    "discord.exe", "msedgewebview2.exe", "steamwebhelper.exe",
}


def _discover_offload_apps() -> list:
    """Detect installed browsers, IDEs, Discord, WebView2, and downloaders for iGPU routing."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    prog_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

    static_candidates = [
        ("Google Chrome", os.path.join(prog_files, r"Google\Chrome\Application\chrome.exe")),
        ("Microsoft Edge", os.path.join(prog_x86, r"Microsoft\Edge\Application\msedge.exe")),
        ("Cốc Cốc Browser", os.path.join(local_app, r"CocCoc\Browser\Application\browser.exe")),
        ("Brave Browser", os.path.join(prog_files, r"BraveSoftware\Brave-Browser\Application\brave.exe")),
        ("Opera Browser", os.path.join(local_app, r"Programs\Opera\opera.exe")),
        ("Visual Studio Code", os.path.join(local_app, r"Programs\Microsoft VS Code\Code.exe")),
        ("Antigravity IDE", os.path.join(local_app, r"Programs\Antigravity\Antigravity.exe")),
        ("Antigravity IDE", os.path.join(prog_files, r"Antigravity\Antigravity.exe")),
        ("IDM Downloader", os.path.join(prog_x86, r"Internet Download Manager\IDMan.exe")),
    ]

    found = {}
    for label, path in static_candidates:
        if path and os.path.isfile(path):
            found[path.lower()] = (label, path)

    for pattern, label in [
        (os.path.join(local_app, r"Discord\app-*\Discord.exe"), "Discord"),
        (os.path.join(prog_x86, r"Microsoft\EdgeWebView\Application\*\msedgewebview2.exe"), "Edge WebView2 Runtime"),
    ]:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                found[path.lower()] = (label, path)

    # Read UserGpuPreferences only for known safe 2D/background apps (never hijack games onto iGPU)
    import winreg
    existing_prefs = {}
    try:
        _, subkey = _REG_PATHS["gpu_pref"]
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, idx)
                    idx += 1
                    if name.lower().endswith(".exe"):
                        existing_prefs[name.lower()] = (name, str(val))
                        if (
                            name.lower() not in found
                            and os.path.basename(name).lower() in _SAFE_IGPU_OFFLOAD_EXES
                            and os.path.isfile(name)
                        ):
                            found[name.lower()] = (os.path.basename(name), name)
                except OSError:
                    break
    except OSError:
        pass

    apps = []
    for norm_path, (label, path) in sorted(found.items(), key=lambda kv: kv[1][0].lower()):
        pref_val = existing_prefs.get(norm_path, (path, ""))[1]
        is_igpu = "GpuPreference=1" in pref_val
        apps.append({
            "name": label,
            "exe_name": os.path.basename(path),
            "path": path,
            "current_pref": pref_val or "Mặc định Windows",
            "is_igpu": is_igpu,
        })
    return apps


def _ensure_games_high_perf_gpu() -> int:
    """Route detected games to High-Performance dGPU (GpuPreference=2) and fix misrouted game EXEs."""
    import winreg
    updated = 0

    try:
        _, subkey = _REG_PATHS["gpu_pref"]
        to_fix = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, idx)
                    idx += 1
                    if name.lower().endswith(".exe"):
                        exe_base = os.path.basename(name).lower()
                        if exe_base not in _SAFE_IGPU_OFFLOAD_EXES and "gpupreference=1" in str(val).lower():
                            to_fix.append(name)
                except OSError:
                    break
        for exe_path in to_fix:
            _reg_write_str("gpu_pref", exe_path, "GpuPreference=2;")
            updated += 1
    except OSError:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"System\GameConfigStore\Children", 0, winreg.KEY_READ) as root_key:
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(root_key, idx)
                    idx += 1
                    with winreg.OpenKey(root_key, sub, 0, winreg.KEY_READ) as sk:
                        try:
                            exe_path, _ = winreg.QueryValueEx(sk, "MatchedExeFullPath")
                        except OSError:
                            continue
                    if not exe_path:
                        continue
                    exe_str = str(exe_path).strip()
                    exe_base = os.path.basename(exe_str).lower()
                    if (
                        exe_base.endswith(".exe")
                        and exe_base not in _SAFE_IGPU_OFFLOAD_EXES
                        and os.path.isfile(exe_str)
                    ):
                        cur_pref = str(_reg_read("gpu_pref", exe_str, "") or "")
                        if "GpuPreference=2;" not in cur_pref:
                            _reg_write_str("gpu_pref", exe_str, "GpuPreference=2;")
                            updated += 1
                except OSError:
                    break
    except OSError:
        pass

    return updated


def _get_display_refresh_hz() -> int:
    """Detect highest active monitor refresh rate (Hz) across all connected displays."""
    class _DISPLAY_DEVICEW(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("DeviceName", ctypes.c_wchar * 32),
            ("DeviceString", ctypes.c_wchar * 128),
            ("StateFlags", ctypes.c_uint32),
            ("DeviceID", ctypes.c_wchar * 128),
            ("DeviceKey", ctypes.c_wchar * 128),
        ]

    class _DEVMODEW(ctypes.Structure):
        _fields_ = [
            ("dmDeviceName", ctypes.c_wchar * 32),
            ("dmSpecVersion", ctypes.c_uint16),
            ("dmDriverVersion", ctypes.c_uint16),
            ("dmSize", ctypes.c_uint16),
            ("dmDriverExtra", ctypes.c_uint16),
            ("dmFields", ctypes.c_uint32),
            ("dmPositionX", ctypes.c_int32),
            ("dmPositionY", ctypes.c_int32),
            ("dmDisplayOrientation", ctypes.c_uint32),
            ("dmDisplayFixedOutput", ctypes.c_uint32),
            ("dmColor", ctypes.c_int16),
            ("dmDuplex", ctypes.c_int16),
            ("dmYResolution", ctypes.c_int16),
            ("dmTTOption", ctypes.c_int16),
            ("dmCollate", ctypes.c_int16),
            ("dmFormName", ctypes.c_wchar * 32),
            ("dmLogPixels", ctypes.c_uint16),
            ("dmBitsPerPel", ctypes.c_uint32),
            ("dmPelsWidth", ctypes.c_uint32),
            ("dmPelsHeight", ctypes.c_uint32),
            ("dmDisplayFlags", ctypes.c_uint32),
            ("dmDisplayFrequency", ctypes.c_uint32),
        ]

    max_hz = 0
    try:
        user32 = ctypes.windll.user32
        dd = _DISPLAY_DEVICEW()
        dd.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
        idx = 0
        while user32.EnumDisplayDevicesW(None, idx, ctypes.byref(dd), 0):
            idx += 1
            # DISPLAY_DEVICE_ACTIVE = 0x1
            if dd.StateFlags & 0x1:
                dm = _DEVMODEW()
                dm.dmSize = ctypes.sizeof(_DEVMODEW)
                if user32.EnumDisplaySettingsW(dd.DeviceName, -1, ctypes.byref(dm)):
                    max_hz = max(max_hz, int(dm.dmDisplayFrequency))
        if max_hz == 0:
            dm = _DEVMODEW()
            dm.dmSize = ctypes.sizeof(_DEVMODEW)
            if user32.EnumDisplaySettingsW(None, -1, ctypes.byref(dm)):
                max_hz = int(dm.dmDisplayFrequency)
    except Exception:
        pass
    return max_hz


def _get_display_mux_info() -> dict:
    """Inspect active vs. available GPUs via EnumDisplayDevicesW to detect MUX dGPU lock and iGPU vendor."""
    class _DISPLAY_DEVICEW(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("DeviceName", ctypes.c_wchar * 32),
            ("DeviceString", ctypes.c_wchar * 128),
            ("StateFlags", ctypes.c_uint32),
            ("DeviceID", ctypes.c_wchar * 128),
            ("DeviceKey", ctypes.c_wchar * 128),
        ]

    active_primary = ""
    active_any = ""
    seen_adapters = []
    try:
        user32 = ctypes.windll.user32
        dd = _DISPLAY_DEVICEW()
        dd.cb = ctypes.sizeof(_DISPLAY_DEVICEW)
        idx = 0
        while user32.EnumDisplayDevicesW(None, idx, ctypes.byref(dd), 0):
            idx += 1
            name = (dd.DeviceString or "").strip()
            if name and name not in seen_adapters:
                seen_adapters.append(name)
            flags = int(dd.StateFlags)
            if (flags & 0x5) == 0x5 and not active_primary:
                active_primary = name
            if (flags & 0x1) and not active_any:
                active_any = name
    except Exception:
        pass

    active_gpu = active_primary or active_any
    has_nvidia = any("nvidia" in a.lower() for a in seen_adapters)
    igpu_name = next(
        (
            a for a in seen_adapters
            if "intel" in a.lower() or (("amd" in a.lower() or "radeon" in a.lower()) and has_nvidia)
        ),
        "",
    )
    has_igpu = bool(igpu_name)
    if igpu_name:
        low = igpu_name.lower()
        igpu_short = "Intel iGPU" if "intel" in low else ("AMD iGPU" if ("amd" in low or "radeon" in low) else "iGPU")
    else:
        igpu_short = "iGPU"

    dgpu_only_active = bool(has_nvidia and has_igpu and "nvidia" in active_gpu.lower())
    if dgpu_only_active:
        mode_label = "NVIDIA GPU only (Khóa card rời)"
    elif has_nvidia and has_igpu:
        mode_label = "Optimus / Hybrid iGPU"
    else:
        mode_label = active_gpu or "Mặc định"

    return {
        "active_gpu": active_gpu,
        "has_nvidia": has_nvidia,
        "has_igpu": has_igpu,
        "igpu_name": igpu_name,
        "igpu_short": igpu_short,
        "dgpu_only_active": dgpu_only_active,
        "mode_label": mode_label,
    }


class _SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", ctypes.c_uint32),
        ("BatteryFullLifeTime", ctypes.c_uint32),
    ]


def _get_hardware_profile(telemetry: dict = None, display_mux: dict = None) -> dict:
    """Detect machine form factor (Laptop vs Desktop PC), CPU/GPU class, and dynamic AI tuning targets."""
    import winreg
    is_laptop = False
    ac_plugged = True
    try:
        sps = _SYSTEM_POWER_STATUS()
        if _kernel32.GetSystemPowerStatus(ctypes.byref(sps)):
            is_laptop = sps.BatteryFlag not in (128, 255)
            ac_plugged = (sps.ACLineStatus == 1)
    except Exception:
        pass

    cpu_name = "CPU Windows"
    cpu_base_mhz = 0
    logical_cores = os.cpu_count() or 0
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            winreg.KEY_READ,
        ) as key:
            val_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            cpu_name = " ".join(str(val_name).split())
            try:
                val_mhz, _ = winreg.QueryValueEx(key, "~MHz")
                cpu_base_mhz = int(val_mhz)
            except OSError:
                pass
    except OSError:
        pass

    low_cpu = cpu_name.lower()
    if "intel" in low_cpu:
        cpu_vendor = "Intel"
    elif "amd" in low_cpu or "ryzen" in low_cpu or "athlon" in low_cpu or "epyc" in low_cpu:
        cpu_vendor = "AMD"
    else:
        cpu_vendor = "Unknown"

    is_u_series = bool(re.search(r"(\d{4,5}u\b|\bu\d{3,4}\b)", low_cpu))
    is_high_perf_cpu = bool(
        re.search(r"(i[579]-|ryzen\s*[579]|core\(tm\)\s*ultra|\d{4,5}h[xk]?|\d{4,5}hs)", low_cpu)
    ) and not is_u_series
    is_high_perf_laptop = bool(is_laptop and is_high_perf_cpu)

    gpu_name = ((telemetry or {}).get("name") or "").lower()
    is_rtx_40_plus = bool(re.search(r"rtx\s*[45]\d{3}", gpu_name))
    has_nvidia = bool((display_mux or {}).get("has_nvidia") or (telemetry or {}).get("available"))
    has_igpu = bool((display_mux or {}).get("has_igpu"))
    dgpu_only = bool((display_mux or {}).get("dgpu_only_active"))

    if not is_laptop:
        form_factor_label = "Desktop PC (Máy bàn)"
    elif is_high_perf_laptop:
        form_factor_label = "Laptop Gaming / Hiệu năng cao"
    else:
        form_factor_label = "Laptop Văn phòng / Mỏng nhẹ"

    if is_high_perf_laptop and cpu_base_mhz >= 2000:
        recommended_freq_cap = max(3600, min(4000, int(round((cpu_base_mhz + 900) / 100.0) * 100)))
    elif is_high_perf_laptop:
        recommended_freq_cap = 3800
    else:
        recommended_freq_cap = 0

    recommended_hags = bool(is_rtx_40_plus)
    recommended_boost_dc = bool(is_laptop and not has_nvidia)
    recommended_max_dc = 85 if (is_laptop and not has_nvidia) else 100
    can_offload_igpu = bool(has_nvidia and has_igpu and not dgpu_only)

    return {
        "cpu_name": cpu_name,
        "cpu_vendor": cpu_vendor,
        "cpu_base_mhz": cpu_base_mhz,
        "logical_cores": logical_cores,
        "is_laptop": is_laptop,
        "ac_plugged": ac_plugged,
        "is_high_perf_laptop": is_high_perf_laptop,
        "is_rtx_40_plus": is_rtx_40_plus,
        "has_nvidia": has_nvidia,
        "has_igpu": has_igpu,
        "dgpu_only": dgpu_only,
        "form_factor_label": form_factor_label,
        "recommended_freq_cap": recommended_freq_cap,
        "recommended_hags": recommended_hags,
        "recommended_boost_dc": recommended_boost_dc,
        "recommended_max_dc": recommended_max_dc,
        "can_offload_igpu": can_offload_igpu,
    }


def _recommended_max_fps(refresh_hz: int) -> int:
    """Calculate optimal G-Sync/VRR FPS cap (3 FPS below active panel max Hz)."""
    if refresh_hz >= 75:
        return refresh_hz - 3
    if refresh_hz > 0:
        return refresh_hz
    return 162


def _build_fps_options(refresh_hz: int, rec_fps: int, current_val: int) -> list:
    """Build dynamic Max Frame Rate options tailored to the active display Hz."""
    base_values = {0, 60, 120, 144, 165, 240, rec_fps}
    if refresh_hz > 0:
        base_values.add(refresh_hz)
    if current_val >= 0:
        base_values.add(current_val)
    options = []
    for val in sorted(base_values):
        if val == 0:
            label = "Tắt (Không giới hạn - Khuyên dùng)"
        elif val == 60:
            label = "60 FPS (Siêu mát)"
        elif val == rec_fps:
            hz_lbl = refresh_hz or (rec_fps + 3)
            label = f"{val} FPS ({hz_lbl}Hz G-Sync)"
        else:
            label = f"{val} FPS"
        options.append({"value": val, "label": label})
    return options


def get_tuning_telemetry() -> dict:
    """Lightweight live GPU + display Hz payload for 2-second UI polling."""
    return {
        "telemetry": _get_nvidia_telemetry(),
        "display_hz": _get_display_refresh_hz(),
    }


def _get_nvidia_telemetry() -> dict:
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0x08000000
    info = {
        "available": False,
        "name": "Không phát hiện NVIDIA GPU",
        "pstate": "-",
        "temp_c": None,
        "power_w": None,
        "clock_mhz": None,
        "mem_clock_mhz": None,
        "util_pct": None,
    }
    try:
        res = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,pstate,temperature.gpu,power.draw,clocks.gr,clocks.mem,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=flags,
            timeout=3,
        )
        if res.returncode == 0 and res.stdout.strip():
            parts = [p.strip() for p in res.stdout.strip().splitlines()[0].split(",")]
            if len(parts) >= 6:
                def _num(s):
                    try:
                        return float(s) if "N/A" not in s else None
                    except ValueError:
                        return None

                info.update({
                    "available": True,
                    "name": parts[0],
                    "pstate": parts[1],
                    "temp_c": _num(parts[2]),
                    "power_w": _num(parts[3]),
                    "clock_mhz": _num(parts[4]),
                    "mem_clock_mhz": _num(parts[5]),
                    "util_pct": _num(parts[6]) if len(parts) >= 7 else None,
                })
    except Exception:
        pass
    return info


def _read_nvdrs_raw(sids: list) -> tuple:
    """Read current NVDRS DWORDs in one session. Returns (available_bool, dict_of_sid_to_entry)."""
    try:
        with NvDrsClient() as drs:
            return True, {sid: drs.get_dword(sid) for sid in sids}
    except Exception:
        return False, {}


def _write_nvdrs_updates(updates: dict):
    """Apply {sid: value_or_none} via NVAPI DRS and save nvdrsdb."""
    with NvDrsClient() as drs:
        for sid, val in updates.items():
            if val is None:
                drs.delete_setting(sid)
            else:
                drs.set_dword(sid, int(val))
        drs.save()


def _ensure_tuning_backup():
    """Capture original system & NVIDIA settings once before CleanPC Master modifies them."""
    if os.path.exists(TUNING_BACKUP_FILE):
        return
    os.makedirs(CONFIG_DIR, exist_ok=True)
    power = _query_powercfg_all()["values"]
    nv_ok, nv_raw = _read_nvdrs_raw(list(_NVIDIA_PROFILE_KEYS.values()))
    apps = _discover_offload_apps()
    app_backup = {app["path"]: _reg_read("gpu_pref", app["path"], None) for app in apps}
    backup = {
        "timestamp": datetime.datetime.now().isoformat(),
        "power": power,
        "nvidia_available": nv_ok,
        "nvidia": {hex(sid): entry for sid, entry in nv_raw.items()},
        "registry": {
            "HwSchMode": _reg_read("gfx_drivers", "HwSchMode", None),
            "AutoGameModeEnabled": _reg_read("game_bar", "AutoGameModeEnabled", None),
            "AllowAutoGameMode": _reg_read("game_bar", "AllowAutoGameMode", None),
            "GameDVR_Enabled": _reg_read("game_cfg", "GameDVR_Enabled", None),
            "AppCaptureEnabled": _reg_read("game_dvr", "AppCaptureEnabled", None),
            "DirectXUserGlobal": _reg_read("gpu_pref", "DirectXUserGlobalSettings", None),
            "EnableTransparency": _reg_read("personalize", "EnableTransparency", None),
            "UwpGlobalUserDisabled": _reg_read("uwp_bg", "GlobalUserDisabled", None),
            "EdgeBackgroundModeEnabled": _reg_read("edge_policy", "BackgroundModeEnabled", None),
            "EdgeStartupBoostEnabled": _reg_read("edge_policy", "StartupBoostEnabled", None),
            "ChromeBackgroundMode": _reg_read("chrome_policy", "BackgroundModeEnabled", None),
            "AppGpuPreferences": app_backup,
        },
    }
    with open(TUNING_BACKUP_FILE, "w", encoding="utf-8") as f:
        json.dump(backup, f, indent=2, ensure_ascii=False)


def _apply_setting_action(setting_id: str, value) -> dict:
    """Execute one setting update and return metadata about whether reboot/admin is required."""
    requires_reboot = False

    # NVIDIA Global Profile settings
    if setting_id in ("nv_max_fps", "nv_bg_fps"):
        iv = int(value)
        _write_nvdrs_updates({_NVIDIA_PROFILE_KEYS[setting_id]: iv if iv > 0 else None})
    elif setting_id in ("nv_power_mode", "nv_tex_quality", "nv_vsync"):
        _write_nvdrs_updates({_NVIDIA_PROFILE_KEYS[setting_id]: int(value)})
    elif setting_id == "nv_optimus":
        val = 1 if bool(value) else 16
        _write_nvdrs_updates({0x10F9DC80: val, 0x10F9DC81: val})
    elif setting_id == "nv_low_latency":
        _write_nvdrs_updates({0x007BA09E: 1 if bool(value) else None})
    elif setting_id == "nv_tex_opt":
        val = 1 if bool(value) else 0
        _write_nvdrs_updates({0x00E73211: val, 0x002ECAF2: val})
    elif setting_id == "nv_refresh_rate":
        _write_nvdrs_updates({0x0064B541: 1 if bool(value) else 0})

    # CPU, PCIe & Intel iGPU Power Plan
    elif setting_id == "cpu_boost_ac":
        _set_powercfg_pair("PERFBOOSTMODE", ac=int(value))
    elif setting_id == "cpu_freq_cap":
        mhz = max(0, int(value))
        _set_powercfg_pair("PROCFREQMAX", ac=mhz, dc=mhz)
        _set_powercfg_pair("PROCFREQMAX1", ac=mhz, dc=mhz)
    elif setting_id == "cpu_boost_dc":
        _set_powercfg_pair("PERFBOOSTMODE", dc=(0 if bool(value) else 4))
    elif setting_id == "cpu_max_dc":
        _set_powercfg_pair("PROCTHROTTLEMAX", dc=int(value))
    elif setting_id == "pcie_aspm":
        if bool(value):
            _set_powercfg_pair("ASPM", ac=0, dc=2)
        else:
            _set_powercfg_pair("ASPM", ac=1, dc=1)
    elif setting_id == "intel_igpu_power":
        if bool(value):
            _set_powercfg_pair("INTEL_GFX", ac=2, dc=0)
        else:
            _set_powercfg_pair("INTEL_GFX", ac=1, dc=1)

    # Windows Gaming & Background Efficiency
    elif setting_id == "win_hags":
        _reg_write_dword("gfx_drivers", "HwSchMode", 2 if bool(value) else 1)
        requires_reboot = True
    elif setting_id == "win_gamemode":
        on = 1 if bool(value) else 0
        _reg_write_dword("game_bar", "AutoGameModeEnabled", on)
        _reg_write_dword("game_bar", "AllowAutoGameMode", on)
    elif setting_id == "win_gamedvr":
        off = 0 if bool(value) else 1
        _reg_write_dword("game_cfg", "GameDVR_Enabled", off)
        _reg_write_dword("game_dvr", "AppCaptureEnabled", off)
    elif setting_id == "win_vrr":
        existing = _reg_read("gpu_pref", "DirectXUserGlobalSettings", "")
        _reg_write_str("gpu_pref", "DirectXUserGlobalSettings", _merge_dx_global_settings(existing, bool(value)))
    elif setting_id == "win_transparency":
        _reg_write_dword("personalize", "EnableTransparency", 0 if bool(value) else 1)
    elif setting_id == "win_uwp_bg":
        _reg_write_dword("uwp_bg", "GlobalUserDisabled", 1 if bool(value) else 0)
    elif setting_id == "browser_bg_off":
        val = 0 if bool(value) else 1
        _reg_write_dword("edge_policy", "BackgroundModeEnabled", val)
        _reg_write_dword("edge_policy", "StartupBoostEnabled", val)
        _reg_write_dword("chrome_policy", "BackgroundModeEnabled", val)
    else:
        raise ValueError(f"Unknown tuning setting: {setting_id}")

    return {"requires_reboot": requires_reboot}


def get_system_tuning_status() -> dict:
    """Inspect live NVIDIA telemetry, power plan, Windows registry states, and iGPU app routing."""
    admin = is_admin()
    telemetry = _get_nvidia_telemetry()
    display_mux = _get_display_mux_info()
    hw = _get_hardware_profile(telemetry, display_mux)
    refresh_hz = _get_display_refresh_hz()
    rec_fps = _recommended_max_fps(refresh_hz)
    pwr = _query_powercfg_all()
    pvals = pwr["values"]

    nv_ok, nv_raw = _read_nvdrs_raw(list(_NVIDIA_PROFILE_KEYS.values()))

    def _nv_val(sid: int, default: int = 0) -> int:
        entry = nv_raw.get(sid)
        return int(entry["value"]) if entry is not None else default

    cur_max_fps = _nv_val(0x10835002, 0)
    hz_label = f"{refresh_hz}Hz" if refresh_hz else "tối đa"
    dgpu_label = telemetry["name"] if telemetry.get("available") else "card đồ họa rời"
    igpu_label = display_mux["igpu_name"] or display_mux["igpu_short"] or "iGPU"
    rec_freq_cap = hw["recommended_freq_cap"]
    rec_hags = hw["recommended_hags"]
    rec_boost_dc = hw["recommended_boost_dc"]
    rec_max_dc = hw["recommended_max_dc"]

    dx_global = str(_reg_read("gpu_pref", "DirectXUserGlobalSettings", "") or "")
    hags_val = _reg_read("gfx_drivers", "HwSchMode", 1)
    game_mode_val = _reg_read("game_bar", "AutoGameModeEnabled", 0)
    dvr_cfg = _reg_read("game_cfg", "GameDVR_Enabled", 1)
    dvr_cap = _reg_read("game_dvr", "AppCaptureEnabled", 1)
    transparency_val = _reg_read("personalize", "EnableTransparency", 1)
    uwp_bg_val = _reg_read("uwp_bg", "GlobalUserDisabled", 0)
    edge_bg = _reg_read("edge_policy", "BackgroundModeEnabled", 1)
    edge_boost = _reg_read("edge_policy", "StartupBoostEnabled", 1)
    chrome_bg = _reg_read("chrome_policy", "BackgroundModeEnabled", 1)

    p_boost_ac = pvals["PERFBOOSTMODE"]["ac"]
    p_boost_dc = pvals["PERFBOOSTMODE"]["dc"]
    p_freq_cap = pvals["PROCFREQMAX1"]["ac"] if pvals["PROCFREQMAX1"]["ac"] is not None else pvals["PROCFREQMAX"]["ac"]
    p_max_dc = pvals["PROCTHROTTLEMAX"]["dc"]
    p_aspm = pvals["ASPM"]
    p_igpu = pvals["INTEL_GFX"]

    if rec_freq_cap > 0:
        freq_cap_desc = (
            f"Điểm ngọt AI ({rec_freq_cap} MHz) tính theo base clock cho {hw['form_factor_label']} ({hw['cpu_vendor']} {hw['logical_cores']} luồng): "
            f"giữ 100% tốc độ đa nhân & FPS nhưng cắt đỉnh áp 1.40V gây nóng 97°C và Thermal Throttling."
        )
        freq_cap_optimal = (p_freq_cap is not None and p_freq_cap > 0 and abs(p_freq_cap - rec_freq_cap) <= 200)
    else:
        freq_cap_desc = (
            f"Với {hw['form_factor_label']} ({hw['cpu_vendor']} {hw['logical_cores']} luồng), AI khuyến nghị Không giới hạn (0 MHz) "
            f"để CPU bung tối đa xung nhịp."
        )
        freq_cap_optimal = (p_freq_cap == 0)

    base_freq_choices = [3500, 3800, 4000, 4200]
    if rec_freq_cap > 0 and rec_freq_cap not in base_freq_choices:
        base_freq_choices.append(rec_freq_cap)
    if p_freq_cap and p_freq_cap > 0 and p_freq_cap not in base_freq_choices:
        base_freq_choices.append(p_freq_cap)
    base_freq_choices = sorted(set(base_freq_choices))

    freq_cap_options = [
        {
            "value": 0,
            "label": "Không giới hạn (Bung max Turbo" + (" - AI Khuyên dùng)" if rec_freq_cap == 0 else " - Dễ vọt 97°C)"),
        }
    ]
    for mhz in base_freq_choices:
        ghz = mhz / 1000.0
        if rec_freq_cap == mhz:
            tag = " - Điểm ngọt AI Khuyên dùng"
        elif mhz <= 3500:
            tag = " - Siêu mát 65–72°C"
        elif mhz == 4000:
            tag = " - Hiệu năng cao"
        else:
            tag = ""
        freq_cap_options.append({"value": mhz, "label": f"{mhz} MHz ({ghz:.1f} GHz{tag})"})

    settings = [
        # Group: nvidia
        {
            "id": "nv_power_mode", "group": "nvidia", "type": "select", "requires_admin": True, "available": nv_ok,
            "label": "Chế độ nguồn NVIDIA (Power Management)",
            "desc": f"Normal giúp {dgpu_label} giảm điện áp nghỉ (~38°C) khi lướt web và tự bung max hiệu năng khi mở game.",
            "current": _nv_val(0x1057EB71, 5), "optimal": 5,
            "is_optimal": nv_ok and _nv_val(0x1057EB71, 5) == 5,
            "options": [
                {"value": 5, "label": "Normal (Khuyên dùng - Mát & Mượt)"},
                {"value": 1, "label": "Prefer Max Perf (Luôn giữ xung cao)"},
                {"value": 0, "label": "Optimal Power"},
            ],
        },
        {
            "id": "nv_optimus", "group": "nvidia", "type": "toggle", "requires_admin": True, "available": nv_ok,
            "label": "Ưu tiên card rời NVIDIA cho Game (Optimus dGPU Prefer)",
            "desc": f"Đặt Profile 3D ưu tiên {dgpu_label} cho toàn bộ game, trong khi trình duyệt và app nền đã tách riêng sang {display_mux['igpu_short']}.",
            "current": _nv_val(0x10F9DC80, 1) == 1 and _nv_val(0x10F9DC81, 1) == 1, "optimal": True,
            "is_optimal": nv_ok and _nv_val(0x10F9DC80, 1) == 1 and _nv_val(0x10F9DC81, 1) == 1,
        },
        {
            "id": "nv_max_fps", "group": "nvidia", "type": "select", "requires_admin": True, "available": nv_ok,
            "label": "Giới hạn FPS tối đa (Max Frame Rate)",
            "desc": "Không giới hạn FPS ở tầng driver (để game tự do chạy tối đa hoặc theo thiết lập trong từng game).",
            "current": cur_max_fps, "optimal": 0,
            "is_optimal": nv_ok and cur_max_fps == 0,
            "options": _build_fps_options(refresh_hz, rec_fps, cur_max_fps),
        },
        {
            "id": "nv_bg_fps", "group": "nvidia", "type": "select", "requires_admin": True, "available": nv_ok,
            "label": "Giới hạn FPS khi ẩn game / Alt-Tab (Background FPS)",
            "desc": "Tắt giới hạn để không khóa FPS khi Alt-Tab (hoặc chọn 30 FPS nếu muốn hạ nhiệt khi ẩn game).",
            "current": _nv_val(0x10835016, 0), "optimal": 0,
            "is_optimal": nv_ok and _nv_val(0x10835016, 0) == 0,
            "options": [
                {"value": 0, "label": "Tắt (Không giới hạn - Khuyên dùng)"},
                {"value": 20, "label": "20 FPS (Siêu mát)"},
                {"value": 30, "label": "30 FPS"},
                {"value": 60, "label": "60 FPS"},
            ],
        },
        {
            "id": "nv_low_latency", "group": "nvidia", "type": "toggle", "requires_admin": True, "available": nv_ok,
            "label": "NVIDIA Low Latency Mode (Giảm độ trễ chuột/phím)",
            "desc": "Tắt để giữ hàng đợi frame tiêu chuẩn, giảm tải đồng bộ cho CPU giúp hạ nhiệt khi chơi FPS cao.",
            "current": _nv_val(0x007BA09E, 0) == 1, "optimal": False,
            "is_optimal": nv_ok and _nv_val(0x007BA09E, 0) == 0,
        },
        {
            "id": "nv_tex_quality", "group": "nvidia", "type": "select", "requires_admin": True, "available": nv_ok,
            "label": "Texture Filtering - Quality",
            "desc": "Ưu tiên Performance giúp tăng độ mượt mà không làm xấu hình ảnh rõ rệt.",
            "current": _nv_val(0x00CE2691, 0), "optimal": 10,
            "is_optimal": nv_ok and _nv_val(0x00CE2691, 0) in (10, 20),
            "options": [
                {"value": 10, "label": "Performance (Khuyên dùng)"},
                {"value": 0, "label": "Quality (Mặc định)"},
                {"value": 20, "label": "High Performance"},
            ],
        },
        {
            "id": "nv_tex_opt", "group": "nvidia", "type": "toggle", "requires_admin": True, "available": nv_ok,
            "label": "Anisotropic & Trilinear Texture Optimization",
            "desc": "Bật tối ưu hóa lọc vân bề mặt để tăng FPS miễn phí ở các góc nhìn xa.",
            "current": _nv_val(0x00E73211, 0) == 1 and _nv_val(0x002ECAF2, 0) == 1, "optimal": True,
            "is_optimal": nv_ok and _nv_val(0x00E73211, 0) == 1 and _nv_val(0x002ECAF2, 0) == 1,
        },
        {
            "id": "nv_refresh_rate", "group": "nvidia", "type": "toggle", "requires_admin": True, "available": nv_ok,
            "label": "Tần số quét ưu tiên cao nhất (Highest Available)",
            "desc": f"Đảm bảo game luôn chạy đúng tần số quét tối đa của màn hình ({hz_label}).",
            "current": _nv_val(0x0064B541, 0) == 1, "optimal": True,
            "is_optimal": nv_ok and _nv_val(0x0064B541, 0) == 1,
        },
        {
            "id": "nv_vsync", "group": "nvidia", "type": "select", "requires_admin": True, "available": nv_ok,
            "label": "Vertical Sync (V-Sync Global)",
            "desc": "Để theo thiết lập từng game (Use 3D app setting) tránh khóa cứng gây tụt FPS hoặc input lag.",
            "current": _nv_val(0x00A879CF, 1620202130), "optimal": 1620202130,
            "is_optimal": nv_ok and _nv_val(0x00A879CF, 1620202130) == 1620202130,
            "options": [
                {"value": 1620202130, "label": "Theo từng game (Khuyên dùng)"},
                {"value": 1199655232, "label": "Luôn tắt (Force Off)"},
                {"value": 138504007, "label": "Luôn bật (Force On)"},
            ],
        },

        # Group: power
        {
            "id": "cpu_boost_ac", "group": "power", "type": "select", "requires_admin": True, "available": p_boost_ac is not None,
            "label": "CPU Turbo Boost khi cắm sạc (AC)",
            "desc": "Efficient Aggressive giữ đúng chuẩn Speed Shift gốc: bung 100% xung nhịp khi cần, không khóa hay giới hạn CPU.",
            "current": p_boost_ac if p_boost_ac is not None else 4, "optimal": 4,
            "is_optimal": p_boost_ac == 4,
            "options": [
                {"value": 0, "label": "Disabled (Siêu mát, không Boost)"},
                {"value": 2, "label": "Aggressive"},
                {"value": 3, "label": "Efficient Enabled"},
                {"value": 4, "label": "Efficient Aggressive (Khuyên dùng - Không giới hạn)"},
            ],
        },
        {
            "id": "cpu_freq_cap", "group": "power", "type": "select", "requires_admin": True, "available": p_freq_cap is not None,
            "label": "Trần xung nhịp Turbo CPU (P-Core & E-Core Max MHz)",
            "desc": freq_cap_desc,
            "current": p_freq_cap if p_freq_cap is not None else 0, "optimal": rec_freq_cap,
            "is_optimal": freq_cap_optimal,
            "options": freq_cap_options,
        },
        {
            "id": "cpu_boost_dc", "group": "power", "type": "toggle", "requires_admin": True, "available": bool(hw["is_laptop"] and p_boost_dc is not None),
            "label": "Tắt CPU Turbo Boost khi dùng Pin (DC)",
            "desc": (
                f"Với {hw['form_factor_label']} (chạy iGPU), AI khuyên BẬT để tắt Turbo Boost khi dùng Pin giúp mát máy và tăng thời lượng pin."
                if rec_boost_dc
                else "Với máy có card rời NVIDIA, AI khuyên TẮT mục này để giữ Turbo Boost hoạt động bình thường cả khi dùng Pin."
            ),
            "current": p_boost_dc == 0, "optimal": rec_boost_dc,
            "is_optimal": (p_boost_dc == 0) if rec_boost_dc else (p_boost_dc is not None and p_boost_dc != 0),
        },
        {
            "id": "cpu_max_dc", "group": "power", "type": "select", "requires_admin": True, "available": bool(hw["is_laptop"] and p_max_dc is not None),
            "label": "Giới hạn hiệu năng CPU khi dùng Pin (DC)",
            "desc": (
                f"Với {hw['form_factor_label']} (không có card rời), AI khuyên giới hạn 85% khi dùng Pin để tối ưu pin & chống nóng."
                if rec_max_dc == 85
                else "Giữ 100% công suất CPU khi dùng Pin (không giới hạn hiệu năng)."
            ),
            "current": p_max_dc if p_max_dc is not None else 100, "optimal": rec_max_dc,
            "is_optimal": p_max_dc == rec_max_dc,
            "options": [
                {"value": 75, "label": "75% (Pin lâu nhất)"},
                {"value": 85, "label": "85%" + (" (AI Khuyên dùng cho Laptop văn phòng)" if rec_max_dc == 85 else "")},
                {"value": 100, "label": "100% (Không giới hạn" + (" - AI Khuyên dùng)" if rec_max_dc == 100 else ")")},
            ],
        },
        {
            "id": "pcie_aspm", "group": "power", "type": "toggle", "requires_admin": True, "available": p_aspm["ac"] is not None,
            "label": "PCIe Link State Power Management (AC Off / Pin Max Savings)",
            "desc": f"Tắt ASPM khi cắm sạc để SSD NVMe & {dgpu_label} đạt băng thông tối đa; bật Max Power Savings khi dùng pin.",
            "current": (p_aspm["ac"] == 0 and p_aspm["dc"] == 2) if hw["is_laptop"] else (p_aspm["ac"] == 0),
            "optimal": True,
            "is_optimal": (p_aspm["ac"] == 0 and p_aspm["dc"] == 2) if hw["is_laptop"] else (p_aspm["ac"] == 0),
        },
        {
            "id": "intel_igpu_power", "group": "power", "type": "toggle", "requires_admin": True,
            "available": bool(p_igpu["ac"] is not None and "intel" in (display_mux.get("igpu_name") or "").lower()),
            "label": "Intel iGPU Power Plan (AC Max Perf / Pin Max Battery)",
            "desc": f"Giúp {igpu_label} mượt ở {hz_label} khi cắm sạc và tiết kiệm điện tối đa khi dùng pin.",
            "current": p_igpu["ac"] == 2 and p_igpu["dc"] == 0, "optimal": True,
            "is_optimal": p_igpu["ac"] == 2 and p_igpu["dc"] == 0,
        },

        # Group: windows
        {
            "id": "win_hags", "group": "windows", "type": "toggle", "requires_admin": True, "available": True, "requires_reboot": True,
            "label": "Hardware-Accelerated GPU Scheduling (HAGS)",
            "desc": (
                f"Với GPU {dgpu_label} (RTX 40/50 Series), AI khuyên BẬT HAGS để kích hoạt DLSS 3/4 Frame Generation và tăng hiệu năng tối đa (cần Restart nếu thay đổi)."
                if rec_hags
                else f"Với {dgpu_label} ({hw['form_factor_label']}), AI khuyên TẮT HAGS giúp card rời hạ xung nghỉ sâu hơn (tránh kẹt P0) và không ép điện áp CPU qua Latency Hint (cần Restart nếu thay đổi)."
            ),
            "current": hags_val == 2, "optimal": rec_hags,
            "is_optimal": (hags_val == 2) if rec_hags else (hags_val != 2),
        },
        {
            "id": "win_gamemode", "group": "windows", "type": "toggle", "requires_admin": False, "available": True,
            "label": "Windows Game Mode",
            "desc": "Tắt Game Mode để bộ lập lịch hệ điều hành tự điều phối nhân xử lý mát mẻ và ổn định hơn.",
            "current": game_mode_val == 1, "optimal": False,
            "is_optimal": game_mode_val == 0,
        },
        {
            "id": "win_gamedvr", "group": "windows", "type": "toggle", "requires_admin": False, "available": True,
            "label": "Tắt quay màn hình nền Xbox Game DVR",
            "desc": "Ngăn Windows ghi hình ngầm giúp giảm giật khựng (stutter) và giải phóng bộ nhớ đệm GPU.",
            "current": dvr_cfg == 0 and dvr_cap == 0, "optimal": True,
            "is_optimal": dvr_cfg == 0 and dvr_cap == 0,
        },
        {
            "id": "win_vrr", "group": "windows", "type": "toggle", "requires_admin": False, "available": True,
            "label": "DirectX Windowed VRR & Flip Optimization",
            "desc": "Giảm độ trễ và giúp game Borderless Windowed mượt ngang Fullscreen.",
            "current": "VRROptimizeEnable=1" in dx_global and "SwapEffectUpgradeEnable=1" in dx_global, "optimal": True,
            "is_optimal": "VRROptimizeEnable=1" in dx_global and "SwapEffectUpgradeEnable=1" in dx_global,
        },
        {
            "id": "win_transparency", "group": "windows", "type": "toggle", "requires_admin": False, "available": True,
            "label": "Tắt hiệu ứng trong suốt (Transparency) của Windows",
            "desc": "Giảm đánh thức iGPU/DWM khi mở Start Menu và cửa sổ làm việc.",
            "current": transparency_val == 0, "optimal": True,
            "is_optimal": transparency_val == 0,
        },
        {
            "id": "win_uwp_bg", "group": "windows", "type": "toggle", "requires_admin": False, "available": True,
            "label": "Tắt ứng dụng Windows Store (UWP) chạy ngầm",
            "desc": "Ngăn các app nền Windows tự đánh thức CPU và tốn RAM vô ích.",
            "current": uwp_bg_val == 1, "optimal": True,
            "is_optimal": uwp_bg_val == 1,
        },
        {
            "id": "browser_bg_off", "group": "windows", "type": "toggle", "requires_admin": True, "available": True,
            "label": "Tắt Edge Startup Boost & Chrome/Edge chạy ngầm",
            "desc": "Đóng trình duyệt sẽ giải phóng sạch tiến trình nền thay vì giữ nguyên dưới khay hệ thống.",
            "current": edge_bg == 0 and edge_boost == 0 and chrome_bg == 0, "optimal": True,
            "is_optimal": edge_bg == 0 and edge_boost == 0 and chrome_bg == 0,
        },
    ]

    apps = _discover_offload_apps() if hw["can_offload_igpu"] else []
    available_settings = [s for s in settings if s["available"]]
    optimal_count = sum(1 for s in available_settings if s["is_optimal"])
    total_count = len(available_settings)
    score_pct = int(round((optimal_count / total_count) * 100)) if total_count else 100

    return {
        "is_admin": admin,
        "has_backup": os.path.exists(TUNING_BACKUP_FILE),
        "hardware_profile": hw,
        "power_scheme": pwr["scheme_name"],
        "display_hz": refresh_hz,
        "display_mux": display_mux,
        "telemetry": telemetry,
        "groups": _TUNING_GROUPS,
        "settings": settings,
        "offload_apps": apps,
        "summary": {
            "optimal_count": optimal_count,
            "total_count": total_count,
            "score_pct": score_pct,
            "offload_enabled_count": sum(1 for a in apps if a["is_igpu"]),
            "offload_total_count": len(apps),
        },
    }


def apply_system_tuning_setting(setting_id: str, value) -> dict:
    """Apply a single performance/GPU setting change after backing up original defaults."""
    _ensure_tuning_backup()
    try:
        meta = _apply_setting_action(setting_id, value)
        msg = "Đã cập nhật thiết lập."
        if meta.get("requires_reboot"):
            msg = "Đã cập nhật! Khởi động lại máy (Restart) để HAGS có hiệu lực."
        return {
            "success": True,
            "message": msg,
            "requires_reboot": meta.get("requires_reboot", False),
            "status": get_system_tuning_status(),
        }
    except PermissionError:
        return {"success": False, "need_admin": True, "error": "Thiết lập này yêu cầu quyền Administrator."}
    except Exception as e:
        err_str = str(e)
        need_adm = "access is denied" in err_str.lower() or "privilege" in err_str.lower() or not is_admin()
        return {"success": False, "need_admin": need_adm, "error": err_str}


def toggle_igpu_offload_app(exe_path: str, enabled: bool) -> dict:
    """Toggle Windows UserGpuPreferences iGPU Power Saving (GpuPreference=1) for a specific app."""
    if not exe_path:
        return {"success": False, "error": "Thiếu đường dẫn ứng dụng."}
    _ensure_tuning_backup()
    try:
        igpu_short = _get_display_mux_info().get("igpu_short", "iGPU")
        if enabled:
            _reg_write_str("gpu_pref", exe_path, "GpuPreference=1;")
        else:
            _reg_delete_value("gpu_pref", exe_path)
        return {
            "success": True,
            "message": f"Đã {'ép dùng ' + igpu_short if enabled else 'trả về mặc định GPU'} cho {os.path.basename(exe_path)}.",
            "status": get_system_tuning_status(),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def apply_optimal_tuning_profile() -> dict:
    """Apply all dynamic hardware-adaptive AI optimizations in one click."""
    return apply_ai_recommendations()


def _scan_game_gpu_findings(dgpu_label: str, display_mux: dict) -> list:
    """Detect installed or configured games not locked to High-Performance dGPU (or forced onto iGPU)."""
    if not display_mux.get("has_nvidia"):
        return []
    import winreg
    existing_prefs = {}
    try:
        _, subkey = _REG_PATHS["gpu_pref"]
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, idx)
                    idx += 1
                    if name.lower().endswith(".exe"):
                        existing_prefs[os.path.normcase(os.path.abspath(name))] = (name, str(val))
                except OSError:
                    break
    except OSError:
        pass

    findings = []
    seen = set()

    # 1. Any non-safe-list executable forced to iGPU (GpuPreference=1)
    for norm_p, (orig_p, pref_val) in existing_prefs.items():
        exe_base = os.path.basename(orig_p).lower()
        if exe_base not in _SAFE_IGPU_OFFLOAD_EXES and "gpupreference=1" in pref_val.lower() and os.path.isfile(orig_p):
            seen.add(norm_p)
            findings.append({
                "id": f"game_gpu:{orig_p}",
                "action_type": "game_gpu",
                "exe_path": orig_p,
                "severity": "high",
                "category": "Phân luồng GPU Game",
                "title": f"Game {os.path.basename(orig_p)} đang bị ép chạy iGPU",
                "current_label": "Đang chạy iGPU (Gây nóng CPU)",
                "recommended_label": f"Ưu tiên {dgpu_label} (High Performance)",
                "reason": "Game đang bị gán GpuPreference=1 (iGPU tích hợp trên CPU). Chuyển sang card rời giúp hạ nhiệt CPU và tăng tối đa FPS.",
                "requires_admin": False,
            })

    # 2. Games tracked by Windows GameConfigStore not yet set to High Performance (GpuPreference=2)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"System\GameConfigStore\Children", 0, winreg.KEY_READ) as root_key:
            idx = 0
            while True:
                try:
                    sub = winreg.EnumKey(root_key, idx)
                    idx += 1
                    with winreg.OpenKey(root_key, sub, 0, winreg.KEY_READ) as sk:
                        try:
                            exe_path, _ = winreg.QueryValueEx(sk, "MatchedExeFullPath")
                        except OSError:
                            continue
                    if not exe_path:
                        continue
                    exe_str = str(exe_path).strip()
                    exe_base = os.path.basename(exe_str).lower()
                    norm_p = os.path.normcase(os.path.abspath(exe_str))
                    if (
                        exe_base.endswith(".exe")
                        and exe_base not in _SAFE_IGPU_OFFLOAD_EXES
                        and norm_p not in seen
                        and os.path.isfile(exe_str)
                    ):
                        pref_val = existing_prefs.get(norm_p, (exe_str, ""))[1]
                        if "gpupreference=2" not in pref_val.lower():
                            seen.add(norm_p)
                            is_igpu = "gpupreference=1" in pref_val.lower()
                            findings.append({
                                "id": f"game_gpu:{exe_str}",
                                "action_type": "game_gpu",
                                "exe_path": exe_str,
                                "severity": "high",
                                "category": "Phân luồng GPU Game",
                                "title": f"Game {os.path.basename(exe_str)} chưa khóa ưu tiên Card rời",
                                "current_label": "Đang chạy iGPU (Gây nóng CPU)" if is_igpu else "Mặc định (Chưa khóa dGPU)",
                                "recommended_label": f"Ưu tiên {dgpu_label} (High Performance)",
                                "reason": "Khóa GpuPreference=2 buộc Windows xuất khung hình game trực tiếp qua card rời, tránh dồn tải vào nhân đồ họa trên CPU.",
                                "requires_admin": False,
                            })
                except OSError:
                    break
    except OSError:
        pass

    return findings


def _measure_deletable_temp_junk(cat: dict) -> tuple:
    """Count actually unlocked (deletable) files and bytes in User Temp so active app locks are ignored."""
    if not cat:
        return 0, 0
    deletable_bytes = 0
    deletable_files = 0
    for base_path in expand_category_paths(cat):
        if os.path.isfile(base_path):
            try:
                with open(base_path, "r+b"):
                    pass
                deletable_bytes += os.path.getsize(base_path)
                deletable_files += 1
            except OSError:
                pass
            continue
        stack = [base_path]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                with open(entry.path, "r+b"):
                                    pass
                                deletable_bytes += entry.stat(follow_symlinks=False).st_size
                                deletable_files += 1
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                        except OSError:
                            pass
            except OSError:
                pass
    return deletable_bytes, deletable_files


def analyze_system_ai() -> dict:
    """AI-assisted hardware profiling & diagnostic scanner returning actionable optimization findings."""
    tuning = get_system_tuning_status()
    hw = tuning["hardware_profile"]
    display_mux = tuning["display_mux"]
    telemetry = tuning["telemetry"]
    mem = get_memory_status()

    user_temp_cat = next((c for c in JUNK_CATEGORIES if c["id"] == "user_temp"), None)
    temp_scan = (
        scan_single_junk_category(user_temp_cat)
        if user_temp_cat
        else {"total_bytes": 0, "total_formatted": "0 B", "total_files": 0}
    )
    deletable_temp_bytes, deletable_temp_files = (
        _measure_deletable_temp_junk(user_temp_cat)
        if temp_scan["total_bytes"] >= 150 * 1024 * 1024
        else (temp_scan["total_bytes"], temp_scan["total_files"])
    )

    dgpu_label = telemetry["name"] if telemetry.get("available") else "Card đồ họa rời"
    igpu_short = display_mux.get("igpu_short", "iGPU")

    findings = []
    group_cat_map = {
        "nvidia": "Card Đồ Họa NVIDIA",
        "power": "CPU & Nguồn Điện",
        "windows": "Windows & Tài Nguyên Nền",
    }
    high_priority_ids = {"cpu_freq_cap", "nv_optimus", "win_hags", "nv_power_mode", "cpu_boost_ac"}

    # 1. Scan all tuning settings
    for s in tuning["settings"]:
        if not s.get("available") or s.get("is_optimal"):
            continue
        if s["type"] == "toggle":
            cur_lbl = "Đang Bật" if s["current"] else "Đang Tắt"
            rec_lbl = "Bật" if s["optimal"] else "Tắt"
        else:
            opts = {str(o["value"]): o["label"] for o in (s.get("options") or [])}
            cur_lbl = opts.get(str(s["current"]), str(s["current"]))
            rec_lbl = opts.get(str(s["optimal"]), str(s["optimal"]))

        findings.append({
            "id": f"setting:{s['id']}",
            "action_type": "setting",
            "setting_id": s["id"],
            "target_value": s["optimal"],
            "severity": "high" if s["id"] in high_priority_ids else "medium",
            "category": group_cat_map.get(s["group"], "Tối ưu hệ thống"),
            "title": s["label"],
            "current_label": cur_lbl,
            "recommended_label": rec_lbl,
            "reason": s["desc"],
            "requires_admin": bool(s.get("requires_admin", False)),
        })

    # 2. Scan Game GPU routing
    findings.extend(_scan_game_gpu_findings(dgpu_label, display_mux))

    # 3. Scan Background iGPU offload (only when Hybrid Optimus is active)
    if hw.get("can_offload_igpu"):
        for app in tuning.get("offload_apps", []):
            if not app.get("is_igpu"):
                findings.append({
                    "id": f"offload:{app['path']}",
                    "action_type": "offload",
                    "exe_path": app["path"],
                    "severity": "medium",
                    "category": "Tiết kiệm nhiệt GPU nền",
                    "title": f"Ứng dụng nền {app['name']} chưa tách sang {igpu_short}",
                    "current_label": app.get("current_pref", "Mặc định Windows"),
                    "recommended_label": f"Chạy trên {igpu_short} (Tiết kiệm điện)",
                    "reason": f"Tách trình duyệt/app nền sang {igpu_short} giúp card rời hạ xung ngủ mát khi không chơi game.",
                    "requires_admin": False,
                })

    # 4. Scan RAM & Standby Cache pressure
    if mem["used_percent"] >= 75 or (
        tuning["is_admin"]
        and mem["used_percent"] >= 65
        and mem["system_cache_bytes"] >= int(4.0 * (1024**3))
    ):
        findings.append({
            "id": "action:clean_memory",
            "action_type": "clean_memory",
            "severity": "medium",
            "category": "Bộ nhớ RAM & Cache",
            "title": f"Bộ nhớ đệm Standby Cache & RAM đang chiếm cao ({mem['used_percent']}% RAM, {mem['system_cache_formatted']} Cache)",
            "current_label": f"Đang dùng {mem['used_formatted']} (Cache {mem['system_cache_formatted']})",
            "recommended_label": "Giải phóng Standby List & Working Sets nhàn rỗi",
            "reason": "Giải phóng bộ nhớ đệm tích tụ giúp ngăn chặn hiện tượng khựng khung hình (micro-stutter) khi vào game hoặc mở tác vụ nặng.",
            "requires_admin": False,
        })

    # 5. Scan User Temp junk (only unlocked/deletable bytes >= 150 MB)
    if deletable_temp_bytes >= 150 * 1024 * 1024:
        del_fmt = format_bytes(deletable_temp_bytes)
        findings.append({
            "id": "action:clean_user_temp",
            "action_type": "clean_user_temp",
            "severity": "low",
            "category": "Tệp tạm & Rác ổ cứng",
            "title": f"Tồn đọng {del_fmt} ({deletable_temp_files} tệp có thể dọn) trong thư mục User Temp",
            "current_label": del_fmt,
            "recommended_label": "Dọn sạch tệp tạm an toàn",
            "reason": "Xóa các tệp rác tạm sinh ra từ trình biên dịch, trình duyệt và phần mềm giúp giảm phân mảnh I/O ổ cứng SSD.",
            "requires_admin": False,
        })

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    if not findings:
        health_score = 100
    else:
        non_setting_penalty = sum(
            8 if f["severity"] == "high" else (4 if f["severity"] == "medium" else 2)
            for f in findings
            if f["action_type"] != "setting"
        )
        health_score = max(0, min(99, tuning["summary"]["score_pct"] - non_setting_penalty))

    hz_str = f"{tuning['display_hz']}Hz" if tuning["display_hz"] else "chuẩn"
    hw_intro = f"Đã nhận diện: {hw['form_factor_label']} • {hw['cpu_name']} • {dgpu_label} • Màn hình {hz_str}."
    if not findings:
        ai_summary = (
            f"{hw_intro} Tuyệt vời! Toàn bộ cấu hình CPU, GPU, phân luồng game/app nền, RAM và rác hệ thống đều đang ở trạng thái tối ưu nhất (100/100 điểm)."
        )
    else:
        high_n = sum(1 for f in findings if f["severity"] == "high")
        med_n = sum(1 for f in findings if f["severity"] == "medium")
        low_n = sum(1 for f in findings if f["severity"] == "low")
        parts = []
        if high_n:
            parts.append(f"{high_n} điểm quan trọng")
        if med_n:
            parts.append(f"{med_n} điểm trung bình")
        if low_n:
            parts.append(f"{low_n} điểm nhẹ")
        ai_summary = (
            f"{hw_intro} AI phát hiện {len(findings)} điểm cần xử lý ({', '.join(parts)}). "
            f"Bạn có thể giữ nguyên tích chọn và bấm \"Tối Ưu Ngay Các Điểm Tìm Ra\" để xử lý tự động."
        )

    return {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "is_admin": tuning["is_admin"],
        "hardware_profile": hw,
        "display_hz": tuning["display_hz"],
        "display_mux": display_mux,
        "telemetry": telemetry,
        "memory": mem,
        "temp_junk_bytes": temp_scan["total_bytes"],
        "temp_junk_formatted": temp_scan["total_formatted"],
        "health_score": health_score,
        "findings_count": len(findings),
        "findings": findings,
        "ai_summary": ai_summary,
        "status": tuning,
    }


def apply_ai_recommendations(finding_ids: list = None) -> dict:
    """Automatically apply selected (or all) AI-detected optimization findings."""
    _ensure_tuning_backup()
    analysis = analyze_system_ai()
    target_set = set(finding_ids) if finding_ids is not None else None
    to_apply = [
        f for f in analysis["findings"]
        if target_set is None or f["id"] in target_set
    ]

    applied_titles = []
    errors = []
    requires_reboot = False

    for f in to_apply:
        fid = f["id"]
        try:
            if fid.startswith("setting:"):
                meta = _apply_setting_action(f["setting_id"], f["target_value"])
                if meta.get("requires_reboot"):
                    requires_reboot = True
            elif fid.startswith("game_gpu:"):
                _reg_write_str("gpu_pref", f["exe_path"], "GpuPreference=2;")
            elif fid.startswith("offload:"):
                _reg_write_str("gpu_pref", f["exe_path"], "GpuPreference=1;")
            elif fid == "action:clean_memory":
                clean_memory()
            elif fid == "action:clean_user_temp":
                clean_junk_category("user_temp", use_recycle_bin=False)
            applied_titles.append(f["title"])
        except Exception as e:
            errors.append(f"{f['title']}: {e}")

    fresh_analysis = analyze_system_ai()
    need_adm = bool(errors) and not is_admin()
    applied_count = len(applied_titles)

    if applied_count == 0 and not errors:
        msg = "Hệ thống đã đạt trạng thái tối ưu hoàn hảo, không có mục nào cần sửa."
    elif not errors:
        msg = f"AI đã tự động tối ưu xong {applied_count} điểm tìm ra!"
    else:
        msg = f"Đã tối ưu {applied_count} điểm. {len(errors)} mục hệ thống cần quyền Administrator."

    return {
        "success": (applied_count > 0 or not to_apply) and len(errors) == 0,
        "partial": applied_count > 0 and len(errors) > 0,
        "need_admin": need_adm,
        "applied_count": applied_count,
        "applied_titles": applied_titles,
        "requires_reboot": requires_reboot,
        "errors": errors,
        "message": msg,
        "analysis": fresh_analysis,
        "status": fresh_analysis["status"],
    }


def _is_backup_already_optimal(b: dict) -> bool:
    """Return True if the saved tuning backup already reflects optimized settings."""
    pwr = b.get("power") or {}
    nv = b.get("nvidia") or {}
    reg = b.get("registry") or {}
    max_dc = (pwr.get("PROCTHROTTLEMAX") or {}).get("dc")
    boost_ac = (pwr.get("PERFBOOSTMODE") or {}).get("ac")
    nv_pm = (nv.get("0x1057eb71") or {}).get("value")
    return (
        max_dc == 85
        and boost_ac == 3
        and (nv_pm == 5 or not b.get("nvidia_available"))
        and reg.get("GameDVR_Enabled") == 0
    )


def restore_tuning_defaults() -> dict:
    """Restore original settings from tuning_backup.json, or Windows/NVIDIA factory defaults if backup is missing/already optimized."""
    errors = []
    use_backup = False
    b = {}

    if os.path.exists(TUNING_BACKUP_FILE):
        try:
            with open(TUNING_BACKUP_FILE, "r", encoding="utf-8") as f:
                b = json.load(f)
            use_backup = not _is_backup_already_optimal(b)
        except Exception:
            use_backup = False

    if use_backup:
        for key in _POWER_SETTING_GUIDS:
            pair = (b.get("power") or {}).get(key) or {}
            if pair.get("ac") is not None or pair.get("dc") is not None:
                try:
                    _set_powercfg_pair(key, ac=pair.get("ac"), dc=pair.get("dc"))
                except Exception as e:
                    errors.append(f"Power {key}: {e}")
            elif key in ("PROCFREQMAX", "PROCFREQMAX1"):
                try:
                    _set_powercfg_pair(key, ac=0, dc=0)
                except Exception as e:
                    errors.append(f"Power {key}: {e}")

        reg = b.get("registry", {})
        if reg.get("HwSchMode") is not None:
            try:
                _reg_write_dword("gfx_drivers", "HwSchMode", reg["HwSchMode"])
            except Exception as e:
                errors.append(f"HwSchMode: {e}")

        for b_key, pk, name in [
            ("AutoGameModeEnabled", "game_bar", "AutoGameModeEnabled"),
            ("AllowAutoGameMode", "game_bar", "AllowAutoGameMode"),
            ("GameDVR_Enabled", "game_cfg", "GameDVR_Enabled"),
            ("AppCaptureEnabled", "game_dvr", "AppCaptureEnabled"),
            ("EnableTransparency", "personalize", "EnableTransparency"),
            ("UwpGlobalUserDisabled", "uwp_bg", "GlobalUserDisabled"),
            ("EdgeBackgroundModeEnabled", "edge_policy", "BackgroundModeEnabled"),
            ("EdgeStartupBoostEnabled", "edge_policy", "StartupBoostEnabled"),
            ("ChromeBackgroundMode", "chrome_policy", "BackgroundModeEnabled"),
        ]:
            try:
                val = reg.get(b_key)
                if val is not None:
                    _reg_write_dword(pk, name, int(val))
                else:
                    _reg_delete_value(pk, name)
            except Exception as e:
                errors.append(f"{b_key}: {e}")

        if reg.get("DirectXUserGlobal") is not None:
            _reg_write_str("gpu_pref", "DirectXUserGlobalSettings", reg["DirectXUserGlobal"])

        for exe, val in (reg.get("AppGpuPreferences") or {}).items():
            if val:
                _reg_write_str("gpu_pref", exe, val)
            else:
                _reg_delete_value("gpu_pref", exe)

        nv_backup = b.get("nvidia", {})
        if nv_backup:
            try:
                updates = {}
                for sid_hex, entry in nv_backup.items():
                    sid = int(sid_hex, 16)
                    updates[sid] = None if (entry is None or entry.get("location") != 0) else int(entry["value"])
                _write_nvdrs_updates(updates)
            except Exception as e:
                errors.append(f"NVIDIA NVAPI: {e}")
    else:
        # True Windows & NVIDIA factory defaults
        try:
            _set_powercfg_pair("PROCTHROTTLEMIN", ac=5, dc=5)
            _set_powercfg_pair("PROCTHROTTLEMAX", ac=100, dc=100)
            _set_powercfg_pair("PERFBOOSTMODE", ac=2, dc=2)
            _set_powercfg_pair("PROCFREQMAX", ac=0, dc=0)
            _set_powercfg_pair("PROCFREQMAX1", ac=0, dc=0)
            _set_powercfg_pair("ASPM", ac=1, dc=2)
            _set_powercfg_pair("INTEL_GFX", ac=1, dc=1)
        except Exception as e:
            errors.append(f"Power Plan: {e}")

        for pk, name, val in [
            ("game_cfg", "GameDVR_Enabled", 1),
            ("game_dvr", "AppCaptureEnabled", 1),
            ("personalize", "EnableTransparency", 1),
        ]:
            try:
                _reg_write_dword(pk, name, val)
            except Exception as e:
                errors.append(f"{name}: {e}")

        for pk, name in [
            ("uwp_bg", "GlobalUserDisabled"),
            ("edge_policy", "BackgroundModeEnabled"),
            ("edge_policy", "StartupBoostEnabled"),
            ("chrome_policy", "BackgroundModeEnabled"),
        ]:
            try:
                _reg_delete_value(pk, name)
            except Exception as e:
                errors.append(f"{name}: {e}")

        for app in _discover_offload_apps():
            try:
                _reg_delete_value("gpu_pref", app["path"])
            except Exception as e:
                errors.append(f"{app['exe_name']}: {e}")

        nv_ok, _ = _read_nvdrs_raw([0x1057EB71])
        if nv_ok:
            try:
                _write_nvdrs_updates({sid: None for sid in _NVIDIA_PROFILE_KEYS.values()})
            except Exception as e:
                errors.append(f"NVIDIA NVAPI: {e}")

    if not errors and os.path.exists(TUNING_BACKUP_FILE):
        try:
            os.remove(TUNING_BACKUP_FILE)
        except OSError:
            pass

    return {
        "success": len(errors) == 0,
        "need_admin": bool(errors) and not is_admin(),
        "errors": errors,
        "message": (
            "Đã khôi phục toàn bộ cấu hình về mặc định!"
            if not errors
            else "Đã khôi phục một phần (một số mục cần quyền Administrator)."
        ),
        "status": get_system_tuning_status(),
    }



