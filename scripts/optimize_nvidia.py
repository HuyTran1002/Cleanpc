"""
optimize_nvidia.py - Automated NVIDIA Control Panel (NVDRS) Optimizer & Restorer
Uses the official nvapi64.dll DRS interface to configure Global Profile settings
for cool idle temperatures and smooth high-FPS gaming, with full backup/restore.
"""

import os
import sys
import json
import ctypes
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_FILE = os.path.join(BASE_DIR, "backup_nvidia_settings.json")

# Official NVAPI QueryInterface function IDs
NVAPI_INITIALIZE = 0x0150E828
NVAPI_UNLOAD = 0xD22BDD7E
NVAPI_DRS_CREATE_SESSION = 0x0694D52E
NVAPI_DRS_DESTROY_SESSION = 0xDAD9CFF8
NVAPI_DRS_LOAD_SETTINGS = 0x375DBD6B
NVAPI_DRS_SAVE_SETTINGS = 0xFCBC7E14
NVAPI_DRS_GET_BASE_PROFILE = 0xDA8466A0
NVAPI_DRS_GET_SETTING = 0x73BF8338
NVAPI_DRS_SET_SETTING = 0x577DD202
NVAPI_DRS_DELETE_PROFILE_SETTING = 0xE4A26362

NVAPI_SETTING_NOT_FOUND = -160


class NVDRS_BINARY_SETTING(ctypes.Structure):
    _fields_ = [
        ("valueLength", ctypes.c_uint32),
        ("valueData", ctypes.c_uint8 * 4096),
    ]


class NVDRS_VALUE_UNION(ctypes.Union):
    _fields_ = [
        ("dwordValue", ctypes.c_uint32),
        ("binaryValue", NVDRS_BINARY_SETTING),
        ("wszValue", ctypes.c_wchar * 2048),
    ]


class NVDRS_SETTING(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("settingName", ctypes.c_wchar * 2048),
        ("settingId", ctypes.c_uint32),
        ("settingType", ctypes.c_int),
        ("settingLocation", ctypes.c_int),
        ("isCurrentPredefined", ctypes.c_uint32),
        ("isPredefinedValid", ctypes.c_uint32),
        ("predefinedValue", NVDRS_VALUE_UNION),
        ("currentValue", NVDRS_VALUE_UNION),
    ]


NVDRS_SETTING_VER = (1 << 16) | ctypes.sizeof(NVDRS_SETTING)

# Verified setting IDs from the installed nvapi64.dll driver
OPTIMAL_SETTINGS = [
    # (setting_id, description, optimal_dword)
    (0x1057EB71, "Power management mode -> Normal (5)", 5),
    (0x10F9DC80, "Optimus flags -> Auto-select (16)", 16),
    (0x10F9DC81, "Enable application for Optimus -> Auto-select (16)", 16),
    (0x10835002, "Max Frame Rate -> 162 FPS (match 165Hz panel)", 162),
    (0x10835016, "Background Application Max Frame Rate -> 30 FPS", 30),
    (0x007BA09E, "Low Latency Mode (Max pre-rendered frames) -> On (1)", 1),
    (0x00CE2691, "Texture filtering - Quality -> Performance (10)", 10),
    (0x00E73211, "Texture filtering - Anisotropic sample optimization -> On (1)", 1),
    (0x002ECAF2, "Texture filtering - Trilinear optimization -> On (1)", 1),
    (0x0064B541, "Preferred refresh rate -> Highest available (1)", 1),
    (0x00A879CF, "Vertical Sync -> Use 3D application setting", 1620202130),
]


class NvDrsClient:
    def __init__(self):
        self.nvapi = ctypes.WinDLL("nvapi64.dll")
        self.qi = self.nvapi.nvapi_QueryInterface
        self.qi.restype = ctypes.c_void_p
        self.qi.argtypes = [ctypes.c_uint32]

        self._init = self._fn(NVAPI_INITIALIZE, ctypes.c_int, [])
        self._unload = self._fn(NVAPI_UNLOAD, ctypes.c_int, [])
        self._create_session = self._fn(NVAPI_DRS_CREATE_SESSION, ctypes.c_int, [ctypes.POINTER(ctypes.c_void_p)])
        self._destroy_session = self._fn(NVAPI_DRS_DESTROY_SESSION, ctypes.c_int, [ctypes.c_void_p])
        self._load_settings = self._fn(NVAPI_DRS_LOAD_SETTINGS, ctypes.c_int, [ctypes.c_void_p])
        self._save_settings = self._fn(NVAPI_DRS_SAVE_SETTINGS, ctypes.c_int, [ctypes.c_void_p])
        self._get_base_profile = self._fn(NVAPI_DRS_GET_BASE_PROFILE, ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
        self._get_setting = self._fn(NVAPI_DRS_GET_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(NVDRS_SETTING)])
        self._set_setting = self._fn(NVAPI_DRS_SET_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(NVDRS_SETTING)])
        self._del_setting = self._fn(NVAPI_DRS_DELETE_PROFILE_SETTING, ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32])
        self.session = ctypes.c_void_p()
        self.profile = ctypes.c_void_p()

    def _fn(self, fid, restype, argtypes):
        addr = self.qi(fid)
        if not addr:
            raise RuntimeError(f"NVAPI function {hex(fid)} not found")
        return ctypes.CFUNCTYPE(restype, *argtypes)(addr)

    def __enter__(self):
        rc = self._init()
        if rc != 0:
            raise RuntimeError(f"NvAPI_Initialize failed: {rc}")
        rc = self._create_session(ctypes.byref(self.session))
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_CreateSession failed: {rc}")
        rc = self._load_settings(self.session)
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_LoadSettings failed: {rc}")
        rc = self._get_base_profile(self.session, ctypes.byref(self.profile))
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_GetBaseProfile failed: {rc}")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.session:
            self._destroy_session(self.session)
        self._unload()

    def get_dword(self, sid: int):
        s = NVDRS_SETTING()
        s.version = NVDRS_SETTING_VER
        rc = self._get_setting(self.session, self.profile, sid, ctypes.byref(s))
        if rc == NVAPI_SETTING_NOT_FOUND:
            return None
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_GetSetting({hex(sid)}) failed: {rc}")
        return {"value": int(s.currentValue.dwordValue), "location": int(s.settingLocation)}

    def set_dword(self, sid: int, value: int):
        s = NVDRS_SETTING()
        s.version = NVDRS_SETTING_VER
        s.settingId = sid
        s.settingType = 0  # NVDRS_DWORD_TYPE
        s.settingLocation = 0  # NVDRS_CURRENT_PROFILE_LOCATION
        s.currentValue.dwordValue = value
        rc = self._set_setting(self.session, self.profile, ctypes.byref(s))
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_SetSetting({hex(sid)}, {value}) failed: {rc}")

    def delete_setting(self, sid: int):
        rc = self._del_setting(self.session, self.profile, sid)
        if rc not in (0, NVAPI_SETTING_NOT_FOUND):
            raise RuntimeError(f"NvAPI_DRS_DeleteProfileSetting({hex(sid)}) failed: {rc}")

    def save(self):
        rc = self._save_settings(self.session)
        if rc != 0:
            raise RuntimeError(f"NvAPI_DRS_SaveSettings failed: {rc}")


def _detect_max_refresh_hz() -> int:
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
            if dd.StateFlags & 0x1:
                dm = _DEVMODEW()
                dm.dmSize = ctypes.sizeof(_DEVMODEW)
                if user32.EnumDisplaySettingsW(dd.DeviceName, -1, ctypes.byref(dm)):
                    max_hz = max(max_hz, int(dm.dmDisplayFrequency))
    except Exception:
        pass
    return max_hz


def get_optimal_settings() -> list:
    hz = _detect_max_refresh_hz()
    rec_fps = (hz - 3) if hz >= 75 else (hz if hz > 0 else 162)
    hz_lbl = hz or 165
    return [
        (0x1057EB71, "Power management mode -> Normal (5)", 5),
        (0x10F9DC80, "Optimus flags -> Auto-select (16)", 16),
        (0x10F9DC81, "Enable application for Optimus -> Auto-select (16)", 16),
        (0x10835002, f"Max Frame Rate -> {rec_fps} FPS (match {hz_lbl}Hz panel)", rec_fps),
        (0x10835016, "Background Application Max Frame Rate -> 30 FPS", 30),
        (0x007BA09E, "Low Latency Mode (Max pre-rendered frames) -> On (1)", 1),
        (0x00CE2691, "Texture filtering - Quality -> Performance (10)", 10),
        (0x00E73211, "Texture filtering - Anisotropic sample optimization -> On (1)", 1),
        (0x002ECAF2, "Texture filtering - Trilinear optimization -> On (1)", 1),
        (0x0064B541, "Preferred refresh rate -> Highest available (1)", 1),
        (0x00A879CF, "Vertical Sync -> Use 3D application setting", 1620202130),
    ]


def optimize():
    settings = get_optimal_settings()
    with NvDrsClient() as drs:
        if not os.path.exists(BACKUP_FILE):
            backup = {}
            for sid, desc, _ in settings:
                backup[hex(sid)] = drs.get_dword(sid)
            with open(BACKUP_FILE, "w", encoding="utf-8") as f:
                json.dump(backup, f, indent=2)
            print(f"      -> Da sao luu cau hinh NVIDIA goc tai: {BACKUP_FILE}")

        for sid, desc, val in settings:
            drs.set_dword(sid, val)
            print(f"      -> {desc}")

        drs.save()
        print("      -> Da luu NVIDIA Global Profile (nvdrsdb) thanh cong!")


def restore():
    with NvDrsClient() as drs:
        if not os.path.exists(BACKUP_FILE):
            for sid, _, _ in OPTIMAL_SETTINGS:
                drs.delete_setting(sid)
            drs.save()
            print("      -> Da xoa cac ghi de NVIDIA ve mac dinh driver.")
            return

        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            backup = json.load(f)

        for sid_hex, entry in backup.items():
            sid = int(sid_hex, 16)
            if entry is None or entry.get("location") != 0:
                drs.delete_setting(sid)
            else:
                drs.set_dword(sid, int(entry["value"]))

        drs.save()
        print("      -> Da khoi phuc cau hinh NVIDIA ve nguyen ban!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["Optimize", "Restore"], required=True)
    args = parser.parse_args()
    if args.action == "Optimize":
        optimize()
    else:
        restore()


if __name__ == "__main__":
    main()
