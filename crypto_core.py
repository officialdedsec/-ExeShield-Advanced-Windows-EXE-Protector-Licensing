"""
crypto_core.py  -  ExeShield crypto + HWID engine  v3
HWID collected entirely via ctypes Win32 API - ZERO subprocess calls,
ZERO console windows, ZERO cmd flashes.

Place in the SAME folder as lock_tool.py, keygen_tool.py, stub_template.py
"""

import os, sys, struct, hashlib, hmac, base64, platform
from zlib import crc32

# ── CHANGE THIS before distributing your tools ───────────────────────────────
MASTER_SECRET = b"CHANGE_THIS_TO_YOUR_OWN_LONG_RANDOM_SECRET_v1"
# ─────────────────────────────────────────────────────────────────────────────

MAGIC       = 0xDEADC0DE
FLAG_HWID   = 0x00000001
BLOB_OFFSET = 0x378
BLOB_SIZE   = 48
SCHEMA_VER  = 1


# ─────────────────────────────────────────────────────────────────────────────
#  Silent HWID collection via ctypes  (Windows only, no subprocess)
# ─────────────────────────────────────────────────────────────────────────────

def _hwid_windows() -> list:
    """
    Collect hardware identifiers using Win32 API via ctypes only.
    No subprocess, no cmd.exe, no console window. Completely silent.
    """
    import ctypes
    import ctypes.wintypes as wt

    k32  = ctypes.windll.kernel32
    adv  = ctypes.windll.advapi32
    parts = []

    # 1. Volume serial number of system drive (C:\)
    # GetVolumeInformationW(root, vol_name, ..., serial, ...)
    try:
        vol_name  = ctypes.create_unicode_buffer(256)
        serial    = ctypes.c_ulong(0)
        max_comp  = ctypes.c_ulong(0)
        flags     = ctypes.c_ulong(0)
        fs_name   = ctypes.create_unicode_buffer(256)
        if k32.GetVolumeInformationW(
            'C:\\', vol_name, 256,
            ctypes.byref(serial), ctypes.byref(max_comp),
            ctypes.byref(flags), fs_name, 256
        ):
            parts.append(f'VOL:{serial.value:08X}')
    except Exception:
        pass

    # 2. Windows Machine GUID from registry
    # RegOpenKeyExW + RegQueryValueExW
    try:
        HKLM         = 0x80000002
        KEY_READ     = 0x20019
        REG_SZ       = 1
        hkey         = wt.HKEY()
        key_path     = r'SOFTWARE\Microsoft\Cryptography'
        if adv.RegOpenKeyExW(HKLM, key_path, 0, KEY_READ,
                             ctypes.byref(hkey)) == 0:
            buf      = ctypes.create_unicode_buffer(256)
            buf_size = ctypes.c_ulong(512)
            val_type = ctypes.c_ulong(0)
            if adv.RegQueryValueExW(hkey, 'MachineGuid', None,
                                    ctypes.byref(val_type),
                                    buf, ctypes.byref(buf_size)) == 0:
                parts.append(f'GUID:{buf.value.upper()}')
            adv.RegCloseKey(hkey)
    except Exception:
        pass

    # 3. Computer name
    try:
        ComputerNameNetBIOS = 0
        buf  = ctypes.create_unicode_buffer(256)
        size = ctypes.c_ulong(256)
        if k32.GetComputerNameExW(ComputerNameNetBIOS, buf, ctypes.byref(size)):
            parts.append(f'PC:{buf.value.upper()}')
    except Exception:
        pass

    # 4. Processor info via GetSystemInfo
    try:
        class SYSTEM_INFO(ctypes.Structure):
            class _U(ctypes.Union):
                class _S(ctypes.Structure):
                    _fields_ = [('wProcessorArchitecture', wt.WORD),
                                ('wReserved',              wt.WORD)]
                _fields_ = [('s', _S), ('dwOemId', wt.DWORD)]
            _fields_ = [('u',                     _U),
                        ('dwPageSize',             wt.DWORD),
                        ('lpMinimumApplicationAddress', ctypes.c_void_p),
                        ('lpMaximumApplicationAddress', ctypes.c_void_p),
                        ('dwActiveProcessorMask',  ctypes.POINTER(wt.DWORD)),
                        ('dwNumberOfProcessors',   wt.DWORD),
                        ('dwProcessorType',        wt.DWORD),
                        ('dwAllocationGranularity',wt.DWORD),
                        ('wProcessorLevel',        wt.WORD),
                        ('wProcessorRevision',     wt.WORD)]
        si = SYSTEM_INFO()
        k32.GetSystemInfo(ctypes.byref(si))
        arch  = si.u.s.wProcessorArchitecture
        procs = si.dwNumberOfProcessors
        ptype = si.dwProcessorType
        parts.append(f'CPU:{arch}:{procs}:{ptype}')
    except Exception:
        pass

    # 5. Disk serial via DeviceIoControl (IOCTL_STORAGE_QUERY_PROPERTY)
    # Opens \\.\PhysicalDrive0 with CreateFileW then queries storage descriptor
    try:
        GENERIC_READ             = 0x80000000
        FILE_SHARE_READ          = 0x00000001
        FILE_SHARE_WRITE         = 0x00000002
        OPEN_EXISTING            = 3
        IOCTL_STORAGE_QUERY_PROP = 0x002D1400
        FILE_FLAG_NO_BUFFERING   = 0x20000000

        hDrive = k32.CreateFileW(
            r'\\.\PhysicalDrive0',
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None
        )
        if hDrive != ctypes.c_void_p(-1).value:
            # STORAGE_PROPERTY_QUERY: PropertyId=0 (StorageDeviceProperty),
            #                         QueryType=0 (PropertyStandardQuery)
            query   = struct.pack('<III', 0, 0, 0)   # 12 bytes
            out_buf = ctypes.create_string_buffer(1024)
            returned = ctypes.c_ulong(0)
            if k32.DeviceIoControl(
                hDrive, IOCTL_STORAGE_QUERY_PROP,
                query, len(query),
                out_buf, 1024,
                ctypes.byref(returned), None
            ):
                # STORAGE_DEVICE_DESCRIPTOR:
                # Version(4) Size(4) DevType(1) DevTypeModifier(1)
                # RemovableMedia(1) CommandQueueing(1) VendorIdOffset(4)
                # ProductIdOffset(4) ProductRevisionOffset(4) SerialNumOffset(4)
                # BusType(4) RawPropertiesLength(4) RawDeviceProperties[...]
                raw = out_buf.raw[:returned.value]
                if len(raw) > 20:
                    sn_off = struct.unpack_from('<I', raw, 16)[0]
                    if 0 < sn_off < len(raw):
                        sn_end = raw.index(b'\x00', sn_off)
                        sn = raw[sn_off:sn_end].decode(errors='ignore').strip()
                        if sn:
                            parts.append(f'DISK:{sn.upper()}')
            k32.CloseHandle(hDrive)
    except Exception:
        pass

    # 6. MAC address of first physical adapter (via GetAdaptersInfo)
    try:
        IP_ADAPTER_INFO_SIZE = 640
        buf = ctypes.create_string_buffer(IP_ADAPTER_INFO_SIZE * 8)
        size = ctypes.c_ulong(len(buf))
        iphlp = ctypes.windll.iphlpapi
        if iphlp.GetAdaptersInfo(buf, ctypes.byref(size)) == 0:
            # First adapter struct, MAC is at offset 196, len at offset 192
            mac_len = struct.unpack_from('<I', buf.raw, 192)[0]
            mac     = buf.raw[196:196+min(mac_len,6)]
            if any(mac):
                parts.append('MAC:' + '-'.join(f'{b:02X}' for b in mac))
    except Exception:
        pass

    return parts


def _hwid_linux() -> list:
    """Linux/CI fallback."""
    parts = []
    for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            with open(path) as f:
                parts.append(f'MID:{f.read().strip().upper()}')
            break
        except Exception:
            pass
    parts.append(f'HOST:{platform.node().upper()}')
    parts.append(f'ARCH:{platform.machine().upper()}')
    return parts


def get_hwid() -> str:
    """
    Collect hardware identifiers.
    Windows: uses ctypes Win32 API exclusively - NO subprocess, NO cmd flash.
    Returns reproducible 32-char uppercase hex string.
    """
    if platform.system() == 'Windows':
        parts = _hwid_windows()
    else:
        parts = _hwid_linux()

    if not parts:
        # Ultimate fallback
        parts = [platform.node(), platform.machine(), platform.processor()]

    combined = '|'.join(sorted(p.strip() for p in parts if p))
    return hashlib.sha256(combined.encode()).hexdigest().upper()[:32]


# ─────────────────────────────────────────────────────────────────────────────
#  Key crypto  (20 bytes HMAC -> 32 base32 chars -> 4 groups of 8)
#  Format: AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD
# ─────────────────────────────────────────────────────────────────────────────

def _derive(hwid: str) -> bytes:
    return hmac.new(MASTER_SECRET,
                    hwid.strip().upper().encode(),
                    hashlib.sha256).digest()[:20]

def generate_key(hwid: str) -> str:
    b32 = base64.b32encode(_derive(hwid)).decode()  # exactly 32 chars
    return '-'.join(b32[i:i+8] for i in range(0, 32, 8))

def verify_key(hwid: str, key_str: str, stored_hwid_hash: bytes) -> bool:
    clean = key_str.replace('-', '').strip().upper()
    if len(clean) != 32:
        return False
    try:
        kb = base64.b32decode(clean)[:20]
    except Exception:
        return False
    if not hmac.compare_digest(kb, _derive(hwid)):
        return False
    cur = hashlib.sha256(hwid.strip().upper().encode()).digest()[:16]
    return hmac.compare_digest(cur, stored_hwid_hash)


# ─────────────────────────────────────────────────────────────────────────────
#  License blob
# ─────────────────────────────────────────────────────────────────────────────

def make_blob(hwid: str) -> bytes:
    hwid_hash = hashlib.sha256(hwid.strip().upper().encode()).digest()[:16]
    hdr  = struct.pack('<IIII', MAGIC, FLAG_HWID, SCHEMA_VER, 0)
    body = hdr + hwid_hash
    chk  = struct.pack('<I', crc32(body) & 0xFFFFFFFF)
    blob = body + chk + b'\x00' * 12
    assert len(blob) == BLOB_SIZE
    return blob

def parse_blob(data: bytes) -> dict:
    if len(data) < BLOB_SIZE:
        return None
    magic, flags, ver, _ = struct.unpack_from('<IIII', data, 0)
    if magic != MAGIC:
        return None
    hwid_hash = data[16:32]
    stored_crc, = struct.unpack_from('<I', data, 32)
    if (crc32(data[:32]) & 0xFFFFFFFF) != stored_crc:
        return None
    return {'flags': flags, 'version': ver, 'hwid_hash': hwid_hash, 'valid': True}

def verify_exe_integrity(path: str) -> tuple:
    try:
        with open(path, 'rb') as f:
            hdr = f.read(2)
            if hdr != b'MZ':
                return False, 'Not a valid PE (missing MZ header)'
            f.seek(BLOB_OFFSET)
            blob = parse_blob(f.read(BLOB_SIZE))
        if blob is None:
            return False, 'No valid license blob at offset 0x378'
        return True, (f"OK  flags=0x{blob['flags']:08X}  "
                      f"hwid_hash={blob['hwid_hash'].hex().upper()}")
    except Exception as e:
        return False, str(e)
