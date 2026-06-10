import os, sys, struct, hashlib, hmac as _hmac
import base64, threading, time
from zlib import crc32
import ctypes
import ctypes.wintypes as _wt

# ── Baked-in at lock-time (replaced by lock_tool.py) ─────────────────────────
_HWID_HASH_HEX  = '%%HWID_HASH_HEX%%'
_APP_NAME       = '%%APP_NAME%%'
_MASTER_SECRET  = bytes.fromhex('%%MASTER_SECRET_HEX%%')
_PAYLOAD_SIZE   = int('%%PAYLOAD_SIZE%%')
_ICON_B64       = '%%ICON_B64%%'
_PER_MACHINE_MODE = '%%PER_MACHINE_MODE%%' == 'True'   # replaced: True or False
# ─────────────────────────────────────────────────────────────────────────────

PAYLOAD_MARKER = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'
REG_BASE       = r'SOFTWARE\ExeShield\Licenses'

try:
    import winreg as _wr; _HAS_REG = True
except ImportError:
    _HAS_REG = False

try:
    import tkinter as _tk; _HAS_TK = True
except ImportError:
    _HAS_TK = False

_k32   = ctypes.windll.kernel32
_ntdll = ctypes.windll.ntdll
_adv   = ctypes.windll.advapi32
_u32   = ctypes.windll.user32


# ═══════════════════════════════════════════════════════════════════════════════
#  PROTECTION CHECKS  (injected here by lock_tool.py)
# ═══════════════════════════════════════════════════════════════════════════════
'PROTECTION_SNIPPETS_START'
_PROTECTION_SNIPPET_PLACEHOLDER_ = 'PROTECTION_SNIPPETS_END'


def _run_protection_checks():
    """
    Calls every protection check function that was compiled in.
    Returns True if any check fires (threat detected).
    """
    # PROTECTION_CALLS_START
    return '__CALLS_PLACEHOLDER__'
    # PROTECTION_CALLS_STOP
    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  HWID  (ctypes Win32 API only - ZERO subprocess, ZERO cmd flash)
# ═══════════════════════════════════════════════════════════════════════════════

def _get_hwid():
    parts = []

    # Volume serial of C:\
    try:
        serial = _wt.DWORD(0)
        if _k32.GetVolumeInformationW('C:\\', None, 0,
                ctypes.byref(serial), None, None, None, 0):
            parts.append(f'VOL:{serial.value:08X}')
    except Exception: pass

    # Machine GUID from registry (silent RegOpenKeyExW)
    try:
        HKLM = 0x80000002; KEY_READ = 0x20019
        hkey = _wt.HKEY()
        if _adv.RegOpenKeyExW(HKLM,
                r'SOFTWARE\Microsoft\Cryptography',
                0, KEY_READ, ctypes.byref(hkey)) == 0:
            buf = ctypes.create_unicode_buffer(256)
            bsz = _wt.DWORD(512)
            vt  = _wt.DWORD(0)
            if _adv.RegQueryValueExW(hkey, 'MachineGuid', None,
                    ctypes.byref(vt), buf, ctypes.byref(bsz)) == 0:
                parts.append(f'GUID:{buf.value.upper()}')
            _adv.RegCloseKey(hkey)
    except Exception: pass

    # Computer name
    try:
        buf  = ctypes.create_unicode_buffer(256)
        size = _wt.DWORD(256)
        if _k32.GetComputerNameExW(0, buf, ctypes.byref(size)):
            parts.append(f'PC:{buf.value.upper()}')
    except Exception: pass

    # Processor info
    try:
        class _SIH(ctypes.Structure):
            class _U(ctypes.Union):
                class _S(ctypes.Structure):
                    _fields_ = [('wArch', _wt.WORD), ('wRes', _wt.WORD)]
                _fields_ = [('s', _S), ('id', _wt.DWORD)]
            _fields_ = [('u', _U), ('dPSz', _wt.DWORD),
                        ('lpMin', ctypes.c_void_p), ('lpMax', ctypes.c_void_p),
                        ('mask', ctypes.POINTER(_wt.DWORD)),
                        ('nProcs', _wt.DWORD), ('pType', _wt.DWORD),
                        ('gran', _wt.DWORD), ('lvl', _wt.WORD), ('rev', _wt.WORD)]
        si = _SIH()
        _k32.GetSystemInfo(ctypes.byref(si))
        parts.append(f'CPU:{si.u.s.wArch}:{si.nProcs}:{si.pType}')
    except Exception: pass

    # Disk serial via DeviceIoControl
    try:
        INVALID = ctypes.c_void_p(-1).value
        hd = _k32.CreateFileW(r'\\.\PhysicalDrive0',
                0x80000000, 3, None, 3, 0, None)
        if hd not in (INVALID, 0):
            query = struct.pack('<III', 0, 0, 0)
            out   = ctypes.create_string_buffer(1024)
            ret   = _wt.DWORD(0)
            if _k32.DeviceIoControl(hd, 0x002D1400, query, len(query),
                    out, 1024, ctypes.byref(ret), None):
                raw = out.raw[:ret.value]
                if len(raw) > 20:
                    sn_off = struct.unpack_from('<I', raw, 16)[0]
                    if 0 < sn_off < len(raw):
                        try:
                            end = raw.index(b'\x00', sn_off)
                            sn  = raw[sn_off:end].decode(errors='ignore').strip()
                            if sn: parts.append(f'DISK:{sn.upper()}')
                        except ValueError: pass
            _k32.CloseHandle(hd)
    except Exception: pass

    # MAC address
    try:
        buf  = ctypes.create_string_buffer(640 * 8)
        size = _wt.DWORD(len(buf))
        if ctypes.windll.iphlpapi.GetAdaptersInfo(buf, ctypes.byref(size)) == 0:
            mac_len = struct.unpack_from('<I', buf.raw, 192)[0]
            mac     = buf.raw[196:196 + min(mac_len, 6)]
            if any(mac):
                parts.append('MAC:' + '-'.join(f'{b:02X}' for b in mac))
    except Exception: pass

    combined = '|'.join(sorted(p.strip() for p in parts if p))
    return hashlib.sha256(combined.encode()).hexdigest().upper()[:32]


# ═══════════════════════════════════════════════════════════════════════════════
#  Bail out silently
# ═══════════════════════════════════════════════════════════════════════════════

def _bail():
    try:
        _k32.TerminateProcess(_k32.GetCurrentProcess(), 0)
    except Exception:
        os._exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
#  Key verification
# ═══════════════════════════════════════════════════════════════════════════════

def _verify(hwid, key_str):
    clean = key_str.replace('-', '').strip().upper()
    if len(clean) != 32: return False
    try:
        kb = base64.b32decode(clean)[:20]
    except Exception: return False

    if _PER_MACHINE_MODE:
        # Key is derived from the CURRENT machine's HWID
        exp = _hmac.new(_MASTER_SECRET,
                        hwid.strip().upper().encode(),
                        hashlib.sha256).digest()[:20]
        return _hmac.compare_digest(kb, exp)
    else:
        # Original behaviour: key must match embedded HWID hash
        exp = _hmac.new(_MASTER_SECRET,
                        hwid.strip().upper().encode(),
                        hashlib.sha256).digest()[:20]
        if not _hmac.compare_digest(kb, exp): return False
        stored = bytes.fromhex(_HWID_HASH_HEX)
        cur = hashlib.sha256(hwid.strip().upper().encode()).digest()[:16]
        return _hmac.compare_digest(cur, stored)


# ═══════════════════════════════════════════════════════════════════════════════
#  Registry key storage
# ═══════════════════════════════════════════════════════════════════════════════

def _reg_load():
    if not _HAS_REG: return None
    try:
        with _wr.OpenKey(_wr.HKEY_CURRENT_USER,
                         REG_BASE + '\\' + _APP_NAME) as k:
            v, _ = _wr.QueryValueEx(k, 'Key'); return v
    except Exception: return None

def _reg_save(key):
    if not _HAS_REG: return
    try:
        with _wr.CreateKey(_wr.HKEY_CURRENT_USER,
                           REG_BASE + '\\' + _APP_NAME) as k:
            _wr.SetValueEx(k, 'Key', 0, _wr.REG_SZ, key)
    except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
#  SECURE PAYLOAD LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════════

# Win32 constants
_GR    = 0x80000000   # GENERIC_READ
_GW    = 0x40000000   # GENERIC_WRITE
_FSR   = 0x00000001   # FILE_SHARE_READ
_FSW   = 0x00000002   # FILE_SHARE_WRITE
_FSD   = 0x00000004   # FILE_SHARE_DELETE
_CA    = 2            # CREATE_ALWAYS
_OE    = 3            # OPEN_EXISTING
_FDOC  = 0x04000000   # FILE_FLAG_DELETE_ON_CLOSE
_FAH   = 0x00000002   # FILE_ATTRIBUTE_HIDDEN
_FAS   = 0x00000004   # FILE_ATTRIBUTE_SYSTEM
_FAT   = 0x00000100   # FILE_ATTRIBUTE_TEMPORARY
_INV   = ctypes.c_void_p(-1).value   # INVALID_HANDLE_VALUE
_WINF  = 0xFFFFFFFF   # WAIT_INFINITE
_SFSW  = 0x00000001   # STARTF_USESHOWWINDOW
_SWSN  = 1            # SW_SHOWNORMAL


class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb',               _wt.DWORD),
        ('lpReserved',       ctypes.c_wchar_p),
        ('lpDesktop',        ctypes.c_wchar_p),
        ('lpTitle',          ctypes.c_wchar_p),
        ('dwX',              _wt.DWORD), ('dwY',          _wt.DWORD),
        ('dwXSize',          _wt.DWORD), ('dwYSize',      _wt.DWORD),
        ('dwXCountChars',    _wt.DWORD), ('dwYCountChars',_wt.DWORD),
        ('dwFillAttribute',  _wt.DWORD),
        ('dwFlags',          _wt.DWORD),
        ('wShowWindow',      _wt.WORD),
        ('cbReserved2',      _wt.WORD),
        ('lpReserved2',      ctypes.c_char_p),
        ('hStdInput',        _wt.HANDLE),
        ('hStdOutput',       _wt.HANDLE),
        ('hStdError',        _wt.HANDLE),
    ]

class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    _wt.HANDLE),
        ('hThread',     _wt.HANDLE),
        ('dwProcessId', _wt.DWORD),
        ('dwThreadId',  _wt.DWORD),
    ]


def _get_secure_dir() -> str:
    """Hidden GUID-named directory under %LOCALAPPDATA%\\Microsoft\\Windows\\."""
    local = (os.environ.get('LOCALAPPDATA') or
             os.environ.get('APPDATA') or 'C:\\Windows\\Temp')
    h = hashlib.sha256(_APP_NAME.encode()).hexdigest()[:32].upper()
    guid = f'{{{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}'
    path = os.path.join(local, 'Microsoft', 'Windows', guid)
    try:
        os.makedirs(path, exist_ok=True)
        _k32.SetFileAttributesW(path, _FAH | _FAS)
    except Exception:
        path = os.environ.get('TEMP', 'C:\\Windows\\Temp')
    return path


def _write_payload(path: str, data: bytes):
    """
    Write payload to disk with HIDDEN + SYSTEM + TEMPORARY attributes.
    Uses a plain write (no FILE_FLAG_DELETE_ON_CLOSE here) so that
    CreateProcessW can open the file without sharing violation.
    Returns True on success.
    """
    h = _k32.CreateFileW(
        path, _GR | _GW,
        _FSR | _FSW | _FSD,   # allow all sharing during write
        None, _CA,
        _FAH | _FAS | _FAT,   # hidden + system + temporary
        None
    )
    if h in (_INV, 0, None):
        raise OSError(f'Write CreateFileW failed: error {_k32.GetLastError()}')
    try:
        written = _wt.DWORD(0)
        raw     = ctypes.create_string_buffer(data, len(data))
        ok      = _k32.WriteFile(h, raw, len(data), ctypes.byref(written), None)
        if not ok or written.value != len(data):
            raise OSError(f'WriteFile wrote {written.value}/{len(data)} bytes')
        _k32.FlushFileBuffers(h)
    finally:
        _k32.CloseHandle(h)


def _open_delete_on_close(path: str):
    """
    Re-open the file AFTER CreateProcess with FILE_FLAG_DELETE_ON_CLOSE.
    The returned handle causes OS to delete file when we close it.
    Must grant FILE_SHARE_READ|WRITE|DELETE so running process can keep it open.
    """
    h = _k32.CreateFileW(
        path, _GR,
        _FSR | _FSW | _FSD,   # full sharing so child process keeps running
        None, _OE,
        _FDOC | _FAH | _FAS | _FAT,
        None
    )
    return h


def _secure_wipe(path: str):
    """Overwrite file content with random bytes, then explicitly delete."""
    try:
        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0
        if size > 0:
            h = _k32.CreateFileW(
                path, _GW, _FSR | _FSW | _FSD,
                None, _OE, 0, None
            )
            if h not in (_INV, 0, None):
                chunk   = os.urandom(min(size, 131072))
                written = _wt.DWORD(0)
                raw     = ctypes.create_string_buffer(chunk, len(chunk))
                _k32.WriteFile(h, raw, len(chunk), ctypes.byref(written), None)
                _k32.CloseHandle(h)
    except Exception:
        pass
    try:
        _k32.DeleteFileW(path)
    except Exception:
        pass


def _cleanup_thread(proc_h, del_h, exe_path: str, dir_path: str):
    """
    Waits for child process to exit, then wipes+deletes file and directory.
    del_h = FILE_FLAG_DELETE_ON_CLOSE handle (OS backup deletion guarantee).
    """
    def _work():
        # Wait for child to exit
        try:
            _k32.WaitForSingleObject(proc_h, _WINF)
            _k32.CloseHandle(proc_h)
        except Exception:
            pass
        time.sleep(0.4)

        # Wipe content with random bytes
        _secure_wipe(exe_path)

        # Close delete-on-close handle → OS deletes file (even if wipe failed)
        if del_h not in (_INV, 0, None):
            try:
                _k32.CloseHandle(del_h)
            except Exception:
                pass

        # Remove the hidden directory
        time.sleep(0.2)
        try:
            _k32.RemoveDirectoryW(dir_path)
        except Exception:
            pass

    threading.Thread(target=_work, daemon=True).start()


def _self_path():
    return sys.executable if getattr(sys, 'frozen', False) else __file__


def _launch():
    # ── 1. Read payload ───────────────────────────────────────────────────────
    with open(_self_path(), 'rb') as f:
        data = f.read()

    idx = data.rfind(PAYLOAD_MARKER)
    if idx == -1:
        _msgbox('Error', f'{_APP_NAME}\n\nPayload not found. File may be corrupted.')
        sys.exit(1)

    start   = idx + len(PAYLOAD_MARKER)
    payload = data[start: start + _PAYLOAD_SIZE]
    if len(payload) != _PAYLOAD_SIZE:
        _msgbox('Error', f'{_APP_NAME}\n\nPayload size mismatch. File may be corrupted.')
        sys.exit(1)

    # ── 2. Pick a hidden path ─────────────────────────────────────────────────
    secure_dir = _get_secure_dir()
    rand_name  = hashlib.sha256(os.urandom(16)).hexdigest()[:24].upper()
    exe_path   = os.path.join(secure_dir, rand_name + '.exe')

    # ── 3. Write payload to disk (close handle before CreateProcess) ──────────
    try:
        _write_payload(exe_path, payload)
    except Exception as e:
        _msgbox('Error', f'{_APP_NAME}\n\nFailed to prepare launch file:\n{e}')
        sys.exit(1)

    # ── 4. Launch via CreateProcessW ─────────────────────────────────────────
    si = _STARTUPINFO()
    si.cb          = ctypes.sizeof(si)
    si.dwFlags     = _SFSW
    si.wShowWindow = _SWSN
    pi = _PROCESS_INFORMATION()

    ok = _k32.CreateProcessW(
        exe_path, None, None, None, False,
        0, None, None,
        ctypes.byref(si), ctypes.byref(pi)
    )

    if not ok:
        err = _k32.GetLastError()
        # Best-effort cleanup since launch failed
        _secure_wipe(exe_path)
        try: _k32.RemoveDirectoryW(secure_dir)
        except Exception: pass
        _msgbox('Error',
                f'{_APP_NAME}\n\nFailed to launch.\nWin32 error: {err}')
        sys.exit(1)

    # Close thread handle (not needed)
    _k32.CloseHandle(pi.hThread)

    # ── 5. Delete file path entry IMMEDIATELY after launch ────────────────────
    # The OS has already mapped the PE into child process memory.
    # DeleteFileW removes the directory entry → path is gone, file is "(deleted)"
    # Process Explorer shows it as non-existent. No tool can copy it by path.
    # The child process continues running from memory mapping — unaffected.
    _k32.DeleteFileW(exe_path)

    # ── 6. Re-open with FILE_FLAG_DELETE_ON_CLOSE (belt-and-suspenders) ───────
    # This ensures OS-level deletion even if the wipe thread fails.
    del_h = _open_delete_on_close(exe_path)

    # ── 7. Anti-screenshot for launched process windows ───────────────────────
    try:
        _apply_screenshot_to_process(pi.dwProcessId)
    except NameError:
        pass

    # ── 8. Start cleanup thread ───────────────────────────────────────────────
    _cleanup_thread(pi.hProcess, del_h, exe_path, secure_dir)

    # ── 9. Stub exits ─────────────────────────────────────────────────────────
    sys.exit(0)


def _apply_screenshot_to_process(pid):
    """Apply WDA_EXCLUDEFROMCAPTURE to all windows of the launched process."""
    def _worker():
        WDA = 0x11
        CB  = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def _cb(hwnd, _):
            wp = ctypes.c_ulong(0)
            _u32.GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
            if wp.value == pid:
                _u32.SetWindowDisplayAffinity(hwnd, WDA)
            return True
        fn = CB(_cb)
        dl = time.time() + 15
        while time.time() < dl:
            _u32.EnumWindows(fn, 0)
            time.sleep(0.5)
    threading.Thread(target=_worker, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
#  Dialogs
# ═══════════════════════════════════════════════════════════════════════════════

def _msgbox(title, text, err=True):
    try:
        ctypes.windll.user32.MessageBoxW(0, text, title,
                                          0x10 if err else 0x40)
    except Exception: pass


def _dialog(hwid):
    if not _HAS_TK:
        _msgbox(_APP_NAME + ' - Activation',
                f'Activation required.\n\nHardware ID:\n{hwid}\n\n'
                f'Contact developer with this ID to receive your activation key.',
                err=False)
        return None

    res  = {'key': None}
    root = _tk.Tk()
    root.title(f'{_APP_NAME}  -  Activation')
    root.resizable(False, False)
    root.configure(bg='#111827')
    root.attributes('-topmost', True)

    W, H = 580, 480
    sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
    root.geometry(f'{W}x{H}+{(sw-W)//2}+{(sh-H)//2}')
    root.minsize(W, H)

    # Anti-screenshot on this dialog window
    try:
        root.update_idletasks()
        _apply_anti_screenshot(root.winfo_id())
    except NameError:
        pass

    # Set window title-bar icon from original EXE
    if _ICON_B64:
        try:
            import base64 as _b64i, tempfile as _tfi
            _ico = _b64i.b64decode(_ICON_B64)
            _ico_path = os.path.join(_tfi.gettempdir(), _APP_NAME + '_i.ico')
            with open(_ico_path, 'wb') as _fw: _fw.write(_ico)
            root.iconbitmap(_ico_path)
        except Exception:
            pass

    # ── Header ────────────────────────────────────────────────────────────────
    hf = _tk.Frame(root, bg='#1f2937', pady=14)
    hf.pack(fill='x')

    # Try to show real EXE icon (48×48) via PIL, else fallback lock emoji
    _icon_shown = False
    if _ICON_B64:
        try:
            import base64 as _b64, io as _io
            _raw = _b64.b64decode(_ICON_B64)
            from PIL import Image as _PI, ImageTk as _PIT
            _img = _PI.open(_io.BytesIO(_raw)).resize((48, 48), _PI.LANCZOS)
            _pim = _PIT.PhotoImage(_img)
            _lbl = _tk.Label(hf, image=_pim, bg='#1f2937')
            _lbl.image = _pim
            _lbl.pack()
            _icon_shown = True
        except Exception:
            pass

    if not _icon_shown:
        _tk.Label(hf, text='🔒', font=('Segoe UI Emoji', 22),
                  bg='#1f2937', fg='#ef4444').pack()

    _tk.Label(hf, text=_APP_NAME,
              font=('Segoe UI', 13, 'bold'), bg='#1f2937', fg='#f9fafb').pack()
    sub = ('Enter your activation key to unlock this program.'
           if _PER_MACHINE_MODE else
           'This copy is locked to a specific PC. Enter your activation key.')
    _tk.Label(hf, text=sub, font=('Segoe UI', 9),
              bg='#1f2937', fg='#9ca3af').pack()

    # ── Content ───────────────────────────────────────────────────────────────
    pad = _tk.Frame(root, bg='#111827')
    pad.pack(fill='x', padx=28, pady=8)

    # Always show HWID (both for per‑machine and classic modes)
    _tk.Label(pad,
              text='Your Hardware ID  (send this to developer to get your key):',
              font=('Segoe UI', 8), bg='#111827', fg='#9ca3af',
              anchor='w').pack(anchor='w')
    hv = _tk.StringVar(value=hwid)
    _tk.Entry(pad, textvariable=hv, font=('Consolas', 10),
              state='readonly', readonlybackground='#1f2937',
              fg='#34d399', relief='flat', bd=0
              ).pack(fill='x', ipady=7, pady=3)

    def _cphwid():
        root.clipboard_clear(); root.clipboard_append(hwid)
        _cl.config(text='✔ Copied')
        root.after(2000, lambda: _cl.config(text='Copy HWID'))
    _cl = _tk.Label(pad, text='Copy HWID', font=('Segoe UI', 8),
                    bg='#111827', fg='#6b7280', cursor='hand2')
    _cl.pack(anchor='e')
    _cl.bind('<Button-1>', lambda e: _cphwid())

    _tk.Label(pad, text='Activation Key:',
              font=('Segoe UI', 8), bg='#111827', fg='#9ca3af',
              anchor='w').pack(anchor='w', pady=(8, 0))
    kv = _tk.StringVar()
    ke = _tk.Entry(pad, textvariable=kv, font=('Consolas', 12),
                   bg='#1f2937', fg='#f9fafb',
                   insertbackground='#34d399', relief='flat', bd=0)
    ke.pack(fill='x', ipady=9, pady=3)
    ke.focus()

    def _fmt(*_):
        raw = kv.get().replace('-', '').upper()[:32]
        fmt = '-'.join(raw[i:i+8] for i in range(0, len(raw), 8))
        kv.set(fmt); ke.icursor(len(fmt))
    ke.bind('<KeyRelease>', _fmt)

    # Periodic protection re-check
    def _periodic():
        if _run_protection_checks():
            root.destroy(); _bail()
        root.after(4000, _periodic)
    root.after(2000, _periodic)

    sv = _tk.StringVar()
    _tk.Label(pad, textvariable=sv, font=('Segoe UI', 8),
              bg='#111827', fg='#ef4444').pack(anchor='w')

    # ── Buttons ───────────────────────────────────────────────────────────────
    bf = _tk.Frame(root, bg='#111827', pady=10)
    bf.pack()

    def _activate():
        if _run_protection_checks():
            root.destroy(); _bail(); return
        k = kv.get().strip()
        if _verify(hwid, k):
            res['key'] = k; root.destroy()
        else:
            sv.set("❌  Invalid key — does not match this PC's hardware.")
            ke.config(bg='#3b0f0f')
            root.after(350, lambda: ke.config(bg='#1f2937'))

    _tk.Button(bf, text='  Activate  ',
               font=('Segoe UI', 10, 'bold'),
               bg='#059669', fg='white', relief='flat',
               padx=24, pady=9, cursor='hand2',
               command=_activate).pack(side='left', padx=6)
    _tk.Button(bf, text='  Cancel  ',
               font=('Segoe UI', 10),
               bg='#374151', fg='#9ca3af', relief='flat',
               padx=24, pady=9, cursor='hand2',
               command=root.destroy).pack(side='left', padx=6)

    ke.bind('<Return>', lambda e: _activate())
    root.protocol('WM_DELETE_WINDOW', root.destroy)
    root.mainloop()
    return res['key']


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    if _run_protection_checks():
        _bail()
    try:
        _apply_anti_dump()
    except NameError:
        pass

    hwid = _get_hwid()

    if _run_protection_checks():
        _bail()

    stored = _reg_load()
    if stored and _verify(hwid, stored):
        _launch()
        return

    key = _dialog(hwid)
    if key and _verify(hwid, key):
        _reg_save(key)
        _launch()


if __name__ == '__main__':
    main()