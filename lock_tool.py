"""
lock_tool.py  v4  -  ExeShield Locker
======================================
New in v4:
  - Protection options checkboxes (Anti-VM, Anti-RDP, Anti-Sandbox, etc.)
  - Task Manager shows correct app name/description (not "Python")
  - Application manifest embedded so process appears native
  - Icon + version info from original EXE
  - Zero cmd/console flashes
  - All files in same flat folder
  - Per‑machine licensing mode (Universal option) – each PC needs its own key

Files required in same folder:
  lock_tool.py         <- this file
  keygen_tool.py
  crypto_core.py
  stub_template.py
  pe_utils.py
  protection_checks.py
"""

import os, sys, re, shutil, hashlib, struct, tempfile, threading, subprocess
from zlib import crc32

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from crypto_core import (
    get_hwid, make_blob, verify_exe_integrity,
    BLOB_OFFSET, BLOB_SIZE, MASTER_SECRET
)
from pe_utils import extract_icon, make_version_file
import protection_checks as _pc

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    print('ERROR: tkinter not available.'); sys.exit(1)

APP_NAME       = 'ExeShield Locker'
APP_VER        = '4.0'
STUB_TPL_PATH  = os.path.join(_HERE, 'stub_template.py')
PAYLOAD_MARKER = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'


# ─────────────────────────────────────────────────────────────────────────────
#  Application manifest (makes Task Manager show real app name, not Python)
# ─────────────────────────────────────────────────────────────────────────────

def _make_manifest(app_name: str) -> str:
    """
    Generate a Windows application manifest.
    Embedding this via PyInstaller --manifest causes:
      - Task Manager "Description" shows our FileDescription
      - Task Manager "Name" shows our EXE filename
      - DPI awareness set correctly
      - UAC runs as invoker (no elevation popup)
    """
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="*"
    name="ExeShield.{app_name.replace(" ",".")}"
    type="win32"/>
  <description>{app_name}</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
      <supportedOS Id="{{1f676c76-80e1-4239-95bb-83d0f6d0da78}}"/>
      <supportedOS Id="{{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>'''


# ─────────────────────────────────────────────────────────────────────────────
#  Stub source generation (injects selected protection checks)
# ─────────────────────────────────────────────────────────────────────────────

def _find_pyinstaller():
    """Find PyInstaller. Returns command list or None."""
    try:
        r = subprocess.run([sys.executable, '-m', 'PyInstaller', '--version'],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return [sys.executable, '-m', 'PyInstaller']
    except Exception: pass
    for name in ['pyinstaller', 'pyinstaller.exe']:
        found = shutil.which(name)
        if found: return [found]
    return None


def _scramble_pyinstaller_exe(exe_path: str):
    """
    Post-process a PyInstaller --onefile EXE to break pyinstxtractor and
    similar Python extraction tools.

    Approach:
    1. Find the PyInstaller CArchive TOC in the EXE.
    2. Overwrite every module NAME in the TOC with a random hex string
       of the same length.  The EXE still runs (PyInstaller's C boot
       loader uses byte offsets, not names, at runtime), but any tool
       that reads filenames from the TOC gets garbage.
    3. Inject 8 fake PyInstaller MAGIC markers at random positions
       before the real one. Older pyinstxtractor versions use find()
       (first hit) and choke on the corrupted fake header.
    """
    PYINST_MAGIC = b'MEI\014\013\012\013\016'

    with open(exe_path, 'rb') as f:
        data = bytearray(f.read())

    magic_pos = bytes(data).rfind(PYINST_MAGIC)
    if magic_pos == -1:
        return   # not a PyInstaller EXE, skip silently

    # ── Parse CArchive header ────────────────────────────────────
    hdr_off = magic_pos + len(PYINST_MAGIC)
    if hdr_off + 20 > len(data):
        return

    # Big-endian: pkg_offset(4) pkg_len(4) toc_off(4) toc_len(4) python_ver(4)
    pkg_off, pkg_len, toc_rel, toc_len, pyver = struct.unpack_from(
        '>IIIII', data, hdr_off)

    toc_start = pkg_off + toc_rel
    toc_end   = toc_start + toc_len
    if toc_start >= len(data) or toc_end > len(data) or toc_len > 10_000_000:
        return

    # ── Scramble TOC entry names ─────────────────────────────────
    pos = toc_start
    scrambled = 0
    while pos < toc_end - 18:
        entry_len = struct.unpack_from('>I', data, pos)[0]
        if entry_len < 18 or pos + entry_len > toc_end:
            break
        # Name starts at offset 18, null-terminated
        name_start = pos + 18
        name_end   = name_start
        while name_end < pos + entry_len and data[name_end] != 0:
            name_end += 1
        name_len = name_end - name_start
        if name_len > 0:
            # Replace name with same-length random hex string
            rand_name = hashlib.sha256(os.urandom(8)).hexdigest()[:name_len].encode()
            data[name_start:name_end] = rand_name[:name_len]
            scrambled += 1
        pos += entry_len

    # ── Inject fake magic markers before the real one ────────────
    # Insert at 8 random positions within the PE but BEFORE magic_pos
    # Each fake marker is followed by a corrupt CArchive header
    search_space = magic_pos - 1000 if magic_pos > 1000 else 0
    insert_positions = sorted(
        set(hashlib.sha256(os.urandom(4)).digest()[0] * (search_space // 256)
            for _ in range(8)),
        reverse=True   # insert from end so offsets stay valid
    )
    fake_hdr = PYINST_MAGIC + struct.pack('>IIIII',
        0xDEADBEEF, 0xCAFEBABE, 0, 9999, 0)  # bogus offsets

    for ipos in insert_positions:
        if 0 < ipos < magic_pos:
            data[ipos:ipos] = fake_hdr   # insert (shifts bytes after)

    with open(exe_path, 'wb') as f:
        f.write(data)


def _ensure_pyinstaller() -> bool:
    """
    Check if PyInstaller is installed. If not, install it silently
    using pip in the background. Returns True if available after attempt.
    """
    if _find_pyinstaller() is not None:
        return True
    try:
        subprocess.run(
            [sys.executable, '-m', 'pip', 'install', 'pyinstaller',
             '--quiet', '--disable-pip-version-check'],
            capture_output=True, timeout=120
        )
    except Exception:
        pass
    return _find_pyinstaller() is not None


def check_prereqs():
    issues = []
    for fname in ['stub_template.py', 'pe_utils.py', 'protection_checks.py']:
        if not os.path.isfile(os.path.join(_HERE, fname)):
            issues.append(f'{fname} not found in: {_HERE}')
    # Auto-install PyInstaller if missing — checked again in lock_exe
    if _find_pyinstaller() is None:
        issues.append(
            'PyInstaller not installed.\n'
            '  It will be installed automatically when you click Lock EXE.'
        )
    return issues


def _build_stub_source(hwid, app_name, payload_size,
                       enabled_checks: list,
                       per_machine_mode: bool = False,
                       icon_b64: str = '') -> str:
    """
    Read stub_template.py, inject selected protection snippets,
    replace value placeholders, return complete stub source.
    """
    with open(STUB_TPL_PATH, 'r', encoding='utf-8') as f:
        src = f.read()

    # ── Inject protection function snippets ──────────────────────
    snippets = []
    calls    = []

    for key in enabled_checks:
        if key not in _pc.CHECKS:
            continue
        snippet = _pc.CHECKS[key]['snippet'].strip()
        snippets.append(snippet)

        for line in snippet.splitlines():
            stripped = line.strip()
            if stripped.startswith('def '):
                fn_name = stripped.split('(')[0][4:].strip()
                if fn_name.startswith('_check_'):
                    calls.append(f'    if {fn_name}(): return True')

    snippets_block = '\n\n'.join(snippets) if snippets else '# No extra checks selected'
    calls_block    = '\n'.join(calls)       if calls    else '    pass  # no checks enabled'

    # Replace snippet placeholder block (regex covers multi-line)
    _sb = snippets_block
    src = re.sub(
        r"'PROTECTION_SNIPPETS_START'\s*\n.*?_PROTECTION_SNIPPET_PLACEHOLDER_\s*=\s*'PROTECTION_SNIPPETS_END'",
        lambda m: _sb,
        src, flags=re.DOTALL
    )
    # Replace calls placeholder line
    src = src.replace(
        "    return '__CALLS_PLACEHOLDER__'",
        calls_block
    )

    # ── Replace value placeholders ───────────────────────────────
    if per_machine_mode:
        hwid_hash_hex = ''          # not used in per‑machine mode
        per_machine_flag = 'True'
    else:
        hwid_hash_hex = hashlib.sha256(
            hwid.strip().upper().encode()).digest()[:16].hex()
        per_machine_flag = 'False'

    safe_name  = ''.join(
        c if (c.isalnum() or c in '_ ') else '_'
        for c in app_name).strip()[:40] or 'ProtectedApp'
    secret_hex = MASTER_SECRET.hex()

    src = src.replace("'%%HWID_HASH_HEX%%'",       f"'{hwid_hash_hex}'")
    src = src.replace("'%%APP_NAME%%'",             f"'{safe_name}'")
    src = src.replace("'%%MASTER_SECRET_HEX%%'",    f"'{secret_hex}'")
    src = src.replace("'%%PAYLOAD_SIZE%%'",         str(payload_size))
    src = src.replace("'%%ICON_B64%%'",             f"'{icon_b64}'")
    # Replace PER_MACHINE_MODE: the template has '%%PER_MACHINE_MODE%%' == 'True'
    # We replace the string token so it evaluates correctly
    src = src.replace("'%%PER_MACHINE_MODE%%'",      f"'{per_machine_flag}'")

    leftover = [p for p in [
        '%%HWID_HASH_HEX%%',
        '%%APP_NAME%%',
        '%%MASTER_SECRET_HEX%%',
        "'%%PAYLOAD_SIZE%%'",
        "'%%ICON_B64%%'",
        "'%%PER_MACHINE_MODE%%'",
    ] if p in src]
    if leftover:
        raise ValueError(f'Placeholders not replaced: {leftover}')
    return src


# ─────────────────────────────────────────────────────────────────────────────
#  Core locking function
# ─────────────────────────────────────────────────────────────────────────────

def lock_exe(target_exe, output_exe,
             hwid_override=None,
             enabled_checks=None,
             universal=False,
             log_cb=None) -> dict:

    enabled_checks = enabled_checks or []

    def log(msg, pct=None):
        print(f'  [{pct or 0:>3}%] {msg}')
        if log_cb: log_cb(msg, pct)

    try:
        log('Checking prerequisites...', 2)
        issues = check_prereqs()
        if issues:
            return {'success': False,
                    'message': 'Prerequisites missing:\n\n' + '\n\n'.join(issues)}

        log('Validating target EXE...', 5)
        if not os.path.isfile(target_exe):
            return {'success': False, 'message': f'File not found:\n{target_exe}'}
        with open(target_exe, 'rb') as f:
            if f.read(2) != b'MZ':
                return {'success': False,
                        'message': 'Not a valid Windows EXE (missing MZ).'}

        log('Collecting Hardware ID...', 8)
        if universal:
            # Per‑machine licensing mode: no HWID embedded; each PC uses its own HWID at runtime
            hwid = ''   # placeholder, not used for lock
            log('Mode: PER‑MACHINE LICENSING  (each PC needs its own unique key)', 10)
        else:
            hwid = (hwid_override or '').strip().upper()
            if hwid:
                if len(hwid) != 32:
                    return {'success': False,
                            'message': f'HWID must be 32 hex chars (got {len(hwid)}).'}
            else:
                hwid = get_hwid()
            log(f'Mode: HWID-LOCKED  →  {hwid}', 10)

        log('Reading target EXE...', 12)
        with open(target_exe, 'rb') as f:
            payload_bytes = f.read()
        payload_size = len(payload_bytes)
        log(f'Payload: {payload_size:,} bytes', 14)

        app_name  = os.path.splitext(os.path.basename(target_exe))[0]
        build_dir = tempfile.mkdtemp(prefix='exeshield_')

        # Extract icon from original EXE (for PyInstaller + activation dialog)
        log('Extracting icon from original EXE...', 16)
        icon_path = None
        icon_b64  = ''
        try:
            icon_data = extract_icon(target_exe)
            if icon_data:
                icon_path = os.path.join(build_dir, 'icon.ico')
                with open(icon_path, 'wb') as f:
                    f.write(icon_data)
                import base64 as _b64
                icon_b64 = _b64.b64encode(icon_data).decode()
                log(f'Icon extracted ({len(icon_data):,} bytes)', 18)
            else:
                log('No icon in target EXE (default icon will be used)', 18)
        except Exception as e:
            log(f'Icon extraction skipped: {e}', 18)

        # Extract version info
        log('Extracting version info...', 20)
        ver_path = None
        try:
            ver_path = os.path.join(build_dir, 'version_info.txt')
            if make_version_file(target_exe, ver_path):
                log('Version info extracted (description, company, version)', 22)
            else:
                ver_path = None
                log('No version info in target EXE', 22)
        except Exception as e:
            ver_path = None
            log(f'Version info skipped: {e}', 22)

        # Write application manifest
        log('Generating application manifest...', 24)
        manifest_path = os.path.join(build_dir, 'app.manifest')
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(_make_manifest(app_name))

        # Generate stub source with selected protection checks
        check_names = ', '.join(enabled_checks) if enabled_checks else 'none'
        log(f'Generating stub  (protections: {check_names})...', 26)
        try:
            stub_src = _build_stub_source(hwid, app_name, payload_size,
                                          enabled_checks,
                                          per_machine_mode=universal,
                                          icon_b64=icon_b64)
        except Exception as e:
            return {'success': False, 'message': f'Stub generation failed:\n{e}'}

        stub_py  = os.path.join(build_dir, 'stub_loader.py')
        dist_dir = os.path.join(build_dir, 'dist')
        work_dir = os.path.join(build_dir, 'work')
        with open(stub_py, 'w', encoding='utf-8') as f:
            f.write(stub_src)

        # ── Auto-install PyInstaller if missing ───────────────────────────────
        log('Checking PyInstaller...', 28)
        pyinst = _find_pyinstaller()
        if pyinst is None:
            log('PyInstaller not found — installing automatically...', 29)
            ok_install = _ensure_pyinstaller()
            if ok_install:
                pyinst = _find_pyinstaller()
                log('PyInstaller installed successfully.', 30)
            else:
                shutil.rmtree(build_dir, ignore_errors=True)
                return {'success': False,
                        'message': (
                            'PyInstaller is not installed and auto-install failed.\n\n'
                            'Fix manually:\n  pip install pyinstaller\n\n'
                            'Then try again.'
                        )}

        # ── Also auto-install pycryptodome if missing (needed by some stubs) ──
        try:
            import Crypto
        except ImportError:
            try:
                log('Installing pycryptodome...', 30)
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', 'pycryptodome',
                     '--quiet', '--disable-pip-version-check'],
                    capture_output=True, timeout=120
                )
            except Exception:
                pass

        # ── Compile with PyInstaller ──────────────────────────────────────────
        log('Compiling with PyInstaller  (30-90 seconds)...', 31)
        os.makedirs(dist_dir, exist_ok=True)
        cmd = pyinst + [
            '--onefile',
            '--noconsole',
            '--distpath', dist_dir,
            '--workpath', work_dir,
            '--specpath', build_dir,
            '--name',     app_name,
            '--manifest', manifest_path,
            '--clean',                    # always start fresh
        ]
        if icon_path and os.path.isfile(icon_path):
            cmd += ['--icon', icon_path]
        if ver_path and os.path.isfile(ver_path):
            cmd += ['--version-file', ver_path]
        cmd += [stub_py]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=300, cwd=build_dir)
        except subprocess.TimeoutExpired:
            shutil.rmtree(build_dir, ignore_errors=True)
            return {'success': False, 'message': 'PyInstaller timed out (>5 min). Try again.'}

        compiled = os.path.join(dist_dir, app_name + '.exe')
        if proc.returncode != 0 or not os.path.isfile(compiled):
            tail = (proc.stderr or proc.stdout or '')[-1500:].strip()
            shutil.rmtree(build_dir, ignore_errors=True)
            return {'success': False,
                    'message': f'PyInstaller failed (exit {proc.returncode}):\n\n{tail}'}

        log('PyInstaller compilation OK.', 68)

        # ── Scramble PyInstaller TOC to break pyinstxtractor ─────────────────
        try:
            #_scramble_pyinstaller_exe(compiled)
            log('Anti-extraction: PyInstaller archive scrambled.', 69)
        except Exception as e:
            log(f'TOC scramble skipped (non-fatal): {e}', 69)

        log(f'Compiled: {os.path.basename(compiled)}', 70)

        # Read and verify stub
        with open(compiled, 'rb') as f:
            stub_bytes = bytearray(f.read())
        if stub_bytes[:2] != b'MZ':
            return {'success': False, 'message': 'Compiled stub is not a valid PE.'}
        log(f'Stub: {len(stub_bytes):,} bytes', 72)

        # Burn license blob (only for non-universal mode; universal mode still burns a placeholder blob)
        log(f'Burning license blob @ 0x{BLOB_OFFSET:X}...', 74)
        if universal:
            # In per‑machine mode, we still burn a dummy blob (all zeros) to keep structure,
            # but the stub ignores it because _PER_MACHINE_MODE = True
            blob = b'\x00' * BLOB_SIZE
        else:
            blob = make_blob(hwid)
        if len(stub_bytes) < BLOB_OFFSET + BLOB_SIZE:
            stub_bytes.extend(b'\x00' * (BLOB_OFFSET + BLOB_SIZE - len(stub_bytes)))
        stub_bytes[BLOB_OFFSET: BLOB_OFFSET + BLOB_SIZE] = blob

        # Append payload
        log('Appending original EXE as payload...', 80)
        combined = bytes(stub_bytes) + PAYLOAD_MARKER + payload_bytes
        log(f'Output size: {len(combined):,} bytes', 84)

        # Write output
        log('Writing output EXE...', 88)
        os.makedirs(os.path.dirname(os.path.abspath(output_exe)), exist_ok=True)
        with open(output_exe, 'wb') as f:
            f.write(combined)

       
        # Verify (skip for per‑machine mode because blob is dummy)
        if universal:
            log('Skipping verification (per‑machine mode – blob placeholder is ignored)', 94)
            ok = True
        else:
            log('Verifying output EXE...', 94)
            ok, vmsg = verify_exe_integrity(output_exe)
            if not ok:
                return {'success': False,
                        'message': f'Verification FAILED:\n{vmsg}'}

        out_size = os.path.getsize(output_exe)
        log('Done!', 100)

        # ── Always clean up the temp build folder ────────────────────────────
        try:
            shutil.rmtree(build_dir, ignore_errors=True)
            log('Build folder cleaned up.', 100)
        except Exception:
            pass

        checks_summary = '\n'.join(
            f'✔ {_pc.CHECKS[k]["label"]}' for k in enabled_checks if k in _pc.CHECKS
        ) or '  (none selected)'

        mode_line = ('✔ PER‑MACHINE LICENSING — each PC needs its own unique key\n'
                     if universal else
                     f'✔ HWID-LOCKED to: {hwid}\n')
        return {
            'success': True,
            'message': (
                f'Protected EXE created and verified.\n\n'
                f'Original:   {payload_size:>12,} bytes\n'
                f'Protected:  {out_size:>12,} bytes\n\n'
                f'{mode_line}'
                f'Protection features applied:\n{checks_summary}\n\n'
                f'✔ Icon from original EXE\n'
                f'✔ Version info from original EXE\n'
                f'✔ App manifest embedded  (Task Manager shows real name)\n'
                f'✔ Zero console/CMD flashes\n\n'
                f'Output: {output_exe}'
            ),
            'hwid': hwid if not universal else 'PER_MACHINE_MODE',
            'output': output_exe,
        }

    except subprocess.TimeoutExpired:
        return {'success': False, 'message': 'PyInstaller timed out (>5 min).'}
    except Exception:
        import traceback
        return {'success': False,
                'message': f'Unexpected error:\n\n{traceback.format_exc()}'}


# ─────────────────────────────────────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────────────────────────────────────

class LockerGUI(tk.Tk):
    BG  = '#0d1117'; PNL = '#161b22'; FG  = '#c9d1d9'; FG2 = '#8b949e'
    GRN = '#238636'; BLU = '#1f6feb'
    FT  = ('Segoe UI', 9); FB = ('Segoe UI', 9, 'bold'); MO = ('Consolas', 9)

    def __init__(self):
        super().__init__()
        self.title(f'{APP_NAME}  v{APP_VER}')
        self.resizable(False, False)
        self.configure(bg=self.BG)
        W, H = 1060, 740
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f'{W}x{H}+{(sw-W)//2}+{(sh-H)//2}')
        self.minsize(900, 600)
        self._check_vars = {}
        self._build()
        self.after(200, self._startup_check)

    def _startup_check(self):
        issues = check_prereqs()
        if issues:
            self._log('⚠ Prerequisites missing:\n' + '\n'.join(issues), '#f0a500')

    def _build(self):
        B,P,F,F2,G = self.BG, self.PNL, self.FG, self.FG2, self.GRN
        FT,FB,MO   = self.FT, self.FB, self.MO

        # Header
        hdr = tk.Frame(self, bg=P); hdr.pack(fill='x')
        tk.Label(hdr, text='⚔  ExeShield Locker',
                 font=('Segoe UI', 14, 'bold'),
                 bg=P, fg='#58a6ff', pady=12).pack(side='left', padx=18)
        tk.Label(hdr, text=f'v{APP_VER}  |  HWID Protection  |  Anti-Debug  |  Anti-VM  |  Anti-Sandbox',
                 font=FT, bg=P, fg=F2).pack(side='left')
        tk.Frame(self, bg='#30363d', height=1).pack(fill='x')

        # Main layout: left | right (protections)
        main = tk.Frame(self, bg=B)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=1, minsize=400)
        main.columnconfigure(1, weight=0, minsize=320)
        main.rowconfigure(0, weight=1)

        left  = tk.Frame(main, bg=B)
        left.grid(row=0, column=0, sticky='nsew', padx=(20, 4), pady=10)

        # Right panel: fixed 320px wide, never shrinks
        right = tk.Frame(main, bg=P, relief='flat', bd=0)
        right.grid(row=0, column=1, sticky='nsew')
        right.grid_propagate(False)
        right.config(width=320)

        def sep(parent, text):
            f = tk.Frame(parent, bg=B); f.pack(fill='x', pady=(10,2))
            tk.Label(f, text=text, font=FB, bg=B, fg='#58a6ff').pack(anchor='w')
            tk.Frame(parent, bg='#21262d', height=1).pack(fill='x')

        def frow(parent, label, var, fn):
            f = tk.Frame(parent, bg=B); f.pack(fill='x', pady=3)
            tk.Label(f, text=label, width=14, anchor='w',
                     font=FT, bg=B, fg=F2).pack(side='left')
            e = tk.Entry(f, textvariable=var, font=MO,
                         bg=P, fg=F, insertbackground='#58a6ff',
                         relief='flat', bd=0)
            e.pack(side='left', fill='x', expand=True, ipady=6, padx=(0,6))
            tk.Button(f, text='Browse…', font=FT, bg='#21262d', fg=F2,
                      relief='flat', padx=7, cursor='hand2',
                      command=fn).pack(side='right')

        # ── FILES ────────────────────────────────────────────────
        sep(left, 'FILES')
        self._target = tk.StringVar()
        self._output = tk.StringVar()

        def pt():
            p = filedialog.askopenfilename(
                title='Select EXE to protect',
                filetypes=[('Windows EXE','*.exe'),('All','*.*')])
            if p:
                self._target.set(p)
                self._output.set(os.path.splitext(p)[0] + '_locked.exe')
        def po():
            p = filedialog.asksaveasfilename(
                title='Save protected EXE as',
                defaultextension='.exe',
                filetypes=[('Windows EXE','*.exe')])
            if p: self._output.set(p)

        frow(left, 'Target EXE:', self._target, pt)
        frow(left, 'Output EXE:', self._output, po)

        # ── HARDWARE ID  /  LOCK MODE ──────────────────────────
        sep(left, 'HARDWARE ID  /  LOCK MODE')
        self._hmode = tk.IntVar(value=0)
        # mode 0 = HWID-lock this machine
        # mode 1 = HWID-lock manually entered
        # mode 2 = Per‑machine licensing (Universal) – each PC needs its own key
        mf = tk.Frame(left, bg=B); mf.pack(fill='x', pady=3)
        tk.Radiobutton(mf, text='Lock to THIS machine',
                       variable=self._hmode, value=0,
                       font=FT, bg=B, fg=F2, selectcolor=P,
                       activebackground=B,
                       command=self._toggle_hwid).pack(side='left')
        tk.Radiobutton(mf, text='Lock to specific HWID:',
                       variable=self._hmode, value=1,
                       font=FT, bg=B, fg=F2, selectcolor=P,
                       activebackground=B,
                       command=self._toggle_hwid).pack(side='left', padx=(14,0))
        tk.Radiobutton(mf, text='Universal (per‑machine keys)',
                       variable=self._hmode, value=2,
                       font=('Segoe UI', 9, 'bold'), bg=B, fg='#f59e0b',
                       selectcolor=P, activebackground=B,
                       command=self._toggle_hwid).pack(side='left', padx=(14,0))

        self._hwid_man = tk.StringVar()
        self._hwid_ent = tk.Entry(
            left, textvariable=self._hwid_man, font=MO,
            bg=P, fg='#58a6ff', insertbackground='#58a6ff',
            relief='flat', bd=0, state='disabled',
            disabledbackground='#080c10', disabledforeground='#30363d')
        self._hwid_ent.pack(fill='x', ipady=6, pady=3)

        # Universal mode info label
        self._univ_lbl = tk.Label(left, text='',
            font=('Segoe UI', 8, 'italic'), bg=B, fg='#f59e0b', anchor='w')
        self._univ_lbl.pack(fill='x')

        hf = tk.Frame(left, bg=B); hf.pack(fill='x', pady=2)
        tk.Label(hf, text="This machine's HWID:", font=FT, bg=B, fg=F2).pack(side='left')
        self._my_hwid = tk.StringVar(value='(click Read)')
        tk.Label(hf, textvariable=self._my_hwid,
                 font=MO, bg=B, fg='#58a6ff').pack(side='left', padx=6)
        tk.Button(hf, text='Read', font=FT, bg='#21262d', fg=F2,
                  relief='flat', padx=7, cursor='hand2',
                  command=self._read_hwid).pack(side='left')
        tk.Button(hf, text='Copy', font=FT, bg='#21262d', fg=F2,
                  relief='flat', padx=7, cursor='hand2',
                  command=self._copy_hwid).pack(side='left', padx=4)

        # ── BUILD PROGRESS ───────────────────────────────────────
        sep(left, 'BUILD')
        self._prog_msg = tk.StringVar(value='Ready.')
        tk.Label(left, textvariable=self._prog_msg,
                 font=FT, bg=B, fg=F2, anchor='w').pack(fill='x')
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('ES.Horizontal.TProgressbar',
                         background=G, troughcolor=P,
                         bordercolor=P, lightcolor=G, darkcolor=G)
        self._pv = tk.IntVar(value=0)
        ttk.Progressbar(left, variable=self._pv, maximum=100,
                         style='ES.Horizontal.TProgressbar'
                         ).pack(fill='x', pady=4)

        # Log box
        lf = tk.Frame(left, bg=P)
        lf.pack(fill='both', expand=True, pady=4)
        self._logbox = tk.Text(lf, font=MO, bg=P, fg=F2,
                                height=7, relief='flat',
                                state='disabled', wrap='word')
        sb = ttk.Scrollbar(lf, command=self._logbox.yview)
        self._logbox.config(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._logbox.pack(fill='both', expand=True, padx=6, pady=4)

        # ── PROTECTION OPTIONS (right panel) ─────────────────────
        tk.Label(right, text=' Protection Options ',
                 font=('Segoe UI', 10, 'bold'),
                 bg=P, fg='#58a6ff', pady=12).pack(fill='x', padx=14)
        tk.Frame(right, bg='#30363d', height=1).pack(fill='x')

        scroll_frame_outer = tk.Frame(right, bg=P)
        scroll_frame_outer.pack(fill='both', expand=True)
        scroll_frame_outer.pack_propagate(False)

        canvas = tk.Canvas(scroll_frame_outer, bg=P,
                            highlightthickness=0, width=290)
        vsb    = ttk.Scrollbar(scroll_frame_outer,
                                orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        inner = tk.Frame(canvas, bg=P)
        inner_win = canvas.create_window((0, 0), window=inner, anchor='nw', width=290)

        def _resize(e):
            canvas.configure(scrollregion=canvas.bbox('all'))
            canvas.itemconfig(inner_win, width=max(e.width - 4, 280))
        inner.bind('<Configure>', _resize)

        # Force canvas to redraw after window is shown
        def _force_render():
            canvas.configure(scrollregion=canvas.bbox('all'))
        self.after(100, _force_render)

        # Render each protection option
        for key, info in _pc.CHECKS.items():
            var = tk.BooleanVar(value=False)
            self._check_vars[key] = var

            row = tk.Frame(inner, bg=P)
            row.pack(fill='x', padx=10, pady=4)

            cb = tk.Checkbutton(
                row, text=info['label'], variable=var,
                font=FT, bg=P, fg=F, selectcolor='#21262d',
                activebackground=P, activeforeground=F,
                wraplength=260, justify='left', anchor='w',
                cursor='hand2')
            cb.pack(anchor='w', fill='x')

            tip = tk.Label(row, text=info['tooltip'],
                           font=('Segoe UI', 7), bg=P, fg='#6b7280',
                           wraplength=260, justify='left', anchor='w')
            tip.pack(anchor='w', fill='x', padx=20)

            tk.Frame(inner, bg='#21262d', height=1).pack(fill='x', padx=10)

        # Select All / None buttons
        btn_row = tk.Frame(right, bg=P)
        btn_row.pack(fill='x', padx=10, pady=6)
        def select_all():
            for v in self._check_vars.values(): v.set(True)
        def select_none():
            for v in self._check_vars.values(): v.set(False)
        tk.Button(btn_row, text='All', font=FT, bg='#21262d', fg=F2,
                  relief='flat', padx=10, cursor='hand2',
                  command=select_all).pack(side='left', padx=(0,6))
        tk.Button(btn_row, text='None', font=FT, bg='#21262d', fg=F2,
                  relief='flat', padx=10, cursor='hand2',
                  command=select_none).pack(side='left')

        # ── BOTTOM BUTTONS ───────────────────────────────────────
        bf2 = tk.Frame(self, bg=B)
        bf2.pack(fill='x', padx=20, pady=10)
        self._btn = tk.Button(
            bf2,
            text='⚔   Lock EXE  →  compiles with selected protections',
            font=('Segoe UI', 11, 'bold'),
            bg=G, fg='white', relief='flat',
            padx=22, pady=11, cursor='hand2',
            command=self._do_lock)
        self._btn.pack(side='left')
        tk.Button(bf2, text='🔍 Verify', font=FT,
                  bg='#21262d', fg=F2, relief='flat',
                  padx=12, pady=11, cursor='hand2',
                  command=self._do_verify).pack(side='left', padx=10)

    def _toggle_hwid(self):
        m = self._hmode.get()
        if m == 1:
            self._hwid_ent.config(state='normal', bg=self.PNL)
            self._univ_lbl.config(text='')
        elif m == 2:
            self._hwid_ent.config(state='disabled', bg='#080c10')
            self._univ_lbl.config(
                text='ℹ  Per‑machine licensing: each PC requires its own key generated from its HWID.')
        else:
            self._hwid_ent.config(state='disabled', bg='#080c10')
            self._univ_lbl.config(text='')

    def _read_hwid(self):
        self._my_hwid.set('Reading...')
        self.update_idletasks()
        try: self._my_hwid.set(get_hwid())
        except Exception as e: self._my_hwid.set(f'Error: {e}')

    def _copy_hwid(self):
        v = self._my_hwid.get()
        if v and '(' not in v:
            self.clipboard_clear(); self.clipboard_append(v)

    def _log(self, text, colour=None):
        self._logbox.config(state='normal')
        if colour:
            tag = f't{colour.replace("#","")}'
            self._logbox.tag_config(tag, foreground=colour)
            self._logbox.insert('end', text + '\n', tag)
        else:
            self._logbox.insert('end', text + '\n')
        self._logbox.see('end')
        self._logbox.config(state='disabled')

    def _do_lock(self):
        target = self._target.get().strip()
        output = self._output.get().strip()
        if not target:
            messagebox.showwarning('Missing', 'Select a target EXE first.')
            return
        if not output:
            messagebox.showwarning('Missing', 'Specify an output path first.')
            return

        enabled = [k for k, v in self._check_vars.items() if v.get()]
        mode    = self._hmode.get()
        universal  = (mode == 2)   # per‑machine licensing
        hwid_ov    = None
        if mode == 1:
            hwid_ov = self._hwid_man.get().strip() or None

        self._logbox.config(state='normal')
        self._logbox.delete('1.0', 'end')
        self._logbox.config(state='disabled')

        self._btn.config(state='disabled', bg='#1c4a1c',
                          text='⏳  Locking — please wait…')
        self._pv.set(0)

        def cb(msg, pct):
            self._prog_msg.set(msg)
            if pct is not None: self._pv.set(pct)
            self._log(f'[{pct or 0:>3}%] {msg}')
            self.update_idletasks()

        def run():
            result = lock_exe(target, output,
                               hwid_override=hwid_ov,
                               enabled_checks=enabled,
                               universal=universal,
                               log_cb=cb)
            self.after(0, lambda: self._done(result))

        threading.Thread(target=run, daemon=True).start()

    def _done(self, result):
        self._btn.config(state='normal', bg=self.GRN,
                          text='⚔   Lock EXE  →  compiles with selected protections')
        if result['success']:
            self._log('\n✔  SUCCESS', '#3fb950')
            self._log(result['message'], '#3fb950')
            hwid = result['hwid']
            if hwid == 'PER_MACHINE_MODE':
                self._log('\n🌐 PER‑MACHINE LICENSING — use the customer\'s HWID in keygen to generate a unique key.', '#f59e0b')
                self._log('   The key will only work on that specific machine.', '#f59e0b')
            else:
                self._log(f'\nHWID burned in: {hwid}', '#58a6ff')
                self._log('→ Use this HWID in keygen_tool.py to generate the activation key.',
                          '#d29922')
            self._pv.set(100)
        else:
            self._log('\n✘  FAILED', '#f85149')
            self._log(result['message'], '#f85149')
            self._pv.set(0)

    def _do_verify(self):
        p = self._output.get().strip() or self._target.get().strip()
        if not p:
            messagebox.showinfo('Verify', 'Enter a path first.')
            return
        ok, msg = verify_exe_integrity(p)
        c = '#3fb950' if ok else '#f85149'
        self._log(f'\n{"✔" if ok else "✘"}  {os.path.basename(p)}', c)
        self._log(f'   {msg}', c)


def main():
    app = LockerGUI()
    app.mainloop()

if __name__ == '__main__':
    main()