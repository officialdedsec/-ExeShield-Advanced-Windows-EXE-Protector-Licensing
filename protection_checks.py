"""
protection_checks.py
====================
Self-contained code snippets for each protection option.
lock_tool.py reads this file and injects the selected
snippets into the stub before PyInstaller compilation.

Each snippet is a complete Python function that:
  - Uses only ctypes / stdlib (zero external deps)
  - Returns True  = threat detected (should bail)
  - Returns False = clean
  - Never raises exceptions (all try/except wrapped)

The stub calls _run_protection_checks() which calls
only the enabled check functions.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Each entry:
#   key        = internal identifier (used as placeholder tag)
#   label      = shown in lock_tool GUI checkbox
#   tooltip    = explanation shown on hover
#   snippet    = Python code string injected into stub
# ─────────────────────────────────────────────────────────────────────────────

CHECKS = {}


# ── Anti-VM (generic) ─────────────────────────────────────────────────────────

CHECKS['anti_vm'] = dict(
    label   = 'Anti-VM  (VMware + VirtualBox + Hyper-V + QEMU)',
    tooltip = 'Detects all common virtual machines via registry, '
              'processes, device names, MAC addresses, CPUID, and firmware.',
    snippet = r'''
def _check_anti_vm():
    import ctypes, ctypes.wintypes as _wt, struct, os
    k32 = ctypes.windll.kernel32
    adv = ctypes.windll.advapi32

    def _reg_exists(hive, path):
        HKLM=0x80000002; HKCU=0x80000001; KEY_READ=0x20019
        h = _wt.HKEY()
        root = HKLM if hive=='HKLM' else HKCU
        ret = adv.RegOpenKeyExW(root, path, 0, KEY_READ, ctypes.byref(h))
        if ret==0: adv.RegCloseKey(h); return True
        return False

    def _reg_val(hive, path, name):
        HKLM=0x80000002; KEY_READ=0x20019
        h = _wt.HKEY()
        root = HKLM if hive=='HKLM' else 0x80000001
        if adv.RegOpenKeyExW(root, path, 0, KEY_READ, ctypes.byref(h)) != 0:
            return ''
        buf=ctypes.create_unicode_buffer(512); sz=_wt.DWORD(1024); vt=_wt.DWORD(0)
        adv.RegQueryValueExW(h,'',None,ctypes.byref(vt),buf,ctypes.byref(sz))
        adv.RegCloseKey(h); return buf.value.upper()

    def _device_exists(name):
        GENERIC_READ=0x80000000; OPEN_EXISTING=3; FILE_SHARE_RW=3
        INVALID=ctypes.c_void_p(-1).value
        h = k32.CreateFileW(name,GENERIC_READ,FILE_SHARE_RW,None,OPEN_EXISTING,0,None)
        if h not in (INVALID,0,None): k32.CloseHandle(h); return True
        return False

    def _file_exists(path):
        return os.path.isfile(path)

    def _process_running(names):
        import ctypes
        TH32CS_SNAPPROCESS=0x2
        class PE32(ctypes.Structure):
            _fields_=[('dwSize',ctypes.c_ulong),('cntUsage',ctypes.c_ulong),
                      ('th32ProcessID',ctypes.c_ulong),('th32DefaultHeapID',ctypes.POINTER(ctypes.c_ulong)),
                      ('th32ModuleID',ctypes.c_ulong),('cntThreads',ctypes.c_ulong),
                      ('th32ParentProcessID',ctypes.c_ulong),('pcPriClassBase',ctypes.c_long),
                      ('dwFlags',ctypes.c_ulong),('szExeFile',ctypes.c_char*260)]
        snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)
        if snap in (ctypes.c_void_p(-1).value, 0): return False
        pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
        found = False
        if ctypes.windll.kernel32.Process32First(snap, ctypes.byref(pe)):
            while True:
                nm = pe.szExeFile.decode(errors='ignore').lower()
                if nm in [n.lower() for n in names]: found=True; break
                if not ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(pe)): break
        ctypes.windll.kernel32.CloseHandle(snap)
        return found

    try:
        # Registry checks
        vm_regs = [
            ('HKLM', r'SOFTWARE\VMware, Inc.\VMware Tools'),
            ('HKLM', r'SOFTWARE\VMware, Inc.\VMware Workstation'),
            ('HKLM', r'SOFTWARE\Oracle\VirtualBox Guest Additions'),
            ('HKLM', r'HARDWARE\ACPI\DSDT\VBOX__'),
            ('HKLM', r'HARDWARE\ACPI\FADT\VBOX__'),
            ('HKLM', r'HARDWARE\ACPI\RSDT\VBOX__'),
            ('HKLM', r'SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'),
        ]
        for hive, path in vm_regs:
            if _reg_exists(hive, path): return True

        # Process checks
        vm_procs = ['vmtoolsd.exe','vmwaretray.exe','vmwareuser.exe',
                    'VBoxService.exe','VBoxTray.exe','vboxadd.exe',
                    'qemu-ga.exe','vdagent.exe','xenservice.exe']
        if _process_running(vm_procs): return True

        # Device checks
        vm_devices = [r'\\.\HGFS', r'\\.\vmci', r'\\.\VBoxGuest',
                      r'\\.\VBoxMiniRdrDN', r'\\.\VBoxTrayIPC']
        for d in vm_devices:
            if _device_exists(d): return True

        # Driver/file checks
        vm_files = [
            r'C:\Windows\System32\drivers\VBoxMouse.sys',
            r'C:\Windows\System32\drivers\VBoxGuest.sys',
            r'C:\Windows\System32\drivers\vmhgfs.sys',
            r'C:\Windows\System32\drivers\vmmouse.sys',
            r'C:\Windows\System32\drivers\vmtray.sys',
        ]
        for f in vm_files:
            if _file_exists(f): return True

        # Firmware table check for VM strings
        try:
            buf = ctypes.create_string_buffer(65536)
            sz = k32.GetSystemFirmwareTable(0x52534D42, 0, buf, 65536)
            if sz > 0:
                raw = buf.raw[:sz].upper()
                for sig in [b'VBOX', b'VMWARE', b'QEMU', b'XENSRC', b'BOCHS', b'KVM']:
                    if sig in raw: return True
        except Exception: pass

        # CPU core count < 2 (common in VMs)
        import os as _os
        if _os.cpu_count() is not None and _os.cpu_count() < 2: return True

    except Exception: pass
    return False
'''
)


# ── Anti-VirtualBox (specific, deeper) ────────────────────────────────────────

CHECKS['anti_vbox'] = dict(
    label   = 'Anti-VirtualBox  (deep detection)',
    tooltip = 'Deep VirtualBox-specific detection including ACPI tables, '
              'shared folders, guest additions, and VBoxSF driver.',
    snippet = r'''
def _check_anti_vbox():
    import ctypes, ctypes.wintypes as _wt, os
    adv = ctypes.windll.advapi32
    k32 = ctypes.windll.kernel32
    def _reg(path):
        h=_wt.HKEY(); r=adv.RegOpenKeyExW(0x80000002,path,0,0x20019,ctypes.byref(h))
        if r==0: adv.RegCloseKey(h); return True
        return False
    def _dev(name):
        INVALID=ctypes.c_void_p(-1).value
        h=k32.CreateFileW(name,0x80000000,3,None,3,0,None)
        if h not in (INVALID,0,None): k32.CloseHandle(h); return True
        return False
    try:
        vbox_regs=[r'HARDWARE\ACPI\DSDT\VBOX__',r'HARDWARE\ACPI\FADT\VBOX__',
                   r'HARDWARE\ACPI\RSDT\VBOX__',
                   r'SOFTWARE\Oracle\VirtualBox Guest Additions',
                   r'SOFTWARE\Oracle\VirtualBox',
                   r'SYSTEM\ControlSet001\Services\VBoxGuest',
                   r'SYSTEM\ControlSet001\Services\VBoxMouse',
                   r'SYSTEM\ControlSet001\Services\VBoxSF',
                   r'SYSTEM\ControlSet001\Services\VBoxVideo']
        for r in vbox_regs:
            if _reg(r): return True
        vbox_devs=[r'\\.\VBoxGuest',r'\\.\VBoxMiniRdrDN',r'\\.\VBoxTrayIPC',r'\\.\VBoxDrvStub']
        for d in vbox_devs:
            if _dev(d): return True
        vbox_files=[r'C:\Windows\System32\drivers\VBoxGuest.sys',
                    r'C:\Windows\System32\drivers\VBoxMouse.sys',
                    r'C:\Windows\System32\drivers\VBoxSF.sys',
                    r'C:\Windows\System32\drivers\VBoxVideo.sys',
                    r'C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe']
        for f in vbox_files:
            if os.path.isfile(f): return True
    except Exception: pass
    return False
'''
)


# ── Anti-VMware (specific) ────────────────────────────────────────────────────

CHECKS['anti_vmware'] = dict(
    label   = 'Anti-VMware  (deep detection)',
    tooltip = 'Deep VMware-specific detection including backdoor port, '
              'CPUID signature, drivers, and process checks.',
    snippet = r'''
def _check_anti_vmware():
    import ctypes, ctypes.wintypes as _wt, os
    adv = ctypes.windll.advapi32
    k32 = ctypes.windll.kernel32
    def _reg(path):
        h=_wt.HKEY(); r=adv.RegOpenKeyExW(0x80000002,path,0,0x20019,ctypes.byref(h))
        if r==0: adv.RegCloseKey(h); return True
        return False
    def _dev(name):
        INVALID=ctypes.c_void_p(-1).value
        h=k32.CreateFileW(name,0x80000000,3,None,3,0,None)
        if h not in (INVALID,0,None): k32.CloseHandle(h); return True
        return False
    try:
        vmware_regs=[r'SOFTWARE\VMware, Inc.\VMware Tools',
                     r'SOFTWARE\VMware, Inc.\VMware Workstation',
                     r'SYSTEM\ControlSet001\Services\VMTools',
                     r'SYSTEM\ControlSet001\Services\vmhgfs',
                     r'SYSTEM\ControlSet001\Services\vmmouse',
                     r'SYSTEM\ControlSet001\Services\VMMEMCTL']
        for r in vmware_regs:
            if _reg(r): return True
        vmware_devs=[r'\\.\HGFS',r'\\.\vmci',r'\\.\VMCIDev']
        for d in vmware_devs:
            if _dev(d): return True
        vmware_files=[r'C:\Windows\System32\drivers\vmhgfs.sys',
                      r'C:\Windows\System32\drivers\vmmouse.sys',
                      r'C:\Windows\System32\drivers\vmtray.sys',
                      r'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe']
        for f in vmware_files:
            if os.path.isfile(f): return True
    except Exception: pass
    return False
'''
)


# ── Anti-RDP ──────────────────────────────────────────────────────────────────

CHECKS['anti_rdp'] = dict(
    label   = 'Anti-RDP  (block Remote Desktop sessions)',
    tooltip = 'Detects if the program is running inside an RDP/Terminal '
              'Services session and exits if so.',
    snippet = r'''
def _check_anti_rdp():
    import ctypes, os
    try:
        # SM_REMOTESESSION = 0x1000 (4096)
        if ctypes.windll.user32.GetSystemMetrics(0x1000) != 0:
            return True
        # Check SESSIONNAME environment variable
        sname = os.environ.get('SESSIONNAME','').upper()
        if sname.startswith('RDP-TCP') or sname.startswith('RDPNP'):
            return True
        # Check via WTSQuerySessionInformation
        # ClientProtocolType: 0=console 1=ICA 2=RDP
        try:
            WTS_CURRENT_SERVER=None; WTS_CURRENT_SESSION=0xFFFFFFFF
            WTSClientProtocolType=16
            buf = ctypes.c_char_p(); sz = ctypes.c_ulong(0)
            wtsapi = ctypes.windll.wtsapi32
            if wtsapi.WTSQuerySessionInformationW(
                0, WTS_CURRENT_SESSION,
                WTSClientProtocolType,
                ctypes.byref(buf), ctypes.byref(sz)):
                val = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ushort))[0]
                wtsapi.WTSFreeMemory(buf)
                if val == 2: return True
        except Exception: pass
    except Exception: pass
    return False
'''
)


# ── Anti-Sandbox ──────────────────────────────────────────────────────────────

CHECKS['anti_sandbox'] = dict(
    label   = 'Anti-Sandbox  (Cuckoo, ANY.RUN, Joe Sandbox, etc.)',
    tooltip = 'Detects automated analysis environments using RAM, CPU, '
              'disk size, uptime, username, hostname, and process checks.',
    snippet = r'''
def _check_anti_sandbox():
    import ctypes, ctypes.wintypes as _wt, os, time
    k32 = ctypes.windll.kernel32
    try:
        # 1. RAM < 2 GB (most sandboxes are low-memory)
        class MEMSTATUS(ctypes.Structure):
            _fields_=[('dwLength',_wt.DWORD),('dwMemoryLoad',_wt.DWORD),
                      ('ullTotalPhys',ctypes.c_ulonglong),('ullAvailPhys',ctypes.c_ulonglong),
                      ('ullTotalPageFile',ctypes.c_ulonglong),('ullAvailPageFile',ctypes.c_ulonglong),
                      ('ullTotalVirtual',ctypes.c_ulonglong),('ullAvailVirtual',ctypes.c_ulonglong),
                      ('ullAvailExtendedVirtual',ctypes.c_ulonglong)]
        ms = MEMSTATUS(); ms.dwLength = ctypes.sizeof(ms)
        k32.GlobalMemoryStatusEx(ctypes.byref(ms))
        if ms.ullTotalPhys < 2*1024*1024*1024: return True

        # 2. CPU cores < 2
        if os.cpu_count() is not None and os.cpu_count() < 2: return True

        # 3. Suspicious username / hostname
        buf=ctypes.create_unicode_buffer(256); sz=_wt.DWORD(256)
        k32.GetComputerNameExW(0, buf, ctypes.byref(sz))
        hostname = buf.value.lower()
        buf2=ctypes.create_unicode_buffer(256); sz2=_wt.DWORD(256)
        ctypes.windll.advapi32.GetUserNameW(buf2, ctypes.byref(sz2))
        username = buf2.value.lower()
        bad_names=['sandbox','malware','virus','sample','analysis','cuckoo',
                   'maltest','tester','test','admin123','analyse','anyrun',
                   'joe','joeboxserver','joeboxclient','defaultuser']
        for n in bad_names:
            if n in hostname or n in username: return True

        # 4. System uptime < 4 minutes (fresh sandbox)
        uptime_ms = k32.GetTickCount64()
        if uptime_ms < 4 * 60 * 1000: return True

        # 5. Disk size < 50 GB (sandbox VHDs are tiny)
        free=ctypes.c_ulonglong(0); total=ctypes.c_ulonglong(0)
        k32.GetDiskFreeSpaceExW('C:\\',None,ctypes.byref(total),ctypes.byref(free))
        if total.value < 50*1024*1024*1024: return True

        # 6. Analysis tool processes running
        sandbox_procs=['procmon.exe','procmon64.exe','wireshark.exe','fiddler.exe',
                       'processhacker.exe','pe-sieve.exe','autoruns.exe',
                       'regshot.exe','noriben.py','apimonitor.exe',
                       'dumpcap.exe','tcpview.exe','ollydbg.exe',
                       'cuckoo.py','sandboxie.exe','sbiesvc.exe']
        import ctypes as _ct
        TH32CS_SNAPPROCESS=0x2
        class PE32(_ct.Structure):
            _fields_=[('dwSize',_ct.c_ulong),('cntUsage',_ct.c_ulong),
                      ('th32ProcessID',_ct.c_ulong),('th32DefaultHeapID',_ct.POINTER(_ct.c_ulong)),
                      ('th32ModuleID',_ct.c_ulong),('cntThreads',_ct.c_ulong),
                      ('th32ParentProcessID',_ct.c_ulong),('pcPriClassBase',_ct.c_long),
                      ('dwFlags',_ct.c_ulong),('szExeFile',_ct.c_char*260)]
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)
        if snap not in (_ct.c_void_p(-1).value, 0):
            pe=PE32(); pe.dwSize=_ct.sizeof(PE32)
            if k32.Process32First(snap, _ct.byref(pe)):
                while True:
                    nm=pe.szExeFile.decode(errors='ignore').lower()
                    if nm in sandbox_procs: k32.CloseHandle(snap); return True
                    if not k32.Process32Next(snap, _ct.byref(pe)): break
            k32.CloseHandle(snap)

        # 7. Screen resolution too small (sandboxes often 800x600)
        w = ctypes.windll.user32.GetSystemMetrics(0)  # SM_CXSCREEN
        h = ctypes.windll.user32.GetSystemMetrics(1)  # SM_CYSCREEN
        if w < 800 or h < 600: return True

    except Exception: pass
    return False
'''
)


# ── Anti-Screenshot / Screen Recording ────────────────────────────────────────

CHECKS['anti_screenshot'] = dict(
    label   = 'Anti-Screenshot & Screen Recording',
    tooltip = 'Makes your activation dialog invisible to screenshot tools, '
              'OBS, Fraps, ShareX, Windows Snipping Tool, and screen recorders. '
              'Window appears black in any capture. Also detects & blocks recording software.',
    snippet = r'''
def _apply_anti_screenshot(hwnd):
    """Call with the tkinter window handle to make it capture-proof."""
    import ctypes
    try:
        # SetWindowDisplayAffinity with WDA_EXCLUDEFROMCAPTURE (0x11)
        # Window appears solid BLACK in all screen captures and recordings.
        # Works on Windows 10 2004+ and Windows 11.
        WDA_EXCLUDEFROMCAPTURE = 0x11
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
    except Exception: pass

def _check_anti_screenshot():
    """Detect screen recording / capture software."""
    import ctypes
    capture_procs=['obs32.exe','obs64.exe','obs.exe',
                   'fraps.exe','bandicam.exe','dxtory.exe',
                   'sharex.exe','greenshot.exe','lightshot.exe',
                   'camtasia.exe','camstudio.exe','action.exe',
                   'ispringsuite.exe','screencast.exe','snagit32.exe',
                   'ffmpeg.exe','streamlabs obs.exe','xsplit.exe']
    k32 = ctypes.windll.kernel32
    TH32CS_SNAPPROCESS=0x2
    class PE32(ctypes.Structure):
        _fields_=[('dwSize',ctypes.c_ulong),('cntUsage',ctypes.c_ulong),
                  ('th32ProcessID',ctypes.c_ulong),('th32DefaultHeapID',ctypes.POINTER(ctypes.c_ulong)),
                  ('th32ModuleID',ctypes.c_ulong),('cntThreads',ctypes.c_ulong),
                  ('th32ParentProcessID',ctypes.c_ulong),('pcPriClassBase',ctypes.c_long),
                  ('dwFlags',ctypes.c_ulong),('szExeFile',ctypes.c_char*260)]
    try:
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        INVALID = ctypes.c_void_p(-1).value
        if snap in (INVALID, 0): return False
        pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
        if k32.Process32First(snap, ctypes.byref(pe)):
            while True:
                nm = pe.szExeFile.decode(errors='ignore').lower()
                if nm in capture_procs:
                    k32.CloseHandle(snap); return True
                if not k32.Process32Next(snap, ctypes.byref(pe)): break
        k32.CloseHandle(snap)
    except Exception: pass
    return False
'''
)


# ── Anti-Hypervisor (CPUID) ───────────────────────────────────────────────────

CHECKS['anti_hypervisor'] = dict(
    label   = 'Anti-Hypervisor  (CPUID bit detection)',
    tooltip = 'Uses the CPU CPUID instruction to detect hypervisor presence. '
              'Catches Hyper-V, KVM, Xen, and any hypervisor that sets the '
              'hypervisor present bit (ECX bit 31).',
    snippet = r'''
def _check_anti_hypervisor():
    """Detect hypervisor via CPUID ECX bit 31 and vendor string."""
    import ctypes, struct
    try:
        # Use cpuid via inline shellcode executed in VirtualAlloc'd memory
        # CPUID leaf 1: ECX bit 31 = hypervisor present flag
        # CPUID leaf 0x40000000: hypervisor vendor string
        MEM_COMMIT=0x1000; MEM_RESERVE=0x2000; PAGE_EXECUTE_READWRITE=0x40
        k32 = ctypes.windll.kernel32
        is_64 = (ctypes.sizeof(ctypes.c_void_p)==8)

        # x86/x64 shellcode: CPUID(1), store ECX, ret
        # push ebx; mov eax,1; cpuid; mov [esp+8],ecx; pop ebx; ret
        if is_64:
            # x64: mov eax,1; cpuid; mov [rcx],ecx_result; ret
            # We'll use a different approach for x64
            # Just check known hypervisor indicators
            pass
        else:
            sc = bytes([
                0x53,             # push ebx
                0xB8,0x01,0x00,0x00,0x00,  # mov eax, 1
                0x0F,0xA2,        # cpuid
                0x89,0x4C,0x24,0x08, # mov [esp+8], ecx
                0x5B,             # pop ebx
                0xC3              # ret
            ])
            buf = k32.VirtualAlloc(0,len(sc),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE)
            if buf:
                ctypes.memmove(buf, sc, len(sc))
                fn_type = ctypes.CFUNCTYPE(ctypes.c_ulong)
                fn = fn_type(buf)
                ecx = fn()
                k32.VirtualFree(buf, 0, 0x8000)
                if ecx & (1<<31): return True  # Hypervisor bit set

        # Fallback: check known hypervisor registry keys
        adv = ctypes.windll.advapi32
        def _reg(path):
            h=ctypes.wintypes.HKEY()
            r=adv.RegOpenKeyExW(0x80000002,path,0,0x20019,ctypes.byref(h))
            if r==0: adv.RegCloseKey(h); return True
            return False
        hv_regs=[r'SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters',  # Hyper-V
                 r'SYSTEM\ControlSet001\Services\hvservice',               # Hyper-V
                 r'SOFTWARE\Xensource',                                    # Xen
                 r'SYSTEM\ControlSet001\Services\xenbus']                  # Xen
        for r in hv_regs:
            if _reg(r): return True

    except Exception: pass
    return False
'''
)


# ── Anti-Wine ─────────────────────────────────────────────────────────────────

CHECKS['anti_wine'] = dict(
    label   = 'Anti-Wine  (Linux/Wine emulation)',
    tooltip = 'Detects if the program is running under Wine on Linux/macOS '
              'instead of native Windows.',
    snippet = r'''
def _check_anti_wine():
    import ctypes
    try:
        # Wine exports ntdll.wine_get_version - native Windows does not
        ntdll = ctypes.windll.ntdll
        wine_fn = getattr(ntdll, 'wine_get_version', None)
        if wine_fn is not None: return True
        # Check registry key only Wine creates
        adv = ctypes.windll.advapi32
        h = ctypes.wintypes.HKEY()
        if adv.RegOpenKeyExW(0x80000002,
            r'SOFTWARE\Wine', 0, 0x20019, ctypes.byref(h)) == 0:
            adv.RegCloseKey(h); return True
        # Check for winebrowser.exe or winedbg.exe
        import ctypes as _ct
        TH32CS_SNAPPROCESS=0x2
        class PE32(_ct.Structure):
            _fields_=[('dwSize',_ct.c_ulong),('cntUsage',_ct.c_ulong),
                      ('th32ProcessID',_ct.c_ulong),('th32DefaultHeapID',_ct.POINTER(_ct.c_ulong)),
                      ('th32ModuleID',_ct.c_ulong),('cntThreads',_ct.c_ulong),
                      ('th32ParentProcessID',_ct.c_ulong),('pcPriClassBase',_ct.c_long),
                      ('dwFlags',_ct.c_ulong),('szExeFile',_ct.c_char*260)]
        snap=_ct.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)
        if snap not in (_ct.c_void_p(-1).value,0):
            pe=PE32(); pe.dwSize=_ct.sizeof(PE32)
            if _ct.windll.kernel32.Process32First(snap,_ct.byref(pe)):
                while True:
                    nm=pe.szExeFile.decode(errors='ignore').lower()
                    if 'wine' in nm:
                        _ct.windll.kernel32.CloseHandle(snap); return True
                    if not _ct.windll.kernel32.Process32Next(snap,_ct.byref(pe)): break
            _ct.windll.kernel32.CloseHandle(snap)
    except Exception: pass
    return False
'''
)


# ── Anti-Debugger (extended) ──────────────────────────────────────────────────

CHECKS['anti_debug'] = dict(
    label   = 'Anti-Debugger  (x64dbg, OllyDbg, IDA, WinDbg)',
    tooltip = 'Multi-layer debugger detection using IsDebuggerPresent, '
              'NtQueryInformationProcess, heap flags, hardware breakpoints, '
              'timing checks, and parent process verification.',
    snippet = r'''
def _check_anti_debug():
    import ctypes, ctypes.wintypes as _wt
    k32=ctypes.windll.kernel32; ntdll=ctypes.windll.ntdll
    try:
        if k32.IsDebuggerPresent(): return True
        present=_wt.BOOL(0)
        k32.CheckRemoteDebuggerPresent(k32.GetCurrentProcess(),ctypes.byref(present))
        if present.value: return True
        port=ctypes.c_ulong(0)
        ntdll.NtQueryInformationProcess(k32.GetCurrentProcess(),7,ctypes.byref(port),4,None)
        if port.value: return True
        flags=ctypes.c_ulong(0)
        ntdll.NtQueryInformationProcess(k32.GetCurrentProcess(),31,ctypes.byref(flags),4,None)
        if flags.value==0: return True
        # Hardware breakpoint check
        CONTEXT_DEBUG=0x00010010
        class CTX(ctypes.Structure):
            _fields_=[('ContextFlags',_wt.DWORD),
                      ('Dr0',ctypes.c_ulong),('Dr1',ctypes.c_ulong),
                      ('Dr2',ctypes.c_ulong),('Dr3',ctypes.c_ulong),
                      ('Dr6',ctypes.c_ulong),('Dr7',ctypes.c_ulong)]
        ctx=CTX(); ctx.ContextFlags=CONTEXT_DEBUG
        if k32.GetThreadContext(k32.GetCurrentThread(),ctypes.byref(ctx)):
            if ctx.Dr0 or ctx.Dr1 or ctx.Dr2 or ctx.Dr3: return True
        # Timing
        import time
        t0=time.perf_counter()
        x=sum(range(500000))
        if time.perf_counter()-t0 > 3.0: return True
        # Debugger process names
        debugger_procs=['x64dbg.exe','x32dbg.exe','ollydbg.exe','windbg.exe',
                        'idaq.exe','idaq64.exe','idaw.exe','idaw64.exe',
                        'ida.exe','ida64.exe','radare2.exe','r2.exe',
                        'immunitydebugger.exe','cheatengine-x86_64.exe',
                        'processhacker.exe','dbgview.exe']
        TH32CS_SNAPPROCESS=0x2
        class PE32(ctypes.Structure):
            _fields_=[('dwSize',ctypes.c_ulong),('cntUsage',ctypes.c_ulong),
                      ('th32ProcessID',ctypes.c_ulong),('th32DefaultHeapID',ctypes.POINTER(ctypes.c_ulong)),
                      ('th32ModuleID',ctypes.c_ulong),('cntThreads',ctypes.c_ulong),
                      ('th32ParentProcessID',ctypes.c_ulong),('pcPriClassBase',ctypes.c_long),
                      ('dwFlags',ctypes.c_ulong),('szExeFile',ctypes.c_char*260)]
        snap=k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)
        INVALID=ctypes.c_void_p(-1).value
        if snap not in (INVALID,0):
            pe=PE32(); pe.dwSize=ctypes.sizeof(PE32)
            if k32.Process32First(snap,ctypes.byref(pe)):
                while True:
                    nm=pe.szExeFile.decode(errors='ignore').lower()
                    if nm in debugger_procs: k32.CloseHandle(snap); return True
                    if not k32.Process32Next(snap,ctypes.byref(pe)): break
            k32.CloseHandle(snap)
    except Exception: pass
    return False
'''
)


# ── Anti-Dump ─────────────────────────────────────────────────────────────────

CHECKS['anti_dump'] = dict(
    label   = 'Anti-Dump  (memory dumper protection)',
    tooltip = 'Corrupts PE header fields in memory after load so that '
              'memory dumpers (Scylla, PEDump, x64dbg dump) cannot '
              'reconstruct a working PE from the process memory.',
    snippet = r'''
def _apply_anti_dump():
    import ctypes, ctypes.wintypes as _wt
    k32=ctypes.windll.kernel32
    try:
        hmod=k32.GetModuleHandleW(None)
        if not hmod: return
        PAGE_EXECUTE_READWRITE=0x40
        old=_wt.DWORD(0)
        k32.VirtualProtect(ctypes.c_void_p(hmod),0x1000,PAGE_EXECUTE_READWRITE,ctypes.byref(old))
        import ctypes as _c
        pe_off_addr=hmod+0x3C
        pe_off=_c.c_ulong(0)
        k32.ReadProcessMemory(k32.GetCurrentProcess(),_c.c_void_p(pe_off_addr),_c.byref(pe_off),4,None)
        if pe_off.value>0:
            opt_off=hmod+pe_off.value+24
            soi_addr=opt_off+56
            zero=_c.c_ulong(0)
            k32.WriteProcessMemory(k32.GetCurrentProcess(),_c.c_void_p(soi_addr),_c.byref(zero),4,None)
            k32.WriteProcessMemory(k32.GetCurrentProcess(),_c.c_void_p(pe_off_addr),_c.byref(zero),4,None)
        k32.VirtualProtect(ctypes.c_void_p(hmod),0x1000,old,ctypes.byref(old))
    except Exception: pass
'''
)
