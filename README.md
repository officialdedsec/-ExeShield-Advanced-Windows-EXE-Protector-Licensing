# 🔒 ExeShield – Advanced Windows EXE Protector & Licensing

**ExeShield** is a professional tool that protects any Windows executable (EXE) with hardware‑based licensing, anti‑tampering, and runtime environment checks.  
It compiles the protector stub into **native machine code** using Nuitka – no Python bytecode left to extract.

> Created by [dedseec.com](https://dedseec.com)

---

## ✨ Features

- **HWID‑based licensing** – lock an EXE to a specific machine’s unique hardware ID.
- **Per‑machine licensing mode** – same protected EXE works on any PC, but each PC requires its own unique key (perfect for digital distribution).
- **Anti‑Debug** – detects x64dbg, OllyDbg, IDA, WinDbg, hardware breakpoints, timing attacks.
- **Anti‑VM** – generic (VMware, VirtualBox, Hyper‑V, QEMU) + deep specific checks.
- **Anti‑Sandbox** – detects Cuckoo, ANY.RUN, Joe Sandbox, low RAM/CPU/disk, suspicious usernames.
- **Anti‑RDP** – blocks Remote Desktop sessions.
- **Anti‑Screenshot** – makes the activation dialog black in all screen captures (Windows 10/11).
- **Anti‑Dump** – corrupts in‑memory PE headers to prevent memory dumpers (Scylla, etc.).
- **Anti‑Extraction** – resists PyInstaller / Nuitka unpackers.
- **Icon & Version Info** – preserves original EXE’s icon, file version, company name.
- **Task Manager** – shows the real application name, not “Python”.
- **Zero console flashes** – completely silent stub.
- **Secure payload launcher** – extracts and runs the original EXE from a hidden + system + temporary location, then wipes it after exit.
- **Key storage** – saves activation keys in the Windows registry (per user).

---

## 📦 Requirements

- Windows 7 / 8 / 10 / 11 (64‑bit recommended)
- Python 3.8 or higher
- Tkinter (usually included with Python)

Install the required package:

```cmd
pip install -r requirements.txt


🚀 Usage
1. Protect an EXE (lock_tool.py)
Run the locker GUI:

cmd
python lock_tool.py
Steps:

Select the target EXE.

Choose output path (default: <original>_locked.exe).

Pick a lock mode:

Lock to THIS machine – uses the current PC’s HWID.

Lock to specific HWID – enter a 32‑hex HWID manually.

Universal (per‑machine keys) – each PC needs its own key (no fixed HWID).

Select any additional protection checks (Anti‑VM, Anti‑Debug, etc.).

Click Lock EXE.
The tool will generate the stub, compile it to native code with Nuitka, burn the license blob, and append the original EXE as payload.

The output is a fully standalone, protected EXE.

2. Generate activation keys (keygen_tool.py)
⚠️ This tool is private – never give it to customers!

cmd
python keygen_tool.py
Enter the customer’s HWID (displayed in the activation dialog of the protected EXE).

(Optional) Add a customer note.

Click Generate Activation Key.

Send the generated key to the customer.

The keygen logs all generated keys to keygen_log.csv (batch mode available).

🔧 Configuration
Before distributing your protected EXEs, change the master secret in crypto_core.py:

python
MASTER_SECRET = b"CHANGE_THIS_TO_YOUR_OWN_LONG_RANDOM_SECRET_v1"
Replace the string with a long, random, secret value – keep it safe!
The same secret must be used in both lock_tool.py and keygen_tool.py.
