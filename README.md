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
![ExeShield Screenshot](Screenshot%202026-06-10%20131233.png)

[![Documentation](https://img.shields.io/badge/docs-USAGE.md-blue)](USAGE.md)

## 📋 Requirements

- Windows 7 / 8 / 10 / 11 (64‑bit recommended)
- Python 3.8 or higher
- Tkinter (usually included with Python)

Install the Python dependencies:

```cmd
pip install -r requirements.txt
