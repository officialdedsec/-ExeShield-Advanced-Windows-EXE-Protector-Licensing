🚀 Step‑by‑Step: Protect an EXE
1. Launch the Locker
Python script:
python lock_tool.py

Executable:
Double‑click ExeShieldLocker.exe

A GUI window will appear.

2. Choose Files
Target EXE: Click Browse and select the .exe you want to protect.

Output EXE: Choose where to save the protected version (default: <original>_locked.exe).

3. Select Lock Mode
Three options are available:

Mode	Description
Lock to THIS machine	Uses the current PC’s hardware ID. The protected EXE will only run on this exact computer.
Lock to specific HWID	Enter a 32‑character hex HWID manually (e.g., from a customer’s machine).
Universal (per‑machine keys)	No fixed HWID. The same protected EXE runs on any PC, but each PC needs its own unique key generated from its HWID.
💡 Tip: For digital distribution, use Universal (per‑machine keys). Customers send you their HWID; you generate a key with your private keygen_tool.py.

4. Apply Protection Options (Optional)
Tick any of the additional checks:

Anti‑VM / Anti‑VirtualBox / Anti‑VMware – detects virtual machines.

Anti‑Debug – catches debuggers (x64dbg, OllyDbg, IDA, etc.).

Anti‑Sandbox – detects analysis environments.

Anti‑RDP – blocks Remote Desktop sessions.

Anti‑Screenshot – makes the activation dialog black in screen captures.

Anti‑Hypervisor – CPUID‑based hypervisor detection.

Anti‑Wine – prevents running under Wine.

Anti‑Dump – corrupts in‑memory PE headers.

5. Build the Protected EXE
Click Lock EXE.
The process will:

Extract icon and version info from the original EXE.

Inject the selected protection code into the stub.

Compile the stub with PyInstaller (auto‑installs PyInstaller if missing).

Burn a license blob at offset 0x378.

Append the original EXE as payload.

Output the final protected EXE.

⏱️ Compilation may take 30–90 seconds depending on your machine.

6. Distribute the Protected EXE
You can now send the protected EXE to your customer. No additional files are needed.

🗝️ Activation & Key Generation (for you)
When the customer runs the protected EXE for the first time, they will see an activation dialog showing their HWID.

They send you that HWID.

You use your private keygen_tool.py to generate a key:

'''cmd
python keygen_tool.py
Enter the HWID, optionally add a note, and click Generate Activation Key.

Send the generated key back to the customer.

The customer enters the key, and the program runs.

🔐 Keys are unique per machine (if universal mode) or per target HWID (if locked to a specific HWID).
