"""
keygen_tool.py  -  ExeShield Private Keygen
============================================
YOUR PRIVATE TOOL - never give this to customers.
Place in the SAME folder as crypto_core.py.

Run:  python keygen_tool.py
"""

import os, sys, csv, datetime

# ── Import from same folder ───────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from crypto_core import generate_key, get_hwid

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
except ImportError:
    print('tkinter required.'); sys.exit(1)

APP_NAME = 'ExeShield Keygen'
APP_VER  = '1.0'
LOG_FILE = os.path.join(_HERE, 'keygen_log.csv')


def _log_key(hwid, key, note=''):
    exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(['Timestamp', 'HWID', 'Key', 'Note'])
        w.writerow([datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    hwid.upper(), key, note])


def clean_hwid(raw: str) -> str:
    """Remove dashes, spaces, and any non-hex characters, keep only 0-9A-F."""
    return ''.join(ch for ch in raw.upper() if ch in '0123456789ABCDEF')


class KeygenGUI(tk.Tk):
    BG    = '#0d0d14'
    PANEL = '#13131e'
    FG    = '#e2e8f0'
    FG2   = '#64748b'
    PURP  = '#7c3aed'
    GREEN = '#10b981'
    FONT  = ('Segoe UI', 9)
    FONB  = ('Segoe UI', 9, 'bold')
    MONO  = ('Consolas', 10)

    def __init__(self):
        super().__init__()
        self.title(f'{APP_NAME}  v{APP_VER}   ⚠ PRIVATE — DO NOT DISTRIBUTE')
        self.resizable(False, False)
        self.configure(bg=self.BG)
        W, H = 720, 560
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f'{W}x{H}+{(sw-W)//2}+{(sh-H)//2}')
        self._build()

    def _build(self):
        B, P, F, F2, PU, GR = (self.BG, self.PANEL, self.FG,
                                 self.FG2, self.PURP, self.GREEN)
        FT, FB, MO = self.FONT, self.FONB, self.MONO

        # Header
        hdr = tk.Frame(self, bg=P)
        hdr.pack(fill='x')
        tk.Label(hdr, text='🗝  ExeShield Keygen',
                 font=('Segoe UI', 14, 'bold'),
                 bg=P, fg='#a78bfa', pady=12).pack(side='left', padx=18)
        tk.Label(hdr, text='⚠  PRIVATE — DO NOT DISTRIBUTE',
                 font=FB, bg=P, fg='#ef4444').pack(side='left')
        tk.Frame(self, bg='#2d1b69', height=2).pack(fill='x')

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TNotebook', background=B, borderwidth=0)
        style.configure('TNotebook.Tab',
                         background=P, foreground=F2,
                         padding=[14, 7], font=FB)
        style.map('TNotebook.Tab',
                  background=[('selected', B)],
                  foreground=[('selected', '#a78bfa')])

        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True)

        self._build_single(nb)
        self._build_batch(nb)
        self._build_log(nb)

    # ── Single key ──────────────────────────────────────────────

    def _build_single(self, nb):
        B, P, F, F2 = self.BG, self.PANEL, self.FG, self.FG2
        FT, FB, MO  = self.FONT, self.FONB, self.MONO
        GR, PU      = self.GREEN, self.PURP

        tab = tk.Frame(nb, bg=B)
        nb.add(tab, text='  🗝  Generate Key  ')

        tk.Frame(tab, bg=B, height=14).pack()
        body = tk.Frame(tab, bg=B)
        body.pack(fill='x', padx=28)

        # HWID input
        tk.Label(body, text="Customer's Hardware ID  (32 hex chars, dashes allowed):",
                 font=FT, bg=B, fg=F2, anchor='w').pack(anchor='w')
        self._hwid_v = tk.StringVar()
        hwe = tk.Entry(body, textvariable=self._hwid_v, font=MO,
                       bg='#1e1b2e', fg='#a78bfa',
                       insertbackground='#a78bfa', relief='flat', bd=0)
        hwe.pack(fill='x', ipady=9, pady=3)
        hwe.focus()

        def _clean_and_update(*_):
            raw = self._hwid_v.get()
            # Only display cleaned hex in the entry (optional, but keep as-is for user convenience)
            # We'll keep raw text, but update length counter based on cleaned version
            cleaned = clean_hwid(raw)
            n = len(cleaned)
            self._hlen.set(f'{n}/32')
        self._hwid_v.trace_add('write', _clean_and_update)
        hwe.bind('<Return>', lambda e: self._gen())

        # Button row
        bf = tk.Frame(body, bg=B)
        bf.pack(fill='x', pady=4)
        tk.Button(bf, text='Paste from clipboard', font=FT,
                  bg='#1e1b2e', fg=F2, relief='flat',
                  padx=10, cursor='hand2',
                  command=self._paste).pack(side='left', padx=(0, 8))
        tk.Button(bf, text="Use this machine's HWID", font=FT,
                  bg='#1e1b2e', fg=F2, relief='flat',
                  padx=10, cursor='hand2',
                  command=lambda: self._hwid_v.set(get_hwid())
                  ).pack(side='left')

        # HWID length counter
        self._hlen = tk.StringVar(value='0/32')
        tk.Label(bf, textvariable=self._hlen,
                 font=FT, bg=B, fg=F2).pack(side='right')

        # Note
        tk.Label(body, text='Customer note (optional, saved to log):',
                 font=FT, bg=B, fg=F2, anchor='w').pack(anchor='w', pady=(8, 0))
        self._note_v = tk.StringVar()
        tk.Entry(body, textvariable=self._note_v, font=FT,
                 bg='#1e1b2e', fg=F, relief='flat', bd=0
                 ).pack(fill='x', ipady=6, pady=3)

        tk.Frame(body, bg='#2d1b69', height=1).pack(fill='x', pady=10)

        # Generate button
        tk.Button(tab, text='🗝   Generate Activation Key',
                  font=('Segoe UI', 12, 'bold'),
                  bg=PU, fg='white', relief='flat',
                  padx=28, pady=11, cursor='hand2',
                  command=self._gen).pack()

        # Status
        self._status_v = tk.StringVar()
        tk.Label(tab, textvariable=self._status_v,
                 font=FT, bg=B, fg='#ef4444').pack(pady=4)

        # Key output
        out = tk.Frame(tab, bg=B)
        out.pack(fill='x', padx=28, pady=4)
        tk.Label(out, text='Activation Key:',
                 font=FT, bg=B, fg=F2, anchor='w').pack(anchor='w')
        self._key_v = tk.StringVar()
        ke = tk.Entry(out, textvariable=self._key_v,
                      font=('Consolas', 15), state='readonly',
                      readonlybackground='#0d1f12',
                      fg=GR, relief='flat', bd=0)
        ke.pack(fill='x', ipady=11, pady=3)

        # Copy row
        cf = tk.Frame(tab, bg=B)
        cf.pack(fill='x', padx=28, pady=2)
        self._copied_v = tk.StringVar()
        tk.Label(cf, textvariable=self._copied_v,
                 font=FT, bg=B, fg=GR).pack(side='right')
        tk.Button(cf, text='  Copy Key  ', font=FT,
                  bg='#1e1b2e', fg=F2, relief='flat',
                  padx=10, cursor='hand2',
                  command=self._copy_key).pack(side='left')

        # Info
        tk.Frame(tab, bg='#2d1b69', height=1).pack(fill='x', padx=28, pady=8)
        tk.Label(tab, justify='left', bg=B, fg=F2, font=FT,
                 text=(
                     'Format:     AAAAA-BBBBB-CCCCC-DDDDD-EEEEE  (26 base32 chars + dashes)\n'
                     'Algorithm:  HMAC-SHA256(MASTER_SECRET, HWID)[0:16]  →  base32\n'
                     'Binding:    This key will ONLY work on the machine with that exact HWID.\n'
                     'Log:        Every generated key is saved to keygen_log.csv'
                 )).pack(padx=28, anchor='w')

    def _paste(self):
        try:
            self._hwid_v.set(self.clipboard_get().strip().upper())
        except Exception:
            pass

    def _copy_key(self):
        k = self._key_v.get()
        if k:
            self.clipboard_clear()
            self.clipboard_append(k)
            self._copied_v.set('✔ Copied!')
            self.after(2000, lambda: self._copied_v.set(''))

    def _gen(self):
        raw = self._hwid_v.get().strip().upper()
        hwid = clean_hwid(raw)
        if not hwid:
            self._status_v.set("Enter the customer's HWID first.")
            return
        if len(hwid) != 32:
            self._status_v.set(
                f'HWID must be exactly 32 hex chars (got {len(hwid)}).\nDashes and spaces are ignored.')
            return
        try:
            int(hwid, 16)
        except ValueError:
            self._status_v.set('HWID must be hex characters only (0-9, A-F).')
            return
        self._status_v.set('')
        key = generate_key(hwid)
        self._key_v.set(key)
        _log_key(hwid, key, self._note_v.get().strip())
        self._refresh_log()

    # ── Batch ───────────────────────────────────────────────────

    def _build_batch(self, nb):
        B, P, F, F2 = self.BG, self.PANEL, self.FG, self.FG2
        FT, FB, MO  = self.FONT, self.FONB, self.MONO
        GR, PU      = self.GREEN, self.PURP

        tab = tk.Frame(nb, bg=B)
        nb.add(tab, text='  📋  Batch  ')

        tk.Frame(tab, bg=B, height=14).pack()
        tk.Label(tab, text='Batch Key Generation',
                 font=('Segoe UI', 11, 'bold'),
                 bg=B, fg=F).pack(padx=24, anchor='w')
        tk.Label(tab,
                 text='Paste one HWID per line (dashes/spaces allowed). Keys generated for all valid ones.',
                 font=FT, bg=B, fg=F2).pack(padx=24, anchor='w', pady=4)

        inf = tk.Frame(tab, bg=B)
        inf.pack(fill='both', expand=True, padx=24, pady=4)
        tk.Label(inf, text='HWIDs  (one per line):',
                 font=FT, bg=B, fg=F2, anchor='w').pack(anchor='w')
        self._bin = tk.Text(inf, font=MO, bg='#1e1b2e', fg='#a78bfa',
                             relief='flat', height=6,
                             insertbackground='#a78bfa')
        self._bin.pack(fill='both', expand=True, pady=4)

        tk.Button(tab, text='  Generate All Keys  ',
                  font=FB, bg=PU, fg='white', relief='flat',
                  padx=16, pady=8, cursor='hand2',
                  command=self._gen_batch).pack(padx=24, anchor='w', pady=4)

        outf = tk.Frame(tab, bg=B)
        outf.pack(fill='both', expand=True, padx=24, pady=4)
        tk.Label(outf, text='Results  (HWID  →  Key):',
                 font=FT, bg=B, fg=F2, anchor='w').pack(anchor='w')
        self._bout = tk.Text(outf, font=MO, bg='#0d1f12', fg=GR,
                              relief='flat', height=8, state='disabled')
        self._bout.pack(fill='both', expand=True, pady=4)

        bf = tk.Frame(tab, bg=B)
        bf.pack(fill='x', padx=24, pady=4)

        def copy_all():
            self.clipboard_clear()
            self.clipboard_append(self._bout.get('1.0', 'end'))

        def save_csv():
            p = filedialog.asksaveasfilename(
                defaultextension='.csv',
                filetypes=[('CSV', '*.csv')])
            if not p:
                return
            with open(p, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['HWID', 'ActivationKey'])
                for line in self._bout.get('1.0', 'end').splitlines():
                    if '->' in line:
                        a, b = line.split('->', 1)
                        w.writerow([a.strip(), b.strip()])

        tk.Button(bf, text='Copy All', font=FT, bg='#1e1b2e', fg=F2,
                  relief='flat', padx=10, cursor='hand2',
                  command=copy_all).pack(side='left', padx=(0, 8))
        tk.Button(bf, text='Save CSV…', font=FT, bg='#1e1b2e', fg=F2,
                  relief='flat', padx=10, cursor='hand2',
                  command=save_csv).pack(side='left')

    def _gen_batch(self):
        lines = self._bin.get('1.0', 'end').strip().splitlines()
        out = []
        for line in lines:
            raw = line.strip().upper()
            hwid = clean_hwid(raw)
            if not hwid:
                out.append(f'{raw}  ->  SKIPPED (empty)')
                continue
            if len(hwid) != 32:
                out.append(f'{hwid}  ->  ERROR: need 32 hex chars (got {len(hwid)})')
                continue
            try:
                int(hwid, 16)
            except ValueError:
                out.append(f'{hwid}  ->  ERROR: not valid hex')
                continue
            key = generate_key(hwid)
            _log_key(hwid, key, 'batch')
            out.append(f'{hwid}  ->  {key}')
        self._bout.config(state='normal')
        self._bout.delete('1.0', 'end')
        self._bout.insert('end', '\n'.join(out))
        self._bout.config(state='disabled')
        self._refresh_log()

    # ── Log ─────────────────────────────────────────────────────

    def _build_log(self, nb):
        B, P, F, F2 = self.BG, self.PANEL, self.FG, self.FG2
        FT, MO      = self.FONT, self.MONO

        tab = tk.Frame(nb, bg=B)
        nb.add(tab, text='  📜  Log  ')

        s = ttk.Style()
        s.configure('KG.Treeview', background='#1e1b2e',
                     fieldbackground='#1e1b2e', foreground=F,
                     rowheight=22, font=MO)
        s.configure('KG.Treeview.Heading', background=P,
                     foreground=F2, font=FT)

        cols = ('Timestamp', 'HWID', 'Key', 'Note')
        self._tree = ttk.Treeview(tab, columns=cols, show='headings',
                                   height=18, style='KG.Treeview')
        for c in cols:
            w = {'Timestamp': 140, 'HWID': 255,
                 'Key': 185, 'Note': 120}[c]
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor='w')
        sb = ttk.Scrollbar(tab, command=self._tree.yview)
        self._tree.config(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True, padx=8, pady=4)

        bf = tk.Frame(tab, bg=B)
        bf.pack(fill='x', padx=10, pady=4)
        tk.Button(bf, text='Refresh', font=FT, bg='#1e1b2e', fg=F2,
                  relief='flat', padx=10, cursor='hand2',
                  command=self._refresh_log).pack(side='left', padx=(0, 8))
        if os.name == 'nt':
            tk.Button(bf, text='Open CSV', font=FT, bg='#1e1b2e', fg=F2,
                      relief='flat', padx=10, cursor='hand2',
                      command=lambda: os.startfile(LOG_FILE)
                                      if os.path.isfile(LOG_FILE) else None
                      ).pack(side='left')
        self._log_lbl = tk.Label(bf, text='', font=FT, bg=B, fg=F2)
        self._log_lbl.pack(side='right')
        self._refresh_log()

    def _refresh_log(self):
        for item in self._tree.get_children():
            self._tree.delete(item)
        if not os.path.isfile(LOG_FILE):
            return
        try:
            with open(LOG_FILE, newline='', encoding='utf-8') as f:
                rows = list(csv.reader(f))[1:]
            for row in reversed(rows):
                self._tree.insert('', 'end', values=row)
            self._log_lbl.config(text=f'{len(rows)} keys generated')
        except Exception:
            pass


def main():
    app = KeygenGUI()
    app.mainloop()


if __name__ == '__main__':
    main()