"""
pe_utils.py  -  PE resource extraction utilities
Extracts icon + version info from any Windows EXE.
Pure Python, zero external dependencies.

Place in the SAME folder as lock_tool.py
"""

import struct
import os


# ─────────────────────────────────────────────────────────────────────────────
#  PE parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

RT_ICON       = 3
RT_GROUP_ICON = 14
RT_VERSION    = 16


def _read32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def _read16(data, off):
    return struct.unpack_from('<H', data, off)[0]


class PEFile:
    """Minimal PE parser sufficient for resource extraction."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()
        self._parse()

    def _parse(self):
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError('Not a valid PE file')
        pe_off = _read32(d, 0x3C)
        if d[pe_off:pe_off+4] != b'PE\0\0':
            raise ValueError('PE signature not found')

        self.pe_off = pe_off
        self.machine = _read16(d, pe_off + 4)
        self.is_64   = (self.machine == 0x8664)
        num_secs     = _read16(d, pe_off + 6)
        opt_size     = _read16(d, pe_off + 20)
        opt_off      = pe_off + 24

        # DataDirectory starts after the standard/windows-specific fields
        dd_base = opt_off + (112 if self.is_64 else 96)

        # Entry 2 = resource directory
        res_rva  = _read32(d, dd_base + 2*8)
        res_size = _read32(d, dd_base + 2*8 + 4)
        self.res_rva  = res_rva
        self.res_size = res_size

        # Parse section table
        sec_off = opt_off + opt_size
        self.sections = []
        for i in range(num_secs):
            so = sec_off + i * 40
            name    = d[so:so+8].rstrip(b'\x00')
            vaddr   = _read32(d, so + 12)
            vsz     = _read32(d, so + 16)
            raw_off = _read32(d, so + 20)
            raw_sz  = _read32(d, so + 24)
            self.sections.append((name, vaddr, vsz, raw_off, raw_sz))

        # Find .rsrc
        self.rsrc_delta = None   # delta: file_offset = rva + rsrc_delta
        for name, vaddr, vsz, raw_off, raw_sz in self.sections:
            if vaddr <= res_rva < vaddr + max(vsz, 1):
                self.rsrc_delta = raw_off - vaddr
                break

    def rva_to_off(self, rva):
        """Convert RVA to file offset using section table."""
        for name, vaddr, vsz, raw_off, raw_sz in self.sections:
            if vaddr <= rva < vaddr + max(vsz, raw_sz, 1):
                return rva - vaddr + raw_off
        return None

    def _res_dir(self, off, level, target_type, target_id=None):
        """
        Recursively walk the resource directory tree.
        Returns list of (id, data_rva, data_size) at leaf level.
        """
        d = self.data
        results = []
        try:
            # IMAGE_RESOURCE_DIRECTORY: 4 chars + 4 timestamps + 2+2 entry counts
            named_count = _read16(d, off + 12)
            id_count    = _read16(d, off + 14)
            total       = named_count + id_count

            for i in range(total):
                entry_off = off + 16 + i * 8
                id_or_name = _read32(d, entry_off)
                subdataoff = _read32(d, entry_off + 4)

                # Get numeric ID (high bit set = named, use lower 31 bits as offset)
                if id_or_name & 0x80000000:
                    res_id = None  # named resource - skip
                else:
                    res_id = id_or_name

                is_subdir = bool(subdataoff & 0x80000000)
                child_off = (subdataoff & 0x7FFFFFFF) + (self.res_rva + self.rsrc_delta)

                if level == 0:
                    # Level 0: type
                    if res_id == target_type:
                        results += self._res_dir(child_off, 1, target_type, target_id)
                elif level == 1:
                    # Level 1: id/name
                    if target_id is None or res_id == target_id:
                        if is_subdir:
                            results += self._res_dir(child_off, 2, target_type, res_id)
                        else:
                            leaf = self._res_leaf(child_off)
                            if leaf:
                                results.append((res_id,) + leaf)
                elif level == 2:
                    # Level 2: language - take first
                    if is_subdir:
                        results += self._res_dir(child_off, 3, target_type, target_id)
                    else:
                        leaf = self._res_leaf(child_off)
                        if leaf:
                            results.append((target_id,) + leaf)
                elif level == 3:
                    leaf = self._res_leaf(child_off)
                    if leaf:
                        results.append((target_id,) + leaf)
        except Exception:
            pass
        return results

    def _res_leaf(self, off):
        """Read IMAGE_RESOURCE_DATA_ENTRY -> (data_rva, size)"""
        try:
            data_rva = _read32(self.data, off)
            size     = _read32(self.data, off + 4)
            return (data_rva, size)
        except Exception:
            return None

    def get_resources(self, res_type, res_id=None):
        """Get list of (id, bytes) for all resources of given type."""
        if self.rsrc_delta is None or self.res_rva == 0:
            return []
        root_off = self.res_rva + self.rsrc_delta
        results  = self._res_dir(root_off, 0, res_type, res_id)
        out = []
        for entry in results:
            rid, rva, size = entry
            file_off = self.rva_to_off(rva)
            if file_off is not None:
                out.append((rid, self.data[file_off: file_off + size]))
        return out

    def get_version_strings(self):
        """Extract FileDescription, ProductName, FileVersion from RT_VERSION."""
        results = self.get_resources(RT_VERSION)
        if not results:
            return {}
        raw = results[0][1]
        strings = {}
        try:
            # VS_VERSIONINFO -> StringFileInfo -> StringTable -> StringStruct
            # Skip VS_VERSIONINFO fixed header
            off = 0
            total_len = _read16(raw, 0)
            val_len   = _read16(raw, 2)

            # Skip "VS_VERSION_INFO\0" key (unicode) + padding + FixedFileInfo
            key_off = 6
            while key_off < len(raw) - 1:
                if raw[key_off:key_off+2] == b'\x00\x00':
                    break
                key_off += 2
            key_off += 2
            # Align to 4 bytes
            key_off = (key_off + 3) & ~3
            # Skip FixedFileInfo (52 bytes if present)
            if val_len >= 52:
                key_off += val_len
            key_off = (key_off + 3) & ~3

            # Now at children (StringFileInfo or VarFileInfo)
            while key_off < total_len and key_off < len(raw) - 6:
                child_len  = _read16(raw, key_off)
                child_vlen = _read16(raw, key_off + 2)
                if child_len == 0:
                    break
                # Read child key
                k_start = key_off + 6
                k_end   = k_start
                while k_end + 1 < len(raw) and raw[k_end:k_end+2] != b'\x00\x00':
                    k_end += 2
                key = raw[k_start:k_end].decode('utf-16-le', errors='ignore')
                k_end += 2
                k_end = (k_end + 3) & ~3

                if key == 'StringFileInfo':
                    # Walk StringTables
                    st_off = k_end
                    while st_off < key_off + child_len and st_off < len(raw) - 6:
                        st_len  = _read16(raw, st_off)
                        st_vlen = _read16(raw, st_off + 2)
                        if st_len == 0: break
                        # Skip StringTable key (codepage hex)
                        sk = st_off + 6
                        while sk + 1 < len(raw) and raw[sk:sk+2] != b'\x00\x00':
                            sk += 2
                        sk += 2; sk = (sk+3) & ~3
                        # Walk String entries
                        sv = sk
                        while sv < st_off + st_len and sv < len(raw) - 6:
                            s_len  = _read16(raw, sv)
                            s_vlen = _read16(raw, sv + 2)
                            if s_len == 0: break
                            # Key
                            nk = sv + 6
                            nk_end = nk
                            while nk_end+1 < len(raw) and raw[nk_end:nk_end+2] != b'\x00\x00':
                                nk_end += 2
                            skey = raw[nk:nk_end].decode('utf-16-le', errors='ignore')
                            nk_end += 2; nk_end = (nk_end+3) & ~3
                            # Value
                            if s_vlen > 0:
                                val_bytes = raw[nk_end: nk_end + s_vlen*2]
                                sval = val_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                                strings[skey] = sval
                            sv += s_len; sv = (sv+3) & ~3
                        st_off += st_len; st_off = (st_off+3) & ~3

                key_off += child_len
                key_off = (key_off + 3) & ~3
        except Exception:
            pass
        return strings


# ─────────────────────────────────────────────────────────────────────────────
#  Icon extraction  ->  .ico file bytes
# ─────────────────────────────────────────────────────────────────────────────

def extract_icon(exe_path: str) -> bytes | None:
    """
    Extract the first icon group from a PE file.
    Returns .ico file bytes or None if no icon found.
    """
    try:
        pe = PEFile(exe_path)

        # Get RT_GROUP_ICON resources
        groups = pe.get_resources(RT_GROUP_ICON)
        if not groups:
            return None

        # Parse the first GRPICONDIR
        grp_id, grp_data = groups[0]

        # GRPICONDIR header
        reserved = _read16(grp_data, 0)
        ico_type  = _read16(grp_data, 2)
        count     = _read16(grp_data, 4)

        # Parse GRPICONDIRENTRY entries (14 bytes each)
        entries = []
        for i in range(count):
            off  = 6 + i * 14
            width  = grp_data[off]
            height = grp_data[off + 1]
            color  = grp_data[off + 2]
            planes = _read16(grp_data, off + 4)
            bits   = _read16(grp_data, off + 6)
            size   = _read32(grp_data, off + 8)
            res_id = _read16(grp_data, off + 12)
            entries.append((width, height, color, planes, bits, size, res_id))

        # Fetch actual icon data for each entry
        icons = []
        for width, height, color, planes, bits, size, res_id in entries:
            found = pe.get_resources(RT_ICON, res_id)
            if found:
                icons.append((width, height, color, planes, bits, found[0][1]))

        if not icons:
            return None

        # Build .ico file
        ico_count = len(icons)
        # ICO header = 6 bytes
        # ICONDIRENTRY = 16 bytes each
        header_size = 6 + ico_count * 16
        offsets = []
        cur_off = header_size
        for *_, data in icons:
            offsets.append(cur_off)
            cur_off += len(data)

        # Write ICO
        out = bytearray()
        out += struct.pack('<HHH', 0, 1, ico_count)  # ICONDIR header
        for i, (width, height, color, planes, bits, data) in enumerate(icons):
            # ICONDIRENTRY: width, height, colorCount, reserved,
            #               planes, bitCount, bytesInRes, imageOffset
            w = width  if width  != 0 else 256
            h = height if height != 0 else 256
            out += struct.pack('<BBBBHHII',
                               width, height, color, 0,
                               planes, bits,
                               len(data), offsets[i])
        for *_, data in icons:
            out += data

        return bytes(out)

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Version info -> PyInstaller version file
# ─────────────────────────────────────────────────────────────────────────────

def make_version_file(exe_path: str, output_path: str) -> bool:
    """
    Read version strings from source EXE and write a PyInstaller
    version_info file that embeds the same metadata into the stub EXE.
    Returns True on success.
    """
    try:
        pe = PEFile(exe_path)
        vs = pe.get_version_strings()

        desc     = vs.get('FileDescription',  vs.get('ProductName', 'Protected Application'))
        company  = vs.get('CompanyName',       '')
        product  = vs.get('ProductName',       desc)
        fver_str = vs.get('FileVersion',       '1.0.0.0')
        pver_str = vs.get('ProductVersion',    fver_str)
        fname    = vs.get('OriginalFilename',  os.path.basename(exe_path))
        copy     = vs.get('LegalCopyright',    '')
        comments = vs.get('Comments',          '')

        def ver_tuple(s):
            parts = s.replace(',', '.').split('.')
            nums = []
            for p in parts[:4]:
                try: nums.append(int(p.strip()))
                except: nums.append(0)
            while len(nums) < 4:
                nums.append(0)
            return tuple(nums[:4])

        fver = ver_tuple(fver_str)
        pver = ver_tuple(pver_str)

        def esc(s):
            return s.replace('\\', '\\\\').replace("'", "\\'")

        content = f"""# auto-generated by ExeShield lock_tool.py
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={fver},
    prodvers={pver},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [
          StringStruct(u'CompanyName',      u'{esc(company)}'),
          StringStruct(u'FileDescription',  u'{esc(desc)}'),
          StringStruct(u'FileVersion',      u'{esc(fver_str)}'),
          StringStruct(u'InternalName',     u'{esc(os.path.splitext(fname)[0])}'),
          StringStruct(u'LegalCopyright',   u'{esc(copy)}'),
          StringStruct(u'OriginalFilename', u'{esc(fname)}'),
          StringStruct(u'ProductName',      u'{esc(product)}'),
          StringStruct(u'ProductVersion',   u'{esc(pver_str)}'),
          StringStruct(u'Comments',         u'{esc(comments)}'),
        ]
      )
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True

    except Exception as e:
        print(f'[pe_utils] make_version_file error: {e}')
        return False
