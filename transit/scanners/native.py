#!/usr/bin/env python3
"""Native executables hidden in any file, whatever its name: ELF (Linux and the BSDs), PE (Windows) and Mach-O
(macOS), thin and fat.

    native.py ROOT [--skip DIR]

One run per scan, started by both engines (scan_pipeline.sh and scan_pipeline.py) so that they behave
identically by construction. It walks ROOT itself: no directory is pruned (node_modules, vendor, build, dist,
target and .venv ship in the approved archive, so they are examined), .transitignore and diff mode do not
apply, and a symbolic link is never followed. Only `.git/objects` (zlib-compressed objects, nothing to read
raw) and --skip DIR (the pipeline's own work directory) are left out.

Step 1, over every file, in full, at any offset:
    a header that is really an executable. ELF is the magic, a type 1..4 and a machine, nothing else (the Linux
    kernel ignores every other field, so a stricter test would be an evasion); PE is `MZ` whose e_lfanew points
    at `PE\\0\\0`; Mach-O is a thin magic with a plausible header, or a fat header whose first slice starts with
    a thin magic. A bare `MZ` or `\\x7fELF` is not a finding: 742 of 102,026 ordinary files contain `MZ`, and
    only 2 contained a real executable.
    The first 4 KB is also tried under a single-byte XOR or ADD.
Step 2, over every file that step 1 passed:
    base64 and hex text, C / Python / PowerShell / Go byte arrays (0x7f, ... and 127, ...), \\x and octal
    escapes and spaced hex are decoded and then given to the same test, one level of gzip / zlib / zip inside
    a decoded blob included. A marker is never reported without the decoded header behind it.

Files whose extension has a scanner of its own (.so .dll .exe, jar, Office, PDF, zip and tar) keep that
scanner's verdict and are not read here.

Output (stdout, binary): NUL-terminated triples  TAG PATH MESSAGE
    F  path  message    a finding, to be recorded as a FAIL that no allowlist and no --min-severity can lower
    E  path  message    the scan could not finish (time budget, an unreadable file or directory); also a FAIL
    S  .     message    findings beyond the cap, summarised
    Z  count message    always the last triple; count is the number of F, E and S triples before it
A missing Z means the run was cut short. Every message is built from the closed tables below and integers:
no byte of the scanned repository (not even its extension) reaches a message, because a message is read for
`:LOW:`-style severity markers and for the rule token of the allowlist.

NATIVE_TIME_BUDGET_S (default 120) bounds the whole run; reaching it is an E record, never a quiet pass.
NATIVE_MAX_FINDINGS (default 200) bounds the individual findings. Standard library only; no sibling imports,
so it also runs under `python3 -I`.
"""
import binascii
import os
import re
import stat
import struct
import sys
import time
import zlib

CHUNK = 2 * 1024 * 1024                  # raw sweep read size
WIN = 64                                 # bytes of header given to the validators (PE reads further with pread)
WHOLE_MAX = 32 * 1024 * 1024             # a file this small is decoded whole; a larger one in overlapping slices
STREAM_CHUNK = 8 * 1024 * 1024
STREAM_OVERLAP = 64 * 1024
RUN_MIN = 64                             # shortest base64 / hex run worth decoding
ALIGN_WINDOW = 64 * 1024                 # alignments 1..3 of a base64 run are tried on this much of it
INFLATE_MAX = 16 * 1024 * 1024
ZIP_MAX_BLOB = 8 * 1024 * 1024
ZIP_MAX_ENTRIES = 32
DEFAULT_BUDGET_S = 120.0
DEFAULT_MAX_FINDINGS = 200

# extensions whose own scanner decides (scan_binary, scan_jar, scan_office, scan_pdf, scan_archive)
OWNED = frozenset(
    "so dll dylib exe elf bin "
    "jar war ear aar "
    "docx docm dotx dotm xlsx xlsm xlsb xltx xltm xlam pptx pptm ppsx ppsm potx potm ppam "
    "doc dot xls xlt xla ppt pot pps ppa "
    "odt ods odp odg ott ots otp otg fodt fods fodp fodg rtf "
    "pdf zip tar gz tgz bz2 xz".split())

# ── closed vocabularies: the only text a message is made of ──────────────────────────────────────────────────────
ELF_ARCH = {2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 10: "mips_rs3_le", 15: "parisc", 20: "ppc", 21: "ppc64", 22: "s390",
            40: "arm", 41: "alpha", 42: "superh", 43: "sparcv9", 50: "ia64", 62: "x86_64", 83: "avr", 92: "openrisc",
            93: "arc", 94: "xtensa", 105: "msp430", 106: "blackfin", 164: "hexagon", 183: "aarch64", 190: "cuda",
            243: "riscv", 247: "bpf", 252: "csky", 258: "loongarch", 0x9026: "alpha"}
ELF_TYPE = {1: "object", 2: "exec", 3: "shared", 4: "core"}
PE_ARCH = {0x014c: "x86", 0x8664: "x86_64", 0x01c0: "arm", 0x01c2: "arm", 0x01c4: "arm", 0xaa64: "arm64", 0xa641: "arm64",
           0x0200: "ia64", 0x5032: "riscv32", 0x5064: "riscv64", 0x6232: "loongarch32", 0x6264: "loongarch64",
           0x01f0: "ppc", 0x01f1: "ppc", 0x0166: "mips", 0x0266: "mips", 0x0366: "mips", 0x0ebc: "ebc"}
MACHO_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64", 0x0200000c: "arm64_32", 18: "ppc",
             0x01000012: "ppc64", 14: "sparc", 6: "m68k", 10: "m88k", 15: "i860"}
MACHO_TYPE = {1: "object", 2: "exec", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle",
              9: "stub", 10: "dsym", 11: "kext", 12: "fileset"}
THIN = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")

# the strings searched for in a buffer, with how many bytes the header starts before the match
MARKS = ((b"\x7fELF", 0), (b"MZ", 0), (b"\xfe\xed\xfa", 0), (b"\xfa\xed\xfe", 1), (b"\xca\xfe\xba", 0))


class Incomplete(Exception):
    """The scan cannot be finished: carries a closed reason."""

    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


_deadline = [0.0]
_tick = [0]


def _check():
    if time.monotonic() > _deadline[0]:
        raise Incomplete("time_budget")


def _tickcheck():
    """Called once per candidate header: a hostile file made of nothing but `MZ` has one candidate every two bytes."""
    _tick[0] += 1
    if not _tick[0] & 0x1FFF:
        _check()


# ── the validators ───────────────────────────────────────────────────────────────────────────────────────────────
def _classify(h, remaining, rd):
    """The closed kind of the executable header at the start of `h`, or None.
    h: the bytes from the header on (at most WIN); remaining: bytes from the header to the end of the data;
    rd(off, n): further bytes, relative to the header."""
    if len(h) < 4:
        return None
    m4 = h[:4]
    if m4 == b"\x7fELF":
        return _elf(h, remaining)
    if h[:2] == b"MZ":
        return _pe(h, remaining, rd)
    if m4 in THIN:
        return _macho(h, remaining)
    if m4[:3] == b"\xca\xfe\xba" and m4[3] in (0xbe, 0xbf):
        return _fat(h, remaining, rd)
    return None


def _elf(h, remaining):
    if len(h) < 20 or remaining < 20:
        return None
    for e in ("<", ">"):                 # EI_DATA is ignored by the kernel, so both byte orders are tried
        t, m = struct.unpack_from(e + "HH", h, 16)
        if 1 <= t <= 4 and (m in ELF_ARCH or 1 <= m <= 511):
            return "ELF_%s_%s" % (ELF_ARCH.get(m, "other"), ELF_TYPE[t])
    return None


def _pe(h, remaining, rd):
    if len(h) < 0x40 or remaining < 0x40:
        return None
    e = struct.unpack_from("<I", h, 0x3C)[0]
    if e < 4 or e + 24 > remaining:      # 4 allows the tiny PE whose header overlaps the DOS header
        return None
    nt = h[e:e + 24] if e + 24 <= len(h) else rd(e, 24)
    if len(nt) < 24 or nt[:4] != b"PE\x00\x00":
        return None
    machine, chars = struct.unpack_from("<HH", nt[4:6] + nt[22:24])
    return "PE_%s_%s" % (PE_ARCH.get(machine, "other"), "dll" if chars & 0x2000 else "exe")


def _macho(h, remaining):
    if len(h) < 28 or remaining < 28:
        return None
    e = ">" if h[0] == 0xfe else "<"
    cpu, ft, nc, sz = (struct.unpack_from(e + "I", h, o)[0] for o in (4, 12, 16, 20))
    if cpu in MACHO_CPU and ft in MACHO_TYPE and 1 <= nc <= 65535 and sz <= remaining:
        return "MachO_%s_%s" % (MACHO_CPU[cpu], MACHO_TYPE[ft])
    return None


def _fat(h, remaining, rd):
    """A fat header shares its first four bytes with a Java class file; the class file has major >= 45 where this has
    the count of architectures (1..44), and a real fat file starts its first slice with a thin magic."""
    if len(h) < 8:
        return None
    n = struct.unpack_from(">I", h, 4)[0]
    if not 1 <= n <= 44:
        return None
    esz = 20 if h[3] == 0xbe else 32
    if len(h) < 8 + esz:
        return None
    cpu = struct.unpack_from(">I", h, 8)[0]
    off = struct.unpack_from(">I", h, 16)[0] if esz == 20 else struct.unpack_from(">Q", h, 16)[0]
    if cpu not in MACHO_CPU or off < 8 + esz * n or off >= remaining:
        return None
    if rd(off, 4) not in THIN:
        return None
    return "MachO_fat"


def _sweep_buffer(data):
    """The first (lowest offset) executable header anywhere in `data`: (kind, offset) or None."""
    best = None
    n = len(data)
    for mark, back in MARKS:
        p = data.find(mark, back)
        while p != -1:
            s = p - back
            if best is not None and s >= best[1]:
                break
            _tickcheck()
            kind = _classify(data[s:s + WIN], n - s, lambda off, cnt, s=s: data[s + off:s + off + cnt])
            if kind:
                best = (kind, s)
                break
            p = data.find(mark, p + 1)
    return best


# ── step 1: the raw bytes of a file ──────────────────────────────────────────────────────────────────────────────
def _sweep_fd(fd, size):
    """-> (hit, head): hit is (kind, offset) or None; head the first 4096 bytes. The whole file is read, in chunks
    that overlap by WIN bytes (a header is judged only when WIN bytes of it are in hand, or at the end of the file)."""
    carry, base, done, head = b"", 0, 0, b""
    while True:
        _check()
        buf = os.read(fd, CHUNK)
        last = len(buf) < CHUNK
        data = carry + buf
        if not head:
            head = data[:4096]
        end = len(data)
        limit = end if last else max(end - WIN, 0)
        best = None
        lo = max(done - base, 0)
        for mark, back in MARKS:
            p = data.find(mark, lo + back)
            while p != -1 and p - back < limit:
                s = p - back
                if best is not None and s >= best[1]:
                    break
                _tickcheck()
                a = base + s
                kind = _classify(data[s:s + WIN], size - a, lambda off, cnt, a=a: os.pread(fd, cnt, a + off))
                if kind:
                    best = (kind, a)
                    break
                p = data.find(mark, p + 1)
        if best is not None:
            return best, head
        done = base + limit
        if last:
            return None, head
        carry = data[limit:]
        base += limit


def _masked_head(fd, head, size):
    """The first bytes of the file are an executable header under a single-byte XOR or ADD: -> kind or None."""
    if len(head) < WIN:
        return None
    for magic in (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                  b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        for op in ("xor", "add"):
            k = (head[0] ^ magic[0]) if op == "xor" else (head[0] - magic[0]) & 255
            if k == 0:
                continue
            if op == "xor":
                if any(head[i] ^ k != magic[i] for i in range(1, len(magic))):
                    continue
                table = bytes(i ^ k for i in range(256))
            else:
                if any((head[i] - k) & 255 != magic[i] for i in range(1, len(magic))):
                    continue
                table = bytes((i - k) & 255 for i in range(256))
            plain = head.translate(table)
            kind = _classify(plain[:WIN], size, lambda off, cnt: os.pread(fd, cnt, off).translate(table))
            if kind:
                return kind
    return None


# ── step 2: text forms ───────────────────────────────────────────────────────────────────────────────────────────
B64_RUN = re.compile(rb"[A-Za-z0-9+/\r\n]{64,}={0,2}")
HEX_FULL = re.compile(rb"[0-9a-fA-F]+")
HEX_SEG = re.compile(rb"[0-9a-fA-F]{%d,}" % RUN_MIN)
HEXARR_RX = re.compile(rb"(?:0[xX][0-9a-fA-F]{1,2}[\s,;]{0,8}){16,}")
ESCX_RX = re.compile(rb"(?:\\[xX][0-9a-fA-F]{2}){16,}")
ESCO_RX = re.compile(rb"(?:\\[0-7]{3}){16,}")
SPHEX_RX = re.compile(rb"(?:[0-9a-fA-F]{2}[ \t:,-]){31,}[0-9a-fA-F]{2}")
DEC_RX = re.compile(rb"(?:[0-9]{1,3}[\s,]{1,8}){15,}[0-9]{1,3}")
SPHEX_GATE = re.compile(rb"7[fF][ \t:,-]45|4[dD][ \t:,-]5[aA]|[cC][eEfF][ \t:,-][fF][aA][ \t:,-][eE][dD]|"
                        rb"[fF][eE][ \t:,-][eE][dD][ \t:,-][fF][aA]|[cC][aA][ \t:,-][fF][eE][ \t:,-][bB][aA]")
DEC_GATE = re.compile(rb"127[ ,\t]{1,3}69[ ,\t]{1,3}76|77[ ,\t]{1,3}90[ ,\t]|20[67][ ,\t]{1,3}250|254[ ,\t]{1,3}237|"
                      rb"202[ ,\t]{1,3}254")
HEX_TOK = re.compile(rb"0[xX]([0-9a-fA-F]{1,2})")
OCT_TOK = re.compile(rb"\\([0-7]{3})")
SPACE_SEP = re.compile(rb"[ \t:,-]")
DEC_TOK = re.compile(rb"[0-9]{1,3}")


def _inflate(data):
    """One level of gzip, zlib or zip inside a decoded blob: the buffers that come out."""
    out = []
    try:
        if data[:2] == b"\x1f\x8b":
            out.append(zlib.decompressobj(31).decompress(data, INFLATE_MAX))
        elif len(data) >= 2 and (data[0] & 0x0F) == 8 and ((data[0] << 8) | data[1]) % 31 == 0:
            out.append(zlib.decompressobj().decompress(data, INFLATE_MAX))
        elif data[:4] == b"PK\x03\x04" and len(data) <= ZIP_MAX_BLOB:
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for zi in z.infolist()[:ZIP_MAX_ENTRIES]:
                    if zi.file_size and not zi.is_dir():
                        with z.open(zi) as member:
                            out.append(member.read(INFLATE_MAX))
    except Exception:                                         # a damaged or exotic stream: nothing to read
        return out
    return out


def _deep(data):
    """A decoded blob: (kind, compressed) for an executable header in it, or one level of decompression inside it."""
    r = _sweep_buffer(data)
    if r:
        return r[0], False
    for inner in _inflate(data):
        r = _sweep_buffer(inner)
        if r:
            return r[0], True
    return None


def _found(enc, deep):
    return deep[0], enc + ("_compressed" if deep[1] else "")


def _scan_forms(data, all_align):
    """base64 / hex / arrays / escapes in `data`, decoded and judged: (kind, encoding) or None. `all_align`: `data` is a
    slice of a larger file, so a run may begin anywhere in the base64 stream and all four alignments are decoded."""
    for m in B64_RUN.finditer(data):
        _check()
        run = m.group().translate(None, b"\r\n").rstrip(b"=")
        if len(run) < RUN_MIN:
            continue
        pure_hex = HEX_FULL.fullmatch(run) is not None
        # hex text: the run itself, or the hex stretches inside a run that has other letters glued on (the loader that
        # decodes it strips them); both parities, because a stray hex digit in front shifts every byte
        for seg in ((run,) if pure_hex else HEX_SEG.findall(run)):
            for k in (0, 1):
                part = seg[k:]
                d = _deep(binascii.unhexlify(part[:len(part) // 2 * 2]))
                if d:
                    return _found("hex", d)
        if pure_hex:
            continue
        for k in (0, 1, 2, 3):
            seg = run[k:] if (k == 0 or all_align) else run[k:k + ALIGN_WINDOW]
            seg = seg[:len(seg) // 4 * 4]
            if len(seg) < RUN_MIN:
                continue
            d = _deep(binascii.a2b_base64(seg))
            if d:
                return _found("base64", d)
    if b"0x" in data or b"0X" in data:
        for m in HEXARR_RX.finditer(data):
            _check()
            d = _deep(bytes(int(t, 16) for t in HEX_TOK.findall(m.group())))
            if d:
                return _found("hex_array", d)
    if b"\\x" in data or b"\\X" in data:
        for m in ESCX_RX.finditer(data):
            _check()
            d = _deep(binascii.unhexlify(m.group().replace(b"\\x", b"").replace(b"\\X", b"")))
            if d:
                return _found("escaped_hex", d)
    if b"\\" in data:
        for m in ESCO_RX.finditer(data):
            _check()
            d = _deep(bytes(int(t, 8) & 255 for t in OCT_TOK.findall(m.group())))
            if d:
                return _found("escaped_octal", d)
    if SPHEX_GATE.search(data):
        for m in SPHEX_RX.finditer(data):
            _check()
            d = _deep(binascii.unhexlify(SPACE_SEP.sub(b"", m.group())))
            if d:
                return _found("spaced_hex", d)
    if DEC_GATE.search(data):
        for m in DEC_RX.finditer(data):
            _check()
            vals = [int(t) for t in DEC_TOK.findall(m.group())]
            if max(vals) > 255:
                continue
            d = _deep(bytes(vals))
            if d:
                return _found("decimal_array", d)
    return None


def _read_all(fd, size):
    parts, left = [], size
    while left > 0:
        b = os.read(fd, min(left, 8 * 1024 * 1024))
        if not b:
            break
        parts.append(b)
        left -= len(b)
    return b"".join(parts)


def _encoded_fd(fd, size):
    if size <= WHOLE_MAX:
        return _scan_forms(_read_all(fd, size), False)
    carry = b""
    while True:
        _check()
        buf = os.read(fd, STREAM_CHUNK)
        if not buf:
            return None
        data = carry + buf
        r = _scan_forms(data, True)
        if r:
            return r
        carry = data[-STREAM_OVERLAP:]


# ── the walk and the records ─────────────────────────────────────────────────────────────────────────────────────
def _walk(root, skip):
    """Every file under `root`, in a fixed order: sorted, directories before the files below them, nothing pruned."""
    errors = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=errors.append):
        dirnames.sort()
        filenames.sort()
        if skip is not None:
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) != skip]
        if os.path.basename(dirpath) == b".git" and b"objects" in dirnames:
            dirnames.remove(b"objects")
        for name in filenames:
            yield os.path.join(dirpath, name)
    for _ in errors:
        yield None


def _owned(path):
    base = os.path.basename(path)
    if b"." not in base:
        return False
    try:
        return base.rsplit(b".", 1)[1].lower().decode("ascii") in OWNED
    except UnicodeDecodeError:
        return False


class Records(object):
    def __init__(self, cap):
        self.cap = cap
        self.items = []
        self.dropped = 0

    def add(self, tag, path, message):
        if len(self.items) < self.cap:
            self.items.append((tag, path, message))
        else:
            self.dropped += 1


def _open(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))


def run(root, skip, budget, cap):
    _deadline[0] = time.monotonic() + budget
    rec = Records(cap)
    files = nbytes = 0
    incomplete = ""
    root = os.path.abspath(root)
    if skip is not None:
        skip = os.path.abspath(skip)
        if skip == root or root.startswith(skip + b"/") or not skip.startswith(root + b"/"):
            skip = None                                       # the work directory is not below the scan root
    cut = len(root) + 1
    try:
        # step 1: every file, raw bytes (and the masked head). It is complete before step 2 starts.
        later = []
        for path in _walk(root, skip):
            _check()
            if path is None:
                rec.add("E", b".", "engine:native_scan_incomplete:unreadable_directory")
                continue
            rel = path[cut:]
            try:
                st = os.lstat(path)
            except OSError:
                rec.add("E", rel, "engine:native_scan_incomplete:unreadable_file")
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size < 4 or _owned(path):
                continue
            files += 1
            fd = -1
            try:
                fd = _open(path)
                size = os.fstat(fd).st_size
                hit, head = _sweep_fd(fd, size)
                nbytes += size
                if hit:
                    rec.add("F", rel, "CWE-506:hidden_native_executable:%s:offset_%d" % hit)
                    continue
                kind = _masked_head(fd, head, size)
                if kind:
                    rec.add("F", rel, "CWE-506:encoded_native_executable:%s:masked_bytes" % kind)
                    continue
                if size >= RUN_MIN:
                    later.append((path, rel))
            except OSError:
                rec.add("E", rel, "engine:native_scan_incomplete:unreadable_file")
            finally:
                if fd >= 0:
                    os.close(fd)
        # step 2: the text forms
        for path, rel in later:
            _check()
            fd = -1
            try:
                fd = _open(path)
                r = _encoded_fd(fd, os.fstat(fd).st_size)
                if r:
                    rec.add("F", rel, "CWE-506:encoded_native_executable:%s:%s" % r)
            except OSError:
                rec.add("E", rel, "engine:native_scan_incomplete:unreadable_file")
            finally:
                if fd >= 0:
                    os.close(fd)
    except Incomplete as e:
        incomplete = e.reason
        rec.items.append(("E", b".", "engine:native_scan_incomplete:%s" % e.reason))     # never dropped by the cap
    out = sys.stdout.buffer
    for tag, path, message in rec.items:
        out.write(tag.encode() + b"\0" + path + b"\0" + message.encode() + b"\0")
    count = len(rec.items)
    if rec.dropped:
        out.write(b"S\0.\0" + ("CWE-506:hidden_native_executable:more_files_not_listed:count_%d" % rec.dropped).encode() + b"\0")
        count += 1
    out.write(b"Z\0" + str(count).encode() + b"\0" +
              ("files=%d bytes=%d incomplete=%d" % (files, nbytes, 1 if incomplete else 0)).encode() + b"\0")
    out.flush()
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: native.py ROOT [--skip DIR]\n")
        return 2
    root, skip = os.fsencode(argv[1]), None
    if len(argv) >= 4 and argv[2] == "--skip":
        skip = os.fsencode(argv[3])
    try:
        budget = float(os.environ.get("NATIVE_TIME_BUDGET_S", DEFAULT_BUDGET_S))
        cap = int(os.environ.get("NATIVE_MAX_FINDINGS", DEFAULT_MAX_FINDINGS))
    except ValueError:
        budget, cap = DEFAULT_BUDGET_S, DEFAULT_MAX_FINDINGS
    return run(root, skip, budget, cap)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
