#!/usr/bin/env python3
"""Native executables hidden in any file, whatever its name: ELF (Linux and the BSDs), PE (Windows) and Mach-O
(macOS), thin and fat.

    native.py ROOT [--skip DIR]

One run per scan, started by both engines (scan_pipeline.sh and scan_pipeline.py) so that they behave
identically by construction. It walks ROOT itself: no directory is pruned (node_modules, vendor, build, dist,
target and .venv ship in the approved archive, so they are examined), .transitignore and diff mode do not
apply, and a symbolic link is never followed. Left out: `<ROOT>/.git/objects` (zlib-compressed objects of the
repository that fetch_repo.sh removes) and --skip DIR (the pipeline's own work directory).

Step 1, over every file, in full, at any offset:
    a header that is really an executable. ELF is the magic, a type 1..4 and a machine, nothing else (the Linux
    kernel ignores every other field, so a stricter test would be an evasion); PE is `MZ` whose e_lfanew points
    at `PE\\0\\0`; Mach-O is a thin magic with a plausible header, or a fat header whose first slice starts with
    a thin magic. A bare `MZ` or `\\x7fELF` is not a finding: 742 of 102,026 ordinary files contain `MZ`, and
    only 2 contained a real executable. The first bytes are also tried under a single-byte XOR or ADD.
Step 2, over every file that step 1 passed, the text forms a loader decodes. Each form is turned into a byte
    stream that tolerates what is around it (indentation, comment prefixes, line wrapping, other text), and the
    stream is given to the step 1 test at any offset:
      base64 and base64url (every character that is not in the alphabet is dropped, `=` ends a stream, all four
      alignments), hex (every non-hex character dropped, both parities; xxd, hexdump -C and od dumps with their
      offsets and gutters), 0x byte and word arrays (comments stripped), decimal and signed-decimal arrays
      (Java byte[], JSON, Python lists), \\x and octal escapes with adjacent string literals joined
      (repr(bytes), msfvenom -f c, printf), and UTF-16 text of any of these. A decoded blob is also searched for
      gzip, zlib, zip, bzip2 and xz data at any offset, one level deep, read as a loader reads it (a zip is walked
      by its local headers, so a lying size, a bad CRC or an encrypted neighbour hides nothing).
    A marker is never reported without the decoded header behind it.

Files whose extension has a scanner of its own keep that scanner's verdict, but only when the content is what the
extension says it is: a `.so .dll .exe .elf .bin` (the scanner fails it on the extension alone), and a `.zip .jar
.docx .pdf .rtf .doc .gz .tar ...` that starts with its container's magic. A `.pdf` that is an ELF, a `.docx` that
is text, a `Makefile.so` (the build-file scanners get a file named like that before its extension is read) are read
here like any other file.

Output (stdout, binary): NUL-terminated triples  TAG PATH MESSAGE
    F  path  message    a finding, to be recorded as a FAIL that no allowlist and no --min-severity can lower
    E  path  message    the scan could not finish (time budget, an unreadable file or directory, a decode limit,
                        memory, an internal error); also a FAIL
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
import codecs
import math
import os
import re
import stat
import struct
import sys
import time
import warnings
import zlib

try:
    import bz2
except ImportError:                                           # a Python built without it: those streams are not read
    bz2 = None
try:
    import lzma
except ImportError:
    lzma = None

warnings.simplefilter("ignore")                               # codecs.escape_decode warns about \d and friends

CHUNK = 2 * 1024 * 1024                  # raw sweep read size
WIN = 64                                 # bytes of header given to the validators (PE reads further with pread)
WHOLE_MAX = 32 * 1024 * 1024             # a file this small is decoded whole; a larger one in overlapping slices
STREAM_CHUNK = 8 * 1024 * 1024
STREAM_OVERLAP = 64 * 1024
B64_MIN = 28                             # shortest base64 stream worth decoding: 20 bytes, an ELF header
HEX_MIN = 40                             # the same in hex digits
PIECE = 1024 * 1024                      # output piece of a decompressor
INFLATE_TOTAL = 256 * 1024 * 1024        # output of all the streams of one decoded blob; more is an E record
ENC_MIN = 64                             # an executable found in decoded text has at least this many bytes from its header on:
                                         # a two-line hex dump of an ELF header in a manual is not a program
DEC_WINDOW = 1 << 20                     # bytes decoded forward from one decimal-array header
DEC_HITS = 32                            # decimal-array headers followed per file
DEFAULT_BUDGET_S = 120.0
DEFAULT_MAX_FINDINGS = 200

# ── which files keep the verdict of the scanner that owns their extension ───────────────────────────────────────
GZ, BZ2_M, XZ_M = b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"
PRINTABLE = bytes(range(32, 127)) + bytes(range(128, 256))


def _always(h):
    return True


def _zip(h):
    return h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _ole(h):
    return h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _rtf(h):
    return h[:5] == b"{\\rtf"


def _legacy_office(h):
    return _zip(h) or _ole(h) or _rtf(h)


def _pdf(h):
    return b"%PDF-" in h[:1024]


OWNERS = {}
for _e in "so dll dylib exe elf bin".split():                 # scan_binary: a FAIL on the extension, whatever the content
    OWNERS[_e] = _always
for _e in ("zip jar war ear aar docx docm dotx dotm xlsx xlsm xlsb xltx xltm xlam pptx pptm ppsx ppsm potx potm ppam "
           "odt ods odp odg ott ots otp otg").split():
    OWNERS[_e] = _zip
for _e in "doc dot xls xlt xla ppt pot pps ppa".split():
    OWNERS[_e] = _legacy_office
OWNERS["rtf"] = _rtf
OWNERS["pdf"] = _pdf
OWNERS["gz"] = OWNERS["tgz"] = lambda h: h[:2] == GZ
OWNERS["bz2"] = lambda h: h[:3] == BZ2_M
OWNERS["xz"] = lambda h: h[:6] == XZ_M
OWNERS["tar"] = lambda h: h[257:262] == b"ustar"
# classify_file reads these names before it looks at an extension: `Makefile.so` is a Makefile to the scanners
NAME_DISPATCHED = (b"Dockerfile", b"Makefile", b"makefile", b"GNUmakefile")

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
    """The whole run cannot be finished: carries a closed reason."""

    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


class Undecodable(Exception):
    """One file cannot be read to the end (a decode limit, an unsupported stream): carries a closed reason."""

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


def _sweep_buffer(data, min_rem=0):
    """The first (lowest offset) executable header anywhere in `data` that has at least `min_rem` bytes from its start to the
    end of `data`: (kind, offset) or None."""
    best = None
    n = len(data)
    for mark, back in MARKS:
        p = data.find(mark, back)
        while p != -1:
            s = p - back
            if best is not None and s >= best[1]:
                break
            _tickcheck()
            kind = _classify(data[s:s + WIN], n - s, lambda off, cnt, s=s: data[s + off:s + off + cnt]) if n - s >= min_rem else None
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
                a = base + s
                if best is not None and a >= best[1]:           # offsets are absolute: compare absolute ones
                    break
                _tickcheck()
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
    if len(head) < 20:
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


# ── compressed data inside a decoded blob ────────────────────────────────────────────────────────────────────────
def _run_decomp(dobj, buf, budget):
    """Stream a decompressor over `buf`: yields output pieces (each prefixed with the last WIN bytes of the one before, so a
    header on a boundary is whole). Stops quietly at a data error, as a loader that ignores a bad CRC does; the total output
    of one blob is bounded, and the bound is Undecodable, never a quiet stop."""
    tail, first = b"", True
    while True:
        _check()
        try:
            if hasattr(dobj, "unconsumed_tail"):                                      # zlib
                out = dobj.decompress(buf if first else dobj.unconsumed_tail, PIECE)
                more = bool(dobj.unconsumed_tail)
            else:                                                                     # bz2, lzma
                out = dobj.decompress(buf if first else b"", PIECE)
                more = not dobj.needs_input and not dobj.eof
        except Exception:
            return
        first = False
        if out:
            budget[0] -= len(out)
            if budget[0] < 0:
                raise Undecodable("decode_limit")
            yield tail + out
            tail = out[-WIN:]
        if dobj.eof or (not more and not out):
            return


def _zip_members(data, budget):
    """The members of every zip in `data`, read from the local headers the way unzip and the JVM read them: the size in a
    header may lie, the CRC is not checked, a member that cannot be read does not stop the next one."""
    mv = memoryview(data)
    p = data.find(b"PK\x03\x04")
    while p != -1:
        _check()
        if p + 30 > len(data):
            return
        ver, flags, method = struct.unpack_from("<HHH", data, p + 4)
        csize, _usize, nlen, elen = struct.unpack_from("<IIHH", data, p + 18)
        start = p + 30 + nlen + elen
        name = data[p + 30:p + 30 + nlen]
        # `PK\x03\x04` is also what source code that talks about zip files decodes to, followed by whatever text came next:
        # only a header with a believable version and a name without control bytes is a member
        if ver > 63 or len(name) != nlen or name.translate(None, PRINTABLE) or start > len(data):
            pass
        elif flags & 1:                                                                # encrypted: nothing to read
            pass
        elif method == 0:
            if csize and not flags & 8:
                end = min(start + csize, len(data))
            else:
                nxt = [q for q in (data.find(b"PK\x03\x04", start), data.find(b"PK\x01\x02", start)) if q != -1]
                end = min(nxt) if nxt else len(data)
            budget[0] -= max(end - start, 0)
            if budget[0] < 0:
                raise Undecodable("decode_limit")
            yield bytes(mv[start:end])
        elif method == 8:
            yield from _run_decomp(zlib.decompressobj(-15), mv[start:], budget)
        elif method == 12 and bz2 is not None:
            yield from _run_decomp(bz2.BZ2Decompressor(), mv[start:], budget)
        elif method == 14 and lzma is not None and len(data) >= start + 9:
            props = data[start + 4]
            filt = [{"id": lzma.FILTER_LZMA1, "lc": props % 9, "lp": (props // 9) % 5, "pb": props // 45,
                     "dict_size": max(struct.unpack_from("<I", data, start + 5)[0], 4096)}]
            try:
                yield from _run_decomp(lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filt), mv[start + 9:], budget)
            except (lzma.LZMAError, ValueError, OverflowError):
                pass
        elif method in (9, 10, 18, 19, 97, 98):
            raise Undecodable("decode_unsupported")                                    # deflate64, PPMd ...: a real member we cannot read
        p = data.find(b"PK\x03\x04", p + 4)


def _gzip_header_end(data, p):
    """Where the deflate data of the gzip member that starts at `p` begins, or None."""
    n = len(data)
    if p + 10 > n:
        return None
    flg = data[p + 3]
    q = p + 10
    if flg & 4:
        if q + 2 > n:
            return None
        q += 2 + struct.unpack_from("<H", data, q)[0]
    for bit in (8, 16):                                                                # a file name, a comment
        if flg & bit:
            z = data.find(b"\0", q)
            if z == -1:
                return None
            q = z + 1
    if flg & 2:
        q += 2
    return q if q < n else None


def _inflate_pieces(data):
    """Everything that compressed data found at any offset of `data` decompresses to, one level deep."""
    budget = [INFLATE_TOTAL]
    mv = memoryview(data)
    p, tries = data.find(b"\x1f\x8b\x08"), 0
    while p != -1 and tries < 64:                                                      # gzip; every member, at any offset
        tries += 1
        off = _gzip_header_end(data, p)
        if off is not None:
            yield from _run_decomp(zlib.decompressobj(-15), mv[off:], budget)        # raw deflate: a bad CRC stops nobody
        p = data.find(b"\x1f\x8b\x08", p + 3)
    for hdr in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):                # zlib; a preset dictionary is not readable
        p, tries = data.find(hdr), 0
        while p != -1 and tries < 32:
            tries += 1
            yield from _run_decomp(zlib.decompressobj(-15), mv[p + 2:], budget)       # a bad Adler checksum stops nobody
            p = data.find(hdr, p + 2)
    if b"PK\x03\x04" in data:
        yield from _zip_members(data, budget)
    if bz2 is not None:
        p, tries = data.find(b"BZh"), 0
        while p != -1 and tries < 32:
            if data[p + 3:p + 4].isdigit() and data[p + 4:p + 10] == b"1AY&SY":
                tries += 1
                yield from _run_decomp(bz2.BZ2Decompressor(), mv[p:], budget)
            p = data.find(b"BZh", p + 3)
    if lzma is not None:
        p, tries = data.find(XZ_M), 0
        while p != -1 and tries < 32:
            tries += 1
            yield from _run_decomp(lzma.LZMADecompressor(), mv[p:], budget)
            p = data.find(XZ_M, p + 6)


def _deep(data):
    """A decoded blob: (kind, compressed) for an executable header in it, or inside compressed data found in it."""
    r = _sweep_buffer(data, ENC_MIN)
    if r:
        return r[0], False
    for piece in _inflate_pieces(data):
        r = _sweep_buffer(piece, ENC_MIN)
        if r:
            return r[0], True
    return None


def _found(enc, deep):
    return deep[0], enc + ("_compressed" if deep[1] else "")


# ── step 2: the text forms ───────────────────────────────────────────────────────────────────────────────────────
_B64_KEEP = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-=")
_HEX_KEEP = set(b"0123456789abcdefABCDEF")
NON_B64 = bytes(c for c in range(256) if c not in _B64_KEEP)
NON_HEX = bytes(c for c in range(256) if c not in _HEX_KEEP)
URLSAFE = bytes.maketrans(b"-_", b"+/")
B64_PART = re.compile(rb"[^=]{%d,}" % B64_MIN)
HEXTOK = re.compile(rb"0[xX]([0-9a-fA-F]{1,8})(?![0-9a-fA-F])")
DUMP_LINE = re.compile(rb"^[ \t]*[0-9a-fA-F]{4,16}:?[ \t]{1,3}((?:[0-9a-fA-F]{2}[ \t]{0,2}){8,16})", re.M)
DEC_SEP = rb"[ ,\t\r\n;\[\](){}]{1,6}"
DEC_GATE = re.compile(
    rb"127" + DEC_SEP + rb"69" + DEC_SEP + rb"76|77" + DEC_SEP + rb"90" + DEC_SEP + rb"-?[0-9]|"
    rb"(?:207|206)" + DEC_SEP + rb"250" + DEC_SEP + rb"237" + DEC_SEP + rb"254|"
    rb"-(?:49|50)" + DEC_SEP + rb"-6" + DEC_SEP + rb"-19" + DEC_SEP + rb"-2|"
    rb"254" + DEC_SEP + rb"237" + DEC_SEP + rb"250" + DEC_SEP + rb"20[67]|"
    rb"-2" + DEC_SEP + rb"-19" + DEC_SEP + rb"-6" + DEC_SEP + rb"-(?:49|50)|"
    rb"202" + DEC_SEP + rb"254" + DEC_SEP + rb"186" + DEC_SEP + rb"19[01]|"
    rb"-54" + DEC_SEP + rb"-2" + DEC_SEP + rb"-70" + DEC_SEP + rb"-6[56]")
DEC_TOK = re.compile(rb"-?[0-9]{1,3}")
ESC_GATE = re.compile(rb"\\x[0-9a-fA-F]{2}|\\[0-7]{3}")
ESC_JOIN = re.compile(rb"[\"'][ \t\r\n+\\]*[\"']")
ESC_TOK = re.compile(rb"\\x([0-9a-fA-F]{2})|\\([0-7]{1,3})|\\([nrtabfv\\'\"?])")
ESC_SIMPLE = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"a": b"\a", b"b": b"\b", b"f": b"\f", b"v": b"\v", b"\\": b"\\",
              b"'": b"'", b'"': b'"', b"?": b"?"}


def _b64_stream(view):
    """base64 and base64url: every character outside the alphabet is dropped (indentation, comment prefixes, quotes, line
    breaks, other separators), `=` ends a stream, and all four alignments are decoded, because text before the payload
    shifts it. A partial last group is padded, not cut."""
    s = view.translate(None, NON_B64)
    if len(s) < B64_MIN:
        return None
    s = s.translate(URLSAFE)
    for m in B64_PART.finditer(s):
        _check()
        part = m.group()
        for k in range(4):
            seg = part[k:]
            r = len(seg) % 4
            if r == 1:
                seg = seg[:-1]
            elif r:
                seg += b"=" * (4 - r)
            if len(seg) < B64_MIN:
                continue
            d = _deep(binascii.a2b_base64(seg))
            if d:
                return _found("base64", d)
    return None


def _hex_filter(view):
    """hex text: every character that is not a hex digit is dropped, so wrapping, indentation, comment prefixes and any
    separator (space, colon, dash, comma) are invisible. Both parities, because a stray digit shifts every byte."""
    h = view.translate(None, NON_HEX)
    if len(h) < HEX_MIN:
        return None
    for k in (0, 1):
        part = h[k:]
        d = _deep(binascii.unhexlify(part[:len(part) // 2 * 2]))
        if d:
            return _found("hex", d)
    return None


def _hex_dump(view):
    """xxd, hexdump -C and od dumps: the offset at the start of a line and the text gutter at its end are left out."""
    out = bytearray()
    for m in DUMP_LINE.finditer(view):
        out += binascii.unhexlify(m.group(1).replace(b" ", b"").replace(b"\t", b""))
        if len(out) > 64 * 1024 * 1024:
            break
    if len(out) < 20:
        return None
    d = _deep(bytes(out))
    return _found("hex", d) if d else None


def _strip_c_comments(t):
    if b"//" in t:
        t = re.sub(rb"//[^\n]*", b"", t)
    if b"/*" in t:
        parts, pos = [], 0
        while True:
            i = t.find(b"/*", pos)
            if i == -1:
                break
            j = t.find(b"*/", i + 2)
            if j == -1:
                break
            parts.append(t[pos:i])
            pos = j + 2
        parts.append(t[pos:])
        t = b" ".join(parts)
    return t


def _hex_tokens(view):
    """`0x7f, 0x45, ...` in C, Python, Go, PowerShell, JSON strings, with comments, suffixes (L, U, u8), rows and any
    indentation between the tokens: the tokens of the whole file are one stream. 8-digit tokens are 32-bit words (both byte
    orders are tried), 4-digit tokens 16-bit words."""
    if b"0x" not in view and b"0X" not in view:
        return None
    t = _strip_c_comments(view)
    b1, w16, w32 = bytearray(), [], []
    n = 0
    for m in HEXTOK.finditer(t):
        n += 1
        if not n & 0xFFFF:
            _check()
        g = m.group(1)
        k = len(g)
        if k <= 2:
            b1.append(int(g, 16))
        elif k == 4:
            w16.append(int(g, 16))
        elif k == 8:
            w32.append(int(g, 16))
    streams = [bytes(b1)]
    if len(w16) >= 10:
        streams += [struct.pack(">%dH" % len(w16), *w16), struct.pack("<%dH" % len(w16), *w16)]
    if len(w32) >= 5:
        streams += [struct.pack(">%dI" % len(w32), *w32), struct.pack("<%dI" % len(w32), *w32)]
    for s in streams:
        if len(s) >= 20:
            d = _deep(s)
            if d:
                return _found("hex_array", d)
    return None


def _decimal_arrays(view):
    """Decimal lists (Python, JSON, C, Java signed `byte[]`) are everywhere in data files, so only a list that holds the first
    bytes of a header is followed; from that point up to a megabyte of values is decoded."""
    hits = 0
    pos = 0
    for g in DEC_GATE.finditer(view):
        if g.start() < pos:
            continue
        hits += 1
        if hits > DEC_HITS:
            break
        _check()
        out, prev = bytearray(), g.start()
        for m in DEC_TOK.finditer(view, g.start(), min(len(view), g.start() + 8 * DEC_WINDOW)):
            if m.start() - prev > 12:
                break
            v = int(m.group())
            if v > 255 or v < -128:
                break
            out.append(v & 255)
            prev = m.end()
            if len(out) >= DEC_WINDOW:
                break
        pos = prev
        if len(out) >= 20:
            d = _deep(bytes(out))
            if d:
                return _found("decimal_array", d)
    return None


def _unescape(t):
    try:
        return codecs.escape_decode(t)[0]
    except ValueError:                                         # a malformed \x somewhere: decode what is well formed
        def one(m):
            if m.group(1):
                return bytes([int(m.group(1), 16)])
            if m.group(2):
                return bytes([int(m.group(2), 8) & 255])
            return ESC_SIMPLE[m.group(3)]
        return ESC_TOK.sub(one, t)


def _escapes(view):
    """\\x7f\\x45, \\177\\105 in C, Python and shell string literals: adjacent literals are joined ("..." "...", "..." + "...",
    line continuations) and the escapes decoded, everything else left as it is, so repr(bytes) (printable bytes literal,
    the rest escaped), msfvenom -f c and printf '\\177ELF...' all come out as the bytes they stand for."""
    seen = 0
    for _ in ESC_GATE.finditer(view):                                   # a binary file has one by chance, a payload has hundreds
        seen += 1
        if seen >= 16:
            break
    if seen < 16:
        return None
    t = ESC_JOIN.sub(b"", view)
    d = _deep(_unescape(t))
    return _found("escaped_bytes", d) if d else None


def _utf16_mode(head):
    """UTF-16 text (PowerShell's Out-File and `>` write it): 'le', 'be' or None, from a byte-order mark or from the NULs."""
    if head[:2] == b"\xff\xfe":
        return "le"
    if head[:2] == b"\xfe\xff":
        return "be"
    n = len(head) // 2
    if n >= 8:
        even0, odd0 = head[0::2].count(0), head[1::2].count(0)
        if odd0 > n * 0.4 and even0 < n * 0.1:
            return "le"
        if even0 > n * 0.4 and odd0 < n * 0.1:
            return "be"
    return None


def _utf16_view(data, mode, first):
    """The ASCII characters of UTF-16 text as bytes. A slice of a larger file starts on an even offset, so the mode of the
    first slice holds for the others; the byte-order mark is skipped only in the first."""
    if mode == "le":
        return data[2::2] if first and data[:2] == b"\xff\xfe" else data[0::2]
    return data[3::2] if first and data[:2] == b"\xfe\xff" else data[1::2]


def _scan_text(data, mode=None, first=True):
    """The text forms in `data` (and in its UTF-16 reading), decoded and judged: (kind, encoding) or None."""
    views = [data]
    if mode is None and first:
        mode = _utf16_mode(data[:4096])
    if mode:
        views.append(_utf16_view(data, mode, first))
    for view in views:
        for form in (_b64_stream, _hex_filter, _hex_dump, _hex_tokens, _decimal_arrays, _escapes):
            r = form(view)
            if r:
                return r
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
        return _scan_text(_read_all(fd, size))
    carry, first, mode = b"", True, None
    while True:
        _check()
        buf = os.read(fd, STREAM_CHUNK)
        if not buf:
            return None
        data = carry + buf
        if first:
            mode = _utf16_mode(data[:4096])
        r = _scan_text(data, mode, first)
        if r:
            return r
        first = False
        carry = data[-STREAM_OVERLAP:]


# ── the walk and the records ─────────────────────────────────────────────────────────────────────────────────────
def _walk(root, skip):
    """Every regular file under `root`, in a fixed order (the files of a directory by name, then its subdirectories by name),
    nothing pruned but `<root>/.git/objects` and `skip`. Iterative: a directory tree a thousand levels deep does not exhaust
    the interpreter's stack. A None is a directory that could not be read."""
    stack = [root]
    gitdir = os.path.join(root, b".git")
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            yield None
            continue
        dirs = []
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if (d == gitdir and e.name == b"objects") or e.path == skip:
                        continue
                    dirs.append(e.path)
                elif e.is_file(follow_symlinks=False):
                    yield e.path
            except OSError:
                yield None
        stack.extend(reversed(dirs))


def _owned_by_scanner(path, head):
    """The scanner that owns this extension decides, and it does read this file: its content is what the extension says."""
    base = os.path.basename(path)
    if base.startswith(NAME_DISPATCHED) or b"." not in base:
        return False
    try:
        claims = OWNERS.get(base.rsplit(b".", 1)[1].lower().decode("ascii"))
    except UnicodeDecodeError:
        return False
    return claims is not None and claims(head)


class Records(object):
    def __init__(self, cap):
        self.cap = cap
        self.items = []
        self.dropped = 0
        self.unfinished = False

    def add(self, tag, path, message):
        if tag == "E":
            self.unfinished = True
        if len(self.items) < self.cap:
            self.items.append((tag, path, message))
        else:
            self.dropped += 1


def _open(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))


def _run_files(root, skip, rec, stats):
    cut = len(root) + 1
    later = []
    # step 1: every file, raw bytes (and the masked head). It is complete before step 2 starts.
    for path in _walk(root, skip):
        _check()
        if path is None:
            rec.add("E", b".", "engine:native_scan_incomplete:unreadable_directory")
            continue
        rel = path[cut:]
        fd = -1
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_size < 4:
                continue
            fd = _open(path)
            size = os.fstat(fd).st_size
            if _owned_by_scanner(path, os.pread(fd, 1024, 0)):
                continue
            stats[0] += 1
            hit, head = _sweep_fd(fd, size)
            stats[1] += size
            if hit:
                rec.add("F", rel, "CWE-506:hidden_native_executable:%s:offset_%d" % hit)
                continue
            kind = _masked_head(fd, head, size)
            if kind:
                rec.add("F", rel, "CWE-506:encoded_native_executable:%s:masked_bytes" % kind)
                continue
            if size >= B64_MIN:
                later.append((path, rel))
        except OSError:
            rec.add("E", rel, "engine:native_scan_incomplete:unreadable_file")
        except MemoryError:
            rec.add("E", rel, "engine:native_scan_incomplete:memory")
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
        except Undecodable as u:
            rec.add("E", rel, "engine:native_scan_incomplete:%s" % u.reason)
        except OSError:
            rec.add("E", rel, "engine:native_scan_incomplete:unreadable_file")
        except MemoryError:
            rec.add("E", rel, "engine:native_scan_incomplete:memory")
        finally:
            if fd >= 0:
                os.close(fd)


def run(root, skip, budget, cap):
    _deadline[0] = time.monotonic() + budget
    rec = Records(cap)
    stats = [0, 0]
    root = os.path.abspath(root)
    if skip is not None:
        skip = os.path.abspath(skip)
        if skip == root or root.startswith(skip + b"/") or not skip.startswith(root + b"/"):
            skip = None                                       # the work directory is not below the scan root
    try:
        _run_files(root, skip, rec, stats)
    except Incomplete as e:
        rec.items.append(("E", b".", "engine:native_scan_incomplete:%s" % e.reason))     # never dropped by the cap
        rec.unfinished = True
    except Exception:                                         # RecursionError, MemoryError ...: the findings so far still count
        rec.items.append(("E", b".", "engine:native_scan_incomplete:internal_error"))
        rec.unfinished = True
    out = sys.stdout.buffer
    for tag, path, message in rec.items:
        out.write(tag.encode() + b"\0" + path + b"\0" + message.encode() + b"\0")
    count = len(rec.items)
    if rec.dropped:
        out.write(b"S\0.\0" + ("CWE-506:hidden_native_executable:more_files_not_listed:count_%d" % rec.dropped).encode() + b"\0")
        count += 1
    out.write(b"Z\0" + str(count).encode() + b"\0" +
              ("files=%d bytes=%d incomplete=%d" % (stats[0], stats[1], 1 if rec.unfinished else 0)).encode() + b"\0")
    out.flush()
    return 0


def _env_number(name, default, cast):
    try:
        v = cast(os.environ.get(name, default))
    except ValueError:
        return default
    if isinstance(v, float) and not math.isfinite(v):
        return default
    return v if v >= 0 else default


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: native.py ROOT [--skip DIR]\n")
        return 2
    root, skip = os.fsencode(argv[1]), None
    if len(argv) >= 4 and argv[2] == "--skip":
        skip = os.fsencode(argv[3])
    return run(root, skip, _env_number("NATIVE_TIME_BUDGET_S", DEFAULT_BUDGET_S, float),
               _env_number("NATIVE_MAX_FINDINGS", DEFAULT_MAX_FINDINGS, int))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
