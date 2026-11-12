# Moved out of scan_pipeline.sh (function _office_facts) without changes to the code below.
# Reads an office document (OOXML, OpenDocument, OLE2, RTF) and prints FACT lines for the scanner.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import base64, codecs, html, io, os, re, signal, struct, sys, time, zipfile, zlib

# argv: <document> <view file: text for the credential rules> <lower-case extension>
path, view_path, ext = sys.argv[1], sys.argv[2], sys.argv[3].lower()


def _knob(name, default):
    try:
        v = float(os.environ.get(name, ""))
        return v if v > 0 else default
    except ValueError:
        return default


MAX_ENTRIES = int(_knob("OFFICE_MAX_ENTRIES", 20000))      # parts whose bytes are read
BUDGET = int(_knob("OFFICE_READ_BUDGET_MB", 256) * 1048576)  # bytes read across all parts
TIME_BUDGET = _knob("OFFICE_TIME_BUDGET_S", 90)
DEADLINE = time.monotonic() + TIME_BUDGET


class Watchdog(BaseException):
    """Raised by the alarm when the cooperative time budget was not enough. A BaseException, so no
    `except Exception` in the analysis code can swallow it and carry on with the slow input."""


def _alarm(signum, frame):
    raise Watchdog()


# The time budget is checked between parts, but one pattern run on one hostile part cannot be
# interrupted by a check: it stops only when the alarm fires (the regex engine polls for signals).
# Whatever was found before the alarm is kept and the document is reported as not fully read.
if hasattr(signal, "setitimer"):
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, TIME_BUDGET + 10)
PART_CAP = 8 * 1048576    # most that is read from one binary part (XML parts are streamed)
CHUNK = 4 * 1048576       # size of one slice of a streamed XML part
EMBED_CAP = 32 * 1048576  # largest embedded container that is opened
VIEW_CAP = 32 * 1048576   # most text handed to the credential rules
MAX_DEPTH = 3             # the document, an object in it, an object in that
HEAD = 4096

facts = {}
state = {"parts": 0, "budget": BUDGET, "view": 0}

# record_fail downgrades a finding whose message contains :LOW: or :INFO: and friends,
# and part names, targets and macro names come from the document: neutralise the colon.
MARKER = re.compile(r":(?=(?:info|low|warning|medium|error|high|critical):)", re.I)


def n_facts():
    return sum(n for n, _ in facts.values())


def emit(tag, detail=""):
    detail = str(detail).replace("\\", "/")
    detail = re.sub(r"[^\x20-\x7e]|\|", "?", detail)[:120]
    detail = MARKER.sub("?", detail)
    n, ex = facts.get(tag, (0, []))
    if len(ex) < 6 and detail not in ex:
        ex.append(detail)
    facts[tag] = (n + 1, ex)


# ── byte shapes ──────────────────────────────────────────────────────────────
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
EXEC_EXT = re.compile(r"\.(exe|dll|scr|bat|cmd|com|pif|cpl|js|jse|vbs|vbe|wsf|wsh|ps1|psm1|hta|lnk|msi|msp|jar|chm|sct|wsc|reg|sh|"
                     r"xll|wll|url|scf|inf|ocx|msc|application|appref-ms|gadget|settingcontent-ms|library-ms|searchconnector-ms)$", re.I)
SHELLS = r"(?:cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|msiexec|certutil|bitsadmin|bash|sh)"
MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def native_kind(head):
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in MACHO:
        return "Mach-O"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if e + 4 <= len(head) and head[e:e + 4] == b"PE\x00\x00":
            return "PE"
    return ""


def texty(head):
    if not head or b"\x00" in head:
        return False
    return sum(1 for b in head if b >= 0x20 or b in (9, 10, 13)) / len(head) > 0.95


# ── hostile text, applied to code-bearing content only ───────────────────────
# Document PROSE is not searched for these: a manual saying "pipe curl into sh" is
# ordinary. They run on macro source, field codes and formulas.
HOSTILE = [
    ("shell_pipe", re.compile(r"(?i)\b(curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:/usr/bin/env\s+|/(?:usr/)?(?:local/)?bin/)?(?:ba|z|da)?sh\b")),
    ("encoded_powershell", re.compile(r"(?i)powershell[^\n]{0,300}\s-(?:e|enc|encodedcommand)[a-z]*\s+[A-Za-z0-9+/=]{20,}")),
    ("lolbin_download", re.compile(r"(?i)(certutil[^\n]{0,60}-urlcache|bitsadmin[^\n]{0,60}/transfer)")),
]

PEM_HEAD = re.compile(r"-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY[A-Z0-9 ]{0,30}-----")
B64_LINE = re.compile(r"^[A-Za-z0-9+/=]+$")
LINE_SPLIT = re.compile(r"\r\n|\r|\n|\\r\\n|\\n|\\r")


def private_key(label, unit):
    if "PRIVATE KEY" not in unit:
        return
    for m in PEM_HEAD.finditer(unit):
        run = 0
        for ln in LINE_SPLIT.split(unit[m.end():m.end() + 900])[:10]:
            ln = ln.strip()
            if ln and B64_LINE.match(ln):
                run += len(ln)
                if run >= 60:
                    emit("private_key", label)
                    return
            else:
                run = 0


view = open(view_path, "w", encoding="utf-8", errors="replace")


def to_view(label, text):
    if state["view"] >= VIEW_CAP:
        emit("incomplete", "text handed to the credential rules is capped at %d MB" % (VIEW_CAP >> 20))
        return
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    view.write("== " + label + "\n" + text + "\n")
    state["view"] += len(text)
    private_key(label, text)


def hostile(label, text):
    for tag, rx in HOSTILE:
        if rx.search(text):
            emit("hostile_" + tag, label)


# ── how a ZIP part is read: like Office does, not like a strict library ──────
READ_ERRORS = (RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, zlib.error, OSError, ValueError)


def entry_bytes(z, info, n):
    """First n bytes of a part. Offset and compressed size come from the central directory and
    the deflate stream is inflated to its end: a CRC, local name or declared size that disagrees
    does not hide a part from Office, so it does not hide it from here."""
    if info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        fp = z.fp
        fp.seek(info.header_offset)
        h = fp.read(30)
        if len(h) == 30 and h[:4] == b"PK\x03\x04":
            nl, el = struct.unpack_from("<HH", h, 26)
            fp.seek(info.header_offset + 30 + nl + el)
            avail = info.compress_size
            if info.compress_type == zipfile.ZIP_STORED:
                return fp.read(min(n, avail))
            d = zlib.decompressobj(-15)
            out = bytearray()
            while len(out) < n and avail > 0 and not d.eof:
                chunk = fp.read(min(65536, avail))
                if not chunk:
                    break
                avail -= len(chunk)
                try:
                    out += d.decompress(chunk, n - len(out))
                except zlib.error:
                    if out:
                        break
                    raise
            return bytes(out[:n])
    with z.open(info) as fh:
        return fh.read(n)


def iter_bytes(z, info, chunk=CHUNK):
    """The part as a sequence of byte chunks, read the way entry_bytes reads it, without ever
    holding more than one chunk: a worksheet can be a hundred megabytes of XML."""
    if info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        fp = z.fp
        fp.seek(info.header_offset)
        h = fp.read(30)
        if len(h) == 30 and h[:4] == b"PK\x03\x04":
            nl, el = struct.unpack_from("<HH", h, 26)
            fp.seek(info.header_offset + 30 + nl + el)
            avail = info.compress_size
            if info.compress_type == zipfile.ZIP_STORED:
                while avail > 0:
                    b = fp.read(min(chunk, avail))
                    if not b:
                        return
                    avail -= len(b)
                    yield b
                return
            d = zlib.decompressobj(-15)
            while avail > 0 and not d.eof:
                raw = fp.read(min(65536, avail))
                if not raw:
                    return
                avail -= len(raw)
                try:
                    out = d.decompress(raw)
                except zlib.error:
                    return
                while d.unconsumed_tail:
                    yield out
                    out = d.decompress(d.unconsumed_tail)
                if out:
                    yield out
            return
    with z.open(info) as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                return
            yield b


def xml_codec(head):
    """The codec an XML part is written in: a byte-order mark, the shape of an unmarked UTF-16/32 '<',
    or the declaration. Office reads UTF-16 parts; a decoder that assumes UTF-8 sees mojibake."""
    if head[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return "utf-32"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if head[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    if head[:4] == b"<\x00\x00\x00":
        return "utf-32-le"
    if head[:4] == b"\x00\x00\x00<":
        return "utf-32-be"
    if head[:2] == b"<\x00":
        return "utf-16-le"
    if head[:2] == b"\x00<":
        return "utf-16-be"
    m = re.match(rb"\s*<\?xml[^>]{0,200}encoding\s*=\s*[\"']([A-Za-z0-9._-]{1,30})", head)
    if m:
        name = m.group(1).decode("ascii", "replace")
        try:
            canon = codecs.lookup(name).name
        except LookupError:
            return "utf-8"
        return "utf-8" if canon.startswith(("utf-16", "utf-32", "utf_16", "utf_32")) else name
    return "utf-8"


def decode_xml(data):
    return data.decode(xml_codec(data[:512]), "replace")


XML_OPEN = (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"))


def xml_normalise(text):
    """What a parser would hand over: comments and processing instructions gone, CDATA turned into
    character data. A field instruction written as `DD<!-- x -->EAUTO` or as CDATA is the same text
    to Word. Every search moves forward only, so the work is linear however many constructs there are."""
    if not any(o in text for o, _ in XML_OPEN):
        return text
    n = len(text)
    nxt = []
    for o, _ in XML_OPEN:
        x = text.find(o)
        nxt.append(x if x != -1 else n + 1)
    out, pos = [], 0
    while True:
        i = nxt.index(min(nxt))
        s = nxt[i]
        if s > n:
            break
        out.append(text[pos:s])
        opener, closer = XML_OPEN[i]
        e = text.find(closer, s + len(opener))
        if i == 1:
            out.append(html.escape(text[s + len(opener):n if e == -1 else e], quote=False))
        pos = n if e == -1 else e + len(closer)
        for k, (o, _) in enumerate(XML_OPEN):
            if nxt[k] < pos:
                x = text.find(o, pos)
                nxt[k] = x if x != -1 else n + 1
    out.append(text[pos:])
    return "".join(out)


def xml_unterminated(buf):
    """Index where a comment, CDATA section or processing instruction that is still open at the end of
    `buf` begins (len(buf) if none): a slice must not end inside one."""
    cut = len(buf)
    for opener, closer in XML_OPEN:
        i = buf.rfind(opener)
        if i != -1 and buf.find(closer, i) == -1:
            cut = min(cut, i)
    return cut


def iter_text(z, info, name, cap_total):
    """Decoded, normalised text chunks of an XML part, each ending after a closing tag so that no
    field instruction or formula is split between two of them. Stops after cap_total bytes."""
    dec, buf, total = None, "", 0
    for b in iter_bytes(z, info):
        if dec is None:
            dec = codecs.getincrementaldecoder(xml_codec(b[:512]))(errors="replace")
        total += len(b)
        buf += dec.decode(b)
        if len(buf) >= CHUNK:
            k = xml_unterminated(buf)
            work, held = xml_normalise(buf[:k]), buf[k:]
            i = work.rfind("</")
            j = work.find(">", i) + 1 if i != -1 else 0
            if j <= 0:
                j = work.rfind(">") + 1
            if j > 0 and len(work) < 3 * CHUNK:
                yield work[:j]
                buf = work[j:] + held
            elif j > 0 or len(work) >= 3 * CHUNK:
                yield work          # no tag boundary in three slices: stop looking for a clean cut
                buf = held
            else:
                buf = work + held
        if total >= cap_total:
            emit("incomplete", "%s was read only in part (read budget)" % name)
            break
    if dec is None:
        return
    buf += dec.decode(b"", final=True)
    buf = xml_normalise(buf)
    if buf:
        yield buf


# ═════════════════════════════════════════════════════════════════════════════
# OLE2 compound files
# ═════════════════════════════════════════════════════════════════════════════
class CFB:
    """A bounded reader for [MS-CFB]: enough to list storages and streams and read them."""

    def __init__(self, data):
        if len(data) < 512 or data[:8] != CFB_MAGIC:
            raise ValueError("not a compound file")
        self.d = data
        major = struct.unpack_from("<H", data, 26)[0]
        self.ssize = 1 << struct.unpack_from("<H", data, 30)[0]
        self.msize = 1 << struct.unpack_from("<H", data, 32)[0]
        if major not in (3, 4) or self.ssize not in (512, 4096) or self.msize != 64:
            raise ValueError("unsupported compound file")
        self.nsec = max(0, (len(data) - self.ssize) // self.ssize)
        n_fat, dir_start, _, cutoff, mf_start, n_mf, df_start, n_df = struct.unpack_from("<IIIIIIII", data, 44)
        self.cutoff = cutoff
        difat = list(struct.unpack_from("<109I", data, 76))
        s, seen = df_start, set()
        for _ in range(min(n_df, 4096)):
            if s >= self.nsec or s in seen:
                break
            seen.add(s)
            blk = struct.unpack_from("<%dI" % (self.ssize // 4), data, self._off(s))
            difat += list(blk[:-1])
            s = blk[-1]
        self.fat = []
        for fs in difat[:max(n_fat, 0)]:
            if fs < self.nsec:
                self.fat += struct.unpack_from("<%dI" % (self.ssize // 4), data, self._off(fs))
        self.minifat = []
        for s in self._chain(mf_start, n_mf + 1):
            self.minifat += struct.unpack_from("<%dI" % (self.ssize // 4), data, self._off(s))
        dirbytes = b"".join(self._sector(s) for s in self._chain(dir_start, 100000))
        self.entries = []
        for i in range(0, min(len(dirbytes), 128 * 100000) - 127, 128):
            e = dirbytes[i:i + 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            kind = e[66]
            if kind == 0:
                self.entries.append(None)
                continue
            name = e[:max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            left, right, child = struct.unpack_from("<III", e, 68)
            start, size = struct.unpack_from("<IQ", e, 116)
            self.entries.append(dict(name=name, kind=kind, left=left, right=right, child=child,
                                     clsid=e[80:96], start=start, size=size & 0xFFFFFFFF if major == 3 else size))
        if not self.entries or self.entries[0] is None or self.entries[0]["kind"] != 5:
            raise ValueError("no root entry")
        self.paths = {}
        self.too_deep = False
        self._walk(0, ())
        self.children = {}
        for pth, ent in self.paths.items():
            self.children.setdefault(pth[:-1], {})[pth[-1]] = ent
        self._mini = None

    def _off(self, s):
        return (s + 1) * self.ssize

    def _sector(self, s):
        o = self._off(s)
        return self.d[o:o + self.ssize]

    def _chain(self, start, limit):
        out, seen, s = [], set(), start
        while s < self.nsec and s not in seen and len(out) < limit and s < len(self.fat) + 1:
            out.append(s)
            seen.add(s)
            s = self.fat[s] if s < len(self.fat) else 0xFFFFFFFE
        return out

    def _walk(self, idx, parent):
        """Children of storage `idx`, as a binary tree of siblings; every entry gets a path."""
        stack = [(self.entries[idx]["child"], parent)]
        seen = set()
        while stack and len(seen) < 100000:
            i, par = stack.pop()
            if i >= len(self.entries) or self.entries[i] is None or i in seen:
                continue
            seen.add(i)
            e = self.entries[i]
            p = par + (e["name"],)
            if len(p) > 64:   # real documents are a handful deep; paths are tuples, so depth costs quadratic memory
                self.too_deep = True
                continue
            self.paths[p] = e
            stack.append((e["left"], par))
            stack.append((e["right"], par))
            if e["kind"] == 1:
                stack.append((e["child"], p))

    def read(self, e, limit=PART_CAP):
        if state["budget"] <= 0:
            emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
            return b""
        data = self._read(e, limit)
        state["budget"] -= len(data)
        return data

    def _read(self, e, limit):
        size = min(e["size"], limit)
        if e["kind"] == 5:
            return b"".join(self._sector(s) for s in self._chain(e["start"], 1 + size // self.ssize))[:size]
        if e["size"] < self.cutoff:
            if self._mini is None:
                r = self.entries[0]
                self._mini = b"".join(self._sector(s) for s in self._chain(r["start"], 1 + r["size"] // self.ssize))[:r["size"]]
            out = bytearray()
            s, seen = e["start"], set()
            while s < len(self.minifat) and s not in seen and len(out) < size:
                seen.add(s)
                out += self._mini[s * 64:(s + 1) * 64]
                s = self.minifat[s]
            return bytes(out[:size])
        return b"".join(self._sector(s) for s in self._chain(e["start"], 1 + size // self.ssize))[:size]

    def streams(self):
        return [(p, e) for p, e in self.paths.items() if e["kind"] == 2]


# ═════════════════════════════════════════════════════════════════════════════
# VBA: MS-OVBA decompression and the project's module list
# ═════════════════════════════════════════════════════════════════════════════
def ovba_decompress(data, start=0):
    if start >= len(data) or data[start] != 1:
        raise ValueError("no compressed container")
    pos, out = start + 1, bytearray()
    while pos + 2 <= len(data) and len(out) < 8 * 1048576:
        header = struct.unpack_from("<H", data, pos)[0]
        if (header >> 12) & 7 != 3:
            break
        end = min(pos + (header & 0xFFF) + 3, len(data))
        pos += 2
        if not (header >> 15) & 1:
            out += data[pos:min(pos + 4096, end)]
            pos = end
            continue
        base = len(out)
        while pos < end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                token = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                diff = len(out) - base
                bits = max((diff - 1).bit_length() if diff > 1 else 0, 4)
                length = (token & (0xFFFF >> bits)) + 3
                offset = (token >> (16 - bits)) + 1
                if offset > len(out):
                    raise ValueError("bad copy token")
                for _ in range(length):
                    out.append(out[-offset])
    return bytes(out)


def vba_modules(dirdata):
    """(stream name, text offset) of each module in a decompressed `dir` stream."""
    mods, pos, cur = [], 0, {}
    while pos + 6 <= len(dirdata):
        rid, size = struct.unpack_from("<HI", dirdata, pos)
        pos += 6
        if rid == 0x09:  # PROJECTVERSION: the size field says 4 and six bytes follow
            pos += 6
            continue
        body = dirdata[pos:pos + size]
        pos += size
        if rid == 0x1A:
            cur["stream"] = body.decode("cp1252", "replace")
        elif rid == 0x31 and len(body) >= 4:
            cur["offset"] = struct.unpack_from("<I", body)[0]
        elif rid == 0x2B:
            if "stream" in cur:
                mods.append((cur["stream"], cur.get("offset", 0)))
            cur = {}
        elif rid == 0x10:
            break
    return mods


# Blanks are [ \t], never \s: with re.M, ^\s* at every line start swallows the following blank lines,
# so N empty lines cost N*N/2 steps (a 2 KB document took longer than the time budget).
AUTO_PROC = re.compile(
    r"(?im)^[ \t]*(?:(?:Public|Private|Friend|Static)[ \t]+)*(?:Sub|Function)[ \t]+(AutoOpen|Auto_Open|AutoExec|AutoNew|AutoClose|Auto_Close|"
    r"Document_Open|Document_New|Document_Close|DocumentOpen|DocumentBeforeClose|Workbook_Open|Workbook_Activate|"
    r"Workbook_BeforeClose|Workbook_Close|Auto_Activate|Auto_Deactivate|PresentationOpen)\b")
# Calls that start a program or fetch from the network. CreateObject alone is not on the list:
# Scripting.Dictionary is the commonest use of it there is.
VBA_DANGER = re.compile(
    r"(?i)\b(Shell\b\s*\(?|ShellExecute\w*|WinExec|CreateProcess\w*|URLDownloadToFile\w*|URLDownloadToCacheFile\w*|"
    r"InternetOpenUrl\w*|DownloadFile|DownloadString|Net\.WebClient|ExecuteExcel4Macro|"
    r"CreateObject\s*\(\s*\"(?:WScript\.Shell|Shell\.Application|MSXML2\.(?:Server)?XMLHTTP[\w.]*|Microsoft\.XMLHTTP|"
    r"WinHttp\.WinHttpRequest[\w.]*|ADODB\.Stream|MSScriptControl\.ScriptControl)\"|GetObject\s*\(\s*\"script:|"
    r"GetObject\s*\(\s*\"winmgmts|powershell|mshta|regsvr32|rundll32|certutil|bitsadmin|cscript\.exe|wscript\.exe|"
    r"cmd(?:\.exe)?\s*/[ck])")
# Functions that allocate or run memory: the core of a shellcode loader. RtlMoveMemory alone is
# CopyMemory, which ordinary code declares, so it is not on the list.
LOADER_API = re.compile(r"(?i)\b(VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|CreateThread|CreateRemoteThread|WriteProcessMemory|"
                        r"QueueUserAPC|NtAllocateVirtualMemory|NtCreateThreadEx|RtlCreateUserThread|EnumSystemLocales[AW]|HeapCreate)\b")
SYSTEM_DLL = re.compile(r'(?i)"(?:kernel32|kernelbase|ntdll)(?:\.dll)?"')


def loader_declarations(text):
    """Names of memory-allocating or thread-starting functions declared from kernel32 or ntdll. One
    declaration is one statement: it can run over several lines (' _' continues it), and the API's
    name comes before Lib or after it (Alias), so the whole statement is searched, once."""
    found, stmt = [], []
    for ln in text.split("\n"):
        s = ln.rstrip()
        stmt.append(s)
        if s.endswith("_"):
            continue
        whole_stmt = " ".join(stmt)
        stmt = []
        if "lib" in whole_stmt.lower() and SYSTEM_DLL.search(whole_stmt):
            found += [m.group(1) for m in LOADER_API.finditer(whole_stmt)]
    if stmt:
        whole_stmt = " ".join(stmt)
        if "lib" in whole_stmt.lower() and SYSTEM_DLL.search(whole_stmt):
            found += [m.group(1) for m in LOADER_API.finditer(whole_stmt)]
    return sorted(set(found))


def analyze_vba(cf, label):
    """Every module's source out of a VBA project; returns True when a project was present."""
    vba = [(p, e) for p, e in cf.streams() if len(p) >= 2 and p[-2].upper() == "VBA"]
    if not vba:
        return False
    sources = {}
    byname = {p[-1]: (p, e) for p, e in vba}
    try:
        dirent = byname["dir"][1]
        for stream, offset in vba_modules(ovba_decompress(cf.read(dirent), 0)):
            if stream in byname:
                data = cf.read(byname[stream][1])
                try:
                    sources[stream] = ovba_decompress(data, offset)
                except ValueError:
                    pass
    except Exception:
        pass
    # Not every module is listed where the dir stream says, and a corrupt dir stream is no
    # reason to stop: look for the compressed container's first bytes in each stream, as olevba does.
    for p, e in vba:
        nm = p[-1]
        if nm in sources or nm in ("dir", "_VBA_PROJECT") or nm.startswith("__SRP"):
            continue
        data = cf.read(e)
        m = re.search(b"\x00Attribut[^e]", data)
        if m and m.start() >= 3:
            try:
                sources[nm] = ovba_decompress(data, m.start() - 3)
            except ValueError:
                pass
    if not sources:
        emit("vba_unreadable", label)
        emit("vba_macro", label + " (source could not be read)")
        return True
    names = sorted(sources)
    emit("vba_macro", label + " " + ", ".join(names))
    seen_src, total = set(), 0
    for nm in names:
        raw = sources[nm]
        key = (len(raw), zlib.crc32(raw))
        if key in seen_src:
            continue   # many directory entries can point at one chain; its text is read once
        seen_src.add(key)
        total += len(raw)
        if total > 32 * 1048576 or out_of_time():
            emit("incomplete", "VBA source past 32 MB or past the time budget was not read")
            break
        text = sources[nm].decode("cp1252", "replace").replace("\r\n", "\n").replace("\r", "\n")
        auto = sorted({m.group(1) for m in AUTO_PROC.finditer(text)})
        danger = sorted({re.sub(r"\s+", " ", m.group(1))[:24] for m in VBA_DANGER.finditer(text)}
                        | {"Lib kernel32 " + a for a in loader_declarations(text)})
        if danger:
            emit("vba_dangerous", "%s%s: %suses %s" % (label + " " if label else "", nm,
                                                       ("auto-runs " + ", ".join(auto) + "; ") if auto else "", ", ".join(danger[:5])))
        elif auto:
            emit("vba_autoexec", "%s: %s" % (nm, ", ".join(auto)))
        hostile(label + nm, text)
        to_view(label + nm, text)
    return True


# ═════════════════════════════════════════════════════════════════════════════
# Embedded objects, wherever they are found
# ═════════════════════════════════════════════════════════════════════════════
def parse_package(data):
    """(file name, payload) of an OLE Package, or None. Layout of \\x01Ole10Native."""
    try:
        pos = 4 + 2  # total size, flags
        end = data.index(b"\x00", pos)
        name = data[pos:end].decode("latin-1")
        pos = data.index(b"\x00", end + 1) + 1       # source path
        pos += 4
        tlen = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + tlen                               # temp path
        dlen = struct.unpack_from("<I", data, pos)[0]
        return name, data[pos + 4:pos + 4 + min(dlen, 8 * 1048576)]
    except (ValueError, struct.error):
        return None


def package_findings(label, name, payload):
    base = os.path.basename(name.replace("\\", "/"))
    kind = native_kind(payload[:65536])
    if EXEC_EXT.search(base) or kind or payload[:2] == b"#!":
        emit("embedded_executable", "%s %s%s" % (label, base, " (%s)" % kind if kind else ""))
    else:
        emit("embedded_object", "%s package %s" % (label, base))


EQ_PAYLOAD = re.compile(rb"(?i)(\b" + SHELLS.encode() + rb"(?:\.exe)?\b\s*/[ck]|\b" + SHELLS.encode() +
                        rb"\.exe\b|https?://|\.(?:exe|bat|vbs|js|hta|ps1)\b|powershell)")


def equation_findings(label, payload):
    # CVE-2017-11882 and its relatives overflow a stack buffer in the Equation Editor's font record,
    # and the shellcode that follows usually names a command or a URL. Old scientific documents
    # carry equations legitimately, so the object alone is only reported.
    if EQ_PAYLOAD.search(payload.replace(b"\x00", b"")):
        emit("equation_exploit", label)
    else:
        emit("equation_object", label)


def blob(label, name, data, depth, in_doc=True):
    """Classify and analyse something embedded in a document."""
    head = data[:HEAD]
    kind = native_kind(head)
    base = os.path.basename(name.replace("\\", "/"))
    if kind or EXEC_EXT.search(base) or head[:2] == b"#!":
        emit("embedded_executable", "%s%s%s" % (label, base, " (%s)" % kind if kind else ""))
        return
    before, known = n_facts(), False
    if head[:8] == CFB_MAGIC:
        known = analyze_cfb(data, label + base + "!", depth + 1)
    elif head[:2] == b"PK":
        known = analyze_zip_bytes(data, label + base + "!", depth + 1)
    elif head[:5] == b"{\\rtf" or b"{\\rt" in head[:1024]:
        analyze_rtf(data, label + base + "!", depth + 1)
        known = True
    # An embedded workbook or chart analyses clean and is ordinary; an object nobody here can
    # read (a stream called CONTENTS, an unknown ZIP) is what is reported.
    if n_facts() == before and not known:
        emit("embedded_object", label + base)


# Text in a macro sheet that makes it run something: an auto-run name (a defined name Excel calls on
# open, close, activate), a call that starts or loads a program, or a command line.
XLM_RUNS = re.compile(rb"(?i)Auto_(?:Open|Close|Activate|Deactivate)|EXEC\(|REGISTER\(|CALL\(|URLDownloadToFile|\b"
                      + SHELLS.encode() + rb"(?:\.exe)?\s*/[ck]")

KNOWN_OFFICE_STREAMS = {"WordDocument", "Workbook", "Book", "PowerPoint Document", "EncryptedPackage"}


def analyze_cfb(data, label, depth):
    if depth > MAX_DEPTH:
        emit("incomplete", "objects nested deeper than %d levels were not opened" % (MAX_DEPTH - 1))
        return True
    try:
        cf = CFB(data)
    except Exception:
        emit("unparseable", label or "document")
        return False
    if cf.too_deep:
        emit("incomplete", "storages nested more than 64 deep were not read")
    names = {p[-1] for p, _ in cf.streams()}
    known = bool(names & KNOWN_OFFICE_STREAMS) or any(len(p) >= 2 and p[-2].upper() == "VBA" for p, _ in cf.streams())
    if "EncryptedPackage" in names and "EncryptionInfo" in names:
        emit("encrypted", (label or "document") + " password-protected")
    try:
        analyze_vba(cf, label)
    except Exception:
        emit("vba_unreadable", label or "document")
    # embedded OLE objects: each child of an ObjectPool, an Excel MBD storage, or any Ole10Native stream
    storages = {}
    for p, e in cf.paths.items():
        if e["kind"] == 1 and (p[0] == "ObjectPool" and len(p) == 2 or p[0].startswith("MBD") and len(p) == 1):
            storages[p] = e
    for p, e in cf.streams():
        if p[-1] == "\x01Ole10Native":
            pk = parse_package(cf.read(e))
            if pk:
                package_findings(label, *pk)
            else:
                emit("embedded_object", label + "/".join(p))
        elif p[-1] == "Equation Native":
            equation_findings(label + "/".join(p[:-1]), cf.read(e))
        elif p[-1] == "\x01Ole":
            # the link information of a linked (not embedded) object: a URL moniker names its target
            ole = cf.read(e, 1048576)
            if URL_MONIKER in ole and remote_url(ole):
                emit("remote_object", label + "/".join(p[:-1]) + " links to a remote URL")
        elif p[-1] in ("Package", "package_stream"):
            # an Office 2007+ (or LibreOffice) document wrapped in an OLE object: open the package
            known = True
            blob(label, "/".join(p), cf.read(e, EMBED_CAP), depth)
    eq_clsid = bytes.fromhex("02CE020000000000C000000000000046")
    for k, (p, e) in enumerate(storages.items()):
        if k >= 5000 or out_of_time():
            emit("incomplete", "more than 5000 embedded objects, the rest were not read")
            break
        kids = cf.children.get(p, {})
        if "\x01Ole10Native" in kids or "Equation Native" in kids:
            continue  # reported above
        def kid_bytes():
            return b"".join(cf.read(ee, 262144) for ee in kids.values() if ee["kind"] == 2)[:1048576]
        if e["clsid"] == eq_clsid:
            equation_findings(label + "/".join(p), kid_bytes())
            continue
        comp = cf.read(kids["\x01CompObj"]) if "\x01CompObj" in kids and kids["\x01CompObj"]["kind"] == 2 else b""
        if b"Equation" in comp:
            equation_findings(label + "/".join(p), kid_bytes())
        elif not set(kids) & KNOWN_OFFICE_STREAMS:
            emit("embedded_object", label + "/".join(p))
    # Excel 4.0 macro sheets: BOUNDSHEET records of type "macro sheet" in the Workbook stream
    for p, e in cf.streams():
        if p[-1] in ("Workbook", "Book") and len(p) == 1:
            wb = cf.read(e)
            pos, sheets, nrec = 0, [], 0
            try:
                while pos + 4 <= len(wb) and len(sheets) < 512 and nrec < 400000:
                    nrec += 1
                    rid, size = struct.unpack_from("<HH", wb, pos)
                    body = wb[pos + 4:pos + 4 + size]
                    if rid == 0x0085 and len(body) >= 8:
                        hidden, dt = body[4], body[5]
                        nm = body[8:8 + body[6]].decode("latin-1", "replace")
                        if dt == 1:
                            sheets.append((nm, hidden & 3))
                    elif rid == 0x01AE and len(body) >= 5:
                        # SUPBOOK: the virtual path of an external workbook, or "application\x03topic" for a DDE link
                        cch, flag = struct.unpack_from("<HB", body, 2)
                        raw_path = body[5:5 + cch * (2 if flag & 1 else 1)]
                        path = raw_path.decode("utf-16-le" if flag & 1 else "latin-1", "replace")
                        if "\x03" in path:
                            service, topic = path.split("\x03", 1)
                            emit(dde_kind(service, topic), "%sSUPBOOK DDE %s" % (label, re.sub(r"[^\x20-\x7e]", "?", path)[:60]))
                        else:
                            classify_target(label + "SUPBOOK ", "externallink", re.sub(r"[\x00-\x1f]", "", path))
                    elif rid == 0x000A and pos > 0:
                        break
                    pos += 4 + size
            except (IndexError, struct.error):
                emit("incomplete", "the Workbook stream ends inside a record")
            runs = XLM_RUNS.search(wb.replace(b"\x00", b""))
            for nm, hid in sheets:
                if hid or runs:
                    emit("xlm_dangerous", "%s%s %s" % (label, nm, "hidden macro sheet" if hid else "macro sheet that runs programs"))
                else:
                    emit("xlm_macro", label + nm)
    # PowerPoint 97-2003 keeps its VBA project and its OLE objects in ExOleObjStg records of the
    # "PowerPoint Document" stream, zlib-compressed: a walk over the record tree finds them.
    for p, e in cf.streams():
        if p[-1] == "PowerPoint Document" and len(p) == 1:
            pd = cf.read(e)
            stack, found = [(0, len(pd))], 0
            while stack and found < 64:
                pos, end = stack.pop()
                while pos + 8 <= end:
                    vi, rtype, rlen = struct.unpack_from("<HHI", pd, pos)
                    body = pos + 8
                    if rlen > end - body:
                        break
                    if vi & 0xF == 0xF:
                        stack.append((body, body + rlen))
                    elif rtype == 0x1011 and rlen > 4:
                        found += 1
                        try:
                            raw = zlib.decompressobj().decompress(pd[body + 4:body + rlen], EMBED_CAP) if (vi >> 4) == 1 else pd[body:body + rlen]
                        except zlib.error:
                            raw = b""
                        if raw:
                            blob(label, "ExOleObjStg%d" % found, raw, depth)
                    pos = body + rlen
    # DDE fields live in the document stream
    for p, e in cf.streams():
        if p[-1] in ("WordDocument", "1Table", "0Table"):
            raw = cf.read(e).replace(b"\x00", b"")
            m = re.search(rb"(?i)DDEAUTO\b|\bDDE\s+\"?(?:[^\s\"]{0,200}[\\/])?(?:" + SHELLS.encode() + rb")\b", raw)
            if not m:
                m2 = re.search(rb"(?i)\bDDE\s+\"[^\"]{1,100}\"\s+\"([^\"]{0,300})\"", raw)
                if m2 and HOSTILE_TOPIC.search(m2.group(1).decode("latin-1")):
                    m = m2
            if m:
                emit("dde", "%s%s: %s" % (label, p[-1], re.sub(rb"[^\x20-\x7e]", b"?", raw[m.start():m.start() + 60]).decode()))
            for t in re.findall(rb"[\x20-\x7e]{8,}", cf.read(e)[:1048576])[:4000]:
                to_view(label + p[-1], t.decode("latin-1"))
    return known


# ═════════════════════════════════════════════════════════════════════════════
# OOXML and OpenDocument: ZIP packages
# ═════════════════════════════════════════════════════════════════════════════
# XML is read with ONE tokenizer. Every regular expression that reached into a tag with [^>]* or
# .*? went quadratic on four megabytes of "<a<a<a…" (a 3 KB document ran for over a minute), and
# "[^>]*" is wrong anyway: '>' is legal inside a quoted attribute value, so an attacker can put one
# before the attribute that matters. A tag here is: a name, then attributes whose values are quoted
# strings, then an optional slash. Matching is deterministic, so it is linear.
# Names are anything XML allows: a prefix can be "é" or "a·b", and a tokenizer that insists on [A-Za-z_]
# or \w never sees the element at all.
_NM = r"[^\s/>=<\"'&]"
TAG = re.compile(r"<(/?(?:[^\W\d]|:)" + _NM + r"*)((?:\s+" + _NM + r"+\s*=\s*(?:\"[^\"]*\"|'[^']*'))*)\s*(/?)>")
ATTR = re.compile(r"(" + _NM + r"+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
URI_HANDLERS = {"ms-msdt", "msdt", "mhtml", "search-ms", "search", "ms-officecmd", "ms-appinstaller", "javascript", "vbscript", "jscript"}
REMOTE_OBJ_TYPES = {"oleobject", "frame", "subdocument", "package", "control", "aschunk", "afchunk", "externaldata"}


def local(name):
    """An element or attribute name without its prefix: a prefix is arbitrary, only the URI it is
    bound to means anything, and a reader that compares the literal text "w:instrText" is blind to
    the same document written with x:."""
    return name.rsplit(":", 1)[-1]


def attrs(raw):
    """{local name in lower case: [every value]}. Two attributes can share a local name under
    different prefixes (Type and x:Type); keeping all of them means the one a reader uses is among
    them, whichever it is."""
    out = {}
    for k, v1, v2 in ATTR.findall(raw):
        lst = out.setdefault(local(k).lower(), [])
        if len(lst) < 8:
            lst.append(html.unescape(v1 or v2))   # TargetMode="Ext&#101;rnal" is External to a parser
    return out


def av(a, name):
    return a.get(name) or [""]


def tag_text(text, end):
    """The character data that follows a tag: up to the next '<', at most 8000 characters."""
    nxt = text.find("<", end, end + 8000)
    return text[end:nxt if nxt != -1 else end + 8000]


ENTITY = re.compile(r"(?is)<!ENTITY\b")
# After the keyword: optional '%', the name, then SYSTEM or PUBLIC. Anchored at the match, so each
# declaration costs its own length (the whitespace runs are disjoint), however many there are.
ENTITY_EXTERNAL = re.compile(r"(?is)\s+(?:%\s+)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\b")


def entity_findings(text):
    """'xxe' for an ENTITY that points at SYSTEM or PUBLIC, 'doctype' for any other declaration.
    Every declaration is examined: one behind four hundred harmless ones is still one."""
    kind = ""
    for m in ENTITY.finditer(text):
        kind = kind or "doctype"
        if ENTITY_EXTERNAL.match(text, m.end()):
            return "xxe"
    if not kind and "<!doctype" in text[:4096].lower():
        kind = "doctype"
    return kind


def is_unc(t):
    """A path on a network share: \\\\host\\x, //host/x, file://host/x, file:////host/x, smb://host/x."""
    t = t.strip()
    return (t.startswith("\\\\") or t.startswith("//") or bool(re.match(r"(?i)^(?:file://[^/]|file:/{4}[^/]|smb://|cifs://)", t))
            or bool(re.match(r"(?i)^file:/{2,}\\\\", t)))


def classify_target(label, kind, tgt, hyperlink=False):
    """One external reference: `kind` is the relationship type (lower case) or the ODF element name."""
    tgt = html.unescape(tgt).strip()
    m = SCHEME.match(tgt)
    scheme = m.group(1).lower() if m and len(m.group(1)) > 1 else ""
    shown = "%s%s -> %s" % (label, kind, tgt[:70])
    if scheme in URI_HANDLERS:
        emit("uri_handler", shown)
        return
    if is_unc(tgt):
        emit("unc_hyperlink" if hyperlink else "unc_path", shown)
        return
    if scheme in ("http", "https", "ftp", "ftps"):
        if hyperlink:
            return
        if kind == "attachedtemplate":
            emit("remote_template", shown)
        elif kind in REMOTE_OBJ_TYPES:
            emit("remote_object", shown)
        else:
            emit("remote_content", shown)


def out_of_time():
    if time.monotonic() > DEADLINE:
        emit("incomplete", "time budget exceeded")
        return True
    return False


def resolve_target(source, target):
    """The part name an internal relationship target points at (OPC: relative to the source part's
    folder, or absolute when it starts with '/')."""
    target = html.unescape(target).strip().replace("\\", "/")
    out = [] if target.startswith("/") else source.split("/")[:-1]
    for seg in target.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
        else:
            out.append(seg)
    return "/".join(out)


def rels_source(name):
    """The part a relationships part belongs to: word/_rels/document.xml.rels -> word/document.xml,
    _rels/.rels -> '' (the package). None when the part is not where Office looks for relationships."""
    comps = name.split("/")
    if len(comps) >= 2 and comps[-2].lower() == "_rels" and comps[-1].lower().endswith(".rels"):
        return "/".join(comps[:-2] + [comps[-1][:-5]])
    return None


def links_to_program(target):
    """A hyperlink whose target is an executable. `.com` is also a TLD: mailto:a@b.com and http://example.com
    are web addresses, so it counts only for a file path."""
    base = target.split("?")[0].strip()
    m = EXEC_EXT.search(base)
    if not m:
        return False
    if m.group(1).lower() == "com":
        sch = SCHEME.match(base)
        return bool(re.search(r"[\\/]", base)) and (not sch or sch.group(1).lower() == "file")
    return True


def analyze_rels(label, text, roles=None, source=None):
    """External relationships are classified; internal ones record what kind of part their target is
    (roles: {target part name in lower case: {relationship types}}), so a part is recognised by what
    points at it and not only by what it is called."""
    for m in TAG.finditer(text):
        if local(m.group(1)) != "Relationship":
            continue
        a = attrs(m.group(2))
        external = any(v.lower() == "external" for v in av(a, "targetmode"))
        for ty in av(a, "type")[:4]:
            kind = html.unescape(ty).rsplit("/", 1)[-1].lower()
            for tgt in av(a, "target")[:4]:
                if external:
                    classify_target(label, kind, tgt, hyperlink=(kind == "hyperlink"))
                    if kind == "hyperlink" and links_to_program(html.unescape(tgt)):
                        emit("link_to_program", "%s%s" % (label, html.unescape(tgt)[:70]))
                elif roles is not None and source is not None:
                    roles.setdefault(resolve_target(source, tgt).lower(), set()).add(kind)


FORMULA_ELEMENT = re.compile(r"<(?:[^\s/<>:]+:)?f[\s>]")
DDE_FIELD = re.compile(r"(?is)^\s*DDE(?:AUTO)?\b")
FETCH_FIELD = re.compile(r"(?is)^\s*(INCLUDETEXT|INCLUDEPICTURE|LINK|IMPORT|HYPERLINK)\b")
FIELD_ARG = re.compile(r'"([^"]{0,2000})"|(\S{1,2000})')
FIELD_SWITCH = re.compile(r"\\[A-Za-z*]")


def field_findings(label, f):
    f = f.strip()
    if DDE_FIELD.match(f):
        emit("dde", "%s%s" % (label, re.sub(r"\s+", " ", f)[:80]))
        return
    m = FETCH_FIELD.match(f)
    if m:
        # Every argument is tried: a switch can come before the file name (INCLUDEPICTURE \\d "..."), and
        # LINK takes a class name first (LINK Excel.Sheet.8 "..."). Word writes a backslash in an
        # argument doubled, so \\\\host\\x is the UNC path \\host\x; an argument written singly is read as
        # it stands. Both spellings are tested.
        for k, am in enumerate(FIELD_ARG.finditer(f, m.end())):
            if k >= 32:
                break
            arg = am.group(1) if am.group(1) is not None else am.group(2)
            if FIELD_SWITCH.match(arg):
                continue
            for v in dict.fromkeys((arg, arg.replace("\\\\", "\\"))):
                classify_target(label, "field", v, hyperlink=(m.group(1).upper() == "HYPERLINK"))


def tag_text(text, end):
    """The character data that follows a tag: up to the next '<', at most 8000 characters."""
    nxt = text.find("<", end, end + 8000)
    return text[end:nxt if nxt != -1 else end + 8000]


def word_fields(label, text, stack):
    """Field instructions, joined across the runs Word splits them into. `stack` carries the
    fields that are still open from one chunk of a large part to the next."""
    for m in TAG.finditer(text):
        name = local(m.group(1))
        if name == "fldChar":
            for t in av(attrs(m.group(2)), "fldchartype"):
                if t == "begin":
                    stack.append([])
                elif t == "end" and stack:
                    field_findings(label, "".join(stack.pop()))
        elif name in ("instrText", "delInstrText") and not m.group(3):
            frag = html.unescape(tag_text(text, m.end()))
            if stack:
                stack[-1].append(frag)
            else:
                field_findings(label, frag)  # an instruction with no begin: Word still reads it
        elif name == "fldSimple":
            for ins in av(attrs(m.group(2)), "instr"):
                field_findings(label, html.unescape(ins))


# A DDE formula is service|topic!item. The service is any name: =MSEXCEL|'..\\..\\cmd.exe /c calc'!A0 starts
# a shell through the service that is always installed, so the topic is read as well.
DDE_ANY = re.compile(r"(?i)^\s*[=+@-]?\s*([A-Za-z0-9_.-]{1,40})\s*\|\s*'?([^'!]*)")
HOSTILE_TOPIC = re.compile(r"(?i)\b" + SHELLS + r"(?:\.exe)?\b|\.(?:exe|bat|cmd|com|ps1|vbs|js|hta|scr|dll)\b|\s/[ck]\s|\\system32\\")


def dde_kind(service, topic):
    """'dde' (blocks) when the service is a shell or the topic names a program or command line, else 'dde_declared'."""
    s = html.unescape(service).strip().strip("'\"")
    if re.match(r"(?i)^" + SHELLS + r"(\.exe)?$", s) or HOSTILE_TOPIC.search(html.unescape(topic or "")):
        return "dde"
    return "dde_declared"


def dde_formula(f):
    m = DDE_ANY.match(f)
    return dde_kind(m.group(1), m.group(2)) if m else None
XLM_CALL = re.compile(r"(?i)\b(EXEC|CALL|REGISTER|FOPEN|FWRITE|URLDownloadToFile\w*|RUN)\s*\(")


def xml_rules(label, name, text, stack, macrosheet=False):
    """Every rule that reads XML, applied to one normalised slice of a part. Which rules apply is
    decided by what the slice contains, not by what the part is called: a main part can be moved
    anywhere an OPC relationship says, and a prefix is arbitrary. Each gate is a plain substring
    test, so a slice with nothing to find costs a handful of scans."""
    shown = label + name
    if "instrText" in text or "fldChar" in text or "fldSimple" in text or "delInstrText" in text:
        word_fields(shown + " ", text, stack)
    if "ddeLink" in text:
        for m in TAG.finditer(text):
            if local(m.group(1)) == "ddeLink":
                a = attrs(m.group(2))
                for svc in av(a, "ddeservice"):
                    emit(dde_kind(svc, " ".join(av(a, "ddetopic"))), "%s service %s" % (shown, html.unescape(svc)))
    # The gate is the existence of an <f> element or a Formula attribute, not a character in its text: the
    # pipe of a DDE formula can be written &#124;, and the raw text then never contains one.
    if macrosheet or "ormula" in text or FORMULA_ELEMENT.search(text):
        for m in TAG.finditer(text):
            nm = local(m.group(1))
            if nm == "f" and not m.group(3):
                f = html.unescape(tag_text(text, m.end()))
                kind = dde_formula(f)
                if kind:
                    emit(kind, "%s %s" % (shown, f.strip()[:60]))
                elif macrosheet and XLM_CALL.search(f):
                    emit("xlm_dangerous", "%s %s" % (shown, f.strip()[:60]))
            else:
                for fv in attrs(m.group(2)).get("formula", ()):   # Excel 2003 XML: ss:Formula="=cmd|'/c calc'!A0"
                    kind = dde_formula(fv)
                    if kind:
                        emit(kind, "%s %s" % (shown, fv.strip()[:60]))
    if "action" in text:   # the attribute name is literal; its value ("ppaction:&#47;/program") may not be
        for m in TAG.finditer(text):
            for act in av(attrs(m.group(2)), "action"):
                act = html.unescape(act).lower()
                if act.startswith("ppaction://program"):
                    emit("ppt_program_action", shown)
                elif act.startswith("ppaction://macro"):
                    emit("ppt_macro_action", "%s %s" % (shown, act[:50]))
    if "webPr" in text:
        for m in TAG.finditer(text):
            if local(m.group(1)) == "webPr":
                for u in av(attrs(m.group(2)), "url"):
                    classify_target(shown + " ", "webquery", u)
    if "state" in text and "sheet" in text:
        for m in TAG.finditer(text):
            if local(m.group(1)) == "sheet" and any(v.lower() in ("hidden", "veryhidden") for v in av(attrs(m.group(2)), "state")):
                state["wb_hidden"] = True
    to_view(shown, text_of(text))


def scan_xml_part(label, name, chunks, macrosheet=False):
    stack = []
    first = True
    for text in chunks:
        if not first and out_of_time():
            break
        if first or "<!ENTITY" in text:
            ef = entity_findings(text)
            if ef:
                emit(ef, label + name)
        first = False
        xml_rules(label, name, text, stack, macrosheet)
    for f in ("".join(x) for x in stack):
        field_findings(label + name + " ", f)


PARA_END = re.compile(r"</(?:[^\s/<>:]+:)?(?:p|h|row|si)>|<(?:[^\s/<>:]+:)?(?:br|line-break)\b[^<>]{0,200}/>")
STRIP_TAGS = re.compile(r"<[^<>]{0,4000}>")


def text_of(xml):
    """Visible text. A paragraph or row ends a line: a PEM key pasted into a document has one
    paragraph per line, and the key rule works on lines."""
    return html.unescape(STRIP_TAGS.sub(" ", PARA_END.sub("\n", xml)))


# ── OpenDocument ─────────────────────────────────────────────────────────────
AUTO_EVENTS = {"office:load", "office:new", "office:create", "office:view-created", "office:activate", "dom:load", "dom:domcontentloaded",
               "dom:domfocusin", "office:layout-finished", "office:page-count-change"}
ODF_DDE_CALL = re.compile(r'(?i)\bDDE\s*\(\s*"([^"]*)"\s*;\s*"([^"]*)"')
ODF_DANGER = re.compile(
    r"(?i)(\bShell\s*\(|SystemShellExecute|os\.system|subprocess|\bsocket\b|urllib|requests\.|__import__|\bctypes\b|\bpty\b|"
    r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|powershell|\bcurl\b|\bwget\b|DownloadFile|\bcmd(?:\.exe)?\s*/[ck]|\bmshta\b)")


def analyze_odf_text(label, name, text, macros_embedded):
    for m in TAG.finditer(text):
        tag, a = local(m.group(1)), attrs(m.group(2))
        if tag == "event-listener":
            targets = [html.unescape(v) for v in a.get("macro-name", []) + a.get("href", [])]
            target = next((v for v in targets if v), "")
            installed = (target.startswith(("application:", "user:")) or "location=application" in target
                         or "location=user" in target)
            if installed:
                continue  # bound to a macro the application ships, not one the document carries
            for event in [v.lower() for v in av(a, "event-name")]:
                if event in AUTO_EVENTS:
                    emit("odf_auto_macro", "%s%s %s -> %s" % (label, name, event, target[:60]))
                elif target:
                    emit("odf_macro", "%s%s %s -> %s" % (label, name, event, target[:60]))
            continue
        for v in a.get("dde-application", []):
            app = html.unescape(v).strip()
            emit(dde_kind(app, " ".join(a.get("dde-topic", []))), "%s%s application %s" % (label, name, app))
        for href in [html.unescape(v).strip() for v in a.get("href", [])]:
            if not href or href.startswith("#") or not (SCHEME.match(href) or is_unc(href)):
                continue
            hyper = tag == "a"
            sch = (SCHEME.match(href).group(1).lower() if SCHEME.match(href) else "")
            if sch in ("vnd.sun.star.script", "macro"):
                if "location=application" not in href:
                    emit("odf_macro", "%s%s link %s" % (label, name, href[:60]))
            elif sch in URI_HANDLERS:
                emit("uri_handler", "%s%s %s -> %s" % (label, name, tag, href[:60]))
            elif is_unc(href):
                emit("unc_hyperlink" if hyper else "unc_path", "%s%s %s -> %s" % (label, name, tag, href[:60]))
            elif sch in ("http", "https", "ftp", "ftps", "file") and not hyper:
                emit("odf_external", "%s%s %s -> %s" % (label, name, tag, href[:60]))
    if "DDE" in text.upper():
        for m in ODF_DDE_CALL.finditer(html.unescape(text)):   # &quot; and &#34; are both a quote
            emit(dde_kind(m.group(1), m.group(2)), "%s%s DDE(%s)" % (label, name, m.group(1)))


SCRIPT_LIB = re.compile(r"(?i)(script|dialog)-l[cb]\.xml$")
ODF_READ = re.compile(r"(?i)^(content\.xml|styles\.xml|META-INF/manifest\.xml|object[^/]*/(content|styles)\.xml)$")
ODF_SCRIPT = re.compile(r"(?i)^(Basic|Scripts)/.+\.(xml|py|js|bsh|java|rb|pl|sh)$")


ODF_ENTITY_ONLY = re.compile(r"(?i)^(meta\.xml|settings\.xml)$")


def analyze_odf_zip(z, infos, label, depth):
    """Macros, event bindings, DDE and external links. meta.xml and settings.xml are not searched
    for links: meta:template points at the file the document was made from, and every document
    made from a template carries it. They are searched for an external entity like every other part."""
    macros = {i.filename for i in infos if ODF_SCRIPT.match(i.filename) and not SCRIPT_LIB.search(i.filename)}

    def one(info):
        n = info.filename
        data = entry_bytes(z, info, PART_CAP)
        state["budget"] -= len(data)
        is_xml = n.lower().endswith(".xml")
        text = xml_normalise(decode_xml(data)) if is_xml else data.decode("utf-8", "replace")
        if n == "META-INF/manifest.xml":
            ef = entity_findings(text)
            if ef:
                emit(ef, label + n)
            if "encryption-data" in text:
                emit("encrypted", label + "manifest declares encrypted parts")
            return
        if n in macros:
            src = html.unescape(re.sub(r"<[^<>]*>", "", text)) if is_xml else text
            danger = sorted({re.sub(r"\s+", " ", m.group(1))[:24] for m in ODF_DANGER.finditer(src)})
            emit("odf_macro", label + n)
            if danger:
                emit("odf_dangerous", "%s%s uses %s" % (label, n, ", ".join(danger[:5])))
            hostile(label + n, src)
            to_view(label + n, src)
            return
        ef = entity_findings(text)
        if ef:
            emit(ef, label + n)
        if ODF_ENTITY_ONLY.match(n):
            return
        analyze_odf_text(label, n, text, bool(macros))
        if n.lower().endswith("content.xml"):
            to_view(label + n, text_of(text))

    for info in infos:
        n = info.filename
        if info.is_dir() or state["budget"] <= 0 or not (ODF_READ.match(n) or n in macros or ODF_ENTITY_ONLY.match(n)):
            continue
        if out_of_time():
            break
        try:
            one(info)
        except Exception:
            emit("unreadable", label + n)   # one part nobody can read does not stop the others


def analyze_zip_bytes(data, label, depth):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        emit("unparseable", label or "document")
        return False
    return analyze_zip(z, label, depth)


FULL_READ = (".rels", ".xml", ".rtf", ".mht", ".htm", ".html", ".bin", ".js", ".vbs", ".hta")
XML_TYPES = ("application/xml", "text/xml")


class Package:
    """What the package says about its own parts: [Content_Types].xml and every relationship, so a
    part is recognised by what it is declared to be and by what points at it, not by its name."""

    def __init__(self, z, infos):
        self.defaults, self.overrides, self.roles = {}, {}, {}
        ct = next((i for i in infos if i.filename.lower() == "[content_types].xml"), None)
        if ct is not None:
            text = xml_normalise(decode_xml(entry_bytes(z, ct, 4 * 1048576)))
            for m in TAG.finditer(text):
                nm, a = local(m.group(1)).lower(), attrs(m.group(2))
                cts = [v.lower() for v in av(a, "contenttype")]
                if nm == "default":
                    for e in av(a, "extension"):
                        self.defaults.setdefault(e.lower(), set()).update(cts)
                elif nm == "override":
                    for pn in av(a, "partname"):
                        self.overrides.setdefault(pn.lower().lstrip("/"), set()).update(cts)

    def finish(self, z, infos, label):
        """Second step, after the content types are known: classify every relationship part."""
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(".rels"):
                continue
            src = rels_source(info.filename)
            if out_of_time():
                break
            if state["budget"] <= 0:
                emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
                break
            try:
                data = entry_bytes(z, info, 4 * 1048576)
                state["budget"] -= len(data)
                if info.file_size > 4 * 1048576:
                    emit("incomplete", "%s is larger than the read limit and was read only in part" % info.filename)
                text = xml_normalise(decode_xml(data))
                ef = entity_findings(text)
                if ef:
                    emit(ef, label + info.filename)
                analyze_rels(label + info.filename + " ", text, self.roles, src)
            except Exception:
                emit("unreadable", label + info.filename)

    def types(self, name):
        low = name.lower()
        return self.overrides.get(low, set()) | self.defaults.get(low.rsplit(".", 1)[-1] if "." in low else "", set())

    def kinds(self, name):
        return self.roles.get(name.lower(), set())

    def is_xml(self, name):
        low = name.lower()
        return low.endswith(".xml") or any(c.endswith("+xml") or c in XML_TYPES for c in self.types(name))

    def is_macrosheet(self, name):
        return (name.lower().startswith("xl/macrosheets/") or any("macrosheet" in c for c in self.types(name))
                or any("macrosheet" in k for k in self.kinds(name)))

    def is_vba(self, name):
        return (name.lower().endswith("vbaproject.bin") or any("vbaproject" in c for c in self.types(name))
                or any("vbaproject" in k for k in self.kinds(name)))

    def is_embedded(self, name):
        return "/embeddings/" in name.lower() or bool(self.kinds(name) & {"oleobject", "package"})

    def is_altchunk(self, name):
        return "afchunk" in name.lower() or "afchunk" in self.kinds(name)

    def is_activex(self, name):
        return "/activex/" in name.lower() or any("activex" in c for c in self.types(name)) or "control" in self.kinds(name)


def analyze_zip(z, label, depth):
    if depth > MAX_DEPTH:
        emit("incomplete", "objects nested deeper than %d levels were not opened" % (MAX_DEPTH - 1))
        return True
    infos = z.infolist()
    names = [i.filename for i in infos]
    for n in names:
        parts = n.replace("\\", "/").split("/")
        if ".." in parts or n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n):
            emit("zip_slip", label + n)
    mt = b""
    for i in infos:
        if i.filename.lower() == "mimetype":   # the spec wants it first; the readers do not insist
            mt = entry_bytes(z, i, 256)
            break
    lows = {n.lower() for n in names}
    has_ct = "[content_types].xml" in lows
    # A package can be both (a stray mimetype entry in a .docx, a stray [Content_Types].xml in an .odt): the
    # applications pick one, so both are read.
    is_odf = mt.startswith(b"application/vnd.oasis.opendocument") or ("content.xml" in lows and "meta-inf/manifest.xml" in lows)
    if not (is_odf or has_ct):
        if depth == 1:
            emit("not_office", "document zip")  # only the file itself can be "not an office document"
        return False
    room = MAX_ENTRIES - state["parts"]
    if len(infos) > room:
        emit("incomplete", "more than %d parts, the rest were not read" % MAX_ENTRIES)
        infos = infos[:max(room, 0)]
    state["parts"] += len(infos)
    if is_odf:
        analyze_odf_zip(z, infos, label, depth)
    pkg = Package(z, infos if has_ct else [])
    if has_ct:
        pkg.finish(z, infos, label)
    macro_seen = False
    state["wb_hidden"] = False
    macrosheets = [n for n in names if has_ct and pkg.is_macrosheet(n)]
    for info in infos:
        if out_of_time():
            break
        try:
            macro_seen = zip_part(z, info, label, depth, is_odf and not has_ct, macro_seen, pkg)
        except Exception:
            emit("unreadable", label + info.filename)
    if macrosheets and "xlm_dangerous" not in facts:
        hid = state.get("wb_hidden")
        emit("xlm_dangerous" if hid else "xlm_macro", label + ("hidden macro sheet " if hid else "") + macrosheets[0])
    if macro_seen and depth == 1 and ext in ("docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx"):
        emit("macro_ext_mismatch", "." + ext)
    return True


def zip_part(z, info, label, depth, is_odf, macro_seen, pkg):
    """One part of an OOXML or OpenDocument package. Returns the updated macro_seen."""
    n, low = info.filename, info.filename.lower()
    if info.is_dir():
        return macro_seen
    embedded = pkg.is_embedded(n) and not is_odf
    std_rels = low.endswith(".rels") and rels_source(n) is not None
    xmlish = not is_odf and pkg.is_xml(n) and not std_rels
    activex = not is_odf and pkg.is_activex(n)
    altchunk = not is_odf and pkg.is_altchunk(n)
    vba = not is_odf and pkg.is_vba(n)
    full = low.endswith(FULL_READ) or embedded or activex or altchunk or xmlish or vba
    if full and state["budget"] <= 0:
        emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
        full = False
    streamed = full and xmlish
    cap = EMBED_CAP if embedded else PART_CAP
    data = entry_bytes(z, info, HEAD if streamed or not full else cap)
    if full and not streamed:
        state["budget"] -= len(data)
        if info.file_size > cap:
            emit("incomplete", "%s is larger than the read limit and was read only in part" % n)
    kind = native_kind(data[:HEAD])
    if kind and not EXEC_EXT.search(n):
        emit("embedded_executable", "%s%s (%s stored under a document name)" % (label, n, kind))
        return macro_seen
    if is_odf:
        if EXEC_EXT.search(n) or low.endswith(".bin"):
            blob(label, n, data, depth)
        return macro_seen
    if std_rels:
        return macro_seen   # classified up front, with the rest of the package's relationships
    if vba:
        macro_seen = True
        analyze_cfb(data, label + n + "!", depth)
    elif activex:
        emit("activex", label + n)
    elif embedded:
        blob(label, n, data, depth)
    elif altchunk:
        emit("altchunk", label + n)
        blob(label, n, data, depth)
    elif EXEC_EXT.search(n):
        emit("embedded_executable", label + n)
    elif streamed:
        before = state["budget"]
        scan_xml_part(label, n, iter_text(z, info, n, state["budget"]), pkg.is_macrosheet(n))
        state["budget"] -= min(info.file_size, before)
    elif data[:8] == CFB_MAGIC:
        blob(label, n, entry_bytes(z, info, EMBED_CAP), depth)   # an OLE file under some other name
    return macro_seen


# ── Flat OPC, Word 2003 XML, Excel 2003 XML ──────────────────────────────────
# Word and Excel open a package written out as ONE XML file (Flat OPC) and the 2003 XML formats
# whatever the extension says; the parts are inline and binary parts are base64.
FLAT_OPC = "schemas.microsoft.com/office/2006/xmlPackage"
XML_2003 = ("schemas.microsoft.com/office/word/2003/wordml", "urn:schemas-microsoft-com:office:spreadsheet",
            "schemas.microsoft.com/office/word/2003/wordml/")


def analyze_flat_xml(text, label, depth):
    """`text` is normalised. Returns True when it was an office document."""
    head = text[:8192]
    odf = "urn:oasis:names:tc:opendocument:xmlns:office:1.0" in head
    opc = FLAT_OPC in head
    if not (odf or opc or any(x in head for x in XML_2003)):
        return False
    ef = entity_findings(text)
    if ef:
        emit(ef, label + "document")
    if odf:
        analyze_odf_text(label, "document", text, False)
        pos = 0
        for _ in range(1000):   # str.find, not a lazy pattern: an opener that never closes would rescan each time
            s = text.find("<script:module", pos)
            gt = text.find(">", s) if s != -1 else -1
            e = text.find("</script:module>", gt) if gt != -1 else -1
            if e == -1:
                break
            emit("odf_macro", "embedded StarBasic module")
            if ODF_DANGER.search(html.unescape(text[gt + 1:e])):
                emit("odf_dangerous", "embedded StarBasic module")
            pos = e + 1
        to_view(label + "document", text_of(text))
        return True
    if not opc:
        scan_xml_part(label, "document", [text], True)
        return True
    starts = [m for m in TAG.finditer(text) if local(m.group(1)) == "part"][:MAX_ENTRIES]
    analyze_rels(label + "package ", text)
    for k, m in enumerate(starts):
        if out_of_time():
            break
        seg = text[m.start():starts[k + 1].start() if k + 1 < len(starts) else len(text)]
        a = attrs(m.group(2))
        pname = av(a, "name")[0]
        ctype = av(a, "contenttype")[0].lower()
        bd = next((b for b in TAG.finditer(seg) if local(b.group(1)) == "binaryData"), None)
        if bd is not None:
            nxt = seg.find("<", bd.end())
            raw = re.sub(r"\s+", "", seg[bd.end():nxt if nxt != -1 else len(seg)])[:EMBED_CAP * 4 // 3 + 8]
            try:
                blob_data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
            except ValueError:
                emit("unreadable", label + pname)
                continue
            if "vbaproject" in ctype or pname.lower().endswith("vbaproject.bin"):
                analyze_cfb(blob_data, label + pname + "!", depth)
                state["flat_macro"] = True
            else:
                blob(label, pname, blob_data, depth)
        else:
            scan_xml_part(label, pname, [seg], "macrosheet" in ctype)
    return True


# ═════════════════════════════════════════════════════════════════════════════
# RTF
# ═════════════════════════════════════════════════════════════════════════════
RTF_SPECIAL = re.compile(r"[{}\\]")
RTF_CTRL = re.compile(r"\\[a-zA-Z]+-?\d* ?|\\'[0-9a-fA-F]{2}|\\.", re.S)
RTF_STEPS = {"left": 4000000}


RTF_BIN = re.compile(r"\\bin(\d{1,9}) ?")
RTF_TOKEN = re.compile(r"\\'([0-9a-fA-F]{2})|\\([\\{}])|\\[a-zA-Z]+-?\d* ?|\\[^a-zA-Z]|[{}]", re.S)


def rtf_plain(g):
    """The text of an RTF fragment as Word reads it: control words (\\additive, \\b0) and groups
    vanish, \\'hh is a character, \\\\ \\{ \\} are themselves."""
    return RTF_TOKEN.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else (m.group(2) or ""), g)


def rtf_group(text, start):
    """(text of the brace group that opens at text[start], whether it closed). Steps are counted
    over all groups: an unterminated group at every object would otherwise cost the whole file each."""
    depth, i = 0, start
    while RTF_STEPS["left"] > 0:
        m = RTF_SPECIAL.search(text, i)
        if not m:
            break
        RTF_STEPS["left"] -= 1
        c, i = m.group(0), m.end()
        if c == "\\":
            mb = RTF_BIN.match(text, i - 1)   # \binN: the next N bytes are data, whatever they are
            i = mb.end() + int(mb.group(1)) if mb else i + 1
        elif c == "{":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return text[start:i], True
    return text[start:], False


def rtf_hex(group, key):
    """Bytes of an \\objdata destination. Word ignores everything that is not a hex digit, and a
    \\binN control word puts N raw bytes into the data (a '}' among them is data, not the end of the group)."""
    m = re.search(r"\\" + key + r"(?![a-z])", group, re.I)
    if not m:
        return b""
    body = group[m.end():]
    out, pending, depth = bytearray(), [], [0]

    def feed(seg):
        seg = re.sub(r"\\'[0-9a-fA-F]{2}|\\[a-zA-Z]+-?\d* ?|\\.", "", seg, flags=re.S)  # control words, escapes
        end, ended = len(seg), False
        for mm in re.finditer(r"[{}]", seg):
            if mm.group(0) == "{":
                depth[0] += 1
            elif depth[0] == 0:
                end, ended = mm.start(), True
                break
            else:
                depth[0] -= 1
        pending.append(re.sub(r"[^0-9a-fA-F]", "", seg[:end]))
        return ended

    def flush():
        h = "".join(pending)
        del pending[:]
        out.extend(bytes.fromhex(h[:len(h) & ~1]))

    pos, ended = 0, False
    for k, mb in enumerate(RTF_BIN.finditer(body)):
        if k >= 10000:
            break
        if mb.start() < pos:
            continue
        if feed(body[pos:mb.start()]):
            ended = True
            break
        flush()
        n = int(mb.group(1))
        out.extend(body[mb.end():mb.end() + n].encode("latin-1", "replace"))
        pos = mb.end() + n
    if not ended:
        feed(body[pos:])
    flush()
    return bytes(out)


URL_MONIKER = bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")   # CLSID_StdURLMoniker, as stored (little-endian GUID)
REMOTE_ASCII = re.compile(rb"(?i)(?:https?|ftp)://|\\\\[A-Za-z0-9.-]+\\")
# The same, as UTF-16LE: a URL moniker stores its target as wide characters, so an ASCII search never sees it.
REMOTE_WIDE = re.compile(rb"(?i)(?:h\x00t\x00t\x00p\x00(?:s\x00)?|f\x00t\x00p\x00):\x00/\x00/\x00|\\\x00\\\x00[A-Za-z0-9]\x00")


def remote_url(data):
    return REMOTE_ASCII.search(data) is not None or REMOTE_WIDE.search(data) is not None


def ole1(data):
    """(class name, native data) of an OLE 1.0 embedded or linked object, or None."""
    try:
        _, fmt = struct.unpack_from("<II", data, 0)
        pos = 8
        ln = struct.unpack_from("<I", data, pos)[0]
        cls = data[pos + 4:pos + 4 + ln].rstrip(b"\x00").decode("latin-1")
        pos += 4 + ln
        for _ in range(2):
            ln = struct.unpack_from("<I", data, pos)[0]
            pos += 4 + ln
        dlen = struct.unpack_from("<I", data, pos)[0]
        return cls, data[pos + 4:pos + 4 + min(dlen, 16 * 1048576)], fmt
    except struct.error:
        return None


def analyze_rtf(data, label, depth):
    if depth > MAX_DEPTH:
        emit("incomplete", "objects nested deeper than %d levels were not opened" % (MAX_DEPTH - 1))
        return
    text = data.decode("latin-1")
    for k, m in enumerate(re.finditer(r"\{\\\*\\template\s+([^{}]{0,2000})\}", text)):
        if k >= 1000:
            emit("incomplete", "more than 1000 RTF templates, the rest were not read")
            break
        tgt = rtf_plain(m.group(1)).strip()
        if SCHEME.match(tgt) or is_unc(tgt):
            classify_target(label, "attachedtemplate", tgt)
    for k, m in enumerate(re.finditer(r"\{\\field\b", text)):
        if k > 5000 or RTF_STEPS["left"] <= 0:
            emit("incomplete", "more RTF fields than were read")
            break
        grp, _ = rtf_group(text, m.start())
        parts = []
        for fm in re.finditer(r"\{(?:\\\*)?\\fldinst\b", grp):
            g, _ = rtf_group(grp, fm.start())
            g = re.sub(r"^\{(?:\\\*)?\\fldinst ?", "", g)
            g = g[:-1] if g.endswith("}") else g
            parts.append(rtf_plain(g))
        field_findings(label, "".join(parts))   # DDE, and INCLUDEPICTURE/INCLUDETEXT/LINK to a remote or UNC target
    n_obj = 0
    for m in re.finditer(r"\{\\object\b", text):
        n_obj += 1
        if n_obj > 200:
            emit("incomplete", "more than 200 embedded objects, the rest were not read")
            break
        grp, closed = rtf_group(text, m.start())
        state["rtf_read"] = state.get("rtf_read", 0) + len(grp)
        if state["rtf_read"] > 96 * 1048576 or out_of_time():
            emit("incomplete", "RTF objects beyond 96 MB (or past the time budget) were not read")
            break
        if not closed:
            emit("incomplete", "an RTF object group is not closed; the rest of the file was not read as objects")
            break
        objdata = rtf_hex(grp, "objdata")
        cm = re.search(r"\\objclass\s+([^}\\]+)", grp)
        cls_decl = cm.group(1).strip() if cm else ""
        o = ole1(objdata) if objdata else None
        cls = (o[0] if o else cls_decl) or cls_decl
        native = o[1] if o else objdata
        tag = "%sobject %d%s" % (label, n_obj, " (%s)" % cls if cls else "")
        auto_link = bool(re.search(r"\\objautlink\b", grp) and re.search(r"\\objupdate\b", grp))
        remote = remote_url(native or b"")
        # CVE-2017-0199: a linked object (Word.Document.8 / htmlfile / OLE2Link) whose URL moniker, stored
        # as UTF-16, makes Word fetch and run the target when the document opens.
        linkish = auto_link or re.search(r"(?i)OLE2Link|StdOleLink", cls + " " + cls_decl) or URL_MONIKER in (native or b"")
        if (auto_link and (remote or re.search(r"(?i)htmlfile|ShockwaveFlash|Microsoft Word|Excel", cls))) or (linkish and remote):
            emit("rtf_remote_link", tag)
            continue
        if re.search(r"(?i)equation", cls):
            if native[:8] == CFB_MAGIC:
                analyze_cfb(native, tag + "!", depth + 1)
            else:
                equation_findings(tag, native)
        elif cls.lower() == "package":
            pk = parse_package(native)
            if pk:
                package_findings(tag + " ", *pk)
            else:
                emit("rtf_object", tag)
        elif native[:8] == CFB_MAGIC:
            before = n_facts()
            analyze_cfb(native, tag + "!", depth + 1)
            if n_facts() == before:
                emit("rtf_object", tag)
        elif native[:2] == b"PK":
            analyze_zip_bytes(native, tag + "!", depth + 1)
        else:
            emit("rtf_object", tag)
    # hex blobs (objects, pictures) are not text. Maximal runs, replaced when long: "{200,}" tried from
    # every position inside a shorter run costs the run's length each time.
    plain = re.sub(r"[0-9a-fA-F\s]+", lambda m: " " if len(m.group()) >= 200 else m.group(), text)
    plain = re.sub(r"\\[a-zA-Z]+-?\d* ?|\\'[0-9a-fA-F]{2}|[{}\\]", " ", plain)
    to_view(label + "text", plain)


# ═════════════════════════════════════════════════════════════════════════════
# Entry point: sniff the container, whatever the extension claims
# ═════════════════════════════════════════════════════════════════════════════
try:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(HEAD)
except OSError:
    size, head = None, None
    emit("unreadable_file")


def whole(limit):
    with open(path, "rb") as fh:
        return fh.read(limit)


def analyze_flat_xml_file():
    """Flat OPC, Word 2003 XML, Excel 2003 XML and flat OpenDocument: one XML file holding the whole document."""
    htxt = head.decode(xml_codec(head[:512]), "replace").lstrip("\ufeff \t\r\n")
    if not htxt.startswith("<"):
        return False
    text = xml_normalise(decode_xml(whole(64 * 1048576)))
    return analyze_flat_xml(text, "", 1)


def run():
    if head is not None:
        if not size:
            emit("empty_file")
        elif native_kind(head):
            emit("disguised_native", native_kind(head))
        elif head[:8] == CFB_MAGIC:
            analyze_cfb(whole(256 * 1048576), "", 1)
        elif head[:2] == b"PK":
            try:
                zf = zipfile.ZipFile(path)
            except Exception:
                emit("unparseable", "document")
            else:
                analyze_zip(zf, "", 1)
        elif head[:5] == b"{\\rtf" or b"{\\rtf" in head[:1024]:
            analyze_rtf(whole(64 * 1048576), "", 1)
        elif analyze_flat_xml_file():
            pass
        else:
            emit("not_office", "text" if texty(head) else "binary")


try:
    if head is not None:
        try:
            run()
        except Watchdog:
            raise
        except Exception as exc:
            # Whatever was found before the failure is kept, and the failure itself is reported:
            # a document built to crash the reader must not come out clean.
            emit("unparseable", "internal error %s" % type(exc).__name__)
except Watchdog:
    emit("incomplete", "time budget exceeded, the analysis was stopped")
if hasattr(signal, "setitimer"):
    signal.setitimer(signal.ITIMER_REAL, 0)
view.close()
for tag, (n, ex) in facts.items():
    print("FACT %s %d %s" % (tag, n, "; ".join(ex)))
print("FACT done")
