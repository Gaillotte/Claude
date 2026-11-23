# Moved out of scan_pipeline.sh (function _jar_facts) without changes to the code below.
# Reads a Java archive (jar/war/ear/aar) and prints FACT lines for the scanner.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import io, os, re, signal, struct, sys, time, zipfile, zlib

# argv: <archive> <view file: the text of the entries, for the credential rules>
path, view_path = sys.argv[1], sys.argv[2]


def _knob(name, default):
    try:
        v = float(os.environ.get(name, ""))
        return v if v > 0 else default
    except ValueError:
        return default


MAX_ENTRIES = int(_knob("JAR_MAX_ENTRIES", 50000))  # entries whose bytes are read
BUDGET = int(_knob("JAR_READ_BUDGET_MB", 64) * 1048576)  # bytes read across all entries
MAX_UNCOMP = int(_knob("JAR_MAX_UNCOMPRESSED_MB", 1024) * 1048576)
DEADLINE = time.monotonic() + _knob("JAR_TIME_BUDGET_S", 90)
ENTRY_CAP = 4 * 1048576   # most that is read from one entry
NEST_CAP = 16 * 1048576   # largest nested archive that is opened
VIEW_CAP = int(_knob("JAR_VIEW_MB", 32) * 1048576)  # most text handed to the credential rules
MAX_DEPTH = 2             # the archive itself, and one level inside it
HEAD = 4096

facts = {}
state = {"entries": 0, "budget": BUDGET, "declared": 0, "view": 0}

# record_fail downgrades a finding when its message contains :LOW: or :INFO: and
# friends, and an entry name is part of the message. Entry names, symlink targets
# and manifest tokens come from the archive, so the colon that opens such a marker
# is neutralised, along with anything a console or a report would misread.
MARKER = re.compile(r":(?=(?:info|low|warning|medium|error|high|critical):)", re.I)


def emit(tag, detail=""):
    detail = re.sub(r"[^\x20-\x7e]|[|\\]", "?", str(detail))[:110]
    detail = MARKER.sub("?", detail)
    n, ex = facts.get(tag, (0, []))
    if len(ex) < 6 and detail not in ex:
        ex.append(detail)
    facts[tag] = (n + 1, ex)


NATIVE_NAME = re.compile(r"\.(so(\.\d+)*|dll|dylib|jnilib|exe|sys|ocx|node|pyd|o|ko|bundle|a|lib|obj|elf)$", re.I)
# Native helpers are shipped without an extension in a platform directory
# (native/linux-x86_64/spawn-helper); an executable stored as logo.png is not that.
NATIVE_DIR = re.compile(r"(^|/)(native|natives|jni|lib|libs|bin|linux|darwin|macos|osx|windows|win32|win64|"
                        r"x86|x86_64|amd64|arm|arm64|aarch64)[^/]*/", re.I)
SCRIPT_NAME = re.compile(r"\.(sh|bat|cmd|ps1|vbs|hta|scr|msi)$", re.I)
ARCHIVE_NAME = re.compile(r"\.(jar|war|ear|aar|zip|tar|tgz|gz|bz2|xz|7z|rar)$", re.I)
CONTENT_NAME = re.compile(
    r"\.(class|properties|xml|json|txt|sh|bat|cmd|ps1|vbs|js|py|jsp|jspx|html?|ya?ml|conf|cfg|ini|"
    r"gradle|kts|md|toml|env|sql|groovy|java|pem|key)$|(^|/)(MANIFEST\.MF)$", re.I)
MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
         b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
# 0xCAFEBABE is the Java class magic AND the Mach-O *fat* magic. kotlinx-coroutines
# ships a class stored as DebugProbesKt.bin, so the magic alone cannot be called
# native. What tells them apart is the next four bytes: a class has minor/major
# version words with major >= 45; a fat binary has an architecture count, 1..44.
CLASS_MAGIC = b"\xca\xfe\xba\xbe"
APPLEDOUBLE = b"\x00\x05\x16\x07"
READ_ERRORS = (RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, zlib.error, OSError, ValueError)

CONT = re.compile(r"\\\r?\n[ \t]*")  # a backslash-newline continues a shell command
HOSTILE = [
    ("shell_pipe", re.compile(
        r"(?i)\b(curl|wget)\b[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:/usr/bin/env\s+|/(?:usr/)?(?:local/)?bin/)?(?:ba|z|da)?sh\b")),
    # /dev/tcp alone is not enough: wait-for-it.sh probes a port with it.
    ("reverse_shell", re.compile(
        r"(?i)(bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/\S+\s+0>&1|exec\s+\d+<>\s*/dev/tcp/|\bnc\s+-[a-z]*e\s)")),
    ("encoded_powershell", re.compile(
        r"(?i)powershell[^\n]{0,300}\s-(?:e|enc|encodedcommand)[a-z]*\s+[A-Za-z0-9+/=]{20,}")),
    ("lolbin_download", re.compile(r"(?i)(certutil[^\n]{0,60}-urlcache|bitsadmin[^\n]{0,60}/transfer)")),
    ("offensive_tool_name", re.compile(r"(?i)(mimikatz|sekurlsa|meterpreter|cobalt\s?strike)")),
]


def utf16_codec(head):
    """The codec of a UTF-16 head, or "": a BOM, or ASCII text with a NUL between the letters."""
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    h = head[:512]
    if len(h) >= 8:
        even, odd = h[0::2], h[1::2]
        if odd.count(0) > len(odd) * 0.6 and even.count(0) < len(even) * 0.1:
            return "utf-16-le"
        if even.count(0) > len(even) * 0.6 and odd.count(0) < len(odd) * 0.1:
            return "utf-16-be"
    return ""


def texty(head):
    """True for a head that reads as text: no NUL (unless UTF-16), and almost all printable."""
    if not head:
        return False
    if utf16_codec(head):
        return True
    if b"\x00" in head:
        return False
    return sum(1 for b in head if b >= 0x20 or b in (9, 10, 13)) / len(head) > 0.95


def native_kind(head, more=None):
    """ELF, Mach-O (thin or fat), or a PE whose e_lfanew really points at PE\\0\\0 (not just an MZ prefix).

    `more(n)` returns the first n bytes of the entry, for a PE whose header lies past `head`.
    """
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] == CLASS_MAGIC and len(head) >= 8:
        return "Mach-O" if 1 <= struct.unpack_from(">I", head, 4)[0] <= 44 else ""
    if head[:4] in MACHO:
        return "Mach-O"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if e + 4 > len(head) and more is not None and e <= 1048576:
            try:
                head = more(e + 4)
            except Exception:
                return ""
        if e + 4 <= len(head) and head[e:e + 4] == b"PE\x00\x00":
            return "PE"
    return ""


def class_strings(data):
    """(UTF-8 constants of the pool, offset where the pool ends), or None if it does not parse."""
    try:
        if data[:4] != CLASS_MAGIC or len(data) < 10:
            return None
        count = struct.unpack_from(">H", data, 8)[0]
        i, pos, out = 1, 10, []
        while i < count:
            tag = data[pos]
            pos += 1
            if tag == 1:
                ln = struct.unpack_from(">H", data, pos)[0]
                out.append(data[pos + 2:pos + 2 + ln].decode("utf-8", "replace"))
                pos += 2 + ln
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                pos += 4
            elif tag in (5, 6):
                pos += 8
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                pos += 2
            elif tag == 15:
                pos += 3
            else:
                return None
            i += 1
        return out, pos
    except (IndexError, struct.error):
        return None


def parse_manifest(raw):
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n ", "", text)  # a line continues on the next one that starts with a space
    attrs = {}
    for line in text.split("\n"):
        if not line.strip():
            break  # the main section ends at the first blank line
        k, _, v = line.partition(":")
        attrs[k.strip().lower()] = v.strip()
    return attrs


def entry_bytes(z, info, n):
    """The first n bytes of an entry, read the way the JVM and unzip read it.

    zipfile checks an entry against the central directory and refuses it when the
    CRC, the local header's name or the declared size disagree, and it stops at the
    declared size. java.util.zip.ZipFile and unzip honour none of that: they take
    the offset and compressed size from the central directory and inflate until the
    stream ends. An entry a strict reader drops is one the JVM still loads, so this
    reads stored and deflated entries directly. Anything else goes to zipfile.
    """
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
                        break  # the JVM hands over what inflated before the error
                    raise
            return bytes(out[:n])
    with z.open(info) as fh:
        return fh.read(n)


def decode_text(data):
    codec = utf16_codec(data[:512])
    return data.decode(codec or "utf-8", "replace")


view = open(view_path, "w", encoding="utf-8", errors="replace")


def _alarm(signum, frame):
    # The time budget is checked between entries, but one pattern run on one hostile entry cannot be
    # interrupted by a check. When the alarm fires the findings so far are printed and the helper
    # exits: a document-sized time budget is reported, never a hang with no verdict.
    emit("incomplete", "time budget exceeded, the analysis was stopped")
    try:
        view.close()
    except Exception:
        pass
    for tag, (n, ex) in facts.items():
        print("FACT %s %d %s" % (tag, n, "; ".join(ex)))
    print("FACT done")
    sys.stdout.flush()
    os._exit(0)


if hasattr(signal, "setitimer"):
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, _knob("JAR_TIME_BUDGET_S", 90) + 10)


def to_view(label, text):
    if state["view"] >= VIEW_CAP:
        emit("incomplete", "text handed to the credential rules is capped at %d MB" % (VIEW_CAP >> 20))
        return
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    view.write("== " + label + "\n" + text + "\n")
    state["view"] += len(text)


def hostile(label, text):
    text = CONT.sub(" ", text)
    for tag, rx in HOSTILE:
        if rx.search(text):
            emit("hostile_" + tag, label)


# The classes are bounded: [A-Z0-9 ]* around "PRIVATE KEY" is quadratic on a run of
# "PRIVATE KEY PRIVATE KEY …", and the time budget is only checked between entries.
PEM_HEAD = re.compile(r"-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY[A-Z0-9 ]{0,30}-----")
B64_LINE = re.compile(r"^[A-Za-z0-9+/=]+$")
LINE_SPLIT = re.compile(r"\r\n|\r|\n|\\r\\n|\\n|\\r")


def private_key(label, unit):
    """A PEM header followed by 60+ base64 characters, however the lines are wrapped.

    Judged inside ONE string, never across neighbours: a class file keeps each
    constant on its own line of the view, and a class path such as
    org/apache/sshd/common/config/keys/loader/openssh/OpenSSHKeyPairResourceParser
    is 78 characters of [A-Za-z0-9/], which a body test reads as base64 (the header
    constant followed by that path failed sshd-common-2.12.1.jar). Lines are
    totalled when each is pure base64, so a key wrapped at 40 or 56 characters, which
    OpenSSL reads, still counts; prose after a header has spaces and does not.
    """
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


def name_checks(infos, label, top):
    """Everything that needs only the central directory. Unbounded by the read limits: it costs nothing."""
    names = [i.filename for i in infos]
    if top and len(set(names)) != len(names):
        emit("duplicate_names", "%d repeated" % (len(names) - len(set(names))))
    for info in infos:
        n, full = info.filename, label + info.filename
        state["declared"] += info.file_size
        parts = n.replace("\\", "/").split("/")
        if ".." in parts or n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n):
            emit("zip_slip", full)
        if SCRIPT_NAME.search(n):
            emit("script_entry", full)
        if info.flag_bits & 0x1 and not info.is_dir():
            emit("encrypted", full)
    return names


def orphan_check(z, infos, label):
    """A local file record that the central directory does not list.

    JarFile, unzip and zipfile all go by the central directory; ZipInputStream,
    JarInputStream and several scanners walk the local headers instead, and would
    see an entry the others never do. Anything between the end of one entry's data
    (plus a data descriptor, at most 24 bytes) and the start of the next is looked
    at for a local header signature.
    """
    order = sorted(infos, key=lambda i: i.header_offset)
    for k, info in enumerate(order):
        z.fp.seek(info.header_offset)
        h = z.fp.read(30)
        if len(h) < 30 or h[:4] != b"PK\x03\x04":
            continue
        nl, el = struct.unpack_from("<HH", h, 26)
        end = info.header_offset + 30 + nl + el + info.compress_size
        nxt = order[k + 1].header_offset if k + 1 < len(order) else z.start_dir
        if nxt - end > 24:
            z.fp.seek(end)
            blob = z.fp.read(min(nxt - end, 1048576))
            i = blob.find(b"PK\x03\x04")
            if i != -1:
                hdr = blob[i:i + 30]
                name = blob[i + 30:i + 30 + struct.unpack_from("<H", hdr, 26)[0]] if len(hdr) == 30 else b""
                emit("orphan_local", label + name.decode("utf-8", "replace"))


def walk(z, label, depth, top):
    infos = z.infolist()
    names = name_checks(infos, label, top)
    room = MAX_ENTRIES - state["entries"]
    if len(infos) > room:
        emit("incomplete", "more than %d entries, the rest were not read" % MAX_ENTRIES)
        infos = infos[:max(room, 0)]
    state["entries"] += len(infos)
    try:
        orphan_check(z, infos, label)
    except Exception:
        pass
    for info in infos:
        if time.monotonic() > DEADLINE:
            emit("incomplete", "time budget exceeded")
            break
        try:
            scan_entry(z, info, label, depth)
        except Exception:
            # One entry that raises (an LZMA stream that is not LZMA, say) must not
            # blank the inspection of the others.
            emit("unreadable", label + info.filename)
    return names


def scan_entry(z, info, label, depth):
    n = info.filename
    full = label + n
    if info.is_dir() or info.flag_bits & 0x1:
        return
    # A symlink entry is a zip-slip with one more step: it is created on
    # extraction and the next entry is written through it.
    if info.create_system == 3 and (info.external_attr >> 16) & 0o170000 == 0o120000:
        try:
            target = entry_bytes(z, info, HEAD).decode("utf-8", "replace")
        except Exception:
            # unzip reads methods this scanner cannot, and still creates the link.
            emit("symlink_unreadable", full)
            return
        t = target.replace("\\", "/")
        if t.startswith("/") or ".." in t.split("/") or re.match(r"^[A-Za-z]:", t):
            emit("symlink_escape", "%s -> %s" % (full, target))
        else:
            emit("symlink", full)
        return
    wants_content = bool(CONTENT_NAME.search(n))
    data = entry_bytes(z, info, ENTRY_CAP if wants_content and state["budget"] > 0 else HEAD)
    head = data[:HEAD]
    # Entries with no recognised name (LICENSE, services files, .cert, .dat) are
    # read as text when they look like text; binary ones are not.
    if not wants_content and texty(head):
        if state["budget"] > 0:
            data = entry_bytes(z, info, ENTRY_CAP)
            wants_content = True
        else:
            emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
    if wants_content:
        if state["budget"] <= 0:
            emit("incomplete", "read budget of %d MB exhausted" % (BUDGET >> 20))
            wants_content = False
        else:
            state["budget"] -= len(data)
    if wants_content and (info.file_size > ENTRY_CAP or len(data) >= ENTRY_CAP):
        emit("incomplete", "an entry larger than %d MB was read only in part" % (ENTRY_CAP >> 20))

    # Finder adds AppleDouble resource forks as __MACOSX/.../._Name.class.
    appledouble = head[:4] == APPLEDOUBLE and (n.startswith("__MACOSX/") or os.path.basename(n).startswith("._"))
    is_class = n.endswith(".class") and not appledouble
    kind = native_kind(head, lambda k: entry_bytes(z, info, k))
    if is_class and len(head) >= 4 and (head[:4] != CLASS_MAGIC or kind == "Mach-O"):
        emit("class_not_bytecode", full)
    native_looking = NATIVE_NAME.search(n) or ("." not in os.path.basename(n) and NATIVE_DIR.search(n))
    if native_looking:
        if kind:
            emit("native_library", full)
    elif kind and not is_class:
        emit("hidden_native", "%s %s" % (kind, full))

    if n.upper() == "META-INF/MANIFEST.MF":
        a = parse_manifest(data)
        if depth == 1 and any(k in a for k in ("premain-class", "agent-class", "launcher-agent-class")):
            emit("agent", a.get("premain-class") or a.get("agent-class") or a.get("launcher-agent-class"))
        for tok in a.get("class-path", "").split():
            if re.match(r"^(https?|ftp)://", tok, re.I):
                emit("classpath_remote", tok)
            elif depth == 1 and (tok.startswith(("/", "\\")) or re.match(r"^([A-Za-z]:|file:)", tok, re.I)):
                emit("classpath_absolute", tok)

    if not is_class and (head[:4] == b"PK\x03\x04" or ARCHIVE_NAME.search(n)):
        emit("nested_archive", full)
        if depth >= MAX_DEPTH:
            emit("incomplete", "archives nested deeper than %d levels were not opened" % MAX_DEPTH)
        elif info.file_size > NEST_CAP or state["budget"] <= 0:
            emit("incomplete", "a nested archive was not opened: " + full)
        else:
            try:
                raw = entry_bytes(z, info, NEST_CAP)
                state["budget"] -= len(raw)
                walk(zipfile.ZipFile(io.BytesIO(raw)), full + "!/", depth + 1, False)
            except Exception:
                emit("nested_unparseable", full)
        return
    if not wants_content:
        return

    if is_class:
        parsed = class_strings(data)
        if parsed is not None:
            units, pool_end = parsed
            # Anything after the pool (a custom attribute, say) is not a constant
            # but loads fine and holds anything.
            tail = re.findall(rb"[\x20-\x7e\t\n\r]{8,}", data[pool_end:])
            units = units + [t.decode("latin-1") for t in tail]
        else:
            units = re.sub(r"[^\x20-\x7e\n]+", "\n", data.decode("latin-1")).split("\n")
    else:
        units = [decode_text(data)]
    text = "\n".join(units)
    to_view(full, text)
    hostile(full, text)
    for u in units:
        private_key(full, u)


# ── Whole-file shape ────────────────────────────────────────────────────
try:
    with open(path, "rb") as fh:
        first = fh.read(4096)
except OSError:
    first = None
    emit("unreadable_file")

zf = None
if first is not None:
    try:
        zf = zipfile.ZipFile(path)
    except Exception:
        if not first:
            emit("empty_file")
        elif first[:2] == b"PK":
            emit("unparseable")
        else:
            emit("not_an_archive", native_kind(first) or first[:8].hex())

if zf is not None:
    k = native_kind(first)
    if first[:2] != b"PK":
        if k:
            emit("prepended_native", k)
        elif first[:2] == b"#!":
            emit("prepended_script")
        else:
            emit("prepended_data", first[:8].hex())
    names = walk(zf, "", 1, True)
    if state["declared"] > MAX_UNCOMP:
        emit("oversize", "%d MB declared" % (state["declared"] >> 20))
    # gradle-wrapper.jar runs on ./gradlew before any code the repository
    # declares. Its shape is checkable; its contents are not (the official
    # checksums are not embedded here), so it always also asks for a manual check.
    # Real wrappers carry META-INF/MANIFEST.MF and LICENSE (maven's also its
    # pom.properties) and nothing else there: anything more, META-INF/versions
    # above all, is a second place for a class to load from.
    spec = {
        "gradle-wrapper.jar": ("gradle", "org/gradle/", r"META-INF/(MANIFEST\.MF|LICENSE)?",
                               "org/gradle/wrapper/GradleWrapperMain.class"),
        "maven-wrapper.jar": ("maven", "org/apache/maven/",
                              r"META-INF/(MANIFEST\.MF|maven/(io\.takari/(maven-wrapper/(pom\.properties)?)?)?)?",
                              "org/apache/maven/wrapper/MavenWrapperMain.class"),
    }.get(os.path.basename(path).lower())
    if spec:
        kind, prefix, meta, must = spec
        meta_ok = re.compile("^" + meta + "$")
        files = [x for x in names if not x.endswith("/")]
        stray = [x for x in files if not (x.startswith(prefix) or (x.startswith("META-INF/") and meta_ok.match(x)))]
        for x in stray[:3]:
            emit("wrapper_unexpected", "unexpected entry " + x)
        if must not in files:
            emit("wrapper_unexpected", "missing " + must)
        if len(files) > 100:
            emit("wrapper_unexpected", "%d entries" % len(files))
        emit("wrapper", kind)
view.close()
for tag, (n, ex) in facts.items():
    print("FACT %s %d %s" % (tag, n, "; ".join(ex)))
print("FACT done")
