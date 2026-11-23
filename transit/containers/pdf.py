# Moved out of scan_pipeline.sh (function _pdf_searchable) without changes to the code below.
# Writes a searchable rendering of a PDF (decoded names, inflated streams) for the PDF rules.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import base64, re, sys, zlib

MAX_INFLATE = 64 * 1024 * 1024       # decompression-bomb ceiling
MAX_READ    = 512 * 1024 * 1024      # repository size limit is 500 MB
MAX_STRING  = 64 * 1024              # longest plausible PDF string literal

_HEX    = re.compile(rb"#([0-9A-Fa-f]{2})")
_NAME   = re.compile(rb"/([A-Za-z0-9#]{1,64})")
_STREAM = re.compile(rb"(?<!end)stream\r?\n?")
_FILTER = re.compile(rb"/Filter\s*(/[A-Za-z0-9]+|\[[^\]]{0,512}\])")

# Filters that can conceal an object dictionary. Decoding these is the whole
# point: a /JavaScript action behind ASCII85 is as invisible to a text rule as
# one behind Flate.
#
# Image filters are deliberately absent. They carry pixels, never dictionaries,
# so failing to decode one is not a coverage gap — and reporting it as one would
# warn on every PDF containing a photograph.
_IMAGE_FILTERS = frozenset((
    "DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode",
))


def _flate(data, budget):
    return zlib.decompressobj().decompress(data, budget)


def _asciihex(data, budget):
    h = re.sub(rb"[^0-9A-Fa-f>]", b"", data).split(b">")[0]
    if len(h) % 2:
        h += b"0"
    return bytes.fromhex(h.decode("ascii"))


def _ascii85(data, budget):
    s = re.sub(rb"\s", b"", data)
    if s.startswith(b"<~"):
        s = s[2:]
    if s.endswith(b"~>"):
        s = s[:-2]
    return base64.a85decode(s)


def _runlength(data, budget):
    out = bytearray()
    i = 0
    while i < len(data):
        n = data[i]
        i += 1
        if n == 128:                    # EOD
            break
        if n < 128:
            out += data[i:i + n + 1]
            i += n + 1
        else:
            if i >= len(data):
                break
            out += bytes([data[i]]) * (257 - n)
            i += 1
        if len(out) > budget:
            break
    return bytes(out)


def _lzw(data, budget, early=1):
    """PDF/TIFF-variant LZW: 9-bit codes growing to 12, 256=clear, 257=EOD."""
    def fresh():
        return [bytes([i]) for i in range(256)] + [b"", b""]

    table = fresh()
    out = bytearray()
    bitpos, nbits, prev = 0, 9, None
    total = len(data) * 8
    while bitpos + nbits <= total:
        i = bitpos >> 3
        chunk = data[i:i + 3]
        if len(chunk) < 3:
            chunk = chunk + b"\x00" * (3 - len(chunk))
        code = (((chunk[0] << 16) | (chunk[1] << 8) | chunk[2])
                >> (24 - (bitpos & 7) - nbits)) & ((1 << nbits) - 1)
        bitpos += nbits

        if code == 256:
            table, nbits, prev = fresh(), 9, None
            continue
        if code == 257:
            break

        if prev is None:
            if code >= len(table):
                break
            entry = table[code]
        elif code < len(table):
            entry = table[code]
            table.append(prev + entry[:1])
        else:
            entry = prev + prev[:1]
            table.append(entry)

        out += entry
        if len(out) > budget:
            break
        prev = entry
        if len(table) + early >= (1 << nbits) and nbits < 12:
            nbits += 1
    return bytes(out)


_DECODERS = {
    "FlateDecode":     _flate,
    "LZWDecode":       _lzw,
    "ASCIIHexDecode":  _asciihex,
    "ASCII85Decode":   _ascii85,
    "RunLengthDecode": _runlength,
}


def blank_strings(data):
    """Blank the interior of every ( ... ) literal, leaving structure intact.

    A name token cannot occur inside a PDF string, so this is what separates a
    real /JavaScript key from the words "Python/JavaScript" set in a paragraph.
    This project's own installation guide contains that phrase, and matching it
    failed the guide against its own scanner — invisibly until stream decoding
    improved enough to expose the text.

    Anchoring alone cannot do this job: requiring a non-name byte before the
    slash would also reject /S/JavaScript, which is valid PDF, because names
    self-delimit and need no separator.
    """
    out = bytearray(data)
    i, n = 0, len(data)
    while i < n:
        if data[i] != 0x28:                 # '('
            i += 1
            continue
        depth, j = 1, i + 1
        limit = min(n, i + MAX_STRING)
        while j < limit and depth:
            c = data[j]
            if c == 0x5C:                   # backslash escapes the next byte
                j += 2
                continue
            if c == 0x28:
                depth += 1
            elif c == 0x29:                 # ')'
                depth -= 1
            j += 1
        if depth:
            # Never closed within a plausible string length, so this "(" is
            # data, not a string opener. Blanking onward from here would let a
            # stray 0x28 in a binary stream swallow a later dictionary and hide
            # the /OpenAction in it.
            i += 1
            continue
        for k in range(i + 1, min(j - 1, n)):
            out[k] = 0x20
        i = max(j, i + 1)
    return bytes(out)


def blank_stream_bodies(data):
    """Replace raw stream bodies with spaces.

    Only used for the raw copy of the file. Object dictionaries live outside
    streams, so nothing searchable is lost, while the binary payloads that
    would otherwise confuse string tracking are removed. Stream contents still
    reach the rules via the decoded chunks, which are emitted separately.
    """
    out = bytearray(data)
    for m in _STREAM.finditer(data):
        end = data.find(b"endstream", m.end())
        if end == -1:
            end = len(data)
        for k in range(m.end(), end):
            out[k] = 0x20
    return bytes(out)


def declared_filters(dict_text):
    """Filter names from a stream's dictionary, in application order."""
    m = _FILTER.search(dict_text)
    if not m:
        return []
    return [n.decode("latin-1")
            for n in re.findall(rb"/([A-Za-z0-9]+)", m.group(1))]


def apply_chain(body, filters, budget):
    """Returns (decoded, undecodable_filter_name).

    A filter chain is applied in order. An image filter ends the chain with no
    gap recorded; anything else we cannot handle is reported by name so the
    operator learns which stream went uninspected.
    """
    data = body
    for name in filters:
        if name in _IMAGE_FILTERS:
            return None, None
        fn = _DECODERS.get(name)
        if fn is None:
            return None, name           # /Crypt, or a filter we do not know
        try:
            data = fn(data, budget)
        except Exception:
            return None, name
    return data, None

# A bare "MZ" says nothing here — compressed PDF bytes contain it by chance in
# every real document. An embedded executable starts with MZ *and* carries the
# PE signature a little further in, which arbitrary data does not.
def looks_like_pe(buf):
    return buf[:2] == b"MZ" and b"PE\x00\x00" in buf[:4096]

# Escaping is only evidence of evasion when it hides one of these. A #xx
# sequence on its own is not: inside a compressed stream it is ordinary binary
# noise, and matching it flagged two of this project's own PDFs, where
# "/#A57Sg" decodes to "\xa57Sg" and means nothing at all.
_DANGEROUS_NAMES = frozenset((
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile",
    b"RichMedia", b"Flash", b"SubmitForm", b"ImportData", b"XFA",
    b"GoToR", b"GoToE", b"ObjStm", b"Encrypt",
))

obfuscated = False


def decode_names(data, track=False):
    """Decode #xx escapes, but only inside name tokens.

    track=True additionally records whether an escape concealed a dangerous
    name. Only the string-blanked view passes it: this project's installation
    guide documents the evasion by writing /J#61vaScript in prose, and counting
    that as an attack failed the guide against its own scanner.
    """
    global obfuscated

    def repl(m):
        global obfuscated
        name = m.group(1)
        if b"#" not in name:
            return m.group(0)
        try:
            dec = _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), name)
        except Exception:
            return m.group(0)
        if track and dec != name and dec in _DANGEROUS_NAMES:
            obfuscated = True
        return b"/" + dec
    return _NAME.sub(repl, data)

try:
    with open(sys.argv[1], "rb") as fh:
        raw = fh.read(MAX_READ)
except Exception:
    raise SystemExit(0)

# Two renderings, because the rules need different things. The "names" view has
# string literals blanked and is where key rules (/JavaScript, /OpenAction, …)
# run. The "full" view keeps everything and is where payload rules run, since
# the script itself lives inside the /JS ( ... ) string.
try:
    names_out = open(sys.argv[2], "wb")
    out = open(sys.argv[3], "wb")
except Exception:
    raise SystemExit(0)


def emit(chunk, is_raw=False):
    out.write(decode_names(chunk))
    out.write(b"\n")
    # Blank strings before decoding names, not after: decoding first could turn
    # an escaped #28 into a "(" and derail string tracking.
    blanked = blank_stream_bodies(chunk) if is_raw else chunk
    names_out.write(decode_names(blank_strings(blanked), track=True))
    names_out.write(b"\n")


emit(raw, is_raw=True)

# A PE signature cannot be expressed as a grep pattern from bash, because a
# bash string cannot hold the NUL bytes it contains. Detect it here and leave
# a plain-text marker for the shell rules to match instead.
pe = looks_like_pe(raw)

budget = MAX_INFLATE
undecoded = set()

for m in _STREAM.finditer(raw):
    if budget <= 0:
        break
    end = raw.find(b"endstream", m.end())
    if end == -1:
        continue
    body = raw[m.end():end]
    if not body:
        continue

    # The stream's own dictionary says how it is encoded. Look back for it
    # rather than guessing, so an undecodable filter can be named.
    head = raw[max(0, m.start() - 2048):m.start()]
    cut = head.rfind(b"<<")
    filters = declared_filters(head[cut:] if cut != -1 else head)

    if filters:
        decoded, bad = apply_chain(body, filters, budget)
        if bad:
            undecoded.add(bad)
    else:
        # No /Filter means the stream is already plaintext and the raw copy
        # above covers it. Still try Flate, because some producers omit the
        # declaration — but a failure here is not a coverage gap.
        try:
            decoded = _flate(body, budget)
        except Exception:
            decoded = None

    if decoded:
        budget -= len(decoded)
        pe = pe or looks_like_pe(decoded)
        emit(decoded)

# Markers go to the full view only; the rules that read them are routed there.
if pe:
    out.write(b"\nAITRANSIT-MARKER-EMBEDDED-PE\n")
if obfuscated:
    out.write(b"\nAITRANSIT-MARKER-NAME-OBFUSCATION\n")
for name in sorted(undecoded):
    out.write(b"\nAITRANSIT-MARKER-UNDECODED-FILTER " + name.encode("latin-1") + b"\n")
out.write(b"\n")
out.close()
names_out.close()
