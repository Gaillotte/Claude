#!/usr/bin/env python3
"""Regenerate the PDF fixtures in tests/fixtures/rules/.

Run from the repository root:

    python3 tests/fixtures/make_pdf_fixtures.py

Three fixtures, each pinning down one property of scan_pdf():

  pdf_openaction_js.pdf   Active content in the plaintext object dictionaries:
                          /OpenAction and /AA auto-run a /JavaScript action, and
                          a /Launch action starts an external program. Must FAIL.

  pdf_compressed_js.pdf   The same catalogue and the same /JavaScript action, but
                          both objects live inside a FlateDecode /ObjStm, so the
                          strings "JavaScript" and "OpenAction" do not appear in
                          the file's plaintext at all. This is the fixture that
                          proves scan_pdf() inflates streams rather than grepping
                          raw bytes; a rule that only reads plaintext passes this
                          file. Must FAIL.

  benign_doc.pdf          A real ReportLab document with compressed content
                          streams and a subset font. Must PASS — it is the guard
                          against a rule so broad it blocks ordinary
                          documentation. (TrueType subset tags look like
                          /AAAAAB+DejaVuSans, which an unanchored /AA rule reads
                          as an AdditionalActions key; that false positive would
                          otherwise block this project's own INSTALL PDF.)

The two malicious fixtures are assembled by hand rather than with a PDF library
so the test controls exactly which bytes land in plaintext and which land inside
a compressed stream. Both carry a cross-reference stream and are structurally
valid; the payloads are inert strings, not working exploits.
"""
from __future__ import annotations

import pathlib
import struct
import zlib

RULES = pathlib.Path(__file__).resolve().parent / "rules"

# An inert stand-in for the JavaScript an attacker would auto-run. It names the
# Acrobat APIs real droppers use so the fixture exercises those rules too, but
# it does nothing: there is no payload and no valid exploit here.
JS_PAYLOAD = (
    r"app.alert({cMsg: 'fixture', cTitle: 'AI Transit test'});"
    r"var s = unescape('%u9090%u9090%u4141');"
    r"util.printf('%45000f', 0);"
    r"this.exportDataObject({cName: 'fixture', nLaunch: 2});"
)


def _pdf_string(text: str) -> bytes:
    """Escape a str for a PDF literal string."""
    out = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return out.encode("latin-1", errors="replace")


def _xref_stream_obj(num: int, entries: list[tuple[int, int, int]], root: int,
                     size: int) -> tuple[bytes, bytes]:
    """Build a PDF 1.5 cross-reference stream object.

    entries is one (type, field2, field3) triple per object number 0..size-1:
      type 0 = free, 1 = at a byte offset, 2 = inside an object stream.
    """
    packed = b"".join(
        struct.pack(">BIH", t, f2, f3) for (t, f2, f3) in entries
    )
    data = zlib.compress(packed, 9)
    head = (
        f"{num} 0 obj\n"
        f"<< /Type /XRef /Size {size} /W [1 4 2] /Root {root} 0 R "
        f"/Filter /FlateDecode /Length {len(data)} >>\nstream\n"
    ).encode("latin-1")
    return head, data


def write_plaintext_fixture(path: pathlib.Path) -> None:
    """Active content sitting in plain sight in the object dictionaries."""
    content = b"BT /F1 12 Tf 40 120 Td (AI Transit PDF fixture) Tj ET\n"

    objs: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R "
           b"/AA << /O 5 0 R /C 6 0 R >> >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
           b"/Resources << /Font << /F1 7 0 R >> >> /Contents 4 0 R >>",
        4: b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
           + content + b"endstream",
        5: b"<< /Type /Action /S /JavaScript /JS (" + _pdf_string(JS_PAYLOAD) + b") >>",
        6: b"<< /Type /Action /S /Launch /F (cmd.exe) "
           b"/P (/c echo ai-transit-fixture) >>",
        7: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }

    buf = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = len(buf)
        buf += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"

    xref_num = max(objs) + 1
    size = xref_num + 1
    entries = [(0, 0, 65535)]
    for num in range(1, xref_num):
        entries.append((1, offsets[num], 0))
    xref_off = len(buf)
    entries.append((1, xref_off, 0))

    head, data = _xref_stream_obj(xref_num, entries, root=1, size=size)
    buf += head + data + b"\nendstream\nendobj\n"
    buf += f"startxref\n{xref_off}\n%%EOF\n".encode()

    path.write_bytes(bytes(buf))


def write_compressed_fixture(path: pathlib.Path) -> None:
    """The same attack, with every telltale name sealed inside an /ObjStm.

    The catalogue (with /OpenAction) and the /JavaScript action both go into the
    compressed object stream, so plaintext grep finds neither.
    """
    content = b"BT /F1 12 Tf 40 120 Td (AI Transit PDF fixture) Tj ET\n"

    # Objects that will be packed into the object stream.
    packed_objs: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
           b"/Resources << /Font << /F1 7 0 R >> >> /Contents 4 0 R >>",
        5: b"<< /Type /Action /S /JavaScript /JS (" + _pdf_string(JS_PAYLOAD) + b") >>",
        7: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }

    # /ObjStm layout: a header of "objnum offset" pairs, then the objects.
    pairs, bodies, cursor = [], [], 0
    for num in sorted(packed_objs):
        pairs.append(f"{num} {cursor}")
        body = packed_objs[num] + b"\n"
        bodies.append(body)
        cursor += len(body)
    header = (" ".join(pairs) + "\n").encode("latin-1")
    objstm_payload = header + b"".join(bodies)
    objstm_data = zlib.compress(objstm_payload, 9)

    objstm_num, content_num, xref_num = 8, 4, 9

    buf = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    # The page content stream stays a normal uncompressed object.
    offsets[content_num] = len(buf)
    buf += (f"{content_num} 0 obj\n".encode()
            + b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
            + content + b"endstream\nendobj\n")

    offsets[objstm_num] = len(buf)
    buf += (f"{objstm_num} 0 obj\n".encode()
            + f"<< /Type /ObjStm /N {len(packed_objs)} /First {len(header)} "
              f"/Filter /FlateDecode /Length {len(objstm_data)} >>\nstream\n".encode()
            + objstm_data + b"\nendstream\nendobj\n")

    size = xref_num + 1
    entries: list[tuple[int, int, int]] = [(0, 0, 65535)]
    stm_index = {num: i for i, num in enumerate(sorted(packed_objs))}
    for num in range(1, size - 1):
        if num in stm_index:
            entries.append((2, objstm_num, stm_index[num]))
        elif num in offsets:
            entries.append((1, offsets[num], 0))
        else:
            entries.append((0, 0, 65535))
    xref_off = len(buf)
    entries.append((1, xref_off, 0))

    head, data = _xref_stream_obj(xref_num, entries, root=1, size=size)
    buf += head + data + b"\nendstream\nendobj\n"
    buf += f"startxref\n{xref_off}\n%%EOF\n".encode()

    path.write_bytes(bytes(buf))

    # The whole point of this fixture: nothing incriminating in the plaintext.
    raw = path.read_bytes()
    for leak in (b"JavaScript", b"OpenAction", b"unescape", b"util.printf"):
        if leak in raw:
            raise SystemExit(
                f"fixture leaks {leak!r} into plaintext — it would no longer "
                "prove that scan_pdf() inflates compressed object streams"
            )


DEJAVU = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def write_obfuscated_fixture(path: pathlib.Path) -> None:
    """The plaintext attack again, with the telltale names hex-escaped.

    /OpenAc#74ion and /J#61vaScript read identically to a PDF viewer, so a rule
    that matches literal text sees an ordinary document. Nothing here is hidden
    by compression — this fixture isolates name escaping on its own.
    """
    content = b"BT /F1 12 Tf 40 120 Td (AI Transit PDF fixture) Tj ET\n"

    objs: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAc#74ion 5 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] "
           b"/Resources << /Font << /F1 6 0 R >> >> /Contents 4 0 R >>",
        4: b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
           + content + b"endstream",
        5: b"<< /Type /Action /S /J#61vaScript /JS ("
           + _pdf_string(JS_PAYLOAD) + b") >>",
        6: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }

    buf = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for num in sorted(objs):
        offsets[num] = len(buf)
        buf += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"

    xref_num = max(objs) + 1
    entries: list[tuple[int, int, int]] = [(0, 0, 65535)]
    for num in range(1, xref_num):
        entries.append((1, offsets[num], 0))
    xref_off = len(buf)
    entries.append((1, xref_off, 0))

    head, data = _xref_stream_obj(xref_num, entries, root=1, size=xref_num + 1)
    buf += head + data + b"\nendstream\nendobj\n"
    buf += f"startxref\n{xref_off}\n%%EOF\n".encode()

    path.write_bytes(bytes(buf))

    raw = path.read_bytes()
    for leak in (b"/JavaScript", b"/OpenAction"):
        if leak in raw:
            raise SystemExit(
                f"fixture leaks unescaped {leak!r} — it would no longer prove "
                "that scan_pdf() decodes hex-escaped names")


def write_benign_fixture(path: pathlib.Path) -> None:
    """A real document, built the way the project builds its own PDFs.

    Embeds DejaVu when it is available, because subsetting is what produces the
    /AAAAAB+DejaVuSans tags that an unanchored /AA rule misreads as an
    AdditionalActions key. Without that tag this fixture would not guard the
    false positive it exists to guard.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    import os
    if os.path.exists(DEJAVU):
        pdfmetrics.registerFont(TTFont("DJVSans", DEJAVU))
        for name in ("Heading1", "BodyText"):
            styles[name].fontName = "DJVSans"

    doc = SimpleDocTemplate(str(path), pagesize=A4, title="Benign fixture",
                            author="AI Transit Pipeline test suite")
    doc.build([
        Paragraph("Ordinary documentation", styles["Heading1"]),
        Spacer(1, 10),
        Paragraph(
            "This file exists so the test suite can prove that scan_pdf() does "
            "not flag an ordinary PDF. It carries compressed content streams "
            "and an embedded font, and no active content whatsoever: no "
            "JavaScript, no automatic actions, no launch actions and no "
            "embedded files.", styles["BodyText"]),
        Paragraph(
            "A rule broad enough to flag this document would also flag this "
            "project's own installation guide, which is how the unanchored "
            "variant of the AdditionalActions rule was caught.",
            styles["BodyText"]),
    ])

    # The subset tag is the whole reason this fixture embeds a font. Say so
    # loudly if a regeneration host lacks DejaVu, rather than quietly shipping
    # a fixture that no longer guards the /AA false positive.
    import re as _re
    if not _re.search(rb"/[A-Z]{6}\+", path.read_bytes()):
        print("  WARNING: benign_doc.pdf carries no font subset tag "
              f"({DEJAVU} missing?) — it no longer guards the /AA false positive")


def main() -> None:
    RULES.mkdir(parents=True, exist_ok=True)
    write_plaintext_fixture(RULES / "pdf_openaction_js.pdf")
    write_compressed_fixture(RULES / "pdf_compressed_js.pdf")
    write_obfuscated_fixture(RULES / "pdf_obfuscated_js.pdf")

    # Only the benign fixture needs ReportLab, and it is committed, so a host
    # without ReportLab can still regenerate the two that matter most.
    benign = RULES / "benign_doc.pdf"
    try:
        write_benign_fixture(benign)
    except ImportError:
        if benign.exists():
            print("  benign_doc.pdf             kept (ReportLab not installed)")
        else:
            raise SystemExit(
                "benign_doc.pdf is missing and ReportLab is not installed.\n"
                "Install it with:  python3 -m pip install reportlab")

    for name in ("pdf_openaction_js.pdf", "pdf_compressed_js.pdf",
                 "pdf_obfuscated_js.pdf", "benign_doc.pdf"):
        p = RULES / name
        if p.exists():
            print(f"  {name:<26} {p.stat().st_size:>7} bytes")


if __name__ == "__main__":
    main()
