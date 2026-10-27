#!/usr/bin/env python3
"""Visual system for the AI Transit Pipeline PDFs.

Kept separate from the parser so the look can be adjusted without touching
document logic, and so the diagram module can share exactly the same colours.

Font choice is not cosmetic here. INSTALL.md uses box-drawing characters
(┌ ─ │ ┘) for its architecture diagram plus → ▶ ✔ elsewhere; the PDF base
fonts encode none of those and render them as solid black squares. DejaVu
covers all of them, so it is used wherever document text can appear.
"""
import os
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

DEJAVU_DIR = "/usr/share/fonts/truetype/dejavu"

# Resolved at import; falls back to the base fonts if DejaVu is unavailable so
# the build still succeeds on a minimal host (box-drawing will degrade there).
FONT_BODY = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_ITAL = "Helvetica-Oblique"
FONT_MONO = "Courier"
FONT_MONO_BOLD = "Courier-Bold"
HAS_DEJAVU = False


def register_fonts() -> bool:
    """Register DejaVu if present. Returns True when box-drawing coverage is available.

    Only four faces are essential — regular and bold, sans and mono. An oblique
    sans is nice to have but is absent from some DejaVu packages (this host ships
    DejaVuSansMono-Oblique but not DejaVuSans-Oblique). Treating the family as
    all-or-nothing would drop back to Helvetica for one optional italic and
    silently reinstate the black-square rendering this exists to prevent, so
    italic degrades on its own instead.
    """
    global FONT_BODY, FONT_BOLD, FONT_ITAL, FONT_MONO, FONT_MONO_BOLD, HAS_DEJAVU

    essential = {
        "DJVSans":      "DejaVuSans.ttf",
        "DJVSans-Bold": "DejaVuSans-Bold.ttf",
        "DJVMono":      "DejaVuSansMono.ttf",
        "DJVMono-Bold": "DejaVuSansMono-Bold.ttf",
    }
    paths = {n: os.path.join(DEJAVU_DIR, f) for n, f in essential.items()}
    if not all(os.path.exists(p) for p in paths.values()):
        return False

    try:
        for name, path in paths.items():
            pdfmetrics.registerFont(TTFont(name, path))
    except Exception:
        return False

    # Optional oblique; fall back to Helvetica-Oblique, which carries every
    # glyph short italic prose actually uses.
    ital = "Helvetica-Oblique"
    obl = os.path.join(DEJAVU_DIR, "DejaVuSans-Oblique.ttf")
    if os.path.exists(obl):
        try:
            pdfmetrics.registerFont(TTFont("DJVSans-Obl", obl))
            ital = "DJVSans-Obl"
        except Exception:
            pass

    pdfmetrics.registerFontFamily(
        "DJVSans", normal="DJVSans", bold="DJVSans-Bold",
        italic=ital, boldItalic="DJVSans-Bold")
    pdfmetrics.registerFontFamily(
        "DJVMono", normal="DJVMono", bold="DJVMono-Bold",
        italic="DJVMono", boldItalic="DJVMono-Bold")

    FONT_BODY, FONT_BOLD, FONT_ITAL = "DJVSans", "DJVSans-Bold", ital
    FONT_MONO, FONT_MONO_BOLD = "DJVMono", "DJVMono-Bold"
    HAS_DEJAVU = True
    return True


# ── Palette ───────────────────────────────────────────────────────────────────
NAVY        = HexColor("#1B3A6B")
NAVY_DEEP   = HexColor("#132B4F")
INK         = HexColor("#15181C")
MUTED       = HexColor("#5B6672")
RULE        = HexColor("#D3DAE4")
PAPER_ALT   = HexColor("#F7F9FC")

CODE_BG     = HexColor("#F5F7FA")
CODE_BD     = HexColor("#DCE3EC")
CODE_INK    = HexColor("#1D2430")

TBL_HEAD    = NAVY
TBL_ZEBRA   = HexColor("#F4F7FB")
TBL_GRID    = HexColor("#D8DFE9")

# One colour per scan layer, reused by the diagrams so the coding is consistent
# document-wide. Chosen to stay distinguishable in greyscale by lightness.
LAYER = {
    "L1": HexColor("#0F6FA8"),   # blue
    "L2": HexColor("#7D3C98"),   # purple
    "L3": HexColor("#0E7C7B"),   # teal
    "L4": HexColor("#B45309"),   # amber-brown
    "L5": HexColor("#2E7D32"),   # green
    "L6": HexColor("#9A7B0A"),   # gold
}

# Callout kinds keyed by the leading word of a blockquote.
CALLOUT = {
    "note":     (HexColor("#EEF4FD"), HexColor("#2F6FBF"), "Note"),
    "tip":      (HexColor("#EFF8F0"), HexColor("#2E7D32"), "Tip"),
    "warning":  (HexColor("#FFF8E6"), HexColor("#C8860D"), "Warning"),
    "critical": (HexColor("#FDEDEC"), HexColor("#B03A2E"), "Critical"),
}

PASS_BG = HexColor("#E4F3E6")
FAIL_BG = HexColor("#FBE6E4")
WARN_BG = HexColor("#FFF6E2")


def make_styles():
    """All paragraph styles. Sizes tuned for a long procedural document."""
    return {
        "cover_title": ParagraphStyle(
            "cover_title", fontName=FONT_BOLD, fontSize=27, leading=32,
            textColor=HexColor("#FFFFFF"), alignment=TA_CENTER),
        "cover_sub": ParagraphStyle(
            "cover_sub", fontName=FONT_BODY, fontSize=13, leading=18,
            textColor=HexColor("#C9D8EC"), alignment=TA_CENTER),
        "cover_meta": ParagraphStyle(
            "cover_meta", fontName=FONT_BODY, fontSize=9, leading=15,
            textColor=MUTED, alignment=TA_CENTER),
        "cover_kicker": ParagraphStyle(
            "cover_kicker", fontName=FONT_BOLD, fontSize=8.5, leading=12,
            textColor=HexColor("#8FB0D9"), alignment=TA_CENTER),

        # H1/H2 names are load-bearing: GuideDoc.afterFlowable keys the TOC and
        # the running header off style.name.
        "H1": ParagraphStyle(
            "H1", fontName=FONT_BOLD, fontSize=16, leading=20,
            textColor=HexColor("#FFFFFF"), spaceBefore=0, spaceAfter=0),
        "H2": ParagraphStyle(
            "H2", fontName=FONT_BOLD, fontSize=11.5, leading=15,
            textColor=NAVY, spaceBefore=13, spaceAfter=4),
        "H3": ParagraphStyle(
            "H3", fontName=FONT_BOLD, fontSize=9.8, leading=13,
            textColor=HexColor("#33455C"), spaceBefore=9, spaceAfter=2),

        "body": ParagraphStyle(
            "body", fontName=FONT_BODY, fontSize=9.3, leading=13.8,
            textColor=INK, spaceAfter=6, alignment=TA_JUSTIFY),
        "bullet": ParagraphStyle(
            "bullet", fontName=FONT_BODY, fontSize=9.3, leading=13.6,
            textColor=INK, leftIndent=14, bulletIndent=4, spaceAfter=3),
        "caption": ParagraphStyle(
            "caption", fontName=FONT_ITAL, fontSize=8, leading=11,
            textColor=MUTED, alignment=TA_CENTER, spaceBefore=4, spaceAfter=10),
        "callout": ParagraphStyle(
            "callout", fontName=FONT_BODY, fontSize=8.8, leading=13,
            textColor=INK, spaceAfter=3),
        "callout_lbl": ParagraphStyle(
            "callout_lbl", fontName=FONT_BOLD, fontSize=7.5, leading=10,
            spaceAfter=3),
        "th": ParagraphStyle(
            "th", fontName=FONT_BOLD, fontSize=8.2, leading=11,
            textColor=HexColor("#FFFFFF")),
        "td": ParagraphStyle(
            "td", fontName=FONT_BODY, fontSize=8.2, leading=11.4, textColor=INK),
        "td_mono": ParagraphStyle(
            "td_mono", fontName=FONT_MONO, fontSize=7.4, leading=11, textColor=CODE_INK),
        "toc0": ParagraphStyle(
            "toc0", fontName=FONT_BOLD, fontSize=9.2, leading=15, textColor=NAVY),
        "toc1": ParagraphStyle(
            "toc1", fontName=FONT_BODY, fontSize=8.3, leading=12.4,
            leftIndent=16, textColor=HexColor("#3B4756")),
    }
