#!/usr/bin/env python3
"""
Converts INSTALL.md to a formatted PDF using ReportLab.
Usage: python3 build_install_pdf.py [INSTALL.md] [output.pdf]
"""

import re
import sys
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether, PageBreak, Preformatted
    )
    from reportlab.platypus.flowables import Flowable
    from reportlab.lib.utils import simpleSplit
except ImportError:
    print("ERROR: pip install reportlab", file=sys.stderr)
    sys.exit(1)

pt = 1

# ── Palette ───────────────────────────────────────────────────────────────────
C_NAVY      = colors.HexColor("#1F3864")
C_DARK      = colors.HexColor("#2E4057")
C_BLUE_LT   = colors.HexColor("#D9E1F2")
C_CODE_BG   = colors.HexColor("#F4F4F4")
C_CODE_BD   = colors.HexColor("#CCCCCC")
C_QUOTE_BG  = colors.HexColor("#EEF3FB")
C_QUOTE_BD  = colors.HexColor("#4472C4")
C_HDR_TBL   = colors.HexColor("#1F3864")
C_ROW_ALT   = colors.HexColor("#F2F5FC")
C_TEXT      = colors.HexColor("#1A1A1A")
C_SUBTEXT   = colors.HexColor("#444444")
C_WHITE     = colors.white
C_BORDER    = colors.HexColor("#BBBBBB")
C_PASS      = colors.HexColor("#C6EFCE")
C_FAIL      = colors.HexColor("#FFC7CE")

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CONTENT_W = PAGE_W - 2 * MARGIN

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = dict(fontName="Helvetica", textColor=C_TEXT, leading=14)
    mono = dict(fontName="Courier",   textColor=C_TEXT)
    return {
        "h1": ParagraphStyle("h1", fontSize=20, fontName="Helvetica-Bold",
                              textColor=C_WHITE, alignment=TA_CENTER,
                              spaceBefore=0, spaceAfter=6),
        "h1sub": ParagraphStyle("h1sub", fontSize=10, fontName="Helvetica",
                                 textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=0),
        "h2": ParagraphStyle("h2", fontSize=14, fontName="Helvetica-Bold",
                              textColor=C_WHITE, spaceBefore=4, spaceAfter=4),
        "h3": ParagraphStyle("h3", fontSize=11, fontName="Helvetica-Bold",
                              textColor=C_NAVY, spaceBefore=8*pt, spaceAfter=3*pt),
        "body": ParagraphStyle("body", fontSize=9, **base),
        "bullet": ParagraphStyle("bullet", fontSize=9, leading=13,
                                  leftIndent=14*pt, firstLineIndent=-10*pt,
                                  fontName="Helvetica", textColor=C_TEXT),
        "subbullet": ParagraphStyle("subbullet", fontSize=9, leading=13,
                                     leftIndent=26*pt, firstLineIndent=-10*pt,
                                     fontName="Helvetica", textColor=C_TEXT),
        "code": ParagraphStyle("code", fontSize=7.5, leading=11,
                                leftIndent=8*pt, rightIndent=4*pt,
                                fontName="Courier", textColor=C_TEXT),
        "quote": ParagraphStyle("quote", fontSize=8.5, leading=13,
                                 leftIndent=12*pt, fontName="Helvetica-Oblique",
                                 textColor=C_SUBTEXT),
        "toc_h": ParagraphStyle("toc_h", fontSize=9, fontName="Helvetica-Bold",
                                  textColor=C_NAVY, spaceBefore=2, spaceAfter=2),
        "toc_i": ParagraphStyle("toc_i", fontSize=8.5, fontName="Helvetica",
                                  textColor=C_SUBTEXT, leftIndent=10*pt,
                                  spaceBefore=1, spaceAfter=1),
        "footer": ParagraphStyle("footer", fontSize=7, fontName="Helvetica",
                                  textColor=colors.HexColor("#888888"),
                                  alignment=TA_CENTER),
        "th": ParagraphStyle("th", fontSize=8.5, fontName="Helvetica-Bold",
                               textColor=C_WHITE),
        "td": ParagraphStyle("td", fontSize=8.5, fontName="Helvetica",
                               textColor=C_TEXT, leading=12),
        "tdmono": ParagraphStyle("tdmono", fontSize=7.8, fontName="Courier",
                                  textColor=C_TEXT, leading=11),
    }

S = make_styles()


# ── Inline markup ─────────────────────────────────────────────────────────────
def inline(text: str) -> str:
    """Convert inline Markdown (bold, inline code, escapes) to ReportLab XML."""
    # Escape XML special chars first (except ones we'll add)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Pull `inline code` out before any emphasis runs. Underscores are
    # extremely common inside code spans (GITHUB_TOKEN, GIT_ASKPASS,
    # MAX_SIZE_MB); leaving them in scope lets the italic rule pair an
    # underscore in one span with one in another and emit overlapping tags
    # like GITHUB<i>TOKEN … GIT</i>ASKPASS, which ReportLab rejects outright.
    code_spans: list[str] = []

    def _stash(m: "re.Match") -> str:
        code_spans.append(m.group(1))
        return f"\x00CODE{len(code_spans) - 1}\x00"

    text = re.sub(r'`([^`]+?)`', _stash, text)

    # **bold** or __bold__
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__',     r'<b>\1</b>', text)
    # *italic*
    text = re.sub(r'\*([^*]+?)\*',  r'<i>\1</i>', text)
    # _italic_ — only at word boundaries, so snake_case identifiers outside
    # code spans are still left alone.
    text = re.sub(r'(?<![\w\\])_([^_]+?)_(?!\w)', r'<i>\1</i>', text)

    # [text](url) — strip links, keep text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)

    # Restore code spans as monospace runs.
    def _restore(m: "re.Match") -> str:
        return (f'<font face="Courier" size="8">'
                f'{code_spans[int(m.group(1))]}</font>')

    text = re.sub(r'\x00CODE(\d+)\x00', _restore, text)
    return text


# ── Code block ────────────────────────────────────────────────────────────────
def CodeBlock(lines: list[str], width: float = CONTENT_W) -> Table:
    """One row per code line so ReportLab can split across pages."""
    code_style = ParagraphStyle(
        "cb", fontName="Courier", fontSize=7.5, leading=11,
        textColor=C_TEXT,
    )
    rows = []
    for line in lines:
        safe = (line.replace("\t", "    ")
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))
        rows.append([Paragraph(safe or " ", code_style)])

    tbl = Table(rows, colWidths=[width - 4])
    nrows = len(rows)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_CODE_BG),
        ("BOX",          (0,0), (-1,-1), 0.5, C_CODE_BD),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",   (0,0), (-1,-1), 1),
        ("BOTTOMPADDING",(0,0), (-1,-1), 1),
        ("TOPPADDING",   (0,0), (0,0), 5),
        ("BOTTOMPADDING",(0,nrows-1), (0,nrows-1), 5),
        ("LINEBEFORE",   (0,0), (0,-1), 3, C_NAVY),
    ]))
    return tbl


# ── Quote block ───────────────────────────────────────────────────────────────
def QuoteBlock(paragraphs: list[Paragraph], width: float = CONTENT_W) -> Table:
    """Blockquote — one row per paragraph so the table can split."""
    rows = [[p] for p in paragraphs]
    tbl = Table(rows, colWidths=[width - 4])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_QUOTE_BG),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("LINEBEFORE",   (0,0), (0,-1), 4, C_QUOTE_BD),
        ("LEFTPADDING",  (0,0), (-1,-1), 12),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
    ]))
    return tbl


# ── Section header banner ─────────────────────────────────────────────────────
def section_banner(title: str) -> Table:
    tbl = Table([[Paragraph(title, S["h2"])]], colWidths=[CONTENT_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("BOX", (0,0), (-1,-1), 0, C_NAVY),
    ]))
    return tbl


# ── Markdown table parser ─────────────────────────────────────────────────────
def parse_md_table(lines: list[str]) -> Table | None:
    """Parse a Markdown pipe table into a ReportLab Table."""
    rows = []
    for line in lines:
        if re.match(r'^\s*\|?[-:| ]+\|?\s*$', line):
            continue  # separator row
        cells = [c.strip() for c in re.split(r'(?<!\\)\|', line.strip('| \t'))]
        if not cells:
            continue
        rows.append(cells)

    if len(rows) < 1:
        return None

    # Determine column count and width distribution
    ncols = max(len(r) for r in rows)
    # Pad short rows
    rows = [r + [""] * (ncols - len(r)) for r in rows]
    col_w = CONTENT_W / ncols

    table_data = []
    for ri, row in enumerate(rows):
        style = S["th"] if ri == 0 else S["td"]
        # Use mono style for cells that look like commands/paths
        cells_out = []
        for cell in row:
            if re.search(r'[`/\\]', cell) and ri > 0:
                p = Paragraph(inline(cell), S["tdmono"])
            else:
                p = Paragraph(inline(cell), style)
            cells_out.append(p)
        table_data.append(cells_out)

    tbl = Table(table_data, colWidths=[col_w] * ncols, repeatRows=1)
    ts = TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), C_HDR_TBL),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ("LEFTPADDING",  (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, C_BORDER),
    ])
    for i in range(1, len(rows)):
        if i % 2 == 0:
            ts.add("BACKGROUND", (0,i), (-1,i), C_ROW_ALT)
    tbl.setStyle(ts)
    return tbl


# ── Cover page ────────────────────────────────────────────────────────────────
def cover_page(version: str = "2.0") -> list:
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d")

    banner = Table(
        [[Paragraph("AI Transit Pipeline", S["h1"])],
         [Paragraph("Installation Guide", S["h1"])],
         [Paragraph(f"Version {version}  ·  {now}", S["h1sub"])]],
        colWidths=[CONTENT_W]
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_DARK),
        ("TOPPADDING", (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
        ("LEFTPADDING", (0,0), (-1,-1), 20),
        ("RIGHTPADDING", (0,0), (-1,-1), 20),
    ]))

    scope = Table([[Paragraph(
        "Applicable to: <font face='Courier' size='8'>fetch_repo.sh  ·  scan_pipeline.sh  ·  "
        "ai_transit.sh  ·  generate_excel_report.py  ·  selfcheck.py</font>",
        ParagraphStyle("scope", fontSize=9, fontName="Helvetica",
                       textColor=C_SUBTEXT, alignment=TA_CENTER)
    )]], colWidths=[CONTENT_W])
    scope.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_BLUE_LT),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("BOX", (0,0), (-1,-1), 0.5, C_BORDER),
    ]))

    return [banner, Spacer(1, 10*pt), scope, PageBreak()]


# ── Main parser ───────────────────────────────────────────────────────────────
def md_to_story(md_text: str) -> list:
    story = []
    lines = md_text.splitlines()
    i = 0
    n = len(lines)

    # Skip leading YAML / title block (first H1 becomes the cover)
    first_h1_done = False

    while i < n:
        line = lines[i]

        # ── Skip pure horizontal rules at top level (we generate our own)
        if re.match(r'^---+\s*$', line):
            i += 1
            continue

        # ── H1
        if line.startswith("# ") and not first_h1_done:
            first_h1_done = True
            story.extend(cover_page())
            i += 1
            continue

        # ── Version subtitle under H1 (bold line)
        if line.startswith("**Version"):
            i += 1
            continue

        # ── Table of Contents header
        if line.strip() in ("## Table of Contents", "## Table of contents"):
            story.append(section_banner("Table of Contents"))
            story.append(Spacer(1, 6*pt))
            i += 1
            # Collect TOC lines until next blank + heading
            toc_items = []
            while i < n and not lines[i].startswith("## ") and not re.match(r'^---', lines[i]):
                tl = lines[i].strip()
                if re.match(r'^\d+\.', tl):
                    # top-level item
                    label = re.sub(r'^\d+\.\s*\[(.+?)\]\(.*?\)', r'\1', tl)
                    label = re.sub(r'^\d+\.\s*', '', label)
                    toc_items.append(Paragraph(f"• {inline(label)}", S["toc_h"]))
                elif tl.startswith("-"):
                    label = re.sub(r'^-\s*\[(.+?)\]\(.*?\)', r'\1', tl)
                    label = re.sub(r'^-\s*', '', label)
                    toc_items.append(Paragraph(f"  – {inline(label)}", S["toc_i"]))
                i += 1
            if toc_items:
                story.extend(toc_items)
            story.append(Spacer(1, 10*pt))
            continue

        # ── H2
        if line.startswith("## "):
            title = line[3:].strip()
            # Strip anchor suffixes like {#self-scan}
            title = re.sub(r'\s*\{#[^}]+\}', '', title)
            story.append(Spacer(1, 14*pt))
            story.append(KeepTogether([section_banner(title), Spacer(1, 6*pt)]))
            i += 1
            continue

        # ── H3
        if line.startswith("### "):
            title = line[4:].strip()
            story.append(Spacer(1, 8*pt))
            story.append(Paragraph(inline(title), S["h3"]))
            story.append(Spacer(1, 2*pt))
            i += 1
            continue

        # ── H4
        if line.startswith("#### "):
            title = line[5:].strip()
            story.append(Paragraph(f"<b>{inline(title)}</b>", S["body"]))
            i += 1
            continue

        # ── Fenced code block
        if line.strip().startswith("```"):
            i += 1
            code_lines = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # closing ```
            if code_lines:
                story.append(Spacer(1, 4*pt))
                story.append(CodeBlock(code_lines))
                story.append(Spacer(1, 6*pt))
            continue

        # ── Markdown table
        if "|" in line and i + 1 < n and re.match(r'^\s*\|?[-:| ]+\|?\s*$', lines[i+1]):
            table_lines = []
            while i < n and "|" in lines[i]:
                table_lines.append(lines[i])
                i += 1
            tbl = parse_md_table(table_lines)
            if tbl:
                story.append(Spacer(1, 4*pt))
                story.append(tbl)
                story.append(Spacer(1, 6*pt))
            continue

        # ── Blockquote
        if line.startswith("> "):
            quote_lines = []
            while i < n and lines[i].startswith("> "):
                quote_lines.append(lines[i][2:])
                i += 1
            paras = []
            for ql in quote_lines:
                if ql.startswith("```"):
                    continue  # skip nested code in quotes
                if ql.strip():
                    paras.append(Paragraph(inline(ql), S["quote"]))
            if paras:
                story.append(Spacer(1, 4*pt))
                story.append(QuoteBlock(paras))
                story.append(Spacer(1, 6*pt))
            continue

        # ── Bullet list
        bullet_match = re.match(r'^(\s*)([-*])\s+(.*)', line)
        if bullet_match:
            indent_len = len(bullet_match.group(1))
            style = S["subbullet"] if indent_len >= 2 else S["bullet"]
            story.append(Paragraph(f"• {inline(bullet_match.group(3))}", style))
            i += 1
            continue

        # ── Numbered list
        num_match = re.match(r'^(\s*)\d+\.\s+(.*)', line)
        if num_match:
            indent_len = len(num_match.group(1))
            style = S["subbullet"] if indent_len >= 2 else S["bullet"]
            story.append(Paragraph(f"{inline(num_match.group(2))}", style))
            i += 1
            continue

        # ── Blank line → small spacer
        if not line.strip():
            story.append(Spacer(1, 5*pt))
            i += 1
            continue

        # ── Regular paragraph
        story.append(Paragraph(inline(line.strip()), S["body"]))
        i += 1

    return story


# ── Page template ─────────────────────────────────────────────────────────────
class DocTemplate(SimpleDocTemplate):
    def __init__(self, filename, **kw):
        super().__init__(filename, **kw)
        self._page_num = 0

    def handle_pageBegin(self):
        super().handle_pageBegin()
        self._page_num += 1

    def afterPage(self):
        canvas = self.canv
        canvas.saveState()
        # Footer bar
        canvas.setFillColor(C_DARK)
        canvas.rect(MARGIN, 1.0*cm, PAGE_W - 2*MARGIN, 0.5*cm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(MARGIN + 4, 1.15*cm,
                          "AI Transit Pipeline — Installation Guide v2.0")
        canvas.drawRightString(PAGE_W - MARGIN - 4, 1.15*cm,
                               f"Page {self._page_num}")
        canvas.restoreState()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    md_path  = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("INSTALL.md")
    pdf_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("AI_Transit_Pipeline_INSTALL.pdf")

    if not md_path.exists():
        print(f"[ERROR] {md_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing {md_path} …")
    text = md_path.read_text(encoding="utf-8")

    story = md_to_story(text)

    print(f"Building PDF …")
    doc = DocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=2.0*cm, bottomMargin=2.0*cm,
        title="AI Transit Pipeline — Installation Guide",
        author="AI Transit Pipeline",
    )
    doc.build(story)
    size_kb = pdf_path.stat().st_size // 1024
    print(f"[OK] {pdf_path}  ({size_kb} KB)")


if __name__ == "__main__":
    main()
