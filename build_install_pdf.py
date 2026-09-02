#!/usr/bin/env python3
"""Render a Markdown guide to an illustrated PDF.

    python3 build_install_pdf.py [source.md] [output.pdf]

Defaults to INSTALL.md -> AI_Transit_Pipeline_INSTALL.pdf.

Fixes carried over from the previous builder, each verified against the
rendered output rather than assumed:

  * Box-drawing characters (┌ ─ │ ┘) and → ▶ ✔ rendered as solid black squares,
    because the PDF base fonts cannot encode them. The §2 architecture diagram
    was destroyed by this. DejaVu is now used for all document text.
  * Every source line became its own Paragraph, so the PDF reproduced the
    markdown's 80-column source wrapping instead of reflowing, and any **bold**
    or `code` spanning a line break printed its literal markers. Consecutive
    lines are now joined into one paragraph before inline markup is applied.
  * {#anchor} suffixes were stripped from H2 only, so 15 leaked into the PDF.
  * Long shell lines overflowed the frame. Each code block is now auto-fitted to
    a size at which its longest line fits, leaving commands byte-identical.
  * No page numbers in the contents, and no running header naming the section.
"""
import os
import re
import sys
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                Spacer, Table, TableStyle, PageBreak,
                                KeepTogether, Flowable,
                                NextPageTemplate)
from reportlab.platypus.tableofcontents import TableOfContents

import pdf_theme as T

PAGE_W, PAGE_H = A4
MARGIN = 2.0 * cm
CONTENT_W = PAGE_W - 2 * MARGIN

T.register_fonts()
S = T.make_styles()

try:
    import install_figures
    FIGURES = install_figures.build_registry()
except Exception as exc:                                  # figures are optional
    FIGURES = {}
    if os.environ.get("PDF_DEBUG"):
        print(f"[warn] figures unavailable: {exc}", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# Inline markup
# ═══════════════════════════════════════════════════════════════════════════════
ANCHOR_RE = re.compile(r'\s*\{#[^}]+\}')


def strip_anchor(title: str) -> str:
    return ANCHOR_RE.sub('', title).strip()


def inline(text: str) -> str:
    """Markdown inline -> ReportLab markup.

    Code spans are lifted out before emphasis runs. Underscores are extremely
    common inside them (GITHUB_TOKEN, MAX_SIZE_MB); leaving them in scope lets
    the italic rule pair an underscore in one span with one in another and emit
    overlapping tags, which ReportLab rejects outright.
    """
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    spans = []

    def _stash(m):
        spans.append(m.group(1))
        return f"\x00C{len(spans) - 1}\x00"

    text = re.sub(r'`([^`]+?)`', _stash, text)

    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    text = re.sub(r'(?<!\*)\*([^*\n]+?)\*(?!\*)', r'<i>\1</i>', text)
    text = re.sub(r'(?<![\w\\])_([^_\n]+?)_(?!\w)', r'<i>\1</i>', text)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)

    def _restore(m):
        body = spans[int(m.group(1))]
        return (f'<font face="{T.FONT_MONO}" size="8" color="#1D2430">'
                f'{body}</font>')

    return re.sub(r'\x00C(\d+)\x00', _restore, text)


# ═══════════════════════════════════════════════════════════════════════════════
# Blocks
# ═══════════════════════════════════════════════════════════════════════════════
CODE_EM = 0.6          # DejaVuSansMono and Courier are both 0.6 em wide
CODE_MAX, CODE_MIN = 8.0, 5.8


def fit_code_size(lines, avail=CONTENT_W, pad=16.0) -> float:
    longest = max((len(l) for l in lines), default=0)
    if not longest:
        return CODE_MAX
    return max(CODE_MIN, min(CODE_MAX, (avail - pad) / (longest * CODE_EM)))


def CodeBlock(lines, avail=CONTENT_W):
    """Shell/code block, auto-fitted so no line overflows the frame."""
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return Spacer(1, 1)

    size = fit_code_size(lines, avail)
    style = T.ParagraphStyle(
        "code", fontName=T.FONT_MONO, fontSize=size, leading=size * 1.42,
        textColor=T.CODE_INK)

    def esc(l):
        return (l.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;").replace(" ", "&nbsp;")) or "&nbsp;"

    # One row per line so the block can break across a page boundary. A
    # single-cell table cannot split, and some listings here are taller than a
    # whole frame, which raises LayoutError and aborts the build.
    rows = [[Paragraph(esc(l), style)] for l in lines]
    tbl = Table(rows, colWidths=[avail], repeatRows=0)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), T.CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.6, T.CODE_BD),
        ("LINEBEFORE", (0, 0), (0, -1), 2.2, T.NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


CALLOUT_RE = re.compile(
    r'^\s*\*{0,2}(note|tip|warning|critical|important|caution)\b[:\*]*\s*',
    re.I)


def Callout(lines, avail=CONTENT_W):
    """A blockquote, styled by its opening keyword when it has one."""
    joined = " ".join(l.strip() for l in lines if l.strip())
    kind, label = "note", None
    m = CALLOUT_RE.match(joined)
    if m:
        word = m.group(1).lower()
        kind = {"important": "warning", "caution": "warning"}.get(word, word)
        if kind not in T.CALLOUT:
            kind = "note"
        label = T.CALLOUT[kind][2]
        joined = joined[m.end():]

    bg, accent, default_label = T.CALLOUT[kind]
    inner = []
    if label or kind != "note":
        lbl = T.ParagraphStyle("cl", parent=S["callout_lbl"], textColor=accent)
        inner.append(Paragraph((label or default_label).upper(), lbl))
    inner.append(Paragraph(inline(joined), S["callout"]))

    tbl = Table([[inner]], colWidths=[avail])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 2.6, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def SectionBanner(number: str, title: str, avail=CONTENT_W):
    """Full-width H1 banner. The Paragraph inside carries style name 'H1',
    which is what GuideDoc.afterFlowable keys the TOC and running header on."""
    label = f"{number}. {title}" if number else title
    p = Paragraph(inline(label), S["H1"])
    tbl = Table([[p]], colWidths=[avail])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), T.NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return tbl


def parse_table(rows, avail=CONTENT_W):
    """Render a GitHub-style markdown table."""
    cells = [[c.strip() for c in r.strip().strip('|').split('|')] for r in rows]
    if len(cells) < 2:
        return None
    header, body = cells[0], cells[2:]          # cells[1] is the --- separator
    ncol = len(header)
    body = [r + [''] * (ncol - len(r)) if len(r) < ncol else r[:ncol]
            for r in body]

    # Weight columns by the longest cell so wide prose columns get the room.
    widths = []
    for i in range(ncol):
        longest = max([len(header[i])] + [len(r[i]) for r in body] or [1])
        widths.append(max(longest, 6))
    total = sum(widths)
    col_w = [max(38.0, avail * w / total) for w in widths]
    scale = avail / sum(col_w)
    col_w = [w * scale for w in col_w]

    def cell(txt, style):
        mono = txt.startswith('`') and txt.endswith('`') and len(txt) > 2
        return Paragraph(inline(txt), S["td_mono"] if mono else style)

    data = [[Paragraph(inline(h), S["th"]) for h in header]]
    data += [[cell(c, S["td"]) for c in r] for r in body]

    tbl = Table(data, colWidths=col_w, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), T.TBL_HEAD),
        ("GRID", (0, 0), (-1, -1), 0.4, T.TBL_GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), T.TBL_ZEBRA))
    tbl.setStyle(TableStyle(style))
    return tbl


class HRule(Flowable):
    def __init__(self, width, colour=None, thickness=0.6):
        super().__init__()
        self.width, self.colour, self.thickness = width, colour or T.RULE, thickness

    def wrap(self, *_):
        return self.width, 6

    def draw(self):
        self.canv.setStrokeColor(self.colour)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 3, self.width, 3)


# ═══════════════════════════════════════════════════════════════════════════════
# Document
# ═══════════════════════════════════════════════════════════════════════════════
class GuideDoc(BaseDocTemplate):
    def __init__(self, filename, title, **kw):
        super().__init__(filename, pagesize=A4, leftMargin=MARGIN,
                         rightMargin=MARGIN, topMargin=2.4 * cm,
                         bottomMargin=1.9 * cm,
                         title=title, author="AI Transit Pipeline", **kw)
        self.doc_title = title
        self.section = ""
        frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 4.3 * cm, id='body')
        self.addPageTemplates([
            PageTemplate(id='cover', frames=[frame]),
            PageTemplate(id='main', frames=[frame], onPageEnd=self._furniture),
        ])

    def afterFlowable(self, flowable):
        style = getattr(flowable, 'style', None)
        name = getattr(style, 'name', '')
        if name not in ('H1', 'H2'):
            return
        try:
            text = flowable.getPlainText()
        except Exception:
            return
        if not text.strip() or text.strip().lower() == 'contents':
            return
        if name == 'H1':
            self.section = text
            self.notify('TOCEntry', (0, text, self.page))
        else:
            self.notify('TOCEntry', (1, text, self.page))

    def _furniture(self, canvas, doc):
        # onPageEnd, not onPage: onPage fires before this page's flowables are
        # laid out, so the header would name the previous section.
        canvas.saveState()
        y = PAGE_H - 1.45 * cm
        canvas.setFont(T.FONT_BODY, 7.2)
        canvas.setFillColor(T.MUTED)
        canvas.drawString(MARGIN, y, self.section[:74])
        canvas.drawRightString(PAGE_W - MARGIN, y, self.doc_title)
        canvas.setStrokeColor(T.RULE)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, y - 4.5, PAGE_W - MARGIN, y - 4.5)

        canvas.setFillColor(T.NAVY)
        canvas.rect(PAGE_W - MARGIN - 26, 1.15 * cm, 26, 12, stroke=0, fill=1)
        canvas.setFillColor(HexColor("#FFFFFF"))
        canvas.setFont(T.FONT_BOLD, 7.5)
        canvas.drawCentredString(PAGE_W - MARGIN - 13, 1.15 * cm + 3.4,
                                 str(doc.page))
        canvas.restoreState()


def cover(meta) -> list:
    title, subtitle, version, groups = meta
    band = Table([[Paragraph(title, S["cover_title"])],
                  [Spacer(1, 6)],
                  [Paragraph(subtitle, S["cover_sub"])]],
                 colWidths=[CONTENT_W])
    band.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), T.NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 30),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
        ("LEFTPADDING", (0, 0), (-1, -1), 24),
        ("RIGHTPADDING", (0, 0), (-1, -1), 24),
    ]))

    story = [Spacer(1, 62), band, Spacer(1, 26)]

    if groups:
        rows = [[Paragraph(f"<b>{k}</b>", S["td"]),
                 Paragraph(v, S["td_mono"])] for k, v in groups]
        t = Table(rows, colWidths=[CONTENT_W * 0.22, CONTENT_W * 0.78])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, T.RULE),
        ]))
        story += [Paragraph("COMPONENTS", S["cover_kicker"]), Spacer(1, 8), t]

    story += [
        Spacer(1, 30), HRule(CONTENT_W),
        Spacer(1, 10),
        Paragraph(f"Version {version} &nbsp;·&nbsp; "
                  f"{datetime.utcnow().strftime('%Y-%m-%d')}", S["cover_meta"]),
        Paragraph("6-layer security gateway for AI-generated repositories",
                  S["cover_meta"]),
        NextPageTemplate('main'),      # furniture starts on the page after this
        PageBreak(),
    ]
    return story


def read_meta(md: str):
    """Title, subtitle, version and the component list from the file header."""
    lines = md.split('\n')
    title = lines[0].lstrip('# ').strip() if lines else "Guide"
    subtitle, version, groups = "", "1.0", []
    for l in lines[1:24]:
        m = re.match(r'\*\*Version\s+([0-9.]+)\*\*', l.strip())
        if m:
            version = m.group(1)
            continue
        m = re.match(r'^(\w[\w\- ]*):\s+(.+)$', l.strip())
        if m and '`' in m.group(2):
            groups.append((m.group(1),
                           m.group(2).replace('`', '').replace(' · ', '  ·  ')))
    if ' — ' in title:
        title, subtitle = title.split(' — ', 1)
    return title, subtitle, version, groups


# ═══════════════════════════════════════════════════════════════════════════════
# Parser
# ═══════════════════════════════════════════════════════════════════════════════
H_RE = re.compile(r'^(#{1,4})\s+(.*)$')
NUM_RE = re.compile(r'^(\d+(?:\.\d+)?)\.\s+(.*)$')
BULLET_RE = re.compile(r'^(\s*)[-*+]\s+(.*)$')
OLIST_RE = re.compile(r'^\s*(\d+)\.\s+(.*)$')


def md_to_story(md: str, toc) -> list:
    lines = md.split('\n')
    n = len(lines)
    story, para_buf = [], []

    # Skip the front matter: the title, version and component lines are already
    # rendered on the cover, and repeating them as body text at the top of the
    # first section reads like a mistake. Start at the first H2.
    i = 0
    for j, l in enumerate(lines):
        if l.startswith('## '):
            i = j
            break
    seen_first_h1 = True

    def flush_para():
        """Join buffered lines into ONE paragraph.

        The previous builder emitted a Paragraph per source line, so the PDF
        reproduced the markdown's source wrapping and any bold or code span
        crossing a newline printed its literal markers.
        """
        if not para_buf:
            return
        text = " ".join(x.strip() for x in para_buf).strip()
        para_buf.clear()
        if text:
            story.append(Paragraph(inline(text), S["body"]))

    guard = 0
    while i < n:
        # A branch that forgets to advance i turns the parser into an infinite
        # loop that looks like a hang rather than an error. Fail loudly instead.
        guard += 1
        if guard > 10 * n + 1000:
            raise RuntimeError(
                f"parser made no progress near line {i}: {lines[i][:80]!r}")
        line = lines[i]
        stripped = line.strip()

        # Headings ────────────────────────────────────────────────────────────
        m = H_RE.match(line)
        if m:
            flush_para()
            level, raw = len(m.group(1)), strip_anchor(m.group(2))
            if level == 1:
                if not seen_first_h1:       # document title, already on cover
                    seen_first_h1 = True
                    i += 1
                    continue
                story.append(Paragraph(inline(raw), S["H2"]))
            elif level == 2:
                if raw.lower().startswith('table of contents'):
                    # Replaced by the generated TOC; skip the hand-written list.
                    i += 1
                    while i < n and not H_RE.match(lines[i]):
                        i += 1
                    continue
                nm = NUM_RE.match(raw)
                number, title = (nm.group(1), nm.group(2)) if nm else ("", raw)
                story.append(Spacer(1, 12))
                story.append(KeepTogether([SectionBanner(number, title),
                                           Spacer(1, 8)]))
                for fn, cap in FIGURES.get(strip_anchor(raw), []):
                    story.extend(figure_flowables(fn, cap))
            elif level == 3:
                story.append(Paragraph(inline(raw), S["H2"]))
                for fn, cap in FIGURES.get(strip_anchor(raw), []):
                    story.extend(figure_flowables(fn, cap))
            else:
                story.append(Paragraph(inline(raw), S["H3"]))
            i += 1
            continue

        # Fenced code ─────────────────────────────────────────────────────────
        if stripped.startswith('```'):
            flush_para()
            i += 1
            buf = []
            while i < n and not lines[i].strip().startswith('```'):
                buf.append(lines[i])
                i += 1
            i += 1
            if buf:
                story.append(Spacer(1, 3))
                story.append(CodeBlock(buf))
                story.append(Spacer(1, 7))
            continue

        # Blockquote ──────────────────────────────────────────────────────────
        if stripped.startswith('>'):
            flush_para()
            buf = []
            while i < n and lines[i].strip().startswith('>'):
                buf.append(lines[i].strip().lstrip('>').strip())
                i += 1
            story.append(Spacer(1, 3))
            story.append(Callout(buf))
            story.append(Spacer(1, 8))
            continue

        # Table ───────────────────────────────────────────────────────────────
        if stripped.startswith('|') and i + 1 < n and \
                re.match(r'^\s*\|[\s:|-]+\|\s*$', lines[i + 1]):
            flush_para()
            buf = []
            while i < n and lines[i].strip().startswith('|'):
                buf.append(lines[i])
                i += 1
            tbl = parse_table(buf)
            if tbl is not None:
                story.append(Spacer(1, 4))
                story.append(tbl)
                story.append(Spacer(1, 9))
            continue

        # Horizontal rule ─────────────────────────────────────────────────────
        if re.match(r'^\s*(-{3,}|\*{3,}|_{3,})\s*$', line):
            flush_para()
            story.append(Spacer(1, 5))
            i += 1                 # without this the first --- loops forever
            continue

        # Lists ───────────────────────────────────────────────────────────────
        bm = BULLET_RE.match(line)
        if bm:
            flush_para()
            depth = len(bm.group(1)) // 2
            st = T.ParagraphStyle(f"b{depth}", parent=S["bullet"],
                                  leftIndent=14 + depth * 12,
                                  bulletIndent=4 + depth * 12)
            story.append(Paragraph(inline(bm.group(2)), st, bulletText="•"))
            i += 1
            continue

        om = OLIST_RE.match(line)
        if om and not H_RE.match(line):
            flush_para()
            story.append(Paragraph(inline(om.group(2)), S["bullet"],
                                   bulletText=f"{om.group(1)}."))
            i += 1
            continue

        # Blank line ends a paragraph ─────────────────────────────────────────
        if not stripped:
            flush_para()
            i += 1
            continue

        para_buf.append(line)
        i += 1

    flush_para()
    return story


def figure_flowables(fn, caption):
    """Render one figure, skipping it if it raises rather than losing the build."""
    try:
        flow = fn(CONTENT_W)
    except Exception as exc:
        if os.environ.get("PDF_DEBUG"):
            print(f"[warn] figure failed: {exc}", file=sys.stderr)
        return []
    out = [Spacer(1, 6), flow]
    if caption:
        out.append(Paragraph(caption, S["caption"]))
    else:
        out.append(Spacer(1, 8))
    return out


# ═══════════════════════════════════════════════════════════════════════════════
def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "INSTALL.md"
    out = sys.argv[2] if len(sys.argv) > 2 else "AI_Transit_Pipeline_INSTALL.pdf"

    md = open(src, encoding="utf-8").read()
    meta = read_meta(md)
    title, subtitle, version, _ = meta
    doc_title = f"{title} — {subtitle}" if subtitle else title

    print(f"Parsing {src} …")
    doc = GuideDoc(out, doc_title)

    toc = TableOfContents()
    toc.levelStyles = [S["toc0"], S["toc1"]]

    story = cover(meta)
    story += [Paragraph("Contents", S["H2"]), Spacer(1, 6), HRule(CONTENT_W),
              Spacer(1, 8), toc, PageBreak()]
    story += md_to_story(md, toc)

    print(f"Building PDF … ({len(FIGURES)} figure slot(s), "
          f"fonts: {'DejaVu' if T.HAS_DEJAVU else 'base'})")
    # multiBuild runs the passes needed to resolve TOC page numbers.
    doc.multiBuild(story)

    kb = os.path.getsize(out) // 1024
    print(f"[OK] {out}  ({kb} KB)")


if __name__ == "__main__":
    main()
