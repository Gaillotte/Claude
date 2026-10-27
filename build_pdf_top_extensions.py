#!/usr/bin/env python3
"""Top 40 file extensions for scanning Claude Code projects  ->  PDF.

    python3 build_pdf_top_extensions.py [top40_extensions_data.json] [out.pdf]

The data file holds the evidence gathered per source and the three scores given to each
candidate extension. The ranking is computed here, not stored, so changing a weight or a
score changes the ranking and nothing else has to be edited:

    score = W_AGENT * agent_score + W_BASELINE * baseline_score + W_STRUCTURAL * structural_score

How each extension is treated by the pipeline today is read from build_pdf_filetypes.FAMILIES,
which build_pdf_filetypes.py --check keeps equal to classify_file() in scan_pipeline.sh.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

HERE = Path(__file__).resolve().parent
DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "top40_extensions_data.json"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "AI_Transit_Pipeline_Top40_Extensions.pdf"

W_AGENT, W_BASELINE, W_STRUCTURAL = 0.5, 0.3, 0.2
TOP_N = 40

NAVY = colors.HexColor("#14213D")
ACCENT = colors.HexColor("#B83A0C")
GOLD = colors.HexColor("#F2C94C")
PAPER = colors.HexColor("#F7F5EF")
RULE = colors.HexColor("#D9D3C3")
MUTED = colors.HexColor("#5E6670")
GREEN = colors.HexColor("#DCEFE0")
AMBER = colors.HexColor("#FBEBC8")
RED = colors.HexColor("#F6D5CF")


# ── fonts ─────────────────────────────────────────────────────────────────────
def register_fonts() -> tuple[str, str, str]:
    base = Path("/usr/share/fonts/truetype/dejavu")
    try:
        pdfmetrics.registerFont(TTFont("DejaVu", str(base / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(base / "DejaVuSans-Bold.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVuMono", str(base / "DejaVuSansMono.ttf")))
        pdfmetrics.registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold",
                                      italic="DejaVu", boldItalic="DejaVu-Bold")
        return "DejaVu", "DejaVu-Bold", "DejaVuMono"
    except Exception:
        return "Helvetica", "Helvetica-Bold", "Courier"


F, FB, FM = register_fonts()


def style(name: str, **kw) -> ParagraphStyle:
    kw.setdefault("fontName", F)
    kw.setdefault("fontSize", 9)
    kw.setdefault("leading", kw["fontSize"] * 1.35)
    kw.setdefault("alignment", TA_LEFT)
    return ParagraphStyle(name, **kw)


S_TITLE = style("title", fontName=FB, fontSize=26, leading=31, textColor=NAVY)
S_H1 = style("h1", fontName=FB, fontSize=16, leading=20, textColor=NAVY, spaceBefore=4, spaceAfter=6)
S_H2 = style("h2", fontName=FB, fontSize=11, leading=14, textColor=ACCENT, spaceBefore=8, spaceAfter=3)
S_BODY = style("body", fontSize=9.5, leading=13.5, spaceAfter=5)
S_SMALL = style("small", fontSize=8, leading=10.5, textColor=MUTED)
S_CELL = style("cell", fontSize=7.6, leading=9.6)
S_CELLB = style("cellb", fontName=FB, fontSize=7.6, leading=9.6)
S_MONO = style("mono", fontName=FM, fontSize=7.6, leading=9.6)
S_HEAD = style("head", fontName=FB, fontSize=7.6, leading=9.6, textColor=colors.white)
S_BOX = style("box", fontSize=9.5, leading=13.5)


def P(text: str, st: ParagraphStyle = S_BODY) -> Paragraph:
    return Paragraph(escape(str(text)), st)


def PR(markup: str, st: ParagraphStyle = S_BODY) -> Paragraph:
    """Paragraph from markup that this script wrote itself (tags allowed)."""
    return Paragraph(markup, st)


# ── what the pipeline does with an extension today ────────────────────────────
def load_families() -> list[dict]:
    spec = importlib.util.spec_from_file_location("ft", HERE / "build_pdf_filetypes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FAMILIES


FAMILIES = load_families()
EXT_TO_FAMILY = {e: f for f in FAMILIES for e in f.get("ext", [])}
INLINE = "classify_file (inline rule)"


def coverage(ext: str) -> tuple[str, str]:
    """(tier, label): dedicated scanner, credential grep only, or the generic fallback."""
    fam = EXT_TO_FAMILY.get(ext)
    if fam is None:
        return "generic", "generic (scan_unknown)"
    if fam["scanner"] == INLINE:
        return "basic", "credential grep only"
    return "dedicated", fam["scanner"]


TIER_COLOUR = {"dedicated": GREEN, "basic": AMBER, "generic": RED}


# ── data and ranking ──────────────────────────────────────────────────────────
def load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def ranked(cands: list[dict]) -> list[dict]:
    out = []
    for c in cands:
        s = (W_AGENT * c["agent_score"] + W_BASELINE * c["baseline_score"]
             + W_STRUCTURAL * c["structural_score"])
        out.append({**c, "score": round(s, 1)})
    out.sort(key=lambda c: (-c["score"], -c["structural_score"], c["ext"]))
    for i, c in enumerate(out, 1):
        c["rank"] = i
    return out


# ── page furniture ────────────────────────────────────────────────────────────
def on_page(canvas, doc) -> None:
    canvas.saveState()
    w, h = doc.pagesize
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 9 * mm, w, 9 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont(FB, 8)
    canvas.drawString(14 * mm, h - 6 * mm, "AI Transit Pipeline  ·  Top 40 file extensions for Claude Code projects")
    canvas.setFillColor(MUTED)
    canvas.setFont(F, 8)
    canvas.drawRightString(w - 14 * mm, 7 * mm, f"Page {doc.page}")
    canvas.drawString(14 * mm, 7 * mm, "Evidence-weighted estimate, not Anthropic telemetry (see \"How the ranking is built\")")
    canvas.restoreState()


def table(rows, widths, head_rows=1, extra=None) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=head_rows)
    st = [
        ("BACKGROUND", (0, 0), (-1, head_rows - 1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, head_rows), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    t.setStyle(TableStyle(st + (extra or [])))
    return t


def box(flowables, fill=PAPER, border=RULE, width=None) -> Table:
    t = Table([[flowables]], colWidths=[width] if width else None)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), fill),
        ("BOX", (0, 0), (-1, -1), 0.8, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


# ── sections ──────────────────────────────────────────────────────────────────
def cut(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def short_source(url: str, title: str) -> str:
    host = urlparse(url).netloc.replace("www.", "") if url else ""
    t = (title or "").strip()
    return f"{t[:54]}{'…' if len(t) > 54 else ''} ({host})" if host else t


def build_story(data: dict, usable_w: float) -> list:
    cands = ranked(data["candidates"])
    top = cands[:TOP_N]
    rest = cands[TOP_N:100]
    ev = data.get("evidence", {})
    n_find = sum(len(s.get("findings", [])) for s in ev.values())
    n_read = sum(1 for s in ev.values() for f in s.get("findings", []) if f.get("fetched"))
    tiers = {"dedicated": 0, "basic": 0, "generic": 0}
    for c in top:
        tiers[coverage(c["ext"])[0]] += 1
    top10 = top[:10]
    top10_basic = [c["ext"] for c in top10 if coverage(c["ext"])[0] == "basic"]
    top10_generic = [c["ext"] for c in top10 if coverage(c["ext"])[0] == "generic"]

    story: list = []

    # 1 ── cover and the answer
    story += [
        P("Top 40 file extensions to support", S_TITLE),
        P("for projects generated by Claude Code", style("sub", fontSize=14, leading=18, textColor=ACCENT)),
        Spacer(1, 2 * mm),
        P(f"Generated {data.get('generated', '')}  ·  scored from {n_find} sourced findings in 5 evidence streams, "
          f"weights {W_AGENT:g} / {W_BASELINE:g} / {W_STRUCTURAL:g}", S_SMALL),
        Spacer(1, 3 * mm),
        box([PR("<b>Read this first.</b> Anthropic does not publish how often Claude Code writes each file extension, "
                "and this report does not pretend otherwise. What follows is a <b>transparent estimate</b>: every "
                "candidate extension gets three scores, the ranking is computed from them with fixed weights, and "
                "each score names the evidence it rests on or says that it is a judgement. "
                f"Of the {n_find} findings gathered, {n_read} were read on the page itself and the rest are search-result "
                "text. The only published per-file-type counts for Claude Code output (a 790-commit sample: Markdown, "
                "TypeScript, XML, JSON and Python lead) come from one paper that could not be opened from the sandbox "
                "and were not reproduced by a later search; treat them as indicative. The one fully read Claude Code "
                "usage dataset gives <i>repository languages</i>, not extensions. For real numbers about <i>your</i> "
                "projects, use the measurement steps on the last pages.", S_BOX)], fill=colors.HexColor("#FFF6DD"), border=GOLD, width=usable_w),
        Spacer(1, 2 * mm),
        P("Key findings", S_H1),
        PR("•&nbsp;&nbsp;<b>Top five:</b> " + ", ".join(c["ext"] for c in top[:5]) + ". Scores within about 10 points of each other "
           "should not be read as a strict order.", S_BODY),
        PR(f"•&nbsp;&nbsp;<b>The two most common types get the thinnest analysis.</b> Of the top ten, {len(top10_basic)} "
           f"({' '.join(top10_basic) or 'none'}) receive a credential grep only"
           + (f" and {len(top10_generic)} ({' '.join(top10_generic)}) the generic fallback" if top10_generic else "") + ".", S_BODY),
        PR("•&nbsp;&nbsp;<b>The strongest Claude Code signals are file names, not extensions:</b> CLAUDE.md, SKILL.md, .mcp.json and "
           ".claude/settings.json. They carry prompt text, server launch commands and hooks, yet sit under .md and .json, and "
           "classify_file() routes only package.json, composer.json and a few other names by basename (see \"What this means for the pipeline\").", S_BODY),
        PR("•&nbsp;&nbsp;<b>Prevalence is not risk.</b> Rare but dangerous types (.pkl, .exe, .jar, .docm, .xlsm, .pem, .env) rank "
           "low here by design; rank them with a separate risk weight.", S_BODY),
        P("Where the pipeline stands today", S_H1),
        P(f"Of the top {TOP_N}, {tiers['dedicated']} extensions already have a dedicated per-type scanner, "
          f"{tiers['basic']} get a credential grep only, and {tiers['generic']} fall to the generic fallback "
          "(universal patterns, secrets, antivirus and licence layers, but no per-type analysis).", S_BODY),
    ]
    summ = [[P(x, S_HEAD) for x in ("Treatment today", "Extensions in the top 40", "Meaning")]]
    for key, label, mean in (
            ("dedicated", "Dedicated scanner", "its own rules in layer 5, plus layers 1, 4 and 6"),
            ("basic", "Credential grep only", "classify_file() has an inline rule and no per-type scanner"),
            ("generic", "Generic fallback", "scan_unknown(): shebang or MIME check, plus layers 1, 4 and 6")):
        exts = " ".join(c["ext"] for c in top if coverage(c["ext"])[0] == key) or "none"
        summ.append([P(label, S_CELLB), P(f"{sum(1 for c in top if coverage(c['ext'])[0] == key)}:  {exts}", S_MONO), P(mean, S_CELL)])
    story.append(table(summ, [38 * mm, usable_w - 38 * mm - 62 * mm, 62 * mm], extra=[
        ("BACKGROUND", (0, 1), (0, 1), GREEN), ("BACKGROUND", (0, 2), (0, 2), AMBER), ("BACKGROUND", (0, 3), (0, 3), RED)]))
    story.append(PageBreak())

    # 2 ── method
    story += [
        P("How the ranking is built", S_H1),
        P("Each candidate extension is scored 0 to 100 on three axes. The scores come from the evidence in the data "
          "file; where no number exists the rationale says the score is a judgement.", S_BODY),
    ]
    axes = [[P(x, S_HEAD) for x in ("Axis", "Weight", "Question it answers", "Main sources")],
            [P("agent_score", S_MONO), P(f"{W_AGENT:g}", S_CELLB),
             P("How common is it in code written by AI coding agents, and Claude Code in particular?", S_CELL),
             P("Anthropic publications; studies of agent-authored pull requests; Claude Code share analyses", S_CELL)],
            [P("baseline_score", S_MONO), P(f"{W_BASELINE:g}", S_CELLB),
             P("How common is it in public repositories in general?", S_CELL),
             P("Large-corpus statistics, GitHub Linguist, Octoverse, developer surveys", S_CELL)],
            [P("structural_score", S_MONO), P(f"{W_STRUCTURAL:g}", S_CELLB),
             P("Does every Claude Code project carry it whatever the language (CLAUDE.md, settings, CI, lockfiles)?", S_CELL),
             P("Claude Code documentation: the files it reads, creates and recommends", S_CELL)]]
    story.append(table(axes, [30 * mm, 18 * mm, 95 * mm, usable_w - 143 * mm]))
    story += [
        Spacer(1, 3 * mm),
        P("score = {:g} × agent + {:g} × baseline + {:g} × structural. Ties are broken by structural score, then by name."
          .format(W_AGENT, W_BASELINE, W_STRUCTURAL), S_BODY),
        P("Why a blend and not a single source", S_H2),
        P("A scanner for Claude Code output has to cover what Claude Code writes (agent axis), what its users' repositories "
          "already contain (baseline axis) and what appears in every project because the tool itself puts it there "
          "(structural axis). A file such as CLAUDE.md or .mcp.json is rare in public corpora and universal in Claude Code "
          "projects, which is why the structural axis exists.", S_BODY),
        P("How the draft was checked", S_H2),
        P("The scores were produced by one agent from the evidence, then reviewed by two independent critics: one looked "
          "for extensions the pool omitted or mis-weighted, the other for scores that claim more than their evidence "
          "supports. A third pass applied the corrections. The critics' reports are summarised below.", S_BODY),
    ]
    for key in ("completeness", "evidence"):
        c = data.get("critic_summaries", {}).get(key)
        if c:
            story.append(PR(f"<b>{key.capitalize()} critic.</b> {escape(' '.join(c.split()))}", style("cs", fontSize=8.3, leading=11, spaceAfter=4)))
    story.append(PageBreak())

    # 3 ── the ranking
    story.append(P(f"The top {TOP_N}", S_H1))
    story.append(P("Colour of the last column: green = dedicated scanner, amber = credential grep only, red = generic "
                   "fallback. Scores are 0 to 100.", S_SMALL))
    story.append(Spacer(1, 2 * mm))
    rows = [[P(x, S_HEAD) for x in ("#", "Ext", "Format", "Score", "Agent", "Base", "Struct", "Basis", "Pipeline today")]]
    extra = []
    for i, c in enumerate(top, 1):
        tier, label = coverage(c["ext"])
        rows.append([P(c["rank"], S_CELLB), P(c["ext"], style("m", fontName=FM, fontSize=8, leading=10)), P(c["format"], S_CELL),
                     P(f"{c['score']:g}", S_CELLB), P(c["agent_score"], S_CELL), P(c["baseline_score"], S_CELL),
                     P(c["structural_score"], S_CELL), P(c["rationale"], style("rat", fontSize=7, leading=8.8)), P(label, S_CELL)])
        extra.append(("BACKGROUND", (8, i), (8, i), TIER_COLOUR[tier]))
    widths = [8 * mm, 17 * mm, 28 * mm, 13 * mm, 13 * mm, 12 * mm, 14 * mm, 0, 37 * mm]
    widths[7] = usable_w - sum(widths)
    story.append(table(rows, widths, extra=extra))
    story.append(PageBreak())

    # 4 ── gaps
    gaps = [c for c in top if coverage(c["ext"])[0] != "dedicated"]
    story += [P("What this means for the pipeline", S_H1),
              P("Extensions in the top 40 that lack a dedicated scanner, in ranking order. These are candidates for new "
                "per-type scanners, not a statement that they are unscanned: layers 1, 4 and 6 and the universal patterns "
                "run on every file.", S_BODY)]
    grows = [[P(x, S_HEAD) for x in ("Rank", "Ext", "Format", "Today", "Basis for the score (shortened; full text in the top-40 table)")]]
    gextra = []
    for i, c in enumerate(gaps, 1):
        tier, label = coverage(c["ext"])
        grows.append([P(c["rank"], S_CELLB), P(c["ext"], S_MONO), P(c["format"], S_CELL), P(label, S_CELL), P(cut(c["rationale"], 210), style("gr", fontSize=7, leading=8.8))])
        gextra.append(("BACKGROUND", (3, i), (3, i), TIER_COLOUR[tier]))
    if len(grows) > 1:
        story.append(table(grows, [11 * mm, 26 * mm, 38 * mm, 38 * mm, usable_w - 113 * mm], extra=gextra))
    else:
        story.append(P("None: every extension in the top 40 has a dedicated scanner.", S_BODY))
    if data.get("special_names"):
        story += [CondPageBreak(55 * mm), Spacer(1, 4 * mm), P("Important files that have no extension", S_H2),
                  P("They cannot appear in an extension ranking but belong in any support list. The pipeline routes some "
                    "of them by name (Dockerfile*, Makefile*, package.json, requirements*.txt, setup.py, gradle files).", S_BODY)]
        nrows = [[P(x, S_HEAD) for x in ("Name", "Why it matters")]]
        for n in data["special_names"]:
            nrows.append([P(n["name"], S_MONO), P(n["why"], S_CELL)])
        story.append(table(nrows, [45 * mm, usable_w - 45 * mm]))
    story.append(PageBreak())

    # 5 ── evidence
    import re
    cited = {i for c in top[:20] for i in c.get("evidence_ids", [])}
    all_f = []
    for stream, blk in ev.items():
        for f in blk.get("findings", []):
            all_f.append({**f, "stream": stream, "full_id": f"{stream}:{f['id']}"})
    order = ["anthropic-primary", "agent-pr-studies", "industry", "corpora", "claude-code-artifacts"]
    caps = {"anthropic-primary": 8, "agent-pr-studies": 12, "industry": 12, "corpora": 8, "claude-code-artifacts": 8}
    shown = []
    for stream in order:
        grp = [f for f in all_f if f["stream"] == stream and f["full_id"] in cited]
        grp.sort(key=lambda f: (not f.get("fetched"), not f.get("claude_code_specific"),
                                {"high": 0, "medium": 1, "low": 2}.get(f.get("confidence", "low"), 2), f["full_id"]))
        shown += grp[:caps.get(stream, 8)]

    story += [P("The evidence behind the scores", S_H1),
              P(f"{len(shown)} of the findings cited by the top 20, grouped by source stream (read pages first), of {len(all_f)} gathered. All {len(all_f)} are in the data "
                "file with their quotes. Findings about Claude Code itself that were read on the page come first. \"read\" means the page "
                "was opened; \"snippet\" means the figure was seen only in a search result and could not be checked.", S_BODY)]
    erows = [[P(x, S_HEAD) for x in ("Id", "Subject", "Figure", "It counts", "CC", "Read", "Source")]]
    for f in shown:
        erows.append([P(f["full_id"], style("id", fontName=FM, fontSize=6.2, leading=7.8)), P(cut(f["subject"], 70), S_CELL),
                      P(cut(f["value"], 80), S_CELLB if len(f["value"]) <= 38 else S_CELL), P(cut(f["measures"], 230), style("ms", fontSize=7, leading=8.8)),
                      P("yes" if f.get("claude_code_specific") else "no", S_CELL),
                      P("read" if f.get("fetched") else "snippet", S_CELL), P(short_source(f.get("source_url", ""), f.get("source_title", "")), style("src", fontSize=6.4, leading=8))])
    story.append(table(erows, [34 * mm, 34 * mm, 36 * mm, 62 * mm, 8 * mm, 12 * mm, usable_w - 186 * mm]))
    nf = [f"{s}: " + " · ".join(cut(x, 130) for x in b.get("not_found", [])[:4]) for s, b in ev.items() if b.get("not_found")]
    if nf:
        story += [Spacer(1, 3 * mm), P("Looked for and not found (first four per stream)", S_H2)]
        for line in nf:
            story.append(P(line, S_SMALL))
    story.append(PageBreak())

    # 6 ── limitations and how to measure
    story += [P("Limits of this estimate", S_H1)]
    for lim in data.get("limitations", []):
        story.append(PR("•&nbsp;&nbsp;" + escape(lim), S_BODY))
    story += [
        P("Getting first-party numbers", S_H1),
        P("Three sources would turn this estimate into measurement. None could be run from the sandbox that produced this report.", S_BODY),
        P("1. Your own repositories", S_H2),
        P("Count tracked files by extension in the projects you want to protect:", S_BODY),
        box([Paragraph("git ls-files | awk -F. 'NF&gt;1 {print tolower($NF)}' | sort | uniq -c | sort -rn | head -40", S_MONO)], width=usable_w),
        Spacer(1, 3 * mm),
        P("To count only files that Claude Code wrote, limit the history to commits whose message carries the "
          "Co-Authored-By trailer, then count what those commits touched:", S_BODY),
        box([Paragraph("git log --grep='Co-Authored-By: Claude' --name-only --pretty=format: | awk -F. 'NF&gt;1 {print tolower($NF)}' | sort | uniq -c | sort -rn | head -40", S_MONO)], width=usable_w),
        P("2. Claude Code's own telemetry", S_H2),
        P("Claude Code can export OpenTelemetry metrics and events. Its code-edit tool decision events carry the language of "
          "the edited file, which is first-party data about what it edits in your organisation. Enable it for a sample of "
          "projects, aggregate by language, and re-score the agent axis in the data file; the ranking recomputes.", S_BODY),
        P("3. The AIDev dataset", S_H2),
        P("The research dataset behind the agent-pull-request studies cited here has a table with one row per changed file "
          "(commit, file name, status, patch; 12,116,310 rows in version 5, all agents) and tags each pull request with its agent. "
          "Filtering to Claude Code and counting extensions of the file names would give the missing per-extension distribution "
          "directly. The table is hosted on Hugging Face (the dataset is named AIDev and is described in the SAILResearch/AI_Teammates_in_SE3 "
          "repository on GitHub), which this sandbox could not reach. Its pull requests come from repositories with more than "
          "100 stars, so it under-represents the small projects where most Claude Code commits land.", S_BODY),
        P("Re-running this report", S_H2),
        PR("<font face='%s'>python3 build_pdf_top_extensions.py top40_extensions_data.json</font> rebuilds the PDF from the data file; "
           "<font face='%s'>python3 build_pdf_filetypes.py --check</font> confirms the \"Pipeline today\" column still matches classify_file()." % (FM, FM), S_BODY),
    ]

    # 7 ── appendix
    if rest:
        story.append(PageBreak())
        story += [P(f"Appendix: candidates ranked {TOP_N + 1} to {TOP_N + len(rest)}", S_H1),
                  P(f"Scored the same way and just below the cut, useful when the list is extended. All {len(cands)} candidates are in the data file.", S_BODY)]
        arows = [[P(x, S_HEAD) for x in ("#", "Ext", "Format", "Score", "Agent", "Base", "Struct", "Pipeline today")]]
        aextra = []
        for i, c in enumerate(rest, 1):
            tier, label = coverage(c["ext"])
            arows.append([P(c["rank"], S_CELLB), P(c["ext"], S_MONO), P(c["format"], S_CELL), P(f"{c['score']:g}", S_CELLB),
                          P(c["agent_score"], S_CELL), P(c["baseline_score"], S_CELL), P(c["structural_score"], S_CELL), P(label, S_CELL)])
            aextra.append(("BACKGROUND", (7, i), (7, i), TIER_COLOUR[tier]))
        story.append(table(arows, [9 * mm, 22 * mm, 60 * mm, 14 * mm, 14 * mm, 12 * mm, 14 * mm, usable_w - 145 * mm], extra=aextra))
    return story


def main() -> int:
    data = load()
    pagesize = landscape(A4)
    doc = SimpleDocTemplate(str(OUT), pagesize=pagesize, leftMargin=14 * mm, rightMargin=14 * mm,
                            topMargin=16 * mm, bottomMargin=14 * mm,
                            title="Top 40 file extensions for Claude Code projects",
                            author="AI Transit Pipeline", subject="File-extension support ranking")
    usable_w = pagesize[0] - 28 * mm
    doc.build(build_story(data, usable_w), onFirstPage=on_page, onLaterPages=on_page)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
