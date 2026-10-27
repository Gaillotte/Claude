#!/usr/bin/env python3
"""Diagrams for the AI Transit Pipeline installation guide.

Each builder takes the available frame width and returns a ReportLab flowable.
build_registry() maps a markdown heading (as written, minus its {#anchor}) to
the figures that belong under it.

Colours come from pdf_theme so the layer coding is identical in the diagrams and
in the surrounding text. Every figure is drawn with explicit coordinates rather
than computed layout, because a diagram that silently overflows its frame is
worse than no diagram.
"""
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon, Group
from reportlab.lib.colors import HexColor, Color

import pdf_theme as T

WHITE = HexColor("#FFFFFF")


def _txt(g, x, y, s, size=8, colour=None, font=None, anchor="start"):
    g.add(String(x, y, s, fontSize=size, fillColor=colour or T.INK,
                 fontName=font or T.FONT_BODY, textAnchor=anchor))


def _box(g, x, y, w, h, fill, stroke=None, sw=0.7):
    g.add(Rect(x, y, w, h, fillColor=fill, strokeColor=stroke,
               strokeWidth=sw if stroke else 0))


def _arrow_down(g, x, y_top, length, colour):
    """Downward arrow with a solid head, drawn from explicit points."""
    g.add(Line(x, y_top, x, y_top - length + 4, strokeColor=colour, strokeWidth=1.2))
    g.add(Polygon([x - 3, y_top - length + 5, x + 3, y_top - length + 5,
                   x, y_top - length], fillColor=colour, strokeColor=None))


def _arrow_right(g, x, y, length, colour):
    g.add(Line(x, y, x + length - 5, y, strokeColor=colour, strokeWidth=1.2))
    g.add(Polygon([x + length - 6, y - 3, x + length - 6, y + 3,
                   x + length, y], fillColor=colour, strokeColor=None))


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 1 — the six scanning layers
# ═══════════════════════════════════════════════════════════════════════════════
LAYERS = [
    ("L1", "Secrets & malware",
     "betterleaks · detect-secrets · ClamAV · YARA",
     "credential or malware found"),
    ("L2", "OWASP Top 10 · CWE Top 25",
     "Semgrep  (4 rulesets, one pass)",
     "ERROR / WARNING finding"),
    ("L3", "Dependency CVEs",
     "trivy · pip-audit · safety · npm audit",
     "HIGH / CRITICAL CVE"),
    ("L4", "Built-in patterns",
     "grep rules — always available, no tool needed",
     "CWE-798 / 22 / 918 / 327 / 338"),
    ("L5", "Per-language SAST",
     "Bandit · ShellCheck · cppcheck · hadolint · checkov",
     "tool-specific finding"),
    ("L6", "Licence & package CVE",
     "ScanCode Toolkit",
     "risky licence → WARN · CVE → FAIL"),
]


def six_layer_pipeline(avail):
    ROW_H, GAP = 30.0, 4.0
    head_h = 16.0
    h = head_h + len(LAYERS) * (ROW_H + GAP) + 22
    d = Drawing(avail, h)
    g = Group()

    tag_w = 30.0
    name_w = avail * 0.30
    tool_x = tag_w + name_w + 8

    y = h - head_h
    _txt(g, 0, y + 3, "LAYER", 6.5, T.MUTED, T.FONT_BOLD)
    _txt(g, tag_w + 4, y + 3, "DETECTS", 6.5, T.MUTED, T.FONT_BOLD)
    _txt(g, tool_x, y + 3, "TOOLS", 6.5, T.MUTED, T.FONT_BOLD)
    _txt(g, avail, y + 3, "FAILS ON", 6.5, T.MUTED, T.FONT_BOLD, anchor="end")
    g.add(Line(0, y - 1, avail, y - 1, strokeColor=T.RULE, strokeWidth=0.6))

    y -= 6
    for tag, detects, tools, fails in LAYERS:
        y -= ROW_H
        col = T.LAYER[tag]
        _box(g, 0, y, avail, ROW_H, T.PAPER_ALT)
        _box(g, 0, y, tag_w, ROW_H, col)
        _txt(g, tag_w / 2, y + ROW_H / 2 - 3.2, tag, 9, WHITE, T.FONT_BOLD,
             anchor="middle")
        _txt(g, tag_w + 8, y + ROW_H / 2 - 2.6, detects, 8.2, T.INK, T.FONT_BOLD)
        _txt(g, tool_x, y + ROW_H / 2 - 2.6, tools, 7.0, T.MUTED)
        _txt(g, avail - 6, y + ROW_H / 2 - 2.6, fails, 6.8, col, T.FONT_BOLD,
             anchor="end")
        y -= GAP

    _txt(g, 0, 6, "Any layer may FAIL. One FAIL quarantines the repository — "
                  "the verdict is PASS only when none do.",
         7.4, T.INK, T.FONT_BOLD)
    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 2 — end-to-end data flow
# ═══════════════════════════════════════════════════════════════════════════════
def pipeline_data_flow(avail):
    h = 138.0
    d = Drawing(avail, h)
    g = Group()

    bw = (avail - 2 * 26) / 3.0
    by, bh = h - 62, 40

    stages = [
        ("SOURCE", "GitHub URL or local path", T.MUTED),
        ("FETCH", "host allow-list · size cap\n.git removed · SHA-256", T.LAYER["L1"]),
        ("SCAN", "6 layers, in sequence", T.LAYER["L2"]),
    ]
    x = 0
    for i, (title, sub, col) in enumerate(stages):
        _box(g, x, by, bw, bh, WHITE, col, 1.0)
        _box(g, x, by + bh - 14, bw, 14, col)
        _txt(g, x + 7, by + bh - 10.5, title, 7.5, WHITE, T.FONT_BOLD)
        for j, ln in enumerate(sub.split("\n")):
            _txt(g, x + 7, by + bh - 26 - j * 9, ln, 6.6, T.MUTED)
        if i < 2:
            _arrow_right(g, x + bw + 5, by + bh / 2, 16, T.MUTED)
        x += bw + 26

    # Verdict split
    cx = avail / 2
    _arrow_down(g, cx, by - 3, 18, T.MUTED)
    _txt(g, cx + 5, by - 15, "verdict", 6.4, T.MUTED)

    ow, oy, oh = (avail - 24) / 2, by - 78, 46
    _box(g, 0, oy, ow, oh, T.PASS_BG, HexColor("#2E7D32"), 0.9)
    _txt(g, 10, oy + oh - 14, "PASS", 10, HexColor("#1B5E20"), T.FONT_BOLD)
    _txt(g, 10, oy + oh - 27, "ZIP archive in Good/", 7.0, T.INK)
    _txt(g, 10, oy + oh - 37, "Excel report included · exit 0", 6.6, T.MUTED)

    _box(g, ow + 24, oy, ow, oh, T.FAIL_BG, HexColor("#B03A2E"), 0.9)
    _txt(g, ow + 34, oy + oh - 14, "FAIL", 10, HexColor("#8C2A20"), T.FONT_BOLD)
    _txt(g, ow + 34, oy + oh - 27, "quarantined, chmod 700", 7.0, T.INK)
    _txt(g, ow + 34, oy + oh - 37, "JSON + HTML reports · exit 1", 6.6, T.MUTED)

    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 3 — the three walkthrough stages
# ═══════════════════════════════════════════════════════════════════════════════
def walkthrough_stages(avail):
    h = 150.0
    d = Drawing(avail, h)
    g = Group()

    bw = (avail - 2 * 22) / 3.0
    by, bh = h - 104, 84

    stages = [
        ("STAGE A", "Install", HexColor("#0F6FA8"), True,
         ["Install the 16 tools", "and the pipeline", "", "§3 – §10"]),
        ("STAGE B", "Stage offline data", HexColor("#B45309"), True,
         ["Semgrep rulesets", "trivy CVE database", "ClamAV signatures", "§11.4"]),
        ("STAGE C", "Disconnect & verify", HexColor("#2E7D32"), False,
         ["Verify each tool", "then the pipeline", "", "§10.1"]),
    ]

    x = 0
    for i, (tag, title, col, connected, bullets) in enumerate(stages):
        _box(g, x, by, bw, bh, WHITE, col, 1.1)
        _box(g, x, by + bh - 17, bw, 17, col)
        _txt(g, x + 8, by + bh - 12.5, tag, 7.6, WHITE, T.FONT_BOLD)

        state = "NETWORK CONNECTED" if connected else "DISCONNECTED"
        scol = T.MUTED if connected else HexColor("#B03A2E")
        _txt(g, x + bw - 8, by + bh - 12.5, state, 5.8, WHITE, T.FONT_BOLD,
             anchor="end")

        _txt(g, x + 8, by + bh - 32, title, 9, T.INK, T.FONT_BOLD)
        for j, b in enumerate(bullets):
            if not b:
                continue
            style_col = scol if b.startswith("§") else T.MUTED
            fnt = T.FONT_BOLD if b.startswith("§") else T.FONT_BODY
            _txt(g, x + 8, by + bh - 46 - j * 10, b, 6.8, style_col, fnt)

        if i < 2:
            _arrow_right(g, x + bw + 3, by + bh / 2, 16, T.MUTED)
        x += bw + 22

    # The point of the figure: C is the acceptance gate.
    _box(g, 0, 0, avail, 30, HexColor("#FDEDEC"))
    g.add(Line(0, 0, 0, 30, strokeColor=HexColor("#B03A2E"), strokeWidth=2.4))
    _txt(g, 10, 18, "Stage C is not optional.", 8, HexColor("#8C2A20"), T.FONT_BOLD)
    _txt(g, 10, 7.5,
         "Until it has run, “offline-ready” is an assumption — and the failure "
         "it guards against is silent.", 7.2, T.INK)

    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 4 — offline capability of each tool
# ═══════════════════════════════════════════════════════════════════════════════
def offline_tool_groups(avail):
    h = 184.0
    d = Drawing(avail, h)
    g = Group()

    cw = (avail - 2 * 14) / 3.0
    cy, ch = h - 138, 124

    groups = [
        ("GROUP A", "Works offline as installed", HexColor("#2E7D32"),
         ["betterleaks", "detect-secrets", "YARA", "grep rules (L4)",
          "Bandit", "ShellCheck", "cppcheck", "hadolint"],
         "nothing to stage"),
        ("GROUP B", "Needs staged data", HexColor("#B45309"),
         ["Semgrep — ruleset YAML", "trivy — CVE database",
          "ClamAV — signatures", "checkov — --skip-download",
          "ScanCode — licence only"],
         "prepare_offline_cache.sh"),
        ("GROUP C", "Cannot work offline", HexColor("#B03A2E"),
         ["pip-audit", "safety", "npm audit", "ScanCode CVE lookup"],
         "not attempted; gap recorded"),
    ]

    x = 0
    for tag, title, col, items, note in groups:
        _box(g, x, cy, cw, ch, WHITE, col, 1.0)
        _box(g, x, cy + ch - 17, cw, 17, col)
        _txt(g, x + 7, cy + ch - 12.5, tag, 7.4, WHITE, T.FONT_BOLD)
        _txt(g, x + 7, cy + ch - 29, title, 7.6, T.INK, T.FONT_BOLD)
        for j, it in enumerate(items):
            _txt(g, x + 7, cy + ch - 42 - j * 9.4, it, 6.5, T.MUTED)
        _txt(g, x + 7, cy + 6, note, 6.2, col, T.FONT_BOLD)
        x += cw + 14

    # The consequence that matters most.
    _box(g, 0, 0, avail, 32, HexColor("#FFF6E2"))
    g.add(Line(0, 0, 0, 32, strokeColor=HexColor("#C8860D"), strokeWidth=2.4))
    _txt(g, 10, 19.5, "Offline, the staged trivy database is the ONLY "
                      "dependency-CVE coverage there is.",
         8, HexColor("#8A5B00"), T.FONT_BOLD)
    _txt(g, 10, 8.5, "Connected, four tools overlap on that job and losing one "
                     "is survivable. Offline there is no redundancy.",
         7.0, T.INK)
    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 5 — the two transfer bundles
# ═══════════════════════════════════════════════════════════════════════════════
def two_bundles(avail):
    h = 132.0
    d = Drawing(avail, h)
    g = Group()

    bw = (avail - 20) / 2.0
    by, bh = h - 106, 92

    for i, (tag, colour, life, items, cadence) in enumerate([
        ("INSTALL BUNDLE", HexColor("#0F6FA8"), "STATIC",
         [".deb system packages", "Python wheels",
          "betterleaks · trivy · hadolint", "pipeline scripts"],
         "Rebuild only when a tool version changes"),
        ("OFFLINE CACHE", HexColor("#B45309"), "PERISHABLE",
         ["Semgrep ruleset YAML", "trivy CVE database",
          "ClamAV signatures", "YARA rules"],
         "Rebuild WEEKLY — stale data reports clean"),
    ]):
        x = i * (bw + 20)
        _box(g, x, by, bw, bh, WHITE, colour, 1.1)
        _box(g, x, by + bh - 18, bw, 18, colour)
        _txt(g, x + 8, by + bh - 13, tag, 7.8, WHITE, T.FONT_BOLD)
        _txt(g, x + bw - 8, by + bh - 13, life, 6.4, WHITE, T.FONT_BOLD,
             anchor="end")
        for j, it in enumerate(items):
            _txt(g, x + 8, by + bh - 33 - j * 10, it, 6.9, T.MUTED)
        g.add(Line(x + 8, by + 20, x + bw - 8, by + 20,
                   strokeColor=T.RULE, strokeWidth=0.5))
        _txt(g, x + 8, by + 9, cadence, 6.5, colour, T.FONT_BOLD)

    _txt(g, 0, 8, "Connected host", 7, T.MUTED, T.FONT_BOLD)
    _arrow_right(g, 74, 10.5, 40, T.MUTED)
    _txt(g, 120, 8, "verify SHA-256 on arrival", 6.6, T.MUTED)
    _arrow_right(g, 232, 10.5, 40, T.MUTED)
    _txt(g, 278, 8, "Air-gapped host", 7, T.MUTED, T.FONT_BOLD)
    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 6 — why a verdict alone is not enough
# ═══════════════════════════════════════════════════════════════════════════════
def coverage_vs_verdict(avail):
    h = 150.0
    d = Drawing(avail, h)
    g = Group()

    bw = (avail - 18) / 2.0
    by, bh = h - 118, 104

    for i, (title, ok, rows, footer, fcol) in enumerate([
        ("Both report PASS …", True,
         [("L1 secrets", "ran"), ("L2 OWASP/CWE", "ran"),
          ("L3 dependency CVE", "ran"), ("L5 per-language", "ran")],
         "coverage_complete: true  →  trustworthy", HexColor("#1B5E20")),
        ("… but only one examined anything", False,
         [("L1 secrets", "ran"), ("L2 OWASP/CWE", "skipped: no rulesets staged"),
          ("L3 dependency CVE", "skipped: no database staged"),
          ("L5 per-language", "ran")],
         "coverage_complete: false  →  inconclusive", HexColor("#8C2A20")),
    ]):
        x = i * (bw + 18)
        edge = HexColor("#2E7D32") if ok else HexColor("#B03A2E")
        _box(g, x, by, bw, bh, WHITE, edge, 1.1)
        _txt(g, x + 8, by + bh - 13, title, 7.6, T.INK, T.FONT_BOLD)
        _box(g, x + 8, by + bh - 32, 42, 13, T.PASS_BG)
        _txt(g, x + 29, by + bh - 28.5, "PASS", 7.4, HexColor("#1B5E20"),
             T.FONT_BOLD, anchor="middle")

        for j, (layer, state) in enumerate(rows):
            yy = by + bh - 48 - j * 11
            ran = state == "ran"
            mark_col = HexColor("#2E7D32") if ran else HexColor("#B03A2E")
            _txt(g, x + 9, yy, "OK" if ran else "GAP", 6.0, mark_col, T.FONT_BOLD)
            _txt(g, x + 27, yy, layer, 6.6, T.INK)
            _txt(g, x + bw - 8, yy, state, 6.0,
                 T.MUTED if ran else mark_col, anchor="end")

        _box(g, x, by, bw, 15, T.PASS_BG if ok else T.FAIL_BG)
        _txt(g, x + 8, by + 5, footer, 6.6, fcol, T.FONT_BOLD)

    _txt(g, 0, 12, "A verdict alone cannot distinguish “clean” from "
                   "“nothing was examined”.", 8, T.INK, T.FONT_BOLD)
    _txt(g, 0, 2, "Automated consumers should gate on the coverage block, not "
                  "on the verdict.", 7.0, T.MUTED)
    d.add(g)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
def build_registry():
    """heading (anchor-stripped) -> [(builder, caption), ...]"""
    return {
        "1. Overview": [
            (six_layer_pipeline,
             "Figure 1 — the six scanning layers, the tools in each, and what "
             "makes each one fail."),
            (pipeline_data_flow,
             "Figure 2 — end-to-end flow from source to verdict."),
        ],
        "The shape of it": [
            (walkthrough_stages,
             "Figure 3 — the three stages of the walkthrough, and the network "
             "state each runs in."),
        ],
        "11.2 Per-tool reference": [
            (offline_tool_groups,
             "Figure 4 — offline capability of each tool, and the one gap with "
             "no redundancy."),
        ],
        "12. Installing on a Disconnected Host": [
            (two_bundles,
             "Figure 5 — the two transfer bundles and their differing "
             "lifetimes."),
        ],
        "11.8 Coverage — proving the scan actually ran": [
            (coverage_vs_verdict,
             "Figure 6 — two reports that both say PASS; only one is "
             "trustworthy."),
        ],
    }
