#!/usr/bin/env python3
"""
Generates the AI Transit Pipeline PDF slide deck via ReportLab.
Format 16:9 — 1333 × 750 pt
Light (white/light gray) background theme, English text.
5-layer scanning architecture version.
"""

from reportlab.lib.pagesizes import landscape
from reportlab.lib.units import inch
pt = 1
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white, black, Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import ImageReader
import math, textwrap, os

W, H = 1333, 750   # points, 16:9 custom format

# ── Palette — LIGHT THEME ────────────────────────────────────────────────────
BG       = HexColor("#FFFFFF")        # slide background: white
BG_CARD  = HexColor("#EEF2F8")        # card background: light blue-gray
ACCENT   = HexColor("#00A8FF")        # accent blue
ACCENT2  = HexColor("#00C49A")        # accent teal (slightly deeper for light bg)
WHITE    = HexColor("#FFFFFF")
LIGHT    = HexColor("#2C3E50")        # body text: dark gray (was light on dark)
GRAY     = HexColor("#7F8C8D")        # secondary text
GREEN    = HexColor("#2ECC71")
RED      = HexColor("#E74C3C")
ORANGE   = HexColor("#F39C12")
YELLOW   = HexColor("#D4A017")        # darker yellow for light bg readability
PURPLE   = HexColor("#8E44AD")
DARK     = HexColor("#1F3864")        # dark navy for text/titles
HDR_BLU  = HexColor("#0070A8")
HDR_GRN  = HexColor("#1A7A40")
HDR_PUR  = HexColor("#6A2FA0")
# Table row alternating colors (light)
ALT_ROW1 = HexColor("#F0F4FA")
ALT_ROW2 = HexColor("#FFFFFF")
# Colored row highlights (light variants)
RED_ROW  = HexColor("#FDE8E8")
ORG_ROW  = HexColor("#FEF3E2")
GRN_ROW  = HexColor("#E8F8EE")

# Layer colors for 5-layer diagram
L1_COLOR = HexColor("#0070A8")   # deep blue
L2_COLOR = HexColor("#8E44AD")   # purple
L3_COLOR = HexColor("#C06010")   # dark orange
L4_COLOR = HexColor("#1A7A40")   # dark green
L5_COLOR = HexColor("#B8860B")   # dark gold

# ── Helpers canvas ────────────────────────────────────────────────────────────
def bg(cv, color=BG):
    cv.setFillColor(color)
    cv.rect(0, 0, W, H, fill=1, stroke=0)

def rect(cv, x, y, w, h, fill, stroke_color=None, stroke_w=0, radius=0):
    cv.setFillColor(fill)
    if stroke_color:
        cv.setStrokeColor(stroke_color)
        cv.setLineWidth(stroke_w)
    else:
        cv.setStrokeColor(fill)
        cv.setLineWidth(0)
    if radius:
        cv.roundRect(x, y, w, h, radius, fill=1, stroke=1 if stroke_color else 0)
    else:
        cv.rect(x, y, w, h, fill=1, stroke=1 if stroke_color else 0)

def line(cv, x1, y1, x2, y2, color, width=1):
    cv.setStrokeColor(color)
    cv.setLineWidth(width)
    cv.line(x1, y1, x2, y2)

def text(cv, s, x, y, size=16, color=LIGHT, bold=False, align="left", max_w=None):
    cv.setFillColor(color)
    fname = "Helvetica-Bold" if bold else "Helvetica"
    cv.setFont(fname, size)
    if max_w and len(s) * size * 0.55 > max_w:
        chars_per_line = max(1, int(max_w / (size * 0.55)))
        lines = textwrap.wrap(s, chars_per_line)
        for i, l in enumerate(lines):
            _draw_text(cv, l, x, y - i * (size * 1.25), size, align)
    else:
        _draw_text(cv, s, x, y, size, align)

def _draw_text(cv, s, x, y, size, align):
    if align == "center":
        cv.drawCentredString(x, y, s)
    elif align == "right":
        cv.drawRightString(x, y, s)
    else:
        cv.drawString(x, y, s)

def text_block(cv, lines_list, x, y, size=14, color=LIGHT, bold=False,
               line_h=None, max_w=None, align="left"):
    lh = line_h or size * 1.4
    for i, line_txt in enumerate(lines_list):
        text(cv, line_txt, x, y - i * lh, size=size, color=color,
             bold=bold, align=align, max_w=max_w)

def header_bar(cv, color, title, title_color=WHITE, size=30):
    rect(cv, 0, H - 80, W, 80, color)
    text(cv, title, 35, H - 52, size=size, color=title_color, bold=True)
    line(cv, 30, H - 82, W - 30, H - 82, ACCENT, 1.5)

def card(cv, x, y, w, h, color=BG_CARD, radius=10):
    # Draw with a subtle border for light theme
    rect(cv, x, y, w, h, color, stroke_color=HexColor("#D0DAE8"), stroke_w=0.8, radius=radius)

def badge(cv, text_s, x, y, w, h, fill, text_color=WHITE, size=11):
    rect(cv, x, y, w, h, fill, radius=5)
    cx = x + w / 2
    cy = y + h / 2 - size * 0.35
    cv.setFillColor(text_color)
    cv.setFont("Helvetica-Bold", size)
    cv.drawCentredString(cx, cy, text_s)

def circle_num(cv, num, cx, cy, r, fill, text_color=WHITE):
    cv.setFillColor(fill)
    cv.circle(cx, cy, r, fill=1, stroke=0)
    cv.setFillColor(text_color)
    cv.setFont("Helvetica-Bold", r)
    cv.drawCentredString(cx, cy - r * 0.35, str(num))

def mono_box(cv, code_lines, x, y, w, h, size=9):
    # Dark background for code — code is always dark
    rect(cv, x, y, w, h, HexColor("#1E2A3A"), stroke_color=ACCENT, stroke_w=1)
    cv.setFillColor(HexColor("#7FFFD4"))
    cv.setFont("Courier", size)
    lh = size * 1.4
    for i, l in enumerate(code_lines):
        cv.drawString(x + 10, y + h - 18 - i * lh, l)

def divider_line(cv, y, color=ACCENT):
    line(cv, 30, y, W - 30, y, color, 1.5)

# ── PDF ───────────────────────────────────────────────────────────────────────
pdf_path = "/home/user/Claude/AI_Transit_Pipeline_Slides_EN.pdf"
cv = canvas.Canvas(pdf_path, pagesize=(W, H))
cv.setTitle("AI Transit Pipeline — Slides")
cv.setAuthor("AI Transit Pipeline")
cv.setSubject("Technical Documentation — AI Code Security")


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — COVER
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 70, W, 70, ACCENT)
rect(cv, 0, 0, W, 70, ACCENT2)

text(cv, "AI TRANSIT PIPELINE", W/2, H - 200, size=58, bold=True,
     color=DARK, align="center")
text(cv, "Securing AI Code Integration in the Enterprise",
     W/2, H - 260, size=22, color=ACCENT, align="center")

line(cv, 100, H - 290, W - 100, H - 290, GRAY, 1)

bullets = [
    "🔍  Secure retrieval from GitHub",
    "🛡   5-layer adaptive multi-layer scan by file type",
    "📦  Approved ZIP archive + Excel traceability report",
]
for i, b in enumerate(bullets):
    text(cv, b, W/2, H - 340 - i * 45, size=18, color=DARK, align="center")

text(cv, "Version 2.0  —  June 2026", W/2, 30, size=12, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — TABLE OF CONTENTS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_BLU)
text(cv, "Table of Contents", 35, H - 53, size=34, color=WHITE, bold=True)
divider_line(cv, H - 83)

items = [
    ("01", "Context & Objectives",                        ACCENT),
    ("02", "Pipeline Architecture — 5 Layers",            ACCENT2),
    ("03", "Phase 1 — Secure Retrieval",                  YELLOW),
    ("04", "Layer 1 — Global Scan",                       ORANGE),
    ("05", "Layer 2 — OWASP Top 10 / CWE Top 25",        PURPLE),
    ("06", "Layer 3 — SCA: Vulnerable Dependencies",      L3_COLOR),
    ("07", "Layer 4 — Universal Patterns",                L4_COLOR),
    ("08", "Layer 5 — Per-type SAST (11 languages)",      L5_COLOR),
    ("09", "Tools Used",                                   GREEN),
    ("10", "Results & Deliverables",                      ACCENT),
    ("11", "Absolute Security Rules",                     RED),
]
cols = 3
for i, (num, title, color) in enumerate(items):
    col = i % cols
    row = i // cols
    x = 30 + col * 435
    y = H - 130 - row * 165
    card(cv, x, y - 130, 420, 140)
    circle_num(cv, num, x + 30, y - 60, 20, color, WHITE)
    text(cv, title, x + 60, y - 68, size=14, color=DARK, bold=True)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — CONTEXT & OBJECTIVES
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT)
text(cv, "01  Context & Objectives", 35, H - 52, size=32, color=WHITE, bold=True)
divider_line(cv, H - 83)

text(cv, "Why this pipeline?", 35, H - 115, size=22, color=ACCENT, bold=True)
problems = [
    "🤖  AI-generated code may contain backdoors, secrets, or dangerous patterns",
    "📥  Developers import code without systematic security review",
    "🏢  The corporate network must remain isolated (partial air-gap)",
    "📋  No traceability without a structured process",
]
for i, p in enumerate(problems):
    text(cv, p, 50, H - 160 - i * 45, size=16, color=DARK)

# Flow diagram
nodes_flow = [
    ("🌐 Internet\n(GitHub)", 990, H - 180, ACCENT),
    ("🛡 AI Transit\nPipeline", 1100, H - 180, ORANGE),
    ("🏢 Internal\nNetwork", 1210, H - 180, GREEN),
]
for label, nx, ny, nc in nodes_flow:
    card(cv, nx - 40, ny - 60, 90, 75, nc, radius=8)
    lines_l = label.split("\n")
    for li, ll in enumerate(lines_l):
        text(cv, ll, nx, ny - 22 - li * 22, size=11, color=WHITE,
             bold=True, align="center")

text(cv, "→", 1065, H - 202, size=20, color=GRAY, align="center")
text(cv, "→", 1175, H - 202, size=20, color=GRAY, align="center")
text(cv, "one-way flow", 1100, H - 265, size=10, color=GRAY, align="center")

# Objectives
text(cv, "Key Objectives", 35, H - 390, size=20, color=ACCENT2, bold=True)
objs = [
    ("Retrieve", "Secure depth-1 clone",        ACCENT),
    ("Scan",     "5-layer adaptive pipeline",    ORANGE),
    ("Decide",   "PASS→ZIP / FAIL→Quarantine",  RED),
    ("Trace",    "Excel + JSON + HTML",          GREEN),
]
for i, (title, sub, c) in enumerate(objs):
    x = 35 + i * 325
    card(cv, x, H - 570, 310, 160, BG_CARD, radius=8)
    rect(cv, x + 10, H - 437, 20, 20, c, radius=4)
    text(cv, title, x + 40, H - 432, size=16, color=c, bold=True)
    text(cv, sub, x + 15, H - 465, size=12, color=DARK)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — ARCHITECTURE (5-layer flow)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "02  Pipeline Architecture — 5-Layer Scanning", 35, H - 52, size=30,
     color=WHITE, bold=True)
divider_line(cv, H - 83, ACCENT2)

# Left: top-level flow (Source -> fetch -> scan -> PASS/FAIL)
text(cv, "Top-level Flow", 190, H - 105, size=14, color=DARK, bold=True, align="center")
top_nodes = [
    ("📂 Source\nGitHub / Local", H - 145, ACCENT),
    ("⬇  fetch_repo.sh\n(Phase 1)", H - 235, HexColor("#3A7AB5")),
    ("🔍 scan_pipeline.sh\n(Phase 2 — 5 Layers)", H - 330, HexColor("#C06010")),
    ("✔  Good/ — ZIP + Excel", H - 455, GREEN),
    ("✘  quarantine/  chmod 700", H - 530, RED),
]
for label, y, c in top_nodes:
    card(cv, 20, y - 65, 350, 58, c, radius=6)
    parts = label.split("\n")
    for pi, p in enumerate(parts):
        text(cv, p, 195, y - 25 - pi * 20, size=11, color=WHITE, bold=True, align="center")

for y_arr in [H - 185, H - 280]:
    text(cv, "▼", 195, y_arr, size=16, color=GRAY, align="center")
text(cv, "PASS ▼", 80, H - 400, size=12, color=GREEN, bold=True)
text(cv, "FAIL ▼", 245, H - 400, size=12, color=RED, bold=True)

# Right: 5-layer cascade
text(cv, "5-Layer Scanning Cascade", 880, H - 100, size=15, color=DARK, bold=True, align="center")

layers = [
    ("L1", "Global",           "AV · gitleaks · detect-secrets · YARA",        L1_COLOR),
    ("L2", "OWASP / CWE",     "Semgrep × 4 rulesets",                          L2_COLOR),
    ("L3", "SCA / CVE",       "trivy · pip-audit · npm audit",                 L3_COLOR),
    ("L4", "Universal",        "CWE-798 · CWE-22 · CWE-918 · CWE-327 · CWE-338", L4_COLOR),
    ("L5", "Per-type SAST",   "11 languages",                                   L5_COLOR),
]

layer_y_start = H - 140
layer_h = 88
layer_gap = 10
layer_x = 390
layer_w = 910

for idx, (lnum, lname, ldesc, lcolor) in enumerate(layers):
    ly = layer_y_start - idx * (layer_h + layer_gap)
    # colored band
    rect(cv, layer_x, ly - layer_h, layer_w, layer_h, lcolor, radius=6)
    # label badge
    rect(cv, layer_x + 8, ly - layer_h + 10, 60, layer_h - 20, WHITE, radius=4)
    text(cv, lnum, layer_x + 38, ly - layer_h/2 - 7, size=14, color=lcolor, bold=True, align="center")
    text(cv, lname, layer_x + 85, ly - 22, size=14, color=WHITE, bold=True)
    text(cv, ldesc, layer_x + 85, ly - 50, size=11, color=HexColor("#D8EEF8"))
    # arrow between layers
    if idx < len(layers) - 1:
        ay = ly - layer_h - layer_gap/2
        text(cv, "▼", layer_x + layer_w/2, ay - 2, size=13, color=GRAY, align="center")

# PASS/FAIL outcome
outcome_y = layer_y_start - len(layers) * (layer_h + layer_gap) - 10
badge(cv, "PASS", layer_x + layer_w/2 - 110, outcome_y - 32, 100, 32, GREEN)
badge(cv, "FAIL", layer_x + layer_w/2 + 10,  outcome_y - 32, 100, 32, RED)
text(cv, "▼", layer_x + layer_w/2, outcome_y + 5, size=13, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — PHASE 1
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HexColor("#C8860A"))
text(cv, "03  Phase 1 — Secure Retrieval", 35, H - 52, size=30,
     color=WHITE, bold=True)
divider_line(cv, H - 83, ORANGE)

steps = [
    ("1", "Host Whitelist",
     "Only github.com is allowed.\nAny other URL is rejected immediately.", ACCENT),
    ("2", "Size Verification",
     "GitHub API queried before clone.\nLimit: 500 MB.", ACCENT2),
    ("3", "Minimal Clone",
     "git clone --depth 1 --no-tags\n--single-branch", ORANGE),
    ("4", ".git/ Removal",
     "Git metadata removed\n(hooks, remotes, submodules).", ORANGE),
    ("5", "SHA-256 Manifest",
     "Hash of each file →\n.manifest_sha256.txt (audit trail).", PURPLE),
    ("6", "Quick Triage",
     "Grep: eval( exec( curl|bash\nrm -rf → immediate alert.", GREEN),
]
for i, (num, title, desc, color) in enumerate(steps):
    col = i % 3
    row = i // 3
    x = 35 + col * 430
    y = H - 120 - row * 290
    card(cv, x, y - 240, 415, 245, BG_CARD, radius=8)
    circle_num(cv, num, x + 30, y - 30, 22, color, WHITE)
    text(cv, title, x + 65, y - 38, size=15, color=color, bold=True)
    for li, dl in enumerate(desc.split("\n")):
        text(cv, dl, x + 20, y - 100 - li * 38, size=13, color=DARK)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 6 — LAYER 1: GLOBAL SCAN
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, L1_COLOR)
text(cv, "04  Layer 1 — Global Scan (all files)", 35, H - 52, size=32, color=WHITE, bold=True)
divider_line(cv, H - 83, L1_COLOR)

text(cv, "AV · gitleaks · detect-secrets · YARA  —  Applies to the ENTIRE directory, regardless of file type",
     W/2, H - 105, size=14, color=DARK, align="center")

tools_g = [
    ("Gitleaks", "🔑",
     ["> 150 credential types", "GitHub/AWS/GCP/Azure tokens",
      "RSA, PEM, SSH, JWT keys", "Entropy analysis + regex"], ACCENT),
    ("detect-secrets", "📊",
     ["Shannon entropy", "Secrets unknown to rule sets",
      "High-density base64/hex", "Complements Gitleaks"], ACCENT2),
    ("ClamAV / AV", "🦠",
     ["Millions of signatures", "Trojans, ransomware, backdoors",
      "Full recursive scan", "freshclam updated base"], ORANGE),
    ("YARA", "🎯",
     ["Industry-standard IOC", "Custom .yar rules",
      "AI backdoor patterns", "Regex + boolean logic"], PURPLE),
]
for i, (name, icon, items_l, color) in enumerate(tools_g):
    x = 25 + i * 326
    card(cv, x, H - 680, 315, 540, BG_CARD, radius=8)
    rect(cv, x, H - 155, 315, 52, color)
    text(cv, f"{icon}  {name}", x + 157, H - 136, size=15, color=WHITE,
         bold=True, align="center")
    for j, item in enumerate(items_l):
        text(cv, f"• {item}", x + 15, H - 210 - j * 65, size=13, color=DARK)
    badge(cv, "FAIL if positive", x + 75, H - 668, 165, 28, RED)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 7 — LAYER 2: OWASP / CWE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, L2_COLOR)
text(cv, "05  Layer 2 — OWASP Top 10 2021 + CWE Top 25 (Semgrep)", 35, H - 52,
     size=26, color=WHITE, bold=True)
divider_line(cv, H - 83, L2_COLOR)

text(cv, "4 Semgrep rulesets run against all code files", W/2, H - 103, size=15,
     color=DARK, bold=True, align="center")

rulesets = [
    ("p/owasp-top-ten", L1_COLOR,
     "OWASP Top 10 2021",
     ["A01 — Broken Access Control",
      "A02 — Cryptographic Failures",
      "A03 — Injection (SQLi, XSS, SSTI…)",
      "A04 — Insecure Design",
      "A05 — Security Misconfiguration",
      "A06 — Vulnerable Components",
      "A07 — Auth Failures",
      "A08 — Data Integrity Failures",
      "A09 — Logging & Monitoring Failures",
      "A10 — SSRF"]),
    ("p/cwe-top-25", L2_COLOR,
     "CWE Top 25 Most Dangerous",
     ["CWE-79  XSS",
      "CWE-89  SQL Injection",
      "CWE-20  Improper Input Validation",
      "CWE-125 Out-of-bounds Read",
      "CWE-78  OS Command Injection",
      "CWE-416 Use After Free",
      "CWE-22  Path Traversal",
      "CWE-352 CSRF",
      "CWE-476 NULL Pointer Dereference",
      "CWE-287 Improper Authentication"]),
    ("p/security-audit", L3_COLOR,
     "General Security Audit",
     ["Broad vulnerability patterns",
      "Misconfigurations",
      "Insecure API usage",
      "Deprecated functions",
      "Crypto weaknesses",
      "Race conditions",
      "Integer overflows",
      "Memory safety issues",
      "Protocol misuse",
      "Hardcoded values"]),
    ("p/secrets", L4_COLOR,
     "Secrets & Credentials",
     ["API keys (AWS, GCP, Azure…)",
      "Private keys (RSA, EC, PEM)",
      "OAuth tokens",
      "Database connection strings",
      "JWT secrets",
      "Slack / Twilio / Stripe tokens",
      "Generic password patterns",
      "High-entropy strings",
      "Environment variable leaks",
      "Config file secrets"]),
]

rw = 310
rx_start = 20
for i, (ruleset, color, title, items_l) in enumerate(rulesets):
    rx = rx_start + i * (rw + 12)
    card(cv, rx, H - 710, rw, 575, BG_CARD, radius=8)
    rect(cv, rx, H - 148, rw, 44, color)
    text(cv, ruleset, rx + rw/2, H - 133, size=12, color=WHITE, bold=True, align="center")
    text(cv, title, rx + rw/2, H - 165, size=11, color=color, bold=True, align="center")
    for j, item in enumerate(items_l):
        text(cv, f"• {item}", rx + 10, H - 195 - j * 50, size=10, color=DARK)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 8 — LAYER 3: SCA / CVE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, L3_COLOR)
text(cv, "06  Layer 3 — SCA: Vulnerable Dependencies (OWASP A06)", 35, H - 52,
     size=26, color=WHITE, bold=True)
divider_line(cv, H - 83, L3_COLOR)

# SCA explainer
card(cv, 20, H - 185, W - 40, 80, BG_CARD, radius=8)
text(cv, "What is SCA?", 40, H - 113, size=15, color=L3_COLOR, bold=True)
text(cv, "Software Composition Analysis (SCA) identifies known vulnerabilities (CVEs) in third-party libraries and dependencies.",
     40, H - 138, size=13, color=DARK, max_w=1270)
text(cv, "OWASP A06:2021 — Vulnerable and Outdated Components is consistently in the OWASP Top 10.",
     40, H - 163, size=13, color=DARK, max_w=1270)

sca_tools = [
    ("trivy", "🔍", L1_COLOR,
     "Universal SCA scanner",
     ["All ecosystems (pip, npm, gem, go, cargo…)",
      "CVE database (NVD, OSV, GitHub Advisory)",
      "Scans requirements.txt, package-lock.json,",
      "  go.sum, Gemfile.lock, Cargo.lock…",
      "CRITICAL / HIGH / MEDIUM / LOW severity",
      "Output: JSON + table report",
      "Also scans Dockerfiles & container images",
      "Regularly updated vulnerability DB"]),
    ("pip-audit / safety", "🐍", HexColor("#B8860B"),
     "Python — requirements*.txt",
     ["pip-audit: official PyPA tool (PURL-based)",
      "safety: PyUp.io database",
      "Scans requirements.txt, requirements-dev.txt",
      "  requirements-*.txt (glob pattern)",
      "Maps to CVE + GHSA identifiers",
      "Detects yanked / abandoned packages",
      "Outputs FAIL on any CRITICAL finding",
      "Complements trivy for Python ecosystem"]),
    ("npm audit", "📦", ACCENT2,
     "JavaScript / Node — package-lock.json",
     ["Built-in npm command (no install needed)",
      "Uses npm registry advisory database",
      "Scans package-lock.json",
      "Severity: critical / high / moderate / low",
      "FAIL on critical or high findings",
      "Reports affected package tree",
      "Identifies fix version when available",
      "Covers direct and transitive dependencies"]),
]

tw = 415
for i, (name, icon, color, subtitle, items_l) in enumerate(sca_tools):
    tx = 20 + i * (tw + 12)
    card(cv, tx, H - 700, tw, 485, BG_CARD, radius=8)
    rect(cv, tx, H - 225, tw, 50, color)
    text(cv, f"{icon}  {name}", tx + tw/2, H - 206, size=15, color=WHITE, bold=True, align="center")
    text(cv, subtitle, tx + tw/2, H - 244, size=12, color=color, bold=True, align="center")
    for j, item in enumerate(items_l):
        text(cv, f"• {item}", tx + 12, H - 278 - j * 50, size=11, color=DARK)
    badge(cv, "FAIL on CRITICAL/HIGH", tx + tw/2 - 90, H - 692, 180, 26, RED)

cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 9 — LAYER 4: UNIVERSAL PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, L4_COLOR)
text(cv, "07  Layer 4 — Universal Patterns (all files)", 35, H - 52,
     size=30, color=WHITE, bold=True)
divider_line(cv, H - 83, L4_COLOR)

text(cv, "Pattern-matched against EVERY file regardless of language — no tool dependency",
     W/2, H - 102, size=13, color=DARK, align="center")

# Table header
col_defs = [
    ("CWE / Standard", 20, 210),
    ("Pattern / Rule",  235, 270),
    ("Example",         510, 450),
    ("Verdict",         965, 350),
]
for hdr, hx, hw in col_defs:
    rect(cv, hx, H - 140, hw, 36, L4_COLOR)
    text(cv, hdr, hx + hw/2, H - 125, size=12, color=WHITE, bold=True, align="center")

univ_rows = [
    ("CWE-798",    "Hardcoded credentials",   'password="...", api_key="..."',    "FAIL", RED,    RED_ROW),
    ("CWE-321",    "Hardcoded crypto key",     "BEGIN RSA PRIVATE KEY",            "FAIL", RED,    RED_ROW),
    ("CWE-22",     "Path traversal",           "../../etc/passwd",                 "FAIL", RED,    RED_ROW),
    ("CWE-918",    "SSRF",                     "requests.get(url=user_input)",     "WARN", ORANGE, ORG_ROW),
    ("CWE-327",    "Weak cryptography",        "md5, sha1, rc4",                   "WARN", ORANGE, ORG_ROW),
    ("CWE-338",    "Weak PRNG",                "Math.random(), rand()",            "WARN", ORANGE, ORG_ROW),
    ("OWASP-A09",  "Logging suppressed",       "logging.disable(logging.CRITICAL)","WARN", ORANGE, ORG_ROW),
]
RH_U = 72
for ri, (cwe, pattern, example, verdict, vcol, rowcol) in enumerate(univ_rows):
    ry = H - 145 - (ri + 1) * RH_U
    rect(cv, 20, ry, 1293, RH_U - 3, rowcol)
    text(cv, cwe,      125, ry + RH_U//2 - 5, size=11, color=vcol, bold=True, align="center")
    text(cv, pattern,  370, ry + RH_U//2 - 5, size=11, color=DARK, align="center")
    text(cv, example,  510, ry + RH_U//2 - 5, size=10, color=HexColor("#333333"), max_w=445)
    badge(cv, verdict, 1000, ry + RH_U//2 - 15, 85, 26, vcol)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 10 — LAYER 5: DISPATCH BY FILE TYPE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, L5_COLOR)
text(cv, "08  Layer 5 — Per-type SAST Dispatch (11 languages)", 35, H - 52,
     size=27, color=WHITE, bold=True)
divider_line(cv, H - 83, L5_COLOR)

hdrs = [("Extension(s)", 25, 165), ("SAST Tool", 195, 260),
        ("Manual Checks", 460, 600), ("Verdict", 1065, 180)]
for hdr, hx, hw in hdrs:
    rect(cv, hx, H - 128, hw, 38, L5_COLOR)
    text(cv, hdr, hx + hw/2, H - 113, size=12, color=WHITE,
         bold=True, align="center")

rows_t = [
    (".py",              "Bandit",      "eval() exec() import os/subprocess",     "FAIL"),
    (".js .ts .jsx",     "Semgrep",     "eval() child_process require(…)",         "FAIL"),
    (".java",            "Semgrep",     "Runtime.exec() ObjectInputStream JNDI Log4Shell TrustAllCerts",  "FAIL"),
    (".php",             "Semgrep",     "shell_exec() echo $_GET include($var) unserialize()",            "FAIL"),
    (".rb",              "Semgrep",     "system/exec eval() ActiveRecord string interpolation",            "FAIL"),
    (".go",              "Semgrep",     "fmt.Sprintf in SQL math/rand TLS MinVersion",                     "FAIL"),
    (".c .cpp .h",       "cppcheck",    "gets() strcpy() system() popen()",        "FAIL"),
    (".sh .bash .ps1",   "ShellCheck",  "curl|bash  wget|sh  eval $var",           "FAIL"),
    (".yml .yaml",       "—",           "Unpinned actions  inline secrets",        "FAIL"),
    (".tf .tfvars",      "checkov",     "Hardcoded secrets  overly broad IAM",     "FAIL"),
    ("Dockerfile",       "hadolint",    ":latest  ADD http://  RUN curl|bash",     "FAIL"),
    (".xml",             "—",           "DOCTYPE + ENTITY (XXE CWE-611)",          "FAIL"),
    (".so .exe .elf",    "strings",     "Auto FAIL + IOC strings",                 "FAIL ⚠"),
    (".zip .tar.gz",     "—",           "Auto FAIL — re-scan after extraction",    "FAIL ⚠"),
    (".sql",             "—",           "xp_cmdshell  DROP TABLE  ; --",           "FAIL"),
]
RH = 40
for ri, (ext, tool, checks, verdict) in enumerate(rows_t):
    ry = H - 135 - (ri + 1) * RH
    fill_r = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
    rect(cv, 25, ry, 1283, RH - 2, fill_r)
    text(cv, ext,     110, ry + 12, size=10, color=ACCENT, bold=True, align="center")
    text(cv, tool,    325, ry + 12, size=10, color=DARK, align="center")
    text(cv, checks,  460, ry + 12, size=9, color=DARK)
    vcolor = RED if "FAIL" in verdict else ORANGE
    text(cv, verdict, 1155, ry + 12, size=10, color=vcolor,
         bold=True, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDES — PER-TYPE CHECKS details (classic languages)
# ═══════════════════════════════════════════════════════════════════════════════
details = [
    ("Python .py", ACCENT,
     "Dynamic execution — high risk of backdoors via eval/exec",
     [("Bandit SAST",          "Python AST: subprocess shell=True, pickle, MD5, SQL, assert…", "FAIL"),
      ("eval() / exec()",      "Arbitrary execution at runtime — trivial backdoor vector",      "FAIL"),
      ("import os/subprocess", "Shell access — requires manual review",                          "WARN")]),
    ("JavaScript .js .ts", HexColor("#B8860B"),
     "Ecosystem exposed to supply-chain attacks",
     [("Semgrep p/javascript", "XSS, prototype pollution, innerHTML, SSTI…",       "FAIL"),
      ("eval()",               "Dynamic execution — classic injection vector",      "FAIL"),
      ("child_process",        "Shell command execution from Node.js",              "FAIL")]),
    ("C / C++ .c .cpp", ORANGE,
     "Risks from manual memory management",
     [("cppcheck",        "Buffer overflows, null ptr, use-after-free, uninit memory.", "FAIL"),
      ("gets() strcpy()", "Unbounded read/copy → buffer overflow",                     "FAIL"),
      ("system() popen()", "Shell command execution → possible injection",             "FAIL")]),
    ("Shell .sh .bash", ACCENT2,
     "Direct execution — command obfuscation is trivial",
     [("ShellCheck",     "Unquoted variables, globbing, dangerous redirections…",  "FAIL"),
      ("curl | bash",    "Remote code execution without integrity check",           "FAIL"),
      ("eval $variable", "Trivial injection if variable controlled by attacker",    "FAIL")]),
    ("YAML / CI .yml", PURPLE,
     "CI/CD pipelines — a bad config opens backdoors",
     [("Unpinned actions", "uses: action@main → vulnerable to tag-hijacking", "FAIL"),
      ("Inline secrets",   "password: value (not ${{ secrets.XXX }})",         "FAIL")]),
    ("Terraform .tf", GREEN,
     "IaC — can provision entire cloud resources",
     [("checkov (CIS)", "S3 buckets, overly broad IAM, DB without at-rest encryption", "FAIL"),
      ("Hardcoded secrets", "password = \"value\" in .tf/.tfvars",                    "FAIL")]),
]

for group_start in range(0, len(details), 2):
    bg(cv)
    rect(cv, 0, H - 80, W, 80, HDR_PUR)
    text(cv, "08  Layer 5 — Per-type Check Details", 35, H - 52,
         size=29, color=WHITE, bold=True)
    divider_line(cv, H - 83, PURPLE)

    for ci in range(2):
        di = group_start + ci
        if di >= len(details):
            break
        name, color, desc, checks = details[di]
        cx = 20 + ci * 660
        cw = 645

        card(cv, cx, H - 710, cw, 600, BG_CARD, radius=8)
        rect(cv, cx, H - 130, cw, 48, color)
        text(cv, name, cx + cw/2, H - 110, size=17, color=WHITE,
             bold=True, align="center")
        text(cv, desc, cx + cw/2, H - 155, size=12, color=GRAY,
             align="center")

        for i, (check, expl, verdict) in enumerate(checks):
            cy = H - 220 - i * 155
            fill_c = ALT_ROW1 if i % 2 == 0 else ALT_ROW2
            rect(cv, cx + 10, cy - 120, cw - 20, 125, fill_c, radius=4)
            vcolor = RED if verdict == "FAIL" else ORANGE
            text(cv, check, cx + 20, cy - 25, size=13, color=vcolor, bold=True)
            badge(cv, verdict, cx + cw - 90, cy - 35, 72, 24, vcolor)
            chars = int((cw - 35) / 7.5)
            lines = textwrap.wrap(expl, chars)
            for li, ll in enumerate(lines):
                text(cv, ll, cx + 20, cy - 65 - li * 26, size=11, color=DARK)
    cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — NEW LANGUAGES (Java, PHP, Ruby, Go, XML)
# ═══════════════════════════════════════════════════════════════════════════════
new_lang_details = [
    ("Java .java", HexColor("#C06010"),
     "Runtime reflection & deserialization — critical attack surface",
     [("Runtime.exec() (CWE-78)",    "OS command injection via Java runtime shell execution",         "FAIL"),
      ("ObjectInputStream (CWE-502)", "Deserialization of untrusted data — RCE vector",              "FAIL"),
      ("Log4Shell JNDI (CVE-2021-44228)", "JNDI lookup in log messages → critical 0-day pattern",   "FAIL"),
      ("TrustAllCerts (CWE-295)",    "Disabled TLS certificate validation → MITM",                   "FAIL")]),
    ("PHP .php", HexColor("#6A2FA0"),
     "Direct user input to shell / output — classic web attack surface",
     [("shell_exec() (CWE-78)",  "Direct shell execution with user-controlled input",            "FAIL"),
      ("echo $_GET (CWE-79)",    "Reflected XSS — user input echoed without sanitization",      "FAIL"),
      ("include($var) (CWE-22)", "Remote/local file inclusion via variable path",               "FAIL"),
      ("unserialize() (CWE-502)","PHP deserialization → object injection & RCE",               "FAIL")]),
    ("Ruby .rb", ACCENT2,
     "Metaprogramming power creates significant injection risk",
     [("system/exec (CWE-78)",       "Shell command injection via system() or exec()",          "FAIL"),
      ("eval() (CWE-95)",            "Dynamic code evaluation — trivial code injection",        "FAIL"),
      ("ActiveRecord interpolation (CWE-89)", "SQL injection via string interpolation in queries", "FAIL")]),
    ("Go .go", HexColor("#00758F"),
     "Low-level control — subtle SQL and crypto pitfalls",
     [("fmt.Sprintf in SQL (CWE-89)", "String-formatted SQL queries → SQL injection",           "FAIL"),
      ("math/rand (CWE-338)",         "Weak PRNG — not cryptographically secure",              "WARN"),
      ("TLS MinVersion (CWE-326)",    "Weak TLS version allowed (< TLS 1.2)",                 "FAIL")]),
    ("XML .xml", HexColor("#8B0000"),
     "XML External Entity (XXE) — file read & SSRF via XML parsers",
     [("DOCTYPE + ENTITY (CWE-611)", "XXE: reads local files or makes internal HTTP requests", "FAIL"),
      ("SYSTEM entity",               "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",             "FAIL")]),
]

for group_start in range(0, len(new_lang_details), 2):
    bg(cv)
    rect(cv, 0, H - 80, W, 80, L5_COLOR)
    text(cv, "08  Layer 5 — New Languages: Java · PHP · Ruby · Go · XML", 35, H - 52,
         size=26, color=WHITE, bold=True)
    divider_line(cv, H - 83, L5_COLOR)

    for ci in range(2):
        di = group_start + ci
        if di >= len(new_lang_details):
            break
        name, color, desc, checks = new_lang_details[di]
        cx = 20 + ci * 660
        cw = 645

        card(cv, cx, H - 710, cw, 600, BG_CARD, radius=8)
        rect(cv, cx, H - 130, cw, 48, color)
        text(cv, name, cx + cw/2, H - 110, size=15, color=WHITE, bold=True, align="center")
        text(cv, desc, cx + cw/2, H - 155, size=11, color=GRAY, align="center")

        item_h = 140 if len(checks) >= 4 else 165
        for i, (check, expl, verdict) in enumerate(checks):
            cy = H - 215 - i * item_h
            fill_c = ALT_ROW1 if i % 2 == 0 else ALT_ROW2
            rect(cv, cx + 10, cy - (item_h - 18), cw - 20, item_h - 5, fill_c, radius=4)
            vcolor = RED if verdict == "FAIL" else ORANGE
            text(cv, check, cx + 20, cy - 22, size=12, color=vcolor, bold=True)
            badge(cv, verdict, cx + cw - 90, cy - 32, 72, 24, vcolor)
            chars = int((cw - 35) / 7.0)
            lines = textwrap.wrap(expl, chars)
            for li, ll in enumerate(lines):
                text(cv, ll, cx + 20, cy - 58 - li * 24, size=10, color=DARK)
    cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — Additional Types (Dockerfile, Binaries, Archives, SQL)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_PUR)
text(cv, "08  Layer 5 — Dockerfile · Binaries · Archives · SQL",
     35, H - 52, size=26, color=WHITE, bold=True)
divider_line(cv, H - 83, PURPLE)

extra = [
    ("Dockerfile", ORANGE,
     [("hadolint", "CIS Docker: :latest, ADD http://, apt without --no-install-recommends", "FAIL"),
      ("RUN curl|bash", "Download + execution without integrity control", "FAIL")]),
    ("Binaries .so .exe .elf", RED,
     [("Auto FAIL", "No binaries in an AI repo — potential implant/RAT", "FAIL"),
      ("strings + IOC", "/bin/sh /etc/passwd exec reverse shell URLs detected", "FAIL")]),
    ("Archives .zip .tar.gz", ORANGE,
     [("Auto FAIL", "Content cannot be scanned without prior extraction", "FAIL"),
      ("Zip-slip", "Extraction to arbitrary paths (../../etc/cron.d/)", "FAIL")]),
    ("SQL .sql", ACCENT2,
     [("xp_cmdshell", "Shell command execution from SQL Server → critical IOC", "FAIL"),
      ("DROP TABLE / --", "Destructive statements + SQL injection pattern", "FAIL")]),
]
for i, (name, color, checks) in enumerate(extra):
    col = i % 2; row = i // 2
    ex = 20 + col * 660
    ey = H - 120 - row * 295

    card(cv, ex, ey - 260, 645, 260, BG_CARD, radius=8)
    rect(cv, ex, ey - 48, 645, 48, color)
    text(cv, name, ex + 322, ey - 26, size=15, color=WHITE, bold=True, align="center")
    for ci2, (check, expl, verdict) in enumerate(checks):
        cy2 = ey - 110 - ci2 * 90
        fill_c2 = ALT_ROW1 if ci2 % 2 == 0 else ALT_ROW2
        rect(cv, ex + 10, cy2 - 72, 625, 78, fill_c2, radius=4)
        text(cv, f"• {check}", ex + 20, cy2 - 22, size=12, color=RED, bold=True)
        badge(cv, verdict, ex + 555, cy2 - 32, 72, 22, RED)
        text(cv, expl, ex + 20, cy2 - 52, size=10, color=DARK, max_w=600)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — TOOLS SUMMARY (updated)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, GREEN)
text(cv, "09  Tools Used — Summary", 35, H - 52, size=32,
     color=WHITE, bold=True)
divider_line(cv, H - 83, GREEN)

text(cv, "All optional in degraded mode — WARN if absent, FAIL only on active finding",
     W/2, H - 103, size=14, color=ORANGE, align="center")

hdrs_t = [("Tool", 20, 180), ("Role", 205, 280),
          ("Installation", 490, 330), ("Scope", 825, 490)]
for hdr, hx, hw in hdrs_t:
    rect(cv, hx, H - 142, hw, 36, HDR_GRN)
    text(cv, hdr, hx + hw/2, H - 128, size=12, color=WHITE,
         bold=True, align="center")

tools_data = [
    ("Gitleaks",       "secrets/tokens",             "GitHub binary",          "L1 Global",   ACCENT),
    ("detect-secrets", "high entropy",               "pip install",            "L1 Global",   ACCENT),
    ("ClamAV",         "malware signatures",         "apt install clamav",     "L1 Global",   ORANGE),
    ("YARA",           "custom IOC",                 "apt install yara",       "L1 Global",   PURPLE),
    ("Semgrep",        "OWASP/CWE rulesets (×4)",   "pip install semgrep",    "L2 OWASP/CWE", L2_COLOR),
    ("trivy",          "SCA universal CVE scan",     "GitHub binary",          "L3 SCA",      L3_COLOR),
    ("pip-audit",      "Python SCA (PyPA)",          "pip install pip-audit",  "L3 SCA",      L3_COLOR),
    ("safety",         "Python SCA (PyUp.io)",       "pip install safety",     "L3 SCA",      L3_COLOR),
    ("npm audit",      "Node.js SCA (built-in)",     "built-in npm",           "L3 SCA",      L3_COLOR),
    ("Bandit",         "Python SAST",                "pip install bandit",     "L5 .py",      HexColor("#B8860B")),
    ("cppcheck",       "C/C++ static analysis",      "apt install cppcheck",   "L5 .c .cpp",  ACCENT2),
    ("ShellCheck",     "shell linting",              "apt install shellcheck", "L5 .sh",      ACCENT2),
    ("hadolint",       "Dockerfile linting",         "GitHub binary",          "L5 Docker",   GREEN),
    ("checkov",        "IaC security",               "pip install checkov",    "L5 .tf",      GREEN),
    ("jq",             "GitHub API JSON parsing",    "apt install jq",         "Utility",     GRAY),
]
RH2 = 38
for ri, (name, role, install, scope, color) in enumerate(tools_data):
    ry2 = H - 145 - (ri + 1) * RH2
    bg2 = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
    rect(cv, 20, ry2, 1295, RH2 - 2, bg2)
    text(cv, name,    110, ry2 + 11, size=10, color=color, bold=True, align="center")
    text(cv, role,    345, ry2 + 11, size=10, color=DARK, align="center")
    text(cv, install, 655, ry2 + 11, size=9,  color=DARK, align="center")
    text(cv, scope,   1070, ry2 + 11, size=10, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — RESULTS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT)
text(cv, "10  Results — ZIP Archive & Excel Report",
     35, H - 52, size=30, color=WHITE, bold=True)
divider_line(cv, H - 83)

# Left column: ZIP
card(cv, 20, H - 700, 620, 590, BG_CARD, radius=8)
rect(cv, 20, H - 135, 620, 50, GREEN)
text(cv, "📦  ZIP Archive  →  Good/", 330, H - 116, size=16,
     color=WHITE, bold=True, align="center")

zip_tree = [
    "Good/",
    "└── repo_20260615_143022.zip",
    "    ├── src/",
    "    │   └── [full source code]",
    "    ├── README.md",
    "    └── scan_report_20260615.xlsx",
]
mono_box(cv, zip_tree, 30, H - 330, 600, 175, size=10)

zip_pts = [
    "✔  Produced only if verdict is PASS",
    "✔  Timestamped name — guaranteed uniqueness",
    "✔  .manifest_sha256.txt excluded",
    "✔  Excel report included directly",
    "✔  Ready for internal network transfer",
    "✔  Optional: GPG encryption",
]
for i, pt in enumerate(zip_pts):
    text(cv, pt, 35, H - 360 - i * 46, size=13, color=DARK)

# Right column: Excel
card(cv, 660, H - 700, 650, 590, BG_CARD, radius=8)
rect(cv, 660, H - 135, 650, 50, ACCENT2)
text(cv, "📊  Excel Report (.xlsx)", 985, H - 116, size=16,
     color=WHITE, bold=True, align="center")

text(cv, "Tab 0 — Summary", 675, H - 163, size=14, color=ACCENT2, bold=True)
tab0_rows = [
    ("Repository / Source", "GitHub URL or local path"),
    ("Scan Date",           "ISO 8601 timestamp"),
    ("SHA-256 Hash",        "Global fingerprint of all files"),
    ("Verdict",             "PASS (green) / FAIL (red)"),
    ("Counters",            "PASS · WARN · FAIL"),
]
for i, (k, v) in enumerate(tab0_rows):
    ry3 = H - 210 - i * 40
    rect(cv, 670, ry3 - 26, 200, 34, HexColor("#D8E8F4"))
    text(cv, k, 675, ry3 - 14, size=11, color=ACCENT2, bold=True)
    text(cv, v, 878, ry3 - 14, size=11, color=DARK)

text(cv, "Tab 1 — Files (one row per file)", 675, H - 430,
     size=14, color=HexColor("#B8860B"), bold=True)
col1_hdrs = ["#", "File", "Type", "Status", "Message"]
col1_x = [675, 715, 935, 1040, 1135]
col1_w = [35, 215, 100, 90, 165]
for j, (h2, hx2, hw2) in enumerate(zip(col1_hdrs, col1_x, col1_w)):
    rect(cv, hx2, H - 470, hw2, 32, PURPLE)
    text(cv, h2, hx2 + hw2/2, H - 456, size=10, color=WHITE,
         bold=True, align="center")

sample = [("1","src/main.py",".py","FAIL","bandit:HIGH", RED, RED_ROW),
          ("2","config.sh",  ".sh","WARN","shellcheck absent", ORANGE, ORG_ROW),
          ("3","README.md",  ".md","PASS","—", GREEN, GRN_ROW)]
for si, (n, f, t, s, m, sc, sr) in enumerate(sample):
    ry4 = H - 472 - (si + 1) * 42
    rect(cv, 675, ry4, 625, 38, sr)
    for val, hx2, hw2 in zip([n, f, t, s, m], col1_x, col1_w):
        vc = sc if val == s else DARK
        text(cv, val, hx2 + hw2/2, ry4 + 12, size=10, color=vc,
             bold=(val == s), align="center")

text(cv, "Sorted FAIL→WARN→PASS | Auto-filter | Row 1 frozen",
     985, H - 690, size=10, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — SECURITY RULES
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, RED)
text(cv, "11  Absolute Security Rules", 35, H - 52, size=32,
     color=WHITE, bold=True)
divider_line(cv, H - 83, RED)

text(cv, "⛔  These rules CANNOT be modified — they constitute the threat model",
     W/2, H - 103, size=14, color=RED, bold=True, align="center")

rules_s = [
    ("🔒  Network Isolation",
     "The transit machine NEVER has direct access to the corporate network."),
    ("➡  One-way Flow",
     "Only approved/ is readable from the inside — not fetch/, logs/, quarantine/."),
    ("🔐  Root-only Quarantine",
     "chmod 700 — no application user can read rejected files."),
    ("🚫  No Manual Move",
     "Never quarantine/ → approved/ without a full pipeline re-scan."),
    ("⚠  Binaries = Absolute FAIL",
     "No .so/.exe/.elf in an AI repo — zero exceptions."),
    ("📦  Archives = Mandatory Re-scan",
     ".zip/.tar.gz → extraction + re-scan in a dedicated isolated environment."),
]
for i, (title, desc) in enumerate(rules_s):
    col = i % 2; row = i // 2
    rx = 20 + col * 660
    ry = H - 145 - row * 190
    card(cv, rx, ry - 162, 645, 165, BG_CARD, radius=8)
    rect(cv, rx, ry - 48, 645, 48, HexColor("#C0000C"))
    text(cv, title, rx + 15, ry - 26, size=14, color=WHITE, bold=True)
    text(cv, desc, rx + 15, ry - 95, size=13, color=DARK, max_w=600)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SUCCESS CRITERIA SLIDES
# ═══════════════════════════════════════════════════════════════════════════════

# Shared table-drawing helper for success-criteria slides
PASS_BG  = HexColor("#E8F5E9")
WARN_BG  = HexColor("#FFF8E1")
FAIL_BG  = HexColor("#FFEBEE")
HDR_NAVY = HexColor("#1F3864")

# Layer badge colors
L1_BADGE = HexColor("#0070A8")   # blue
L2_BADGE = HexColor("#8E44AD")   # purple
L3_BADGE = HexColor("#007B7B")   # teal
L4_BADGE = HexColor("#C06010")   # orange
L5_BADGE = HexColor("#2E7D32")   # green


def sc_header(cv, subtitle):
    bg(cv)
    rect(cv, 0, H - 80, W, 80, HDR_NAVY)
    text(cv, "Success Criteria per Tool", 35, H - 53, size=30, color=WHITE, bold=True)
    text(cv, subtitle, W - 35, H - 53, size=13, color=HexColor("#A0B8D0"), bold=False, align="right")
    line(cv, 30, H - 82, W - 30, H - 82, ACCENT, 1.5)


def draw_layer_pill(cv, label, x, y, w, h, color):
    rect(cv, x, y, w, h, color, radius=5)
    cx = x + w / 2
    cy = y + h / 2 - 5
    cv.setFillColor(WHITE)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(cx, cy, label)


def sc_table(cv, table_y, col_defs, rows, row_h=30):
    """Draw a success-criteria table.
    col_defs: list of (header_str, x, width)
    rows: list of (layer_label, layer_color, tool, pass_txt, warn_txt, fail_txt, standard)
    """
    # header row
    for hdr, hx, hw in col_defs:
        rect(cv, hx, table_y, hw, 28, HDR_NAVY)
        cv.setFillColor(WHITE)
        cv.setFont("Helvetica-Bold", 10)
        cv.drawCentredString(hx + hw / 2, table_y + 9, hdr)

    cur_y = table_y - row_h
    for ri, row in enumerate(rows):
        layer_lbl, layer_col, tool, pass_t, warn_t, fail_t, standard = row
        bg_row = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
        # draw row background spanning all columns
        x0 = col_defs[0][1]
        x_end = col_defs[-1][1] + col_defs[-1][2]
        rect(cv, x0, cur_y, x_end - x0, row_h - 1, bg_row)

        # layer pill — first col
        pill_x = col_defs[0][1] + 3
        draw_layer_pill(cv, layer_lbl, pill_x, cur_y + 5, col_defs[0][2] - 6, row_h - 11, layer_col)

        # tool
        cv.setFillColor(DARK)
        cv.setFont("Helvetica-Bold", 9)
        cv.drawString(col_defs[1][1] + 4, cur_y + 9, tool)

        # PASS cell
        if pass_t:
            rect(cv, col_defs[2][1], cur_y + 2, col_defs[2][2] - 2, row_h - 5, PASS_BG)
            cv.setFillColor(HexColor("#1B5E20"))
            cv.setFont("Helvetica", 8)
            cv.drawCentredString(col_defs[2][1] + col_defs[2][2] / 2, cur_y + 9, pass_t)

        # WARN cell
        if warn_t:
            rect(cv, col_defs[3][1], cur_y + 2, col_defs[3][2] - 2, row_h - 5, WARN_BG)
            cv.setFillColor(HexColor("#5D4037"))
            cv.setFont("Helvetica", 8)
            cv.drawCentredString(col_defs[3][1] + col_defs[3][2] / 2, cur_y + 9, warn_t)

        # FAIL cell
        if fail_t:
            rect(cv, col_defs[4][1], cur_y + 2, col_defs[4][2] - 2, row_h - 5, FAIL_BG)
            cv.setFillColor(HexColor("#B71C1C"))
            cv.setFont("Helvetica", 8)
            cv.drawCentredString(col_defs[4][1] + col_defs[4][2] / 2, cur_y + 9, fail_t)

        # standard
        cv.setFillColor(GRAY)
        cv.setFont("Helvetica", 8)
        cv.drawString(col_defs[5][1] + 4, cur_y + 9, standard)

        cur_y -= row_h


# ── SLIDE A: Layer 1 (Global) & Layer 2 (OWASP/CWE) ──────────────────────────
sc_header(cv, "Slide A — Layer 1 & Layer 2")

text(cv, "Success Criteria — Layer 1 (Global) & Layer 2 (OWASP/CWE)",
     W / 2, H - 103, size=16, color=DARK, bold=True, align="center")

# column definitions: (header, x, width)
col_A = [
    ("Layer",    20,  60),
    ("Tool",     82, 190),
    ("PASS",    274, 220),
    ("WARN",    496, 200),
    ("FAIL",    698, 200),
    ("Standard",900, 413),
]

rows_A = [
    # layer_lbl, layer_col, tool, pass, warn, fail, standard
    ("L1", L1_BADGE, "gitleaks",        "0 secrets found",        "—",                  "≥1 credential match",   "CWE-798 / OWASP A02"),
    ("L1", L1_BADGE, "detect-secrets",  "0 high-entropy hits",    "—",                  "≥1 entropy hit",        "CWE-798 / OWASP A02"),
    ("L1", L1_BADGE, "ClamAV",          "0 signatures matched",   "DB not updated",     "≥1 malware signature",  "OWASP A08 / CERT"),
    ("L1", L1_BADGE, "YARA",            "0 IOC rules triggered",  "Custom rules absent","≥1 YARA rule hit",      "MITRE ATT&CK / IOC"),
    ("L2", L2_BADGE, "Semgrep p/owasp-top-ten", "0 findings",    "Semgrep not found",  "≥1 HIGH/CRITICAL",      "OWASP Top 10 2021"),
    ("L2", L2_BADGE, "Semgrep p/cwe-top-25",    "0 findings",    "—",                  "≥1 HIGH/CRITICAL",      "CWE Top 25"),
    ("L2", L2_BADGE, "Semgrep p/security-audit", "0 findings",   "—",                  "≥1 HIGH/CRITICAL",      "OWASP / CERT"),
    ("L2", L2_BADGE, "Semgrep p/secrets",        "0 findings",   "—",                  "≥1 secret detected",    "CWE-798 / OWASP A02"),
]

sc_table(cv, H - 135, col_A, rows_A, row_h=56)

text(cv, "All L1 findings → FAIL  |  L2 findings scored by severity: HIGH/CRITICAL → FAIL, MEDIUM → WARN",
     W / 2, 30, size=11, color=GRAY, align="center")
cv.showPage()


# ── SLIDE B: Layer 3 (SCA) & Layer 4 (Universal Patterns) ────────────────────
sc_header(cv, "Slide B — Layer 3 & Layer 4")

text(cv, "Success Criteria — Layer 3 (SCA) & Layer 4 (Universal Patterns)",
     W / 2, H - 103, size=16, color=DARK, bold=True, align="center")

col_B = [
    ("Layer",    20,  60),
    ("Tool",     82, 200),
    ("PASS",    284, 210),
    ("WARN",    496, 195),
    ("FAIL",    693, 205),
    ("CWE / OWASP", 900, 413),
]

rows_B = [
    ("L3", L3_BADGE, "trivy",            "0 CVEs CRITICAL/HIGH",  "MEDIUM CVE found",   "≥1 CRITICAL/HIGH CVE",  "OWASP A06 / NVD"),
    ("L3", L3_BADGE, "pip-audit / safety","0 vulnerable pkgs",    "Outdated package",   "≥1 known CVE in reqs",  "OWASP A06 / PyPA"),
    ("L3", L3_BADGE, "npm audit",         "0 critical/high",      "moderate advisory",  "critical or high vuln", "OWASP A06 / npm"),
    ("L4", L4_BADGE, "Hardcoded creds",   "0 matches",            "—",                  "password= / api_key=",  "CWE-798"),
    ("L4", L4_BADGE, "Hardcoded crypto",  "0 matches",            "—",                  "BEGIN RSA PRIVATE KEY", "CWE-321"),
    ("L4", L4_BADGE, "Path traversal",    "0 matches",            "—",                  "../../etc/passwd",      "CWE-22"),
    ("L4", L4_BADGE, "SSRF pattern",      "0 matches",            "user_input in URL",  "—",                     "CWE-918 / OWASP A10"),
    ("L4", L4_BADGE, "Weak crypto",       "0 matches",            "md5 / sha1 / rc4",   "—",                     "CWE-327"),
    ("L4", L4_BADGE, "Weak PRNG",         "0 matches",            "Math.random()/rand()","—",                    "CWE-338"),
    ("L4", L4_BADGE, "Logging disabled",  "0 matches",            "logging.disable(…)", "—",                     "OWASP A09"),
]

sc_table(cv, H - 135, col_B, rows_B, row_h=49)

text(cv, "L3: CRITICAL/HIGH CVE → FAIL  |  L4: hardcoded secrets/traversal → FAIL; weak patterns → WARN",
     W / 2, 30, size=11, color=GRAY, align="center")
cv.showPage()


# ── SLIDE C: Layer 5 (Per-type SAST) — Summary Matrix ────────────────────────
sc_header(cv, "Slide C — Layer 5 Summary")

text(cv, "Success Criteria — Layer 5 (Per-type SAST) — Summary Matrix",
     W / 2, H - 103, size=16, color=DARK, bold=True, align="center")

# Column definitions for the L5 matrix
col_C = [
    ("Lang / Type",    20,  120),
    ("Key Tool",      142,  145),
    ("# Checks",      289,   80),
    ("Verdict if triggered", 371, 190),
    ("Key Standards",  563,  750),
]

# header row
table_y_C = H - 135
for hdr, hx, hw in col_C:
    rect(cv, hx, table_y_C, hw, 26, HDR_NAVY)
    cv.setFillColor(WHITE)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(hx + hw / 2, table_y_C + 8, hdr)

rows_C = [
    ("Python .py",        "Bandit",       "50+",  "FAIL",   "CWE-78, CWE-89, CWE-94, OWASP A03"),
    ("JS / TS .js .ts",   "Semgrep",      "40+",  "FAIL",   "CWE-79, CWE-94, OWASP A03 XSS/Injection"),
    ("C / C++ .c .cpp",   "cppcheck",     "30+",  "FAIL",   "CWE-120, CWE-125, CWE-416, CERT-C"),
    ("Shell .sh .bash",   "ShellCheck",   "20+",  "FAIL",   "CWE-78, OWASP A03, CERT"),
    ("Java .java",        "Semgrep",      "25+",  "FAIL",   "CWE-78, CWE-502, CVE-2021-44228, CWE-295"),
    ("PHP .php",          "Semgrep",      "20+",  "FAIL",   "CWE-78, CWE-79, CWE-22, CWE-502"),
    ("Ruby .rb",          "Semgrep",      "15+",  "FAIL",   "CWE-78, CWE-89, CWE-95"),
    ("Go .go",            "Semgrep",      "15+",  "FAIL/WARN","CWE-89, CWE-326, CWE-338"),
    ("XML .xml",          "grep (regex)", "2",    "FAIL",   "CWE-611 (XXE)"),
    ("YAML .yml",         "—  (regex)",   "2",    "FAIL",   "Supply-chain / OWASP A08"),
    ("Terraform .tf",     "checkov",      "50+",  "FAIL",   "CIS Benchmarks, OWASP A05, CWE-798"),
    ("Dockerfile",        "hadolint",     "30+",  "FAIL",   "CIS Docker Benchmark, OWASP A05"),
    ("SQL .sql",          "grep (regex)", "3",    "FAIL",   "CWE-89, CWE-78"),
    ("Binary .so .exe",   "strings+Auto", "—",    "FAIL ⚠","Auto-FAIL policy — no binaries in AI repos"),
    ("Archive .zip .tar", "—  (policy)",  "—",    "FAIL ⚠","Auto-FAIL — re-scan after extraction"),
]

row_h_C = 36
cur_y_C = table_y_C - row_h_C
for ri, (lang, tool, num_checks, verdict, standards) in enumerate(rows_C):
    bg_row = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
    x0 = col_C[0][1]
    x_end = col_C[-1][1] + col_C[-1][2]
    rect(cv, x0, cur_y_C, x_end - x0, row_h_C - 1, bg_row)

    # layer badge (always L5)
    draw_layer_pill(cv, "L5", x0 + 2, cur_y_C + 6, 28, row_h_C - 13, L5_BADGE)

    cv.setFillColor(DARK)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawString(col_C[0][1] + 33, cur_y_C + 12, lang)

    cv.setFont("Helvetica", 9)
    cv.drawCentredString(col_C[1][1] + col_C[1][2] / 2, cur_y_C + 12, tool)

    cv.setFillColor(ACCENT)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(col_C[2][1] + col_C[2][2] / 2, cur_y_C + 12, num_checks)

    vcolor = RED if "FAIL" in verdict else ORANGE
    rect(cv, col_C[3][1] + 2, cur_y_C + 4, col_C[3][2] - 4, row_h_C - 9,
         FAIL_BG if "FAIL" in verdict else WARN_BG)
    cv.setFillColor(vcolor)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(col_C[3][1] + col_C[3][2] / 2, cur_y_C + 12, verdict)

    cv.setFillColor(GRAY)
    cv.setFont("Helvetica", 8)
    cv.drawString(col_C[4][1] + 4, cur_y_C + 12, standards)

    cur_y_C -= row_h_C

text(cv, "All L5 positive findings → FAIL  |  Missing tool → WARN (degraded mode)  |  Binaries & Archives → Auto-FAIL",
     W / 2, 20, size=10, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL SLIDES — one per tool
# ═══════════════════════════════════════════════════════════════════════════════

L6_COLOR = HexColor("#1A6B8A")   # teal for Layer 6

TOOL_CATALOG = [
    # (tool_name, layer_label, layer_color, install_cmd, purpose, offline, scan_cmd,
    #  pass_condition, fail_condition, warn_condition)
    (
        "betterleaks", "Layer 1 — Secrets & Credentials", L1_COLOR,
        "go install github.com/betterleaks/betterleaks@latest\n  brew install betterleaks",
        "Detects secrets, credentials and API keys embedded in source files.\n"
        "Successor to gitleaks — maintained by the same author with a more\n"
        "expressive allowlist system. Scans all file types, not just git history.",
        True,   # offline
        "betterleaks dir <repo_dir> -v",
        "Exit code 0 — no secrets or credentials detected in any file.",
        "Exit code ≠ 0 — at least one secret pattern matched (API key, token,\n"
        "password, private key …). → Pipeline verdict: FAIL.",
        "Tool not installed → scan skipped, WARN logged (degraded mode).",
    ),
    (
        "detect-secrets", "Layer 1 — Secrets & Credentials", L1_COLOR,
        "pip install detect-secrets",
        "Entropy-based secret detector — complements betterleaks with a\n"
        "different detection engine. Uses Shannon entropy and regex rules\n"
        "to find high-entropy strings that look like secrets.",
        True,
        "detect-secrets scan <repo_dir>",
        "JSON output with empty 'results' dict — no high-entropy secrets found.",
        "JSON output lists one or more findings → Pipeline verdict: FAIL.",
        "Tool not installed → scan skipped, WARN logged.",
    ),
    (
        "ClamAV  (clamscan)", "Layer 1 — Antivirus", L1_COLOR,
        "sudo apt-get install clamav clamav-daemon\nsudo freshclam   # update DB",
        "Open-source antivirus engine. Scans all files against a database\n"
        "of known malware signatures. Requires periodic DB updates via freshclam\n"
        "to stay effective against recent threats.",
        True,   # works offline once DB is updated
        "clamscan -r --no-summary <repo_dir>",
        "Exit code 0 — no virus signatures matched.",
        "Exit code 1 — at least one infected file found → Pipeline verdict: FAIL.",
        "freshclam DB not updated (>7 days) → WARN. Tool missing → WARN.",
    ),
    (
        "YARA", "Layer 1 — Custom IOC Rules", L1_COLOR,
        "sudo apt-get install yara",
        "Pattern-matching engine for malware and IOC detection. Loads all\n"
        ".yar rule files from yara-rules/ and matches them against every file.\n"
        "Rules are fully customisable — add organisation-specific IOC patterns.",
        True,
        "yara -r <rules_dir>/*.yar <repo_dir>",
        "No output — no rule matched any file.",
        "At least one YARA rule matched → Pipeline verdict: FAIL.",
        "No .yar files in yara-rules/ → WARN. Tool missing → WARN.",
    ),
    (
        "Semgrep", "Layer 2 — OWASP / CWE / CERT", L2_COLOR,
        "pip install semgrep",
        "Static analysis engine with a large open rule library.\n"
        "Runs four rulesets: p/owasp-top-ten, p/cwe-top-25,\n"
        "p/security-audit, p/secrets. Covers injection, XSS, insecure\n"
        "deserialization, SSRF, weak crypto and 100+ more patterns.",
        False,  # needs internet for rule download first time
        "semgrep --config p/owasp-top-ten --config p/cwe-top-25\n"
        "  --config p/security-audit --config p/secrets\n"
        "  --json <repo_dir>",
        "JSON output with empty 'results' list — no rule matched.",
        "ERROR or WARNING severity findings → Pipeline verdict: FAIL.",
        "INFO severity → WARN. Tool missing or no internet → WARN.",
    ),
    (
        "trivy", "Layer 3 — SCA / CVE", L3_COLOR,
        "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/\n"
        "  main/contrib/install.sh | sh -s -- -b /usr/local/bin",
        "Software Composition Analysis — scans dependency manifests\n"
        "(requirements.txt, package-lock.json, go.sum, pom.xml …) and\n"
        "cross-references installed packages against NVD, OSV and GitHub\n"
        "Advisory databases to find known CVEs.",
        False,  # needs DB download first time
        "trivy fs <repo_dir> --scanners vuln\n"
        "  --severity HIGH,CRITICAL --format json",
        "JSON output with no vulnerabilities at HIGH or CRITICAL severity.",
        "CRITICAL or HIGH CVE found in a dependency → Pipeline verdict: FAIL.",
        "MEDIUM/LOW CVE → WARN. DB not up to date → WARN. Missing → WARN.",
    ),
    (
        "pip-audit", "Layer 3 — Python CVE", L3_COLOR,
        "pip install pip-audit",
        "Audits Python requirements files against the Python Packaging\n"
        "Advisory Database (PyPA) and OSV. Checks requirements.txt,\n"
        "requirements*.txt and setup.cfg for packages with known CVEs.",
        False,
        "pip-audit -r requirements.txt --format json",
        "JSON output with no vulnerabilities listed.",
        "Any CVE found in a Python dependency → Pipeline verdict: FAIL.",
        "Tool missing → WARN, scan skipped.",
    ),
    (
        "safety", "Layer 3 — Python Advisories", L3_COLOR,
        "pip install safety",
        "Checks Python dependencies against the Safety DB — a curated\n"
        "advisory database maintained by PyUp.io. Complements pip-audit\n"
        "with additional advisories not always in OSV.",
        False,
        "safety check -r requirements.txt --json",
        "Exit code 0 — no advisories matched.",
        "Any advisory matched → Pipeline verdict: FAIL.",
        "Tool missing or DB unreachable → WARN.",
    ),
    (
        "npm audit", "Layer 3 — Node.js CVE", L3_COLOR,
        "sudo apt-get install nodejs npm\n(or: nvm install --lts)",
        "Built into npm — audits package-lock.json against the npm security\n"
        "advisory registry. Finds known CVEs in Node.js dependencies\n"
        "and their transitive dependencies.",
        False,
        "npm audit --json   (run in dir with package-lock.json)",
        "JSON output with 0 vulnerabilities at high or critical level.",
        "Critical or high severity advisory found → Pipeline verdict: FAIL.",
        "Moderate/low → WARN. No package-lock.json → scan skipped.",
    ),
    (
        "grep  (universal patterns)", "Layer 4 — Universal Pattern Scan", L4_COLOR,
        "Built-in — no installation required",
        "Runs on every file regardless of extension. Checks for:\n"
        "CWE-798 (hardcoded credentials), CWE-22 (path traversal),\n"
        "CWE-918 (SSRF patterns), CWE-327 (weak crypto constants),\n"
        "CWE-338 (weak PRNG), OWASP-A09 (logging of sensitive data).",
        True,
        "grep -rE '<pattern>' <file>   (run per-pattern, per-file)",
        "No pattern matches across all CWE checks for this file.",
        "Any pattern match → finding recorded. Severity determines WARN or FAIL.",
        "N/A — grep is always available.",
    ),
    (
        "Bandit", "Layer 5 — Python SAST", L5_COLOR,
        "pip install bandit",
        "Python-specific static analyser. Detects common security issues:\n"
        "use of assert, subprocess with shell=True, hardcoded passwords,\n"
        "use of pickle, XML vulnerabilities, SQL injection via string format,\n"
        "insecure random, weak hashing, and more (100+ plugins).",
        True,
        "bandit -ll -r <python_file_or_dir>",
        "Exit code 0 — no medium or high confidence issues found.",
        "MEDIUM or HIGH severity + MEDIUM or HIGH confidence → FAIL.",
        "LOW confidence findings → WARN. Tool missing → WARN.",
    ),
    (
        "ShellCheck", "Layer 5 — Shell Script SAST", L5_COLOR,
        "sudo apt-get install shellcheck",
        "Static analyser for Bash/sh/dash/ksh scripts. Detects quoting\n"
        "errors, injection risks, undefined variables, deprecated syntax,\n"
        "unintended word splitting, and unsafe patterns that could lead\n"
        "to command injection or data leakage.",
        True,
        "shellcheck --severity=warning <script.sh>",
        "Exit code 0 — no warnings or errors.",
        "Exit code ≠ 0 (errors/warnings at warning level or above) → FAIL.",
        "Tool missing → WARN.",
    ),
    (
        "cppcheck", "Layer 5 — C/C++ SAST", L5_COLOR,
        "sudo apt-get install cppcheck",
        "Static analyser for C and C++. Detects buffer overflows, memory\n"
        "leaks, null-pointer dereferences, use-after-free, out-of-bounds\n"
        "array access, and undefined behaviour — without compiling the code.",
        True,
        "cppcheck --enable=warning,security --error-exitcode=1 <file.cpp>",
        "Exit code 0 — no errors or security warnings.",
        "Exit code 1 — at least one security or error finding → FAIL.",
        "Tool missing → WARN.",
    ),
    (
        "hadolint", "Layer 5 — Dockerfile Linter", L5_COLOR,
        "curl -sSL https://github.com/hadolint/hadolint/releases/\n"
        "  download/v2.12.0/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint",
        "Linter for Dockerfiles. Enforces Dockerfile best practices and\n"
        "detects security misconfigurations: running as root, using :latest\n"
        "tags, unnecessary privileges, secrets in ENV/ARG, ADD vs COPY,\n"
        "and shell injection risks.",
        True,
        "hadolint --failure-threshold warning <Dockerfile>",
        "Exit code 0 — no warnings or errors.",
        "DL or SC rules triggered at warning level or above → FAIL.",
        "Tool missing → WARN.",
    ),
    (
        "checkov", "Layer 5 — Terraform / IaC SAST", L5_COLOR,
        "pip install checkov",
        "Static analysis for Infrastructure-as-Code: Terraform (.tf),\n"
        "CloudFormation, Kubernetes YAML, Ansible, ARM templates.\n"
        "Maps findings to CIS Benchmarks, NIST, SOC2 and OWASP.\n"
        "Over 1000 built-in checks.",
        True,
        "checkov -d <dir> --framework terraform --output json",
        "All checks pass — no FAILED checks in JSON output.",
        "At least one FAILED check → Pipeline verdict: FAIL.",
        "SKIPPED checks → WARN. Tool missing → WARN.",
    ),
    (
        "ScanCode Toolkit", "Layer 6 — Licence, Copyright & CVE", L6_COLOR,
        "pip install scancode-toolkit",
        "Full-text licence and copyright analyser. Detects SPDX licence\n"
        "expressions across all source files using a library of 30 000+\n"
        "licence texts. Also detects package manifests and CVEs in detected\n"
        "packages. Produces JSON / SPDX / CycloneDX reports.",
        True,
        "scancode --license --copyright --vulnerability\n"
        "  --package --json-pp report.json <repo_dir>",
        "No risky licences (GPL/AGPL/LGPL/SSPL …) detected AND no\n"
        "HIGH/CRITICAL CVE in detected packages.",
        "CRITICAL or HIGH CVE in a detected package → FAIL.",
        "Risky licence detected (score ≥ 70) → WARN (legal review required).\n"
        "LOW/MEDIUM CVE → WARN. Tool missing → WARN.",
    ),
]


def tool_slide(cv, tool_data):
    (name, layer, lcolor, install, purpose, offline,
     scan_cmd, pass_cond, fail_cond, warn_cond) = tool_data

    bg(cv)
    # Header bar
    rect(cv, 0, H - 72, W, 72, lcolor)
    text(cv, name, 28, H - 48, size=30, color=WHITE, bold=True)
    text(cv, layer, W - 28, H - 48, size=14, color=HexColor("#CCDDEE"),
         align="right")
    divider_line(cv, H - 75, lcolor)

    COL1 = 28
    COL2 = 680
    CW   = 630

    # ── Purpose ──────────────────────────────────────────────────────────────
    rect(cv, COL1, H - 90, CW, 20, HexColor("#E8EEF8"), radius=0)
    text(cv, "PURPOSE", COL1 + 8, H - 104, size=9, color=lcolor, bold=True)
    card(cv, COL1, H - 270, CW, 170, HexColor("#F5F8FF"), radius=6)
    y = H - 125
    for line_txt in purpose.split("\n"):
        text(cv, line_txt.strip(), COL1 + 12, y, size=11, color=DARK)
        y -= 22

    # ── Install ───────────────────────────────────────────────────────────────
    text(cv, "INSTALL", COL1 + 8, H - 292, size=9, color=lcolor, bold=True)
    mono_box(cv, install.split("\n"), COL1, H - 390, CW, 90, size=9)

    # ── Scan command ─────────────────────────────────────────────────────────
    text(cv, "SCAN COMMAND", COL1 + 8, H - 415, size=9, color=lcolor, bold=True)
    mono_box(cv, scan_cmd.split("\n"), COL1, H - 510, CW, 90, size=9)

    # ── Offline badge ─────────────────────────────────────────────────────────
    offline_color = GREEN if offline else ORANGE
    offline_label = "✔  Works OFFLINE" if offline else "⚠  Requires INTERNET (first run)"
    badge(cv, offline_label, COL1, H - 545, 320, 26,
          HexColor("#D4EDDA") if offline else HexColor("#FFF3CD"),
          text_color=HexColor("#155724") if offline else HexColor("#856404"),
          size=10)

    # ── Right column: PASS / WARN / FAIL ─────────────────────────────────────
    # PASS
    rect(cv, COL2, H - 90, CW, 20, HexColor("#E8EEF8"), radius=0)
    text(cv, "✔  PASS condition", COL2 + 8, H - 104, size=9,
         color=HexColor("#1A7A40"), bold=True)
    card(cv, COL2, H - 230, CW, 130, HexColor("#F0FBF4"), radius=6)
    y = H - 125
    for line_txt in pass_cond.split("\n"):
        text(cv, line_txt.strip(), COL2 + 12, y, size=10,
             color=HexColor("#1A5C30"))
        y -= 20

    # FAIL
    text(cv, "✘  FAIL condition  →  pipeline blocked", COL2 + 8, H - 252,
         size=9, color=RED, bold=True)
    card(cv, COL2, H - 400, CW, 140, HexColor("#FFF5F5"), radius=6)
    y = H - 275
    for line_txt in fail_cond.split("\n"):
        text(cv, line_txt.strip(), COL2 + 12, y, size=10,
             color=HexColor("#7B1818"))
        y -= 20

    # WARN
    text(cv, "⚠  WARN condition  →  logged, pipeline continues",
         COL2 + 8, H - 422, size=9, color=ORANGE, bold=True)
    card(cv, COL2, H - 560, CW, 132, HexColor("#FFFDF0"), radius=6)
    y = H - 445
    for line_txt in warn_cond.split("\n"):
        text(cv, line_txt.strip(), COL2 + 12, y, size=10,
             color=HexColor("#7A5800"))
        y -= 20

    # Footer
    text(cv, f"AI Transit Pipeline  —  {name}  —  {layer}",
         W / 2, 18, size=9, color=GRAY, align="center")
    cv.showPage()


for tool_data in TOOL_CATALOG:
    tool_slide(cv, tool_data)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — TOOL SUMMARY TABLE (all tools + success/fail rationale)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 72, W, 72, DARK)
text(cv, "Tool Summary — Acceptance Rationale", 28, H - 48,
     size=28, color=WHITE, bold=True)
divider_line(cv, H - 75, ACCENT)

SUMMARY_TOOLS = [
    # (tool, layer, offline, pass_short, fail_short, warn_short)
    ("betterleaks",       "L1", True,
     "Exit 0 — no secrets",
     "Secret/key detected → FAIL",
     "Not installed → WARN"),
    ("detect-secrets",    "L1", True,
     "Empty results JSON",
     "High-entropy string found → FAIL",
     "Not installed → WARN"),
    ("ClamAV",            "L1", True,
     "Exit 0 — no virus",
     "Infected file found → FAIL",
     "DB outdated / missing → WARN"),
    ("YARA",              "L1", True,
     "No rule matched",
     "IOC rule matched → FAIL",
     "No rules / missing → WARN"),
    ("Semgrep",           "L2", False,
     "Empty results list",
     "ERROR/WARNING severity → FAIL",
     "INFO / no internet → WARN"),
    ("trivy",             "L3", False,
     "No HIGH/CRITICAL CVE",
     "CRITICAL or HIGH CVE → FAIL",
     "MEDIUM/LOW CVE → WARN"),
    ("pip-audit",         "L3", False,
     "No CVE in Python deps",
     "Any Python CVE → FAIL",
     "Not installed → WARN"),
    ("safety",            "L3", False,
     "No advisory matched",
     "Advisory matched → FAIL",
     "Not installed → WARN"),
    ("npm audit",         "L3", False,
     "0 critical/high vulns",
     "Critical/high vuln → FAIL",
     "No package-lock.json → skip"),
    ("grep (patterns)",   "L4", True,
     "No CWE pattern matched",
     "CWE-798/22/918/327/338 hit → FAIL",
     "N/A — always available"),
    ("Bandit",            "L5", True,
     "No medium/high issues",
     "Medium+ severity + confidence → FAIL",
     "Low confidence → WARN"),
    ("ShellCheck",        "L5", True,
     "Exit 0 — no warnings",
     "Warning-level finding → FAIL",
     "Not installed → WARN"),
    ("cppcheck",          "L5", True,
     "No errors/security warns",
     "Security/error finding → FAIL",
     "Not installed → WARN"),
    ("hadolint",          "L5", True,
     "Exit 0 — no warnings",
     "DL/SC rule triggered → FAIL",
     "Not installed → WARN"),
    ("checkov",           "L5", True,
     "All IaC checks pass",
     "Any FAILED check → FAIL",
     "SKIPPED checks → WARN"),
    ("ScanCode",          "L6", True,
     "No risky licence, no CVE",
     "CRITICAL/HIGH CVE in pkg → FAIL",
     "Risky licence (GPL…) → WARN"),
]

# Column layout
HDR_Y = H - 90
row_h = 36
cols = [
    ("Tool",        28,  155),
    ("Layer",      188,   46),
    ("Offline",    240,   60),
    ("✔ PASS",     308,  270),
    ("✘ FAIL",     585,  310),
    ("⚠ WARN",     902,  400),
]

# Header
rect(cv, 25, HDR_Y - 4, W - 50, row_h - 2, DARK)
for hdr, hx, hw in cols:
    cv.setFillColor(WHITE)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(hx + hw / 2, HDR_Y + 9, hdr)

# Rows
for ri, (tool, layer, offline, pass_s, fail_s, warn_s) in enumerate(SUMMARY_TOOLS):
    ry = HDR_Y - row_h - ri * row_h
    row_bg = HexColor("#F5F8FF") if ri % 2 == 0 else WHITE
    rect(cv, 25, ry, W - 50, row_h - 1, row_bg)

    lcolor_map = {"L1": L1_COLOR, "L2": L2_COLOR, "L3": L3_COLOR,
                  "L4": L4_COLOR, "L5": L5_COLOR, "L6": L6_COLOR}
    lc = lcolor_map.get(layer, DARK)

    def cell(txt, hx, hw, color=DARK, bold=False, center=False):
        cv.setFillColor(color)
        cv.setFont("Helvetica-Bold" if bold else "Helvetica", 8)
        if center:
            cv.drawCentredString(hx + hw / 2, ry + 12, txt)
        else:
            cv.drawString(hx + 4, ry + 12, txt)

    cell(tool,   28,  155, lc, bold=True)
    # Layer badge
    rect(cv, 190, ry + 6, 40, 22, lc, radius=4)
    cv.setFillColor(WHITE)
    cv.setFont("Helvetica-Bold", 8)
    cv.drawCentredString(210, ry + 14, layer)
    # Offline
    ol_c = HexColor("#1A7A40") if offline else ORANGE
    cv.setFillColor(ol_c)
    cv.setFont("Helvetica-Bold", 9)
    cv.drawCentredString(270, ry + 14, "✔" if offline else "⚠")
    # Pass
    cell(pass_s, 308, 270, HexColor("#1A5C30"))
    # Fail
    cell(fail_s, 585, 310, HexColor("#7B1818"))
    # Warn
    cell(warn_s, 902, 400, HexColor("#7A5800"))

# Bottom note
text(cv,
     "FAIL = package blocked, moved to quarantine  |  "
     "WARN = logged, pipeline continues (degraded mode)  |  "
     "All layers must PASS for the ZIP to be released",
     W / 2, 18, size=9, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — CONCLUSION (updated)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "Summary", 35, H - 52, size=36, color=WHITE, bold=True)
divider_line(cv, H - 83, ACCENT2)

recap = [
    ("🌐", "Source",   "GitHub (whitelist)\nor local path",           ACCENT),
    ("⬇",  "Fetch",    "Minimal clone\n.git removed · SHA-256",       ACCENT2),
    ("🔍", "6 Layers", "L1→L2→L3→L4→L5→L6\n16 tools · SCA · Licence",  ORANGE),
    ("📦", "PASS",     "ZIP in Good/\nwith Excel included",           GREEN),
    ("🚨", "FAIL",     "Quarantine\nchmod 700 + report",              RED),
]
for i, (icon, label, desc, color) in enumerate(recap):
    x = 40 + i * 252
    card(cv, x, H - 590, 240, 460, BG_CARD, radius=10)
    rect(cv, x + 50, H - 175, 140, 120, color, radius=10)
    text(cv, icon, x + 120, H - 115, size=36, color=WHITE, align="center")
    text(cv, label, x + 120, H - 225, size=18, color=color, bold=True, align="center")
    for li, dl in enumerate(desc.split("\n")):
        text(cv, dl, x + 120, H - 285 - li * 38, size=13, color=DARK, align="center")
    if i < 4:
        text(cv, "→", x + 248, H - 370, size=24, color=GRAY, align="center")

# Standards badges
badge_labels = ["OWASP", "CWE", "CERT", "SCA"]
badge_colors = [L2_COLOR, L2_COLOR, PURPLE, L3_COLOR]
for bi, (bl, bc) in enumerate(zip(badge_labels, badge_colors)):
    badge(cv, bl, 280 + bi * 200, H - 645, 160, 34, bc)

text(cv, "6-layer pipeline · OWASP · CWE · CERT · SCA · Licence (ScanCode) · Degraded mode · Timestamped reports",
     W/2, H - 680, size=13, color=GRAY, align="center")
text(cv, "github.com/Gaillotte/Claude  —  branch claude/vigilant-carson-f8twy0",
     W/2, H - 710, size=11, color=HexColor("#557799"), align="center")
cv.showPage()


cv.save()
print(f"PDF generated: {pdf_path}")

# Count pages by re-reading (ReportLab doesn't expose page count after save)
import struct, zlib, re as _re

with open(pdf_path, "rb") as f:
    data = f.read()

page_count = data.count(b"/Type /Page\n") + data.count(b"/Type/Page\n") + data.count(b"/Type /Page ")
# More reliable: count showPage calls = page count
# Use /Count in the Pages dict
m = _re.search(rb'/Count\s+(\d+)', data)
if m:
    page_count = int(m.group(1))

size_kb = len(data) / 1024
print(f"File size: {size_kb:.1f} KB")
print(f"Page count: {page_count}")
