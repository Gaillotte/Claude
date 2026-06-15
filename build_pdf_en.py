#!/usr/bin/env python3
"""
Generates the AI Transit Pipeline PDF slide deck via ReportLab.
Format 16:9 — 1333 × 750 pt
Light (white/light gray) background theme, English text.
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
    "🛡   Adaptive multi-layer scan by file type",
    "📦  Approved ZIP archive + Excel traceability report",
]
for i, b in enumerate(bullets):
    text(cv, b, W/2, H - 340 - i * 45, size=18, color=DARK, align="center")

text(cv, "Version 1.0  —  June 2026", W/2, 30, size=12, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — TABLE OF CONTENTS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_BLU)
text(cv, "Table of Contents", 35, H - 53, size=34, color=WHITE, bold=True)
divider_line(cv, H - 83)

items = [
    ("01", "Context & Objectives",               ACCENT),
    ("02", "Pipeline Architecture",              ACCENT2),
    ("03", "Phase 1 — Secure Retrieval",         YELLOW),
    ("04", "Phase 2 — Multi-layer Scan",         ORANGE),
    ("05", "Per-type Check Details",             PURPLE),
    ("06", "Tools Used",                         GREEN),
    ("07", "Results & Deliverables",             ACCENT),
    ("08", "Absolute Security Rules",            RED),
]
for i, (num, title, color) in enumerate(items):
    col = 0 if i < 4 else 1
    row = i % 4
    x = 40 + col * 650
    y = H - 155 - row * 140
    card(cv, x, y - 95, 610, 105)
    circle_num(cv, num, x + 35, y - 45, 22, color, WHITE)
    text(cv, title, x + 75, y - 53, size=17, color=DARK, bold=True)
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
    ("Scan",     "Adaptive multi-layer",         ORANGE),
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
# SLIDE 4 — ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "02  Pipeline Architecture", 35, H - 52, size=32,
     color=WHITE, bold=True)
divider_line(cv, H - 83, ACCENT2)

flow_nodes = [
    ("📂 Source  GitHub / Local",      H - 130, ACCENT),
    ("⬇  fetch_repo.sh  (Phase 1)",    H - 230, HexColor("#3A7AB5")),
    ("🔍 scan_pipeline.sh  (Phase 2)", H - 330, HexColor("#C06010")),
    ("✔  Good/ — ZIP + Excel",         H - 480, GREEN),
    ("✘  quarantine/  chmod 700",      H - 560, RED),
]
for label, y, c in flow_nodes:
    card(cv, 25, y - 72, 360, 65, c, radius=6)
    text(cv, label, 210, y - 46, size=13, color=WHITE, bold=True, align="center")

for y_arr in [H - 170, H - 270]:
    text(cv, "▼", 205, y_arr, size=18, color=GRAY, align="center")
text(cv, "PASS ▼", 90, H - 425, size=13, color=GREEN, bold=True)
text(cv, "FAIL ▼", 255, H - 425, size=13, color=RED, bold=True)

# Phase 1 detail
text(cv, "Phase 1 — fetch_repo.sh", 420, H - 110, size=16, color=ACCENT, bold=True)
p1 = ["✦  Host whitelist (github.com only)",
      "✦  Size check via GitHub API (< 500 MB)",
      "✦  git clone --depth 1 --no-tags",
      "✦  .git/ removal (no metadata)",
      "✦  SHA-256 manifest of all files",
      "✦  Quick scan for suspicious patterns"]
for i, l in enumerate(p1):
    text(cv, l, 430, H - 145 - i * 37, size=13, color=DARK)

# Phase 2 detail
text(cv, "Phase 2 — scan_pipeline.sh", 880, H - 110, size=16, color=ORANGE, bold=True)
p2 = ["🌐 GLOBAL Layer:",
      "   Gitleaks · detect-secrets · ClamAV · YARA",
      "",
      "📄 PER-TYPE Layer:",
      "   .py → Bandit + eval/exec",
      "   .js/.ts → Semgrep + child_process",
      "   .sh → ShellCheck + curl|bash",
      "   .yml → unpinned actions",
      "   .tf → checkov + hardcoded secrets",
      "   Dockerfile → hadolint + :latest",
      "   .so/.exe → auto FAIL + strings"]
for i, l in enumerate(p2):
    text(cv, l, 890, H - 145 - i * 37, size=12, color=DARK)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — PHASE 1
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HexColor("#C8860A"))  # darker yellow bar for contrast
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
# SLIDE 6 — GLOBAL LAYER
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ORANGE)
text(cv, "04  Phase 2 — Global Layer", 35, H - 52, size=32, color=WHITE, bold=True)
divider_line(cv, H - 83, ORANGE)

text(cv, "Applies to the ENTIRE directory, regardless of file type",
     W/2, H - 105, size=16, color=DARK, align="center")

tools_g = [
    ("Gitleaks", "🔑",
     ["> 150 credential types", "GitHub/AWS/GCP/Azure tokens",
      "RSA, PEM, SSH, JWT keys", "Entropy analysis + regex"], ACCENT),
    ("detect-secrets", "📊",
     ["Shannon entropy", "Secrets unknown to rule sets",
      "High-density base64/hex", "Complements Gitleaks"], ACCENT2),
    ("ClamAV", "🦠",
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
# SLIDE 7 — DISPATCH BY FILE TYPE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, PURPLE)
text(cv, "04  Phase 2 — Dispatch by File Type", 35, H - 52,
     size=28, color=WHITE, bold=True)
divider_line(cv, H - 83, PURPLE)

hdrs = [("Extension(s)", 25, 165), ("SAST Tool", 195, 260),
        ("Manual Checks", 460, 600), ("Verdict", 1065, 180)]
for hdr, hx, hw in hdrs:
    rect(cv, hx, H - 128, hw, 38, HDR_PUR)
    text(cv, hdr, hx + hw/2, H - 113, size=12, color=WHITE,
         bold=True, align="center")

rows_t = [
    (".py",             "Bandit",      "eval() exec() import os/subprocess",     "FAIL"),
    (".js .ts .jsx",    "Semgrep",     "eval() child_process require(…)",         "FAIL"),
    (".c .cpp .h",      "cppcheck",    "gets() strcpy() system() popen()",        "FAIL"),
    (".sh .bash .ps1",  "ShellCheck",  "curl|bash  wget|sh  eval $var",           "FAIL"),
    (".yml .yaml",      "—",           "Unpinned actions  inline secrets",        "FAIL"),
    (".tf .tfvars",     "checkov",     "Hardcoded secrets  overly broad IAM",     "FAIL"),
    ("Dockerfile",      "hadolint",    ":latest  ADD http://  RUN curl|bash",     "FAIL"),
    (".so .exe .elf",   "strings",     "Auto FAIL + IOC strings",                 "FAIL ⚠"),
    (".zip .tar.gz",    "—",           "Auto FAIL — re-scan after extraction",    "FAIL ⚠"),
    (".sql",            "—",           "xp_cmdshell  DROP TABLE  ; --",           "FAIL"),
    (".json .md .txt",  "—",           "password: secret: token: api_key=",       "FAIL"),
]
RH = 48
for ri, (ext, tool, checks, verdict) in enumerate(rows_t):
    ry = H - 135 - (ri + 1) * RH
    fill_r = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
    rect(cv, 25, ry, 1283, RH - 2, fill_r)
    text(cv, ext,     110, ry + 14, size=11, color=ACCENT, bold=True, align="center")
    text(cv, tool,    325, ry + 14, size=11, color=DARK, align="center")
    text(cv, checks,  460, ry + 14, size=10, color=DARK)
    vcolor = RED if "FAIL" in verdict else ORANGE
    text(cv, verdict, 1155, ry + 14, size=11, color=vcolor,
         bold=True, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDES 8–10 — PER-TYPE CHECKS (3 slides × 2 columns)
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
    text(cv, "05  Per-type Check Details", 35, H - 52,
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
# SLIDE — Additional Types (Dockerfile, Binaries, Archives, SQL)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_PUR)
text(cv, "05  Checks by Type — Dockerfile · Binaries · Archives · SQL",
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
# SLIDE — TOOLS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, GREEN)
text(cv, "06  Tools Used — Summary", 35, H - 52, size=32,
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
    ("Gitleaks",       "secrets/tokens",          "GitHub binary",         "Global",      ACCENT),
    ("detect-secrets", "high entropy",             "pip install",           "Global",      ACCENT),
    ("ClamAV",         "malware signatures",       "apt install clamav",    "Global",      ORANGE),
    ("YARA",           "custom IOC",               "apt install yara",      "Global",      PURPLE),
    ("Bandit",         "Python SAST",              "pip install bandit",    ".py",         HexColor("#B8860B")),
    ("Semgrep",        "multi-lang SAST",          "pip install semgrep",   ".js .ts",     HexColor("#B8860B")),
    ("cppcheck",       "C/C++ static analysis",    "apt install cppcheck",  ".c .cpp",     ACCENT2),
    ("ShellCheck",     "shell linting",            "apt install shellcheck", ".sh .bash",  ACCENT2),
    ("hadolint",       "Dockerfile linting",       "GitHub binary",         "Dockerfile",  GREEN),
    ("checkov",        "IaC security",             "pip install checkov",   ".tf .hcl",    GREEN),
    ("jq",             "GitHub API JSON parsing",  "apt install jq",        "Utility",     GRAY),
]
RH2 = 46
for ri, (name, role, install, scope, color) in enumerate(tools_data):
    ry2 = H - 145 - (ri + 1) * RH2
    bg2 = ALT_ROW1 if ri % 2 == 0 else ALT_ROW2
    rect(cv, 20, ry2, 1295, RH2 - 2, bg2)
    text(cv, name,    110, ry2 + 14, size=11, color=color, bold=True, align="center")
    text(cv, role,    345, ry2 + 14, size=11, color=DARK, align="center")
    text(cv, install, 655, ry2 + 14, size=10, color=DARK, align="center")
    text(cv, scope,   1070, ry2 + 14, size=11, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — RESULTS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT)
text(cv, "07  Results — ZIP Archive & Excel Report",
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
text(cv, "08  Absolute Security Rules", 35, H - 52, size=32,
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
# SLIDE — CONCLUSION
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "Summary", 35, H - 52, size=36, color=WHITE, bold=True)
divider_line(cv, H - 83, ACCENT2)

recap = [
    ("🌐", "Source",  "GitHub (whitelist)\nor local path",     ACCENT),
    ("⬇",  "Fetch",   "Minimal clone\n.git removed · SHA-256", ACCENT2),
    ("🔍", "Scan",    "Global layer\n+ 11 file types",         ORANGE),
    ("📦", "PASS",    "ZIP in Good/\nwith Excel included",     GREEN),
    ("🚨", "FAIL",    "Quarantine\nchmod 700 + report",        RED),
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

text(cv, "Bash pipeline · Degraded mode · Optional tools · Timestamped reports",
     W/2, H - 640, size=14, color=GRAY, align="center")
text(cv, "github.com/Gaillotte/Claude  —  branch claude/vigilant-carson-f8twy0",
     W/2, H - 680, size=11, color=HexColor("#557799"), align="center")
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
