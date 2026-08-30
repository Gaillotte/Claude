#!/usr/bin/env python3
"""
Génère le PDF des slides AI Transit Pipeline directement via ReportLab.
Format 16:9 — 1333 × 750 pt (≈ 47 × 26.5 cm)
"""

from reportlab.lib.pagesizes import landscape
from reportlab.lib.units import inch
pt = 1  # 1 point = 1 unité ReportLab
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white, black, Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import ImageReader
import math, textwrap, os

W, H = 1333, 750   # points, format 16:9 custom

# ── Palette ──────────────────────────────────────────────────────────────────
BG      = HexColor("#0D1B2A")
BG_CARD = HexColor("#1B2A3B")
ACCENT  = HexColor("#00A8FF")
ACCENT2 = HexColor("#00D4AA")
WHITE   = HexColor("#FFFFFF")
LIGHT   = HexColor("#CCDDEE")
GRAY    = HexColor("#889999")
GREEN   = HexColor("#2ECC71")
RED     = HexColor("#E74C3C")
ORANGE  = HexColor("#F39C12")
YELLOW  = HexColor("#F1C40F")
PURPLE  = HexColor("#E070FF")
DARK    = HexColor("#060F18")
HDR_BLU = HexColor("#0070A8")
HDR_GRN = HexColor("#106030")
HDR_PUR = HexColor("#602070")
RED_ROW = HexColor("#2A0505")
ORG_ROW = HexColor("#2A1A00")
GRN_ROW = HexColor("#052005")
DARK_ROW= HexColor("#0E1E2E")
MID_ROW = HexColor("#162A3C")

def c2p(color: HexColor) -> Color:
    return color

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

def text(cv, s, x, y, size=16, color=WHITE, bold=False, align="left", max_w=None):
    cv.setFillColor(color)
    fname = "Helvetica-Bold" if bold else "Helvetica"
    cv.setFont(fname, size)
    if max_w and len(s) * size * 0.55 > max_w:
        # wrapping simple
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

def text_block(cv, lines_list, x, y, size=14, color=WHITE, bold=False,
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
    rect(cv, x, y, w, h, color, radius=radius)

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
    rect(cv, x, y, w, h, DARK, stroke_color=ACCENT, stroke_w=1)
    cv.setFillColor(HexColor("#7FFFD4"))
    cv.setFont("Courier", size)
    lh = size * 1.4
    for i, l in enumerate(code_lines):
        cv.drawString(x + 10, y + h - 18 - i * lh, l)

def divider_line(cv, y, color=ACCENT):
    line(cv, 30, y, W - 30, y, color, 1.5)

# ── PDF ───────────────────────────────────────────────────────────────────────
pdf_path = "/home/user/Claude/AI_Transit_Pipeline_Slides.pdf"
cv = canvas.Canvas(pdf_path, pagesize=(W, H))
cv.setTitle("AI Transit Pipeline — Slides")
cv.setAuthor("AI Transit Pipeline")
cv.setSubject("Documentation technique — Sécurisation code IA")


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — COUVERTURE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 70, W, 70, ACCENT)
rect(cv, 0, 0, W, 70, ACCENT2)

text(cv, "AI TRANSIT PIPELINE", W/2, H - 200, size=58, bold=True,
     color=WHITE, align="center")
text(cv, "Sécuriser l'intégration du code IA en entreprise",
     W/2, H - 260, size=22, color=ACCENT2, align="center")

line(cv, 100, H - 290, W - 100, H - 290, GRAY, 1)

bullets = [
    "🔍  Récupération sécurisée depuis GitHub",
    "🛡   Scan multicouche adaptatif par type de fichier",
    "📦  Archive ZIP approuvée + rapport Excel de traçabilité",
]
for i, b in enumerate(bullets):
    text(cv, b, W/2, H - 340 - i * 45, size=18, color=LIGHT, align="center")

text(cv, "Version 1.0  —  Juin 2026", W/2, 30, size=12, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — SOMMAIRE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_BLU)
text(cv, "Sommaire", 35, H - 53, size=34, color=WHITE, bold=True)
divider_line(cv, H - 83)

items = [
    ("01", "Contexte & objectifs",             ACCENT),
    ("02", "Architecture du pipeline",          ACCENT2),
    ("03", "Phase 1 — Récupération sécurisée", YELLOW),
    ("04", "Phase 2 — Scan multicouche",        ORANGE),
    ("05", "Détail des checks par type",        PURPLE),
    ("06", "Outils utilisés",                   GREEN),
    ("07", "Résultats & livrables",             ACCENT),
    ("08", "Règles de sécurité absolues",       RED),
]
for i, (num, title, color) in enumerate(items):
    col = 0 if i < 4 else 1
    row = i % 4
    x = 40 + col * 650
    y = H - 155 - row * 140
    card(cv, x, y - 95, 610, 105)
    circle_num(cv, num, x + 35, y - 45, 22, color, WHITE)
    text(cv, title, x + 75, y - 53, size=17, color=WHITE, bold=True)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — CONTEXTE & OBJECTIFS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT)
text(cv, "01  Contexte & Objectifs", 35, H - 52, size=32, color=WHITE, bold=True)
divider_line(cv, H - 83)

text(cv, "Pourquoi ce pipeline ?", 35, H - 115, size=22, color=ACCENT, bold=True)
problems = [
    "🤖  Le code IA généré peut contenir des backdoors, secrets ou patterns dangereux",
    "📥  Les développeurs importent du code sans revue de sécurité systématique",
    "🏢  Le réseau d'entreprise doit rester isolé (air-gap partiel)",
    "📋  Aucune traçabilité sans processus structuré",
]
for i, p in enumerate(problems):
    text(cv, p, 50, H - 160 - i * 45, size=16, color=LIGHT)

# Schéma flux
nodes_flow = [
    ("🌐 Internet\n(GitHub)", 990, H - 180, ACCENT),
    ("🛡 Pipeline\nAI Transit", 1100, H - 180, ORANGE),
    ("🏢 Réseau\ninterne", 1210, H - 180, GREEN),
]
for label, nx, ny, nc in nodes_flow:
    card(cv, nx - 40, ny - 60, 90, 75, nc, radius=8)
    lines = label.split("\n")
    for li, ll in enumerate(lines):
        text(cv, ll, nx, ny - 22 - li * 22, size=11, color=WHITE,
             bold=True, align="center")

text(cv, "→", 1065, H - 202, size=20, color=GRAY, align="center")
text(cv, "→", 1175, H - 202, size=20, color=GRAY, align="center")
text(cv, "flux unidirectionnel", 1100, H - 265, size=10, color=GRAY, align="center")

# Objectifs
text(cv, "Objectifs clés", 35, H - 390, size=20, color=ACCENT2, bold=True)
objs = [
    ("Récupérer", "Clone sécurisé depth 1", ACCENT),
    ("Scanner",   "Multicouche adaptatif",   ORANGE),
    ("Décider",   "PASS→ZIP / FAIL→Quarantaine", RED),
    ("Tracer",    "Excel + JSON + HTML",     GREEN),
]
for i, (title, sub, c) in enumerate(objs):
    x = 35 + i * 325
    card(cv, x, H - 570, 310, 160, BG_CARD, radius=8)
    badge(cv, "", x + 10, H - 435, 20, 20, c)
    rect(cv, x + 10, H - 437, 20, 20, c, radius=4)
    text(cv, title, x + 40, H - 432, size=16, color=c, bold=True)
    text(cv, sub, x + 15, H - 465, size=12, color=LIGHT)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "02  Architecture du pipeline", 35, H - 52, size=32,
     color=HexColor("#0D1B2A"), bold=True)
divider_line(cv, H - 83, ACCENT2)

# Nœuds flux gauche
flow_nodes = [
    ("📂 Source  GitHub / Local",      H - 130, ACCENT),
    ("⬇  fetch_repo.sh  (Phase 1)",    H - 230, HexColor("#255585")),
    ("🔍 scan_pipeline.sh  (Phase 2)", H - 330, HexColor("#854510")),
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

# Détail phase 1
text(cv, "Phase 1 — fetch_repo.sh", 420, H - 110, size=16, color=ACCENT, bold=True)
p1 = ["✦  Whitelist hôtes (github.com uniquement)",
      "✦  Vérif. taille via API GitHub (< 500 MB)",
      "✦  git clone --depth 1 --no-tags",
      "✦  Suppression .git/ (pas de metadata)",
      "✦  Manifest SHA-256 de tous les fichiers",
      "✦  Triage rapide patterns suspects"]
for i, l in enumerate(p1):
    text(cv, l, 430, H - 145 - i * 37, size=13, color=LIGHT)

# Détail phase 2
text(cv, "Phase 2 — scan_pipeline.sh", 880, H - 110, size=16, color=ORANGE, bold=True)
p2 = ["🌐 Couche GLOBALE :",
      "   Gitleaks · detect-secrets · ClamAV · YARA",
      "",
      "📄 Couche PAR TYPE :",
      "   .py → Bandit + eval/exec",
      "   .js/.ts → Semgrep + child_process",
      "   .sh → ShellCheck + curl|bash",
      "   .yml → actions non-pinnées",
      "   .tf → checkov + secrets hardcodés",
      "   Dockerfile → hadolint + :latest",
      "   .so/.exe → FAIL auto + strings"]
for i, l in enumerate(p2):
    text(cv, l, 890, H - 145 - i * 37, size=12, color=LIGHT)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — PHASE 1
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, YELLOW)
text(cv, "03  Phase 1 — Récupération sécurisée", 35, H - 52, size=30,
     color=HexColor("#0D1B2A"), bold=True)
divider_line(cv, H - 83, YELLOW)

steps = [
    ("1", "Whitelist hôtes",
     "Seul github.com autorisé.\nToute autre URL rejetée immédiatement.", ACCENT),
    ("2", "Vérification taille",
     "API GitHub interrogée avant clone.\nLimite : 500 MB.", ACCENT2),
    ("3", "Clone minimal",
     "git clone --depth 1 --no-tags\n--single-branch", YELLOW),
    ("4", "Suppression .git/",
     "Métadonnées Git supprimées\n(hooks, remotes, submodules).", ORANGE),
    ("5", "Manifest SHA-256",
     "Hash de chaque fichier →\n.manifest_sha256.txt (audit).", PURPLE),
    ("6", "Triage rapide",
     "Grep : eval( exec( curl|bash\nrm -rf → alerte immédiate.", GREEN),
]
for i, (num, title, desc, color) in enumerate(steps):
    col = i % 3
    row = i // 3
    x = 35 + col * 430
    y = H - 120 - row * 290
    card(cv, x, y - 240, 415, 245, BG_CARD, radius=8)
    circle_num(cv, num, x + 30, y - 30, 22, color, BG)
    text(cv, title, x + 65, y - 38, size=15, color=color, bold=True)
    for li, dl in enumerate(desc.split("\n")):
        text(cv, dl, x + 20, y - 100 - li * 38, size=13, color=LIGHT)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 6 — COUCHE GLOBALE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ORANGE)
text(cv, "04  Phase 2 — Couche globale", 35, H - 52, size=32, color=WHITE, bold=True)
divider_line(cv, H - 83, ORANGE)

text(cv, "S'applique à TOUT le répertoire, quel que soit le type de fichier",
     W/2, H - 105, size=16, color=LIGHT, align="center")

tools_g = [
    ("Gitleaks", "🔑",
     ["> 150 types de credentials", "Tokens GitHub/AWS/GCP/Azure",
      "Clés RSA, PEM, SSH, JWT", "Analyse entropique + regex"], ACCENT),
    ("detect-secrets", "📊",
     ["Entropie de Shannon", "Secrets inconnus des règles",
      "Base64/hex à haute densité", "Complémentaire Gitleaks"], ACCENT2),
    ("ClamAV", "🦠",
     ["Millions de signatures", "Trojans, ransomwares, backdoors",
      "Scan récursif complet", "Base freshclam mise à jour"], ORANGE),
    ("YARA", "🎯",
     ["Standard IOC industrie", "Règles .yar personnalisées",
      "Patterns backdoors IA", "Regex + logique booléenne"], PURPLE),
]
for i, (name, icon, items, color) in enumerate(tools_g):
    x = 25 + i * 326
    card(cv, x, H - 680, 315, 540, BG_CARD, radius=8)
    rect(cv, x, H - 155, 315, 52, color)
    text(cv, f"{icon}  {name}", x + 157, H - 136, size=15, color=BG,
         bold=True, align="center")
    for j, item in enumerate(items):
        text(cv, f"• {item}", x + 15, H - 210 - j * 65, size=13, color=LIGHT)
    badge(cv, "FAIL si positif", x + 85, H - 668, 145, 28, RED)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 7 — DISPATCH PAR TYPE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, PURPLE)
text(cv, "04  Phase 2 — Dispatch par type de fichier", 35, H - 52,
     size=28, color=WHITE, bold=True)
divider_line(cv, H - 83, PURPLE)

hdrs = [("Extension(s)", 25, 165), ("Outil SAST", 195, 260),
        ("Checks manuels", 460, 600), ("Verdict", 1065, 180)]
for hdr, hx, hw in hdrs:
    rect(cv, hx, H - 128, hw, 38, HDR_PUR)
    text(cv, hdr, hx + hw/2, H - 113, size=12, color=WHITE,
         bold=True, align="center")

rows_t = [
    (".py",             "Bandit",      "eval() exec() import os/subprocess",     "FAIL"),
    (".js .ts .jsx",    "Semgrep",     "eval() child_process require(…)",         "FAIL"),
    (".c .cpp .h",      "cppcheck",    "gets() strcpy() system() popen()",        "FAIL"),
    (".sh .bash .ps1",  "ShellCheck",  "curl|bash  wget|sh  eval $var",           "FAIL"),
    (".yml .yaml",      "—",           "Actions non-pinnées  secrets inline",     "FAIL"),
    (".tf .tfvars",     "checkov",     "Secrets en dur  IAM trop larges",         "FAIL"),
    ("Dockerfile",      "hadolint",    ":latest  ADD http://  RUN curl|bash",     "FAIL"),
    (".so .exe .elf",   "strings",     "FAIL automatique + IOC strings",          "FAIL ⚠"),
    (".zip .tar.gz",    "—",           "FAIL auto — re-scan extraction requis",   "FAIL ⚠"),
    (".sql",            "—",           "xp_cmdshell  DROP TABLE  ; --",           "FAIL"),
    (".json .md .txt",  "—",           "password: secret: token: api_key=",       "FAIL"),
]
RH = 48
for ri, (ext, tool, checks, verdict) in enumerate(rows_t):
    ry = H - 135 - (ri + 1) * RH
    fill_r = DARK_ROW if ri % 2 == 0 else MID_ROW
    rect(cv, 25, ry, 1283, RH - 2, fill_r)
    text(cv, ext,     110, ry + 14, size=11, color=ACCENT, bold=True, align="center")
    text(cv, tool,    325, ry + 14, size=11, color=ACCENT, align="center")
    text(cv, checks,  460, ry + 14, size=10, color=LIGHT)
    vcolor = RED if "FAIL" in verdict else ORANGE
    text(cv, verdict, 1155, ry + 14, size=11, color=vcolor,
         bold=True, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDES 8–10 — CHECKS PAR TYPE (3 slides × 2 colonnes)
# ═══════════════════════════════════════════════════════════════════════════════
details = [
    ("Python .py", ACCENT,
     "Exécution dynamique — risque élevé de backdoors via eval/exec",
     [("Bandit SAST",         "AST Python : subprocess shell=True, pickle, MD5, SQL, assert…", "FAIL"),
      ("eval() / exec()",     "Exécution arbitraire à l'exécution — backdoor triviale",        "FAIL"),
      ("import os/subprocess","Accès shell système — nécessite revue manuelle",                 "WARN")]),
    ("JavaScript .js .ts", YELLOW,
     "Écosystème exposé aux supply-chain attacks",
     [("Semgrep p/javascript","XSS, prototype pollution, innerHTML, SSTI…",     "FAIL"),
      ("eval()",              "Exécution dynamique — vecteur injection classique","FAIL"),
      ("child_process",       "Exécution commandes shell depuis Node.js",         "FAIL")]),
    ("C / C++ .c .cpp", ORANGE,
     "Risques liés à la gestion manuelle de la mémoire",
     [("cppcheck",       "Buffer overflows, null ptr, use-after-free, mémoire non init.", "FAIL"),
      ("gets() strcpy()", "Lecture/copie sans limite de taille → buffer overflow",        "FAIL"),
      ("system() popen()","Exécution commandes shell → injection possible",               "FAIL")]),
    ("Shell .sh .bash", ACCENT2,
     "Exécution directe — obfuscation de commandes facile",
     [("ShellCheck",     "Variables non quotées, globbing, redirections dangereuses…", "FAIL"),
      ("curl | bash",    "Exécution code distant sans vérification d'intégrité",       "FAIL"),
      ("eval $variable", "Injection triviale si variable contrôlée par attaquant",      "FAIL")]),
    ("YAML / CI .yml", PURPLE,
     "Pipelines CI/CD — une mauvaise config ouvre des backdoors",
     [("Actions non-pinnées","uses: action@main → vulnérable au tag-hijacking", "FAIL"),
      ("Secrets inline",     "password: valeur (pas ${{ secrets.XXX }})",        "FAIL")]),
    ("Terraform .tf", GREEN,
     "IaC — peut provisionner des ressources cloud entières",
     [("checkov (CIS)","Buckets S3, IAM trop larges, BDD sans chiffrement at-rest","FAIL"),
      ("Secrets en dur","password = \"valeur\" dans .tf/.tfvars",                  "FAIL")]),
]

for group_start in range(0, len(details), 2):
    bg(cv)
    rect(cv, 0, H - 80, W, 80, HDR_PUR)
    text(cv, "05  Détail des vérifications par type", 35, H - 52,
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
        text(cv, name, cx + cw/2, H - 110, size=17, color=BG,
             bold=True, align="center")
        text(cv, desc, cx + cw/2, H - 155, size=12, color=GRAY,
             align="center")

        for i, (check, expl, verdict) in enumerate(checks):
            cy = H - 220 - i * 155
            fill_c = DARK_ROW if i % 2 == 0 else MID_ROW
            rect(cv, cx + 10, cy - 120, cw - 20, 125, fill_c, radius=4)
            vcolor = RED if verdict == "FAIL" else ORANGE
            text(cv, check, cx + 20, cy - 25, size=13, color=vcolor, bold=True)
            badge(cv, verdict, cx + cw - 90, cy - 35, 72, 24, vcolor)
            # Wrap explication
            chars = int((cw - 35) / 7.5)
            lines = textwrap.wrap(expl, chars)
            for li, ll in enumerate(lines):
                text(cv, ll, cx + 20, cy - 65 - li * 26, size=11, color=LIGHT)
    cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — Types supplémentaires (Dockerfile, Binaires, Archives, SQL)
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, HDR_PUR)
text(cv, "05  Checks par type — Dockerfile · Binaires · Archives · SQL",
     35, H - 52, size=26, color=WHITE, bold=True)
divider_line(cv, H - 83, PURPLE)

extra = [
    ("Dockerfile", ORANGE,
     [("hadolint", "CIS Docker : :latest, ADD http://, apt sans --no-install-recommends", "FAIL"),
      ("RUN curl|bash", "Téléchargement + exécution sans contrôle d'intégrité", "FAIL")]),
    ("Binaires .so .exe .elf", RED,
     [("FAIL automatique", "Aucun binaire dans un repo IA — implant/RAT potentiel", "FAIL"),
      ("strings + IOC", "/bin/sh /etc/passwd exec reverse shell URLs détectés", "FAIL")]),
    ("Archives .zip .tar.gz", ORANGE,
     [("FAIL automatique", "Contenu non scannable sans extraction préalable", "FAIL"),
      ("Zip-slip", "Extraction vers chemins arbitraires (../../etc/cron.d/)", "FAIL")]),
    ("SQL .sql", ACCENT2,
     [("xp_cmdshell", "Exécution commandes shell depuis SQL Server → IOC critique", "FAIL"),
      ("DROP TABLE / --", "Instructions destructrices + pattern injection SQL", "FAIL")]),
]
for i, (name, color, checks) in enumerate(extra):
    col = i % 2; row = i // 2
    ex = 20 + col * 660
    ey = H - 120 - row * 295

    card(cv, ex, ey - 260, 645, 260, BG_CARD, radius=8)
    rect(cv, ex, ey - 48, 645, 48, color)
    text(cv, name, ex + 322, ey - 26, size=15, color=BG, bold=True, align="center")
    for ci2, (check, expl, verdict) in enumerate(checks):
        cy2 = ey - 110 - ci2 * 90
        fill_c2 = DARK_ROW if ci2 % 2 == 0 else MID_ROW
        rect(cv, ex + 10, cy2 - 72, 625, 78, fill_c2, radius=4)
        text(cv, f"• {check}", ex + 20, cy2 - 22, size=12, color=RED, bold=True)
        badge(cv, verdict, ex + 555, cy2 - 32, 72, 22, RED)
        text(cv, expl, ex + 20, cy2 - 52, size=10, color=LIGHT, max_w=600)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — OUTILS SYNTHÈSE
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, GREEN)
text(cv, "06  Outils utilisés — Synthèse", 35, H - 52, size=32,
     color=BG, bold=True)
divider_line(cv, H - 83, GREEN)

text(cv, "Tous optionnels en dégradé — WARN si absent, FAIL uniquement sur finding actif",
     W/2, H - 103, size=14, color=ORANGE, align="center")

hdrs_t = [("Outil", 20, 180), ("Rôle", 205, 280),
          ("Installation", 490, 330), ("Scope", 825, 490)]
for hdr, hx, hw in hdrs_t:
    rect(cv, hx, H - 142, hw, 36, HDR_GRN)
    text(cv, hdr, hx + hw/2, H - 128, size=12, color=WHITE,
         bold=True, align="center")

tools_data = [
    ("Gitleaks",       "secrets/tokens",          "GitHub binary",        "Global",      ACCENT),
    ("detect-secrets", "entropie élevée",          "pip install",          "Global",      ACCENT),
    ("ClamAV",         "malware signatures",       "apt install clamav",   "Global",      ORANGE),
    ("YARA",           "IOC personnalisés",         "apt install yara",     "Global",      PURPLE),
    ("Bandit",         "SAST Python",              "pip install bandit",   ".py",         YELLOW),
    ("Semgrep",        "SAST multi-lang",          "pip install semgrep",  ".js .ts",     YELLOW),
    ("cppcheck",       "analyse statique C/C++",   "apt install cppcheck", ".c .cpp",     ACCENT2),
    ("ShellCheck",     "lint shell",               "apt install shellcheck",".sh .bash",  ACCENT2),
    ("hadolint",       "lint Dockerfile",          "GitHub binary",        "Dockerfile",  GREEN),
    ("checkov",        "sécurité IaC",             "pip install checkov",  ".tf .hcl",    GREEN),
    ("jq",             "parsing JSON API GitHub",   "apt install jq",       "Utilitaire",  GRAY),
]
RH2 = 46
for ri, (name, role, install, scope, color) in enumerate(tools_data):
    ry2 = H - 145 - (ri + 1) * RH2
    bg2 = DARK_ROW if ri % 2 == 0 else MID_ROW
    rect(cv, 20, ry2, 1295, RH2 - 2, bg2)
    text(cv, name,    110, ry2 + 14, size=11, color=color, bold=True, align="center")
    text(cv, role,    345, ry2 + 14, size=11, color=LIGHT, align="center")
    text(cv, install, 655, ry2 + 14, size=10, color=LIGHT, align="center")
    text(cv, scope,   1070, ry2 + 14, size=11, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — RÉSULTATS
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT)
text(cv, "07  Résultats — Archive & Rapport Excel",
     35, H - 52, size=30, color=WHITE, bold=True)
divider_line(cv, H - 83)

# Colonne gauche : ZIP
card(cv, 20, H - 700, 620, 590, BG_CARD, radius=8)
rect(cv, 20, H - 135, 620, 50, GREEN)
text(cv, "📦  Archive ZIP  →  Good/", 330, H - 116, size=16,
     color=BG, bold=True, align="center")

zip_tree = [
    "Good/",
    "└── repo_20260615_143022.zip",
    "    ├── src/",
    "    │   └── [code source complet]",
    "    ├── README.md",
    "    └── scan_report_20260615.xlsx",
]
mono_box(cv, zip_tree, 30, H - 330, 600, 175, size=10)

zip_pts = [
    "✔  Produite uniquement si verdict PASS",
    "✔  Nom horodaté — unicité garantie",
    "✔  .manifest_sha256.txt exclu",
    "✔  Rapport Excel inclus directement",
    "✔  Prête au transfert réseau interne",
    "✔  Optionnel : chiffrement GPG",
]
for i, pt in enumerate(zip_pts):
    text(cv, pt, 35, H - 360 - i * 46, size=13, color=LIGHT)

# Colonne droite : Excel
card(cv, 660, H - 700, 650, 590, BG_CARD, radius=8)
rect(cv, 660, H - 135, 650, 50, ACCENT2)
text(cv, "📊  Rapport Excel (.xlsx)", 985, H - 116, size=16,
     color=BG, bold=True, align="center")

text(cv, "Onglet 0 — Résumé", 675, H - 163, size=14, color=ACCENT2, bold=True)
tab0_rows = [
    ("Dépôt / Source",  "URL GitHub ou chemin local"),
    ("Date du scan",    "Horodatage ISO 8601"),
    ("Hash SHA-256",    "Empreinte globale de tous les fichiers"),
    ("Verdict",         "PASS (vert) / FAIL (rouge)"),
    ("Compteurs",       "PASS · WARN · FAIL"),
]
for i, (k, v) in enumerate(tab0_rows):
    ry3 = H - 210 - i * 40
    rect(cv, 670, ry3 - 26, 200, 34, HexColor("#103050"))
    text(cv, k, 675, ry3 - 14, size=11, color=ACCENT2, bold=True)
    text(cv, v, 878, ry3 - 14, size=11, color=LIGHT)

text(cv, "Onglet 1 — Fichiers (une ligne/fichier)", 675, H - 430,
     size=14, color=YELLOW, bold=True)
col1_hdrs = ["#", "Fichier", "Type", "Statut", "Message"]
col1_x = [675, 715, 935, 1040, 1135]
col1_w = [35, 215, 100, 90, 165]
for j, (h2, hx2, hw2) in enumerate(zip(col1_hdrs, col1_x, col1_w)):
    rect(cv, hx2, H - 470, hw2, 32, HexColor("#300160"))
    text(cv, h2, hx2 + hw2/2, H - 456, size=10, color=YELLOW,
         bold=True, align="center")

sample = [("1","src/main.py",".py","FAIL","bandit:HIGH", RED, RED_ROW),
          ("2","config.sh",  ".sh","WARN","shellcheck absent", ORANGE, ORG_ROW),
          ("3","README.md",  ".md","PASS","—", GREEN, GRN_ROW)]
for si, (n, f, t, s, m, sc, sr) in enumerate(sample):
    ry4 = H - 472 - (si + 1) * 42
    rect(cv, 675, ry4, 625, 38, sr)
    for val, hx2, hw2 in zip([n, f, t, s, m], col1_x, col1_w):
        vc = sc if val == s else LIGHT
        text(cv, val, hx2 + hw2/2, ry4 + 12, size=10, color=vc,
             bold=(val == s), align="center")

text(cv, "Trié FAIL→WARN→PASS | Filtre auto | Ligne 1 figée",
     985, H - 690, size=10, color=GRAY, align="center")
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — RÈGLES DE SÉCURITÉ
# ═══════════════════════════════════════════════════════════════════════════════
bg(cv)
rect(cv, 0, H - 80, W, 80, RED)
text(cv, "08  Règles de sécurité absolues", 35, H - 52, size=32,
     color=WHITE, bold=True)
divider_line(cv, H - 83, RED)

text(cv, "⛔  Ces règles NE PEUVENT PAS être modifiées — elles constituent le modèle de menace",
     W/2, H - 103, size=14, color=RED, bold=True, align="center")

rules_s = [
    ("🔒  Isolation réseau",
     "La machine de transit n'a JAMAIS accès direct au réseau d'entreprise."),
    ("➡  Flux unidirectionnel",
     "Seul approved/ est lisible depuis l'interne — pas fetch/, logs/, quarantine/."),
    ("🔐  Quarantaine root-only",
     "chmod 700 — aucun utilisateur applicatif ne peut lire les fichiers refusés."),
    ("🚫  Pas de déplacement manuel",
     "Jamais quarantine/ → approved/ sans re-scan complet du pipeline."),
    ("⚠  Binaires = FAIL absolu",
     "Aucun .so/.exe/.elf dans un repo IA — zéro exception."),
    ("📦  Archives = re-scan obligatoire",
     ".zip/.tar.gz → extraction + re-scan dans un environnement isolé dédié."),
]
for i, (title, desc) in enumerate(rules_s):
    col = i % 2; row = i // 2
    rx = 20 + col * 660
    ry = H - 145 - row * 190
    card(cv, rx, ry - 162, 645, 165, BG_CARD, radius=8)
    rect(cv, rx, ry - 48, 645, 48, HexColor("#6A0000"))
    text(cv, title, rx + 15, ry - 26, size=14, color=RED, bold=True)
    text(cv, desc, rx + 15, ry - 95, size=13, color=LIGHT, max_w=600)
cv.showPage()


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE — CONCLUSION
# ═══════════════════════════════════════════════════════════════════════════════
# ── SLIDE — Exploitation & assurance qualité ─────────────────────────────────
bg(cv)
header_bar(cv, HDR_BLU, "Exploitation et assurance qualité")

text(cv, "Options d'exécution", 40, H - 125, size=18, color=ACCENT, bold=True)
opt_rows = [
    ("--quiet / --verbose", "Verbosité des journaux"),
    ("--min-severity", "Seuil de blocage : low | medium | high | critical"),
    ("--since COMMIT", "Mode différentiel : uniquement les fichiers modifiés"),
    ("--report-only", "Ne bloque jamais, ne met rien en quarantaine"),
    ("--no-zip / --no-excel", "Rapports seuls, sans archive"),
]
card(cv, 30, H - 375, W / 2 - 50, 230)
for i, (flag, desc) in enumerate(opt_rows):
    yy = H - 175 - i * 38
    cv.setFont("Courier-Bold", 11); cv.setFillColor(ACCENT2)
    cv.drawString(50, yy, flag)
    text(cv, desc, 50, yy - 16, size=10.5, color=GRAY, max_w=W / 2 - 90)

text(cv, "Contrôles par dépôt", 40, H - 415, size=18, color=ACCENT, bold=True)
text_block(cv, [
    ".transitignore  —  motifs gitignore, fichiers exclus de toutes les couches",
    ".transit-allow.json  —  rétrograde un FAIL connu en WARN, avec justification",
], 40, H - 448, size=12, color=GRAY, line_h=26)

text(cv, "Le pipeline se vérifie lui-même", W / 2 + 20, H - 125, size=18, color=ACCENT2, bold=True)
card(cv, W / 2 + 10, H - 375, W / 2 - 50, 230)
qa_lines = [
    ("Suite de tests", "51 assertions, sans aucun outil de scan requis"),
    ("Corpus de règles", "chaque finding doit viser le bon fichier"),
    ("Garde-fous", "le code sûr ne doit jamais être signalé"),
    ("Intégration continue", "lint · test · pins · docker"),
    ("Validation par mutation", "le défaut est réintroduit, le test doit échouer"),
]
for i, (title, desc) in enumerate(qa_lines):
    yy = H - 175 - i * 38
    text(cv, title, W / 2 + 30, yy, size=12, color=WHITE, bold=True)
    text(cv, desc, W / 2 + 30, yy - 16, size=10.5, color=GRAY, max_w=W / 2 - 90)

line(cv, 40, H - 520, W - 40, H - 520, HexColor("#22374D"), 1)
text(cv, "Une suite qu'on n'a jamais vue échouer n'apporte aucune preuve.",
     W / 2, H - 560, size=15, color=ACCENT2, align="center", bold=True)
text(cv, "Deux tests de cette suite passaient sur du code notoirement défectueux : les tests eux-mêmes étaient faux.",
     W / 2, H - 590, size=12, color=GRAY, align="center")
cv.showPage()


bg(cv)
rect(cv, 0, H - 80, W, 80, ACCENT2)
text(cv, "En résumé", 35, H - 52, size=36, color=BG, bold=True)
divider_line(cv, H - 83, ACCENT2)

recap = [
    ("🌐", "Source",  "GitHub (whitelist)\nou chemin local",     ACCENT),
    ("⬇",  "Fetch",   "Clone minimal\n.git supprimé · SHA-256", ACCENT2),
    ("🔍", "Scan",    "Couche globale\n+ 11 types de fichiers",  ORANGE),
    ("📦", "PASS",    "ZIP dans Good/\navec Excel inclus",       GREEN),
    ("🚨", "FAIL",    "Quarantaine\nchmod 700 + rapport",        RED),
]
for i, (icon, label, desc, color) in enumerate(recap):
    x = 40 + i * 252
    card(cv, x, H - 590, 240, 460, BG_CARD, radius=10)
    # Icône
    rect(cv, x + 50, H - 175, 140, 120, color, radius=10)
    text(cv, icon, x + 120, H - 115, size=36, color=WHITE, align="center")
    text(cv, label, x + 120, H - 225, size=18, color=color, bold=True, align="center")
    for li, dl in enumerate(desc.split("\n")):
        text(cv, dl, x + 120, H - 285 - li * 38, size=13, color=LIGHT, align="center")
    if i < 4:
        text(cv, "→", x + 248, H - 370, size=24, color=GRAY, align="center")

text(cv, "Pipeline bash · Mode dégradé · Outils optionnels · Rapports horodatés",
     W/2, H - 640, size=14, color=GRAY, align="center")
text(cv, "github.com/Gaillotte/Claude  —  branche claude/vigilant-carson-f8twy0",
     W/2, H - 680, size=11, color=HexColor("#445566"), align="center")
cv.showPage()


cv.save()
print(f"PDF généré : {pdf_path}")
print(f"Pages : {cv.getPageNumber() - 1}")
