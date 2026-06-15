#!/usr/bin/env python3
"""
Generates the Word documentation for the AI Transit Pipeline tool (English version).
"""

from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

# ── Palette ──────────────────────────────────────────────────────────────────
BLUE_DARK   = RGBColor(0x1F, 0x38, 0x64)   # main headings
BLUE_MED    = RGBColor(0x2E, 0x75, 0xB6)   # secondary headings
GREEN       = RGBColor(0x37, 0x86, 0x44)
RED         = RGBColor(0xC0, 0x00, 0x00)
ORANGE      = RGBColor(0xED, 0x7D, 0x31)
GRAY_LIGHT  = "D9E1F2"
BLUE_HEADER = "1F3864"
GREEN_BG    = "C6EFCE"
RED_BG      = "FFC7CE"
YELLOW_BG   = "FFEB9C"


# ── Helpers ───────────────────────────────────────────────────────────────────
def set_cell_bg(cell, hex_color: str):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement("w:shd")
    shd.set(qn("w:val"),   "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"),  hex_color)
    tcPr.append(shd)


def set_cell_border(cell, **kwargs):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = OxmlElement("w:tcBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        border = OxmlElement(f"w:{side}")
        border.set(qn("w:val"),   kwargs.get("val",   "single"))
        border.set(qn("w:sz"),    kwargs.get("sz",    "4"))
        border.set(qn("w:space"), "0")
        border.set(qn("w:color"), kwargs.get("color", "AAAAAA"))
        tcBorders.append(border)
    tcPr.append(tcBorders)


def heading(doc, text, level=1, color=None):
    p = doc.add_heading(text, level=level)
    run = p.runs[0] if p.runs else p.add_run(text)
    run.font.color.rgb = color or (BLUE_DARK if level == 1 else BLUE_MED)
    return p


def para(doc, text="", bold=False, italic=False, color=None, size=10, indent=0):
    p = doc.add_paragraph()
    if indent:
        p.paragraph_format.left_indent = Cm(indent)
    run = p.add_run(text)
    run.bold   = bold
    run.italic = italic
    run.font.size = Pt(size)
    if color:
        run.font.color.rgb = color
    return p


def bullet(doc, text, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Cm(0.5 + level * 0.5)
    run = p.add_run(text)
    run.font.size = Pt(10)
    return p


def add_table_header(table, headers, bg=BLUE_HEADER):
    row = table.rows[0]
    for i, h in enumerate(headers):
        cell = row.cells[i]
        cell.text = h
        run = cell.paragraphs[0].runs[0]
        run.font.bold  = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.size  = Pt(9)
        cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        set_cell_bg(cell, bg)
        set_cell_border(cell)


def add_row(table, values, bg=None, bold_first=False):
    row = table.add_row()
    for i, v in enumerate(values):
        cell = row.cells[i]
        cell.text = str(v)
        run = cell.paragraphs[0].runs[0]
        run.font.size = Pt(9)
        if bold_first and i == 0:
            run.font.bold = True
        if bg:
            set_cell_bg(cell, bg)
        set_cell_border(cell)
    return row


def set_col_widths(table, widths_cm):
    for i, w in enumerate(widths_cm):
        for cell in table.column_cells(i):
            cell.width = Cm(w)


def code_block(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent  = Cm(1)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(4)
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x00, 0x00, 0x80)
    return p


def page_break(doc):
    doc.add_page_break()


# ═══════════════════════════════════════════════════════════════════════════════
# DOCUMENT
# ═══════════════════════════════════════════════════════════════════════════════
doc = Document()

# Margins
for section in doc.sections:
    section.top_margin    = Cm(2.0)
    section.bottom_margin = Cm(2.0)
    section.left_margin   = Cm(2.5)
    section.right_margin  = Cm(2.0)

# Base style
style = doc.styles["Normal"]
style.font.name = "Calibri"
style.font.size = Pt(10)

# ── Cover page ────────────────────────────────────────────────────────────────
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("\n\n\n")

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("AI TRANSIT PIPELINE")
r.font.size  = Pt(28)
r.font.bold  = True
r.font.color.rgb = BLUE_DARK

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Technical Documentation")
r.font.size  = Pt(16)
r.font.color.rgb = BLUE_MED

doc.add_paragraph()
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Secure retrieval and scanning pipeline\nfor AI-generated code\nbefore integration into an isolated corporate network")
r.font.size  = Pt(12)
r.font.italic = True
r.font.color.rgb = RGBColor(0x40, 0x40, 0x40)

doc.add_paragraph("\n\n")
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Version 1.0  —  June 2026")
r.font.size  = Pt(10)
r.font.color.rgb = RGBColor(0x60, 0x60, 0x60)

page_break(doc)

# ── Table of contents ─────────────────────────────────────────────────────────
heading(doc, "Table of Contents", level=1)
toc_items = [
    ("1.", "Objectives and Context"),
    ("2.", "Pipeline Architecture"),
    ("    2.1", "Overview"),
    ("    2.2", "Data Flow"),
    ("    2.3", "Runtime Directory Structure"),
    ("3.", "Phase 1 — Secure Retrieval (fetch_repo.sh)"),
    ("4.", "Phase 2 — Multi-Layer Security Scan (scan_pipeline.sh)"),
    ("    4.1", "Global Layer"),
    ("    4.2", "Per-File-Type Layer"),
    ("5.", "Detailed Checks by File Type"),
    ("    5.1", "Python (.py)"),
    ("    5.2", "JavaScript / TypeScript (.js .ts .jsx .tsx)"),
    ("    5.3", "C / C++ (.c .cpp .h .hpp)"),
    ("    5.4", "Shell / PowerShell (.sh .bash .zsh .ps1)"),
    ("    5.5", "YAML / GitHub Actions (.yml .yaml)"),
    ("    5.6", "Terraform / HCL (.tf .tfvars .hcl)"),
    ("    5.7", "Dockerfile"),
    ("    5.8", "Binaries (.so .dll .exe .elf)"),
    ("    5.9", "Archives (.zip .tar.gz)"),
    ("    5.10", "SQL (.sql)"),
    ("    5.11", "Documents (.json .xml .md .txt)"),
    ("6.", "Tools Used — Detailed Description"),
    ("7.", "Results — Archives and Reports"),
    ("    7.1", "Approved ZIP Archive (Good/ directory)"),
    ("    7.2", "Excel Scan Report"),
    ("    7.3", "JSON Report"),
    ("    7.4", "HTML Report"),
    ("8.", "Absolute Security Rules"),
    ("9.", "Prerequisites and Installation"),
]
for num, title in toc_items:
    p = doc.add_paragraph()
    r = p.add_run(f"{num}  {title}")
    r.font.size = Pt(10)
    if not num.startswith(" "):
        r.font.bold = True

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 1. OBJECTIVES
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "1. Objectives and Context", level=1)

para(doc, (
    "The rise of generative AI tools (GitHub Copilot, ChatGPT, Claude, etc.) "
    "is leading development teams to massively import automatically generated code. "
    "This code may contain exposed secrets, dangerous patterns, steganographic backdoors, "
    "or malicious dependencies — without the developer being aware of it."
))
para(doc, (
    "AI Transit Pipeline is a security tool interposed between the Internet and the "
    "isolated corporate network (partial air-gap). It ensures that no file "
    "enters the internal environment without undergoing a multi-layer scan."
))

heading(doc, "Main Objectives", level=2)
bullets = [
    "Securely retrieve any public GitHub repository (depth 1, minimal attack surface).",
    "Apply an adaptive multi-layer scan according to each file type.",
    "Automatically quarantine any suspicious code (chmod 700).",
    "Produce an approved ZIP archive + detailed Excel report for business teams.",
    "Operate in degraded mode: if a tool is absent, emit a warning and continue.",
    "Trace every decision in timestamped JSON, HTML, and Excel reports.",
]
for b in bullets:
    bullet(doc, b)

heading(doc, "Security Principles", level=2)
sec_bullets = [
    "Unidirectional flow: only the approved/ directory is readable from the internal network.",
    "No eval, no curl | bash in the pipeline itself.",
    "Host whitelist: only github.com is authorized as a remote source.",
    "Binaries and archives are systematically rejected in an AI repo.",
    "Any quarantined file requires a full re-scan before any reintegration.",
]
for b in sec_bullets:
    bullet(doc, b)

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 2. ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "2. Pipeline Architecture", level=1)

heading(doc, "2.1 Overview", level=2)
para(doc, "The pipeline consists of four bash scripts and one Python script:", bold=False)

# Scripts table
t = doc.add_table(rows=1, cols=3)
t.style = "Table Grid"
add_table_header(t, ["Script / File", "Role", "Phase"])
set_col_widths(t, [4.5, 11, 2.5])
scripts = [
    ("ai_transit.sh",             "Main entry point — orchestrates the complete pipeline", "—"),
    ("fetch_repo.sh",             "Phase 1: secure retrieval from GitHub or local path", "1"),
    ("scan_pipeline.sh",          "Phase 2: adaptive multi-layer scan by file type", "2"),
    ("generate_excel_report.py",  "Generation of the Excel report included in the approved archive", "2"),
    ("install_deps.sh",           "Automatic installation of all scan tools (Ubuntu/Debian)", "Setup"),
]
for row_data in scripts:
    add_row(t, row_data, bold_first=True)
doc.add_paragraph()

# ── ASCII flow diagram ────────────────────────────────────────────────────────
heading(doc, "2.2 Data Flow", level=2)
para(doc, "The diagram below represents the complete flow from the source to the final decision:")

diagram = """\
┌──────────────────────────────────────────────────────────────────────┐
│                        INPUT                                         │
│   GitHub URL (https://github.com/org/repo)                           │
│   or Local Path (/path/to/repo)                                      │
└─────────────────────────┬────────────────────────────────────────────┘
                          │
                          ▼  ai_transit.sh
                    ┌─────────────┐
                    │  PHASE 1    │  fetch_repo.sh
                    │  Fetch      ├── Host whitelist (github.com)
                    │             ├── GitHub API size check (< 500 MB)
                    │             ├── Clone --depth 1 --no-tags
                    │             ├── .git/ removal
                    │             ├── SHA-256 manifest
                    │             └── Quick raw pattern triage
                    └──────┬──────┘
                           │
                           ▼  scan_pipeline.sh
                    ┌──────────────────────────────────────────────┐
                    │  PHASE 2 — GLOBAL LAYER                      │
                    │  ├── Gitleaks      → secrets / tokens / keys │
                    │  ├── detect-secrets → high entropy           │
                    │  ├── ClamAV        → malware signatures      │
                    │  └── YARA          → custom IOC rules        │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  PHASE 2 — PER-TYPE LAYER                    │
                    │  ├── .py      → Bandit + eval/exec           │
                    │  ├── .js/.ts  → Semgrep + child_process      │
                    │  ├── .c/.cpp  → cppcheck + gets/strcpy       │
                    │  ├── .sh      → ShellCheck + curl|bash       │
                    │  ├── .yml     → unpinned actions             │
                    │  ├── .tf/.hcl → checkov + inline secrets     │
                    │  ├── Dockerfile → hadolint + :latest         │
                    │  ├── .so/.exe → automatic FAIL + strings     │
                    │  ├── .zip     → FAIL + re-scan required      │
                    │  └── .sql     → xp_cmdshell + DROP + inject. │
                    └──────────────┬───────────────────────────────┘
                                   │
                  ┌────────────────┴─────────────────┐
                  │           FINAL DECISION          │
                  └──────┬──────────────┬────────────┘
                         │              │
                    PASS ▼         FAIL ▼
            ┌────────────────┐  ┌────────────────────┐
            │ Good/          │  │ quarantine/        │
            │ *.zip          │  │ chmod 700          │
            │ ├── code/      │  │ (root access only) │
            │ └── report     │  └────────────────────┘
            │     .xlsx      │
            └────────────────┘"""

code_block(doc, diagram)

heading(doc, "2.3 Runtime Directory Structure", level=2)
para(doc, f"Root directory configurable via the WORK_DIR variable (default: /opt/ai-transit):")

tree = """\
/opt/ai-transit/
├── fetch/          ← Cloned repos (temporary working area)
├── quarantine/     ← Rejected files (chmod 700 — root only)
├── approved/       ← Approved archives (internal network read)
├── reports/        ← Timestamped JSON + HTML reports
├── logs/           ← Timestamped logs
└── yara-rules/     ← Custom YARA rules (.yar)"""
code_block(doc, tree)

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 3. PHASE 1
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "3. Phase 1 — Secure Retrieval (fetch_repo.sh)", level=1)

para(doc, (
    "The fetch_repo.sh script is responsible for the secure acquisition of source code. "
    "It constitutes the first filter of the pipeline before any content scanning."
))

steps = [
    ("Source validation",
     "If the input is a URL, only the github.com domain is allowed (strict whitelist). "
     "Any other source (GitLab, Bitbucket, private server) is immediately rejected."),

    ("Size check",
     "Before any download, the GitHub API is queried to determine the repository size. "
     "If it exceeds 500 MB, the fetch is cancelled. This prevents denial-of-service attacks "
     "(repo-bomb) and unintentional monorepo downloads."),

    ("Minimal clone",
     "The command git clone --depth 1 --no-tags --single-branch is used. "
     "--depth 1: only retrieves the latest commit (no history). "
     "--no-tags: excludes tags (potential injection vector). "
     "--single-branch: minimizes the attack surface."),

    ("Git metadata removal",
     "The .git/ directory is completely removed after the clone. Git metadata "
     "can contain references to external resources (submodules, hooks) "
     "and is not needed for scanning."),

    ("SHA-256 manifest",
     "A .manifest_sha256.txt file is generated in the fetched directory. It contains "
     "the SHA-256 hash of each file, allowing verification of content integrity "
     "between the fetch and the scan."),

    ("Quick triage",
     "A fast grep on known dangerous patterns (eval(, exec(, base64_decode, "
     "curl | bash, rm -rf /) is performed to immediately warn the operator, "
     "without blocking the pipeline (warnings will be confirmed or refuted during the scan)."),
]

for title, desc in steps:
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(0.5)
    r = p.add_run(f"▸ {title}: ")
    r.font.bold = True
    r.font.color.rgb = BLUE_MED
    r.font.size = Pt(10)
    r2 = p.add_run(desc)
    r2.font.size = Pt(10)

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 4. PHASE 2
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "4. Phase 2 — Multi-Layer Security Scan (scan_pipeline.sh)", level=1)

para(doc, (
    "The scan proceeds in two successive and complementary layers. "
    "Each file receives an individual status (PASS / WARN / FAIL) tracked in the final report."
))

heading(doc, "4.1 Global Layer", level=2)
para(doc, (
    "The global layer applies to the entire scanned directory, "
    "regardless of file type. It is executed first."
))

t = doc.add_table(rows=1, cols=3)
t.style = "Table Grid"
add_table_header(t, ["Tool", "What it detects", "Verdict if positive"])
set_col_widths(t, [3.5, 11, 3.5])
global_tools = [
    ("Gitleaks",        "Authentication tokens, API keys, secrets, credentials throughout the code", "FAIL"),
    ("detect-secrets",  "High-entropy strings (passwords, keys) through statistical analysis",       "FAIL"),
    ("ClamAV",          "Known malware signatures, trojans, viruses (ClamAV database)",              "FAIL"),
    ("YARA",            "Custom IOC rules defined in /opt/ai-transit/yara-rules/*.yar",              "FAIL"),
]
for row in global_tools:
    bg = RED_BG if row[2] == "FAIL" else YELLOW_BG
    add_row(t, row, bg=None, bold_first=True)
doc.add_paragraph()

heading(doc, "4.2 Per-File-Type Layer", level=2)
para(doc, (
    "After the global layer, each file is dispatched to a specialized scanner "
    "based on its extension. If a specialized tool is absent, a warning (WARN) "
    "is emitted but the scan continues — only active findings generate a FAIL."
))

t = doc.add_table(rows=1, cols=4)
t.style = "Table Grid"
add_table_header(t, ["Extension(s)", "Category", "Scanners called", "Manual checks"])
set_col_widths(t, [3.5, 3, 4, 7.5])
dispatch = [
    (".py",                "Python",      "Bandit",          "eval(), exec(), import os/subprocess/pty"),
    (".js .ts .jsx .tsx",  "JavaScript",  "Semgrep",         "eval(), child_process, require('child_process')"),
    (".c .cpp .h .hpp",    "C / C++",     "cppcheck",        "gets(), strcpy(), system(), popen()"),
    (".sh .bash .zsh .ps1","Shell",       "ShellCheck",      "curl|bash, wget|sh, eval $variable"),
    (".yml .yaml",         "YAML / CI",   "—",               "Unpinned actions (@main), inline secrets"),
    (".tf .tfvars .hcl",   "Terraform",   "checkov",         "Hardcoded secrets (password = \"…\")"),
    ("Dockerfile",         "Docker",      "hadolint",        ":latest, ADD http://, RUN curl|bash"),
    (".so .dll .exe .elf", "Binary",      "strings",         "Automatic FAIL + IOC search in strings"),
    (".zip .tar.gz",       "Archive",     "—",               "Automatic FAIL, extraction + re-scan required"),
    (".sql",               "SQL",         "—",               "xp_cmdshell, DROP TABLE/DATABASE, injections"),
    (".json .xml .md .txt","Documents",   "—",               "Inline secrets (password:, api_key=, token:)"),
    ("* (others)",         "Unknown",     "file (MIME)",     "Binary detection by MIME type"),
]
for row in dispatch:
    add_row(t, row, bold_first=True)
doc.add_paragraph()

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 5. DETAIL BY TYPE
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "5. Detailed Checks by File Type", level=1)

file_types = [
    # (title, extensions, intro_description, checks: [(check, explanation, verdict)])
    (
        "5.1 Python (.py)",
        ".py",
        "Python files are particularly risky because the language provides very powerful "
        "dynamic execution primitives, often used in malicious code.",
        [
            ("Bandit — Severity MEDIUM or HIGH",
             "Bandit is a Python-specialized static security analyzer. It detects "
             "dozens of dangerous patterns: SQL injections, use of subprocess "
             "with shell=True, disabling SSL verification, use of pickle "
             "(dangerous deserialization), insecure random number generation, etc. "
             "Only MEDIUM and HIGH severities trigger a FAIL (LOW is ignored).",
             "FAIL"),
            ("eval() / exec() — dynamic execution",
             "The presence of eval() or exec() in code is systematically flagged. "
             "These functions allow executing arbitrary code at runtime, "
             "which constitutes a trivial backdoor in AI-generated code.",
             "FAIL"),
            ("import os / subprocess / pty",
             "Importing system modules that allow shell command execution "
             "(os.system, subprocess.Popen, pty.spawn) is flagged as a warning. "
             "This is not systematically malicious but requires manual review.",
             "WARN"),
        ]
    ),
    (
        "5.2 JavaScript / TypeScript (.js .ts .jsx .tsx)",
        ".js, .ts, .jsx, .tsx",
        "The JavaScript ecosystem is highly exposed to supply-chain attacks "
        "and injections via dynamic execution mechanisms.",
        [
            ("Semgrep — ruleset p/javascript",
             "Semgrep is a multi-language static analysis tool based on AST patterns. "
             "The p/javascript ruleset covers: XSS injections, prototype pollution, "
             "dangerous use of innerHTML/document.write, eval(), "
             "uncontrolled JSON deserialization, and supply-chain attack patterns.",
             "FAIL"),
            ("eval() / child_process",
             "The presence of eval() or importing/requiring the child_process module is "
             "detected by grep. child_process allows executing shell commands "
             "from Node.js — its use in AI-generated code is highly suspicious.",
             "FAIL"),
        ]
    ),
    (
        "5.3 C / C++ (.c .cpp .h .hpp)",
        ".c, .cpp, .h, .hpp",
        "C/C++ code presents specific risks related to manual memory management "
        "and insecure legacy functions.",
        [
            ("cppcheck",
             "cppcheck is a C/C++ static analyzer that detects: buffer overflows, "
             "null pointer dereferences, memory leaks, use of uninitialized memory, "
             "division by zero, and array management errors. "
             "Any error or warning results in FAIL.",
             "FAIL"),
            ("Dangerous legacy functions",
             "gets(): reads input without size limit → guaranteed buffer overflow. "
             "strcpy(): copies without size check → overflow. "
             "system(): executes a shell command → possible injection. "
             "popen(): opens a shell process → arbitrary execution. "
             "These functions are forbidden in modern secure C (C11 Annex K).",
             "FAIL"),
        ]
    ),
    (
        "5.4 Shell / PowerShell (.sh .bash .zsh .ps1 .psm1)",
        ".sh, .bash, .zsh, .ps1, .psm1",
        "Shell scripts are direct attack vectors because their execution "
        "is immediate and their syntax easily allows command obfuscation.",
        [
            ("ShellCheck",
             "ShellCheck is a specialized linter for bash/sh/zsh scripts. "
             "It detects: unquoted variables (injection), uncontrolled globbing, "
             "dangerous redirections, suspicious nested subshells, "
             "and many syntax errors that can lead to unexpected behavior. "
             "The minimum alert level is 'warning' ('style' suggestions are ignored).",
             "FAIL"),
            ("curl | bash / wget | sh",
             "The pattern curl <url> | bash or wget <url> | sh is one of the most common "
             "techniques to execute remote code without integrity verification. "
             "Its presence in an AI-generated script is a strong indicator of compromise.",
             "FAIL"),
            ("eval $variable",
             "Using eval with a variable (eval $cmd, eval \"$input\") "
             "allows trivial command injection if the variable is controlled "
             "by an attacker or comes from an external source.",
             "FAIL"),
        ]
    ),
    (
        "5.5 YAML / GitHub Actions (.yml .yaml)",
        ".yml, .yaml",
        "YAML files are ubiquitous in CI/CD pipelines. "
        "A misconfiguration can open backdoors in the infrastructure.",
        [
            ("Unpinned GitHub Actions",
             "In GitHub Actions workflows, using an action without pinning "
             "to a commit hash (uses: actions/checkout@main instead of @sha256:abc123…) "
             "exposes the pipeline to a tag-hijacking attack: if the tag is "
             "rewritten by an attacker, a malicious version of the action runs "
             "in the CI.",
             "FAIL"),
            ("Plaintext secrets",
             "The presence of literal values associated with keys password, secret, "
             "token, key in YAML (not a ${{ secrets.XXX }} reference) indicates "
             "a secret hardcoded in configuration code.",
             "FAIL"),
        ]
    ),
    (
        "5.6 Terraform / HCL (.tf .tfvars .hcl)",
        ".tf, .tfvars, .hcl",
        "Infrastructure-as-code Terraform can provision entire cloud resources. "
        "A configuration error can expose critical services.",
        [
            ("checkov",
             "checkov is an IaC security scanner. It checks: "
             "S3 bucket encryption, overly permissive security rules (0.0.0.0/0), "
             "overly broad IAM (*), missing logging, unintentional public resources, "
             "and hardcoded secrets in Terraform resources.",
             "FAIL"),
            ("Hardcoded secrets in variables",
             ".tfvars files often contain variable values. "
             "The presence of password = \"value\", secret = \"value\" or token = \"value\" "
             "in plaintext is detected and flagged.",
             "FAIL"),
        ]
    ),
    (
        "5.7 Dockerfile",
        "Dockerfile, Dockerfile.*",
        "A malicious Dockerfile can install backdoors, exfiltrate data, "
        "or create images with compromised dependencies.",
        [
            ("hadolint",
             "hadolint is a Dockerfile linter based on Docker and CIS best practices. "
             "It detects: use of :latest (non-reproducible), "
             "apt commands without --no-install-recommends, "
             "COPY . . without .dockerignore, "
             "unnecessary port exposure, "
             "and use of ADD to download remote files.",
             "FAIL"),
            (":latest — unversioned tag",
             "Using images with the :latest tag (FROM ubuntu:latest) "
             "is forbidden because the image content can change at any time "
             "and introduce vulnerabilities or malicious code.",
             "FAIL"),
            ("ADD http:// — remote download",
             "The ADD instruction with an HTTP URL downloads remote content "
             "during the build without integrity verification. Prefer RUN curl + sha256 check.",
             "FAIL"),
            ("RUN curl | bash",
             "Same pattern as shell scripts: downloading and directly executing "
             "a remote script without validation.",
             "FAIL"),
        ]
    ),
    (
        "5.8 Binaries (.so .dll .dylib .exe .elf .bin)",
        ".so, .dll, .dylib, .exe, .elf, .bin",
        "Binary files have no place in an AI-generated code repository. "
        "Their presence is systematically considered suspicious.",
        [
            ("Automatic FAIL",
             "Every binary is automatically classified FAIL, without exception. "
             "An AI source code repository must not contain any precompiled executables "
             "or shared libraries — these could be implants or RATs.",
             "FAIL"),
            ("strings — IOC search",
             "The strings tool extracts all readable character strings from the binary. "
             "A search is performed to detect IOCs (Indicators of Compromise): "
             "HTTP/HTTPS URLs, system paths (/etc/passwd, /bin/sh), "
             "keywords exec, shell, reverse. "
             "These findings are recorded in the report but do not change the verdict "
             "(already FAIL).",
             "FAIL"),
        ]
    ),
    (
        "5.9 Archives (.zip .tar .tar.gz .tgz .bz2)",
        ".zip, .tar, .tar.gz, .tgz, .bz2",
        "Archives require special handling because their contents are not "
        "directly scannable without prior extraction.",
        [
            ("Automatic FAIL + re-scan required",
             "Every archive is classified FAIL. It must be extracted in an isolated "
             "environment and re-scanned separately with the full pipeline. "
             "This rule also prevents zip-slip attacks (extraction "
             "to arbitrary paths like ../../etc/cron.d/).",
             "FAIL"),
        ]
    ),
    (
        "5.10 SQL (.sql)",
        ".sql",
        "SQL files can contain destructive instructions or allow "
        "system command execution via database extensions.",
        [
            ("xp_cmdshell",
             "SQL Server stored procedure allowing shell command execution "
             "from the database. Its use is a critical IOC.",
             "FAIL"),
            ("DROP TABLE / DROP DATABASE",
             "Destructive instructions that can erase production data. "
             "Their presence in AI-generated code is flagged.",
             "FAIL"),
            ("; -- (injection comment)",
             "Classic SQL injection pattern: terminating a legitimate query "
             "and commenting out the rest to alter application logic.",
             "FAIL"),
        ]
    ),
    (
        "5.11 Documents (.json .xml .md .txt)",
        ".json, .xml, .md, .txt",
        "Documentation and text configuration files may contain "
        "secrets accidentally exposed in examples or comments.",
        [
            ("Inline secrets",
             "Detection of patterns password:, secret:, token:, api_key= "
             "followed by a literal value (not a variable or placeholder). "
             "This covers secrets exposed in README files, "
             "example configurations, or data files.",
             "FAIL"),
        ]
    ),
]

for title, exts, intro, checks in file_types:
    heading(doc, title, level=2)
    para(doc, f"Applicable extensions: {exts}", italic=True, color=RGBColor(0x60, 0x60, 0x60))
    para(doc, intro)

    t = doc.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    add_table_header(t, ["Check", "Detailed explanation", "Verdict"])
    set_col_widths(t, [4, 11.5, 2])
    for check, expl, verdict in checks:
        row = t.add_row()
        row.cells[0].text = check
        row.cells[0].paragraphs[0].runs[0].font.bold = True
        row.cells[0].paragraphs[0].runs[0].font.size = Pt(9)
        row.cells[1].text = expl
        row.cells[1].paragraphs[0].runs[0].font.size = Pt(9)
        row.cells[2].text = verdict
        run = row.cells[2].paragraphs[0].runs[0]
        run.font.size = Pt(9)
        run.font.bold = True
        if verdict == "FAIL":
            run.font.color.rgb = RED
            set_cell_bg(row.cells[2], RED_BG)
        elif verdict == "WARN":
            run.font.color.rgb = ORANGE
            set_cell_bg(row.cells[2], YELLOW_BG)
        for cell in row.cells:
            set_cell_border(cell)
    doc.add_paragraph()

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 6. TOOLS
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "6. Tools Used — Detailed Description", level=1)

para(doc, (
    "All tools are optional: if a tool is absent at scan time, "
    "the pipeline emits a WARN and continues. A FAIL is only triggered if a present tool "
    "actually detects a problem."
))

tools = [
    (
        "Gitleaks",
        "pip/binary GitHub Releases",
        "Secret and token detection",
        "Gitleaks uses regular expressions and entropy rules to identify "
        "secrets in source code. It covers more than 150 credential types: "
        "GitHub/GitLab/AWS/GCP/Azure tokens, RSA/PEM/SSH private keys, "
        "Stripe/Twilio/SendGrid API keys, JWT tokens, database credentials, "
        "TLS certificates, and generic high-entropy strings. "
        "It works without a Git repository (--no-git) to scan arbitrary directories."
    ),
    (
        "detect-secrets",
        "pip install detect-secrets",
        "Statistical entropy detection",
        "Yelp's detect-secrets uses an approach complementary to Gitleaks: "
        "it applies Shannon entropy analysis to detect strings that are statistically "
        "too random to be ordinary text. It also identifies structured patterns "
        "(base64, hex) that correspond to keys or tokens. "
        "The advantage is detecting secrets not yet covered by known rules."
    ),
    (
        "ClamAV (clamscan)",
        "apt install clamav",
        "Malware signature antivirus",
        "ClamAV is an open-source antivirus maintained by Cisco. Its signature database "
        "(updated via freshclam) covers millions of known malwares, trojans, ransomwares, "
        "backdoors and exploits. It scans each file in recursive mode "
        "(-r) and operates in quiet mode (--quiet) to return only positive detections. "
        "Particularly effective for detecting embedded malicious binaries."
    ),
    (
        "YARA",
        "apt install yara",
        "Custom IOC rules",
        "YARA is the industry standard for describing and detecting malware patterns. "
        "It allows writing custom rules combining string matches, "
        "regular expressions, and logical conditions. "
        ".yar rules placed in /opt/ai-transit/yara-rules/ are automatically "
        "applied to each scan. This allows adding rules specific to "
        "steganographic backdoors unique to generative AI models."
    ),
    (
        "Bandit",
        "pip install bandit",
        "Python SAST",
        "Bandit is the reference tool for Python static security analysis (SAST). "
        "It traverses the AST (Abstract Syntax Tree) of Python code and applies tests "
        "covering: SQL injections (B608), subprocess with shell=True (B603), "
        "pickle deserialization (B301), assert used for security (B101), "
        "weak DES/MD5 encryption (B303/B324), non-cryptographic random number generation "
        "(B311), and many others. "
        "Only MEDIUM and HIGH severities are retained to avoid noise."
    ),
    (
        "Semgrep",
        "pip install semgrep",
        "Multi-language SAST",
        "Semgrep is a static analyzer based on syntactic patterns that operates "
        "on the AST of many languages (Python, JS/TS, Go, Java, Ruby, PHP…). "
        "It uses the community ruleset p/javascript for JavaScript/TypeScript, "
        "covering: XSS injections, prototype pollution, path traversal, "
        "open redirects, Server-Side Template Injection, and supply-chain patterns. "
        "Semgrep's advantage is its precision: it understands code semantics "
        "unlike simple grep."
    ),
    (
        "cppcheck",
        "apt install cppcheck",
        "C/C++ static analysis",
        "cppcheck is a C/C++ static analyzer that detects errors without false positives. "
        "It covers: buffer overflows, null pointer dereferences, "
        "memory leaks (new without delete), use-after-free, "
        "division by zero, uninitialized variables, "
        "and array index errors. It parses C/C++ code without prior compilation."
    ),
    (
        "ShellCheck",
        "apt install shellcheck",
        "Shell script linting",
        "ShellCheck is the reference tool for static analysis of bash/sh/zsh scripts. "
        "It detects hundreds of issues: unquoted variables (SC2086), "
        "incorrect comparisons (SC2039), unprotected paths (SC2086), "
        "ambiguous redirections (SC2094), unnecessary subshells (SC2005), "
        "and security patterns like injections via variables. "
        "The minimum 'warning' level filters style suggestions."
    ),
    (
        "hadolint",
        "binary GitHub Releases",
        "Dockerfile linting",
        "hadolint (Haskell Dockerfile Linter) applies Docker and CIS best practices. "
        "It detects: :latest usage (DL3007), pip install without --no-cache-dir (DL3042), "
        "apt-get without --no-install-recommends (DL3008), COPY . . without .dockerignore, "
        "ADD for URLs (DL3020), sudo usage (DL3004), "
        "and curl piped to bash (DL4006). "
        "It also leverages ShellCheck to analyze RUN commands."
    ),
    (
        "checkov",
        "pip install checkov",
        "IaC security (Terraform, YAML)",
        "checkov scans Terraform code and cloud configurations to detect "
        "security bad practices according to CIS benchmarks. "
        "It checks: S3 buckets without encryption (CKV_AWS_19), "
        "security groups with 0.0.0.0/0 access (CKV_AWS_25), "
        "overly broad IAM policies (CKV_AWS_40), "
        "databases without at-rest encryption (CKV_AWS_16), "
        "and hardcoded secrets in Terraform variables."
    ),
    (
        "jq",
        "apt install jq",
        "JSON parsing (GitHub API)",
        "jq is used to parse the GitHub API response when checking "
        "the repository size before cloning. It extracts the .size field (in KB) "
        "to compare it against the 500 MB limit. It is also used to "
        "format the JSON report display in case of FAIL in ai_transit.sh."
    ),
]

for tool_name, install, role, desc in tools:
    heading(doc, tool_name, level=2)
    p = doc.add_paragraph()
    r = p.add_run(f"Installation: ")
    r.font.bold = True
    r.font.size = Pt(10)
    r2 = p.add_run(install)
    r2.font.name = "Courier New"
    r2.font.size = Pt(9)
    r2.font.color.rgb = RGBColor(0x00, 0x00, 0x80)

    p = doc.add_paragraph()
    r = p.add_run(f"Role: ")
    r.font.bold = True
    r.font.size = Pt(10)
    r2 = p.add_run(role)
    r2.font.size = Pt(10)
    r2.font.italic = True

    para(doc, desc)

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 7. RESULTS
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "7. Results — Archives and Reports", level=1)

heading(doc, "7.1 Approved ZIP Archive (Good/ directory)", level=2)
para(doc, (
    "When the scan completes with a PASS verdict (no critical findings), "
    "the pipeline produces a ZIP archive in the Good/ subdirectory located "
    "next to the scripts."
))

para(doc, "Archive contents:", bold=True)
archive_tree = """\
Good/
└── repo_YYYYMMDD_HHMMSS_YYYYMMDD_HHMMSS.zip
    ├── [complete source code of the scanned repository]
    │   ├── src/
    │   ├── README.md
    │   └── ...
    └── scan_report_YYYYMMDD_HHMMSS.xlsx   ← included Excel report"""
code_block(doc, archive_tree)

bullets_archive = [
    "The ZIP name contains the fetched directory name and a timestamp for uniqueness.",
    "The .manifest_sha256.txt file is excluded from the archive (internal use only).",
    "The scan Excel report is included directly in the archive, adjacent to the code.",
    "The archive is ready for transfer to the corporate network via the approved/ directory.",
    "Optional: GPG encryption of the archive if GPG_RECIPIENT is defined.",
]
for b in bullets_archive:
    bullet(doc, b)

heading(doc, "7.2 Excel Scan Report (generate_excel_report.py)", level=2)
para(doc, (
    "The Excel report is generated by the Python script generate_excel_report.py "
    "from the JSON report. It is included in the approved ZIP archive and "
    "intended for business and security teams."
))

# Tab 0
heading(doc, "Tab 0 — Summary", level=3)
t = doc.add_table(rows=1, cols=2)
t.style = "Table Grid"
add_table_header(t, ["Field", "Content"])
set_col_widths(t, [6, 11.5])
sheet0_rows = [
    ("Repository / Source",    "GitHub URL or local path provided as input"),
    ("Scan date",              "ISO 8601 timestamp (e.g. 2026-06-15T14:30:22Z)"),
    ("Global SHA-256 hash",    "SHA-256 fingerprint calculated across all repository files (sha256sum of all sorted files). Allows verifying the integrity of the batch."),
    ("Verdict",                "PASS (green background) or FAIL (red background)"),
    ("PASS files",             "Number of files that passed all checks"),
    ("WARN files",             "Number of warnings (tool absent or suspicious non-blocking pattern)"),
    ("FAIL files",             "Number of files with at least one critical finding"),
    ("Scanned directory",      "Absolute path of the directory scanned on the transit machine"),
]
for row in sheet0_rows:
    add_row(t, row, bold_first=True)
doc.add_paragraph()

# Tab 1
heading(doc, "Tab 1 — Files", level=3)
t = doc.add_table(rows=1, cols=2)
t.style = "Table Grid"
add_table_header(t, ["Column", "Content"])
set_col_widths(t, [6, 11.5])
sheet1_rows = [
    ("#",                  "Line number (priority order: FAIL → WARN → PASS)"),
    ("File",               "Full absolute path of the scanned file"),
    ("Type",               "File extension (.py, .sh, .yml, etc.)"),
    ("Status",             "PASS (green) / WARN (yellow) / FAIL (red)"),
    ("Message / Finding",  "Description of the detected issue(s) (empty if PASS)"),
]
for row in sheet1_rows:
    add_row(t, row, bold_first=True)
doc.add_paragraph()

para(doc, (
    "The Tab 1 table is sorted by descending criticality (FAIL first) "
    "and has an auto-filter on all columns. The first row is frozen "
    "to facilitate navigation in large reports."
))

heading(doc, "7.3 JSON Report", level=2)
para(doc, "A complete JSON report is generated in ${WORK_DIR}/reports/ at each execution:")
json_example = """\
{
  "verdict": "PASS | FAIL",
  "timestamp": "2026-06-15T14:30:22Z",
  "repo_input": "https://github.com/org/repo",
  "directory": "/opt/ai-transit/fetch/repo_20260615_143022",
  "repo_hash": "a3f5c8d2e1b9...",
  "summary": { "pass": 42, "warn": 3, "fail": 0 },
  "findings": {
    "/path/to/file.py": "bandit:Severity:HIGH | dynamic_exec:eval/exec"
  },
  "file_results": {
    "/path/to/file.py": { "status": "FAIL", "message": "bandit:Severity:HIGH" },
    "/path/to/main.sh": { "status": "PASS", "message": "" }
  }
}"""
code_block(doc, json_example)

heading(doc, "7.4 HTML Report", level=2)
para(doc, (
    "A dark-themed HTML report is generated alongside the JSON. "
    "It can be viewed directly in a browser on the transit machine "
    "(without network connection) and presents findings in a color-coded table. "
    "Reports are stored in ${WORK_DIR}/reports/ with a unique timestamp "
    "to build an audit history."
))

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 8. SECURITY RULES
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "8. Absolute Security Rules", level=1)

para(doc, (
    "These rules must never be modified. They constitute the fundamental "
    "threat model of the pipeline."
), bold=True, color=RED)

rules = [
    ("Network isolation",
     "The machine running this pipeline must never have direct access to the corporate "
     "network. It is on an isolated segment with only outbound access to "
     "the Internet (for fetch) and inbound access from the internal network to read "
     "only the approved/ directory (unidirectional flow)."),
    ("Unidirectional flow",
     "Only the approved/ directory is accessible for reading from the corporate network. "
     "No other pipeline directory (fetch/, quarantine/, reports/) must be "
     "accessible from the internal network."),
    ("Root-only quarantine",
     "The quarantine/ directory is chmod 700 — root access only. "
     "No application user must be able to read rejected files."),
    ("No moving from quarantine",
     "Never move a file from quarantine/ to approved/ without a full re-scan "
     "with the pipeline. Any manual bypass invalidates the security guarantees."),
    ("Binaries systematically rejected",
     "Binary files (.so, .exe, .elf, .dll) are always classified FAIL "
     "without exception. No precompiled executable must enter the internal network "
     "through this pipeline."),
    ("Archives — mandatory re-scan",
     "Archives (.zip, .tar.gz) are rejected because their content cannot be "
     "scanned without prior extraction in a dedicated isolated environment."),
]

for i, (title, desc) in enumerate(rules, 1):
    p = doc.add_paragraph()
    r = p.add_run(f"Rule {i} — {title}")
    r.font.bold = True
    r.font.color.rgb = RED
    r.font.size = Pt(11)
    para(doc, desc, indent=0.5)

page_break(doc)

# ══════════════════════════════════════════════════════════════════════════════
# 9. PREREQUISITES
# ══════════════════════════════════════════════════════════════════════════════
heading(doc, "9. Prerequisites and Installation", level=1)

heading(doc, "Operating System", level=2)
bullet(doc, "Ubuntu 22.04 LTS or Debian 12 (recommended)")
bullet(doc, "bash ≥ 5.0 (set -euo pipefail, associative arrays)")
bullet(doc, "python3 ≥ 3.10 + pip")
bullet(doc, "git ≥ 2.30")
bullet(doc, "zip, sha256sum, file, strings (binutils)")

heading(doc, "Automatic Installation", level=2)
code_block(doc, "sudo WORK_DIR=/opt/ai-transit bash install_deps.sh")

heading(doc, "Usage", level=2)
usages = [
    ("Full pipeline (GitHub URL)",
     "./ai_transit.sh https://github.com/org/repo"),
    ("Full pipeline with branch",
     "./ai_transit.sh https://github.com/org/repo main"),
    ("Pipeline on local path",
     "./ai_transit.sh /local/path/to/repo"),
    ("Fetch only",
     "WORK_DIR=/opt/ai-transit bash fetch_repo.sh https://github.com/org/repo"),
    ("Scan only (on already-fetched folder)",
     "WORK_DIR=/opt/ai-transit bash scan_pipeline.sh /opt/ai-transit/fetch/repo_xxx"),
    ("Excel report generation only",
     "python3 generate_excel_report.py report.json report.xlsx"),
]
for title, cmd in usages:
    p = doc.add_paragraph()
    r = p.add_run(f"{title}:")
    r.font.bold = True
    r.font.size = Pt(10)
    code_block(doc, cmd)

heading(doc, "Environment Variables", level=2)
t = doc.add_table(rows=1, cols=3)
t.style = "Table Grid"
add_table_header(t, ["Variable", "Default", "Description"])
set_col_widths(t, [4, 5, 8.5])
env_rows = [
    ("WORK_DIR",      "/opt/ai-transit", "Pipeline root directory"),
    ("OUTPUT_DIR",    "./Good",          "Output directory for approved archives"),
    ("GPG_RECIPIENT", "(empty)",         "GPG email for optional archive encryption"),
    ("REPO_INPUT",    "(auto)",          "Automatically passed to scan for traceability"),
]
for row in env_rows:
    add_row(t, row, bold_first=True)

doc.add_paragraph()

# Save
out_path = "/home/user/Claude/AI_Transit_Pipeline_Documentation_EN.docx"
doc.save(out_path)
print(f"Document generated: {out_path}")
