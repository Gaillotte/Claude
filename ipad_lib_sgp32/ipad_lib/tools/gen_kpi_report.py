#!/usr/bin/env python3
"""
Generate a PDF KPI report for the ipad library after each build.

Usage:
    gen_kpi_report.py --build-dir <dir> --source-dir <dir> --output <file.pdf>
"""

import argparse
import datetime
import os
import subprocess
import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable,
    )
except ImportError:
    print("[kpi] reportlab not installed — skipping PDF report")
    print("[kpi] Install with: pip install reportlab")
    sys.exit(0)


# ── Colour palette ─────────────────────────────────────────────────────────────
BLUE_DARK  = colors.HexColor("#1A3A5C")
BLUE_MID   = colors.HexColor("#2E6DA4")
BLUE_LIGHT = colors.HexColor("#D6E8F7")
GREY_ROW   = colors.HexColor("#F4F7FB")
GREEN_OK   = colors.HexColor("#217346")
RED_WARN   = colors.HexColor("#C0392B")


# ── Shell helpers ──────────────────────────────────────────────────────────────
def run(cmd: list[str], default: str = "N/A") -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       text=True).strip()
    except Exception:
        return default


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def stripped_size(path: str) -> int:
    tmp = path + ".strip_tmp"
    try:
        subprocess.check_call(
            ["strip", "--strip-unneeded", "-o", tmp, path],
            stderr=subprocess.DEVNULL,
        )
        return os.path.getsize(tmp)
    except Exception:
        return 0
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def section_sizes(path: str) -> dict[str, int]:
    """Parse `size` output → dict {text, data, bss, total}."""
    out = run(["size", path])
    lines = out.splitlines()
    if len(lines) < 2:
        return {}
    headers = lines[0].split()
    values  = lines[1].split()
    result = {}
    for h, v in zip(headers, values):
        try:
            result[h] = int(v)
        except ValueError:
            pass
    return result


def exported_symbols(path: str) -> int:
    out = run(["nm", "-D", "--defined-only", path])
    return sum(1 for line in out.splitlines() if " T " in line)


def shared_deps(path: str) -> list[str]:
    out = run(["ldd", path])
    deps = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            name = line.split("=>")[0].strip()
            deps.append(name)
        elif line.startswith("linux-vdso"):
            deps.append(line.split()[0])
    return deps


def git_info(source_dir: str) -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_DIR"] = os.path.join(source_dir, ".git")
    env["GIT_WORK_TREE"] = source_dir

    def g(cmd):
        try:
            return subprocess.check_output(
                cmd, cwd=source_dir, stderr=subprocess.DEVNULL, text=True
            ).strip()
        except Exception:
            return "N/A"

    return {
        "commit": g(["git", "log", "-1", "--format=%h"]),
        "branch": g(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "date":   g(["git", "log", "-1", "--format=%ci"]),
        "author": g(["git", "log", "-1", "--format=%an"]),
    }


# ── Collect all metrics ────────────────────────────────────────────────────────
def collect(build_dir: str, source_dir: str) -> dict:
    lib = os.path.join(build_dir, "libipad.so.1.0.0")
    app = os.path.join(build_dir, "ipad_app")

    lib_exists = os.path.isfile(lib)
    app_exists = os.path.isfile(app)

    sec_lib = section_sizes(lib) if lib_exists else {}
    sec_app = section_sizes(app) if app_exists else {}

    # Per-handle RAM estimate (bytes) — matches sizeof_probe values
    profile_size   = 216   # sizeof(ipad_profile_t)
    event_size     = 152   # sizeof(ipad_event_t)
    euicc_size     = 124   # sizeof(ipad_euicc_info_t)
    event_q_slots  = 32
    handle_static  = 40 + 48 + 120 + 16  # mutex+cv+config+log handler
    handle_heap    = handle_static + euicc_size + event_q_slots * event_size
    thread_stack   = 64 * 1024           # default Linux stack

    return {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "build_dir":    build_dir,
        "source_dir":   source_dir,
        "git":          git_info(source_dir),

        # Library
        "lib_exists":   lib_exists,
        "lib_full_kb":  file_size(lib) // 1024 if lib_exists else 0,
        "lib_strip_kb": stripped_size(lib) // 1024 if lib_exists else 0,
        "lib_text":     sec_lib.get("text", 0),
        "lib_data":     sec_lib.get("data", 0),
        "lib_bss":      sec_lib.get("bss", 0),
        "lib_rodata":   sec_lib.get("dec", 0) - sec_lib.get("text", 0)
                        - sec_lib.get("data", 0) - sec_lib.get("bss", 0)
                        if sec_lib else 0,
        "lib_symbols":  exported_symbols(lib) if lib_exists else 0,
        "lib_deps":     shared_deps(lib) if lib_exists else [],

        # Application
        "app_exists":   app_exists,
        "app_full_kb":  file_size(app) // 1024 if app_exists else 0,
        "app_strip_kb": stripped_size(app) // 1024 if app_exists else 0,
        "app_text":     sec_app.get("text", 0),
        "app_data":     sec_app.get("data", 0),
        "app_bss":      sec_app.get("bss", 0),

        # RAM
        "profile_size":  profile_size,
        "event_size":    event_size,
        "euicc_size":    euicc_size,
        "handle_heap":   handle_heap,
        "thread_stack":  thread_stack,
        "ram_total":     handle_heap + thread_stack,
        "ram_static_kb": (sec_lib.get("data", 0) + sec_lib.get("bss", 0)) // 1024 + 1,

        # Target context
        "target_ram_mb":   512,
        "target_flash_mb": 4096,
    }


# ── PDF layout helpers ─────────────────────────────────────────────────────────
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("title_main",
        fontSize=18, textColor=BLUE_DARK, spaceAfter=4,
        fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("subtitle",
        fontSize=10, textColor=BLUE_MID, spaceAfter=2,
        fontName="Helvetica"))
    ss.add(ParagraphStyle("section_head",
        fontSize=12, textColor=BLUE_DARK, spaceBefore=12, spaceAfter=4,
        fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("body",
        fontSize=9, textColor=colors.black, spaceAfter=2,
        fontName="Helvetica"))
    ss.add(ParagraphStyle("small",
        fontSize=8, textColor=colors.grey,
        fontName="Helvetica"))
    return ss


def _table(data: list, col_widths=None, header_row=True) -> Table:
    t = Table(data, colWidths=col_widths)
    style = [
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("BACKGROUND",   (0, 0), (-1, 0), BLUE_MID),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("ALIGN",        (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",        (1, 1), (-1, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY_ROW]),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    t.setStyle(TableStyle(style))
    return t


def _bar(label: str, value_kb: int, ref_kb: int, ss) -> list:
    """Return flowables for a simple ASCII progress bar."""
    pct = min(value_kb / ref_kb * 100, 100) if ref_kb else 0
    filled = int(pct / 5)
    bar = "█" * filled + "░" * (20 - filled)
    raw = GREEN_OK.hexval() if pct < 1 else BLUE_MID.hexval()
    # hexval() returns '0xRRGGBB' — convert to '#RRGGBB'
    colour_str = "#" + format(int(raw, 16), "06X")
    text = f"<font color='{colour_str}'>{bar}</font>  {value_kb} KB / {ref_kb} KB  ({pct:.3f} %)"
    return [Paragraph(f"<b>{label}</b>", ss["body"]),
            Paragraph(text, ss["body"]),
            Spacer(1, 4)]


# ── Build PDF ─────────────────────────────────────────────────────────────────
def generate(m: dict, output_path: str) -> None:
    ss = _styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    W = A4[0] - 4*cm
    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("IPAd Library — Build KPI Report", ss["title_main"]))
    story.append(Paragraph(
        f"GSMA SGP.32 · Qualcomm SA525 · Generated {m['generated_at']}",
        ss["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BLUE_MID,
                            spaceAfter=8))

    # ── Git info ──────────────────────────────────────────────────────────────
    g = m["git"]
    story.append(Paragraph("Build information", ss["section_head"]))
    story.append(_table([
        ["Field", "Value"],
        ["Branch",      g["branch"]],
        ["Commit",      g["commit"]],
        ["Commit date", g["date"]],
        ["Author",      g["author"]],
        ["Build dir",   m["build_dir"]],
    ], col_widths=[W*0.3, W*0.7]))
    story.append(Spacer(1, 6))

    # ── Binary size ───────────────────────────────────────────────────────────
    story.append(Paragraph("Binary size", ss["section_head"]))

    lib_row = (f"{m['lib_full_kb']} KB" if m["lib_exists"] else "not built",
               f"{m['lib_strip_kb']} KB" if m["lib_exists"] else "—")
    app_row = (f"{m['app_full_kb']} KB" if m["app_exists"] else "not built",
               f"{m['app_strip_kb']} KB" if m["app_exists"] else "—")

    story.append(_table([
        ["Artefact",          "With debug symbols", "Stripped (production)"],
        ["libipad.so",        lib_row[0],           lib_row[1]],
        ["ipad_app",          app_row[0],           app_row[1]],
        ["Total",
         f"{m['lib_full_kb'] + m['app_full_kb']} KB",
         f"{m['lib_strip_kb'] + m['app_strip_kb']} KB"],
    ], col_widths=[W*0.4, W*0.3, W*0.3]))
    story.append(Spacer(1, 8))

    # Section breakdown
    if m["lib_exists"]:
        story.append(Paragraph("Library section breakdown (libipad.so)", ss["section_head"]))
        story.append(_table([
            ["Section",   "Size (bytes)", "Description"],
            [".text",     f"{m['lib_text']:,}",  "Machine code"],
            [".rodata",   f"{max(m['lib_rodata'],0):,}", "Read-only constants, strings"],
            [".data",     f"{m['lib_data']:,}",  "Initialised global variables"],
            [".bss",      f"{m['lib_bss']:,}",   "Zero-initialised globals"],
        ], col_widths=[W*0.2, W*0.25, W*0.55]))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Exported public symbols: <b>{m['lib_symbols']}</b>",
            ss["body"]))
        story.append(Spacer(1, 4))
        if m["lib_deps"]:
            deps_str = ", ".join(m["lib_deps"])
            story.append(Paragraph(
                f"Shared library dependencies: <i>{deps_str}</i>", ss["small"]))
        story.append(Spacer(1, 6))

    # ── Flash footprint vs SA525 ───────────────────────────────────────────────
    story.append(Paragraph("Flash footprint vs SA525 capacity", ss["section_head"]))
    total_strip = m["lib_strip_kb"] + m["app_strip_kb"]
    target_flash_kb = m["target_flash_mb"] * 1024
    for flowable in _bar(
        "libipad.so (stripped)", m["lib_strip_kb"], target_flash_kb, ss
    ):
        story.append(flowable)
    for flowable in _bar(
        "Total deployment",      total_strip,        target_flash_kb, ss
    ):
        story.append(flowable)
    story.append(Spacer(1, 6))

    # ── RAM ───────────────────────────────────────────────────────────────────
    story.append(Paragraph("RAM consumption at runtime", ss["section_head"]))
    story.append(_table([
        ["Memory zone",               "Size (bytes)", "Size (KB)", "Notes"],
        ["ipad_ctx_s heap (1 handle)",
         f"{m['handle_heap']:,}", f"{m['handle_heap']//1024:.1f}",
         "malloc'd at ipad_init()"],
        ["  ↳ event queue (32 slots)",
         f"{32*m['event_size']:,}", f"{32*m['event_size']//1024:.1f}",
         "included in handle"],
        ["  ↳ eUICC info",
         f"{m['euicc_size']:,}", "—", "included in handle"],
        ["Worker thread stack",
         f"{m['thread_stack']:,}", f"{m['thread_stack']//1024:.0f}",
         "default; reducible to 8 KB"],
        ["Static (.data + .bss)",
         f"{m['lib_data']+m['lib_bss']:,}",
         f"{(m['lib_data']+m['lib_bss'])//1024:.1f}",
         "loaded once, shared between handles"],
        ["TOTAL (typical, 1 handle)",
         f"{m['ram_total']:,}",
         f"{m['ram_total']//1024:.0f}",
         ""],
    ], col_widths=[W*0.38, W*0.17, W*0.12, W*0.33]))
    story.append(Spacer(1, 8))

    # RAM bar vs SA525
    target_ram_kb = m["target_ram_mb"] * 1024
    story.append(Paragraph("RAM footprint vs SA525 capacity (512 MB)", ss["section_head"]))
    for flowable in _bar(
        "Total RAM (typical)", m["ram_total"] // 1024, target_ram_kb, ss
    ):
        story.append(flowable)
    story.append(Spacer(1, 6))

    # ── struct sizes ──────────────────────────────────────────────────────────
    story.append(Paragraph("Key data structure sizes", ss["section_head"]))
    story.append(_table([
        ["Structure",          "Size (bytes)", "Purpose"],
        ["ipad_profile_t",     f"{m['profile_size']}",
         "One installed eSIM profile descriptor"],
        ["ipad_event_t",       f"{m['event_size']}",
         "One queued event (ICCID + detail + status)"],
        ["ipad_euicc_info_t",  f"{m['euicc_size']}",
         "eUICC identity and capabilities"],
    ], col_widths=[W*0.3, W*0.2, W*0.5]))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "IPAd Library v1.0.0 · GSMA SGP.32 · Qualcomm SA525 TelSDK",
        ss["small"]))

    doc.build(story)
    print(f"[kpi] Report written to: {output_path}")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate a PDF KPI report for the ipad library")
    parser.add_argument("--build-dir",  required=True,
                        help="CMake build directory (contains libipad.so)")
    parser.add_argument("--source-dir", required=True,
                        help="Project source root (for git info)")
    parser.add_argument("--output",     required=True,
                        help="Output PDF path")
    args = parser.parse_args()

    metrics = collect(
        os.path.abspath(args.build_dir),
        os.path.abspath(args.source_dir),
    )
    generate(metrics, args.output)


if __name__ == "__main__":
    main()
