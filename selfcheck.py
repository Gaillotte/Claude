#!/usr/bin/env python3
"""
AI Transit Pipeline — Self-Check & Safety Report Generator
Executes all §11 installation integrity checks and produces a PDF report.

Usage:
    python3 selfcheck.py [--bundle-dir DIR] [--output report.pdf] [--checksums checksums.json]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
except ImportError:
    print("[ERROR] reportlab missing — install with: pip install reportlab", file=sys.stderr)
    sys.exit(1)

pt = 1  # 1 point = 1 ReportLab unit

# ── Colours ──────────────────────────────────────────────────────────────────
C_PASS    = colors.HexColor("#C6EFCE")
C_FAIL    = colors.HexColor("#FFC7CE")
C_WARN    = colors.HexColor("#FFEB9C")
C_SKIP    = colors.HexColor("#E0E0E0")
C_HEADER  = colors.HexColor("#1F3864")
C_TITLE   = colors.HexColor("#2E4057")
C_TEXT    = colors.HexColor("#1A1A2E")
C_WHITE   = colors.white
C_BORDER  = colors.HexColor("#999999")

STATUS_COLOR = {"PASS": C_PASS, "FAIL": C_FAIL, "WARN": C_WARN, "SKIP": C_SKIP}
STATUS_LABEL = {"PASS": "✔ PASS", "FAIL": "✘ FAIL", "WARN": "⚠ WARN", "SKIP": "— SKIP"}


# ── Data model ───────────────────────────────────────────────────────────────
@dataclass
class CheckResult:
    id: str
    title: str
    status: str           # PASS | FAIL | WARN | SKIP
    summary: str
    details: list[str] = field(default_factory=list)
    command: str = ""
    elapsed: float = 0.0


# ── Runner helpers ────────────────────────────────────────────────────────────
def _run(cmd: list[str], timeout: int = 120, env: dict | None = None,
         cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, **(env or {})},
            cwd=str(cwd) if cwd else None,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ── §11.1  Meta-scan ─────────────────────────────────────────────────────────
def check_meta_scan(bundle_dir: Path) -> CheckResult:
    """Run ShellCheck + Bandit directly on bundle files (lightweight meta-scan)."""
    details = []
    failures = []
    warnings = []

    sh_files = list(bundle_dir.glob("*.sh"))
    py_files = list(bundle_dir.glob("*.py"))

    # ShellCheck
    if _has("shellcheck"):
        for f in sh_files:
            rc, out, err = _run(["shellcheck", "--severity=warning", str(f)])
            if rc != 0:
                combined = (out + "\n" + err).strip()
                first_lines = "\n".join(combined.splitlines()[:6])
                failures.append(f"shellcheck {f.name}: {first_lines}")
            else:
                details.append(f"shellcheck {f.name}: OK")
    else:
        warnings.append("shellcheck not installed — shell script analysis skipped")

    # Bandit
    if _has("bandit"):
        for f in py_files:
            rc, out, err = _run(["bandit", "-ll", "-q", str(f)])
            if rc not in (0, 1):
                warnings.append(f"bandit {f.name}: tool error")
            elif "Issue:" in out:
                hits = [l for l in out.splitlines() if "Issue:" in l]
                failures.append(f"bandit {f.name}: {len(hits)} issue(s) — {hits[0]}")
            else:
                details.append(f"bandit {f.name}: OK")
    else:
        warnings.append("bandit not installed — Python SAST skipped")

    # detect-secrets
    if _has("detect-secrets"):
        rc, out, err = _run(["detect-secrets", "scan", str(bundle_dir)])
        try:
            ds = json.loads(out)
            n = sum(len(v) for v in ds.get("results", {}).values())
            if n > 0:
                failures.append(f"detect-secrets: {n} potential secret(s) found")
            else:
                details.append("detect-secrets: no secrets detected")
        except json.JSONDecodeError:
            warnings.append("detect-secrets: could not parse output")
    else:
        warnings.append("detect-secrets not installed — secret scan skipped")

    details = warnings + details
    if failures:
        return CheckResult("11.1", "Meta-scan of bundle files",
                           "FAIL", f"{len(failures)} issue(s) detected",
                           failures + details,
                           "shellcheck *.sh && bandit *.py && detect-secrets scan .")
    if warnings and not details:
        return CheckResult("11.1", "Meta-scan of bundle files",
                           "SKIP", "No analysis tools available",
                           warnings,
                           "shellcheck *.sh && bandit *.py && detect-secrets scan .")
    if warnings:
        return CheckResult("11.1", "Meta-scan of bundle files",
                           "WARN", "Partial scan — some tools missing",
                           details,
                           "shellcheck *.sh && bandit *.py && detect-secrets scan .")
    return CheckResult("11.1", "Meta-scan of bundle files",
                       "PASS", f"{len(sh_files)} shell + {len(py_files)} Python files — all clean",
                       details,
                       "shellcheck *.sh && bandit *.py && detect-secrets scan .")


# ── §11.2  Binary checksums ───────────────────────────────────────────────────
def check_binary_checksums(checksums: dict[str, str]) -> CheckResult:
    """Compare installed binary hashes against a reference dict {path: expected_sha256}."""
    if not checksums:
        return CheckResult("11.2", "Binary SHA-256 checksums",
                           "SKIP", "No reference checksums provided (--checksums file not given)",
                           ["Pass --checksums path/to/checksums.json to enable this check."],
                           "sha256sum <binary>")

    details = []
    failures = []
    for path_str, expected in checksums.items():
        p = Path(path_str)
        if not p.exists():
            details.append(f"SKIP  {path_str} — not installed")
            continue
        rc, out, _ = _run(["sha256sum", path_str])
        actual = out.split()[0] if out else ""
        if actual.lower() == expected.lower():
            details.append(f"OK    {path_str}")
        else:
            failures.append(f"MISMATCH  {path_str}\n"
                            f"         expected: {expected}\n"
                            f"         actual  : {actual}")

    if failures:
        return CheckResult("11.2", "Binary SHA-256 checksums",
                           "FAIL", f"{len(failures)} checksum mismatch(es)",
                           failures + details, "sha256sum <binary>")
    return CheckResult("11.2", "Binary SHA-256 checksums",
                       "PASS", "All installed binaries match reference checksums",
                       details, "sha256sum <binary>")


# ── §11.3  GPG / cosign ───────────────────────────────────────────────────────
def check_signatures() -> CheckResult:
    """Check whether GPG and cosign are available for future signature verification."""
    details = []
    missing = []

    for tool in ("gpg", "cosign"):
        if _has(tool):
            rc, out, _ = _run([tool, "--version"], timeout=10)
            version_line = out.splitlines()[0] if out else "unknown version"
            details.append(f"{tool}: {version_line}")
        else:
            missing.append(f"{tool} not installed")

    if missing:
        return CheckResult("11.3", "GPG / Cosign signature tools",
                           "WARN",
                           "Signature verification tools partially missing — "
                           "manual verification recommended before production deployment",
                           missing + details,
                           "gpg --verify / cosign verify-blob")
    return CheckResult("11.3", "GPG / Cosign signature tools",
                       "PASS", "gpg and cosign are available",
                       details,
                       "gpg --verify / cosign verify-blob")


# ── §11.4  Python CVE scan ───────────────────────────────────────────────────
def check_python_cve(bundle_dir: Path) -> CheckResult:
    """Run pip-audit and safety against the current Python environment."""
    details = []
    failures = []
    warnings = []

    # pip-audit
    if _has("pip-audit"):
        rc, out, err = _run(["pip-audit", "--format", "json"], timeout=180)
        if rc == -1:
            warnings.append(f"pip-audit: {err}")
        else:
            try:
                audit = json.loads(out)
                vulns = [d for d in audit.get("dependencies", []) if d.get("vulns")]
                if vulns:
                    for dep in vulns:
                        for v in dep["vulns"]:
                            sev = v.get("fix_versions", ["?"])
                            failures.append(
                                f"{dep['name']}=={dep['version']} — {v['id']} "
                                f"(fix: {', '.join(sev)})"
                            )
                else:
                    details.append("pip-audit: no vulnerabilities found")
            except (json.JSONDecodeError, KeyError):
                # Fallback: parse plain text
                if "No known vulnerabilities" in out:
                    details.append("pip-audit: no vulnerabilities found")
                else:
                    warnings.append(f"pip-audit: could not parse output — {out[:200]}")
    else:
        warnings.append("pip-audit not installed — run: pip install pip-audit")

    # safety
    if _has("safety"):
        rc, out, err = _run(["safety", "check", "--json"], timeout=120)
        if rc == -1:
            warnings.append(f"safety: {err}")
        else:
            try:
                result = json.loads(out)
                vulns = result if isinstance(result, list) else result.get("vulnerabilities", [])
                if vulns:
                    for v in vulns[:5]:
                        if isinstance(v, list) and len(v) >= 4:
                            failures.append(f"safety: {v[0]}=={v[2]} — {v[3][:120]}")
                        elif isinstance(v, dict):
                            failures.append(f"safety: {v.get('package_name')} — {v.get('advisory', '')[:120]}")
                else:
                    details.append("safety: no advisories found")
            except (json.JSONDecodeError, KeyError):
                if rc == 0:
                    details.append("safety: no advisories found")
                else:
                    warnings.append("safety: could not parse output")
    else:
        warnings.append("safety not installed — run: pip install safety")

    # trivy on venv if available
    venv = Path(sys.executable).parent.parent
    if _has("trivy") and (venv / "lib").exists():
        rc, out, err = _run(
            ["trivy", "fs", str(venv), "--scanners", "vuln",
             "--severity", "HIGH,CRITICAL", "--format", "json", "--quiet"],
            timeout=300
        )
        try:
            tj = json.loads(out)
            vuln_list = [
                v for r in tj.get("Results", [])
                for v in r.get("Vulnerabilities") or []
            ]
            if vuln_list:
                for v in vuln_list[:5]:
                    failures.append(
                        f"trivy: {v.get('PkgName')} {v.get('InstalledVersion')} — "
                        f"{v.get('VulnerabilityID')} [{v.get('Severity')}]"
                    )
                if len(vuln_list) > 5:
                    failures.append(f"  … and {len(vuln_list) - 5} more — see full trivy report")
            else:
                details.append("trivy fs (venv): no HIGH/CRITICAL CVEs")
        except (json.JSONDecodeError, KeyError):
            warnings.append("trivy fs: could not parse output")

    all_details = warnings + details
    if failures:
        return CheckResult("11.4", "Python dependency CVE scan",
                           "FAIL", f"{len(failures)} vulnerability finding(s)",
                           failures + all_details,
                           "pip-audit && safety check && trivy fs <venv>")
    if warnings and not details:
        return CheckResult("11.4", "Python dependency CVE scan",
                           "SKIP", "CVE scan tools not available",
                           warnings,
                           "pip install pip-audit safety && pip-audit && safety check")
    if warnings:
        return CheckResult("11.4", "Python dependency CVE scan",
                           "WARN", "Partial scan — some tools missing",
                           all_details,
                           "pip-audit && safety check && trivy fs <venv>")
    return CheckResult("11.4", "Python dependency CVE scan",
                       "PASS", "No HIGH/CRITICAL CVEs in Python environment",
                       details,
                       "pip-audit && safety check && trivy fs <venv>")


# ── §11.5  Host OS CVE scan ───────────────────────────────────────────────────
def check_host_cve() -> CheckResult:
    """Run trivy rootfs to audit OS packages."""
    if not _has("trivy"):
        return CheckResult("11.5", "Host OS package CVE scan",
                           "SKIP", "trivy not installed",
                           ["Install with: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"],
                           "trivy rootfs /")

    rc, out, err = _run(
        ["trivy", "rootfs", "/",
         "--scanners", "vuln",
         "--severity", "HIGH,CRITICAL",
         "--ignore-unfixed",
         "--format", "json",
         "--quiet"],
        timeout=600
    )

    try:
        tj = json.loads(out)
        vuln_list = [
            v for r in tj.get("Results", [])
            for v in (r.get("Vulnerabilities") or [])
        ]
        if not vuln_list:
            return CheckResult("11.5", "Host OS package CVE scan",
                               "PASS", "No unpatched HIGH/CRITICAL CVEs on host OS",
                               ["trivy rootfs: no HIGH/CRITICAL unpatched CVEs found"],
                               "trivy rootfs / --severity HIGH,CRITICAL --ignore-unfixed")

        details = []
        for v in vuln_list[:10]:
            details.append(
                f"{v.get('PkgName')} {v.get('InstalledVersion')} — "
                f"{v.get('VulnerabilityID')} [{v.get('Severity')}] "
                f"fix: {v.get('FixedVersion', 'none')}"
            )
        if len(vuln_list) > 10:
            details.append(f"… and {len(vuln_list) - 10} more — run trivy rootfs / for full output")

        return CheckResult("11.5", "Host OS package CVE scan",
                           "WARN" if all(v.get("Severity") == "HIGH" for v in vuln_list) else "FAIL",
                           f"{len(vuln_list)} unpatched HIGH/CRITICAL CVE(s) on host",
                           details,
                           "trivy rootfs / --severity HIGH,CRITICAL --ignore-unfixed")
    except (json.JSONDecodeError, KeyError):
        return CheckResult("11.5", "Host OS package CVE scan",
                           "WARN", "trivy ran but output could not be parsed",
                           [err[:300] if err else out[:300]],
                           "trivy rootfs /")


# ── §11.6  Bundle integrity ───────────────────────────────────────────────────
def check_bundle_integrity(bundle_dir: Path) -> CheckResult:
    """Verify SHA-256 manifest of bundle files."""
    manifest = bundle_dir / ".bundle_manifest.sha256"

    if not manifest.exists():
        # Generate it now and report SKIP (first run)
        sh_files = sorted(bundle_dir.glob("*.sh"))
        py_files = sorted(bundle_dir.glob("*.py"))
        target_files = sh_files + py_files
        if not target_files:
            return CheckResult("11.6", "Bundle file integrity (SHA-256 manifest)",
                               "SKIP", "No .sh or .py files found in bundle directory",
                               [], "sha256sum --check .bundle_manifest.sha256")

        lines = []
        for f in target_files:
            rc, out, _ = _run(["sha256sum", str(f)])
            if rc == 0:
                lines.append(out)

        manifest.write_text("\n".join(lines) + "\n")
        return CheckResult("11.6", "Bundle file integrity (SHA-256 manifest)",
                           "WARN",
                           "Manifest did not exist — created now. Re-run selfcheck.py to verify.",
                           [f"Manifest written to: {manifest}",
                            f"Covers {len(lines)} file(s)"],
                           "sha256sum --check .bundle_manifest.sha256")

    # cwd= changes the actual working directory of the subprocess so relative
    # paths inside the manifest resolve correctly (env["PWD"] alone does not).
    rc, out, err = _run(["sha256sum", "--check", "--quiet", str(manifest)],
                        env={"PWD": str(bundle_dir)},
                        cwd=bundle_dir)
    if rc == 0:
        n = len(manifest.read_text().strip().splitlines())
        return CheckResult("11.6", "Bundle file integrity (SHA-256 manifest)",
                           "PASS", f"All {n} bundle file(s) match the manifest",
                           [f"Manifest: {manifest}"],
                           "sha256sum --check .bundle_manifest.sha256")

    bad = [l for l in (out + "\n" + err).splitlines() if "FAILED" in l or "WARNING" in l]
    return CheckResult("11.6", "Bundle file integrity (SHA-256 manifest)",
                       "FAIL", "File tampering detected — manifest mismatch",
                       bad or ["sha256sum check failed — see details above"],
                       "sha256sum --check .bundle_manifest.sha256")


# ── §11.7  AIDE / file integrity monitor ─────────────────────────────────────
def check_aide() -> CheckResult:
    """Check if AIDE is installed and last run was clean."""
    if not _has("aide"):
        return CheckResult("11.7", "File integrity monitor (AIDE)",
                           "SKIP",
                           "AIDE not installed — recommended for production environments",
                           ["Install with: sudo apt-get install aide",
                            "Then initialise: sudo aide --init"],
                           "sudo aide --check")

    rc, out, err = _run(["aide", "--check"], timeout=300)
    summary_lines = [l for l in (out + "\n" + err).splitlines()
                     if any(k in l for k in ("changed", "added", "removed", "error", "Total"))]
    if rc == 0:
        return CheckResult("11.7", "File integrity monitor (AIDE)",
                           "PASS", "AIDE check passed — no unexpected file changes",
                           summary_lines or ["aide --check returned 0"],
                           "sudo aide --check")
    return CheckResult("11.7", "File integrity monitor (AIDE)",
                       "FAIL", "AIDE detected file system changes",
                       summary_lines or ["aide --check returned non-zero — review aide output"],
                       "sudo aide --check")


# ── PDF report builder ───────────────────────────────────────────────────────
def build_pdf(results: list[CheckResult], output_path: Path, bundle_dir: Path) -> None:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
        title="AI Transit Pipeline — Self-Check Report"
    )

    styles = getSampleStyleSheet()
    S = {
        "title": ParagraphStyle("title", fontSize=20, textColor=C_WHITE,
                                 alignment=TA_CENTER, spaceAfter=4*pt, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("subtitle", fontSize=11, textColor=C_WHITE,
                                    alignment=TA_CENTER, fontName="Helvetica"),
        "h2": ParagraphStyle("h2", fontSize=13, textColor=C_TITLE,
                               fontName="Helvetica-Bold", spaceBefore=14*pt, spaceAfter=4*pt),
        "body": ParagraphStyle("body", fontSize=9, textColor=C_TEXT,
                                fontName="Helvetica", leading=13),
        "mono": ParagraphStyle("mono", fontSize=8, textColor=C_TEXT,
                                fontName="Courier", leading=11, leftIndent=10*pt),
        "small": ParagraphStyle("small", fontSize=7.5, textColor=colors.HexColor("#555555"),
                                 fontName="Helvetica"),
        "verdict_pass": ParagraphStyle("vp", fontSize=11, textColor=colors.HexColor("#1D6A2E"),
                                        fontName="Helvetica-Bold", alignment=TA_CENTER),
        "verdict_fail": ParagraphStyle("vf", fontSize=11, textColor=colors.HexColor("#9B1C1C"),
                                        fontName="Helvetica-Bold", alignment=TA_CENTER),
        "verdict_warn": ParagraphStyle("vw", fontSize=11, textColor=colors.HexColor("#92400E"),
                                        fontName="Helvetica-Bold", alignment=TA_CENTER),
    }

    story = []

    # ── Cover banner ──────────────────────────────────────────────────────────
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    hostname = _run(["hostname"], timeout=5)[1] or "unknown"
    banner_data = [[Paragraph("AI Transit Pipeline", S["title"])],
                   [Paragraph("Installation Self-Check Report", S["subtitle"])],
                   [Paragraph(f"Generated: {now}  |  Host: {hostname}", S["subtitle"])],
                   [Paragraph(f"Bundle: {bundle_dir}", S["subtitle"])]]
    banner = Table([[row[0]] for row in banner_data], colWidths=[17*cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_TITLE),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_TITLE]),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("RIGHTPADDING", (0,0), (-1,-1), 16),
    ]))
    story.append(banner)
    story.append(Spacer(1, 16*pt))

    # ── Global verdict ────────────────────────────────────────────────────────
    counts = {s: sum(1 for r in results if r.status == s)
              for s in ("PASS", "FAIL", "WARN", "SKIP")}
    # A majority of SKIPs means the installation is incomplete — do not report PASS.
    skip_threshold = len(results) // 2  # more than half
    if counts["FAIL"] > 0:
        global_verdict = "FAIL"
        verdict_style = S["verdict_fail"]
        verdict_bg = C_FAIL
    elif counts["WARN"] > 0 or counts["SKIP"] > skip_threshold:
        global_verdict = "WARN"
        verdict_style = S["verdict_warn"]
        verdict_bg = C_WARN
    else:
        global_verdict = "PASS"
        verdict_style = S["verdict_pass"]
        verdict_bg = C_PASS

    summary_rows = [
        [Paragraph("Global Verdict", ParagraphStyle("gh", fontSize=10,
                    fontName="Helvetica-Bold", textColor=C_WHITE)),
         Paragraph(f"PASS: {counts['PASS']}  |  WARN: {counts['WARN']}  |  "
                   f"FAIL: {counts['FAIL']}  |  SKIP: {counts['SKIP']}",
                   ParagraphStyle("gd", fontSize=10, fontName="Helvetica",
                                  textColor=C_WHITE)),
         Paragraph(global_verdict, ParagraphStyle("gv", fontSize=12,
                    fontName="Helvetica-Bold", textColor=C_TEXT, alignment=TA_CENTER))],
    ]
    summary_tbl = Table(summary_rows, colWidths=[4*cm, 9*cm, 4*cm])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (1,0), C_HEADER),
        ("BACKGROUND", (2,0), (2,0), verdict_bg),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("BOX", (0,0), (-1,-1), 1, C_BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 20*pt))

    # ── Overview table ────────────────────────────────────────────────────────
    story.append(Paragraph("Check Overview", S["h2"]))
    header = [Paragraph(h, ParagraphStyle("th", fontSize=9, fontName="Helvetica-Bold",
                                           textColor=C_WHITE))
              for h in ["ID", "Check", "Status", "Summary"]]
    rows = [header]
    for r in results:
        bg = STATUS_COLOR[r.status]
        rows.append([
            Paragraph(r.id, S["body"]),
            Paragraph(r.title, S["body"]),
            Paragraph(STATUS_LABEL[r.status],
                      ParagraphStyle("sl", fontSize=9, fontName="Helvetica-Bold",
                                      textColor=C_TEXT)),
            Paragraph(r.summary[:120], S["body"]),
        ])
    ov_tbl = Table(rows, colWidths=[1.2*cm, 5.5*cm, 1.8*cm, 8.5*cm])
    ts = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_HEADER),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
        ("BOX", (0,0), (-1,-1), 1, C_BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
    ])
    for i, r in enumerate(results, start=1):
        ts.add("BACKGROUND", (2, i), (2, i), STATUS_COLOR[r.status])
    ov_tbl.setStyle(ts)
    story.append(ov_tbl)
    story.append(Spacer(1, 24*pt))

    # ── Per-check detail sections ─────────────────────────────────────────────
    story.append(Paragraph("Detailed Results", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 8*pt))

    for r in results:
        bg = STATUS_COLOR[r.status]
        block = []

        # Section header
        hdr_data = [[
            Paragraph(f"§{r.id}  {r.title}",
                      ParagraphStyle("dh", fontSize=10, fontName="Helvetica-Bold",
                                      textColor=C_WHITE)),
            Paragraph(STATUS_LABEL[r.status],
                      ParagraphStyle("ds", fontSize=10, fontName="Helvetica-Bold",
                                      textColor=C_TEXT, alignment=TA_CENTER)),
        ]]
        hdr_tbl = Table(hdr_data, colWidths=[13.5*cm, 3.5*cm])
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,0), C_HEADER),
            ("BACKGROUND", (1,0), (1,0), bg),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("BOX", (0,0), (-1,-1), 0.5, C_BORDER),
        ]))
        block.append(hdr_tbl)
        block.append(Spacer(1, 4*pt))

        # Summary line
        block.append(Paragraph(f"<b>Result:</b> {r.summary}", S["body"]))

        # Command
        if r.command:
            block.append(Spacer(1, 3*pt))
            block.append(Paragraph(f"<b>Command:</b>", S["body"]))
            block.append(Paragraph(r.command, S["mono"]))

        # Details
        if r.details:
            block.append(Spacer(1, 4*pt))
            block.append(Paragraph("<b>Details:</b>", S["body"]))
            for line in r.details[:20]:
                safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                block.append(Paragraph(f"• {safe}", S["mono"]))
            if len(r.details) > 20:
                block.append(Paragraph(f"  … {len(r.details)-20} more line(s) truncated", S["small"]))

        block.append(Spacer(1, 12*pt))
        story.append(KeepTogether(block))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 6*pt))
    story.append(Paragraph(
        "AI Transit Pipeline — Self-Check Report  |  "
        f"Generated {now}  |  "
        "Checks correspond to §11 of the Installation Guide (INSTALL.md)",
        S["small"]
    ))

    doc.build(story)


# ── Main ─────────────────────────────────────────────────────────────────────
def _build_json_report(results: list[CheckResult], bundle_dir: Path,
                       verdict: str = "") -> dict:
    """Serialize check results to a JSON-serialisable dict."""
    counts = {s: sum(1 for r in results if r.status == s)
              for s in ("PASS", "FAIL", "WARN", "SKIP")}
    if not verdict:
        verdict = ("FAIL" if counts["FAIL"] > 0
                   else ("WARN" if counts["WARN"] > 0 else "PASS"))
    return {
        "verdict": verdict,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "bundle_dir": str(bundle_dir),
        "checks": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status,
                "summary": r.summary,
                "details": r.details,
                "command": r.command,
                "elapsed_s": round(r.elapsed, 3),
            }
            for r in results
        ],
        "summary": counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI Transit Pipeline self-check — runs §11 checks and produces a report"
    )
    parser.add_argument(
        "--bundle-dir", default=str(Path(__file__).parent),
        help="Directory containing the pipeline scripts (default: script's own directory)"
    )
    parser.add_argument(
        "--output", default="selfcheck_report.pdf",
        help="Output path base (default: selfcheck_report.pdf). "
             "For --format json the extension is replaced with .json; "
             "for --format both, both files are written."
    )
    parser.add_argument(
        "--checksums",
        help="Path to a JSON file mapping binary paths to their expected SHA-256 hashes. "
             "Example: {\"/usr/local/bin/betterleaks\": \"abc123...\"}",
        default=None
    )
    parser.add_argument(
        "--format", dest="fmt", choices=["pdf", "json", "both"], default="pdf",
        help="Output format: pdf (default), json, or both"
    )
    parser.add_argument(
        "--only",
        help="Comma-separated list of check numbers to run, e.g. 11.1,11.3,11.5. "
             "Other checks are skipped.",
        default=None
    )
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir).resolve()
    output_path = Path(args.output).resolve()

    if not bundle_dir.is_dir():
        print(f"[ERROR] Bundle directory not found: {bundle_dir}", file=sys.stderr)
        sys.exit(1)

    # Parse --only filter
    only_ids: set[str] | None = None
    if args.only:
        only_ids = {s.strip() for s in args.only.split(",") if s.strip()}

    # Load optional binary checksums
    checksums: dict[str, str] = {}
    if args.checksums:
        try:
            checksums = json.loads(Path(args.checksums).read_text())
        except Exception as exc:
            print(f"[WARN] Could not load checksums file: {exc}", file=sys.stderr)

    print("AI Transit Pipeline — Self-Check")
    print(f"Bundle : {bundle_dir}")
    print(f"Output : {output_path}  (format: {args.fmt})")
    if only_ids:
        print(f"Only   : {', '.join(sorted(only_ids))}")
    print()

    all_checks = [
        ("11.1", "§11.1  Meta-scan",              lambda: check_meta_scan(bundle_dir)),
        ("11.2", "§11.2  Binary checksums",        lambda: check_binary_checksums(checksums)),
        ("11.3", "§11.3  GPG / cosign tools",      check_signatures),
        ("11.4", "§11.4  Python CVE scan",         lambda: check_python_cve(bundle_dir)),
        ("11.5", "§11.5  Host OS CVE scan",        check_host_cve),
        ("11.6", "§11.6  Bundle file integrity",   lambda: check_bundle_integrity(bundle_dir)),
        ("11.7", "§11.7  AIDE integrity monitor",  check_aide),
    ]

    results: list[CheckResult] = []
    matched_ids: set[str] = set()
    for check_id, label, fn in all_checks:
        if only_ids and check_id not in only_ids:
            continue
        matched_ids.add(check_id)
        print(f"  Running {label} … ", end="", flush=True)
        result = fn()
        results.append(result)
        icon = {"PASS": "✔", "FAIL": "✘", "WARN": "⚠", "SKIP": "—"}[result.status]
        print(f"{icon} {result.status}  — {result.summary}")

    if only_ids and not matched_ids:
        print(f"[ERROR] --only filter '{args.only}' matched no checks. "
              f"Valid IDs: {', '.join(cid for cid, _, __ in all_checks)}",
              file=sys.stderr)
        sys.exit(2)

    print()
    counts = {s: sum(1 for r in results if r.status == s)
              for s in ("PASS", "FAIL", "WARN", "SKIP")}
    print(f"  PASS={counts['PASS']}  WARN={counts['WARN']}  FAIL={counts['FAIL']}  SKIP={counts['SKIP']}")

    global_verdict = "FAIL" if counts["FAIL"] > 0 else ("WARN" if counts["WARN"] > 0 else "PASS")
    print(f"  Global verdict: {global_verdict}")
    print()

    # ── Output generation ─────────────────────────────────────────────────────
    pdf_path = output_path.with_suffix(".pdf")
    json_path = output_path.with_suffix(".json")

    if args.fmt in ("pdf", "both"):
        print("  Generating PDF report … ", end="", flush=True)
        build_pdf(results, pdf_path, bundle_dir)
        print("done")
        print(f"  PDF saved to: {pdf_path}")

    if args.fmt in ("json", "both"):
        report_data = _build_json_report(results, bundle_dir, verdict=global_verdict)
        json_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False))
        print(f"  JSON saved to: {json_path}")

    sys.exit(1 if global_verdict == "FAIL" else 0)


if __name__ == "__main__":
    main()
