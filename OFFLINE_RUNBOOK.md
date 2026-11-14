# Air-Gapped Scan — Operating Procedure

**AI Transit Pipeline | Companion to INSTALL.md §11**

---

## Purpose and the one risk that governs it

This procedure covers scanning a repository on a host with no network access.

Everything here exists to prevent a single failure: **an offline scan that
reports PASS without having examined anything.** The scanners that need a
network do not announce their absence loudly on their own — a missing ruleset or
an unstaged database produces an empty result, and an empty result is
indistinguishable from a clean one unless you check for it.

So the procedure is built around one habit: **after every scan, confirm which
layers actually ran.** Step 5 is not optional paperwork. It is the step that
makes the other four mean something.

---

## Roles

| Role | Works on | Responsible for |
|------|----------|-----------------|
| **Cache operator** | Connected host | Building, dating and signing the offline cache |
| **Scan operator** | Air-gapped host | Verifying the cache, running scans, reading the coverage report |

The two may be the same person. The separation matters because the cache
operator is the only one who can fix a missing asset, and the scan operator is
the only one who can see that one is missing.

---

## Phase 0 — Pre-flight

On the **air-gapped host**, once, before first use.

```bash
# 1. The pipeline itself is installed and parses
bash -n ai_transit.sh fetch_repo.sh scan_pipeline.sh && echo "scripts OK"

# 2. The test suite passes — it needs no scanning tools and no network
./tests/run_tests.sh
# Expected: ✔ 1083/1083 passed

# 3. Record which scanners are present
for t in gitleaks detect-secrets clamscan yara semgrep trivy \
         bandit shellcheck cppcheck hadolint checkov scancode; do
    command -v "$t" >/dev/null && echo "  present : $t" || echo "  MISSING : $t"
done

# 4. Generate the bundle integrity manifest
python3 selfcheck.py --write-manifest
```

A tool listed as `MISSING` will be reported as a WARN on every scan and will
never contribute findings. Decide now whether that is acceptable; do not
discover it in a report six weeks later. `trivy` and `scancode` are the
exception: they are called only when you switch on layers 3 and 6
(`RUN_SCA=true`, `RUN_SCANCODE=true`; see Phase 3), so with those layers off
their absence is not reported.

---

## Phase 1 — Build the cache (connected host)

```bash
./prepare_offline_cache.sh /tmp/offline-cache
```

Read its summary before continuing. It reports what it staged and what it could
not.

**Verify the four asset groups are present and plausible:**

```bash
cd /tmp/offline-cache
ls -1 semgrep-rules/          # expect: owasp-top-ten, cwe-top-25,
                              #         security-audit, secrets, javascript (.yaml)
du -sh trivy-db/              # expect: several hundred MB, not a few KB
                              #         (read only when you run with RUN_SCA=true)
ls -1 clamav/                 # expect: *.cvd or *.cld files
ls -1 yara-rules/             # your own rules; may legitimately be empty
```

A `trivy-db` of a few kilobytes means the database did not download. If you will
enable layer 3 (`RUN_SCA=true`), that is the single most consequential thing to
get right — see the note in Phase 5. With layer 3 off, which is the default, the
database is not read.

**Date the cache.** The scan operator cannot tell how old the data is otherwise:

```bash
date -u +%Y-%m-%d > /tmp/offline-cache/.cache_built_on
cat /tmp/offline-cache/.cache_built_on
```

**Package and sign:**

```bash
cd /tmp
tar -czf offline-cache.tar.gz offline-cache
sha256sum offline-cache.tar.gz | tee offline-cache.tar.gz.sha256
```

Transfer both files. Communicate the SHA-256 through a **different channel** than
the archive itself — a checksum that travelled with the file it protects proves
nothing about tampering in transit.

---

## Phase 2 — Verify on arrival (air-gapped host)

Do not skip to extraction.

```bash
# 1. The archive matches what the cache operator sent
sha256sum -c offline-cache.tar.gz.sha256
# Expected: offline-cache.tar.gz: OK

# 2. Extract
sudo tar -xzf offline-cache.tar.gz -C /opt/ai-transit/

# 3. Every file inside is intact
cd /opt/ai-transit/offline-cache
sha256sum --check .cache_manifest.sha256 | grep -v ': OK$' || echo "all files OK"

# 4. How old is this data?
echo "cache built: $(cat .cache_built_on 2>/dev/null || echo 'UNKNOWN — reject')"
```

If step 1 or 3 fails, **stop**. Do not scan with a cache you cannot verify;
request a fresh transfer.

If step 4 says `UNKNOWN`, treat the cache as untrusted for CVE purposes — you
cannot judge whether its vulnerability data is current.

---

## Phase 3 — Configure

```bash
# Persist for the scan operator's shell
cat >> ~/.bashrc <<'EOF'
export WORK_DIR=/opt/ai-transit
export OFFLINE_CACHE=/opt/ai-transit/offline-cache
EOF
source ~/.bashrc
```

The scan is always offline. `scan_pipeline.sh` has no online mode: it points each
tool at the staged cache whatever the environment says, and `ai_transit.sh` always
runs it with `OFFLINE=true`, so there is nothing to switch on and an operator who
forgets a flag cannot get a scan that hangs on timeouts. `OFFLINE_CACHE` is the
variable that matters. The `--offline` flag (Phase 4) governs only the fetch
step, where it makes `ai_transit.sh` refuse a remote URL immediately;
`ai_transit.sh` does not read an `OFFLINE` environment variable.

**Layers 3 and 6 are off by default.** Layer 3 (dependency CVEs: trivy) runs only
with `RUN_SCA=true`, and layer 6 (ScanCode licences) only with
`RUN_SCANCODE=true`. Export them in the same way if you want those layers; layer 3
then reads the trivy database staged in Phase 1. While they are off, the report
records `skipped:disabled` for them and `coverage_complete` stays `False`
(Phase 5).

---

## Phase 4 — Run the scan

Remote URLs cannot be fetched without a network. Bring the repository to the
host and scan the directory. Pass `--offline` so that a remote URL is refused at
once (`Cannot clone ... without a network`) instead of attempted; the scan itself
is offline with or without it.

```bash
./ai_transit.sh --offline /path/to/repo
```

Common variants:

```bash
# CI gate — verdict only
./ai_transit.sh --offline --quiet /path/to/repo

# Audit without blocking or quarantining
./ai_transit.sh --offline --report-only /path/to/repo

# Reports only, no archive
./ai_transit.sh --offline --no-zip --no-excel /path/to/repo

# Through Docker (with OFFLINE_CACHE set, the wrapper mounts that directory
# read-only at /offline-cache and forwards RUN_SCA / RUN_SCANCODE; the image
# stages no Semgrep rulesets, so layer 2 runs in the container only with the cache)
./docker-run.sh --offline /path/to/repo
```

| Exit code | Meaning |
|-----------|---------|
| `0` | PASS — approved archive in `./Good/` |
| `1` | FAIL — quarantined, reports in `$WORK_DIR/reports/` |

---

## Phase 5 — Confirm the scan was real

**This is the step that distinguishes a trustworthy offline result from an empty
one.** A PASS is only meaningful if the layers that produce findings actually
ran.

Every report carries a machine-readable **coverage** block stating, per layer,
whether it ran. Use it — do not read the verdict alone, and do not grep warning
text, because a layer can fail to run for two unrelated reasons (the tool is not
installed, or its data was not staged) that produce different messages.

```bash
REPORT=$(ls -t "$WORK_DIR"/reports/report_*.json | head -1)

python3 - "$REPORT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("verdict          :", d["verdict"])
print("coverage_complete:", d["coverage_complete"])
print()
for layer, state in sorted(d["coverage"].items()):
    mark = "OK  " if state.startswith("ran") else "GAP "
    print(f"  {mark} {layer:26} {state}")
PY
```

Typical output for a correctly staged offline host:

```
verdict          : PASS
coverage_complete: False

  GAP  L1_ioc_yara                skipped:yara or rules directory missing
  OK   L1_malware                 ran
  OK   L1_secrets_entropy         ran
  OK   L1_secrets_gitleaks        ran
  OK   L2_owasp_cwe               ran
  GAP  L3_dependency_cve          skipped:disabled (RUN_SCA is not true)
  OK   L4_patterns                ran
  OK   L5_per_language_sast       ran
  GAP  L6_licence                 skipped:disabled (RUN_SCANCODE is not true)
```

`L1_ioc_yara` is a legitimate gap if you have not written custom IOC rules —
YARA rules are yours to supply, and having none is a configuration choice rather
than a failure. Layers 3 and 6 read `skipped:disabled` because they are switched
off by default (`RUN_SCA=true` and `RUN_SCANCODE=true` turn them on), which is
also why `coverage_complete` cannot read `True` until they are enabled; every
other layer should read `ran`.

### The acceptance gate

These five layers are the ones a verdict rests on. If any is not `ran`, the
result is not trustworthy regardless of what it says.

The one exception is a layer the report itself records as deliberately switched
off: layer 3 reads `skipped:disabled` unless `RUN_SCA=true`, and the gate leaves
it out in exactly that case. The gate reads the **report**, not the environment,
so a layer 3 that was enabled but could not run (for instance
`skipped:trivy database not staged for offline use`) is still a rejection.

```bash
python3 - "$REPORT" <<'PY'
import json, sys
REQUIRED = [
    "L1_secrets_gitleaks",      # credential leakage
    "L1_malware",               # malware signatures
    "L2_owasp_cwe",             # OWASP Top 10 / CWE Top 25
    "L3_dependency_cve",        # dependency vulnerabilities (off by default)
    "L5_per_language_sast",     # per-language static analysis
]
cov  = json.load(open(sys.argv[1])).get("coverage", {})
# A layer the report records as deliberately disabled is not a gap in the installation.
REQUIRED = [l for l in REQUIRED if not cov.get(l, "").startswith("skipped:disabled")]
gaps = [l for l in REQUIRED if not cov.get(l, "missing").startswith("ran")]
if gaps:
    print("REJECT — these layers did not run:", file=sys.stderr)
    for g in gaps:
        print(f"  {g}: {cov.get(g, 'not recorded')}", file=sys.stderr)
    sys.exit(2)
print("ACCEPT — all required layers ran")
PY
```

Exit `2` means the scan is inconclusive, not that the repository is bad. Fix the
staging and scan again; do not promote the artefact on the strength of a verdict
that rests on layers which never executed.

### What offline coverage actually looks like

| Layer | Offline status |
|-------|----------------|
| L1 secrets — gitleaks, detect-secrets | Full |
| L1 malware — ClamAV | Full **if** signatures staged |
| L1 IOC — YARA | Full (your own rules) |
| L2 OWASP/CWE — Semgrep | Full **if** rulesets staged |
| L3 dependency CVEs | Off by default (`RUN_SCA=true` enables it); then **trivy only** — see below |
| L4 pattern rules | Full, always |
| L5 per-language SAST | Full |
| L6 licence and copyright | Off by default (`RUN_SCANCODE=true` enables it); then Full |
| L6 package CVEs | Not available |

**The one asymmetry worth internalising:** with layer 3 enabled, the staged trivy
database is your *only* dependency-CVE coverage. pip-audit, safety and npm audit
have no offline mode and are never run by the scan, which records an `OFFLINE:`
warning when it finds a manifest they would have examined. There is no
redundancy — if the trivy database is missing or stale, dependency
vulnerabilities simply go unreported. With layer 3 off, the default, they are not
examined at all, and the report says so.

---

## Phase 6 — Keep the cache current

Vulnerability data ages. A stale database reports clean results for everything
published after it was built — the same outcome as not scanning, but harder to
notice because the report looks normal.

| Asset | Suggested cadence | Consequence of staleness |
|-------|-------------------|--------------------------|
| trivy database (layer 3 only) | **Weekly** | Recent CVEs unreported |
| ClamAV signatures | **Weekly** | Recent malware undetected |
| Semgrep rulesets | Monthly | Missing newer rules; existing ones still valid |
| YARA rules | On change | Your own IOC coverage |

Repeat Phases 1–2 to refresh. Keep the previous cache until the new one is
verified, so a failed transfer does not leave the host with nothing.

**Check the age of the running cache at any time:**

```bash
echo "cache built : $(cat "$OFFLINE_CACHE/.cache_built_on" 2>/dev/null || echo UNKNOWN)"
echo "today       : $(date -u +%Y-%m-%d)"
```

---

## Phase 7 — Periodic self-check

Monthly, or after any change to the pipeline files:

```bash
python3 selfcheck.py --only 11.1,11.4,11.6 --format both --output selfcheck_report
```

Check 11.6 compares the bundle against its manifest. A FAIL means a pipeline file
changed since the manifest was written — either an intentional update (regenerate
with `--write-manifest`) or something that warrants investigation.

Checks that reach the network (11.4 Python CVE, 11.5 host OS CVE) will report
SKIP or WARN offline. That is expected.

---

## Failure reference

| Symptom | Cause | Resolution |
|---------|-------|------------|
| A remote URL is attempted instead of refused | `--offline` not passed; it is the only thing that makes the fetch step refuse (the scan itself is always offline) | Pass `--offline`, and give a local path |
| `Cannot clone ... without a network` | Remote URL in offline mode | Copy the repository locally, pass its path |
| `L3_dependency_cve` / `L6_licence` read `skipped:disabled` | Layers 3 and 6 are off by default | Export `RUN_SCA=true` / `RUN_SCANCODE=true` if you want them; stage the trivy database first for layer 3 |
| Scan finishes suspiciously fast, few findings | Cache not staged | Run the Phase 5 check |
| `sha256sum -c` fails on arrival | Corrupt or tampered transfer | Do not extract; request a fresh transfer |
| `.cache_built_on` missing | Cache built without dating | Treat CVE results as untrusted; rebuild |
| Everything WARNs as "tool missing" | Scanners not installed on this host | Phase 0 step 3; install per INSTALL.md §6 |
| `declare -A: invalid option` | bash < 4.0 | Install bash 5 |

---

## Quick reference card

```
CONNECTED HOST
  ./prepare_offline_cache.sh /tmp/offline-cache
  date -u +%Y-%m-%d > /tmp/offline-cache/.cache_built_on
  tar -czf offline-cache.tar.gz -C /tmp offline-cache
  sha256sum offline-cache.tar.gz          # send via a separate channel

AIR-GAPPED HOST
  sha256sum -c offline-cache.tar.gz.sha256          # must pass
  tar -xzf offline-cache.tar.gz -C /opt/ai-transit/
  cd /opt/ai-transit/offline-cache
  sha256sum --check .cache_manifest.sha256          # must pass

  export OFFLINE_CACHE=/opt/ai-transit/offline-cache
  # optional, off by default: export RUN_SCA=true RUN_SCANCODE=true
  ./ai_transit.sh --offline /path/to/repo       # the scan is offline regardless;
                                                # --offline makes the fetch refuse a URL

  REPORT=$(ls -t $WORK_DIR/reports/report_*.json | head -1)
  python3 gate.py "$REPORT"                        # ALWAYS do this

  exit 0 : all required layers ran -> verdict is trustworthy
  exit 2 : a required layer did not run -> verdict is inconclusive,
           fix the staging and scan again
```

---

## Appendix — the gate as a script

Save as `gate.py` next to the pipeline:

```python
#!/usr/bin/env python3
"""Reject an offline scan whose verdict rests on layers that never ran."""
import json, sys

REQUIRED = [
    "L1_secrets_gitleaks",      # credential leakage
    "L1_malware",               # malware signatures
    "L2_owasp_cwe",             # OWASP Top 10 / CWE Top 25
    "L3_dependency_cve",        # dependency vulnerabilities (off by default)
    "L5_per_language_sast",     # per-language static analysis
]

report = json.load(open(sys.argv[1]))
cov    = report.get("coverage", {})
# A layer the report records as deliberately disabled is not a gap in the installation.
REQUIRED = [l for l in REQUIRED if not cov.get(l, "").startswith("skipped:disabled")]
gaps   = [l for l in REQUIRED if not cov.get(l, "missing").startswith("ran")]

if gaps:
    print("REJECT — these layers did not run:", file=sys.stderr)
    for g in gaps:
        print(f"  {g}: {cov.get(g, 'not recorded')}", file=sys.stderr)
    sys.exit(2)

print(f"ACCEPT — all required layers ran (verdict: {report['verdict']})")
```

Adjust `REQUIRED` to your policy. Removing a layer from that list is a decision
to accept scans that do not cover it — make it deliberately, not by omission.
The `skipped:disabled` line works the other way: it accepts a layer 3 that was
never switched on. If your policy requires dependency scanning on every scan,
delete that line, and a disabled layer 3 is rejected too.

---

*Per-tool technical reference: INSTALL.md §11. Flags and environment variables:
INSTALL.md §9.*
