#!/usr/bin/env bash
# AI Transit Pipeline — test suite
#
# Runs without any scanning tool installed: the pipeline degrades to its
# grep-based rules, which is exactly how CI executes it. Tools that happen to
# be present are used, but no assertion depends on them.
#
# Usage:
#   ./tests/run_tests.sh              # run everything
#   ./tests/run_tests.sh -v           # show command output for failures
#   ./tests/run_tests.sh rules        # run only groups matching "rules"
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
FIXTURES="${TESTS_DIR}/fixtures"

VERBOSE=false
FILTER=""
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=true ;;
        *)            FILTER="$arg" ;;
    esac
done

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'
BLUE='\033[34m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

PASS_N=0; FAIL_N=0; SKIP_N=0
CURRENT_GROUP=""
declare -a FAILURES=()

# Scratch space; removed on exit.
SCRATCH="$(mktemp -d)"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

group() {
    CURRENT_GROUP="$1"
    if [[ -n "$FILTER" && "$1" != *"$FILTER"* ]]; then
        CURRENT_GROUP="__skip__"
        return
    fi
    echo
    echo -e "${BOLD}${BLUE}── $1 ${RESET}"
}

_skipping() { [[ "$CURRENT_GROUP" == "__skip__" ]]; }

ok_test() {
    (( PASS_N++ ))
    echo -e "  ${GREEN}✔${RESET} $1"
}

fail_test() {
    (( FAIL_N++ ))
    local name="$1"; shift
    echo -e "  ${RED}✘${RESET} $name"
    [[ $# -gt 0 ]] && echo -e "    ${DIM}$*${RESET}"
    FAILURES+=("${CURRENT_GROUP} :: ${name}")
}

skip_test() {
    (( SKIP_N++ ))
    echo -e "  ${YELLOW}—${RESET} $1 ${DIM}(skipped: ${2:-})${RESET}"
}

# ── Assertions ────────────────────────────────────────────────────────────────
assert_eq() {
    local expected="$1" actual="$2" name="$3"
    if [[ "$expected" == "$actual" ]]; then
        ok_test "$name"
    else
        fail_test "$name" "expected '${expected}', got '${actual}'"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" name="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        ok_test "$name"
    else
        fail_test "$name" "expected to find '${needle}'"
        $VERBOSE && echo -e "    ${DIM}--- actual ---\n${haystack}${RESET}"
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" name="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        ok_test "$name"
    else
        fail_test "$name" "did NOT expect '${needle}', but found it"
        $VERBOSE && echo -e "    ${DIM}--- actual ---\n${haystack}${RESET}"
    fi
}

assert_file_exists() {
    if [[ -f "$1" ]]; then ok_test "$2"; else fail_test "$2" "missing file: $1"; fi
}

# ── Pipeline driver ───────────────────────────────────────────────────────────
# run_pipeline <fixture_dir> [extra flags...]
# Sets: RUN_EXIT, RUN_OUT, RUN_WORK, RUN_JSON
run_pipeline() {
    local fixture="$1"; shift
    RUN_WORK="${SCRATCH}/work_$$_${RANDOM}"
    mkdir -p "$RUN_WORK"
    RUN_OUT=$(cd "$ROOT_DIR" && WORK_DIR="$RUN_WORK" OUTPUT_DIR="${RUN_WORK}/out" \
        timeout 300 ./ai_transit.sh "$@" "$fixture" 2>&1)
    RUN_EXIT=$?
    RUN_JSON=$(ls -t "${RUN_WORK}"/reports/report_*.json 2>/dev/null | head -1 || true)
}

# Read a value out of the JSON report with python3.
json_get() {
    python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
cur=d
for k in sys.argv[2].split('.'):
    cur=cur.get(k) if isinstance(cur,dict) else None
print(cur if cur is not None else '')
" "$1" "$2" 2>/dev/null || echo ""
}

# All finding text in the report, as one blob.
json_findings() {
    python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for p,i in d.get('file_results',{}).items():
    print(p, i.get('status',''), i.get('message',''))
" "$1" 2>/dev/null || echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# LAYER A — Rule corpus
# One scan over a directory of small files, each crafted to trigger (or
# deliberately not trigger) a specific rule. Asserting on rule IDs here is what
# catches false positives and false negatives cheaply.
# ═════════════════════════════════════════════════════════════════════════════
group "Layer A — rule corpus (detection correctness)"
if ! _skipping; then
    run_pipeline "${FIXTURES}/rules"

    if [[ -z "$RUN_JSON" ]]; then
        fail_test "rule corpus scan produced a JSON report" "no report written"
    else
        F=$(json_findings "$RUN_JSON")

        # ── True positives, checked per file ─────────────────────────────────
        # Asserting against the whole blob would pass even if a finding were
        # attributed to the wrong file, so match each finding on the line for
        # the file it belongs to. (A NUL-record off-by-one once shifted every
        # message onto the following file while the blob still "contained" it.)
        line_for() { echo "$F" | grep "/$1 " || true; }

        assert_contains "$(line_for sql_injection.py)" "CWE-89:SQL_injection" \
            "sql_injection.py is flagged for SQL injection"
        assert_contains "$(line_for hardcoded_secret.py)" "CWE-798" \
            "hardcoded_secret.py is flagged for a hardcoded credential"
        assert_contains "$(line_for exec.ps1)" "CWE-78:PowerShell_command_execution" \
            "exec.ps1 is flagged for Invoke-Expression"
        assert_contains "$(line_for deserialize.py)" "CWE-502" \
            "deserialize.py is flagged for insecure deserialization"
        # Extensionless scripts are routed by shebang; without that they fall
        # through to scan_unknown and skip per-language analysis entirely.
        assert_contains "$(line_for entrypoint)" "CWE-502" \
            "extensionless script is analysed via its shebang"

        # Status and message must agree: a PASS file carrying a [FAIL] message
        # means the report's parallel arrays have drifted out of alignment.
        MISMATCH=$(python3 -c "
import json,sys
d=json.load(open('$RUN_JSON'))
for p,i in d.get('file_results',{}).items():
    if i.get('status')=='PASS' and '[FAIL]' in i.get('message',''):
        print(p)
" 2>/dev/null || true)
        if [[ -z "$MISMATCH" ]]; then
            ok_test "no file is PASS while carrying a [FAIL] message"
        else
            fail_test "no file is PASS while carrying a [FAIL] message" "$MISMATCH"
        fi

        # ── False-positive guards: these must NOT be flagged ─────────────────
        # Regression guard for the P8 fix: the parameterised query form is the
        # correct, safe pattern and must never be reported as an injection.
        SAFE_LINE=$(echo "$F" | grep 'safe_sql.py' || true)
        assert_not_contains "$SAFE_LINE" "CWE-89" \
            "does NOT flag parameterised SQL (execute(\"… = ?\", (v,)))"

        SAFE_SH=$(echo "$F" | grep 'safe_shell.sh' || true)
        assert_not_contains "$SAFE_SH" "CWE-78" \
            "does NOT flag quoted shell variable expansion"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER B — End-to-end verdicts
# ═════════════════════════════════════════════════════════════════════════════
group "Layer B — end-to-end verdicts"
if ! _skipping; then
    run_pipeline "${FIXTURES}/clean" --quiet
    assert_eq "0" "$RUN_EXIT" "clean repo exits 0"
    [[ -n "$RUN_JSON" ]] && assert_eq "PASS" "$(json_get "$RUN_JSON" verdict)" \
        "clean repo verdict is PASS"

    run_pipeline "${FIXTURES}/vulnerable" --quiet
    assert_eq "1" "$RUN_EXIT" "vulnerable repo exits 1"
    [[ -n "$RUN_JSON" ]] && assert_eq "FAIL" "$(json_get "$RUN_JSON" verdict)" \
        "vulnerable repo verdict is FAIL"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER C — Flags and features
# ═════════════════════════════════════════════════════════════════════════════
group "Layer C — flags and features"
if ! _skipping; then
    # --report-only: never blocks, and must not quarantine.
    run_pipeline "${FIXTURES}/vulnerable" --report-only
    assert_eq "0" "$RUN_EXIT" "--report-only exits 0 despite FAIL verdict"
    QN=$(ls -A "${RUN_WORK}/quarantine" 2>/dev/null | wc -l)
    assert_eq "0" "$QN" "--report-only leaves quarantine empty"
    FN=$(ls -d "${RUN_WORK}"/fetch/repo_* 2>/dev/null | wc -l)
    assert_eq "1" "$FN" "--report-only preserves the fetched directory"

    # Default (no --report-only) must quarantine.
    run_pipeline "${FIXTURES}/vulnerable" --quiet
    QN=$(ls -A "${RUN_WORK}/quarantine" 2>/dev/null | wc -l)
    if (( QN > 0 )); then ok_test "default run quarantines on FAIL"
    else fail_test "default run quarantines on FAIL" "quarantine empty"; fi

    # --min-severity critical: a HIGH finding should no longer block.
    run_pipeline "${FIXTURES}/vulnerable" --quiet --min-severity critical
    assert_eq "0" "$RUN_EXIT" "--min-severity critical downgrades HIGH to WARN"

    # Missing argument must be a clean error, not a crash.
    OUT=$(cd "$ROOT_DIR" && ./ai_transit.sh --min-severity 2>&1); EC=$?
    assert_eq "1" "$EC" "--min-severity with no argument exits 1"
    assert_contains "$OUT" "requires an argument" \
        "--min-severity with no argument explains itself"

    # .transit-allow.json downgrades a matching FAIL to WARN.
    run_pipeline "${FIXTURES}/allowlisted" --quiet
    assert_eq "0" "$RUN_EXIT" "allowlisted finding does not block"

    # .transitignore excludes matched files from scanning.
    run_pipeline "${FIXTURES}/ignored" --quiet
    assert_eq "0" "$RUN_EXIT" ".transitignore excludes the offending file"

    # --no-zip / --no-excel: reports still written, no archive produced.
    run_pipeline "${FIXTURES}/clean" --quiet --no-zip --no-excel
    assert_eq "0" "$RUN_EXIT" "--no-zip --no-excel still exits 0 on PASS"
    ZN=$(ls "${RUN_WORK}/out"/*.zip 2>/dev/null | wc -l)
    assert_eq "0" "$ZN" "--no-zip produces no archive"
    assert_file_exists "$RUN_JSON" "--no-zip still writes the JSON report"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER C2 — Offline / air-gapped operation
# Stubs stand in for semgrep and trivy so the flags passed to them can be
# asserted without installing either. What matters is that offline the pipeline
# never reaches for the network AND never stays silent about a layer it could
# not run: a quiet skip would present an empty result as a clean one.
# ═════════════════════════════════════════════════════════════════════════════
group "Layer C2 — offline mode"
if ! _skipping; then
    STUBS="${SCRATCH}/stubs"
    mkdir -p "$STUBS"
    for tool in semgrep trivy; do
        cat > "${STUBS}/${tool}" <<EOF
#!/bin/sh
echo "\$@" >> "${STUBS}/${tool}_calls.txt"
echo '{"results":[],"Results":[]}'
EOF
        chmod +x "${STUBS}/${tool}"
    done

    # Offline with nothing staged: both layers must be reported as not run.
    rm -f "${STUBS}"/*_calls.txt
    RUN_WORK="${SCRATCH}/off_bare"; mkdir -p "$RUN_WORK"
    OUT=$(cd "$ROOT_DIR" && PATH="${STUBS}:$PATH" WORK_DIR="$RUN_WORK" \
          OUTPUT_DIR="${RUN_WORK}/out" timeout 300 ./ai_transit.sh --offline \
          "${FIXTURES}/clean" 2>&1)

    assert_contains "$OUT" "OFFLINE:Layer 2 skipped entirely" \
        "offline without staged rules reports Layer 2 as not run"
    assert_contains "$OUT" "OFFLINE:trivy database not staged" \
        "offline without a staged DB reports the CVE scan as not run"
    assert_contains "$OUT" "OFFLINE:Python dependency CVE scan unavailable" \
        "offline names pip-audit/safety as unavailable rather than skipping quietly"

    if [[ -f "${STUBS}/semgrep_calls.txt" ]]; then
        fail_test "offline never invokes semgrep without staged rules" \
                  "semgrep was called"
    else
        ok_test "offline never invokes semgrep without staged rules"
    fi
    if [[ -f "${STUBS}/trivy_calls.txt" ]]; then
        fail_test "offline never invokes trivy without a staged database" \
                  "trivy was called"
    else
        ok_test "offline never invokes trivy without a staged database"
    fi

    # Offline with staged assets: local paths and update-suppressing flags.
    rm -f "${STUBS}"/*_calls.txt
    CACHE="${SCRATCH}/cache"
    mkdir -p "${CACHE}/semgrep-rules" "${CACHE}/trivy-db/db"
    for r in owasp-top-ten cwe-top-25 security-audit secrets; do
        echo "rules: []" > "${CACHE}/semgrep-rules/${r}.yaml"
    done
    touch "${CACHE}/trivy-db/db/trivy.db"
    RUN_WORK="${SCRATCH}/off_staged"; mkdir -p "$RUN_WORK"
    (cd "$ROOT_DIR" && PATH="${STUBS}:$PATH" WORK_DIR="$RUN_WORK" \
     OUTPUT_DIR="${RUN_WORK}/out" OFFLINE_CACHE="$CACHE" \
     timeout 300 ./ai_transit.sh --offline "${FIXTURES}/clean" >/dev/null 2>&1) || true

    SG=$(cat "${STUBS}/semgrep_calls.txt" 2>/dev/null || true)
    assert_contains "$SG" "${CACHE}/semgrep-rules/owasp-top-ten.yaml" \
        "offline points semgrep at the staged ruleset file"
    assert_not_contains "$SG" "--config=p/" \
        "offline never resolves a semgrep registry identifier"
    assert_contains "$SG" "--metrics=off" \
        "offline disables semgrep telemetry"

    TV=$(cat "${STUBS}/trivy_calls.txt" 2>/dev/null || true)
    assert_contains "$TV" "--skip-db-update" "offline stops trivy updating its database"
    assert_contains "$TV" "--offline-scan"   "offline puts trivy in offline-scan mode"
    assert_contains "$TV" "$CACHE"           "offline points trivy at the staged cache"

    # A remote URL cannot be honoured without a network; refuse, do not hang.
    RUN_WORK="${SCRATCH}/off_remote"; mkdir -p "$RUN_WORK"
    OUT=$(cd "$ROOT_DIR" && WORK_DIR="$RUN_WORK" timeout 60 ./ai_transit.sh \
          --offline https://github.com/org/repo 2>&1); EC=$?
    assert_eq "1" "$EC" "offline refuses a remote URL"
    assert_contains "$OUT" "without a network" \
        "offline explains why a remote URL cannot be used"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER D — Output artifacts
# ═════════════════════════════════════════════════════════════════════════════
group "Layer D — output artifacts"
if ! _skipping; then
    run_pipeline "${FIXTURES}/clean" --quiet

    assert_file_exists "$RUN_JSON" "JSON report is written"
    if [[ -n "$RUN_JSON" ]]; then
        if python3 -c "import json;json.load(open('$RUN_JSON'))" 2>/dev/null; then
            ok_test "JSON report is valid JSON"
        else
            fail_test "JSON report is valid JSON" "json.load failed"
        fi
        assert_contains "$(cat "$RUN_JSON")" '"verdict"' "JSON report has a verdict field"
    fi
    assert_file_exists "${RUN_JSON%.json}.html" "HTML report is written"

    # ZIP entries must be repo-relative: an archive carrying the internal
    # WORK_DIR layout leaks server paths to whoever receives it.
    ZIP=$(ls -t "${RUN_WORK}/out"/*.zip 2>/dev/null | head -1 || true)
    if [[ -z "$ZIP" ]]; then
        fail_test "PASS run produces a ZIP archive" "no zip in output dir"
    else
        ok_test "PASS run produces a ZIP archive"
        if command -v unzip &>/dev/null; then
            ENTRIES=$(unzip -Z1 "$ZIP" 2>/dev/null)
            # zip stores paths with the leading "/" stripped, so comparing
            # against the absolute $RUN_WORK would never match. Look for the
            # internal layout marker instead.
            assert_not_contains "$ENTRIES" "fetch/repo_" \
                "ZIP entries do not embed the internal work directory"
            # Must match a whole entry, not a substring: the bad form
            # "tmp/work/fetch/repo_x/src/app.py" also contains "src/app.py".
            if echo "$ENTRIES" | grep -qx 'src/app\.py'; then
                ok_test "ZIP entries are rooted at the repository"
            else
                fail_test "ZIP entries are rooted at the repository" \
                    "no entry equal to 'src/app.py'"
                $VERBOSE && echo -e "    ${DIM}${ENTRIES}${RESET}"
            fi
        else
            skip_test "ZIP entry paths" "unzip not installed"
        fi
    fi

    # Excel report: only assert when openpyxl is available.
    if python3 -c "import openpyxl" 2>/dev/null; then
        XLSX="${SCRATCH}/report.xlsx"
        if python3 "${ROOT_DIR}/generate_excel_report.py" "$RUN_JSON" "$XLSX" >/dev/null 2>&1; then
            SHEETS=$(python3 -c "
from openpyxl import load_workbook
print(','.join(load_workbook('$XLSX').sheetnames))")
            assert_contains "$SHEETS" "Findings" "Excel report has a Findings tab"
        else
            fail_test "Excel report generates" "generate_excel_report.py failed"
        fi
    else
        skip_test "Excel report" "openpyxl not installed"
    fi

    # Redirected output must not contain terminal escape sequences.
    if [[ "$RUN_OUT" == *$'\033[K'* ]]; then
        fail_test "no erase-line escape codes when output is redirected" \
                  "found \\033[K in captured output"
    else
        ok_test "no erase-line escape codes when output is redirected"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER E — Diff mode (needs git)
# ═════════════════════════════════════════════════════════════════════════════
group "Layer E — diff mode"
if ! _skipping; then
    if ! command -v git &>/dev/null; then
        skip_test "diff mode scans only changed files" "git not installed"
    else
        REPO="${SCRATCH}/diffrepo"
        mkdir -p "$REPO/src"
        git init -q "$REPO"
        git -C "$REPO" config user.email test@example.com
        git -C "$REPO" config user.name  test
        echo 'print("unchanged")' > "$REPO/src/untouched.py"
        git -C "$REPO" add -A && git -C "$REPO" commit -qm base
        BASE=$(git -C "$REPO" rev-parse HEAD)
        cp "${FIXTURES}/rules/sql_injection.py" "$REPO/src/added.py"
        git -C "$REPO" add -A && git -C "$REPO" commit -qm change

        run_pipeline "$REPO" --since "$BASE"
        assert_contains "$RUN_OUT" "1 file(s) will be scanned" \
            "diff mode scans exactly the changed file"
        assert_contains "$RUN_OUT" "Layer 5: 1 files scanned" \
            "diff mode scan count matches the changed-file count"

        # Without --since, .git must not be copied at all: on a large repo the
        # history is gigabytes copied only to be deleted moments later.
        run_pipeline "$REPO" --quiet
        FETCHED=$(ls -d "${RUN_WORK}"/fetch/repo_* 2>/dev/null | head -1 || true)
        if [[ -z "$FETCHED" ]]; then
            FETCHED=$(ls -d "${RUN_WORK}"/quarantine/repo_* 2>/dev/null | head -1 || true)
        fi
        if [[ -n "$FETCHED" ]]; then
            if [[ -d "${FETCHED}/.git" ]]; then
                fail_test "local copy excludes .git" "${FETCHED}/.git exists"
            else
                ok_test "local copy excludes .git"
            fi
        else
            skip_test "local copy excludes .git" "no fetched directory found"
        fi
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER F — Static checks on the pipeline itself
# ═════════════════════════════════════════════════════════════════════════════
group "Layer F — static checks"
if ! _skipping; then
    for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh; do
        if bash -n "${ROOT_DIR}/${f}" 2>/dev/null; then
            ok_test "${f} parses"
        else
            fail_test "${f} parses" "$(bash -n "${ROOT_DIR}/${f}" 2>&1 | head -3)"
        fi
    done

    for f in selfcheck.py generate_excel_report.py; do
        if python3 -c "import ast;ast.parse(open('${ROOT_DIR}/${f}').read())" 2>/dev/null; then
            ok_test "${f} parses"
        else
            fail_test "${f} parses"
        fi
    done

    # `local` outside a function is valid syntax but aborts at runtime under
    # `set -e` ("local: can only be used in a function") -- exactly the
    # regression that silently broke private-repo cloning. bash -n cannot see
    # it, so check statically here.
    #
    # Depth is tracked by net brace balance per line: one-line definitions such
    # as `info() { echo; }` open and close on the same line, so a naive counter
    # that only decrements on a lone `}` would stay permanently incremented and
    # never report anything.
    for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh; do
        BAD=$(awk '
            {
                line = $0
                sub(/#.*$/, "", line)
                gsub(/\047[^\047]*\047/, "", line)
                gsub(/"[^"]*"/, "", line)

                if (depth == 0 && $0 ~ /^[[:space:]]*local[[:space:]]/)
                    print FILENAME ":" NR ": " $0

                n = gsub(/\{/, "{", line)
                m = gsub(/\}/, "}", line)
                depth += n - m
                if (depth < 0) depth = 0
            }
        ' "${ROOT_DIR}/${f}")
        if [[ -z "$BAD" ]]; then
            ok_test "${f} has no top-level 'local'"
        else
            fail_test "${f} has no top-level 'local'" "$BAD"
        fi
    done

    # IFS is a SET of delimiter characters, not a delimiter string. Writing
    # IFS=':::' is silently identical to IFS=':' and scatters fields across
    # the empty splits. This class of bug shipped twice (the allowlist loader
    # and the semgrep result parser), so lint for it directly: any quoted IFS
    # assignment longer than one character is a defect.
    for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh; do
        BAD=$(grep -nE "IFS=('[^']{2,}'|\"[^\"]{2,}\")" "${ROOT_DIR}/${f}" \
              | grep -v '\$' \
              | grep -vE '^[0-9]+:[[:space:]]*#' || true)
        if [[ -z "$BAD" ]]; then
            ok_test "${f} has no multi-character IFS"
        else
            fail_test "${f} has no multi-character IFS" "$BAD"
        fi
    done

    if command -v shellcheck &>/dev/null; then
        SC_FAIL=""
        for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh; do
            shellcheck --severity=error "${ROOT_DIR}/${f}" >/dev/null 2>&1 || SC_FAIL+="${f} "
        done
        if [[ -z "$SC_FAIL" ]]; then
            ok_test "shellcheck reports no errors"
        else
            fail_test "shellcheck reports no errors" "failing: ${SC_FAIL}"
        fi
    else
        skip_test "shellcheck" "not installed"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}────────────────────────────────────────${RESET}"
TOTAL=$(( PASS_N + FAIL_N ))
if (( FAIL_N == 0 )); then
    echo -e "${GREEN}${BOLD}  ✔  ${PASS_N}/${TOTAL} passed${RESET}${SKIP_N:+  (${SKIP_N} skipped)}"
    echo
    exit 0
else
    echo -e "${RED}${BOLD}  ✘  ${FAIL_N} of ${TOTAL} failed${RESET}${SKIP_N:+  (${SKIP_N} skipped)}"
    echo
    for f in "${FAILURES[@]}"; do echo -e "    ${RED}•${RESET} $f"; done
    echo
    exit 1
fi
