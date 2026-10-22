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
            "exec.ps1 is reported for Invoke-Expression (a WARN: see the PowerShell group below)"
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

        # ── PDF active content ───────────────────────────────────────────────
        # A PDF is a container: it can auto-run JavaScript, launch a program and
        # carry an embedded executable. Before scan_pdf() existed, .pdf had no
        # handler and fell through to scan_unknown, where application/pdf is not
        # one of the dangerous MIME types — so a weaponised PDF was recorded
        # PASS with no findings.
        assert_contains "$(line_for pdf_openaction_js.pdf)" "CWE-94:PDF_javascript" \
            "PDF with an embedded /JavaScript action is flagged"
        assert_contains "$(line_for pdf_openaction_js.pdf)" "PDF_auto_execute" \
            "PDF that auto-runs an action on open is flagged"
        assert_contains "$(line_for pdf_openaction_js.pdf)" "CWE-78:PDF_launch_action" \
            "PDF /Launch action is flagged"

        # The payload in this fixture exists ONLY inside a FlateDecode /ObjStm:
        # the strings "JavaScript" and "OpenAction" appear nowhere in the file's
        # plaintext. A rule that greps raw bytes passes it; only inflating the
        # streams finds it.
        assert_contains "$(line_for pdf_compressed_js.pdf)" "CWE-94:PDF_javascript" \
            "PDF hiding JavaScript in a compressed object stream is flagged"

        # /OpenAc#74ion and /J#61vaScript read identically to a viewer. The
        # strings "/OpenAction" and "/JavaScript" are absent from this file.
        assert_contains "$(line_for pdf_obfuscated_js.pdf)" "PDF_name_hex_obfuscation" \
            "PDF hex-escaping /JavaScript to evade a text rule is flagged"
        assert_contains "$(line_for pdf_obfuscated_js.pdf)" "CWE-94:PDF_javascript" \
            "hex-escaped names are decoded before the rules run"

        # Flate was once the only filter scan_pdf() decoded, so an action behind
        # ASCII85 or LZW was as invisible to it as a Flate one was to plain grep.
        assert_contains "$(line_for pdf_ascii85_js.pdf)" "CWE-94:PDF_javascript" \
            "PDF hiding JavaScript behind ASCII85Decode is flagged"
        assert_contains "$(line_for pdf_lzw_js.pdf)" "CWE-94:PDF_javascript" \
            "PDF hiding JavaScript behind LZWDecode is flagged"

        # A stray "(" in binary stream data must not blank the dictionary that
        # follows it and hide the /OpenAction there.
        assert_contains "$(line_for pdf_paren_swallow_js.pdf)" "PDF_auto_execute" \
            "an unbalanced ( in stream data does not swallow a later /OpenAction"

        # An undecodable filter must be reported, not silently skipped: an
        # uninspected stream is not a clean one. Image filters are excluded, so
        # the ordinary document below must not pick this up.
        assert_not_contains "$(line_for benign_doc.pdf)" "stream_filter_not_decoded" \
            "does NOT report an undecoded filter for an ordinary document"

        # ── Makefiles ────────────────────────────────────────────────────────
        # A Makefile recipe is shell, and $(shell ...) runs when make merely
        # READS the file — before any target is invoked — so a malicious one
        # does not need to be built to do damage.
        assert_contains "$(line_for evil.mk)" "CWE-78:make_curl_pipe_shell" \
            "Makefile piping a download into a shell is flagged"
        assert_contains "$(line_for evil.mk)" "CWE-798:make_hardcoded_credential" \
            "unquoted credential in a Makefile variable is flagged"
        assert_contains "$(line_for evil.mk)" "CWE-494:make_download_without_cert" \
            "Makefile disabling TLS verification is flagged"
        assert_contains "$(line_for evil.mk)" "make_reverse_shell" \
            "Makefile reverse shell is flagged"
        assert_contains "$(line_for evil.mk)" "CWE-912:make_persistence" \
            "Makefile installing cron/authorized_keys persistence is flagged"

        # A file called Makefile has no extension, so it reaches scan_makefile
        # only via the basename branch of classify_file.
        assert_contains "$(line_for Makefile)" "CWE-798:make_hardcoded_credential" \
            "extensionless Makefile is routed by basename, not extension"

        # ── HTML ─────────────────────────────────────────────────────────────
        # Inline <script> is ordinary, so these rules target the constructs
        # that are not: dynamic execution, a percent-encoded payload, a remote
        # script over plaintext, a hidden iframe, credentials in the markup and
        # a cookie read wired straight to a network sink.
        assert_contains "$(line_for evil.html)" "CWE-95:html_eval" \
            "HTML calling eval() is flagged"
        assert_contains "$(line_for evil.html)" "CWE-319:html_remote_script" \
            "HTML loading a remote script over http:// is flagged"
        assert_contains "$(line_for evil.html)" "CWE-798:html_hardcoded_credential_in_attribute" \
            "credential in an input value attribute is flagged"
        assert_contains "$(line_for evil.html)" "CWE-200:html_cookie_exfiltration" \
            "document.cookie wired to a network sink is flagged"
        assert_contains "$(line_for evil.html)" "html_hidden_iframe" \
            "zero-size or display:none iframe is flagged"

        # .htm must route exactly as .html does.
        assert_contains "$(line_for tracker.htm)" "html_hidden_iframe" \
            ".htm is routed to the HTML scanner as well as .html"

        # ── PowerShell ───────────────────────────────────────────────────────
        # The scanner had three rules and was wrong in both directions. On the 69
        # real .ps1 files on this host (32 distinct) it FAILed 8, every one a false
        # positive: npm.ps1 and npx.ps1 (Invoke-Expression on a command they
        # assemble), pnpm's completion script, and Playwright's browser installers
        # (download an MSI, run msiexec). Meanwhile `iex $c`, `IEX (iwr …)` and
        # `-enc …` all passed, because the rules were case-sensitive and `iex` was
        # only matched before a parenthesis.
        assert_contains "$(line_for ps_download_exec.ps1)" "CWE-78:PowerShell_download_and_execute" \
            "DownloadString piped to IEX is flagged"
        assert_contains "$(line_for ps_irm_iex.ps1)" "CWE-78:PowerShell_download_and_execute" \
            "lower-case \`irm … | iex\` with no parenthesis is flagged"
        assert_contains "$(line_for ps_mixed_case.ps1)" "CWE-78:PowerShell_download_and_execute" \
            "mixed-case InVoKe-ExPrEsSiOn is flagged (PowerShell is case-insensitive)"
        assert_contains "$(line_for ps_encoded_short.ps1)" "CWE-78:PowerShell_EncodedCommand_obfuscation" \
            "the short form -enc <base64> is flagged"
        assert_contains "$(line_for ps_amsi.ps1)" "CWE-693:PowerShell_AMSI_bypass" \
            "an AMSI bypass is flagged"
        assert_contains "$(line_for ps_defender.ps1)" "CWE-693:PowerShell_disables_Defender" \
            "Set-MpPreference -DisableRealtimeMonitoring \$true is flagged"
        assert_contains "$(line_for ps_persistence.ps1)" "CWE-912:PowerShell_persistence" \
            "writing a CurrentVersion\\Run key is flagged"
        assert_contains "$(line_for ps_reverse_shell.ps1)" "CWE-78:PowerShell_reverse_shell" \
            "a TCPClient stream fed to iex is flagged"
        assert_contains "$(line_for ps_shellcode.ps1)" "CWE-94:PowerShell_in_memory_shellcode_loader" \
            "VirtualAlloc with CreateThread is flagged"
        assert_contains "$(line_for ps_secret.ps1)" "CWE-798:hardcoded_credential" \
            "a literal \$Password and ConvertTo-SecureString -AsPlainText are flagged"
        assert_contains "$(line_for ps_obfuscated.ps1)" "CWE-95:PowerShell_obfuscated_Invoke_Expression" \
            "i\`e\`x with backticks inside the name is flagged"
        assert_contains "$(line_for ps_plaintext_dl_run.ps1)" "CWE-319:PowerShell_plaintext_download_then_run" \
            "a plaintext http:// download that is then run is flagged"
        assert_contains "$(line_for ps_offensive_tool.ps1)" "CWE-506:PowerShell_known_offensive_tool" \
            "Invoke-Mimikatz is flagged"

        # Every PowerShell extension must reach the scanner. .ps1 is above; each
        # of these is a different file type with the same interpreter behind it.
        assert_contains "$(line_for ps_decode_exec.psm1)" "CWE-95:PowerShell_decodes_and_executes" \
            ".psm1 (module): decode on one line, execute on another, is flagged"
        assert_contains "$(line_for ps_manifest.psd1)" "powershell:manifest_runs_scripts_at_import" \
            ".psd1 (manifest) is scanned: ScriptsToProcess is reported"
        assert_contains "$(line_for ps_session.pssc)" "powershell:manifest_runs_scripts_at_import" \
            ".pssc (session configuration) is scanned"
        assert_contains "$(line_for ps_role.psrc)" "powershell:role_capability_exposes_everything" \
            ".psrc (role capability) is scanned: a wildcard VisibleCmdlets is reported"
        assert_contains "$(line_for ps_types.ps1xml)" "CWE-78:PowerShell_download_and_execute" \
            ".ps1xml (type/format data): a script block that downloads and executes is flagged"
        assert_contains "$(line_for ps_console.psc1)" "CWE-611:xxe_external_entity_references_a_resource" \
            ".psc1 (console file) is scanned as XML: an external entity is flagged"
        assert_contains "$(line_for ps_cmdlet.cdxml)" "CWE-78:PowerShell_download_and_execute" \
            ".cdxml (CIM cmdlet definition) is scanned for PowerShell payloads"
        assert_contains "$(line_for ps_shebang_pwsh)" "CWE-78:PowerShell_download_and_execute" \
            "an extensionless script with a pwsh shebang is scanned"
        assert_contains "$(line_for ps_shebang_powershell)" "CWE-78:PowerShell_download_and_execute" \
            "an extensionless script with a powershell shebang is scanned"

        # Extension CASE. The dispatch was case-sensitive, so UPPER.PS1 and
        # UPPER.PY fell through to scan_unknown and PASSED while lower.ps1 and
        # lower.py FAILed. Windows users write .PS1; the fix is general.
        assert_contains "$(line_for ps_upper_ext.PS1)" "CWE-78:PowerShell_download_and_execute" \
            "an upper-case .PS1 extension reaches the PowerShell scanner"
        assert_contains "$(line_for case_upper.PY)" "CWE-78:OS_command_injection_risk" \
            "an upper-case .PY extension reaches the Python scanner"

        # Near-misses, modelled on the real scripts. Invoke-Expression on its own
        # appears in npm.ps1, npx.ps1 and pnpm's completion and was benign every
        # time, so it is a WARN; so is Start-Process, and an https download that
        # is then run (Playwright). None may FAIL.
        SAFE_NPM=$(echo "$F" | grep 'ps_safe_npm_shim.ps1' || true)
        assert_not_contains "$SAFE_NPM" "[FAIL]" \
            "does NOT fail npm's own shim: Invoke-Expression on a command it assembles"
        assert_contains "$SAFE_NPM" "PowerShell_command_execution_Invoke_Expression" \
            "a lone Invoke-Expression is reported, but does not block"
        SAFE_INST=$(echo "$F" | grep 'ps_safe_installer.ps1' || true)
        assert_not_contains "$SAFE_INST" "[FAIL]" \
            "does NOT fail Playwright's installer: https download, then msiexec"
        assert_contains "$SAFE_INST" "powershell:downloads_then_runs_a_program" \
            "an https download that is then run is reported, but does not block"
        SAFE_PSMISC=$(echo "$F" | grep 'ps_safe_misc.ps1' || true)
        assert_not_contains "$SAFE_PSMISC" "[FAIL]" \
            "does NOT fail a TcpClient port check, Read-Host, \$env: tokens or \$tokenEndpoint"

        # ── The bracket-expression bug ───────────────────────────────────────
        # GNU grep reads \s as a shorthand class only OUTSIDE a bracket expression.
        # Inside one, [^"\s]{4,} is a negated set of the literal characters \ and s,
        # so the universal credential rule required four characters none of which was
        # an "s": it missed password = "sup3rs3cret" and every other secret with an
        # "s" near the front. Four sites had it.
        assert_contains "$(line_for cred_s_values.py)" "CWE-798:hardcoded_credential" \
            "a secret with an s in its first four characters is flagged"
        assert_contains "$(line_for cred_s.json)" "CWE-798:hardcoded_credential_in_JSON" \
            "the same in a JSON file"
        assert_contains "$(line_for cred_s.md)" "CWE-798:hardcoded_credential_in_doc" \
            "the same in a document"
        assert_contains "$(line_for cred_s.yaml)" "CWE-798:inline_credential_in_yaml" \
            "the same in YAML"
        # The YAML site's bug ran the other way: its class did not exclude
        # whitespace, so `password:` followed by trailing spaces counted as a value.
        # Fixing the bracket REMOVES this false positive (27 of 3328 real YAML files).
        assert_not_contains "$(line_for cred_empty.yaml)" "CWE-798" \
            "does NOT flag an empty YAML value followed by trailing spaces"
        assert_not_contains "$(line_for cred_s_safe.py)" "CWE-798" \
            "does NOT flag env lookups, empty strings, \${...} or {{ templates }}"

        # ── Windows batch (.bat / .cmd) ──────────────────────────────────────
        # 116 real batch files on this host were all recorded PASS: .bat and .cmd
        # had no handler. Three properties of the language shape the scanner, and
        # all three occur in the real files: 104 of 116 use CRLF line endings, 56
        # carry REM/:: comment lines, and 6 use caret line-continuation, which lets
        # an attacker split `certutil` and `-urlcache` across lines. All the
        # fixtures below are CRLF-encoded.
        assert_contains "$(line_for bat_certutil_dl.bat)" "CWE-78:bat_download_cradle_certutil_or_bitsadmin" \
            "certutil -urlcache is flagged"
        assert_contains "$(line_for bat_ps_cradle.cmd)" "CWE-78:bat_powershell_download_cradle" \
            ".cmd: a PowerShell DownloadString cradle is flagged"
        assert_contains "$(line_for bat_ps_encoded.bat)" "CWE-78:bat_powershell_encoded_command" \
            "powershell -enc <base64> is flagged"
        assert_contains "$(line_for bat_certutil_decode.bat)" "CWE-78:bat_certutil_decodes_to_an_executable" \
            "certutil -decode into an .exe is flagged"
        assert_contains "$(line_for bat_download_run.bat)" "CWE-78:bat_download_then_execute" \
            "curl … && start <downloaded file> is flagged"
        assert_contains "$(line_for bat_secret.bat)" "CWE-798:bat_hardcoded_credential" \
            "set DB_PASSWORD=<literal> is flagged"
        assert_contains "$(line_for bat_persistence.bat)" "CWE-912:bat_persistence_run_key" \
            "reg add … CurrentVersion\\Run is flagged"
        assert_contains "$(line_for bat_startup_folder.bat)" "CWE-912:bat_persistence_startup_folder" \
            "copying a file into the Startup folder is flagged"
        assert_contains "$(line_for bat_defender.bat)" "CWE-693:bat_security_control_disabled" \
            "disabling Defender and the firewall is flagged"
        assert_contains "$(line_for bat_wipe.bat)" "bat:destructive_delete_of_a_drive_root_or_profile" \
            "rd /s /q C:\\ is flagged"
        assert_contains "$(line_for bat_insecure_tls.bat)" "CWE-494:bat_download_without_certificate_verification" \
            "curl -k is flagged"
        assert_contains "$(line_for bat_admin.bat)" "CWE-250:bat_local_admin_account_added" \
            "net localgroup administrators … /add is flagged"
        assert_contains "$(line_for bat_caret_name.bat)" "CWE-78:bat_caret_obfuscated_command_name" \
            "c^e^r^t^u^t^i^l with carets inside the name is flagged"

        # The same download as bat_certutil_dl.bat, split across caret-continued
        # lines. A line-based rule never sees `certutil` and `-urlcache` together.
        assert_contains "$(line_for bat_continued.bat)" "CWE-78:bat_download_cradle_certutil_or_bitsadmin" \
            "a certutil download split across ^-continued lines is still flagged"
        # Upper-case extension AND upper-case content: batch is case-insensitive.
        assert_contains "$(line_for bat_UPPER.BAT)" "CWE-78:bat_download_cradle_certutil_or_bitsadmin" \
            "an upper-case .BAT holding CERTUTIL -URLCACHE is flagged"

        # Near-misses taken from the real scripts: the MIT licence in REM comments
        # (the bare word `copy` is 27 of 116 on that alone), commented-out
        # payloads, `for /f` substitution (19 of 116), `SET "PATH=%~dp0;%PATH%"`,
        # `rd /s /q build`, `set /p PASSWORD=` (a prompt, not a literal), a
        # credential-named variable holding a %reference%, caret continuation.
        SAFE_BAT=$(echo "$F" | grep 'bat_safe_real.cmd' || true)
        assert_not_contains "$SAFE_BAT" "[FAIL]" \
            "does NOT fail real-world batch idioms, licence comments or commented-out payloads"
        assert_contains "$SAFE_BAT" "bat:powershell_execution_policy_bypass" \
            "-ExecutionPolicy Bypass is reported, but does not block"
        # Maven's own mvn.cmd trims a trailing backslash with two substring
        # extractions on one line. Assembling a command looks different: the
        # extractions are ADJACENT, building a word one character at a time.
        assert_not_contains "$SAFE_BAT" "assembled_from_variable_substrings" \
            "does NOT warn on Maven's trailing-backslash trim (two extractions apart)"
        assert_contains "$(line_for bat_substring_cmd.bat)" "bat:command_assembled_from_variable_substrings" \
            "a command built from adjacent %v:~n,1% extractions is reported"
        SAFE_FETCH=$(echo "$F" | grep 'bat_safe_fetch.bat' || true)
        assert_not_contains "$SAFE_FETCH" "[FAIL]" \
            "does NOT fail an https download that is not run, or certutil -decode to a .cer"

        # ── Java archives (.jar, .war, .ear, .aar) ───────────────────────────
        # A .jar is a ZIP of compiled code, and it had no handler: it fell through
        # to scan_unknown and was recorded PASS. Three things make it worth a
        # scanner of its own. It is executable code a reviewer cannot read. The
        # container format can carry paths that escape the extraction directory
        # (zip-slip) and bytes that are not what the entry name says. And
        # gradle-wrapper.jar, committed to nearly every Gradle repository, is run
        # by ./gradlew before any code the repository declares. Calibration is 365
        # real jars on this host: none of the FAIL rules below fires on any of them.
        JSAFE=$(line_for jar_safe.jar)
        assert_not_contains "$JSAFE" "[FAIL]" \
            "does NOT fail an ordinary jar (Main-Class, relative Class-Path, curl in prose, MZ-prefixed text, a class stored as .bin)"
        assert_contains "$JSAFE" "jar:vendored_compiled_code_not_reviewable" \
            "an ordinary jar is reported, never silently passed: bytecode is not reviewed"
        assert_not_contains "$JSAFE" "hidden_under_a_non_native_name" \
            "a class stored as .bin (0xCAFEBABE is also the Mach-O fat magic) is not a hidden executable"
        assert_not_contains "$JSAFE" "jar:wrapper" \
            "an ordinary jar does not get the build-wrapper message"

        assert_contains "$(line_for jar_zipslip.jar)" "CWE-22:jar_entry_path_traversal_zip_slip" \
            "a jar entry named ../../… or /etc/… is flagged as zip-slip"
        assert_contains "$(line_for jar_fake_class.jar)" "CWE-506:jar_class_entry_is_not_bytecode" \
            "a .class entry that does not begin 0xCAFEBABE is flagged"
        JHID=$(line_for jar_hidden_exe.jar)
        assert_contains "$JHID" "CWE-506:jar_native_executable_hidden_under_a_non_native_name" \
            "a Windows executable stored as logo.png is flagged"
        assert_contains "$JHID" "data/blob.dat" \
            "an ELF binary stored as blob.dat is flagged"
        assert_contains "$JHID" "res/icon.gif" \
            "a Mach-O binary stored as icon.gif is flagged"
        assert_contains "$(line_for jar_remote_classpath.jar)" "CWE-829:jar_manifest_class_path_names_a_remote_url" \
            "a manifest Class-Path naming an http:// jar is flagged"
        assert_contains "$(line_for jar_remote_classpath.jar)" "jar:manifest_class_path_is_absolute" \
            "an absolute Class-Path entry is reported"
        assert_contains "$(line_for jar_nested_evil.jar)" "lib/inner.jar!/../escape.txt" \
            "a zip-slip entry inside a jar nested in the jar is found"
        assert_contains "$(line_for jar_nested_evil.jar)" "jar:contains_nested_archive" \
            "a nested archive is reported"

        assert_contains "$(line_for jar_symlink.jar)" "CWE-22:jar_symlink_entry_points_outside_the_archive" \
            "a symlink entry pointing at ../../etc is flagged"
        assert_contains "$(line_for jar_symlink.jar)" "jar:contains_symlink_entry" \
            "an ordinary relative symlink entry is reported"
        JTU=$(line_for jar_text_unlisted.jar)
        assert_contains "$JTU" "jar_embeds_download_piped_to_shell(1: res/payload.dat)" \
            "text in an entry with no recognised extension is read"
        assert_not_contains "$JTU" "res/binary.dat" \
            "…while a binary entry holding the same string is not (it would be noise)"
        assert_contains "$(line_for jar_private_key.jar)" "CWE-321:hardcoded_private_key" \
            "a PEM private key stored as a resource is flagged"
        assert_contains "$(line_for jar_private_key.jar)" "Keys.class" \
            "a PEM private key held as one string constant in a class file is flagged"
        assert_not_contains "$JSAFE" "hardcoded_private_key" \
            "a PEM header constant next to a long class path (sshd-common) is not a private key"

        # The limit is stated, not hidden: depth 3 is not opened, and the jar says so.
        JDEEP=$(line_for jar_nested_deep.jar)
        assert_contains "$JDEEP" "jar:inspection_incomplete" \
            "archives nested beyond the depth limit report that they were not fully inspected"
        assert_not_contains "$JDEEP" "[FAIL]" \
            "…and the fixture documents the gap honestly: the payload at depth 3 is not seen"

        JHT=$(line_for jar_hostile_text.jar)
        assert_contains "$JHT" "CWE-78:jar_embeds_download_piped_to_shell" \
            "curl … | sh inside a jar resource is flagged"
        assert_contains "$JHT" "CWE-78:jar_embeds_reverse_shell" \
            "/dev/tcp reverse shell inside a jar resource is flagged"
        assert_contains "$JHT" "CWE-78:jar_embeds_encoded_powershell" \
            "powershell -enc <base64> inside a jar resource is flagged"
        assert_contains "$JHT" "CWE-494:jar_embeds_certutil_or_bitsadmin_download" \
            "certutil -urlcache inside a jar resource is flagged"
        # These strings sit inside the class file's constant pool, between binary
        # length fields: they are found by parsing the pool, not by grepping bytes.
        JHC=$(line_for jar_hostile_class.jar)
        assert_contains "$JHC" "CWE-78:jar_embeds_download_piped_to_shell" \
            "curl … | sh in a class file's constant pool is flagged"
        assert_contains "$JHC" "[WARN] jar:offensive_tool_name_in_content" \
            "an offensive-tool name in a class file is reported, as a warning only: security libraries name these tools"

        assert_contains "$(line_for jar_not_zip.jar)" "jar:file_is_not_an_archive_despite_its_extension" \
            "an ELF binary named .jar is flagged"
        assert_contains "$(line_for jar_prepended_pe.jar)" "CWE-506:jar_native_executable_prepended_to_archive" \
            "a Windows executable glued in front of a valid archive is flagged"
        assert_contains "$(line_for jar_prepended_script.jar)" "jar:launch_script_prepended_to_archive" \
            "a shell launch script before the archive (Spring Boot style) is reported"
        assert_not_contains "$(line_for jar_prepended_script.jar)" "[FAIL]" \
            "…but is not a failure"
        assert_contains "$(line_for jar_truncated.jar)" "jar:unparseable_archive_not_inspected" \
            "a truncated jar is reported as not inspected"
        assert_not_contains "$(line_for jar_truncated.jar)" "[FAIL]" \
            "a truncated jar does not block"
        assert_contains "$(line_for jar_empty.jar)" "jar:empty_file" \
            "a zero-byte jar is reported"
        assert_contains "$(line_for jar_prepended_data.jar)" "jar:data_before_archive_start" \
            "arbitrary bytes before the archive are reported"
        assert_contains "$(line_for jar_nested_broken.jar)" "jar:nested_archive_could_not_be_opened" \
            "a nested 'archive' that does not parse is reported"
        assert_contains "$(line_for jar_unreadable.jar)" "jar:entries_could_not_be_read" \
            "an entry stored with an unsupported compression method is reported as unreadable"

        assert_contains "$(line_for jar_agent.jar)" "jar:java_agent_in_manifest" \
            "Premain-Class in a manifest (a Java agent) is reported"
        assert_not_contains "$(line_for jar_agent.jar)" "[FAIL]" \
            "…and is not a failure: 2 of 365 real jars are legitimate agents"
        assert_contains "$(line_for jar_native.jar)" "jar:bundles_native_library" \
            "native libraries named .so/.dll/.dylib are reported"
        assert_not_contains "$(line_for jar_native.jar)" "[FAIL]" \
            "…and are not failures: 17 of 365 real jars bundle them"
        assert_contains "$(line_for jar_scripts.jar)" "jar:bundles_script_file" \
            "a .sh or .bat entry inside a jar is reported"
        assert_contains "$(line_for jar_duplicates.jar)" "jar:duplicate_entry_names" \
            "two entries with the same name are reported"
        assert_contains "$(line_for jar_encrypted.jar)" "jar:encrypted_entries_not_inspected" \
            "encrypted entries are reported as not inspected"
        assert_not_contains "$(line_for jar_big.jar)" "jar:inspection_incomplete" \
            "a 3 MB text entry is within the default limits"

        assert_contains "$(line_for jar_routing.war)" "CWE-22:jar_entry_path_traversal_zip_slip" \
            ".war is routed to the jar scanner"
        assert_contains "$(line_for jar_routing.ear)" "CWE-22:jar_entry_path_traversal_zip_slip" \
            ".ear is routed to the jar scanner"
        assert_contains "$(line_for jar_routing.aar)" "CWE-22:jar_entry_path_traversal_zip_slip" \
            ".aar is routed to the jar scanner"
        assert_contains "$(line_for case_UPPER.JAR)" "CWE-22:jar_entry_path_traversal_zip_slip" \
            "an upper-case .JAR extension is routed to the jar scanner"

        # gradle-wrapper.jar runs on ./gradlew before any code the repository
        # declares. Its shape is checked; its contents cannot be: the official
        # checksums are not embedded here.
        assert_contains "$(line_for wrapper_good/gradle-wrapper.jar)" "jar:wrapper_checksum_must_be_verified" \
            "a structurally normal gradle-wrapper.jar still asks for a checksum check"
        assert_not_contains "$(line_for wrapper_good/gradle-wrapper.jar)" "[FAIL]" \
            "a structurally normal gradle-wrapper.jar does not fail"
        assert_contains "$(line_for wrapper_evil/gradle-wrapper.jar)" "CWE-494:wrapper_jar_has_unexpected_content" \
            "a gradle-wrapper.jar carrying classes outside org/gradle is flagged"
        assert_contains "$(line_for wrapper_evil/gradle-wrapper.jar)" "install.sh" \
            "the finding names the stray entry"
        assert_contains "$(line_for wrapper_hollow/gradle-wrapper.jar)" "missing org/gradle/wrapper/GradleWrapperMain.class" \
            "a gradle-wrapper.jar without GradleWrapperMain is flagged"
        assert_contains "$(line_for wrapper_maven/maven-wrapper.jar)" "jar:wrapper_checksum_must_be_verified" \
            "maven-wrapper.jar is held to the same shape check"

        # ── setup.py ─────────────────────────────────────────────────────────
        # setup.py runs on a source `pip install`, so it is install-time code with
        # its own risk model: os.system and subprocess are ordinary build tools
        # there, and fetching-then-executing is the thing that is not. The generic
        # Python rules failed 4 of 36 real setup.py files on ordinary idioms.
        assert_contains "$(line_for setup_evil/setup.py)" "CWE-78:setup_py_fetches_and_executes" \
            "setup.py piping a download into a shell is flagged"
        assert_contains "$(line_for setup_evil/setup.py)" "CWE-95:setup_py_executes_a_network_response" \
            "setup.py exec()-ing a network response is flagged"
        assert_contains "$(line_for setup_evil/setup.py)" "CWE-95:setup_py_decodes_and_executes" \
            "setup.py decoding a blob and exec()-ing it is flagged"
        assert_contains "$(line_for setup_evil/setup.py)" "CWE-78:setup_py_reverse_shell" \
            "setup.py opening a socket to a shell is flagged"
        assert_contains "$(line_for setup_evil/setup.py)" "CWE-912:setup_py_persistence" \
            "setup.py writing authorized_keys is flagged"

        # ── Gradle ───────────────────────────────────────────────────────────
        # A .gradle script is not a declarative file with a few dangerous
        # constructs in it: it is a program, compiled and evaluated in full at
        # CONFIGURATION time, on `gradle tasks`, on `--dry-run`, and on IDE
        # import. Before this, *.gradle fell through to scan_unknown (PASS) and
        # *.gradle.kts went to scan_kotlin, which has Kotlin SOURCE rules and
        # none of these.
        assert_contains "$(line_for gradle_evil/build.gradle)" "CWE-829:gradle_apply_from_remote_script" \
            "Gradle apply from an http:// URL is flagged"
        assert_contains "$(line_for gradle_evil/build.gradle)" "CWE-494:gradle_insecure_repository_protocol_enabled" \
            "Gradle allowInsecureProtocol = true is flagged"
        assert_contains "$(line_for gradle_evil/build.gradle)" "CWE-78:gradle_process_spawn_from_literal" \
            "Gradle \"cmd\".execute() is flagged"
        # build.gradle.kts must reach scan_gradle, not scan_kotlin: the Kotlin
        # spelling is isAllowInsecureProtocol and scan_kotlin cannot see it.
        assert_contains "$(line_for gradle_kts/build.gradle.kts)" "CWE-494:gradle_insecure_repository_protocol_enabled" \
            "build.gradle.kts is scanned as Gradle (isAllowInsecureProtocol)"
        assert_contains "$(line_for gradle_kts/build.gradle.kts)" "CWE-78:gradle_process_spawn_from_literal" \
            "build.gradle.kts new ProcessBuilder(...) is flagged"
        assert_contains "$(line_for gradle_evil/gradle.properties)" "CWE-829:gradle_daemon_java_agent" \
            "-javaagent in org.gradle.jvmargs is flagged"
        assert_contains "$(line_for gradle_evil/gradle.properties)" "CWE-494:gradle_dependency_verification_disabled" \
            "org.gradle.dependency.verification=off is flagged"
        assert_contains "$(line_for gradle_evil/gradle.properties)" "CWE-798:gradle_credential_in_properties" \
            "signing.password=<literal> in gradle.properties is flagged"
        assert_contains "$(line_for gradle_evil/gradle.properties)" "CWE-295:gradle_truststore_override" \
            "a trustStore override in gradle.properties is reported"
        assert_contains "$(line_for gradle_wrapper_evil/gradle-wrapper.properties)" "CWE-494:gradle_wrapper_plaintext_distribution" \
            "a plaintext distributionUrl in the wrapper is flagged"

        # ── Package manifests ────────────────────────────────────────────────
        # package.json and requirements.txt got one inline credential grep and
        # nothing else, so an install hook that pipes a download into a shell
        # was approved. npm runs preinstall/install/postinstall on every
        # `npm install`, and prepare on a bare one: execution before any build.
        assert_contains "$(line_for pkg_evil/package.json)" "CWE-78:npm_lifecycle_hook_fetches_and_executes" \
            "an npm postinstall piping curl into a shell is flagged"
        assert_contains "$(line_for pkg_evil/package.json)" "CWE-78:npm_lifecycle_hook_decodes_and_executes" \
            "an npm hook decoding base64 into a shell is flagged"
        # The key is written post\u0069nstall. npm reads that as postinstall; the
        # literal text "postinstall" appears nowhere in the file, so a pattern
        # rule never sees it. Only parsing the JSON does.
        assert_contains "$(line_for pkg_escaped/package.json)" "CWE-78:npm_lifecycle_hook_fetches_and_executes" \
            "an npm hook whose key is written with a \\u escape is still flagged"
        assert_contains "$(line_for pkg_evil/package.json)" "CWE-319:npm_dependency_over_plaintext" \
            "an npm dependency fetched over http:// or git:// is flagged"
        assert_contains "$(line_for composer_evil/composer.json)" "CWE-78:composer_hook_fetches_and_executes" \
            "a Composer install hook piping curl into a shell is flagged"
        assert_contains "$(line_for composer_evil/composer.json)" "CWE-319:composer_insecure_transport" \
            "Composer secure-http=false or an http:// repository is flagged"
        assert_contains "$(line_for req_evil/requirements.txt)" "CWE-319:pip_index_or_requirement_over_plaintext" \
            "a pip index or requirement over http:// or git:// is flagged"
        assert_contains "$(line_for req_evil/requirements.txt)" "CWE-798:pip_credentials_embedded_in_url" \
            "credentials embedded in a pip index URL are flagged"

        # ── XML ──────────────────────────────────────────────────────────────
        # XXE needs an entity that actually references an external resource.
        # A bare <!DOCTYPE was failing 736 of 3362 real XML files (22%), and
        # pom.xml and Ant's build.xml both route here — so Maven and Ant repos
        # were quarantined over a doctype.
        assert_contains "$(line_for xxe.xml)" "CWE-611:xxe_external_entity_references_a_resource" \
            "an entity referencing file:///etc/passwd is flagged"
        assert_contains "$(line_for credential.xml)" "CWE-798:hardcoded_credential_in_XML" \
            "a plaintext credential in XML element text is flagged"
        # A line-based rule is evaded by a line break; the declaration below
        # puts ENTITY, the name, SYSTEM and the target on four separate lines.
        assert_contains "$(line_for xxe_split.xml)" "CWE-611:xxe_external_entity_references_a_resource" \
            "an entity declaration split across lines is still flagged"
        assert_contains "$(line_for xml_bomb.xml)" "CWE-776:xml_entity_expansion_bomb" \
            "a nested-entity expansion bomb is flagged"

        # Build files that route through scan_xml: Maven and Ant have no
        # build-specific rules of their own, so pom.xml and build.xml were
        # checked for XXE and nothing else.
        assert_contains "$(line_for pom.xml)" "CWE-319:maven_repository_over_plaintext_http" \
            "a Maven repository over http:// is flagged"
        assert_contains "$(line_for pom.xml)" "CWE-78:maven_exec_runs_shell_or_downloader" \
            "exec-maven-plugin running sh is flagged"
        assert_contains "$(line_for build.xml)" "CWE-319:ant_get_over_plaintext_http" \
            "Ant <get> over http:// is flagged"
        assert_contains "$(line_for build.xml)" "CWE-78:ant_exec_runs_shell_or_downloader" \
            "Ant <exec> running sh is flagged"
        assert_contains "$(line_for build.xml)" "CWE-798:ant_credential_attribute" \
            "Ant <sshexec> with a literal password is flagged"

        # ── CMake ────────────────────────────────────────────────────────────
        # set(NAME "value") is a function call, not an assignment, so the
        # universal CWE-798 rule — which expects key = "value" — cannot see a
        # credential in a CMake file at all. And file(DOWNLOAD …) runs at
        # CONFIGURE time, so `cmake .` alone is enough to fetch and execute.
        assert_contains "$(line_for evil.cmake)" "CWE-798:cmake_hardcoded_credential" \
            "credential in a CMake set() call is flagged"
        assert_contains "$(line_for evil.cmake)" "CWE-319:cmake_download_over_plaintext_http" \
            "CMake fetching over plaintext http is flagged"
        assert_contains "$(line_for evil.cmake)" "CWE-295:cmake_tls_verification_disabled" \
            "CMake disabling TLS verification is flagged"
        assert_contains "$(line_for evil.cmake)" "cmake_hardening_disabled" \
            "CMake removing stack-protector or FORTIFY_SOURCE is flagged"

        # CMakeLists.txt ends in .txt, so without a basename branch it reaches
        # only the plain-text scanner.
        assert_contains "$(line_for CMakeLists.txt)" "CWE-798:cmake_hardcoded_credential" \
            "CMakeLists.txt is routed by basename, not by its .txt extension"

        # ── Universal layer: traversal and key material ──────────────────────
        # Both of these rules run on EVERY file, and neither had any test
        # coverage at all until now — while between them they quarantined 65%
        # of real HTML and 30% of real Makefiles.
        assert_contains "$(line_for traversal.txt)" "CWE-22:path_traversal" \
            "encoded, sensitive-target and input-composed traversal is flagged"
        assert_contains "$(line_for private_key.txt)" "CWE-321:hardcoded_private_key" \
            "a PEM private key block is flagged"
        assert_contains "$(line_for pgp_private.asc)" "CWE-321:hardcoded_private_key" \
            "a PGP private key with armor headers before the body is flagged"
        assert_contains "$(line_for service_account.json)" "CWE-321:hardcoded_private_key" \
            "a PEM key held on one line as a JSON string with \\n escapes is flagged"

        # ── False-positive guards: these must NOT be flagged ─────────────────
        # Regression guard for the P8 fix: the parameterised query form is the
        # correct, safe pattern and must never be reported as an injection.
        SAFE_LINE=$(echo "$F" | grep 'safe_sql.py' || true)
        assert_not_contains "$SAFE_LINE" "CWE-89" \
            "does NOT flag parameterised SQL (execute(\"… = ?\", (v,)))"

        SAFE_SH=$(echo "$F" | grep 'safe_shell.sh' || true)
        assert_not_contains "$SAFE_SH" "CWE-78" \
            "does NOT flag quoted shell variable expansion"

        # An ordinary document must stay clean. benign_doc.pdf embeds a subset
        # font, so it carries /AAAAAA+DejaVuSans tags; an unanchored /AA rule
        # reads those as an AdditionalActions key and would block this project's
        # own installation guide.
        # An ordinary Makefile must stay clean. `rm -rf $(BUILD)` in a clean
        # target and a bare `$(shell git rev-parse)` are the most common
        # constructs there are; a rule broad enough to flag them is unusable.
        SAFE_MK=$(echo "$F" | grep 'safe.mk' || true)
        assert_not_contains "$SAFE_MK" "CWE-78" \
            "does NOT flag rm -rf \$(BUILD) or a non-fetching \$(shell ...)"
        assert_not_contains "$SAFE_MK" "CWE-798" \
            "does NOT flag a Makefile credential sourced from the environment"

        # safe.html deliberately carries the near-miss of almost every rule
        # above: unescape(encodeURIComponent(x)) — the standard UTF-8 idiom
        # found in most bundled JS — an https script pinned with SRI, a
        # visible iframe with real dimensions, a relative form action, and a
        # cookie read in a different statement from its fetch().
        # A literal "../" is a relative path, not an attack. This is the guard
        # for the worst false positive the pipeline has had: -I../include and
        # href="../commands" quarantined the repository.
        # safe.cmake carries the near-miss of every CMake rule: a credential
        # read from the environment, a variable merely NAMED …_TOKEN, a
        # hash-pinned https download, execute_process running git, and a
        # set_package_properties URL — which is a homepage, not a fetch. Two
        # real CMake modules were failed by a rule that could not tell those
        # last two apart.
        # The near-misses: a husky `prepare`, a node -e guard (it is in a real
        # claude-code package.json), a local postinstall script, a download
        # script that is not a lifecycle hook, a dependency literally named
        # csrf-token, a file: link and a GitHub shorthand. Only the install-time
        # hook is worth a WARN; none may FAIL.
        SAFE_PKG=$(echo "$F" | grep 'pkg_safe/package.json' || true)
        assert_not_contains "$SAFE_PKG" "[FAIL]" \
            "does NOT fail an ordinary package.json (husky, node -e, file: link)"
        assert_contains "$SAFE_PKG" "npm:install_time_hook_present" \
            "an install-time hook is reported, but does not block"
        # The near-misses, each from a real setup.py: exec of a local version
        # file, a literal os.system (requests, ruamel.yaml), a git subprocess and
        # a build_ext subclass. Reported as a program being run; none may FAIL.
        SAFE_SETUP=$(echo "$F" | grep 'setup_safe/setup.py' || true)
        assert_not_contains "$SAFE_SETUP" "[FAIL]" \
            "does NOT fail exec(fp.read(), ns), a literal os.system or a git subprocess"
        assert_contains "$SAFE_SETUP" "setup:runs_a_program_at_install_time" \
            "setup.py running a program is reported, but does not block"

        # The measured near-misses. POM metadata over http:// matched 21 of 6249
        # real build scripts; query.execute() is a Gradle API call (2 of the 3
        # real .execute() hits); commandLineIncludePatterns is a property whose
        # name merely begins with commandLine; rootVariant.get() contains ant.get(.
        SAFE_GRADLE=$(echo "$F" | grep 'gradle_safe/build.gradle' || true)
        assert_not_contains "$SAFE_GRADLE" "[FAIL]" \
            "does NOT fail POM-metadata http:// urls, query.execute() or a local apply"
        assert_contains "$SAFE_GRADLE" "gradle_build_step_runs_process" \
            "an exec/commandLine build step is reported, but does not block"
        SAFE_KTS=$(echo "$F" | grep 'gradle_kts_safe/build.gradle.kts' || true)
        assert_not_contains "$SAFE_KTS" "[FAIL]" \
            "does NOT fail an ordinary build.gradle.kts"
        SAFE_GPROPS=$(echo "$F" | grep 'gradle_safe/gradle.properties' || true)
        assert_not_contains "$SAFE_GPROPS" "[FAIL]" \
            "does NOT fail JVM tuning flags or a blank signing.password"
        SAFE_WRAP=$(echo "$F" | grep 'gradle_wrapper_safe/gradle-wrapper.properties' || true)
        assert_not_contains "$SAFE_WRAP" "[FAIL]" \
            "does NOT fail an https distributionUrl"

        # Valid JSON with nothing to report yields no findings — which the first
        # version mistook for "could not parse", so 1172 of 1193 real manifests
        # went down the weaker pattern fallback. The repository and homepage
        # URLs here are what that fallback then failed 154 files on.
        PLAIN_PKG=$(echo "$F" | grep 'pkg_plain/package.json' || true)
        assert_not_contains "$PLAIN_PKG" "pkg:not_parsed" \
            "a valid package.json with nothing to report is not treated as unparseable"
        assert_not_contains "$PLAIN_PKG" "[FAIL]" \
            "does NOT fail repository and homepage URLs over git:// and http://"
        INVALID_PKG=$(echo "$F" | grep 'pkg_invalid/package.json' || true)
        assert_contains "$INVALID_PKG" "pkg:not_parsed_as_json_checked_by_pattern_only" \
            "invalid JSON is reported as inspected by pattern only"
        assert_contains "$INVALID_PKG" "CWE-78:npm_lifecycle_hook_fetches_and_executes" \
            "a hook in invalid JSON is still flagged by the pattern fallback"
        assert_not_contains "$INVALID_PKG" "CWE-319" \
            "the fallback does NOT read a repository url as a plaintext dependency"
        SAFE_COMPOSER=$(echo "$F" | grep 'composer_safe/composer.json' || true)
        assert_not_contains "$SAFE_COMPOSER" "[FAIL]" \
            "does NOT fail a Composer manifest with @php and callable hooks"
        SAFE_REQ=$(echo "$F" | grep 'req_safe/requirements.txt' || true)
        assert_not_contains "$SAFE_REQ" "[FAIL]" \
            "does NOT fail pinned requirements or a commit-pinned VCS line"
        assert_contains "$SAFE_REQ" "pip:trusted_host_disables_tls_verification" \
            "--trusted-host is reported, but does not block"

        # safe_xml.xml carries the whole false-positive set: an ordinary
        # PUBLIC doctype, two legitimate internal entities, the checkstyle
        # attribute lines the old credential rule matched by running [^>]*
        # across tag boundaries, and the four correct credential forms —
        # a ${...} reference, a Maven-encrypted value, a placeholder, and a
        # path to a key rather than the key.
        SAFE_XML=$(echo "$F" | grep 'safe_xml.xml' || true)
        assert_not_contains "$SAFE_XML" "CWE-611:xxe" \
            "does NOT flag an ordinary doctype or a text-shortcut entity"
        assert_not_contains "$SAFE_XML" "CWE-798" \
            "does NOT flag a checkstyle tokens attribute or a \${...} password"

        # safe_xml.xml also ends with a real-looking <password> inside <!-- -->,
        # the shape of Maven's own shipped settings.xml. That is covered by the
        # CWE-798 assertion above: without comment stripping it would fail.

        # safe.pom carries the default archetype homepage over http://, a
        # -SNAPSHOT version (176 of 221 real poms) and exec-maven-plugin running
        # java; build-safe.xml an https <get> and an env-sourced password.
        SAFE_POM=$(echo "$F" | grep 'safe.pom' || true)
        assert_not_contains "$SAFE_POM" "CWE-319" \
            "does NOT flag the archetype <url>http://maven.apache.org</url>"
        assert_not_contains "$SAFE_POM" "CWE-78" \
            "does NOT flag exec-maven-plugin running java"
        SAFE_ANT=$(echo "$F" | grep 'build-safe.xml' || true)
        assert_not_contains "$SAFE_ANT" "CWE-319" \
            "does NOT flag an Ant <get> over https"
        assert_not_contains "$SAFE_ANT" "CWE-798" \
            "does NOT flag an Ant password sourced from the environment"

        SAFE_CMAKE=$(echo "$F" | grep 'safe.cmake' || true)
        assert_not_contains "$SAFE_CMAKE" "CWE-798" \
            "does NOT flag a CMake credential read from the environment"
        assert_not_contains "$SAFE_CMAKE" "CWE-319" \
            "does NOT flag a homepage URL or a hash-pinned https download"
        assert_not_contains "$SAFE_CMAKE" "cmake_hardening_disabled" \
            "does NOT flag -fstack-protector-strong as disabled hardening"

        SAFE_PATHS=$(echo "$F" | grep 'safe_relative_paths.txt' || true)
        assert_not_contains "$SAFE_PATHS" "CWE-22" \
            "does NOT flag an ordinary relative path such as -I../include"

        # Writing about keys is not committing one, and a public certificate is
        # published by design.
        SAFE_KEY=$(echo "$F" | grep 'safe_key_prose.txt' || true)
        assert_not_contains "$SAFE_KEY" "CWE-321" \
            "does NOT flag the words PRIVATE KEY or CERTIFICATE in prose"
        # The same file also carries a PEM header used as a MIME magic signature,
        # which has no key body after it.
        assert_contains "$SAFE_KEY" "crypto:public_certificate_embedded" \
            "a public certificate is reported, but does not block"

        SAFE_HTML=$(echo "$F" | grep 'safe.html' || true)
        assert_not_contains "$SAFE_HTML" "CWE-95" \
            "does NOT flag unescape(encodeURIComponent(x)) as a payload"
        assert_not_contains "$SAFE_HTML" "CWE-319" \
            "does NOT flag an https script or a relative form action"
        assert_not_contains "$SAFE_HTML" "CWE-200" \
            "does NOT flag a cookie read separate from its fetch()"
        assert_not_contains "$SAFE_HTML" "html_hidden_iframe" \
            "does NOT flag a visible iframe with real dimensions"

        SAFE_PDF=$(echo "$F" | grep 'benign_doc.pdf' || true)
        assert_not_contains "$SAFE_PDF" "PDF_auto_execute" \
            "does NOT read a /AAAAAA+ font subset tag as an /AA auto-action"
        assert_not_contains "$SAFE_PDF" "CWE-94" \
            "does NOT flag an ordinary PDF as carrying active content"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER B — End-to-end verdicts
# ═════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════
# Java archive limits
# ═════════════════════════════════════════════════════════════════════════════
# scan_jar() never extracts to disk and bounds every read, so a decompression
# bomb costs a capped read. Each limit has to be REPORTED when it is reached: an
# archive that was not fully read must not look like one that was. The limits
# are environment knobs so the paths can be exercised on a 11 KB fixture.
group "Java archive limits"
if ! _skipping; then
    JARLIM="${SCRATCH}/jar_limits"
    mkdir -p "$JARLIM"
    cp "${FIXTURES}/rules/jar_big.jar" "$JARLIM/"
    cp "${FIXTURES}/rules/jar_late_slip.jar" "$JARLIM/"
    jar_with() {   # jar_with <file> VAR=value … ; prints the findings for that file
        local name="$1"; shift
        (
            export "$@"
            run_pipeline "$JARLIM" --quiet
            [[ -n "$RUN_JSON" ]] && json_findings "$RUN_JSON" | grep "/${name} " || true
        )
    }
    assert_contains "$(jar_with jar_big.jar JAR_MAX_ENTRIES=1)" "more than 1 entries" \
        "JAR_MAX_ENTRIES: entries beyond the limit are reported as not read"
    assert_contains "$(jar_with jar_late_slip.jar JAR_MAX_ENTRIES=1)" "CWE-22:jar_entry_path_traversal_zip_slip" \
        "JAR_MAX_ENTRIES does not limit the name check: a zip-slip entry past the limit is still found"
    assert_contains "$(jar_with jar_big.jar JAR_READ_BUDGET_MB=1)" "read budget of 1 MB exhausted" \
        "JAR_READ_BUDGET_MB: an exhausted read budget is reported"
    assert_contains "$(jar_with jar_big.jar JAR_VIEW_MB=1)" "capped at 1 MB" \
        "JAR_VIEW_MB: text beyond the credential-rule cap is reported"
    assert_contains "$(jar_with jar_big.jar JAR_MAX_UNCOMPRESSED_MB=1)" "jar:declared_uncompressed_size_over_limit" \
        "JAR_MAX_UNCOMPRESSED_MB: a declared size over the limit is reported"
    assert_contains "$(jar_with jar_big.jar JAR_TIME_BUDGET_S=0.001)" "time budget exceeded" \
        "JAR_TIME_BUDGET_S: an exceeded time budget is reported"

    # The helper must report a file it cannot open, not die: no facts at all would
    # read as "nothing found". Run as root a real permission error cannot be
    # produced, so the helper is extracted from the scanner and given a path that
    # is not there.
    JARPY="${SCRATCH}/jar_facts.py"
    awk '/^_jar_facts\(\) \{/{f=1;next} f&&/<<.PYEOF.*/{g=1;next} g&&/^PYEOF$/{exit} g{print}' \
        "${ROOT_DIR}/scan_pipeline.sh" > "$JARPY"
    JARGONE=$(python3 -I "$JARPY" "${SCRATCH}/no_such.jar" "${SCRATCH}/view.txt" 2>&1 || true)
    assert_contains "$JARGONE" "FACT unreadable_file" \
        "a file that cannot be opened is reported as unreadable"
    assert_contains "$JARGONE" "FACT done" \
        "…and the helper still finishes, so the scanner can tell it from a crash"
fi

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

# A monorepo with dozens of requirements files. Layer 3 listed them with
# `find … | head -5`; under `set -o pipefail`, head exiting early kills find
# with SIGPIPE once its output no longer fits one 4 KB write, the pipeline
# returns 141, and `set -e` aborted the whole scan — no verdict, no report.
# Eight short paths never trigger it, which is how it went unnoticed; it needs
# a few dozen realistic ones. ai_transit.sh defaults a missing verdict to FAIL,
# so the failure was safe but wrong: the repository was quarantined for having
# too many requirements files.
MONO="${SCRATCH}/monorepo"
for i in $(seq 1 40); do
    mkdir -p "${MONO}/service-number-${i}/backend/application/config"
    echo "requests==2.31.0" > "${MONO}/service-number-${i}/backend/application/config/requirements.txt"
done
run_pipeline "$MONO" --quiet
assert_eq "0" "$RUN_EXIT" "a monorepo with 40 requirements files completes and passes"
if [[ -n "$RUN_JSON" ]]; then
    ok_test "a monorepo with 40 requirements files writes a report"
else
    fail_test "a monorepo with 40 requirements files writes a report" \
              "scan died without a report (exit ${RUN_EXIT}; 141 is SIGPIPE under pipefail)"
fi
MONOLOCK="${SCRATCH}/monorepo_locks"
for i in $(seq 1 45); do
    mkdir -p "${MONOLOCK}/package-number-${i}/frontend/application/workspace"
    echo '{"lockfileVersion":3}' > "${MONOLOCK}/package-number-${i}/frontend/application/workspace/package-lock.json"
done
run_pipeline "$MONOLOCK" --quiet
if [[ -n "$RUN_JSON" ]]; then
    ok_test "a monorepo with 45 lockfiles writes a report"
else
    fail_test "a monorepo with 45 lockfiles writes a report" \
              "scan died without a report (exit ${RUN_EXIT}; 141 is SIGPIPE under pipefail)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Known credential formats, built at run time
# ═════════════════════════════════════════════════════════════════════════════
# Each token below is assembled from a context, a prefix and two halves of a
# body that sit in separate quoted strings, so this file never holds a
# contiguous token. Two reasons: this pipeline run over its own repository
# would otherwise flag its own test suite, and a secret scanner on the remote
# may refuse a push that contains provider-shaped strings.
SECR="${SCRATCH}/known_secrets"
mkdir -p "$SECR"
put_secret() { printf '%s\n' "$2" > "${SECR}/known_$1.txt"; }
put_secret aws_access_key_id "aws_access_key_id = ""AKIA""WSLDPOPA""8IDMMTGM"
put_secret aws_secret_access_key "aws_secret_access_key = ""toB5aoVsS8hhss6inCQm""w31l26fqXAhjVmMyamjX"
put_secret github_token "export GITHUB_TOKEN=""ghp_""oKFEOeVI2WdxcX4L8y""aUEcp4bWTkt2HGVHQx"
put_secret github_fine_grained_pat "token: ""github_pat_""Uc2tDa29hb5sLLd6cUGXayGrBbDUvQ""mSuP4MJ5SQGUH7FrVQ2quG8z1YJ0Kw"
put_secret gitlab_pat "GITLAB_TOKEN=""glpat-""Twtt7L5tbe""6IDp_3st9F"
put_secret stripe_live_key "STRIPE_KEY=""sk_live_""KUbMBGKxflzvZd""u34gMRmaUrUwyM"
put_secret slack_token "SLACK_BOT_TOKEN=""xoxb-""871990237361-137326652659""-tZddgPODHoEidsYlVEEBxzud"
put_secret google_api_key "key = ""AIza""CrCX6iZlxlj7fDNuR""GwJSfhIENqKTTiqt2x"
put_secret google_oauth_token "access = ""ya29.""N5OXzzezpSWT9SqRzG9l""Up--cLLpQJa3WIeMosrs"
put_secret sendgrid_key "SENDGRID=""SG.""mhSJnHLwAXcUnTf6MvPTVg.QU9gnSsHUU""FRleDJAlNhCYlhQupaD70ahgOQ0TvJDK5"
put_secret npm_token "//registry.npmjs.org/:_authToken=""npm_""NMNGQAItkyWqEc3VQh""aX31ke6Uu53X2ohd5c"
put_secret pypi_token "password = ""pypi-AgEIcHlwaS5vcmc""8dNKdzVHlw6s5wWOroxjtBhYeNvuvg""lFU9leuBZHYyEBrxKbg2Ir6zOKRuhl"
put_secret huggingface_token "HF_TOKEN=""hf_""HyqmHLPFDUi4OOEit""j59FfZTWuE7xVAuwQ"
put_secret anthropic_key "ANTHROPIC_API_KEY=""sk-ant-api03-""DRlCCy2XaflpZPEIkEosNeLJvFZJX_ucvqIDITZFgE0_F""bvIY3nXCZY72Co5fzjVj-zG5eISJVAG7_rr0xKBvwNsmJ"
put_secret openai_project_key "OPENAI_API_KEY=""sk-proj-""8VpoAuXnm-sMkbiTANEBhAxQ""FknjLLlzjkXnHlNfyeG6hf9q"
put_secret openai_legacy_key "OPENAI_API_KEY=""sk-""WXrSZrLEeoS7bCDUC64yhrYq""zb3joq4YDtfomwplf3LZ3cws"
put_secret shopify_token "SHOPIFY=""shpat_""cd7701ff77976566""445ff51d43c0a76f"
put_secret digitalocean_token "DO_TOKEN=""dop_v1_""81e402f19126284c122a510e2ed5e81d""a5487e8579f405b60532147c46e01bfa"
put_secret jwt "session = ""eyJlCIxr89LcspvfiHbtwjH_j3Db0BtCH9sY"".""eyJFsvZc6Xjc3Gy4Orwd""naWW-iTRnXvaZtm9eaygGWI"".""3r90T2kmsR95izWTG1E3s9nE_5jG_f34X5FPbxph9y5"
# Near-misses: every line here is something a naive pattern flags.
{
    echo "aws_access_key_id = ""AKIAIOSFODNN7""EXAMPLE"      # AWS's own documentation key
    echo "token = ""ghp_""$(printf 'x%.0s' $(seq 1 36))"    # placeholder body
    echo "token = ""ghp_""$(printf 'A%.0s' $(seq 1 36))"    # one repeated character
    echo "token = ""ghp_16C7e42F""292c6912E7710c838347Ae178B4a"  # GitHub's documentation example
    echo "STRIPE_KEY=""sk_test_""PP7tbgUZLQPJww5wQMMyBQQn5zpG"           # test mode, harmless
    echo "x = hf_config_value_that_is_long_enough_to_look_real"   # underscores end the token
    echo "commit 3a7bd3e2360a3d29eea436fcfb7e44c735d117c4"        # a git sha
    echo "id = zzAKIA""Z961ELEFI1I64MFQ""zz"             # token embedded mid-identifier
} > "${SECR}/known_safe.txt"
# The same token inside a jar: once as a text resource, once as a string constant
# in a class file's constant pool, where it sits between binary length fields.
AITRANSIT_TEST_TOKEN="ghp_""oKFEOeVI2WdxcX4L8y""aUEcp4bWTkt2HGVHQx" \
    python3 "${FIXTURES}/make_jar_fixtures.py" --credential-jars "$SECR"
run_pipeline "$SECR" --quiet
FK=""
[[ -n "$RUN_JSON" ]] && FK=$(json_findings "$RUN_JSON")
kline() { echo "$FK" | grep "/$1 " || true; }

assert_contains "$(kline known_aws_access_key_id.txt)" "CWE-798:known_credential_format_aws_access_key_id" \
    "an AWS access key id is flagged"
assert_contains "$(kline known_aws_secret_access_key.txt)" "CWE-798:known_credential_format_aws_secret_access_key" \
    "an AWS secret access key is flagged"
assert_contains "$(kline known_github_token.txt)" "CWE-798:known_credential_format_github_token" \
    "a GitHub personal access token is flagged"
assert_contains "$(kline known_github_fine_grained_pat.txt)" "CWE-798:known_credential_format_github_fine_grained_pat" \
    "a GitHub fine-grained token is flagged"
assert_contains "$(kline known_gitlab_pat.txt)" "CWE-798:known_credential_format_gitlab_pat" \
    "a GitLab access token is flagged"
assert_contains "$(kline known_stripe_live_key.txt)" "CWE-798:known_credential_format_stripe_live_key" \
    "a Stripe live secret key is flagged"
assert_contains "$(kline known_slack_token.txt)" "CWE-798:known_credential_format_slack_token" \
    "a Slack token is flagged"
assert_contains "$(kline known_google_api_key.txt)" "CWE-798:known_credential_format_google_api_key" \
    "a Google API key is flagged"
assert_contains "$(kline known_google_oauth_token.txt)" "CWE-798:known_credential_format_google_oauth_token" \
    "a Google OAuth token is flagged"
assert_contains "$(kline known_sendgrid_key.txt)" "CWE-798:known_credential_format_sendgrid_key" \
    "a SendGrid key is flagged"
assert_contains "$(kline known_npm_token.txt)" "CWE-798:known_credential_format_npm_token" \
    "an npm token is flagged"
assert_contains "$(kline known_pypi_token.txt)" "CWE-798:known_credential_format_pypi_token" \
    "a PyPI token is flagged"
assert_contains "$(kline known_huggingface_token.txt)" "CWE-798:known_credential_format_huggingface_token" \
    "a Hugging Face token is flagged"
assert_contains "$(kline known_anthropic_key.txt)" "CWE-798:known_credential_format_anthropic_key" \
    "an Anthropic API key is flagged"
assert_contains "$(kline known_openai_project_key.txt)" "CWE-798:known_credential_format_openai_project_key" \
    "an OpenAI project key is flagged"
assert_contains "$(kline known_openai_legacy_key.txt)" "CWE-798:known_credential_format_openai_legacy_key" \
    "a legacy OpenAI key is flagged"
assert_contains "$(kline known_shopify_token.txt)" "CWE-798:known_credential_format_shopify_token" \
    "a Shopify token is flagged"
assert_contains "$(kline known_digitalocean_token.txt)" "CWE-798:known_credential_format_digitalocean_token" \
    "a DigitalOcean token is flagged"
assert_contains "$(kline jar_cred_text.jar)" "CWE-798:known_credential_format_github_token" \
    "a GitHub token in a jar's text resource is flagged"
assert_contains "$(kline jar_cred_class.jar)" "CWE-798:known_credential_format_github_token" \
    "a GitHub token in a class file's constant pool is flagged"
assert_contains "$(kline known_jwt.txt)" "jwt_embedded" \
    "a JWT is reported, but does not block"
assert_not_contains "$(kline known_jwt.txt)" "[FAIL]" \
    "a JWT alone does NOT fail the file"
assert_not_contains "$(kline known_safe.txt)" "[FAIL]" \
    "does NOT flag documentation keys, placeholders, test keys or mid-identifier matches"


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

    # The report must state, per layer, whether it ran. A verdict alone cannot
    # distinguish "clean" from "nothing was examined"; this is what the
    # air-gapped acceptance gate keys on (OFFLINE_RUNBOOK.md phase 5).
    run_pipeline "${FIXTURES}/clean" --offline --quiet
    if [[ -n "$RUN_JSON" ]]; then
        assert_contains "$(cat "$RUN_JSON")" '"coverage"' \
            "report includes a per-layer coverage block"
        assert_contains "$(cat "$RUN_JSON")" '"coverage_complete"' \
            "report states whether coverage was complete"

        # With no scanners installed, the layers that need them must be
        # reported as gaps -- not silently omitted.
        GAPS=$(python3 -c "
import json,sys
d=json.load(open('$RUN_JSON'))
print(' '.join(sorted(d.get('coverage_gaps',[]))))
" 2>/dev/null || true)
        assert_contains "$GAPS" "L2_owasp_cwe" \
            "a layer whose tool is absent is recorded as a coverage gap"

        # Layers built into the pipeline always run and must say so.
        L4=$(python3 -c "
import json
print(json.load(open('$RUN_JSON')).get('coverage',{}).get('L4_patterns',''))
" 2>/dev/null || true)
        assert_eq "ran" "$L4" "built-in pattern layer reports that it ran"
    fi
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

    # The HTML report embeds file paths and finding text, and both come from the
    # repository being scanned: a file can be NAMED <img src=x onerror=…>, and a
    # jar entry can carry the same text into a finding message. Written
    # unescaped, either runs in the reviewer's browser when they open the report.
    XSS="${SCRATCH}/xss_repo"
    mkdir -p "$XSS"
    echo hello > "$XSS/<img src=x onerror=alert(1)>.txt"
    python3 - "$XSS/hostile.jar" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("../<script>alert(2)</script>.sh", "x")
PYEOF
    run_pipeline "$XSS" --quiet
    XSS_HTML=$(cat "${RUN_JSON%.json}.html" 2>/dev/null || true)
    assert_not_contains "$XSS_HTML" "<img src=x onerror" \
        "HTML report: a hostile file name is not written as markup"
    assert_not_contains "$XSS_HTML" "<script>alert(2)" \
        "HTML report: a hostile jar entry name in a finding is not written as markup"
    assert_contains "$XSS_HTML" "&lt;img src=x onerror" \
        "HTML report: the hostile file name is shown escaped, not dropped"
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

    # grep_check must pass its pattern after -e. Without it a pattern that
    # begins with a dash — "-----BEGIN RSA PRIVATE KEY-----" being the one that
    # matters — is parsed as options, and grep exits 2 with "unrecognized
    # option". `if` reads 2 as false, so the rule is silently inert: it never
    # fires and never complains. Same family as the two bugs above.
    BAD=$(grep -nE '^grep_check(_i)?\(\)' "${ROOT_DIR}/scan_pipeline.sh" \
          | grep -v -- '-e ' || true)
    if [[ -z "$BAD" ]]; then
        ok_test "grep_check helpers pass their pattern after -e"
    else
        fail_test "grep_check helpers pass their pattern after -e" "$BAD"
    fi

    # A backslash class inside a bracket expression. GNU grep treats \s, \w and \d
    # as shorthand classes only OUTSIDE a bracket: inside one, [^"\s] is a negated
    # set of the literal characters \ and s. The universal credential rule had it,
    # and so required four characters none of which was an "s" — it missed
    # password = "sup3rs3cret" while looking correct on every test using a value
    # without one. Another instance of the silent-inert-rule family. Comments are
    # skipped, and so are heredoc bodies: the manifest scanner embeds Python, where
    # [\w.-] is correct.
    for f in scan_pipeline.sh fetch_repo.sh ai_transit.sh docker-run.sh; do
        BAD=$(awk '
            inhd { if ($0 == term) inhd = 0; next }
            { if (match($0, /<<-?[[:space:]]*\047?[A-Za-z_]+\047?/)) {
                  t = substr($0, RSTART, RLENGTH); gsub(/<<-?[[:space:]]*|\047/, "", t)
                  term = t; inhd = 1 }
              print NR ": " $0 }' "${ROOT_DIR}/${f}" \
              | grep -vE '^[0-9]+: [[:space:]]*#' \
              | grep -E '\[\^?[^]]*\\[swdSWD][^]]*\]' || true)
        if [[ -z "$BAD" ]]; then
            ok_test "${f} has no backslash class inside a bracket expression"
        else
            fail_test "${f} has no backslash class inside a bracket expression" "$BAD"
        fi
    done

    # `find … | head -N` under `set -o pipefail`. head exits after N lines, find
    # is killed by SIGPIPE once its output no longer fits one write, the pipeline
    # returns 141 and `set -e` aborts the scan with no verdict and no report.
    # `sed -n '1,Np'` reads everything and has none of that. Backslash-continued
    # lines are joined first, because the offending site was split across two.
    BAD=$(sed -e ':a' -e '/\\$/N' -e 's/\\\n[[:space:]]*/ /' -e 'ta' "${ROOT_DIR}/scan_pipeline.sh" \
          | grep -nE 'find .*\|[[:space:]]*head' || true)
    if [[ -z "$BAD" ]]; then
        ok_test "scan_pipeline.sh has no find piped into head"
    else
        fail_test "scan_pipeline.sh has no find piped into head" "$BAD"
    fi

    # A RETURN trap is not scoped to the function that installs it: it keeps
    # firing as later functions return. If its body defers expansion — single
    # quotes around '$tmp' rather than double — then by the time it runs in some
    # other function the variable is out of scope and set -u aborts the whole
    # scan. That is how the first cut of scan_pdf() killed every run after the
    # first PDF. A RETURN trap must bake its paths in at install time, so a
    # single-quoted body referencing a variable is a defect.
    for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh docker-run.sh; do
        BAD=$(grep -nE "trap[[:space:]]+'[^']*\\\$[^']*'[[:space:]]+RETURN" \
              "${ROOT_DIR}/${f}" \
              | grep -vE '^[0-9]+:[[:space:]]*#' || true)
        if [[ -z "$BAD" ]]; then
            ok_test "${f} has no RETURN trap that defers variable expansion"
        else
            fail_test "${f} has no RETURN trap that defers variable expansion" "$BAD"
        fi
    done

    # Documentation quotes the assertion count ("68/68 passed", "68 assertions")
    # in several places. Those numbers drift silently every time a test is added,
    # and a doc that misstates its own verification is a doc readers stop
    # trusting. Check them against the real total.
    #
    # Compared against PASS_N, the number of assertions that have actually run
    # by this point; this group is last, so it is close to the final total.
    #
    # Counting assertion *call sites* in this file instead does not work: sites
    # inside the per-script lint loops run four times each, and sites in
    # branches that did not execute never run at all, so the figure lands well
    # above the real total (95 against 84). An EXPECTED_N doing exactly that
    # sat here unused, with a comment claiming it was the expectation.
    STALE=""
    while IFS= read -r hit; do
        [[ -z "$hit" ]] && continue
        num="${hit##*:}"
        num="${num%%/*}"; num="${num%% *}"
        # Allow a small margin: the point is to catch drift, not to force an
        # edit for every single new assertion.
        if (( num < PASS_N - 6 || num > PASS_N + 6 )); then
            STALE+="${hit}"$'\n'
        fi
    done < <(grep -rnoE '[0-9]+/[0-9]+ passed|[0-9]+ assertions' \
             "${ROOT_DIR}"/*.md "${ROOT_DIR}"/build_*.py 2>/dev/null || true)

    # Count how many references exist at all. A sed that runs with an empty
    # variable silently deletes the number rather than updating it, leaving
    # "Expected: ✔ / passed" — and a guard that only checks values would pass on
    # that, because there is no longer a value to disagree with.
    N_REFS=$(grep -rcoE '[0-9]+/[0-9]+ passed|[0-9]+ assertions' \
             "${ROOT_DIR}"/*.md "${ROOT_DIR}"/build_*.py 2>/dev/null \
             | awk -F: '{n+=$2} END{print n+0}')

    if [[ -n "$FILTER" ]]; then
        # Under a filter PASS_N counts only the selected groups, so comparing
        # documented totals against it would report false drift.
        skip_test "documented assertion counts match the suite" "run without a filter"
    elif (( N_REFS < 5 )); then
        fail_test "documented assertion counts match the suite" \
                  "only ${N_REFS} count reference(s) found across the docs — numbers were likely deleted rather than updated"
    elif [[ -z "$STALE" ]]; then
        ok_test "documented assertion counts match the suite"
    else
        fail_test "documented assertion counts match the suite" \
                  "suite reports ${PASS_N}; stale references:"$'\n'"${STALE}"
    fi

    # Section cross-references break silently when sections are renumbered, and
    # INSTALL.md has been renumbered twice. Verify every "§N" and "§N.M" points
    # at a heading that exists.
    BADREF=$(python3 - "${ROOT_DIR}/INSTALL.md" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
heads = {(m.group(1) if not m.group(2) else f"{m.group(1)}.{m.group(2)}")
         for m in re.finditer(r'^#{2,3} (\d+)(?:\.(\d+))?\.?\s', s, re.M)}
bad = sorted({r for r in re.findall(r'§(\d+(?:\.\d+)?)', s) if r not in heads})
print(' '.join('§'+b for b in bad))
PY
)
    if [[ -z "$BADREF" ]]; then
        ok_test "INSTALL.md cross-references all resolve"
    else
        fail_test "INSTALL.md cross-references all resolve" "dangling: ${BADREF}"
    fi

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
