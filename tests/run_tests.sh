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
