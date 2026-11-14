"""Document and binary scanners of the Python engine: the inline credential rules of JSON and of prose files, the binary and
archive scanners, the container scanners (PDF, Java archives, office documents) that run the helper programs of
transit/containers/, and scan_unknown (shebang, then file(1)).

One function per scanner, named as in scan_pipeline.sh and in the same order of checks; the two inline branches of classify_file
(`.json` and `.md`/`.txt`/`.rst`) are scan_json and scan_doc. The helper programs are the ones the shell runs, with the shell's
arguments; their FACT lines are read the way the shell reads them, and the fail and warn vocabularies are tables of
(tag, message) rows. A scanner that returns 3 (scan_office on a file it was handed by its first bytes that is not an office
document) tells classify_file to go on. No module-level state. Standard library only.
"""
import os
import re
import subprocess
import tempfile

from transit.core import (FILE_STATUS, _ascii_lower, _known_cred_check, _s, call_scanner, first_line, grep_check, has_cmd,
                          record_fail, record_pass, record_warn, run_helper, run_tool, shebang_scanner)


# ── The inline branches of classify_file ─────────────────────────────────────
def scan_json(f):
    """`.json`: one credential rule."""
    if grep_check(r'(password|secret|token|api_key|private_key)\s*"?\s*:\s*"[^"${[:space:]]{4,}', f):
        record_fail(f, "CWE-798:hardcoded_credential_in_JSON")
    else:
        record_pass(f)


def scan_doc(f):
    """`.md`, `.txt`, `.rst`: one credential rule."""
    if grep_check(r'(password|secret|api_key)\s*[:=]\s*[^${[:space:]][^[:space:]]{4,}', f):
        record_fail(f, "CWE-798:hardcoded_credential_in_doc")
    else:
        record_pass(f)


# ── Small shell idioms ───────────────────────────────────────────────────────
def _mktemp(prefix):
    """`mktemp "${TMPDIR:-/tmp}/<prefix>XXXXXX" 2>/dev/null || ""`."""
    try:
        fd, path = tempfile.mkstemp(prefix=prefix, dir=os.environ.get("TMPDIR") or "/tmp")
    except OSError:
        return ""
    os.close(fd)
    return path


def _rm(path):
    """`rm -f`."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _nonempty(path):
    """`[[ -s path ]]`."""
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


def _pipe_output(argv1, argv2):
    """`out=$(argv1 | argv2 || true); [[ -n "$out" ]]`: does the second program print anything. The exit statuses are not read, only
    the output, like the shell reads it; both programs have stdin and stderr on /dev/null."""
    try:
        p1 = subprocess.Popen([os.fsencode(a) for a in argv1], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen([os.fsencode(a) for a in argv2], stdin=p1.stdout, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)
    except OSError:
        return False
    p1.stdout.close()
    printed = False
    while True:
        chunk = p2.stdout.read(65536)
        if not chunk:
            break
        printed = printed or bool(chunk.strip(b"\n"))        # `$(...)` drops trailing newlines
    p2.stdout.close()
    p2.wait()
    p1.wait()
    return printed


# ── Binaries and archives ────────────────────────────────────────────────────
def scan_binary(f):
    record_fail(f, "binary:unexpected_binary_in_AI_repo")
    if has_cmd("strings"):
        if _pipe_output(["strings", "--", f], ["grep", "-iE", "-e", "(http://|https://|/etc/passwd|/bin/sh|exec|shell|reverse|c2server)"]):
            record_fail(f, "binary:IOC_strings_detected")


def scan_archive(f):
    record_fail(f, "archive:requires_dedicated_rescan")
    # CWE-22: zip-slip check on zip archives
    if has_cmd("unzip") and f.endswith(".zip"):
        if _pipe_output(["unzip", "-l", "--", f], ["grep", "-e", r"\.\."]):
            record_fail(f, "CWE-22:zip_slip_path_traversal_in_archive")


# ── The FACT lines of the container helpers ──────────────────────────────────
def _read_facts(raw):
    """`while IFS= read -r line; do [[ $line == "FACT "* ]] ...`: the helper's stdout as ({tag: count}, {tag: detail}). `$(...)`
    drops NUL bytes; a line that is not a FACT line is ignored; the last line for a tag wins."""
    count, detail = {}, {}
    for line in _s(raw.replace(b"\0", b"")).split("\n"):
        if not line.startswith("FACT "):
            continue
        line = line[len("FACT "):]
        tag = line.split(" ", 1)[0]
        line = line[len(tag):]
        line = line[1:] if line.startswith(" ") else line
        n = line.split(" ", 1)[0]
        d = line[len(n):]
        count[tag], detail[tag] = n, (d[1:] if d.startswith(" ") else d)
    return count, detail


def _fact_message(msg, n, d, tag):
    """`${msg}(${fact_n[$tag]}${fact_d[$tag]:+: ${fact_d[$tag]}})`."""
    return "%s(%s%s)" % (msg, n[tag], ": " + d[tag] if d[tag] else "")


def _report_facts(f, n, d, fail_map, warn_map):
    """Record the FAILs of fail_map, then the WARNs of warn_map, for the tags the helper reported. -> (a FAIL was recorded,
    anything was recorded)."""
    failed = recorded = False
    for tag, msg in fail_map:
        if tag in n:
            record_fail(f, _fact_message(msg, n, d, tag))
            failed = recorded = True
    for tag, msg in warn_map:
        if tag in n:
            record_warn(f, _fact_message(msg, n, d, tag))
            recorded = True
    return failed, recorded


# ── Java archives (.jar .war .ear .aar) ──────────────────────────────────────
def _jar_facts(f, view):
    """`python3 transit/containers/jar.py FILE VIEW 2>/dev/null` -> (exit status, stdout)."""
    return run_helper("containers/jar.py", f, view)


# Each of these has no innocent reading in a repository, and each measured 0 of 365 real jars.
_JAR_FAIL = (
    ("zip_slip", "CWE-22:jar_entry_path_traversal_zip_slip"),
    ("class_not_bytecode", "CWE-506:jar_class_entry_is_not_bytecode"),
    ("hidden_native", "CWE-506:jar_native_executable_hidden_under_a_non_native_name"),
    ("private_key", "CWE-321:hardcoded_private_key"),
    ("classpath_remote", "CWE-829:jar_manifest_class_path_names_a_remote_url"),
    ("prepended_native", "CWE-506:jar_native_executable_prepended_to_archive"),
    ("not_an_archive", "jar:file_is_not_an_archive_despite_its_extension"),
    ("symlink_escape", "CWE-22:jar_symlink_entry_points_outside_the_archive"),
    ("symlink_unreadable", "CWE-22:jar_symlink_entry_target_unreadable"),
    ("orphan_local", "CWE-22:jar_local_entry_missing_from_central_directory"),
    ("wrapper_unexpected", "CWE-494:wrapper_jar_has_unexpected_content"),
    ("hostile_shell_pipe", "CWE-78:jar_embeds_download_piped_to_shell"),
    ("hostile_reverse_shell", "CWE-78:jar_embeds_reverse_shell"),
    ("hostile_encoded_powershell", "CWE-78:jar_embeds_encoded_powershell"),
    ("hostile_lolbin_download", "CWE-494:jar_embeds_certutil_or_bitsadmin_download"),
)
# Ordinary in some jars (native libraries 17 of 365, agents 2 of 365), or a statement that something was not looked at.
_JAR_WARN = (
    ("agent", "jar:java_agent_in_manifest"),
    ("native_library", "jar:bundles_native_library"),
    ("script_entry", "jar:bundles_script_file"),
    ("symlink", "jar:contains_symlink_entry"),
    ("nested_archive", "jar:contains_nested_archive"),
    ("nested_unparseable", "jar:nested_archive_could_not_be_opened"),
    ("classpath_absolute", "jar:manifest_class_path_is_absolute"),
    ("duplicate_names", "jar:duplicate_entry_names_readers_may_disagree_about_which_is_used"),
    ("encrypted", "jar:encrypted_entries_not_inspected"),
    ("unreadable", "jar:entries_could_not_be_read"),
    ("incomplete", "jar:inspection_incomplete"),
    ("oversize", "jar:declared_uncompressed_size_over_limit"),
    ("unparseable", "jar:unparseable_archive_not_inspected"),
    ("unreadable_file", "jar:file_could_not_be_read"),
    ("empty_file", "jar:empty_file"),
    ("prepended_script", "jar:launch_script_prepended_to_archive"),
    ("prepended_data", "jar:data_before_archive_start"),
    ("hostile_offensive_tool_name", "jar:offensive_tool_name_in_content"),
)


def scan_jar(f):
    if not has_cmd("python3"):
        record_warn(f, "jar:not_inspected(install python3 so scan_jar can read the archive)")
        return 0
    view = _mktemp("aitransit_jar_")
    if not view:
        record_warn(f, "jar:not_inspected(could not create a temporary file)")
        return 0
    try:
        rc, raw = _jar_facts(f, view)
        n, d = _read_facts(raw if rc == 0 else b"")            # `facts=$(...) || facts=""`

        if "done" not in n:
            # The helper died before finishing. Say so: no facts is not a clean jar.
            record_warn(f, "jar:inspection_failed(the archive could not be read; treat as not inspected)")
            return 0

        failed, _ = _report_facts(f, n, d, _JAR_FAIL, _JAR_WARN)
        if "wrapper" in n:
            record_warn(f, "jar:wrapper_checksum_must_be_verified(%s wrapper jar runs before any code the repository declares; "
                           "its shape is checked but not its contents)" % d["wrapper"])

        # Credentials in the text of the entries. Class files are searched through their constant pools, where string
        # constants live. Private keys are judged per string inside the helper.
        if _nonempty(view):
            if _known_cred_check(f, view):
                failed = True

        # Bytecode is not reviewed. A jar with nothing wrong with its structure is still opaque executable code, and says so.
        if not failed:
            record_warn(f, "jar:vendored_compiled_code_not_reviewable")
        return 0
    finally:
        _rm(view)


# ── Office documents ─────────────────────────────────────────────────────────
def _office_facts(f, view, ext):
    """`python3 transit/containers/office.py FILE VIEW EXT 2>/dev/null` -> (exit status, stdout)."""
    return run_helper("containers/office.py", f, view, ext)


# No innocent reading in a repository of AI-generated code.
_OFFICE_FAIL = (
    ("zip_slip", "CWE-22:office_part_path_traversal_zip_slip"),
    ("disguised_native", "CWE-506:office_file_is_a_native_executable_despite_its_extension"),
    ("vba_dangerous", "CWE-94:office_vba_macro_runs_programs_or_downloads"),
    ("xlm_dangerous", "CWE-94:office_excel4_macro_sheet_is_hidden_or_runs_programs"),
    ("dde", "CWE-94:office_dde_field_or_formula_starts_a_program"),
    ("ppt_program_action", "CWE-78:office_presentation_action_runs_a_program"),
    ("remote_template", "CWE-829:office_remote_template_injection"),
    ("remote_object", "CWE-829:office_object_or_frame_fetched_from_a_remote_host"),
    ("uri_handler", "CWE-94:office_link_uses_a_script_or_diagnostic_uri_scheme"),
    ("unc_path", "CWE-522:office_references_a_unc_path_ntlm_leak"),
    ("embedded_executable", "CWE-506:office_embeds_an_executable_or_script"),
    ("equation_exploit", "CWE-94:office_equation_editor_object_carries_a_payload"),
    ("xxe", "CWE-611:office_part_declares_an_external_entity"),
    ("odf_auto_macro", "CWE-94:odf_macro_runs_on_open"),
    ("odf_dangerous", "CWE-94:odf_macro_runs_programs_or_downloads"),
    ("rtf_remote_link", "CWE-829:rtf_linked_object_updates_from_a_remote_source"),
    ("private_key", "CWE-321:hardcoded_private_key"),
    ("hostile_shell_pipe", "CWE-78:office_macro_or_script_pipes_a_download_into_a_shell"),
    ("hostile_encoded_powershell", "CWE-78:office_macro_or_script_runs_encoded_powershell"),
    ("hostile_lolbin_download", "CWE-494:office_macro_or_script_downloads_with_certutil_or_bitsadmin"),
)
# Ordinary in some documents, or a statement that something was not looked at.
_OFFICE_WARN = (
    ("vba_macro", "office:contains_vba_macro"),
    ("vba_autoexec", "office:vba_macro_runs_when_the_document_opens"),
    ("macro_ext_mismatch", "office:vba_macro_in_a_non_macro_extension"),
    ("xlm_macro", "office:excel4_macro_sheet"),
    ("remote_content", "office:remote_image_or_content_fetched_when_opened"),
    ("unc_hyperlink", "office:hyperlink_to_a_unc_path"),
    ("embedded_object", "office:contains_embedded_object"),
    ("activex", "office:contains_activex_control"),
    ("equation_object", "office:equation_editor_object"),
    ("ppt_macro_action", "office:presentation_action_runs_a_macro"),
    ("link_to_program", "office:hyperlink_targets_a_program"),
    ("odf_macro", "odf:contains_macro"),
    ("odf_external", "odf:external_resource_linked"),
    ("dde_declared", "office:dde_connection_declared"),
    ("doctype", "office:xml_part_has_a_doctype"),
    ("encrypted", "office:encrypted_content_not_inspected"),
    ("unparseable", "office:container_could_not_be_parsed"),
    ("vba_unreadable", "office:vba_project_could_not_be_read"),
    ("altchunk", "office:contains_alternate_format_chunk"),
    ("rtf_object", "rtf:contains_embedded_ole_object"),
    ("incomplete", "office:inspection_incomplete"),
    ("unreadable", "office:parts_could_not_be_read"),
    ("unreadable_file", "office:file_could_not_be_read"),
    ("empty_file", "office:empty_file"),
)


def scan_office(f, sniffed=""):
    """-> 3 when the file was routed here by its first bytes (`sniffed`) and is not an office document; 0 otherwise."""
    ext = _ascii_lower(f.rsplit(".", 1)[-1] if "." in f else f)      # `${f##*.}`, lower-cased

    if not has_cmd("python3"):
        record_warn(f, "office:not_inspected(install python3 so scan_office can read the document)")
        return 0
    view = _mktemp("aitransit_office_")
    if not view:
        record_warn(f, "office:not_inspected(could not create a temporary file)")
        return 0
    try:
        rc, raw = _office_facts(f, view, ext)
        n, d = _read_facts(raw if rc == 0 else b"")            # `facts=$(...) || facts=""`

        if "done" not in n:
            record_warn(f, "office:inspection_failed(the document could not be read; treat as not inspected)")
            return 0

        # Not an office document at all. The extension decides only what happens next.
        if "not_office" in n:
            _rm(view)
            # Routed here only because its first kilobyte mentions {\rtf (a shell script with a comment, a note about the
            # format): hand it back to the scanner its name and shebang call for.
            if sniffed == "sniffed":
                return 3
            # Plausibly plain text: a .doc README, Graphviz .dot, gettext .pot, tab-separated .xls
            if d["not_office"] == "text" and ext in ("doc", "dot", "pot", "xls", "xlt", "xla", "ppt", "pps", "ppa"):
                scan_unknown(f)
                return 0
            record_warn(f, "office:not_an_office_document_despite_its_extension(%s)" % d["not_office"])
            return 0

        failed, recorded = _report_facts(f, n, d, _OFFICE_FAIL, _OFFICE_WARN)

        # Credentials in the text of the document, through the same rules as Layer 4.
        if _nonempty(view):
            if _known_cred_check(f, view):
                failed = recorded = True

        # A document with nothing to report is data, not code: PASS (unlike a jar, which is code).
        if not (recorded or FILE_STATUS.get(f)):
            record_pass(f)
        return 0
    finally:
        _rm(view)


# ── PDF ──────────────────────────────────────────────────────────────────────
def _pdf_has(f, pattern):
    """`grep -qaE PATTERN FILE`."""
    return run_tool(["grep", "-qaE", "-e", pattern, "--", f])[0] == 0


def _pdf_searchable(f, names_out, out):
    """`python3 transit/containers/pdf.py FILE NAMES_VIEW FULL_VIEW 2>/dev/null || true`: the helper writes both views."""
    run_helper("containers/pdf.py", f, names_out, out)


def scan_pdf(f):
    failed = False

    # A .pdf that is not a PDF at all is worth saying out loud.
    try:
        with open(f, "rb") as fh:
            has_header = b"%PDF-" in fh.read(1024)
    except OSError:
        has_header = False
    if not has_header:
        record_warn(f, "pdf:no_PDF_header_extension_may_be_misleading")

    # Two views: `names` has string literals blanked and carries the key rules; `searchable` keeps everything and carries the
    # payload rules, because the script itself sits inside the /JS ( ... ) string.
    searchable = names = f
    tmp = tmpn = ""
    if has_cmd("python3"):
        tmp = _mktemp("aitransit_pdf_")
        tmpn = _mktemp("aitransit_pdfn_")
    try:
        if tmp and tmpn:
            _pdf_searchable(f, tmpn, tmp)
            if _nonempty(tmp):
                searchable = tmp
            if _nonempty(tmpn):
                names = tmpn
        if searchable == f and _pdf_has(f, "/ObjStm"):
            record_warn(f, "pdf:compressed_object_streams_not_inspected(install python3 so scan_pdf can inflate them)")

        # Active content. CWE-94: an embedded script at all. Held in a variable because the shellcode and known-exploit rules
        # below are only meaningful alongside it: a PDF that merely documents unescape() is not an attack.
        has_js = False
        if _pdf_has(names, "/(JavaScript|JS)[^A-Za-z0-9#]"):
            record_fail(f, "CWE-94:PDF_javascript_embedded")
            has_js = failed = True

        # /OpenAction and /AA run without the reader clicking anything
        if _pdf_has(names, "/(OpenAction|AA)[^A-Za-z0-9#]"):
            record_fail(f, "CWE-94:PDF_auto_execute_action_on_open")
            failed = True

        # CWE-78: /Launch starts an external program
        if _pdf_has(names, "/Launch[^A-Za-z0-9#]"):
            record_fail(f, "CWE-78:PDF_launch_action_starts_external_program")
            failed = True

        # CWE-506: embedded payload
        if _pdf_has(names, "/EmbeddedFile"):
            record_fail(f, "CWE-506:PDF_embedded_file_payload")
            failed = True
        if _pdf_has(searchable, "AITRANSIT-MARKER-EMBEDDED-PE|This program cannot be run in DOS mode"):
            record_fail(f, "CWE-506:PDF_embedded_windows_executable")
            failed = True

        # /OpenAc#74ion reads identically to a PDF viewer and defeats a plain-text rule; the helper leaves a marker where an
        # escape decodes to one of the dangerous names.
        if _pdf_has(searchable, "AITRANSIT-MARKER-NAME-OBFUSCATION"):
            record_fail(f, "CWE-94:PDF_name_hex_obfuscation_hides_active_content")
            failed = True

        # Rich media players carry their own exploit history
        if _pdf_has(names, "/(RichMedia|Flash)[^A-Za-z0-9#]"):
            record_fail(f, "CWE-94:PDF_rich_media_active_content")
            failed = True

        # CWE-200: a form that posts elsewhere, or pulls data in
        if _pdf_has(names, "/(SubmitForm|ImportData)[^A-Za-z0-9#]"):
            record_fail(f, "CWE-200:PDF_form_submits_or_imports_data")
            failed = True

        if has_js:
            # Acrobat JavaScript entry points with a public exploit history
            if _pdf_has(searchable, r"(util\.printf|collab\.getIcon|media\.newPlayer|spell\.customDictionaryOpen|"
                                    r"this\.exportDataObject|app\.launchURL|getAnnots)[[:space:]]*\("):
                record_fail(f, "CWE-94:PDF_javascript_known_exploit_api")
                failed = True
            # Heap-spray and shellcode shapes
            if _pdf_has(searchable, r"(unescape[[:space:]]*\(|%u[0-9A-Fa-f]{4}%u[0-9A-Fa-f]{4}|String\.fromCharCode[[:space:]]*\()"):
                record_fail(f, "CWE-94:PDF_javascript_shellcode_pattern")
                failed = True

        # Opaque or review-worthy, but not active content on its own
        if _pdf_has(names, "/Encrypt[^A-Za-z0-9#]"):
            record_warn(f, "pdf:encrypted_content_could_not_be_inspected")
        if _pdf_has(names, "/XFA[^A-Za-z0-9#]"):
            record_warn(f, "pdf:XFA_form_attack_surface")
        if _pdf_has(names, "/(GoToR|GoToE)[^A-Za-z0-9#]"):
            record_warn(f, "pdf:remote_or_embedded_destination")

        # A stream behind a filter we could not decode has not been inspected, and that must be said rather than left to read as
        # clean. `grep -ao ... | awk '{print $2}' | sort -u | paste -sd, -`: the names, byte-sorted and unique, empty one included.
        _, raw = run_tool(["grep", "-ao", "-e", "AITRANSIT-MARKER-UNDECODED-FILTER [A-Za-z0-9]*", "--", searchable])
        found = set()
        for line in raw.split(b"\n")[:-1] if raw.endswith(b"\n") else raw.split(b"\n"):
            words = line.split()
            found.add(words[1] if len(words) > 1 else b"")
        undecoded = b",".join(sorted(found)).decode("latin-1")
        if undecoded:
            record_warn(f, "pdf:stream_filter_not_decoded(%s)_those_streams_were_not_inspected" % undecoded)

        # Incremental updates: what a reader shows need not be the only revision. `-o` then `wc -l`, because grep -c counts
        # matching lines and a PDF may hold several revisions with barely a newline between them.
        _, raw = run_tool(["grep", "-ao", "-e", "%%EOF", "--", f])
        if raw.count(b"\n") > 1:
            record_warn(f, "pdf:incremental_updates_multiple_revisions")
    finally:
        for p in (tmp, tmpn):
            if p:
                _rm(p)
    if not failed:
        record_pass(f)


# ── Unknown ──────────────────────────────────────────────────────────────────
def scan_unknown(f):
    # Extensionless scripts are common (entrypoint, run, hooks). Route them to the right scanner by shebang instead of skipping
    # per-type analysis (core.shebang_scanner reduces the line to the interpreter it names first, `env -S` and CR included).
    scanner = shebang_scanner(first_line(f))
    if scanner:
        call_scanner(scanner, f)
        return

    if has_cmd("file"):
        rc, raw = run_tool(["file", "--mime-type", "-b", "--", f])
        mime = _s(raw.replace(b"\0", b""))
        if rc != 0:
            mime += "unknown\n"                                  # `file ... || echo "unknown"` inside `$(...)`
        mime = mime.rstrip("\n")
        if re.search(r"^(application/x-executable|application/x-sharedlib|application/x-dosexec)", mime, re.M):
            record_fail(f, "binary:unexpected_executable_mime:" + mime)
            return
    record_pass(f)
