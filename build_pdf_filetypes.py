#!/usr/bin/env python3
"""
File-type slide deck: one slide per scanner family (every extension that shares
a handler shares a slide), what tools and rules run on it, and one slide on
unknown extensions.

    python3 build_pdf_filetypes.py            # writes AI_Transit_Pipeline_FileTypes_EN.pdf
    python3 build_pdf_filetypes.py --check    # compare the routes below with scan_pipeline.sh

The routing table in scan_pipeline.sh (classify_file) is the source of truth. A
deck that lists an extension the scanner no longer routes, or omits one it does,
misleads exactly the people who rely on it, so --check parses classify_file and
fails on any difference; tests/run_tests.sh runs it.

Rules are summarised from the scanner functions and from the per-scanner sections
of CLAUDE.md. Where a slide says something is not covered, that is a measured or
stated limit, not an omission.

Format 16:9 — 1333 x 750 pt, light theme, matching AI_Transit_Pipeline_Slides_EN.pdf.
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "scan_pipeline.sh")
OUT = os.path.join(HERE, "AI_Transit_Pipeline_FileTypes_EN.pdf")

# ── The deck's data ───────────────────────────────────────────────────────────
# ext:   extension patterns exactly as classify_file's `case ".$ext"` lists them
# base:  basename patterns exactly as its `case "$base"` lists them
# shebang: extensionless files routed here by their first line (scan_unknown)
# tools: external tools that run on this type (name, behaviour)
# fail / warn: the rules, one line each
# note:  calibration and known limits
FAMILIES = [
    dict(
        key="python", title="Python", scanner="scan_python",
        ext=[".py"], shebang=["#!…python"],
        tools=[("Bandit", "bandit -q -l -i. Any MEDIUM or HIGH issue → FAIL (bandit:<severity>:<test id>). Not installed → WARN.")],
        fail=["CWE-78  os.system, subprocess.call, subprocess.Popen, commands.getoutput",
              "CWE-95  eval( or exec(",
              "CWE-502  pickle.load(s), marshal.loads, yaml.load( without a Loader",
              "CWE-89  execute / executemany with an f-string, +, % or .format() query",
              "CWE-703  assert is_admin / is_authenticated / has_perm / user.is…"],
        warn=["CWE-601  redirect( or HttpResponseRedirect( fed from request.…",
              "bandit missing"],
        note="Broad by design: eval, exec and os.system fail even with a literal argument. setup.py and conanfile.py are routed to the install-time scanner instead."),
    dict(
        key="setuppy", title="Install-time Python — setup.py, conanfile.py", scanner="scan_setup_py",
        base=["setup.py|conanfile.py"],
        tools=[("— none —", "Replaces scan_python for these two names: Bandit and the generic eval / exec / os.system FAILs do not run on them.")],
        fail=["A download piped into a shell",
              "exec / eval of a network response",
              "A blob decoded and executed in the same file (whole-file test)",
              "A socket handed to a shell, or a pty",
              "Writing authorized_keys, a crontab or a systemd unit"],
        warn=["Overriding install / develop / egg_info",
              "Downloading at install time",
              "Running a program"],
        note="setup.py runs on a source pip install and a Conan recipe on conan install, so both fire before anything is imported. 36 real setup.py: 4 FAIL → 0 FAIL, 3 WARN."),
    dict(
        key="js", title="JavaScript / TypeScript", scanner="scan_javascript",
        ext=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"], shebang=["#!…node"],
        tools=[("Semgrep p/javascript", "Run per file. Any finding → FAIL (semgrep:js:N_findings). Not installed → WARN.")],
        fail=["CWE-79  innerHTML / outerHTML / document.write / insertAdjacentHTML assignment",
              "CWE-78  child_process, exec(, execSync(, spawn(",
              "CWE-95  eval( or new Function(",
              "CWE-1321  __proto__, constructor[prototype], Object.assign({}",
              "CWE-915  Object.assign / _.merge / deepmerge( with req.… as the source",
              "CWE-89  SQL in a template literal (query / raw / knex.raw / sequelize.query)"],
        warn=["CWE-611  DOMParser, parseXML, libxmljs.parseXml",
              "semgrep missing"],
        note="package.json is routed to the manifest scanner, not here."),
    dict(
        key="java", title="Java source", scanner="scan_java",
        ext=[".java"],
        tools=[("— none per file —", "Semgrep covers Java at Layer 2 (whole directory).")],
        fail=["CWE-78  Runtime.getRuntime().exec( or ProcessBuilder(",
              "CWE-89  createQuery / createNativeQuery / prepareStatement with \"…\" +",
              "CWE-502  ObjectInputStream, XMLDecoder, XStream",
              "CVE-2021-44228  jndi:, ldap://, rmi://, ${jndi (Log4Shell)",
              "CWE-295  TrustAllCerts / an empty X509TrustManager"],
        warn=["CWE-79  request.getParameter written to the response",
              "CWE-611  DocumentBuilderFactory.newInstance() — check the entity configuration"],
        note="Compiled Java is a different file type: .jar .war .ear .aar have their own scanner."),
    dict(
        key="php", title="PHP", scanner="scan_php",
        ext=[".php"], shebang=["#!…php"],
        tools=[("— none per file —", "Semgrep covers PHP at Layer 2 (whole directory).")],
        fail=["CWE-78  shell_exec, exec, system, passthru, popen, proc_open",
              "CWE-89  mysql_query / mysqli_query / pg_query concatenating a variable",
              "CWE-79  echo $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER",
              "CWE-22  include / require with a variable path",
              "CWE-502  unserialize( of $_GET / $_POST / $_COOKIE / $_REQUEST"],
        warn=[],
        note="Every rule here is a FAIL: PHP has no reviewable tier."),
    dict(
        key="ruby", title="Ruby", scanner="scan_ruby",
        ext=[".rb"], shebang=["#!…ruby"],
        tools=[("— none per file —", "Semgrep covers Ruby at Layer 2 (whole directory).")],
        fail=["CWE-78  system, exec, Kernel.exec, %x{ or a backtick command",
              "CWE-95  eval( / eval {",
              "CWE-89  where / find_by_sql / execute with \"…#{…}\" interpolation",
              "CWE-22  File.read / File.open / IO.read of params[…]"],
        warn=[],
        note="A Rakefile is not routed to this scanner: it was measured and rejected (8 of 62 false positives on markdown backticks)."),
    dict(
        key="go", title="Go", scanner="scan_go",
        ext=[".go"],
        tools=[("— none per file —", "Semgrep covers Go at Layer 2 (whole directory).")],
        fail=["CWE-89  fmt.Sprintf building SELECT / INSERT / UPDATE / DELETE"],
        warn=["CWE-78  exec.Command(",
              "CWE-22  os.Open / ioutil.ReadFile / http.ServeFile of r.URL or path",
              "CWE-338  \"math/rand\" imported",
              "CWE-326  tls.Config{ without MinVersion"],
        note="Mostly reviewable-tier: only SQL built by fmt.Sprintf blocks."),
    dict(
        key="c", title="C / C++", scanner="scan_c_cpp",
        ext=[".c", ".cpp", ".cc", ".h", ".hpp"],
        tools=[("cppcheck", "--enable=all. Any error: or warning: line → FAIL (cppcheck:<first>). Not installed → WARN.")],
        fail=["CWE-120  gets, gets_s, strcpy, strcat, sprintf, vsprintf",
              "CWE-78  system, popen, execl / execle / execlp / execv / execve / execvp",
              "CWE-134  printf-family call with argv, getenv, user_input or stdin as the format",
              "CWE-377  tmpnam, tempnam, mktemp (TOCTOU temp file)"],
        warn=["CWE-190  malloc(a * b) — possible integer overflow",
              "CWE-415  two free() calls on one line — possible double free",
              "CWE-338  rand()"],
        note="CERT STR31 / MEM30 / INT30 / ENV33 / FIO45 / MSC30 are the reference points."),
    dict(
        key="rust", title="Rust", scanner="scan_rust",
        ext=[".rs"],
        tools=[("— none —", "Three built-in rules, deliberately small.")],
        fail=["CWE-119  unsafe { block — needs human review",
              "CWE-78  std::process::Command",
              "CWE-798  password / secret / api_key / token assigned a 4+ character literal"],
        warn=[],
        note="Known gap: a build.rs legitimately uses std::process::Command (how pkg-config and cc run), so it over-fires. No build.rs existed on the host to calibrate a better rule."),
    dict(
        key="kotlin", title="Kotlin", scanner="scan_kotlin",
        ext=[".kt", ".kts"],
        tools=[("— none —", "*.gradle.kts is a Gradle build script, not Kotlin source: it goes to the Gradle scanner.")],
        fail=["CWE-78  Runtime.getRuntime().exec(",
              "CWE-798  password / secret / apiKey / api_key / token assigned a 4+ character literal",
              "CWE-327  MessageDigest.getInstance(\"MD5\") or \"SHA-1\""],
        warn=[],
        note="foo.main.kts and other non-Gradle Kotlin scripts still come here."),
    dict(
        key="csharp", title="C#", scanner="scan_csharp",
        ext=[".cs"],
        tools=[("— none —", "Four built-in rules.")],
        fail=["CWE-78  Process.Start(",
              "CWE-798  password / secret / apiKey / api_key / token assigned a 4+ character literal",
              "CWE-327  new MD5CryptoServiceProvider()",
              "CWE-89  a \"SELECT …\" literal followed by + (concatenation)"],
        warn=[],
        note="Only SELECT is matched for SQL concatenation."),
    dict(
        key="shell", title="Shell", scanner="scan_shell",
        ext=[".sh", ".bash", ".zsh", ".ksh"], shebang=["#!…/bash", "#!…/sh", "#!…/zsh", "#!…/ksh", "#!/usr/bin/env bash|sh"],
        tools=[("ShellCheck", "shellcheck -S warning. Any warning → FAIL (shellcheck:warnings). Not installed → WARN.")],
        fail=["CWE-78  curl … | bash / sh and wget … | bash / sh",
              "CWE-88  eval $variable"],
        warn=["CWE-426  export PATH= starting with a relative directory",
              "CWE-377  predictable temp name (/tmp/$$, /tmp/<name>tmp)",
              "IFS manipulation",
              "shellcheck missing"],
        note="Makefile recipes, PowerShell and batch files have their own scanners."),
    dict(
        key="powershell", title="PowerShell", scanner="scan_powershell · scan_powershell_xml",
        ext=[".ps1", ".psm1", ".psd1", ".pssc", ".psrc", ".ps1xml", ".psc1", ".cdxml"], shebang=["#!…pwsh", "#!…powershell"],
        tools=[("— none —", "One shared rule set (_ps_rules). The XML types (.ps1xml .psc1 .cdxml) also get scan_xml's external-entity check.")],
        fail=["Fetch then execute: irm … | iex, DownloadString + iex, or a download piped to a shell",
              "-EncodedCommand and its abbreviations (-enc, -e) followed by a base64 blob",
              "FromBase64String with iex / ScriptBlock::Create / Assembly::Load / VirtualAlloc (whole file)",
              "A backtick inside the command name, an AMSI bypass, Defender disabled",
              "Persistence: Run key, WMI event consumer, Startup folder; socket fed to a shell; VirtualAlloc + CreateThread",
              "A literal $Password, or ConvertTo-SecureString \"…\" -AsPlainText",
              "A plaintext http:// download that is then run"],
        warn=["Invoke-Expression alone (a deliberate relaxation)",
              "Start-Process / cmd /c, an https download then run",
              "Execution-policy bypass, hidden window, Defender exclusion",
              "Scheduled task, certificate validation off, local account creation",
              "ScriptsToProcess in a manifest; wildcard VisibleCmdlets in a role capability"],
        note="Matching is case-insensitive, and so is the extension (UPPER.PS1 used to bypass the scanner). 32 real scripts: 8 FAIL (all false positives) → 0. None of the module, manifest or XML types exists on the host, so those routes rest on fixtures. Legacy .msh is not routed."),
    dict(
        key="batch", title="Windows batch", scanner="scan_bat",
        ext=[".bat", ".cmd"],
        tools=[("— none —", "Works on a normalised view: CR stripped, REM / :: comment lines dropped, ^ continuations joined. Case-insensitive.")],
        fail=["certutil -urlcache, bitsadmin /transfer, a PowerShell DownloadString cradle, curl -k",
              "powershell -enc <base64> (any abbreviation); certutil -decode into an executable",
              "Download then execute on one line; carets inside a command name",
              "A Run / RunOnce / Winlogon / IFEO key, or a file copied into the Startup folder",
              "UAC, Defender or the firewall turned off; a new member of local Administrators",
              "A delete aimed exactly at a drive root or the profile; format; set …PASSWORD=<literal>"],
        warn=["net user /add, schtasks /create, certutil -decode of anything else",
              "Fetch and run in one script; a plaintext http:// download",
              "-ExecutionPolicy Bypass, hidden PowerShell window",
              "mshta / wscript / rundll32 / regsvr32; wmic process call create; a remote UNC path",
              "A command assembled from adjacent %v:~n,1% extractions"],
        note="116 real files, all clean — but they are npm shims, virtualenv and Maven wrappers, with no Windows-native automation, so that says little about recall. .btm and the 4DOS family are not routed."),
    dict(
        key="makefile", title="Makefile", scanner="scan_makefile",
        ext=[".mk", ".mak", ".make"], base=["Makefile*|makefile*|GNUmakefile*"],
        tools=[("— none —", "$(shell …) runs when make merely reads the file, before any target; recipe lines are shell.")],
        fail=["A download piped into a shell; a parse-time fetch $(shell curl …)",
              "A base64-decoded payload executed; a reverse shell",
              "A hardcoded credential (assignments are unquoted, so the universal rule cannot see them)",
              "TLS verification disabled",
              "A setuid / setgid bit; cron or authorized_keys persistence",
              "rm -rf of exactly /, ~ or $HOME"],
        warn=["sudo in a recipe", "chmod 777", "A plaintext http:// download", "Clone-and-build from a remote"],
        note="88 real Makefiles: no finding of any kind. No rule for a bare $(eval …): it fired on 7 of 88 as ordinary metaprogramming."),
    dict(
        key="cmake", title="CMake", scanner="scan_cmake",
        ext=[".cmake"], base=["CMakeLists.txt|CMakeLists.*.txt"],
        tools=[("— none —", "file(DOWNLOAD) and execute_process() run at configure time: cmake . is enough.")],
        fail=["A credential in set(NAME \"value\") — a function call the universal rule cannot see",
              "A plaintext http:// download, or TLS_VERIFY OFF",
              "A download piped into a shell",
              "Hardening removed: -fno-stack-protector, _FORTIFY_SOURCE=0, execstack",
              "file(WRITE …) into /etc, ~/.ssh or cron"],
        warn=["A build step that fetches", "COMMAND sh -c", "install(CODE | SCRIPT)", "GIT_TAG on a moving branch"],
        note="1 of 1116 real files fails: a plaintext archive URL in CMake's own ExternalProject documentation. execute_process appears in 106 of 1116, so it is not a finding by itself."),
    dict(
        key="gradle", title="Gradle", scanner="scan_gradle",
        base=["gradle.properties|gradle-wrapper.properties|*.gradle|*.gradle.kts"],
        tools=[("— none —", "A Gradle script is a program, evaluated in full at configuration time (gradle tasks, --dry-run, an IDE import). settings.gradle runs first.")],
        fail=["Build scripts: apply from 'http(s)://…', allowInsecureProtocol = true",
              "Build scripts: a process started from a literal or list, a ProcessBuilder (matched without new, so Kotlin is covered), Runtime.exec",
              "gradle.properties: a literal *.password / *.secret / *.apiKey",
              "gradle.properties: dependency verification off or lenient; -javaagent / -agentpath in org.gradle.jvmargs",
              "gradle-wrapper.properties: a plaintext distributionUrl"],
        warn=["A configuration-time remote fetch", "exec / commandLine / javaexec", "A trustStore override", "validateDistributionUrl=false"],
        note="6413 real files, 99.6% pass; the 26 FAILs are credentials in Gradle's own docs and tests, one doc snippet, two genuine spawns. A missing distributionSha256Sum is deliberately not reported (20 of 26 omit it). gradle-wrapper.jar is a jar: see Java archives."),
    dict(
        key="manifest", title="Package manifests", scanner="scan_package_json · scan_requirements",
        base=["package.json|composer.json", "requirements*.txt|constraints*.txt"],
        tools=[("trivy · pip-audit · npm audit", "At Layer 3, whole directory: CVEs in the dependencies a manifest names. This slide is about what the manifest itself can run.")],
        fail=["npm: preinstall / install / postinstall (and prepare) that pipe a download into a shell, decode base64, open /dev/tcp or use nc -e",
              "npm: a dependency on http://, git:// or git+http://",
              "Composer: the same hook rules; secure-http false; an http:// repository",
              "pip: an index, -f or requirement over http:// or git://; credentials embedded in a URL"],
        warn=["An install-time hook being present", "A non-lifecycle script that pipes or fetches",
              "A git or tarball dependency", "--trusted-host; --extra-index-url (dependency confusion)",
              "A VCS requirement not pinned to a commit"],
        note="JSON is parsed, not grepped: \"post\\u0069nstall\" is postinstall to npm. Calibration is weak: 0 of 1193 real package.json fail, but they are mostly published packages. Lockfiles, go.mod and meson_options.txt are not covered."),
    dict(
        key="xml", title="XML, Maven and Ant", scanner="scan_xml",
        ext=[".xml", ".pom"],
        tools=[("— none —", "Matches on a newline-folded, comment-stripped view. pom.xml and build.xml get Maven / Ant rules by name.")],
        fail=["XXE: <!ENTITY … SYSTEM pointing at file:, expect:, php:, gopher:, jar:, netdoc:, ftp:, http(s): or an absolute path",
              "An entity expansion bomb: 4+ named references in one entity value",
              "A credential in <password> / <token> / <secret> / <apiKey> / <privateKey> with a 6+ character literal",
              "Maven: a <repository> whose <url> is http://; exec-maven-plugin / antrun running sh, bash, cmd, powershell, curl, wget",
              "Ant: <get> over http://; <exec> of a shell or downloader; <sshexec> / <scp> with a literal password="],
        warn=["A relative SYSTEM include (DocBook) or a PUBLIC DTD reference", "The exec or antrun plugin being present; system scope", "Any Ant <exec>"],
        note="A bare <!DOCTYPE failed 736 of 3362 real XML files, so it is no longer a rule: 0 of 3362 fail now. The Ant half rests on only 22 real files. No -SNAPSHOT rule (176 of 221 real poms use one)."),
    dict(
        key="yaml", title="YAML / CI / Kubernetes", scanner="scan_yaml",
        ext=[".yml", ".yaml"],
        tools=[("— none per file —", "checkov covers Terraform, not YAML; Semgrep runs at Layer 2.")],
        fail=["OWASP A08  uses: owner/action with no @ref — an unpinned GitHub Action",
              "CWE-798  password / secret / token / key / api_key: followed by a literal",
              "OWASP A05  privileged: true",
              "OWASP A05  hostNetwork / hostPID / hostIPC: true"],
        warn=["CWE-94  {{ request.… / user.… / .env.… }} — possible template injection"],
        note="Known weak spot: the bare key: rule flags about 7% of real YAML files."),
    dict(
        key="terraform", title="Terraform / HCL", scanner="scan_terraform",
        ext=[".tf", ".tfvars", ".hcl"],
        tools=[("checkov", "checkov -f --quiet (--skip-download when offline). Any failed check → FAIL (checkov:N_CIS_IaC_findings). Not installed → WARN.")],
        fail=["CWE-798  password / secret / token = \"…\"",
              "OWASP A05  acl = \"public-read\" (S3)",
              "OWASP A02  encrypted = false"],
        warn=["OWASP A05  cidr_blocks = [\"0.0.0.0/0\"]"],
        note="Offline, checkov must be pointed at staged data or it silently contributes nothing."),
    dict(
        key="docker", title="Dockerfile", scanner="scan_docker",
        base=["Dockerfile*"],
        tools=[("hadolint", "Any lint issue → FAIL (hadolint:dockerfile_issue). Not installed → WARN.")],
        fail=["OWASP A05  a :latest base image",
              "CWE-494  ADD of an http(s):// URL — no integrity check",
              "CWE-78  RUN curl | bash or wget | sh",
              "CWE-798  ENV PASSWORD / SECRET / TOKEN / API_KEY / PRIVATE_KEY baked into a layer"],
        warn=["CWE-250  no non-root USER directive"],
        note="Matched by basename: Dockerfile.dev and Dockerfile.prod count."),
    dict(
        key="html", title="HTML", scanner="scan_html",
        ext=[".html", ".htm", ".xhtml"],
        tools=[("— none —", "Inline <script> is ordinary, so every rule targets a construct with no innocent reading. Each was counted on 388 real files.")],
        fail=["eval(); a percent-encoded payload in unescape(); document.write() fed from a decoder",
              "<script src=\"http://…\">; <base href=\"http://\">; <form action=\"http://\">",
              "A hidden iframe: display:none, visibility:hidden, zero width or height",
              "A credential in a name / value attribute pair or a <meta content>",
              "A cookie read wired to a network sink (matched in both orders)"],
        warn=["innerHTML / outerHTML / insertAdjacentHTML", "new Function(; a bare atob(",
              "A protocol-relative <script src=\"//…\">", "An external meta refresh; a javascript: URI"],
        note="2 of 388 real files fail: both genuine eval() calls in the bundled Go trace viewer (vendoring it needs a .transit-allow.json entry). build/, dist/, coverage/ and node_modules/ are pruned first."),
    dict(
        key="pdf", title="PDF", scanner="scan_pdf",
        ext=[".pdf"],
        tools=[("— stdlib decoder —", "Decodes Flate, LZW, ASCIIHex, ASCII85 and RunLength filter chains (64 MB ceiling) and #xx name escapes; two views, so prose cannot fire a key rule.")],
        fail=["CWE-94  /JavaScript, /JS, /OpenAction, /AA — also hex-escaped (/J#61vaScript) and inside compressed object streams",
              "CWE-78  /Launch",
              "CWE-506  /EmbeddedFile, or an embedded Windows executable",
              "Rich media; /SubmitForm, /ImportData",
              "Known exploit APIs (util.printf, collab.getIcon, media.newPlayer …) and unescape shellcode shapes"],
        warn=["Encrypted (/Encrypt) — reported, not decrypted", "A stream behind an undecodable filter, named",
              "XFA forms; remote or embedded destinations (/GoToR, /GoToE)", "Incremental updates (several %%EOF)"],
        note="The five PDFs this project ships are the acceptance test: scan them and expect PASS with no finding. Image filters are excluded — they carry pixels, never dictionaries."),
    dict(
        key="sql", title="SQL", scanner="scan_sql",
        ext=[".sql"],
        tools=[("— none —", "Four built-in rules.")],
        fail=["CWE-78  xp_cmdshell, sp_OACreate, OPENROWSET, BULK INSERT",
              "CWE-89  DROP TABLE / DATABASE / SCHEMA / VIEW / FUNCTION / PROCEDURE",
              "CWE-89  injection patterns: ; --, '--, OR 1=1, AND 1=1",
              "CWE-89  UNION [ALL] SELECT"],
        warn=[],
        note="A migration that legitimately drops a table fails: use .transit-allow.json."),
    dict(
        key="json", title="JSON", scanner="classify_file (inline rule)",
        ext=[".json"],
        tools=[("— none —", "One built-in rule. package.json and composer.json are routed to the manifest scanner by name.")],
        fail=["CWE-798  \"password\" / \"secret\" / \"token\" / \"api_key\" / \"private_key\": \"<4+ character literal>\""],
        warn=[],
        note="After the bracket-expression fix this rule sees values containing an \"s\": 12 of 2252 real JSON files flag (9 before)."),
    dict(
        key="docs", title="Documentation and text", scanner="classify_file (inline rule)",
        ext=[".md", ".txt", ".rst"],
        tools=[("— none —", "One built-in rule. CMakeLists.txt and requirements*.txt end in .txt but are routed by name first.")],
        fail=["CWE-798  password / secret / api_key followed by : or = and a literal value"],
        warn=[],
        note="A README that quotes an attack string (a credential or a traversal example) fails: INSTALL.md and CLAUDE.md of this project do. That is what .transit-allow.json is for."),
    dict(
        key="binary", title="Native binaries", scanner="scan_binary",
        ext=[".so", ".dll", ".dylib", ".exe", ".elf", ".bin"],
        tools=[("strings", "Extracts readable strings and looks for http://, https://, /etc/passwd, /bin/sh, exec, shell, reverse, c2server.")],
        fail=["binary:unexpected_binary_in_AI_repo — EVERY file of these types, whatever it contains",
              "binary:IOC_strings_detected — in addition, when the strings search hits"],
        warn=[],
        note=".bin is blocked, not analysed: a harmless weights file fails exactly like an ELF, while the same pickle named .pkl or .pt passes (see Unknown extensions). Content-based routing would fix both."),
    dict(
        key="archive", title="Archives", scanner="scan_archive",
        ext=[".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz"],
        tools=[("unzip -l", ".zip only: lists the entries and looks for '..' in a path.")],
        fail=["archive:requires_dedicated_rescan — EVERY archive",
              "CWE-22  a .zip entry whose path contains '..' (zip-slip)"],
        warn=[],
        note="An archive is not opened: it must be extracted in an isolated environment and rescanned. Java archives are the exception (next slide)."),
    dict(
        key="jar", title="Java archives", scanner="scan_jar",
        ext=[".jar", ".war", ".ear", ".aar"],
        tools=[("stdlib zipfile helper", "Opened in place, never extracted. Reads entries like the JVM does; bounded by entry, byte, text, size, time and depth limits — each one reached is reported.")],
        fail=["Zip-slip: a path with .., a leading / or a drive letter; a symlink out of the archive; a local record the central directory does not list",
              "A .class that is not bytecode; a PE / ELF / Mach-O under a non-native name or glued in front of the archive",
              "A manifest Class-Path naming an http(s):// or ftp:// jar",
              "curl | sh, a reverse shell, encoded PowerShell, certutil -urlcache — in a resource, UTF-16 text, a class constant or attribute",
              "A PEM private key at any line width; any of the 18 known credential formats",
              "gradle-wrapper.jar / maven-wrapper.jar with entries outside the expected tree or no main class"],
        warn=["EVERY jar: its bytecode is not reviewed, so a clean jar still warns",
              "Java agents; native libraries; scripts; nested archives; symlinks; duplicate names",
              "Encrypted or unreadable entries; any limit reached (inspection_incomplete)",
              "Every wrapper jar: verify its SHA-256 yourself"],
        note="365 real jars: one FAIL, a genuine embedded test key. .war / .ear / .aar are routed but unmeasured. Bytecode is not decompiled. A jar under build/, dist/, target/ or vendor/ is pruned and never scanned."),
]

# What a file that matches nothing above goes through (scan_unknown).
UNKNOWN_SHEBANG = [
    ("#!…python", "scan_python"), ("#!…/bash, /sh, /zsh, /ksh, env bash|sh", "scan_shell"),
    ("#!…ruby", "scan_ruby"), ("#!…node", "scan_javascript"),
    ("#!…php", "scan_php"), ("#!…pwsh, powershell", "scan_powershell"),
]

LAYERS = [
    ("L1", "Global", "Whole directory", "betterleaks · detect-secrets · ClamAV · YARA"),
    ("L2", "Semgrep", "Whole directory", "p/owasp-top-ten · p/cwe-top-25 · p/security-audit · p/secrets"),
    ("L3", "Dependencies", "Manifests", "trivy · pip-audit · safety · npm audit"),
    ("L4", "Universal patterns", "EVERY file", "Credentials · 18 known token formats · PEM keys · traversal · SSRF · weak crypto / PRNG"),
    ("L5", "Per-type scanner", "By type", "One slide per type in this deck"),
    ("L6", "ScanCode", "Whole directory", "Licences (GPL / AGPL / LGPL / SSPL / BUSL → WARN) · CVE HIGH / CRITICAL → FAIL"),
]


# ── Drift guard ───────────────────────────────────────────────────────────────
def routed_patterns() -> tuple[set[str], set[str]]:
    """(extension patterns, basename patterns) as classify_file's two case statements list them."""
    src = open(SCANNER, encoding="utf-8").read()
    body = src[src.index("classify_file() {"):]
    body = body[:body.index("\n}\n")]

    def labels(block: str) -> list[str]:
        out = []
        for ln in block.splitlines():
            m = re.match(r"\s*([^\s#][^)]*)\)", ln)
            if m and not ln.strip().startswith("*)"):
                out.append(m.group(1).strip())
        return out

    b0 = body.index('case "$base" in')
    b1 = body.index("esac", b0)
    base = labels(body[b0 + len('case "$base" in'):b1])
    e0 = body.index('case ".$ext" in')
    e1 = body.index("\n    esac", e0)
    ext_block = body[e0 + len('case ".$ext" in'):e1]
    exts: list[str] = []
    for lab in labels(ext_block):
        exts.extend(p.strip() for p in lab.split("|") if p.strip().startswith("."))
    return set(exts), set(base)


def deck_patterns() -> tuple[set[str], set[str]]:
    exts: set[str] = set()
    base: set[str] = set()
    for f in FAMILIES:
        exts.update(f.get("ext", []))
        base.update(f.get("base", []))
    return exts, base


def check() -> int:
    code_ext, code_base = routed_patterns()
    deck_ext, deck_base = deck_patterns()
    bad = False
    for label, a, b in (("extension", code_ext, deck_ext), ("basename pattern", code_base, deck_base)):
        for x in sorted(a - b):
            print(f"routed in scan_pipeline.sh but missing from the deck: {label} {x}")
            bad = True
        for x in sorted(b - a):
            print(f"in the deck but not routed in scan_pipeline.sh: {label} {x}")
            bad = True
    if not bad:
        print(f"deck matches classify_file: {len(deck_ext)} extensions, {len(deck_base)} basename patterns, {len(FAMILIES)} scanner slides")
    return 1 if bad else 0


# ── Rendering ─────────────────────────────────────────────────────────────────
def render() -> None:
    from reportlab.lib.colors import HexColor
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfgen import canvas
    import pdf_theme

    pdf_theme.register_fonts()
    F, FB, FM, FMB = pdf_theme.FONT_BODY, pdf_theme.FONT_BOLD, pdf_theme.FONT_MONO, pdf_theme.FONT_MONO_BOLD

    W, H = 1333, 750
    BG, CARD = HexColor("#FFFFFF"), HexColor("#EEF2F8")
    ACCENT, DARK, INK, GRAY = HexColor("#00A8FF"), HexColor("#1F3864"), HexColor("#2C3E50"), HexColor("#6B7886")
    RED, RED_BG = HexColor("#B3261E"), HexColor("#FDECEC")
    AMB, AMB_BG = HexColor("#8A5A00"), HexColor("#FEF4E0")
    GRN, GRN_BG = HexColor("#1A7A40"), HexColor("#E8F8EE")
    BLU, BLU_BG = HexColor("#0070A8"), HexColor("#E6F2FA")
    LAYER_C = {"L1": "#0F6FA8", "L2": "#7D3C98", "L3": "#0E7C7B", "L4": "#B45309", "L5": "#2E7D32", "L6": "#9A7B0A"}
    EDGE = HexColor("#D0DAE8")

    cv = canvas.Canvas(OUT, pagesize=(W, H))
    cv.setTitle("AI Transit Pipeline — what is scanned, per file type")
    cv.setAuthor("AI Transit Pipeline")
    page = {"n": 0}

    def rect(x, y, w, h, fill, stroke=None, r=0):
        cv.setFillColor(fill)
        cv.setStrokeColor(stroke or fill)
        cv.setLineWidth(0.8 if stroke else 0)
        (cv.roundRect(x, y, w, h, r, fill=1, stroke=1 if stroke else 0) if r
         else cv.rect(x, y, w, h, fill=1, stroke=1 if stroke else 0))

    def txt(s, x, y, size=12, font=None, color=INK, align="left"):
        cv.setFillColor(color)
        cv.setFont(font or F, size)
        {"left": cv.drawString, "right": cv.drawRightString, "center": cv.drawCentredString}[align](x, y, s)

    def frame(title, subtitle=None, badge=None):
        page["n"] += 1
        rect(0, 0, W, H, BG)
        rect(0, H - 84, W, 84, DARK)
        txt(title, 36, H - 54, 30, FB, HexColor("#FFFFFF"))
        if badge:
            bw = cv.stringWidth(badge, FMB, 14) + 28
            rect(W - 36 - bw, H - 62, bw, 32, HexColor("#0F6FA8"), r=6)
            txt(badge, W - 36 - bw / 2, H - 52, 14, FMB, HexColor("#FFFFFF"), "center")
        cv.setStrokeColor(ACCENT)
        cv.setLineWidth(1.5)
        cv.line(30, H - 87, W - 30, H - 87)
        if subtitle:
            txt(subtitle, 36, H - 112, 14, F, GRAY)
        txt("AI Transit Pipeline — file types", 36, 18, 9, F, GRAY)
        txt(str(page["n"]), W - 36, 18, 9, FB, GRAY, "right")

    def fit(items, width, height, size_max=16.0, size_min=9.5, gap=7):
        """Largest font size at which the bullets fit; raise rather than clip."""
        s = size_max
        while s >= size_min - 1e-9:
            used = 0.0
            wide = False
            for it in items:
                lines = simpleSplit(it, F, s, width - 16)
                # simpleSplit cannot break inside a word, so a long token (a rule
                # identifier, a path) would run out of its card: count that as not fitting.
                wide = wide or any(cv.stringWidth(ln, F, s) > width - 16 for ln in lines)
                used += len(lines) * s * 1.28 + gap
            if used <= height and not wide:
                return s
            s -= 0.5
        raise SystemExit(f"slide text does not fit ({len(items)} bullets in {width:.0f}x{height:.0f}pt): shorten it: {items[0][:60]}")

    def bullets(items, x, top, width, height, color=INK, mark="•", markcolor=None, size_max=16.0):
        if not items:
            return
        s = fit(items, width, height, size_max)
        y = top
        for it in items:
            lines = simpleSplit(it, F, s, width - 16)
            cv.setFillColor(markcolor or color)
            cv.setFont(FB, s)
            cv.drawString(x, y - s, mark)
            cv.setFillColor(color)
            cv.setFont(F, s)
            for i, ln in enumerate(lines):
                cv.drawString(x + 16, y - s - i * s * 1.28, ln)
            y -= len(lines) * s * 1.28 + 7

    def column(x, w, head, items, fg, bg, top, bottom, empty="No rule in this tier"):
        rect(x, bottom, w, top - bottom, bg, EDGE, 8)
        txt(head, x + 14, top - 24, 13, FB, fg)
        if items:
            bullets(items, x + 14, top - 36, w - 28, top - bottom - 48, INK, "•", fg)
        else:
            txt(empty, x + 14, top - 54, 12, F, GRAY)

    def chips(items, x, y, size=13, fill=BLU_BG, fg=BLU, maxx=None):
        for it in items:
            w = cv.stringWidth(it, FMB, size) + 20
            if maxx and x + w > maxx:
                break
            rect(x, y - 7, w, size + 14, fill, EDGE, 5)
            txt(it, x + 10, y, size, FMB, fg)
            x += w + 8
        return x

    EVERY = ("Also applied to every file: L1 betterleaks · detect-secrets · ClamAV · YARA   |   L2 Semgrep   |   "
             "L4 universal patterns (credentials, key material, traversal, SSRF, weak crypto)   |   L6 ScanCode")

    # ── slide numbers are needed by the index before the slides exist ─────────
    first_family_page = 4
    page_of = {f["key"]: first_family_page + i for i, f in enumerate(FAMILIES)}
    unknown_page = first_family_page + len(FAMILIES)

    # 1. Title
    page["n"] += 1
    rect(0, 0, W, H, DARK)
    txt("What the AI Transit Pipeline checks,", 80, H - 270, 44, FB, HexColor("#FFFFFF"))
    txt("file type by file type", 80, H - 328, 44, FB, HexColor("#7FD3FF"))
    txt(f"{len(FAMILIES)} scanner slides covering every extension the pipeline routes, and one on unknown extensions.", 80, H - 390, 18, F, HexColor("#D5E3F5"))
    txt("Each slide: the extensions · the tools that run · the rules that FAIL · the rules that only WARN · the known limits.", 80, H - 424, 15, F, HexColor("#AFC4DE"))
    txt("Source of truth: classify_file() in scan_pipeline.sh. python3 build_pdf_filetypes.py --check fails if this deck drifts from it.", 80, 60, 12, F, HexColor("#8EA6C4"))
    cv.showPage()

    # 2. What every file gets
    frame("What every file gets", "Layer 5 is the part that varies by type. The other layers do not look at the extension.")
    y = H - 160
    for code, name, scope, what in LAYERS:
        rect(36, y - 64, W - 72, 74, CARD, EDGE, 8)
        rect(36, y - 64, 8, 74, HexColor(LAYER_C[code]))
        txt(code, 64, y - 20, 22, FB, HexColor(LAYER_C[code]))
        txt(name, 130, y - 20, 17, FB, DARK)
        txt(scope, 130, y - 44, 13, F, GRAY)
        txt(what, 430, y - 32, 14, F, INK)
        y -= 90
    txt("WARN = logged, the pipeline continues.  FAIL = the repository is quarantined and no ZIP is produced.  .transit-allow.json downgrades a named FAIL to WARN; .transitignore removes a file from every scan.",
        36, 52, 11, F, GRAY)
    cv.showPage()

    # 3. Routing
    frame("How a file is routed", "classify_file() decides in this order; the first match wins.")
    steps = [
        ("0", "Excluded?", ".transitignore patterns and the default pruned directories (node_modules, .git, vendor, dist, build, target, coverage …) never reach a scanner."),
        ("1", "Basename", "Dockerfile*, Makefile*, CMakeLists.txt, package.json, composer.json, requirements*.txt, constraints*.txt, *.gradle, *.gradle.kts, gradle*.properties, setup.py, conanfile.py."),
        ("2", "Extension", "Lower-cased first, so .PS1 and .JAR are treated like .ps1 and .jar. One slide per family in this deck."),
        ("3", "Shebang", "No known extension: the first line decides — python, bash / sh / zsh / ksh, ruby, node, php, pwsh / powershell."),
        ("4", "MIME type", "Still nothing: file --mime-type. An executable type (x-executable, x-sharedlib, x-dosexec) → FAIL."),
        ("5", "Default", "Anything else passes Layer 5 untouched. See \"Unknown extensions\"."),
    ]
    y = H - 160
    for n, head, body in steps:
        rect(36, y - 66, W - 72, 74, CARD, EDGE, 8)
        rect(52, y - 52, 44, 44, DARK, r=22)
        txt(n, 74, y - 40, 22, FB, HexColor("#FFFFFF"), "center")
        txt(head, 118, y - 26, 18, FB, DARK)
        for i, ln in enumerate(simpleSplit(body, F, 13, W - 72 - 300)):
            txt(ln, 330, y - 22 - i * 17, 13, F, INK)
        y -= 90
    cv.showPage()

    # 4+. one slide per scanner family
    for f in FAMILIES:
        assert page["n"] + 1 == page_of[f["key"]]
        frame(f["title"], None, f["scanner"])
        routes = list(f.get("ext", [])) + [b.replace("|", "  ") for b in f.get("base", [])]
        x = chips(routes, 36, H - 118, 14, maxx=W - 36)
        if f.get("shebang"):
            txt("also by shebang: " + "  ".join(f["shebang"]), 36, H - 150, 11, F, GRAY)
        top, bottom = H - 168, 112
        wt, wf, ww = 330, 560, W - 72 - 330 - 560 - 40
        # tools
        rect(36, bottom, wt, top - bottom, BLU_BG, EDGE, 8)
        txt("TOOLS APPLIED", 50, top - 24, 13, FB, BLU)
        yy = top - 42
        for name, how in f["tools"]:
            for ln in simpleSplit(name, FB, 15, wt - 28):
                txt(ln, 50, yy - 12, 15, FB, DARK)
                yy -= 20
            sz = 13.5
            for ln in simpleSplit(how, F, sz, wt - 28):
                txt(ln, 50, yy - 10, sz, F, INK)
                yy -= sz * 1.3
            yy -= 8
        if yy < bottom + 14:
            raise SystemExit(f"tools text overflows on slide {f['title']}")
        for name, how in f["tools"]:
            for t_, fnt, sz_ in ((name, FB, 15), (how, F, 13.5)):
                if any(cv.stringWidth(w, fnt, sz_) > wt - 28 for w in t_.split()):
                    raise SystemExit(f"an unbreakable word runs out of the tools card on slide {f['title']}: {t_[:50]}")
        column(36 + wt + 20, wf, "FAIL — blocks the repository", f["fail"], RED, RED_BG, top, bottom)
        column(36 + wt + 20 + wf + 20, ww, "WARN — reported, does not block", f["warn"], AMB, AMB_BG, top, bottom,
               empty="No reviewable tier: every rule here blocks.")
        # note
        rect(36, 52, W - 72, 48, CARD, EDGE, 6)
        nl = simpleSplit("Note: " + f["note"], F, 11, W - 72 - 24)
        if len(nl) > 2 or any(cv.stringWidth(ln, F, 11) > W - 72 - 24 for ln in nl):
            raise SystemExit(f"note too long on slide {f['title']} ({len(nl)} lines)")
        for i, ln in enumerate(nl):
            txt(ln, 48, 86 - i * 15, 11, F, INK)
        txt(EVERY, 36, 38, 8.5, F, GRAY)
        cv.showPage()

    # unknown extensions
    assert page["n"] + 1 == unknown_page
    frame("Unknown extensions — what is allowed", "Anything not routed above. It is not skipped: it still passes every layer except Layer 5.")
    top, bottom = H - 130, 62
    col_w = (W - 72 - 40) / 3
    # col 1: routing of an unknown file
    rect(36, bottom, col_w, top - bottom, BLU_BG, EDGE, 8)
    txt("HOW IT IS HANDLED", 50, top - 24, 13, FB, BLU)
    yy = top - 44
    for lab, tgt in UNKNOWN_SHEBANG:
        txt(lab, 50, yy, 11.5, FM, DARK)
        txt("→ " + tgt, 50 + col_w - 28, yy, 11.5, FMB, GRN, "right")
        yy -= 20
    yy -= 8
    body1 = ["No shebang: file --mime-type. x-executable, x-sharedlib or x-dosexec → FAIL (binary:unexpected_executable_mime).",
             "Any other type → PASS. That is \"allowed\".",
             "If the file command is not installed the MIME check is skipped and the file passes."]
    bullets(body1, 50, yy, col_w - 28, yy - bottom - 12, INK, "•", BLU, 14)
    # col 2: what still applies
    x2 = 36 + col_w + 20
    rect(x2, bottom, col_w, top - bottom, GRN_BG, EDGE, 8)
    txt("STILL APPLIED", x2 + 14, top - 24, 13, FB, GRN)
    bullets(["L1  betterleaks, detect-secrets, ClamAV and YARA — whole directory",
             "L2  Semgrep rulesets — whole directory",
             "L4  universal patterns on this very file: hardcoded credentials, the 18 known token formats, PEM private keys, path traversal in three contexts, SSRF, weak crypto and PRNG, debug artefacts, logging suppression",
             "L6  ScanCode licences and CVEs",
             "Examples that land here: .png .jpg .csv .toml .ini .cfg .conf .lock .env .svg .proto .safetensors"],
            x2 + 14, top - 36, col_w - 28, top - bottom - 48, INK, "•", GRN, 14)
    # col 3: what is NOT checked
    x3 = x2 + col_w + 20
    rect(x3, bottom, col_w, top - bottom, AMB_BG, EDGE, 8)
    txt("WHAT PASSES UNEXAMINED", x3 + 14, top - 24, 13, FB, AMB)
    bullets(["Source in a language with no scanner: Perl, Lua, VBScript, Groovy (outside Gradle), Scala, Swift, Dart, Elixir … — no per-language rule runs, only Layer 4.",
             "Pickled models and weights: .pkl .pickle .pt .pth .ckpt .joblib. A pickle that runs os.system PASSED when tested; loading one executes it.",
             "A .bin pickle is the opposite case: blocked with every other .bin, harmlessly or not.",
             "Content disguised by name: a script saved as .txt gets only the document rule.",
             "Remedy for a legitimate file: .transit-allow.json (FAIL → WARN, with a reason) or .transitignore."],
            x3 + 14, top - 36, col_w - 28, top - bottom - 48, INK, "•", AMB, 14)
    cv.showPage()

    # index
    frame("Index — every routed extension and basename", "Extension → slide number.")
    entries = []
    for f in FAMILIES:
        for e in f.get("ext", []):
            entries.append((e, page_of[f["key"]]))
        for b in f.get("base", []):
            for pat in b.split("|"):
                entries.append((pat, page_of[f["key"]]))
    entries.sort(key=lambda t: t[0].lower())
    cols = 5
    per = -(-len(entries) // cols)
    cw = (W - 72) / cols
    for i, (e, pg) in enumerate(entries):
        c, r = divmod(i, per)
        x, y = 36 + c * cw, H - 150 - r * 24
        txt(e, x, y, 12, FMB, DARK)
        txt(f"p. {pg}", x + cw - 30, y, 12, F, GRAY, "right")
    txt("Unknown extensions: p. %d" % unknown_page, 36, 40, 12, FB, AMB)
    cv.showPage()

    cv.save()
    print(f"wrote {OUT} ({page['n']} slides)")


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check())
    rc = check()
    if rc:
        sys.exit(rc)
    render()
