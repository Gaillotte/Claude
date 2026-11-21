# File types the pipeline does not scan

What a file gets depends on its **extension, its name and (when it has no known extension) its first line**. This
page lists the types that no scanner understands, what still covers them, and how that was checked.

> **A file no scanner understands now FAILS, always** (`unscanned:no_scanner_for_this_file_type`, HIGH). Sections 4.2,
> 4.4 and 4.5 below used to PASS; they are the types that fail. The finding is a hard FAIL: the repository's own
> `.transit-allow.json` and `--min-severity` cannot lower it. Exception: the pipeline's own root `.transitignore`.
> Files that are never classified (section 4.1) do not fail here. Details: `CLAUDE.md`, "Files no scanner understands fail".

Source of truth: `classify_file` and `scan_unknown` in `scan_pipeline.sh` and `scan_pipeline.py` / `transit/scan_docs.py`
(`_BASENAME_RULES`, `_EXT_RULES`, `shebang_scanner` in `transit/core.py`, `DEFAULT_EXCLUDE_DIRS`). Regenerate the routed list with
the snippet at the end.

## 1. How a file is classified

```
every file  ──►  universal pattern rules (layer 4)            credentials, key material, path traversal ...
            ──►  basename?   Dockerfile*, Makefile*, package.json ...     → that scanner, stop
            ──►  extension?  one of the 109 routed extensions             → that scanner, stop
            ──►  .md .txt .rst                                            → documentation rules (+ RTF sniff)
            ──►  anything else: first line `#!` for python, ruby, node, php, pwsh or a shell
                                                                          → that language scanner
                                otherwise `scan_unknown`: MIME check for a native executable, then FAIL (unscanned)
```

The extension is compared in lower case. Names are matched before extensions (`Makefile.so` is a Makefile).

## 2. What is scanned per type (the routed set: 109 extensions and 7 name-pattern groups, 16 patterns in all)

| Scanner | Extensions / names |
|---|---|
| Python | `.py` |
| JavaScript / TypeScript | `.js .ts .jsx .tsx .mjs .cjs` |
| Java, PHP, Ruby, Go, Rust, C# | `.java` · `.php` · `.rb` · `.go` · `.rs` · `.cs` |
| Kotlin | `.kt .kts` (but `*.gradle.kts` goes to Gradle) |
| C / C++ | `.c .cpp .h .hpp .cc` |
| Shell | `.sh .bash .zsh .ksh` |
| PowerShell | `.ps1 .psm1 .psd1 .pssc .psrc` and `.ps1xml .psc1 .cdxml` |
| Windows batch | `.bat .cmd` |
| YAML, Terraform | `.yml .yaml` · `.tf .tfvars .hcl` |
| JSON, SQL | `.json` · `.sql` (shallow, see section 4) |
| XML, Maven, Ant | `.xml .pom` |
| HTML | `.html .htm .xhtml` |
| Make, CMake | `.mk .mak .make` and `Makefile*`, `makefile*`, `GNUmakefile*` · `.cmake`, `CMakeLists.txt` |
| Gradle | `*.gradle`, `*.gradle.kts`, `gradle.properties`, `gradle-wrapper.properties` |
| Dockerfile | `Dockerfile*` |
| Package manifests | `package.json`, `composer.json`, `requirements*.txt`, `constraints*.txt` |
| Install-time Python | `setup.py`, `conanfile.py` |
| Binaries | `.so .dll .dylib .exe .elf .bin` (always a FAIL) |
| Archives | `.zip .tar .gz .tgz .bz2 .xz` (always a FAIL: "requires dedicated rescan") |
| Java archives | `.jar .war .ear .aar` |
| Office documents | OOXML, OpenDocument (also flat), legacy OLE2, `.rtf` (39 extensions) |
| PDF | `.pdf` |
| Documentation | `.md .txt .rst` |

## 3. What covers every file, scanned or not

- **Universal pattern rules (layer 4)** on every file, binary included: hard-coded credentials, 18 known token formats, PEM
  private keys, encoded path traversal, a few others.
- **Native-executable sweep** on every file except the top-level `.git/objects`: a real ELF, PE or Mach-O at any offset,
  or encoded (see `CLAUDE.md`, "Native executables by content"). It also reads the skipped directories of section 4.1.
- **Whole-directory tools, if installed:** gitleaks, detect-secrets, ClamAV, YARA, Semgrep (layer 2). Semgrep has its own
  idea of which languages it understands; that was **not measured here** (none of these tools is installed on the test
  host except ShellCheck). ScanCode (layer 6) and the dependency scanners (layer 3) are off by default.

## 4. What is not scanned, by category

### 4.1 Never opened by the per-file scanners (these do not fail as unscanned: they are never classified)

| What | Detail |
|---|---|
| Skipped directories | `node_modules .git vendor .tox __pycache__ .venv venv dist build .next .nuxt .cache target coverage` (matched below the scan root, directories only) |
| `.transitignore` patterns | the files and directories listed in it |
| Diff mode (`--since`) | every file not changed since that commit |
| Symbolic links | not followed; a link that leaves the scanned directory is a FAIL, any other a WARN |

Only section 3 reaches these. The approved archive contains the skipped directories, which is why the native sweep reads them.

### 4.2 Opened, but no scanner for the type (`scan_unknown`, then **FAIL**)

| Group | Examples |
|---|---|
| Source languages | Perl `.pl .pm`, Lua `.lua`, Swift, Dart, Scala, R, Julia, Haskell, OCaml, Elixir, Erlang, Clojure, Objective-C `.m`, Zig, Nim, Fortran, assembly `.s .asm`, `.vue`, `.svelte` |
| Config and markup | `.toml .ini .conf .cfg .env .properties .plist`, systemd `.service .timer`, `.css .scss`, `.svg`, `.xsl .xsd`, `.graphql .proto`, `.m4`, `.in` |
| Data and notebooks | `.ipynb`, `.jsonl .ndjson`, `.csv .tsv`, `.patch .diff`, `.map`, `.lock` |
| Keys and certificates | `.pem .crt .key .p12` (private keys are still found by the universal rule) |
| Scripts without a routed interpreter | a Perl, Lua, awk, tcl or fish script without an extension (shebang routing covers only python, ruby, node, php, pwsh/powershell, bash, sh, zsh, ksh) |
| Launchers | `.lnk .url .hta .vbs .wsf .reg .inf .desktop .scpt`, `.btm`, `.msh*` |
| Office-adjacent | `.one .pub .vsd .msg`; `.csv .tsv .slk` formula injection |
| Dependency data | `go.mod`, `go.sum`, `yarn.lock`, Gradle version catalogs (`libs.versions.toml`) |

### 4.3 Opened by a shallow scanner only

`.json`, `.sql`, `.yml/.yaml`, `.md/.txt/.rst`: credential-style rules and a few patterns, not a parse of the format.
`package-lock.json` is `.json`, so it gets the JSON credential rule and nothing about its dependency data.

### 4.4 Containers that are not opened

`.whl .egg .nupkg .apk .ipa .vsix .xpi .crx .epub .7z .rar .zst .cab .iso .msi .rpm .deb .a`. They fail as unscanned,
unopened; a native file stored uncompressed inside one may still be seen by the native sweep, one stored compressed is not.
A valid PDF, zip, jar or Office document with a payload appended or stored inside keeps its own scanner's verdict.

### 4.5 Binary data with no format parsing

| Group | Examples |
|---|---|
| Machine-learning artefacts | `.pkl .pickle .pt .pth .ckpt .h5 .onnx .safetensors .npy .npz` — a pickle can execute code when it is loaded; nothing here inspects one |
| Media | `.png .jpg .jpeg .gif .webp .ico .mp3 .mp4 .wav .ttf .woff .woff2` |
| Databases and tables | `.sqlite .db .parquet` |
| Bytecode | `.class .pyc .wasm .dex` (flagged only by name or by the native sweep, never analysed) |

## 5. Evidence

### 5.1 Hostile content in unrouted types, before the rule existed (this host, Python engine)

| File | Content | Result |
|---|---|---|
| `evil.pl` | Perl reverse shell (`IO::Socket`, `exec("/bin/sh -i")`) | PASS, nothing flagged |
| `evil.lua` | `os.execute("curl … \| sh")` | PASS, nothing flagged |
| `evil.svg` | `<script>eval(atob("…"))</script>` | PASS, nothing flagged |
| `evil.service` | `curl … \| sh` | PASS, nothing flagged |
| `evil.swift` | `Process()` launching `/bin/sh -c "curl … \| sh"` | PASS, nothing flagged |
| `noext_perl` | `#!/usr/bin/perl` + `system("curl … \| sh")` | PASS, nothing flagged |
| `secret.toml` | `password = "hunter2hunter2"` | **FAIL**, `CWE-798:hardcoded_credential` (universal rule) |

### 5.2 How much of a real tree is unrouted

`/usr /opt /root /var /home` of the test host: **67,610 of 171,428 files (39%)** have no per-type scanner. A Linux system
tree is not an AI-generated repository (it is full of `.pyi`, `.pyc`, `.svg`, man pages and package metadata), so read the
number as an order of magnitude. The most common unrouted extensions:

| Extension | Files | MB | | Extension | Files | MB |
|---|---:|---:|---|---|---:|---:|
| (no extension) | 14,571 | 3,706 | | `.png` | 645 | 4.4 |
| `.pyi` | 11,718 | 31 | | `.gemspec` | 520 | 0.8 |
| `.pyc` | 8,785 | 147 | | `.toml` | 427 | 1.1 |
| `.svg` | 5,633 | 20 | | `.symbols` | 328 | 6.5 |
| `.vim` | 1,671 | 13 | | `.conf` | 224 | 0.5 |
| `.rbs` | 1,652 | 22 | | `.service` | 153 | 0.1 |
| `.pl` | 1,206 | 8.1 | | `.jsonl` | 126 | 54 |
| `.s` | 1,167 | 11 | | `.css` | 112 | 0.8 |
| `.ui` | 1,098 | 31 | | `.ttf` | 110 | 58 |
| `.bc` | 958 | 23 | | `.pem` | 102 | 2.9 |
| `.crt` | 938 | 1.2 | | `.properties` | 97 | 4.3 |
| `.pm` | 937 | 14 | | `.gem`, `.jmod`, `.a`, `.o` | 95, 69, 140, 97 | 12, 85, 196, 35 |

(The no-extension group includes scripts that the shebang routing does scan.)

## 6. Adding a scanner for one of these types, in this order of value

1. **Model and pickle files** (they fail today, but nothing looks inside) (`.pkl .pickle .pt .pth .ckpt .h5`): the highest-impact gap for AI-generated repositories.
2. **Perl and Lua**, by extension and by shebang (the same rules as shell: download piped into an interpreter, reverse shells, encoded payloads).
3. **`.svg`** (script in an image), **`.toml`/`.ini`/`.env`** (credentials, install hooks in `pyproject.toml`), **`.ipynb`** (code cells, outputs), **systemd units** and **`.plist`** (persistence).
4. **Launchers** (`.lnk .hta .vbs .wsf`) and **containers** (`.whl`, `.apk`, `.nupkg`, `.deb`): open them and scan their members.

The types above already fail; a scanner gives them depth and lets a clean one pass. Each new scanner follows "Adding or modifying a scan layer" in `CLAUDE.md`: a rule in both engines, a positive and a
near-miss fixture, a calibration on real files, and a golden-report update.

## 7. Regenerating the routed list

```bash
python3 - <<'PY'
src = open("scan_pipeline.py").read()
ns = {}
exec(src[src.index("_BASENAME_RULES = ("):src.index("_EXT_SCANNER = {")], ns)
routed = set()
for exts, scanner in ns["_EXT_RULES"]:
    routed |= set(exts.split())
routed |= {".xml", ".pom", ".md", ".txt", ".rst"}
print(len(routed), "routed extensions")
print(" ".join(sorted(routed)))
print([p for patterns, _ in ns["_BASENAME_RULES"] for p in patterns])
PY
python3 build_pdf_filetypes.py --check      # the file-type deck is checked against classify_file
```
