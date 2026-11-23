# Moved out of scan_pipeline.sh (function _pkg_facts) without changes to the code below.
# Parses package.json / composer.json / requirements*.txt and prints FACT lines for the scanner.
# Run by path from the bash engine; also importable by the Python engine. Standard library only.
import json, os, re, sys

path = sys.argv[1]
base = os.path.basename(path)
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        d = json.load(fh)
except Exception:
    print("FACT unparsed")
    raise SystemExit(0)
if not isinstance(d, dict):
    print("FACT unparsed")
    raise SystemExit(0)
# Parsing succeeded. This is stated outright because a manifest with nothing to
# report prints nothing else, and empty output must not be read as a failure.
print("FACT parsed")

PIPE   = re.compile(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.I)
DECODE = re.compile(r"(base64\s+(-d|-D|--decode)|openssl\s+enc\s+-d)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b"
                    r"|/dev/tcp/|\bnc(at)?\s+-[a-z]*e\b", re.I)
FETCH  = re.compile(r"\b(curl|wget)\b", re.I)


def emit(kind):
    print("FACT " + kind)


def commands(value):
    """A script is a string, or for Composer a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


if base == "composer.json":
    LIFE = {"pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
            "post-autoload-dump", "post-root-package-install", "post-create-project-cmd",
            "pre-autoload-dump", "post-package-install", "post-package-update"}
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    for key, val in scripts.items():
        for cmd in commands(val):
            # "@php artisan x" is a script reference and "Vendor\Class::method" a
            # PHP callable; only a shell command line can fetch and execute.
            if cmd.startswith("@") or "::" in cmd:
                continue
            life = key in LIFE
            if PIPE.search(cmd):
                emit("hook_pipe" if life else "script_pipe")
            elif DECODE.search(cmd):
                emit("hook_decode" if life else "script_decode")
            elif FETCH.search(cmd):
                emit("script_fetch")
    cfg = d.get("config") if isinstance(d.get("config"), dict) else {}
    if cfg.get("secure-http") is False:
        emit("composer_insecure")
    repos = d.get("repositories")
    items = list(repos.values()) if isinstance(repos, dict) else (repos if isinstance(repos, list) else [])
    for r in items:
        if isinstance(r, dict) and isinstance(r.get("url"), str) and r["url"].startswith("http://"):
            emit("composer_insecure")
    raise SystemExit(0)

# npm
LIFE_NPM = {"preinstall", "install", "postinstall", "prepare", "prepack", "postpack",
            "prepublish", "prepublishOnly", "publish", "postpublish",
            "preuninstall", "uninstall", "postuninstall"}
INSTALL_TIME = {"preinstall", "install", "postinstall"}
scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
for key, val in scripts.items():
    if not isinstance(val, str):
        continue
    life = key in LIFE_NPM
    if key in INSTALL_TIME:
        emit("install_hook")
    if PIPE.search(val):
        emit("hook_pipe" if life else "script_pipe")
    elif DECODE.search(val):
        emit("hook_decode" if life else "script_decode")
    elif FETCH.search(val):
        emit("script_fetch")

for dk in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
    deps = d.get(dk) if isinstance(d.get(dk), dict) else {}
    for spec in deps.values():
        if not isinstance(spec, str):
            continue
        if re.match(r"^(http://|git://|git\+http://)", spec):
            emit("dep_plain")
        elif (re.match(r"^(https://|git\+https://|git\+ssh://|github:|gitlab:|bitbucket:)", spec)
              or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", spec)):
            emit("dep_remote")
