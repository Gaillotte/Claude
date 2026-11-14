"""Known credential formats (bash ``_known_cred_check`` and the ``KNOWN_CRED_*`` tables).

Owner of: the 18 provider-format rules and the JWT warning, shared by the universal layer, by the jar scanner (a text view of
the archive entries) and by the office scanner (the text of a document): contract 5.1 (``CWE-798:known_credential_format_<provider>``),
8.7 (``grep -I`` semantics, A14/D-014) and CLAUDE.md "Known credential formats".

Layering: depends on ``transit.rules`` (``Matcher``) and the ``ScanContext`` type. This is NOT a registered scanner (no ``SCANNERS``): it is a
library function other scanners call. It must stay importable without ``transit.scanners.universal``.

EVERY PATTERN HERE IS A ``Matcher`` built at import (the alternation, the 18 providers, the JWT; ids ``credentials/alternation``,
``credentials/<provider name>``, ``credentials/jwt``), never an ad-hoc ``rx.ere_to_py`` call, so the registry, the 600 KB hostile-line test and
the fuzz gate cover them (review log R-18). The exclusion ``EXCLUSION`` has a back-reference, so it has no linear matcher and is NOT a
``Matcher``; it is compiled with ``rx.ere_to_py`` and applied only to the short matched text (see step 2).

Matching, exactly bash's (``-I`` is ``binary="skip"``):
  1. ONE alternation of all 18 provider patterns, each wrapped as ``(^|[^A-Za-z0-9])(<pat>)([^A-Za-z0-9]|$)``, is searched with
     ``binary="skip"`` (``ctx.search(ALTERNATION.match, data=...)``); a file whose first 32 KiB hold a NUL byte matches nothing (A14, D-014
     copied; switch D-014 reads it).
  2. Only if it hits, each provider is tried: the lines that match are located with ``ctx.spans(PROVIDER_MATCHERS[name])`` (budgeted), the matched
     text of each (``rx.only_matching`` on that line, leftmost-first where grep is leftmost-longest, a documented rx difference)
     is tested against ``EXCLUSION``; the provider is a FAIL if some match survives. ``rx.only_matching`` has no ``budget=``: it is
     never called on a line longer than ``Limits.long_line_bytes``. For such a line the match is reported WITHOUT the exclusion
     test (fail closed; new divergence D-030 in the design, section 12).
  3. The JWT pattern is a WARN, not a FAIL.
"""
from __future__ import annotations

import dataclasses
import types
from typing import Mapping

from transit import rx
from transit.rules import Match, Matcher
from transit.scanners import ScanContext

#: Name and ERE of each provider, in bash order (``KNOWN_CRED_NAMES`` / ``KNOWN_CRED_PATS``). The message is
#: ``CWE-798:known_credential_format_<name>``. Patterns are copied from tests/conformance/patterns.json (ids ``_known_cred_check:*``).
PROVIDER_NAMES: tuple[str, ...] = (
    "aws_access_key_id", "aws_secret_access_key", "github_token", "github_fine_grained_pat", "gitlab_pat", "stripe_live_key",
    "slack_token", "google_api_key", "google_oauth_token", "sendgrid_key", "npm_token", "pypi_token", "huggingface_token",
    "anthropic_key", "openai_project_key", "openai_legacy_key", "shopify_token", "digitalocean_token",
)
#: The 18 patterns of ``KNOWN_CRED_PATS``, in the order of ``PROVIDER_NAMES`` (bash single-quotes resolved, nothing else changed).
_BARE_PATTERNS: tuple[str, ...] = (
    r"(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}",
    r"""[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy][[:space:]]*["']?[[:space:]]*[=:][[:space:]]*["']?[A-Za-z0-9/+=]{40}""",
    r"gh[pousr]_[A-Za-z0-9]{36,255}",
    r"github_pat_[A-Za-z0-9_]{50,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"[sr]k_live_[A-Za-z0-9]{24,}",
    r"xox[bpars]-[0-9]{8,14}-[0-9]{8,14}(-[0-9]{8,14})?-[A-Za-z0-9]{20,}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"ya29\.[0-9A-Za-z_-]{30,}",
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    r"npm_[A-Za-z0-9]{36}",
    r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
    r"hf_[A-Za-z0-9]{34,}",
    r"sk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9_-]{60,}",
    r"sk-proj-[A-Za-z0-9_-]{40,}",
    r"sk-[A-Za-z0-9]{48}",
    r"shp(at|ca|pa|ss)_[a-f0-9]{32}",
    r"dop_v1_[a-f0-9]{64}",
)
PROVIDER_PATTERNS: Mapping[str, str] = types.MappingProxyType(dict(zip(PROVIDER_NAMES, _BARE_PATTERNS)))

#: Placeholder exclusion (bash ``KNOWN_CRED_EXCL``), case-insensitive. It contains a back-reference, so it has no linear matcher; it is
#: applied only to the short matched text, never to a whole line.
#: The last alternative is GitHub's documentation token. It is written in two pieces on purpose, as bash does (``ghp_16C7e42F''292c...``):
#: this repository is itself scanned, and a contiguous provider-shaped string in a source file would be reported.
EXCLUSION = (r"EXAMPLE|SAMPLE|DUMMY|PLACEHOLDER|YOUR|REDACTED|FAKE|CHANGEME|x{6,}|0{10,}|\*{3,}|\.{3}|1234567890|abcdefgh|"
             r"([A-Za-z0-9])\1{9,}|" "ghp_16C7e42F" "292c6912E7710c838347Ae178B4a")

JWT_PATTERN = r"(^|[^A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9]|$)"
JWT_MESSAGE = "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential"
_FAIL_PREFIX = "CWE-798:known_credential_format_"

#: Each provider pattern bounded on both sides, as bash passes it to ``grep -o`` (``(^|[^A-Za-z0-9])(<pat>)([^A-Za-z0-9]|$)``): a token inside
#: a longer identifier or a base64 blob does not count. The alternation of all 18 is ``KNOWN_CRED_ALL``.
_WRAPPED: Mapping[str, str] = types.MappingProxyType(
    {name: "(^|[^A-Za-z0-9])(" + pattern + ")([^A-Za-z0-9]|$)" for name, pattern in zip(PROVIDER_NAMES, _BARE_PATTERNS)})

#: Registered matchers (``binary="skip"``): the alternation of all 18 wrapped patterns, one per provider (keys are ``PROVIDER_NAMES``), and the
#: JWT pattern. ``skip`` is ``grep -I``: a buffer whose first 32 KiB hold a NUL byte matches nothing (A14, D-014).
ALTERNATION: "Matcher | None" = Matcher("credentials/alternation",
                                         Match("|".join(_WRAPPED[name] for name in PROVIDER_NAMES), binary="skip"))
PROVIDER_MATCHERS: Mapping[str, Matcher] = types.MappingProxyType(
    {name: Matcher("credentials/" + name, Match(_WRAPPED[name], binary="skip")) for name in PROVIDER_NAMES})
JWT: "Matcher | None" = Matcher("credentials/jwt", Match(JWT_PATTERN, binary="skip"))

def _registered_regex(rule_id: str) -> object:
    for rule in rx.registered():
        if rule.id == rule_id:
            return rule.compiled
    raise LookupError("rule %s is not registered" % rule_id)


#: What ``rx.only_matching`` needs: the compiled object each provider Matcher registered with ``rx.rule`` (looked up by id, not compiled
#: again, so the pattern that runs is the registered one), and the exclusion, compiled once at import (a back-reference: it has no
#: linear matcher and is never run on anything longer than one matched token, see ``_provider_fires``).
_PROVIDER_REGEX: Mapping[str, object] = types.MappingProxyType({name: _registered_regex("credentials/" + name) for name in PROVIDER_NAMES})
_EXCLUSION_REGEX = rx.ere_to_py(EXCLUSION, True)


@dataclasses.dataclass(frozen=True)
class CredentialResult:
    """``failed``: at least one provider FAIL was recorded (bash returns 0 only then, for ``triggered``). ``providers``: names that
    fired, in bash order. ``jwt``: the WARN was recorded."""
    failed: bool
    providers: tuple[str, ...]
    jwt: bool


def check_known_credentials(ctx: ScanContext, *, data: "bytes | None" = None, report_file: "str | None" = None) -> CredentialResult:
    """Run steps 1 to 3 above on ``data`` (default: the file's own bytes) and record through ``ctx``: one ``record_fail`` per provider that
    fired (``CWE-798:known_credential_format_<name>``), then the JWT ``record_warn``. ``report_file`` is the path the findings land on
    (default ``ctx.path``); the jar scanner passes the archive path and a text view as ``data``. Honours the file deadline
    (``ScanBudgetExceeded``). Never prints or stores the matched text.

    A buffer whose first 32 KiB hold a NUL byte matches nothing, as in bash (``grep -I``, A14); with the switch ``D-014``
    (``TRANSIT_FIXES=D-014``) the NUL bytes are first turned into line ends and the buffer is searched like any other."""
    text = ctx.view.data() if data is None else data
    if b"\0" in text and ctx.cfg.fix("D-014"):
        # D-014 (accepted for the Python engine): read the file grep without -I would read, where a NUL byte ends a line. The Matchers are
        # ``binary="skip"`` (the default copies bash, A14), so they are given a derived view in which no NUL byte is left; its size is the
        # file's, which ``FileView.data`` already bounds by ``Limits.max_file_bytes``.
        text = data = text.replace(b"\0", b"\n")
    limit = ctx.cfg.limits.long_line_bytes
    fired: "list[str]" = []
    if ctx.search(ALTERNATION.match, data=data):                         # bash ``grep -qIE``: one pass decides whether any provider is present
        for name in PROVIDER_NAMES:
            if _provider_fires(ctx, name, text, data, limit):
                ctx.record_fail(_FAIL_PREFIX + name, file=report_file)
                fired.append(name)
    jwt = ctx.search(JWT.match, data=data)
    if jwt:                                                               # a signed token, not necessarily a secret: a WARN
        ctx.record_warn(JWT_MESSAGE, file=report_file)
    return CredentialResult(failed=bool(fired), providers=tuple(fired), jwt=jwt)


def _provider_fires(ctx: ScanContext, name: str, text: bytes, data: "bytes | None", limit: int) -> bool:
    """bash ``grep -ohIE PROVIDER file | grep -viE EXCLUSION``: does some match of the provider survive the placeholder exclusion?

    The lines come from ``ctx.spans`` (budgeted, linear on a buffer with an over-long line, never materialised). Each line is cut out and
    ``rx.only_matching`` gives the matched texts (one token and a delimiter on each side), every one of which is tested against the
    exclusion: a line holding a placeholder and a real token still fires, and the word EXAMPLE somewhere else on the line excludes nothing.
    ``rx.only_matching`` has no ``budget=``, so it is never called on a line longer than ``long_line_bytes``: for such a line the provider
    is reported WITHOUT the exclusion test (fail closed, D-030)."""
    compiled = _PROVIDER_REGEX[name]
    for start, end in ctx.spans(PROVIDER_MATCHERS[name], data=data):
        if end - start > limit:
            return True
        for matched in rx.only_matching(compiled, text[start:end]):
            if _EXCLUSION_REGEX.search(matched) is None:
                return True
    return False
