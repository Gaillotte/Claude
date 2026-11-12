"""Known credential formats (bash ``_known_cred_check`` and the ``KNOWN_CRED_*`` tables).

Owner of: the 18 provider-format rules and the JWT warning, shared by the universal layer, by the jar scanner (a text view of
the archive entries) and by the office scanner (the text of a document): contract 5.1 (``CWE-798:known_credential_format_<provider>``),
8.7 (``grep -I`` semantics, A14/D-014) and CLAUDE.md "Known credential formats".

Layering: depends on ``transit.rx`` and the ``ScanContext`` type. This is NOT a registered scanner (no ``SCANNERS``): it is a
library function other scanners call. It must stay importable without ``transit.scanners.universal``.

Matching, exactly bash's (``-I`` is ``binary="skip"``):
  1. ONE alternation of all 18 provider patterns, each wrapped as ``(^|[^A-Za-z0-9])(<pat>)([^A-Za-z0-9]|$)``, is searched with
     ``binary="skip"``; a file whose first 32 KiB hold a NUL byte matches nothing (A14, D-014 copied; switch D-014 reads it).
  2. Only if it hits, each provider is tried: the lines that match are located with ``rx.matching_lines`` (budgeted), the matched
     text of each (``rx.only_matching`` on that line, leftmost-first where grep is leftmost-longest, a documented rx difference)
     is tested against ``EXCLUSION``; the provider is a FAIL if some match survives. ``rx.only_matching`` has no ``budget=``: it is
     never called on a line longer than ``Limits.long_line_bytes``. For such a line the match is reported WITHOUT the exclusion
     test (fail closed; new divergence D-030 in the design, section 12).
  3. The JWT pattern is a WARN, not a FAIL.
"""
from __future__ import annotations

import dataclasses
from typing import Mapping

from transit.scanners import ScanContext

#: Name and ERE of each provider, in bash order (``KNOWN_CRED_NAMES`` / ``KNOWN_CRED_PATS``). The message is
#: ``CWE-798:known_credential_format_<name>``. Patterns are copied from tests/conformance/patterns.json (ids ``_known_cred_check:*``).
PROVIDER_NAMES: tuple[str, ...] = (
    "aws_access_key_id", "aws_secret_access_key", "github_token", "github_fine_grained_pat", "gitlab_pat", "stripe_live_key",
    "slack_token", "google_api_key", "google_oauth_token", "sendgrid_key", "npm_token", "pypi_token", "huggingface_token",
    "anthropic_key", "openai_project_key", "openai_legacy_key", "shopify_token", "digitalocean_token",
)
PROVIDER_PATTERNS: Mapping[str, str] = {}  # filled by the implementation from the 18 patterns of KNOWN_CRED_PATS (see above)

#: Placeholder exclusion (bash ``KNOWN_CRED_EXCL``), case-insensitive. It contains a back-reference, so it has no linear matcher; it is
#: applied only to the short matched text, never to a whole line.
#: The last alternative is GitHub's documentation token. It is written in two pieces on purpose, as bash does (``ghp_16C7e42F''292c...``):
#: this repository is itself scanned, and a contiguous provider-shaped string in a source file would be reported.
EXCLUSION = (r"EXAMPLE|SAMPLE|DUMMY|PLACEHOLDER|YOUR|REDACTED|FAKE|CHANGEME|x{6,}|0{10,}|\*{3,}|\.{3}|1234567890|abcdefgh|"
             r"([A-Za-z0-9])\1{9,}|" "ghp_16C7e42F" "292c6912E7710c838347Ae178B4a")

JWT_PATTERN = r"(^|[^A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}([^A-Za-z0-9]|$)"
JWT_MESSAGE = "CWE-798:jwt_embedded_review_whether_it_is_a_live_credential"


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
    (``ScanBudgetExceeded``). Never prints or stores the matched text."""
    raise NotImplementedError
