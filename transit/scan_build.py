"""Build and configuration file scanners of the Python engine: package manifests, requirements, Gradle, CMake, Makefile ...

One function per scanner, named as in scan_pipeline.sh, and no module-level state. Only scan_requirements is here so far;
the engineers who port the others add them. Standard library only.
"""
from transit.core import grep_check_excl, grep_rules, record_pass, record_warn

_REQUIREMENTS_RULES = [
    ('fail', r'^[[:space:]]*((--index-url|-i|--extra-index-url|--find-links|-f)[[:space:]=]+http://|(-e[[:space:]]+)?(git\+http://|git://)|http://[^[:space:]]+\.(tar\.gz|tgz|zip|whl|tar\.bz2))',
     'CWE-319:pip_index_or_requirement_over_plaintext', 'i'),
    ('fail', r'(https?|git\+https?|ssh)://[^/[:space:]:@]+:[^/[:space:]@]+@', 'CWE-798:pip_credentials_embedded_in_url'),
    ('warn', r'^[[:space:]]*--trusted-host', 'pip:trusted_host_disables_tls_verification', 'i'),
    ('warn', r'^[[:space:]]*--extra-index-url', 'pip:extra_index_url_enables_dependency_confusion', 'i'),
]


def scan_requirements(f):
    failed = grep_rules(f, _REQUIREMENTS_RULES)
    # A VCS requirement not pinned to a commit follows a moving branch.
    if grep_check_excl(r'git\+(https|ssh)://', r'@[0-9a-f]{7,40}([#[:space:]]|$)', f):
        record_warn(f, "pip:vcs_requirement_not_pinned_to_a_commit")
    if not failed:
        record_pass(f)
