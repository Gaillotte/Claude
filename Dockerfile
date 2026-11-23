## AI Transit Pipeline — Standalone Docker Image
## Usage: docker build -t ai-transit . && docker run --rm -v $(pwd)/Good:/output ai-transit <repo_url>
##
## Build args (override to pin different versions):
##   --build-arg TRIVY_VERSION=0.69.3
##   --build-arg GITLEAKS_VERSION=8.30.1
##   --build-arg HADOLINT_VERSION=2.12.0

# ── Stage 1: builder — compile gitleaks (Go binary) ───────────────────────────
# gitleaks v8.30.1 needs Go 1.24.11 or newer (its go.mod), which Ubuntu 22.04's
# golang-go package (1.18) is far too old for, so the builder is the Go image.
# CGO_ENABLED=0 gives a static binary: the runtime stage is a different distribution
# from this one, and a dynamically linked binary would depend on this one's libc.
# The module path is the one declared in gitleaks' go.mod, zricethezav/gitleaks/v8.
FROM golang:1.24-bookworm AS builder

ARG GITLEAKS_VERSION=8.30.1

RUN CGO_ENABLED=0 go install github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION} \
    && cp /go/bin/gitleaks /usr/local/bin/gitleaks

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM ubuntu:22.04

ARG TRIVY_VERSION=0.69.3
ARG HADOLINT_VERSION=2.12.0

# SHA-256 digests of the release artifacts above. An empty value downgrades the
# build to a warning instead of failing, so a version bump does not hard-break
# the image before someone fills in the new digest.
#   hadolint 2.12.0  — verified against the real Linux-x86_64 artifact
#   trivy 0.69.3     — equal to the digest in the release's own trivy_0.69.3_checksums.txt.
#                      0.69.3 is one of the two binaries GHSA-69fq-xp46-6x23 (the March 2026
#                      compromise of the Trivy releases) names as safe; v0.69.4 was malicious,
#                      and the releases before 0.69.2 are no longer downloadable.
ARG HADOLINT_SHA256=56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75

ENV DEBIAN_FRONTEND=noninteractive \
    WORK_DIR=/opt/ai-transit \
    OUTPUT_DIR=/output \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System packages ────────────────────────────────────────────────────────────
# Not pinned per package (DL3008): Ubuntu replaces a package's version when it ships a security update, so an exact
# version here would stop the image building within weeks. The pin is the base image tag above.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash git curl ca-certificates jq zip unzip file coreutils \
    python3 python3-pip \
    shellcheck cppcheck \
    clamav clamav-daemon yara \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ── Python packages ────────────────────────────────────────────────────────────
# Exact versions of the set the CI image build resolved on 2026-11-14 (the build that passed all six smoke tests).
# Their dependencies still float: for a full lock, `pip freeze` that image into a constraints file.
# To move a tool: change its version here, rebuild, and let the smoke tests and the Python-engine checks run.
# Known overlap: checkov 3.4.5 requires bc-detect-secrets (a fork) which installs the same `detect_secrets` package and
# `detect-secrets` command as Yelp's detect-secrets. pip sees two distributions and reports no conflict. Measured in the
# CI docker job on 2026-11-14: both are installed (bc-detect-secrets 1.5.52, detect-secrets 1.5.0) and
# `detect-secrets --version` prints 1.5.52, so the command the pipeline runs is the fork and the 1.5.0 pin below does
# not decide it. Isolating checkov in its own venv would make the pin mean something. The CI step prints this each run.
RUN pip3 install --no-cache-dir \
    openpyxl==3.1.5 \
    reportlab==5.1.0 \
    detect-secrets==1.5.0 \
    bandit==1.9.4 \
    pip-audit==2.10.1 \
    safety==3.8.1 \
    semgrep==1.185.0 \
    checkov==3.4.5 \
    scancode-toolkit==32.5.0

# ── gitleaks (pre-built binary from builder stage) ────────────────────────────
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks

# ── trivy (pinned version + integrity check) ──────────────────────────────────
# A pinned version alone only defends against "wrong version", not "wrong
# binary". Set TRIVY_SHA256 to enforce integrity; when it is empty the build
# still succeeds but prints a loud warning, because the correct digest depends
# on TRIVY_VERSION and must be filled in per pin. The `pins` CI job prints the
# digest for the current pin — paste it here.
# The pipe is `echo <digest> | sha256sum -c -`: its status is sha256sum's, and the build shell (dash) has no pipefail.
# hadolint ignore=DL4006
RUN set -eux; \
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -sfL "$url" -o /tmp/trivy.tar.gz; \
    if [ -n "${TRIVY_SHA256}" ]; then \
        echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    else \
        echo "WARNING: TRIVY_SHA256 is unset — trivy installed WITHOUT integrity verification."; \
        echo "         Actual digest: $(sha256sum /tmp/trivy.tar.gz | cut -d' ' -f1)"; \
        echo "         Rebuild with --build-arg TRIVY_SHA256=<digest> to enforce it."; \
    fi; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    trivy --version

# ── hadolint (pinned version + integrity check) ───────────────────────────────
# Digest verified against the real 2.12.0 Linux-x86_64 release artifact.
# If HADOLINT_VERSION is changed, HADOLINT_SHA256 must be updated to match.
# The pipe is `echo <digest> | sha256sum -c -`: its status is sha256sum's, and the build shell (dash) has no pipefail.
# hadolint ignore=DL4006
RUN set -eux; \
    curl -sSL \
      "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
      -o /usr/local/bin/hadolint; \
    if [ -n "${HADOLINT_SHA256}" ]; then \
        echo "${HADOLINT_SHA256}  /usr/local/bin/hadolint" | sha256sum -c -; \
    else \
        echo "WARNING: HADOLINT_SHA256 is unset — hadolint installed WITHOUT verification."; \
        echo "         Actual digest: $(sha256sum /usr/local/bin/hadolint | cut -d' ' -f1)"; \
    fi; \
    chmod +x /usr/local/bin/hadolint; \
    hadolint --version

# ── ClamAV virus database ──────────────────────────────────────────────────────
# Download the signature DB; warn loudly if it fails (e.g. air-gap) but do not
# abort the build — the DB files can be copied in later via a volume mount.
RUN freshclam --quiet 2>&1 || { \
      echo ""; \
      echo "WARNING: freshclam failed — ClamAV signature database is EMPTY."; \
      echo "   The container will start but ClamAV scans will produce no detections."; \
      echo "   To fix: mount a pre-downloaded DB at /var/lib/clamav/ or run"; \
      echo "   'docker exec <container> freshclam' after the container starts."; \
      echo ""; \
    }; \
    ls /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null \
      || echo "WARNING: no ClamAV database files found in /var/lib/clamav/"

# ── Pipeline scripts ───────────────────────────────────────────────────────────
WORKDIR /app
COPY fetch_repo.sh scan_pipeline.sh scan_pipeline.py ai_transit.sh prepare_offline_cache.sh prepare_offline_install.sh verify_offline_install.sh \
     generate_excel_report.py selfcheck.py ./
# The Python helpers scan_pipeline.sh runs by path (office, jar, PDF, manifests, report writer, tool readers)
COPY transit ./transit
RUN chmod +x ./*.sh

# ── Work directories ───────────────────────────────────────────────────────────
# Spelled out: RUN uses /bin/sh (dash on Ubuntu), which does no brace expansion, so
# `mkdir -p /opt/ai-transit/{fetch,quarantine}` made one directory with a literal
# brace name and the chmod after it found nothing.
RUN mkdir -p /opt/ai-transit/fetch /opt/ai-transit/quarantine /opt/ai-transit/approved \
        /opt/ai-transit/reports /opt/ai-transit/logs /opt/ai-transit/yara-rules \
    && chmod 700 /opt/ai-transit/quarantine \
    && mkdir -p /output

# ── Non-root runtime user ─────────────────────────────────────────────────────
# Running as root would trigger CWE-250 in the pipeline's own scanner.
# The transit user owns /app and /opt/ai-transit; /output is world-writable.
RUN groupadd -r transit && useradd -r -g transit -s /usr/sbin/nologin transit \
    && chown -R transit:transit /app /opt/ai-transit \
    && chmod 777 /output

USER transit

VOLUME ["/output"]

ENTRYPOINT ["bash", "/app/ai_transit.sh"]
# No default CMD — running the container without arguments prints usage (exit 1)
# because $# -lt 1 triggers the usage block in ai_transit.sh.
