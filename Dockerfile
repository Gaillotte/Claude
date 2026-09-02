## AI Transit Pipeline — Standalone Docker Image
## Usage: docker build -t ai-transit . && docker run --rm -v $(pwd)/Good:/output ai-transit <repo_url>
##
## Build args (override to pin different versions):
##   --build-arg TRIVY_VERSION=0.58.2
##   --build-arg BETTERLEAKS_VERSION=0.1.0
##   --build-arg HADOLINT_VERSION=2.12.0

# ── Stage 1: builder — compile betterleaks (Go binary) ────────────────────────
FROM ubuntu:22.04 AS builder

ARG BETTERLEAKS_VERSION=0.1.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN go install github.com/betterleaks/betterleaks@v${BETTERLEAKS_VERSION} \
    && cp /root/go/bin/betterleaks /usr/local/bin/betterleaks

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM ubuntu:22.04

ARG TRIVY_VERSION=0.58.2
ARG HADOLINT_VERSION=2.12.0

# SHA-256 digests of the release artifacts above. An empty value downgrades the
# build to a warning instead of failing, so a version bump does not hard-break
# the image before someone fills in the new digest.
#   hadolint 2.12.0  — verified against the real Linux-x86_64 artifact
#   trivy            — UNVERIFIED: could not be resolved from the development
#                      environment; the `pins` CI job prints the correct digest
ARG HADOLINT_SHA256=56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010
ARG TRIVY_SHA256=

ENV DEBIAN_FRONTEND=noninteractive \
    WORK_DIR=/opt/ai-transit \
    OUTPUT_DIR=/output \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash git curl ca-certificates jq zip unzip file coreutils \
    python3 python3-pip \
    shellcheck cppcheck \
    clamav clamav-daemon yara \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ── Python packages ────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    openpyxl \
    reportlab \
    detect-secrets \
    bandit \
    pip-audit \
    safety \
    semgrep \
    checkov \
    scancode-toolkit

# ── betterleaks (pre-built binary from builder stage) ─────────────────────────
COPY --from=builder /usr/local/bin/betterleaks /usr/local/bin/betterleaks

# ── trivy (pinned version + integrity check) ──────────────────────────────────
# A pinned version alone only defends against "wrong version", not "wrong
# binary". Set TRIVY_SHA256 to enforce integrity; when it is empty the build
# still succeeds but prints a loud warning, because the correct digest depends
# on TRIVY_VERSION and must be filled in per pin. The `pins` CI job prints the
# digest for the current pin — paste it here.
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
COPY fetch_repo.sh scan_pipeline.sh ai_transit.sh prepare_offline_cache.sh prepare_offline_install.sh verify_offline_install.sh \
     generate_excel_report.py selfcheck.py ./
RUN chmod +x *.sh

# ── Work directories ───────────────────────────────────────────────────────────
RUN mkdir -p /opt/ai-transit/{fetch,quarantine,approved,reports,logs,yara-rules} \
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
