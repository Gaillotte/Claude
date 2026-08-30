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

# ── trivy (pinned version) ────────────────────────────────────────────────────
RUN curl -sfL \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# ── hadolint (pinned version) ─────────────────────────────────────────────────
RUN curl -sSL \
    "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

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
COPY fetch_repo.sh scan_pipeline.sh ai_transit.sh \
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
