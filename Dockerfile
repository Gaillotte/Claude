## AI Transit Pipeline — Standalone Docker Image
## Usage: docker build -t ai-transit . && docker run --rm -v $(pwd)/Good:/output ai-transit <repo_url>

FROM ubuntu:22.04

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

# ── betterleaks ───────────────────────────────────────────────────────────────
RUN apt-get install -y --no-install-recommends golang-go \
    && go install github.com/betterleaks/betterleaks@latest \
    && cp /root/go/bin/betterleaks /usr/local/bin/betterleaks \
    && apt-get remove -y golang-go && apt-get autoremove -y \
    && rm -rf /root/go/pkg /root/go/src /var/lib/apt/lists/*

# ── trivy ─────────────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── hadolint ──────────────────────────────────────────────────────────────────
ARG HADOLINT_VERSION=2.12.0
RUN curl -sSL \
    "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# ── ClamAV virus database ──────────────────────────────────────────────────────
# Download the signature DB; warn loudly if it fails (e.g. air-gap) but do not
# abort the build — the DB files can be copied in later via a volume mount.
RUN freshclam --quiet 2>&1 || { \
      echo ""; \
      echo "⚠  WARNING: freshclam failed — ClamAV signature database is EMPTY."; \
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

VOLUME ["/output"]

ENTRYPOINT ["bash", "/app/ai_transit.sh"]
CMD ["--help"]
