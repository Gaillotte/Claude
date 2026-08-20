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
    checkov

# ── gitleaks ──────────────────────────────────────────────────────────────────
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

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
RUN freshclam --quiet || true

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
