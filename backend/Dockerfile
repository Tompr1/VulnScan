FROM python:3.11-slim
# Utiliser des miroirs Debian accessibles
RUN sed -i \
    -e 's|https\?://deb.debian.org/debian$|http://debian.mirrors.ovh.net/debian|' \
    -e 's|https\?://deb.debian.org/debian-security$|http://cloudfront.debian.net/debian-security|' \
    -e 's|https\?://security.debian.org/debian-security$|http://cloudfront.debian.net/debian-security|' \
    /etc/apt/sources.list.d/debian.sources

# Install system dependencies including curl for health checks,
# nmap for port scanning, git for testssl.sh, and Perl for nikto/testssl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    unzip \
    git \
    bsdmainutils \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ── External pentest tools ─────────────────────────────────────────

# Nuclei (ProjectDiscovery) — template-based vulnerability scanning.
# Only the template update is optional (it needs network at build time): a
# failed binary download must fail the build, not ship an image without nuclei.
ARG NUCLEI_VERSION=3.3.7
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
      -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    (nuclei -update-templates -silent || echo "WARNING: nuclei templates not updated")

# testssl.sh — comprehensive TLS/SSL testing

# testssl.sh — installation depuis les fichiers locaux
COPY vendor/testssl.sh/ /opt/testssl.sh/

RUN chmod +x /opt/testssl.sh/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ffuf — fast web fuzzer (directory/vhost/parameter discovery)

# ffuf 2.1.0 — installation depuis Debian Trixie
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffuf && \
    rm -rf /var/lib/apt/lists/*

# subfinder (ProjectDiscovery) — passive subdomain enumeration

# subfinder 2.6.7 — copie depuis l'image Docker officielle
COPY --from=projectdiscovery/subfinder:v2.6.7 \
    /usr/local/bin/subfinder /usr/local/bin/subfinder

# httpx (ProjectDiscovery) — HTTP probing + tech detection.
# Installed as `httpx-pd`: the Python httpx package from requirements.txt
# installs its own /usr/local/bin/httpx script and would overwrite it.

# httpx ProjectDiscovery 1.6.9
# Installer sous httpx-pd pour éviter le conflit avec Python httpx
COPY --from=projectdiscovery/httpx:v1.6.9 \
    /usr/local/bin/httpx /usr/local/bin/httpx-pd

# sqlmap — advanced SQL injection testing
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Bundled wordlist for ffuf (common directories/files)

# Wordlists locales pour ffuf, fournies par Debian
RUN apt-get update && \
    apt-get install -y --no-install-recommends dirb && \
    mkdir -p /opt/wordlists && \
    cp /usr/share/dirb/wordlists/common.txt \
       /opt/wordlists/common.txt && \
    cp /usr/share/dirb/wordlists/big.txt \
       /opt/wordlists/raft-medium-directories.txt && \
    test -s /opt/wordlists/common.txt && \
    test -s /opt/wordlists/raft-medium-directories.txt && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (required for Claude Code CLI).
# 24.x, not 20.x: Node 20 reached end of life in March 2026 and does not get
# security fixes — CVE-2026-111497 (Brotli decoder OOB write, CVSS 9.2) is
# fixed in v24.22.1 and has no 20.x release at all. Note that
# `process.versions.brotli` still reports 1.2.0 on a patched build: Node
# cherry-picked the fix without bumping the upstream version string, so a
# version comparison alone will misjudge it.
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI
# The CLI version here must match the one that wrote the profile mounted at
# /root/.claude (see CLAUDE_CONFIG_DIR): a v2-written credentials file is not
# readable by a v1 CLI, which then fails every call with
# "Invalid API key · Please run /login".
#
# v2.x ships as a Bun-bundled standalone binary that segfaults on CPUs lacking
# AVX/AVX2 (older bare-metal servers, low-spec VMs). Check the host first with
#   grep -o avx2 /proc/cpuinfo | head -1
# and if it comes back empty, build the Node.js-based v1 line instead:
#   docker compose build --build-arg CLAUDE_CLI_VERSION=1 backend worker-ai
# — and then log in with that same v1 CLI so the profile formats match.
ARG CLAUDE_CLI_VERSION=2
WORKDIR /tmp
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}

WORKDIR /app


# Install Python dependencies via alternative PyPI mirror
COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    --timeout 30 \
    --retries 2 \
    --index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    -r requirements.txt
# Copy application code
COPY . .

# Default command (overridden by docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]

