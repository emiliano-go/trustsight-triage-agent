# syntax=docker/dockerfile:1

# TrustSight triage agent job image.
#
# Build context must be the directory that contains all three sibling
# checkouts (docker-compose.yml sets this to the repo parent):
#     docker build -f trustsight-triage-agent/Dockerfile -t triage-agent ..
#
# Like trustsight-harness/Dockerfile, the image carries the sibling checkouts
# side by side because the harness's [tool.uv.sources] expects ../trustsight.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="trustsight-triage-agent" \
      org.opencontainers.image.description="Triage agent: alerts to verified verdicts, PRs and IOC alerts" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

# Base tools: git (agent clones AUR repos read-only), curl and gpg (repo
# keys, release downloads), nodejs/npm (opencode CLI).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl git gpg nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# opencode CLI, pinned via npm (installs the `opencode` binary on PATH).
RUN npm install -g opencode-ai@1.19.3

# GitHub's official MCP server binary, pinned version + sha256 checksum.
ARG GITHUB_MCP_VERSION=2.0.2
ARG GITHUB_MCP_SHA256=815e27d931c796af0c97f24fd211e14f8a4607d4528377719a5ad2352086b0b0
RUN curl -fsSL \
    "https://github.com/github/github-mcp-server/releases/download/v${GITHUB_MCP_VERSION}/github-mcp-server_Linux_x86_64.tar.gz" \
    -o /tmp/github-mcp-server.tar.gz \
    && echo "${GITHUB_MCP_SHA256}  /tmp/github-mcp-server.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/github-mcp-server.tar.gz -C /usr/local/bin github-mcp-server \
    && chmod +x /usr/local/bin/github-mcp-server \
    && rm /tmp/github-mcp-server.tar.gz

# Cloudflare WARP from Cloudflare's official apt repo. The package ships
# warp-svc (the daemon) and warp-cli (the client). There is no systemd in
# a container, so nothing starts here: the entrypoint launches warp-svc
# manually when ENABLE_WARP_ROTATION=1.
RUN curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
    | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
    > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflare-warp \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.12.13

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_PREFERENCE=system

WORKDIR /app/trustsight-triage-agent
COPY trustsight /app/trustsight
COPY trustsight-harness /app/trustsight-harness
COPY trustsight-triage-agent /app/trustsight-triage-agent

# Harness first (its [tool.uv.sources] needs the sibling trustsight), then
# the triage agent itself. --locked refuses to resolve fresh.
RUN cd /app/trustsight-harness \
    && uv sync --locked --no-install-project --python /usr/local/bin/python3 \
    && uv sync --locked --python /usr/local/bin/python3 \
    && cd /app/trustsight-triage-agent \
    && uv sync --locked --python /usr/local/bin/python3

ENV PATH="/app/trustsight-harness/.venv/bin:/app/trustsight-triage-agent/.venv/bin:${PATH}" \
    HARNESS_MCP_COMMAND="/app/trustsight-harness/.venv/bin/harness-mcp"

RUN useradd --create-home --shell /usr/sbin/nologin triage \
    && mkdir -p /job \
    && chown -R triage:triage /job /app/trustsight-triage-agent
ENV HOME=/tmp/home
# Root on purpose: docker/entrypoint.sh runs the privileged bootstrap
# (warp-svc needs the TUN device and root state) and setpriv-drops to the
# unprivileged `triage` user before exec'ing the job. The job never runs
# as root; do not add -u/--user overrides (they would skip the drop).
USER root

COPY trustsight-triage-agent/docker/entrypoint.sh /usr/local/bin/triage-entrypoint
ENTRYPOINT ["triage-entrypoint"]
CMD ["triage-agent", "dispatch"]
