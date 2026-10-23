# syntax=docker/dockerfile:1

# TrustSight triage agent image: the local-model watcher, no opencode.
#
# Build context must be the directory that contains all three sibling
# checkouts (docker-compose.yml sets this to the repo parent):
#     docker build -f trustsight-triage-agent/Dockerfile -t triage-agent ..
#
# The image carries trustsight/ and trustsight-harness/ beside this repo
# because the harness's [tool.uv.sources] expects ../trustsight, and because
# the runtime starts the harness MCP server from its checkout.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="trustsight-triage-agent" \
      org.opencontainers.image.description="Local-model triage agent for TrustSight alerts" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

# git: the AUR MCP reads package histories; ca-certificates: AUR/feed TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.12.13

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_PREFERENCE=system

WORKDIR /app/trustsight-triage-agent
COPY trustsight /app/trustsight
COPY trustsight-harness /app/trustsight-harness
COPY trustsight-triage-agent /app/trustsight-triage-agent

# Harness first (its [tool.uv.sources] needs the sibling trustsight), with
# the mcp extra the runtime launches it with; then the triage agent.
RUN cd /app/trustsight-harness \
    && uv sync --locked --extra mcp --python /usr/local/bin/python3 \
    && cd /app/trustsight-triage-agent \
    && uv sync --locked --python /usr/local/bin/python3

ENV TRIAGE_WORKSPACE=/app \
    TRIAGE_STATE_DIR=/var/lib/triage \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/cache \
    PATH="/app/trustsight-harness/.venv/bin:/app/trustsight-triage-agent/.venv/bin:${PATH}"

RUN useradd --create-home --shell /usr/sbin/nologin triage \
    && mkdir -p /var/lib/triage /tmp/home /tmp/cache \
    && chown -R triage:triage /var/lib/triage /tmp/home /tmp/cache

USER triage

# Foreground watcher; compose/systemd own the process lifetime. The model
# endpoint is TRIAGE_MODEL_BASE_URL (default 127.0.0.1:11434/v1).
CMD ["/app/trustsight-triage-agent/bin/triage-agent", "run"]
