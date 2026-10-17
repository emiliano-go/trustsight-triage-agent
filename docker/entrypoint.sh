#!/bin/sh
# Entrypoint for the triage agent job container.
#
# There is no systemd in the container, but Cloudflare WARP's daemon
# (warp-svc) normally runs as a systemd service. When warp egress rotation
# is enabled we start warp-svc manually as a background userspace daemon,
# wait for the registration to come up, then hand off to the agent command.
set -u

if [ "${ENABLE_WARP_ROTATION:-0}" = "1" ]; then
    echo "entrypoint: starting warp-svc (no systemd in container)"
    # The container root is read-only; logs go to the /tmp tmpfs.
    /bin/warp-svc >/tmp/warp-svc.log 2>&1 &
    warp_pid=$!
    # warp-cli refuses to talk until warp-svc has created its socket.
    for _ in $(seq 1 30); do
        if warp-cli status >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    echo "entrypoint: warp-cli status: $(warp-cli status 2>&1 | head -n 1)"
    trap 'kill "$warp_pid" 2>/dev/null || true' EXIT INT TERM
fi

exec "$@"
