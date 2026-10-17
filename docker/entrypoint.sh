#!/bin/sh
# Entrypoint for the triage agent job container.
#
# The container starts as ROOT solely so this bootstrap can run; the job
# itself never does. Order of operations:
#
# 1. Create $HOME (default /tmp/home; the rootfs is read-only and /tmp is
#    a tmpfs), owned by the unprivileged job user. opencode's bun runtime
#    writes caches under $HOME and dies with ENOENT when it is missing.
# 2. When ENABLE_WARP_ROTATION=1, start warp-svc (there is no systemd in
#    a container; warp-svc needs root for the TUN device and its state
#    dir) and wait until WARP is fully ambient: daemon socket up,
#    anonymous registration present, tunnel Status: Connected. Fail-open
#    preserved: on any timeout, warn and proceed on the plain egress.
# 3. Drop privileges to the unprivileged job user (setpriv, no PAM) and
#    exec the job command. Everything privileged happens before the drop;
#    nothing after it runs as root.
set -u

JOB_USER="${TRIAGE_JOB_USER:-triage}"

# --- 1. writable $HOME for the job user ------------------------------------

home_dir="${HOME:-/tmp/home}"
if [ "$(id -u)" = "0" ]; then
    install -d -m 700 -o "$JOB_USER" -g "$JOB_USER" "$home_dir" \
        || echo "entrypoint: WARNING could not create $home_dir" >&2
else
    mkdir -p "$home_dir" 2>/dev/null \
        || echo "entrypoint: WARNING could not create $home_dir" >&2
fi

# --- 2. ambient WARP egress (root only) -------------------------------------

if [ "${ENABLE_WARP_ROTATION:-0}" = "1" ]; then
    echo "entrypoint: starting warp-svc (no systemd in container)"
    # The container root is read-only; logs go to the /tmp tmpfs.
    /bin/warp-svc >/tmp/warp-svc.log 2>&1 &
    warp_pid=$!
    trap 'kill "$warp_pid" 2>/dev/null || true' EXIT INT TERM

    # warp-cli refuses to talk until warp-svc has created its socket; on a
    # cold container that routinely takes longer than 30s.
    # --accept-tos is a GLOBAL warp-cli flag and must precede the
    # subcommand; this client version has no --accept-terms variant.
    warp() { warp-cli --accept-tos "$@"; }
    socket_up=""
    for _ in $(seq 1 60); do
        if warp status >/dev/null 2>&1; then
            socket_up=1
            break
        fi
        sleep 2
    done

    if [ -z "$socket_up" ]; then
        echo "entrypoint: WARNING warp-cli never came up;" \
             "running on plain egress" >&2
    else
        # Register an anonymous consumer if none exists. tunnel_only
        # routes the tunnel but leaves /etc/resolv.conf alone: warp-svc
        # rewrites resolv.conf by default, which is fatal on the
        # read-only rootfs (FailedToSetDns kills the connection startup).
        if ! warp registration show >/dev/null 2>&1; then
            echo "entrypoint: registering anonymous WARP consumer"
            warp registration new >/dev/null 2>&1 || true
        fi
        warp mode tunnel_only >/dev/null 2>&1 || true
        warp connect >/dev/null 2>&1 || true
        connected=""
        for _ in $(seq 1 45); do
            if warp status 2>/dev/null | grep -qi "Status update: Connected"; then
                connected=1
                break
            fi
            sleep 2
        done
        if [ -z "$connected" ]; then
            echo "entrypoint: WARNING warp never connected;" \
                 "running on plain egress" >&2
        else
            echo "entrypoint: WARP connected: $(warp status 2>&1 | head -n 1)"
        fi
    fi
fi

# --- 3. privilege drop, then the job ----------------------------------------

if [ "$(id -u)" = "0" ]; then
    echo "entrypoint: dropping privileges to $JOB_USER for the job"
    # --keep-groups (not --clear-groups): the worker container mounts the
    # host docker socket and gets access via compose group_add (host docker
    # gid). Clearing groups here would strip that access from the job user;
    # job containers give root no extra groups, so keeping them is a no-op
    # there. Never run the worker with -u/--user: it must reach this drop.
    exec setpriv --reuid "$JOB_USER" --regid "$JOB_USER" --keep-groups "$@"
fi

exec "$@"
