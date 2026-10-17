# trustsight-triage-agent

Turns TrustSight watcher alerts into verified verdicts, fix PRs, and
confirmed-IOC alerts.

The agent polls the TrustSight feed for `trustsight.alerts` events, enqueues
one job per over-threshold `(package, version transition)`, and runs each job
in a hardened container where an LLM agent (opencode) triages the alert. Every
verdict is cross-checked by the deterministic TrustSight harness before
anything leaves the container, every PR is re-verified by a backstop after the
agent opens it, and nothing merges automatically: a maintainer reviews, signs,
and merges every artifact.

> **Experimental.** The default model route is the free OpenCode Zen tier
> (`opencode/MiMo-V2.6-Flash`), which may be discontinued or rate-limited at
> any time, and WARP egress rotation is an experimental mitigation for exactly
> that. Both are expected to be replaced by a paid API key; treat the rotation
> machinery as scaffolding, not as a stable interface.

## Architecture

```
                        trustsight watcher
                               |  (emits on over-threshold cycles)
                               v
                    +---------------------+
                    | TrustSight feed sink |   https://watcher.trustsight.org
                    |  (trustsight-feed)   |   /api/feed?event=trustsight.alerts
                    +----------+----------+
                               |  GET every TRIAGE_POLL_INTERVAL_SECONDS (120s)
                               v
                    +---------------------+
                    |     dispatcher      |  src/triage_agent/dispatcher.py
                    |  dedupe: sha256 of  |  per-process Deduper + SQLite
                    | (alerts, over_      |  content_hash UNIQUE per job
                    |  threshold) blocks  |
                    +----------+----------+
                               |  one job per (package, version transition)
                               v
                    +---------------------+
                    |    SQLite job queue  |  src/triage_agent/queue.py
                    | queued -> running -> |  strict status transitions,
                    | verified -> pr_opened|  WAL, symlink-safe job files
                    |          -> alert_sent
                    +----------+----------+
                               |  prompt build (prompt.py)
                               v
          +----------------------------------------------------+
          |           hardened job container (Dockerfile)       |
          |  python:3.12-slim-bookworm, non-root user `triage`  |
          |  opencode + MiMo-V2.6-Flash + fallback models       |
          |  MCP: harness-mcp (verify/render)                   |
          |      github-mcp-server (contents+pull_requests)     |
          |  agent writes /job/verdict.json, then calls:        |
          |    1. fp_agent_verify  (harness cross-check)        |
          |    2. fp_agent_pr + GitHub PR   (FP path)           |
          |    3. fp_agent_alert            (TP path)           |
          +----------------------+-----------------------------+
                                 | verified verdict result
                                 v
              +-------------------------------------------+
              |  post-verification stages (pipeline.py)    |
              |  FP: pr_backstop re-renders expected PR    |
              |      via `harness fp_agent_pr`; mismatch   |
              |      closes the PR, job fails              |
              |  TP: special_alert POSTs the               |
              |      fp_agent_alert envelope to ntfy and   |
              |      the Ed25519-signed feed sink          |
              +-------------------------------------------+
```

## Harness coupling: CLI and MCP, not imports

This repo does **not** depend on `trustsight-harness` as a Python package.
The harness is already installed in the job image. Two surfaces are used:

- **CLI**, from the pipeline: `harness fp_agent_verify --verdict <file>` and
  `harness fp_agent_pr --result <file> --target-repo <repo> --date <day>`.
  Object arguments travel as temp files (verdicts and results are capped near
  1 MiB, past argv limits), never as argv or stdin.
- **MCP**, from inside the sandbox: the agent calls the `harness` MCP tools
  `fp_agent_verify`, `fp_agent_pr`, and `fp_agent_alert`.

This keeps the two repos decoupled and lets the job image pin its own harness
version.

## Pipeline stages

1. **Dispatch** (`dispatcher.py`). `GET {TRUSTSIGHT_FEED_URL}/api/feed?event=
   trustsight.alerts` every `TRIAGE_POLL_INTERVAL_SECONDS` (default 120).
   Each feed row's payload is hashed as the canonical JSON of its
   `(alerts, over_threshold)` blocks; a hash already seen this process run is
   skipped, so re-delivered cycles do not double-enqueue. Each
   `over_threshold` entry becomes one job keyed by a sha256 content hash of
   the `(package, old_version, new_version, aur_url, rules)` payload
   (UNIQUE in SQLite, so restarts do not re-enqueue). Entries with
   `ioc_matches` are enqueued with kind `ioc` and resolve to the alert path
   without an agent run.
2. **Prompt build** (`prompt.py`). Embeds the package, AUR URL, version
   transition, fired rules, and findings, and instructs the agent to write
   `/job/verdict.json` matching the schema exactly, then call the harness
   tools in order. The instruction text deliberately avoids em dashes and
   ` -- ` to stay compatible with the harness format gate.
3. **Agent run** (`runner.py`, behind a `RunnerBackend`). `run_job` delegates
   the actual execution to a pluggable backend; the job image is the
   opencode container described below, and a `LocalStubBackend` writes a
   canned verdict for tests. opencode runs the triage agent under
   `agent/opencode.json`: model `opencode/MiMo-V2.6-Flash` with
   fallback models `opencode/grok-code` and `opencode/kimi-k2-thinking`, bash
   /edit/write tools disabled, and two MCP servers: `harness`
   (`harness-mcp`, read-only truth) and `github` (`github-mcp-server stdio
   --toolsets repos:contents,repos:pull_requests`, token from
   `GITHUB_PERSONAL_ACCESS_TOKEN`). The agent clones nothing and executes
   nothing: AUR evidence is inspected read-only.
4. **Verdict validation** (`runner.validate_verdict`). Strict local check
   before the harness is consulted: document at most 1 MiB, strings at most
   4096 chars, package name against the AUR-safe regex, exactly the schema
   keys. A symlinked verdict path is refused. `uncertain` or `low`
   confidence verdicts stop here as `needs_review` and never reach the
   harness.
5. **Harness verification** (`harness fp_agent_verify`). The verdict is
   cross-checked against deterministic, current-snapshot evidence in the
   harness (AUR replay of the cited rules via `check_phantom_install` and
   `check_url_in_source`, IOC schema validation for TP). Malformed input
   raises; unverifiable evidence returns `verified: false`. Fail closed is
   the only direction: the job fails rather than proceed on doubt.
6. **FP path: PR backstop** (`pr_backstop.py`). The agent opens the PR
   itself via the GitHub MCP tools, using exactly the branch, title, body,
   and file map returned by `fp_agent_pr`. The backstop re-fetches the
   opened PR over the GitHub REST API and re-renders the expected title and
   body with `harness fp_agent_pr --result <file> --target-repo trustsight
   --date <today>`. On title or body mismatch the PR is closed via PATCH and
   the job fails; a missing PR also fails. This is the second independent
   render of the same content, so format-gate or content drift between the
   agent's PR and the harness's canonical render cannot survive.
7. **TP path: special alert** (`special_alert.py`). The
   `harness fp_agent_alert` envelope (event `trustsight.confirmed-ioc`,
   priority deliberately `default`, never urgent) is POSTed to the ntfy
   webhook (`TRUSTSIGHT_NTFY_WEBHOOK`, with `Title` and `Priority` headers)
   and, when `TRUSTSIGHT_FEED_KEY` is set, to the signed feed sink. Feed
   signing mirrors `trustsight.notify` exactly: Ed25519 over
   `webhook_id.timestamp.body`, key as base64 PKCS#8 DER, deterministic
   webhook id so retried POSTs dedupe. The job only fails if no sink
   accepted the alert.

## Configuration

All settings come from the environment (`triage_agent.config.Settings`).
Secrets are never defaulted; `Settings.require_job_secrets()` enforces the
job-only ones (`GITHUB_PERSONAL_ACCESS_TOKEN`, `TRUSTSIGHT_FEED_KEY`) at run
time for real runs (unit tests and dry runs are exempt).

| Variable | Default | Meaning |
|---|---|---|
| `TRUSTSIGHT_FEED_URL` | `https://watcher.trustsight.org` | Feed sink base URL. Must be http(s). Also the signed-alert POST target. |
| `TRIAGE_POLL_INTERVAL_SECONDS` | `120` | Dispatcher poll interval. Minimum 1. |
| `TRUSTSIGHT_NTFY_WEBHOOK` | none | ntfy webhook URL for TP alerts. Optional; without it only the feed sink is tried. |
| `TRUSTSIGHT_FEED_KEY` | none | Base64 PKCS#8 (DER) Ed25519 private key for signed feed alerts. Required for real jobs. |
| `TRUSTSIGHT_FEED_KEY_ID` | `triage-agent` | `webhook-key-id` header value. |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | none | Token for the GitHub MCP server and the PR backstop REST calls. Required for real jobs. |
| `TRIAGE_MODEL` | `opencode/MiMo-V2.6-Flash` | Model route for the runner; matches the pin in `agent/opencode.json`. |
| `TRIAGE_JOB_ROOT` | `/job` | Directory the agent writes `verdict.json` under. |
| `TRIAGE_HARNESS_CLI` | `harness` | Harness CLI binary on PATH. |
| `TRIAGE_HARNESS_TIMEOUT_SECONDS` | `900` | Timeout for `harness` CLI invocations. |
| `TRIAGE_WARP_ROTATION` | `true` | Enable WARP egress rotation on 429s. |
| `TRIAGE_WARP_MAX_ROTATIONS` | `5` | Rotation budget per job before falling back. |
| `TRIAGE_WARP_BACKOFF_MIN` | `30.0` | Retry backoff lower bound (seconds); same default as `BackoffSchedule`. |
| `TRIAGE_WARP_BACKOFF_MAX` | `900.0` | Retry backoff upper bound (seconds); same default as `BackoffSchedule`. |
| `TRIAGE_WARP_BACKOFF_FACTOR` | `2.0` | Exponential factor; must be >= 1. |
| `TRIAGE_WARP_BACKOFF_JITTER` | `0.25` | Jitter fraction; must be in [0, 1). |
| `WARP_CLI` | `warp-cli` (on PATH) | warp-cli binary name override. |
| `ENABLE_WARP_ROTATION` | `0` (compose) | Container entrypoint switch: starts `warp-svc` manually. Separate from `TRIAGE_WARP_ROTATION`. |

Booleans accept `1/true/yes/on` and `0/false/no/off`; malformed values are a
`ConfigError`, as are out-of-range integers and non-http(s) feed URLs.

## The agent contract

`agent/AGENT.md` is the complete contract the opencode agent runs under.
Summary:

- One TrustSight watcher alert, one AUR package, two MCP servers: `harness`
  (verification and rendering, read-only truth) and `github` (contents and
  pull_requests only). No shell, no file edit tools, no network beyond those
  servers.
- Clone nothing, change nothing. The AUR repository is inspected read-only
  through prompt context and harness cross-checks.
- Decide FP, TP, or uncertain and write `/job/verdict.json` matching the
  schema exactly (`schema_version` 1, `package`, `verdict`, `confidence`,
  `rationale`, `evidence`, `proposed_changes`): no extra keys, no string over
  4096 characters, ASCII only, no em dashes, no ` -- `.
- Call `fp_agent_verify` with the verdict. On `verified: false` or an error
  (or an uncertain / low-confidence verdict), stop: the job ends as
  `needs_review` or `failed`. Never proceed on an unverified verdict.
- Verified FP: call `fp_agent_pr` with the verified result, then
  `create_branch`, `create_or_update_file` for every path in the returned
  files map, and `create_pull_request` with exactly the returned title and
  body onto the returned branch. Report the PR URL.
- Verified TP: call `fp_agent_alert` with the verified result and stop. The
  pipeline delivers the envelope; the agent posts nothing itself.
- One verdict file, one PR at most, one alert at most, per job. If any tool
  errors, stop and report the error string; do not retry in a loop and do
  not improvise around a failed tool.

## Security model

- **The agent is untrusted input.** Every layer assumes the model may
  misbehave, be prompt-injected by fetched content, or simply be wrong. The
  defense is layered, not supervisory: local verdict schema validation ->
  `fp_agent_verify` deterministic cross-check (fail closed) -> the harness
  format gate on every rendered string -> the PR backstop comparing the
  actually-opened PR against an independent re-render. A bad verdict cannot
  reach the outside world without passing all of them.
- **PRs are inert artifacts.** An FP produces a suppression proposal at
  `data/fp-suppressions/<date>-<pkg>.json` (or a triage report under
  `benign/fp-<date>/` in the harness repo); a TP produces a per-date IOC
  file at `data/iocs/triage-<date>.json`. None of it is live config: a
  maintainer reviews, signs, and merges. There is no auto-merge path
  anywhere in the pipeline.
- **Nothing fetched is executed.** The AUR snapshot is read-only evidence;
  the agent has no bash, edit, or write tool; opencode's own file access is
  limited to the verdict path the prompt provides.
- **Container hardening.** The job image builds from
  `python:3.12-slim-bookworm` and pins every fetched binary: `opencode-ai@1.19.3`
  from npm, `github-mcp-server` 2.0.2 with a sha256 checksum verified at
  build time, and Cloudflare WARP from Cloudflare's official apt repo. The
  compose service runs as the image's non-root `triage` user on a read-only
  root filesystem (writable scratch on `/tmp` and the WARP state dir
  `/var/lib/cloudflare-warp` as tmpfs), drops all capabilities and re-adds
  `NET_ADMIN` only for the job service because WARP's wireguard tunnel
  needs TUN device management, and sets `no-new-privileges`. The egress
  allowlist the container needs (AUR, git hosts, opencode.ai, feed sink,
  ntfy) is documented as a comment block in `docker-compose.yml`;
  enforcement is at the surrounding network/firewall layer, not compose.
- **Unsigned commits, by design.** The PR the agent opens is authored by the
  user's own GitHub account via `GITHUB_PERSONAL_ACCESS_TOKEN` and is
  deliberately unsigned and unprivileged. Combined with the inert-artifact
  rule and the maintainer merge gate, the token's blast radius is "open a
  clearly-labeled proposal PR", never "change what TrustSight runs".

## Rate limits and WARP rotation

Free model routes rate-limit; the policy (`rate_limit.py`) is deterministic
and pure, so tests pin the RNG and get exact delays.

- **Backoff.** `BackoffSchedule`: exponential, factor 2, from 30 s to a 900 s
  cap, plus up to 25% jitter. `detect_429` matches HTTP 429 or "rate limit"
  in the response text. `WarpSettings.schedule()` builds the schedule from
  config (`TRIAGE_WARP_BACKOFF_*`), which is the single source of truth:
  the defaults in `config.py` are these numbers, not placeholders.
- **Rotation policy.** `RotationPolicy.decide` on a detected 429: rotate WARP
  egress while `rotations_used < TRIAGE_WARP_MAX_ROTATIONS` (default 5), then
  one fallback-model attempt (the `fallback_models` list in
  `agent/opencode.json`), then fail the job. A non-429 error fails the job
  immediately; the rotation policy is not a generic retry mechanism.
- **Warp management** (`warp.py`). `WarpManager` drives `warp-cli` against
  `warp-svc`. There is no systemd in a container, so `docker/entrypoint.sh`
  starts `warp-svc` manually when `ENABLE_WARP_ROTATION=1` and waits for the
  CLI socket. Every manager method returns `(ok, detail)` and never raises:
  a warp failure fails the current job, never the dispatcher loop. Rotation
  is `registration delete`, `registration new --accept-terms`, `connect`,
  then a bounded wait for the Connected status. If warp cannot connect, the
  job fails open without rotation rather than blocking the queue.

## Failure modes

| Condition | Behaviour |
|---|---|
| Feed poll fails (network, parse) | Logged, loop continues; retried next cycle. Never crashes the dispatcher. |
| Verdict fails local validation | Job -> `failed` with the validation reason. |
| Verdict `uncertain` or `low` confidence | Job -> `needs_review`; harness verification is never invoked. Re-queueable via `needs_review -> running`. |
| `fp_agent_verify` returns `verified: false` | Job -> `failed`; the verify reason is recorded. The agent is instructed to stop before this on its own. |
| `fp_agent_verify` CLI error | Job -> `failed` with the harness stderr excerpt. |
| FP without a PR from the agent | Job -> `failed` ("no PR found"). |
| PR backstop mismatch | The PR is closed via GitHub PATCH and the job -> `failed` with `title mismatch` / `body mismatch`. A failed close is noted in the reason. |
| Backstop cannot render or reach GitHub | Job -> `failed` (backstop never raises; every failure is `ok=False`). |
| TP alert rejected by all sinks | Job -> `failed`; the alert envelope is dropped (logged), never retried in-band. |
| Warp down / cannot connect | The rotation attempt returns `ok=False`; the job proceeds fail-open on the plain egress. Warp failure never kills the dispatcher. |
| Rotation budget exhausted | One fallback-model attempt; if that is also rate limited, the job -> `failed`. |
| Missing job secrets | `Settings.require_job_secrets()` raises `ConfigError` before a real run starts. |

## Development and testing

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest -q
```

### Dry run

`scripts/dry_run.py` exercises the full pipeline end to end without a real
LLM, without touching the real GitHub repos, and without a GITHUB token,
ntfy webhook, or feed key:

```bash
uv run python scripts/dry_run.py --mode fp    # FP path: PR backstop (default)
uv run python scripts/dry_run.py --mode ioc   # TP/IOC path: special alert
```

Both modes replay a canned verdict (`tests/fixtures/verdict_niri_screenshare_*.json`,
derived from the real `fp-2026-10-16` `niri-screenshare` entry) through
`backends.ReplayBackend` instead of running opencode, and drive the real
`pipeline.process_job` against a temp SQLite queue. What it touches:

- **Real harness CLI** (`harness fp_agent_verify --verdict <file>`,
  `fp_agent_pr`, `fp_agent_alert`) against the **real AUR** — read-only
  RPC/API traffic is the only network access; nothing is written anywhere.
- **GitHub**: an in-process localhost stub (`tests/stub_github.py`,
  `GitHubApiStub`) serving `GET`/`PATCH /repos/{o}/{r}/pulls/{n}`, seeded
  with exactly the title and body `fp_agent_pr` rendered. A dummy bearer
  token is sent; it is never validated.
- **ntfy/feed**: an in-process localhost receiver (`AlertSinkStub`) records
  the POSTed alert envelope; the signed feed sink is skipped (no key).

The script prints a stage-by-stage report (enqueue, verify, render,
pipeline, backstop/alert sink) and exits non-zero if any gate fails. What
it proves: the queue transitions reach `pr_opened` (fp) or `alert_sent`
(ioc), the harness cross-check accepts the canned verdicts against live AUR
evidence, and the backstop/alert delivery stages integrate end to end. The
composition is also covered offline (fake verify/render, real stubs) in
`tests/test_dry_run.py`.

102 offline tests cover the dispatcher, queue, verdict validation, pipeline
composition, PR backstop, special alert, warp manager, and rate-limit policy;
the queue and verdict paths run against fakes with no network.

CI (`.github/workflows/ci.yml`) has two jobs, deliberately isolated so a
WARP outage never blocks the offline suite:

- **unit**: `uv sync --extra dev`, `ruff check`, `pytest -q`.
- **warp-integration**: installs Cloudflare WARP on the runner, starts
  `warp-svc` manually exactly like the container entrypoint, registers an
  anonymous consumer (`warp-cli registration new --accept-terms`), connects,
  and asserts the egress is really WARP via `cloudflare.com/cdn-cgi/trace`.
  It then drives the fake-429 rotation path with the unit-test fake warp
  binary (`WARP_CLI` pointed at a script) and asserts the exact
  `registration delete` / `registration new --accept-terms` / `connect`
  sequence. Needs no secrets.

## Container

`Dockerfile` (build context: the directory containing the three sibling
checkouts, see `docker-compose.yml`) installs the pinned opencode CLI,
GitHub's official `github-mcp-server` (pinned version + sha256), and
Cloudflare WARP from the official apt repo. The three sibling checkouts
(`trustsight`, `trustsight-harness`, `trustsight-triage-agent`) are copied
side by side because the harness's `[tool.uv.sources]` expects
`../trustsight`; the harness venv's `harness-mcp` is on PATH via
`HARNESS_MCP_COMMAND`. There is no systemd in the container, so
`docker/entrypoint.sh` starts `warp-svc` manually when
`ENABLE_WARP_ROTATION=1`. Build and run:

```bash
docker compose -f trustsight-triage-agent/docker-compose.yml up --build
```

## Status

Core runtime modules, warp rotation, PR backstop, special alert delivery,
pipeline composition, agent contract, container build, and CI are in place;
102 offline tests cover the dispatcher/queue/verdict runner plus the new
modules.
