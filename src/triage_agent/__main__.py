"""Console entry point: dispatcher loop, worker loop, or queue status."""

from __future__ import annotations

import argparse
import logging
import sys

from .config import ConfigError, Settings
from .dispatcher import run_forever as dispatch_forever
from .queue import JobQueue

log = logging.getLogger(__name__)


def _cmd_dispatch(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    with JobQueue(args.db) as queue:
        requeued = queue.requeue_stale(settings.stale_job_seconds)
        if requeued:
            log.warning("requeued %d stale running job(s) on startup",
                        requeued)
        dispatch_forever(settings, queue)
    return 0


def _cmd_worker(args: argparse.Namespace) -> int:
    from .worker import Worker

    settings = Settings.from_env()
    settings.require_job_secrets()
    with JobQueue(args.db) as queue:
        worker = Worker(settings, queue)
        worker.install_signal_handlers()
        worker.run_forever()
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    with JobQueue(args.db) as queue:
        for status, count in queue.counts().items():
            print(f"{status}: {count}")
    return 0


def _cmd_agent_job(args: argparse.Namespace) -> int:
    from .agent_job import main as agent_job_main

    return agent_job_main(args.args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triage-agent")
    parser.add_argument(
        "command",
        nargs="?",
        default="dispatch",
        choices=["dispatch", "worker", "status", "agent-job"],
        help=(
            "dispatch: feed poll loop (default); worker: claim and run"
            " queued jobs; status: queue counts by state; agent-job:"
            " in-container agent entrypoint (run by the docker backend)"
        ),
    )
    parser.add_argument("--db", default="triage.sqlite3", help="queue DB path")
    parser.add_argument(
        "args",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    try:
        if args.command == "status":
            return _cmd_status(args)
        if args.command == "worker":
            return _cmd_worker(args)
        if args.command == "agent-job":
            return _cmd_agent_job(args)
        return _cmd_dispatch(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
