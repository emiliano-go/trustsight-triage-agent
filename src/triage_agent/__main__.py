"""Console entry point: dispatcher loop or single-job verification."""

from __future__ import annotations

import argparse
import logging
import sys

from .config import ConfigError, Settings
from .dispatcher import run_forever
from .queue import JobQueue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triage-agent")
    parser.add_argument(
        "command",
        nargs="?",
        default="dispatch",
        choices=["dispatch"],
        help="dispatch: run the feed poll loop (default)",
    )
    parser.add_argument("--db", default="triage.sqlite3", help="queue DB path")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    with JobQueue(args.db) as queue:
        run_forever(settings, queue)
    return 0


if __name__ == "__main__":
    sys.exit(main())
