"""In-process localhost HTTP stubs, reusable by tests and ``scripts/dry_run.py``.

``GitHubApiStub`` serves the small slice of the GitHub REST API the PR
backstop uses: ``GET`` and ``PATCH /repos/{owner}/{repo}/pulls/{number}``
plus ``GET /repos/{owner}/{repo}/pulls`` (the list endpoint, honoring the
``state`` and ``head`` query filters for PR discovery by branch).
``AlertSinkStub`` accepts any POST (the ntfy webhook shape) and records it.
Both run on 127.0.0.1 port 0 in a daemon thread and are context managers.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAX_BODY_BYTES = 1 << 20

_PULLS_LIST_RE = re.compile(r"\A/repos/[^/]+/[^/]+/pulls\Z")


class GitHubApiStub:
    """A fake GitHub pull-requests endpoint.

    Args:
        pr: The PR payload GET returns and PATCH mutates (``state`` set to
            ``closed`` on PATCH).
        pulls: PR payloads for the list endpoint (discovery by branch).
            Each may carry ``head: {"ref": branch}``; the ``head`` query
            filter matches on that ref (``owner:branch`` or bare branch).
        status: HTTP status GET answers with (use 404 to simulate a missing
            PR); PATCH always answers 200.
    """

    def __init__(
        self,
        *,
        pr: dict | None = None,
        pulls: list | None = None,
        status: int = 200,
        owner: str = "acme",
        repo: str = "trustsight",
        number: int = 42,
    ):
        self.pr = pr if pr is not None else {}
        self.pulls = pulls
        self.status = status
        self.owner = owner
        self.repo = repo
        self.number = number
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib name
                stub._record("GET", self)
                parsed = urlparse(self.path)
                if _PULLS_LIST_RE.match(parsed.path):
                    self._reply(200, stub._list_pulls(parsed.query))
                    return
                if stub.status != 200:
                    self._reply(stub.status, {"message": "Not Found"})
                    return
                self._reply(200, stub.pr)

            def do_PATCH(self) -> None:  # noqa: N802 - stdlib name
                stub._record("PATCH", self)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, MAX_BODY_BYTES))
                if json.loads(body or b"{}").get("state") == "closed":
                    stub.pr["state"] = "closed"
                self._reply(200, stub.pr)

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/vnd.github+json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: object) -> None:
                return  # keep test output quiet

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def _record(self, method: str, handler: BaseHTTPRequestHandler) -> None:
        self.requests.append({"method": method, "path": handler.path})

    def _list_pulls(self, query: str) -> list:
        if self.pulls is None:
            return []
        head = parse_qs(query).get("head", [None])[0]
        if not head:
            return list(self.pulls)
        branch = head.rsplit(":", 1)[-1]
        return [
            p
            for p in self.pulls
            if p.get("head", {}).get("ref") == branch
            or p.get("head", {}).get("ref") == head
        ]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def api_base(self) -> str:
        return self.url

    @property
    def pr_url(self) -> str:
        return (
            f"https://github.com/{self.owner}/{self.repo}/pull/{self.number}"
        )

    @property
    def patches(self) -> list[dict]:
        return [r for r in self.requests if r["method"] == "PATCH"]

    def __enter__(self) -> GitHubApiStub:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class AlertSinkStub:
    """Records every POST (ntfy webhook shape); always answers 200."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib name
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, MAX_BODY_BYTES))
                stub.received.append(
                    {
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(body or b"null"),
                    }
                )
                data = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: object) -> None:
                return  # keep test output quiet

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}/alerts"

    def __enter__(self) -> AlertSinkStub:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
