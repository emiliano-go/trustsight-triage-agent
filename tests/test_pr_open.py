"""Orchestrator-side PR creation over a stubbed GitHub REST API."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from triage_agent.pr_open import PrOpenError, open_pr

RENDERED = {
    "branch": "triage/fp-multi-deadbeef",
    "title": "FP triage: pkg-a, pkg-b (+1 more)",
    "body": "| Finding | False trigger | Fix |\n",
    "files": {
        "data/fp-suppressions/2026-10-17-pkg-a.json": '{"a": 1}\n',
        "data/fp-suppressions/2026-10-17-pkg-b.json": '{"b": 2}\n',
    },
}


class GitHubWriteStub:
    """Serves the git ref, contents, and pulls write slice of the API."""

    def __init__(self, *, pulls_status: int = 201, ref_status: int = 200):
        self.requests: list[dict] = []
        self.pulls_status = pulls_status
        self.ref_status = ref_status
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib name
                stub._record("GET", self)
                if "git/ref/heads/" in self.path:
                    if stub.ref_status != 200:
                        self._reply(stub.ref_status, {"message": "no"})
                        return
                    self._reply(200, {"object": {"sha": "abc123"}})
                    return
                self._reply(404, {"message": "unexpected"})

            def do_POST(self) -> None:  # noqa: N802 - stdlib name
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                stub._record("POST", self, body)
                if self.path.endswith("/git/refs"):
                    self._reply(201, {})
                elif self.path.endswith("/pulls"):
                    if stub.pulls_status != 201:
                        self._reply(stub.pulls_status, {"message": "no"})
                        return
                    self._reply(201, {"html_url":
                                      "https://github.com/acme/t/pull/9"})
                else:
                    self._reply(404, {"message": "unexpected"})

            def do_PUT(self) -> None:  # noqa: N802 - stdlib name
                stub._record("PUT", self)
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                self._reply(201, {"content": {}})

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/vnd.github+json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    @property
    def api_base(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def _record(self, method: str, handler: BaseHTTPRequestHandler,
                body: dict | None = None) -> None:
        entry = {"method": method, "path": handler.path}
        if body is not None:
            entry["body"] = body
        self.requests.append(entry)

    def paths(self, method: str) -> list[str]:
        return [r["path"] for r in self.requests if r["method"] == method]

    def __enter__(self) -> GitHubWriteStub:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def test_open_pr_creates_branch_files_and_pr():
    with GitHubWriteStub() as gh:
        url = open_pr(
            RENDERED, token="tok", owner="acme",
            api_base=gh.api_base,
        )
    assert url == "https://github.com/acme/t/pull/9"
    assert any("git/ref/heads/main" in p for p in gh.paths("GET"))
    assert any(p.endswith("/git/refs") for p in gh.paths("POST"))
    ref_posts = [r for r in gh.requests
                 if r["method"] == "POST" and r["path"].endswith("/git/refs")]
    assert ref_posts[0]["body"]["ref"] == "refs/heads/triage/fp-multi-deadbeef"
    puts = gh.paths("PUT")
    for path in RENDERED["files"]:
        assert any(urlparse(p).path.endswith(f"/contents/{path}")
                   for p in puts)
    pulls = [p for p in gh.paths("POST") if p.endswith("/pulls")]
    assert len(pulls) == 1


def test_open_pr_requires_token():
    with pytest.raises(PrOpenError, match="token"):
        open_pr(RENDERED, token=None, owner="acme",
                client=object())


def test_open_pr_requires_branch_and_files():
    with GitHubWriteStub() as gh:
        with pytest.raises(PrOpenError, match="branch or files"):
            open_pr({"title": "t"}, token="tok", owner="acme",
                    api_base=gh.api_base)


def test_open_pr_surfaces_pull_failure():
    with GitHubWriteStub(pulls_status=422) as gh:
        with pytest.raises(PrOpenError, match="cannot open PR"):
            open_pr(RENDERED, token="tok", owner="acme",
                    api_base=gh.api_base)


def test_open_pr_surfaces_missing_base_branch():
    with GitHubWriteStub(ref_status=404) as gh:
        with pytest.raises(PrOpenError, match="base branch"):
            open_pr(RENDERED, token="tok", owner="acme",
                    api_base=gh.api_base)
