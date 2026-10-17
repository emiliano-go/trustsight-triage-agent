"""Orchestrator-side PR creation over the GitHub REST API.

Single-package jobs keep the existing flow: the in-container agent opens the
PR itself through the GitHub MCP tools.  Multi-package jobs aggregate FP
packages into one PR *after* every per-package agent run, so the orchestrator
opens that PR directly, using exactly the branch, title, body, and file map
the harness ``fp_agent_pr`` op rendered (the same render the PR backstop
recomputes for comparison).  The same helper also opens the per-package IOC
register PRs that confirmed (TP) packages in a multi-package job need, since
the multi-package analysis prompt tells the agent not to touch GitHub.

Nothing here raises anything but :class:`PrOpenError` with an
operator-readable reason; callers fail the job closed on error.
"""

from __future__ import annotations

import base64
import logging
from typing import Protocol

import httpx

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 1 << 20
API_BASE = "https://api.github.com"
DEFAULT_BASE_BRANCH = "main"


class PrOpenError(RuntimeError):
    pass


class HttpClient(Protocol):
    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response: ...


def _check_size(resp: httpx.Response) -> None:
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise PrOpenError("GitHub API response exceeds size cap")


def _request(
    http: HttpClient,
    method: str,
    url: str,
    *,
    token: str,
    timeout: float,
    **kwargs: object,
) -> httpx.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    resp = http.request(method, url, headers=headers, timeout=timeout, **kwargs)
    _check_size(resp)
    return resp


def create_branch(
    http: HttpClient,
    *,
    owner: str,
    repo: str,
    branch: str,
    token: str,
    base_branch: str = DEFAULT_BASE_BRANCH,
    api_base: str = API_BASE,
    timeout: float = 30.0,
) -> None:
    """Create ``refs/heads/<branch>`` at the base branch's current head."""

    ref_url = f"{api_base}/repos/{owner}/{repo}/git/ref/heads/{base_branch}"
    resp = _request(http, "GET", ref_url, token=token, timeout=timeout)
    if resp.status_code != 200:
        raise PrOpenError(
            f"cannot read base branch {base_branch}: {resp.status_code}"
        )
    base = resp.json()
    try:
        sha = base["object"]["sha"]
    except (TypeError, KeyError) as exc:
        raise PrOpenError(f"unexpected base ref payload: {exc}") from exc
    resp = _request(
        http,
        "POST",
        f"{api_base}/repos/{owner}/{repo}/git/refs",
        token=token,
        timeout=timeout,
        json={"ref": f"refs/heads/{branch}", "sha": sha},
    )
    if resp.status_code not in (201, 422):  # 422: ref already exists
        raise PrOpenError(f"cannot create branch {branch}: {resp.status_code}")


def put_files(
    http: HttpClient,
    *,
    owner: str,
    repo: str,
    branch: str,
    files: dict[str, str],
    token: str,
    api_base: str = API_BASE,
    timeout: float = 30.0,
) -> None:
    """Create one commit per path on *branch* with the rendered content."""

    for path, content in files.items():
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        resp = _request(
            http,
            "PUT",
            f"{api_base}/repos/{owner}/{repo}/contents/{path}",
            token=token,
            timeout=timeout,
            json={
                "message": f"Add {path}",
                "content": encoded,
                "branch": branch,
            },
        )
        if resp.status_code not in (200, 201):
            raise PrOpenError(f"cannot write {path}: {resp.status_code}")


def create_pull_request(
    http: HttpClient,
    *,
    owner: str,
    repo: str,
    rendered: dict,
    token: str,
    base_branch: str = DEFAULT_BASE_BRANCH,
    api_base: str = API_BASE,
    timeout: float = 30.0,
) -> str:
    """Open the PR for a harness ``fp_agent_pr`` render; return its html_url."""

    branch = rendered["branch"]
    resp = _request(
        http,
        "POST",
        f"{api_base}/repos/{owner}/{repo}/pulls",
        token=token,
        timeout=timeout,
        json={
            "title": rendered["title"],
            "head": branch,
            "base": base_branch,
            "body": rendered["body"],
        },
    )
    if resp.status_code != 201:
        raise PrOpenError(f"cannot open PR: {resp.status_code}")
    try:
        return resp.json()["html_url"]
    except (TypeError, KeyError) as exc:
        raise PrOpenError(f"unexpected pulls payload: {exc}") from exc


def open_pr(
    rendered: dict,
    *,
    token: str,
    owner: str,
    repo: str = "trustsight",
    client: HttpClient | None = None,
    base_branch: str = DEFAULT_BASE_BRANCH,
    api_base: str = API_BASE,
    timeout: float = 30.0,
) -> str:
    """Create branch, upload every rendered file, and open the PR.

    Returns the PR's html_url. Raises :class:`PrOpenError` on any failure;
    a failure after the branch or some files landed leaves the orphaned
    branch behind (harmless: the backstop only ever matches the exact
    rendered branch and title/body).
    """

    if not token:
        raise PrOpenError("github token not configured")
    branch = rendered.get("branch")
    files = rendered.get("files")
    if not branch or not isinstance(files, dict) or not files:
        raise PrOpenError("harness render lacks a branch or files")
    if client is not None:
        return _open_pr(
            client, rendered, token=token, owner=owner, repo=repo,
            base_branch=base_branch, api_base=api_base, timeout=timeout,
        )
    with httpx.Client() as http:
        return _open_pr(
            http, rendered, token=token, owner=owner, repo=repo,
            base_branch=base_branch, api_base=api_base, timeout=timeout,
        )


def _open_pr(
    http: HttpClient,
    rendered: dict,
    *,
    token: str,
    owner: str,
    repo: str,
    base_branch: str,
    api_base: str,
    timeout: float,
) -> str:
    create_branch(
        http, owner=owner, repo=repo, branch=rendered["branch"], token=token,
        base_branch=base_branch, api_base=api_base, timeout=timeout,
    )
    put_files(
        http, owner=owner, repo=repo, branch=rendered["branch"],
        files=rendered["files"], token=token, api_base=api_base, timeout=timeout,
    )
    return create_pull_request(
        http, owner=owner, repo=repo, rendered=rendered, token=token,
        base_branch=base_branch, api_base=api_base, timeout=timeout,
    )
