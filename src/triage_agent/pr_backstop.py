"""PR backstop: verify the PR the agent opened matches the harness render.

After a job verifies FP, the agent (behind the backend) opens a PR through
the GitHub MCP tools.  This module re-fetches that PR over the GitHub REST
API and recomputes the expected title and body by re-running
``harness fp_agent_pr`` against the verified result, exactly the render the
agent was instructed to use.  On any mismatch the PR is closed via PATCH
and the job fails closed: a wrong PR must not linger open.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import date
from typing import Protocol

import httpx

MAX_RESPONSE_BYTES = 1 << 20
API_BASE = "https://api.github.com"

_PR_URL_RE = re.compile(
    r"\Ahttps://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)/?\Z"
)


class BackstopError(RuntimeError):
    pass


@dataclass(frozen=True)
class BackstopResult:
    ok: bool
    reason: str | None = None
    pr_url: str | None = None


class HttpClient(Protocol):
    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response: ...


def parse_pr_url(pr_url: str) -> tuple[str, str, int]:
    match = _PR_URL_RE.match(pr_url.strip())
    if not match:
        raise BackstopError(f"not a GitHub PR URL: {pr_url!r}")
    return match["owner"], match["repo"], int(match["number"])


def harness_render_pr(
    verify_result: dict,
    *,
    target_repo: str = "trustsight",
    day: str | None = None,
    cli: str = "harness",
    timeout: int = 900,
) -> dict:
    """Recompute the expected PR content via `harness fp_agent_pr`.

    Invokes the real CLI flags:
    ``harness fp_agent_pr --result <file> --target-repo <repo> --date <day>``.
    The result travels as a temp file because argv has a size limit and
    verified results can approach the 1 MiB verdict cap. *day* defaults to
    today (UTC), matching the render the agent was instructed to use.
    """

    if day is None:
        day = date.today().isoformat()
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", encoding="utf-8", delete=False
    ) as handle:
        json.dump(verify_result, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [cli, "fp_agent_pr", "--result", path,
             "--target-repo", target_repo, "--date", day],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    finally:
        os.unlink(path)
    if proc.returncode != 0:
        raise BackstopError(
            f"harness fp_agent_pr exited {proc.returncode}:"
            f" {proc.stderr.strip()[:512]}"
        )
    rendered = json.loads(proc.stdout)
    if not isinstance(rendered, dict) or "error" in rendered:
        raise BackstopError(f"harness fp_agent_pr: {rendered.get('error')}")
    return rendered


def _check_size(resp: httpx.Response) -> None:
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise BackstopError("GitHub API response exceeds size cap")


def find_pr(
    *,
    branch: str,
    repo: str,
    token: str,
    client: HttpClient,
    api_base: str = API_BASE,
    timeout: float = 30.0,
    head_owner: str | None = None,
) -> str | None:
    """Discover the open PR for *branch* via the pulls list endpoint.

    *repo* is the full ``owner/name`` the PR targets. GitHub's ``head``
    filter wants ``owner:branch``; when *head_owner* is unknown the bare
    branch is passed, which the API and the offline stub both accept.
    Returns the PR's html_url, or None when no open PR matches.
    """

    head = f"{head_owner}:{branch}" if head_owner else branch
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    resp = client.request(
        "GET",
        f"{api_base}/repos/{repo}/pulls",
        params={"state": "open", "head": head},
        headers=headers,
        timeout=timeout,
    )
    _check_size(resp)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    items = resp.json()
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    return first.get("html_url")


def check_pr(
    *,
    pr_url: str | None,
    verify_result: dict,
    token: str | None,
    client: HttpClient | None = None,
    cli: str = "harness",
    timeout: float = 30.0,
    target_repo: str = "trustsight",
    day: str | None = None,
    api_base: str = API_BASE,
    discover_branch: bool = False,
    pr_owner: str | None = None,
) -> BackstopResult:
    """Fetch the PR, compare title and body against the harness render.

    Never raises: every failure mode returns ``BackstopResult(ok=False)``.
    When *pr_url* is None and *discover_branch* is set, the PR is located
    through the pulls list endpoint by the branch of the harness render
    (the agent opens the PR itself and only GitHub knows its URL).
    """

    if not token:
        return BackstopResult(False, "github token not configured")
    try:
        if pr_url is not None:
            owner, repo, number = parse_pr_url(pr_url)
            expected = harness_render_pr(
                verify_result, target_repo=target_repo, day=day, cli=cli
            )
        else:
            if not discover_branch:
                return BackstopResult(False, "no PR URL and discovery disabled")
            expected = harness_render_pr(
                verify_result, target_repo=target_repo, day=day, cli=cli
            )
            branch = expected.get("branch")
            if not branch:
                return BackstopResult(False, "harness render has no branch")
            if client is None:
                with httpx.Client() as http:
                    pr_url = find_pr(
                        branch=branch,
                        repo=f"{pr_owner}/{target_repo}" if pr_owner
                        else target_repo,
                        token=token,
                        client=http,
                        api_base=api_base,
                        timeout=timeout,
                        head_owner=pr_owner,
                    )
            else:
                pr_url = find_pr(
                    branch=branch,
                    repo=f"{pr_owner}/{target_repo}" if pr_owner
                    else target_repo,
                    token=token,
                    client=client,
                    api_base=api_base,
                    timeout=timeout,
                    head_owner=pr_owner,
                )
            if pr_url is None:
                return BackstopResult(False, "no PR found")
            owner, repo, number = parse_pr_url(pr_url)
    except Exception as exc:
        return BackstopResult(False, f"backstop setup: {exc}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    api_url = f"{api_base}/repos/{owner}/{repo}/pulls/{number}"
    try:
        if client is not None:
            result = _verify_pr(http=client, api_url=api_url, headers=headers,
                                expected=expected, timeout=timeout)
        else:
            with httpx.Client() as http:
                result = _verify_pr(http=http, api_url=api_url, headers=headers,
                                    expected=expected, timeout=timeout)
    except Exception as exc:
        return BackstopResult(False, f"github api: {exc}")
    if result.ok:
        return BackstopResult(True, pr_url=pr_url)
    return result


def _verify_pr(
    *,
    http: HttpClient,
    api_url: str,
    headers: dict[str, str],
    expected: dict,
    timeout: float,
) -> BackstopResult:
    resp = http.request("GET", api_url, headers=headers, timeout=timeout)
    _check_size(resp)
    if resp.status_code == 404:
        return BackstopResult(False, "no PR found")
    resp.raise_for_status()
    pr = resp.json()
    if not isinstance(pr, dict):
        return BackstopResult(False, "unexpected PR payload")
    title_ok = pr.get("title") == expected["title"]
    body_ok = (pr.get("body") or "") == expected["body"]
    if title_ok and body_ok:
        return BackstopResult(True)
    detail = (
        "title mismatch" if not title_ok
        else "body mismatch (format gate or content drift)"
    )
    close = http.request(
        "PATCH", api_url, headers=headers, json={"state": "closed"}, timeout=timeout
    )
    if close.status_code != 200:
        detail += f"; close PATCH failed ({close.status_code})"
    return BackstopResult(False, detail)
