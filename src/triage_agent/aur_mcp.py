"""Read-only AUR MCP server: files from the snapshot tarball, git history.

The third MCP server the triage agent talks to (alongside the harness and
GitHub servers). The harness MCP already covers AUR metadata (``aur_info``)
and the PKGBUILD text (``aur_pkgbuild``); this server adds the two pieces
it lacks:

- ``aur_file(package, filename)``: any small build file from the AUR
  snapshot tarball (.install files, patches, desktop entries), so the
  agent never needs curl or git to inspect them.
- ``aur_git_log(package, limit)``: recent commit history of the package's
  AUR git repository, to establish whether the flagged change matches an
  upstream release or is an out-of-band edit.

Everything is read-only and bounded: package names are validated against
the AUR-safe regex, paths are basenames (no traversal), the snapshot is
read fully in memory with compressed/uncompressed caps, and the git clone
is a bare, blob-less, depth-capped shallow fetch into a temp dir. Nothing
is executed; the only network peers are aur.archlinux.org.

Run: ``python -m triage_agent.aur_mcp`` (stdio).
"""

from __future__ import annotations

import io
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

import httpx

_NAME_RE = re.compile(r"^[A-Za-z0-9@_+][A-Za-z0-9@._+-]{0,254}\Z")

SNAPSHOT_URL = "https://aur.archlinux.org/cgit/aur.git/snapshot/{}.tar.gz"
GIT_URL = "https://aur.archlinux.org/{}.git"

MAX_SNAPSHOT_COMPRESSED = 10 * 1024 * 1024  # 10 MiB compressed tarball
MAX_SNAPSHOT_TOTAL = 20 * 1024 * 1024  # 20 MiB uncompressed members
MAX_FILE_BYTES = 512 * 1024  # per extracted file, plenty for build scripts
MAX_FILES = 256  # members kept from one snapshot
MAX_GIT_LOG = 50  # depth and entry cap for aur_git_log
HTTP_TIMEOUT = 30.0

#: Per-process snapshot cache: validated package name -> {filename: bytes}.
#: One MCP server process serves one job, so this is exactly the "cached
#: per job" lifetime.
_SNAPSHOTS: dict[str, dict[str, bytes]] = {}

_CLIENT: httpx.Client | None = None


def _http_get(url: str) -> bytes:
    """One bounded GET. Split out so tests can monkeypatch it."""

    global _CLIENT
    if _CLIENT is None:
        _CLIENT = httpx.Client(timeout=HTTP_TIMEOUT)
    resp = _CLIENT.get(url)
    resp.raise_for_status()
    if len(resp.content) > MAX_SNAPSHOT_COMPRESSED:
        raise ValueError(f"response exceeds {MAX_SNAPSHOT_COMPRESSED} bytes")
    return resp.content


def _check_name(package: str) -> str:
    if not isinstance(package, str) or not _NAME_RE.match(package):
        raise ValueError(f"invalid AUR package name: {package!r}")
    return package


def fetch_snapshot(package: str) -> dict[str, bytes]:
    """Small files from the package's AUR snapshot tarball, cached.

    Returns a mapping of relative file name to content; members larger
    than :data:`MAX_FILE_BYTES` are dropped (the agent does not need
    shipped binaries or sources for triage).
    """

    name = _check_name(package)
    if name in _SNAPSHOTS:
        return _SNAPSHOTS[name]
    data = _http_get(SNAPSHOT_URL.format(name))
    files: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            # The snapshot root is <base>/; strip it and refuse anything
            # that tries to escape (absolute paths, dotdots, nesting).
            if len(parts) != 2 or parts[1] in ("", ".", ".."):
                continue
            if member.size > MAX_FILE_BYTES:
                continue
            if total + member.size > MAX_SNAPSHOT_TOTAL:
                break
            if len(files) >= MAX_FILES:
                break
            handle = archive.extractfile(member)
            if handle is None:
                continue
            content = handle.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                continue
            files[parts[1]] = content
            total += len(content)
    _SNAPSHOTS[name] = files
    return files


def aur_file_impl(package: str, filename: str) -> dict:
    """Content of one build file from the AUR snapshot (read-only)."""

    try:
        name = _check_name(package)
        base = Path(str(filename)).name
        if not base or base != str(filename):
            return {"error": f"filename must be a plain name: {filename!r}"}
        files = fetch_snapshot(name)
        if base not in files:
            return {"error": f"{base} not in the {name} snapshot",
                    "files": sorted(files)}
        return {"package": name, "filename": base,
                "content": files[base].decode("utf-8", "replace"),
                "size": len(files[base])}
    except ValueError as exc:
        return {"error": str(exc)}
    except httpx.HTTPError as exc:
        return {"error": f"AUR request failed: {type(exc).__name__}"}


def aur_git_log_impl(package: str, limit: int = 20) -> dict:
    """Recent commits of the package's AUR git repository.

    A bare, blob-less, depth-capped shallow clone into a temp dir; only
    ``git log`` output is returned. Establishes whether the flagged
    version transition corresponds to an upstream commit.
    """

    try:
        name = _check_name(package)
        count = max(1, min(int(limit), MAX_GIT_LOG))
    except (ValueError, TypeError) as exc:
        return {"error": f"invalid arguments: {exc}"}
    with tempfile.TemporaryDirectory(prefix="aur-log-") as tmp:
        clone = subprocess.run(
            ["git", "clone", "--bare", "--single-branch", "--depth",
             str(count), "--filter=blob:none", GIT_URL.format(name), tmp],
            capture_output=True, text=True, timeout=120,
        )
        if clone.returncode != 0:
            return {"error": f"git clone failed: {clone.stderr.strip()[:300]}"}
        log = subprocess.run(
            ["git", "-C", tmp, "log", f"-n{count}",
             "--pretty=format:%H%x1f%an%x1f%ad%x1f%s", "--date=iso-strict"],
            capture_output=True, text=True, timeout=60,
        )
        if log.returncode != 0:
            return {"error": f"git log failed: {log.stderr.strip()[:300]}"}
    commits = []
    for line in log.stdout.splitlines():
        fields = line.split("\x1f")
        if len(fields) == 4:
            commits.append({"sha": fields[0], "author": fields[1],
                            "date": fields[2], "subject": fields[3]})
    return {"package": name, "commits": commits}


def main() -> None:
    from mcp.server.mcpserver import MCPServer

    mcp = MCPServer(
        "trustsight-aur",
        instructions=(
            "Read-only AUR access for TrustSight triage: build files from "
            "the snapshot tarball and recent git history. No writes, no "
            "arbitrary URLs."
        ),
    )

    @mcp.tool()
    def aur_file(package: str, filename: str) -> dict:
        """Fetch one build file (.install, patch, desktop entry) from the
        AUR snapshot tarball for a package. Returns its text content."""
        return aur_file_impl(package, filename)

    @mcp.tool()
    def aur_git_log(package: str, limit: int = 20) -> dict:
        """Recent commits of the package's AUR git repository (sha, author,
        date, subject), newest first. Use to check whether the flagged
        version transition matches an upstream release."""
        return aur_git_log_impl(package, limit)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
