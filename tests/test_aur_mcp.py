"""aur_mcp: snapshot extraction, name validation, git log, size caps."""

from __future__ import annotations

import io
import json
import tarfile
from types import SimpleNamespace

import pytest

from triage_agent import aur_mcp


def _tarball(files: dict[str, bytes], root: str = "pkg") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buf.getvalue()


@pytest.fixture(autouse=True)
def clear_cache(monkeypatch):
    monkeypatch.setattr(aur_mcp, "_SNAPSHOTS", {})
    yield


class TestFetchSnapshot:
    def test_extracts_files_and_strips_root(self, monkeypatch):
        monkeypatch.setattr(
            aur_mcp, "_http_get",
            lambda url: _tarball({"PKGBUILD": b"a=1", "pkg.install": b"echo"}),
        )
        files = aur_mcp.fetch_snapshot("some-pkg")
        assert files == {"PKGBUILD": b"a=1", "pkg.install": b"echo"}

    def test_caches_per_package(self, monkeypatch):
        calls = []

        def fake_get(url):
            calls.append(url)
            return _tarball({"PKGBUILD": b"x"})

        monkeypatch.setattr(aur_mcp, "_http_get", fake_get)
        aur_mcp.fetch_snapshot("dup-pkg")
        aur_mcp.fetch_snapshot("dup-pkg")
        assert len(calls) == 1

    def test_refuses_traversal_members(self, monkeypatch):
        monkeypatch.setattr(
            aur_mcp, "_http_get",
            lambda url: _tarball({"../evil": b"x", "deep/nested": b"y",
                                  "ok": b"z"}),
        )
        files = aur_mcp.fetch_snapshot("trav-pkg")
        assert files == {"ok": b"z"}

    def test_drops_oversized_members(self, monkeypatch):
        big = b"x" * (aur_mcp.MAX_FILE_BYTES + 1)
        monkeypatch.setattr(
            aur_mcp, "_http_get",
            lambda url: _tarball({"big": big, "small": b"ok"}),
        )
        assert aur_mcp.fetch_snapshot("size-pkg") == {"small": b"ok"}

    def test_rejects_bad_names(self, monkeypatch):
        monkeypatch.setattr(aur_mcp, "_http_get",
                            lambda url: pytest.fail("no HTTP expected"))
        with pytest.raises(ValueError):
            aur_mcp.fetch_snapshot("../etc")


class TestAurFile:
    def test_returns_content(self, monkeypatch):
        monkeypatch.setattr(
            aur_mcp, "_http_get",
            lambda url: _tarball({"PKGBUILD": b"pkgver=1"}),
        )
        result = aur_mcp.aur_file_impl("a-pkg", "PKGBUILD")
        assert result["content"] == "pkgver=1"
        assert result["filename"] == "PKGBUILD"

    def test_unknown_file_lists_available(self, monkeypatch):
        monkeypatch.setattr(
            aur_mcp, "_http_get",
            lambda url: _tarball({"PKGBUILD": b"x"}),
        )
        result = aur_mcp.aur_file_impl("a-pkg", "nope.install")
        assert "error" in result
        assert result["files"] == ["PKGBUILD"]

    def test_traversal_filename_refused(self, monkeypatch):
        result = aur_mcp.aur_file_impl("a-pkg", "../../etc/passwd")
        assert "error" in result

    def test_http_error_is_reported(self, monkeypatch):
        import httpx

        def boom(url):
            raise httpx.ConnectError("offline")

        monkeypatch.setattr(aur_mcp, "_http_get", boom)
        result = aur_mcp.aur_file_impl("a-pkg", "PKGBUILD")
        assert "error" in result


FAKE_LOG = (
    "aaa\x1fdcelasun\x1f2026-10-17T02:00:00+00:00\x1fbump to 3.2.3\n"
    "bbb\x1fdcelasun\x1f2026-10-16T02:00:00+00:00\x1fbump to 3.2.2"
)


def _git_runner(log_text=FAKE_LOG):
    def runner(cmd, **kwargs):
        if cmd[1] == "clone":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout=log_text, stderr="")
    return runner


class TestAurGitLog:
    def test_parses_commits(self, monkeypatch):
        monkeypatch.setattr(aur_mcp.subprocess, "run", _git_runner())
        result = aur_mcp.aur_git_log_impl("some-pkg", limit=5)
        assert len(result["commits"]) == 2
        first = result["commits"][0]
        assert first["sha"] == "aaa"
        assert "bump to 3.2.3" in first["subject"]
        assert first["date"].startswith("2026-10-17")

    def test_clone_failure_reported(self, monkeypatch):
        def runner(cmd, **kwargs):
            return SimpleNamespace(returncode=128, stdout="",
                                   stderr="not found")
        monkeypatch.setattr(aur_mcp.subprocess, "run", runner)
        result = aur_mcp.aur_git_log_impl("ghost-pkg")
        assert "error" in result

    def test_limit_capped(self, monkeypatch):
        calls = {}

        def runner(cmd, **kwargs):
            if cmd[1] == "clone":
                calls["depth"] = cmd[cmd.index("--depth") + 1]
            return _git_runner()(cmd, **kwargs)

        monkeypatch.setattr(aur_mcp.subprocess, "run", runner)
        result = aur_mcp.aur_git_log_impl("some-pkg", limit=9999)
        assert calls["depth"] == str(aur_mcp.MAX_GIT_LOG)
        assert "error" not in result

    def test_bad_name_refused(self, monkeypatch):
        result = aur_mcp.aur_git_log_impl("bad name; rm -rf /")
        assert "error" in result


def test_output_is_json_serializable(monkeypatch):
    monkeypatch.setattr(
        aur_mcp, "_http_get",
        lambda url: _tarball({"PKGBUILD": b"x"}),
    )
    json.dumps(aur_mcp.aur_file_impl("j-pkg", "PKGBUILD"))
    monkeypatch.setattr(aur_mcp.subprocess, "run", _git_runner())
    json.dumps(aur_mcp.aur_git_log_impl("j-pkg"))
