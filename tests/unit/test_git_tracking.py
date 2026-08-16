import subprocess
from pathlib import Path

import pytest

from rlsentinel.repo import git_tracking


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    return repo


def test_is_git_repo_true(git_repo: Path):
    assert git_tracking.is_git_repo(git_repo) is True


def test_is_git_repo_false(tmp_path: Path, monkeypatch):
    # Scope git's upward .git search to tmp_path so this assertion is robust
    # even on machines where an ancestor directory (e.g. $HOME) is itself a
    # git repo -- git's own upward-search semantics would otherwise "find"
    # that unrelated repo and make this test flaky depending on the host.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    assert git_tracking.is_git_repo(not_a_repo) is False


def test_tracked_files_returns_committed_file(git_repo: Path):
    tracked = git_repo / "committed.txt"
    tracked.write_text("hello")
    _git(git_repo, "add", "committed.txt")
    _git(git_repo, "commit", "-q", "-m", "initial")

    result = git_tracking.tracked_files(git_repo)
    assert (git_repo / "committed.txt").resolve() in [p.resolve() for p in result]


def test_untracked_unignored_files_includes_stray_file(git_repo: Path):
    stray = git_repo / "stray.env"
    stray.write_text("SECRET=1")

    result = git_tracking.untracked_unignored_files(git_repo)
    assert (git_repo / "stray.env").resolve() in [p.resolve() for p in result]


def test_untracked_unignored_files_excludes_gitignored(git_repo: Path):
    (git_repo / ".gitignore").write_text(".env\n")
    _git(git_repo, "add", ".gitignore")
    _git(git_repo, "commit", "-q", "-m", "add gitignore")

    ignored = git_repo / ".env"
    ignored.write_text("SECRET=1")

    result = git_tracking.untracked_unignored_files(git_repo)
    assert (git_repo / ".env").resolve() not in [p.resolve() for p in result]


def test_is_ignored_true_for_gitignored_path(git_repo: Path):
    (git_repo / ".gitignore").write_text(".env\n")
    _git(git_repo, "add", ".gitignore")
    _git(git_repo, "commit", "-q", "-m", "add gitignore")

    env_file = git_repo / ".env"
    env_file.write_text("SECRET=1")

    assert git_tracking.is_ignored(git_repo, env_file) is True


def test_is_ignored_false_for_unignored_path(git_repo: Path):
    plain = git_repo / "plain.env"
    plain.write_text("SECRET=1")

    assert git_tracking.is_ignored(git_repo, plain) is False
