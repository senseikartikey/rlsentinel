"""Thin wrappers around real `git` subprocess calls.

Deliberately not a hand-rolled .gitignore parser: git itself correctly
handles nested .gitignore files, global excludes, and all the edge cases a
reimplementation would risk getting subtly wrong.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def is_git_repo(repo: Path) -> bool:
    result = _run_git(repo, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.strip() == "true"


def tracked_files(repo: Path) -> list[Path]:
    """Files git actually tracks -- already excludes anything covered by
    .gitignore, so no extra ignore-handling is needed for this list.
    """
    result = _run_git(repo, "ls-files")
    if result.returncode != 0:
        return []
    return [repo / line for line in result.stdout.splitlines() if line.strip()]


def untracked_unignored_files(repo: Path) -> list[Path]:
    """Files that exist on disk, aren't tracked, and aren't gitignored --
    exactly the 'one `git add .` away from being leaked' set.
    """
    result = _run_git(repo, "ls-files", "--others", "--exclude-standard")
    if result.returncode != 0:
        return []
    return [repo / line for line in result.stdout.splitlines() if line.strip()]


def is_ignored(repo: Path, path: Path) -> bool:
    try:
        rel = path.relative_to(repo)
    except ValueError:
        rel = path
    result = _run_git(repo, "check-ignore", "-q", str(rel))
    return result.returncode == 0
