"""File discovery for the repo scan: git-aware when possible, plain filesystem
walk as a fallback for non-git directories.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rlsentinel.repo import git_tracking

DEFAULT_WALK_EXCLUDES = {"node_modules", ".venv", "venv", "dist", "build", ".git", "__pycache__"}

# Skip obviously-binary or huge-and-irrelevant extensions to keep the scan fast
# and avoid decoding errors on binary content.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".pyc", ".lock",
}


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    tracked: bool  # False also covers "unknown" for non-git repos


def discover_files(repo: Path) -> tuple[list[ScanTarget], bool]:
    """Returns (targets, is_git). Callers use is_git to decide whether the
    tracked/untracked distinction is meaningful for severity purposes.
    """
    if git_tracking.is_git_repo(repo):
        targets = [
            ScanTarget(path=p, tracked=True)
            for p in git_tracking.tracked_files(repo)
            if p.is_file() and p.suffix not in SKIP_EXTENSIONS
        ]
        return targets, True

    targets = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix in SKIP_EXTENSIONS:
            continue
        if any(part in DEFAULT_WALK_EXCLUDES for part in path.parts):
            continue
        targets.append(ScanTarget(path=path, tracked=False))
    return targets, False


def find_env_files(repo: Path) -> list[Path]:
    """.env, .env.local, .env.* anywhere in the working tree (not limited to
    tracked files -- this is specifically looking for stray untracked ones).
    """
    candidates = []
    for path in repo.rglob(".env*"):
        if path.is_file() and not any(
            part in DEFAULT_WALK_EXCLUDES for part in path.parts
        ):
            candidates.append(path)
    return candidates
