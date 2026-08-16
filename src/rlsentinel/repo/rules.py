"""Repo-scan orchestration and severity judgment.

_finding_for_match is the pure decision function (match + tracking context ->
Finding) that unit tests exercise directly without touching the filesystem.
scan_repo is the I/O-performing orchestrator that wires walker/git_tracking/
jwt_detect together.
"""

from __future__ import annotations

from pathlib import Path

from rlsentinel.model import Finding
from rlsentinel.repo import git_tracking, walker
from rlsentinel.repo.jwt_detect import SupabaseKeyMatch, find_supabase_keys
from rlsentinel.severity import Severity

ROLE_ORDER = {"service_role": 3, "authenticated": 2, "anon": 1}


def _finding_for_match(
    match: SupabaseKeyMatch,
    location: str,
    *,
    tracked: bool,
    is_git: bool,
) -> Finding:
    if match.role == "service_role":
        severity = Severity.CRITICAL
    elif not is_git:
        severity = Severity.MEDIUM
    elif tracked:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    status = "committed to git" if (is_git and tracked) else "present in the working tree"
    return Finding(
        id="LEAKED_SUPABASE_KEY",
        severity=severity,
        category="repo",
        title=f"Supabase '{match.role}' key found in {location}",
        description=(
            f"A Supabase API key with role claim '{match.role}' was found {status} "
            f"at {location}. {'This role has full database access, bypassing RLS entirely.' if match.role == 'service_role' else 'If RLS is misconfigured on any table, this key can read/write it via the public REST API.'}"
        ),
        location=location,
        remediation=(
            "Rotate this key in the Supabase dashboard immediately, then remove it from "
            "source (use environment variables / a secrets manager instead)."
            if (is_git and tracked)
            else "Move this value to a gitignored .env file or a secrets manager before it gets committed."
        ),
        evidence=match.redacted(),
    )


def _env_file_finding(path: Path, repo: Path, match: SupabaseKeyMatch) -> Finding:
    rel = path.relative_to(repo)
    severity = Severity.HIGH if match.role == "service_role" else Severity.MEDIUM
    return Finding(
        id="UNTRACKED_ENV_KEY_NOT_IGNORED",
        severity=severity,
        category="repo",
        title=f"Untracked {rel} holds a Supabase '{match.role}' key and isn't gitignored",
        description=(
            f"{rel} contains a Supabase '{match.role}' key. It isn't currently tracked by "
            "git, but it also isn't covered by .gitignore -- it will be committed by the "
            "next unsuspecting `git add .`/`git add -A`."
        ),
        location=str(rel),
        remediation=f"Add '{rel.name}' (or a pattern covering it) to .gitignore.",
        evidence=match.redacted(),
    )


def scan_repo(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    targets, is_git = walker.discover_files(repo)

    if not is_git:
        findings.append(
            Finding(
                id="NOT_A_GIT_REPO_WARNING",
                severity=Severity.LOW,
                category="repo",
                title="Not a git repository -- tracked/ignored distinction unavailable",
                description=(
                    f"{repo} is not inside a git working tree. rlsentinel scanned all "
                    "files on disk (minus common build/dependency directories), but cannot "
                    "distinguish 'committed', 'gitignored', or 'about to be committed' -- "
                    "every match below is reported at a flat severity."
                ),
                location=str(repo),
                remediation="Run `git init` to get precise tracked/ignored severity scoring.",
            )
        )

    for target in targets:
        try:
            text = target.path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in find_supabase_keys(text):
            rel_location = str(target.path.relative_to(repo))
            findings.append(
                _finding_for_match(match, rel_location, tracked=target.tracked, is_git=is_git)
            )

    if is_git:
        tracked_set = {p.resolve() for p in git_tracking.tracked_files(repo)}
        for env_path in walker.find_env_files(repo):
            resolved = env_path.resolve()
            if resolved in tracked_set:
                continue  # already covered by the tracked-file scan above
            if git_tracking.is_ignored(repo, env_path):
                continue  # correctly gitignored -- not a finding
            try:
                text = env_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in find_supabase_keys(text):
                findings.append(_env_file_finding(env_path, repo, match))

    return findings
