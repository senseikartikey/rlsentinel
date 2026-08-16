import subprocess
from pathlib import Path

import pytest

from rlsentinel.repo.rules import scan_repo
from tests.unit.jwt_helpers import make_fake_jwt


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


def test_committed_key_is_high_severity(git_repo: Path):
    key_file = git_repo / "src" / "supabase.ts"
    key_file.parent.mkdir(parents=True)
    key_file.write_text(f'const KEY = "{make_fake_jwt(role="anon")}";\n')
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add key")

    findings = scan_repo(git_repo)
    leaked = [f for f in findings if f.id == "LEAKED_SUPABASE_KEY"]
    assert len(leaked) == 1
    assert leaked[0].severity.name == "HIGH"
    assert "src/supabase.ts" in leaked[0].location.replace("\\", "/")


def test_service_role_key_is_always_critical(git_repo: Path):
    key_file = git_repo / "config.py"
    key_file.write_text(f'SERVICE_KEY = "{make_fake_jwt(role="service_role")}"\n')
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add service key")

    findings = scan_repo(git_repo)
    leaked = [f for f in findings if f.id == "LEAKED_SUPABASE_KEY"]
    assert leaked[0].severity.name == "CRITICAL"


def test_gitignored_env_key_produces_no_finding(git_repo: Path):
    (git_repo / ".gitignore").write_text(".env\n")
    _git(git_repo, "add", ".gitignore")
    _git(git_repo, "commit", "-q", "-m", "add gitignore")

    (git_repo / ".env").write_text(f'SUPABASE_ANON_KEY={make_fake_jwt(role="anon")}\n')

    findings = scan_repo(git_repo)
    assert [f for f in findings if f.id in ("LEAKED_SUPABASE_KEY", "UNTRACKED_ENV_KEY_NOT_IGNORED")] == []


def test_untracked_unignored_env_key_is_flagged(git_repo: Path):
    (git_repo / ".env").write_text(f'SUPABASE_ANON_KEY={make_fake_jwt(role="anon")}\n')

    findings = scan_repo(git_repo)
    flagged = [f for f in findings if f.id == "UNTRACKED_ENV_KEY_NOT_IGNORED"]
    assert len(flagged) == 1
    assert flagged[0].severity.name == "MEDIUM"


def test_non_git_directory_gets_warning_and_flat_medium(tmp_path: Path, monkeypatch):
    # See test_git_tracking.test_is_git_repo_false for why this is needed.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "notes.txt").write_text(f'key = "{make_fake_jwt(role="anon")}"\n')

    findings = scan_repo(plain)
    warning = [f for f in findings if f.id == "NOT_A_GIT_REPO_WARNING"]
    leaked = [f for f in findings if f.id == "LEAKED_SUPABASE_KEY"]
    assert len(warning) == 1
    assert len(leaked) == 1
    assert leaked[0].severity.name == "MEDIUM"


def test_clean_repo_has_no_leak_findings(git_repo: Path):
    (git_repo / "README.md").write_text("nothing sensitive here\n")
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "clean")

    findings = scan_repo(git_repo)
    assert [f for f in findings if f.category == "repo" and f.id != "NOT_A_GIT_REPO_WARNING"] == []


def test_evidence_is_always_redacted(git_repo: Path):
    jwt = make_fake_jwt(role="anon")
    (git_repo / "app.py").write_text(f'KEY = "{jwt}"\n')
    _git(git_repo, "add", "-A")
    _git(git_repo, "commit", "-q", "-m", "add key")

    findings = scan_repo(git_repo)
    leaked = next(f for f in findings if f.id == "LEAKED_SUPABASE_KEY")
    assert jwt not in leaked.evidence
    assert jwt not in leaked.description
