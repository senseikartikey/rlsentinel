"""Typer app: argument wiring only. All real logic lives in db/, repo/, output/."""

from __future__ import annotations

from pathlib import Path

import psycopg
import typer
from rich.console import Console

from rlsentinel import __version__
from rlsentinel.config import resolve_db_url
from rlsentinel.db.connection import read_only_connection
from rlsentinel.db.introspect import take_snapshot
from rlsentinel.db.rules import evaluate as evaluate_db
from rlsentinel.model import ScanReport
from rlsentinel.output.json_out import to_json
from rlsentinel.output.terminal import render
from rlsentinel.repo.rules import scan_repo
from rlsentinel.severity import FAIL_ON_CHOICES, meets_threshold

app = typer.Typer(
    help=(
        "Find publicly-exposed Supabase/Postgres tables (RLS disabled + "
        "anon/authenticated access) and leaked Supabase API keys in your repo."
    )
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"rlsentinel {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


@app.command()
def scan(
    db_url: str | None = typer.Option(
        None, "--db-url", help="Postgres connection string. Falls back to $DATABASE_URL."
    ),
    repo: Path = typer.Option(Path("."), "--repo", help="Path to the repo to scan for leaked keys."),
    db_only: bool = typer.Option(False, "--db-only", help="Only run the database scan."),
    repo_only: bool = typer.Option(False, "--repo-only", help="Only run the repo scan."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of the terminal report."),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help=f"Minimum severity that causes a non-zero exit code. One of: {', '.join(FAIL_ON_CHOICES)}.",
    ),
    timeout: int = typer.Option(5, "--timeout", help="DB statement timeout, seconds."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
) -> None:
    """Run the security scan. By default scans both the database and the
    current directory, then prints a human-readable report.
    """
    if db_only and repo_only:
        typer.echo("Error: --db-only and --repo-only are mutually exclusive.", err=True)
        raise typer.Exit(code=2)

    if fail_on not in FAIL_ON_CHOICES:
        typer.echo(f"Error: --fail-on must be one of {', '.join(FAIL_ON_CHOICES)}.", err=True)
        raise typer.Exit(code=2)

    report = ScanReport()
    run_db = not repo_only
    run_repo = not db_only

    if run_db:
        resolved_db_url = resolve_db_url(db_url)
        if not resolved_db_url:
            typer.echo(
                "Error: no database URL provided. Pass --db-url or set $DATABASE_URL, "
                "or use --repo-only to skip the database scan.",
                err=True,
            )
            raise typer.Exit(code=2)
        try:
            with read_only_connection(resolved_db_url, timeout_seconds=timeout) as conn:
                snapshot = take_snapshot(conn)
            report.findings.extend(evaluate_db(snapshot))
        except psycopg.OperationalError as exc:
            typer.echo(f"Error: could not connect to database: {exc}", err=True)
            raise typer.Exit(code=2)

    if run_repo:
        if not repo.is_dir():
            typer.echo(f"Error: --repo path does not exist or is not a directory: {repo}", err=True)
            raise typer.Exit(code=2)
        report.findings.extend(scan_repo(repo.resolve()))

    exit_code = 1 if any(meets_threshold(f.severity, fail_on) for f in report.findings) else 0

    if json_output:
        typer.echo(to_json(report, exit_code))
    else:
        render(report, exit_code, console=Console(no_color=no_color))

    raise typer.Exit(code=exit_code)
