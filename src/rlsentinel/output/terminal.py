"""Human-readable terminal report via rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rlsentinel.model import Finding, ScanReport
from rlsentinel.severity import Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(report: ScanReport, exit_code: int, console: Console | None = None) -> None:
    console = console or Console()
    summary = report.summary()

    summary_line = ", ".join(
        f"[{SEVERITY_COLORS[Severity[k.upper()]]}]{v} {k.upper()}[/]"
        for k, v in summary.items()
        if v > 0
    ) or "[green]0 findings[/]"
    console.print(Panel(summary_line, title="rlsentinel scan summary", expand=False))

    for category, label in (("db", "Database"), ("repo", "Repository")):
        cat_findings = [f for f in report.findings if f.category == category]
        if not cat_findings:
            continue
        table = Table(title=label)
        table.add_column("Severity")
        table.add_column("Location")
        table.add_column("Finding")
        for f in sorted(cat_findings, key=lambda f: f.severity, reverse=True):
            table.add_row(
                f"[{SEVERITY_COLORS[f.severity]}]{f.severity.name}[/]", f.location, f.title
            )
        console.print(table)

    actionable = [
        f
        for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if actionable:
        console.print()
        console.print("[bold]Details and remediation:[/bold]")
        for f in sorted(actionable, key=lambda f: f.severity, reverse=True):
            _render_detail(console, f)

    console.print()
    console.print(f"Exit code: {exit_code}")


def _render_detail(console: Console, f: Finding) -> None:
    console.print(f"\n[{SEVERITY_COLORS[f.severity]}]{f.severity.name}[/] - {f.title}")
    console.print(f"  {f.description}")
    if f.evidence:
        console.print(f"  Evidence: {f.evidence}")
    console.print(f"  [bold]Fix:[/bold] [green]{f.remediation}[/green]")
