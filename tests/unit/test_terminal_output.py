"""Regression coverage for the bracket-swallowing bug: rich's Console.print
treats `[...]` as markup unless escaped, and real Finding descriptions from
db/rules.py legitimately contain literal brackets (e.g. "grants [SELECT] to
[anon]"). Every dynamic field must survive rendering unescaped-looking, i.e.
still contain its brackets in the output text.
"""

from __future__ import annotations

from rich.console import Console

from rlsentinel.model import Finding, ScanReport
from rlsentinel.output.terminal import render
from rlsentinel.severity import Severity


def render_to_text(report: ScanReport, exit_code: int = 1) -> str:
    console = Console(record=True, width=120, no_color=True)
    render(report, exit_code, console=console)
    return console.export_text()


def test_bracketed_description_survives_rendering():
    report = ScanReport(
        findings=[
            Finding(
                id="RLS_DISABLED_PUBLIC_GRANT",
                severity=Severity.CRITICAL,
                category="db",
                title="public.tokens exposed",
                description="Table grants [SELECT] to [anon] and is credential-shaped.",
                location="public.tokens",
                remediation="ALTER TABLE public.tokens ENABLE ROW LEVEL SECURITY;",
            )
        ]
    )
    text = render_to_text(report)
    assert "[SELECT]" in text
    assert "[anon]" in text


def test_bracketed_title_in_summary_table_survives():
    report = ScanReport(
        findings=[
            Finding(
                id="RLS_DISABLED_PUBLIC_GRANT",
                severity=Severity.HIGH,
                category="db",
                title="public.tokens exposed to [anon]",
                description="desc",
                location="public.tokens",
                remediation="fix it",
            )
        ]
    )
    text = render_to_text(report)
    assert "[anon]" in text


def test_bracketed_evidence_survives():
    report = ScanReport(
        findings=[
            Finding(
                id="LEAKED_SUPABASE_KEY",
                severity=Severity.HIGH,
                category="repo",
                title="key found",
                description="desc",
                location="src/app.py",
                remediation="rotate it",
                evidence="prefix...[redacted]...suffix",
            )
        ]
    )
    text = render_to_text(report)
    assert "[redacted]" in text


def test_rendering_does_not_crash_on_unbalanced_brackets():
    report = ScanReport(
        findings=[
            Finding(
                id="X",
                severity=Severity.MEDIUM,
                category="db",
                title="weird [ title",
                description="odd ] description [ here",
                location="public.x",
                remediation="fix",
            )
        ]
    )
    # Should not raise -- just needs to render without throwing.
    render_to_text(report)
