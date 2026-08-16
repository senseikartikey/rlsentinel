"""Shared data contract between the db scanner, repo scanner, and output layer.

Kept dependency-free (stdlib only) so it can be imported by every other module
without pulling in psycopg, typer, or rich.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rlsentinel import __version__
from rlsentinel.severity import Severity

SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    category: str  # "db" | "repo"
    title: str
    description: str
    location: str
    remediation: str
    evidence: str | None = None  # always pre-redacted before this is constructed


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_version: str = __version__

    def summary(self) -> dict[str, int]:
        counts = {s.name.lower(): 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name.lower()] += 1
        return counts

    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)
