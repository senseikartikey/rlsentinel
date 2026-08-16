"""Versioned JSON output. schema_version is bumped only on a breaking shape
change, so a future GitHub Action / SARIF converter can depend on this
contract without touching scan logic.
"""

from __future__ import annotations

import json

from rlsentinel.model import SCHEMA_VERSION, ScanReport


def to_dict(report: ScanReport, exit_code: int) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": report.tool_version,
        "scanned_at": report.scanned_at.isoformat(),
        "summary": report.summary(),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.name.lower(),
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "location": f.location,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in sorted(report.findings, key=lambda f: f.severity, reverse=True)
        ],
        "exit_code": exit_code,
    }


def to_json(report: ScanReport, exit_code: int) -> str:
    return json.dumps(to_dict(report, exit_code), indent=2)
