import json

from rlsentinel.model import Finding, ScanReport
from rlsentinel.output.json_out import to_dict, to_json
from rlsentinel.severity import Severity


def make_report():
    return ScanReport(
        findings=[
            Finding(
                id="RLS_DISABLED_PUBLIC_GRANT",
                severity=Severity.CRITICAL,
                category="db",
                title="public.tokens exposed",
                description="desc",
                location="public.tokens",
                remediation="ALTER TABLE public.tokens ENABLE ROW LEVEL SECURITY;",
            ),
            Finding(
                id="RLS_ENABLED_NO_POLICIES",
                severity=Severity.INFO,
                category="db",
                title="public.stops locked",
                description="desc",
                location="public.stops",
                remediation="No action needed.",
            ),
        ]
    )


def test_schema_version_present():
    d = to_dict(make_report(), exit_code=1)
    assert d["schema_version"] == "1"


def test_summary_counts_by_severity():
    d = to_dict(make_report(), exit_code=1)
    assert d["summary"]["critical"] == 1
    assert d["summary"]["info"] == 1
    assert d["summary"]["high"] == 0


def test_findings_sorted_most_severe_first():
    d = to_dict(make_report(), exit_code=1)
    severities = [f["severity"] for f in d["findings"]]
    assert severities == ["critical", "info"]


def test_exit_code_included():
    d = to_dict(make_report(), exit_code=1)
    assert d["exit_code"] == 1


def test_to_json_is_valid_json():
    output = to_json(make_report(), exit_code=1)
    parsed = json.loads(output)
    assert parsed["schema_version"] == "1"


def test_empty_report_has_zero_summary():
    d = to_dict(ScanReport(), exit_code=0)
    assert all(v == 0 for v in d["summary"].values())
    assert d["findings"] == []
