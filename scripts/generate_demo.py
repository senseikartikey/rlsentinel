"""Regenerates docs/demo.svg -- a real render of rlsentinel's terminal output
(via rich's Console(record=True).export_svg()) using representative findings
built from the actual Finding/Severity model, not a mockup.

Run: python scripts/generate_demo.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from rlsentinel.model import Finding, ScanReport
from rlsentinel.output.terminal import render
from rlsentinel.severity import Severity

report = ScanReport(
    findings=[
        Finding(
            id="RLS_DISABLED_PUBLIC_GRANT",
            severity=Severity.CRITICAL,
            category="db",
            title="public.njt_token_cache has RLS disabled and is exposed to anon",
            description=(
                "Table public.njt_token_cache has Row-Level Security disabled and grants "
                "[SELECT] to [anon] and appears to hold credential-shaped data. Any request "
                "to Supabase's public REST API can read/write this table with no authentication."
            ),
            location="public.njt_token_cache",
            remediation="ALTER TABLE public.njt_token_cache ENABLE ROW LEVEL SECURITY;",
        ),
        Finding(
            id="RLS_DISABLED_PUBLIC_GRANT",
            severity=Severity.HIGH,
            category="db",
            title="public.user_uploads has RLS disabled and is exposed to anon",
            description=(
                "Table public.user_uploads has Row-Level Security disabled and grants "
                "[SELECT, INSERT, UPDATE] to [anon] with public write access."
            ),
            location="public.user_uploads",
            remediation="ALTER TABLE public.user_uploads ENABLE ROW LEVEL SECURITY;",
        ),
        Finding(
            id="LEAKED_SUPABASE_KEY",
            severity=Severity.HIGH,
            category="repo",
            title="Supabase 'anon' key found in src/lib/supabase.ts",
            description=(
                "A Supabase API key with role claim 'anon' was found committed to git at "
                "src/lib/supabase.ts."
            ),
            location="src/lib/supabase.ts",
            remediation="Rotate this key in the Supabase dashboard, then move it to an env var.",
            evidence="eyJhbGciOi...<redacted>...5vdWdo",
        ),
        Finding(
            id="RLS_ENABLED_WITH_POLICIES",
            severity=Severity.INFO,
            category="db",
            title="public.stops: RLS enabled with 1 policy",
            description="Table public.stops has RLS enabled with 1 policy defined.",
            location="public.stops",
            remediation="Review policy definitions manually.",
        ),
        Finding(
            id="CONNECTING_ROLE_BYPASSES_RLS",
            severity=Severity.INFO,
            category="db",
            title="Connected as 'postgres', which bypasses RLS by design",
            description=(
                "rlsentinel connected using the 'postgres' role, which has BYPASSRLS set. "
                "This is expected for an application's own direct database connection."
            ),
            location="role:postgres",
            remediation="No action needed.",
        ),
    ]
)

exit_code = 1
console = Console(record=True, width=100)
render(report, exit_code, console=console)

out = Path(__file__).parent.parent / "docs" / "demo.svg"
out.parent.mkdir(exist_ok=True)
console.save_svg(str(out), title="rlsentinel scan")
print(f"wrote {out}")
