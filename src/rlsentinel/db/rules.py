"""The security judgment logic. Pure functions over plain data (DbSnapshot and
friends) -> list[Finding]. No I/O here at all -- this is what makes the
rule logic exhaustively unit-testable without a live database.
"""

from __future__ import annotations

from collections import defaultdict

from rlsentinel.credential_patterns import is_credential_shaped
from rlsentinel.db.introspect import DbSnapshot
from rlsentinel.model import Finding
from rlsentinel.severity import Severity

# The roles Supabase's PostgREST layer actually uses to serve the public API.
# A grant to any of these (or to PUBLIC, which they inherit) is a public-exposure
# signal; grants to other roles (e.g. an app's own service role) are not.
PUBLIC_FACING_ROLES = {"anon", "authenticated", "PUBLIC"}
WRITE_PRIVILEGES = {"INSERT", "UPDATE", "DELETE"}


def evaluate(snapshot: DbSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_anon_bypassrls_findings(snapshot))
    findings.extend(_current_role_context_finding(snapshot))
    findings.extend(_rls_disabled_public_grant_findings(snapshot))
    findings.extend(_policy_context_findings(snapshot))
    return findings


def _anon_bypassrls_findings(snapshot: DbSnapshot) -> list[Finding]:
    """anon/authenticated with rolbypassrls=true defeats RLS everywhere,
    silently, regardless of any table's RLS setting. Always CRITICAL.
    """
    findings = []
    for role in snapshot.roles:
        if role.rolname in ("anon", "authenticated") and role.rolbypassrls:
            findings.append(
                Finding(
                    id="ANON_BYPASSRLS_MISCONFIGURED",
                    severity=Severity.CRITICAL,
                    category="db",
                    title=f"Role '{role.rolname}' bypasses Row-Level Security",
                    description=(
                        f"The '{role.rolname}' role has BYPASSRLS set. This role is used by "
                        "Supabase's public REST API (PostgREST), so every RLS policy on every "
                        "table is silently ignored for public requests -- enabling RLS on "
                        "individual tables will not protect them while this is set."
                    ),
                    location=f"role:{role.rolname}",
                    remediation=f"ALTER ROLE {role.rolname} NOBYPASSRLS;",
                )
            )
    return findings


def _current_role_context_finding(snapshot: DbSnapshot) -> list[Finding]:
    """The role rlsentinel itself connected as bypassing RLS is expected and
    safe when it's a superuser/owner-style app connection (e.g. Supabase's
    'postgres' role) -- surfaced as INFO context, never as a problem.
    """
    current = next(
        (r for r in snapshot.roles if r.rolname == snapshot.current_role), None
    )
    if current is None or not current.rolbypassrls:
        return []
    if current.rolname in ("anon", "authenticated"):
        return []  # already covered, and elevated, by _anon_bypassrls_findings
    return [
        Finding(
            id="CONNECTING_ROLE_BYPASSES_RLS",
            severity=Severity.INFO,
            category="db",
            title=f"Connected as '{current.rolname}', which bypasses RLS by design",
            description=(
                f"rlsentinel connected using the '{current.rolname}' role, which has "
                "BYPASSRLS set. This is expected for an application's own direct database "
                "connection (e.g. a service backend) and is not itself a finding -- the "
                "public exposure risk is whether 'anon'/'authenticated' can reach a table "
                "with RLS disabled, not whether your own backend can."
            ),
            location=f"role:{current.rolname}",
            remediation="No action needed.",
        )
    ]


def _rls_disabled_public_grant_findings(snapshot: DbSnapshot) -> list[Finding]:
    grants_by_table: dict[tuple[str, str], list] = defaultdict(list)
    for g in snapshot.grants:
        if g.grantee in PUBLIC_FACING_ROLES:
            grants_by_table[(g.schema_name, g.table_name)].append(g)

    columns_by_table: dict[tuple[str, str], list[str]] = defaultdict(list)
    for c in snapshot.columns:
        columns_by_table[(c.schema_name, c.table_name)].append(c.column_name)

    findings = []
    for table in snapshot.tables:
        if table.rls_enabled:
            continue
        key = (table.schema_name, table.table_name)
        exposing_grants = grants_by_table.get(key, [])
        if not exposing_grants:
            continue

        grantees = sorted({g.grantee for g in exposing_grants})
        privileges = sorted({g.privilege_type for g in exposing_grants})

        table_credential_shaped = is_credential_shaped(table.table_name)
        column_credential_shaped = any(
            is_credential_shaped(col) for col in columns_by_table.get(key, [])
        )
        has_write = bool(WRITE_PRIVILEGES & set(privileges))

        if table_credential_shaped or column_credential_shaped:
            severity = Severity.CRITICAL
            risk_note = "and appears to hold credential-shaped data"
        elif has_write:
            severity = Severity.HIGH
            risk_note = "with public write access"
        else:
            severity = Severity.MEDIUM
            risk_note = "with public read access"

        location = f"{table.schema_name}.{table.table_name}"
        findings.append(
            Finding(
                id="RLS_DISABLED_PUBLIC_GRANT",
                severity=severity,
                category="db",
                title=f"{location} has RLS disabled and is exposed to {', '.join(grantees)}",
                description=(
                    f"Table {location} has Row-Level Security disabled and grants "
                    f"[{', '.join(privileges)}] to [{', '.join(grantees)}] {risk_note}. "
                    "Any request to Supabase's public REST API can read/write this table "
                    "with no authentication."
                ),
                location=location,
                remediation=f"ALTER TABLE {location} ENABLE ROW LEVEL SECURITY;",
            )
        )
    return findings


def _policy_context_findings(snapshot: DbSnapshot) -> list[Finding]:
    policy_counts: dict[tuple[str, str], int] = defaultdict(int)
    for p in snapshot.policies:
        policy_counts[(p.schema_name, p.table_name)] += 1

    findings = []
    for table in snapshot.tables:
        if not table.rls_enabled:
            continue
        key = (table.schema_name, table.table_name)
        count = policy_counts.get(key, 0)
        location = f"{table.schema_name}.{table.table_name}"
        if count == 0:
            findings.append(
                Finding(
                    id="RLS_ENABLED_NO_POLICIES",
                    severity=Severity.INFO,
                    category="db",
                    title=f"{location}: RLS enabled, no policies (fully locked)",
                    description=(
                        f"Table {location} has RLS enabled with zero policies defined. "
                        "With no policies, no rows are visible via the public API at all -- "
                        "this is the fully-locked-down state."
                    ),
                    location=location,
                    remediation="No action needed.",
                )
            )
        else:
            findings.append(
                Finding(
                    id="RLS_ENABLED_WITH_POLICIES",
                    severity=Severity.INFO,
                    category="db",
                    title=f"{location}: RLS enabled with {count} polic{'y' if count == 1 else 'ies'}",
                    description=(
                        f"Table {location} has RLS enabled with {count} polic"
                        f"{'y' if count == 1 else 'ies'} defined. rlsentinel does not analyze "
                        "policy logic for soundness (e.g. USING (true)) in this version -- "
                        "review the policy definitions manually."
                    ),
                    location=location,
                    remediation="Review policy definitions manually.",
                )
            )
    return findings
