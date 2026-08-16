from rlsentinel.db.introspect import (
    ColumnInfo,
    DbSnapshot,
    GrantInfo,
    PolicyInfo,
    RoleInfo,
    TableInfo,
)
from rlsentinel.db.rules import evaluate
from rlsentinel.severity import Severity

DEFAULT_ROLES = [
    RoleInfo(rolname="anon", rolsuper=False, rolbypassrls=False, rolcanlogin=False),
    RoleInfo(rolname="authenticated", rolsuper=False, rolbypassrls=False, rolcanlogin=False),
    RoleInfo(rolname="service_role", rolsuper=False, rolbypassrls=True, rolcanlogin=False),
    RoleInfo(rolname="postgres", rolsuper=True, rolbypassrls=True, rolcanlogin=True),
]


def make_snapshot(
    tables=None, grants=None, roles=None, current_role="postgres", policies=None, columns=None
) -> DbSnapshot:
    return DbSnapshot(
        tables=tables or [],
        grants=grants or [],
        roles=roles if roles is not None else DEFAULT_ROLES,
        current_role=current_role,
        policies=policies or [],
        columns=columns or [],
    )


def find_by_id(findings, finding_id):
    return [f for f in findings if f.id == finding_id]


def test_anon_bypassrls_is_critical():
    roles = [
        RoleInfo(rolname="anon", rolsuper=False, rolbypassrls=True, rolcanlogin=False),
        RoleInfo(rolname="authenticated", rolsuper=False, rolbypassrls=False, rolcanlogin=False),
    ]
    snapshot = make_snapshot(roles=roles, current_role="postgres")
    findings = find_by_id(evaluate(snapshot), "ANON_BYPASSRLS_MISCONFIGURED")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_authenticated_bypassrls_is_critical():
    roles = [
        RoleInfo(rolname="anon", rolsuper=False, rolbypassrls=False, rolcanlogin=False),
        RoleInfo(rolname="authenticated", rolsuper=False, rolbypassrls=True, rolcanlogin=False),
    ]
    snapshot = make_snapshot(roles=roles)
    findings = find_by_id(evaluate(snapshot), "ANON_BYPASSRLS_MISCONFIGURED")
    assert len(findings) == 1


def test_no_finding_when_anon_authenticated_do_not_bypass():
    snapshot = make_snapshot()
    assert find_by_id(evaluate(snapshot), "ANON_BYPASSRLS_MISCONFIGURED") == []


def test_connecting_role_bypassrls_is_info_context_not_a_problem():
    snapshot = make_snapshot(current_role="postgres")
    findings = find_by_id(evaluate(snapshot), "CONNECTING_ROLE_BYPASSES_RLS")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_connecting_role_without_bypassrls_gets_no_context_finding():
    roles = [
        RoleInfo(rolname="app_user", rolsuper=False, rolbypassrls=False, rolcanlogin=True),
    ]
    snapshot = make_snapshot(roles=roles, current_role="app_user")
    assert find_by_id(evaluate(snapshot), "CONNECTING_ROLE_BYPASSES_RLS") == []


def test_rls_disabled_no_grant_produces_no_finding():
    tables = [TableInfo(schema_name="public", table_name="internal_only", rls_enabled=False, rls_forced=False)]
    snapshot = make_snapshot(tables=tables)
    assert find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT") == []


def test_rls_disabled_select_only_anon_grant_is_medium():
    tables = [TableInfo(schema_name="public", table_name="routes", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="routes", grantee="anon", privilege_type="SELECT")]
    snapshot = make_snapshot(tables=tables, grants=grants)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].location == "public.routes"


def test_rls_disabled_write_grant_is_high():
    tables = [TableInfo(schema_name="public", table_name="routes", rls_enabled=False, rls_forced=False)]
    grants = [
        GrantInfo(schema_name="public", table_name="routes", grantee="anon", privilege_type="SELECT"),
        GrantInfo(schema_name="public", table_name="routes", grantee="anon", privilege_type="INSERT"),
    ]
    snapshot = make_snapshot(tables=tables, grants=grants)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert findings[0].severity == Severity.HIGH


def test_rls_disabled_credential_shaped_table_name_is_critical():
    tables = [TableInfo(schema_name="public", table_name="njt_token_cache", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="njt_token_cache", grantee="anon", privilege_type="SELECT")]
    snapshot = make_snapshot(tables=tables, grants=grants)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert findings[0].severity == Severity.CRITICAL


def test_rls_disabled_credential_shaped_column_is_critical():
    tables = [TableInfo(schema_name="public", table_name="users", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="users", grantee="anon", privilege_type="SELECT")]
    columns = [ColumnInfo(schema_name="public", table_name="users", column_name="api_token")]
    snapshot = make_snapshot(tables=tables, grants=grants, columns=columns)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert findings[0].severity == Severity.CRITICAL


def test_public_grant_counts_as_exposure():
    tables = [TableInfo(schema_name="public", table_name="stops", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="stops", grantee="PUBLIC", privilege_type="SELECT")]
    snapshot = make_snapshot(tables=tables, grants=grants)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert len(findings) == 1


def test_grant_to_unrelated_role_is_not_exposure():
    tables = [TableInfo(schema_name="public", table_name="internal", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="internal", grantee="service_role", privilege_type="SELECT")]
    snapshot = make_snapshot(tables=tables, grants=grants)
    assert find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT") == []


def test_rls_enabled_no_policies_is_info_good_state():
    tables = [TableInfo(schema_name="public", table_name="stops", rls_enabled=True, rls_forced=False)]
    snapshot = make_snapshot(tables=tables)
    findings = find_by_id(evaluate(snapshot), "RLS_ENABLED_NO_POLICIES")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_rls_enabled_with_policies_is_info():
    tables = [TableInfo(schema_name="public", table_name="stops", rls_enabled=True, rls_forced=False)]
    policies = [
        PolicyInfo(
            schema_name="public",
            table_name="stops",
            policy_name="read_own",
            permissive="PERMISSIVE",
            roles=["authenticated"],
            cmd="SELECT",
        )
    ]
    snapshot = make_snapshot(tables=tables, policies=policies)
    findings = find_by_id(evaluate(snapshot), "RLS_ENABLED_WITH_POLICIES")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "1" in findings[0].title


def test_remediation_is_exact_alter_table_statement():
    tables = [TableInfo(schema_name="public", table_name="stops", rls_enabled=False, rls_forced=False)]
    grants = [GrantInfo(schema_name="public", table_name="stops", grantee="anon", privilege_type="SELECT")]
    snapshot = make_snapshot(tables=tables, grants=grants)
    findings = find_by_id(evaluate(snapshot), "RLS_DISABLED_PUBLIC_GRANT")
    assert findings[0].remediation == "ALTER TABLE public.stops ENABLE ROW LEVEL SECURITY;"
