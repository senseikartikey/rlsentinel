import pytest

from rlsentinel.db.connection import read_only_connection
from rlsentinel.db.introspect import take_snapshot
from rlsentinel.db.rules import evaluate

pytestmark = pytest.mark.integration


def test_seeded_database_produces_expected_findings(postgres_dsn):
    with read_only_connection(postgres_dsn) as conn:
        snapshot = take_snapshot(conn)
    findings = evaluate(snapshot)

    exposed = [f for f in findings if f.location == "public.exposed_tokens"]
    assert len(exposed) == 1
    assert exposed[0].id == "RLS_DISABLED_PUBLIC_GRANT"
    assert exposed[0].severity.name == "CRITICAL"  # 'token' column is credential-shaped

    protected = [f for f in findings if f.location == "public.protected_stops"]
    assert any(f.id == "RLS_ENABLED_WITH_POLICIES" for f in protected)

    internal = [f for f in findings if f.location == "public.internal_only"]
    assert internal == []

    context = [f for f in findings if f.id == "CONNECTING_ROLE_BYPASSES_RLS"]
    assert len(context) == 1
    assert context[0].severity.name == "INFO"

    # anon/authenticated must not themselves be flagged as bypassing RLS
    assert [f for f in findings if f.id == "ANON_BYPASSRLS_MISCONFIGURED"] == []


def test_read_only_connection_cannot_write(postgres_dsn):
    import psycopg

    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), read_only_connection(postgres_dsn) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE should_never_exist (id serial)")
