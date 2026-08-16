"""Raw SQL only. No connection handling, no result parsing -- see introspect.py."""

TABLES_AND_RLS = """
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS rls_forced
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg_temp_%'
  AND n.nspname NOT LIKE 'pg_toast_temp_%'
ORDER BY n.nspname, c.relname;
"""

TABLE_GRANTS = """
SELECT
    table_schema,
    table_name,
    grantee,
    privilege_type
FROM information_schema.role_table_grants
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_name, grantee;
"""

# The well-known Supabase role names, PLUS whichever role we actually
# connected as (which may not be literally named 'postgres' -- e.g. a
# self-hosted Postgres, or a CI test database, can use any superuser name).
# Without the `OR rolname = current_user` clause, the connecting-role context
# check in rules.py would silently never fire for any non-Supabase setup.
ROLE_FLAGS = """
SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
FROM pg_catalog.pg_roles
WHERE rolname IN ('anon', 'authenticated', 'service_role', 'postgres', 'authenticator')
   OR rolname = current_user
ORDER BY rolname;
"""

CURRENT_ROLE = "SELECT current_user AS current_user, session_user AS session_user;"

POLICIES = """
SELECT schemaname, tablename, policyname, permissive, roles, cmd
FROM pg_catalog.pg_policies
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schemaname, tablename;
"""

COLUMNS = """
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_name, ordinal_position;
"""
