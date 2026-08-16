-- Mimics a real Supabase project's role setup + a few representative tables,
-- one per scenario the rule engine needs to get right.

DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
      CREATE ROLE anon NOLOGIN NOBYPASSRLS;
   END IF;
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
      CREATE ROLE authenticated NOLOGIN NOBYPASSRLS;
   END IF;
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
      CREATE ROLE service_role NOLOGIN BYPASSRLS;
   END IF;
END
$$;

-- Scenario 1: RLS off, granted to anon, credential-shaped column -> CRITICAL
CREATE TABLE IF NOT EXISTS public.exposed_tokens (
    id serial PRIMARY KEY,
    token text
);
GRANT SELECT ON public.exposed_tokens TO anon;

-- Scenario 2: RLS on with a policy -> INFO, "review manually"
CREATE TABLE IF NOT EXISTS public.protected_stops (
    id serial PRIMARY KEY,
    name text
);
ALTER TABLE public.protected_stops ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS read_all ON public.protected_stops;
CREATE POLICY read_all ON public.protected_stops FOR SELECT USING (true);

-- Scenario 3: RLS off, no anon/authenticated/PUBLIC grant -> no finding
CREATE TABLE IF NOT EXISTS public.internal_only (
    id serial PRIMARY KEY,
    data text
);
