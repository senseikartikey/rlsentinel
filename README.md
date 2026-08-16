# rlsentinel

[![PyPI](https://img.shields.io/pypi/v/rlsentinel)](https://pypi.org/project/rlsentinel/)
[![CI](https://github.com/senseikartikey/rlsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/senseikartikey/rlsentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/rlsentinel)](https://pypi.org/project/rlsentinel/)

Find publicly-exposed Supabase/Postgres tables (Row-Level Security disabled +
reachable via the `anon`/`authenticated` roles) and leaked Supabase API keys
in your repo.

## Why this exists

Supabase gives every Postgres table a public REST API by default. If Row-Level
Security is off, anyone holding the project's public `anon` key can read or
write every row in that table — no login required. This isn't a hypothetical:
[CVE-2025-48757](https://github.com/advisories) found 303 endpoints across 170
production apps exposed exactly this way, and a 2025 study found **10.3% of
AI-generated apps** ship with this exact hole, because AI coding assistants
routinely scaffold Supabase projects without turning RLS on.

I hit this myself. A Supabase security alert on a live project told me all 13
of my public tables had RLS disabled — including one holding a live,
usable third-party API bearer token. Anyone who found the project URL could
have read a working credential straight out of the database with zero
authentication. The fix was one SQL statement per table
(`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`), but nothing had told me to run
it until a vendor alert caught it after the fact.

`rlsentinel` is the tool that would have caught it before it shipped.

## Example output

<img src="docs/demo.svg" alt="rlsentinel scan terminal output showing a CRITICAL RLS-disabled finding, a HIGH leaked key finding, and remediation SQL" width="100%">

## What it checks

**Database scan** (`--db-url` / `$DATABASE_URL`):
- Every table across all non-system schemas: is RLS enabled?
- Is the table granted to `anon`, `authenticated`, or `PUBLIC` (which those
  roles inherit)?
- Do `anon`/`authenticated` have `BYPASSRLS` set, which silently defeats RLS
  everywhere regardless of any table's own setting?
- Does the exposed table/column look like it holds a credential (name
  heuristics: `token`, `secret`, `password`, `api_key`, `session`, and more)?
  Those get escalated to CRITICAL.
- Policy presence is reported for context (RLS on + 0 policies = fully
  locked; RLS on + N policies = "review manually" — policy *logic* isn't
  analyzed in this version).

**Repo scan** (`--repo`, defaults to `.`):
- Finds JWT-shaped strings and decodes (never verifies — no key needed) the
  payload to check for Supabase's `role` claim (`anon`/`authenticated`/
  `service_role`), which is far more precise than a naive regex.
- Distinguishes keys committed to git, keys in an untracked-but-not-gitignored
  `.env` (one `git add .` away from leaking), and keys in a properly
  gitignored `.env` (not a finding).
- Secrets are always redacted in output — never printed in full.

## Install

```bash
pip install rlsentinel
```

## Usage

```bash
export DATABASE_URL=postgresql://user:pass@host:5432/postgres
rlsentinel scan
```

```bash
rlsentinel scan --db-only --fail-on critical
rlsentinel scan --repo-only --json
```

Exit codes: `0` clean (or all findings below `--fail-on`), `1` a qualifying
finding was found, `2` a tool/execution error (bad connection string, bad
repo path, etc). This makes `rlsentinel scan --fail-on high` usable directly
in CI once a GitHub Action wrapper exists (see below).

## What this deliberately doesn't do yet

- No GitHub Action wrapper (the CLI's exit codes and `--json` schema are
  designed so one can be added without touching scan logic).
- No RLS policy *soundness* analysis (e.g. catching `USING (true)`) — only
  presence/count.
- No indirect-grant detection via role membership (`pg_auth_members`) — only
  direct grants and `PUBLIC`.
- Supabase-specific role conventions (`anon`/`authenticated`) — not a generic
  multi-tenant RLS auditor.
- No auto-remediation. `rlsentinel` never writes to the database it scans
  (every DB connection is opened `READ ONLY` with a short statement timeout)
  — it prints the exact SQL for you to run.

## Development

```bash
pip install -e ".[dev]"
pytest tests/unit                  # fast, no Docker required
pytest -m integration              # spins up ephemeral Postgres via testcontainers
```

On Windows with Docker Desktop, testcontainers' resource-reaper sidecar can fail to
expose its port (`ConnectionError: Port mapping ... is not available`). If you hit
this, set `TESTCONTAINERS_RYUK_DISABLED=true` before running the integration tests.

`docs/demo.svg` (the screenshot above) is generated, not hand-drawn:

```bash
python scripts/generate_demo.py
```

## License

MIT
