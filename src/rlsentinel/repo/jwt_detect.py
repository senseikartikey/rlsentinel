"""JWT-shaped string detection with role-claim verification.

Deliberately more precise than a naive regex: a JWT is decoded (never
signature-verified -- no key is available, and none is needed) and only
counted as a genuine Supabase key if its payload's "role" claim is exactly
"anon", "authenticated", or "service_role". Unrelated JWTs (Firebase, Auth0,
custom app tokens) essentially never carry this exact claim shape, so this
keeps false positives low without needing an issuer allowlist.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

_JWT_PATTERN = re.compile(
    r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)

SUPABASE_ROLE_CLAIMS = {"anon", "authenticated", "service_role"}


@dataclass(frozen=True)
class SupabaseKeyMatch:
    role: str  # "anon" | "authenticated" | "service_role"
    raw: str

    def redacted(self) -> str:
        return f"{self.raw[:10]}...<redacted>...{self.raw[-6:]}"


def _b64url_decode(segment: str) -> bytes | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None


def find_supabase_keys(text: str) -> list[SupabaseKeyMatch]:
    """Scan `text` for JWT-shaped substrings and return only those whose
    payload role claim matches a known Supabase role.
    """
    matches: list[SupabaseKeyMatch] = []
    for candidate in _JWT_PATTERN.finditer(text):
        raw = candidate.group(0)
        header_seg, payload_seg, _sig_seg = raw.split(".")

        header_bytes = _b64url_decode(header_seg)
        payload_bytes = _b64url_decode(payload_seg)
        if header_bytes is None or payload_bytes is None:
            continue

        try:
            header = json.loads(header_bytes)
            payload = json.loads(payload_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        if not isinstance(header, dict) or "alg" not in header:
            continue
        if not isinstance(payload, dict):
            continue

        role = payload.get("role")
        if role in SUPABASE_ROLE_CLAIMS:
            matches.append(SupabaseKeyMatch(role=role, raw=raw))

    return matches
