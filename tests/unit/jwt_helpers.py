"""Shared helper for building fake-but-structurally-valid JWTs in tests.

These are never verified (rlsentinel never checks signatures), so the
signature segment can be any base64url-safe garbage.
"""

from __future__ import annotations

import base64
import json


def _b64url(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_fake_jwt(role: str | None = "anon", *, valid_header: bool = True) -> str:
    header = {"alg": "HS256", "typ": "JWT"} if valid_header else {"typ": "JWT"}
    payload = {"iss": "supabase", "ref": "abcdefghijklmno"}
    if role is not None:
        payload["role"] = role
    header_seg = _b64url(header)
    payload_seg = _b64url(payload)
    sig_seg = base64.urlsafe_b64encode(b"not-a-real-signature-but-long-enough").rstrip(b"=").decode()
    return f"{header_seg}.{payload_seg}.{sig_seg}"
