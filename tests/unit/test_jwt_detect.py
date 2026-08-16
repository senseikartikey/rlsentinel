from rlsentinel.repo.jwt_detect import find_supabase_keys
from tests.unit.jwt_helpers import make_fake_jwt


def test_detects_anon_role():
    jwt = make_fake_jwt(role="anon")
    matches = find_supabase_keys(f"SUPABASE_ANON_KEY={jwt}")
    assert len(matches) == 1
    assert matches[0].role == "anon"


def test_detects_authenticated_role():
    jwt = make_fake_jwt(role="authenticated")
    matches = find_supabase_keys(jwt)
    assert len(matches) == 1
    assert matches[0].role == "authenticated"


def test_detects_service_role():
    jwt = make_fake_jwt(role="service_role")
    matches = find_supabase_keys(jwt)
    assert len(matches) == 1
    assert matches[0].role == "service_role"


def test_ignores_jwt_without_role_claim():
    jwt = make_fake_jwt(role=None)
    assert find_supabase_keys(jwt) == []


def test_ignores_jwt_with_unrelated_role():
    jwt = make_fake_jwt(role="admin")
    assert find_supabase_keys(jwt) == []


def test_ignores_malformed_base64():
    assert find_supabase_keys("not.a.jwt-at-all-!!!!!!!!!.nope") == []


def test_ignores_two_segment_strings():
    assert find_supabase_keys("just.twosegments") == []


def test_ignores_plain_text():
    assert find_supabase_keys("hello world, nothing to see here") == []


def test_finds_multiple_keys_in_text():
    anon = make_fake_jwt(role="anon")
    service = make_fake_jwt(role="service_role")
    text = f"ANON={anon}\nSERVICE={service}\n"
    matches = find_supabase_keys(text)
    roles = sorted(m.role for m in matches)
    assert roles == ["anon", "service_role"]


def test_redacted_never_shows_full_key():
    jwt = make_fake_jwt(role="anon")
    matches = find_supabase_keys(jwt)
    redacted = matches[0].redacted()
    assert jwt not in redacted
    assert "..." in redacted
    assert "<redacted>" in redacted


def test_does_not_crash_on_invalid_json_payload():
    # header/payload segments that decode as valid base64 but not valid JSON
    import base64

    garbage_seg = base64.urlsafe_b64encode(b"not json at all").rstrip(b"=").decode()
    fake = f"{garbage_seg}.{garbage_seg}.{garbage_seg}abcdefghij"
    assert find_supabase_keys(fake) == []
