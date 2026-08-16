import pytest

from rlsentinel.credential_patterns import is_credential_shaped


@pytest.mark.parametrize(
    "name",
    [
        "api_token",
        "TOKEN",
        "user_password",
        "secret_key",
        "njt_token_cache",
        "oauth_state",
        "refresh_token",
        "service_role_key",
        "SessionData",
        "client_secret",
    ],
)
def test_matches_credential_shaped_names(name):
    assert is_credential_shaped(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "stops",
        "routes",
        "trip_updates",
        "weather_hourly",
        "id",
        "created_at",
        "display_name",
    ],
)
def test_does_not_match_ordinary_names(name):
    assert is_credential_shaped(name) is False
