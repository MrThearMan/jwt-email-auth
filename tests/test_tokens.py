from datetime import timedelta
from time import sleep
from unittest.mock import PropertyMock, patch

import pytest
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated

from jwt_email_auth.tokens import AccessToken, RefreshToken

from .conftest import equals_regex


def test_create_access_token():
    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex("[a-zA-Z0-9-_.]+")
    assert str(token).count(".") == 2


def test_create_access_token__from_request(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {old_token}"

    token = AccessToken.from_request(drf_request)

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex("[a-zA-Z0-9-_.]+")
    assert str(token).count(".") == 2


def test_create_access_token__from_request__authorization_header_not_found(drf_request):
    with pytest.raises(NotAuthenticated, match="No Authorization header found from request."):
        AccessToken.from_request(drf_request)


def test_create_access_token__from_request__authorization_header_invalid(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"{old_token}"
    with pytest.raises(AuthenticationFailed, match="Invalid Authorization header."):
        AccessToken.from_request(drf_request)


def test_create_access_token__from_request__authorization_header_invalid_prefix(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"Foo {old_token}"
    with pytest.raises(AuthenticationFailed, match="Invalid prefix."):
        AccessToken.from_request(drf_request)


def test_create_access_token__add_audience(settings):
    settings.JWT_EMAIL_AUTH = {"AUDIENCE": "foo"}

    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat", "aud"]
    assert token.payload["aud"] == "foo"


def test_create_access_token__add_issuer(settings):
    settings.JWT_EMAIL_AUTH = {"ISSUER": "foo"}

    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat", "iss"]
    assert token.payload["iss"] == "foo"


def test_decode_access_token():
    token = AccessToken(token=str(AccessToken()))

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex("[a-zA-Z0-9-_.]+")
    assert str(token).count(".") == 2


def test_decode_access_token__expired():
    with patch(
        "jwt_email_auth.tokens.AccessToken.lifetime",
        new_callable=PropertyMock,
        return_value=timedelta(seconds=1),
    ):
        old_token = str(AccessToken())

    # Wait for token to expire
    sleep(2)

    with pytest.raises(AuthenticationFailed, match="Signature has expired."):
        AccessToken(token=old_token)


def test_decode_access_token__decing_error():
    with pytest.raises(AuthenticationFailed, match="Error decoding signature."):
        AccessToken(token="foo")


def test_decode_access_token__invalid_token(settings):
    # All other PyJWT errors are caugth with this error

    settings.JWT_EMAIL_AUTH = {"ISSUER": "foo"}
    token = str(AccessToken())

    settings.JWT_EMAIL_AUTH = {"ISSUER": "bar"}
    with pytest.raises(AuthenticationFailed, match="Invalid token."):
        AccessToken(token=token)


def test_decode_access_token__invalid_token_type():
    token = str(RefreshToken())

    with pytest.raises(AuthenticationFailed, match="Invalid token type."):
        AccessToken(token=token)


def test_access_token__get_claim():
    token = AccessToken()

    assert token["type"] == "access"
    assert token.get("type") == "access"
    assert token.get("foo") is None
    assert token.get("foo", "bar") == "bar"


def test_access_token__contains():
    token = AccessToken()

    assert "type" in token
    assert "foo" not in token


def test_access_token__set_claim():
    token = AccessToken()

    assert token.get("foo") is None
    token["foo"] = "bar"
    assert token.get("foo") == "bar"


def test_access_token__delete_claim():
    token = AccessToken()

    assert token.get("type") == "access"
    del token["type"]
    assert token.get("type") is None


def test_access_token__update():
    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    token.update({"foo": "bar"}, testing=123)
    assert list(token.payload.keys()) == ["type", "exp", "iat", "foo", "testing"]


def test_access_token__repr():
    token = AccessToken()

    assert repr(token) == repr(token.payload)


def test_refresh_token():
    token = RefreshToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex("[a-zA-Z0-9-_.]+")
    assert str(token).count(".") == 2


@pytest.mark.parametrize("sync", [[False], [True]])
def test_refresh_token__new_access_token(sync: bool):
    token = RefreshToken()
    access_token = token.new_access_token(sync=sync)

    assert list(access_token.payload.keys()) == ["type", "exp", "iat"]
    assert str(access_token) == equals_regex("[a-zA-Z0-9-_.]+")
    assert str(access_token).count(".") == 2

    if sync:
        assert token["iat"] == access_token["iat"]
    else:
        assert token["iat"] != access_token["iat"]
