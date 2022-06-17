import re
from datetime import timedelta
from time import sleep
from unittest.mock import PropertyMock, patch

import pytest
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated

from jwt_email_auth.rotation.models import RefreshTokenRotationLog
from jwt_email_auth.tokens import AccessToken, RefreshToken

from .conftest import equals_regex


def test_access_token():
    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


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


def test_access_token__add_audience(settings):
    settings.JWT_EMAIL_AUTH = {"AUDIENCE": "foo"}

    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat", "aud"]
    assert token.payload["aud"] == "foo"


def test_access_token__add_issuer(settings):
    settings.JWT_EMAIL_AUTH = {"ISSUER": "foo"}

    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat", "iss"]
    assert token.payload["iss"] == "foo"


def test_access_token__add_not_before_time(settings):
    settings.JWT_EMAIL_AUTH = {"NOT_BEFORE_TIME": timedelta(minutes=1)}

    token = AccessToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat", "nbf"]


def test_access_token__sync_with():
    old_token = AccessToken()
    sleep(1)
    new_token = AccessToken()

    new_token.sync_with(old_token)

    assert old_token["exp"] == new_token["exp"]


def test_access_token__sync_with__not_before(settings):
    settings.JWT_EMAIL_AUTH = {"NOT_BEFORE_TIME": timedelta(minutes=1)}

    old_token = AccessToken()
    sleep(1)
    new_token = AccessToken()

    new_token.sync_with(old_token)

    assert old_token["exp"] == new_token["exp"]


def test_access_token__from_request__header(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {old_token}"

    token = AccessToken.from_request(drf_request)

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_access_token__from_request__cookies(settings, drf_request):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    old_token = AccessToken()

    drf_request.COOKIES["access"] = str(old_token)

    token = AccessToken.from_request(drf_request)

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_access_token__from_request__cookies__refresh(settings, drf_request):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    old_token = RefreshToken()

    drf_request.COOKIES["refresh"] = str(old_token)

    token = RefreshToken.from_request(drf_request)

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_access_token__from_request__cookies__not_found(settings, drf_request):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    with pytest.raises(NotAuthenticated, match=re.escape("No token found from request cookies")):
        AccessToken.from_request(drf_request)

    with pytest.raises(NotAuthenticated, match=re.escape("No token found from request cookies")):
        RefreshToken.from_request(drf_request)


def test_access_token__from_request__authorization_header_not_found(drf_request):
    with pytest.raises(NotAuthenticated, match="No Authorization header found from request."):
        AccessToken.from_request(drf_request)


def test_access_token__from_request__authorization_header_invalid(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"{old_token}"
    with pytest.raises(AuthenticationFailed, match="Invalid Authorization header."):
        AccessToken.from_request(drf_request)


def test_access_token__from_request__authorization_header_invalid_prefix(drf_request):
    old_token = AccessToken()

    drf_request.META["HTTP_AUTHORIZATION"] = f"Foo {old_token}"
    with pytest.raises(AuthenticationFailed, match="Invalid prefix."):
        AccessToken.from_request(drf_request)


def test_access_token__from_token():
    token = AccessToken(token=str(AccessToken()))

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_access_token__from_token__expired():
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


def test_access_token__from_token__decoding_error():
    with pytest.raises(AuthenticationFailed, match="Error decoding signature."):
        AccessToken(token="foo")


def test_access_token__from_token__invalid_token(settings):
    # All other PyJWT errors are caugth with this error

    settings.JWT_EMAIL_AUTH = {"ISSUER": "foo"}
    token = str(AccessToken())

    settings.JWT_EMAIL_AUTH = {"ISSUER": "bar"}
    with pytest.raises(AuthenticationFailed, match="Invalid token."):
        AccessToken(token=token)


def test_access_token__from_token__invalid_token_type():
    token = str(RefreshToken())

    with pytest.raises(AuthenticationFailed, match="Invalid token type."):
        AccessToken(token=token)


def test_refresh_token():
    token = RefreshToken()

    assert list(token.payload.keys()) == ["type", "exp", "iat"]
    assert str(token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


@pytest.mark.django_db
def test_refresh_token__add_to_log(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    assert token["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1


@pytest.mark.django_db
def test_refresh_token__check_log(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    log = token.check_log()
    assert log.id == 1

    RefreshTokenRotationLog.objects.get(id=log.id).delete()

    with pytest.raises(AuthenticationFailed, match=re.escape("Token is no longer accepted.")):
        token.check_log()


@pytest.mark.django_db
def test_refresh_token__rotate(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    assert token["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1

    new_token = token.rotate()

    assert str(token) != str(new_token)
    assert new_token["jti"] == 2
    assert len(RefreshTokenRotationLog.objects.all()) == 1


@pytest.mark.django_db
def test_refresh_token__rotate__delete_new_token_when_old_token_used(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    old_token = RefreshToken()
    old_token.create_log()

    log_1 = old_token.check_log()
    assert log_1.id == 1

    logs = list(RefreshTokenRotationLog.objects.all())
    assert len(logs) == 1
    assert logs[0].id == 1

    new_token = old_token.rotate()

    log_2 = new_token.check_log()
    assert log_2.id == 2

    logs = list(RefreshTokenRotationLog.objects.all())
    assert len(logs) == 1
    assert logs[0].id == 2

    with pytest.raises(AuthenticationFailed, match=re.escape("Token is no longer accepted.")):
        old_token.check_log()

    logs = list(RefreshTokenRotationLog.objects.all())
    assert len(logs) == 0


@pytest.mark.django_db
def test_refresh_token__remove_from_log__by_token_title(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    assert token["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1

    RefreshTokenRotationLog.objects.remove_by_token_title(token=str(token))

    assert len(RefreshTokenRotationLog.objects.all()) == 0


@pytest.mark.django_db
def test_refresh_token__remove_from_log__by_token_title__cipher(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    assert token["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1

    RefreshTokenRotationLog.objects.remove_by_token_title(token=str(token))

    assert len(RefreshTokenRotationLog.objects.all()) == 0


@pytest.mark.django_db
def test_refresh_token__remove_from_log__by_token_title__cipher__changed(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    refresh = RefreshToken()
    refresh.create_log()

    assert refresh["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1

    token = str(refresh)

    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    RefreshTokenRotationLog.objects.remove_by_token_title(token=token)

    # Cannot delete log due to decrypt failure!
    assert len(RefreshTokenRotationLog.objects.all()) == 1


@pytest.mark.django_db
def test_refresh_token__remove_from_log__by_title(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    token = RefreshToken()
    token.create_log()

    assert token["jti"] == 1
    assert len(RefreshTokenRotationLog.objects.all()) == 1

    RefreshTokenRotationLog.objects.remove_by_title(title=str(token["sub"]))

    assert len(RefreshTokenRotationLog.objects.all()) == 0


@pytest.mark.django_db
def test_refresh_token__expired():
    with patch(
        "jwt_email_auth.tokens.RefreshToken.lifetime",
        new_callable=PropertyMock,
        return_value=timedelta(seconds=1),
    ):
        old_token = str(RefreshToken())

    # Wait for token to expire
    sleep(2)

    with pytest.raises(AuthenticationFailed, match="Signature has expired."):
        RefreshToken(token=old_token)


@pytest.mark.django_db
def test_refresh_token__expired__rotated(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    with patch(
        "jwt_email_auth.tokens.RefreshToken.lifetime",
        new_callable=PropertyMock,
        return_value=timedelta(seconds=1),
    ):
        token = RefreshToken()
        token.create_log()

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    # Wait for token to expire
    sleep(2)

    with pytest.raises(AuthenticationFailed, match="Signature has expired."):
        RefreshToken(token=str(token))

    assert len(RefreshTokenRotationLog.objects.all()) == 0


@pytest.mark.django_db
def test_refresh_token__remove_expired_tokens_from_other_groups(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    with patch(
        "jwt_email_auth.tokens.RefreshToken.lifetime",
        new_callable=PropertyMock,
        return_value=timedelta(seconds=1),
    ):
        old_token = RefreshToken()
        old_token.create_log()

    logs = list(RefreshTokenRotationLog.objects.all())
    assert len(logs) == 1
    assert logs[0].id == 1

    # Wait for token to expire
    sleep(2)

    new_token = RefreshToken()
    new_token.create_log()

    logs = list(RefreshTokenRotationLog.objects.all())
    assert len(logs) == 1
    assert logs[0].id == 2


@pytest.mark.django_db
def test_refresh_token__missing_jti(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    token = RefreshToken()

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    with pytest.raises(AuthenticationFailed, match='Token is missing the "jti" claim'):
        RefreshToken(token=str(token))


@pytest.mark.django_db
def test_refresh_token__missing_sub(settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    token = RefreshToken()
    token["jti"] = 1

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    with pytest.raises(AuthenticationFailed, match='Token is missing the "sub" claim'):
        RefreshToken(token=str(token))


@pytest.mark.parametrize("sync", [[False], [True]])
def test_refresh_token__new_access_token(sync: bool):
    token = RefreshToken()
    access_token = token.new_access_token(sync=sync)

    assert list(access_token.payload.keys()) == ["type", "exp", "iat"]
    assert str(access_token) == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert str(access_token).count(".") == 2

    if sync:
        assert token["iat"] == access_token["iat"]
    else:
        assert token["iat"] != access_token["iat"]
