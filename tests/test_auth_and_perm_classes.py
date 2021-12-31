import logging

import pytest

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.models import StatelessUser
from jwt_email_auth.permissions import HasValidJWT
from jwt_email_auth.tokens import AccessToken


def test_has_valid_jwt(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    instance = HasValidJWT()
    assert instance.has_permission(drf_request, None) is True


def test_has_valid_jwt__missing_authorization_header(drf_request, caplog):
    caplog.set_level(logging.DEBUG)
    instance = HasValidJWT()

    assert instance.has_permission(drf_request, None) is False

    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.permissions"
    assert level == logging.DEBUG
    assert message == "No Authorization header found from request."


def test_has_valid_jwt__allow_options_request_in_debug_mode(settings, drf_request):
    instance = HasValidJWT()
    settings.DEBUG = True
    drf_request.method = "OPTIONS"

    assert instance.has_permission(drf_request, None) is True


def test_jwt_authentication(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    instance = JWTAuthentication()
    result = instance.authenticate(drf_request)

    if result is None:
        pytest.fail("Authentication did not succeed.")

    user, auth = result
    assert isinstance(user, StatelessUser)
    assert str(user.token) == str(token)
    assert auth == str(token)


def test_jwt_authentication__missing_authorization_header(drf_request, caplog):
    caplog.set_level(logging.DEBUG)
    instance = JWTAuthentication()

    assert instance.authenticate(drf_request) is None

    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.authentication"
    assert level == logging.DEBUG
    assert message == "No Authorization header found from request."


def test_jwt_authentication__get_authenticate_header():
    instance = JWTAuthentication()
    result = instance.authenticate_header(None)
    assert result == 'Bearer realm="api"'
