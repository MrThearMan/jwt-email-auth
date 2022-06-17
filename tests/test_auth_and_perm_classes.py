import logging

import pytest
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient

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


def test_perm_view(drf_request):
    client = APIClient()
    token = AccessToken()
    response: Response = client.get("/test-perm", format="json", HTTP_AUTHORIZATION=f"Bearer {token}")

    # Since JWTAuthentication not used, user and token are not available
    assert response.data.get("token") == "None"
    assert response.data.get("user") == "AnonymousUser"
    assert response.data.get("is_authenticated") is False
    assert response.status_code == status.HTTP_200_OK


def test_perm_view__credential_not_provided(drf_request):
    client = APIClient()
    response: Response = client.get("/test-perm", format="json")

    assert response.data.get("detail") == "No Authorization header found from request."
    assert response.data.get("detail").code == "not_authenticated"
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_perm_view__invalid_header(drf_request):
    client = APIClient()
    token = AccessToken()
    response: Response = client.get("/test-perm", format="json", HTTP_AUTHORIZATION=f"{token}")

    assert response.data.get("detail") == "Invalid Authorization header."
    # code is passed to response
    assert response.data.get("detail").code == "invalid_header"
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_auth_view(drf_request):
    client = APIClient()
    token = AccessToken()
    response: Response = client.get("/test-auth", format="json", HTTP_AUTHORIZATION=f"Bearer {token}")

    assert response.data.get("token") == str(token)
    assert response.data.get("user") == "StatelessUser"
    assert response.data.get("is_authenticated") is True
    assert response.status_code == status.HTTP_200_OK


def test_auth_view__credential_not_provided(drf_request):
    client = APIClient()
    response: Response = client.get("/test-auth", format="json")

    assert response.data.get("token") == "None"
    assert response.data.get("user") == "AnonymousUser"
    assert response.data.get("is_authenticated") is False
    assert response.status_code == status.HTTP_200_OK


def test_auth_and_permission_view(drf_request):
    client = APIClient()
    token = AccessToken()
    response: Response = client.get("/test-both", format="json", HTTP_AUTHORIZATION=f"Bearer {token}")

    assert response.data.get("token") == str(token)
    assert response.data.get("user") == "StatelessUser"
    assert response.data.get("is_authenticated") is True
    assert response.status_code == status.HTTP_200_OK


def test_auth_and_permission_view__credential_not_provided(drf_request):
    client = APIClient()
    response: Response = client.get("/test-both", format="json")

    assert response.data.get("detail") == "Authentication credentials were not provided."
    assert response.data.get("detail").code == "not_authenticated"
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_auth_and_permission_view__options_request_without_token(drf_request, settings):
    settings.DEBUG = True
    client = APIClient()
    response: Response = client.options("/test-both", format="json")

    assert response.data == {
        "name": "Test View3",
        "description": "",
        "renders": ["application/json"],
        "parses": ["application/json"],
    }
    assert response.status_code == status.HTTP_200_OK
