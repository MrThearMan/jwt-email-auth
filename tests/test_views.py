import json
import logging
import re
from copy import deepcopy
from datetime import timedelta
from time import sleep
from unittest.mock import PropertyMock, patch

import pytest
from django.core.cache import cache
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.test import APIClient

from jwt_email_auth.rotation.models import RefreshTokenRotationLog
from jwt_email_auth.tokens import AccessToken, RefreshToken
from jwt_email_auth.utils import (
    TOKEN_PATTERN,
    blocking_handler,
    generate_cache_key,
    random_code,
    validate_login_and_provide_login_data,
)
from jwt_email_auth.views import BaseAuthView

from .conftest import equals_regex
from .helpers import get_login_code_from_message


def test_base_auth_view_extra_actions():
    assert BaseAuthView.get_extra_actions() == []


# Authenticate view


def test_authenticate_endpoint(caplog):
    client = APIClient()

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"
    func_1 = validate_login_and_provide_login_data
    str_2 = "jwt_email_auth.utils.random_code"
    func_2 = random_code

    with patch(str_1, side_effect=func_1) as mock_1, patch(str_2, side_effect=func_2) as mock_2:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock_1.assert_called_once_with("foo@bar.com")
    mock_2.assert_called_once()

    log_source, level, message = caplog.record_tuples[0]
    code = get_login_code_from_message(message)

    assert log_source == "jwt_email_auth.views"
    assert level == logging.INFO
    assert re.match(r"Login code: '\d{6}'", message)
    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code}


def test_authenticate_endpoint__login_code_already_exists(caplog):
    client = APIClient()

    response1 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")
    response2 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert response1.status_code == status.HTTP_204_NO_CONTENT
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    code_1 = get_login_code_from_message(caplog.record_tuples[0][2])
    code_2 = get_login_code_from_message(caplog.record_tuples[1][2])

    assert code_1 != code_2


def test_authenticate_endpoint__block_user_sending_too_many_emails(settings, caplog):
    client = APIClient()
    caplog.set_level(logging.DEBUG)

    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
    }

    with patch("jwt_email_auth.utils.send_mail") as mock:
        response1 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")
        response2 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert response1.status_code == status.HTTP_204_NO_CONTENT
    assert response2.status_code == status.HTTP_412_PRECONDITION_FAILED

    assert response2.data.get("detail") == "This user is not allowed to send another login code yet."


def test_authenticate_endpoint__use_email_template(settings, caplog):
    client = APIClient()
    caplog.set_level(logging.DEBUG)

    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
        "LOGIN_EMAIL_HTML_TEMPLATE": "email_test_template.html",
    }

    str_1 = "jwt_email_auth.utils.send_mail"
    str_2 = "jwt_email_auth.utils.render_to_string"

    with patch(str_1) as mock1, patch(str_2, side_effect=render_to_string) as mock2:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock1.assert_called_once()
    mock2.assert_called_once()

    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.views"
    assert level == logging.DEBUG
    assert re.match(r"\{'code': '\d{6}'}", message)  # noqa
    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_authenticate_endpoint__send_mock_email(settings):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
    }

    with patch("jwt_email_auth.utils.send_mail") as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_called_once_with(
        subject=equals_regex(r".+"),
        message=equals_regex(r".+"),
        from_email=None,
        recipient_list=["foo@bar.com"],
        html_message=None,
    )


def test_authenticate_endpoint__email_sending_fails(settings, caplog):
    client = APIClient()
    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
    }

    class TestException(Exception):
        def __init__(self):
            super().__init__("foo")

    with patch("jwt_email_auth.utils.send_login_email", side_effect=TestException) as mock:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.views"
    assert level == logging.CRITICAL
    assert message == "Login code sending failed: TestException('foo')"

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) is None

    assert response.data.get("detail") == "Failed to send login codes. Try again later."
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_authenticate_endpoint__validate_email():
    client = APIClient()
    response = client.post("/authenticate", {"email": "foobar"}, format="json")

    assert response.data.get("email")[0] == "Enter a valid email address."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_authenticate_endpoint__email_is_mandatory():
    client = APIClient()
    response = client.post("/authenticate", {}, format="json")

    assert response.data.get("email")[0] == "This field is required."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_authenticate_endpoint__skip_code_checks_for(settings):
    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
        "SKIP_CODE_CHECKS_FOR": ["foo@bar.com"],
    }

    client = APIClient()

    with patch("jwt_email_auth.utils.send_mail") as mock:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_not_called()
    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) is not None


# Login view


def test_login_endpoint(caplog):
    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    access = response.data["access"]
    refresh = response.data["refresh"]
    assert TOKEN_PATTERN.match(access) is not None
    assert TOKEN_PATTERN.match(refresh) is not None
    assert response.status_code == status.HTTP_200_OK

    assert cache.get(key) is None


def test_login_endpoint__user_gets_blocked__ip(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "LOGIN_ATTEMPTS": 1,
    }

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    real_code = get_login_code_from_message(message)

    while True:
        code = random_code()
        if code != real_code:
            break

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data.get("detail") == "Incorrect login code."
    # 401 is coerced to 403 by APIView.handle_exception since login endpoint doesn't contain an
    # authentication_class, and thus WWW-Authenticate header cannot be determined.
    assert response1.status_code == status.HTTP_403_FORBIDDEN

    str_1 = "jwt_email_auth.utils.blocking_handler"
    str_2 = "jwt_email_auth.utils.generate_cache_key"
    func_1 = blocking_handler
    func_2 = generate_cache_key

    with patch(str_1, side_effect=func_1) as mock1, patch(str_2, side_effect=func_2) as mock2:
        response2 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    mock1.assert_called_once()
    mock2.assert_called_once_with(equals_regex(r".*"), extra_prefix="block")

    message = caplog.record_tuples[-2][2]

    assert response2.data.get("detail") == equals_regex(r"Maximum number of attempts reached. Try again in \d minutes.")
    assert response2.status_code == status.HTTP_412_PRECONDITION_FAILED

    assert message == equals_regex(r"Blocked login for '.+' due to too many attempts\.")

    response3 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert response3.data.get("detail") == "This user is not allowed to send another login code yet."
    assert response3.status_code == status.HTTP_412_PRECONDITION_FAILED


def test_login_endpoint__user_gets_blocked__email(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "LOGIN_ATTEMPTS": 1,
        "LOGIN_BLOCKER_CACHE_KEY_CALLBACK": "jwt_email_auth.utils.blocking_cache_key_from_email",
    }

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    real_code = get_login_code_from_message(message)

    while True:
        code = random_code()
        if code != real_code:
            break

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data.get("detail") == "Incorrect login code."
    # 401 is coerced to 403 by APIView.handle_exception since login endpoint doesn't contain an
    # authentication_class, and thus WWW-Authenticate header cannot be determined.
    assert response1.status_code == status.HTTP_403_FORBIDDEN

    str_1 = "jwt_email_auth.utils.blocking_handler"
    str_2 = "jwt_email_auth.utils.generate_cache_key"
    func_1 = blocking_handler
    func_2 = generate_cache_key

    with patch(str_1, side_effect=func_1) as mock1, patch(str_2, side_effect=func_2) as mock2:
        response2 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    mock1.assert_called_once()
    mock2.assert_called_once_with("foo@bar.com", extra_prefix="block")

    message = caplog.record_tuples[-2][2]

    assert response2.data.get("detail") == equals_regex(r"Maximum number of attempts reached. Try again in \d minutes.")
    assert response2.status_code == status.HTTP_412_PRECONDITION_FAILED

    assert message == equals_regex(r"Blocked login for '.+' due to too many attempts\.")

    response3 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert response3.data.get("detail") == "This user is not allowed to send another login code yet."
    assert response3.status_code == status.HTTP_412_PRECONDITION_FAILED


def test_login_endpoint__expected_claims_found(settings, caplog):
    caplog.set_level(logging.DEBUG)
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123, "bar": "true"}

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"
    with patch(str_1, side_effect=custom_login_data_function) as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_called_once()

    login_data = caplog.record_tuples[0][2]
    message = caplog.record_tuples[1][2]
    code = get_login_code_from_message(message)

    assert json.loads(login_data.replace("'", '"')) == {"foo": 123, "bar": "true", "code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    AccessToken(token=response.data["access"])


def test_login_endpoint__expected_claims_not_found(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123}

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"

    with patch(str_1, side_effect=custom_login_data_function) as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_called_once()

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code, "foo": 123}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data.get("detail") == "Data was corrupted. Try to send another login code."
    assert response.status_code == status.HTTP_410_GONE

    assert cache.get(key) is None


def test_login_endpoint__login_code_not_found():
    client = APIClient()
    response = client.post("/login", {"email": "foo@bar.com", "code": 123456}, format="json")

    assert response.data.get("detail") == "No login code found for 'foo@bar.com'."
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_login_endpoint__validate_email():
    client = APIClient()
    response = client.post("/login", {"email": "foobar", "code": 123456}, format="json")

    assert response.data.get("email")[0] == "Enter a valid email address."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_login_endpoint__email_and_code_are_mandatory():
    client = APIClient()
    response = client.post("/login", {}, format="json")

    assert response.data.get("email")[0] == "This field is required."
    assert response.data.get("code")[0] == "This field is required."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_login_endpoint__skip_code_checks_for(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "SENDING_ON": True,
        "SKIP_CODE_CHECKS": False,
        "SKIP_CODE_CHECKS_FOR": ["foo@bar.com"],
    }

    client = APIClient()

    with patch("jwt_email_auth.utils.send_mail") as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_not_called()

    # Code doesn't matter if user in SKIP_CODE_CHECKS_FOR
    response = client.post("/login", {"email": "foo@bar.com", "code": "..."}, format="json")

    access = response.data["access"]
    refresh = response.data["refresh"]
    assert TOKEN_PATTERN.match(access) is not None
    assert TOKEN_PATTERN.match(refresh) is not None
    assert response.status_code == status.HTTP_200_OK


def test_login_endpoint__login_code_expired(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "LOGIN_CODE_LIFETIME": timedelta(seconds=1),
    }
    key = generate_cache_key("foo@bar.com", extra_prefix="login")

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert cache.get(key) == {"code": equals_regex(r"\d{6}")}

    # Wait for token to expire
    sleep(2)

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data.get("detail") == "No login code found for 'foo@bar.com'."
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_login_endpoint__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT
    assert response1.cookies["access"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert response1.cookies["refresh"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_login_endpoint__cipher(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response.status_code == status.HTTP_200_OK

    access = response.data["access"]
    refresh = response.data["refresh"]

    # Should be encoded
    assert TOKEN_PATTERN.match(access) is None
    assert TOKEN_PATTERN.match(refresh) is None

    access_token = AccessToken(access)
    assert access_token.payload["type"] == "access"
    refresh_token = RefreshToken(refresh)
    assert refresh_token.payload["type"] == "refresh"

    assert cache.get(key) is None


def test_login_endpoint__cipher__changed(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response.status_code == status.HTTP_200_OK

    access = response.data["access"]
    refresh = response.data["refresh"]

    # Should be encoded
    assert TOKEN_PATTERN.match(access) is None
    assert TOKEN_PATTERN.match(refresh) is None

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    with pytest.raises(AuthenticationFailed, match=re.escape("Wrong cipher key.")):
        AccessToken(access)

    with pytest.raises(AuthenticationFailed, match=re.escape("Wrong cipher key.")):
        RefreshToken(refresh)

    assert cache.get(key) is None


def test_login_endpoint__cipher__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com", extra_prefix="login")
    assert cache.get(key) == {"code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT

    access = response.cookies["access"].value
    refresh = response.cookies["refresh"].value

    # Should be encoded
    assert TOKEN_PATTERN.match(access) is None
    assert TOKEN_PATTERN.match(refresh) is None

    access_token = AccessToken(access)
    assert access_token.payload["type"] == "access"
    refresh_token = RefreshToken(refresh)
    assert refresh_token.payload["type"] == "refresh"

    assert cache.get(key) is None


# Refresh view


def test_refresh_endpoint(caplog):
    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    # After some time has passed, the expiry time on the new access token will be different
    # -> Tokens will be different
    sleep(2)

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }
    assert response2.status_code == status.HTTP_200_OK

    assert response1.data["access"] != response2.data["access"]


def test_refresh_endpoint__refresh_token_expired(caplog):
    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    with patch(
        "jwt_email_auth.tokens.RefreshToken.lifetime",
        new_callable=PropertyMock,
        return_value=timedelta(seconds=1),
    ):
        response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    # Wait for token to expire
    sleep(2)

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data.get("detail") == "Signature has expired."
    assert response2.status_code == status.HTTP_403_FORBIDDEN


def test_refresh_endpoint__expected_claims_found(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123, "bar": "true"}

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"

    with patch(str_1, side_effect=custom_login_data_function):
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }
    assert response2.status_code == status.HTTP_200_OK


def test_refresh_endpoint__expected_claims_not_found(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "EXPECTED_CLAIMS": ["foo"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123}

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"

    with patch(str_1, side_effect=custom_login_data_function):
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    settings.JWT_EMAIL_AUTH = {
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data.get("detail") == "Missing token claims: ['bar']."
    assert response2.status_code == status.HTTP_403_FORBIDDEN


def test_refresh_endpoint__token_is_mandatory():
    client = APIClient()
    response = client.post("/refresh", {}, format="json")

    assert response.data.get("token")[0] == "This field is required."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_refresh_endpoint__check_user_still_exists(settings, caplog):
    client = APIClient()

    str_1 = "jwt_email_auth.utils.user_check_callback"

    settings.JWT_EMAIL_AUTH = {
        "USER_CHECK_CALLBACK": str_1,
    }

    def custom_user_check_callback(refresh: RefreshToken):
        return

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    with patch(str_1, side_effect=custom_user_check_callback) as user_check:
        response2 = client.post("/refresh", {"token": response1.data["refresh"], "user_check": True}, format="json")

    user_check.assert_called_once()

    assert response2.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }
    assert response2.status_code == status.HTTP_200_OK


def test_refresh_endpoint__check_user_still_exists__not_found(settings, caplog):
    client = APIClient()

    str_1 = "jwt_email_auth.utils.user_check_callback"

    settings.JWT_EMAIL_AUTH = {
        "USER_CHECK_CALLBACK": str_1,
    }

    def custom_user_check_callback(refresh: RefreshToken):
        raise NotFound("User not found.")

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    with patch(str_1, side_effect=custom_user_check_callback) as user_check:
        response2 = client.post("/refresh", {"token": response1.data["refresh"], "user_check": True}, format="json")

    user_check.assert_called_once()

    assert response2.status_code == status.HTTP_404_NOT_FOUND
    assert response2.data == {"detail": "User not found."}


@pytest.mark.django_db
def test_refresh_endpoint__rotate(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }
    assert response2.status_code == status.HTTP_200_OK

    assert len(RefreshTokenRotationLog.objects.all()) == 1


@pytest.mark.django_db
def test_refresh_endpoint__rotate__using_old_refresh_invalidates_current_one(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response3 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response4 = client.post("/refresh", {"token": response2.data["refresh"]}, format="json")

    assert response4.data == {"detail": "Token is no longer accepted."}
    assert response4.status_code == status.HTTP_403_FORBIDDEN


def test_refresh_endpoint__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT
    assert response1.cookies["access"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert response1.cookies["refresh"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/refresh", {"token": str(RefreshToken())}, format="json")

    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT
    assert response2.cookies["access"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert response2.cookies["refresh"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def test_refresh_endpoint__cipher(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    # After some time has passed, the expiry time on the new access token will be different
    # -> Tokens will be different
    sleep(2)

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    access = response2.data["access"]
    refresh = response2.data["refresh"]

    # Should be encoded
    assert TOKEN_PATTERN.match(access) is None
    assert TOKEN_PATTERN.match(refresh) is None

    access_token = AccessToken(access)
    assert access_token.payload["type"] == "access"
    refresh_token = RefreshToken(refresh)
    assert refresh_token.payload["type"] == "refresh"

    assert response2.status_code == status.HTTP_200_OK

    assert response1.data["access"] != response2.data["access"]


def test_refresh_endpoint__cipher__changed(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")
    assert response2.data == {"token": ["JWT decrypt failed."]}
    assert response2.status_code == status.HTTP_400_BAD_REQUEST


def test_refresh_endpoint__cipher__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/refresh", {"token": str(RefreshToken())}, format="json")

    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    access = response2.cookies["access"].value
    refresh = response2.cookies["refresh"].value

    # Should be encoded
    assert TOKEN_PATTERN.match(access) is None
    assert TOKEN_PATTERN.match(refresh) is None

    access_token = AccessToken(access)
    assert access_token.payload["type"] == "access"
    refresh_token = RefreshToken(refresh)
    assert refresh_token.payload["type"] == "refresh"


# Logout


@pytest.mark.django_db
def test_logout_endpoint(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/logout", {"token": response1.data["refresh"]}, format="json")
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response3 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_logout_endpoint__with_old_token(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response3 = client.post("/logout", {"token": response1.data["refresh"]}, format="json")
    assert response3.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response4 = client.post("/refresh", {"token": response2.data["refresh"]}, format="json")

    assert response4.data == {"detail": "Token is no longer accepted."}
    assert response4.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_logout_endpoint__cipher(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/logout", {"token": response1.data["refresh"]}, format="json")
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response3 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_logout_endpoint__cipher__changed(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    response2 = client.post("/logout", {"token": response1.data["refresh"]}, format="json")
    assert response2.data == {"token": ["JWT decrypt failed."]}
    assert response2.status_code == status.HTTP_400_BAD_REQUEST

    # Cannot delete log due to decrypt failure!
    assert len(RefreshTokenRotationLog.objects.all()) == 1


@pytest.mark.django_db
def test_logout_endpoint__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/logout", {"token": str(RefreshToken())}, format="json")
    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    # token given due to serializer being set at import time, not used in reality
    response3 = client.post("/refresh", {"token": str(RefreshToken())}, format="json")

    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_logout_endpoint__cipher__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "USE_COOKIES": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/logout", {"token": str(RefreshToken())}, format="json")
    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    # token given due to serializer being set at import time, not used in reality
    response3 = client.post("/refresh", {"token": str(RefreshToken())}, format="json")

    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


# Update


def _data_callback(*args, **kwargs):
    return {"foo": 0, "bar": False}


@pytest.mark.django_db
def test_update_endpoint(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }

    token = AccessToken(str(response1.data["access"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    token = RefreshToken(str(response1.data["refresh"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post(
        "/update", {"data": {"foo": 1, "bar": True}, "token": response1.data["refresh"]}, format="json"
    )

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    assert response2.data == {
        "access": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
        "refresh": equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$"),
    }

    token = AccessToken(str(response2.data["access"]))
    assert token["foo"] == 1
    assert token["bar"] is True

    token = RefreshToken(str(response2.data["refresh"]))
    assert token["foo"] == 1
    assert token["bar"] is True

    assert response1.data["access"] != response2.data["access"]
    assert response1.data["refresh"] != response2.data["refresh"]

    response3 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")
    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_update_endpoint__unexpected_claim(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post("/update", {"data": {"fizz": "buzz"}, "token": response1.data["refresh"]}, format="json")
    assert response2.data == {"detail": "'fizz' not found from the list of expected claims."}
    assert response2.status_code == status.HTTP_412_PRECONDITION_FAILED


@pytest.mark.django_db
def test_update_endpoint__not_allowed_to_update(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post(
        "/update", {"data": {"foo": 1, "bar": True}, "token": response1.data["refresh"]}, format="json"
    )
    assert response2.data == {"detail": "Not allowed to update claim 'bar'."}
    assert response2.status_code == status.HTTP_412_PRECONDITION_FAILED


@pytest.mark.django_db
def test_update_endpoint__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT
    assert response1.cookies["access"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert response1.cookies["refresh"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")

    token = AccessToken(response1.cookies["access"].value)
    assert token["foo"] == 0
    assert token["bar"] is False

    token = RefreshToken(response1.cookies["refresh"].value)
    assert token["foo"] == 0
    assert token["bar"] is False

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    cookies = deepcopy(response1.cookies)
    client.cookies = cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/update", {"data": {"foo": 1, "bar": True}, "token": str(RefreshToken())}, format="json")

    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT
    assert response2.cookies["access"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")
    assert response2.cookies["refresh"].value == equals_regex(r"^[\w-]+\.[\w-]+\.[\w-]+$")

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    token = AccessToken(response2.cookies["access"].value)
    assert token["foo"] == 1
    assert token["bar"] is True

    token = RefreshToken(response2.cookies["refresh"].value)
    assert token["foo"] == 1
    assert token["bar"] is True


@pytest.mark.django_db
def test_update_endpoint__cipher(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.status_code == status.HTTP_200_OK

    token = AccessToken(str(response1.data["access"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    token = RefreshToken(str(response1.data["refresh"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    response2 = client.post(
        "/update", {"data": {"foo": 1, "bar": True}, "token": response1.data["refresh"]}, format="json"
    )
    assert response2.status_code == status.HTTP_200_OK

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    token = AccessToken(str(response2.data["access"]))
    assert token["foo"] == 1
    assert token["bar"] is True

    token = RefreshToken(str(response2.data["refresh"]))
    assert token["foo"] == 1
    assert token["bar"] is True

    assert response1.data["access"] != response2.data["access"]
    assert response1.data["refresh"] != response2.data["refresh"]

    response3 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")
    assert response3.data == {"detail": "Token is no longer accepted."}
    assert response3.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_update_endpoint__cipher__changed(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.status_code == status.HTTP_200_OK

    token = AccessToken(str(response1.data["access"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    token = RefreshToken(str(response1.data["refresh"]))
    assert token["foo"] == 0
    assert token["bar"] is False

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    response2 = client.post(
        "/update", {"data": {"foo": 1, "bar": True}, "token": response1.data["refresh"]}, format="json"
    )
    assert response2.data == {"token": ["JWT decrypt failed."]}
    assert response2.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_update_endpoint__cipher__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "ROTATE_REFRESH_TOKENS": True,
        "EXPECTED_CLAIMS": ["foo", "bar"],
        "UPDATEABLE_CLAIMS": ["foo", "bar"],
        "LOGIN_VALIDATION_AND_DATA_CALLBACK": "tests.test_views._data_callback",
        "USE_COOKIES": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    assert len(RefreshTokenRotationLog.objects.all()) == 0

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT

    token = AccessToken(response1.cookies["access"].value)
    assert token["foo"] == 0
    assert token["bar"] is False

    token = RefreshToken(response1.cookies["refresh"].value)
    assert token["foo"] == 0
    assert token["bar"] is False

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    cookies = deepcopy(response1.cookies)
    client.cookies = cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.post("/update", {"data": {"foo": 1, "bar": True}, "token": str(RefreshToken())}, format="json")
    assert response2.data is None
    assert response2.status_code == status.HTTP_204_NO_CONTENT

    assert len(RefreshTokenRotationLog.objects.all()) == 1

    token = AccessToken(response2.cookies["access"].value)
    assert token["foo"] == 1
    assert token["bar"] is True

    token = RefreshToken(response2.cookies["refresh"].value)
    assert token["foo"] == 1
    assert token["bar"] is True


# Token claims


def test_token_claim_endpoint(caplog):
    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    response2 = client.get("/claims", HTTP_AUTHORIZATION=f"Bearer {response1.data['access']}", format="json")
    assert response2.status_code == status.HTTP_200_OK
    assert response2.data == {"type": "access", "exp": equals_regex(r"\d+"), "iat": equals_regex(r"\d+")}


def test_token_claim_endpoint__expected_claims(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123, "bar": "true"}

    client = APIClient()

    str_1 = "jwt_email_auth.utils.validate_login_and_provide_login_data"
    with patch(str_1, side_effect=custom_login_data_function) as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_called_once()

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    response2 = client.get("/claims", HTTP_AUTHORIZATION=f"Bearer {response1.data['access']}", format="json")
    assert response2.status_code == status.HTTP_200_OK
    assert response2.data == {
        "foo": 123,
        "bar": "true",
        "type": "access",
        "exp": equals_regex(r"\d+"),
        "iat": equals_regex(r"\d+"),
    }


def test_token_claim_endpoint__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.get("/claims", format="json")
    assert response2.status_code == status.HTTP_200_OK
    assert response2.data == {"type": "access", "exp": equals_regex(r"\d+"), "iat": equals_regex(r"\d+")}


def test_token_claim_endpoint__cipher(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    response2 = client.get("/claims", HTTP_AUTHORIZATION=f"Bearer {response1.data['access']}", format="json")
    assert response2.status_code == status.HTTP_200_OK
    assert response2.data == {"type": "access", "exp": equals_regex(r"\d+"), "iat": equals_regex(r"\d+")}


def test_token_claim_endpoint__cipher__changed(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    response2 = client.get("/claims", HTTP_AUTHORIZATION=f"Bearer {response1.data['access']}", format="json")
    assert response2.data == {"detail": "Authentication credentials were not provided."}
    assert response2.status_code == status.HTTP_401_UNAUTHORIZED


def test_token_claim_endpoint__cipher__use_cookies(caplog, settings):
    settings.JWT_EMAIL_AUTH = {
        "USE_COOKIES": True,
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")
    assert response1.data is None
    assert response1.status_code == status.HTTP_204_NO_CONTENT

    client.cookies = response1.cookies
    # token given due to serializer being set at import time, not used in reality
    response2 = client.get("/claims", format="json")
    assert response2.status_code == status.HTTP_200_OK
    assert response2.data == {"type": "access", "exp": equals_regex(r"\d+"), "iat": equals_regex(r"\d+")}
