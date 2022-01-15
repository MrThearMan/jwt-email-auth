import json
import logging
import re
from datetime import timedelta
from time import sleep
from unittest.mock import PropertyMock, patch

from django.core.cache import cache
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.test import APIClient

from jwt_email_auth.tokens import AccessToken, RefreshToken
from jwt_email_auth.utils import blocking_handler, default_login_data, generate_cache_key, login_validation, random_code

from .conftest import equals_regex
from .helpers import get_login_code_from_message


def test_authenticate_endpoint(caplog):
    client = APIClient()

    # fmt: off
    with patch("jwt_email_auth.utils.login_validation", side_effect=login_validation) as mock1, \
        patch("jwt_email_auth.utils.default_login_data", side_effect=default_login_data) as mock2, \
        patch("jwt_email_auth.utils.random_code", side_effect=random_code) as mock3:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")
    # fmt: on

    mock1.assert_called_once_with(email="foo@bar.com")
    mock2.assert_called_once()
    mock3.assert_called_once()

    log_source, level, message = caplog.record_tuples[0]
    code = get_login_code_from_message(message)

    assert log_source == "jwt_email_auth.views"
    assert level == logging.INFO
    assert re.match(r"Login code: '\d{6}'", message)
    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT

    key = generate_cache_key("foo@bar.com")
    assert cache.get(key) == {"code": code}


def test_login_endpoint(caplog):
    client = APIClient()

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com")
    assert cache.get(key) == {"code": code}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data == {"access": equals_regex(r"[a-zA-Z0-9-_.]+"), "refresh": equals_regex(r"[a-zA-Z0-9-_.]+")}
    assert response.data["access"].count(".") == 2
    assert response.data["refresh"].count(".") == 2
    assert response.status_code == status.HTTP_200_OK

    assert cache.get(key) is None


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

    assert response2.data == {"access": equals_regex(r"[a-zA-Z0-9-_.]+")}
    assert response2.status_code == status.HTTP_200_OK

    assert response1.data["access"] != response2.data["access"]


def test_authenticate_endpoint__login_code_already_exists():
    client = APIClient()

    response1 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")
    response2 = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert response1.status_code == status.HTTP_204_NO_CONTENT

    assert response2.data == {
        "message": "Login code for 'foo@bar.com' already exists. "
        "Please check your inbox and spam folder, or try again later."
    }
    assert response2.status_code == status.HTTP_200_OK


def test_authenticate_endpoint__use_email_template(settings, caplog):
    client = APIClient()
    caplog.set_level(logging.DEBUG)

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": True,
        "LOGIN_EMAIL_HTML_TEMPLATE": "email_test_template.html",
    }

    # fmt: off
    with patch("jwt_email_auth.utils.send_mail") as mock1, \
        patch("jwt_email_auth.utils.render_to_string", side_effect=render_to_string) as mock2:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")
    # fmt: on

    mock1.assert_called_once()
    mock2.assert_called_once()

    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.views"
    assert level == logging.DEBUG
    assert re.match(r"\{'code': '\d{6}'}", message)  # noqa
    assert response.data is None
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_login_endpoint__user_gets_blocked(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
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

    with patch("jwt_email_auth.utils.blocking_handler", side_effect=blocking_handler) as mock:
        response2 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    mock.assert_called_once_with(ip=equals_regex(r".+"))

    message = caplog.record_tuples[-2][2]

    assert response2.data.get("detail") == equals_regex(r"Maximum number of attempts reached. Try again in \d minutes.")
    assert response2.status_code == status.HTTP_403_FORBIDDEN

    assert message == equals_regex(r"Blocked user with ip '.+' due to too many login attempts\.")


def test_authenticate_endpoint__send_mock_email(settings):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": True,
    }

    with patch("jwt_email_auth.utils.send_mail", return_value=None) as mock:
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
        "SEND_EMAILS": True,
    }

    class TestException(Exception):
        def __init__(self):
            super().__init__("foo")

    with patch("jwt_email_auth.utils.send_login_email", side_effect=TestException) as mock:
        response = client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    # mock.assert_called_once()
    log_source, level, message = caplog.record_tuples[0]

    assert log_source == "jwt_email_auth.views"
    assert level == logging.CRITICAL
    assert message == "Email sending failed: TestException('foo')"

    key = generate_cache_key("foo@bar.com")
    assert cache.get(key) is None

    assert response.data.get("detail") == "Failed to send login codes. Try again later."
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_login_endpoint__expected_claims_found(settings, caplog):
    caplog.set_level(logging.DEBUG)
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123, "bar": "true"}

    with patch("jwt_email_auth.utils.default_login_data", side_effect=custom_login_data_function) as mock:
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
        "SEND_EMAILS": False,
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123}

    with patch("jwt_email_auth.utils.default_login_data", side_effect=custom_login_data_function) as mock:
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    mock.assert_called_once()

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    key = generate_cache_key("foo@bar.com")
    assert cache.get(key) == {"code": code, "foo": 123}

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data.get("detail") == "Data was corrupted. Try to send another login code."
    assert response.status_code == status.HTTP_410_GONE

    assert cache.get(key) is None

    log_source, level, message = caplog.record_tuples[-2]

    assert log_source == "jwt_email_auth.views"
    assert level == logging.WARNING
    assert message == (
        "Some data was missing from saved login info. "
        "If you set EXPECTED_CLAIMS, you should provide a custom "
        "LOGIN_DATA function that returns them."
    )


def test_login_endpoint__login_code_not_found():
    client = APIClient()
    response = client.post("/login", {"email": "foo@bar.com", "code": 123456}, format="json")

    assert response.data.get("detail") == "No login code found code for 'foo@bar.com'."
    assert response.status_code == status.HTTP_404_NOT_FOUND


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


def test_login_endpoint__login_code_expired(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "LOGIN_CODE_LIFETIME": timedelta(seconds=1),
    }
    key = generate_cache_key("foo@bar.com")

    client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    assert cache.get(key) == {"code": equals_regex(r"\d{6}")}

    # Wait for token to expire
    sleep(2)

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    assert response.data.get("detail") == "No login code found code for 'foo@bar.com'."
    assert response.status_code == status.HTTP_404_NOT_FOUND


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

    with patch("jwt_email_auth.utils.default_login_data", side_effect=custom_login_data_function):
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data == {"access": equals_regex(r".+")}
    assert response2.status_code == status.HTTP_200_OK


def test_refresh_endpoint__expected_claims_not_found(settings, caplog):
    client = APIClient()

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "EXPECTED_CLAIMS": ["foo"],
    }

    def custom_login_data_function(email: str):
        return {"foo": 123}

    with patch("jwt_email_auth.utils.default_login_data", side_effect=custom_login_data_function):
        client.post("/authenticate", {"email": "foo@bar.com"}, format="json")

    message = caplog.record_tuples[0][2]
    code = get_login_code_from_message(message)

    response1 = client.post("/login", {"email": "foo@bar.com", "code": code}, format="json")

    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "EXPECTED_CLAIMS": ["foo", "bar"],
    }

    response2 = client.post("/refresh", {"token": response1.data["refresh"]}, format="json")

    assert response2.data.get("detail") == "Missing claims."
    assert response2.status_code == status.HTTP_403_FORBIDDEN


def test_refresh_endpoint__token_is_mandatory():
    client = APIClient()
    response = client.post("/refresh", {}, format="json")

    assert response.data.get("token")[0] == "This field is required."
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_refresh_endpoint__return_both_tokens(settings):
    client = APIClient()
    token = RefreshToken()
    settings.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
        "REFRESH_VIEW_BOTH_TOKENS": True,
    }
    response = client.post("/refresh", {"token": str(token)}, format="json")

    assert response.data == {
        "access": equals_regex(r"[a-zA-Z0-9-_.]+"),
        "refresh": equals_regex(r"[a-zA-Z0-9-_.]+"),
    }
    assert response.status_code == status.HTTP_200_OK

    # returned refresh token is the same as input
    assert str(token) == str(response.data["refresh"])
