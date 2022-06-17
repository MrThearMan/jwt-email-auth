import re
from unittest.mock import patch

import pytest
from rest_framework.exceptions import NotAuthenticated, ValidationError

from jwt_email_auth.apps import JwtEmailAuthConfig
from jwt_email_auth.tokens import AccessToken
from jwt_email_auth.utils import (
    blocking_cache_key_from_email,
    blocking_cache_key_from_ip,
    decrypt_with_cipher,
    encrypt_with_cipher,
    generate_cache_key,
    random_code,
    token_from_headers,
    valid_jwt_format,
)


def test_random_code():
    assert len(random_code()) == 6


def test_app_name():
    assert JwtEmailAuthConfig.name == "jwt_email_auth"


def test_generate_cache_key():
    key = generate_cache_key("foo", extra_prefix="bar")
    prefix, hsh = key.split("-bar-", maxsplit=1)

    assert prefix == "Django"
    assert hsh == "acbd18db4cc2f85cedef654fccc4a4d8"


def test_token_from_headers(drf_request):
    drf_request.META["HTTP_AUTHORIZATION"] = "Bearer foobar"
    token = token_from_headers(drf_request)
    assert token == "foobar"


def test_token_from_headers__not_found(drf_request):
    with pytest.raises(NotAuthenticated, match="No Authorization header found from request."):
        token_from_headers(drf_request)


def test_blocking_cache_key_from_ip(drf_request):
    drf_request.META["HTTP_X_FORWARDED_FOR"] = "127.0.0.1"

    key = blocking_cache_key_from_ip(drf_request)
    assert key == "Django-block-f528764d624db129b32c21fbca0cb8d6"


def test_blocking_cache_key_from_email(drf_request):
    drf_request._full_data = drf_request._data = {"email": "foo@bar.com"}

    key = blocking_cache_key_from_email(drf_request)
    assert key == "Django-block-f3ada405ce890b6f8204094deb12d8a8"


def test_encrypt_and_decrypt_with_cipher(settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    access_token = AccessToken()
    token = str(access_token)
    encrytped = encrypt_with_cipher(token)
    decrypted = decrypt_with_cipher(encrytped)

    assert decrypted == token
    assert decrypted != str(access_token)  # Different nonce


def test_encrypt_and_decrypt_with_cipher__cipher_missing(settings):
    with pytest.raises(RuntimeError, match=re.escape("Cipher key not set.")):
        encrypt_with_cipher("")

    with pytest.raises(RuntimeError, match=re.escape("Cipher key not set.")):
        decrypt_with_cipher("")


def test_encrypt_and_decrypt_with_cipher__invalid_cipher(settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "foo",
    }

    with pytest.raises(RuntimeError, match=re.escape("Invalid cipher key.")):
        encrypt_with_cipher("")

    with pytest.raises(RuntimeError, match=re.escape("Invalid cipher key.")):
        decrypt_with_cipher("")


def test_encrypt_and_decrypt_with_cipher__changed_cipher(settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    access_token = AccessToken()
    token = str(access_token)
    encrytped = encrypt_with_cipher(token)

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "hh0NVjHB4SuIn5RzoamdJbjtm55I4g8i5T3yBznnvko=",
    }

    with pytest.raises(RuntimeError, match=re.escape("Wrong cipher key.")):
        decrypt_with_cipher(encrytped)


def test_valid_jwt_format():
    access_token = AccessToken()
    valid_jwt_format(str(access_token))


def test_valid_jwt_format__invalid():
    with pytest.raises(ValidationError, match=re.escape("Invalid JWT format.")):
        valid_jwt_format("")


def test_valid_jwt_format__encrypted(settings):
    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "6uSRBb+rzufBRKv9uQAGVzFMwXqiBq7bmbcPr5QHVPg=",
    }

    access_token = AccessToken()
    token = str(access_token)
    with patch("jwt_email_auth.utils.decrypt_with_cipher", side_effect=decrypt_with_cipher) as m1:
        valid_jwt_format(token)

    m1.assert_called_once_with(token)


def test_valid_jwt_format__encrypted__invalid(settings):
    access_token = AccessToken()
    token = str(access_token)

    settings.JWT_EMAIL_AUTH = {
        "CIPHER_KEY": "foo",
    }

    with pytest.raises(ValidationError, match=re.escape("JWT decrypt failed.")):
        valid_jwt_format(token)
