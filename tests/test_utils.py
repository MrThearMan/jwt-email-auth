import pytest
from rest_framework.exceptions import NotAuthenticated

from jwt_email_auth.apps import JwtEmailAuthConfig
from jwt_email_auth.utils import (
    blocking_cache_key_from_email,
    blocking_cache_key_from_ip,
    generate_cache_key,
    random_code,
    token_from_headers,
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
