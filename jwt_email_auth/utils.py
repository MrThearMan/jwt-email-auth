from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
import re
from functools import wraps
from inspect import cleandoc
from typing import TYPE_CHECKING
from warnings import warn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy
from ipware import get_client_ip
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ValidationError

from .settings import auth_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from rest_framework.request import Request

    from .tokens import RefreshToken
    from .typing import Any


__all__ = [
    "EXAMPLE_PRIVATE_KEY",
    "TOKEN_PATTERN",
    "decrypt_with_cipher",
    "encrypt_with_cipher",
    "generate_cache_key",
    "generate_code_sent_cache_key",
    "generate_login_data_cache_key",
    "generate_user_blocking_cache_key",
    "get_id_value_from_request_data",
    "parse_signing_key",
    "send_login_email",
    "token_from_headers",
    "user_is_blocked",
    "valid_jwt_format",
]


logger = logging.getLogger(__name__)

TOKEN_PATTERN = re.compile(r"^[\w-]+\.[\w-]+\.[\w-]+$")

# EXAMPLE_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMOFDpS02jVpNbJidXBM+s9QzWqVx56pxZdWEgVjA4T"
EXAMPLE_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----|"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW|"
    "QyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEwAAAJDEf7enxH+3|"
    "pwAAAAtzc2gtZWQyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEw|"
    "AAAECjUueNb+pa9Mf0cVahpJzyBbwQgZrp2qLgYykEiC4g4IMOFDpS02jVpNbJidXBM+s9|"
    "QzWqVx56pxZdWEgVjA4TAAAAC2xhbXBwQEtBTlRPAQI=|"
    "-----END OPENSSH PRIVATE KEY-----"
)


def random_code() -> str:
    return str(random.randint(1, 999_999)).zfill(6)  # noqa: S311


def get_ip(request: Request) -> str:
    ip, _ = get_client_ip(
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )
    return ip


def generate_cache_key(content: str, /, extra_prefix: str) -> str:
    """Generate cache key using a prefix (from auth_settings), and md5 hexdigest."""
    return f"{auth_settings.CACHE_PREFIX}-{extra_prefix}-{hashlib.md5(content.encode()).hexdigest()}"  # noqa: S324


def generate_login_data_cache_key(value: str) -> str:
    return generate_cache_key(value, extra_prefix="login")


def generate_code_sent_cache_key(value: str) -> str:
    return generate_cache_key(value, extra_prefix="sendcode")


def generate_user_blocking_cache_key(value: str) -> str:
    return generate_cache_key(value, extra_prefix="block")


def validate_login_and_provide_login_data(email: str) -> dict[str, Any]:  # noqa: ARG001
    """Default function to validate login and provide login data. It is meant to be overriden in Django settings."""
    return {}


def blocking_handler(request: Request) -> None:  # noqa: ARG001
    return


def blocking_cache_key_from_ip(request: Request) -> str:
    value = get_ip(request)
    return generate_user_blocking_cache_key(value)


def blocking_cache_key_from_email(request: Request) -> str:
    value = get_id_value_from_request_data(request.data)
    return generate_user_blocking_cache_key(value)


def get_id_value_from_request_data(data: dict[str, Any]) -> str:
    return next(value for key, value in data.items() if key != "code")


def user_is_blocked(request: Request, record_attempt: bool = True) -> bool:  # noqa: FBT001, FBT002
    cache_key = auth_settings.LOGIN_BLOCKER_CACHE_KEY_CALLBACK(request)
    attempt = cache.get(cache_key, 0) + 1

    if record_attempt:
        cache.set(cache_key, attempt, auth_settings.LOGIN_COOLDOWN.total_seconds())

    block: bool = attempt > auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked: bool = attempt - 1 <= auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked login for {get_ip(request)!r} due to too many attempts.")
        auth_settings.USER_BLOCKED_ADDITIONAL_HANDLER(request)

    return block


def send_login_email(email: str, login_data: dict[str, Any], request: Request) -> None:
    code = login_data["code"]
    valid = int(auth_settings.LOGIN_CODE_LIFETIME.total_seconds() // 60)
    plain_message = cleandoc(auth_settings.LOGIN_EMAIL_MESSAGE.format(code=code, valid=valid))

    html_message = None
    if auth_settings.LOGIN_EMAIL_HTML_TEMPLATE is not None:
        html_message = render_to_string(
            template_name=auth_settings.LOGIN_EMAIL_HTML_TEMPLATE,
            context={"code": code, "valid": valid},
            request=request,
        )

    send_mail(
        subject=auth_settings.LOGIN_SUBJECT_LINE,
        message=plain_message,
        from_email=auth_settings.LOGIN_SENDING_EMAIL,
        recipient_list=[email],
        html_message=html_message,
    )


def token_from_headers(request: Request) -> str:
    """
    Return token from request headers.

    :param request: Request with token in headers/cookies.
    :raises NotAuthenticated: No token in headers/cookies.
    :raises AuthenticationFailed: Token was invalid.
    """
    auth_header = get_authorization_header(request)
    if not auth_header:
        raise NotAuthenticated(gettext_lazy("No Authorization header found from request."))

    try:
        prefix, encoded_token = auth_header.decode().split()
    except ValueError as error:
        raise AuthenticationFailed(gettext_lazy("Invalid Authorization header."), code="invalid_header") from error

    if prefix.lower() != auth_settings.HEADER_PREFIX.lower():
        raise AuthenticationFailed(gettext_lazy("Invalid prefix."), code="invalid_header_prefix")

    return encoded_token


def valid_jwt_format(token: str) -> None:
    if auth_settings.CIPHER_KEY is not None:
        try:
            token = decrypt_with_cipher(token)
        except Exception as error:
            raise ValidationError(gettext_lazy("JWT decrypt failed."), code="jwt_decrypt_failed") from error

    match = TOKEN_PATTERN.match(token)
    if match is None:
        raise ValidationError(gettext_lazy("Invalid JWT format."), code="invalid_jwt_format")


def load_example_signing_key() -> Ed25519PrivateKey:
    """
    Loads an example signing key for signing and checking the signature of JWTs.
    You should set 'SIGNING_KEY' to your environment variables, or change this callback
    with the JWT_EMAIL_AUTH["SIGNING_KEY"] setting before going to production.
    """
    key = os.getenv("SIGNING_KEY", EXAMPLE_PRIVATE_KEY)
    if key == EXAMPLE_PRIVATE_KEY:
        warn(
            "Using the default signing key. "
            "Please change before going to production. "
            "To change, set 'SIGNING_KEY' environment variable.",
            stacklevel=2,
        )
    return parse_signing_key(key)


def parse_signing_key(key: str) -> Ed25519PrivateKey:
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())


def encrypt_with_cipher(string: str) -> str:
    try:
        key = base64.b64decode(auth_settings.CIPHER_KEY)
    except TypeError as error:
        raise RuntimeError(gettext_lazy("Cipher key not set.")) from error
    except Exception as error:
        raise RuntimeError(gettext_lazy("Invalid cipher key.")) from error

    nonce = os.urandom(12)
    cipher = AESGCM(key)
    encrypted_token = cipher.encrypt(nonce, string.encode(encoding="utf-8"), None)
    return base64.b64encode(nonce + encrypted_token).decode()


def decrypt_with_cipher(string: str | bytes) -> str:
    try:
        key = base64.b64decode(auth_settings.CIPHER_KEY)
    except TypeError as error:
        raise RuntimeError(gettext_lazy("Cipher key not set.")) from error
    except Exception as error:
        raise RuntimeError(gettext_lazy("Invalid cipher key.")) from error

    string = base64.b64decode(string)
    nonce = string[:12]
    data = string[12:]
    cipher = AESGCM(key=key)

    try:
        decrypted_token = cipher.decrypt(nonce, data, None)
    except InvalidTag as error:
        raise RuntimeError(gettext_lazy("Wrong cipher key.")) from error

    return decrypted_token.decode()


def user_check_callback(refresh: RefreshToken) -> None:  # noqa: ARG001
    """Default function to check if token user still exists."""
    return  # pragma: no cover


def iterable_cache(provider: str, *args: Any, **kwargs: Any) -> Callable[..., Any]:
    r"""
    Decorate classes "__next__" magic method. This creates a cache that remembers
    the current iterator object the instance is iterating over. The cached instance is
    provided to "__next__" as an argument, so it can just call next(...) on it.
    Once the iterator is iterated, it clears the cached iterator,
    so the class can then be iterated again.

    class A:
        def __iter__(self):
            return self

        @iterable_cache(provider="keys")
        def __next__(self, keys):
            return

        def keys(self):
            # items are provided here

    :params provider: Function that provides the items to iterate over.
                      Additional arguments can be provided to it from *args and **kwargs.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        items = None

        @wraps(func)
        def wrapper(self: Any) -> Any:
            nonlocal items
            if items is None:
                items = iter(getattr(self, provider)(*args, **kwargs))

            try:
                return func(self, items)
            except StopIteration:
                items = None
                raise

        return wrapper

    return decorator
