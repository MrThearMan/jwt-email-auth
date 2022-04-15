import logging
from hashlib import md5
from inspect import cleandoc
from os import getenv
from random import randint
from typing import Any, Dict
from warnings import warn

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _
from ipware import get_client_ip  # type: ignore
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import NotAuthenticated
from rest_framework.request import Request

from .settings import auth_settings


__all__ = [
    "generate_cache_key",
    "send_login_email",
    "token_from_headers",
    "user_is_blocked",
]


logger = logging.getLogger(__name__)


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


def get_ip(request: Request) -> str:
    ip, is_routable = get_client_ip(  # pylint: disable=C0103,W0612
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )
    return ip


def generate_cache_key(content: str, /, extra_prefix: str) -> str:
    """Generate cache key using a prefix (from auth_settings), and md5 hexdigest."""
    return f"{auth_settings.CACHE_PREFIX}-{extra_prefix}-{md5(content.encode()).hexdigest()}"


def validate_login_and_provide_login_data(email: str) -> Dict[str, Any]:  # pylint: disable=W0613
    """Default function to validate login and provide login data. It is meant to be overriden in Django settings."""
    return {}


def blocking_handler(request: Request) -> None:  # pylint: disable=W0613
    return


def blocking_cache_key_from_ip(request: Request) -> str:
    return generate_cache_key(get_ip(request), extra_prefix="block")


def blocking_cache_key_from_email(request: Request) -> str:
    value = [value for key, value in request.data.items() if key != "code"][0]
    return generate_cache_key(value, extra_prefix="block")


def user_is_blocked(request: Request) -> bool:
    cache_key = auth_settings.LOGIN_BLOCKER_CACHE_KEY_CALLBACK(request)
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, auth_settings.LOGIN_COOLDOWN.total_seconds())

    block: bool = attempts > auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked: bool = attempts - 1 <= auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked login for {get_ip(request)!r} due to too many attempts.")
        auth_settings.USER_BLOCKED_ADDITIONAL_HANDLER(request)

    return block


def send_login_email(email: str, login_data: Dict[str, Any], request: Request) -> None:
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
    """Return token from request headers.

    :raises NotAuthenticated: No token in Authorization header.
    """
    auth_header = get_authorization_header(request)
    if not auth_header:
        raise NotAuthenticated(_("No Authorization header found from request."))
    return auth_header.split()[1].decode()


def load_example_signing_key() -> Ed25519PrivateKey:
    """Loads an example signing key for signing and checking the signature of JWT tokens.
    You should set 'SIGNING_KEY' to your environment variables, or change this callback
    with the JWT_EMAIL_AUTH["SIGNING_KEY"] setting before going to production.
    """

    # _default_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMOFDpS02jVpNbJidXBM+s9QzWqVx56pxZdWEgVjA4T"
    _default_private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----|"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW|"
        "QyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEwAAAJDEf7enxH+3|"
        "pwAAAAtzc2gtZWQyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEw|"
        "AAAECjUueNb+pa9Mf0cVahpJzyBbwQgZrp2qLgYykEiC4g4IMOFDpS02jVpNbJidXBM+s9|"
        "QzWqVx56pxZdWEgVjA4TAAAAC2xhbXBwQEtBTlRPAQI=|"
        "-----END OPENSSH PRIVATE KEY-----"
    )

    key = getenv("SIGNING_KEY", _default_private_key)
    if key == _default_private_key:
        warn(
            "Using the default signing key. "
            "Please change before going to production. "
            "To change, set 'SIGNING_KEY' environment variable."
        )
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())  # type: ignore
