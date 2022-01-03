import logging
from hashlib import md5
from inspect import cleandoc
from random import randint
from typing import Any, Dict

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
    "user_login_blocked",
    "send_login_email",
    "token_from_headers",
]


logger = logging.getLogger(__name__)


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


def generate_cache_key(content: str) -> str:
    """Generate cache key using a prefix (from auth_settings), and md5 hexdigest."""
    return f"{auth_settings.CACHE_PREFIX}-{md5(content.encode()).hexdigest()}"


def default_login_data(email: str) -> Dict[str, Any]:  # pylint: disable=W0613
    """Default login data function. It is meant to be overriden in Django settings."""
    return {}


def login_validation(email: str) -> None:  # pylint: disable=W0613
    """Default function to validate login. It is meant to be overriden in Django settings."""
    return


def blocking_handler(ip: str) -> None:  # pylint: disable=W0613,C0103
    """Default blocker ip handler. It is meant to be overriden in Django settings."""
    return


def user_login_blocked(request: Request) -> bool:

    ip, is_routable = get_client_ip(  # pylint: disable=C0103,W0612
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )

    cache_key = generate_cache_key(ip)
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, auth_settings.LOGIN_COOLDOWN.total_seconds())

    block: bool = attempts > auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked: bool = attempts - 1 <= auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked user with ip '{ip}' due to too many login attempts.")
        auth_settings.BLOCKING_HANDLER(ip=ip)

    return block


def send_login_email(request: Request, email: str, login_data: Dict[str, Any]) -> None:
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

    if auth_settings.SEND_EMAILS:
        send_mail(
            subject=auth_settings.LOGIN_SUBJECT_LINE,
            message=plain_message,
            from_email=auth_settings.LOGIN_SENDING_EMAIL,
            recipient_list=[email],
            html_message=html_message,
        )
    else:
        logger.info(plain_message if html_message is None else html_message)


def token_from_headers(request: Request) -> str:
    """Return token from request headers.

    :raises NotAuthenticated: No token in Authorization header.
    """
    auth_header = get_authorization_header(request)
    if not auth_header:
        raise NotAuthenticated(_("No Authorization header found from request."))
    return auth_header.split()[1].decode()
