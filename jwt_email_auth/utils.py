import logging
from random import randint
from inspect import cleandoc
from hashlib import md5

from django.core.mail import send_mail
from django.core.cache import cache
from django.template.loader import render_to_string
from django.utils.translation import override

from rest_framework.request import Request

from ipware import get_client_ip

from .settings import auth_settings


__all__ = [
    "generate_cache_key",
    "user_login_blocked",
    "send_login_email",
]


logger = logging.getLogger(__name__)


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


def generate_cache_key(content: str) -> str:
    """Generate cache key using a prefix (from auth_settings), and md5 hexdigest."""
    return f"{auth_settings.CACHE_PREFIX}-{md5(content.encode()).hexdigest()}"


def default_login_data() -> dict:
    """Default login data function that is meant to be overriden in Django settings."""
    return {}


def user_login_blocked(request: Request) -> bool:

    ip, is_routable = get_client_ip(
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )

    cache_key = generate_cache_key(ip)
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, auth_settings.LOGIN_COOLDOWN.total_seconds())

    block = attempts >= auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked = attempts - 1 < auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked user with ip '{ip}' due to too many login attempts.")

    return block


def send_login_email(request: Request, code: str, email: str) -> None:

    with override(request.LANGUAGE_CODE):
        plain_message = cleandoc(
            auth_settings.LOGIN_EMAIL_MESSAGE.format(
                code=code,
                valid=auth_settings.LOGIN_CODE_LIFETIME.total_seconds() // 60
            )
        )

    html_message = None
    if auth_settings.LOGIN_EMAIL_HTML_TEMPLATE is not None:
        html_message = render_to_string(
            auth_settings.LOGIN_EMAIL_HTML_TEMPLATE,
            context={"code": code, "valid": auth_settings.LOGIN_CODE_LIFETIME.total_seconds() // 60},
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
        logger.info(plain_message)
