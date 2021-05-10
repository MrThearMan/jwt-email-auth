"""Python utility functions, that have nothing to do with the Dynamics database."""

import logging
from inspect import cleandoc
from hashlib import md5
from ipware import get_client_ip

from django.conf import settings
from django.core.mail import send_mail
from django.core.cache import cache
from django.utils.translation import override, gettext_lazy as _

from rest_framework.request import Request

from .settings import auth_settings
from .exceptions import EmailServerException


__all__ = [
    "user_login_blocked",
    "send_login_email",
]


logger = logging.getLogger(__name__)


def user_login_blocked(request: Request):

    ip, is_routable = get_client_ip(
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )

    cache_key = f"{auth_settings.CACHE_PREFIX}-{md5(ip.encode()).hexdigest()}"
    attempts = cache.get(cache_key, 0) + 1
    cache.set(cache_key, attempts, auth_settings.LOGIN_COOLDOWN)

    block = attempts >= auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked = attempts - 1 < auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked user with ip '{ip}' due to too many login attempts.")

    return block


def send_login_email(language: str, code: str, email: str):

    with override(language):
        valid = auth_settings.LOGIN_CODE_LIFETIME // 60
        plain_message = cleandoc(
            _(
                f"""
                    Your login code:
                    
                    {code}
                    
                    This code is valid for the next {valid} minutes.
                """
            )
        )

    if settings.DEBUG:
        print(plain_message)

    if auth_settings.SEND_BY_EMAIL:
        try:
            send_mail(
                subject=_("Login to Django"),
                message=plain_message,
                from_email=None,  # Use default from email
                recipient_list=[email],
            )
        except Exception as e:  # noqa
            logger.error(f"Failed to send login code: {e}")
            raise EmailServerException(_("Unable to send login codes. Please try again later."))
