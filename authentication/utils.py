"""Python utility functions, that have nothing to do with the Dynamics database."""

import logging
from hashlib import md5
from ipware import get_client_ip

from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _

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


def send_login_email(request: Request, code: str, email: str, link: str):
    context = {
        "code": code,
        "valid": auth_settings.LOGIN_CODE_LIFETIME,
        "link": link,
    }

    html_message = render_to_string(
        "authentication/login_email.html",
        context=context,
        request=request,
    )

    plain_message = "\n\n".join(
        [stripped for value in strip_tags(html_message).split("\n") if (stripped := value.strip()) != ""]
    )

    if settings.DEBUG:
        print("\n")
        print(plain_message)
        print("\n")

    # TODO: Change to dynamics api call "change action email"
    # when email has been configured from Dynamics end

    if auth_settings.SEND_BY_EMAIL:
        try:
            send_mail(
                subject=_("Login to Joki"),
                message=plain_message,
                html_message=html_message,
                from_email=None,  # Use default from email
                recipient_list=[email],
            )
        except Exception as e:  # noqa
            logger.warning(f"Failed to send login code: {e}")
            raise EmailServerException(_("Unable to send login codes. Please try again later."))
