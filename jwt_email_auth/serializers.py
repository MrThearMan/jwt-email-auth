""""""

import logging
from random import randint
from hashlib import md5

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework.exceptions import NotFound, AuthenticationFailed

from .utils import send_login_email
from .exceptions import LoginCodeStillValid, EmailServerException, CorruptedDataException
from .tokens import RefreshToken
from .settings import auth_settings


__all__ = [
    "LoginCodeSerializer",
    "ObtainTokenSerializer",
    "RefreshTokenSerializer",
]


logger = logging.getLogger(__name__)


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


class LoginCodeSerializer(serializers.Serializer):

    email = serializers.EmailField(help_text="Email address to send the code to.")

    def validate(self, attrs):

        cache_key = f"{auth_settings.CACHE_PREFIX}-{md5(attrs['email'].encode()).hexdigest()}"

        if cache.get(cache_key, None) is not None:
            raise LoginCodeStillValid()

        data = auth_settings.LOGIN_DATA()
        data["code"] = random_code()
        cache.set(cache_key, data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        try:
            send_login_email(self._context.get("request"), code=data["code"], email=attrs["email"])
        except Exception:
            cache.delete(cache_key)
            raise EmailServerException(_("Failed to send login codes. Try again later."))

        return {}


class ObtainTokenSerializer(serializers.Serializer):

    code = serializers.CharField(help_text="Six digit code.")
    email = serializers.EmailField(help_text="Email address the code was sent to.")

    def validate(self, attrs):

        cache_key = f"{auth_settings.CACHE_PREFIX}-{md5(attrs['email'].encode()).hexdigest()}"

        if login_info := cache.get(cache_key, None):
            raise NotFound(_(f"No login code found code for '{attrs['email']}'."))

        if not auth_settings.SKIP_CODE_CHECKS:
            if login_info.get("code", None) != attrs["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        refresh = RefreshToken()
        try:
            refresh.update({key: login_info[key] for key in auth_settings.EXPECTED_CLAIMS})
        except KeyError:
            logger.debug("Some data was missing from saved login info. If you set EXPECTED_CLAIMS, you "
                         "should provide a custom LOGIN_DATA function that returns them in a dict.")
            cache.delete(cache_key)
            raise CorruptedDataException(_("Data was corrupted. Try to send another login code."))

        cache.delete(cache_key)

        refresh = RefreshToken()
        access = refresh.new_access_token()
        access.sync_with(refresh)

        return {"access": str(access), "refresh": str(refresh)}


class RefreshTokenSerializer(serializers.Serializer):

    token = serializers.CharField(help_text="Refresh token.")

    def validate(self, attrs):
        refresh = RefreshToken(attrs["token"], expected_claims=auth_settings.EXPECTED_CLAIMS)
        access = refresh.new_access_token()
        return {"access": str(access)}
