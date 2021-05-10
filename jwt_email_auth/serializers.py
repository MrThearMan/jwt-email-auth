from random import randint
from hashlib import md5

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework.exceptions import NotFound

from .utils import send_login_email
from .exceptions import LoginCodeStillValid
from .tokens import RefreshToken
from .settings import auth_settings


__all__ = [
    "LoginCodeSerializer",
    "ObtainTokenSerializer",
    "RefreshTokenSerializer",
]


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


class LoginCodeSerializer(serializers.Serializer):

    email = serializers.EmailField()

    def validate(self, attrs):

        cache_key = f"{auth_settings.CACHE_PREFIX}-{md5(attrs['email'].encode()).hexdigest()}"
        if cache.get(cache_key, None) is not None:
            raise LoginCodeStillValid()

        code = random_code()
        cache.set(cache_key, code, auth_settings.LOGIN_CODE_LIFETIME)

        language = self._context.get("request").LANGUAGE_CODE
        send_login_email(language, code=code, email=attrs["email"])

        return {}


class ObtainTokenSerializer(serializers.Serializer):

    code = serializers.CharField()
    email = serializers.EmailField()

    def validate(self, attrs):

        cache_key = f"{auth_settings.CACHE_PREFIX}-{md5(attrs['email'].encode()).hexdigest()}"

        if cache.get(cache_key, None) != attrs["code"]:
            raise NotFound(_("Invalid login information."))

        cache.delete(cache_key)

        refresh = RefreshToken()
        access = refresh.new_access_token()
        access.sync_with(refresh)

        return {"access": str(access), "refresh": str(refresh)}


class RefreshTokenSerializer(serializers.Serializer):

    token = serializers.CharField()

    def validate(self, attrs):
        refresh = RefreshToken(attrs["token"])
        access = refresh.new_access_token()
        return {"access": str(access)}
