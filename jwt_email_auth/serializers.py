from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.utils.functional import cached_property
from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.request import Request
from rest_framework.settings import api_settings

from .fields import TokenField
from .settings import auth_settings
from .tokens import AccessToken

if TYPE_CHECKING:
    from django.db import models

    from .typing import Any, ClassVar

__all__ = [
    "AccessSerializerMixin",
    "BaseAccessSerializer",
    "BaseLoginSerializer",
    "BaseSendLoginCodeSerializer",
    "CookieSerializerMixin",
    "HeaderSerializerMixin",
    "LoginSerializer",
    "LogoutSerializer",
    "RefreshTokenSerializer",
    "RequestFromContextMixin",
    "SendLoginCodeSerializer",
    "TokenClaimOutputSerializer",
    "TokenClaimSerializer",
    "TokenOutputSerializer",
    "TokenUpdateSerializer",
]


logger = logging.getLogger(__name__)


# Utility


class RequestFromContextMixin:
    @cached_property
    def request_from_context(self) -> Request:
        request: Request | None = self.context.get("request")
        if request is None or not isinstance(request, Request):
            raise ValidationError(
                {
                    api_settings.NON_FIELD_ERRORS_KEY: ErrorDetail(
                        string="Must include a Request object in the context of the Serializer.",
                        code="request_missing",
                    )
                }
            )
        return request


class HeaderSerializerMixin(RequestFromContextMixin):
    take_from_headers: ClassVar[list[str]] = []
    """Headers to take values from.
    Header names will be converted to snake_case.
    """

    @cached_property
    def header_values(self) -> dict[str, Any]:
        request = self.request_from_context
        return {key.replace("-", "_").lower(): request.headers.get(key, None) for key in self.take_from_headers}

    def add_headers(self, data: dict[str, Any]) -> dict[str, Any]:
        # Remove any values added to original header names.
        for key in self.take_from_headers:
            data.pop(key, None)
        data.update(self.header_values)
        return data

    def to_internal_value(self, data: dict[str, Any]) -> dict[str, Any]:
        ret = super().to_internal_value(data)
        return self.add_headers(ret)

    def to_representation(self, instance: models.Model) -> dict[str, Any]:
        ret = super().to_representation(instance)
        return self.add_headers(ret)


class CookieSerializerMixin(RequestFromContextMixin):
    take_from_cookies: ClassVar[list[str]] = []
    """Cookies to take values from.
    Cookie names will be converted to snake_case.
    """

    @cached_property
    def cookie_values(self) -> dict[str, Any]:
        request = self.request_from_context
        return {key.replace("-", "_").lower(): request.COOKIES.get(key, None) for key in self.take_from_cookies}

    def add_cookies(self, data: dict[str, Any]) -> dict[str, Any]:
        # Remove any values added to original cookie names.
        for key in self.take_from_cookies:
            data.pop(key, None)
        data.update(self.cookie_values)
        return data

    def to_internal_value(self, data: dict[str, Any]) -> dict[str, Any]:
        ret = super().to_internal_value(data)
        return self.add_cookies(ret)

    def to_representation(self, instance: models.Model) -> dict[str, Any]:
        ret = super().to_representation(instance)
        return self.add_cookies(ret)


class AccessSerializerMixin(RequestFromContextMixin):
    """
    Serializer that adds the specified claims from request JWT to the serializer data.
    Serializer must have the incoming request object in its context dictionary.
    """

    take_from_token: ClassVar[list[str]] = []
    """List of keys to take from the token claims and pass to the serializer.
    Claims can be anything specified in auth_settings.EXPECTED_CLAIMS.
    A ValidationError will be raised if token doesn't have all of these claims.
    """

    @cached_property
    def token_claims(self) -> dict[str, Any]:
        request = self.request_from_context

        data = {}
        token = AccessToken.from_request(request)
        missing: list[str] = []
        for key in self.take_from_token:
            try:
                data[key] = token[key]
            except KeyError:  # noqa: PERF203
                missing.append(key)
        if missing:
            raise ValidationError(
                {claim: ErrorDetail(string="Missing token claim.", code="missing_claim") for claim in missing}
            )
        return data

    def add_token_claims(self, data: dict[str, Any]) -> dict[str, Any]:
        data.update(self.token_claims)
        return data

    def to_internal_value(self, data: dict[str, Any]) -> dict[str, Any]:
        ret = super().to_internal_value(data)
        return self.add_token_claims(ret)

    def to_representation(self, instance: models.Model) -> dict[str, Any]:
        ret = super().to_representation(instance)
        return self.add_token_claims(ret)


class BaseAccessSerializer(CookieSerializerMixin, HeaderSerializerMixin, AccessSerializerMixin, serializers.Serializer):
    """
    Serializer that adds the specified token claims, headers, and cookies from request
    JWT to the serializer data. Serializer must have the incoming request object in its context dictionary.
    """

    @cached_property
    def fields(self) -> dict[str, serializers.Field]:
        fields = super().fields
        for header_name in self.take_from_headers:
            fields[header_name] = serializers.CharField(default=None, allow_null=True, allow_blank=True)
        for cookie_name in self.take_from_cookies:
            fields[cookie_name] = serializers.CharField(default=None, allow_null=True, allow_blank=True)
        return fields


# Input


class BaseSendLoginCodeSerializer(serializers.Serializer):
    pass


class SendLoginCodeSerializer(BaseSendLoginCodeSerializer):
    email = serializers.EmailField(help_text="Email address to send the code to.")


class BaseLoginSerializer(serializers.Serializer):
    code = serializers.CharField(help_text="Login code.")


class LoginSerializer(BaseLoginSerializer):
    email = serializers.EmailField(help_text="Email address the code was sent to.")


class RefreshTokenSerializer(serializers.Serializer):
    token = TokenField(help_text="Refresh token.", required=not auth_settings.USE_COOKIES)
    user_check = serializers.BooleanField(default=False, help_text="Check that user for token still exists.")


class LogoutSerializer(serializers.Serializer):
    token = TokenField(help_text="Refresh token.", required=not auth_settings.USE_COOKIES)


class TokenUpdateSerializer(serializers.Serializer):
    data = serializers.DictField(help_text="Claims to update.")
    token = TokenField(help_text="Refresh token.", required=not auth_settings.USE_COOKIES)


class TokenClaimSerializer(serializers.Serializer):
    pass


# Output (for schema)


class TokenOutputSerializer(serializers.Serializer):
    """New refresh and access token pair."""

    access = TokenField(help_text="Access token.")
    refresh = TokenField(help_text="Refresh token.")


class TokenClaimOutputSerializer(serializers.Serializer):
    """Token claims."""
