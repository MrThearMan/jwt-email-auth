import logging

from django.utils.functional import cached_property
from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.request import Request
from rest_framework.settings import api_settings

from .fields import TokenField
from .settings import auth_settings
from .tokens import AccessToken
from .typing import Any, Dict, List, Optional


__all__ = [
    "BaseAccessSerializer",
    "BaseHeaderSerializer",
    "BaseLoginSerializer",
    "BaseSendLoginCodeSerializer",
    "LoginSerializer",
    "LogoutSerializer",
    "RefreshTokenSerializer",
    "SendLoginCodeSerializer",
    "TokenClaimOutputSerializer",
    "TokenClaimSerializer",
    "TokenOutputSerializer",
    "TokenUpdateSerializer",
]


logger = logging.getLogger(__name__)


# Utility


class BaseHeaderSerializer(serializers.Serializer):
    """Serializer that adds the specified headers from request to the serializer data.
    Serializer must have the incoming request object in its context dictionary.
    """

    take_from_headers: List[str] = []
    """Headers to take values from.
    Header names should be in Capitalized-Kebab-Case, but
    keys in the serializer data will be in snake_case.
    """

    @cached_property
    def request_from_context(self) -> Request:
        request: Optional[Request] = self.context.get("request")
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

    @cached_property
    def header_values(self) -> Dict[str, Any]:
        request = self.request_from_context
        return {key.replace("-", "_").lower(): request.headers.get(key, None) for key in self.take_from_headers}

    def add_headers(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data.update(self.header_values)
        return data

    def to_internal_value(self, data: Dict[str, Any]) -> Dict[str, Any]:
        ret = super().to_internal_value(data)
        ret = self.add_headers(ret)
        return ret

    def to_representation(self, instance) -> Dict[str, Any]:
        ret = super().to_representation(instance)
        ret = self.add_headers(ret)
        return ret


class BaseAccessSerializer(BaseHeaderSerializer):
    """Serializer that adds the specified claims from request JWT to the serializer data.
    Serializer must have the incoming request object in its context dictionary.
    """

    take_from_token: List[str] = []
    """List of keys to take from token claims and pass to bound method.
    Claims can be anything specified in JWT_EMAIL_AUTH["EXPECTED_CLAIMS"] django setting.
    A ValidationError will be raised if token doesn't have all of these claims.
    """

    @cached_property
    def token_claims(self) -> Dict[str, Any]:
        request = self.request_from_context

        data = {}
        token = AccessToken.from_request(request)
        missing: List[str] = []
        for key in self.take_from_token:
            try:
                data[key] = token[key]
            except KeyError:
                missing.append(key)
        if missing:
            raise ValidationError(
                {claim: ErrorDetail(string="Missing token claim.", code="missing_claim") for claim in missing}
            )
        return data

    def add_token_claims(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data.update(self.token_claims)
        return data

    def to_internal_value(self, data: Dict[str, Any]) -> Dict[str, Any]:
        ret = super().to_internal_value(data)
        ret = self.add_token_claims(ret)
        return ret

    def to_representation(self, instance) -> Dict[str, Any]:
        ret = super().to_representation(instance)
        ret = self.add_token_claims(ret)
        return ret


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
