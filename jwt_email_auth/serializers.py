import logging
from typing import Any, Dict, List, Optional

from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.request import Request
from rest_framework.settings import api_settings

from .tokens import AccessToken


__all__ = [
    "BaseAccessSerializer",
    "RefreshTokenSerializer",
    "LoginSerializer",
    "SendLoginCodeSerializer",
]


logger = logging.getLogger(__name__)


class SendLoginCodeSerializer(serializers.Serializer):  # pylint: disable=W0223
    email = serializers.EmailField(help_text="Email address to send the code to.")


class LoginSerializer(serializers.Serializer):  # pylint: disable=W0223
    code = serializers.CharField(help_text="Login code.")
    email = serializers.EmailField(help_text="Email address the code was sent to.")


class RefreshTokenSerializer(serializers.Serializer):  # pylint: disable=W0223
    token = serializers.CharField(help_text="Refresh token.")


class BaseAccessSerializer(serializers.Serializer):  # pylint: disable=W0223
    """Serializer that takes specified claims from request JWT and adds them to the serializer data.
    Serializer must have the incoming request object in its context dictionary.
    """

    take_form_token: List[str] = []
    """List of keys to take from token claims and pass to bound method.
    Claims can be anything specified in JWT_EMAIL_AUTH["EXPECTED_CLAIMS"] django setting.
    A ValidationError will be raised if token doesn't have all of these claims.
    """

    @cached_property
    def token_claims(self) -> Dict[str, Any]:
        request: Optional[Request] = self.context.get("request")
        if request is None or not isinstance(request, Request):
            raise ValidationError(
                {
                    api_settings.NON_FIELD_ERRORS_KEY: ErrorDetail(
                        string=_("Must include a Request object in the context of the Serializer."),
                        code="request_missing",
                    )
                }
            )

        data = {}
        token = AccessToken.from_request(request)
        missing: List[str] = []
        for key in self.take_form_token:
            try:
                data[key] = token[key]
            except KeyError:
                missing.append(key)
        if missing:
            raise ValidationError(
                {claim: ErrorDetail(string=_("Missing token claim."), code="missing_claim") for claim in missing}
            )
        return data

    def add_token_claims(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data.update(self.token_claims)
        return data

    def to_internal_value(self, data: Dict[str, Any]) -> Dict[str, Any]:
        ret = super().to_internal_value(data)
        return self.add_token_claims(ret)

    def to_representation(self, instance) -> Dict[str, Any]:
        ret = super().to_representation(instance)
        return self.add_token_claims(ret)
