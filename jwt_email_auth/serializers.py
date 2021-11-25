from rest_framework import serializers
from rest_framework.fields import empty

from .settings import auth_settings
from .tokens import AccessToken


__all__ = [
    "BaseAccessSerializer",
    "RefreshTokenSerializer",
    "LoginSerializer",
    "SendLoginCodeSerializer",
]


class SendLoginCodeSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Email address to send the code to.")

    def validate(self, attrs):
        return auth_settings.VALIDATION_CALLBACK(email=attrs["email"])


class LoginSerializer(serializers.Serializer):
    code = serializers.CharField(help_text="Login code.")
    email = serializers.EmailField(help_text="Email address the code was sent to.")


class RefreshTokenSerializer(serializers.Serializer):
    token = serializers.CharField(help_text="Refresh token.")


class BaseAccessSerializer(serializers.Serializer):
    """Base serializer that adds hidden token field, and takes specified claims from it."""

    take_form_token: list[str] = []  # from authentication.settings.EXPECTED_CLAIMS
    """List of keys to take from token claims and pass to bound method."""

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        self.initial_data = self.add_token_claims(getattr(self, "initial_data", {}))

    def add_token_claims(self, data: dict) -> dict:
        token = AccessToken.from_request(
            request=self.context.get("request"),
            expected_claims=auth_settings.EXPECTED_CLAIMS,
        )
        data.update({key: token[key] for key in self.take_form_token})
        return data

    def to_internal_value(self, data: dict) -> dict:
        ret = super().to_internal_value(data)
        return self.add_token_claims(ret)

    def to_representation(self, instance) -> dict:
        ret = super().to_representation(instance)
        return self.add_token_claims(ret)
