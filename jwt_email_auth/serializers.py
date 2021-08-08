from django.utils.functional import cached_property
from rest_framework.serializers import Serializer
from rest_framework.fields import empty

from .tokens import AccessToken
from .settings import auth_settings


__all__ = ["BaseAccessSerializer"]


class BaseAccessSerializer(Serializer):
    """Base serializer that adds hidden token field, and takes specified claims from it."""

    take_form_token: list[str] = []
    """List of keys to take from token claims and pass to bound method."""

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        self.initial_data.update(self._token_claims)

    @cached_property
    def _token_claims(self) -> dict:
        token = AccessToken.from_request(
            request=self.context.get("request"),
            expected_claims=auth_settings.EXPECTED_CLAIMS,
        )
        return {key: token[key] for key in self.take_form_token}

    def to_internal_value(self, data):
        ret = super().to_internal_value(data)
        return ret.update(self._token_claims)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        return ret.update(self._token_claims)
