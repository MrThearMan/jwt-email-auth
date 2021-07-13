from rest_framework.serializers import Serializer

from .tokens import AccessToken
from .settings import auth_settings


__all__ = ["BaseAccessSerializer"]


class BaseAccessSerializer(Serializer):
    """Base serializer that adds hidden token field, and takes specified claims from it."""

    take_form_token: list[str] = []
    """List of keys to take from token claims and pass to bound method."""

    def to_internal_value(self, data):
        """Add specified claims from token to data during validation."""
        ret = super().to_internal_value(data)
        token = AccessToken.from_request(
            request=self.context.get("request"),
            expected_claims=auth_settings.EXPECTED_CLAIMS,
        )
        for key in self.take_form_token:
            ret[key] = token[key]
        return ret
