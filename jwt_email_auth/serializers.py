from rest_framework.serializers import Serializer

from .fields import AutoTokenField


__all__ = ["BaseAccessSerializer"]


class BaseAccessSerializer(Serializer):
    """Base serializer that adds hidden token field, and takes specified claims from it."""

    token = AutoTokenField()
    take_form_token: list[str] = []
    """List of keys to take from token claims and pass to bound method."""

    def to_internal_value(self, data):
        """Pop token and add specified claims from it to data before validation."""
        ret = super().to_internal_value(data)
        token = ret.pop("token")
        for key in self.take_form_token:
            ret[key] = token[key]
        return ret
