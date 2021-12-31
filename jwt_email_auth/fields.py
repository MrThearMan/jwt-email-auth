from functools import lru_cache
from typing import Any, Optional

from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ValidationError
from rest_framework.fields import HiddenField, empty
from rest_framework.request import Request

from .tokens import AccessToken


__all__ = [
    "AutoTokenField",
]


class AutoTokenField(HiddenField):
    """A field that automatically populates from the parent serializers context.
    The context dictionary's must include a Request object, and that Request object
    must have an 'Authorization' header, from which the JWT is created.
    If any of these are missing, or the created JWT is not valid, an error will be raised.

    Parent serializers 'validated_data' attribute will contain an 'AccessToken' object.
    Parent serializers 'data' attribute will contain the encoded token as a string.

    AutoTokenField is not shown in the generated schema (due to sublassing HiddenField),
    since the purpose for this field is to accept the token from the Authorization header
    and not from user input.
    """

    def __init__(self, **kwargs):
        kwargs["default"] = empty
        super().__init__(**kwargs)

        # Both must always be False so that token appears
        # in both 'validated_data' and 'data' attributes
        self.write_only = False
        self.read_only = False

    @lru_cache(maxsize=None)
    def get_default(self) -> AccessToken:  # type: ignore
        request: Optional[Request] = self.parent.context.get("request")
        if request is None or not isinstance(request, Request):
            raise ValidationError("Must include a Request object in the context of the Serializer.")

        try:
            return AccessToken.from_request(request)
        except (AuthenticationFailed, NotAuthenticated) as error:
            raise ValidationError(error.detail) from error

    def run_validation(self, data: Any = ...) -> AccessToken:
        return self.get_default()

    def get_attribute(self, instance) -> AccessToken:
        return self.get_default()

    def to_representation(self, value: AccessToken) -> str:
        return str(value)
