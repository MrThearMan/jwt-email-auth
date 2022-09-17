from django.utils.functional import cached_property
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ValidationError
from rest_framework.fields import CharField, HiddenField, empty
from rest_framework.request import Request

from .tokens import AccessToken
from .typing import Any, Optional
from .utils import valid_jwt_format


__all__ = [
    "AutoTokenField",
    "TokenField",
]


class TokenField(CharField):
    """Validates incoming tokens are in the correct format."""

    default_validators = [valid_jwt_format]


class AutoTokenField(HiddenField):
    """A field that automatically populates from the parent serializers context.
    The context dictionary's must include a Request object, and that Request object
    must have the authorization token, either in its cookies or the 'Authorization' header
    depending on settings, from which the JWT is created. If any of these are missing,
    or the created JWT is not valid, an error will be raised.

    Parent serializers 'validated_data' attribute will contain an 'AccessToken' object.
    Parent serializers 'data' attribute will contain the encoded token as a string.

    AutoTokenField is not shown in the generated schema (due to sublassing HiddenField),
    since the purpose for this field is to accept the token from the request and not
    from user input.
    """

    def __init__(self, **kwargs):
        kwargs["default"] = empty
        super().__init__(**kwargs)

        # Both must always be False so that token appears
        # in both 'validated_data' and 'data' attributes
        self.write_only = False
        self.read_only = False

    @cached_property
    def _default(self) -> AccessToken:  # type: ignore
        request: Optional[Request] = self.parent.context.get("request")
        if request is None or not isinstance(request, Request):
            raise ValidationError("Must include a Request object in the context of the Serializer.")

        try:
            return AccessToken.from_request(request)
        except (AuthenticationFailed, NotAuthenticated) as error:
            raise ValidationError(error.detail) from error

    def get_default(self) -> AccessToken:  # type: ignore
        return self._default

    def run_validation(self, data: Any = ...) -> AccessToken:
        return self.get_default()

    def get_attribute(self, instance) -> AccessToken:
        return self.get_default()

    def to_representation(self, value: AccessToken) -> str:
        return str(value)
