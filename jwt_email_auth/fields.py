from rest_framework.fields import HiddenField, empty

from .tokens import AccessToken, RefreshToken
from .settings import auth_settings


__all__ = [
    "AutoTokenField",
]


class AutoTokenField(HiddenField):
    """Field where the JWT gets added from authorization header,
    but is not shown to the user in schema."""

    def __init__(self, **kwargs):
        key = kwargs.pop("return_key", None)
        self.refresh_token = kwargs.pop("refresh_token", False)

        kwargs["default"] = empty
        super().__init__(**kwargs)

        self.return_key = key or self.field_name
        self.write_only = kwargs.get("write_only", self.write_only)

    def get_value(self, dictionary):
        """Fetch token from data."""
        return dictionary.get(self.field_name, empty)

    def to_internal_value(self, data):
        """Try to construct an Access token, or Refresh token if specified.

        :raises AuthenticationFailed: JWT token expired or malformed.
        """
        if self.refresh_token:
            return RefreshToken(token=data, expected_claims=auth_settings.EXPECTED_CLAIMS)
        return AccessToken(token=data, expected_claims=auth_settings.EXPECTED_CLAIMS)

    def to_representation(self, value):
        """Construct the JWT for outgoing data."""

        # Change the key under which the token is returned under
        self.field_name = self.return_key

        # Special case when refresh token is given,
        # should return new access token instead
        if self.refresh_token:
            return str(value.new_access_token())
        return str(value)
