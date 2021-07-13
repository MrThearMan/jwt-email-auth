from rest_framework.fields import CharField

from .tokens import AccessToken, RefreshToken
from .settings import auth_settings


__all__ = [
    "AutoTokenField",
]


class AutoTokenField(CharField):
    """Field where the JWT can be added from authorization header"""

    def __init__(self, **kwargs):
        key = kwargs.pop("return_key", None)
        self.refresh_token = kwargs.pop("refresh_token", False)
        super().__init__(**kwargs)
        self.return_key = key or self.field_name

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
