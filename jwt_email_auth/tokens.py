import jwt
from typing import List, Union, Dict, Any
from datetime import datetime

from django.utils.encoding import smart_text
from django.utils.translation import gettext_lazy as _

from rest_framework.authentication import get_authorization_header
from rest_framework.request import Request
from rest_framework.exceptions import AuthenticationFailed

from .settings import auth_settings


__all__ = [
    "AccessToken",
    "RefreshToken",
]


TokenType = Union["AccessToken", "RefreshToken"]


class AccessToken:

    token_type = "access"
    lifetime = auth_settings.ACCESS_TOKEN_LIFETIME

    def __init__(self, token: str = None, expected_claims: List[str] = None, type_check: bool = True):
        """Create a new token or construct one from encoded string.

        :param token: Encoded token without prefix.
        :param expected_claims: Verify that these custom claims are present.
        :param type_check: Check if token is of correct token type.
        :raises AuthenticationFailed: Token was invalid
        """
        if token:
            try:
                self.payload = jwt.decode(
                    jwt=token,
                    key=auth_settings.SIGNING_KEY,
                    options={
                        "require_exp": True,
                        "verify_exp": True,
                        "verify_aud": auth_settings.AUDIENCE is not None,
                        "verify_iss": auth_settings.ISSUER is not None,
                    },
                    leeway=auth_settings.LEEWAY,
                    audience=auth_settings.AUDIENCE,
                    issuer=auth_settings.ISSUER,
                    algorithms=[auth_settings.ALGORITHM],
                )
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed(_("Signature has expired."))
            except jwt.DecodeError:
                raise AuthenticationFailed(_("Error decoding signature."))
            except jwt.InvalidTokenError:
                raise AuthenticationFailed(_("Invalid token."))

            if expected_claims is not None:
                self.verify_payload(expected_claims)
            if type_check:
                self.verify_token_type()

        else:  # new token
            self.payload = {"type": self.token_type}
            self.renew()

            if auth_settings.AUDIENCE is not None:
                self.payload["aud"] = auth_settings.AUDIENCE
            if auth_settings.ISSUER is not None:
                self.payload["iss"] = auth_settings.ISSUER

    @classmethod
    def from_request(cls, request: Request, expected_claims: List[str] = None):
        """Construct a token from request Authorization header.

        :param request: Request with Authorization header.
        :param expected_claims: Verify that these custom claims are present.
        :raises AuthenticationFailed: Request header or token was invalid.
        """
        try:
            prefix, encoded_token = get_authorization_header(request).split()
        except ValueError:
            raise AuthenticationFailed(_("Invalid Authorization header."))

        if smart_text(prefix).lower() != auth_settings.HEADER_PREFIX.lower():
            raise AuthenticationFailed(_("Invalid prefix."))

        return cls(token=encoded_token, expected_claims=expected_claims)

    def __repr__(self) -> str:
        return repr(self.payload)

    def __str__(self) -> str:
        return jwt.encode(
            payload=self.payload,
            key=auth_settings.SIGNING_KEY,
            algorithm=auth_settings.ALGORITHM,
            headers=auth_settings.EXTRA_HEADERS,
        )

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def __setitem__(self, key: str, value: Union[int, float, str, bool, bytes]) -> None:
        self.payload[key] = value

    def __delitem__(self, key: str) -> None:
        del self.payload[key]

    def __contains__(self, key: str) -> bool:
        return key in self.payload

    def get(self, key: str, default: str = None) -> Any:
        return self.payload.get(key, default)

    def verify_payload(self, expected_claims: List[str]) -> None:
        for claim in expected_claims:
            if claim not in self:
                raise AuthenticationFailed(_("Missing claims."))

    def verify_token_type(self) -> None:
        if self.token_type != self.payload.get("type", "notype"):
            raise AuthenticationFailed(_("Invalid token type."))

    def sync_with(self, token: TokenType) -> None:
        """Sync this token's expiry and issuing times to the other token's.
        NOTE: THIS WILL CHANGE THE ENCODED TOKEN, SO BE SURE TO SAVE IT!
        """
        self.payload["exp"] = token["iat"] + self.lifetime
        self.payload["iat"] = token["iat"]

    def renew(self) -> None:
        """Renew token expiration.
        NOTE: THIS WILL CHANGE THE ENCODED TOKEN, SO BE SURE TO SAVE IT!
        """
        self.payload["exp"] = datetime.utcnow() + self.lifetime
        self.payload["iat"] = datetime.utcnow()


class RefreshToken(AccessToken):

    token_type = "refresh"
    lifetime = auth_settings.REFRESH_TOKEN_LIFETIME

    def new_access_token(self) -> "AccessToken":
        access = AccessToken()

        for claim, value in self.payload.items():
            if claim in ("aud", "iss", "exp", "iat", "type"):
                continue
            access[claim] = value

        return access

    def update(self, data: Dict[str, str] = None, **kwargs: str) -> None:
        """Update payload.
        NOTE: THIS WILL CHANGE THE ENCODED TOKEN, SO BE SURE TO SAVE IT!
        """
        self.payload.update({} if data is None else data, **kwargs)
