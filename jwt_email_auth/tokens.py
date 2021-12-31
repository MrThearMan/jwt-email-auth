import logging
from datetime import datetime
from typing import Any, Dict, Optional, Union

import jwt
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.request import Request

from .settings import auth_settings


__all__ = [
    "AccessToken",
    "RefreshToken",
]


Token = Union["AccessToken", "RefreshToken"]

logger = logging.getLogger(__name__)


class AccessToken:

    token_type = "access"
    lifetime = auth_settings.ACCESS_TOKEN_LIFETIME

    def __init__(self, token: Optional[str] = None, check_claims: bool = True, type_check: bool = True):
        """Create a new token or construct one from encoded string.

        :param token: Encoded token without prefix.
        :param check_claims: Verify that claims set in the EXPECTED_CLAIMS are found.
        :param type_check: Check if token is of correct token type.
        :raises AuthenticationFailed: Token was invalid.
        """

        if token is not None:
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
            except jwt.ExpiredSignatureError as error:
                logger.info(error)
                raise AuthenticationFailed(_("Signature has expired.")) from error
            except jwt.DecodeError as error:
                logger.info(error)
                raise AuthenticationFailed(_("Error decoding signature.")) from error
            except jwt.InvalidTokenError as error:
                logger.info(error)
                raise AuthenticationFailed(_("Invalid token.")) from error

            if check_claims:
                self.verify_payload()
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
    def from_request(cls, request: Request, check_claims: bool = True) -> "AccessToken":
        """Construct a token from request Authorization header.

        :param request: Request with Authorization header.
        :param check_claims: Verify that claims set in the EXPECTED_CLAIMS are found.
        :raises NotAuthenticated: No token in Authorization header.
        :raises AuthenticationFailed: Request header or token was invalid.
        """

        auth_header = get_authorization_header(request)
        if not auth_header:
            raise NotAuthenticated(_("No Authorization header found from request."))

        try:
            prefix, encoded_token = auth_header.decode().split()
        except ValueError as error:
            raise AuthenticationFailed(_("Invalid Authorization header.")) from error

        if force_str(prefix).lower() != auth_settings.HEADER_PREFIX.lower():
            raise AuthenticationFailed(_("Invalid prefix."))

        return cls(token=encoded_token, check_claims=check_claims)

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
        """Fetch the value of a claim from this token."""
        return self.payload.get(key, default)

    def update(self, data: Dict[str, Any] = None, **kwargs: Any) -> None:
        """Update payload. Note that this will change the encoded token so be sure to save it!"""
        self.payload.update({} if data is None else data, **kwargs)

    def verify_payload(self) -> None:
        for claim in auth_settings.EXPECTED_CLAIMS:
            if claim not in self:
                logger.info(f"Missing claim: {claim}")
                raise AuthenticationFailed(_("Missing claims."))

    def verify_token_type(self) -> None:
        if self.token_type != self.payload.get("type", "notype"):
            logger.info(f"Invalid token type: {self.token_type}")
            raise AuthenticationFailed(_("Invalid token type."))

    def sync_with(self, token: Token) -> None:
        """Sync this token with the other token, as if they were created at the same time.
        Changes this token's "exp" and "iat" claims and thus the encoded token so be sure to save it!
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

    def new_access_token(self, sync: bool = False) -> "AccessToken":
        """Create a new access token from this refresh token.

        :param sync: Sync access the two tokens, as if they were created at the same time.
                     This changes the created access tokens "exp" and "iat" claims.
        """
        access = AccessToken()
        if sync:
            access.sync_with(self)

        for claim, value in self.payload.items():
            if claim in ("aud", "iss", "exp", "iat", "type"):
                continue
            access[claim] = value

        return access
