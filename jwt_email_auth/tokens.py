# pylint: disable=import-outside-toplevel
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import jwt
from django.db import transaction
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.request import Request

from .settings import auth_settings


if TYPE_CHECKING:
    from .rotation.models import RefreshTokenRotationLog


__all__ = [
    "AccessToken",
    "RefreshToken",
]


Token = Union["AccessToken", "RefreshToken"]

logger = logging.getLogger(__name__)


class AccessToken:

    token_type = "access"
    lifetime = auth_settings.ACCESS_TOKEN_LIFETIME

    def __init__(self, token: Optional[str] = None) -> None:
        """Create a new token or construct one from encoded string.

        :param token: Encoded token without prefix.
        :raises AuthenticationFailed: Token was invalid.
        """
        rotate = auth_settings.ROTATE_REFRESH_TOKENS and self.token_type == "refresh"

        if token is not None:
            try:
                self.payload = jwt.decode(
                    jwt=token,
                    key=auth_settings.SIGNING_KEY,
                    options={
                        "require": ["jti", "sub"] if rotate else [],
                        "verify_exp": True,
                        "verify_iat": True,
                        "verify_nbf": auth_settings.NOT_BEFORE_TIME is not None,
                        "verify_aud": auth_settings.AUDIENCE is not None,
                        "verify_iss": auth_settings.ISSUER is not None,
                    },
                    leeway=auth_settings.LEEWAY,
                    audience=auth_settings.AUDIENCE,
                    issuer=auth_settings.ISSUER,
                    algorithms=[auth_settings.ALGORITHM],
                )

            except jwt.MissingRequiredClaimError as error:
                logger.info(error)
                raise AuthenticationFailed(str(error), code="missing_rotation_claim") from error

            except jwt.ExpiredSignatureError as error:
                logger.info(error)
                if rotate:
                    from .rotation.models import RefreshTokenRotationLog

                    RefreshTokenRotationLog.objects.remove_by_jti(token)

                raise AuthenticationFailed(_("Signature has expired."), code="signature_expired") from error

            except jwt.DecodeError as error:
                logger.info(error)
                raise AuthenticationFailed(_("Error decoding signature."), code="decoding_error") from error

            except jwt.InvalidTokenError as error:
                logger.info(error)
                raise AuthenticationFailed(_("Invalid token."), code="invalid_token") from error

            except Exception as error:  # pragma: no cover
                logger.info(error)
                raise AuthenticationFailed(_("Unexpected error."), code="unexpected_error") from error

            self.verify_token_type()
            self.verify_payload()

        else:  # new token
            now = datetime.now(tz=timezone.utc)
            self.payload = {"type": self.token_type, "exp": now + self.lifetime, "iat": now}

            if auth_settings.NOT_BEFORE_TIME is not None:
                self.payload["nbf"] = now + auth_settings.NOT_BEFORE_TIME
            if auth_settings.AUDIENCE is not None:
                self.payload["aud"] = auth_settings.AUDIENCE
            if auth_settings.ISSUER is not None:
                self.payload["iss"] = auth_settings.ISSUER

    @classmethod
    def from_request(cls, request: Request) -> "AccessToken":
        """Construct a token from request Authorization header.

        :param request: Request with Authorization header.
        :raises NotAuthenticated: No token in Authorization header.
        :raises AuthenticationFailed: Request header or token was invalid.
        """

        auth_header = get_authorization_header(request)
        if not auth_header:
            raise NotAuthenticated(_("No Authorization header found from request."))

        try:
            prefix, encoded_token = auth_header.decode().split()
        except ValueError as error:
            raise AuthenticationFailed(_("Invalid Authorization header."), code="invalid_header") from error

        if force_str(prefix).lower() != auth_settings.HEADER_PREFIX.lower():
            raise AuthenticationFailed(_("Invalid prefix."), code="invalid_header_prefix")

        return cls(token=encoded_token)

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

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Fetch the value of a claim from this token."""
        return self.payload.get(key, default)

    def update(self, data: Dict[str, Any] = None, **kwargs: Any) -> None:
        """Update payload."""
        self.payload.update({} if data is None else data, **kwargs)

    def verify_payload(self) -> None:
        missing_claims: List[str] = []
        for claim in auth_settings.EXPECTED_CLAIMS:
            if claim not in self:
                missing_claims.append(claim)

        if missing_claims:
            raise AuthenticationFailed(f"Missing token claims: {missing_claims}.", code="missing_claims")

    def verify_token_type(self) -> None:
        if self.token_type != self.payload.get("type", "notype"):
            logger.info(f"Invalid token type: {self.token_type}")
            raise AuthenticationFailed(_("Invalid token type."), code="invalid_type")

    def sync_with(self, token: Token) -> None:
        """Sync this token with the other token, as if they were created at the same time."""
        self.payload["exp"] = token["iat"] + self.lifetime
        self.payload["iat"] = token["iat"]
        if auth_settings.NOT_BEFORE_TIME is not None:
            self.payload["nbf"] = token["iat"] + auth_settings.NOT_BEFORE_TIME

    def copy_claims(self, token: Token) -> None:
        """Copy claims from token."""
        for claim, value in token.payload.items():
            if claim in ("exp", "iat", "nbf", "aud", "iss", "jti", "sub", "type"):
                continue
            self[claim] = value


class RefreshToken(AccessToken):

    token_type = "refresh"
    lifetime = auth_settings.REFRESH_TOKEN_LIFETIME

    def new_access_token(self, sync: bool = False) -> "AccessToken":
        """Create a new access token from this refresh token.

        :param sync: Sync the two tokens, as if they were created at the same time.
        """
        access = AccessToken()
        if sync:
            access.sync_with(self)

        access.copy_claims(self)
        return access

    def rotate(self) -> "RefreshToken":
        """Rotate refresh token."""
        log = self.check_log()
        refresh = RefreshToken()
        refresh.copy_claims(self)
        refresh.add_to_log(group=log.group)
        return refresh

    def check_log(self) -> "RefreshTokenRotationLog":
        """Check if token is in the rotation log."""
        from .rotation.models import RefreshTokenRotationLog

        jti = int(self.payload["jti"])
        sub = str(self.payload["sub"])
        try:
            log = RefreshTokenRotationLog.objects.get(id=jti)
        except RefreshTokenRotationLog.DoesNotExist as error:  # pylint: disable=no-member
            RefreshTokenRotationLog.objects.prune_group_and_expired_logs(group=sub)
            raise AuthenticationFailed(_("Token is no longer accepted."), code="unaccepted_token") from error

        return log

    @transaction.atomic
    def add_to_log(self, group: Optional[uuid.UUID] = None) -> None:
        """
        Update rotation log for the given group,
        and set the "jti" and "sub" claims for this token.
        """
        from .rotation.models import RefreshTokenRotationLog

        if group is None:
            group = uuid.uuid4()

        log = RefreshTokenRotationLog.objects.create(group=group, expires_at=self["exp"])
        RefreshTokenRotationLog.objects.prune_group_and_expired_logs(group=log.group, id_=log.id)
        self.payload["jti"] = log.id
        self.payload["sub"] = str(group)
