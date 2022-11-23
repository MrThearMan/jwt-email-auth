import logging
import uuid
from datetime import datetime, timezone

import jwt
from django.utils.translation import gettext_lazy
from magic_specs import Definition
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.request import Request

from .settings import auth_settings
from .typing import TYPE_CHECKING, Any, Dict, List, LoginMethod, Optional, Union
from .utils import decrypt_with_cipher, encrypt_with_cipher, token_from_headers


if TYPE_CHECKING:
    from .rotation.models import RefreshTokenRotationLog


__all__ = [
    "AccessToken",
    "RefreshToken",
    "TokenType",
]


logger = logging.getLogger(__name__)


Token = Union["AccessToken", "RefreshToken"]


class TokenType(Definition):
    access = auth_settings.ACCESS_TOKEN_KEY
    refresh = auth_settings.REFRESH_TOKEN_KEY


class AccessToken:

    token_type = TokenType(TokenType.access)
    lifetime = auth_settings.ACCESS_TOKEN_LIFETIME

    def __init__(self, token: Optional[str] = None) -> None:  # noqa: C901
        """Create a new token or construct one from encoded string.

        :param token: Encoded token without prefix.
        :raises AuthenticationFailed: Token was invalid.
        """
        rotate = auth_settings.ROTATE_REFRESH_TOKENS and self.token_type == "refresh"

        if token is not None:
            if auth_settings.CIPHER_KEY is not None:
                try:
                    token = decrypt_with_cipher(token)
                except RuntimeError as error:
                    logger.info(error)
                    raise AuthenticationFailed(str(error), code="decrypt_error") from error

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

                    RefreshTokenRotationLog.objects.remove_by_token_title(token=token)

                raise AuthenticationFailed(gettext_lazy("Signature has expired."), code="signature_expired") from error

            except jwt.DecodeError as error:
                logger.info(error)
                raise AuthenticationFailed(gettext_lazy("Error decoding signature."), code="decoding_error") from error

            except jwt.InvalidTokenError as error:
                logger.info(error)
                raise AuthenticationFailed(gettext_lazy("Invalid token."), code="invalid_token") from error

            except Exception as error:  # pragma: no cover
                logger.info(error)
                raise AuthenticationFailed(gettext_lazy("Unexpected error."), code="unexpected_error") from error

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
        """Construct a token from request.

        :param request: Request with token in headers/cookies.
        :raises NotAuthenticated: No token in headers/cookies.
        :raises AuthenticationFailed: Token was invalid.
        """
        token: Optional[str] = None
        prefer: Optional[str] = request.headers.get("Prefer")

        if token is None and prefer == LoginMethod.TOKEN.value and auth_settings.USE_TOKENS:
            token = token_from_headers(request)

        if token is None and auth_settings.USE_COOKIES:
            token = request.COOKIES.get(cls.token_type)

        if token is None and auth_settings.USE_TOKENS:
            token = token_from_headers(request)

        if token is None:
            raise NotAuthenticated(gettext_lazy("Token not found from request."))

        return cls(token=token)

    def __repr__(self) -> str:
        return repr(self.payload)

    def __str__(self) -> str:
        token = jwt.encode(
            payload=self.payload,
            key=auth_settings.SIGNING_KEY,
            algorithm=auth_settings.ALGORITHM,
            headers=auth_settings.EXTRA_HEADERS,
        )
        if auth_settings.CIPHER_KEY is not None:
            token = encrypt_with_cipher(token)

        return token

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
            raise AuthenticationFailed(gettext_lazy("Invalid token type."), code="invalid_type")

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

    token_type = TokenType(TokenType.refresh)
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
        refresh.create_log(title=log.title)
        return refresh

    def check_log(self) -> "RefreshTokenRotationLog":
        """Check if token is in the rotation log."""
        # Import is here so that jwt rotation remains optional
        from .rotation.models import RefreshTokenRotationLog

        try:
            log = RefreshTokenRotationLog.objects.get(id=int(self.payload["jti"]))
        except RefreshTokenRotationLog.DoesNotExist as error:
            RefreshTokenRotationLog.objects.remove_by_title(title=str(self.payload["sub"]))
            raise AuthenticationFailed(gettext_lazy("Token is no longer accepted."), code="unaccepted_token") from error

        return log

    def create_log(self, title: Optional[uuid.UUID] = None) -> None:
        """
        Update rotation log for the given title,
        and set the "jti" and "sub" claims for this token.
        """
        # Import is here so that jwt rotation remains optional
        from .rotation.models import RefreshTokenRotationLog

        if title is None:
            title = uuid.uuid4()

        log = RefreshTokenRotationLog.objects.pass_title(title=str(title), expires_at=self.payload["exp"])
        self.payload["sub"] = str(title)
        self.payload["jti"] = log.id
