# pylint: disable=import-outside-toplevel
import logging
from typing import Any, Dict, List, Type

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer
from rest_framework.views import APIView

from .authentication import JWTAuthentication
from .exceptions import (
    ClaimNotUpdateable,
    CorruptedDataException,
    SendCodeCooldown,
    ServerException,
    UnexpectedClaim,
    UserBanned,
)
from .permissions import HasValidJWT
from .schema import (
    LoginViewSchema,
    LogoutViewSchema,
    RefreshTokenViewSchema,
    SendLoginCodeViewSchema,
    TokenClaimViewSchema,
    UpdateTokenViewSchema,
)
from .serializers import (
    LoginSerializer,
    LogoutSerializer,
    RefreshTokenSerializer,
    SendLoginCodeSerializer,
    TokenClaimSerializer,
    TokenUpdateSerializer,
)
from .settings import auth_settings
from .tokens import AccessToken, RefreshToken
from .utils import generate_cache_key, user_is_blocked


__all__ = [
    "SendLoginCodeView",
    "LoginView",
    "RefreshTokenView",
    "LogoutView",
    "UpdateTokenView",
]


logger = logging.getLogger(__name__)


class BaseAuthView(APIView):
    """Base class for JWT authentication"""

    serializer_class: Type[BaseSerializer]

    def get_serializer(self, *args: Any, **kwargs: Any) -> BaseSerializer:
        kwargs["serializer_class"] = self.get_serializer_class()
        return self.initialize_serializer(*args, **kwargs)

    def initialize_serializer(self, *args: Any, **kwargs: Any) -> BaseSerializer:
        serializer_class: Type[BaseSerializer] = kwargs.pop("serializer_class")
        kwargs.setdefault("context", self.get_serializer_context())
        kwargs.setdefault("many", getattr(serializer_class, "many", False))
        return serializer_class(*args, **kwargs)

    def get_serializer_class(self) -> Type[BaseSerializer]:
        assert self.serializer_class, "Serializer class not defined"
        return self.serializer_class

    def get_serializer_context(self):
        return {"request": self.request, "format": self.format_kwarg, "view": self}

    @classmethod
    def get_extra_actions(cls) -> List[str]:
        return []

    @staticmethod
    def response_with_cookies(access: AccessToken, refresh: RefreshToken) -> Response:
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.set_cookie(
            key="access",
            value=str(access),
            expires=access["exp"],
            path=auth_settings.SET_COOKIE_ACCESS_PATH,
            domain=auth_settings.SET_COOKIE_DOMAIN,
            secure=auth_settings.SET_COOKIE_SECURE,
            httponly=auth_settings.SET_COOKIE_HTTPONLY,
            samesite=auth_settings.SET_COOKIE_SAMESITE,
        )
        response.set_cookie(
            key="refresh",
            value=str(refresh),
            expires=refresh["exp"],
            path=auth_settings.SET_COOKIE_REFRESH_PATH,
            domain=auth_settings.SET_COOKIE_DOMAIN,
            secure=auth_settings.SET_COOKIE_SECURE,
            httponly=auth_settings.SET_COOKIE_HTTPONLY,
            samesite=auth_settings.SET_COOKIE_SAMESITE,
        )
        return response


class SendLoginCodeView(BaseAuthView):
    """Send a new login code."""

    serializer_class: Type[BaseSerializer] = SendLoginCodeSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = SendLoginCodeViewSchema()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login_info = self.serializer_class(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data
        value = self._get_id_value(data)

        if user_is_blocked(request, record_attempt=False):
            raise SendCodeCooldown()

        login_data_cache_key = generate_cache_key(value, extra_prefix="login")
        code_sent_cache_key = generate_cache_key(value, extra_prefix="sendcode")

        login_data = self._get_login_data(code_sent_cache_key, login_data_cache_key, value)

        login_data["code"] = auth_settings.CODE_GENERATOR()
        logger.debug(login_data)
        cache.set(login_data_cache_key, login_data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        if not auth_settings.SENDING_ON or value in auth_settings.SKIP_CODE_CHECKS_FOR:
            logger.info(f"Login code: '{login_data['code']}'")
            return Response(status=status.HTTP_204_NO_CONTENT)

        try:
            auth_settings.SEND_LOGIN_CODE_CALLBACK(value, login_data, self.request)
            cache.set(code_sent_cache_key, 1, auth_settings.CODE_SEND_COOLDOWN.total_seconds())

        except Exception as error:
            cache.delete(login_data_cache_key)
            logger.critical(f"Login code sending failed: {type(error).__name__}('{error}')")
            raise ServerException(_("Failed to send login codes. Try again later.")) from error

        return Response(status=status.HTTP_204_NO_CONTENT)

    def _get_id_value(self, data: Dict[str, Any]) -> Any:
        return [value for key, value in data.items()][0]

    def _get_login_data(self, code_sent_cache_key: str, login_data_cache_key: str, value: Any) -> Dict[str, Any]:
        login_data = cache.get(login_data_cache_key)
        if login_data is None:
            login_data = auth_settings.LOGIN_VALIDATION_AND_DATA_CALLBACK(value)
        else:
            code_sent = cache.get(code_sent_cache_key)
            if code_sent is not None:
                raise SendCodeCooldown()
        return login_data


class LoginView(BaseAuthView):
    """Get new refresh and access token pair."""

    serializer_class: Type[BaseSerializer] = LoginSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = LoginViewSchema()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login = self.serializer_class(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data
        value = self._get_id_value(data)

        if user_is_blocked(request):
            raise UserBanned(cooldown=int(auth_settings.LOGIN_COOLDOWN.total_seconds() // 60))

        login_data_cache_key = generate_cache_key(value, extra_prefix="login")
        code_sent_cache_key = generate_cache_key(value, extra_prefix="sendcode")

        login_data = cache.get(login_data_cache_key, None)
        if login_data is None:
            raise NotFound(_("No login code found for '%(value)s'.") % {"value": value})

        login_code = login_data.pop("code", None)
        if not auth_settings.SKIP_CODE_CHECKS and value not in auth_settings.SKIP_CODE_CHECKS_FOR:
            if login_code != data["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        cache.delete(code_sent_cache_key)
        cache.delete(login_data_cache_key)

        claim_data = self._get_claims(login_data)

        refresh = RefreshToken()
        if auth_settings.ROTATE_REFRESH_TOKENS:
            refresh.create_log()

        refresh.update(claim_data)
        access = refresh.new_access_token(sync=True)

        if auth_settings.USE_COOKIES:
            return self.response_with_cookies(access, refresh)

        data = {"access": str(access), "refresh": str(refresh)}
        return Response(data=data, status=status.HTTP_200_OK)

    def _get_id_value(self, data: Dict[str, Any]) -> Any:
        return [value for key, value in data.items() if key != "code"][0]

    def _get_claims(self, login_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return {key: login_data[key] for key in auth_settings.EXPECTED_CLAIMS}
        except KeyError as error:
            raise CorruptedDataException(_("Data was corrupted. Try to send another login code.")) from error


class RefreshTokenView(BaseAuthView):
    """Get new access token from a refresh token."""

    serializer_class: Type[BaseSerializer] = RefreshTokenSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = RefreshTokenViewSchema()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        data = self.serializer_class(data=request.data)
        data.is_valid(raise_exception=True)
        token = request.COOKIES["refresh"] if auth_settings.USE_COOKIES else data.data["token"]

        refresh = RefreshToken(token=token)

        user_check = data.data.get("user_check", False)
        if user_check:
            auth_settings.USER_CHECK_CALLBACK(refresh)

        if auth_settings.ROTATE_REFRESH_TOKENS:
            refresh = refresh.rotate()

        access = refresh.new_access_token(sync=auth_settings.ROTATE_REFRESH_TOKENS)

        if auth_settings.USE_COOKIES:
            return self.response_with_cookies(access, refresh)

        data = {"access": str(access), "refresh": str(refresh)}
        return Response(data=data, status=status.HTTP_200_OK)


class LogoutView(BaseAuthView):
    """Invalidate refresh token when logging out."""

    serializer_class: Type[BaseSerializer] = LogoutSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = LogoutViewSchema()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        # Import is here so that jwt rotation remains optional
        from .rotation.models import RefreshTokenRotationLog

        data = self.serializer_class(data=request.data)
        data.is_valid(raise_exception=True)
        token = request.COOKIES["refresh"] if auth_settings.USE_COOKIES else data.data["token"]
        RefreshTokenRotationLog.objects.remove_by_token_title(token=token)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UpdateTokenView(BaseAuthView):
    """Update token claims. Changes the token signatures."""

    serializer_class: Type[BaseSerializer] = TokenUpdateSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = UpdateTokenViewSchema()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        token = self.serializer_class(data=request.data)
        token.is_valid(raise_exception=True)
        data = token.data

        for claim in data["data"]:
            if claim not in auth_settings.EXPECTED_CLAIMS:
                raise UnexpectedClaim(claim=claim)
            if claim not in auth_settings.UPDATEABLE_CLAIMS:
                raise ClaimNotUpdateable(claim=claim)

        token = request.COOKIES["refresh"] if auth_settings.USE_COOKIES else data["token"]
        refresh = RefreshToken(token=token)
        refresh.update(data["data"])
        if auth_settings.ROTATE_REFRESH_TOKENS:
            refresh = refresh.rotate()

        access = refresh.new_access_token(sync=auth_settings.ROTATE_REFRESH_TOKENS)

        if auth_settings.USE_COOKIES:
            return self.response_with_cookies(access, refresh)

        data = {"access": str(access), "refresh": str(refresh)}
        return Response(data=data, status=status.HTTP_200_OK)


class TokenClaimView(BaseAuthView):
    """Extract token claims."""

    serializer_class: Type[BaseSerializer] = TokenClaimSerializer

    authentication_classes: List[Type[BaseAuthentication]] = [JWTAuthentication]
    permission_classes: List[Type[BasePermission]] = [HasValidJWT]

    schema = TokenClaimViewSchema()

    def get(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        access = AccessToken.from_request(request)
        return Response(data=access.payload, status=status.HTTP_200_OK)
