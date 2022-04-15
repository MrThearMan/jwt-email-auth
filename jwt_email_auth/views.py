import logging
from typing import Any, List, Type

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer
from rest_framework.views import APIView

from .exceptions import CorruptedDataException, SendCodeCooldown, ServerException
from .schema import JWTEmailAuthSchema
from .serializers import (
    LoginOutputSerializer,
    LoginSerializer,
    RefreshTokenOutputOneSerializer,
    RefreshTokenOutputTwoSerializer,
    RefreshTokenSerializer,
    SendLoginCodeSerializer,
)
from .settings import auth_settings
from .tokens import RefreshToken
from .utils import generate_cache_key, user_is_blocked


__all__ = [
    "SendLoginCodeView",
    "LoginView",
    "RefreshTokenView",
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


class SendLoginCodeView(BaseAuthView):
    """Send a new login code."""

    serializer_class: Type[BaseSerializer] = SendLoginCodeSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = JWTEmailAuthSchema(
        responses={
            204: "Authorization successful, login data cached and code sent.",
            400: "Missing data or invalid types.",
            412: "This user is not allowed to send another login code yet.",
            503: "Server could not send login code.",
        }
    )

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login_info = self.serializer_class(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data
        value = [value for key, value in data.items()][0]

        login_data_cache_key = generate_cache_key(value, extra_prefix="login")
        code_sent_cache_key = generate_cache_key(value, extra_prefix="sendcode")

        login_data = cache.get(login_data_cache_key, None)
        if login_data is None:
            login_data = auth_settings.LOGIN_VALIDATION_AND_DATA_CALLBACK(value)
        else:
            code_sent = cache.get(code_sent_cache_key, None)
            if code_sent is not None:
                raise SendCodeCooldown()

        login_data["code"] = auth_settings.CODE_GENERATOR()
        logger.debug(login_data)
        cache.set(login_data_cache_key, login_data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        if not auth_settings.SENDING_ON:
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


class LoginView(BaseAuthView):
    """Get new refresh and access token pair."""

    serializer_class: Type[BaseSerializer] = LoginSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = JWTEmailAuthSchema(
        responses={
            200: LoginOutputSerializer,
            400: "Missing data or invalid types.",
            401: "Given login code was incorrect, or user has been blocked after too many attemps at login.",
            404: "No data found for login code.",
            410: "Login data was corrupted.",
        }
    )

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login = self.serializer_class(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data
        value = [value for key, value in data.items() if key != "code"][0]

        if user_is_blocked(request):
            raise PermissionDenied(
                _("Maximum number of attempts reached. Try again in %(x)s minutes.")
                % {"x": int(auth_settings.LOGIN_COOLDOWN.total_seconds() // 60)}
            )

        login_data_cache_key = generate_cache_key(value, extra_prefix="login")
        code_sent_cache_key = generate_cache_key(value, extra_prefix="sendcode")

        login_data = cache.get(login_data_cache_key, None)
        if login_data is None:
            raise NotFound(_("No login code found for '%(value)s'.") % {"value": value})

        login_code = login_data.pop("code", None)
        if not auth_settings.SKIP_CODE_CHECKS:
            if login_code != data["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        cache.delete(code_sent_cache_key)
        cache.delete(login_data_cache_key)

        try:
            claim_data = {key: login_data[key] for key in auth_settings.EXPECTED_CLAIMS}
        except KeyError as error:
            raise CorruptedDataException(_("Data was corrupted. Try to send another login code.")) from error

        refresh = RefreshToken()
        refresh.update(claim_data)
        access = refresh.new_access_token(sync=True)
        data = {"access": str(access), "refresh": str(refresh)}
        return Response(data=data, status=status.HTTP_200_OK)


class RefreshTokenView(BaseAuthView):
    """Get new access token from a refresh token."""

    serializer_class: Type[BaseSerializer] = RefreshTokenSerializer

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []

    schema = JWTEmailAuthSchema(
        responses={
            200: (
                RefreshTokenOutputTwoSerializer
                if auth_settings.REFRESH_VIEW_BOTH_TOKENS
                else RefreshTokenOutputOneSerializer
            ),
            400: "Missing data or invalid types",
            401: "Refresh token has expired or is invalid.",
        }
    )

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        token = self.serializer_class(data=request.data)
        token.is_valid(raise_exception=True)
        data = token.data

        refresh = RefreshToken(data["token"])
        access = refresh.new_access_token()
        data = {"access": str(access)}

        if auth_settings.REFRESH_VIEW_BOTH_TOKENS:
            data["refresh"] = str(refresh)

        return Response(data=data, status=status.HTTP_200_OK)
