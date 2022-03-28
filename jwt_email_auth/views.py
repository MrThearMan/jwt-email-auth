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
from rest_framework.schemas.openapi import AutoSchema
from rest_framework.serializers import BaseSerializer
from rest_framework.views import APIView

from .exceptions import CorruptedDataException, ServerException
from .schema import LoginSchemaMixin, RefreshTokenSchemaMixin, SendLoginCodeSchemaMixin
from .serializers import LoginSerializer, RefreshTokenSerializer, SendLoginCodeSerializer
from .settings import auth_settings
from .tokens import RefreshToken
from .utils import generate_cache_key, user_login_blocked


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
    """Send a new login code to the given email."""

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = SendLoginCodeSerializer
    schema = type("Schema", (SendLoginCodeSchemaMixin, AutoSchema), {})()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login_info = self.serializer_class(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data
        key = list(login_info.fields.keys())[0]
        value = data[key]

        cache_key = generate_cache_key(value)
        if cache.get(cache_key, None) is not None:
            message = _(
                "Login code for '%(value)s' already exists. "
                "Please wait a moment for the message to arrive or try again later."
            ) % {"value": value}
            return Response(data={"detail": message}, status=status.HTTP_200_OK)

        auth_settings.VALIDATION_CALLBACK(value)
        login_data = auth_settings.LOGIN_DATA(value)
        login_data["code"] = auth_settings.CODE_GENERATOR()
        logger.debug(login_data)
        cache.set(cache_key, login_data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        if not auth_settings.SENDING_ON:
            logger.info(f"Login code: '{login_data['code']}'")
            return Response(status=status.HTTP_204_NO_CONTENT)

        try:
            auth_settings.LOGIN_CALLBACK(value, login_data=login_data, request=self.request)
        except Exception as error:
            cache.delete(cache_key)
            logger.critical(f"Login code sending failed: {type(error).__name__}('{error}')")
            raise ServerException(_("Failed to send login codes. Try again later.")) from error

        return Response(status=status.HTTP_204_NO_CONTENT)


class LoginView(BaseAuthView):
    """Get new refresh and access token pair from a login code and email."""

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = LoginSerializer
    schema = type("Schema", (LoginSchemaMixin, AutoSchema), {})()

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        if user_login_blocked(request):
            raise PermissionDenied(
                _("Maximum number of attempts reached. Try again in %(x)s minutes.")
                % {"x": int(auth_settings.LOGIN_COOLDOWN.total_seconds() // 60)}
            )

        login = self.serializer_class(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data
        key = [key for key in login.fields.keys() if key != "code"][0]
        value = data[key]

        cache_key = generate_cache_key(value)
        login_data = cache.get(cache_key, None)
        if login_data is None:
            raise NotFound(_("No login code found for '%(value)s'.") % {"value": value})

        login_code = login_data.pop("code", None)
        if not auth_settings.SKIP_CODE_CHECKS:
            if login_code != data["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        refresh = RefreshToken()
        try:
            refresh.update({key: login_data[key] for key in auth_settings.EXPECTED_CLAIMS})
        except KeyError as error:
            logger.warning(
                "Some data was missing from saved login info. If you set EXPECTED_CLAIMS, "
                "you should provide a custom LOGIN_DATA function that returns them."
            )
            cache.delete(cache_key)
            raise CorruptedDataException(_("Data was corrupted. Try to send another login code.")) from error

        cache.delete(cache_key)

        access = refresh.new_access_token(sync=True)

        data = {"access": str(access), "refresh": str(refresh)}

        return Response(data=data, status=status.HTTP_200_OK)


class RefreshTokenView(BaseAuthView):
    """Get new access token from a refresh token."""

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = RefreshTokenSerializer
    schema = type("Schema", (RefreshTokenSchemaMixin, AutoSchema), {})()

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
