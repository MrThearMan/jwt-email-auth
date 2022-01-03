import logging
from typing import List, Type

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

from .exceptions import CorruptedDataException, EmailServerException
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


class SendLoginCodeView(APIView):
    """Send a new login code to the given email.

    HTTP 200 OK: Login code for this email already cached,
    no email sent as one should have been sent already.

    HTTP 204 No Content: Email was sent successfully.

    HTTP 400 Bad Request: Email not given or type somehow invalid.

    HTTP 409 Conflict: There is already a login code valid for this email.

    HTTP 503 Service Unavailable: Email server could not send email.
    """

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = SendLoginCodeSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        login_info = self.serializer_class(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data
        email = data["email"]

        cache_key = generate_cache_key(email)
        if cache.get(cache_key, None) is not None:
            message = _(
                "Login code for '%(email)s' already exists. "
                "Please check your inbox and spam folder, or try again later."
            ) % {"email": email}
            return Response(data={"message": message}, status=status.HTTP_200_OK)

        auth_settings.VALIDATION_CALLBACK(email=email)
        login_data = auth_settings.LOGIN_DATA(email=email)
        login_data["code"] = auth_settings.CODE_GENERATOR()
        logger.debug(login_data)
        cache.set(cache_key, login_data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        try:
            auth_settings.LOGIN_EMAIL_CALLBACK(request=self.request, email=email, login_data=login_data)
        except Exception as error:
            cache.delete(cache_key)
            logger.critical(f"Email sending failed: {type(error).__name__}('{error}')")
            raise EmailServerException(_("Failed to send login codes. Try again later.")) from error

        return Response(status=status.HTTP_204_NO_CONTENT)


class LoginView(APIView):
    """Get new refresh and access token pair from a login code and email.

    HTTP 200 OK: Login was successful.

    HTTP 400 Bad Request: Email or code not given or their types are somehow invalid.

    HTTP 403 Forbidden: Given login code was incorrect,
    or user has been blocked after too many attemps at login.

    HTTP 404 Not Found: No login code found for given email.

    HTTP 410 Gone: Login data was corrupted.
    """

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = LoginSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        if user_login_blocked(request):
            raise PermissionDenied(
                _("Maximum number of attempts reached. Try again in %(x)s minutes.")
                % {"x": int(auth_settings.LOGIN_COOLDOWN.total_seconds() // 60)}
            )

        login = self.serializer_class(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data

        cache_key = generate_cache_key(data["email"])
        login_data = cache.get(cache_key, None)
        if login_data is None:
            raise NotFound(_("No login code found code for '%(email)s'.") % {"email": data["email"]})

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


class RefreshTokenView(APIView):
    """Get new access token from a refresh token.

    HTTP 200 OK: Refresh token valid and new access token was created.

    HTTP 400 Bad Request: Token not given or type somehow invalid.

    HTTP 403 Forbidden: Refresh token has expired or is invalid.
    """

    authentication_classes: List[Type[BaseAuthentication]] = []
    permission_classes: List[Type[BasePermission]] = []
    serializer_class: Type[BaseSerializer] = RefreshTokenSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:  # pylint: disable=W0613
        token = self.serializer_class(data=request.data)
        token.is_valid(raise_exception=True)
        data = token.data

        refresh = RefreshToken(data["token"])
        access = refresh.new_access_token()
        data = {"access": str(access)}

        return Response(data=data, status=status.HTTP_200_OK)
