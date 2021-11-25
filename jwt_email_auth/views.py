import logging

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .exceptions import CorruptedDataException, EmailServerException, LoginCodeStillValid
from .serializers import LoginSerializer, RefreshTokenSerializer, SendLoginCodeSerializer
from .settings import auth_settings
from .tokens import RefreshToken
from .utils import generate_cache_key, send_login_email, user_login_blocked


__all__ = [
    "SendLoginCodeView",
    "LoginView",
    "RefreshTokenView",
]


logger = logging.getLogger(__name__)


class SendLoginCodeView(APIView):
    """Send a new login code to the email POST-ed here.

    HTTP 400 Bad Request: Email not given or type somehow invalid.

    HTTP 409 Conflict: There is already a login code valid for this email.

    HTTP 503 Service Unavailable: Email server could not send email.
    """

    authentication_classes = []
    permission_classes = []
    serializer_class: serializers.Serializer = SendLoginCodeSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        login_info = self.serializer_class(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data

        cache_key = generate_cache_key(data["email"])
        if cache.get(cache_key, None) is not None:
            return Response(status=status.HTTP_204_NO_CONTENT)

        login_data = auth_settings.LOGIN_DATA()
        login_data["code"] = auth_settings.CODE_GENERATOR()
        logger.info(login_data)
        cache.set(cache_key, login_data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        try:
            send_login_email(self.request, code=login_data["code"], email=data["email"])
        except Exception as error:
            cache.delete(cache_key)
            logger.critical(error)
            raise EmailServerException(_("Failed to send login codes. Try again later."))

        return Response(status=status.HTTP_204_NO_CONTENT)


class LoginView(APIView):
    """Get new refresh and access token pair from a login code and email.

    HTTP 400 Bad Request: Email or code not given or their types are somehow invalid.

    HTTP 403 Forbidden: User has been blocked aftr too many attemps at login.

    HTTP 404 Not Found: No login code found for given email.

    HTTP 410 Gone: Login data was corrupted.
    """

    authentication_classes = []
    permission_classes = []
    serializer_class: serializers.Serializer = LoginSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        if user_login_blocked(request):
            raise PermissionDenied(
                _("Maximum number of attempts reached. Try again in %(x)s minutes.")
                % {"x": auth_settings.LOGIN_COOLDOWN.total_seconds() // 60}
            )

        login = self.serializer_class(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data

        cache_key = generate_cache_key(data["email"])
        login_info = cache.get(cache_key, None)
        if login_info is None:
            raise NotFound(_("No login code found code for '%(email)s'.") % {"email": data["email"]})

        if not auth_settings.SKIP_CODE_CHECKS:
            if login_info.pop("code", None) != data["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        refresh = RefreshToken()
        try:
            refresh.update({key: login_info[key] for key in auth_settings.EXPECTED_CLAIMS})
        except KeyError:
            logger.warning(
                "Some data was missing from saved login info. If you set EXPECTED_CLAIMS, you "
                "should provide a custom LOGIN_DATA function that returns them in a dict."
            )
            cache.delete(cache_key)
            raise CorruptedDataException(_("Data was corrupted. Try to send another login code."))

        cache.delete(cache_key)

        refresh = RefreshToken()
        access = refresh.new_access_token()
        access.sync_with(refresh)

        data = {"access": str(access), "refresh": str(refresh)}

        return Response(data=data, status=status.HTTP_202_ACCEPTED)


class RefreshTokenView(APIView):
    """Get new access token by POST-ing refresh token here.

    HTTP 400 Bad Request: Token not given or type somehow invalid.

    HTTP 401 Unauthorized: Refresh token has expired or is invalid.
    """

    authentication_classes = []
    permission_classes = []
    serializer_class: serializers.Serializer = RefreshTokenSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        token = self.serializer_class(data=request.data)
        token.is_valid(raise_exception=True)
        data = token.data

        refresh = RefreshToken(data["token"], expected_claims=auth_settings.EXPECTED_CLAIMS)
        access = refresh.new_access_token()
        data = {"access": str(access)}

        return Response(data=data, status=status.HTTP_200_OK)
