import logging

from django.core.cache import cache
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework import serializers
from rest_framework.exceptions import NotFound, AuthenticationFailed, PermissionDenied
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView

from .exceptions import LoginCodeStillValid, EmailServerException, CorruptedDataException
from .utils import user_login_blocked, send_login_email, generate_cache_key
from .settings import auth_settings
from .tokens import RefreshToken


__all__ = [
    "SendLoginCodeView",
    "LoginView",
    "RefreshTokenView",
]


logger = logging.getLogger(__name__)


class SendLoginCodeView(APIView):
    """Send a new login code to the email POST-ed here.

    Raises:
        - HTTP 400 Bad Request: Email not given or type somehow invalid.
        - HTTP 409 Conflict: There is already a login code valid for this email.
        - HTTP 503 Service Unavailable: Email server could not send email.
    """

    class SendLoginCodeSerializer(serializers.Serializer):
        email = serializers.EmailField(help_text="Email address to send the code to.")

    def post(self, request: Request, *args, **kwargs) -> Response:
        login_info = self.SendLoginCodeSerializer(data=request.data)
        login_info.is_valid(raise_exception=True)
        data = login_info.data
        email = data["email"]

        cache_key = generate_cache_key(email)
        if cache.get(cache_key, None) is not None:
            raise LoginCodeStillValid()

        data = auth_settings.LOGIN_DATA()
        data["code"] = auth_settings.CODE_GENERATOR()
        cache.set(cache_key, data, auth_settings.LOGIN_CODE_LIFETIME.total_seconds())

        try:
            send_login_email(self.request, code=data["code"], email=email)
        except Exception:
            cache.delete(cache_key)
            raise EmailServerException(_("Failed to send login codes. Try again later."))

        return Response(status=status.HTTP_204_NO_CONTENT)


class LoginView(APIView):
    """Get new refresh and access token pair from a login code and email.

    Raises:
        - HTTP 400 Bad Request: Email or code not given or their types are somehow invalid.
        - HTTP 403 Forbidden: User has been blocked aftr too many attemps at login.
        - HTTP 404 Not Found: No login code found for given email.
        - HTTP 410 Gone: Login data was corrupted.
    """

    class LoginSerializer(serializers.Serializer):
        code = serializers.CharField(help_text="Login code.")
        email = serializers.EmailField(help_text="Email address the code was sent to.")

    def post(self, request: Request, *args, **kwargs) -> Response:
        if user_login_blocked(request):
            raise PermissionDenied(
                _("Maximum number of attempts reached. Try again in %(x)s minutes.")
                % {"x": auth_settings.LOGIN_COOLDOWN.total_seconds() // 60}
            )

        login = self.LoginSerializer(data=request.data)
        login.is_valid(raise_exception=True)
        data = login.data

        cache_key = generate_cache_key(data["email"])
        if login_info := cache.get(cache_key, None):
            raise NotFound(_("No login code found code for '%(email)s'.") % {"email": data["email"]})

        if not auth_settings.SKIP_CODE_CHECKS:
            if login_info.pop("code", None) != data["code"]:
                raise AuthenticationFailed(_("Incorrect login code."))

        refresh = RefreshToken()
        try:
            refresh.update({key: login_info[key] for key in auth_settings.EXPECTED_CLAIMS})
        except KeyError:
            logger.debug(
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

    Raises:
        - HTTP 400 Bad Request: Token not given or type somehow invalid.
        - HTTP 401 Unauthorized: Refresh token has expired or is invalid.
    """

    class RefreshTokenSerializer(serializers.Serializer):
        token = serializers.CharField(help_text="Refresh token.")

    def post(self, request: Request, *args, **kwargs) -> Response:
        token = self.RefreshTokenSerializer(data=request.data)
        token.is_valid(raise_exception=True)
        data = token.data

        refresh = RefreshToken(data["token"], expected_claims=auth_settings.EXPECTED_CLAIMS)
        access = refresh.new_access_token()
        data = {"access": str(access)}

        return Response(data=data, status=status.HTTP_200_OK)
