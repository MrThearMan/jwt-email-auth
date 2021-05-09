import logging

from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.response import Response
from rest_framework.request import Request

from common.views import BaseAPIView
from common.mixins import GetMixin, PostMixin
from .utils import user_login_blocked, send_login_email
from .settings import auth_settings
from .serializers import *


__all__ = [
    "AuthenticateWithEmail",
    "ObtainJWT",
    "RefreshJWT",
]


logger = logging.getLogger(__name__)


class AuthenticateWithEmail(PostMixin, BaseAPIView):
    """Send a new login link to the email POST-ed here."""

    serializer_classes = {
        "POST": LoginCodeSerializer,
    }
    status_ok = status.HTTP_204_NO_CONTENT

    def handle_post(self, request, data, *args, **kwargs):
        send_login_email(request=request, code=data["code"], email=data["email"], link="")  # TODO: add link


class ObtainJWT(GetMixin, BaseAPIView):
    """Get new refresh and access token pair from a login code and email in query params."""

    serializer_classes = {
        "GET": ObtainTokenSerializer,
    }
    status_ok = status.HTTP_202_ACCEPTED

    def get(self, request: Request, *args, **kwargs) -> Response:

        if user_login_blocked(request):
            x = auth_settings.LOGIN_COOLDOWN // 60
            return Response(
                data={"blocked": _(f"Maximum number of attempts reached. Try again in {x} minutes.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        return super().get(request, *args, **kwargs)


class RefreshJWT(PostMixin, BaseAPIView):
    """Get new access token by POST-ing refresh token here."""

    serializer_classes = {
        "POST": RefreshTokenSerializer,
    }
