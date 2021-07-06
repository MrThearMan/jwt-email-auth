import logging

from typing import Dict, Any
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework.authentication import get_authorization_header

from .utils import user_login_blocked
from .settings import auth_settings
from .serializers import *


__all__ = [
    "SendLoginCode",
    "Login",
    "RefreshToken",
]


logger = logging.getLogger(__name__)


class BaseAPIView(APIView):

    serializer_classes = {}
    """Key: method name (uppercase), value: serializer class."""
    status_ok = status.HTTP_200_OK

    def get_serializer(self, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        kwargs.setdefault("context", self.get_serializer_context())
        return serializer_class(*args, **kwargs)

    def get_serializer_class(self):
        return self.serializer_classes[self.request.method]

    def get_serializer_context(self) -> Dict[str, Any]:
        return {"request": self.request, "view": self}

    def run_serializer(self, request: Request, data: Dict[str, Any], *args, **kwargs) -> Response:
        if self.permission_classes or self.authentication_classes:
            auth_header = get_authorization_header(request)
            if not auth_header:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            data.setdefault("token", auth_header.split()[1].decode())

        data.update(**kwargs)

        serializer = self.get_serializer(data=data)





class SendLoginCode(APIView):
    """Send a new login code to the email POST-ed here."""

    def post(self, request: Request, *args, **kwargs) -> Response:

        serializer = LoginCodeSerializer(data=request.data, context={"request": self.request, "view": self})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        return Response(data=data, status=status.HTTP_200_OK)


class Login(BaseAPIView):
    """Get new refresh and access token pair from a login code and email."""

    serializer_classes = {
        "POST": ObtainTokenSerializer,
    }
    status_ok = status.HTTP_202_ACCEPTED

    def post(self, request: Request, *args, **kwargs) -> Response:

        if user_login_blocked(request):
            x = auth_settings.LOGIN_COOLDOWN.total_seconds() // 60
            return Response(
                data={"blocked": _(f"Maximum number of attempts reached. Try again in {x} minutes.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        return self.run_serializer(request, request.data, *args, **kwargs)


class RefreshToken(BaseAPIView):
    """Get new access token by POST-ing refresh token here."""

    serializer_classes = {
        "POST": RefreshTokenSerializer,
    }

    def post(self, request: Request, *args, **kwargs) -> Response:
        return self.run_serializer(request, request.data, *args, **kwargs)
