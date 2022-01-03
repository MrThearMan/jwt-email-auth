from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT


try:
    from django.urls import re_path
except ImportError:
    from django.conf.urls import url as re_path

from jwt_email_auth.views import LoginView, RefreshTokenView, SendLoginCodeView


class TestView1(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = []

    def get(self, request: Request, *args, **kwargs) -> Response:
        data = {
            "token": str(request.auth),
            "user": str(request.user),
            "is_authenticated": request.user.is_authenticated,
        }
        return Response(data=data, status=status.HTTP_200_OK)


class TestView2(APIView):

    authentication_classes = []
    permission_classes = [HasValidJWT]

    def get(self, request: Request, *args, **kwargs) -> Response:
        data = {
            "token": str(request.auth),
            "user": str(request.user),
            "is_authenticated": request.user.is_authenticated,
        }
        return Response(data=data, status=status.HTTP_200_OK)


class TestView3(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [HasValidJWT]

    def get(self, request: Request, *args, **kwargs) -> Response:
        data = {
            "token": str(request.auth),
            "user": str(request.user),
            "is_authenticated": request.user.is_authenticated,
        }
        return Response(data=data, status=status.HTTP_200_OK)


urlpatterns = [
    re_path(r"authenticate", SendLoginCodeView.as_view(), name="authenticate"),
    re_path(r"login", LoginView.as_view(), name="login"),
    re_path(r"refresh", RefreshTokenView.as_view(), name="refresh"),
    re_path(r"test-auth", TestView1.as_view(), name="test-auth"),
    re_path(r"test-perm", TestView2.as_view(), name="test-perm"),
    re_path(r"test-both", TestView3.as_view(), name="test-both"),
]
