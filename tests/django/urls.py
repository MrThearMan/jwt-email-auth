from django.urls import path
from django.views.generic import TemplateView
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas import get_schema_view
from rest_framework.schemas.openapi import AutoSchema
from rest_framework.views import APIView

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT
from jwt_email_auth.schema import add_unauthenticated_response
from jwt_email_auth.views import (
    LoginView,
    LogoutView,
    RefreshTokenView,
    SendLoginCodeView,
    TokenClaimView,
    UpdateTokenView,
)


class Schema(AutoSchema):
    def get_responses(self, path, method):
        r = super().get_responses(path, method)
        add_unauthenticated_response(self, r)
        return r


class TestView1(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = []

    schema = Schema()

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
    path("authenticate", SendLoginCodeView.as_view(), name="authenticate"),
    path("login", LoginView.as_view(), name="login"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("refresh", RefreshTokenView.as_view(), name="refresh"),
    path("update", UpdateTokenView.as_view(), name="update"),
    path("claims", TokenClaimView.as_view(), name="claims"),
    path("test-auth", TestView1.as_view(), name="test-auth"),
    path("test-perm", TestView2.as_view(), name="test-perm"),
    path("test-both", TestView3.as_view(), name="test-both"),
    path(
        "openapi/",
        get_schema_view(
            title="Your Project",
            description="API for all things",
            version="1.0.0",
        ),
        name="openapi-schema",
    ),
    path(
        "swagger-ui/",
        TemplateView.as_view(
            template_name="swagger-ui.html",
            extra_context={"schema_url": "openapi-schema"},
        ),
        name="swagger-ui",
    ),
]
