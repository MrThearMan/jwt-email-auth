from typing import Any, Dict, Type, Union

from rest_framework import serializers
from rest_framework.schemas.openapi import AutoSchema
from rest_framework.views import APIView

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT
from jwt_email_auth.serializers import (
    DetailSerializer,
    LoginOutputSerializer,
    RefreshTokenOutputOneSerializer,
    RefreshTokenOutputTwoSerializer,
    SendLoginCodeOutputSerializer,
)
from jwt_email_auth.settings import auth_settings


__all__ = [
    "add_jwt_email_auth_security_scheme",
    "add_jwt_email_auth_security_requirement",
    "add_unauthenticated_response",
    "DisablePermChecks",
    "MultipleResponseMixin",
    "SendLoginCodeSchemaMixin",
    "LoginSchemaMixin",
    "RefreshTokenSchemaMixin",
]


def add_jwt_email_auth_security_scheme(schema: Dict[str, Any]) -> None:
    """Add JWT email auth Security Scheme to the OpenAPI V3 Scheme.
    Use in `rest_framework.schemas.openapi.SchemaGenerator.get_schema`.
    """
    schema["components"]["securitySchemes"] = {
        "jwt_email_auth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
    }


def add_jwt_email_auth_security_requirement(view: APIView, operation: Dict[str, Any]) -> None:
    """Add JWT email auth security requirement to the view if it has JWT permission or authentication classes.
    Use in `rest_framework.schemas.openapi.AutoSchema.get_operation`.
    """
    if JWTAuthentication in view.authentication_classes or HasValidJWT in view.permission_classes:
        operation["security"] = [{"jwt_email_auth": []}]


def add_unauthenticated_response(self: AutoSchema, responses: Dict[int, Any]) -> None:
    """Adds 401 response to the given responses-dict if it has JWT permission or authentication classes.
    Use in `rest_framework.schemas.openapi.AutoSchema.get_responses`.
    """
    if JWTAuthentication in self.view.authentication_classes or HasValidJWT in self.view.permission_classes:
        responses.setdefault(
            401,
            {
                "content": {
                    "application/json": {
                        "schema": self._get_reference(DetailSerializer()),  # pylint: disable=W0212
                    },
                },
                "description": "Unauthenticated",
            },
        )


class DisablePermChecks:
    """`rest_framework.schemas.openapi.SchemaGenerator` mixin class.

    Disable permission checks so that views with `HasValidJWT` in
    `permission_classes` are shown in the schema.
    """

    def has_view_permissions(self, path, method, view) -> bool:  # pylint: disable=W0613,R0201
        return True


class MultipleResponseMixin:
    """`rest_framework.schemas.openapi.AutoSchema` mixin class.

    Allows setting multiple responses for different status codes.
    Values can be serializers, or string (which will then use `jwt_email_auth.serializers.DetailSerializer`).
    """

    responses: Dict[int, Union[str, Type[serializers.Serializer]]] = {}

    def get_components(self, path, method) -> Dict[str, Any]:
        request_serializer = self.get_serializer(path, method)

        components = {}

        component_name = self.get_component_name(DetailSerializer())
        content = self.map_serializer(DetailSerializer())
        components.setdefault(component_name, content)

        if isinstance(request_serializer, serializers.Serializer):
            component_name = self.get_component_name(request_serializer)
            content = self.map_serializer(request_serializer)
            components.setdefault(component_name, content)

        for serializer_class in self.responses.values():
            if isinstance(serializer_class, type) and issubclass(serializer_class, serializers.Serializer):
                serializer = self.view.initialize_serializer(serializer_class=serializer_class)
                component_name = self.get_component_name(serializer)
                content = self.map_serializer(serializer)
                components.setdefault(component_name, content)

        return components

    def get_responses(self, path, method) -> Dict[str, Any]:  # pylint: disable=W0613
        data = {}

        responses = self.responses
        add_unauthenticated_response(self, responses)

        for status_code, info in responses.items():
            serializer_class = DetailSerializer

            if isinstance(info, type) and issubclass(info, serializers.Serializer):
                serializer_class = info
                info = serializer_class.__doc__

            serializer = self.view.initialize_serializer(serializer_class=serializer_class)

            schema = self._get_reference(serializer)

            data[str(status_code)] = {
                "content": {"application/json": {"schema": schema}},
                "description": info,
            }

        return data


class SendLoginCodeSchemaMixin(MultipleResponseMixin):

    responses = {
        200: "Login code for this email already cached, no email sent as one should have been sent already.",
        204: SendLoginCodeOutputSerializer,
        400: "Email not given or type somehow invalid.",
        503: "Email server could not send email.",
    }


class LoginSchemaMixin(MultipleResponseMixin):

    responses = {
        200: LoginOutputSerializer,
        400: "Email or code not given or their types are somehow invalid.",
        401: "Given login code was incorrect, or user has been blocked after too many attemps at login.",
        404: "No login code found for given email.",
        410: "Login data was corrupted.",
    }


class RefreshTokenSchemaMixin(MultipleResponseMixin):

    responses = {
        200: (
            RefreshTokenOutputTwoSerializer
            if auth_settings.REFRESH_VIEW_BOTH_TOKENS
            else RefreshTokenOutputOneSerializer
        ),
        400: "Token not given or type somehow invalid.",
        401: "Refresh token has expired or is invalid.",
    }
