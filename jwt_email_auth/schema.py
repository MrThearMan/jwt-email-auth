from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework import serializers, status
from rest_framework.schemas.openapi import AutoSchema

from .authentication import JWTAuthentication
from .permissions import HasValidJWT
from .serializers import TokenClaimOutputSerializer, TokenOutputSerializer

if TYPE_CHECKING:
    from rest_framework.views import APIView

    from .typing import Any, ClassVar

__all__ = [
    "DisablePermChecks",
    "JWTEmailAuthSchemaMixin",
    "LoginViewSchema",
    "LoginViewSchemaMixin",
    "LogoutViewSchema",
    "LogoutViewSchemaMixin",
    "RefreshTokenViewSchema",
    "RefreshTokenViewSchemaMixin",
    "SendLoginCodeViewSchema",
    "SendLoginCodeViewSchemaMixin",
    "TokenClaimViewSchema",
    "TokenClaimViewSchemaMixin",
    "UpdateTokenViewSchema",
    "UpdateTokenViewSchemaMixin",
    "add_jwt_email_auth_security_requirement",
    "add_jwt_email_auth_security_scheme",
    "add_unauthenticated_response",
]


NO_CONTENT_SCHEMA = {"type": "string", "default": ""}

ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "detail": {
            "type": "string",
            "default": "Error message.",
        },
    },
}


def add_jwt_email_auth_security_scheme(schema: dict[str, Any]) -> None:
    """
    Add JWT email auth Security Scheme to the OpenAPI V3 Scheme.
    Use in `rest_framework.schemas.openapi.SchemaGenerator.get_schema`.
    """
    schema["components"]["securitySchemes"] = {
        "jwt_email_auth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
    }


def add_jwt_email_auth_security_requirement(view: APIView, operation: dict[str, Any]) -> None:
    """
    Add JWT email auth security requirement to the view if it has JWT permission or authentication classes.
    Use in `rest_framework.schemas.openapi.AutoSchema.get_operation`.
    """
    if JWTAuthentication in view.authentication_classes or HasValidJWT in view.permission_classes:
        operation["security"] = [{"jwt_email_auth": []}]


def add_unauthenticated_response(self: AutoSchema, responses: dict[str, Any]) -> None:
    """
    Adds 401 response to the given responses-dict if it has JWT permission or authentication classes.
    Use in `rest_framework.schemas.openapi.AutoSchema.get_responses`.
    """
    if JWTAuthentication in self.view.authentication_classes or HasValidJWT in self.view.permission_classes:
        responses.setdefault(
            "401",
            {
                "content": {"application/json": {"schema": ERROR_SCHEMA}},
                "description": "Unauthenticated",
            },
        )


class DisablePermChecks:
    """
    `rest_framework.schemas.openapi.SchemaGenerator` mixin class.

    Disable permission checks so that views with `HasValidJWT` in
    `permission_classes` are shown in the schema.
    """

    def has_view_permissions(self, path: str, method: str, view: APIView) -> bool:
        return True


class JWTEmailAuthSchemaMixin:
    responses: ClassVar[dict[int, str | type[serializers.Serializer]]] = {}

    def get_components(self, path: str, method: str) -> dict[str, Any]:
        components = {}

        request_serializer = self.get_serializer(path, method)
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

    def get_responses(self, path: str, method: str) -> dict[str, Any]:
        data = {}
        response_media_types = self.map_renderers(path, method)

        for status_code, info in self.responses.items():
            if status_code == status.HTTP_204_NO_CONTENT:
                schema = NO_CONTENT_SCHEMA

            elif isinstance(info, type) and issubclass(info, serializers.Serializer):
                serializer_class = info
                info = serializer_class.__doc__  # noqa: PLW2901
                serializer = self.view.initialize_serializer(serializer_class=serializer_class)
                schema = {"schema": self.get_reference(serializer)}
            else:
                schema = {"schema": ERROR_SCHEMA}

            data[str(status_code)] = {
                "content": dict.fromkeys(response_media_types, schema),
                "description": info,
            }

        return data


class SendLoginCodeViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        204: "Authorization successful, login data cached and code sent.",
        400: "Missing data or invalid values.",
        412: "This user is not allowed to send another login code yet.",
        503: "Server could not send login code.",
    }


class SendLoginCodeViewSchema(SendLoginCodeViewSchemaMixin, AutoSchema):
    pass


class LoginViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        200: TokenOutputSerializer,
        204: "New refresh and access token pair returned in cookies.",
        400: "Missing data or invalid values.",
        403: "Given login code was incorrect.",
        404: "Authorization not attempted, or login code expired.",
        410: "Login data was corrupted.",
        412: "User has been blocked after too many attempts at login.",
    }


class LoginViewSchema(LoginViewSchemaMixin, AutoSchema):
    pass


class RefreshTokenViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        200: TokenOutputSerializer,
        204: "New refresh and access token pair returned in cookies.",
        400: "Missing data or invalid values.",
        403: "Refresh token has expired or is invalid.",
        404: "Refresh token user no longer exists.",
        500: "Could not find refresh token based on settings.",
    }


class RefreshTokenViewSchema(RefreshTokenViewSchemaMixin, AutoSchema):
    pass


class LogoutViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        204: "Refresh token invalidated.",
        400: "Missing data or invalid values.",
        500: "Could not find refresh token based on settings.",
    }


class LogoutViewSchema(LogoutViewSchemaMixin, AutoSchema):
    pass


class UpdateTokenViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        200: TokenOutputSerializer,
        204: "New refresh and access token pair returned in cookies.",
        400: "Missing data or invalid values.",
        403: "Refresh token has expired or is invalid.",
        412: "A given claim not found from the list of expected claims, or is not allowed to be updated.",
        500: "Could not find refresh token based on settings.",
    }


class UpdateTokenViewSchema(UpdateTokenViewSchemaMixin, AutoSchema):
    pass


class TokenClaimViewSchemaMixin(JWTEmailAuthSchemaMixin):
    responses: ClassVar[dict[int, str]] = {
        200: TokenClaimOutputSerializer,
        400: "Missing data or invalid values.",
        403: "Access token has expired or is invalid.",
    }


class TokenClaimViewSchema(TokenClaimViewSchemaMixin, AutoSchema):
    pass
