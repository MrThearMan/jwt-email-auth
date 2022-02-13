from rest_framework.views import APIView

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT
from jwt_email_auth.schema import (
    DisablePermChecks,
    add_jwt_email_auth_security_requirement,
    add_jwt_email_auth_security_scheme,
    add_unauthenticated_response,
)
from jwt_email_auth.views import LoginView, RefreshTokenView, SendLoginCodeView


def test_disable_perm_checks():
    checker = DisablePermChecks()
    assert checker.has_view_permissions("", "", "") is True


def test_add_jwt_email_auth_security_scheme():
    schema = {"components": {}}
    add_jwt_email_auth_security_scheme(schema)
    assert schema == {
        "components": {
            "securitySchemes": {
                "jwt_email_auth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
            }
        }
    }


def test_add_jwt_email_auth_security_requirement__authentication_classes():
    class View(APIView):
        authentication_classes = [JWTAuthentication]
        permission_classes = []

    operation = {}
    add_jwt_email_auth_security_requirement(View, operation)
    assert operation == {
        "security": [
            {
                "jwt_email_auth": [],
            },
        ]
    }


def test_add_jwt_email_auth_security_requirement__permission_classes():
    class View(APIView):
        authentication_classes = []
        permission_classes = [HasValidJWT]

    operation = {}
    add_jwt_email_auth_security_requirement(View, operation)
    assert operation == {
        "security": [
            {
                "jwt_email_auth": [],
            },
        ]
    }


def test_add_jwt_email_auth_security_requirement__none():
    class View(APIView):
        authentication_classes = []
        permission_classes = []

    operation = {}
    add_jwt_email_auth_security_requirement(View, operation)
    assert operation == {}


def test_add_unauthenticated_response__authentication_classes():
    class View(APIView):
        authentication_classes = [JWTAuthentication]
        permission_classes = []

    responses = {}
    add_unauthenticated_response(View, responses)
    assert responses == {401: "Unauthenticated"}


def test_add_unauthenticated_response__permission_classes():
    class View(APIView):
        authentication_classes = []
        permission_classes = [HasValidJWT]

    responses = {}
    add_unauthenticated_response(View, responses)
    assert responses == {401: "Unauthenticated"}


def test_add_unauthenticated_response__none():
    class View(APIView):
        authentication_classes = []
        permission_classes = []

    responses = {}
    add_unauthenticated_response(View, responses)
    assert responses == {}


def test_send_login_code_schema__get_components(drf_request):
    view = SendLoginCodeView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_components("", "")
    assert components == {
        "Detail": {
            "properties": {
                "detail": {
                    "type": "string",
                },
            },
            "required": ["detail"],
            "type": "object",
        },
        "SendLoginCode": {
            "properties": {
                "email": {
                    "description": "Email address to send the code to.",
                    "format": "email",
                    "type": "string",
                }
            },
            "required": ["email"],
            "type": "object",
        },
        "SendLoginCodeOutput": {
            "properties": {},
            "type": "object",
        },
    }


def test_login_schema__get_components(drf_request):
    view = LoginView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_components("", "")
    assert components == {
        "Detail": {
            "properties": {
                "detail": {
                    "type": "string",
                },
            },
            "required": ["detail"],
            "type": "object",
        },
        "Login": {
            "properties": {
                "code": {
                    "description": "Login code.",
                    "type": "string",
                },
                "email": {
                    "description": "Email address the code was sent to.",
                    "format": "email",
                    "type": "string",
                },
            },
            "required": ["code", "email"],
            "type": "object",
        },
        "LoginOutput": {
            "properties": {
                "access": {
                    "description": "Access token.",
                    "type": "string",
                },
                "refresh": {
                    "description": "Refresh token.",
                    "type": "string",
                },
            },
            "required": ["access", "refresh"],
            "type": "object",
        },
    }


def test_refresh_token_schema__get_components(drf_request):
    view = RefreshTokenView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_components("", "")
    assert components == {
        "Detail": {
            "properties": {
                "detail": {
                    "type": "string",
                },
            },
            "required": ["detail"],
            "type": "object",
        },
        "RefreshToken": {
            "properties": {
                "token": {
                    "description": "Refresh token.",
                    "type": "string",
                },
            },
            "required": ["token"],
            "type": "object",
        },
        "RefreshTokenOutputOne": {
            "properties": {
                "access": {
                    "description": "Access token.",
                    "type": "string",
                },
            },
            "required": ["access"],
            "type": "object",
        },
    }


def test_send_login_code_schema__get_responses(drf_request):
    view = SendLoginCodeView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_responses("", "")
    assert components == {
        "200": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Login code for this email already cached, no email "
            "sent as one should have been sent already.",
        },
        "204": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/SendLoginCodeOutput",
                    },
                },
            },
            "description": "Email was sent successfully.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Email not given or type somehow invalid.",
        },
        "503": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Email server could not send email.",
        },
    }


def test_login_schema__get_responses(drf_request):
    view = LoginView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_responses("", "")
    assert components == {
        "200": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/LoginOutput"},
                },
            },
            "description": "Refresh token valid and new access token was created.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Email or code not given or their types are somehow invalid.",
        },
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Given login code was incorrect, or user has been "
            "blocked after too many attemps at login.",
        },
        "404": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "No login code found for given email.",
        },
        "410": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Login data was corrupted.",
        },
    }


def test_refresh_token_schema__get_responses(drf_request):
    view = RefreshTokenView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_responses("", "")
    assert components == {
        "200": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/RefreshTokenOutputOne",
                    },
                },
            },
            "description": "Login was successful.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Token not given or type somehow invalid.",
        },
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Detail",
                    },
                },
            },
            "description": "Refresh token has expired or is invalid.",
        },
    }
