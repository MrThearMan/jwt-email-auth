from rest_framework.schemas.openapi import AutoSchema
from rest_framework.views import APIView

from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT
from jwt_email_auth.schema import (
    DisablePermChecks,
    JWTEmailAuthSchema,
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
        schema = type("Schema", (JWTEmailAuthSchema, AutoSchema), {})()

    responses = {}
    add_unauthenticated_response(View().schema, responses)
    assert responses == {
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "default": "Error message.",
                            },
                        },
                    },
                },
            },
            "description": "Unauthenticated",
        }
    }


def test_add_unauthenticated_response__permission_classes():
    class View(APIView):
        authentication_classes = []
        permission_classes = [HasValidJWT]
        schema = type("Schema", (JWTEmailAuthSchema, AutoSchema), {})()

    responses = {}
    add_unauthenticated_response(View().schema, responses)
    assert responses == {
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "default": "Error message.",
                            },
                        },
                    },
                },
            },
            "description": "Unauthenticated",
        }
    }


def test_add_unauthenticated_response__none():
    class View(APIView):
        authentication_classes = []
        permission_classes = []
        schema = type("Schema", (JWTEmailAuthSchema, AutoSchema), {})()

    responses = {}
    add_unauthenticated_response(View().schema, responses)
    assert responses == {}


def test_send_login_code_schema__get_components(drf_request):
    view = SendLoginCodeView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_components("", "")
    assert components == {
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
    }


def test_login_schema__get_components(drf_request):
    view = LoginView()
    view.request = drf_request
    view.request.method = "POST"
    view.format_kwarg = None
    components = view.schema.get_components("", "")
    assert components == {
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
        "204": {
            "content": {
                "application/json": {
                    "default": "",
                    "type": "string",
                },
            },
            "description": "Authorization successful, login data cached and code sent.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Missing data or invalid types.",
        },
        "412": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "This user is not allowed to send another login code yet.",
        },
        "503": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Server could not send login code.",
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
                    "schema": {
                        "$ref": "#/components/schemas/LoginOutput",
                    },
                },
            },
            "description": "Refresh token valid and new access token was created.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Missing data or invalid types.",
        },
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Given login code was incorrect, or user has been "
            "blocked after too many attemps at login.",
        },
        "404": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "No data found for login code.",
        },
        "410": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
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
            "description": "Token refreshed.",
        },
        "400": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Missing data or invalid types",
        },
        "401": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "default": "Error message.",
                                "type": "string",
                            },
                        },
                        "type": "object",
                    }
                }
            },
            "description": "Refresh token has expired or is invalid.",
        },
    }
