import logging
from datetime import timedelta
from inspect import cleandoc
from pathlib import Path

from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from .typing import Any, Dict, List, Literal, NamedTuple, Optional, Set, Union


__all__ = [
    "auth_settings",
]


logger = logging.getLogger(__name__)


class JWTEmailAuthSettings(NamedTuple):
    # Whether emails should be sent or not. When off,
    # login code is logged instead (for development).
    SENDING_ON: bool = False
    #
    # When True, any code will work in login
    SKIP_CODE_CHECKS: bool = False
    #
    # List of emails for which code checks and email sending are off,
    # even if SKIP_CODE_CHECKS=False and/or SENDING_ON=True.
    # Useful for creating review accounts in an otherwise closed system.
    SKIP_CODE_CHECKS_FOR: List[str] = []
    #
    # How long an access token is valid for
    ACCESS_TOKEN_LIFETIME: timedelta = timedelta(minutes=5)
    #
    # How long a refresh token is valid for
    REFRESH_TOKEN_LIFETIME: timedelta = timedelta(days=14)
    #
    # How long a login code is stored in cache
    LOGIN_CODE_LIFETIME: timedelta = timedelta(minutes=5)
    #
    # After user has exceeded defined number of login attempts,
    # this is the cooldown until they can attempt login again.
    LOGIN_COOLDOWN: timedelta = timedelta(minutes=5)
    #
    # After a user has sent a login code, this is the cooldown until
    # they can send one again.
    CODE_SEND_COOLDOWN: timedelta = timedelta(minutes=1)
    #
    # How long after the creation of the JWT does it become valid.
    NOT_BEFORE_TIME: Optional[timedelta] = None
    #
    # If True, return a new refresh token when requesting a new
    # access token from RefreshTokenView. The old refresh token will
    # be invalid after the new one is created.
    ROTATE_REFRESH_TOKENS: bool = False
    #
    # Number of login attempts until user is banned
    LOGIN_ATTEMPTS: int = 10
    #
    # List of expected custom JWT claims
    EXPECTED_CLAIMS: List[str] = []
    #
    # Which expected claims can be updated without re-authentication
    UPDATEABLE_CLAIMS: List[str] = []
    #
    # Email sender. Default is settings.DEFAULT_FROM_EMAIL
    LOGIN_SENDING_EMAIL: Optional[str] = None
    #
    # Email subject line
    LOGIN_SUBJECT_LINE: str = "Login to Django"
    #
    # Message to send in email. Must have {code} and {valid}!
    LOGIN_EMAIL_MESSAGE: str = cleandoc(
        """
            Your login code:

            {code}

            This code is valid for the next {valid} minutes.
        """
    )
    #
    # Path to html_message template. Context must have {{ code }} and {{ valid }}!
    LOGIN_EMAIL_HTML_TEMPLATE: Optional[Path] = None
    #
    # Issuer of the JWT
    ISSUER: Optional[str] = None
    #
    # Intended recipient of the JWT
    AUDIENCE: Optional[str] = None
    #
    # A time margin in seconds for the expiration check
    LEEWAY: int = 0
    #
    # Algorithm to sign and decrypt the token with
    ALGORITHM: str = "EdDSA"
    #
    # Authorization scheme used in Authorization header, as in `HEADER_PREFIX token`
    HEADER_PREFIX: str = "Bearer"
    #
    # Additional JWT header fields
    EXTRA_HEADERS: Optional[Dict[str, str]] = None
    #
    # Cache prefix
    CACHE_PREFIX: str = "Django"
    #
    # When True (default), OPTIONS requests can be made to the endpoint without token for schema access
    OPTIONS_SCHEMA_ACCESS: bool = True
    #
    # Function to load JWT signing key.
    # Takes no arguments. Returns the Ed25519PrivateKey-object used to check the JWT signature.
    # Default function loads an example key, DO NOT USE IT IN PRODUCTION!
    SIGNING_KEY: str = "jwt_email_auth.utils.load_example_signing_key"
    #
    # If set, JWT will be encrypted with AES in GCM-mode using this as the secret key.
    # Should be either 16, 24, or 32 bytes, encoded to base64, e.g., `b64encode(urandom(32)).decode()`
    CIPHER_KEY: Optional[str] = None
    #
    # Function to generate a login code.
    # Takes no arguments. Returns a login code (str).
    CODE_GENERATOR: str = "jwt_email_auth.utils.random_code"
    #
    # Function that sends the login email.
    # Arguments: email (str), and login data (Dict[str, Any]), and request (Request). Returns None.
    SEND_LOGIN_CODE_CALLBACK: str = "jwt_email_auth.utils.send_login_email"
    #
    # Function to use for validating user and providing login data.
    # Arguments: email (str). Returns login data (Dict[str, Any]).
    LOGIN_VALIDATION_AND_DATA_CALLBACK: str = "jwt_email_auth.utils.validate_login_and_provide_login_data"
    #
    # Function to generate cache key for storing user's login attempts.
    # Arguments: request (Request). Returns a cache key (str).
    LOGIN_BLOCKER_CACHE_KEY_CALLBACK: str = "jwt_email_auth.utils.blocking_cache_key_from_ip"
    #
    # Function for additional handling for blocked users.
    # Arguments: request (Request). Returns None.
    USER_BLOCKED_ADDITIONAL_HANDLER: str = "jwt_email_auth.utils.blocking_handler"
    #
    # Function to check if token user still exists in refresh view.
    # Arguments: refresh (RefreshToken). Returns None or raises `rest_framework.exceptions.NotFound`.
    USER_CHECK_CALLBACK: str = "jwt_email_auth.utils.user_check_callback"
    #
    # If True, can authenticate with tokens in Authorization header.
    # Set this to False and `USE_COOKIES` to True to only allow cookie authentication.
    USE_TOKENS: bool = True
    #
    # If True, can authenticate with tokens in HttpOnly headers.
    # Cookies will be checked before Authorization headers if they are enabled.
    USE_COOKIES: bool = False
    #
    # Default login method to use if none is given in Prefer-headers. If not set,
    # cookie-based login will be used if enabled, else token-based.
    DEFAULT_LOGIN_METHOD: Optional[Literal["token", "cookies"]] = None  # noqa: F821
    #
    # Cookie key to use for the access token
    ACCESS_TOKEN_KEY: str = "access"
    #
    # Cookie key to use for the refresh token
    REFRESH_TOKEN_KEY: str = "refresh"
    #
    # Indicates that the cookie is sent to the server only when
    # a request is made with the https: scheme (except on localhost),
    # and therefore, is more resistant to man-in-the-middle attacks.
    SET_COOKIE_SECURE: bool = True
    #
    # Indicates the path that must exist in the requested URL
    # for the browser to send the access token cookie.
    SET_COOKIE_ACCESS_PATH: str = "/"
    #
    # Indicates the path that must exist in the requested URL
    # for the browser to send the refresh token cookie.
    SET_COOKIE_REFRESH_PATH: str = "/"
    #
    # Defines the host to which the cookie will be sent.
    # If None, this attribute defaults to the host of the
    # current document URL, not including subdomains.
    SET_COOKIE_DOMAIN: Optional[str] = None
    #
    # If True, forbids JavaScript from accessing the cookie.
    SET_COOKIE_HTTPONLY: bool = True
    #
    # Controls whether a cookie is sent with cross-origin requests,
    # providing some protection against cross-site request forgery attacks (CSRF).
    SET_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"  # noqa: F821
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    #
    # Indicate whether the originating client is on the right or left in the X-Forwarded-For header
    PROXY_ORDER: Literal["left-most", "right-most"] = "left-most"  # noqa: F821
    #
    # Number of proxies between the server and internet
    PROXY_COUNT: Optional[int] = None
    #
    # Only these proxy IPs are allowed connections
    PROXY_TRUSTED_IPS: Optional[List[str]] = None
    #
    # Meta precedence order
    REQUEST_HEADER_ORDER: Optional[List[str]] = None


SETTING_NAME: str = "JWT_EMAIL_AUTH"

DEFAULTS: Dict[str, Any] = JWTEmailAuthSettings()._asdict()

IMPORT_STRINGS: Set[Union[bytes, str]] = {
    b"SIGNING_KEY",
    "CODE_GENERATOR",
    "SEND_LOGIN_CODE_CALLBACK",
    "LOGIN_VALIDATION_AND_DATA_CALLBACK",
    "LOGIN_BLOCKER_CACHE_KEY_CALLBACK",
    "USER_BLOCKED_ADDITIONAL_HANDLER",
    "USER_CHECK_CALLBACK",
}

REMOVED_SETTINGS: Set[str] = {
    "LOGIN_EMAIL_CALLBACK",
    "SEND_EMAILS",
    "LOGIN_DATA",
    "VALIDATION_CALLBACK",
    "LOGIN_CALLBACK",
    "BLOCKING_HANDLER",
    "LOGIN_BLOCKER_CALLBACK",
    "REFRESH_VIEW_BOTH_TOKENS",
    "SET_COOKIE_PATH",
}


auth_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)

reload_jwt_auth_settings = reload_settings(SETTING_NAME, auth_settings)

setting_changed.connect(reload_jwt_auth_settings)
