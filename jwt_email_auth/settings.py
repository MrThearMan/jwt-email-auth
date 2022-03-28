import logging
from datetime import timedelta
from inspect import cleandoc
from pathlib import Path
from typing import Any, Dict, List, Literal, NamedTuple, Optional, Set, Union

from django.conf import settings
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings


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
    # "Dot import notation" to a function to run to load JWT signing key.
    # Takes no arguments and returns the Ed25519PrivateKey object used to check the JWT signature.
    # Default function loads an example key, DO NOT USE IT IN PRODUCTION!
    SIGNING_KEY: str = "jwt_email_auth.utils.load_example_signing_key"
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
    # "Dot import notation" to a function to use for validating use from email.
    # Takes a single argument "email" of type str and returns None.
    # Default is no validation.
    VALIDATION_CALLBACK: str = "jwt_email_auth.utils.login_validation"
    #
    # "Dot import notation" to a function to run to gather login data.
    # Takes a single argument "email" and returns a Dict[str, Any], where Any can be cached in your cache backend.
    # Default is no data.
    LOGIN_DATA: str = "jwt_email_auth.utils.default_login_data"
    #
    # "Dot import notation" to a function to generate a login code.
    # Takes no arguments and returns a string.
    # Default is a function that returns a 6-digit string.
    CODE_GENERATOR: str = "jwt_email_auth.utils.random_code"
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
    # Encoding and decoding options:
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
    # List of expected JWT content
    EXPECTED_CLAIMS: List[str] = []
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    #
    # Indicate whether the originating client is on the right or left in the X-Forwarded-For header
    PROXY_ORDER: Literal["left-most", "right-most"] = "left-most"
    #
    # Number of proxies between the server and internet
    PROXY_COUNT: Optional[int] = None
    #
    # Only these proxy IPs are allowed connections
    PROXY_TRUSTED_IPS: Optional[List[str]] = None
    #
    # Meta precedence order
    REQUEST_HEADER_ORDER: Optional[List[str]] = None
    #
    # Cache prefix for login codes and banned IPs
    CACHE_PREFIX: str = "Django"
    #
    # Number of login attempts until banned
    LOGIN_ATTEMPTS: int = 10
    #
    # How long until login ban lifted
    LOGIN_COOLDOWN: timedelta = timedelta(minutes=5)
    #
    # "Dot import notation" to a function that does additional handling for blocked IPs.
    # Takes a single argument "ip" of type str, and return None.
    # Default is no additional handling
    BLOCKING_HANDLER: str = "jwt_email_auth.utils.blocking_handler"
    #
    # "Dot import notation" to a function that sends the login email.
    # Takes three arguments: request (Request), email (str), and login data (Dict[str, Any]).
    # Default handler uses django's send_mail function.
    LOGIN_CALLBACK: str = "jwt_email_auth.utils.send_login_email"
    #
    # When True (default), OPTIONS requests can be made to the endpoint without token for schema access
    OPTIONS_SCHEMA_ACCESS: bool = True
    #
    # If True, Refresh view sould return both the access token, and the refresh token
    REFRESH_VIEW_BOTH_TOKENS: bool = False


SETTING_NAME: str = "JWT_EMAIL_AUTH"

USER_SETTINGS: Optional[Dict[str, Any]] = getattr(settings, SETTING_NAME, None)

DEFAULTS: Dict[str, Any] = JWTEmailAuthSettings()._asdict()

IMPORT_STRINGS: Set[Union[bytes, str]] = {
    b"SIGNING_KEY",
    "VALIDATION_CALLBACK",
    "LOGIN_DATA",
    "CODE_GENERATOR",
    "BLOCKING_HANDLER",
    "LOGIN_CALLBACK",
}

REMOVED_SETTINGS: Set[str] = {
    "LOGIN_EMAIL_CALLBACK",
    "SEND_EMAILS",
}


auth_settings = SettingsHolder(
    user_settings=USER_SETTINGS,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)


setting_changed.connect(reload_settings(SETTING_NAME, auth_settings))
