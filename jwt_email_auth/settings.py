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
    # How long an access token is valid for
    ACCESS_TOKEN_LIFETIME: timedelta = timedelta(minutes=5)
    #
    # How long a refresh token is valid for
    REFRESH_TOKEN_LIFETIME: timedelta = timedelta(days=14)
    #
    # How long a login code is stored in cache
    LOGIN_CODE_LIFETIME: timedelta = timedelta(minutes=5)
    #
    # After user has exceeded defined number of login attemprs,
    # this is the cooldown until they can attempt login again.
    LOGIN_COOLDOWN: timedelta = timedelta(minutes=5)
    #
    # After a user has sent a login code, this is the cooldown until
    # they can send one again.
    CODE_SEND_COOLDOWN: timedelta = timedelta(minutes=1)
    #
    # Number of login attempts until user is banned
    LOGIN_ATTEMPTS: int = 10
    #
    # List of expected JWT content
    EXPECTED_CLAIMS: List[str] = []
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
    # If True, Refresh view sould return both the access token, and the refresh token
    REFRESH_VIEW_BOTH_TOKENS: bool = False
    #
    # Function to load JWT signing key.
    # Takes no arguments. Returns the Ed25519PrivateKey-object used to check the JWT signature.
    # Default function loads an example key, DO NOT USE IT IN PRODUCTION!
    SIGNING_KEY: str = "jwt_email_auth.utils.load_example_signing_key"
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


SETTING_NAME: str = "JWT_EMAIL_AUTH"

USER_SETTINGS: Optional[Dict[str, Any]] = getattr(settings, SETTING_NAME, None)

DEFAULTS: Dict[str, Any] = JWTEmailAuthSettings()._asdict()

IMPORT_STRINGS: Set[Union[bytes, str]] = {
    b"SIGNING_KEY",
    "CODE_GENERATOR",
    "SEND_LOGIN_CODE_CALLBACK",
    "LOGIN_VALIDATION_AND_DATA_CALLBACK",
    "LOGIN_BLOCKER_CACHE_KEY_CALLBACK",
    "USER_BLOCKED_ADDITIONAL_HANDLER",
}

REMOVED_SETTINGS: Set[str] = {
    "LOGIN_EMAIL_CALLBACK",
    "SEND_EMAILS",
    "LOGIN_DATA",
    "VALIDATION_CALLBACK",
    "LOGIN_CALLBACK",
    "BLOCKING_HANDLER",
    "LOGIN_BLOCKER_CALLBACK",
}


auth_settings = SettingsHolder(
    user_settings=USER_SETTINGS,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)

reload_jwt_auth_settings = reload_settings(SETTING_NAME, auth_settings)

setting_changed.connect(reload_jwt_auth_settings)
