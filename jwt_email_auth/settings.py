import logging
import os
from datetime import timedelta
from inspect import cleandoc
from pathlib import Path
from typing import Dict, List, Literal, Optional, TypedDict
from warnings import warn

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from django.conf import settings
from django.test.signals import setting_changed
from rest_framework.settings import APISettings


__all__ = [
    "auth_settings",
]


logger = logging.getLogger(__name__)


class JWTEmailAuthSettings(TypedDict):
    # Send email, off by default
    SEND_EMAILS: bool
    #
    # When True, any code will work in login
    SKIP_CODE_CHECKS: bool
    #
    # JWT signing key
    SIGNING_KEY: Ed25519PrivateKey
    #
    # How long an access token is valid for
    ACCESS_TOKEN_LIFETIME: timedelta
    #
    # How long a refresh token is valid for
    REFRESH_TOKEN_LIFETIME: timedelta
    #
    # How long a login code is stored in cache
    LOGIN_CODE_LIFETIME: timedelta
    #
    # "Dot import notation" to a function to use for validating use from email.
    # Takes a single argument "email" of type str and returns None.
    # Default is no validation.
    VALIDATION_CALLBACK: str
    #
    # "Dot import notation" to a function to run to gather login data.
    # Takes a single argument "email" and returns a Dict[str, Any], where Any can be cached in your cache backend.
    # Default is no data.
    LOGIN_DATA: str
    #
    # "Dot import notation" to a function to generate a login code.
    # Takes no arguments and returns a string.
    # Default is a function that returns a 6-digit string.
    CODE_GENERATOR: str
    #
    # Email sender. Default is settings.DEFAULT_FROM_EMAIL
    LOGIN_SENDING_EMAIL: Optional[str]
    #
    # Email subject line
    LOGIN_SUBJECT_LINE: str
    #
    # Message to send in email. Must have {code} and {valid}!
    LOGIN_EMAIL_MESSAGE: str
    #
    # Path to html_message template. Context must have {{ code }} and {{ valid }}!
    LOGIN_EMAIL_HTML_TEMPLATE: Optional[Path]
    #
    # Encoding and decoding options:
    #
    # Issuer of the JWT
    ISSUER: Optional[str]
    #
    # Intended recipient of the JWT
    AUDIENCE: Optional[str]
    #
    # A time margin in seconds for the expiration check
    LEEWAY: int
    #
    # Algorithm to sign and decrypt the token with
    ALGORITHM: str
    #
    # Authorization: <HEADER_PREFIX> <token>
    HEADER_PREFIX: str
    #
    # Additional JWT header fields
    EXTRA_HEADERS: Optional[Dict[str, str]]
    #
    # List of expected JWT content
    EXPECTED_CLAIMS: List[str]
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    #
    # Indicate whether the originating client is on the right or left in the X-Forwarded-For header
    PROXY_ORDER: Literal["left-most", "right-most"]
    #
    # Number of proxies between the server and internet
    PROXY_COUNT: Optional[int]
    #
    # Only these proxy IPs are allowed connections
    PROXY_TRUSTED_IPS: Optional[List[str]]
    #
    # Meta precedence order
    REQUEST_HEADER_ORDER: Optional[List[str]]
    #
    # Cache prefix for login codes and banned IPs
    CACHE_PREFIX: str
    #
    # Number of login attempts until banned
    LOGIN_ATTEMPTS: int
    #
    # How long until login ban lifted
    LOGIN_COOLDOWN: timedelta
    #
    # "Dot import notation" to a function that does additional handling for blocked IPs.
    # Takes a single argument "ip" of type str, and return None.
    # Default is no additional handling
    BLOCKING_HANDLER: str
    #
    # "Dot import notation" to a function that sends the login email.
    # Takes three arguments: request (Request), email (str), and login data (Dict[str, Any]).
    # Default handler uses django's send_mail function.
    LOGIN_EMAIL_CALLBACK: str


# DO NOT USE IN PRODUCTION!
_DEFAULT_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMOFDpS02jVpNbJidXBM+s9QzWqVx56pxZdWEgVjA4T"
_DEFAULT_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----|"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW|"
    "QyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEwAAAJDEf7enxH+3|"
    "pwAAAAtzc2gtZWQyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEw|"
    "AAAECjUueNb+pa9Mf0cVahpJzyBbwQgZrp2qLgYykEiC4g4IMOFDpS02jVpNbJidXBM+s9|"
    "QzWqVx56pxZdWEgVjA4TAAAAC2xhbXBwQEtBTlRPAQI=|"
    "-----END OPENSSH PRIVATE KEY-----"
)


def load_signing_key() -> Ed25519PrivateKey:
    key = os.environ.get("SIGNING_KEY", _DEFAULT_PRIVATE_KEY)
    if key == _DEFAULT_PRIVATE_KEY:
        warn(
            "Using the default signing key. "
            "Please change before going to production. "
            "To change, set 'SIGNING_KEY' environment variable."
        )
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())  # type: ignore


USER_SETTINGS = getattr(settings, "JWT_EMAIL_AUTH", None)

DEFAULTS = JWTEmailAuthSettings(
    SEND_EMAILS=False,
    SKIP_CODE_CHECKS=False,
    SIGNING_KEY=load_signing_key(),
    ACCESS_TOKEN_LIFETIME=timedelta(minutes=5),
    REFRESH_TOKEN_LIFETIME=timedelta(days=14),
    LOGIN_CODE_LIFETIME=timedelta(minutes=5),
    VALIDATION_CALLBACK="jwt_email_auth.utils.login_validation",
    LOGIN_DATA="jwt_email_auth.utils.default_login_data",
    CODE_GENERATOR="jwt_email_auth.utils.random_code",
    LOGIN_SENDING_EMAIL=None,
    LOGIN_SUBJECT_LINE="Login to Django",
    LOGIN_EMAIL_MESSAGE=cleandoc(
        """
            Your login code:

            {code}

            This code is valid for the next {valid} minutes.
        """
    ),
    LOGIN_EMAIL_HTML_TEMPLATE=None,
    ISSUER=None,
    AUDIENCE=None,
    LEEWAY=0,
    ALGORITHM="EdDSA",
    HEADER_PREFIX="Bearer",
    EXTRA_HEADERS=None,
    EXPECTED_CLAIMS=[],
    PROXY_ORDER="left-most",
    PROXY_COUNT=None,
    PROXY_TRUSTED_IPS=None,
    REQUEST_HEADER_ORDER=None,
    CACHE_PREFIX="Django",
    LOGIN_ATTEMPTS=10,
    LOGIN_COOLDOWN=timedelta(minutes=5),
    BLOCKING_HANDLER="jwt_email_auth.utils.blocking_handler",
    LOGIN_EMAIL_CALLBACK="jwt_email_auth.utils.send_login_email",
)

# List of settings that may be in string dot import notation.
IMPORT_STRINGS = [
    "VALIDATION_CALLBACK",
    "LOGIN_DATA",
    "CODE_GENERATOR",
    "BLOCKING_HANDLER",
    "LOGIN_EMAIL_CALLBACK",
]

_AUTH_SETTINGS = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)  # type: ignore


class SettingsProxy:
    """Proxy object to JWT settings. This way when settings are reloaded from the
    setting_changed -signal they are also availale to modules have already imported
    auth_settings.
    """

    def __getattribute__(self, item):
        return _AUTH_SETTINGS.__getattr__(item)


auth_settings = SettingsProxy()


def reload_api_settings(*args, **kwargs) -> None:  # pylint: disable=W0613
    global _AUTH_SETTINGS  # pylint: disable=W0603

    setting, value = kwargs["setting"], kwargs["value"]

    if setting == "JWT_EMAIL_AUTH":
        _AUTH_SETTINGS = APISettings(value, DEFAULTS, IMPORT_STRINGS)  # type: ignore


setting_changed.connect(reload_api_settings)
