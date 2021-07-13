"""Default settings for the JWT email authentication."""

import os
from datetime import timedelta

from warnings import warn

from django.conf import settings
from django.test.signals import setting_changed

from rest_framework.settings import APISettings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


__all__ = [
    "auth_settings",
]


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


def load_signing_key() -> "Ed25519PrivateKey":
    key = os.environ.get("SIGNING_KEY", _DEFAULT_PRIVATE_KEY)
    if key == _DEFAULT_PRIVATE_KEY:
        warn(
            "Using the default signing key. "
            "Please change before going to production. "
            "To change, set 'SIGNING_KEY' environment variable."
        )
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())


USER_SETTINGS = getattr(settings, "JWT_EMAIL_AUTH", None)

DEFAULTS = {
    "SEND_EMAILS": False,                                       # bool: Send email, off by default
    "SKIP_CODE_CHECKS": False,                                  # bool: When True, any code will work in login
    "SIGNING_KEY": load_signing_key(),                          # str: JWT signing key
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),              # timedelta: How long a access token is valid for
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),               # timedelta: How long a refresh token is valid for
    "LOGIN_CODE_LIFETIME": timedelta(minutes=5),                # timedelta: How long a login code is stored in cache
    "LOGIN_DATA": "jwt_email_auth.utils.default_login_data",    # callable -> dict: Function to run to gather login data
    "CODE_GENERATOR": "jwt_email_auth.utils.random_code",       # callable -> str: Function to generate a login code
    "LOGIN_SENDING_EMAIL": None,                                # str: Email sender. Default is settings.DEFAULT_FROM_EMAIL
    "LOGIN_SUBJECT_LINE": "Login to Django",                    # str: Email subject line
    "LOGIN_EMAIL_MESSAGE": (                                    # str: Message to send in email. Must have {code} and {valid}!
        """
            Your login code:
            
            {code}
            
            This code is valid for the next {valid} minutes.
        """
    ),
    "LOGIN_EMAIL_HTML_TEMPLATE": None,                          # str: Path to html_message template. Context must have {{ code }} and {{ valid }}!
    #
    # Encoding and decoding options:
    "ISSUER": None,                                             # str: Issuer of the JWT
    "AUDIENCE": None,                                           # str: Intended recipient of the JWT
    "LEEWAY": 0,                                                # int: A time margin in seconds for the expiration check
    "ALGORITHM": "EdDSA",                                       # str: Algorithm to sign and decrypt the token with
    "HEADER_PREFIX": "Bearer",                                  # str: Authorization: <HEADER_PREFIX> <token>
    "EXTRA_HEADERS": None,                                      # dict: Additional JWT header fields
    "EXPECTED_CLAIMS": None,                                    # list[str]: List of expected JWT content
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    "PROXY_ORDER": "left-most",                                 # str: "left-most" or "right-most"
    "PROXY_COUNT": None,                                        # int: Number of proxies between the server and internet
    "PROXY_TRUSTED_IPS": None,                                  # list[str]: Only these proxy IPs are allowed connections
    "REQUEST_HEADER_ORDER": None,                               # list[str]: Meta precedence order
    "CACHE_PREFIX": "Django",                                   # str: Cache prefix for login codes and banned IPs
    "LOGIN_ATTEMPTS": 10,                                       # int: Number of login attempts until banned
    "LOGIN_COOLDOWN": timedelta(minutes=5),                     # timedelta: How long until login ban lifted
}

# List of settings that may be in string dot import notation.
IMPORT_STRINGS = [
    "LOGIN_DATA",
    "CODE_GENERATOR",
]

auth_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    global auth_settings

    setting, value = kwargs["setting"], kwargs["value"]

    if setting == "JWT_EMAIL_AUTH":
        auth_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)


setting_changed.connect(reload_api_settings)
