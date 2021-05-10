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


USER_SETTINGS = getattr(settings, "JWT", None)

DEFAULTS = {
    "SEND_BY_EMAIL": True,
    "SIGNING_KEY": load_signing_key(),
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "LOGIN_CODE_LIFETIME": 5 * 60,  # int: seconds
    #
    # Encoding and decoding options:
    "ISSUER": None,                 # str: Issuer of the JWT.
    "AUDIENCE": None,               # str: Intended recipient of the JWT.
    "LEEWAY": 0,                    # int: A time margin in seconds for the expiration check
    "ALGORITHM": "EdDSA",           # str: Algorithm to sign and decrypt the token with
    "HEADER_PREFIX": "Bearer",      # str: Authorization: <HEADER_PREFIX> <token>
    "EXTRA_HEADERS": None,          # dict: Additional JWT header fields
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    "PROXY_ORDER": "left-most",     # str: "left-most" or "right-most"
    "PROXY_COUNT": None,            # int:
    "PROXY_TRUSTED_IPS": None,      # list[str]:
    "REQUEST_HEADER_ORDER": None,   # list[str]:
    "CACHE_PREFIX": "Django",       # str:
    "LOGIN_ATTEMPTS": 10,           # int: attempts
    "LOGIN_COOLDOWN": 5 * 60,       # int: seconds
}

# List of settings that may be in string dot import notation.
IMPORT_STRINGS = []

auth_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    global auth_settings

    setting, value = kwargs["setting"], kwargs["value"]

    if setting == "JWT":
        auth_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)


setting_changed.connect(reload_api_settings)
