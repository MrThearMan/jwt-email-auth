import os
from datetime import timedelta

from django.conf import settings
from django.test.signals import setting_changed

from rest_framework.settings import APISettings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


__all__ = [
    "auth_settings",
]


def load_signing_key() -> "Ed25519PrivateKey":
    key = os.environ.get("SIGNING_KEY")
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())


USER_SETTINGS = getattr(settings, "JWT", None)

DEFAULTS = {
    "SEND_BY_EMAIL": True,
    "SIGNING_KEY": load_signing_key(),
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "LOGIN_CODE_LIFETIME": 5,  # int: minutes
    #
    # Encoding and decoding options:
    "ISSUER": None,  # str: Issuer of the JWT.
    "AUDIENCE": None,  # str: Intended recipient of the JWT.
    "LEEWAY": 0,  # int: A time margin in seconds for the expiration check
    "ALGORITHM": "EdDSA",  # str: Algorithm to sign and decrypt the token with
    "HEADER_PREFIX": "Bearer",  # str: Authorization: <HEADER_PREFIX> <token>
    "EXTRA_HEADERS": None,  # dict: Additional JWT header fields
    #
    # IP address spoofing prevention settings:
    # https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
    # TODO: Configure these?
    "PROXY_ORDER": "left-most",  # str: "left-most" or "right-most"
    "PROXY_COUNT": None,  # int:
    "PROXY_TRUSTED_IPS": None,  # list[str]:
    "REQUEST_HEADER_ORDER": None,  # list[str]:
    "CACHE_PREFIX": "TTK",  # str:
    "LOGIN_ATTEMPTS": 10,  # int: attempts
    "LOGIN_COOLDOWN": 5 * 60,  # int: seconds
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
