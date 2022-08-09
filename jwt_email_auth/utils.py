import logging
import re
from base64 import b64decode, b64encode
from hashlib import md5
from inspect import cleandoc
from os import getenv, urandom
from random import randint
from typing import TYPE_CHECKING, Any, Dict, Union
from warnings import warn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from django.core.cache import cache
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _
from ipware import get_client_ip
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ValidationError
from rest_framework.request import Request

from .settings import auth_settings


if TYPE_CHECKING:
    from .tokens import RefreshToken


__all__ = [
    "generate_cache_key",
    "send_login_email",
    "token_from_headers",
    "user_is_blocked",
    "valid_jwt_format",
    "encrypt_with_cipher",
    "decrypt_with_cipher",
    "TOKEN_PATTERN",
]


logger = logging.getLogger(__name__)

TOKEN_PATTERN = re.compile(r"^[\w-]+\.[\w-]+\.[\w-]+$")


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


def get_ip(request: Request) -> str:
    ip, is_routable = get_client_ip(  # pylint: disable=C0103,W0612
        request=request,
        proxy_order=auth_settings.PROXY_ORDER,
        proxy_count=auth_settings.PROXY_COUNT,
        proxy_trusted_ips=auth_settings.PROXY_TRUSTED_IPS,
        request_header_order=auth_settings.REQUEST_HEADER_ORDER,
    )
    return ip


def generate_cache_key(content: str, /, extra_prefix: str) -> str:
    """Generate cache key using a prefix (from auth_settings), and md5 hexdigest."""
    return f"{auth_settings.CACHE_PREFIX}-{extra_prefix}-{md5(content.encode()).hexdigest()}"


def validate_login_and_provide_login_data(email: str) -> Dict[str, Any]:  # pylint: disable=W0613
    """Default function to validate login and provide login data. It is meant to be overriden in Django settings."""
    return {}


def blocking_handler(request: Request) -> None:  # pylint: disable=W0613
    return


def blocking_cache_key_from_ip(request: Request) -> str:
    return generate_cache_key(get_ip(request), extra_prefix="block")


def blocking_cache_key_from_email(request: Request) -> str:
    value = [value for key, value in request.data.items() if key != "code"][0]
    return generate_cache_key(value, extra_prefix="block")


def user_is_blocked(request: Request, record_attempt: bool = True) -> bool:
    cache_key = auth_settings.LOGIN_BLOCKER_CACHE_KEY_CALLBACK(request)
    attempt = cache.get(cache_key, 0) + 1

    if record_attempt:
        cache.set(cache_key, attempt, auth_settings.LOGIN_COOLDOWN.total_seconds())

    block: bool = attempt > auth_settings.LOGIN_ATTEMPTS
    wasnt_blocked: bool = attempt - 1 <= auth_settings.LOGIN_ATTEMPTS

    if block and wasnt_blocked:
        logger.warning(f"Blocked login for {get_ip(request)!r} due to too many attempts.")
        auth_settings.USER_BLOCKED_ADDITIONAL_HANDLER(request)

    return block


def send_login_email(email: str, login_data: Dict[str, Any], request: Request) -> None:
    code = login_data["code"]
    valid = int(auth_settings.LOGIN_CODE_LIFETIME.total_seconds() // 60)
    plain_message = cleandoc(auth_settings.LOGIN_EMAIL_MESSAGE.format(code=code, valid=valid))

    html_message = None
    if auth_settings.LOGIN_EMAIL_HTML_TEMPLATE is not None:
        html_message = render_to_string(
            template_name=auth_settings.LOGIN_EMAIL_HTML_TEMPLATE,
            context={"code": code, "valid": valid},
            request=request,
        )

    send_mail(
        subject=auth_settings.LOGIN_SUBJECT_LINE,
        message=plain_message,
        from_email=auth_settings.LOGIN_SENDING_EMAIL,
        recipient_list=[email],
        html_message=html_message,
    )


def token_from_headers(request: Request) -> str:
    """Return token from request headers.

    :param request: Request with token in headers/cookies.
    :raises NotAuthenticated: No token in headers/cookies.
    :raises AuthenticationFailed: Token was invalid.
    """
    auth_header = get_authorization_header(request)
    if not auth_header:
        raise NotAuthenticated(_("No Authorization header found from request."))

    try:
        prefix, encoded_token = auth_header.decode().split()
    except ValueError as error:
        raise AuthenticationFailed(_("Invalid Authorization header."), code="invalid_header") from error

    if prefix.lower() != auth_settings.HEADER_PREFIX.lower():
        raise AuthenticationFailed(_("Invalid prefix."), code="invalid_header_prefix")

    return encoded_token


def valid_jwt_format(token: str) -> None:
    if auth_settings.CIPHER_KEY is not None:
        try:
            token = decrypt_with_cipher(token)
        except Exception as error:
            raise ValidationError(_("JWT decrypt failed."), code="jwt_decrypt_failed") from error

    match = TOKEN_PATTERN.match(token)
    if match is None:
        raise ValidationError(_("Invalid JWT format."), code="invalid_jwt_format")


def load_example_signing_key() -> Ed25519PrivateKey:
    """Loads an example signing key for signing and checking the signature of JWTs.
    You should set 'SIGNING_KEY' to your environment variables, or change this callback
    with the JWT_EMAIL_AUTH["SIGNING_KEY"] setting before going to production.
    """

    # _default_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIMOFDpS02jVpNbJidXBM+s9QzWqVx56pxZdWEgVjA4T"
    _default_private_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----|"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW|"
        "QyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEwAAAJDEf7enxH+3|"
        "pwAAAAtzc2gtZWQyNTUxOQAAACCDDhQ6UtNo1aTWyYnVwTPrPUM1qlceeqcWXVhIFYwOEw|"
        "AAAECjUueNb+pa9Mf0cVahpJzyBbwQgZrp2qLgYykEiC4g4IMOFDpS02jVpNbJidXBM+s9|"
        "QzWqVx56pxZdWEgVjA4TAAAAC2xhbXBwQEtBTlRPAQI=|"
        "-----END OPENSSH PRIVATE KEY-----"
    )

    key = getenv("SIGNING_KEY", _default_private_key)
    if key == _default_private_key:
        warn(
            "Using the default signing key. "
            "Please change before going to production. "
            "To change, set 'SIGNING_KEY' environment variable."
        )
    key = "\n".join(key.split("|"))
    return load_ssh_private_key(key.encode(), password=None, backend=default_backend())  # type: ignore


def encrypt_with_cipher(string: str) -> str:
    try:
        key = b64decode(auth_settings.CIPHER_KEY)
    except TypeError as error:
        raise RuntimeError(_("Cipher key not set.")) from error
    except Exception as error:
        raise RuntimeError(_("Invalid cipher key.")) from error

    nonce = urandom(12)
    cipher = AESGCM(key)
    encrypted_token = cipher.encrypt(nonce, string.encode(encoding="utf-8"), None)
    return b64encode(nonce + encrypted_token).decode()


def decrypt_with_cipher(string: Union[str, bytes]) -> str:
    try:
        key = b64decode(auth_settings.CIPHER_KEY)
    except TypeError as error:
        raise RuntimeError(_("Cipher key not set.")) from error
    except Exception as error:
        raise RuntimeError(_("Invalid cipher key.")) from error

    string = b64decode(string)
    nonce = string[:12]
    data = string[12:]
    cipher = AESGCM(key=key)

    try:
        decrypted_token = cipher.decrypt(nonce, data, None)
    except InvalidTag as error:
        raise RuntimeError(_("Wrong cipher key.")) from error

    return decrypted_token.decode()


def user_check_callback(refresh: "RefreshToken") -> None:  # pylint: disable=W0613
    """Default function to check if token user still exists."""
    return  # pragma: no cover
