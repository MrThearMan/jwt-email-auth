import logging

from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication

from .settings import auth_settings
from .tokens import AccessToken
from .models import StatelessUser


__all__ = [
    "JWTAuthentication",
]


logger = logging.getLogger(__name__)


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            token = AccessToken.from_request(request, expected_claims=auth_settings.EXPECTED_CLAIMS)
            return StatelessUser(token), None
        except AuthenticationFailed as f:
            logger.debug(f)
            return

    def authenticate_header(self, request):
        return f'{auth_settings.HEADER_PREFIX} realm="api"'
