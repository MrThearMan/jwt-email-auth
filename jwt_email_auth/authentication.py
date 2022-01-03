import logging
from typing import Optional, Tuple

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.request import Request

from .models import StatelessUser
from .settings import auth_settings
from .tokens import AccessToken


__all__ = [
    "JWTAuthentication",
]


logger = logging.getLogger(__name__)


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request: Request) -> Optional[Tuple[StatelessUser, str]]:
        try:
            token = AccessToken.from_request(request)
            return StatelessUser(token=token), str(token)
        except (AuthenticationFailed, NotAuthenticated) as error:
            logger.debug(error)
            return None

    def authenticate_header(self, request: Request) -> str:
        return f'{auth_settings.HEADER_PREFIX} realm="api"'
