import logging

from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed

from .tokens import AccessToken


__all__ = [
    "HasValidJWT",
]


logger = logging.getLogger(__name__)


class HasValidJWT(BasePermission):
    def has_permission(self, request, view):
        try:
            AccessToken.from_request(request)
        except AuthenticationFailed as f:
            logger.debug(f)
            return False

        return True
