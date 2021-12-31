import logging

from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.permissions import BasePermission

from .tokens import AccessToken


__all__ = [
    "HasValidJWT",
]


logger = logging.getLogger(__name__)


class HasValidJWT(BasePermission):
    def has_permission(self, request, view):

        # Allow viewing the schema if in debug mode
        if request.method == "OPTIONS" and settings.DEBUG:
            return True

        try:
            AccessToken.from_request(request)
        except (AuthenticationFailed, NotAuthenticated) as error:
            logger.debug(error)
            return False

        return True
