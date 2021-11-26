import logging

from django.conf import settings

from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed

from .tokens import AccessToken
from .settings import auth_settings


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
            AccessToken.from_request(request, expected_claims=auth_settings.EXPECTED_CLAIMS)
        except AuthenticationFailed as f:
            logger.debug(f)
            return False

        return True
