import logging

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.permissions import BasePermission

from .settings import auth_settings
from .tokens import AccessToken


__all__ = [
    "HasValidJWT",
]


logger = logging.getLogger(__name__)


class HasValidJWT(BasePermission):

    message = _("Invalid token.")
    code = "permission_denied"

    def has_permission(self, request, view):
        if request.method == "OPTIONS" and settings.DEBUG and auth_settings.OPTIONS_SCHEMA_ACCESS:
            logger.debug("Allow access for OPTIONS requests in DEBUG mode.")
            return True

        try:
            AccessToken.from_request(request)
        except (AuthenticationFailed, NotAuthenticated) as error:
            logger.debug(error)
            self.message = error.detail
            self.code = error.detail.code
            return False

        return True
