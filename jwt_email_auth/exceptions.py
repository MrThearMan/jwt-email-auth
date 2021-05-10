from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import APIException
from rest_framework import status


__all__ = [
    "EmailServerException",
    "LoginCodeStillValid",
]


class EmailServerException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Email server did not respond.")
    default_code = "email_server_down"


class LoginCodeStillValid(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _("A login code for this email is still valid.")
    default_code = "login_still_valid"
