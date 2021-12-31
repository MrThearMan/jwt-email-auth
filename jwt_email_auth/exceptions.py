from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException


__all__ = [
    "EmailServerException",
    "LoginCodeStillValid",
    "CorruptedDataException",
]


class EmailServerException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Email server did not respond.")
    default_code = "email_server_down"


class LoginCodeStillValid(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _("A login code for this email is still valid.")
    default_code = "login_still_valid"


class CorruptedDataException(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = _("Data was corrupted.")
    default_code = "data_corruption"
