from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import APIException
from rest_framework import status


__all__ = [
    "EmailServerException",
    "UniquenessException",
    "InvalidDateException",
]


class EmailServerException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Email server did not respond.")
    default_code = "email_server_down"


class UniquenessException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _("Property must be unique.")
    default_code = "must_be_unique"


class InvalidDateException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _("Invalid date(s).")
    default_code = "invalid_dates"
