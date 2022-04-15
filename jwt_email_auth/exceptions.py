from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException


__all__ = [
    "ServerException",
    "CorruptedDataException",
    "SendCodeCooldown",
]


class ServerException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Server did not respond.")
    default_code = "server_down"


class SendCodeCooldown(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _("This user is not allowed to send another login code yet.")
    default_code = "send_code_cooldown"


class CorruptedDataException(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = _("Data was corrupted.")
    default_code = "data_corruption"
