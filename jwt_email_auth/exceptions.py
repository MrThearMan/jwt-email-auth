from typing import Any, Optional

from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException


__all__ = [
    "ServerException",
    "SendCodeCooldown",
    "UserBanned",
    "UnexpectedClaim",
    "ClaimNotUpdateable",
    "CorruptedDataException",
]


class ServerException(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = _("Server did not respond.")
    default_code = "server_down"


class SendCodeCooldown(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _("This user is not allowed to send another login code yet.")
    default_code = "send_code_cooldown"


class UserBanned(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _("Maximum number of attempts reached. Try again in %(x)s minutes.")
    default_code = "user_banned"

    def __init__(self, cooldown: int, detail: Optional[str] = None, code: Optional[str] = None):
        self.default_detail %= {"x": cooldown}
        super().__init__(detail, code)


class UnexpectedClaim(APIException):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _("'%(claim)s' not found from the list of expected claims.")
    default_code = "unexpected_claim"

    def __init__(self, claim: Any, detail: Optional[str] = None, code: Optional[str] = None):
        self.default_detail %= {"claim": str(claim)}
        super().__init__(detail, code)


class ClaimNotUpdateable(UnexpectedClaim):
    status_code = status.HTTP_412_PRECONDITION_FAILED
    default_detail = _("Not allowed to update claim '%(claim)s'.")
    default_code = "claim_not_updateable"

    def __init__(self, claim: Any, detail: Optional[str] = None, code: Optional[str] = None):
        self.default_detail %= {"claim": str(claim)}
        super().__init__(detail, code)


class CorruptedDataException(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = _("Data was corrupted.")
    default_code = "data_corruption"
