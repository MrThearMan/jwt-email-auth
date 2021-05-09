"""Functions that take care of fetching things from the Dynamics database."""

from django.conf import settings
from django.utils.translation import gettext_lazy as _

from rest_framework.exceptions import NotFound, NotAuthenticated

from dynamics import DynamicsClient
from dynamics.exceptions import DynamicsException
from dynamics.normalizers import as_str
from .exceptions import UniquenessException


__all__ = [
    "dynamics_login_check",
]


def dynamics_login_check(email: str):

    api = DynamicsClient.from_environment()
    api.table = "contacts"
    api.select = ["contactid", "firstname", "lastname", "emailaddress1", "ecr_roles_os"]
    api.filter = [f"emailaddress1 eq '{email}'"]
    api.expand = {
        "parentcustomerid_account": {"select": ["accountid", "ecr_jokipartner"]},
    }

    try:
        result = api.GET()
    except NotFound:
        raise NotFound(_(f"Contact with email '{email}' does not exist."))
    except Exception:
        raise DynamicsException(_("There was a problem communicating with the server."))

    if len(result) != 1:
        raise UniquenessException(_(f"More than one contact with email '{email}' was found."))

    roles = result[0]["ecr_roles_os"].split(",")

    if not any([role in roles for role in settings.REQUIRED_ROLES]):
        raise NotAuthenticated(_("This account does not have the appropriate privileges for booking."))

    # TODO: Remove in later releases?
    # if not result[0]["parentcustomerid_account"]["ecr_jokipartner"]:
    #     raise NotAuthenticated(_("Your company is not a Joki partner."))

    wanted_info = {
        "contact_id": as_str(result[0]["contactid"]),
        "company_id": as_str(result[0]["parentcustomerid_account"]["accountid"]),
        "first_name": as_str(result[0]["firstname"]),
        "last_name": as_str(result[0]["lastname"]),
        "email": as_str(result[0]["emailaddress1"]),
    }

    return wanted_info
