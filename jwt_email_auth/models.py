from uuid import uuid4
from typing import TYPE_CHECKING

from django.utils.functional import cached_property
from django.contrib.auth.models import AnonymousUser

if TYPE_CHECKING:
    from .tokens import AccessToken


__all__ = ["StatelessUser"]


class StatelessUser(AnonymousUser):
    """
    User that is not actually logged in, but enables
    authentication and permission checks.
    """

    is_active = True
    username = "StatelessUser"

    def __init__(self, token: "AccessToken" = None):
        self.token = token if token is not None else {}
        self.is_partner: bool = self.token.get("partner", False)

    @cached_property
    def id(self):
        return uuid4()

    @cached_property
    def pk(self):
        return self.id

    @property
    def is_authenticated(self):
        return True

    def __str__(self):
        return self.__class__.__name__

    def __eq__(self, other):
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(str(self.token))
