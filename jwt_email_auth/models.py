from typing import TYPE_CHECKING, Any
from uuid import uuid4

from django.contrib.auth.models import AnonymousUser
from django.utils.functional import cached_property


if TYPE_CHECKING:
    from .tokens import AccessToken


__all__ = ["StatelessUser"]


class StatelessUser(AnonymousUser):  # pylint: disable=W0223
    """
    User that is not actually logged in, but enables
    authentication and permission checks.
    """

    is_active = True
    username = "StatelessUser"

    def __init__(self, token: "AccessToken" = None):
        self.token = token if token is not None else {}

    @cached_property
    def id(self) -> str:  # pylint: disable=C0103,R0201
        return str(uuid4())

    @cached_property
    def pk(self) -> str:  # pylint: disable=C0103
        return self.id

    @property
    def is_authenticated(self) -> bool:  # type: ignore
        return True

    def __str__(self) -> str:
        return self.__class__.__name__

    def __eq__(self, other: Any) -> bool:
        return hash(self) == hash(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(str(self.token))
