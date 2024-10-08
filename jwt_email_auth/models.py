from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from django.contrib.auth.models import AnonymousUser
from django.utils.functional import cached_property

if TYPE_CHECKING:
    from .tokens import AccessToken


__all__ = [
    "StatelessUser",
]


class StatelessUser(AnonymousUser):
    """
    User that is not actually logged in, but enables
    authentication and permission checks.
    """

    is_active = True
    username = "StatelessUser"

    def __init__(self, token: AccessToken | None = None) -> None:
        self.token = token if token is not None else {}

    @cached_property
    def id(self) -> str:
        return str(uuid.uuid4())

    @cached_property
    def pk(self) -> str:
        return self.id

    @property
    def is_authenticated(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.__class__.__name__

    def __eq__(self, other: object) -> bool:
        return hash(self) == hash(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(str(self.token))
