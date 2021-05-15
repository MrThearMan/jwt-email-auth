from uuid import uuid4

from django.db.models.manager import EmptyManager
from django.contrib.auth.models import Permission, Group
from django.utils.functional import cached_property


__all__ = [
    "StatelessUser",
]


class StatelessUser:
    """User that is not actually logged in, but enables
    authentication and permission checks."""

    is_active = True
    is_anonymous = True
    is_authenticated = True

    _groups = EmptyManager(Group)
    _user_permissions = EmptyManager(Permission)

    def __init__(self, token):
        self.token = token

    @cached_property
    def id(self):
        return uuid4()

    @cached_property
    def pk(self):
        return self.id

    @cached_property
    def username(self):
        return "StatelessUser"

    @cached_property
    def is_staff(self):
        return False

    @cached_property
    def is_superuser(self):
        return False

    def __str__(self):
        return self.__class__.__name__

    def __eq__(self, other):
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(str(self.token))

    @property
    def groups(self):
        return self._groups

    @property
    def user_permissions(self):
        return self._user_permissions

    def get_user_permissions(self, *args, **kwargs):
        return set()

    def get_group_permissions(self, *args, **kwargs):
        return set()

    def get_all_permissions(self, *args, **kwargs):
        return set()

    def has_perm(self, *args, **kwargs):
        return False

    def has_perms(self, *args, **kwargs):
        return False

    def has_module_perms(self, *args, **kwargs):
        return False

    def get_username(self):
        return self.username
