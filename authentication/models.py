from uuid import uuid4
from random import randint
from datetime import datetime, timedelta

from django.db import models
from django.db.models.manager import EmptyManager
from django.contrib.auth.models import Permission, Group
from django.utils.functional import cached_property
from django.utils import timezone

from .settings import auth_settings


__all__ = [
    "StatelessUser",
    "LoginCode",
]


class StatelessUser:
    """
    User that is not actually logged in, but enables
    authentication and permission checks.
    """

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
        return self.token["email"]

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


def random_code() -> str:
    return str(randint(1, 999_999)).zfill(6)


def get_expiry() -> datetime:
    return timezone.now() + timedelta(minutes=auth_settings.LOGIN_CODE_LIFETIME)


class LoginCodeManager(models.Manager):
    def get_queryset(self):
        # Delete expired tokens on query
        # TODO: should this be atomic?
        expired_codes = super(LoginCodeManager, self).get_queryset().exclude(expiry_time__gt=timezone.now())
        expired_codes.delete()
        return super(LoginCodeManager, self).get_queryset()


class LoginCode(models.Model):

    code = models.CharField("code", max_length=6, default=random_code, help_text="Code than can be exchanged to a JWT")
    first_name = models.CharField("first name", max_length=255)
    last_name = models.CharField("last name", max_length=255)
    company_id = models.UUIDField("company name", help_text="Dynamics account id")
    contact_id = models.UUIDField("contact name", help_text="Dynamics contact id")
    email = models.EmailField("email")
    expiry_time = models.DateTimeField("expiry time", default=get_expiry)

    objects = LoginCodeManager()

    def __str__(self):
        return self.email
