from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar, Literal, NamedTuple

from django.db.models import TextChoices

__all__ = [
    "Any",
    "Callable",
    "ClassVar",
    "Literal",
    "LoginMethod",
    "NamedTuple",
]


class LoginMethod(TextChoices):
    TOKEN = "token"
    COOKIES = "cookies"
