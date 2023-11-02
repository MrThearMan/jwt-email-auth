from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)

from django.db.models import TextChoices

__all__ = [
    "Any",
    "ClassVar",
    "Dict",
    "List",
    "Literal",
    "LoginMethod",
    "NamedTuple",
    "Optional",
    "Set",
    "Tuple",
    "Type",
    "Union",
    "Callable",
]


class LoginMethod(TextChoices):
    TOKEN = "token"
    COOKIES = "cookies"
