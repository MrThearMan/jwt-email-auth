from typing import TYPE_CHECKING, Any, ClassVar, Dict, List, Literal, NamedTuple, Optional, Set, Tuple, Type, Union

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
    "TYPE_CHECKING",
    "Union",
]


class LoginMethod(TextChoices):
    TOKEN = "token"
    COOKIES = "cookies"
