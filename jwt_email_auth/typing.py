from typing import TYPE_CHECKING, Any, Dict, List, Literal, NamedTuple, Optional, Set, Tuple, Type, Union

from django.db.models import TextChoices


__all__ = [
    "Any",
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
