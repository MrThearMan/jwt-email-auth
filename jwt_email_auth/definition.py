from __future__ import annotations

from collections.abc import Hashable, Iterator, KeysView, ValuesView
from typing import Any

from .utils import iterable_cache

__all__ = [
    "Definition",
]


class Sentinel:
    pass


_ignore = {
    "__module__",
    "__qualname__",
    "__doc__",
    "__annotations__",
    "__new__",
    "__classcell__",
    "__firstlineno__",
    "__static_attributes__",
}

_internal = {
    "_key2value_map_",
    "_value2key_map_",
    "_unique_",
    "_default_key_",
    "_default_value_",
}


class DefinitionMeta(type):
    def __new__(  # noqa: C901, ANN204
        cls,
        clss: str,
        bases: tuple[type],
        classdict: dict[str, Any],
        *,
        default_key: str = Sentinel,
        default_value: Any = Sentinel,
        unique: bool = True,
    ):
        _key_to_baseclass_: dict[str, type] = {}
        _key2value_map_: dict[str, Any] = {}
        _value2key_map_: dict[Any, str] = {}
        for base in bases:
            for key, value in getattr(base, "_key2value_map_", {}).items():
                if unique and not isinstance(value, Hashable):
                    msg = f"'{value}' is not hashable, and thus cannot be used for uniquely-valued Definitions."
                    raise ValueError(msg)

                if key in _key2value_map_:
                    msg = f"'{_key_to_baseclass_[key].__name__}' and '{base.__name__}' both defined '{key}'"
                    raise ValueError(msg)

                if unique and value in _value2key_map_:
                    msg = f"'{_value2key_map_[value]}' and '{key}' have the same value: {value}"
                    raise ValueError(msg)

                _key_to_baseclass_[key] = base
                _key2value_map_[key] = value
                if unique:
                    _value2key_map_[value] = key

        _new_class_ = super().__new__(cls, clss, bases, classdict)
        _new_class_._key2value_map_: dict[str, Any] = _key2value_map_  # type: ignore[assignment]
        _new_class_._value2key_map_: dict[Any, str] = _value2key_map_  # type: ignore[assignment]
        _new_class_._unique_: bool = unique  # type: ignore[assignment]
        _new_class_._default_key_: str = default_key  # type: ignore[assignment]
        _new_class_._default_value_: Any = default_value  # type: ignore[assignment]

        for key, value in classdict.items():
            if key in _ignore:
                continue

            if unique and not isinstance(value, Hashable):
                msg = f"'{value}' is not hashable, and thus cannot be used for uniquely-valued Definitions."
                raise ValueError(msg)

            if key in _new_class_._key2value_map_:
                msg = f"'{_key_to_baseclass_[key].__name__}' already defined '{key}'"
                raise ValueError(msg)

            if unique and value in _new_class_._value2key_map_:
                msg = f"'{_new_class_._value2key_map_[value]}' and '{key}' have the same value: {value}"
                raise ValueError(msg)

            _new_class_._key2value_map_[key] = value
            if unique:
                _new_class_._value2key_map_[value] = key

        return _new_class_

    def __setattr__(cls, key: Any, value: Any) -> None:
        # Allow specific attributes to be set once
        if key in _internal and key not in cls.__dict__:
            return super().__setattr__(key, value)

        msg = "Definition cannot be changed once created."
        raise AttributeError(msg)

    def __delattr__(cls, key: Any) -> None:
        msg = "Definition cannot be changed once created."
        raise AttributeError(msg)

    def __getitem__(cls, key: Any) -> Any:
        try:
            return cls._key2value_map_[key]
        except KeyError:
            if cls._default_value_ is not Sentinel:
                return cls._default_value_
            raise

    def __call__(cls, value: Any = Sentinel) -> str:
        if value is Sentinel:
            msg = "Definition should not be instantiated."
            raise TypeError(msg)

        if not cls._unique_:
            msg = "Non unique-valued Definitions do not support reverse lookups."
            raise TypeError(msg)

        try:
            return cls._value2key_map_[value]
        except KeyError:
            if cls._default_key_ is not Sentinel:
                return cls._default_key_
            raise

    def __contains__(cls, item: Any) -> bool:
        return item in cls.values()

    def __str__(cls) -> str:
        return "{" + ", ".join([f"{key}={value}" for key, value in cls._key2value_map_.items()]) + "}"

    def __len__(cls) -> int:
        return len(cls._key2value_map_)

    def __iter__(cls) -> DefinitionMeta:
        return cls

    @iterable_cache(provider="values")
    def __next__(cls, keys: Iterator[str]) -> str:  # noqa: PLE0302
        return next(keys)

    def keys(cls) -> KeysView[str]:
        """All definition keys in the Definition."""
        return cls._key2value_map_.keys()

    def values(cls) -> ValuesView[Any]:
        """All definition values in the Definition."""
        return cls._key2value_map_.values()


class Definition(metaclass=DefinitionMeta):
    r"""
    Create Definitions by subclassing this class.

    You can use the following class-level keywork arguments
    to change how the Definition behaves:

                  Arguments go here↴
    class MyDefinition(Definition, key=...):
        ...

    default_key: str — When no key is for a given value is found,
                       return this instead of raising a KeyError.
    default_value: Any — When no value is for a given key is found,
                         return this instead of raising a KeyError.
    unique: bool — By default, all keys and values in a definition have
                   to be unique. You can set unique=False to disable this,
                   but it also disables reverse lookup with values.
    """
