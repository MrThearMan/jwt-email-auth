import logging
import re

import pytest
from django.core.cache import cache
from django.http import HttpRequest
from pytest import FixtureRequest, LogCaptureFixture
from rest_framework.request import Request
from settings_holder import SettingsWrapper


__all__ = [
    "equals_regex",
]


@pytest.fixture()
def drf_request() -> Request:
    return Request(HttpRequest())


@pytest.fixture()
def settings():
    wrapper = SettingsWrapper()
    try:
        yield wrapper
    finally:
        wrapper.finalize()


@pytest.fixture(autouse=True)
def cleanup(request: FixtureRequest):
    """Cleanup testing cache once the test has finished in the request scope."""

    def clear_cache():
        cache.clear()

    request.addfinalizer(clear_cache)


@pytest.fixture()
def caplog(caplog: LogCaptureFixture):
    caplog.set_level(logging.INFO)
    yield caplog


class equals_regex:  # noqa
    """Assert that a given string meets some expectations."""

    def __init__(self, pattern: str, flags: int = 0):
        self._regex = re.compile(pattern, flags)

    def __eq__(self, actual: str):
        try:
            return bool(self._regex.match(str(actual)))
        except TypeError:
            return False

    def __repr__(self):
        return self._regex.pattern
