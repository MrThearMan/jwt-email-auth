import logging
import os
import re

import pytest
from django.core.cache import cache
from django.http import HttpRequest
from pytest import FixtureRequest, LogCaptureFixture
from pytest_django.fixtures import SettingsWrapper
from rest_framework.request import Request


__all__ = [
    "equals_regex",
]


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.django.settings")


@pytest.fixture(scope="session", autouse=True)
def setup_django_settings() -> SettingsWrapper:
    wrapper = SettingsWrapper()
    wrapper.DEBUG = False
    wrapper.LANGUAGE_CODE = "en"
    wrapper.LANGUAGES = [("en", "English"), ("fi", "Finland")]
    wrapper.DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
    wrapper.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cache_table"}
    }
    wrapper.JWT_EMAIL_AUTH = {
        "SEND_EMAILS": False,
    }

    yield wrapper
    wrapper.finalize()


@pytest.fixture()
def drf_request() -> Request:
    return Request(HttpRequest())


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
            return bool(self._regex.match(actual))
        except TypeError:
            return False

    def __repr__(self):
        return self._regex.pattern
