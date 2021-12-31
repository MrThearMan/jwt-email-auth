import re

import pytest


__all__ = [
    "get_login_code_from_message",
]


def get_login_code_from_message(message: str) -> str:
    """Finds a 6-digit login code from the given string."""
    try:
        return re.search(r"\d{6}", message)[0]
    except IndexError:
        pytest.fail("Authenticate endpoint did not log a 6 digit login code.")
