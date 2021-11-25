from jwt_email_auth.utils import random_code


def test_random_code():
    assert len(random_code()) == 6
