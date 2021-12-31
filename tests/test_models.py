from jwt_email_auth.models import StatelessUser
from jwt_email_auth.tokens import AccessToken


def test_stateless_user():
    user = StatelessUser()
    assert user.token == {}
    assert str(user) == "StatelessUser"
    # Check that property is cached
    assert user.id == user.id == user.pk
    assert user.is_authenticated


def test_stateless_user__user_same_if_token_is_same():
    token = AccessToken()
    user0 = StatelessUser()
    user1 = StatelessUser(token=token)
    user2 = StatelessUser(token=token)

    assert user0 != user1
    assert user1 == user2
