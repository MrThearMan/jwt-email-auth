import pytest
from rest_framework.exceptions import ValidationError
from rest_framework.serializers import Serializer

from jwt_email_auth.fields import AutoTokenField
from jwt_email_auth.tokens import AccessToken


def test_auto_token_field(drf_request):
    class TestSerializer(Serializer):
        token = AutoTokenField()

    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    serializer = TestSerializer(data={}, context={"request": drf_request})
    serializer.is_valid(raise_exception=True)

    assert str(serializer.validated_data.get("token")) == str(token)
    assert serializer.data == {"token": str(token)}


def test_auto_token_field__invalid_token(drf_request):
    class TestSerializer(Serializer):
        token = AutoTokenField()

    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"{token}"

    serializer = TestSerializer(data={}, context={"request": drf_request})

    with pytest.raises(ValidationError, match="Invalid Authorization header.") as error:
        serializer.is_valid(raise_exception=True)

    assert error.value.detail == {"token": ["Invalid Authorization header."]}


def test_auto_token_field__missing_token(drf_request):
    class TestSerializer(Serializer):
        token = AutoTokenField()

    serializer = TestSerializer(data={}, context={"request": drf_request})

    with pytest.raises(ValidationError, match="No Authorization header found from request.") as error:
        serializer.is_valid(raise_exception=True)

    assert error.value.detail == {"token": ["No Authorization header found from request."]}


def test_auto_token_field__missing_request():
    class TestSerializer(Serializer):
        token = AutoTokenField()

    serializer = TestSerializer(data={})

    with pytest.raises(
        ValidationError, match="Must include a Request object in the context of the Serializer."
    ) as error:
        serializer.is_valid(raise_exception=True)

    assert error.value.detail == {"token": ["Must include a Request object in the context of the Serializer."]}
