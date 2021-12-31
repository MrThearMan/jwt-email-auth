from unittest.mock import patch

import pytest
from rest_framework.exceptions import ValidationError

from jwt_email_auth.serializers import BaseAccessSerializer
from jwt_email_auth.tokens import AccessToken


def test_base_access_serializer(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(context={"request": drf_request})
    assert serializer.initial_data == {"type": "access"}


def test_base_access_serializer__validated_data_includes_claims(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(context={"request": drf_request})
    serializer.is_valid(raise_exception=True)
    assert serializer.validated_data == {"type": "access"}


def test_base_access_serializer__data_includes_claims(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(context={"request": drf_request})
    serializer.is_valid(raise_exception=True)
    assert serializer.data == {"type": "access"}


def test_base_access_serializer__context_not_included():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        TestSerializer()


def test_base_access_serializer__request_not_included():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        TestSerializer(context={})


def test_base_access_serializer__request_not_correct_type():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        TestSerializer(context={"request": "foo"})


def test_base_access_serializer__missing_claim(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type", "foo"]

    with pytest.raises(ValidationError, match=r"Token missing required claims for endpoint: \['foo']."):
        TestSerializer(context={"request": drf_request})


def test_base_access_serializer__missing_multiple_claims(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type", "foo", "bar"]

    with pytest.raises(ValidationError, match=r"Token missing required claims for endpoint: \['foo', 'bar']."):
        TestSerializer(context={"request": drf_request})


def test_base_access_serializer__claims_are_cached(drf_request):
    token = AccessToken()
    token.update(foo=1, bar=2)
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    with patch("jwt_email_auth.serializers.AccessToken.from_request", side_effect=AccessToken.from_request) as mock:

        class TestSerializer(BaseAccessSerializer):
            take_form_token = ["type", "foo", "bar"]

        serializer = TestSerializer(context={"request": drf_request})
        serializer.is_valid(raise_exception=True)
        assert serializer.initial_data == {"type": "access", "foo": 1, "bar": 2}
        assert serializer.validated_data == {"type": "access", "foo": 1, "bar": 2}
        assert serializer.data == {"type": "access", "foo": 1, "bar": 2}

    # Access token is only created one to fetch claims from it
    mock.assert_called_once()
