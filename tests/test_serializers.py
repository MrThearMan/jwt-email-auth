import logging
import re
from unittest.mock import patch

import pytest
from rest_framework.exceptions import ValidationError

from jwt_email_auth.serializers import BaseAccessSerializer
from jwt_email_auth.tokens import AccessToken


def test_base_access_serializer__validated_data(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(data={}, context={"request": drf_request})
    serializer.is_valid(raise_exception=True)
    assert serializer.validated_data == {"type": "access"}


def test_base_access_serializer__data(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(data={}, context={"request": drf_request})
    serializer.is_valid(raise_exception=True)
    assert serializer.data == {"type": "access"}


def test_base_access_serializer__context_not_included():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(data={})

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        serializer.is_valid(raise_exception=True)


def test_base_access_serializer__request_not_included():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(data={}, context={})

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        serializer.is_valid(raise_exception=True)


def test_base_access_serializer__request_not_correct_type():
    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type"]

    serializer = TestSerializer(data={}, context={"request": "foo"})

    with pytest.raises(ValidationError, match="Must include a Request object in the context of the Serializer."):
        serializer.is_valid(raise_exception=True)


def test_base_access_serializer__missing_claim(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type", "foo"]

    serializer = TestSerializer(data={}, context={"request": drf_request})

    with pytest.raises(ValidationError) as exc_info:
        serializer.is_valid(raise_exception=True)

    assert exc_info.value.detail == {"foo": "Missing token claim."}


def test_base_access_serializer__missing_multiple_claims(drf_request):
    token = AccessToken()
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    class TestSerializer(BaseAccessSerializer):
        take_form_token = ["type", "foo", "bar"]

    serializer = TestSerializer(data={}, context={"request": drf_request})

    with pytest.raises(ValidationError) as exc_info:
        serializer.is_valid(raise_exception=True)

    assert exc_info.value.detail == {"foo": "Missing token claim.", "bar": "Missing token claim."}


def test_base_access_serializer__claims_are_cached(drf_request):
    token = AccessToken()
    token.update(foo=1, bar=2)
    drf_request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    with patch("jwt_email_auth.serializers.AccessToken.from_request", side_effect=AccessToken.from_request) as mock:

        class TestSerializer(BaseAccessSerializer):
            take_form_token = ["type", "foo", "bar"]

        serializer = TestSerializer(data={}, context={"request": drf_request})
        serializer.is_valid(raise_exception=True)
        assert serializer.validated_data == {"type": "access", "foo": 1, "bar": 2}
        assert serializer.data == {"type": "access", "foo": 1, "bar": 2}

    # Access token is only created one to fetch claims from it
    mock.assert_called_once()
