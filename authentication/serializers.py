from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework.exceptions import NotFound

from .selectors import dynamics_login_check
from .models import LoginCode
from .exceptions import UniquenessException
from .tokens import RefreshToken


__all__ = [
    "LoginCodeSerializer",
    "ObtainTokenSerializer",
    "RefreshTokenSerializer",
]


class LoginCodeSerializer(serializers.Serializer):

    email = serializers.EmailField()

    def validate(self, attrs):

        if LoginCode.objects.filter(email=attrs["email"]).exists():
            raise UniquenessException(_("A login code for this email is still valid."))

        data = dynamics_login_check(attrs["email"])
        new_code = LoginCode.objects.create(**data)

        return {"email": new_code.email, "code": new_code.code}


class ObtainTokenSerializer(serializers.Serializer):

    code = serializers.CharField()
    email = serializers.EmailField()

    def validate(self, attrs):

        try:
            code = LoginCode.objects.get(code=str(attrs["code"]), email=attrs["email"])
        except LoginCode.DoesNotExist:
            raise NotFound(_("Invalid login information."))

        refresh = RefreshToken()
        refresh.update(
            {
                "contact_id": str(code.contact_id),
                "company_id": str(code.company_id),
                "first_name": code.first_name,
                "last_name": code.last_name,
            }
        )

        code.delete()

        access = refresh.new_access_token()
        access.sync_with(refresh)

        return {"access": str(access), "refresh": str(refresh)}


class RefreshTokenSerializer(serializers.Serializer):

    token = serializers.CharField()

    def validate(self, attrs):
        refresh = RefreshToken(
            token=attrs["token"],
            expected_claims=["contact_id", "company_id", "first_name", "last_name"],
        )
        access = refresh.new_access_token()
        # same refresh token given back.
        return {"access": str(access), "refresh": str(refresh)}
