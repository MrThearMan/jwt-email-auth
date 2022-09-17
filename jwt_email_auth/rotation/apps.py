from django.apps import AppConfig
from django.utils.translation import gettext_lazy


class JwtEmailAuthRotationConfig(AppConfig):
    name = "jwt_email_auth.rotation"
    verbose_name = gettext_lazy("JWT rotation")
    default_auto_field = "django.db.models.BigAutoField"
