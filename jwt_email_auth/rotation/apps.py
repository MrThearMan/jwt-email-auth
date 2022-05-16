from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class JwtEmailAuthRotationConfig(AppConfig):
    name = "jwt_email_auth.rotation"
    verbose_name = _("JWT rotation")
    default_auto_field = "django.db.models.BigAutoField"
