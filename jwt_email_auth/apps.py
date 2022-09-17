from django.apps import AppConfig
from django.utils.translation import gettext_lazy


class JwtEmailAuthConfig(AppConfig):
    name = "jwt_email_auth"
    verbose_name = gettext_lazy("JWT Email Authentication")
    default_auto_field = "django.db.models.BigAutoField"
