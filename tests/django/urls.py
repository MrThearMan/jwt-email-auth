try:
    from django.urls import re_path
except ImportError:
    from django.conf.urls import url as re_path

from jwt_email_auth.views import LoginView, RefreshTokenView, SendLoginCodeView


urlpatterns = [
    re_path(r"authenticate", SendLoginCodeView.as_view(), name="authenticate"),
    re_path(r"login", LoginView.as_view(), name="login"),
    re_path(r"refresh", RefreshTokenView.as_view(), name="refresh"),
]
