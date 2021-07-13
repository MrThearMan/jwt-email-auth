# JSON Web Token Email Authentiation

```python
pip install jwt-email-auth
```

This module enables JSON Web Token Authentication in Django Rest framework without using Django's User model.
Instead, login information is stored in [cache](https://docs.djangoproject.com/en/3.2/topics/cache/#the-low-level-cache-api),
sent to the user's inbox, and obtained using a code that was sent to the given email.

### Requirements:
- [requirements.txt](https://github.com/MrThearMan/jwt-email-auth/blob/main/requirements.txt)

---

## Setup

1. Add `jwt_email_auth` to Django's installed apps.

```python
INSTALLED_APPS = [
    ...
    "jwt_email_auth",
    ...
]
```


2. Add authentication, login, and token refresh views to urlpatterns.
```python
from django.urls import path
from jwt_email_auth.views import SendLoginCodeView, LoginView, RefreshTokenView

urlpatterns = [
    ...
    path("authentication/", SendLoginCodeView.as_view(), name="authentication"),
    path("login/", LoginView.as_view(), name="login"),
    path("refresh/", RefreshTokenView.as_view(), name="refresh"),
    ...
]

# Or use routers...
# --------------------------------------------------------------------------------

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from jwt_email_auth.views import SendLoginCodeView, LoginView, RefreshTokenView

router = DefaultRouter()
router.register(r"authentication", SendLoginCodeView, "authentication")
router.register(r"login", LoginView, "login")
router.register(r"refresh", RefreshTokenView, "refresh")

urlpatterns = [
    ...
    path("", include(router.urls)),
    ...
]
```

3. Configure JWT email auth settings.

```python
JWT_EMAIL_AUTH = {
    # Required:
    # 
    # Off by default, will log message instead if False.
    "SEND_EMAILS": True,
    # A path to a function, in dot import notation, 
    # that returns what should be stored in cache before login 
    # codes are sent. This data is then added to the JWT claims 
    # when the login is successful. Note that 'code' is reserved 
    # for the login code that the login is made with, and it's not 
    # added to JWT claims during login.
    "LOGIN_DATA": "path.to.function",
   
    # Other useful ones:
    # 
    # Skip login code checks, for development.
    "SKIP_CODE_CHECKS": True,
    # How long tokens are valid. By default, access tokens 
    # are valid for 5 minutes, and refresh tokens for 14 days.
    "ACCESS_TOKEN_LIFETIME": timedelta(...),
    "REFRESH_TOKEN_LIFETIME": timedelta(...),
    # How long login codes are valid in cache (5 minutes by default).
    "LOGIN_CODE_LIFETIME": timedelta(...),
    # Path to an alternative code generator function, in dot import notation.
    "CODE_GENERATOR": "path.to.function",
    # The message to send. Should contain '{code}' and '{valid}' which will be 
    # replaced by the login code and valid time in minutes.
    "LOGIN_EMAIL_MESSAGE": "...",
    # Path to login HTML template. Context for this will include two values, 
    # 'code' (code needed for login) and 'valid' (code valid time in minutes).
    "LOGIN_EMAIL_HTML_TEMPLATE": "templates/example_login.html",
    # List of extra claims that token validation expects to find inside the token.
    # If not all of these are found, token is deemed invalid. Off by default.
    "EXPECTED_CLAIMS": [...],
    # How many times login can be attemted before used is banned 
    # for a short while (10 by default).
    "LOGIN_ATTEMPTS": 10,
    # How long user needs to wait from last login attempt until login 
    # ban is lifted (5 minutes by default)
    "LOGIN_COOLDOWN": timedelta(...),
}
```

Have a look at the [provided settings](jwt_email_auth/settings.py) for more.


4. Configure Django's email [email settings](https://docs.djangoproject.com/en/3.2/topics/email/#quick-example).

```python
# Not all of these may be required
EMAIL_HOST_USER = ...
EMAIL_HOST_PASSWORD = ...
EMAIL_HOST = ...
EMAIL_PORT = ...
EMAIL_USE_TLS = ...
EMAIL_USE_SSL = ...
EMAIL_BACKEND = ...
EMAIL_SENDER = ...
EMAIL_SUBJECT_PREFIX = ...
DEFAULT_FROM_EMAIL = ...
SERVER_EMAIL = ...
```

5. Add OpenSSH based [ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) `SIGNING_KEY` (in PEM format)
   to environment variables. You can create one with, e.g., ssh-keygen using the command `ssh-keygen -t ed25519`. The linebreaks in PEM
   format should be replaced with | (pipe) characters. If you do not want to use environment variables, override the `SIGNING_KEY` setting.
   
> A [default signing key](jwt_email_auth/settings.py) is provided for reference, but this should obviously be changed in production environments.

6. (Optional) Add custom authentication classes to Rest framework settings.

```python
REST_FRAMEWORK = {
    ...
    "DEFAULT_AUTHENTICATION_CLASSES": [
        ...
        "jwt_email_auth.authentication.JWTAuthentication",
        ...
    ],
    "DEFAULT_PERMISSION_CLASSES": [
       ...
       "jwt_email_auth.permissions.HasValidJWT",
       ...
    ]
    ...
}
```

## Usage


1. Send a login code to the *authentication* endpoint (from [SendLoginCodeView](jwt_email_auth/views.py) class).

|Request|Response|
|---|---|
|POST [Authentication URI] <br>Content-Type: application/json|HTTP 204 NO CONTENT
|{<br><span style="margin-left: 1rem"></span>"email":"person@example.com"<br>}|...|


2. POST the login code and email to *login* endpoint (from [LoginView](jwt_email_auth/views.py) class).

|Request|Response|
|---|---|
|POST [Login URI] <br>Content-Type: application/json|HTTP 204 ACCEPTED
|{<br><span style="margin-left: 1rem"></span>"email":"person@example.com"<br><span style="margin-left: 1rem"></span>"code":"123222"<br>}|{<br><span style="margin-left: 1rem"></span>"access":"..."<br><span style="margin-left: 1rem"></span>"refresh":"..."<br>}|


3. Refresh access token from the *refresh token* endpoint (from [RefreshTokenView](jwt_email_auth/views.py) class).

|Request|Response|
|---|---|
|POST [Refresh Token URI] <br>Content-Type: application/json|HTTP 200 OK
|{<br><span style="margin-left: 1rem"></span>"token":"..."<br>}|{<br><span style="margin-left: 1rem"></span>"access":"..."<br>}|


### Authentication and Permission classes

Add the [JWTAuthentication](jwt_email_auth/authentication.py) or [HasValidJWT](jwt_email_auth/permissions.py)
to Rest framework's settings or or to the classe's authentication or permission classes

```python
from rest_framework.views import APIView
from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT


class SomeView(APIView):
   
   authentication_classes = [JWTAuthentication]
   permission_classes = [HasValidJWT]
   
   ...
```

### Base Access Serializer

If you need to use claims from the token in you code, you can use the [BaseAccessSerializer](jwt_email_auth/serializers.py).

```python
from rest_framework.views import APIView
from rest_framework.authentication import get_authorization_header
from jwt_email_auth.serializers import BaseAccessSerializer


class SomeSerializer(BaseAccessSerializer):
   
   take_form_token = ["example", "values"]
   ...


class SomeView(APIView):
   
    def post(self, request, *args, **kwargs):
   
        prefix, encoded_token = get_authorization_header(request).split()
        serializer = SomeSerializer(data={"token": encoded_token})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data  # use .validated_data and not .data!
      
        print(data)  # {"example": ..., "values": ...}
        ...
```

