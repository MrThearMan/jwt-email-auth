# Setup

① Add authentication, login, and token refresh views to urlpatterns.

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


② Configure settings with the `JWT_EMAIL_AUTH` key. Here is a minimal config:

```python
JWT_EMAIL_AUTH = {
    "SENDING_ON": True,  # needs to be set explicitly!
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=14),
    "LOGIN_CODE_LIFETIME": timedelta(minutes=5),
    "EXPECTED_CLAIMS": ["foo", "bar"],
    "CACHE_PREFIX": "PREFIX",
    "LOGIN_ATTEMPTS": 10,
    "LOGIN_COOLDOWN": timedelta(minutes=5),
    "LOGIN_DATA": "path.to.module.function",
}

```

Here is the full list of settings and what they mean.

| Setting                   | Description                                                                                                                                                                                                                                             | Type                        |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| SENDING_ON                | Whether emails should be sent or not. <br>When off, login code is logged instead. <br>This can be useful during development.                                                                                                                            | bool                        |
| SKIP_CODE_CHECKS          | When True, login code will not be checked <br>on login. This can be useful during <br>development.                                                                                                                                                      | bool                        |
| SIGNING_KEY               | "Dot import notation" to a function to <br>load JWT signing key. Takes no arguments <br>and returns the [Ed25519PrivateKey][pk]<br> object used to check the JWT signature. <br>Default function loads an example key,<br> DO NOT USE IT IN PRODUCTION! | str                         |
| ACCESS_TOKEN_LIFETIME     | How long an access token is valid for                                                                                                                                                                                                                   | timedelta                   |
| REFRESH_TOKEN_LIFETIME    | How long a refresh token is valid for                                                                                                                                                                                                                   | timedelta                   |
| LOGIN_CODE_LIFETIME       | How long a login code is stored in cache                                                                                                                                                                                                                | timedelta                   |
| VALIDATION_CALLBACK       | "Dot import notation" to a function to use <br>for validating use from email. <br>Takes a single argument "email" of <br>type str and returns None. <br>Default is no validation.                                                                       | str                         |
| LOGIN_DATA                | "Dot import notation" to a function to run <br>to gather login data. Takes no <br>arguments and returns a Dict[str, Any],<br> where Any can be cached <br>in your cache backend. Default is no data.                                                    | str                         |
| CODE_GENERATOR            | "Dot import notation" to a function to <br>generate a login code. Takes no <br>arguments and returns a string. Default is a <br>function that returns a 6-digit string.                                                                                 | str                         |
| LOGIN_SENDING_EMAIL       | Email sender. Default is <br>settings.DEFAULT_FROM_EMAIL                                                                                                                                                                                                | str*                        |
| LOGIN_SUBJECT_LINE        | Email subject line                                                                                                                                                                                                                                      | str                         |
| LOGIN_EMAIL_MESSAGE       | Message to send in email. <br>Must have {code} and {valid}.                                                                                                                                                                                             | str                         |
| LOGIN_EMAIL_HTML_TEMPLATE | Path to html_message template. <br>Context must have {{ code }} and {{ valid }}.                                                                                                                                                                        | Path*                       |
| ISSUER                    | Issuer of the JWT                                                                                                                                                                                                                                       | str*                        |
| AUDIENCE                  | Intended recipient of the JWT                                                                                                                                                                                                                           | str*                        |
| LEEWAY                    | A time margin in seconds for the <br>expiration check                                                                                                                                                                                                   | int                         |
| ALGORITHM                 | Algorithm to sign and decrypt the token with                                                                                                                                                                                                            | str                         |
| HEADER_PREFIX             | Authorization scheme used in Authorization <br>header, as in `HEADER_PREFIX token`                                                                                                                                                                      | str                         |
| EXTRA_HEADERS             | Additional JWT header fields                                                                                                                                                                                                                            | Dict[str, str]*             |
| EXPECTED_CLAIMS           | List of expected JWT content                                                                                                                                                                                                                            | List[str]                   |
| PROXY_ORDER               | Indicate whether the originating client <br>is on the right or left in the <br>X-Forwarded-For header                                                                                                                                                   | "left-most"<br>"right-most" |
| PROXY_COUNT               | Number of proxies between the server <br>and internet                                                                                                                                                                                                   | int]                        |
| PROXY_TRUSTED_IPS         | Only these proxy IPs are allowed connections                                                                                                                                                                                                            | List[str]*                  |
| REQUEST_HEADER_ORDER      | Meta precedence order                                                                                                                                                                                                                                   | List[str]*                  |
| CACHE_PREFIX              | Cache prefix for login codes and banned IPs                                                                                                                                                                                                             | str                         |
| LOGIN_ATTEMPTS            | Number of login attempts until banned                                                                                                                                                                                                                   | int                         |
| LOGIN_COOLDOWN            | How long until login ban lifted                                                                                                                                                                                                                         | timedelta                   |
| BLOCKING_HANDLER          | "Dot import notation" to a function that <br>does additional handling for <br>blocked IPs. Takes a single argument "ip" of <br>type str, and return None. <br>Default is no additional handling.                                                        | str                         |
| LOGIN_CALLBACK            | "Dot import notation" to a function that <br>sends the login email.  <br>Takes three arguments: email (str)<br>and login data (Dict[str, Any]), and<br>request (Request). Default handler uses <br>django's `send_mail` function.                       | str                         |
| OPTIONS_SCHEMA_ACCESS     | When True (default), OPTIONS requests <br>can be made to the endpoint <br>without token for schema access.                                                                                                                                              | bool                        |
| REFRESH_VIEW_BOTH_TOKENS  | If True, Refresh view sould return <br>both the access token, and <br>the refresh token                                                                                                                                                                 | bool                        |

\* Optional, can be left None


③ Add OpenSSH based [ed25519][ed25519] `SIGNING_KEY` (in PEM format) to environment variables.
You can create one with, e.g., ssh-keygen using the command `ssh-keygen -t ed25519`.
The linebreaks in PEM format should be replaced with | (pipe) characters.
If you do not want to use environment variables, override the `SIGNING_KEY` setting.

> A default signing key is provided for reference in the settings-module,
> but this should obviously be changed in production environments.


④ Configure Django's email [email settings][email_settings] (if using django's email sending).

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


⑤ (Optional) Add custom authentication classes to Rest framework settings.

```python
REST_FRAMEWORK = {
    ...
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "jwt_email_auth.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "jwt_email_auth.permissions.HasValidJWT",
    ]
    ...
}
```

[pk]: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
[ed25519]: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
[email_settings]: https://docs.djangoproject.com/en/3.2/topics/email/#quick-example