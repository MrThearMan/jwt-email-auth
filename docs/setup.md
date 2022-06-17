# Setup

① Add authentication, login and refresh views to urlpatterns.

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
```


② Configure settings with the `JWT_EMAIL_AUTH` key. Here is a minimal config (some values are defaults):

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
    "CODE_SEND_COOLDOWN": timedelta(minutes=1),
    "LOGIN_VALIDATION_AND_DATA_CALLBACK": "path.to.module.function",
}
```

Here are the rest of the settings and what they mean.

| Setting                     | Description                                                                                                                                                                                                    | Type           |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| `SENDING_ON`                | Whether emails<br>should be sent or not.<br>When off, login code is<br>logged instead<br>(for development).                                                                                                    | bool           |
| `SKIP_CODE_CHECKS`          | When True, any<br>code will work in login.                                                                                                                                                                     | bool           |
| `SKIP_CODE_CHECKS_FOR`      | List of emails for<br>which code checks and<br>email sending are off, even<br>if SKIP_CODE_CHECKS=False<br>and/or SENDING_ON=True.<br>Useful for creating review<br>accounts in an otherwise<br>closed system. | list[str]      |
| `ACCESS_TOKEN_LIFETIME`     | How long an access<br>token is valid for.                                                                                                                                                                      | timedelta      |
| `REFRESH_TOKEN_LIFETIME`    | How long a refresh<br>token is valid for.                                                                                                                                                                      | timedelta      |
| `LOGIN_CODE_LIFETIME`       | How long a login<br>code is stored in cache.                                                                                                                                                                   | timedelta      |
| `LOGIN_COOLDOWN`            | After user has<br>exceeded defined number<br>of login attemprs,<br>this is the cooldown<br>until they can attempt<br>login again.                                                                              | timedelta      |
| `CODE_SEND_COOLDOWN`        | After a user has<br>sent a login code,<br>this is the cooldown<br>until they can send<br>one again.                                                                                                            | timedelta      |
| `NOT_BEFORE_TIME`           | How long after the<br>creation of the<br>JWT does it<br>become valid.                                                                                                                                          | timedelta      |
| `ROTATE_REFRESH_TOKENS`     | If True, return a<br>new refresh token<br>when requesting a new<br>access token from<br>RefreshTokenView. The old<br>refresh token will be invalid<br>after the new one is created.                            | bool           |
| `LOGIN_ATTEMPTS`            | Number of login<br>attempts until user<br>is banned.                                                                                                                                                           | int            |
| `EXPECTED_CLAIMS`           | List of expected JWT<br>content.                                                                                                                                                                               | list[str]      |
| `UPDATEABLE_CLAIMS`         | Which expected claims<br>can be updated without<br>re-authentication using<br>the `update` view.                                                                                                               | list[str]      |
| `LOGIN_SENDING_EMAIL`       | Email sender.                                                                                                                                                                                                  | str            |
| `LOGIN_SUBJECT_LINE`        | Email subject line.                                                                                                                                                                                            | str            |
| `LOGIN_EMAIL_MESSAGE`       | Message to send in<br>email. Must have<br>{code} and {valid}!                                                                                                                                                  | str            |
| `LOGIN_EMAIL_HTML_TEMPLATE` | Path to html_message<br>template. Context<br>must have {{ code }}<br>and {{ valid }}!                                                                                                                          | Path           |
| `CACHE_PREFIX`              | Cache prefix.                                                                                                                                                                                                  | str            |
| `OPTIONS_SCHEMA_ACCESS`     | When True (default),<br>OPTIONS requests can<br>be made to the endpoint<br>without token for schema<br>access.                                                                                                 | bool           |
| `CIPHER_KEY`                | If set, JWT will be<br>encrypted with AES in<br>GCM-mode using this as<br>the secret key. Should be<br>either 16, 24, or 32 bytes,<br>encoded to base64.                                                       | str            |
| `ISSUER`                    | Issuer of the JWT.                                                                                                                                                                                             | str            |
| `AUDIENCE`                  | Intended recipient<br>of the JWT.                                                                                                                                                                              | str            |
| `LEEWAY`                    | A time margin in<br>seconds for the<br>expiration check.                                                                                                                                                       | int            |
| `ALGORITHM`                 | Algorithm to sign<br>and decrypt the<br>token with.                                                                                                                                                            | str            |
| `HEADER_PREFIX`             | Authorization scheme<br>used in Authorization header,<br>as in `HEADER_PREFIX token`.                                                                                                                          | str            |
| `EXTRA_HEADERS`             | Additional JWT header<br>fields.                                                                                                                                                                               | dict[str, str] |

These settings should be specified in "dot import notation" to a function, which will be imported as the value for the setting.

| Setting                              | Description                                                             | Arguments                          | Returns        |
|--------------------------------------|-------------------------------------------------------------------------|------------------------------------|----------------|
| `SIGNING_KEY`                        | Function to load<br>JWT signing key.                                    |                                    | ?              |
| `CODE_GENERATOR`                     | Function to generate<br>a login code.                                   |                                    | str            |
| `SEND_LOGIN_CODE_CALLBACK`           | Function that sends<br>the login email.                                 | str,<br>dict[str, Any],<br>Request | None           |
| `LOGIN_VALIDATION_AND_DATA_CALLBACK` | Function to use for<br>validating user and providing<br>login data.     | str                                | dict[str, Any] |
| `LOGIN_BLOCKER_CACHE_KEY_CALLBACK`   | Function to generate<br>cache key for storing user's<br>login attempts. | Request                            | str            |
| `USER_BLOCKED_ADDITIONAL_HANDLER`    | Function for additional<br>handling for blocked users.                  | Request                            | None           |


[IP address spoofing][IP spoofing] prevention settings:

| Setting                | Description                                                                                            | Type                        |
|------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------|
| `PROXY_ORDER`          | Indicate whether the<br>originating client is on<br>the right or left in the<br>X-Forwarded-For header | "left-most"<br>"right-most" |
| `PROXY_COUNT`          | Number of proxies between<br>the server and internet.                                                  | int                         |
| `PROXY_TRUSTED_IPS`    | Only these proxy IPs<br>are allowed connections                                                        | List[str]                   |
| `REQUEST_HEADER_ORDER` | Meta precedence order.                                                                                 | List[str]                   |

Settings when using cookies:

| Setting                   | Description                                                                                                                                                                                               | Type                        |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| `USE_COOKIES`             | If True, use cookies<br>instead of response data<br>to return access and<br>refresh tokens                                                                                                                | bool                        |
| `SET_COOKIE_SECURE`       | Indicates that the<br>cookie is sent to the server<br>only when a request is<br>made with the https: scheme<br>(except on localhost) and<br>therefore, is more resistant to<br>man-in-the-middle attacks. | bool                        |
| `SET_COOKIE_ACCESS_PATH`  | Indicates the path<br>that must exist in the requested<br>URL for the browser<br>to send the access token cookie.                                                                                         | str                         |
| `SET_COOKIE_REFRESH_PATH` | Indicates the path<br>that must exist in the requested<br>URL for the browser<br>to send the refresh token cookie.                                                                                        | str                         |
| `SET_COOKIE_DOMAIN`       | Defines the host to<br>which the cookie will be sent.<br>If None, this attribute<br>defaults to the host of the<br>current document URL, not<br>including subdomains.                                     | str                         |
| `SET_COOKIE_HTTPONLY`     | If True, forbids JavaScript<br>from accessing the cookie.                                                                                                                                                 | bool                        |
| `SET_COOKIE_SAMESITE`     | Controls whether a cookie<br>is sent with cross-origin<br>requests, providing some<br>protection against cross-site<br>request forgery attacks (CSRF).                                                    | "lax"<br>"strict"<br>"none" |


③ Add OpenSSH based [ed25519][ed25519] `SIGNING_KEY` (in PEM format) to environment variables.
You can create one with, e.g., ssh-keygen using the command `ssh-keygen -t ed25519`.
The linebreaks in PEM format should be replaced with | (pipe) characters.
If you do not want to use environment variables, override the `SIGNING_KEY` setting.

> A default signing key is provided for reference in the settings-module,
> but this should be changed in production environments.


④ Configure Django's [email settings][email_settings] (if using django's email sending):

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


⑤ (Optional) Add default `authentication_classes` or `permission_classes`:

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
[IP spoofing]: https://github.com/un33k/django-ipware/blob/master/README.md#advanced-users
