# JWT rotation

The library comes with a builtin [Refresh token rotation][jwt-rotation] system.
This can be used to also return a new refresh token from the token refresh endpoint,
and keep a log of the currently active token (a whitelist) via an inherited "title".
Then, if a user, whether the real one or a malicious third party, tries to use a
refresh token with that title, but that is currently not the active token in the log,
all tokens with the given title will be invalidated. This strategy can help protect
the old tokens from being reused.

To use rotated refresh tokens, add the following settings:

```python
INSTALLED_APPS = [
    ...
    "jwt_email_auth.rotation",
    ...
]

JWT_EMAIL_AUTH = {
    ...
    "ROTATE_REFRESH_TOKENS": True,
    ...
}
```

Now you need to apply migration. Then, optionally, you can use the
`logout` view to invalidate your refresh token when the user logs out.
You might even consider using the `update` view to allow updating token
claims after they are created.

```python
from django.urls import path
from jwt_email_auth.views import LogoutView, UpdateTokenView

urlpatterns = [
    ...
    path("logout/", LogoutView.as_view(), name="logout"),
    path("update/", UpdateTokenView.as_view(), name="update"),
    ...
]
```

> Please think carefully the security implications of
> allowing token claims to be updated without re-authentication!
> You can control, which claims can be updated with the
> `UPDATEABLE_CLAIMS` setting.


[jwt-rotation]: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
