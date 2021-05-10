# JSON Web Token Email Authentiation
```
pip install jwt-email-auth
```
This module enables JSON Web Token Authentication in Django Rest framework without using django's User model at all. In fact, no database interaction is needed at all - everything is stored in [cache](https://docs.djangoproject.com/en/3.2/topics/cache/#the-low-level-cache-api). 

### Requirements:
- [requirements.txt](https://github.com/MrThearMan/jwt-email-auth/blob/main/requirements.txt)
- Django's [CACHES](https://docs.djangoproject.com/en/3.2/ref/settings/#std:setting-CACHES)-setting configured (should be by default).
- Django's [email](https://docs.djangoproject.com/en/3.2/topics/email/#quick-example) settings configured

---

### Authentication is done in two steps:
1. Request login from `SendLoginCode` view.
    - This will send a 6-digit login code to the email given in the POST data.
2. POST the login code and email to `Login` view to get access and refresh tokens.
    - Refresh token is valid for 14 days, access token for 5 minutes

Access and Refresh token lifetimes are configurable in setting.py thought a `JWT` setting dictionary.

Login codes are stay in the cache for 5 minutes by default (configurable with the `JWT` setting).

Access token can be refreshed from `RefreshToken`-view with the Refresh token in POST data. This will respond with a new valid Access token, if the Refresh token is still valid.

Authentication is done with [ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) based public-private signing key authentication. A default signing key is provided, but this should obviously be changed in production environments. Other authentication algorithms can be configured with the `JWT` setting.

Bruteforce attempts to login are handled by an IP based cache record, which will block an IP after 10 login attempts by default (configurable with the `JWT` setting). You can futher configure the proxy settings in your environment to the `JWT` setting for extra security.
