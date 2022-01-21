# JSON Web Token Email Authentiation

[![Coverage Status](https://coveralls.io/repos/github/MrThearMan/jwt-email-auth/badge.svg?branch=main)](https://coveralls.io/github/MrThearMan/jwt-email-auth?branch=main)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/MrThearMan/jwt-email-auth/Tests)](https://github.com/MrThearMan/jwt-email-auth/actions/workflows/main.yml)
[![PyPI](https://img.shields.io/pypi/v/jwt-email-auth)](https://pypi.org/project/jwt-email-auth)
[![GitHub](https://img.shields.io/github/license/MrThearMan/jwt-email-auth)](https://github.com/MrThearMan/jwt-email-auth/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/MrThearMan/jwt-email-auth)](https://github.com/MrThearMan/jwt-email-auth/commits/main)
[![GitHub issues](https://img.shields.io/github/issues-raw/MrThearMan/jwt-email-auth)](https://github.com/MrThearMan/jwt-email-auth/issues)


[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/jwt-email-auth)](https://pypi.org/project/jwt-email-auth)
[![PyPI - Django Version](https://img.shields.io/pypi/djversions/jwt-email-auth)](https://pypi.org/project/jwt-email-auth)

```shell
pip install jwt-email-auth
```

---

**Documentation**: [https://mrthearman.github.io/jwt-email-auth/](https://mrthearman.github.io/jwt-email-auth/)

**Source Code**: [https://github.com/MrThearMan/jwt-email-auth](https://github.com/MrThearMan/jwt-email-auth)

---

This module enables JSON Web Token Authentication in Django Rest framework without using Django's User model.
Instead, login information is stored in [cache](https://docs.djangoproject.com/en/3.2/topics/cache/#the-low-level-cache-api),
a login code is sent to the user's email inbox, and then the cached information is obtained
using the code that was sent to the given email.
