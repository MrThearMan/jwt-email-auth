# JSON Web Token Email Authentication

[![Coverage Status][coverage-badge]][coverage]
[![GitHub Workflow Status][status-badge]][status]
[![PyPI][pypi-badge]][pypi]
[![GitHub][licence-badge]][licence]
[![GitHub Last Commit][repo-badge]][repo]
[![GitHub Issues][issues-badge]][issues]
[![Downloads][downloads-badge]][pypi]

[![Python Version][version-badge]][pypi]
[![Django Version][django-badge]][pypi]
[![DRF Version][drf-badge]][pypi]

```shell
pip install jwt-email-auth
```

---

**Documentation**: [https://mrthearman.github.io/jwt-email-auth/](https://mrthearman.github.io/jwt-email-auth/)

**Source Code**: [https://github.com/MrThearMan/jwt-email-auth/](https://github.com/MrThearMan/jwt-email-auth/)

---


This module enables JSON Web Token Authentication in Django Rest framework without using Django's User model.
Instead, login information is stored in [cache][cache], a login code is sent to the user's email inbox,
and then the cached information is obtained using the code that was sent to the given email.


[cache]: https://docs.djangoproject.com/en/3.2/topics/cache/#the-low-level-cache-api

[coverage-badge]: https://coveralls.io/repos/github/MrThearMan/jwt-email-auth/badge.svg?branch=main
[status-badge]: https://img.shields.io/github/workflow/status/MrThearMan/jwt-email-auth/Test
[pypi-badge]: https://img.shields.io/pypi/v/jwt-email-auth
[licence-badge]: https://img.shields.io/github/license/MrThearMan/jwt-email-auth
[repo-badge]: https://img.shields.io/github/last-commit/MrThearMan/jwt-email-auth
[issues-badge]: https://img.shields.io/github/issues-raw/MrThearMan/jwt-email-auth
[version-badge]: https://img.shields.io/pypi/pyversions/jwt-email-auth
[downloads-badge]: https://img.shields.io/pypi/dm/jwt-email-auth
[django-badge]: https://img.shields.io/pypi/djversions/jwt-email-auth
[drf-badge]: https://img.shields.io/badge/drf%20versions-3.12.0%20--%203.13.0-blue

[coverage]: https://coveralls.io/github/MrThearMan/jwt-email-auth?branch=main
[status]: https://github.com/MrThearMan/jwt-email-auth/actions/workflows/test.yml
[pypi]: https://pypi.org/project/jwt-email-auth
[licence]: https://github.com/MrThearMan/jwt-email-auth/blob/main/LICENSE
[repo]: https://github.com/MrThearMan/jwt-email-auth/commits/main
[issues]: https://github.com/MrThearMan/jwt-email-auth/issues
