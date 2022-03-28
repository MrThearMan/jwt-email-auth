from os import environ
from pathlib import Path

from django.core.management.utils import get_random_secret_key


BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = get_random_secret_key()
DEBUG = True
ALLOWED_HOSTS = []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR / "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "django" / "db.sqlite3",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "nice",
        },
    },
    "formatters": {
        "nice": {
            "format": "[{asctime}] {module}.{funcName}: <{levelname}> {message}",
            "datefmt": "%d/%b/%Y %H:%M:%S",
            "style": "{",
        }
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

ROOT_URLCONF = "tests.django.urls"
WSGI_APPLICATION = "tests.django.wsgi.application"
LANGUAGE_CODE = "en-us"
LANGUAGES = [("en", "English"), ("fi", "Finland")]
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True
STATIC_URL = "/static/"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
DEFAULT_FROM_EMAIL = SERVER_EMAIL = EMAIL_HOST_USER = "lamppu.matti.akseli@gmail.com"
EMAIL_HOST_PASSWORD = environ.get("GOOGLE_APP_PASSWORD")
EMAIL_USE_TLS = True
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"


JWT_EMAIL_AUTH = {
    "SENDING_ON": False,
}

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [],
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
}

# REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"].insert(0, "rest_framework.renderers.BrowsableAPIRenderer")
