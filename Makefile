export DJANGO_SETTINGS_MODULE = tests.django.settings

.PHONY: help
.PHONY: dev
.PHONY: docs
.PHONY: tests
.PHONY: test
.PHONY: translations
.PHONY: tox
.PHONY: hook
.PHONY: pre-commit
.PHONY: pre-commit-update
.PHONY: mypy
.PHONY: Makefile

# Trick to allow passing commands to make
# Use quotes (" ") if command contains flags (-h / --help)
args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

# If command doesn't match, do not throw error
%:
	@:

define helptext

  Commands:

  dev                  Serve manual testing server
  docs                 Serve mkdocs for development.
  translations         Make and compile translations.
  tests                Run all tests with coverage.
  test <name>          Run all tests maching the given <name>
  tox                  Run all tests with tox.
  hook                 Install pre-commit hook.
  pre-commit           Run pre-commit hooks on all files.
  pre-commit-update    Update all pre-commit hooks to latest versions.
  mypy                 Run mypy on all files.

  Use quotes (" ") if command contains flags (-h / --help)
endef

export helptext

help:
	@echo "$$helptext"

dev:
	@poetry run python manage.py runserver localhost:8000

docs:
	@poetry run mkdocs serve

tests:
	@poetry run coverage run -m pytest -vv -s --log-cli-level=INFO

test:
	@poetry run pytest -s -vv -k $(call args, "")

translations:
	@echo ""
	@echo Making translations...
	@poetry run python manage.py makemessages -l fi -i ".venv*" -i ".tox*"
	@echo ""
	@echo Compiling...
	@poetry run python manage.py compilemessages -i ".tox*" -i ".venv*"
	@echo ""
	@echo Done!

tox:
	@poetry run tox

hook:
	@poetry run pre-commit install

pre-commit:
	@poetry run pre-commit run --all-files

pre-commit-update:
	@poetry run pre-commit autoupdate

mypy:
	@poetry run mypy jwt_email_auth/
