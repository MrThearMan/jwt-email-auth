export DJANGO_SETTINGS_MODULE = tests.django.settings

.PHONY: help dev serve-docs build-docs submit-docs translations tests test tox hook pre-commit black isort pylint flake8 mypy Makefile

# Trick to allow passing commands to make
# Use quotes (" ") if command contains flags (-h / --help)
args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

# If command doesn't match, do not throw error
%:
	@:

help:
	@echo ""
	@echo "Commands:"
	@echo "  dev              Serve manual testing server on 127.0.0.1:8080."
	@echo "  docs       	  Serve mkdocs on 127.0.0.1:8000 for development."
	@echo "  translations     Make and compile translations."
	@echo "  tests            Run all tests"
	@echo "  test <name>      Run tests maching the given <name>"
	@echo "  tox              Run tests with tox."
	@echo "  hook             Install pre-commit hook."
	@echo "  pre-commit       Run pre-commit hooks on all files."
	@echo "  black            Run black on all files."
	@echo "  isort            Run isort on all files."
	@echo "  pylink           Run pylint on all files."
	@echo "  flake8           Run flake8 on all files."
	@echo "  mypy             Run mypy on all files."

dev:
	@poetry run python manage.py runserver 127.0.0.1:8080

docs:
	@poetry run mkdocs serve

tox:
	@poetry run tox

tests:
	@poetry run coverage run -m pytest -vv -s --log-cli-level=INFO

test:
	@poetry run pytest -s -vv -k $(call args, "")

translations:
	@echo ""
	@echo Making translations...
	@poetry run python manage.py makemessages -l fi --ignore=.venv/* --ignore=.tox/*
	@echo ""
	@echo Compiling...
	@poetry run python manage.py compilemessages --ignore=.venv/* --ignore=.tox/*
	@echo ""
	@echo Done!

hook:
	@poetry run pre-commit install

pre-commit:
	@poetry run pre-commit run --all-files

black:
	@poetry run black .

isort:
	@poetry run isort .

pylint:
	@poetry run pylint jwt_email_auth/

flake8:
	@poetry run flake8 --max-line-length=120 --extend-ignore=E203,E501 jwt_email_auth/

mypy:
	@poetry run mypy jwt_email_auth/
