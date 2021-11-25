
export DJANGO_SETTINGS_MODULE = tests.django.settings

.PHONY: help dev-setup dev-server dev-docs build-docs submit-docs lock tests test tox pre-commit black isort pylint flake8 mypy Makefile

# Trick to allow passing commands to make
# Use quotes (" ") if command contains flags (-h / --help)
args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

# If command doesn't match, do not throw error
%:
	@:

help:
	@echo ""
	@echo "Commands:"
	@echo "  dev-setup        Install poetry, the virtual environment, and pre-commit hook."
	@echo "  dev-server       Serve manual testing server on 127.0.0.1:8080."
	@echo "  dev-docs         Serve mkdocs on 127.0.0.1:8000 for development."
	@echo "  build-docs       Build documentation site."
	@echo "  submit-docs      Sumbit docs to github pages."
	@echo "  lock             Resolve dependencies into the poetry lock-file."
	@echo "  tests            Run tests with pytest-cov."
	@echo "  test <name>      Run tests maching the given <name>"
	@echo "  tox              Run tests with tox."
	@echo "  pre-commit       Run pre-commit hooks on all files."
	@echo "  black            Run black on all files."
	@echo "  isort            Run isort on all files."
	@echo "  pylink           Run pylint on all files."
	@echo "  flake8           Run flake8 on all files."
	@echo "  mypy             Run mypy on all files."

dev-setup:
	@echo "If this fails, you may need to add Poetry's install directory to PATH and re-run this script."
	@timeout 3
	@curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python -
	@poetry install
	@poetry run pre-commit install

lock:
	@poetry lock

tox:
	@poetry run tox

test:
	@poetry run pytest -s -vv -k $(call args, "")

tests:
	@poetry run coverage run pytest -vv -s --log-cli-level=INFO

dev-server:
	@poetry run python manage.py runserver 127.0.0.1:8080

dev-docs:
	@poetry run mkdocs serve

build-docs:
	@poetry run mkdocs build

submit-docs:
	@poetry run mkdocs gh-deploy

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
