"""Python utility functions, that have nothing to do with the Dynamics database."""

import logging
from typing import Optional, List
from threading import Thread

from django.core import mail
from django.core.mail.backends.base import BaseEmailBackend


__all__ = [
    "send_threaded_mail",
]


logger = logging.getLogger(__name__)


class EmailThread(Thread):
    """Spin a simple email sending thread."""

    def __init__(
        self,
        subject: str,
        message: str,
        from_email: Optional[str],
        recipient_list: List[str],
        fail_silently: bool = False,
        auth_user: str = None,
        auth_password: str = None,
        connection: "BaseEmailBackend" = None,
        html_message: str = None,
    ):
        self.subject = subject
        self.message = message
        self.recipient_list = recipient_list
        self.fail_silently = fail_silently
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.from_email = from_email
        self.connection = connection
        self.html_message = html_message
        Thread.__init__(self)

    def run(self):
        try:
            mail.send_mail(
                subject=self.subject,
                message=self.message,
                from_email=self.from_email,
                recipient_list=self.recipient_list,
                fail_silently=self.fail_silently,
                auth_user=self.auth_user,
                auth_password=self.auth_password,
                connection=self.connection,
                html_message=self.html_message,
            )
        except Exception as e:  # noqa
            logger.error(f"Could not send email: {e}")


def send_threaded_mail(
    subject: str,
    message: str,
    from_email: Optional[str],
    recipient_list: List[str],
    fail_silently: bool = False,
    auth_user: str = None,
    auth_password: str = None,
    connection: "BaseEmailBackend" = None,
    html_message: str = None,
):
    """Send an email in the background using the builtin threading module.

    :param subject: Subject of the email
    :param message: Email message in plain form.
    :param from_email: Sending email address. If None, uses settings.DEFAULT_FROM_EMAIL.
    :param recipient_list: List of email to send to.
    :param fail_silently: Should email sending errors not be shown?
    :param auth_user: Email sender login username. If None, uses settings.EMAIL_HOST_USER.
    :param auth_password: Email sender login password. If None, uses settings.EMAIL_HOST_PASSWORD.
    :param connection: An already established email backend connection.
                       If None, creates one from auth_user and auth_password.
    :param html_message: Email message in HTML form. Use tables for layout and inline css for styling.
                         Falls back to message if recipient's email client cant read HTML.
    """

    EmailThread(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=recipient_list,
        fail_silently=fail_silently,
        auth_user=auth_user,
        auth_password=auth_password,
        connection=connection,
        html_message=html_message,
    ).start()
