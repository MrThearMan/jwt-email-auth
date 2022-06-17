import logging
from datetime import datetime, timezone

import jwt
from django.db import models, transaction
from django.db.models import Q

from ..settings import auth_settings
from ..utils import decrypt_with_cipher


__all__ = ["RefreshTokenRotationLog"]


logger = logging.getLogger(__name__)


class RefreshTokenRotationLogManager(models.Manager):
    def remove_by_token_title(self, token: str) -> None:
        """Remove logs with a title matching the given token's "sub" claim, plus all expired logs."""
        if auth_settings.CIPHER_KEY is not None:
            try:
                token = decrypt_with_cipher(token)
            except RuntimeError as error:
                logger.exception("Cannot decrypt token.", exc_info=error)
                return

        payload = jwt.decode(jwt=token, options={"verify_signature": False})
        self.remove_by_title(title=str(payload["sub"]))

    def remove_by_title(self, title: str) -> None:
        """Remove logs with the given title, plus all expired logs."""
        cond = Q(title=title) | Q(expires_at__lte=datetime.now(tz=timezone.utc))
        self.filter(cond).delete()

    @transaction.atomic
    def pass_title(self, title: str, expires_at: datetime) -> "RefreshTokenRotationLog":
        """Remove logs with the given title, plus all expired logs, and then create a new log for the title."""
        self.remove_by_title(title=title)
        log = self.create(title=title, expires_at=expires_at)
        return log


class RefreshTokenRotationLog(models.Model):

    id = models.BigAutoField(primary_key=True)
    expires_at = models.DateTimeField(editable=False, help_text="Date and time when the token expires.")
    title = models.UUIDField(editable=False, help_text="Title this refresh token holds.")

    objects = RefreshTokenRotationLogManager()
