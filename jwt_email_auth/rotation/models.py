from datetime import datetime, timezone

import jwt
from django.db import models
from django.db.models import Q


__all__ = ["RefreshTokenRotationLog"]


class RefreshTokenRotationLogManager(models.Manager):
    def remove_by_jti(self, token: str) -> None:
        """Remove token from rotation log based on its jti claim."""
        payload = jwt.decode(jwt=token, options={"verify_signature": False})
        jti = int(payload["jti"])
        self.filter(id=jti).delete()

    def prune_group_and_expired_logs(self, log: "RefreshTokenRotationLog") -> None:
        """Remove other rotation logs in the given log's group, and all other groups' expired logs."""
        self.filter((Q(group=log.group) & ~Q(id=log.id)) | Q(expires_at__lte=datetime.now(tz=timezone.utc))).delete()


class RefreshTokenRotationLog(models.Model):

    id = models.BigAutoField(primary_key=True)
    expires_at = models.DateTimeField(editable=False, help_text="Date and time when the token expires.")
    group = models.UUIDField(editable=False, help_text="Group this refresh token belongs to.")

    objects = RefreshTokenRotationLogManager()
