import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt
from django.db import models
from django.db.models import Q


__all__ = ["RefreshTokenRotationLog"]


class RefreshTokenRotationLogManager(models.Manager):
    def remove_by_jti(self, token: str) -> None:
        """Remove token from rotation log based on its jti claim, plus all expired logs."""
        payload = jwt.decode(jwt=token, options={"verify_signature": False})
        jti = int(payload["jti"])
        self.filter(Q(id=jti) | Q(expires_at__lte=datetime.now(tz=timezone.utc))).delete()

    def prune_group_and_expired_logs(self, group: uuid.UUID, id_: Optional[int] = None) -> None:
        """Remove other rotation logs in the given log's group, plus all expired logs."""
        cond = Q(group=group)
        if id_ is not None:
            cond &= ~Q(id=id_)

        cond |= Q(expires_at__lte=datetime.now(tz=timezone.utc))
        self.filter(cond).delete()


class RefreshTokenRotationLog(models.Model):

    id = models.BigAutoField(primary_key=True)
    expires_at = models.DateTimeField(editable=False, help_text="Date and time when the token expires.")
    group = models.UUIDField(editable=False, help_text="Group this refresh token belongs to.")

    objects = RefreshTokenRotationLogManager()
