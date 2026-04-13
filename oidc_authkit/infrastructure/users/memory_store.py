"""In-memory user store for testing and development."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from oidc_authkit.domain.models import ExternalIdentity, LocalUser


class InMemoryUserStore:
    """Simple in-memory user store — for testing and demos."""

    def __init__(self) -> None:
        self._users: dict[str | int, LocalUser] = {}
        self._index: dict[tuple[str, str], str | int] = {}

    async def get_by_external_identity(
        self, issuer: str, subject: str
    ) -> LocalUser | None:
        uid = self._index.get((issuer, subject))
        if uid is None:
            return None
        return self._users.get(uid)

    async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        user = LocalUser(
            id=user_id,
            issuer=identity.issuer,
            subject=identity.subject,
            email=identity.email,
            username=identity.username,
            display_name=identity.display_name,
            is_active=True,
            created_at=now,
            last_login_at=now,
        )
        self._users[user_id] = user
        self._index[(identity.issuer, identity.subject)] = user_id
        return user

    async def update_from_identity(
        self, user: LocalUser, identity: ExternalIdentity
    ) -> LocalUser:
        user.email = identity.email
        user.username = identity.username
        user.display_name = identity.display_name
        user.last_login_at = datetime.now(timezone.utc)
        return user

    async def get_by_id(self, user_id: str | int) -> LocalUser | None:
        return self._users.get(user_id)
