"""Auth event hooks — extensible lifecycle callbacks."""

from __future__ import annotations

import logging

from oidc_authkit.domain.models import ExternalIdentity, LocalUser

logger = logging.getLogger(__name__)


class AuthEventHooks:
    """Default (no-op) event hooks. Subclass to add custom behavior."""

    async def on_login_start(self) -> None:
        logger.debug("login_start")

    async def on_login_success(
        self, user: LocalUser, identity: ExternalIdentity
    ) -> None:
        logger.debug("login_success: user=%s", user.id)

    async def on_login_failure(self, reason: str = "") -> None:
        logger.debug("login_failure: reason=%s", reason)

    async def on_user_created(self, user: LocalUser) -> None:
        logger.debug("user_created: user=%s", user.id)

    async def on_user_updated(self, user: LocalUser) -> None:
        logger.debug("user_updated: user=%s", user.id)

    async def on_logout(self) -> None:
        logger.debug("logout")
