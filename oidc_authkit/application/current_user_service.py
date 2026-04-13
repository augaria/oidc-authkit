"""Current user service — resolves the current user from session."""

from __future__ import annotations

import logging
from typing import Any

from oidc_authkit.domain.models import ExternalIdentity, UserContext
from oidc_authkit.infrastructure.session.cookie_store import CookieSessionStore

logger = logging.getLogger(__name__)


class CurrentUserService:
    """Resolves the current user context from session data."""

    def __init__(
        self,
        session_store: CookieSessionStore,
        user_store: object,  # UserStore protocol
    ) -> None:
        self._session_store = session_store
        self._user_store = user_store

    async def get_current_user(self, session_data: dict[str, Any]) -> UserContext:
        """Get the currently authenticated user, or an anonymous context."""
        principal = await self._session_store.get(session_data)
        if principal is None:
            return UserContext(is_authenticated=False)

        local_user = await self._user_store.get_by_id(principal.local_user_id)
        if local_user is None:
            logger.warning(
                "Session references non-existent user %s", principal.local_user_id
            )
            return UserContext(is_authenticated=False)

        if not local_user.is_active:
            logger.warning("User %s is inactive", local_user.id)
            return UserContext(is_authenticated=False)

        identity = ExternalIdentity(
            issuer=principal.issuer,
            subject=principal.subject,
        )

        return UserContext(
            is_authenticated=True,
            local_user=local_user,
            external_identity=identity,
            groups=local_user.extra.get("groups", []),
        )
