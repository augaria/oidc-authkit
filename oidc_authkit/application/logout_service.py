"""Logout service — clears the local session."""

from __future__ import annotations

import logging

from oidc_authkit.config.models import AuthConfig
from oidc_authkit.hooks.events import AuthEventHooks

logger = logging.getLogger(__name__)


class LogoutService:
    """Handles local session logout."""

    def __init__(self, config: AuthConfig, hooks: AuthEventHooks) -> None:
        self._config = config
        self._hooks = hooks

    async def logout(self) -> dict:
        """Clear session and return logout data.

        Returns dict with:
            - redirect_to: post-logout redirect target
            - clear_cookie: cookie name to clear
        """
        await self._hooks.on_logout()
        logger.info("User logged out")

        return {
            "redirect_to": self._config.post_logout_redirect_path,
            "clear_cookie": self._config.cookie_name,
        }
