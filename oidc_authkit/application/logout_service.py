"""Logout service — clears local session and builds RP-Initiated Logout URL."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from oidc_authkit.config.models import AuthConfig
from oidc_authkit.hooks.events import AuthEventHooks
from oidc_authkit.infrastructure.oidc.authlib_client import AuthlibOIDCClient
from oidc_authkit.infrastructure.session.cookie_store import CookieSessionStore

logger = logging.getLogger(__name__)


class LogoutService:
    """Handles local session logout and OIDC provider-side session termination."""

    def __init__(
        self,
        config: AuthConfig,
        hooks: AuthEventHooks,
        oidc_client: AuthlibOIDCClient,
        session_store: CookieSessionStore,
    ) -> None:
        self._config = config
        self._hooks = hooks
        self._oidc = oidc_client
        self._session_store = session_store

    async def logout(self, session_data: dict | None = None) -> dict:
        """Clear session and return logout data.

        If the OIDC provider supports end_session_endpoint and we have an
        id_token from the session, redirect to the provider to end the SSO
        session (RP-Initiated Logout). Otherwise fall back to local-only logout.

        Returns dict with:
            - redirect_to: post-logout redirect target (may be the provider's end_session URL)
            - clear_cookie: cookie name to clear
        """
        await self._hooks.on_logout()
        logger.info("User logged out")

        redirect_to = self._config.post_logout_redirect_path

        # Try RP-Initiated Logout: redirect to provider's end_session_endpoint
        id_token = None
        if session_data:
            principal = await self._session_store.get(session_data)
            if principal and principal.id_token:
                id_token = principal.id_token

        try:
            end_session_endpoint = await self._oidc.get_end_session_endpoint()
        except Exception:
            end_session_endpoint = None

        if end_session_endpoint and id_token:
            post_logout_uri = self._config.base_url.rstrip("/") + self._config.post_logout_redirect_path
            params = {
                "id_token_hint": id_token,
                "post_logout_redirect_uri": post_logout_uri,
            }
            redirect_to = f"{end_session_endpoint}?{urlencode(params)}"
            logger.info("RP-Initiated Logout: redirecting to OIDC provider")

        return {
            "redirect_to": redirect_to,
            "clear_cookie": self._config.cookie_name,
        }
