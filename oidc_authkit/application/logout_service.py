"""Logout service — clears local session and terminates OIDC provider session."""

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

        Logout strategy (in priority order):
        1. OIDC RP-Initiated Logout — if provider exposes end_session_endpoint
           in discovery, redirect there with id_token_hint + post_logout_redirect_uri.
        2. Provider native logout — fall back to {issuer}/logout?rd={redirect_uri}.
           Works with Authelia and other providers that accept an `rd` parameter.

        Returns dict with:
            - redirect_to: post-logout redirect target
            - clear_cookie: cookie name to clear
        """
        await self._hooks.on_logout()
        logger.info("User logged out")

        post_logout_uri = self._config.base_url.rstrip("/") + self._config.post_logout_redirect_path

        # Extract id_token from session (for id_token_hint)
        id_token = None
        if session_data:
            principal = await self._session_store.get(session_data)
            if principal and principal.id_token:
                id_token = principal.id_token

        # Strategy 1: OIDC RP-Initiated Logout (standard end_session_endpoint)
        try:
            end_session_endpoint = await self._oidc.get_end_session_endpoint()
        except Exception:
            end_session_endpoint = None

        if end_session_endpoint:
            params: dict[str, str] = {
                "post_logout_redirect_uri": post_logout_uri,
            }
            if id_token:
                params["id_token_hint"] = id_token
            redirect_to = f"{end_session_endpoint}?{urlencode(params)}"
            logger.info("RP-Initiated Logout: redirecting to OIDC provider end_session_endpoint")
        else:
            # Strategy 2: Provider native logout with rd redirect parameter
            issuer = self._config.issuer.rstrip("/")
            redirect_to = f"{issuer}/logout?{urlencode({'rd': post_logout_uri})}"
            logger.info("Fallback logout: redirecting to provider native logout at %s", redirect_to)

        return {
            "redirect_to": redirect_to,
            "clear_cookie": self._config.cookie_name,
        }
