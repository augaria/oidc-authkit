"""Login service — initiates OIDC authorization flow."""

from __future__ import annotations

import logging

from oidc_authkit.config.models import AuthConfig
from oidc_authkit.infrastructure.oidc.authlib_client import AuthlibOIDCClient
from oidc_authkit.infrastructure.utils.urls import build_callback_url
from oidc_authkit.protocol.nonce import NonceManager
from oidc_authkit.protocol.state import StateManager

logger = logging.getLogger(__name__)


class LoginService:
    """Initiates the OIDC authorization flow."""

    def __init__(
        self,
        config: AuthConfig,
        oidc_client: AuthlibOIDCClient,
        state_manager: StateManager,
        nonce_manager: NonceManager,
    ) -> None:
        self._config = config
        self._oidc = oidc_client
        self._state_mgr = state_manager
        self._nonce_mgr = nonce_manager

    async def initiate_login(self, return_to: str | None = None) -> dict:
        """Build authorization redirect data.

        Returns a dict with:
            - authorization_url: the URL to redirect the user to
            - state: the generated state value
            - nonce: the generated nonce value
            - return_to: validated return target
        """
        state = self._state_mgr.generate()
        nonce = self._nonce_mgr.generate()
        redirect_uri = build_callback_url(self._config.base_url, self._config.callback_path)

        authorization_url = await self._oidc.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            scopes=self._config.scopes,
        )

        logger.info("Login initiated, redirecting to OIDC provider")

        return {
            "authorization_url": authorization_url,
            "state": state,
            "nonce": nonce,
            "return_to": return_to or "/",
        }
