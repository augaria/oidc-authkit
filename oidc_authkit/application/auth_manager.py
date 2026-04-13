"""AuthManager — high-level facade that assembles all auth components."""

from __future__ import annotations

import logging
from typing import Any

from oidc_authkit.application.callback_service import CallbackService
from oidc_authkit.application.current_user_service import CurrentUserService
from oidc_authkit.application.login_service import LoginService
from oidc_authkit.application.logout_service import LogoutService
from oidc_authkit.config.models import AuthConfig
from oidc_authkit.config.validator import validate_config
from oidc_authkit.domain.models import UserContext
from oidc_authkit.hooks.events import AuthEventHooks
from oidc_authkit.infrastructure.oidc.authlib_client import AuthlibOIDCClient
from oidc_authkit.infrastructure.session.cookie_store import CookieSessionStore
from oidc_authkit.infrastructure.users.memory_store import InMemoryUserStore
from oidc_authkit.infrastructure.utils.urls import SafeRedirectStrategy
from oidc_authkit.protocol.nonce import NonceManager
from oidc_authkit.protocol.state import StateManager

logger = logging.getLogger(__name__)


class AuthManager:
    """High-level facade for the auth system.

    Assembles config, services, and infrastructure. Framework adapters
    delegate to this class.
    """

    def __init__(
        self,
        config: AuthConfig,
        session_store: CookieSessionStore | None = None,
        user_store: Any | None = None,
        oidc_client: AuthlibOIDCClient | None = None,
        redirect_strategy: SafeRedirectStrategy | None = None,
        hooks: AuthEventHooks | None = None,
    ) -> None:
        validate_config(config)
        self.config = config

        self.hooks = hooks or AuthEventHooks()

        # Infrastructure
        self.oidc_client = oidc_client or AuthlibOIDCClient(config.to_oidc_config())
        self.session_store = session_store or CookieSessionStore(config.to_session_config())
        self.user_store = user_store or InMemoryUserStore()
        self.redirect_strategy = redirect_strategy or SafeRedirectStrategy()

        # Protocol
        self.state_manager = StateManager(config.secret_key)
        self.nonce_manager = NonceManager()

        # Application services
        self.login_service = LoginService(
            config=config,
            oidc_client=self.oidc_client,
            state_manager=self.state_manager,
            nonce_manager=self.nonce_manager,
        )
        self.callback_service = CallbackService(
            config=config,
            oidc_client=self.oidc_client,
            state_manager=self.state_manager,
            session_store=self.session_store,
            user_store=self.user_store,
            redirect_strategy=self.redirect_strategy,
            hooks=self.hooks,
        )
        self.current_user_service = CurrentUserService(
            session_store=self.session_store,
            user_store=self.user_store,
        )
        self.logout_service = LogoutService(
            config=config,
            hooks=self.hooks,
        )

        logger.info("AuthManager initialized for %s", config.base_url)

    async def initiate_login(self, return_to: str | None = None) -> dict:
        """Start the OIDC login flow."""
        return await self.login_service.initiate_login(return_to=return_to)

    async def handle_callback(
        self,
        code: str,
        state: str,
        stored_state: str,
        stored_nonce: str,
        stored_return_to: str | None = None,
    ) -> dict:
        """Handle the OIDC callback."""
        return await self.callback_service.handle_callback(
            code=code,
            state=state,
            stored_state=stored_state,
            stored_nonce=stored_nonce,
            stored_return_to=stored_return_to,
        )

    async def get_current_user(self, session_data: dict[str, Any]) -> UserContext:
        """Get the current user context."""
        return await self.current_user_service.get_current_user(session_data)

    async def logout(self) -> dict:
        """Logout and clear session."""
        return await self.logout_service.logout()
