"""FastAPI/Starlette adapter for oidc-authkit."""

from __future__ import annotations

import logging
from typing import Any, Callable

from fastapi import Depends, FastAPI, Request

from oidc_authkit.application.auth_manager import AuthManager
from oidc_authkit.config.models import AuthConfig
from oidc_authkit.domain.errors import ForbiddenError, UnauthorizedError
from oidc_authkit.domain.models import UserContext
from oidc_authkit.hooks.events import AuthEventHooks
from oidc_authkit.infrastructure.utils.urls import SafeRedirectStrategy

logger = logging.getLogger(__name__)

# Key for storing OIDC flow data in cookies (state, nonce, return_to)
_FLOW_COOKIE = "oidc_authkit_flow"


class FastAPIAuth:
    """FastAPI integration for oidc-authkit.

    Usage:
        auth = FastAPIAuth(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="session-secret-key-here",
        )
        auth.init_app(app)
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        base_url: str,
        secret_key: str,
        *,
        user_store: Any | None = None,
        hooks: AuthEventHooks | None = None,
        redirect_strategy: SafeRedirectStrategy | None = None,
        **kwargs: Any,
    ) -> None:
        config = AuthConfig(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            secret_key=secret_key,
            **kwargs,
        )
        self._manager = AuthManager(
            config=config,
            user_store=user_store,
            hooks=hooks,
            redirect_strategy=redirect_strategy,
        )
        self._config = config

    @property
    def manager(self) -> AuthManager:
        return self._manager

    def init_app(self, app: FastAPI) -> None:
        """Register auth routes on a FastAPI application."""
        from oidc_authkit.adapters.fastapi.routes import create_auth_router

        router = create_auth_router(self._manager, self._config)
        app.include_router(router)
        logger.info("FastAPIAuth routes registered")

    async def current_user(self, request: Request) -> UserContext:
        """Get the current user from the request session."""
        cookie_value = request.cookies.get(self._config.cookie_name)
        session_data = {"cookie_value": cookie_value} if cookie_value else {}
        return await self._manager.get_current_user(session_data)

    def require_user(self) -> Callable:
        """FastAPI dependency that requires an authenticated user.

        Usage:
            @app.get("/protected")
            async def protected(user = auth.require_user()):
                ...
        """
        auth_self = self

        async def _dependency(request: Request) -> UserContext:
            user = await auth_self.current_user(request)
            if not user.is_authenticated:
                raise UnauthorizedError("Authentication required")
            return user

        return Depends(_dependency)

    def require_group(self, group: str) -> Callable:
        """FastAPI dependency that requires user to be in a specific group.

        Usage:
            @app.get("/admin")
            async def admin(user = auth.require_group("admins")):
                ...
        """
        auth_self = self

        async def _dependency(request: Request) -> UserContext:
            user = await auth_self.current_user(request)
            if not user.is_authenticated:
                raise UnauthorizedError("Authentication required")
            if group not in user.groups:
                raise ForbiddenError(f"Group '{group}' required")
            return user

        return Depends(_dependency)
