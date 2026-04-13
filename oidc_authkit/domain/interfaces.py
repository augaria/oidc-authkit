"""Abstract interfaces for oidc-authkit domain layer."""

from __future__ import annotations

from typing import Any, Protocol

from oidc_authkit.domain.models import (
    Claims,
    ExternalIdentity,
    LocalUser,
    SessionPrincipal,
    TokenSet,
    UserContext,
    PermissionRequirement,
)


class SessionStore(Protocol):
    """Abstract session store interface."""

    async def get(self, session_data: dict[str, Any]) -> SessionPrincipal | None:
        """Retrieve session principal from session data."""
        ...

    async def save(self, principal: SessionPrincipal) -> dict[str, Any]:
        """Serialize principal to session data dict."""
        ...


class UserStore(Protocol):
    """Abstract user store interface."""

    async def get_by_external_identity(self, issuer: str, subject: str) -> LocalUser | None:
        """Find local user by external identity."""
        ...

    async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
        """Create a new local user from external identity."""
        ...

    async def update_from_identity(
        self, user: LocalUser, identity: ExternalIdentity
    ) -> LocalUser:
        """Update local user from external identity."""
        ...

    async def get_by_id(self, user_id: str | int) -> LocalUser | None:
        """Find local user by ID."""
        ...


class OIDCClient(Protocol):
    """Abstract OIDC client interface."""

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
        scopes: list[str],
    ) -> str:
        """Build an OIDC authorization URL."""
        ...

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> TokenSet:
        """Exchange authorization code for tokens."""
        ...

    async def parse_id_token(
        self,
        token_set: TokenSet,
        nonce: str,
    ) -> Claims:
        """Parse and validate id_token, returning claims."""
        ...

    async def fetch_userinfo(self, token_set: TokenSet) -> dict[str, Any]:
        """Fetch userinfo from OIDC provider."""
        ...


class RedirectStrategy(Protocol):
    """Controls post-login redirect behavior with open redirect protection."""

    def validate_redirect_target(self, target: str, base_url: str) -> str:
        """Validate and return a safe redirect target. Returns fallback on failure."""
        ...


class PermissionEvaluator(Protocol):
    """Evaluates whether a user satisfies a permission requirement."""

    async def has_permission(
        self, user: UserContext, requirement: PermissionRequirement
    ) -> bool:
        ...
