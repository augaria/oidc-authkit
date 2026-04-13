"""Domain error types for oidc-authkit."""

from __future__ import annotations


class AuthError(Exception):
    """Base error for all auth-related errors."""


class ConfigurationError(AuthError):
    """Invalid configuration."""


class OIDCDiscoveryError(AuthError):
    """Failed to discover OIDC provider metadata."""


class StateMismatchError(AuthError):
    """OIDC state parameter mismatch."""


class NonceMismatchError(AuthError):
    """OIDC nonce mismatch in id_token."""


class TokenValidationError(AuthError):
    """Failed to validate id_token."""


class UserStoreError(AuthError):
    """Error in user store operations."""


class SessionStoreError(AuthError):
    """Error in session store operations."""


class UnauthorizedError(AuthError):
    """User is not authenticated."""


class ForbiddenError(AuthError):
    """User is authenticated but lacks permission."""


class RedirectValidationError(AuthError):
    """Redirect target failed safety validation."""
