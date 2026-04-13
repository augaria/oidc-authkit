"""oidc-authkit: Universal Python OIDC authentication package for Authelia integration."""

from oidc_authkit.config.models import AuthConfig, SessionConfig, UserMappingConfig
from oidc_authkit.domain.models import (
    Claims,
    ExternalIdentity,
    LocalUser,
    SessionPrincipal,
    UserContext,
)
from oidc_authkit.domain.errors import (
    AuthError,
    ConfigurationError,
    ForbiddenError,
    UnauthorizedError,
)

__all__ = [
    "AuthConfig",
    "SessionConfig",
    "UserMappingConfig",
    "Claims",
    "ExternalIdentity",
    "LocalUser",
    "SessionPrincipal",
    "UserContext",
    "AuthError",
    "ConfigurationError",
    "ForbiddenError",
    "UnauthorizedError",
]

__version__ = "0.1.0"
