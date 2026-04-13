"""Domain models for oidc-authkit."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Claims:
    """Parsed OIDC claims from id_token / userinfo."""

    issuer: str
    subject: str
    email: str | None = None
    email_verified: bool | None = None
    preferred_username: str | None = None
    name: str | None = None
    groups: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExternalIdentity:
    """Identity as provided by the OIDC provider."""

    issuer: str
    subject: str
    email: str | None = None
    username: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)
    claims: Claims | None = None


@dataclass
class LocalUser:
    """Application-local user entity."""

    id: str | int
    issuer: str
    subject: str
    email: str | None
    username: str | None
    display_name: str | None
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionPrincipal:
    """Minimal identity stored in session."""

    local_user_id: str | int
    issuer: str
    subject: str
    auth_time: float
    session_version: int = 1


@dataclass
class UserContext:
    """Current user context exposed to application code."""

    is_authenticated: bool
    local_user: LocalUser | None = None
    external_identity: ExternalIdentity | None = None
    groups: list[str] = field(default_factory=list)


@dataclass
class TokenSet:
    """Token set returned from code exchange."""

    access_token: str
    token_type: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionRequirement:
    """A permission requirement that can be evaluated."""

    requirement_type: str
    value: str
