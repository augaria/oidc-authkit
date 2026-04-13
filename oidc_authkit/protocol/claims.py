"""Claims extraction and mapping from OIDC tokens."""

from __future__ import annotations

from typing import Any

from oidc_authkit.config.models import UserMappingConfig
from oidc_authkit.domain.models import Claims, ExternalIdentity


def extract_claims(raw: dict[str, Any]) -> Claims:
    """Extract structured claims from raw OIDC claims dict."""
    groups = raw.get("groups", [])
    if isinstance(groups, str):
        groups = [groups]

    return Claims(
        issuer=raw.get("iss", ""),
        subject=raw.get("sub", ""),
        email=raw.get("email"),
        email_verified=raw.get("email_verified"),
        preferred_username=raw.get("preferred_username"),
        name=raw.get("name"),
        groups=groups,
        raw=raw,
    )


def claims_to_identity(claims: Claims, config: UserMappingConfig) -> ExternalIdentity:
    """Convert Claims to ExternalIdentity using mapping config."""
    return ExternalIdentity(
        issuer=claims.issuer,
        subject=claims.subject,
        email=claims.raw.get(config.email_claim),
        username=claims.raw.get(config.username_claim),
        display_name=claims.raw.get(config.display_name_claim),
        groups=claims.raw.get(config.groups_claim, []),
        claims=claims,
    )
