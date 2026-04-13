"""Nonce management for OIDC id_token verification."""

from __future__ import annotations

import secrets


class NonceManager:
    """Generates nonce values for OIDC id_token binding."""

    def generate(self) -> str:
        """Generate a cryptographically secure nonce."""
        return secrets.token_urlsafe(32)
