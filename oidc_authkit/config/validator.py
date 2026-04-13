"""Configuration validation utilities."""

from __future__ import annotations

from urllib.parse import urlparse

from oidc_authkit.config.models import AuthConfig
from oidc_authkit.domain.errors import ConfigurationError


def validate_config(config: AuthConfig) -> None:
    """Validate an AuthConfig, raising ConfigurationError on problems."""
    errors: list[str] = []

    # Validate base_url
    parsed = urlparse(config.base_url)
    if not parsed.scheme or not parsed.netloc:
        errors.append(f"base_url must be a valid URL with scheme and host, got: {config.base_url}")

    if config.require_https and parsed.scheme != "https":
        errors.append(
            f"base_url must use https when require_https=True, got: {config.base_url}"
        )

    # Validate issuer
    issuer_parsed = urlparse(config.issuer)
    if not issuer_parsed.scheme or not issuer_parsed.netloc:
        errors.append(f"issuer must be a valid URL, got: {config.issuer}")

    # Validate paths
    for name, path in [
        ("callback_path", config.callback_path),
        ("login_path", config.login_path),
        ("logout_path", config.logout_path),
    ]:
        if not path.startswith("/"):
            errors.append(f"{name} must start with '/', got: {path}")

    # Validate secret_key length
    if len(config.secret_key) < 16:
        errors.append("secret_key must be at least 16 characters long")

    # Validate scopes
    if "openid" not in config.scopes:
        errors.append("scopes must include 'openid'")

    if errors:
        raise ConfigurationError(
            "Invalid auth configuration:\n" + "\n".join(f"  - {e}" for e in errors)
        )
