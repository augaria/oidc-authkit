"""Tests for configuration models and validator."""

import pytest

from oidc_authkit.config.models import AuthConfig, OIDCConfig, SessionConfig, UserMappingConfig
from oidc_authkit.config.validator import validate_config
from oidc_authkit.domain.errors import ConfigurationError


class TestAuthConfig:
    def test_basic_creation(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret123",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "myapp"
        assert config.callback_path == "/oidc/callback"
        assert config.login_path == "/oidc/login"
        assert config.logout_path == "/oidc/logout"
        assert "openid" in config.scopes

    def test_discovery_url_auto_generated(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        assert (
            config.discovery_url
            == "https://auth.example.com/.well-known/openid-configuration"
        )

    def test_discovery_url_strips_trailing_slash(self):
        config = AuthConfig(
            issuer="https://auth.example.com/",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        assert (
            config.discovery_url
            == "https://auth.example.com/.well-known/openid-configuration"
        )

    def test_discovery_url_custom(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
            discovery_url="https://auth.example.com/custom-discovery",
        )
        assert config.discovery_url == "https://auth.example.com/custom-discovery"

    def test_to_oidc_config(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        oidc = config.to_oidc_config()
        assert isinstance(oidc, OIDCConfig)
        assert oidc.issuer == config.issuer
        assert oidc.client_id == config.client_id

    def test_to_session_config(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        session = config.to_session_config()
        assert isinstance(session, SessionConfig)
        assert session.secret_key == config.secret_key

    def test_to_user_mapping_config(self):
        config = AuthConfig(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        mapping = config.to_user_mapping_config()
        assert isinstance(mapping, UserMappingConfig)
        assert mapping.create_user_if_missing is True


class TestValidateConfig:
    def _make_config(self, **overrides):
        defaults = dict(
            issuer="https://auth.example.com",
            client_id="myapp",
            client_secret="secret",
            base_url="https://myapp.example.com",
            secret_key="a-long-enough-secret-key",
        )
        defaults.update(overrides)
        return AuthConfig(**defaults)

    def test_valid_config_passes(self):
        validate_config(self._make_config())

    def test_invalid_base_url(self):
        with pytest.raises(ConfigurationError, match="base_url"):
            validate_config(self._make_config(base_url="not-a-url"))

    def test_http_base_url_with_require_https(self):
        with pytest.raises(ConfigurationError, match="https"):
            validate_config(self._make_config(base_url="http://myapp.example.com"))

    def test_http_allowed_when_require_https_false(self):
        validate_config(
            self._make_config(base_url="http://localhost:8000", require_https=False)
        )

    def test_invalid_issuer(self):
        with pytest.raises(ConfigurationError, match="issuer"):
            validate_config(self._make_config(issuer="not-a-url"))

    def test_callback_path_must_start_with_slash(self):
        with pytest.raises(ConfigurationError, match="callback_path"):
            validate_config(self._make_config(callback_path="auth/callback"))

    def test_short_secret_key(self):
        with pytest.raises(ConfigurationError, match="secret_key"):
            validate_config(self._make_config(secret_key="short"))

    def test_missing_openid_scope(self):
        with pytest.raises(ConfigurationError, match="openid"):
            validate_config(self._make_config(scopes=["profile", "email"]))
