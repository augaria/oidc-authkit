"""Tests for redirect validation."""

from oidc_authkit.infrastructure.utils.urls import SafeRedirectStrategy, build_callback_url


class TestSafeRedirectStrategy:
    def setup_method(self):
        self.strategy = SafeRedirectStrategy()
        self.base_url = "https://myapp.example.com"

    def test_relative_path(self):
        assert self.strategy.validate_redirect_target("/settings", self.base_url) == "/settings"

    def test_relative_path_with_query(self):
        assert (
            self.strategy.validate_redirect_target("/page?a=1", self.base_url)
            == "/page?a=1"
        )

    def test_same_origin(self):
        assert (
            self.strategy.validate_redirect_target(
                "https://myapp.example.com/page", self.base_url
            )
            == "/page"
        )

    def test_empty_returns_root(self):
        assert self.strategy.validate_redirect_target("", self.base_url) == "/"

    def test_external_url_rejected(self):
        assert (
            self.strategy.validate_redirect_target("https://evil.com/page", self.base_url)
            == "/"
        )

    def test_protocol_relative_rejected(self):
        assert (
            self.strategy.validate_redirect_target("//evil.com/page", self.base_url)
            == "/"
        )

    def test_javascript_rejected(self):
        assert (
            self.strategy.validate_redirect_target("javascript:alert(1)", self.base_url)
            == "/"
        )


class TestBuildCallbackUrl:
    def test_basic(self):
        assert (
            build_callback_url("https://myapp.example.com", "/oidc/callback")
            == "https://myapp.example.com/oidc/callback"
        )

    def test_strips_trailing_slash(self):
        assert (
            build_callback_url("https://myapp.example.com/", "/oidc/callback")
            == "https://myapp.example.com/oidc/callback"
        )
