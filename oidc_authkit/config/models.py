"""Configuration models for oidc-authkit."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class OIDCConfig(BaseModel):
    """OIDC provider configuration."""

    issuer: str
    client_id: str
    client_secret: str
    scopes: list[str] = Field(default=["openid", "profile", "email", "groups"])
    auto_fetch_userinfo: bool = False
    clock_skew_seconds: int = 60
    discovery_url: str | None = None
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"

    @model_validator(mode="after")
    def _set_discovery_url(self) -> OIDCConfig:
        if self.discovery_url is None:
            self.discovery_url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        return self


class SessionConfig(BaseModel):
    """Session / cookie configuration."""

    cookie_name: str = "oidc_authkit_session"
    secret_key: str
    same_site: Literal["lax", "strict", "none"] = "lax"
    secure: bool = True
    http_only: bool = True
    max_age_seconds: int = 86400
    refresh_on_request: bool = True


class UserMappingConfig(BaseModel):
    """Controls how OIDC claims map to local users."""

    create_user_if_missing: bool = True
    update_profile_on_login: bool = True
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    display_name_claim: str = "name"
    groups_claim: str = "groups"


class AuthConfig(BaseModel):
    """Top-level auth configuration combining all sub-configs."""

    issuer: str
    client_id: str
    client_secret: str
    base_url: str
    secret_key: str
    callback_path: str = "/oidc/callback"
    login_path: str = "/oidc/login"
    logout_path: str = "/oidc/logout"
    post_logout_redirect_path: str = "/"
    scopes: list[str] = Field(default=["openid", "profile", "email", "groups"])
    auto_fetch_userinfo: bool = False
    require_https: bool = True
    allow_anonymous: bool = True
    clock_skew_seconds: int = 60
    discovery_url: str | None = None
    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"

    # Session settings
    cookie_name: str = "oidc_authkit_session"
    same_site: Literal["lax", "strict", "none"] = "lax"
    cookie_secure: bool = True
    cookie_http_only: bool = True
    max_age_seconds: int = 86400
    refresh_on_request: bool = True

    # User mapping settings
    create_user_if_missing: bool = True
    update_profile_on_login: bool = True
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    display_name_claim: str = "name"
    groups_claim: str = "groups"

    @model_validator(mode="after")
    def _set_discovery_url(self) -> AuthConfig:
        if self.discovery_url is None:
            self.discovery_url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        return self

    def to_oidc_config(self) -> OIDCConfig:
        return OIDCConfig(
            issuer=self.issuer,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=self.scopes,
            auto_fetch_userinfo=self.auto_fetch_userinfo,
            clock_skew_seconds=self.clock_skew_seconds,
            discovery_url=self.discovery_url,
            token_endpoint_auth_method=self.token_endpoint_auth_method,
        )

    def to_session_config(self) -> SessionConfig:
        return SessionConfig(
            cookie_name=self.cookie_name,
            secret_key=self.secret_key,
            same_site=self.same_site,
            secure=self.cookie_secure,
            http_only=self.cookie_http_only,
            max_age_seconds=self.max_age_seconds,
            refresh_on_request=self.refresh_on_request,
        )

    def to_user_mapping_config(self) -> UserMappingConfig:
        return UserMappingConfig(
            create_user_if_missing=self.create_user_if_missing,
            update_profile_on_login=self.update_profile_on_login,
            username_claim=self.username_claim,
            email_claim=self.email_claim,
            display_name_claim=self.display_name_claim,
            groups_claim=self.groups_claim,
        )
