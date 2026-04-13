"""Authlib-based OIDC client implementation."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from authlib.jose import jwt as authlib_jwt
from authlib.jose.errors import JoseError

from oidc_authkit.config.models import OIDCConfig
from oidc_authkit.domain.errors import (
    OIDCDiscoveryError,
    TokenValidationError,
)
from oidc_authkit.domain.models import Claims, TokenSet
from oidc_authkit.protocol.claims import extract_claims

logger = logging.getLogger(__name__)


class AuthlibOIDCClient:
    """OIDC client backed by Authlib + httpx."""

    def __init__(self, config: OIDCConfig) -> None:
        self._config = config
        self._metadata: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    async def _ensure_metadata(self) -> dict[str, Any]:
        if self._metadata is not None:
            return self._metadata

        assert self._config.discovery_url is not None
        async with httpx.AsyncClient() as client:
            resp = await client.get(self._config.discovery_url)
            if resp.status_code != 200:
                raise OIDCDiscoveryError(
                    f"Failed to fetch OIDC discovery document: HTTP {resp.status_code}"
                )
            self._metadata = resp.json()
        return self._metadata

    async def _ensure_jwks(self) -> dict[str, Any]:
        if self._jwks is not None:
            return self._jwks

        metadata = await self._ensure_metadata()
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise OIDCDiscoveryError("OIDC metadata missing jwks_uri")

        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri)
            if resp.status_code != 200:
                raise OIDCDiscoveryError(f"Failed to fetch JWKS: HTTP {resp.status_code}")
            self._jwks = resp.json()
        return self._jwks

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
        scopes: list[str],
    ) -> str:
        """Build the authorization URL for the OIDC provider."""
        metadata = await self._ensure_metadata()
        authorization_endpoint = metadata.get("authorization_endpoint")
        if not authorization_endpoint:
            raise OIDCDiscoveryError("OIDC metadata missing authorization_endpoint")

        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
        }

        # Build URL with query params
        from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

        parsed = urlparse(authorization_endpoint)
        existing = parse_qs(parsed.query)
        existing.update({k: [v] for k, v in params.items()})
        query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in existing.items()})
        url = urlunparse(parsed._replace(query=query))

        logger.debug("Built authorization URL: %s", url)
        return url

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> TokenSet:
        """Exchange authorization code for tokens."""
        metadata = await self._ensure_metadata()
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise OIDCDiscoveryError("OIDC metadata missing token_endpoint")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }

        if self._config.token_endpoint_auth_method == "client_secret_basic":
            auth = (self._config.client_id, self._config.client_secret)
            kwargs: dict = {"auth": auth}
        else:
            data["client_id"] = self._config.client_id
            data["client_secret"] = self._config.client_secret
            kwargs = {}

        async with httpx.AsyncClient() as client:
            resp = await client.post(token_endpoint, data=data, **kwargs)
            if resp.status_code != 200:
                raise TokenValidationError(
                    f"Token exchange failed: HTTP {resp.status_code}, {resp.text}"
                )
            token_data = resp.json()

        return TokenSet(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "Bearer"),
            id_token=token_data.get("id_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            scope=token_data.get("scope"),
            raw=token_data,
        )

    async def parse_id_token(
        self,
        token_set: TokenSet,
        nonce: str,
    ) -> Claims:
        """Parse and validate id_token, returning claims."""
        if not token_set.id_token:
            raise TokenValidationError("No id_token in token set")

        jwks = await self._ensure_jwks()

        try:
            claims_data = authlib_jwt.decode(
                token_set.id_token,
                jwks,
                claims_options={
                    "iss": {"essential": True, "value": self._config.issuer},
                    "aud": {"essential": True, "value": self._config.client_id},
                    "nonce": {"essential": True, "value": nonce},
                },
            )
            claims_data.validate(leeway=self._config.clock_skew_seconds)
        except JoseError as exc:
            raise TokenValidationError(f"id_token validation failed: {exc}") from exc

        return extract_claims(dict(claims_data))

    async def get_end_session_endpoint(self) -> str | None:
        """Get the end_session_endpoint from OIDC discovery metadata."""
        metadata = await self._ensure_metadata()
        return metadata.get("end_session_endpoint")

    async def fetch_userinfo(self, token_set: TokenSet) -> dict[str, Any]:
        """Fetch userinfo from OIDC provider."""
        metadata = await self._ensure_metadata()
        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise OIDCDiscoveryError("OIDC metadata missing userinfo_endpoint")

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {token_set.access_token}"},
            )
            if resp.status_code != 200:
                raise TokenValidationError(
                    f"Userinfo fetch failed: HTTP {resp.status_code}"
                )
            return resp.json()
