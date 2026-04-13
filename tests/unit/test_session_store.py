"""Tests for session store."""

import pytest

from oidc_authkit.config.models import SessionConfig
from oidc_authkit.domain.models import SessionPrincipal
from oidc_authkit.infrastructure.session.cookie_store import CookieSessionStore


@pytest.fixture
def config():
    return SessionConfig(
        secret_key="a-long-enough-secret-key-for-testing",
        cookie_name="test_session",
    )


@pytest.fixture
def store(config):
    return CookieSessionStore(config)


class TestCookieSessionStore:
    @pytest.mark.asyncio
    async def test_save_and_get(self, store):
        principal = SessionPrincipal(
            local_user_id="user-123",
            issuer="https://auth.example.com",
            subject="sub-456",
            auth_time=1000000.0,
        )
        data = await store.save(principal)
        assert "cookie_value" in data
        assert data["cookie_name"] == "test_session"

        restored = await store.get(data)
        assert restored is not None
        assert restored.local_user_id == "user-123"
        assert restored.issuer == "https://auth.example.com"
        assert restored.subject == "sub-456"

    @pytest.mark.asyncio
    async def test_empty_session(self, store):
        assert await store.get({}) is None
        assert await store.get({"cookie_value": None}) is None

    @pytest.mark.asyncio
    async def test_invalid_cookie(self, store):
        assert await store.get({"cookie_value": "garbage-data"}) is None

    @pytest.mark.asyncio
    async def test_different_secret_rejects(self, config):
        store1 = CookieSessionStore(config)
        principal = SessionPrincipal(
            local_user_id="user-123",
            issuer="https://auth.example.com",
            subject="sub-456",
            auth_time=1000000.0,
        )
        data = await store1.save(principal)

        config2 = SessionConfig(
            secret_key="different-secret-key-for-testing",
            cookie_name="test_session",
        )
        store2 = CookieSessionStore(config2)
        assert await store2.get(data) is None
