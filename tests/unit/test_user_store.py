"""Tests for InMemoryUserStore."""

import pytest

from oidc_authkit.domain.models import ExternalIdentity
from oidc_authkit.infrastructure.users.memory_store import InMemoryUserStore


@pytest.fixture
def store():
    return InMemoryUserStore()


@pytest.fixture
def identity():
    return ExternalIdentity(
        issuer="https://auth.example.com",
        subject="user1",
        email="user@example.com",
        username="user1",
        display_name="User One",
        groups=["users"],
    )


class TestInMemoryUserStore:
    @pytest.mark.asyncio
    async def test_create_and_get(self, store, identity):
        user = await store.create_from_identity(identity)
        assert user.id is not None
        assert user.issuer == identity.issuer
        assert user.subject == identity.subject
        assert user.email == identity.email
        assert user.is_active is True

    @pytest.mark.asyncio
    async def test_get_by_external_identity(self, store, identity):
        user = await store.create_from_identity(identity)
        found = await store.get_by_external_identity(
            identity.issuer, identity.subject
        )
        assert found is not None
        assert found.id == user.id

    @pytest.mark.asyncio
    async def test_get_by_id(self, store, identity):
        user = await store.create_from_identity(identity)
        found = await store.get_by_id(user.id)
        assert found is not None
        assert found.subject == user.subject

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store):
        assert await store.get_by_external_identity("x", "y") is None
        assert await store.get_by_id("nonexistent") is None

    @pytest.mark.asyncio
    async def test_update(self, store, identity):
        user = await store.create_from_identity(identity)
        identity.email = "new@example.com"
        identity.display_name = "New Name"
        updated = await store.update_from_identity(user, identity)
        assert updated.email == "new@example.com"
        assert updated.display_name == "New Name"
        assert updated.last_login_at is not None
