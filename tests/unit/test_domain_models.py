"""Tests for domain models."""

from datetime import datetime, timezone

from oidc_authkit.domain.models import (
    Claims,
    ExternalIdentity,
    LocalUser,
    SessionPrincipal,
    UserContext
)


class TestClaims:
    def test_basic(self):
        c = Claims(issuer="https://auth.example.com", subject="user1")
        assert c.issuer == "https://auth.example.com"
        assert c.subject == "user1"
        assert c.email is None
        assert c.groups == []
        assert c.raw == {}


class TestExternalIdentity:
    def test_basic(self):
        ei = ExternalIdentity(
            issuer="https://auth.example.com",
            subject="user1",
            email="user@example.com",
            username="user1",
            display_name="User One",
            groups=["admins"],
        )
        assert ei.email == "user@example.com"
        assert "admins" in ei.groups


class TestLocalUser:
    def test_basic(self):
        now = datetime.now(timezone.utc)
        u = LocalUser(
            id="abc",
            issuer="https://auth.example.com",
            subject="user1",
            email="user@example.com",
            username="user1",
            display_name="User One",
            is_active=True,
            created_at=now,
        )
        assert u.id == "abc"
        assert u.is_active
        assert u.last_login_at is None


class TestSessionPrincipal:
    def test_basic(self):
        sp = SessionPrincipal(
            local_user_id="abc",
            issuer="https://auth.example.com",
            subject="user1",
            auth_time=1000000.0,
        )
        assert sp.session_version == 1


class TestUserContext:
    def test_anonymous(self):
        ctx = UserContext(is_authenticated=False)
        assert not ctx.is_authenticated
        assert ctx.local_user is None
        assert ctx.groups == []

    def test_authenticated(self):
        now = datetime.now(timezone.utc)
        user = LocalUser(
            id="abc",
            issuer="https://auth.example.com",
            subject="user1",
            email="user@example.com",
            username="user1",
            display_name="User One",
            is_active=True,
            created_at=now,
        )
        ctx = UserContext(
            is_authenticated=True,
            local_user=user,
            groups=["users"],
        )
        assert ctx.is_authenticated
        assert ctx.local_user is not None
        assert "users" in ctx.groups
