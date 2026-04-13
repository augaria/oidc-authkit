"""Tests for permissions."""

import pytest
from datetime import datetime, timezone

from oidc_authkit.domain.models import LocalUser, UserContext
from oidc_authkit.permissions.requirements import (
    DefaultPermissionEvaluator,
    GroupRequirement,
    require_authenticated,
    require_group,
)


def _make_user(groups: list[str] | None = None) -> UserContext:
    user = LocalUser(
        id="1",
        issuer="https://auth.example.com",
        subject="sub1",
        email="test@example.com",
        username="test",
        display_name="Test",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    return UserContext(
        is_authenticated=True,
        local_user=user,
        groups=groups or [],
    )


class TestPermissions:
    def test_require_authenticated_true(self):
        assert require_authenticated(_make_user()) is True

    def test_require_authenticated_false(self):
        assert require_authenticated(UserContext(is_authenticated=False)) is False

    def test_require_group_present(self):
        assert require_group(_make_user(["admins"]), "admins") is True

    def test_require_group_absent(self):
        assert require_group(_make_user(["users"]), "admins") is False

    def test_require_group_unauthenticated(self):
        assert require_group(UserContext(is_authenticated=False), "admins") is False


class TestDefaultPermissionEvaluator:
    @pytest.mark.asyncio
    async def test_group_requirement_met(self):
        evaluator = DefaultPermissionEvaluator()
        req = GroupRequirement("admins")
        assert await evaluator.has_permission(_make_user(["admins"]), req) is True

    @pytest.mark.asyncio
    async def test_group_requirement_not_met(self):
        evaluator = DefaultPermissionEvaluator()
        req = GroupRequirement("admins")
        assert await evaluator.has_permission(_make_user(["users"]), req) is False

    @pytest.mark.asyncio
    async def test_unknown_requirement_type(self):
        from oidc_authkit.domain.models import PermissionRequirement

        evaluator = DefaultPermissionEvaluator()
        req = PermissionRequirement(requirement_type="custom", value="x")
        assert await evaluator.has_permission(_make_user(), req) is False
