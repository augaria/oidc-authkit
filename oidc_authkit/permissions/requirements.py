"""Permission requirements and evaluation."""

from __future__ import annotations

from oidc_authkit.domain.models import PermissionRequirement, UserContext


def require_authenticated(user: UserContext) -> bool:
    """Check if user is authenticated."""
    return user.is_authenticated


def require_group(user: UserContext, group: str) -> bool:
    """Check if user belongs to a group."""
    return user.is_authenticated and group in user.groups


class GroupRequirement(PermissionRequirement):
    """Requirement that user belongs to a specific group."""

    def __init__(self, group: str) -> None:
        super().__init__(requirement_type="group", value=group)


class DefaultPermissionEvaluator:
    """Default evaluator supporting group requirements."""

    async def has_permission(
        self, user: UserContext, requirement: PermissionRequirement
    ) -> bool:
        if requirement.requirement_type == "group":
            return require_group(user, requirement.value)
        if requirement.requirement_type == "authenticated":
            return require_authenticated(user)
        return False
