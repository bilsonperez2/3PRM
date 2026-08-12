"""RBAC scaffolding.

Real authentication (OAuth/SSO) is out of scope for the Phase 1 MVP. This module
defines the role model and a request-scoped "current user" dependency now, so every
route already depends on it. Wiring in real auth later means replacing the body of
get_current_user() — no route signatures need to change.
"""

from enum import Enum

from fastapi import Depends, HTTPException, Request, status


class Role(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    READ_ONLY = "read_only"
    EXECUTIVE = "executive"


class CurrentUser:
    def __init__(self, subject: str, role: Role) -> None:
        self.subject = subject
        self.role = role


def get_current_user(request: Request) -> CurrentUser:
    """Stub identity provider.

    TODO(auth): replace with real session/JWT/SSO validation. Until then every
    request is treated as an authenticated admin so Phase 1 endpoints are usable
    without blocking on an auth system — this must not be relied on outside a
    trusted internal network.
    """
    return CurrentUser(subject="dev-user", role=Role.ADMIN)


def require_role(*allowed: Role):
    def _dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {user.role.value} is not permitted to perform this action.",
            )
        return user

    return _dependency
