"""User and authentication schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import EmailStr, Field

from app.models.enums import UserRole
from app.schemas.common import CamelModel


class UserRead(CamelModel):
    id: int
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class UserCreate(CamelModel):
    email: EmailStr
    full_name: str = Field(default="", max_length=120)
    password: str = Field(min_length=8, max_length=256)
    role: UserRole = UserRole.ANALYST


class LoginRequest(CamelModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int
    user: UserRead
    #: What this role may do, as enforced by the backend.
    permissions: list[str] = Field(default_factory=list)


class CurrentUser(UserRead):
    """The signed-in user plus the permissions their role grants."""

    permissions: list[str] = Field(default_factory=list)


class PasswordChangeRequest(CamelModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
