"""Authentication."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.enums import AuditAction, UserRole
from app.models.user import User
from app.repositories.user_repository import user_repository
from app.schemas.user import UserCreate
from app.services import audit_service

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when authentication fails."""


def create_user(db: Session, payload: UserCreate) -> User:
    if user_repository.get_by_email(db, payload.email):
        raise AuthError("A user with that email already exists.")

    user = User(
        email=payload.email.lower().strip(),
        full_name=payload.full_name or payload.email.split("@")[0],
        hashed_password=hash_password(payload.password),
        role=payload.role.value,
        is_active=True,
    )
    return user_repository.add(db, user)


def authenticate(
    db: Session, email: str, password: str, *, ip_address: str | None = None
) -> User:
    """Return the user for valid credentials, otherwise raise :class:`AuthError`."""
    user = user_repository.get_by_email(db, email)

    # Verify against a dummy hash when the user is unknown so the response time
    # does not reveal whether an account exists.
    if user is None:
        verify_password(password, hash_password("aegisx-timing-equaliser"))
        audit_service.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            target_type="user",
            target_id=email,
            ip_address=ip_address,
            details={"reason": "unknown_user"},
        )
        raise AuthError("Invalid email or password.")

    if not verify_password(password, user.hashed_password) or not user.is_active:
        audit_service.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            user=user,
            target_type="user",
            target_id=user.email,
            ip_address=ip_address,
            details={"reason": "bad_password" if user.is_active else "inactive"},
        )
        raise AuthError("Invalid email or password.")

    user.last_login_at = datetime.now(timezone.utc)
    audit_service.record(
        db,
        action=AuditAction.LOGIN,
        user=user,
        target_type="user",
        target_id=user.email,
        ip_address=ip_address,
    )
    db.flush()
    return user


def issue_token(user: User) -> tuple[str, int]:
    """Return ``(token, expires_in_seconds)`` for an authenticated user."""
    token = create_access_token(
        str(user.id),
        extra_claims={
            "email": user.email,
            "role": user.role,
            "tv": user.token_version,
        },
    )
    return token, settings.access_token_expire_minutes * 60


def invalidate_sessions(db: Session, user: User) -> int:
    """Revoke every token already issued to this user.

    Bumping the version makes previously issued tokens fail validation on their
    next request, without needing to track individual tokens.
    """
    user.token_version += 1
    db.flush()
    return user.token_version


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    """Change a password after verifying the current one, then log every
    session out - a password change that leaves old sessions alive is not a
    password change."""
    if not verify_password(current_password, user.hashed_password):
        raise AuthError("Current password is incorrect.")
    if verify_password(new_password, user.hashed_password):
        raise AuthError("The new password must differ from the current one.")

    user.hashed_password = hash_password(new_password)
    invalidate_sessions(db, user)
    audit_service.record(
        db,
        action=AuditAction.PASSWORD_CHANGED,
        user=user,
        target_type="user",
        target_id=user.email,
    )
    db.flush()


def ensure_seed_user(db: Session) -> User | None:
    """Create the bootstrap analyst account when the users table is empty."""
    if not settings.seed_demo_user or settings.is_production:
        return None
    if user_repository.count(db) > 0:
        return None

    user = create_user(
        db,
        UserCreate(
            email=settings.demo_user_email,
            full_name=settings.demo_user_name,
            password=settings.demo_user_password,
            role=UserRole.ADMIN,
        ),
    )
    logger.warning(
        "Created bootstrap account %s from environment configuration. "
        "Change this password before sharing the instance.",
        user.email,
    )
    return user
