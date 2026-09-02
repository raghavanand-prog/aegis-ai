"""Shared API dependencies: authentication and authorization."""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging_config import bind_user
from app.core.rbac import Permission, has_permission, permissions_for
from app.core.security import TokenError, decode_access_token
from app.models.enums import AuditAction, UserRole
from app.models.user import User
from app.repositories.user_repository import user_repository
from app.services import audit_service

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def client_ip(request: Request) -> str | None:
    """Best-effort client address, honouring a single proxy hop."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the caller from a bearer token.

    Beyond signature and expiry, the token's ``tv`` claim must still match the
    user's current token version - that is how a password change or a "sign out
    everywhere" invalidates tokens that are otherwise perfectly valid.
    """
    if credentials is None or not credentials.credentials:
        raise CREDENTIALS_ERROR

    try:
        payload = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CREDENTIALS_ERROR from exc

    user = user_repository.get(db, user_id)
    if user is None or not user.is_active:
        raise CREDENTIALS_ERROR

    token_version = payload.get("tv")
    if token_version is not None and int(token_version) != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Every subsequent log line for this request names the acting user.
    bind_user(user.email)
    return user


def require(*permissions: Permission) -> Callable[..., User]:
    """Dependency factory: caller must hold every listed permission.

    Denials are audited. An account probing endpoints it has no rights to is
    exactly the signal a SOC platform should keep.
    """

    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        missing = [
            permission
            for permission in permissions
            if not has_permission(user.role, permission)
        ]
        if missing:
            audit_service.record(
                db,
                action=AuditAction.ACCESS_DENIED,
                user=user,
                target_type="endpoint",
                target_id=request.url.path,
                ip_address=client_ip(request),
                details={
                    "role": user.role,
                    "required": [permission.value for permission in missing],
                    "method": request.method,
                },
            )
            db.commit()
            logger.warning(
                "authorization denied",
                extra={
                    "path": request.url.path,
                    "role": user.role,
                    "required": [permission.value for permission in missing],
                    "result": "denied",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Your role does not permit this action: "
                    + ", ".join(permission.value for permission in missing)
                ),
            )
        return user

    return dependency


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Kept for endpoints that are administrative as a whole rather than
    tied to one permission."""
    if user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required"
        )
    return user


def current_permissions(user: User) -> list[str]:
    return sorted(permission.value for permission in permissions_for(user.role))
