"""Authentication and session management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_permissions, get_current_user, require
from app.core.database import get_db
from app.core.rbac import Permission, permission_matrix
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.common import Message
from app.schemas.user import (
    CurrentUser,
    LoginRequest,
    PasswordChangeRequest,
    TokenResponse,
    UserCreate,
    UserRead,
)
from app.services import audit_service, auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

UNAUTHORIZED = {
    401: {"model": Message, "description": "Invalid credentials or expired/revoked session"}
}
FORBIDDEN = {403: {"model": Message, "description": "Role lacks the required permission"}}


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Exchange credentials for an access token",
    description=(
        "Verifies the password server-side and returns a signed JWT.\n\n"
        "The response is identical for an unknown account and a wrong password, and the "
        "unknown-account path still performs a hash comparison so response time does not "
        "reveal whether an account exists. Failed attempts are written to the audit trail "
        "and this endpoint has its own tight rate limit."
    ),
    responses={**UNAUTHORIZED, 429: {"model": Message, "description": "Rate limited"}},
)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        user = auth_service.authenticate(
            db, payload.email, payload.password, ip_address=client_ip(request)
        )
    except auth_service.AuthError as exc:
        db.commit()  # persist the failed-login audit entry
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    token, expires_in = auth_service.issue_token(user)
    db.commit()
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user=UserRead.model_validate(user),
        permissions=current_permissions(user),
    )


@router.get(
    "/me",
    response_model=CurrentUser,
    summary="Current user and effective permissions",
    description=(
        "Returns the authenticated user together with the permissions their role grants. "
        "The frontend uses this to decide what to show; the backend enforces the same "
        "matrix independently on every route."
    ),
    responses=UNAUTHORIZED,
)
def me(user: User = Depends(get_current_user)) -> CurrentUser:
    return CurrentUser(
        **UserRead.model_validate(user).model_dump(), permissions=current_permissions(user)
    )


@router.get(
    "/permissions",
    summary="Role to permission matrix",
    description="The full RBAC matrix, exactly as the backend enforces it.",
    responses=UNAUTHORIZED,
)
def permissions(_: User = Depends(get_current_user)) -> dict[str, list[str]]:
    return permission_matrix()


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Record a logout",
    description=(
        "Tokens are stateless, so the client discards its copy; this endpoint exists to "
        "write the audit entry. Use `/auth/logout-all` to actually revoke issued tokens."
    ),
    responses=UNAUTHORIZED,
)
def logout(
    request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> None:
    audit_service.record(
        db,
        action=AuditAction.LOGOUT,
        user=user,
        target_type="user",
        target_id=user.email,
        ip_address=client_ip(request),
    )
    db.commit()


@router.post(
    "/logout-all",
    response_model=Message,
    summary="Revoke every session for the current user",
    description=(
        "Increments the user's token version, so every token issued before this call fails "
        "validation on its next request. Use after a suspected credential compromise."
    ),
    responses=UNAUTHORIZED,
)
def logout_all(
    request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Message:
    version = auth_service.invalidate_sessions(db, user)
    audit_service.record(
        db,
        action=AuditAction.SESSIONS_REVOKED,
        user=user,
        target_type="user",
        target_id=user.email,
        ip_address=client_ip(request),
        details={"tokenVersion": version},
    )
    db.commit()
    return Message(detail="All sessions revoked. Sign in again to continue.")


@router.post(
    "/change-password",
    response_model=Message,
    summary="Change your password",
    description=(
        "Verifies the current password, stores a new PBKDF2 digest and revokes every "
        "existing session - a password change that leaves old sessions alive is not a "
        "password change."
    ),
    responses={**UNAUTHORIZED, 400: {"model": Message, "description": "Password rejected"}},
)
def change_password(
    payload: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Message:
    try:
        auth_service.change_password(
            db, user, payload.current_password, payload.new_password
        )
    except (auth_service.AuthError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    db.commit()
    return Message(detail="Password changed. All sessions have been signed out.")


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an analyst account",
    description="Administrator only. Passwords are hashed before storage and never returned.",
    responses={**UNAUTHORIZED, **FORBIDDEN, 409: {"model": Message, "description": "Email taken"}},
)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require(Permission.USERS_MANAGE)),
) -> UserRead:
    try:
        user = auth_service.create_user(db, payload)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit_service.record(
        db,
        action=AuditAction.USER_CREATED,
        user=actor,
        target_type="user",
        target_id=user.email,
        ip_address=client_ip(request),
        details={"role": user.role},
    )
    db.commit()
    return UserRead.model_validate(user)
