"""Audit trail endpoints (read-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.repositories.audit_repository import audit_repository
from app.schemas.audit import AuditLogRead
from app.schemas.common import Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditLogRead])
def list_audit_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.AUDIT_READ)),
    action: str | None = Query(default=None, max_length=64),
    target_id: str | None = Query(default=None, alias="targetId", max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[AuditLogRead]:
    entries, total = audit_repository.list_paginated(
        db, action=action, target_id=target_id, limit=limit, offset=offset
    )
    return Page[AuditLogRead](
        items=[AuditLogRead.model_validate(entry) for entry in entries],
        total=total,
        limit=limit,
        offset=offset,
    )
