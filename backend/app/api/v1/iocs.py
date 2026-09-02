"""Indicator of compromise endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.enums import AuditAction, IOCType
from app.models.user import User
from app.repositories.ioc_repository import ioc_repository
from app.schemas.common import Page
from app.schemas.ioc import IOCRead
from app.services import audit_service
from app.services.serializers import ioc_to_schema

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("", response_model=Page[IOCRead])
def list_iocs(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.IOCS_READ)),
    ioc_type: IOCType | None = Query(default=None, alias="type"),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[IOCRead]:
    iocs, total = ioc_repository.list_paginated(
        db,
        ioc_type=ioc_type.value if ioc_type else None,
        search=search,
        limit=limit,
        offset=offset,
    )
    # Indicator lookups are an analyst action worth keeping: knowing who
    # searched for which indicator matters during an investigation review.
    if search or ioc_type:
        audit_service.record(
            db,
            action=AuditAction.IOC_VIEWED,
            user=user,
            target_type="ioc",
            target_id=search or (ioc_type.value if ioc_type else None),
            ip_address=client_ip(request),
            details={"resultCount": total},
        )
        db.commit()

    return Page[IOCRead](
        items=[ioc_to_schema(ioc) for ioc in iocs], total=total, limit=limit, offset=offset
    )
