"""Audit trail writes.

Every analyst action that changes state, and every read of a specific event,
is recorded. The trail is append-only: nothing in the API updates or deletes
an audit row.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.enums import AuditAction
from app.models.user import User
from app.repositories.audit_repository import audit_repository


def record(
    db: Session,
    *,
    action: AuditAction | str,
    user: User | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action.value if isinstance(action, AuditAction) else str(action),
        user_id=user.id if user else None,
        username=user.email if user else "system",
        target_type=target_type,
        target_id=target_id,
        ip_address=ip_address,
        details=details or {},
    )
    return audit_repository.add(db, entry)
