"""Response action request/approval schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.response.actions import ResponseActionType
from app.schemas.common import CamelModel


def _require_text(value: str, field: str) -> str:
    """Reject a value that is empty once stripped.

    ``min_length=1`` accepts ``"  "``, which would then be refused deeper in
    by the service with a different status code. Two layers disagreeing about
    what counts as "given" is how a caller learns to distrust the first one.
    """
    if not value.strip():
        raise ValueError(f"{field} cannot be blank.")
    return value.strip()


class ResponseActionCreate(CamelModel):
    action_type: ResponseActionType
    parameters: dict[str, Any] = Field(default_factory=dict)
    #: Why this containment is warranted. Required by the service too, so a
    #: non-HTTP caller cannot skip it.
    justification: str = Field(min_length=1, max_length=2000)

    @field_validator("justification")
    @classmethod
    def _justification_not_blank(cls, value: str) -> str:
        return _require_text(value, "justification")


class ResponseActionApprove(CamelModel):
    #: The evidence manifest the approver was shown. **Required** - unlike a
    #: lifecycle transition, where it is optional for clients that predate it.
    #: These endpoints are new, so there is no compatibility to preserve and an
    #: unprotected approval would be a choice rather than an inheritance.
    expected_evidence_digest: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=2000)


class ResponseActionReject(CamelModel):
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, value: str) -> str:
        return _require_text(value, "reason")


class ResponseActionRead(CamelModel):
    request_ref: str
    incident_ref: str
    action_type: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    #: SHA-256 over the parameters at request time. An approval is checked
    #: against this, so editing the row between request and approval is refused.
    parameters_digest: str
    justification: str
    status: str
    requested_by: str
    requested_by_role: str | None = None
    requested_at: datetime
    decided_by: str | None = None
    decided_by_role: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    #: The decision binding recording the evidence this was decided on. Null
    #: while pending. Look it up under /incidents/{id}/decisions.
    decision_ref: str | None = None
    #: Stated plainly on every response: V9 decides, it does not act.
    executed: bool = False
    execution_note: str = (
        "AEGISX records the decision only. No response action is executed "
        "against any system in this version."
    )


class ResponseActionList(CamelModel):
    incident_id: str
    total: int
    pending: int
    items: list[ResponseActionRead] = Field(default_factory=list)
