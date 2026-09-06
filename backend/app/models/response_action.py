"""A request for a containment action, and the decision taken on it.

One row per request. It records what somebody wants done, why, who asked, and -
once a second authorised person decides - what they decided and which evidence
they were shown.

**Nothing here executes anything.** There is no provider column, no execution
record, no result. That is not an oversight: V9 stops at the decision, and a
row that could be marked "executed" without an executor behind it would be a
claim the system cannot support.

Append-only in the way that matters: a request is written once in
``requested``, decided exactly once, and never decided again. The decision
fields are the only ones that change, and they change from NULL to a value one
time. ``response.approval`` refuses a second decision, and there is no service
function or endpoint that would revise one.

The evidence the approver was shown is **not** stored here. It is a
``DecisionEvidenceBinding``, the same record a lifecycle decision produces, so
there is one evidence-integrity mechanism rather than two - and a response
approval shows up in ``GET /incidents/{id}/decisions`` beside the containment
transition it justifies, with the same drift verdict computed the same way.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, utcnow
from app.response.actions import ResponseActionStatus


class ResponseActionRequest(Base):
    __tablename__ = "response_action_requests"

    __table_args__ = (
        # The queries this serves: an incident's requests, and the pending
        # queue an approver works from.
        Index("ix_response_requests_incident_created", "incident_id", "requested_at"),
        Index("ix_response_requests_status_created", "status", "requested_at"),
        CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'withdrawn')",
            name="ck_response_requests_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: Stable, human-readable reference used in the API path, e.g.
    #: ``RAR-INC-1024-0001``. Fixed once written.
    request_ref: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Denormalised so the request stays readable if the incident is gone.
    incident_ref: Mapped[str] = mapped_column(String(32), nullable=False)

    # --- What was asked for ------------------------------------------------
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    parameters: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    #: SHA-256 over the canonical parameters at request time. Re-checked at
    #: approval, so an approver signs off the action that was actually asked
    #: for rather than whatever the row says by then.
    parameters_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Why this is warranted. Required - a containment request with no stated
    #: reason gives an approver nothing to weigh.
    justification: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(
        String(16), default=ResponseActionStatus.REQUESTED.value, nullable=False, index=True
    )

    # --- Who asked ---------------------------------------------------------
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # --- Who decided, and how ----------------------------------------------
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: The evidence binding recorded when this was approved. NULL for a request
    #: that is still pending, was rejected, or was withdrawn - none of which
    #: rest on evidence the way an approval does.
    evidence_binding_id: Mapped[int | None] = mapped_column(
        ForeignKey("decision_evidence_bindings.id", ondelete="SET NULL"), nullable=True
    )

    incident = relationship("Incident", back_populates="response_requests")
    evidence_binding = relationship("DecisionEvidenceBinding")

    @property
    def is_pending(self) -> bool:
        return self.status == ResponseActionStatus.REQUESTED.value

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ResponseActionRequest {self.request_ref} "
            f"{self.action_type} {self.status}>"
        )
