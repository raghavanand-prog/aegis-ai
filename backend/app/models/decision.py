"""What evidence a decision was taken on.

One row per consequential decision, written in the same transaction as the
decision itself. A decision whose binding failed to write does not exist -
that is the point of the shared transaction, and it is why nothing here has an
update or delete path.

**Append-only, and enforced by absence rather than by policy.** There is no
service function that modifies a binding and no endpoint that reaches one. An
analyst cannot revise what a past decision rested on, because nothing in the
application can.

The row deliberately stores fingerprints, never evidence. ``evidence_snapshot``
is a map of ``evidence_id -> content digest`` plus each item's integrity level;
it is what makes a later change *attributable* rather than merely detectable.
Copying the evidence itself would duplicate the source objects and create a
second, divergent version of records that are currently the only version there
is - the same reasoning that kept Phase C a projection.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, JSONType, utcnow


class DecisionEvidenceBinding(Base):
    __tablename__ = "decision_evidence_bindings"

    __table_args__ = (
        # The two queries this table serves: "what decisions were taken on this
        # incident" (the workspace panel) and "show me this one" (verification).
        Index("ix_decision_bindings_incident_decided", "incident_id", "decided_at"),
        Index("ix_decision_bindings_ref", "decision_ref"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: Stable, human-readable reference, e.g. ``DEC-INC-1024-0003``. Used in the
    #: API path, so it must not change once written.
    decision_ref: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )

    #: What kind of decision this was. A string rather than an enum column
    #: because later phases add decision types (an approved response action,
    #: say) and widening a CHECK constraint for each one buys nothing here -
    #: the value is descriptive, and no authorization depends on it.
    decision_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Denormalised so the binding stays readable if the incident row is gone.
    incident_ref: Mapped[str] = mapped_column(String(32), nullable=False)

    # --- What was decided --------------------------------------------------
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Who decided it ----------------------------------------------------
    decided_by: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Recorded rather than inferred, following V7: an authority that cannot be
    #: stated later is not an authority.
    decided_by_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    # --- What the evidence was --------------------------------------------
    #: The digest over the whole evidence set. Authoritative for detection: it
    #: covers every item, including any the snapshot's per-item map truncated.
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: ``EvidenceSnapshot.to_dict()`` - per-item digests and integrity levels,
    #: the degraded providers at decision time, and the truncation flag.
    evidence_snapshot: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    incident = relationship("Incident", back_populates="decision_bindings")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<DecisionEvidenceBinding {self.decision_ref} "
            f"{self.from_state}->{self.to_state}>"
        )
