"""A cloud posture finding, as stored.

One row per (check, resource). A scan run again does not accumulate rows: it
updates the one that already exists, moving ``last_seen_at`` and, when the
configuration changed, the detail. That is a deliberate choice with a cost,
and the cost is recorded honestly rather than hidden - see ``Integrity`` in the
evidence provider, where this projects as **mutable**.

The alternative, a new row per scan, would be append-only and therefore
tamper-evident, but it would also mean a nightly scan of an unremediated
bucket producing three hundred and sixty-five identical findings a year. Cloud
posture is a *current state*, not a stream of observations, so the row is the
state and the digest is what proves whether it moved.

**Every row is simulated.** ``is_simulated`` is not nullable and has no server
default: a row that did not say what it was would be the most misleading record
in the database.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, JSONType, utcnow


class CloudPostureFinding(Base):
    __tablename__ = "cloud_posture_findings"

    __table_args__ = (
        # The two queries this serves: everything about one resource (the
        # correlation path from an incident), and the severity-ordered
        # backlog for one account.
        Index("ix_cloud_findings_resource", "resource_key"),
        Index("ix_cloud_findings_account_severity", "account", "severity"),
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_cloud_findings_severity",
        ),
        CheckConstraint(
            "provider IN ('aws', 'azure', 'gcp')",
            name="ck_cloud_findings_provider",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    #: ``CF-`` + sha256(check_id|resource_key)[:16]. Stable across rescans,
    #: which is what makes a rescan an update rather than a duplicate.
    finding_id: Mapped[str] = mapped_column(
        String(32), unique=True, index=True, nullable=False
    )

    check_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    #: The hardening theme this check addresses, in words. Never a benchmark
    #: identifier - AEGISX has not been assessed against any framework.
    control: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --- Resource identity, stored in parts ------------------------------
    # The parts are stored rather than only the ARN because correlation
    # compares them field by field. Reconstituting them by parsing a string
    # at query time would put the parser on the hot path and, worse, make the
    # comparison depend on parsing being identical in two places.
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    #: The canonical joined form, built from the parsed parts. Indexed, and the
    #: only thing correlation matches on.
    resource_key: Mapped[str] = mapped_column(String(1024), nullable=False)

    detail: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    #: Which snapshot file this came from, so a finding can be traced back to
    #: the input that produced it.
    source_file: Mapped[str | None] = mapped_column(String(255), nullable=True)

    #: Not nullable, no default. See the module docstring.
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    #: Moved on every rescan that still finds the problem. This is the field
    #: that makes the row mutable.
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
