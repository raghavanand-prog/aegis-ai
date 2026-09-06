"""Decision-binding API schemas.

Response shapes only. Bindings are written by the transition that creates them,
never by a request, so there is no request body in this module.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel


class ChangedEvidenceRead(CamelModel):
    evidence_id: str
    integrity: str
    kind: str
    provider: str
    #: Both ends. "It changed" is not actionable; "from this to that" is.
    digest_at_decision: str
    digest_now: str


class DriftReportRead(CamelModel):
    #: unchanged / extended / refreshed / tampered.
    verdict: str
    severity: int
    #: True when what the decision *rested on* has moved. `extended` is false -
    #: new evidence does not change the basis of the earlier decision - while
    #: `refreshed` is true, because a routine cause does not make a changed
    #: verdict a routine consequence.
    undermines_decision: bool
    manifest_matches: bool
    manifest_at_decision: str
    manifest_now: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[ChangedEvidenceRead] = Field(default_factory=list)
    #: False when the decision-time snapshot was truncated, so which item moved
    #: may be unanswerable. Detection is unaffected - the manifest covers
    #: everything - but a clean verdict must not be read as proof.
    attribution_complete: bool = True
    #: Providers that were unreachable when the decision was taken, i.e. the
    #: decision was made on partial evidence.
    degraded_at_decision: list[dict[str, Any]] = Field(default_factory=list)


class DecisionBindingRead(CamelModel):
    decision_ref: str
    decision_type: str
    incident_ref: str
    from_state: str | None = None
    to_state: str
    reason: str | None = None
    decided_by: str
    decided_by_role: str | None = None
    decided_at: datetime
    manifest_digest: str
    evidence_count: int
    #: Present on the list and detail endpoints alike: a binding whose drift is
    #: not shown invites the reader to assume nothing moved.
    drift: DriftReportRead


class DecisionBindingList(CamelModel):
    incident_id: str
    total: int
    #: The worst verdict across every decision on this incident, so a workspace
    #: can badge the incident without walking the list.
    worst_verdict: str
    items: list[DecisionBindingRead] = Field(default_factory=list)
