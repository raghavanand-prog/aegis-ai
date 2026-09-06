"""Storing posture findings, and deciding which ones belong to an incident.

Two responsibilities, and the second is the one with teeth.

**Storing.** A scan is written by ``finding_id``, which is derived from (check,
resource). Running the same scan twice moves ``last_seen_at`` on the existing
rows instead of writing new ones. There is no delete: a finding that stops
appearing keeps its row and its stale ``last_seen_at``, because "this resource
was fixed" and "the scanner stopped covering it" are different facts and the
absence of a row cannot tell them apart.

**Correlating.** A posture finding is shown on an incident when the two concern
the same resource. The resources an incident is *about* are read out of its
CloudTrail events - the principal that made the call, and any resource named in
the call's parameters.

That second source is attacker-influenced, and the rule that makes it safe is
narrow enough to state in one sentence: **a resource named inside an event is
only accepted when its account matches the account the event itself was
recorded in.** Without that, anyone able to get a string into a request
parameter could name a resource in an account they have nothing to do with and
have that account's posture rendered on their incident. The principal ARN gets
the same treatment, and comparison is always structural - see
``cloud.resources``.

The one exception is a resource whose ARN carries no account at all - an S3
bucket - where the name is globally unique and therefore *is* the identity.
See ``_belongs_to``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cloud.findings import CloudFinding, FindingSeverity, finding_id, severity_rank
from app.cloud.resources import ResourceRef, parse_arn
from app.cloud.scanner import ScanResult
from app.models.cloud_finding import CloudPostureFinding

logger = logging.getLogger(__name__)

#: How many resources one incident may pull posture for. An incident linked to
#: two hundred events must not turn into an unbounded fan-out.
MAX_RESOURCES_PER_INCIDENT = 100

#: How deep into a call's parameters to look for an ARN. Request parameters are
#: attacker-shaped and arbitrarily nestable.
MAX_PARAMETER_DEPTH = 3

#: Bound on findings returned for one incident, for the same reason the
#: evidence collectors are bounded.
MAX_FINDINGS_PER_INCIDENT = 200


# --- Storing ---------------------------------------------------------------


def record_scan(db: Session, result: ScanResult) -> dict[str, int]:
    """Persist one scan's findings. Returns what changed."""
    created = 0
    updated = 0
    now = datetime.now(timezone.utc)

    for finding in result.findings:
        assert finding.resource is not None  # guaranteed by CloudFinding
        identifier = finding_id(finding)
        row = db.execute(
            select(CloudPostureFinding).where(
                CloudPostureFinding.finding_id == identifier
            )
        ).scalar_one_or_none()

        if row is None:
            db.add(_to_row(finding, identifier, result, now))
            created += 1
            continue

        # The row is the current state of the resource, so the mutable fields
        # move. `first_seen_at` never does: how long a problem has been open
        # is the most useful thing the row knows.
        row.title = finding.title
        row.description = finding.description
        row.severity = finding.severity.value
        row.control = finding.control
        row.detail = dict(finding.detail)
        row.source_file = result.source_file
        row.is_simulated = finding.is_simulated
        row.last_seen_at = now
        updated += 1

    db.flush()
    return {"created": created, "updated": updated, "total": len(result.findings)}


def _to_row(
    finding: CloudFinding, identifier: str, result: ScanResult, now: datetime
) -> CloudPostureFinding:
    resource = finding.resource
    assert resource is not None
    return CloudPostureFinding(
        finding_id=identifier,
        check_id=finding.check_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        control=finding.control,
        provider=resource.provider.value,
        account=resource.account,
        region=resource.region,
        service=resource.service,
        resource_type=resource.resource_type,
        resource_id=resource.resource_id,
        resource_key=resource.key,
        detail=dict(finding.detail),
        source_file=result.source_file,
        is_simulated=finding.is_simulated,
        first_seen_at=now,
        last_seen_at=now,
    )


# --- Reading ---------------------------------------------------------------


def list_findings(
    db: Session,
    *,
    account: str | None = None,
    severity: FindingSeverity | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[CloudPostureFinding], int]:
    statement = select(CloudPostureFinding)
    if account:
        statement = statement.where(CloudPostureFinding.account == account)
    if severity:
        statement = statement.where(CloudPostureFinding.severity == severity.value)

    rows = list(db.execute(statement).scalars())
    rows.sort(
        key=lambda row: (
            -severity_rank(FindingSeverity(row.severity)),
            row.resource_key,
            row.check_id,
        )
    )
    return rows[offset : offset + limit], len(rows)


def findings_for_resources(
    db: Session, resources: list[ResourceRef]
) -> list[CloudPostureFinding]:
    """Findings about exactly these resources.

    Matched on ``resource_key``, which is built from an already-parsed
    reference on both sides. Nothing here compares an ARN as text.
    """
    if not resources:
        return []

    keys = {resource.key for resource in resources}
    rows = list(
        db.execute(
            select(CloudPostureFinding).where(CloudPostureFinding.resource_key.in_(keys))
        ).scalars()
    )
    rows.sort(
        key=lambda row: (
            -severity_rank(FindingSeverity(row.severity)),
            row.resource_key,
            row.check_id,
        )
    )
    return rows[:MAX_FINDINGS_PER_INCIDENT]


# --- Correlating -----------------------------------------------------------


def _belongs_to(ref: ResourceRef, event_account: str) -> bool:
    """Whether a resource named in an event may be correlated with it.

    The rule has two branches and both are about identity, not permission.

    An **account-scoped** ARN (IAM, EC2, CloudTrail) is accepted only when its
    account matches the account the event was recorded in. Two accounts can
    each hold a ``role/deploy``, so without this check anyone able to get a
    string into a request parameter could name a role in an account they have
    nothing to do with and have that account's posture rendered on their
    incident.

    An **accountless** ARN - ``arn:aws:s3:::name`` - is accepted on the name
    alone, because S3 omits the account for a reason: bucket names are
    globally unique, so the name *is* the identity and there is no second
    bucket for it to be confused with. Requiring an account here would not
    tighten anything; it would simply mean no bucket ever correlates.
    """
    return ref.account in ("", event_account)


def resources_for_incident(incident: Any) -> list[ResourceRef]:
    """Which cloud resources this incident is about.

    Read from the incident's CloudTrail events: the calling principal, and any
    resource named in the call's parameters. A named resource is accepted only
    when it sits in the same account the event was recorded in - see the module
    docstring for why that check is the whole of the security story here.
    """
    found: dict[str, ResourceRef] = {}

    for event in (incident.events or [])[:MAX_RESOURCES_PER_INCIDENT]:
        data = getattr(event, "normalized_data", None)
        if not isinstance(data, dict):
            continue

        account = data.get("aws_account_id")
        if not isinstance(account, str) or not account:
            # Without the event's own account there is nothing to check a
            # named resource against, so nothing from this event is trusted.
            continue

        principal = parse_arn(data.get("principal_arn"))
        if principal is not None and _belongs_to(principal, account):
            found[principal.key] = principal

        for candidate in _arns_in(data.get("request_parameters")):
            ref = parse_arn(candidate)
            if ref is not None and _belongs_to(ref, account):
                found[ref.key] = ref

        if len(found) >= MAX_RESOURCES_PER_INCIDENT:
            break

    return list(found.values())[:MAX_RESOURCES_PER_INCIDENT]


def _arns_in(value: Any, depth: int = 0) -> list[str]:
    """Every ARN-looking string in a request-parameters structure.

    Bounded in depth and breadth. This walks attacker-shaped input, so it is
    written to terminate rather than to be thorough.
    """
    if depth > MAX_PARAMETER_DEPTH:
        return []
    if isinstance(value, str):
        return [value] if value.startswith("arn:") else []
    if isinstance(value, dict):
        out: list[str] = []
        for item in list(value.values())[:50]:
            out.extend(_arns_in(item, depth + 1))
        return out
    if isinstance(value, list):
        out = []
        for item in value[:50]:
            out.extend(_arns_in(item, depth + 1))
        return out
    return []


def findings_for_incident(db: Session, incident: Any) -> list[CloudPostureFinding]:
    """Posture findings about the resources this incident concerns."""
    return findings_for_resources(db, resources_for_incident(incident))
