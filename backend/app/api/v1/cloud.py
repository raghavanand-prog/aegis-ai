"""Cloud security posture endpoints.

**AEGISX has no cloud provider integration.** There is no SDK in this project,
no credential handling, and no network call anywhere on this path. Findings are
computed by local checks from configuration snapshots stored on disk, every
stored row is flagged ``is_simulated``, and every response here repeats that in
a ``note`` field rather than leaving it to the documentation.

That is the same position ``CloudTrailFileSource`` has taken since V7, for the
same reason: this environment has no AWS account, and a "validated cloud
integration" without one would be a claim the project cannot support.

Two routes:

* ``GET  /cloud/findings`` - the posture backlog, worst first
* ``POST /cloud/scan``     - re-run the local checks over the snapshots

The scan is administrator-only and audited. It reads files this repository
ships, runs pure functions over them, and writes rows - it takes no path, no
URL and no credential from the caller, so there is nothing here for a caller to
point somewhere else.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.cloud.findings import FindingSeverity
from app.cloud.scanner import scan_all
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.cloud_finding import CloudPostureFinding
from app.models.enums import AuditAction
from app.models.user import User
from app.schemas.cloud import CloudFindingPage, CloudFindingRead, CloudScanRead
from app.services import audit_service, cloud_posture_service

router = APIRouter(prefix="/cloud", tags=["cloud"])


def _to_schema(row: CloudPostureFinding) -> CloudFindingRead:
    return CloudFindingRead.model_validate(
        {
            "findingId": row.finding_id,
            "checkId": row.check_id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "control": row.control,
            "resource": {
                "provider": row.provider,
                "account": row.account,
                "region": row.region,
                "service": row.service,
                "resourceType": row.resource_type,
                "resourceId": row.resource_id,
            },
            "detail": row.detail or {},
            "sourceFile": row.source_file,
            "isSimulated": row.is_simulated,
            "firstSeenAt": row.first_seen_at,
            "lastSeenAt": row.last_seen_at,
        }
    )


@router.get(
    "/findings",
    response_model=CloudFindingPage,
    summary="Cloud posture findings",
    description=(
        "Misconfigurations found by the local checks, worst severity first. **Simulated**: "
        "computed from configuration snapshots on disk, not from a cloud account. Severity "
        "orders the queue and is not a risk score - AEGISX cannot know what is in a bucket."
    ),
)
def list_findings(
    account: str | None = Query(default=None, max_length=64),
    severity: FindingSeverity | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require(Permission.CLOUD_READ)),
) -> CloudFindingPage:
    rows, total = cloud_posture_service.list_findings(
        db, account=account, severity=severity, limit=limit, offset=offset
    )
    return CloudFindingPage.model_validate(
        {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [_to_schema(row).model_dump(by_alias=True) for row in rows],
        }
    )


@router.post(
    "/scan",
    response_model=CloudScanRead,
    summary="Run the simulated posture scan",
    description=(
        "Re-runs every check over the configuration snapshots shipped with this repository "
        "and records the findings. **Nothing is contacted**: no cloud API, no credentials, "
        "no network. The caller supplies no path or target - the snapshots are the ones in "
        "the repository - so there is nothing here to point elsewhere. Administrator only, "
        "and audited, because it writes rows every analyst then reads."
    ),
)
def run_scan(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require(Permission.CLOUD_SCAN)),
) -> CloudScanRead:
    results = scan_all()

    created = 0
    updated = 0
    resources = 0
    for result in results:
        counts = cloud_posture_service.record_scan(db, result)
        created += counts["created"]
        updated += counts["updated"]
        resources += result.resources_scanned

    audit_service.record(
        db,
        action=AuditAction.CLOUD_POSTURE_SCANNED,
        user=user,
        target_type="cloud_posture",
        target_id="simulated-scan",
        details={
            "snapshots": [result.source_file for result in results],
            "resourcesScanned": resources,
            "findingsCreated": created,
            "findingsUpdated": updated,
            "isSimulated": True,
        },
        ip_address=client_ip(request),
    )
    db.commit()

    return CloudScanRead.model_validate(
        {
            "scans": [result.to_dict() for result in results],
            "findingsCreated": created,
            "findingsUpdated": updated,
            "resourcesScanned": resources,
        }
    )
