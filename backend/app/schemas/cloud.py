"""Cloud posture schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import CamelModel

#: Stated on every response that carries findings. Not a footnote in the docs:
#: a reader who takes these for real cloud findings would draw conclusions
#: about infrastructure that does not exist.
SIMULATION_NOTE = (
    "Simulated. AEGISX has no cloud provider integration: findings are computed "
    "from configuration snapshots on disk by local checks, and no cloud account "
    "has been contacted."
)


class CloudResourceRead(CamelModel):
    provider: str
    account: str
    region: str | None = None
    service: str
    resource_type: str
    resource_id: str


class CloudFindingRead(CamelModel):
    finding_id: str
    check_id: str
    title: str
    description: str
    severity: str
    #: The hardening theme, in words. Never a benchmark identifier - see
    #: ``app/cloud/checks.py``.
    control: str | None = None
    resource: CloudResourceRead
    detail: dict = Field(default_factory=dict)
    source_file: str | None = None
    is_simulated: bool
    first_seen_at: datetime
    last_seen_at: datetime


class CloudFindingPage(CamelModel):
    total: int
    limit: int
    offset: int
    items: list[CloudFindingRead] = Field(default_factory=list)
    note: str = SIMULATION_NOTE


class CloudScanRead(CamelModel):
    """What one simulated scan did."""

    scans: list[dict] = Field(default_factory=list)
    findings_created: int
    findings_updated: int
    resources_scanned: int
    is_simulated: bool = True
    note: str = SIMULATION_NOTE
