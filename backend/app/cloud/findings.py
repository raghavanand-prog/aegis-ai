"""What a cloud posture finding is.

A finding is a *reported* claim: some scanner asserts that a resource is
configured in a way that is dangerous. It is not telemetry - nothing happened -
and it is not a detection. An analyst weighs it differently from either, which
is why it gets its own evidence kind rather than being squeezed into one of the
existing six.

Every finding this project produces is ``is_simulated=True`` and the flag has no
default. Nothing in AEGISX has scanned a real cloud account; a record that
claimed otherwise would be the most misleading thing the platform could hold,
so producing one has to be a deliberate act rather than an omission.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.ai.sanitize import contains_injection_attempt, scrub_text, scrub_value
from app.cloud.resources import ResourceRef


class FindingSeverity(str, Enum):
    """How bad this configuration is, as the check author judged it.

    Deliberately the same four words as ``Severity`` on an event, so a console
    does not present an analyst with two severity scales to reconcile. It is a
    separate enum because a posture severity and an alert severity are not the
    same measurement and merging the types would invite averaging them.
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


_ORDER = {
    FindingSeverity.CRITICAL: 4,
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
}


def severity_rank(severity: FindingSeverity) -> int:
    """For ordering. Not a score, and never summed."""
    return _ORDER[severity]


@dataclass(frozen=True, slots=True)
class CloudFinding:
    """One misconfiguration, on one resource, as asserted by one check."""

    check_id: str
    title: str
    description: str
    severity: FindingSeverity
    resource: ResourceRef | None
    #: Check-specific facts. Scrubbed, because it is rendered and reaches the
    #: AI analyst's evidence package.
    detail: dict[str, Any]
    #: Whether this came from a simulated scan. Required, never defaulted.
    is_simulated: bool
    #: The control this check is modelled on, when there is one. A name, not a
    #: compliance claim - see ``checks.py``.
    control: str | None = field(default=None)

    def __post_init__(self) -> None:
        if self.resource is None:
            raise ValueError(
                "A finding must name the resource it is about. A misconfiguration "
                "with no resource cannot be remediated or correlated."
            )
        if not (self.check_id or "").strip():
            raise ValueError("A finding must carry its check_id.")
        if not (self.description or "").strip():
            raise ValueError(
                "A finding must say what is wrong. A severity with no description "
                "is an alarm an analyst cannot act on."
            )

    @property
    def contains_injection_attempt(self) -> bool:
        """Whether the finding's text tries to steer a reader.

        Posture findings reach the AI analyst through the same evidence
        package as everything else, so they are checked by the same sanitiser.
        A second implementation here would be a second thing to keep correct.
        """
        return contains_injection_attempt(self.title) or contains_injection_attempt(
            self.description
        )

    def to_dict(self) -> dict[str, Any]:
        assert self.resource is not None  # guaranteed by __post_init__
        return {
            "findingId": finding_id(self),
            "checkId": self.check_id,
            "title": scrub_text(self.title),
            "description": scrub_text(self.description),
            "severity": self.severity.value,
            "control": self.control,
            "resource": {
                "provider": self.resource.provider.value,
                "account": self.resource.account,
                "region": self.resource.region,
                "service": self.resource.service,
                "resourceType": self.resource.resource_type,
                "resourceId": self.resource.resource_id,
                "key": self.resource.key,
            },
            "detail": scrub_value(self.detail),
            "isSimulated": self.is_simulated,
        }


def finding_id(finding: CloudFinding) -> str:
    """A stable identity for "this check, on this resource".

    Covers what the finding is *about* and nothing else - not when it was seen,
    not its description, not its detail. A posture scan run nightly must
    recognise yesterday's finding as the same problem rather than accumulating
    a new one every night, and a check whose wording is improved must not
    orphan every finding it has ever raised.
    """
    assert finding.resource is not None
    digest = hashlib.sha256(
        f"{finding.check_id}|{finding.resource.key}".encode()
    ).hexdigest()
    return f"CF-{digest[:16]}"
