"""The posture checks AEGISX runs, and what they are worth.

Each check is a pure function from one resource's configuration to zero or one
findings. They are ordinary code, tested like ordinary code - the *input* is
what is fixture-backed, not the logic. A real scanner replaces where the
configuration snapshot comes from and reuses every check below unchanged.

**On compliance frameworks.** These checks are modelled on widely published
cloud hardening guidance, and the ``control`` field names the theme each one
addresses in plain words. It deliberately does **not** carry CIS, NIST or
ISO control numbers. AEGISX has not been assessed against any of those
frameworks, and a benchmark identifier next to a finding reads as a compliance
mapping somebody validated. Nobody validated one here, and inventing the
numbers would be exactly the kind of unearned authority this project has
avoided elsewhere.

**On severity.** The severity attached to each check is the check author's
judgement about the configuration in isolation. It is not risk: a public bucket
holding public data is not a critical problem, and AEGISX cannot know what is
in the bucket. Severity orders a queue; it does not conclude anything.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from app.cloud.findings import CloudFinding, FindingSeverity
from app.cloud.resources import ResourceRef, parse_arn

logger = logging.getLogger(__name__)

#: Ports that should not be reachable from the whole internet. Not a complete
#: list of dangerous exposure - it is the set this check can justify.
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis"}

#: The one CIDR that means "everybody".
ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    """One resource's configuration, as a scanner would have read it."""

    arn: str
    resource_kind: str
    config: dict[str, Any]

    @property
    def ref(self) -> ResourceRef | None:
        return parse_arn(self.arn)


#: A check: given a snapshot, either a finding or nothing.
Check = Callable[[ResourceSnapshot], CloudFinding | None]


def _finding(
    snapshot: ResourceSnapshot,
    *,
    check_id: str,
    title: str,
    description: str,
    severity: FindingSeverity,
    control: str,
    detail: dict[str, Any],
) -> CloudFinding | None:
    ref = snapshot.ref
    if ref is None:
        # An unparseable ARN produces no finding rather than an unattached one.
        # A finding nobody can locate cannot be remediated and would attach to
        # nothing during correlation.
        return None
    return CloudFinding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        resource=ref,
        detail=detail,
        control=control,
        is_simulated=True,
    )


# --- Storage ---------------------------------------------------------------


def check_bucket_public(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "s3_bucket":
        return None
    if snapshot.config.get("publicAccessBlock") is not False:
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-S3-001",
        title="Bucket is not protected by a public access block",
        description=(
            "Public access block is disabled, so a bucket or object policy is "
            "able to expose this bucket's contents to anonymous callers."
        ),
        severity=FindingSeverity.CRITICAL,
        control="Object storage should not be reachable anonymously",
        detail={"publicAccessBlock": False},
    )


def check_bucket_unencrypted(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "s3_bucket":
        return None
    if snapshot.config.get("defaultEncryption"):
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-S3-002",
        title="Bucket has no default encryption",
        description=(
            "Objects written without an explicit encryption header are stored "
            "unencrypted at rest."
        ),
        severity=FindingSeverity.HIGH,
        control="Data at rest should be encrypted by default",
        detail={"defaultEncryption": snapshot.config.get("defaultEncryption")},
    )


def check_bucket_no_logging(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "s3_bucket":
        return None
    if snapshot.config.get("accessLogging"):
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-S3-003",
        title="Bucket has no access logging",
        description=(
            "Reads and writes are not recorded, so an investigation cannot "
            "establish afterwards what was taken from this bucket."
        ),
        severity=FindingSeverity.MEDIUM,
        control="Access to sensitive stores should be recorded",
        detail={"accessLogging": False},
    )


# --- Identity --------------------------------------------------------------


def check_role_trusts_anyone(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "iam_role":
        return None
    principals = snapshot.config.get("trustPolicyPrincipals") or []
    if "*" not in principals:
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-IAM-001",
        title="Role can be assumed by any principal",
        description=(
            "The trust policy allows sts:AssumeRole from Principal '*'. Anyone "
            "who can reach the STS endpoint can take this role's permissions."
        ),
        severity=FindingSeverity.CRITICAL,
        control="Roles should be assumable only by named principals",
        detail={"trustPolicyPrincipals": list(principals)},
    )


def check_role_is_administrator(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind not in {"iam_role", "iam_user"}:
        return None
    attached = snapshot.config.get("attachedPolicies") or []
    admin = [name for name in attached if "AdministratorAccess" in str(name)]
    if not admin:
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-IAM-002",
        title="Principal holds full administrative access",
        description=(
            "AdministratorAccess grants every action on every resource, so any "
            "compromise of this principal is a compromise of the account."
        ),
        severity=FindingSeverity.HIGH,
        control="Permissions should be scoped to what the principal does",
        detail={"attachedPolicies": admin},
    )


def check_user_without_mfa(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "iam_user":
        return None
    if snapshot.config.get("mfaEnabled") is not False:
        return None
    if not snapshot.config.get("consoleAccess"):
        # No console password means no interactive sign-in to protect.
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-IAM-003",
        title="Console user has no MFA",
        description=(
            "This user can sign in to the console with a password alone, so a "
            "single credential is enough to reach the account."
        ),
        severity=FindingSeverity.HIGH,
        control="Interactive sign-in should require a second factor",
        detail={"mfaEnabled": False, "consoleAccess": True},
    )


def check_access_key_stale(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "iam_user":
        return None
    age = snapshot.config.get("oldestAccessKeyAgeDays")
    if not isinstance(age, int) or age < 365:
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-IAM-004",
        title="Access key has not been rotated for over a year",
        description=(
            "A long-lived static credential has had a long time to leak, and "
            "nothing about its age is visible to whoever holds a copy."
        ),
        severity=FindingSeverity.MEDIUM,
        control="Static credentials should be rotated",
        detail={"oldestAccessKeyAgeDays": age},
    )


# --- Network ---------------------------------------------------------------


def check_security_group_open(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "security_group":
        return None

    exposed: list[dict[str, Any]] = []
    for rule in snapshot.config.get("ingress") or []:
        cidr = str(rule.get("cidr", ""))
        if cidr not in {ANY_IPV4, ANY_IPV6}:
            continue
        port = rule.get("port")
        if isinstance(port, int) and port in ADMIN_PORTS:
            exposed.append({"port": port, "service": ADMIN_PORTS[port], "cidr": cidr})

    if not exposed:
        return None

    names = ", ".join(sorted({entry["service"] for entry in exposed}))
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-NET-001",
        title=f"Administrative access open to the internet ({names})",
        description=(
            f"Ingress from {ANY_IPV4} reaches {names}. Anything reachable this "
            "way is reachable by every scanner on the internet."
        ),
        severity=FindingSeverity.CRITICAL,
        control="Administrative ports should not be internet-facing",
        detail={"exposed": exposed},
    )


# --- Logging ---------------------------------------------------------------


def check_trail_disabled(snapshot: ResourceSnapshot) -> CloudFinding | None:
    if snapshot.resource_kind != "cloudtrail_trail":
        return None
    if snapshot.config.get("isLogging"):
        return None
    return _finding(
        snapshot,
        check_id="AEGISX-CLD-LOG-001",
        title="Trail is not logging",
        description=(
            "API activity for this trail is not being recorded. An "
            "investigation covering this period will have no cloud audit trail."
        ),
        severity=FindingSeverity.HIGH,
        control="Control-plane activity should be recorded",
        detail={"isLogging": False},
    )


#: Every check, in a stable order so a scan's output is reproducible.
CHECKS: tuple[Check, ...] = (
    check_bucket_public,
    check_bucket_unencrypted,
    check_bucket_no_logging,
    check_role_trusts_anyone,
    check_role_is_administrator,
    check_user_without_mfa,
    check_access_key_stale,
    check_security_group_open,
    check_trail_disabled,
)


def run_checks(snapshots: Iterable[ResourceSnapshot]) -> list[CloudFinding]:
    """Every finding across every resource.

    A check that raises is a bug in that check, and it must not cost the
    findings from the other eight - the same reasoning as the evidence
    registry. It is re-raised nowhere and reported as no finding, which is the
    conservative direction: a missing finding is visible as an absence in the
    check coverage, whereas a half-finished scan silently claims a clean bill.
    """
    findings: list[CloudFinding] = []
    for snapshot in snapshots:
        for check in CHECKS:
            try:
                finding = check(snapshot)
            except Exception as exc:  # noqa: BLE001 - one bad check must not void the scan
                logger.warning(
                    "cloud posture check failed",
                    extra={
                        "check": getattr(check, "__name__", "unknown"),
                        "error": type(exc).__name__,
                    },
                )
                continue
            if finding is not None:
                findings.append(finding)
    return findings
