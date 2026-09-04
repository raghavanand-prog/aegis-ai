"""AWS CloudTrail management-event records.

**Why CloudTrail is the source V7 added.** It is the first adapter written
*against* the canonical contract rather than moved into it, so it is the test of
whether Phase 4's abstraction actually holds. It is also shaped unlike anything
already mapped: no hostname, no process, no command line, a principal expressed
as an ARN, and the interesting signal carried in an API name rather than in a
vendor's own severity. If a vendor field were going to leak into the canonical
contract, a source this different is where it would happen.

It is additionally the class of telemetry the long-term architecture points at -
cloud logs and IAM analysis - and it can be parsed and validated locally from
fixture files with no credentials and no network.

**This is fixture-backed and labelled simulated.** ``CloudTrailFileSource``
reads JSON files from disk. Nothing here has been run against a real AWS
account, no live provider has been called, and no claim in this project is
evidence about real cloud traffic. The records in ``fixtures/`` are hand-written
to the public CloudTrail record schema.

**Mapping choices, and what is deliberately not claimed.** The event types below
are drawn from the vocabulary the V4-V6 detection rules already use, so a
CloudTrail record reaches the same rules as an endpoint record rather than a
parallel cloud-only path. Where CloudTrail has no honest equivalent - a denied
API call is not a failed sign-in - a distinct type is emitted and **no existing
rule fires on it**. Stretching it onto ``auth_failure`` would have made a
cloud-detection capability appear to exist because a rule happened to match.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.adapters.base import AdapterError, TelemetryAdapter, candidate, ioc

#: The CloudTrail source name this adapter is registered for.
SOURCE_NAME = "AWS CloudTrail"

#: IAM and organisation API calls that grant or widen access. Detected as
#: ``privilege_escalation``, which DET-PRIV-001 already covers.
PRIVILEGE_GRANTING_EVENTS = frozenset(
    {
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "AddUserToGroup",
        "CreateAccessKey",
        "CreateLoginProfile",
        "CreateUser",
        "PutGroupPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "UpdateAssumeRolePolicy",
        "UpdateLoginProfile",
    }
)

#: Calls that read a secret. ``credential_access`` - DET-CRED-001's type.
CREDENTIAL_ACCESS_EVENTS = frozenset(
    {
        "BatchGetSecretValue",
        "Decrypt",
        "GetPasswordData",
        "GetSecretValue",
        "GetSessionToken",
    }
)

#: Bytes moved in a single recorded call at which the transfer is treated as
#: exfiltration-shaped. Matches the EDR adapter's threshold so the two sources
#: do not disagree about what "large" means.
EXFIL_BYTES = 500_000_000

#: Error codes that mean "denied", as opposed to a malformed request.
DENIAL_CODES = frozenset({"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"})


def _principal(identity: dict[str, Any]) -> str | None:
    """The acting principal, preferring the human-legible form.

    ``userName`` where AWS supplied one, else the last ARN segment, else the
    principal id. Never the account id: an account is not a user, and putting
    one in the username column would group every principal in the account
    together in the UI and in the per-group cap.
    """
    for key in ("userName", "sessionIssuerUserName"):
        value = identity.get(key)
        if value:
            return str(value)
    arn = identity.get("arn")
    if arn:
        tail = str(arn).rsplit("/", 1)[-1]
        return tail or str(arn)
    principal_id = identity.get("principalId")
    return str(principal_id) if principal_id else None


def _bytes_transferred(raw: dict[str, Any]) -> int:
    additional = raw.get("additionalEventData") or {}
    for key in ("bytesTransferredOut", "bytesTransferredIn"):
        value = additional.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
    return 0


def _classify(raw: dict[str, Any], event_name: str) -> tuple[str, str]:
    """Return ``(event_type, severity)`` for one record.

    Ordered most-specific first. A denied call is classified as denied even when
    the API it attempted is privilege-granting: the attempt is the fact, and
    reporting a failed ``AttachUserPolicy`` as a privilege escalation would
    record a change that did not happen.
    """
    if raw.get("errorCode") in DENIAL_CODES:
        return "cloud_api_denied", Severity.MEDIUM.value

    if event_name == "ConsoleLogin":
        failed = (raw.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
        if failed:
            return "auth_failure", Severity.MEDIUM.value
        return "auth_success", Severity.LOW.value

    if event_name in CREDENTIAL_ACCESS_EVENTS:
        return "credential_access", Severity.HIGH.value

    if event_name in PRIVILEGE_GRANTING_EVENTS:
        return "privilege_escalation", Severity.HIGH.value

    if _bytes_transferred(raw) >= EXFIL_BYTES:
        return "data_exfiltration", Severity.HIGH.value

    return "cloud_api_call", Severity.LOW.value


class CloudTrailAdapter(TelemetryAdapter):
    """Maps a CloudTrail record onto the canonical contract."""

    name = "cloudtrail"
    source_names = (SOURCE_NAME,)
    source_type = SourceType.CLOUD
    #: Deliberately no ``fallback_for``. A cloud log is not necessarily
    #: CloudTrail, and parsing an unknown cloud source with this adapter would
    #: produce confident nonsense - the failure mode V6's silent
    #: ``FALLBACK_BY_TYPE`` had and nobody could see.

    def parse(self, raw: dict[str, Any]):
        event_name = raw.get("eventName")
        event_source = raw.get("eventSource")
        if not event_name or not event_source:
            raise AdapterError(
                "A CloudTrail record must carry eventName and eventSource. "
                f"Got keys {sorted(raw)[:8]}. Refusing rather than emitting an "
                "event whose action is unknown."
            )

        identity = raw.get("userIdentity") or {}
        username = _principal(identity)
        event_type, severity = _classify(raw, str(event_name))
        source_ip = raw.get("sourceIPAddress")
        region = raw.get("awsRegion")
        error_code = raw.get("errorCode")

        description = (
            f"{username or 'an unidentified principal'} called {event_name} on "
            f"{event_source} in {region or 'an unknown region'}"
            + (f"; denied ({error_code})." if error_code else ".")
        )

        return self.from_candidate(
            candidate(
                event_type=event_type,
                title=f"AWS {event_name} by {username or 'unknown principal'}",
                description=description,
                severity=severity,
                username=username,
                source_ip=source_ip,
                # No hostname, no process, no command line: CloudTrail describes
                # an API call, and inventing a host for one would put a machine
                # name in front of an analyst that does not exist.
                normalized_data={
                    "aws_event_name": event_name,
                    "aws_event_source": event_source,
                    "aws_region": region,
                    "aws_account_id": raw.get("recipientAccountId")
                    or identity.get("accountId"),
                    "principal_type": identity.get("type"),
                    "principal_arn": identity.get("arn"),
                    "user_agent": raw.get("userAgent"),
                    "error_code": error_code,
                    "error_message": raw.get("errorMessage"),
                    "read_only": raw.get("readOnly"),
                    "management_event": raw.get("managementEvent"),
                    "mfa_authenticated": (
                        (identity.get("sessionContext") or {})
                        .get("attributes", {})
                        .get("mfaAuthenticated")
                    ),
                    "bytes_transferred": _bytes_transferred(raw),
                    "request_parameters": raw.get("requestParameters") or {},
                },
                # CloudTrail asserts no ATT&CK technique, so this adapter
                # asserts none either. Inferring one from the API name would put
                # attribution nobody made in front of an analyst.
                mitre_techniques=[],
                iocs=[entry for entry in [ioc("ip", source_ip)] if entry],
            )
        )
