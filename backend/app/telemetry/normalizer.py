"""Normalization layer.

Vendor telemetry arrives in whatever shape the vendor chose. The normalizer
maps every source onto one canonical event structure so detection, storage and
the UI never need to know which product produced a record. Fields that do not
fit the canonical schema are preserved verbatim under ``normalized_data``.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import Severity, SourceType
from app.telemetry.base import RawTelemetry


class NormalizationError(ValueError):
    """Raised when a record cannot be mapped onto the canonical schema."""


def _ioc(kind: str, value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    return (kind, str(value))


def _candidate(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_type": "unknown",
        "title": "Security event",
        "description": None,
        "severity": Severity.LOW.value,
        "hostname": None,
        "username": None,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "process": None,
        "command_line": None,
        "normalized_data": {},
        "mitre_techniques": [],
        "iocs": [],
    }
    base.update(kwargs)
    return base


def _normalize_defender(raw: dict[str, Any]) -> dict[str, Any]:
    action = raw.get("ActionType", "")
    if action == "AntivirusDetection":
        threat = raw.get("ThreatName", "Unknown threat")
        return _candidate(
            event_type="malware_detected",
            title=f"Malware detected: {threat}",
            description=(
                f"{threat} found in {raw.get('FileName')} on {raw.get('DeviceName')}; "
                f"action taken: {raw.get('RemediationAction')}."
            ),
            severity=Severity.HIGH.value,
            hostname=raw.get("DeviceName"),
            username=raw.get("AccountName"),
            process=raw.get("InitiatingProcessFileName"),
            normalized_data={
                "threat_name": threat,
                "file_name": raw.get("FileName"),
                "sha256": raw.get("SHA256"),
                "remediation": raw.get("RemediationAction"),
                "vendor_severity": raw.get("Severity"),
            },
            iocs=[ioc for ioc in [_ioc("hash", raw.get("SHA256"))] if ioc],
        )

    return _candidate(
        event_type="antivirus_scan",
        title="Antivirus scan completed",
        description=(
            f"{raw.get('ScanType')} scan on {raw.get('DeviceName')} covered "
            f"{raw.get('FilesScanned')} files with {raw.get('ThreatsFound', 0)} detections."
        ),
        severity=Severity.LOW.value,
        hostname=raw.get("DeviceName"),
        normalized_data={
            "scan_type": raw.get("ScanType"),
            "files_scanned": raw.get("FilesScanned"),
            "threats_found": raw.get("ThreatsFound", 0),
        },
    )


def _normalize_sysmon(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = int(raw.get("EventID", 0) or 0)
    image = raw.get("Image") or ""
    process_name = image.split("\\")[-1] if image else None

    if event_id == 10:
        source_image = raw.get("SourceImage") or ""
        return _candidate(
            event_type="credential_access",
            title="Process accessed LSASS memory",
            description=(
                f"{source_image} opened {raw.get('TargetImage')} with access "
                f"{raw.get('GrantedAccess')} on {raw.get('Computer')}."
            ),
            severity=Severity.HIGH.value,
            hostname=raw.get("Computer"),
            username=raw.get("User"),
            process=source_image.split("\\")[-1] if source_image else None,
            normalized_data={
                "sysmon_event_id": event_id,
                "source_image": source_image,
                "target_image": raw.get("TargetImage"),
                "granted_access": raw.get("GrantedAccess"),
            },
        )

    command_line = raw.get("CommandLine")
    return _candidate(
        event_type="process_creation",
        title=f"Process created: {process_name or 'unknown'}",
        description=f"{command_line} started by {raw.get('ParentImage')} on {raw.get('Computer')}.",
        severity=Severity.LOW.value,
        hostname=raw.get("Computer"),
        username=raw.get("User"),
        process=process_name,
        command_line=command_line,
        normalized_data={
            "sysmon_event_id": event_id,
            "parent_image": raw.get("ParentImage"),
            "process_id": raw.get("ProcessId"),
            "image": image,
        },
    )


def _normalize_entra(raw: dict[str, Any]) -> dict[str, Any]:
    upn = raw.get("userPrincipalName", "")
    username = upn.split("@")[0] if upn else None
    location = raw.get("location") or {}
    country = location.get("countryOrRegion")

    if raw.get("impossibleTravel") or raw.get("riskEventType") == "impossibleTravel":
        return _candidate(
            event_type="anomalous_signin",
            title=f"Impossible travel sign-in for {username}",
            description=(
                f"Sign-in from {country} shortly after activity in "
                f"{(raw.get('previousLocation') or {}).get('countryOrRegion')}."
            ),
            severity=Severity.HIGH.value,
            username=username,
            source_ip=raw.get("ipAddress"),
            normalized_data={
                "impossible_travel": True,
                "risk_level": raw.get("riskLevelDuringSignIn"),
                "country": country,
                "previous_country": (raw.get("previousLocation") or {}).get("countryOrRegion"),
                "upn": upn,
            },
            iocs=[ioc for ioc in [_ioc("ip", raw.get("ipAddress"))] if ioc],
        )

    failures = int(raw.get("failureCount", 0) or 0)
    if raw.get("resultType") not in {"0", 0} or failures:
        return _candidate(
            event_type="auth_failure",
            title=f"{failures or 1} failed sign-in attempt(s) for {username}",
            description=f"{raw.get('resultDescription')} from {raw.get('ipAddress')} ({country}).",
            severity=Severity.MEDIUM.value if failures >= 5 else Severity.LOW.value,
            username=username,
            source_ip=raw.get("ipAddress"),
            normalized_data={
                "failure_count": failures,
                "result_type": raw.get("resultType"),
                "result_description": raw.get("resultDescription"),
                "country": country,
                "upn": upn,
            },
            iocs=[ioc for ioc in [_ioc("ip", raw.get("ipAddress"))] if ioc],
        )

    return _candidate(
        event_type="auth_success",
        title=f"Successful sign-in for {username}",
        description=f"{raw.get('appDisplayName')} sign-in from {raw.get('ipAddress')} ({country}).",
        severity=Severity.LOW.value,
        username=username,
        source_ip=raw.get("ipAddress"),
        normalized_data={
            "application": raw.get("appDisplayName"),
            "country": country,
            "risk_level": raw.get("riskLevelDuringSignIn"),
            "upn": upn,
        },
    )


def _normalize_firewall(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("action") == "deny":
        ports = int(raw.get("distinct_ports", 0) or 0)
        return _candidate(
            event_type="firewall_deny",
            title=f"Blocked connections from {raw.get('src_ip')}",
            description=(
                f"{raw.get('deny_count')} denied {raw.get('protocol')} connections across "
                f"{ports} ports towards {raw.get('dst_ip')}."
            ),
            severity=Severity.MEDIUM.value if ports >= 20 else Severity.LOW.value,
            source_ip=raw.get("src_ip"),
            destination_ip=raw.get("dst_ip"),
            destination_port=raw.get("dst_port"),
            normalized_data={
                "action": "deny",
                "protocol": raw.get("protocol"),
                "distinct_ports": ports,
                "deny_count": raw.get("deny_count"),
                "rule": raw.get("rule"),
            },
            iocs=[ioc for ioc in [_ioc("ip", raw.get("src_ip"))] if ioc],
        )

    return _candidate(
        event_type="firewall_allow",
        title=f"Outbound connection to {raw.get('dst_ip')}",
        description=(
            f"{raw.get('protocol')} {raw.get('src_ip')} -> {raw.get('dst_ip')}:"
            f"{raw.get('dst_port')} permitted by {raw.get('rule')}."
        ),
        severity=Severity.LOW.value,
        source_ip=raw.get("src_ip"),
        destination_ip=raw.get("dst_ip"),
        destination_port=raw.get("dst_port"),
        normalized_data={
            "action": "allow",
            "protocol": raw.get("protocol"),
            "bytes_out": raw.get("bytes_out"),
            "rule": raw.get("rule"),
        },
    )


def _normalize_dns(raw: dict[str, Any]) -> dict[str, Any]:
    domain = raw.get("query")
    periodic = bool(raw.get("periodic"))
    return _candidate(
        event_type="dns_query",
        title=f"DNS {raw.get('query_type')} query for {domain}",
        description=(
            f"{raw.get('client_ip')} resolved {domain} ({raw.get('response_code')})."
            + (f" {raw.get('query_count')} queries at a fixed interval." if periodic else "")
        ),
        severity=Severity.MEDIUM.value if periodic else Severity.LOW.value,
        source_ip=raw.get("client_ip"),
        destination_ip=raw.get("resolved_ip"),
        normalized_data={
            "query": domain,
            "query_type": raw.get("query_type"),
            "response_code": raw.get("response_code"),
            "query_count": raw.get("query_count", 0),
            "periodic": periodic,
            "interval_seconds": raw.get("interval_seconds"),
        },
        iocs=[ioc for ioc in [_ioc("domain", domain if periodic else None)] if ioc],
    )


def _normalize_linux(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("facility") == "sudo":
        return _candidate(
            event_type="privilege_escalation",
            title=f"Privileged command run by {raw.get('user')}",
            description=f"{raw.get('user')} executed {raw.get('command')} on {raw.get('host')}.",
            severity=Severity.MEDIUM.value,
            hostname=raw.get("host"),
            username=raw.get("user"),
            process="sudo",
            command_line=raw.get("command"),
            normalized_data={
                "facility": "sudo",
                "privilege_change": bool(raw.get("privilege_change")),
                "result": raw.get("result"),
            },
        )

    return _candidate(
        event_type="auth_success",
        title=f"SSH login accepted for {raw.get('user')}",
        description=(
            f"{raw.get('auth_method')} authentication from {raw.get('src_ip')} on {raw.get('host')}."
        ),
        severity=Severity.LOW.value,
        hostname=raw.get("host"),
        username=raw.get("user"),
        source_ip=raw.get("src_ip"),
        process="sshd",
        normalized_data={
            "facility": "sshd",
            "auth_method": raw.get("auth_method"),
            "result": raw.get("result"),
        },
    )


#: Outbound volume (bytes) at which an EDR transfer record is treated as an
#: exfiltration-shaped event. Matches the detection engine's own threshold.
EDR_EXFIL_BYTES = 500_000_000


def _edr_event_type(raw: dict[str, Any]) -> str:
    """Classify an EDR record from what it reports, not by elimination.

    Regression guard: this used to be a two-way branch that labelled every
    non-ransomware EDR record as ``data_exfiltration``, which handed the
    detection engine a pre-cooked verdict for benign file activity.
    """
    if raw.get("encryption_suspected"):
        return "ransomware_behavior"

    tactic = str(raw.get("tactic", "") or "").lower()
    bytes_out = raw.get("bytes_out") or 0
    try:
        bytes_out = int(bytes_out)
    except (TypeError, ValueError):
        bytes_out = 0

    if tactic == "exfiltration" or bytes_out >= EDR_EXFIL_BYTES:
        return "data_exfiltration"
    return "edr_detection"


def _normalize_edr(raw: dict[str, Any]) -> dict[str, Any]:
    technique = raw.get("technique")
    event_type = _edr_event_type(raw)
    is_ransomware = event_type == "ransomware_behavior"
    process = (raw.get("process") or "").split("\\")[-1] or None

    vendor_severity = str(raw.get("severity", "") or "").capitalize()
    if is_ransomware:
        severity = Severity.CRITICAL.value
    elif event_type == "data_exfiltration":
        severity = Severity.HIGH.value
    elif vendor_severity in {s.value for s in Severity}:
        severity = vendor_severity
    else:
        severity = Severity.LOW.value

    return _candidate(
        event_type=event_type,
        title=raw.get("detection_name", "EDR detection"),
        description=(
            f"{raw.get('detection_name')} on {raw.get('hostname')} "
            f"({raw.get('tactic')} / {technique})."
        ),
        severity=severity,
        hostname=raw.get("hostname"),
        username=raw.get("user"),
        process=process,
        command_line=raw.get("command_line"),
        destination_ip=raw.get("dst_ip"),
        mitre_techniques=[technique] if technique else [],
        normalized_data={
            "detection_name": raw.get("detection_name"),
            "tactic": raw.get("tactic"),
            "files_modified": raw.get("files_modified", 0),
            "encryption_suspected": is_ransomware,
            "bytes_out": raw.get("bytes_out", 0),
            "vendor_severity": raw.get("severity"),
        },
        iocs=[ioc for ioc in [_ioc("ip", raw.get("dst_ip"))] if ioc],
    )


#: source name -> mapper
NORMALIZERS = {
    "Microsoft Defender": _normalize_defender,
    "Sysmon": _normalize_sysmon,
    "Entra ID": _normalize_entra,
    "Perimeter Firewall": _normalize_firewall,
    "DNS Resolver": _normalize_dns,
    "Linux Auditd": _normalize_linux,
    "EDR Agent": _normalize_edr,
}

#: fallback mapper per telemetry class, used for sources with no dedicated map
FALLBACK_BY_TYPE = {
    SourceType.ENDPOINT: _normalize_sysmon,
    SourceType.IDENTITY: _normalize_entra,
    SourceType.FIREWALL: _normalize_firewall,
    SourceType.DNS: _normalize_dns,
    SourceType.OPERATING_SYSTEM: _normalize_linux,
    SourceType.EDR: _normalize_edr,
}


def normalize(record: RawTelemetry) -> dict[str, Any]:
    """Map one raw record onto the canonical event structure."""
    mapper = NORMALIZERS.get(record.source) or FALLBACK_BY_TYPE.get(record.source_type)
    if mapper is None:
        raise NormalizationError(f"No normalizer registered for source {record.source!r}")

    candidate = mapper(record.raw)
    candidate.update(
        {
            "source": record.source,
            "source_type": record.source_type.value,
            "timestamp": record.received_at,
            "raw_log": record.raw_log,
            "is_synthetic": record.is_synthetic,
        }
    )
    return candidate
