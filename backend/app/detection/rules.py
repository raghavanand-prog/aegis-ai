"""Detection rules (deterministic).

These are hand-written rules, not a model. Every detection AEGISX produces is
explainable by construction: a rule matches, and the rule says in plain words
why it matched.

Rule identity
-------------
Each rule has a stable id (``DET-<AREA>-<NNN>``) and a semantic version. The id
is written onto every detection, so a stored event always says which version of
which rule produced it. Changing what a rule matches means bumping its version;
the id never gets reused for different logic.

The ``legacy_id`` field carries the V1 identifier (``AEGIS-R0xx``) so detections
stored before the V2 rename remain interpretable.

Rules read only fields a real collector would populate, so the same rules apply
unchanged to synthetic telemetry, to the labelled evaluation dataset, and to a
future real source.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from app.models.enums import Severity

SEVERITY_ORDER = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

LOLBINS = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "msbuild.exe",
}

ENCODED_POWERSHELL = re.compile(r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE)
SUSPICIOUS_DOWNLOAD = re.compile(
    r"(invoke-webrequest|downloadstring|curl\s+http|wget\s+http|iwr\s+http)", re.IGNORECASE
)
# Long, high-entropy looking labels are a crude DGA/beaconing signal.
DGA_LABEL = re.compile(r"^[a-z0-9]{16,}$", re.IGNORECASE)

#: Thresholds live here rather than inside the matchers so the evaluation
#: dataset and the documentation can reference the same numbers.
BRUTE_FORCE_MIN_FAILURES = 5
PORT_SCAN_MIN_PORTS = 20
PORT_SCAN_MIN_DENIES = 50
RANSOMWARE_MIN_FILES = 200
BEACON_MIN_QUERIES = 50
EXFIL_MIN_BYTES = 500_000_000


@dataclass(frozen=True)
class Rule:
    """One deterministic detection rule.

    ``matches`` returns a human readable reason when the rule fires, or None.
    Returning the reason (rather than a bool) is what makes every detection
    explainable without a second lookup table.
    """

    id: str
    version: str
    name: str
    description: str
    severity: Severity
    risk: int
    mitre: tuple[str, ...]
    #: Ground-truth labels this rule is intended to catch (used by evaluation).
    labels: tuple[str, ...]
    matches: Callable[[dict[str, Any]], str | None]
    legacy_id: str | None = None

    @property
    def identity(self) -> str:
        return f"{self.id}@{self.version}"


@dataclass
class Detection:
    """A single rule match, as stored on the event and shown to the analyst."""

    rule_id: str
    rule_version: str
    rule_name: str
    reason: str
    severity: str
    risk_contribution: int
    mitre_techniques: list[str]
    matched_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "ruleVersion": self.rule_version,
            "ruleName": self.rule_name,
            "reason": self.reason,
            "severity": self.severity,
            "riskContribution": self.risk_contribution,
            "mitreTechniques": list(self.mitre_techniques),
            "matchedAt": self.matched_at,
        }


@dataclass
class DetectionResult:
    severity: str
    risk_score: int
    mitre_techniques: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    #: Wall-clock time spent evaluating every rule against this event.
    duration_ms: float = 0.0

    @property
    def matched(self) -> bool:
        return bool(self.matched_rules)

    def detections_as_dicts(self) -> list[dict[str, Any]]:
        return [detection.to_dict() for detection in self.detections]


# --------------------------------------------------------------------------- helpers
def _get(candidate: dict[str, Any], key: str, default: Any = None) -> Any:
    value = candidate.get(key)
    return default if value is None else value


def _text(candidate: dict[str, Any], key: str) -> str:
    return str(_get(candidate, key, "") or "").lower()


def _data(candidate: dict[str, Any]) -> dict[str, Any]:
    payload = candidate.get("normalized_data") or {}
    return payload if isinstance(payload, dict) else {}


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- matchers
def _failed_login_burst(candidate: dict[str, Any]) -> str | None:
    if _text(candidate, "event_type") not in {"auth_failure", "sign_in_failure"}:
        return None
    failures = _int(_data(candidate).get("failure_count"))
    if failures < BRUTE_FORCE_MIN_FAILURES:
        return None
    principal = _get(candidate, "username", "an account")
    source = _get(candidate, "source_ip", "an unknown address")
    return (
        f"{failures} authentication failures for {principal} from {source} "
        f"(threshold {BRUTE_FORCE_MIN_FAILURES})"
    )


def _encoded_powershell(candidate: dict[str, Any]) -> str | None:
    command = str(_get(candidate, "command_line", "") or "")
    if "powershell" not in _text(candidate, "process"):
        return None
    match = ENCODED_POWERSHELL.search(command)
    if not match:
        return None
    return (
        "PowerShell launched with a base64 encoded command "
        f"({len(match.group(0))} character payload), which hides the script from log review"
    )


def _remote_download(candidate: dict[str, Any]) -> str | None:
    command = str(_get(candidate, "command_line", "") or "")
    match = SUSPICIOUS_DOWNLOAD.search(command)
    if not match:
        return None
    return f"Command line fetches remote content using {match.group(0).strip()!r}"


def _lolbin(candidate: dict[str, Any]) -> str | None:
    process = _text(candidate, "process").split("\\")[-1]
    if process not in LOLBINS:
        return None
    return f"{process} is a signed Windows binary commonly abused to run attacker code"


def _credential_dumping(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    target = str(data.get("target_image", "") or data.get("target_process", "")).lower()
    if "lsass" in target:
        source = data.get("source_image") or _get(candidate, "process", "a process")
        access = data.get("granted_access")
        return (
            f"{source} opened LSASS memory"
            + (f" with access mask {access}" if access else "")
            + " - the standard step for stealing credentials"
        )
    if _text(candidate, "event_type") == "credential_access":
        return "Telemetry classified this activity as credential access"
    return None


def _ransomware(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    files = _int(data.get("files_modified"))
    if _text(candidate, "event_type") == "ransomware_behavior":
        return f"Endpoint agent reported mass encryption behaviour ({files} files modified)"
    if files >= RANSOMWARE_MIN_FILES and data.get("encryption_suspected"):
        return (
            f"{files} files modified with encryption suspected "
            f"(threshold {RANSOMWARE_MIN_FILES})"
        )
    return None


def _malware_detected(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    threat = data.get("threat_name")
    if _text(candidate, "event_type") in {"malware_detected", "threat_detected"} or threat:
        return f"Endpoint protection named a threat: {threat or 'unnamed detection'}"
    return None


def _dns_beaconing(candidate: dict[str, Any]) -> str | None:
    if _text(candidate, "event_type") not in {"dns_query", "dns_request"}:
        return None

    data = _data(candidate)
    domain = str(data.get("query", "") or "")
    label = domain.split(".")[0] if domain else ""
    queries = _int(data.get("query_count"))

    if DGA_LABEL.match(label):
        return (
            f"Domain {domain} has a {len(label)} character random-looking label, "
            "consistent with algorithmically generated infrastructure"
        )
    if data.get("periodic") or queries >= BEACON_MIN_QUERIES:
        interval = data.get("interval_seconds")
        return (
            f"{queries} queries for {domain}"
            + (f" at a fixed {interval}s interval" if interval else "")
            + " - a beaconing pattern rather than user browsing"
        )
    return None


def _port_scan(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    ports = _int(data.get("distinct_ports"))
    denies = _int(data.get("deny_count"))

    if ports >= PORT_SCAN_MIN_PORTS:
        return (
            f"{_get(candidate, 'source_ip', 'A source')} touched {ports} distinct ports "
            f"(threshold {PORT_SCAN_MIN_PORTS})"
        )
    if _text(candidate, "event_type") == "firewall_deny" and denies >= PORT_SCAN_MIN_DENIES:
        return f"{denies} blocked connection attempts (threshold {PORT_SCAN_MIN_DENIES})"
    return None


def _impossible_travel(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    if data.get("impossible_travel") or _text(candidate, "event_type") == "anomalous_signin":
        previous = data.get("previous_country")
        current = data.get("country")
        return (
            "Sign-in location is not physically reachable from the previous sign-in"
            + (f" ({previous} -> {current})" if previous and current else "")
        )
    return None


def _privilege_escalation(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    if _text(candidate, "event_type") in {"privilege_escalation", "sudo_abuse"}:
        return f"Privileged command executed by {_get(candidate, 'username', 'a user')}"
    if data.get("privilege_change") and _text(candidate, "username") != "root":
        return (
            f"Privilege change for non-root account {_get(candidate, 'username', 'unknown')}"
        )
    return None


def _data_exfiltration(candidate: dict[str, Any]) -> str | None:
    data = _data(candidate)
    volume = _int(data.get("bytes_out"))
    if _text(candidate, "event_type") == "data_exfiltration":
        return f"Telemetry classified this transfer as exfiltration ({volume} bytes)"
    if volume >= EXFIL_MIN_BYTES:
        return (
            f"{round(volume / 1_000_000)} MB left the environment in one transfer "
            f"(threshold {round(EXFIL_MIN_BYTES / 1_000_000)} MB)"
        )
    return None


# --------------------------------------------------------------------------- catalogue
RULES: tuple[Rule, ...] = (
    Rule(
        id="DET-AUTH-001",
        version="1.0",
        legacy_id="AEGIS-R001",
        name="Credential brute force",
        description=(
            "Repeated authentication failures for a single principal within one telemetry "
            f"record (>= {BRUTE_FORCE_MIN_FAILURES} failures)."
        ),
        severity=Severity.HIGH,
        risk=45,
        mitre=("T1110",),
        labels=("BRUTE_FORCE",),
        matches=_failed_login_burst,
    ),
    Rule(
        id="DET-PS-001",
        version="1.0",
        legacy_id="AEGIS-R002",
        name="Suspicious PowerShell",
        description="PowerShell started with a long base64 encoded command.",
        severity=Severity.HIGH,
        risk=50,
        mitre=("T1059.001", "T1027"),
        labels=("SUSPICIOUS_POWERSHELL",),
        matches=_encoded_powershell,
    ),
    Rule(
        id="DET-EXEC-001",
        version="1.0",
        legacy_id="AEGIS-R003",
        name="Remote payload download",
        description="Command line downloads content from a remote host.",
        severity=Severity.MEDIUM,
        risk=30,
        mitre=("T1105",),
        labels=("SUSPICIOUS_DOWNLOAD",),
        matches=_remote_download,
    ),
    Rule(
        id="DET-EXEC-002",
        version="1.0",
        legacy_id="AEGIS-R004",
        name="Living-off-the-land binary",
        description="Execution of a signed Windows binary commonly abused by attackers.",
        severity=Severity.MEDIUM,
        risk=30,
        mitre=("T1218",),
        labels=("LOLBIN_EXECUTION",),
        matches=_lolbin,
    ),
    Rule(
        id="DET-CRED-001",
        version="1.0",
        legacy_id="AEGIS-R005",
        name="Credential dumping",
        description="A process read LSASS memory, or telemetry flagged credential access.",
        severity=Severity.CRITICAL,
        risk=80,
        mitre=("T1003.001",),
        labels=("CREDENTIAL_ACCESS",),
        matches=_credential_dumping,
    ),
    Rule(
        id="DET-RANSOM-001",
        version="1.0",
        legacy_id="AEGIS-R006",
        name="Ransomware behaviour",
        description=(
            "Mass file modification consistent with encryption "
            f"(>= {RANSOMWARE_MIN_FILES} files)."
        ),
        severity=Severity.CRITICAL,
        risk=90,
        mitre=("T1486",),
        labels=("RANSOMWARE",),
        matches=_ransomware,
    ),
    Rule(
        id="DET-MAL-001",
        version="1.0",
        legacy_id="AEGIS-R007",
        name="Malware detected",
        description="Endpoint protection reported a named threat.",
        severity=Severity.HIGH,
        risk=55,
        mitre=("T1204.002",),
        labels=("MALWARE",),
        matches=_malware_detected,
    ),
    Rule(
        id="DET-DNS-001",
        version="1.0",
        legacy_id="AEGIS-R008",
        name="Suspicious DNS beaconing",
        description="Algorithmically generated or periodic DNS traffic.",
        severity=Severity.HIGH,
        risk=50,
        mitre=("T1071.004",),
        labels=("SUSPICIOUS_DNS",),
        matches=_dns_beaconing,
    ),
    Rule(
        id="DET-NET-001",
        version="1.0",
        legacy_id="AEGIS-R009",
        name="Network reconnaissance",
        description=(
            f"Connections across many distinct ports (>= {PORT_SCAN_MIN_PORTS}) or a large "
            f"burst of denies (>= {PORT_SCAN_MIN_DENIES})."
        ),
        severity=Severity.MEDIUM,
        risk=35,
        mitre=("T1046",),
        labels=("PORT_SCAN",),
        matches=_port_scan,
    ),
    Rule(
        id="DET-AUTH-002",
        version="1.0",
        legacy_id="AEGIS-R010",
        name="Anomalous sign-in",
        description="Sign-in from a location that is implausible for this principal.",
        severity=Severity.HIGH,
        risk=45,
        mitre=("T1078",),
        labels=("ANOMALOUS_SIGNIN",),
        matches=_impossible_travel,
    ),
    Rule(
        id="DET-PRIV-001",
        version="1.0",
        legacy_id="AEGIS-R011",
        name="Privilege escalation",
        description="Unexpected privilege change or privileged command for a standard account.",
        severity=Severity.HIGH,
        risk=55,
        mitre=("T1548",),
        labels=("PRIVILEGE_ESCALATION",),
        matches=_privilege_escalation,
    ),
    Rule(
        id="DET-EXFIL-001",
        version="1.0",
        legacy_id="AEGIS-R012",
        name="Large outbound transfer",
        description=(
            "Unusually large volume of data leaving the environment "
            f"(>= {round(EXFIL_MIN_BYTES / 1_000_000)} MB)."
        ),
        severity=Severity.CRITICAL,
        risk=70,
        mitre=("T1041",),
        labels=("DATA_EXFILTRATION",),
        matches=_data_exfiltration,
    ),
)

#: id -> rule, for lookups from the API and the evaluation reports.
RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

#: V1 id -> V2 id, so detections stored before the rename stay interpretable.
LEGACY_RULE_IDS: dict[str, str] = {
    rule.legacy_id: rule.id for rule in RULES if rule.legacy_id is not None
}

#: Ground-truth labels the rule set claims to cover. Anything outside this set
#: is a known blind spot rather than an accident - evaluation reports it as such.
COVERED_LABELS: frozenset[str] = frozenset(
    label for rule in RULES for label in rule.labels
)


def catalogue() -> list[dict[str, Any]]:
    """Machine-readable rule catalogue (served by the API, used in docs)."""
    return [
        {
            "id": rule.id,
            "version": rule.version,
            "legacyId": rule.legacy_id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.value,
            "riskContribution": rule.risk,
            "mitreTechniques": list(rule.mitre),
            "labels": list(rule.labels),
        }
        for rule in RULES
    ]


def evaluate(
    candidate: dict[str, Any], *, base_severity: str = Severity.LOW.value
) -> DetectionResult:
    """Run every rule against a normalized event candidate.

    A rule that raises is skipped rather than allowed to drop the event: losing
    telemetry because one matcher has a bug is worse than missing one detection.
    """
    started = datetime.now(timezone.utc)
    start_perf = perf_counter()

    severity = base_severity
    risk = 0
    techniques: list[str] = list(candidate.get("mitre_techniques") or [])
    matched: list[str] = []
    detections: list[Detection] = []

    for rule in RULES:
        try:
            reason = rule.matches(candidate)
        except Exception:  # noqa: BLE001, S112 - a broken rule must not drop telemetry
            continue
        if not reason:
            continue

        matched.append(rule.id)
        risk += rule.risk
        if SEVERITY_ORDER[rule.severity.value] > SEVERITY_ORDER.get(severity, 1):
            severity = rule.severity.value
        for technique in rule.mitre:
            if technique not in techniques:
                techniques.append(technique)

        detections.append(
            Detection(
                rule_id=rule.id,
                rule_version=rule.version,
                rule_name=rule.name,
                reason=reason,
                severity=rule.severity.value,
                risk_contribution=rule.risk,
                mitre_techniques=list(rule.mitre),
                matched_at=started.isoformat(),
            )
        )

    return DetectionResult(
        severity=severity,
        risk_score=min(risk, 100),
        mitre_techniques=techniques,
        matched_rules=matched,
        detections=detections,
        duration_ms=(perf_counter() - start_perf) * 1000.0,
    )
