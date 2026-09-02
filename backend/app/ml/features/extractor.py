"""Feature extraction: normalized event -> numeric vector.

One implementation, used by training, by evaluation and by live inference. That
is the whole point: a feature that is computed one way when the model is fitted
and another way when it scores production traffic produces a detector that
looks excellent in evaluation and is useless in the SOC.

Design rules this module holds to:

1. **No detection output is ever a feature.** Rule matches, rule severity and
   the rule risk score are deliberately excluded. Feeding the rules' own verdict
   to the anomaly detector would make the two signals correlated by
   construction, and the "hybrid" score would be measuring the rules twice.
2. **Deterministic.** No randomness, no clock reads. Anything time-dependent
   comes from the event's own timestamp or from the supplied context.
3. **Bounded.** Every value is scaled or clipped, so one absurd field in a
   malformed record cannot dominate the vector.
4. **Explainable.** Feature names are plain English, because they are shown to
   an analyst as the reason an event was flagged.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.ml.features.context import BehaviorContext
from app.ml.schemas import FEATURE_SCHEMA_VERSION, FeatureVector

# --------------------------------------------------------------------------- vocab
#: Event classes the extractor recognises. Anything else lands in "other", so
#: a new telemetry source cannot silently change the vector's width.
EVENT_CLASSES: tuple[str, ...] = (
    "authentication",
    "process",
    "network",
    "dns",
    "malware",
    "file",
    "privilege",
)

_EVENT_TYPE_CLASS: dict[str, str] = {
    "auth_failure": "authentication",
    "sign_in_failure": "authentication",
    "auth_success": "authentication",
    "sign_in_success": "authentication",
    "anomalous_signin": "authentication",
    "ssh_login": "authentication",
    "process_creation": "process",
    "credential_access": "process",
    "sudo_abuse": "privilege",
    "privilege_escalation": "privilege",
    "firewall_allow": "network",
    "firewall_deny": "network",
    "network_connection": "network",
    "data_exfiltration": "network",
    "lateral_movement": "network",
    "dns_query": "dns",
    "dns_request": "dns",
    "malware_detected": "malware",
    "threat_detected": "malware",
    "antivirus_scan": "malware",
    "ransomware_behavior": "file",
    "file_modification": "file",
}

_FAILURE_EVENT_TYPES = {"auth_failure", "sign_in_failure"}
_SUCCESS_EVENT_TYPES = {"auth_success", "sign_in_success", "ssh_login"}

LOLBINS = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "cscript.exe",
    "wscript.exe",
}

SHELLS = {"powershell.exe", "cmd.exe", "bash", "sh", "zsh", "pwsh.exe", "python.exe"}

#: RFC 1918 plus the RFC 5737 documentation range the synthetic generator uses
#: for "inside the estate". Anything else counts as external.
_INTERNAL_PREFIXES = ("10.", "192.168.", "198.51.100.", "127.")
_INTERNAL_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")

#: Ports a workstation talks to all day. Traffic to anything else is not
#: suspicious by itself, but it is *unusual*, which is what the model wants.
COMMON_PORTS = {80, 443, 53, 22, 3389, 445, 139, 25, 587, 993, 143, 123, 389, 636}


# --------------------------------------------------------------------------- helpers
def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or isinstance(value, bool):
            return float(bool(value)) if isinstance(value, bool) else default
        return float(value)
    except (TypeError, ValueError):
        return default


def _log_scale(value: float, ceiling: float) -> float:
    """Compress a wide numeric range into 0..1.

    Byte counts and event counts span orders of magnitude; without this a single
    500 MB transfer would swamp every other feature in the distance metric.
    """
    if value <= 0:
        return 0.0
    return min(math.log1p(value) / math.log1p(ceiling), 1.0)


def _entropy(text: str) -> float:
    """Shannon entropy per character, normalized to 0..1.

    A cheap numeric description of how varied a string's characters are.

    Worth stating plainly, because the obvious intuition is wrong: this does
    NOT reliably mark encoded payloads as "high entropy". Base64-encoded
    PowerShell is UTF-16LE underneath, so it is dense in repeated ``A``
    characters and scores *lower* than an ordinary varied command line. The
    feature is still informative - it separates repetitive machine-generated
    strings from hand-typed ones in both directions - but it is not an
    encoded-payload detector, and the deterministic rule DET-PS-001 is what
    actually catches those.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    bits = -sum((n / total) * math.log2(n / total) for n in counts.values())
    # log2(95) covers printable ASCII; 6.6 bits/char is effectively random.
    return min(bits / 6.6, 1.0)


def _is_internal(address: str | None) -> bool:
    if not address:
        return False
    return address.startswith(_INTERNAL_PREFIXES) or bool(_INTERNAL_172.match(address))


def _basename(process: str | None) -> str:
    if not process:
        return ""
    return process.replace("/", "\\").split("\\")[-1].lower()


def _event_class(event_type: str) -> str:
    return _EVENT_TYPE_CLASS.get(event_type, "other")


def _timestamp(candidate: dict[str, Any]) -> datetime:
    stamp = candidate.get("timestamp")
    if isinstance(stamp, datetime):
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    if isinstance(stamp, str):
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _data(candidate: dict[str, Any]) -> dict[str, Any]:
    payload = candidate.get("normalized_data") or {}
    return payload if isinstance(payload, dict) else {}


# --------------------------------------------------------------------------- schema
#: The feature vector, in order. This tuple IS the schema: changing it means
#: bumping FEATURE_SCHEMA_VERSION and retraining, because a model fitted on the
#: old order cannot read the new one.
FEATURE_NAMES: tuple[str, ...] = (
    # --- temporal ---------------------------------------------------------
    "hour_sin",
    "hour_cos",
    "day_of_week",
    "is_off_hours",
    "is_weekend",
    # --- event shape ------------------------------------------------------
    *(f"class_{name}" for name in EVENT_CLASSES),
    "class_other",
    # --- authentication ---------------------------------------------------
    "auth_failure_count",
    "is_auth_failure",
    "is_auth_success",
    "user_failure_ratio",
    # --- network ----------------------------------------------------------
    "destination_port_scaled",
    "is_uncommon_port",
    "bytes_out_scaled",
    "bytes_in_scaled",
    "distinct_ports_scaled",
    "connection_count_scaled",
    "source_is_external",
    "destination_is_external",
    # --- process ----------------------------------------------------------
    "is_process_event",
    "command_length_scaled",
    "command_entropy",
    "is_lolbin",
    "is_shell",
    "process_rarity",
    # --- entity frequency -------------------------------------------------
    "host_event_count_scaled",
    "user_event_count_scaled",
    "source_ip_event_count_scaled",
    "host_is_new",
    "user_is_new",
    "source_ip_is_new",
    # --- behavioural diversity / burstiness -------------------------------
    "host_distinct_users_scaled",
    "user_distinct_hosts_scaled",
    "source_ip_distinct_destinations_scaled",
    "host_events_per_minute_scaled",
    "source_ip_events_per_minute_scaled",
    # --- payload volume ---------------------------------------------------
    "files_modified_scaled",
    "query_count_scaled",
    "raw_log_length_scaled",
)

FEATURE_COUNT = len(FEATURE_NAMES)


class FeatureExtractor:
    """Turns normalized event candidates into :class:`FeatureVector` instances."""

    schema_version = FEATURE_SCHEMA_VERSION
    names = FEATURE_NAMES

    def __init__(self, context: BehaviorContext | None = None) -> None:
        #: Owned rather than optional: features that need history must behave
        #: identically whether or not a caller supplied a context, so an empty
        #: one is created instead of silently changing the vector's meaning.
        self.context = context if context is not None else BehaviorContext()

    # ------------------------------------------------------------------- main
    def extract(self, candidate: dict[str, Any], *, observe: bool = True) -> FeatureVector:
        """Build the vector for one candidate.

        The context is read *before* the event is recorded, so "how many events
        has this host produced" never counts the event being described.
        """
        stamp = _timestamp(candidate)
        data = _data(candidate)
        event_type = str(candidate.get("event_type") or "unknown").lower()
        event_class = _event_class(event_type)

        hostname = candidate.get("hostname")
        username = candidate.get("username")
        source_ip = candidate.get("source_ip")
        destination_ip = candidate.get("destination_ip")
        process = _basename(candidate.get("process"))
        command_line = str(candidate.get("command_line") or "")

        host_ctx = self.context.snapshot("host", hostname, stamp)
        user_ctx = self.context.snapshot("user", username, stamp)
        ip_ctx = self.context.snapshot("source_ip", source_ip, stamp)
        process_ctx = self.context.snapshot("process", process or None, stamp)

        hour = stamp.hour
        weekday = stamp.weekday()
        destination_port = int(_num(candidate.get("destination_port")))

        values: list[float] = [
            # temporal - hour as a circle, so 23:00 and 00:00 are neighbours
            math.sin(2 * math.pi * hour / 24),
            math.cos(2 * math.pi * hour / 24),
            weekday / 6.0,
            1.0 if (hour < 7 or hour >= 19) else 0.0,
            1.0 if weekday >= 5 else 0.0,
        ]

        values.extend(1.0 if event_class == name else 0.0 for name in EVENT_CLASSES)
        values.append(1.0 if event_class == "other" else 0.0)

        # authentication
        values.extend(
            [
                _log_scale(_num(data.get("failure_count")), 100),
                1.0 if event_type in _FAILURE_EVENT_TYPES else 0.0,
                1.0 if event_type in _SUCCESS_EVENT_TYPES else 0.0,
                float(user_ctx["failure_ratio"]),
            ]
        )

        # network
        values.extend(
            [
                min(destination_port / 65535.0, 1.0) if destination_port > 0 else 0.0,
                1.0 if destination_port > 0 and destination_port not in COMMON_PORTS else 0.0,
                _log_scale(_num(data.get("bytes_out") or data.get("bytes_sent")), 1_000_000_000),
                _log_scale(_num(data.get("bytes_in") or data.get("bytes_received")), 1_000_000_000),
                _log_scale(_num(data.get("distinct_ports")), 1_000),
                _log_scale(
                    _num(data.get("connection_count") or data.get("deny_count")), 1_000
                ),
                0.0 if _is_internal(source_ip) else (1.0 if source_ip else 0.0),
                0.0 if _is_internal(destination_ip) else (1.0 if destination_ip else 0.0),
            ]
        )

        # process
        values.extend(
            [
                1.0 if event_class in {"process", "privilege"} else 0.0,
                _log_scale(len(command_line), 4_096),
                _entropy(command_line),
                1.0 if process in LOLBINS else 0.0,
                1.0 if process in SHELLS else 0.0,
                # Rarity: 1.0 for a process never seen in the window, falling
                # away as it becomes routine.
                1.0 / (1.0 + process_ctx["count"]) if process else 0.0,
            ]
        )

        # entity frequency
        values.extend(
            [
                _log_scale(host_ctx["count"], 500),
                _log_scale(user_ctx["count"], 500),
                _log_scale(ip_ctx["count"], 500),
                float(host_ctx["is_new"]),
                float(user_ctx["is_new"]),
                float(ip_ctx["is_new"]),
            ]
        )

        # behavioural diversity and burstiness
        values.extend(
            [
                _log_scale(host_ctx["distinct_companions"], 50),
                _log_scale(user_ctx["distinct_companions"], 50),
                _log_scale(ip_ctx["distinct_companions"], 100),
                _log_scale(host_ctx["rate_per_minute"], 60),
                _log_scale(ip_ctx["rate_per_minute"], 60),
            ]
        )

        # payload volume
        values.extend(
            [
                _log_scale(_num(data.get("files_modified")), 10_000),
                _log_scale(_num(data.get("query_count")), 1_000),
                _log_scale(len(str(candidate.get("raw_log") or "")), 4_096),
            ]
        )

        if observe:
            self.observe(candidate)

        assert len(values) == FEATURE_COUNT, (  # noqa: S101 - guards the schema contract
            f"feature vector width drifted: {len(values)} != {FEATURE_COUNT}"
        )
        return FeatureVector(names=FEATURE_NAMES, values=tuple(values))

    # ---------------------------------------------------------------- context
    def observe(self, candidate: dict[str, Any]) -> None:
        """Fold one event into the rolling context."""
        stamp = _timestamp(candidate)
        event_type = str(candidate.get("event_type") or "unknown").lower()
        hostname = candidate.get("hostname")
        username = candidate.get("username")
        source_ip = candidate.get("source_ip")
        destination_ip = candidate.get("destination_ip")
        destination_port = candidate.get("destination_port")
        process = _basename(candidate.get("process"))

        outcome = None
        if event_type in _FAILURE_EVENT_TYPES:
            outcome = "failure"
        elif event_type in _SUCCESS_EVENT_TYPES:
            outcome = "success"

        self.context.observe(
            "host", hostname, timestamp=stamp, companion=username, outcome=outcome
        )
        self.context.observe(
            "user", username, timestamp=stamp, companion=hostname, outcome=outcome
        )
        self.context.observe(
            "source_ip",
            source_ip,
            timestamp=stamp,
            companion=(
                f"{destination_ip}:{destination_port}"
                if destination_ip or destination_port
                else None
            ),
            outcome=outcome,
        )
        if process:
            self.context.observe("process", process, timestamp=stamp, companion=hostname)
        if destination_ip:
            self.context.observe("destination", destination_ip, timestamp=stamp)

    def reset(self) -> None:
        self.context.reset()
