"""UNSW-NB15 -> AEGISX normalized event.

    parquet row -> RawTelemetry (firewall-shaped) -> production normalize()
                -> normalized candidate -> production FeatureExtractor

The adapter's whole job is the first arrow. Everything after it is the code
that runs in ingestion, unmodified, which is what makes it legitimate to
compare these numbers to the way AEGISX behaves in production.

Mapping decisions, and the reasoning behind each
------------------------------------------------

**Every flow becomes ``firewall_allow``, never ``firewall_deny``.** UNSW-NB15
is a passive capture: the ``state`` column records how the TCP conversation
ended (FIN, RST, INT...), not whether a policy engine permitted or blocked it.
Reading "RST" as "the firewall denied this" would invent a policy decision the
capture never made - and would hand the port-scan rule a ``deny_count`` it
could fire on, manufacturing detections out of a type error. So the action is
always ``allow`` and the port-scan rule stays silent.

**No aggregate counters are synthesised.** AEGISX's ``distinct_ports`` and
``deny_count`` describe a firewall's own aggregation over a window. A single
flow record cannot supply them, and deriving them by grouping rows would be
constructing evidence the sensor never produced.

**The 40+ engineered UNSW features are dropped, on purpose.** They stop at the
adapter boundary and never reach the candidate. AEGISX's production feature
extractor is the only feature path in the evaluation, so the ML numbers measure
*AEGISX's* feature schema rather than the dataset's. (A supervised reference
model over the native features is reported separately, clearly labelled as a
different feature space.)

Consequence, stated up front rather than discovered in the results
-----------------------------------------------------------------

AEGISX's deterministic rules are endpoint-, identity- and process-oriented.
On flow-only telemetry, ten of the twelve cannot fire for want of the fields
they read; the port-scan rule cannot fire because no policy decision exists;
and the exfiltration rule cannot fire because the largest flow in the corpus
is 13.7 MB against a 500 MB threshold. **The expected rules baseline on this
dataset is zero detections, and that is a property of the telemetry, not a
measured failure of the rules.** See docs/DATASET_CARD.md.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from app.evaluation.datasets.base import EvaluationSample
from app.models.enums import SourceType
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize

SOURCE_NAME = "Perimeter Firewall"

#: Columns the adapter reads. Everything else in the source is ignored, and
#: listing them here makes "what could possibly have reached a feature" a
#: closed, reviewable set.
REQUIRED_COLUMNS: tuple[str, ...] = (
    "srcip",
    "sport",
    "dstip",
    "dsport",
    "proto",
    "state",
    "service",
    "dur",
    "sbytes",
    "dbytes",
    "Spkts",
    "Dpkts",
    "Stime",
    "attack_cat",
    "label",
)

#: Columns that take part in the duplicate group key. The label is excluded -
#: grouping must be decided by the observation, not by its answer.
GROUP_COLUMNS: tuple[str, ...] = tuple(
    column for column in REQUIRED_COLUMNS if column not in ("attack_cat", "label")
)


class AdapterError(ValueError):
    """Raised when a source row cannot be mapped without inventing something."""


def parse_port(value: Any) -> int | None:
    """Parse a UNSW port field.

    80 of the 2.28M rows carry a hexadecimal port (``0x000c``) and a few carry
    a dash. Both are parsed or refused explicitly; neither is silently coerced
    to zero, which would create a plausible-looking port that was never seen.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def group_key(row: dict[str, Any]) -> str:
    """Stable key placing exact duplicates of a flow in the same split.

    46% of the corpus (1,053,500 rows) participates in an exact-duplicate
    group. Without this, copies of a training flow appear in the test set and
    every metric is inflated by memorisation. No duplicate group in the source
    carries conflicting labels, so grouping loses no information.
    """
    digest = hashlib.sha256()
    for column in GROUP_COLUMNS:
        digest.update(str(row.get(column)).encode())
        digest.update(b"\x00")
    return digest.hexdigest()[:24]


def to_raw_telemetry(row: dict[str, Any], *, index: int) -> RawTelemetry:
    """Map one flow record onto a vendor-shaped firewall record."""
    src = row.get("srcip")
    dst = row.get("dstip")
    if not src or not dst:
        raise AdapterError(f"row {index} has no source or destination address")

    stime = row.get("Stime")
    if stime is None:
        raise AdapterError(f"row {index} has no start time")
    timestamp = datetime.fromtimestamp(int(stime), tz=timezone.utc)

    protocol = str(row.get("proto") or "unknown").lower()
    dst_port = parse_port(row.get("dsport"))
    src_port = parse_port(row.get("sport"))
    sbytes = int(row.get("sbytes") or 0)
    dbytes = int(row.get("dbytes") or 0)
    service = str(row.get("service") or "-")
    state = str(row.get("state") or "-")

    raw: dict[str, Any] = {
        # Fields the production firewall normalizer reads.
        "action": "allow",
        "src_ip": str(src),
        "dst_ip": str(dst),
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_out": sbytes,
        "rule": "observed-flow",
        # Retained for traceability in the raw log only. These are NOT read by
        # the normalizer and cannot reach a feature.
        "src_port": src_port,
        "bytes_in": dbytes,
        "service": service,
        "state": state,
        "duration_seconds": float(row.get("dur") or 0.0),
        "packets_out": int(row.get("Spkts") or 0),
        "packets_in": int(row.get("Dpkts") or 0),
    }

    raw_log = (
        f"[FLOW] {protocol} {src}:{src_port if src_port is not None else '-'} -> "
        f"{dst}:{dst_port if dst_port is not None else '-'} "
        f"service={service} state={state} sbytes={sbytes} dbytes={dbytes}"
    )

    return RawTelemetry(
        source=SOURCE_NAME,
        source_type=SourceType.FIREWALL,
        raw=raw,
        raw_log=raw_log,
        received_at=timestamp,
        # Real captured traffic, not generated by AEGISX. The flag is what the
        # UI and the AI evidence package read to decide whether a finding is
        # about real activity, so it must not lie.
        is_synthetic=False,
    )


def to_sample(row: dict[str, Any], *, index: int, category: str, is_malicious: bool) -> EvaluationSample:
    """Map one labelled flow onto a normalized, evaluation-ready sample."""
    record = to_raw_telemetry(row, index=index)
    candidate = normalize(record)
    return EvaluationSample(
        id=f"UNSW-{index:08d}",
        category=category,
        is_malicious=is_malicious,
        candidate=candidate,
        timestamp=record.received_at,
        group_key=group_key(row),
        original_label=str(row.get("attack_cat") or ""),
    )
