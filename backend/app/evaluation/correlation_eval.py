"""Behavioural correlation evaluation.

What is being measured, and against what ground truth
-----------------------------------------------------

The corpus is built from the synthetic *campaign* generators, which emit a
multi-event attack as a unit: repeated sign-in failures against one account
followed by a success, one principal reaching several hosts, a host moving
through several activity stages. Each campaign is injected with a known
identity, so ground truth here is not a per-event label - it is **"these
specific events belong to one attack"**.

Around them sits ordinary unrelated traffic, so a correlator that groups on
entity alone rather than on behaviour is penalised rather than flattered.

Metrics, and what each one is not
---------------------------------

``campaignDetectionRate``
    Fraction of injected campaigns that produced at least one sequence. This is
    recall over *attacks*, not over events.

``sequencePurity``
    For each sequence matched to a campaign, the fraction of its members that
    actually belong to that campaign. This is the metric that catches
    over-grouping - the V3 bug where a sequence keyed on a user swallowed
    unrelated DNS and antivirus events, inflating both its size and its score.

``spuriousSequenceRate``
    Sequences that match no injected campaign, over all sequences. A sequence
    over background traffic is not automatically wrong - real analysts do open
    cases on odd-looking benign activity - so this is reported as a rate to be
    read, not as an error count.

``alertReduction``
    Events absorbed into sequences versus sequences produced. The operational
    claim correlation makes is that an analyst reads fewer things; this
    measures whether that is true here.

What this evaluation deliberately does not claim
------------------------------------------------

AEGISX's patterns are hand-written and entity-scoped. This measures how well
those specific patterns recover campaigns the same project generated, which is
a weaker claim than "AEGISX correlates real attacks well". It is **not**
comparable to learned attack-graph inference, and no result here should be
read as evidence about one.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.correlation import engine as correlation_engine
from app.models.event import Event
from app.repositories.event_repository import event_repository
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import NormalizationError, normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

logger = logging.getLogger("aegisx.evaluation.correlation")

REPORT_SCHEMA_VERSION = "1.0"

CAMPAIGN_BUILDERS = (
    "_campaign_credential_attack",
    "_campaign_lateral_movement",
    "_campaign_host_intrusion",
)


@dataclass
class Campaign:
    """One injected attack, and the events it produced."""

    campaign_id: str
    kind: str
    event_ids: set[int] = field(default_factory=set)


@dataclass
class CorrelationReport:
    schema_version: str
    generated_at: str
    campaigns: list[dict[str, Any]]
    totals: dict[str, Any]
    latency: dict[str, Any]
    sequences: list[dict[str, Any]]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "generatedAt": self.generated_at,
            "campaigns": self.campaigns,
            "totals": self.totals,
            "latency": self.latency,
            "sequences": self.sequences,
            "notes": self.notes,
        }

    def to_text(self) -> str:
        totals = self.totals
        lines = [
            "",
            "=" * 78,
            "  AEGISX V4 CORRELATION EVALUATION",
            "=" * 78,
            "",
            f"  Campaigns injected      {totals['campaignsInjected']}",
            f"  Campaigns detected      {totals['campaignsDetected']}"
            f"  ({_pct(totals['campaignDetectionRate'])})",
            f"  Background events       {totals['backgroundEvents']}",
            f"  Events ingested         {totals['eventsIngested']}",
            "",
            f"  Sequences opened        {totals['sequencesOpened']}",
            f"  Matched to a campaign   {totals['sequencesMatched']}",
            f"  Spurious                {totals['spuriousSequences']}"
            f"  ({_pct(totals['spuriousSequenceRate'])})",
            f"  Mean sequence purity    {_pct(totals['meanSequencePurity'])}",
            f"  Mean sequence size      {totals['meanSequenceSize']}",
            f"  Mean confidence         {totals['meanConfidence']}",
            "",
            f"  Alert reduction         {totals['eventsInSequences']} events -> "
            f"{totals['sequencesOpened']} sequences "
            f"({totals['alertReductionFactor']}x)",
            "",
            "  Correlation latency (per ingested event, database included)",
            f"    mean {self.latency['meanMs']} ms   p95 {self.latency['p95Ms']} ms   "
            f"p99 {self.latency['p99Ms']} ms",
            "",
            "  BY CAMPAIGN KIND",
        ]
        for entry in self.campaigns:
            lines.append(
                f"    {entry['kind']:32} {entry['detected']}/{entry['injected']} detected"
                f"   purity {_pct(entry['meanPurity'])}"
            )
        lines.append("")
        lines.append("  NOTES")
        for note in self.notes:
            lines.append(f"    - {note}")
        lines.append("")
        lines.append("=" * 78)
        return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "NOT AVAILABLE" if value is None else f"{value * 100:.1f}%"


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return round(ordered[index], 4)


def _persist(db: Session, record: RawTelemetry) -> Event | None:
    """Persist one normalized record as an event, without the full pipeline.

    Deliberately narrow: this evaluation measures correlation, so it stores the
    normalized event and calls the correlation engine, and leaves scoring,
    notification and broadcasting out. Anything else would be measuring the
    ingestion path instead.
    """
    try:
        candidate = normalize(record)
    except NormalizationError:
        return None

    event = Event(
        timestamp=candidate["timestamp"],
        source=candidate["source"],
        source_type=candidate["source_type"],
        event_type=candidate["event_type"],
        title=candidate["title"],
        description=candidate.get("description"),
        severity=candidate["severity"],
        status="New",
        risk_score=0,
        risk_level="Low",
        risk_signals=[],
        hostname=candidate.get("hostname"),
        username=candidate.get("username"),
        source_ip=candidate.get("source_ip"),
        destination_ip=candidate.get("destination_ip"),
        destination_port=candidate.get("destination_port"),
        process=candidate.get("process"),
        command_line=candidate.get("command_line"),
        raw_log=candidate.get("raw_log"),
        normalized_data=candidate.get("normalized_data") or {},
        mitre_techniques=[],
        detection_rules=[],
        detections=[],
        is_synthetic=True,
    )
    return event_repository.create(db, event)


def run_correlation_evaluation(
    db: Session,
    *,
    campaigns_per_kind: int = 8,
    background_events: int = 200,
    seed: int = 4242,
) -> CorrelationReport:
    """Inject known campaigns into background traffic and measure recovery."""
    source = SyntheticTelemetrySource(seed=seed)
    now = datetime.now(timezone.utc)

    # Build the schedule first so campaign events are interleaved with
    # background traffic rather than arriving as clean, isolated bursts.
    scheduled: list[tuple[RawTelemetry, str | None]] = []
    campaigns: dict[str, Campaign] = {}

    for kind in CAMPAIGN_BUILDERS:
        builder = getattr(source, kind)
        for index in range(campaigns_per_kind):
            campaign_id = f"{kind}-{index:03d}"
            campaigns[campaign_id] = Campaign(campaign_id=campaign_id, kind=kind)
            for record in builder():
                scheduled.append((record, campaign_id))

    for record in source.collect(background_events):
        scheduled.append((record, None))

    # Deterministic interleave: a fixed stride rather than a shuffle, so the
    # arrival order is reproducible without depending on RNG call ordering.
    scheduled.sort(key=lambda item: (hash(item[0].raw_log) % 997, item[1] or ""))

    latencies: list[float] = []
    ingested = 0
    background = 0
    start = now - timedelta(minutes=25)

    for offset, (record, campaign_id) in enumerate(scheduled):
        # Compress everything into the correlation window; a campaign spread
        # over hours would be a test of the window setting, not the patterns.
        record.received_at = start + timedelta(seconds=offset * 2)
        event = _persist(db, record)
        if event is None:
            continue
        db.flush()
        ingested += 1
        if campaign_id is None:
            background += 1
        else:
            campaigns[campaign_id].event_ids.add(event.id)

        began = time.perf_counter()
        correlation_engine.correlate_event(db, event, broadcast=False)
        latencies.append((time.perf_counter() - began) * 1000.0)

    db.flush()

    from app.models.sequence import SecuritySequence

    sequences = list(db.query(SecuritySequence).all())

    sequence_rows: list[dict[str, Any]] = []
    matched_campaigns: set[str] = set()
    purities_by_campaign_kind: dict[str, list[float]] = {kind: [] for kind in CAMPAIGN_BUILDERS}
    all_purities: list[float] = []
    spurious = 0
    events_in_sequences = 0

    for sequence in sequences:
        member_ids = {event.id for event in sequence.events}
        events_in_sequences += len(member_ids)

        # Attribute the sequence to whichever campaign contributes most of it.
        best_campaign: Campaign | None = None
        best_overlap = 0
        for campaign in campaigns.values():
            overlap = len(member_ids & campaign.event_ids)
            if overlap > best_overlap:
                best_campaign, best_overlap = campaign, overlap

        purity = best_overlap / len(member_ids) if member_ids else None
        if best_campaign is None or best_overlap == 0:
            spurious += 1
        else:
            matched_campaigns.add(best_campaign.campaign_id)
            purities_by_campaign_kind[best_campaign.kind].append(purity or 0.0)
            all_purities.append(purity or 0.0)

        sequence_rows.append(
            {
                "sequenceId": sequence.sequence_id,
                "pattern": sequence.pattern,
                "eventCount": len(member_ids),
                "confidence": sequence.confidence,
                "riskScore": sequence.risk_score,
                "matchedCampaign": best_campaign.campaign_id if best_campaign else None,
                "matchedCampaignKind": best_campaign.kind if best_campaign else None,
                "purity": round(purity, 4) if purity is not None else None,
                "membersFromCampaign": best_overlap,
            }
        )

    per_kind: list[dict[str, Any]] = []
    for kind in CAMPAIGN_BUILDERS:
        injected = sum(1 for c in campaigns.values() if c.kind == kind)
        detected = sum(
            1
            for c in campaigns.values()
            if c.kind == kind and c.campaign_id in matched_campaigns
        )
        purities = purities_by_campaign_kind[kind]
        per_kind.append(
            {
                "kind": kind,
                "injected": injected,
                "detected": detected,
                "detectionRate": round(detected / injected, 4) if injected else None,
                "meanPurity": (
                    round(sum(purities) / len(purities), 4) if purities else None
                ),
            }
        )

    confidences = [s.confidence for s in sequences if s.confidence is not None]
    sizes = [len(s.events) for s in sequences]

    totals = {
        "campaignsInjected": len(campaigns),
        "campaignsDetected": len(matched_campaigns),
        "campaignDetectionRate": (
            round(len(matched_campaigns) / len(campaigns), 4) if campaigns else None
        ),
        "backgroundEvents": background,
        "eventsIngested": ingested,
        "sequencesOpened": len(sequences),
        "sequencesMatched": len(sequences) - spurious,
        "spuriousSequences": spurious,
        "spuriousSequenceRate": (
            round(spurious / len(sequences), 4) if sequences else None
        ),
        "meanSequencePurity": (
            round(sum(all_purities) / len(all_purities), 4) if all_purities else None
        ),
        "meanSequenceSize": round(sum(sizes) / len(sizes), 2) if sizes else None,
        "meanConfidence": (
            round(sum(confidences) / len(confidences), 4) if confidences else None
        ),
        "eventsInSequences": events_in_sequences,
        "alertReductionFactor": (
            round(events_in_sequences / len(sequences), 2) if sequences else None
        ),
    }

    latency = {
        "measured": "correlate_event() including its database queries",
        "samples": len(latencies),
        "meanMs": round(sum(latencies) / len(latencies), 4) if latencies else None,
        "p50Ms": _percentile(latencies, 0.50),
        "p95Ms": _percentile(latencies, 0.95),
        "p99Ms": _percentile(latencies, 0.99),
        "maxMs": round(max(latencies), 4) if latencies else None,
    }

    notes = [
        "Ground truth is campaign membership, not a per-event label: the question "
        "is whether the correlator recovered the attack, not whether it flagged "
        "each event.",
        "A sequence is attributed to the campaign contributing most of its members; "
        "purity is the fraction of members that actually belong to that campaign.",
        "Spurious sequences are reported as a rate, not counted as errors. A "
        "sequence over background traffic can be legitimate.",
        "AEGISX correlation is hand-written, entity-scoped and time-bounded. These "
        "figures measure recovery of campaigns this project generated; they are NOT "
        "evidence about real attacks and NOT comparable to learned attack-graph "
        "inference.",
        "Purity is depressed partly by the evaluation setup, not only by the "
        "correlator: the synthetic generator draws from a small pool of users and "
        "hosts, so background traffic legitimately shares an entity with a campaign "
        "and an entity-scoped correlator cannot separate the two. The figure is a "
        "lower bound on purity and an upper bound on how well entity scoping can "
        "ever do on a namespace this small.",
        "Latency includes database access and was measured on a development "
        "machine against SQLite. It is not a production throughput claim.",
    ]

    report = CorrelationReport(
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=datetime.now(timezone.utc).isoformat(),
        campaigns=per_kind,
        totals=totals,
        latency=latency,
        sequences=sorted(sequence_rows, key=lambda row: row["sequenceId"]),
        notes=notes,
    )
    logger.info(
        "Correlation evaluation: %s/%s campaigns detected, %s sequences, purity %s",
        totals["campaignsDetected"],
        totals["campaignsInjected"],
        totals["sequencesOpened"],
        totals["meanSequencePurity"],
    )
    return report
