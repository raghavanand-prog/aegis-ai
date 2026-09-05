"""The built-in evidence providers.

Each one projects rows AEGISX already holds into ``EvidenceItem``s. None of them
copies a source object: ``content`` carries the facts an analyst reads in a
list, and ``source_ref`` points at the row holding everything else.

The integrity level each provider declares is a statement about the actual
storage, checked against the code that writes it, not an aspiration:

===================  ==============  =========================================
Source               Integrity       Why
===================  ==============  =========================================
Event                write_once      Written at ingestion; ``detections`` and
                                     ``risk_signals`` are set there and not
                                     rewritten afterwards.
MLInference          append_only     Unique per (event, model, version), and
                                     the threshold in force is stored on the
                                     row so a later change cannot rewrite it.
AIAnalysis           append_only     A new row per request; never updated.
SecuritySequence     mutable         A sequence is *extended* as related
                                     events arrive - the event count, risk and
                                     rationale all change in place.
IOC                  mutable         ``sighting_count`` is incremented and
                                     ``last_seen`` moved on every new sighting.
ThreatIntelResult    mutable         Re-lookup **overwrites** status,
                                     reputation and ``looked_up_at`` on the
                                     existing row. The verdict behind a past
                                     decision can change with nothing to show
                                     for it but the digest.
===================  ==============  =========================================

That last row is the one worth reading twice. It is not a defect introduced
here - it is how V3 designed the cache, sensibly, to avoid unbounded growth -
but it means a threat-intelligence verdict is the *least* stable evidence in
the system and it must not be presented as though it were a fixed record.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.evidence.models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceOrigin,
    Integrity,
    Provenance,
)
from app.evidence.provider import HEALTHY, EvidenceProvider, ProviderHealth
from app.evidence.registry import register

#: Bounds, for the same reason ``app.ai.evidence`` has them: an incident with
#: ten thousand linked events must not produce a response nothing can render.
MAX_EVENTS = 200
MAX_ITEMS_PER_PROVIDER = 500


def _subsystem_health(probe_name: str) -> ProviderHealth:
    """Translate a subsystem probe into this provider's health.

    Imported inside the call rather than at module scope: ``health_service``
    reaches into the ML engine, the AI service and the threat-intelligence
    client, and a top-level import would drag all three into every module that
    merely wants to describe an evidence item.

    Looked up by name on the module so that a probe monkeypatched in a test -
    or, later, swapped for a different implementation - is seen here too. Two
    opinions about whether the anomaly model is loaded is precisely the
    divergence this indirection exists to prevent.
    """
    from app.services import health_service

    state = getattr(health_service, probe_name)()
    if state["status"] == health_service.HEALTHY:
        return HEALTHY
    return ProviderHealth(
        status=state["status"],
        # A probe always explains a non-healthy status, but this provider is
        # not the place to discover it did not: an unexplained degradation
        # would raise out of ProviderHealth and take the page with it.
        reason=state.get("reason")
        or f"The {probe_name.removesuffix('_health')} subsystem is {state['status']}.",
    )


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; the domain refuses those."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _events(incident: Any) -> list[Any]:
    return sorted(incident.events or [], key=lambda event: event.timestamp)[:MAX_EVENTS]


class EventEvidenceProvider(EvidenceProvider):
    """The telemetry itself: what the estate reported."""

    name = "aegisx.telemetry"
    produces = (EvidenceKind.EVENT,)

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for event in _events(incident):
            items.append(
                EvidenceItem(
                    kind=EvidenceKind.EVENT,
                    title=event.title,
                    content={
                        "eventId": event.event_id,
                        "source": event.source,
                        "sourceType": event.source_type,
                        "eventType": event.event_type,
                        "severity": event.severity,
                        "riskScore": event.risk_score,
                        "hostname": event.hostname,
                        "username": event.username,
                        "sourceIp": event.source_ip,
                        "destinationIp": event.destination_ip,
                        "destinationPort": event.destination_port,
                        "process": event.process,
                        "commandLine": event.command_line,
                    },
                    provenance=Provenance(
                        provider=self.name,
                        source_ref=f"event:{event.event_id}",
                        origin=EvidenceOrigin.OBSERVED,
                        integrity=Integrity.WRITE_ONCE,
                        observed_at=_aware(event.timestamp),
                        collected_at=_aware(event.created_at) or _aware(event.timestamp),
                        # No confidence: an event is a record that something
                        # was logged, not a claim with a strength.
                        incident_ref=incident.incident_id,
                        event_ref=event.event_id,
                        is_synthetic=bool(event.is_synthetic),
                    ),
                )
            )
        return items


class RuleEvidenceProvider(EvidenceProvider):
    """Deterministic detections, as recorded on the event at ingestion."""

    name = "aegisx.rules"
    produces = (EvidenceKind.RULE_DETECTION,)

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for event in _events(incident):
            for index, detection in enumerate(event.detections or []):
                rule_id = detection.get("ruleId") or f"index-{index}"
                items.append(
                    EvidenceItem(
                        kind=EvidenceKind.RULE_DETECTION,
                        title=detection.get("ruleName") or f"Rule {rule_id} matched",
                        content={
                            "ruleId": rule_id,
                            "ruleVersion": detection.get("ruleVersion"),
                            "ruleName": detection.get("ruleName"),
                            "reason": detection.get("reason"),
                            "severity": detection.get("severity"),
                            "riskContribution": detection.get("riskContribution"),
                            "mitreTechniques": detection.get("mitreTechniques") or [],
                        },
                        provenance=Provenance(
                            provider=self.name,
                            source_ref=f"event:{event.event_id}#detection:{rule_id}",
                            origin=EvidenceOrigin.DERIVED,
                            integrity=Integrity.WRITE_ONCE,
                            observed_at=_aware(event.timestamp),
                            collected_at=_aware(event.created_at) or _aware(event.timestamp),
                            # A deterministic rule either matched or it did
                            # not. Attaching a confidence would invent a
                            # gradient the mechanism does not have.
                            incident_ref=incident.incident_id,
                            event_ref=event.event_id,
                            is_synthetic=bool(event.is_synthetic),
                        ),
                    )
                )
        return items


class MLEvidenceProvider(EvidenceProvider):
    """Anomaly model verdicts."""

    name = "aegisx.ml"
    produces = (EvidenceKind.ML_INFERENCE,)

    def health(self) -> ProviderHealth:
        """Degraded when no anomaly model is loaded.

        This is the provider that made the case for Phase F. A SOC running on
        rules alone is a supported mode, so the engine reports *degraded* and
        this projection returns nothing - and until now it reported nothing
        while claiming to be healthy, which reads as "the model looked and
        found no anomalies". Those are opposite conclusions.
        """
        return _subsystem_health("ml_health")

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for event in _events(incident):
            for inference in event.ml_inferences or []:
                items.append(
                    EvidenceItem(
                        kind=EvidenceKind.ML_INFERENCE,
                        title=(
                            f"{inference.model_name}@{inference.model_version} scored "
                            f"{event.event_id}"
                        ),
                        content={
                            "model": inference.model_name,
                            "modelVersion": inference.model_version,
                            "featureSchemaVersion": inference.feature_schema_version,
                            "anomalyScore": round(inference.anomaly_score, 4),
                            "scoreKind": "anomaly_score (ranking, NOT a probability)",
                            "threshold": inference.threshold,
                            "isAnomaly": inference.is_anomaly,
                            "topContributors": (inference.top_contributors or [])[:5],
                        },
                        provenance=Provenance(
                            provider=self.name,
                            source_ref=f"ml_inference:{inference.id}",
                            origin=EvidenceOrigin.DERIVED,
                            integrity=Integrity.APPEND_ONLY,
                            observed_at=_aware(event.timestamp),
                            collected_at=_aware(inference.inferred_at),
                            confidence=float(inference.anomaly_score),
                            # Named, because it is the number most likely to be
                            # misread in the whole system.
                            confidence_basis=(
                                "anomaly score: a ranking of how unusual this event is "
                                "relative to the training corpus. NOT a probability of "
                                "compromise and NOT a calibrated confidence."
                            ),
                            incident_ref=incident.incident_id,
                            event_ref=event.event_id,
                            is_synthetic=bool(event.is_synthetic),
                        ),
                    )
                )
        return items


class IndicatorEvidenceProvider(EvidenceProvider):
    """Indicators extracted from the incident's events."""

    name = "aegisx.indicators"
    produces = (EvidenceKind.INDICATOR,)

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for ioc in (incident.iocs or [])[:MAX_ITEMS_PER_PROVIDER]:
            items.append(
                EvidenceItem(
                    kind=EvidenceKind.INDICATOR,
                    title=f"{ioc.type}: {ioc.value}",
                    content={
                        "type": ioc.type,
                        "value": ioc.value,
                        "severity": ioc.severity,
                        "sightingCount": ioc.sighting_count,
                        "firstSeen": _iso(ioc.first_seen),
                        "lastSeen": _iso(ioc.last_seen),
                    },
                    provenance=Provenance(
                        provider=self.name,
                        source_ref=f"ioc:{ioc.id}",
                        origin=EvidenceOrigin.OBSERVED,
                        # sighting_count is incremented and last_seen moved
                        # every time the indicator is seen again.
                        integrity=Integrity.MUTABLE,
                        observed_at=_aware(ioc.first_seen),
                        collected_at=_aware(ioc.last_seen) or _aware(ioc.first_seen),
                        confidence=_scale(ioc.confidence),
                        confidence_basis=(
                            "AEGISX indicator confidence, 0-100, assigned by the "
                            "extractor that produced the indicator."
                        ),
                        incident_ref=incident.incident_id,
                    ),
                )
            )
        return items


class ThreatIntelEvidenceProvider(EvidenceProvider):
    """Third-party reputation verdicts.

    The only built-in provider whose evidence is somebody else's assertion, and
    the only one whose underlying row is rewritten in place.
    """

    name = "aegisx.threatintel"
    produces = (EvidenceKind.THREAT_INTEL,)

    def health(self) -> ProviderHealth:
        """Degraded when no intelligence provider is configured.

        Cached verdicts from a previously configured provider still project, so
        this can be degraded and non-empty at once. That combination is the
        honest one: the rows are real, and nothing new can be looked up.
        """
        return _subsystem_health("threat_intel_health")

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for ioc in incident.iocs or []:
            for result in ioc.threat_intel or []:
                items.append(
                    EvidenceItem(
                        kind=EvidenceKind.THREAT_INTEL,
                        title=f"{result.provider} on {result.ioc_value}: {result.reputation}",
                        content={
                            "indicator": result.ioc_value,
                            "indicatorType": result.ioc_type,
                            "externalProvider": result.provider,
                            "status": result.status,
                            "reputation": result.reputation,
                            "maliciousVerdicts": result.malicious_count,
                            "suspiciousVerdicts": result.suspicious_count,
                            "harmlessVerdicts": result.harmless_count,
                            "isActionable": result.is_actionable,
                            # A failed lookup is not a clean verdict, and this
                            # is where that distinction has to survive.
                            "note": (
                                None
                                if result.is_actionable
                                else "No verdict was obtained. This is not evidence of safety."
                            ),
                        },
                        provenance=Provenance(
                            # The AEGISX subsystem that holds the row...
                            provider=self.name,
                            source_ref=f"threat_intel_result:{result.id}",
                            origin=EvidenceOrigin.REPORTED,
                            integrity=Integrity.MUTABLE,
                            observed_at=_aware(result.last_analysis_at),
                            collected_at=_aware(result.looked_up_at),
                            confidence=(
                                _scale(result.confidence) if result.is_actionable else None
                            ),
                            confidence_basis=(
                                f"{result.provider} vendor confidence, 0-100"
                                if result.is_actionable
                                else None
                            ),
                            incident_ref=incident.incident_id,
                            # ...and the third party that actually said it. Kept
                            # apart: conflating "AEGISX holds this" with "this
                            # vendor asserts this" is how an external opinion
                            # gets read as a platform finding.
                            extra={"assertedBy": result.provider},
                        ),
                    )
                )
        return items


class CorrelationEvidenceProvider(EvidenceProvider):
    """Sequences the correlation engine grouped."""

    name = "aegisx.correlation"
    produces = (EvidenceKind.CORRELATION,)

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        seen: set[int] = set()
        sequences = list(incident.sequences or [])
        for event in _events(incident):
            sequences.extend(event.sequences or [])

        for sequence in sequences:
            if sequence.id in seen:
                continue
            seen.add(sequence.id)
            items.append(
                EvidenceItem(
                    kind=EvidenceKind.CORRELATION,
                    title=sequence.title,
                    content={
                        "sequenceId": sequence.sequence_id,
                        "pattern": sequence.pattern,
                        "eventCount": sequence.event_count,
                        "riskScore": sequence.risk_score,
                        "whyTheseEventsWereGrouped": sequence.rationale or [],
                        "entities": sequence.entities or {},
                        "startTime": _iso(sequence.start_time),
                        "endTime": _iso(sequence.end_time),
                    },
                    provenance=Provenance(
                        provider=self.name,
                        source_ref=f"security_sequence:{sequence.sequence_id}",
                        origin=EvidenceOrigin.DERIVED,
                        # A sequence is extended in place as events arrive.
                        integrity=Integrity.MUTABLE,
                        observed_at=_aware(sequence.start_time),
                        collected_at=_aware(sequence.created_at) or _aware(sequence.start_time),
                        confidence=float(sequence.confidence),
                        confidence_basis=(
                            "correlation confidence, derived from the number of distinct "
                            "signal types and events grouped. Not a model output."
                        ),
                        incident_ref=incident.incident_id,
                    ),
                )
            )
        return items


class AIAnalysisEvidenceProvider(EvidenceProvider):
    """The AI analyst's readings.

    Included as evidence because an analyst deciding *why* an incident was
    treated as dangerous needs to see whether a model's narrative was part of
    the reasoning. It is marked ``analytic`` and carries the grounding verdict,
    so it can never be mistaken for something that was observed.
    """

    name = "aegisx.ai"
    produces = (EvidenceKind.AI_ANALYSIS,)

    def health(self) -> ProviderHealth:
        """Degraded when no AI provider is available.

        Past analyses remain readable when the provider goes away - they are
        rows, not calls - so this too can be degraded with evidence present.
        """
        return _subsystem_health("ai_health")

    def collect(self, db: Any, incident: Any) -> list[EvidenceItem]:
        items = []
        for analysis in incident.ai_analyses or []:
            items.append(
                EvidenceItem(
                    kind=EvidenceKind.AI_ANALYSIS,
                    title=f"AI {analysis.kind} ({analysis.provider})",
                    content={
                        "kind": analysis.kind,
                        "aiProvider": analysis.provider,
                        "model": analysis.model,
                        "summary": analysis.summary,
                        "whyItMatters": analysis.why_it_matters,
                        "statedConfidence": analysis.confidence,
                        "grounded": analysis.grounded,
                        "groundingWarnings": analysis.grounding_warnings or [],
                        "evidenceFingerprint": analysis.evidence_fingerprint,
                        "note": (
                            "Generated by a language model from the evidence above. "
                            "It is a reading of the evidence, never an observation."
                        ),
                    },
                    provenance=Provenance(
                        provider=self.name,
                        source_ref=f"ai_analysis:{analysis.id}",
                        origin=EvidenceOrigin.ANALYTIC,
                        integrity=Integrity.APPEND_ONLY,
                        observed_at=_aware(analysis.created_at),
                        collected_at=_aware(analysis.created_at),
                        # The model's own word for how sure it is, which is not
                        # a calibrated quantity - so it is not offered as one.
                        confidence=None,
                        confidence_basis=None,
                        incident_ref=incident.incident_id,
                        extra={
                            "statedConfidence": analysis.confidence,
                            "grounded": analysis.grounded,
                            "requestedBy": analysis.requested_by,
                        },
                    ),
                )
            )
        return items


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.isoformat() if aware else None


def _scale(value: int | None) -> float | None:
    """A 0-100 integer confidence as the domain's 0..1."""
    if value is None:
        return None
    return max(0.0, min(1.0, float(value) / 100.0))


for _provider in (
    EventEvidenceProvider(),
    RuleEvidenceProvider(),
    MLEvidenceProvider(),
    IndicatorEvidenceProvider(),
    ThreatIntelEvidenceProvider(),
    CorrelationEvidenceProvider(),
    AIAnalysisEvidenceProvider(),
):
    register(_provider)
