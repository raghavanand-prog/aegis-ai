"""Evidence package construction.

The AI analyst is given exactly one thing: a structured, sanitised description
of what the platform already knows about an incident. It has no tools, no
database access and no ability to look anything up. If a fact is not in this
package, the analyst has no way to know it - which is what makes the grounding
check in ``grounding.py`` meaningful rather than decorative.

    incident -> events -> rule findings
                       -> ML findings
                       -> IOCs + threat intelligence
                       -> correlated sequences
                       -> MITRE context (with provenance)
                       -> timeline
                       -> risk breakdown

Every string in the package has been through ``sanitize.scrub_*``. Every list
is capped. The package carries a fingerprint so an analysis can be told apart
from one produced before newer events arrived.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.ai.sanitize import contains_injection_attempt, scrub_text, scrub_value
from app.core.config import settings
from app.correlation import mitre
from app.models.incident import Incident
from app.threatintel import service as threat_intel_service

EVIDENCE_SCHEMA_VERSION = "1.0"

#: Caps. These bound both provider cost and how much untrusted text reaches a
#: model in one request.
MAX_IOCS = 25
MAX_SEQUENCES = 5
MAX_TIMELINE = 30
MAX_TECHNIQUES = 20


@dataclass
class EvidencePackage:
    """Everything the AI analyst is allowed to reason from."""

    incident: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    rule_findings: list[dict[str, Any]] = field(default_factory=list)
    ml_findings: list[dict[str, Any]] = field(default_factory=list)
    threat_intelligence: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    sequences: list[dict[str, Any]] = field(default_factory=list)
    mitre_context: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    #: What is missing, and why. Handed to the model explicitly so "we do not
    #: know" is a first-class input rather than something it has to infer from
    #: an absent key.
    gaps: list[str] = field(default_factory=list)
    #: Telemetry fields that looked like an attempt to steer a model.
    injection_flags: list[str] = field(default_factory=list)
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "incident": self.incident,
            "events": self.events,
            "ruleFindings": self.rule_findings,
            "mlFindings": self.ml_findings,
            "threatIntelligence": self.threat_intelligence,
            "iocs": self.iocs,
            "correlatedSequences": self.sequences,
            "mitreContext": self.mitre_context,
            "timeline": self.timeline,
            "risk": self.risk,
            "knownGaps": self.gaps,
        }

    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def summary(self) -> dict[str, int | bool]:
        """Compact counts, stored on the analysis row and shown in the UI."""
        return {
            "events": len(self.events),
            "ruleFindings": len(self.rule_findings),
            "mlFindings": len(self.ml_findings),
            "threatIntelligence": len(self.threat_intelligence),
            "iocs": len(self.iocs),
            "sequences": len(self.sequences),
            "techniques": len(self.mitre_context),
            "timelineEntries": len(self.timeline),
            "gaps": len(self.gaps),
            "injectionAttemptsDetected": len(self.injection_flags),
        }

    @property
    def is_sufficient(self) -> bool:
        """Whether there is anything here worth reasoning about.

        An incident with no events and no findings gets an explicit
        "insufficient evidence" answer without a provider ever being called -
        cheaper, faster, and impossible to hallucinate through.
        """
        return bool(self.events) and bool(
            self.rule_findings or self.ml_findings or self.threat_intelligence or self.sequences
        )


def _iso(value: datetime | None) -> str | None:
    """UTC-stamped, so the model never sees an ambiguous instant either."""
    if value is None:
        return None
    stamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return stamp.isoformat()


def _flag(flags: list[str], label: str, value: Any) -> None:
    if value and contains_injection_attempt(value):
        flags.append(label)


def build(db, incident: Incident) -> EvidencePackage:  # noqa: ANN001 - Session
    """Assemble the evidence package for one incident."""
    flags: list[str] = []
    gaps: list[str] = []

    events = sorted(incident.events or [], key=lambda event: event.timestamp)[
        : settings.ai_max_evidence_events
    ]
    total_events = len(incident.events or [])
    if total_events > len(events):
        gaps.append(
            f"Only the earliest {len(events)} of {total_events} linked events are "
            "included in this package; the rest were omitted to bound the request."
        )

    # --- Events ------------------------------------------------------------
    event_entries: list[dict[str, Any]] = []
    rule_findings: list[dict[str, Any]] = []
    ml_findings: list[dict[str, Any]] = []
    technique_entries: list[dict[str, Any]] = []

    for event in events:
        _flag(flags, f"{event.event_id}.commandLine", event.command_line)
        _flag(flags, f"{event.event_id}.title", event.title)
        _flag(flags, f"{event.event_id}.description", event.description)

        event_entries.append(
            {
                "id": event.event_id,
                "timestamp": _iso(event.timestamp),
                "source": scrub_text(event.source, max_length=120),
                "sourceType": scrub_text(event.source_type, max_length=64),
                "eventType": scrub_text(event.event_type, max_length=64),
                "title": scrub_text(event.title, max_length=255),
                "description": scrub_text(event.description, max_length=600),
                "severity": event.severity,
                "riskScore": event.risk_score,
                "hostname": scrub_text(event.hostname, max_length=255),
                "username": scrub_text(event.username, max_length=255),
                "sourceIp": scrub_text(event.source_ip, max_length=64),
                "destinationIp": scrub_text(event.destination_ip, max_length=64),
                "destinationPort": event.destination_port,
                "process": scrub_text(event.process, max_length=255),
                "commandLine": scrub_text(event.command_line),
                "isSynthetic": event.is_synthetic,
                # Raw logs are deliberately excluded: they are the least
                # structured, most attacker-controlled text in the system, and
                # the normalized fields above already carry the substance.
                "normalizedData": scrub_value(event.normalized_data or {}),
            }
        )

        for detection in event.detections or []:
            rule_findings.append(
                {
                    "eventId": event.event_id,
                    "ruleId": scrub_text(detection.get("ruleId"), max_length=64),
                    "ruleVersion": scrub_text(detection.get("ruleVersion"), max_length=32),
                    "ruleName": scrub_text(detection.get("ruleName"), max_length=120),
                    "reason": scrub_text(detection.get("reason"), max_length=500),
                    "severity": detection.get("severity"),
                    "riskContribution": detection.get("riskContribution"),
                    "mitreTechniques": [
                        scrub_text(t, max_length=16)
                        for t in (detection.get("mitreTechniques") or [])
                    ],
                    "detectionSource": "deterministic-rule",
                }
            )

        for inference in event.ml_inferences or []:
            ml_findings.append(
                {
                    "eventId": event.event_id,
                    "model": inference.model_name,
                    "modelVersion": inference.model_version,
                    "featureSchemaVersion": inference.feature_schema_version,
                    # Named explicitly so the model cannot read it as a
                    # probability of compromise.
                    "anomalyScore": round(inference.anomaly_score, 4),
                    "scoreKind": "anomaly_score (ranking, NOT a probability)",
                    "threshold": inference.threshold,
                    "isAnomaly": inference.is_anomaly,
                    "featuresFurthestFromNormal": [
                        {
                            "feature": contribution.get("name"),
                            "direction": contribution.get("direction"),
                            "standardDeviations": contribution.get("deviation"),
                        }
                        for contribution in (inference.top_contributors or [])[:5]
                    ],
                    "detectionSource": "unsupervised-anomaly-model",
                }
            )

    technique_entries.extend(mitre.from_events(events))

    # --- Indicators and external reputation --------------------------------
    ioc_entries: list[dict[str, Any]] = []
    intel_entries: list[dict[str, Any]] = []
    indicators = list(incident.iocs or [])[:MAX_IOCS]

    for ioc in indicators:
        _flag(flags, f"ioc.{ioc.id}", ioc.value)
        ioc_entries.append(
            {
                "type": ioc.type,
                "value": scrub_text(ioc.value, max_length=512),
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "sightingCount": ioc.sighting_count,
                "firstSeen": _iso(ioc.first_seen),
                "lastSeen": _iso(ioc.last_seen),
            }
        )
        for result in ioc.threat_intel or []:
            intel_entries.append(
                {
                    "indicator": scrub_text(result.ioc_value, max_length=512),
                    "indicatorType": result.ioc_type,
                    "provider": result.provider,
                    "status": result.status,
                    "reputation": result.reputation,
                    "providerConfidence": result.confidence,
                    "maliciousVerdicts": result.malicious_count,
                    "suspiciousVerdicts": result.suspicious_count,
                    "harmlessVerdicts": result.harmless_count,
                    "lastAnalysisAt": _iso(result.last_analysis_at),
                    "lookedUpAt": _iso(result.looked_up_at),
                    "isActionable": result.is_actionable,
                    "note": (
                        None
                        if result.is_actionable
                        else "No verdict was obtained; this is not evidence of safety."
                    ),
                }
            )

    if indicators and not intel_entries:
        intel_status = threat_intel_service.status()
        gaps.append(
            "No external threat intelligence is attached to these indicators "
            f"(provider: {intel_status['provider']}, configured: "
            f"{intel_status['configured']}). Their reputation is unknown, not clean."
        )

    # --- Correlated sequences ---------------------------------------------
    sequence_entries: list[dict[str, Any]] = []
    seen_sequences: set[int] = set()
    for event in events:
        for sequence in event.sequences or []:
            if sequence.id in seen_sequences or len(sequence_entries) >= MAX_SEQUENCES:
                continue
            seen_sequences.add(sequence.id)
            sequence_entries.append(
                {
                    "id": sequence.sequence_id,
                    "pattern": sequence.pattern,
                    "title": scrub_text(sequence.title, max_length=255),
                    "description": scrub_text(sequence.description, max_length=600),
                    "riskScore": sequence.risk_score,
                    "correlationConfidence": sequence.confidence,
                    "eventCount": sequence.event_count,
                    "startTime": _iso(sequence.start_time),
                    "endTime": _iso(sequence.end_time),
                    "whyTheseEventsWereGrouped": [
                        scrub_text(reason, max_length=300)
                        for reason in (sequence.rationale or [])
                    ],
                    "entities": scrub_value(sequence.entities or {}),
                    "detectionSource": "correlation-engine",
                }
            )
            technique_entries.extend(sequence.techniques or [])

    # --- MITRE, timeline, risk --------------------------------------------
    techniques = mitre.merge(technique_entries)[:MAX_TECHNIQUES]

    timeline = [
        {
            "timestamp": entry.get("timestamp"),
            "action": scrub_text(entry.get("action"), max_length=64),
            "actor": scrub_text(entry.get("actor"), max_length=120),
            "detail": scrub_text(entry.get("detail"), max_length=400),
        }
        for entry in (incident.timeline or [])[-MAX_TIMELINE:]
    ]

    # --- Gaps --------------------------------------------------------------
    if not ml_findings:
        gaps.append(
            "No ML anomaly scores are attached to these events. The anomaly model "
            "was unavailable or the events predate it - absence of an anomaly score "
            "is not evidence that the behaviour was normal."
        )
    if not rule_findings:
        gaps.append(
            "No deterministic detection rule matched any of these events."
        )
    if not sequence_entries:
        gaps.append("These events are not part of any correlated sequence.")
    if any(event.is_synthetic for event in events):
        gaps.append(
            "Some or all of these events are SYNTHETIC telemetry generated by the "
            "AEGISX simulator. They do not describe activity on a real system."
        )

    incident_entry = {
        "id": incident.incident_id,
        "title": scrub_text(incident.title, max_length=255),
        "description": scrub_text(incident.description, max_length=1000),
        "severity": incident.severity,
        "status": incident.status,
        "riskScore": incident.risk_score,
        "analyst": scrub_text(incident.analyst, max_length=120),
        "createdAt": _iso(incident.created_at),
        "eventCount": total_events,
    }
    _flag(flags, "incident.title", incident.title)
    _flag(flags, "incident.description", incident.description)

    return EvidencePackage(
        incident=incident_entry,
        events=event_entries,
        rule_findings=rule_findings,
        ml_findings=ml_findings,
        threat_intelligence=intel_entries,
        iocs=ioc_entries,
        sequences=sequence_entries,
        mitre_context=techniques,
        timeline=timeline,
        risk={
            "incidentRiskScore": incident.risk_score,
            "signals": scrub_value(incident.risk_signals or []),
            "scoringNote": (
                "Risk is a weighted sum of rule, ML, threat-intelligence and "
                "correlation signals. See the signals list for each contribution."
            ),
        },
        gaps=gaps,
        injection_flags=flags,
    )
