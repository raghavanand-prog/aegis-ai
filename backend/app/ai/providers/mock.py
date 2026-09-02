"""Deterministic offline analyst.

This is not a stub that returns lorem ipsum. It reads the evidence package out
of the prompt and writes a genuine, fully grounded analysis from it - every
statement traced to an identifier that is actually present, every technique
taken from `mitreContext`, "insufficient evidence" returned when the evidence
really is insufficient.

That makes it three useful things at once:

* the default provider, so a fresh clone has a working AI analyst with no API
  key, no account and no network access;
* the honest baseline - anything a hosted model adds over this is the value the
  model is actually contributing;
* a test fixture that exercises the whole path (evidence -> prompt -> parse ->
  ground -> store) deterministically.

It is labelled ``mock`` everywhere it appears, and the API reports it as
template-generated rather than model-generated, because that is what it is.
"""

from __future__ import annotations

import json
from time import perf_counter
from typing import Any

from app.ai.base import AIAnalystProvider, ProviderResponse
from app.ai.prompts import EVIDENCE_CLOSE, EVIDENCE_OPEN


class MockAnalystProvider(AIAnalystProvider):
    name = "mock"

    @property
    def model_name(self) -> str:
        return "aegisx-template-analyst-1.0"

    @property
    def configured(self) -> bool:
        return True

    def complete(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        started = perf_counter()
        evidence = _extract_evidence(user_prompt)
        if evidence is None:
            return ProviderResponse.failure(
                "Evidence block missing from the prompt", model=self.model_name
            )

        analysis = _analyse(evidence)
        return ProviderResponse(
            ok=True,
            text=json.dumps(analysis, indent=2),
            model=self.model_name,
            tokens_used=0,
            latency_ms=(perf_counter() - started) * 1000.0,
        )


def _extract_evidence(prompt: str) -> dict[str, Any] | None:
    start = prompt.find(EVIDENCE_OPEN)
    end = prompt.find(EVIDENCE_CLOSE)
    if start == -1 or end <= start:
        return None
    body = prompt[start + len(EVIDENCE_OPEN) : end].strip()
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _analyse(evidence: dict[str, Any]) -> dict[str, Any]:  # noqa: C901 - one flat report builder
    incident = evidence.get("incident") or {}
    events = evidence.get("events") or []
    rules = evidence.get("ruleFindings") or []
    ml = evidence.get("mlFindings") or []
    intel = [t for t in (evidence.get("threatIntelligence") or []) if t.get("isActionable")]
    sequences = evidence.get("correlatedSequences") or []
    techniques = evidence.get("mitreContext") or []
    gaps = evidence.get("knownGaps") or []
    risk = evidence.get("risk") or {}

    supporting: list[dict[str, str]] = []
    hosts = sorted({e.get("hostname") for e in events if e.get("hostname")})
    users = sorted({e.get("username") for e in events if e.get("username")})
    sources = sorted({e.get("sourceIp") for e in events if e.get("sourceIp")})
    synthetic = any(e.get("isSynthetic") for e in events)

    # --- Insufficient evidence --------------------------------------------
    if not events or not (rules or ml or intel or sequences):
        return {
            "summary": (
                f"Incident {incident.get('id', 'unknown')} contains "
                f"{len(events)} linked event(s) and no detection findings. There is "
                "not enough evidence here to characterise what happened."
            ),
            "whyItMatters": (
                "An incident with no rule match, no anomaly score, no external "
                "reputation and no correlated sequence carries no signal to reason "
                "about. It may still be worth reviewing manually."
            ),
            "riskAssessment": (
                f"Recorded risk score is {incident.get('riskScore', 0)}/100. Nothing in "
                "the supplied evidence explains or contradicts it."
            ),
            "likelyBehaviour": "Insufficient evidence to say.",
            "supportingEvidence": (
                [{"claim": "The incident exists", "evidenceRef": incident.get("id", "")}]
                if incident.get("id")
                else []
            ),
            "mitreTechniques": [],
            "investigationSteps": [
                "Confirm the events expected to be part of this incident are actually linked to it.",
                "Check whether the telemetry sources involved were healthy at the time.",
                "Review the raw telemetry directly, since no detection layer produced a finding.",
            ],
            "containmentActions": [
                "No containment is justified by this evidence. Establish what happened first."
            ],
            "confidence": "insufficient_evidence",
            "uncertainty": (
                "Everything. "
                + (" ".join(gaps) if gaps else "No findings were attached to this incident.")
            ),
        }

    # --- Observations ------------------------------------------------------
    observations: list[str] = []

    if rules:
        rule_names = sorted({r.get("ruleName") for r in rules if r.get("ruleName")})
        observations.append(
            f"{len(rules)} deterministic rule match(es) across "
            f"{len({r.get('eventId') for r in rules})} event(s): "
            + ", ".join(str(name) for name in rule_names[:4])
        )
        for finding in rules[:4]:
            supporting.append(
                {
                    "claim": str(finding.get("reason", "")),
                    "evidenceRef": str(finding.get("ruleId", "")),
                }
            )

    anomalies = [m for m in ml if m.get("isAnomaly")]
    if anomalies:
        strongest = max(anomalies, key=lambda item: item.get("anomalyScore", 0))
        drivers = [
            str(d.get("feature"))
            for d in (strongest.get("featuresFurthestFromNormal") or [])[:3]
        ]
        observations.append(
            f"the anomaly model flagged {len(anomalies)} of {len(ml)} scored event(s) as "
            f"statistically unusual (highest anomaly score "
            f"{strongest.get('anomalyScore')}, threshold {strongest.get('threshold')})"
            + (f"; furthest from normal: {', '.join(drivers)}" if drivers else "")
        )
        supporting.append(
            {
                "claim": (
                    "The anomaly model ranked this behaviour as unusual against its "
                    "learned baseline"
                ),
                "evidenceRef": str(strongest.get("eventId", strongest.get("model", ""))),
            }
        )
    elif ml:
        observations.append(
            f"{len(ml)} event(s) were scored by the anomaly model and none exceeded the "
            "anomaly threshold"
        )

    for verdict in intel[:3]:
        observations.append(
            f"{verdict.get('provider')} reports {verdict.get('indicator')} as "
            f"{verdict.get('reputation')} "
            f"({verdict.get('maliciousVerdicts')} malicious verdict(s))"
        )
        supporting.append(
            {
                "claim": f"External reputation for {verdict.get('indicator')} is "
                f"{verdict.get('reputation')}",
                "evidenceRef": str(verdict.get("indicator", "")),
            }
        )

    for sequence in sequences[:2]:
        observations.append(
            f"correlation pattern {sequence.get('pattern')} grouped "
            f"{sequence.get('eventCount')} related events as {sequence.get('title')!r} "
            f"(correlation confidence {sequence.get('correlationConfidence')})"
        )
        supporting.append(
            {
                "claim": str(
                    (sequence.get("whyTheseEventsWereGrouped") or ["Events were correlated"])[0]
                ),
                "evidenceRef": str(sequence.get("id", "")),
            }
        )

    scope = []
    if hosts:
        scope.append(f"{len(hosts)} host(s) ({', '.join(str(h) for h in hosts[:3])})")
    if users:
        scope.append(f"{len(users)} account(s) ({', '.join(str(u) for u in users[:3])})")
    if sources:
        scope.append(f"{len(sources)} source address(es)")

    summary = (
        f"Incident {incident.get('id')} links {incident.get('eventCount', len(events))} "
        f"event(s)"
        + (f" involving {', '.join(scope)}. " if scope else ". ")
        + "The platform observed: "
        + "; ".join(observations)
        + "."
    )
    if synthetic:
        summary += (
            " These events are SYNTHETIC telemetry from the AEGISX simulator and do not "
            "describe activity on a real system."
        )

    # --- Interpretation ----------------------------------------------------
    mapped = [t for t in techniques if t.get("provenance") == "mapped"]
    inferred = [t for t in techniques if t.get("provenance") == "inferred"]

    if mapped:
        likely = (
            "Consistent with "
            + ", ".join(str(t.get("technique")) for t in mapped[:3])
            + ", each declared directly by a deterministic rule that stated the "
            "condition it matched."
        )
    elif inferred:
        likely = (
            "The correlation engine inferred "
            + ", ".join(str(t.get("technique")) for t in inferred[:3])
            + " from the shape of the sequence. That is an inference from event "
            "ordering, not a directly observed technique."
        )
    elif anomalies:
        likely = (
            "The only positive signal is statistical: the behaviour is unusual against "
            "the learned baseline. Unusual is not malicious, and the anomaly model "
            "identifies no attack technique. Corroboration is needed before "
            "characterising this as attacker behaviour."
        )
    else:
        likely = "Insufficient evidence to characterise the behaviour."

    signals = risk.get("signals") or []
    signal_text = ", ".join(
        f"{s.get('type')} {s.get('source')} (+{s.get('contribution')})"
        for s in signals[:5]
        if isinstance(s, dict)
    )
    risk_assessment = (
        f"Recorded risk score is {incident.get('riskScore', 0)}/100, severity "
        f"{incident.get('severity')}."
        + (f" Contributions: {signal_text}." if signal_text else "")
    )

    why = _why_it_matters(rules, anomalies, intel, sequences, hosts, users)

    # --- Confidence --------------------------------------------------------
    corroborating = sum(bool(x) for x in (rules, anomalies, intel, sequences))
    if corroborating >= 3:
        confidence = "high"
    elif corroborating == 2:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "summary": summary,
        "whyItMatters": why,
        "riskAssessment": risk_assessment,
        "likelyBehaviour": likely,
        "supportingEvidence": supporting[:10],
        "mitreTechniques": [
            {
                "technique": str(t.get("technique")),
                "provenance": str(t.get("provenance")),
                "rationale": str(t.get("detail") or f"Recorded by {t.get('source')}"),
            }
            for t in techniques[:8]
        ],
        "investigationSteps": _investigation_steps(hosts, users, sources, rules, anomalies, intel),
        "containmentActions": _containment_actions(hosts, users, sources, intel, synthetic),
        "confidence": confidence,
        "uncertainty": (
            " ".join(gaps)
            if gaps
            else "No significant gaps were flagged in the evidence package."
        ),
    }


def _why_it_matters(rules, anomalies, intel, sequences, hosts, users) -> str:
    if intel:
        return (
            "An external reputation service has an adverse verdict on an indicator "
            "involved here. That is corroboration independent of AEGISX's own rules, "
            "which raises this above ordinary noise."
        )
    if sequences and rules:
        return (
            "A deterministic rule fired AND the correlation engine grouped this with "
            "related activity. Two independent signals agreeing on the same entities "
            "is materially stronger than either alone."
        )
    if rules:
        return (
            "A deterministic rule matched a known attack pattern and stated the "
            "condition it matched. That is an explainable finding, not a statistical "
            "guess."
        )
    if anomalies:
        return (
            "The only signal is statistical novelty. It is worth a look, but on its own "
            "it does not establish that anything malicious happened - unusual behaviour "
            "is common in a healthy estate."
        )
    if sequences:
        return (
            "Individually unremarkable events were grouped by the correlation engine. "
            "The pattern is the finding; no single event here is notable."
        )
    return (
        f"Activity touching {len(hosts)} host(s) and {len(users)} account(s) was linked "
        "into one incident."
    )


def _investigation_steps(hosts, users, sources, rules, anomalies, intel) -> list[str]:
    steps: list[str] = []
    if users:
        steps.append(
            f"Review the full authentication history for {', '.join(str(u) for u in users[:3])} "
            "around this window, including successful sign-ins outside this incident."
        )
    if hosts:
        steps.append(
            f"Pull process and network telemetry from {', '.join(str(h) for h in hosts[:3])} "
            "for the surrounding period."
        )
    if sources:
        steps.append(
            f"Establish whether {', '.join(str(s) for s in sources[:3])} is expected to "
            "reach this environment at all."
        )
    if rules:
        steps.append(
            "Read each rule's stated reason and confirm the matched condition reflects "
            "real activity rather than a known-benign pattern."
        )
    if anomalies:
        steps.append(
            "Check the features listed as furthest from normal against what is routine "
            "for this host or account - the model has no notion of intent."
        )
    if not intel:
        steps.append(
            "Run threat-intelligence enrichment on the indicators; no external verdict "
            "is currently attached."
        )
    steps.append("Confirm whether this activity was authorised before treating it as an intrusion.")
    return steps[:6]


def _containment_actions(hosts, users, sources, intel, synthetic) -> list[str]:
    if synthetic:
        return [
            "No containment applies: this incident is built from synthetic telemetry "
            "produced by the AEGISX simulator, not from a real system.",
            "If practising the workflow, record the intended action - AEGISX stores "
            "response actions and never executes them.",
        ]

    actions: list[str] = []
    if users:
        actions.append(
            f"Consider forcing a credential reset and session revocation for "
            f"{', '.join(str(u) for u in users[:3])} if the activity is unexplained."
        )
    if hosts:
        actions.append(
            f"Consider isolating {', '.join(str(h) for h in hosts[:2])} pending review, "
            "weighing the operational impact."
        )
    if intel:
        actions.append(
            "Block the indicators with adverse external reputation at the perimeter."
        )
    elif sources:
        actions.append(
            f"Consider rate-limiting or blocking {sources[0]} at the perimeter if it has "
            "no legitimate business reaching this environment."
        )
    actions.append(
        "Record whichever action is taken against this incident. AEGISX stores response "
        "actions for the audit trail and executes nothing automatically."
    )
    return actions[:5]
