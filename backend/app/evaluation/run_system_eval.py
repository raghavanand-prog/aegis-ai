"""Correlation, AI-analyst, threat-intelligence and degraded-mode evaluation.

    python -m app.evaluation.run_system_eval

These subsystems cannot be scored with a confusion matrix over a public corpus,
so they are evaluated on the corpus and conditions that can actually support
them: correlation against injected campaigns with known membership, the AI
analyst against the production grounding verifier, threat intelligence against
what exists (which, with no provider configured, is the SSRF refusals), and
degraded mode by breaking each optional subsystem in turn.

Writes one schema-versioned JSON report. Where a figure cannot honestly be
computed it is reported as NOT AVAILABLE with the reason, never estimated.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.evaluation.correlation_eval import run_correlation_evaluation
from app.evaluation.reports.store import write_report
from app.evaluation.system_eval import run_system_evaluation
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

logger = logging.getLogger("aegisx.evaluation.system")

REPORT_SCHEMA_VERSION = "1.0"
REPORT_PREFIX = "v4-system-eval"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.evaluation.run_system_eval",
        description=(
            "Evaluate correlation, the AI analyst, threat intelligence and degraded "
            "mode."
        ),
    )
    parser.add_argument(
        "--campaigns-per-kind",
        type=int,
        default=8,
        help="attack campaigns injected per campaign type (default: 8)",
    )
    parser.add_argument(
        "--background-events",
        type=int,
        default=200,
        help="unrelated events interleaved with the campaigns (default: 200)",
    )
    parser.add_argument(
        "--ai-incidents",
        type=int,
        default=5,
        help="incidents to run through the AI analyst (default: 5)",
    )
    parser.add_argument("--seed", type=int, default=4242)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument(
        "--skip-correlation",
        action="store_true",
        help="skip the correlation evaluation (it writes events to the database)",
    )
    add_timeout_argument(parser)
    return parser


def _ai_incidents(db, limit: int) -> list:  # noqa: ANN001 - Session
    """Promote the highest-risk sequences so the AI analyst has real evidence.

    Mirrors what the promote endpoint does, minus the HTTP layer and the audit
    entry: an analyst promoting a sequence is the only way an incident is ever
    created from correlation, and evaluating the AI on anything else would be
    evaluating it on evidence the product never produces.
    """
    from app.models.enums import SequenceStatus, Severity
    from app.models.sequence import SecuritySequence
    from app.schemas.incident import IncidentCreate
    from app.services import incident_service

    sequences = (
        db.query(SecuritySequence)
        .order_by(SecuritySequence.risk_score.desc())
        .limit(limit)
        .all()
    )
    incidents = []
    for sequence in sequences:
        if sequence.incident_id is not None:
            continue
        rationale = "\n".join(f"- {reason}" for reason in (sequence.rationale or []))
        payload = IncidentCreate(
            title=sequence.title,
            description=(
                f"{sequence.description}\n\n"
                f"Correlated by {sequence.pattern} on {sequence.correlation_key} "
                f"(confidence {sequence.confidence:.2f}).\n\n"
                f"Why these events were grouped:\n{rationale}"
            ),
            severity=Severity(sequence.severity),
            source="AEGISX Correlation",
            analyst="evaluation-harness",
            event_ids=[event.event_id for event in sequence.events],
            mitre_techniques=[
                str(entry.get("technique"))
                for entry in (sequence.techniques or [])
                if entry.get("technique")
            ],
        )
        try:
            incident = incident_service.create_incident(db, payload, user=None)
        except (incident_service.IncidentError, ValueError) as exc:
            logger.warning("Could not promote %s: %s", sequence.sequence_id, exc)
            continue
        sequence.incident_id = incident.id
        sequence.status = SequenceStatus.PROMOTED.value
        db.flush()
        incident_service.recompute_risk(db, incident)
        incidents.append(incident)
    db.flush()
    return incidents


def summarise(payload: dict[str, Any]) -> str:
    lines: list[str] = []

    correlation = payload.get("correlation")
    if correlation:
        totals = correlation["totals"]
        lines.extend(
            [
                "",
                "=" * 78,
                "  AEGISX V4 SYSTEM EVALUATION",
                "=" * 78,
                "",
                "  CORRELATION",
                f"    campaigns detected    {totals['campaignsDetected']}/"
                f"{totals['campaignsInjected']}",
                f"    mean sequence purity  {totals['meanSequencePurity']}",
                f"    spurious sequences    {totals['spuriousSequences']} of "
                f"{totals['sequencesOpened']}",
                f"    alert reduction       {totals['alertReductionFactor']}x",
                "",
            ]
        )
    else:
        lines.extend(["", "=" * 78, "  AEGISX V4 SYSTEM EVALUATION", "=" * 78, ""])

    ai = payload["aiAnalyst"]
    lines.append("  AI ANALYST")
    lines.append(f"    provider              {ai['provider']}")
    lines.append(f"    label                 {ai['resultLabel']}")
    if ai["unavailableReason"]:
        lines.append(f"    NOT AVAILABLE         {ai['unavailableReason']}")
    else:
        totals = ai["totals"]
        lines.append(
            f"    grounded              {totals['groundedAnalyses']}/"
            f"{totals['completed']}  ({totals['groundingRate']})"
        )
        lines.append(
            f"    unsupported techniques {totals['unsupportedTechniqueWarnings']}"
        )
        lines.append(f"    unresolved references  {totals['unresolvedReferenceWarnings']}")
        lines.append(f"    latency mean          {totals['latency']['meanMs']} ms")
    lines.append("")

    intel = payload["threatIntelligence"]
    lines.append("  THREAT INTELLIGENCE")
    lines.append(f"    provider              {intel['provider']}")
    if intel["unavailableReason"]:
        lines.append(f"    NOT AVAILABLE         {intel['unavailableReason']}")
    lines.append(
        f"    SSRF probes refused   {intel['ssrfValidation']['allRefused']} "
        f"({len(intel['ssrfValidation']['probes'])} probes)"
    )
    lines.append("")

    degraded = payload["degradedModes"]
    lines.append("  DEGRADED MODE")
    lines.append(
        f"    ingestion survived every scenario: "
        f"{degraded['ingestionSurvivedEveryScenario']}"
    )
    for entry in degraded["scenarios"]:
        lines.append(
            f"    {entry['scenario']:26} normalized {entry['eventsNormalized']}  "
            f"rules {entry['ruleDetections']}  survived {entry['ingestionSurvived']}"
        )
    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    watchdog = start_watchdog(args.max_seconds, label="v4 system evaluation")

    try:
        from app.core.database import get_session_factory

        settings = get_settings()
        session = get_session_factory()()
        try:
            payload: dict[str, Any] = {
                "schemaVersion": REPORT_SCHEMA_VERSION,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "command": " ".join(sys.argv),
            }

            incidents: list = []
            if not args.skip_correlation:
                print("Running correlation evaluation...")
                correlation = run_correlation_evaluation(
                    session,
                    campaigns_per_kind=args.campaigns_per_kind,
                    background_events=args.background_events,
                    seed=args.seed,
                )
                session.commit()
                payload["correlation"] = correlation.to_dict()
                print(correlation.to_text())
                incidents = _ai_incidents(session, args.ai_incidents)
                session.commit()

            print("Running AI, threat-intelligence and degraded-mode evaluation...")
            payload.update(run_system_evaluation(session, incidents))
            session.commit()
        finally:
            session.close()

        print(summarise(payload))

        directory = Path(args.output_dir) if args.output_dir else None
        detailed, latest = write_report(
            payload,
            directory or settings.evaluation_reports_dir or None,
            prefix=REPORT_PREFIX,
        )
        print(f"  Report written to {detailed}")
        print(f"  Latest pointer   {latest}\n")
        return 0
    finally:
        if watchdog is not None:
            watchdog.cancel()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
