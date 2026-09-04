"""CLI: measure the approval workflow's own processing cost.

    python -m app.adaptation.experiments.run_approval_latency_eval --iterations 20

Times ``create -> approve -> deploy -> rollback`` through the service layer,
plus the four-eyes refusal that sits on the approval path.

**This is system processing latency and it is labelled as such in the report.**
Human analyst decision latency - the number that actually governs how long an
adaptation waits - is reported as ``UNMEASURED``, because no analyst population
exists and inventing one with a simulator would produce a finding about the
simulator. See the module docstring of ``approval_latency`` for why that choice
was made rather than filling the row.

The measurement runs against a **temporary database**, created and discarded per
invocation, so it never writes probe proposals into a working database and never
depends on what one already contains.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.adaptation.experiments import approval_latency
from app.evaluation.reports.store import write_report
from app.evaluation.watchdog import add_argument as add_timeout_argument
from app.evaluation.watchdog import start as start_watchdog

REPORT_PREFIX = "v8-approval-latency"
SCHEMA_VERSION = "1.0"


def _environment() -> dict[str, Any]:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "backend": "sqlite (temporary file, created and discarded per run)",
        "process": "single, in-process; excludes HTTP, auth and serialization",
    }


def _render(report: dict[str, Any]) -> str:
    result = report["result"]
    lines = [
        "",
        "=" * 74,
        "  AEGISX APPROVAL WORKFLOW LATENCY",
        "=" * 74,
        "",
        f"  Iterations   {result['iterations']}",
        f"  Environment  {report['environment']['platform']}",
        "",
        "  SYSTEM PROCESSING LATENCY (milliseconds)",
        "",
        f"    {'stage':<26}{'n':>5}{'mean':>10}{'p50':>10}{'p95':>10}{'max':>10}",
        "    " + "-" * 71,
    ]
    for stage, stats in result["perStage"].items():
        lines.append(
            f"    {stage:<26}{stats['samples']:>5}"
            f"{stats['mean']:>10.4f}{stats['p50']:>10.4f}"
            f"{stats['p95']:>10.4f}{stats['max']:>10.4f}"
        )
    e2e = result["endToEnd"]
    lines += [
        "    " + "-" * 71,
        f"    {'end-to-end (4 stages)':<26}{e2e['samples']:>5}"
        f"{e2e['mean']:>10.4f}{e2e['p50']:>10.4f}"
        f"{e2e['p95']:>10.4f}{e2e['max']:>10.4f}",
        "",
        f"  Four-eyes refusals exercised: {result['refusals']['self_approval']}"
        f" / {result['iterations']}",
        "",
        "  HUMAN ANALYST DECISION LATENCY",
        "",
        f"    STATUS: {result['humanLatencyStatus']}",
        "",
    ]
    for line in _wrap(result["doesNotMeasure"], 68):
        lines.append(f"    {line}")
    lines.append("")
    lines.append("    To close it:")
    for line in _wrap(result["humanLatencyRequires"], 66):
        lines.append(f"      {line}")
    lines += ["", "=" * 74, ""]
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_approval_latency_eval")
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="complete workflows to time (default: 20)",
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    add_timeout_argument(parser)
    args = parser.parse_args(argv)

    if args.iterations < 1:
        print("error: --iterations must be at least 1", file=sys.stderr)
        return 2

    watchdog = start_watchdog(args.max_seconds, label="v8 approval latency")
    try:
        # Imported here, after argument parsing, so --help does not pay for
        # SQLAlchemy and the app's settings.
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from app.models.base import Base

        with tempfile.TemporaryDirectory(prefix="aegisx-latency-") as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'latency.db'}")
            # create_all rather than alembic: this measures the service layer's
            # cost against the current models, and running 11 migrations would
            # time the migrations instead.
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine)()
            try:
                result = approval_latency.measure(session, iterations=args.iterations)
                session.commit()
            finally:
                session.close()
                engine.dispose()

        report = {
            "schemaVersion": SCHEMA_VERSION,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "command": " ".join(sys.argv),
            "environment": _environment(),
            "result": result,
        }

        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(_render(report))

        path, _ = write_report(report, args.output_dir, prefix=REPORT_PREFIX)
        print(f"  Report written to {path}\n")
        return 0
    finally:
        if watchdog is not None:
            watchdog.cancel()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
