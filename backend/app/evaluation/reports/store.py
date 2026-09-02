"""Evaluation report storage.

Reports are plain JSON files on disk. The API serves the most recent one; when
no evaluation has been run there is simply nothing to serve, and the UI says so
rather than inventing history.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings

REPORTS_DIR = Path(__file__).resolve().parent
LATEST_FILENAME = "latest.json"


def reports_dir(directory: str | Path | None = None) -> Path:
    if directory:
        return Path(directory)
    if settings.evaluation_reports_dir:
        return Path(settings.evaluation_reports_dir)
    return REPORTS_DIR


def write_report(
    report: dict[str, Any], directory: str | Path | None = None
) -> tuple[Path, Path]:
    """Write a timestamped report plus ``latest.json``. Returns both paths."""
    target = reports_dir(directory)
    target.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    detailed = target / f"detection-eval-{stamp}.json"
    latest = target / LATEST_FILENAME

    payload = json.dumps(report, indent=2, sort_keys=False)
    detailed.write_text(payload, encoding="utf-8")
    latest.write_text(payload, encoding="utf-8")
    return detailed, latest


def load_latest(directory: str | Path | None = None) -> dict[str, Any] | None:
    """Return the most recent report, or None when none has been produced."""
    latest = reports_dir(directory) / LATEST_FILENAME
    if not latest.exists():
        return None
    try:
        return json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def list_reports(directory: str | Path | None = None) -> list[str]:
    target = reports_dir(directory)
    if not target.exists():
        return []
    return sorted(
        path.name for path in target.glob("detection-eval-*.json") if path.is_file()
    )
