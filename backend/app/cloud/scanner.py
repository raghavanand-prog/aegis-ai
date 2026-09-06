"""Reading a cloud configuration snapshot from disk and running the checks.

**This is the only class that would change if AEGISX ever scanned a real cloud
account.** It is deliberately the whole of the provider-specific surface: the
checks in ``checks.py`` take a ``ResourceSnapshot`` and do not know or care
whether it came from a file or from an API, so a live scanner is a different
loader and nothing else.

Nothing here reads credentials, resolves a hostname or opens a socket. The
fixtures are hand-written to the shape the AWS APIs return, and every finding
produced through this scanner is ``is_simulated=True``. That flag is carried all
the way to the stored row and to the API response - there is no point at which
a simulated finding stops being labelled one.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.cloud.checks import ResourceSnapshot, run_checks
from app.cloud.findings import CloudFinding

logger = logging.getLogger("aegisx.cloud.scanner")

DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

#: An upper bound on a snapshot file. A posture snapshot is inventory, not
#: telemetry: real ones are large but bounded, and a file larger than this is a
#: mistake rather than a big estate.
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024

#: An upper bound on resources per snapshot, for the same reason the evidence
#: collectors bound their output: a scan nothing can render is not a scan.
MAX_RESOURCES = 5000


class SnapshotError(RuntimeError):
    """A snapshot file could not be read or is not a snapshot."""


@dataclass(frozen=True, slots=True)
class ScanResult:
    """One scan of one account."""

    account: str
    provider: str
    #: When the *snapshot* was taken, which is not when it was scanned. A
    #: finding is only as current as the configuration it was computed from.
    generated_at: str | None
    resources_scanned: int
    findings: tuple[CloudFinding, ...]
    source_file: str
    #: Always true in this version, and stated per-scan rather than assumed.
    is_simulated: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "account": self.account,
            "provider": self.provider,
            "generatedAt": self.generated_at,
            "resourcesScanned": self.resources_scanned,
            "findingCount": len(self.findings),
            "sourceFile": self.source_file,
            "isSimulated": self.is_simulated,
            "executionNote": (
                "A simulated posture scan. AEGISX read a configuration snapshot from "
                "disk; no cloud provider was contacted and no credentials exist."
            ),
        }


def read_snapshot(path: Path) -> dict[str, Any]:
    """Read and validate one snapshot document."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SnapshotError(f"Snapshot is unreadable: {type(exc).__name__}") from exc

    if size > MAX_SNAPSHOT_BYTES:
        raise SnapshotError(
            f"Snapshot is {size} bytes, above the {MAX_SNAPSHOT_BYTES} limit."
        )

    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"Snapshot could not be parsed: {type(exc).__name__}") from exc

    if not isinstance(document, dict):
        raise SnapshotError("Snapshot is not an object.")
    return document


def load_snapshot(document: dict[str, Any]) -> list[ResourceSnapshot]:
    """Turn a snapshot document into resource configurations."""
    entries = document.get("resources")
    if not isinstance(entries, list):
        raise SnapshotError("Snapshot has no resources array.")

    snapshots: list[ResourceSnapshot] = []
    for entry in entries[:MAX_RESOURCES]:
        if not isinstance(entry, dict):
            continue
        arn = entry.get("arn")
        kind = entry.get("kind")
        config = entry.get("config")
        if not isinstance(arn, str) or not isinstance(kind, str):
            continue
        snapshots.append(
            ResourceSnapshot(
                arn=arn,
                resource_kind=kind,
                config=config if isinstance(config, dict) else {},
            )
        )
    return snapshots


def scan_file(path: Path) -> ScanResult:
    """Run every check against one snapshot file."""
    document = read_snapshot(path)
    snapshots = load_snapshot(document)
    findings = run_checks(snapshots)

    logger.info(
        "simulated cloud posture scan complete",
        extra={
            "file": path.name,
            "resources": len(snapshots),
            "findings": len(findings),
        },
    )

    return ScanResult(
        account=str(document.get("account", "")),
        provider=str(document.get("provider", "aws")),
        generated_at=document.get("generatedAt"),
        resources_scanned=len(snapshots),
        findings=tuple(findings),
        source_file=path.name,
    )


def available_snapshots(directory: Path | None = None) -> list[Path]:
    """Snapshot files shipped with the repository, in a stable order."""
    base = directory or DEFAULT_FIXTURE_DIR
    if not base.is_dir():
        return []
    return sorted(base.glob("*.json"))


def scan_all(directory: Path | None = None) -> list[ScanResult]:
    """Every available snapshot, with a broken one skipped rather than fatal."""
    results: list[ScanResult] = []
    for path in available_snapshots(directory):
        try:
            results.append(scan_file(path))
        except SnapshotError as exc:
            logger.warning(
                "skipping unreadable posture snapshot",
                extra={"file": path.name, "error": str(exc)},
            )
    return results
