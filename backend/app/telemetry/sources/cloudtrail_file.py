"""A telemetry source that reads AWS CloudTrail records from files on disk.

**This is fixture-backed and labelled simulated. Nothing here has ever talked to
AWS.** No credentials are read, no network call is made, and no result produced
through this source is evidence about real cloud activity. It is marked
``is_synthetic`` on every record it emits, exactly as the generator is.

**Why a file source rather than a live one.** A live CloudTrail integration
needs an AWS account, credentials, and a trail - none of which this environment
has, and manufacturing a "validated live provider" without them is the failure
mode the V6 audit spent a session correcting. What a file source *can* do is
exercise the whole path for real: a genuine CloudTrail record shape enters at
one end, and an alert comes out the other through the same normalizer, feature
extractor and detection engine every other source uses.

CloudTrail delivers real records as gzipped JSON files containing a
``{"Records": [...]}`` envelope, which is also how the fixtures are written. A
future live source replaces *this class* - the S3/CloudWatch client and its
credential handling - and reuses ``CloudTrailAdapter`` unchanged. That split is
the point of Phase 4.
"""

from __future__ import annotations

import gzip
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.enums import SourceType
from app.telemetry.adapters.cloudtrail import SOURCE_NAME
from app.telemetry.base import RawTelemetry, TelemetrySource

logger = logging.getLogger("aegisx.telemetry.cloudtrail")

#: Fixtures shipped with the repository.
DEFAULT_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cloudtrail"


class CloudTrailFileSource(TelemetrySource):
    """Emits CloudTrail records read from ``.json`` / ``.json.gz`` files.

    Records are emitted in a stable order - files sorted by name, records in
    file order - so a run over a fixture directory is reproducible without a
    seed, the same property the caps rely on.
    """

    name = SOURCE_NAME
    source_type = SourceType.CLOUD
    #: False, and the distinction is load-bearing. ``is_external`` means "talks
    #: to something outside this process", which gates a source behind an
    #: operator opt-in. Reading a local file does not, and claiming otherwise
    #: would make the flag meaningless for the live source that will need it.
    is_external = False

    def __init__(
        self,
        fixture_dir: Path | str | None = None,
        *,
        repeat: bool = True,
    ) -> None:
        self.fixture_dir = Path(fixture_dir) if fixture_dir else DEFAULT_FIXTURE_DIR
        #: Whether ``collect`` starts over when the fixtures are exhausted. True
        #: for a demo that should keep producing; False when a test wants each
        #: record exactly once.
        self.repeat = repeat
        self._records: list[dict[str, Any]] | None = None
        self._position = 0
        self._malformed = 0

    # ------------------------------------------------------------- loading
    def _load(self) -> list[dict[str, Any]]:
        if self._records is not None:
            return self._records

        records: list[dict[str, Any]] = []
        if not self.fixture_dir.is_dir():
            logger.warning(
                "CloudTrail fixture directory %s does not exist; the source will "
                "emit nothing.",
                self.fixture_dir,
            )
            self._records = records
            return records

        for path in sorted(self.fixture_dir.iterdir()):
            if path.suffix not in {".json", ".gz"}:
                continue
            records.extend(self._read_file(path))

        self._records = records
        logger.info(
            "Loaded %d CloudTrail record(s) from %s (%d unreadable file(s) skipped)",
            len(records),
            self.fixture_dir,
            self._malformed,
        )
        return records

    def _read_file(self, path: Path) -> list[dict[str, Any]]:
        """Read one trail file. A bad file is skipped, never fatal.

        A single corrupt file must not stop the source: the collector loop is
        supposed to survive a bad record, and a source that raised on one would
        take the whole ingestion path down with it.
        """
        try:
            if path.suffix == ".gz":
                payload = gzip.decompress(path.read_bytes()).decode()
            else:
                payload = path.read_text()
            document = json.loads(payload)
        except (OSError, ValueError, gzip.BadGzipFile):
            self._malformed += 1
            logger.warning("Skipping unreadable CloudTrail file %s", path)
            return []

        # CloudTrail's own envelope, or a bare list for convenience.
        if isinstance(document, dict):
            records = document.get("Records", [])
        elif isinstance(document, list):
            records = document
        else:
            self._malformed += 1
            logger.warning("Skipping CloudTrail file %s: unexpected top-level shape", path)
            return []

        return [record for record in records if isinstance(record, dict)]

    # ------------------------------------------------------------ emitting
    def _raw_log(self, record: dict[str, Any]) -> str:
        """A one-line rendering, for the analyst-facing raw log column."""
        identity = record.get("userIdentity") or {}
        return (
            f"[CloudTrail] {record.get('eventTime', '')} "
            f"{record.get('eventSource', '')} {record.get('eventName', '')} "
            f"principal={identity.get('arn') or identity.get('principalId') or 'unknown'} "
            f"src={record.get('sourceIPAddress', '')}"
        ).strip()

    def _received_at(self, record: dict[str, Any]) -> datetime:
        """The record's own ``eventTime``, falling back to now.

        Using the record's time rather than the wall clock matters for the
        behavioural features, which are stateful and ordered: replaying a trail
        with every record stamped "now" would collapse a day of activity into
        one instant and change what the detector sees.
        """
        raw_time = record.get("eventTime")
        if isinstance(raw_time, str):
            try:
                parsed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
            if parsed is not None:
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    def collect(self, count: int = 1) -> Iterable[RawTelemetry]:
        records = self._load()
        if not records:
            return []
        return list(self._take(records, count))

    def _take(self, records: list[dict[str, Any]], count: int) -> Iterator[RawTelemetry]:
        for _ in range(max(0, count)):
            if self._position >= len(records):
                if not self.repeat:
                    return
                self._position = 0
            record = records[self._position]
            self._position += 1
            yield RawTelemetry(
                source=self.name,
                source_type=self.source_type,
                raw=record,
                raw_log=self._raw_log(record),
                received_at=self._received_at(record),
                # Always. These are fixtures, and a record that claimed
                # otherwise would let simulated activity be counted as real.
                is_synthetic=True,
            )

    def health(self) -> dict[str, Any]:
        return {
            **super().health(),
            "mode": "fixture",
            "simulated": True,
            "fixtureDir": str(self.fixture_dir),
            "recordsAvailable": len(self._load()),
            "unreadableFiles": self._malformed,
        }
