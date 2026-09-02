"""Telemetry collector.

Owns the ingestion loop: pull raw records from every registered source,
normalize them, run detection, persist, and broadcast. The generator lives
here in the backend rather than in the browser, so every client sees the same
stream and the data survives a page reload.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import session_scope
from app.models.event import Event
from app.services import event_service
from app.telemetry.base import TelemetrySource
from app.telemetry.normalizer import NormalizationError, normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

logger = logging.getLogger(__name__)


class ExternalSourceRefused(RuntimeError):
    """Raised when an external source is registered without explicit opt-in."""


class TelemetryCollector:
    """Periodically pulls telemetry from its sources into the event pipeline."""

    def __init__(
        self,
        sources: list[TelemetrySource] | None = None,
        *,
        interval_seconds: float | None = None,
        events_per_tick: int | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds or settings.telemetry_interval_seconds
        self.events_per_tick = events_per_tick or settings.telemetry_events_per_tick
        self.sources: list[TelemetrySource] = []
        self._task: asyncio.Task | None = None
        self._running = False
        self._ingested = 0
        self._errors = 0
        self._last_tick: datetime | None = None
        self._started_at: datetime | None = None

        for source in sources if sources is not None else [SyntheticTelemetrySource()]:
            self.register(source)

    # ------------------------------------------------------------- lifecycle
    def register(self, source: TelemetrySource) -> None:
        """Add a source, refusing external ones unless explicitly enabled."""
        if source.is_external and not settings.telemetry_allow_external_sources:
            raise ExternalSourceRefused(
                f"Source {source.name!r} talks to systems outside this process. Set "
                "TELEMETRY_ALLOW_EXTERNAL_SOURCES=true to enable it deliberately."
            )
        self.sources.append(source)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._started_at = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._run(), name="aegisx-telemetry-collector")
        logger.info(
            "Telemetry collector started: %d source(s), %.1fs interval, %d event(s) per tick",
            len(self.sources),
            self.interval_seconds,
            self.events_per_tick,
        )

    async def stop(self) -> None:
        self._running = False
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            pass
        finally:
            self._task = None
        logger.info("Telemetry collector stopped after ingesting %d event(s)", self._ingested)

    # ------------------------------------------------------------------ loop
    async def _run(self) -> None:
        while self._running:
            try:
                await asyncio.to_thread(self.tick)
            except asyncio.CancelledError:  # pragma: no cover - shutdown path
                raise
            except Exception:  # noqa: BLE001 - the loop must survive a bad record
                self._errors += 1
                logger.exception("Telemetry tick failed")
            await asyncio.sleep(self.interval_seconds)

    def tick(self) -> int:
        """Run one collection cycle. Returns the number of events ingested."""
        with session_scope() as db:
            events = self.collect_once(db)
        self._last_tick = datetime.now(timezone.utc)
        self._ingested += len(events)
        return len(events)

    def collect_once(self, db: Session, *, broadcast: bool = True) -> list[Event]:
        """Collect, normalize and persist one batch. Synchronous and testable."""
        ingested: list[Event] = []

        for source in self.sources:
            for record in source.collect(self.events_per_tick):
                try:
                    candidate = normalize(record)
                except NormalizationError:
                    self._errors += 1
                    logger.warning("Dropping unmappable record from %s", record.source)
                    continue

                event = event_service.ingest_candidate(db, candidate, broadcast=broadcast)
                ingested.append(event)

        return ingested

    # ---------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "intervalSeconds": self.interval_seconds,
            "eventsPerTick": self.events_per_tick,
            "eventsIngested": self._ingested,
            "errors": self._errors,
            "startedAt": self._started_at.isoformat() if self._started_at else None,
            "lastTickAt": self._last_tick.isoformat() if self._last_tick else None,
            "sources": [source.health() for source in self.sources],
            "externalSourcesAllowed": settings.telemetry_allow_external_sources,
        }


#: Application-wide collector instance, started from the FastAPI lifespan hook.
collector = TelemetryCollector()
