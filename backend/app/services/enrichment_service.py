"""Background enrichment.

The ingestion path has one job: get telemetry into the database and onto the
analysts' screens. Anything that can be slow - an HTTP call to a reputation
service, a correlation query over a time window - runs here instead, after the
event is already persisted and broadcast.

    FAST PATH (synchronous, in the request/collector thread)
        normalize -> rules -> ML inference -> risk score -> persist
        -> IOCs -> notification -> WebSocket

    SLOW PATH (this worker)
        threat intelligence -> correlation -> rescore -> broadcast update

ML inference stays on the fast path deliberately: it is a single in-process
scikit-learn call measured in fractions of a millisecond, it needs the events in
arrival order to keep its rolling context coherent, and its score is part of the
event's risk from the moment the event exists. Network calls are the thing worth
deferring, not arithmetic.

Why a bounded thread queue and not a broker: this is a modular monolith serving
one SOC. A queue with a ceiling and a worker thread is the whole requirement.
Kafka would add an operational dependency, a deployment story and a failure mode
in exchange for throughput nothing here needs.

The queue drops work rather than growing without bound, and says so in the log
and in its own status. Silent unbounded growth is how a background worker takes
a process down.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.core.database import session_scope

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentTask:
    """One unit of deferred work, addressed by primary key.

    Only the id crosses the thread boundary. Passing an ORM instance between
    sessions is how you get a DetachedInstanceError at three in the morning.
    """

    event_id: int
    enqueued_at: datetime


class EnrichmentWorker:
    """Single background thread draining a bounded queue of enrichment tasks."""

    def __init__(self, max_size: int | None = None) -> None:
        self._queue: queue.Queue[EnrichmentTask | None] = queue.Queue(
            maxsize=max_size or settings.enrichment_queue_size
        )
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

        self._processed = 0
        self._dropped = 0
        self._failures = 0
        self._enriched_indicators = 0
        self._sequences_touched = 0
        self._last_run: datetime | None = None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._run, name="aegisx-enrichment", daemon=True
            )
            self._thread.start()
        logger.info(
            "Enrichment worker started (queue size %d)", self._queue.maxsize
        )

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
        try:
            self._queue.put_nowait(None)  # wake the worker so it can exit
        except queue.Full:  # pragma: no cover - shutdown with a full queue
            pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        self._thread = None
        logger.info("Enrichment worker stopped after %d task(s)", self._processed)

    # ---------------------------------------------------------------- submit
    def submit(self, event_id: int) -> bool:
        """Queue an event for enrichment. Returns False when the queue is full.

        Never blocks. A full queue means enrichment is falling behind ingestion,
        which is a degraded state worth reporting - not a reason to stall the
        pipeline that feeds it.
        """
        if not settings.enrichment_enabled or not self._running:
            return False
        try:
            self._queue.put_nowait(
                EnrichmentTask(event_id=event_id, enqueued_at=datetime.now(timezone.utc))
            )
            return True
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:  # log the first, then every hundredth
                logger.warning(
                    "Enrichment queue is full; skipping enrichment for event %d "
                    "(%d dropped so far). Detection and ingestion are unaffected.",
                    event_id,
                    self._dropped,
                )
            return False

    # ------------------------------------------------------------------ loop
    def _run(self) -> None:
        while self._running:
            try:
                task = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if task is None:  # shutdown sentinel
                self._queue.task_done()
                break

            try:
                self._process(task)
                self._processed += 1
            except Exception:  # noqa: BLE001 - one bad event must not kill the worker
                self._failures += 1
                logger.exception("Enrichment failed for event %d", task.event_id)
            finally:
                self._last_run = datetime.now(timezone.utc)
                self._queue.task_done()

    def _process(self, task: EnrichmentTask) -> None:
        # Imported here rather than at module scope: these modules import the
        # services package, which imports this one.
        from app.correlation import engine as correlation_engine
        from app.models.event import Event
        from app.services import event_service
        from app.threatintel import service as threat_intel_service

        with session_scope() as db:
            event = db.get(Event, task.event_id)
            if event is None:  # deleted between enqueue and processing
                return

            intel_results = []
            if settings.threat_intel_enabled:
                try:
                    intel_results = threat_intel_service.enrich_iocs(db, list(event.iocs or []))
                    self._enriched_indicators += len(intel_results)
                except Exception:  # noqa: BLE001 - enrichment is best-effort
                    logger.exception("Threat intelligence enrichment failed")

            sequences = []
            if settings.correlation_enabled:
                try:
                    sequences = correlation_engine.correlate_event(db, event)
                    self._sequences_touched += len(sequences)
                except Exception:  # noqa: BLE001
                    logger.exception("Correlation failed")

            # Rescore only when enrichment actually found something, so an
            # ordinary event is not rewritten and rebroadcast for nothing.
            if intel_results or sequences:
                event_service.rescore_event(db, event, threat_intel=intel_results)

    # ---------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        depth = self._queue.qsize()
        return {
            "enabled": settings.enrichment_enabled,
            "running": self._running,
            "queueDepth": depth,
            "queueCapacity": self._queue.maxsize,
            "processed": self._processed,
            "dropped": self._dropped,
            "failures": self._failures,
            "indicatorsEnriched": self._enriched_indicators,
            "sequencesTouched": self._sequences_touched,
            "lastRunAt": self._last_run.isoformat() if self._last_run else None,
            # Degraded rather than unavailable: dropping enrichment costs
            # context, not detection.
            "degraded": self._dropped > 0 or depth > self._queue.maxsize * 0.8,
        }

    def drain(self, timeout: float = 10.0) -> None:
        """Block until the queue is empty. Tests only - never called in production."""
        deadline = threading.Event()
        deadline.wait(0)
        self._queue.join()


#: Application-wide worker, started from the FastAPI lifespan hook.
worker = EnrichmentWorker()
