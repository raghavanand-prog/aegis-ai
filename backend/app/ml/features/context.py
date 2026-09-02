"""Rolling behavioural context.

Several of the most useful features are not properties of one event at all -
"is this a rare process on this host", "how many distinct users has this host
seen", "how bursty is this source address" - they are properties of what came
before it.

This class keeps those counters in a bounded, in-memory sliding window.

Two properties matter more than anything else here:

**Determinism.** Feeding the same events in the same order into a fresh context
always yields the same features. That is what makes training reproducible and
what makes an evaluation run comparable to the one before it.

**Identical use in training and inference.** The training pipeline replays its
dataset chronologically through this exact class, so a feature never means one
thing when the model is fitted and something else when it scores live
telemetry. Training/inference skew is the classic way an ML detector silently
stops working, and the only defence is to have one implementation.

The window is time-based, and every structure inside is capped, so a long
running process cannot grow without bound.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock

#: How far back the counters look.
DEFAULT_WINDOW_MINUTES = 60
#: Upper bound on how many distinct entities of one kind are tracked. Past this
#: the least recently seen entity is evicted: a memory ceiling matters more
#: than perfect recall of an entity nobody has seen in an hour.
MAX_ENTITIES = 5_000
#: Upper bound on retained observations per entity.
MAX_OBSERVATIONS = 500


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass
class _EntityState:
    """Everything remembered about one entity inside the window."""

    #: Observation timestamps, oldest first.
    seen: deque[datetime] = field(default_factory=lambda: deque(maxlen=MAX_OBSERVATIONS))
    #: Companion values observed with this entity (users on a host, ports on an
    #: address, ...). Capped, and reset with the window.
    companions: dict[str, deque[datetime]] = field(default_factory=dict)
    failures: int = 0
    successes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def prune(self, cutoff: datetime) -> None:
        while self.seen and self.seen[0] < cutoff:
            self.seen.popleft()
        stale = []
        for key, stamps in self.companions.items():
            while stamps and stamps[0] < cutoff:
                stamps.popleft()
            if not stamps:
                stale.append(key)
        for key in stale:
            del self.companions[key]

    @property
    def count(self) -> int:
        return len(self.seen)

    @property
    def distinct_companions(self) -> int:
        return len(self.companions)


class BehaviorContext:
    """Sliding-window counters for hosts, users, addresses and processes."""

    #: Entity kinds tracked. Named explicitly so the feature extractor and the
    #: context cannot drift apart.
    KINDS = ("host", "user", "source_ip", "process", "destination")

    def __init__(self, window_minutes: int = DEFAULT_WINDOW_MINUTES) -> None:
        self.window = timedelta(minutes=window_minutes)
        self._entities: dict[str, dict[str, _EntityState]] = {
            kind: {} for kind in self.KINDS
        }
        #: Entities seen at any point since the context was created, used for
        #: the "first time we have ever seen this" features. Bounded.
        self._ever_seen: dict[str, set[str]] = defaultdict(set)
        self._lock = RLock()
        self._observations = 0

    # ------------------------------------------------------------------ reads
    def snapshot(self, kind: str, value: str | None, now: datetime | None = None) -> dict:
        """Counters for one entity, without recording a new observation.

        Always called *before* :meth:`observe` for the event being scored, so a
        feature never counts the event it is describing.
        """
        if not value:
            return {
                "count": 0,
                "distinct_companions": 0,
                "is_new": 1.0,
                "rate_per_minute": 0.0,
                "failure_ratio": 0.0,
                "age_minutes": 0.0,
            }

        now = _utc(now)
        cutoff = now - self.window
        with self._lock:
            state = self._entities.get(kind, {}).get(value)
            ever = value in self._ever_seen.get(kind, set())
            if state is None:
                return {
                    "count": 0,
                    "distinct_companions": 0,
                    "is_new": 0.0 if ever else 1.0,
                    "rate_per_minute": 0.0,
                    "failure_ratio": 0.0,
                    "age_minutes": 0.0,
                }

            state.prune(cutoff)
            span_minutes = 0.0
            if state.first_seen is not None:
                span_minutes = max((now - _utc(state.first_seen)).total_seconds() / 60.0, 0.0)

            attempts = state.failures + state.successes
            return {
                "count": float(state.count),
                "distinct_companions": float(state.distinct_companions),
                "is_new": 0.0 if ever else 1.0,
                # Rate over the observed span, floored at one minute so a burst
                # of two events in one second does not become a huge number.
                "rate_per_minute": state.count / max(min(span_minutes, self.window.total_seconds() / 60), 1.0),
                "failure_ratio": (state.failures / attempts) if attempts else 0.0,
                "age_minutes": min(span_minutes, self.window.total_seconds() / 60),
            }

    # ----------------------------------------------------------------- writes
    def observe(
        self,
        kind: str,
        value: str | None,
        *,
        timestamp: datetime | None = None,
        companion: str | None = None,
        outcome: str | None = None,
    ) -> None:
        """Record that ``value`` was seen. ``outcome`` is "failure"/"success"."""
        if not value or kind not in self._entities:
            return

        now = _utc(timestamp)
        with self._lock:
            bucket = self._entities[kind]
            state = bucket.get(value)
            if state is None:
                if len(bucket) >= MAX_ENTITIES:
                    self._evict(bucket)
                state = _EntityState(first_seen=now)
                bucket[value] = state

            state.seen.append(now)
            state.last_seen = now
            if state.first_seen is None:
                state.first_seen = now
            if companion:
                stamps = state.companions.get(companion)
                if stamps is None:
                    if len(state.companions) >= MAX_OBSERVATIONS:
                        state.companions.pop(next(iter(state.companions)))
                    stamps = deque(maxlen=MAX_OBSERVATIONS)
                    state.companions[companion] = stamps
                stamps.append(now)
            if outcome == "failure":
                state.failures += 1
            elif outcome == "success":
                state.successes += 1

            ever = self._ever_seen[kind]
            if len(ever) < MAX_ENTITIES * 2:
                ever.add(value)
            self._observations += 1

    @staticmethod
    def _evict(bucket: dict[str, _EntityState]) -> None:
        """Drop the least recently seen entity to keep the map bounded."""
        oldest_key = min(
            bucket,
            key=lambda key: bucket[key].last_seen or datetime.min.replace(tzinfo=timezone.utc),
        )
        del bucket[oldest_key]

    # ------------------------------------------------------------------ admin
    def reset(self) -> None:
        with self._lock:
            self._entities = {kind: {} for kind in self.KINDS}
            self._ever_seen = defaultdict(set)
            self._observations = 0

    @property
    def observation_count(self) -> int:
        return self._observations

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "observations": self._observations,
                "windowMinutes": int(self.window.total_seconds() // 60),
                **{f"{kind}s": len(values) for kind, values in self._entities.items()},
            }
