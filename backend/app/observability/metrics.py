"""An in-process metrics registry.

Three instrument types, no dependencies, and one design decision that matters
more than the rest: **cardinality is bounded**.

The usual way a metrics endpoint takes a service down is a label whose values
are unbounded. Instrument requests by ``request.url.path`` and every incident
id becomes a permanent series; memory grows for as long as the process lives
and the scrape gets slower until it times out. The instrumentation, added to
make the service observable, is what makes it fall over.

So each metric has a ceiling. Past it, a *new* label combination is dropped and
``aegisx_metrics_series_dropped_total`` counts it; combinations already present
keep recording, because those are the ones carrying real traffic. That is a
bounded resource with a clear failure state that is visible in the metrics
themselves, rather than an unbounded one that fails later and elsewhere.

The right fix is still not to let unbounded values reach a label at all - the
HTTP instrumentation uses the matched *route template*, not the path - and the
ceiling is what happens when somebody gets that wrong.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from threading import Lock

#: The most distinct label combinations one metric may hold. Chosen to be far
#: above any legitimate use here - the API has fewer than a hundred routes -
#: and far below a number that would cost real memory.
MAX_SERIES_PER_METRIC = 500

#: Default latency ladder, in seconds. Fixed rather than configurable: buckets
#: that change between deployments make historical comparison meaningless.
DEFAULT_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

#: An empty label set, used as the key for an unlabelled metric.
_NO_LABELS: tuple[tuple[str, str], ...] = ()


def _key(
    label_names: tuple[str, ...], labels: dict[str, str] | None
) -> tuple[tuple[str, str], ...]:
    """Turn a label mapping into a stable, hashable key.

    Refuses a mapping whose names do not match the declaration. A typo would
    otherwise create a parallel series that looks right in a dashboard and
    carries a fraction of the traffic.
    """
    labels = labels or {}
    if set(labels) != set(label_names):
        raise ValueError(
            f"labels {sorted(labels)} do not match the declared "
            f"{sorted(label_names)} for this metric."
        )
    return tuple((name, str(labels[name])) for name in sorted(label_names))


class _Instrument:
    """Shared bookkeeping: name, help text, labels and the series ceiling."""

    kind = "untyped"

    def __init__(
        self,
        name: str,
        documentation: str,
        label_names: tuple[str, ...],
        registry: MetricsRegistry,
    ) -> None:
        self.name = name
        self.documentation = documentation
        self.label_names = tuple(label_names)
        self._registry = registry
        self._lock = Lock()

    def series_count(self) -> int:
        raise NotImplementedError

    def _may_create(self, present: bool) -> bool:
        """Whether a new series may be added, counting the drop if not."""
        if present:
            return True
        if self.series_count() < MAX_SERIES_PER_METRIC:
            return True
        self._registry._record_drop()
        return False


class Counter(_Instrument):
    """A value that only ever increases."""

    kind = "counter"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def increment(self, amount: float = 1, *, labels: dict[str, str] | None = None) -> None:
        if amount < 0:
            raise ValueError(
                "A counter cannot be decremented by a negative amount: every "
                "rate() computed over it would be wrong."
            )
        key = _key(self.label_names, labels)
        with self._lock:
            if not self._may_create(key in self._values):
                return
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, *, labels: dict[str, str] | None = None) -> float:
        key = _key(self.label_names, labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def series_count(self) -> int:
        return len(self._values)

    def samples(self) -> list[tuple[tuple[tuple[str, str], ...], float]]:
        with self._lock:
            return sorted(self._values.items())


class Gauge(_Instrument):
    """A value that goes up and down."""

    kind = "gauge"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._values: dict[tuple[tuple[str, str], ...], float] = {}

    def set(self, amount: float, *, labels: dict[str, str] | None = None) -> None:
        key = _key(self.label_names, labels)
        with self._lock:
            if not self._may_create(key in self._values):
                return
            self._values[key] = float(amount)

    def value(self, *, labels: dict[str, str] | None = None) -> float:
        key = _key(self.label_names, labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def series_count(self) -> int:
        return len(self._values)

    def samples(self) -> list[tuple[tuple[tuple[str, str], ...], float]]:
        with self._lock:
            return sorted(self._values.items())


@dataclass
class HistogramSnapshot:
    """One label set's distribution, with cumulative buckets."""

    buckets: dict[float, int] = field(default_factory=dict)
    count: int = 0
    total: float = 0.0


class Histogram(_Instrument):
    """A distribution, recorded into a fixed bucket ladder."""

    kind = "histogram"

    def __init__(
        self,
        name: str,
        documentation: str,
        label_names: tuple[str, ...],
        registry: MetricsRegistry,
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> None:
        super().__init__(name, documentation, label_names, registry)
        self.buckets = tuple(sorted(buckets))
        self._series: dict[tuple[tuple[str, str], ...], HistogramSnapshot] = {}

    def observe(self, amount: float, *, labels: dict[str, str] | None = None) -> None:
        if amount < 0 or math.isnan(amount):
            raise ValueError(
                "A histogram observation cannot be negative or NaN: durations "
                "and sizes are the only things measured here."
            )
        key = _key(self.label_names, labels)
        with self._lock:
            if not self._may_create(key in self._series):
                return
            snapshot = self._series.get(key)
            if snapshot is None:
                snapshot = HistogramSnapshot(
                    buckets=dict.fromkeys(self.buckets, 0)
                )
                self._series[key] = snapshot
            snapshot.count += 1
            snapshot.total += amount
            for bound in self.buckets:
                if amount <= bound:
                    snapshot.buckets[bound] += 1

    def snapshot(self, *, labels: dict[str, str] | None = None) -> HistogramSnapshot:
        key = _key(self.label_names, labels)
        with self._lock:
            existing = self._series.get(key)
            if existing is None:
                return HistogramSnapshot(buckets=dict.fromkeys(self.buckets, 0))
            return HistogramSnapshot(
                buckets=dict(existing.buckets),
                count=existing.count,
                total=existing.total,
            )

    def series_count(self) -> int:
        return len(self._series)

    def samples(self) -> list[tuple[tuple[tuple[str, str], ...], HistogramSnapshot]]:
        with self._lock:
            return sorted(
                (key, HistogramSnapshot(dict(s.buckets), s.count, s.total))
                for key, s in self._series.items()
            )


class MetricsRegistry:
    """Every instrument in this process."""

    def __init__(self) -> None:
        self._instruments: dict[str, _Instrument] = {}
        self._lock = Lock()
        self._dropped = 0

    def _record_drop(self) -> None:
        # Not itself a Counter: it is incremented from inside a Counter's lock,
        # and a metric that could deadlock the thing it measures is not a
        # useful metric.
        self._dropped += 1

    def dropped_series(self) -> int:
        return self._dropped

    def _get_or_create(self, instrument: _Instrument) -> _Instrument:
        with self._lock:
            existing = self._instruments.get(instrument.name)
            if existing is None:
                self._instruments[instrument.name] = instrument
                return instrument
            if (
                existing.label_names != instrument.label_names
                or existing.kind != instrument.kind
            ):
                raise ValueError(
                    f"{instrument.name!r} is already registered as a "
                    f"{existing.kind} with labels {list(existing.label_names)}. "
                    "Two shapes of the same metric would each see part of the "
                    "traffic."
                )
            return existing

    def counter(
        self, name: str, documentation: str, label_names: tuple[str, ...] = ()
    ) -> Counter:
        return self._get_or_create(Counter(name, documentation, label_names, self))

    def gauge(
        self, name: str, documentation: str, label_names: tuple[str, ...] = ()
    ) -> Gauge:
        return self._get_or_create(Gauge(name, documentation, label_names, self))

    def histogram(
        self,
        name: str,
        documentation: str,
        label_names: tuple[str, ...] = (),
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> Histogram:
        return self._get_or_create(
            Histogram(name, documentation, label_names, self, buckets)
        )

    def instruments(self) -> list[_Instrument]:
        with self._lock:
            return [self._instruments[name] for name in sorted(self._instruments)]


def _escape_label(value: str) -> str:
    """Escape a label value for the text format.

    Nothing user-influenced should reach a label - the HTTP instrumentation
    uses route templates, not paths. This is the second line of defence, so
    that a value which slips through is a cosmetic problem rather than one
    that corrupts every line after it.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_number(value: float) -> str:
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def _format_bound(value: float) -> str:
    """Render a bucket boundary.

    Kept apart from `_format_number` so a bound of 1.0 renders as "1.0" rather
    than "1". Prometheus would accept either, but `le` is a label value and a
    ladder that reads 0.005, 0.01, 1, 2.5 is harder to scan than one that does
    not change shape halfway up.
    """
    return f"{value:g}" if value < 1 else f"{value:.1f}".rstrip("0") + (
        "0" if float(value).is_integer() else ""
    )


def _labels_text(key: tuple[tuple[str, str], ...], extra: str | None = None) -> str:
    parts = [f'{name}="{_escape_label(value)}"' for name, value in key]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def render_prometheus(registry: MetricsRegistry) -> str:
    """Render every instrument in the Prometheus text exposition format."""
    lines: list[str] = []

    for instrument in registry.instruments():
        lines.append(f"# HELP {instrument.name} {instrument.documentation}")
        lines.append(f"# TYPE {instrument.name} {instrument.kind}")

        if isinstance(instrument, Histogram):
            for key, snapshot in instrument.samples():
                for bound in instrument.buckets:
                    label = _labels_text(key, f'le="{_format_bound(bound)}"')
                    lines.append(
                        f"{instrument.name}_bucket{label} {snapshot.buckets[bound]}"
                    )
                inf_label = _labels_text(key, 'le="+Inf"')
                lines.append(
                    f"{instrument.name}_bucket{inf_label} {snapshot.count}"
                )
                lines.append(
                    f"{instrument.name}_count{_labels_text(key)} {snapshot.count}"
                )
                lines.append(
                    f"{instrument.name}_sum{_labels_text(key)} "
                    f"{_format_number(snapshot.total)}"
                )
            continue

        for key, value in instrument.samples():  # type: ignore[assignment]
            lines.append(
                f"{instrument.name}{_labels_text(key)} {_format_number(value)}"
            )

    return "\n".join(lines) + "\n"
