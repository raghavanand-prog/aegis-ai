"""The metrics registry, as pure logic.

No HTTP, no database, no scrape. What is checked here is the behaviour that
decides whether a metrics system is an asset or an outage:

**Cardinality is bounded.** The classic way a metrics endpoint takes a service
down is a label whose values are unbounded - a request path containing an
incident id, say. Every distinct value becomes a permanent series, memory grows
without limit, and the scrape gets slower until it times out. So the registry
has a ceiling, and crossing it drops the new series and *says so* through a
counter rather than failing silently or growing anyway.

**The exposition cannot be corrupted.** Label values end up inside a text
format where a quote or a newline changes the meaning of the line. Nothing
user-influenced should reach a label in the first place, and the registry
escapes them regardless - the two together are what make a stray value a
cosmetic problem rather than a parsing one.
"""

from __future__ import annotations

import pytest

from app.observability.metrics import (
    MAX_SERIES_PER_METRIC,
    MetricsRegistry,
    render_prometheus,
)


@pytest.fixture()
def registry() -> MetricsRegistry:
    return MetricsRegistry()


# --- Counters --------------------------------------------------------------


class TestCounter:
    def test_it_counts(self, registry: MetricsRegistry) -> None:
        counter = registry.counter("aegisx_events_total", "Events ingested.")
        counter.increment()
        counter.increment(3)
        assert counter.value() == 4

    def test_it_counts_per_label_set(self, registry: MetricsRegistry) -> None:
        counter = registry.counter("aegisx_requests_total", "Requests.", ("method",))
        counter.increment(labels={"method": "GET"})
        counter.increment(labels={"method": "GET"})
        counter.increment(labels={"method": "POST"})

        assert counter.value(labels={"method": "GET"}) == 2
        assert counter.value(labels={"method": "POST"}) == 1

    def test_a_counter_never_goes_backwards(self, registry: MetricsRegistry) -> None:
        """A decreasing counter breaks every rate() built on it."""
        counter = registry.counter("aegisx_events_total", "Events.")
        with pytest.raises(ValueError, match="negative"):
            counter.increment(-1)

    def test_an_unseen_label_set_reads_as_zero_not_an_error(
        self, registry: MetricsRegistry
    ) -> None:
        counter = registry.counter("aegisx_requests_total", "Requests.", ("method",))
        assert counter.value(labels={"method": "DELETE"}) == 0

    def test_the_same_metric_twice_is_the_same_metric(
        self, registry: MetricsRegistry
    ) -> None:
        """Two modules instrumenting the same thing must not get two registries
        of it, or each sees half the traffic."""
        first = registry.counter("aegisx_events_total", "Events.")
        second = registry.counter("aegisx_events_total", "Events.")
        first.increment()
        assert second.value() == 1

    def test_redeclaring_with_different_labels_is_refused(
        self, registry: MetricsRegistry
    ) -> None:
        registry.counter("aegisx_requests_total", "Requests.", ("method",))
        with pytest.raises(ValueError, match="already registered"):
            registry.counter("aegisx_requests_total", "Requests.", ("route",))

    def test_labels_must_match_the_declaration(self, registry: MetricsRegistry) -> None:
        """A typo'd label name would silently create a parallel series."""
        counter = registry.counter("aegisx_requests_total", "Requests.", ("method",))
        with pytest.raises(ValueError, match="labels"):
            counter.increment(labels={"methd": "GET"})


# --- Gauges ----------------------------------------------------------------


class TestGauge:
    def test_it_goes_up_and_down(self, registry: MetricsRegistry) -> None:
        gauge = registry.gauge("aegisx_open_incidents", "Open incidents.")
        gauge.set(7)
        assert gauge.value() == 7
        gauge.set(3)
        assert gauge.value() == 3


# --- Histograms ------------------------------------------------------------


class TestHistogram:
    def test_it_records_into_cumulative_buckets(self, registry: MetricsRegistry) -> None:
        histogram = registry.histogram(
            "aegisx_request_seconds", "Latency.", buckets=(0.1, 0.5, 1.0)
        )
        for value in (0.05, 0.2, 0.7, 2.0):
            histogram.observe(value)

        snapshot = histogram.snapshot()
        # Prometheus buckets are "less than or equal", and cumulative.
        assert snapshot.buckets[0.1] == 1
        assert snapshot.buckets[0.5] == 2
        assert snapshot.buckets[1.0] == 3
        assert snapshot.count == 4
        assert snapshot.total == pytest.approx(2.95)

    def test_a_negative_observation_is_refused(self, registry: MetricsRegistry) -> None:
        histogram = registry.histogram("aegisx_request_seconds", "Latency.")
        with pytest.raises(ValueError, match="negative"):
            histogram.observe(-0.5)


# --- Cardinality, which is the part that can cause an outage ---------------


class TestCardinalityIsBounded:
    def test_a_flood_of_label_values_does_not_grow_without_limit(
        self, registry: MetricsRegistry
    ) -> None:
        """The failure this exists to prevent: an unbounded label value - a
        request path carrying an incident id - turning every request into a
        permanent series."""
        counter = registry.counter("aegisx_requests_total", "Requests.", ("route",))
        for index in range(MAX_SERIES_PER_METRIC * 3):
            counter.increment(labels={"route": f"/incidents/INC-{index}"})

        assert counter.series_count() == MAX_SERIES_PER_METRIC

    def test_dropping_a_series_is_counted_rather_than_silent(
        self, registry: MetricsRegistry
    ) -> None:
        """A metrics system that quietly stops recording is worse than one that
        is obviously broken."""
        counter = registry.counter("aegisx_requests_total", "Requests.", ("route",))
        for index in range(MAX_SERIES_PER_METRIC + 25):
            counter.increment(labels={"route": f"/r/{index}"})

        assert registry.dropped_series() == 25

    def test_series_already_present_keep_recording_after_the_ceiling(
        self, registry: MetricsRegistry
    ) -> None:
        """Hitting the ceiling must not stop the metrics that matter. The ones
        already there are the ones with real traffic."""
        counter = registry.counter("aegisx_requests_total", "Requests.", ("route",))
        counter.increment(labels={"route": "/api/v1/events"})
        for index in range(MAX_SERIES_PER_METRIC * 2):
            counter.increment(labels={"route": f"/junk/{index}"})

        counter.increment(labels={"route": "/api/v1/events"})
        assert counter.value(labels={"route": "/api/v1/events"}) == 2


# --- Exposition ------------------------------------------------------------


class TestExposition:
    def test_it_renders_the_prometheus_text_format(
        self, registry: MetricsRegistry
    ) -> None:
        registry.counter("aegisx_events_total", "Events ingested.").increment(5)
        text = render_prometheus(registry)

        assert "# HELP aegisx_events_total Events ingested." in text
        assert "# TYPE aegisx_events_total counter" in text
        assert "aegisx_events_total 5" in text

    def test_labels_are_rendered_in_a_stable_order(
        self, registry: MetricsRegistry
    ) -> None:
        """An unstable order makes every scrape a diff."""
        counter = registry.counter(
            "aegisx_requests_total", "Requests.", ("method", "route", "status")
        )
        counter.increment(labels={"status": "200", "route": "/x", "method": "GET"})
        text = render_prometheus(registry)
        assert 'method="GET",route="/x",status="200"' in text

    def test_a_hostile_label_value_cannot_break_the_format(
        self, registry: MetricsRegistry
    ) -> None:
        """Nothing user-influenced should reach a label. This is the second
        line of defence: a stray quote or newline must be a cosmetic problem,
        not a parsing one."""
        counter = registry.counter("aegisx_requests_total", "Requests.", ("route",))
        counter.increment(labels={"route": 'a"b\\c\nd'})
        text = render_prometheus(registry)

        line = next(
            entry for entry in text.splitlines() if entry.startswith("aegisx_requests_total{")
        )
        # The quote, the backslash and the newline are all escaped, so the
        # value stays one label on one line.
        assert line == 'aegisx_requests_total{route="a\\"b\\\\c\\nd"} 1', line
        assert len(text.splitlines()) == 3, "a newline in a label split the output"

    def test_a_histogram_renders_its_bucket_ladder(
        self, registry: MetricsRegistry
    ) -> None:
        histogram = registry.histogram(
            "aegisx_request_seconds", "Latency.", buckets=(0.1, 1.0)
        )
        histogram.observe(0.05)
        text = render_prometheus(registry)

        assert "# TYPE aegisx_request_seconds histogram" in text
        assert 'aegisx_request_seconds_bucket{le="0.1"} 1' in text
        assert 'aegisx_request_seconds_bucket{le="+Inf"} 1' in text
        assert "aegisx_request_seconds_count 1" in text
        assert "aegisx_request_seconds_sum 0.05" in text

    def test_the_output_ends_with_a_newline(self, registry: MetricsRegistry) -> None:
        """Prometheus rejects a body whose final line is unterminated."""
        registry.counter("aegisx_events_total", "Events.").increment()
        assert render_prometheus(registry).endswith("\n")

    def test_an_empty_registry_renders_nothing_rather_than_failing(
        self, registry: MetricsRegistry
    ) -> None:
        assert render_prometheus(registry) == "\n"


# --- Concurrency -----------------------------------------------------------


class TestConcurrency:
    def test_counting_from_many_threads_loses_nothing(
        self, registry: MetricsRegistry
    ) -> None:
        """The collector runs on a background task while requests are served,
        so increments genuinely race."""
        from concurrent.futures import ThreadPoolExecutor

        counter = registry.counter("aegisx_events_total", "Events.")

        def bump() -> None:
            for _ in range(500):
                counter.increment()

        with ThreadPoolExecutor(max_workers=8) as pool:
            for _ in range(8):
                pool.submit(bump)

        assert counter.value() == 8 * 500
