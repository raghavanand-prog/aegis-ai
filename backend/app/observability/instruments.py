"""The metrics AEGISX actually records.

One module-level registry. Instruments are declared here rather than created
where they are used, so that the full set is readable in one place and two
call sites cannot register the same name with different labels.

**Every label on this page has a small, fixed set of values.** That is the
whole discipline: ``route`` is the matched route *template*, never the request
path, so ``/api/v1/incidents/{incident_id}`` is one series rather than one per
incident. A request that matches no route is labelled ``unmatched``, which
means a flood of random 404 paths collapses into a single series instead of
being the cheapest denial of service available against a metrics endpoint.

**What is deliberately not measured.** Nothing keyed by user, incident,
account, indicator or any other identifier. A metric is a permanent series and
a scrape target is usually less protected than the API - a counter per user
would turn the metrics endpoint into a slow leak of who works here and what
they touch.
"""

from __future__ import annotations

from app.observability.metrics import MetricsRegistry

registry = MetricsRegistry()

#: HTTP surface.
http_requests = registry.counter(
    "aegisx_http_requests_total",
    "HTTP requests, by route template, method and status class.",
    ("route", "method", "status"),
)
http_request_seconds = registry.histogram(
    "aegisx_http_request_duration_seconds",
    "HTTP request duration in seconds, by route template.",
    ("route",),
)
http_exceptions = registry.counter(
    "aegisx_http_exceptions_total",
    "Requests that raised out of the application, by route template.",
    ("route",),
)

#: The SOC pipeline. These are the numbers an operator is actually asked about.
events_ingested = registry.counter(
    "aegisx_events_ingested_total",
    "Security events accepted into the pipeline, by source type.",
    ("source_type",),
)
incidents_created = registry.counter(
    "aegisx_incidents_created_total",
    "Incidents opened, by severity.",
    ("severity",),
)
incident_transitions = registry.counter(
    "aegisx_incident_transitions_total",
    "Incident lifecycle transitions, by target state.",
    ("target",),
)

#: V9 governance. A refused approval is the interesting one: it means the
#: four-eyes rule or the evidence-freshness check did its job.
response_actions = registry.counter(
    "aegisx_response_actions_total",
    "Response action requests and decisions, by outcome.",
    ("outcome",),
)
evidence_drift = registry.counter(
    "aegisx_evidence_drift_total",
    "Evidence integrity verdicts computed against recorded decisions.",
    ("verdict",),
)

#: The metrics system's own health. A dropped series means an unbounded label
#: reached an instrument, which is a bug worth alerting on.
#: A gauge rather than a counter despite only ever rising: the value is read
#: back from the registry at scrape time rather than incremented here, and a
#: `_total` suffix on something that is not a counter misleads every tool that
#: reads the name.
series_dropped = registry.gauge(
    "aegisx_metrics_series_dropped",
    "Label combinations refused because a metric hit its series ceiling.",
)


def status_class(status_code: int) -> str:
    """Bucket a status into 2xx/3xx/4xx/5xx.

    The exact code is in the logs, which are queryable and expire. A metric is
    a permanent series, and the difference between 401 and 403 has never been
    worth one.
    """
    return f"{status_code // 100}xx"


def snapshot() -> str:
    """Render everything, refreshing the registry's self-report first."""
    from app.observability.metrics import render_prometheus

    series_dropped.set(registry.dropped_series())
    return render_prometheus(registry)
