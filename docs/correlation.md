# Event correlation

Individually unremarkable events become a finding when they are related. Twenty
failed logins are noise; twenty failed logins followed by a success from the
same address is a story.

```
new event ─► candidate keys ─► fetch window ─► evaluate patterns
          ─► open or extend a SecuritySequence ─► score ─► notify
```

## A sequence is not an incident

The correlation engine **never** creates an incident. It opens a
`SecuritySequence`, scores it with the same transparent strategy events use,
and — above `CORRELATION_INCIDENT_RISK` (default 70) — raises a notification so
an analyst can decide. Promotion is always a human action
(`POST /sequences/{id}/promote`).

A statistical grouping deciding on its own that the SOC has an incident is
exactly the behaviour that makes a queue unusable.

## Where it runs

On the **enrichment path**, not the ingestion path. An event is persisted,
broadcast and visible to analysts before the correlator ever looks at it.

```
FAST PATH (synchronous)
    normalize → rules → ML inference → risk score → persist
    → IOCs → notification → WebSocket

SLOW PATH (app/services/enrichment_service.py, one worker thread)
    threat intelligence → correlation → rescore → broadcast update
```

A slow correlation query must never be able to delay telemetry landing. The
queue is bounded (`ENRICHMENT_QUEUE_SIZE`, default 2000) and **drops** work
rather than growing without bound, reporting the drop count via
`GET /api/v1/health/enrichment`. Dropped enrichment costs context, not
detection.

Why a thread queue and not a broker: this is a modular monolith serving one SOC.
Kafka would add an operational dependency, a deployment story and a failure mode
in exchange for throughput nothing here needs.

## Patterns

`app/correlation/patterns.py`. A pattern answers two questions: *which group
does this event belong to* (the correlation key) and *is that group worth
telling anyone about* (the verdict).

| Id | Groups on | Fires when | Infers |
| --- | --- | --- | --- |
| `COR-AUTH-001` | user, else source address | ≥2 auth failures; much stronger when a success follows | T1110 |
| `COR-HOST-001` | host | ≥3 distinct activity stages (authentication, execution, privilege change, network, malware) | — |
| `COR-LAT-001` | user | one principal against ≥3 distinct hosts/destinations | T1021 |
| `COR-NET-001` | source address | one address, varied sustained activity | — |

Patterns are entity-based and time-bounded. They do not attempt to reconstruct
an attacker's intent; they observe that several things happened to the same
host, user or address inside a window, and say so.

**Membership is filtered by the pattern's own candidacy test.** The entity query
is a cheap first pass, then `key_for` is applied to every row. Without that, a
"credential attack sequence" keyed on a user would absorb every unrelated event
that user produced in the window — inflating the count, the score and the story
it tells.

`COR-LAT-001` exists because the deterministic rule set has **no lateral
movement rule**, and the V2 evaluation measures and reports that gap. The signal
is not in any single event: it is one principal appearing on hosts it does not
normally appear on. That is a correlation problem, not a rule problem.

## Rationale

Every sequence stores plain-language statements of *why* those events were
grouped, and the UI renders them prominently:

```
- 23 authentication failure(s) in the correlation window
- a successful sign-in followed at 2026-09-02T09:13:33Z
- attempts came from 2 distinct source addresses
- the ML model flagged at least one of these events as anomalous
```

A correlation an analyst cannot interrogate is just an assertion.

## Scoring

`_score_sequence` uses the **strongest** rule contribution among the members,
not the sum. One rule firing across twenty linked events is one finding observed
twenty times; summing would let repetition alone manufacture a critical. ML and
correlation contributions are added under the same weights events use, and the
result is stored as `riskSignals[]`.

An incident promoted from a sequence has its risk recomputed from the union of
its member events' signals and the sequence's own signal
(`incident_service.recompute_risk`), so the score and the breakdown underneath
it always agree. A test asserts that.

## MITRE provenance

`app/correlation/mitre.py`. A technique on a sequence is not the same kind of
claim as a technique on a rule match, and pretending otherwise is how a platform
ends up asserting that "AI discovered T1110".

| Provenance | Meaning |
| --- | --- |
| `mapped` | A deterministic rule declared it and stated the condition it matched. |
| `inferred` | The correlation engine derived it from the *shape* of the sequence. |
| `contextual` | Merely present on a member event; background, not a finding. |

When the same technique arrives with several provenances, the strongest wins.

**The ML model contributes no techniques at all.** Isolation Forest identifies
statistical outliers and has no concept of an attack technique; asserting one on
its behalf would be a fabrication. The MITRE tab in the UI says so explicitly.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `CORRELATION_ENABLED` | `true` | |
| `CORRELATION_WINDOW_MINUTES` | `30` | How far back the correlator looks. |
| `CORRELATION_MIN_EVENTS` | `3` | Floor before a group is judged. |
| `CORRELATION_INCIDENT_RISK` | `70` | Above this, a notification is raised. |
| `ENRICHMENT_ENABLED` | `true` | Background worker master switch. |
| `ENRICHMENT_QUEUE_SIZE` | `2000` | Bounded; excess is dropped and reported. |
