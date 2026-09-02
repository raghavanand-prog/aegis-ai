# AEGISX Architecture

> **Scope note.** The diagram and prose below describe the **V1** shape, which
> remains the foundation and is still accurate for the ingestion path. V2 added
> hardening, RBAC and audit; V3 added ML, correlation, threat intelligence and
> the AI analyst; V4 added the research/evaluation layer. What each version
> changed is summarised at the end of this file, with pointers to the documents
> that describe them in full.

## Shape (V1)

A modular monolith backend and a single-page frontend.

```
                     +-------------------------------+
 TelemetrySource --> |  TelemetryCollector (asyncio) |
 (synthetic, V1)     +---------------+---------------+
                                     |
                              Normalizer  (vendor shape -> canonical event)
                                     |
                              Detection rules  (severity, risk, ATT&CK)
                                     |
                       EventService  ->  PostgreSQL
                                     |
                     +---------------+---------------+
                     |                               |
              NotificationService            ConnectionManager
                     |                               |
                 PostgreSQL                    WebSocket clients
                                                     |
                                            React SOC console
```

Splitting ingestion into its own service would buy independent scaling and cost a
deployment story, a queue and cross-service failure modes. At one event every few
seconds, none of that is earned yet; the seam that matters (the `TelemetrySource`
interface and the service layer) is already in place, so the split stays cheap when
volume justifies it.

## Layers

| Layer | Responsibility | Rule |
| --- | --- | --- |
| `api/` | HTTP and WebSocket surface, validation, status codes | No business logic |
| `services/` | Orchestration: ingest, promote, aggregate, authenticate | No SQL |
| `repositories/` | Every query in the system | No HTTP concepts |
| `models/` | SQLAlchemy mappings | No behaviour |
| `telemetry/` | Sources, normalization, the collection loop | Independent of HTTP |
| `detection/` | Pure functions over a normalized event | No I/O |

Detection is pure and I/O free, so rules are unit-testable without a database and
can later be swapped for, or compared against, a model.

## Data model

```
User 1---* Incident *---1 (assignee)
Incident 1---* Event          an incident groups the events that evidence it
Event *---* IOC               indicators are shared and de-duplicated
Incident *---* IOC
Notification ->? Event, ->? Incident
AuditLog ->? User             append-only
```

Design decisions worth defending:

* **Two identifiers per row.** An integer primary key for foreign keys, and a human
  readable `EVT-000042` / `INC-1024` for the UI and URLs. The readable id is
  assigned in the same transaction as the insert via a unique placeholder, so
  concurrent writers cannot collide on a number.
* **JSONB for variable telemetry.** `normalized_data` keeps source-specific fields
  without a table per vendor; `raw_log` keeps the original for forensics. JSONB on
  PostgreSQL, plain JSON on SQLite so the tests need no database server.
* **Denormalized `analyst` name on incidents.** The UI must render an owner even
  when the account is gone; the FK still points at the user when there is one.
* **Audit trail is append-only.** No endpoint updates or deletes an audit row.

## Realtime

One WebSocket at `/api/v1/ws/stream`, authenticated by JWT before the socket is
accepted. The server broadcasts envelopes (`event.created`, `incident.created`,
`notification.created`, ...) and sends a heartbeat when idle. The client reconnects
with exponential backoff and jitter, and a watchdog forces a reconnect when the
heartbeat stops - an open socket is not the same as a working one.

Because HTTP handlers run in a threadpool while the socket lives on the event loop,
broadcasts from request handlers are scheduled onto the loop rather than awaited
inline.

## Frontend

* `services/api/` - one axios instance, typed endpoint modules, and mappers that
  translate API payloads into the shapes the existing components already render.
  Components never call axios directly.
* `services/realtime/` - shared WebSocket client, a hook for connection status, and
  a throttled cache-sync hook that invalidates React Query keys (a busy stream would
  otherwise turn a push channel back into a polling storm).
* Feature hooks (`useEvents`, `useIncidents`, `useAnalytics`, `useNotifications`)
  wrap React Query so pages stay declarative.
* `IncidentContext` survives as a thin cache layer over the API, so components that
  used the old store keep working; nothing persistent lives in React state now.

The Events page merges WebSocket arrivals on top of the fetched page so new
telemetry appears instantly, while the server list stays the source of truth.

## Failure behaviour

| Failure | Behaviour |
| --- | --- |
| Backend down | `ApiError.isNetworkError`; pages show "Backend unreachable" with retry |
| Token expired/revoked | 401 clears the token, the app returns to sign-in |
| WebSocket drops | Banner shows reconnecting; backoff retries; data still loads over HTTP |
| WebSocket rejected (4401) | Marked unauthorized instead of retry-looping |
| A telemetry record cannot be normalized | Dropped, counted, logged; the loop continues |
| A detection rule raises | Caught per rule; the event is still stored |
| Database unavailable at startup | Logged; readiness reports degraded; the API still answers `/health` |

## Threat model (V1 scope)

AEGISX V1 is an internal console for authenticated analysts on a trusted network.
It assumes the telemetry it receives is honest, which is fine for a synthetic source
and **not** fine for a real one: an attacker who can write to an ingestion endpoint
can flood the queue or forge benign-looking events. Before a real collector is
attached, `POST /events` needs per-source authentication and rate limiting.

Known limits carried into V2: the access token sits in `localStorage` (XSS-readable),
the stream token appears in the WebSocket URL, there is no refresh-token rotation,
roles exist but are only enforced on admin endpoints, and detection has no measured
false-positive rate - the single most important number this system currently does
not have.

---

# V2 additions

V2 changed no product behaviour that V1 users depended on. It added
measurement, authorization, observability and reproducibility around the same
architecture.

## Detection and evaluation layers

```
app/detection/          pure functions: rules in, DetectionResult out (no I/O)
app/evaluation/
  labels.py             ground-truth label vocabulary
  datasets/             deterministic labelled dataset generator
  metrics/              confusion matrix, per-class, per-rule, latency
  runners/              engine → metrics → report
  reports/              JSON output (gitignored; reproducible from the seed)
  run_detection_eval.py CLI entrypoint
```

Detection stayed pure on purpose: because it performs no I/O, the same function
the ingestion pipeline calls is the one the evaluation harness calls, so the
measured engine is provably the running engine. A future model plugs in at the
same seam and is measured with the same harness.

Evaluation depends on detection and on the normalizer, and on nothing else -
notably not on the database. That is why the engine is now created lazily
(`app/core/database.get_engine`): importing an application module must not open
a connection or require a driver, or the CLI cannot run without PostgreSQL.

## Rule identity

`detection_rules` (a flat list of ids, cheap to filter) and `detections` (the
full explanation per match) are stored side by side on the event. Ids are
stable, versions are semantic, and V1's `AEGIS-R0xx` ids survive as `legacyId`
so old rows stay interpretable. A `rulesetFingerprint` over ids, versions,
severities and weights lets a report prove which engine it measured.

## Middleware stack

Registration order matters - Starlette runs the last registered middleware
first:

```
CORS                     outermost: preflights answered even for rejected requests
RequestContextMiddleware request id, timing, one structured log line per request
SecurityHeadersMiddleware
RateLimitMiddleware      sliding window, separate bucket for authentication
BodySizeLimitMiddleware  innermost: reject oversized bodies before parsing
```

## Observability

Structured JSON logs (`LOG_FORMAT=json`, `console` for local work) carrying
timestamp, severity, service, environment, logger, message, request id, acting
user, operation, duration and result. Context is held in `contextvars` and bound
by the middleware, so a log line written deep in a service still names the
request and the analyst.

Health is reported per component as `healthy` / `degraded` / `unavailable`.
Degraded is a real state and is used: a telemetry collector that is running but
has not produced a tick within three intervals is degraded, not healthy - an
important distinction for a system whose whole job is to be current.

## Authorization

`app/core/rbac.py` holds one explicit permission matrix for three roles. Routes
depend on `require(Permission.X)`, which checks the caller's role, audits
denials and returns 403. The frontend reads the same matrix from `/auth/me` to
hide controls, but the check that matters happens server-side.

## Frontend reliability

* Error boundaries at three levels: the app root, the routed page (reset on
  navigation) and each Analytics panel. A crash in one chart cannot blank the
  console.
* `SystemStatusBar` merges browser connectivity, API reachability, component
  health and WebSocket state into one line, shown only when something is wrong.
* The Events page merges WebSocket arrivals on top of fetched pages and
  de-duplicates by event id, so a reconnect cannot double-insert rows.
* Component tests (vitest + Testing Library) cover the Events flow, promotion,
  incident rendering, error boundaries and the detection-quality panel with the
  API layer mocked.

## What deliberately did not change

* Still a modular monolith. No queue, no cache, no microservices: nothing in the
  measured behaviour justifies them yet.
* Threat Intelligence remains static demo content and is labelled as such.
* "Derived Insights" remains arithmetic over aggregates and says so on screen.
* No ML. See [DETECTION.md](DETECTION.md) and [EVALUATION.md](EVALUATION.md).


---

## What later versions changed

### V2 — hardening
RBAC on every route, append-only audit logging, structured logs, health
endpoints, rate limiting, and the first detection evaluation
(`docs/EVALUATION.md`).

### V3 — hybrid detection
The pipeline gained a **fast path** and a **slow path**, which the V1 diagram
above does not show:

```
FAST PATH (synchronous, in the collector/request thread)
  telemetry -> normalize -> feature extraction (45 features)
            -> deterministic rules + ML inference + event context
            -> hybrid risk scoring -> persist -> WebSocket
            -> enqueue enrichment

SLOW PATH (one bounded worker thread)
  threat intelligence -> correlation -> rescore + rebroadcast

ANALYST-DRIVEN (never automatic)
  SecuritySequence --(analyst promotes)--> Incident -> AI analyst
```

ML is on the fast path because it is a sub-millisecond in-process call needing
events in arrival order; **network** calls are what get deferred. Correlation
never creates an incident. The AI layer has no tools, no database access and no
authority. See `docs/ml-architecture.md`, `docs/correlation.md`,
`docs/threat-intelligence.md`, `docs/ai-architecture.md`.

### V4 — research and evaluation
A measurement layer *around* the system, conceptually separate from it:

```
dataset -> deterministic adapter -> PRODUCTION normalizer -> normalized event
        -> PRODUCTION feature extractor -> detector -> prediction
        -> ground truth -> metrics -> experiment result
```

Nothing in `app/evaluation` participates in detection, and no HTTP endpoint can
start an experiment. The evaluation layer reuses the production normalizer and
feature extractor deliberately: a metric computed over features the running
system does not produce would measure something that was never deployed.

New modules: `app/evaluation/{datasets,experiments,splits,metrics}`,
`app/models/evaluation.py`, `app/api/v1/evaluation.py`,
`frontend/src/features/research/`. Migration `0004_v4_evaluation`.

See `docs/EVALUATION_METHODOLOGY.md`, `docs/DATASET_CARD.md`,
`docs/MODEL_CARD.md`, `docs/REPRODUCIBILITY.md`, `docs/RESEARCH_REPORT.md`.
