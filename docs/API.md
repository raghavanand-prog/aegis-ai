# API Reference

Base URL: `/api/v1`. Interactive documentation is generated from the code and
served at `/docs` (Swagger UI) and `/redoc`; the OpenAPI schema is at
`/openapi.json`. This file is the map; the generated docs are the detail.

## Conventions

* **Authentication**: `Authorization: Bearer <token>` from `POST /auth/login`.
* **Authorization**: every route requires a permission from the role matrix
  (`GET /auth/permissions`). A missing permission returns **403** and is audited.
* **Identifiers**: the API exposes human-readable ids (`EVT-000042`,
  `INC-1024`). Integer primary keys never leave the backend.
* **JSON casing**: camelCase in both directions.
* **Pagination**: list endpoints return `{items, total, limit, offset}` and
  accept `limit` (max 500) and `offset`.
* **Errors**: `{"detail": "..."}`; validation failures add `errors[]` with field
  names, and every error response carries `requestId` for log correlation.
* **Request id**: send `X-Request-ID` to have it echoed and used in logs;
  otherwise one is generated.

## Endpoints

### auth

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | Exchange credentials for a token (tight rate limit) |
| GET | `/auth/me` | any session | Current user and effective permissions |
| GET | `/auth/permissions` | any session | Full role → permission matrix |
| POST | `/auth/logout` | any session | Record the logout |
| POST | `/auth/logout-all` | any session | Revoke every token issued to this user |
| POST | `/auth/change-password` | any session | Rotate password and sign out all sessions |
| POST | `/auth/users` | `users:manage` | Create an account |

### events

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/events` | `events:read` | Paginated events (`search`, `severity`, `status`, `source`, `sourceType`) |
| GET | `/events/{id}` | `events:read` | One event with its detection explanations (audited) |
| POST | `/events` | `events:ingest` | Ingest from an external collector |
| PATCH | `/events/{id}/status` | `events:update` | Triage status |
| POST | `/events/{id}/promote` | `events:promote` | Create an incident from the event |

Each event carries `detections[]`: rule id, rule version, name, the reason it
fired, severity, risk contribution and MITRE techniques.

### incidents

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/incidents` | `incidents:read` | Paginated incidents |
| GET | `/incidents/{id}` | `incidents:read` | One incident with events, IOCs and timeline |
| POST | `/incidents` | `incidents:create` | Create from one or more events |
| PATCH | `/incidents/{id}` | `incidents:update` | Status, severity, assignment |
| POST | `/incidents/{id}/response` | `incidents:respond` | Record a response action (recorded, never executed) |

### detection

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/detection/rules` | `detection:read` | Versioned rule catalogue and ruleset fingerprint |
| GET | `/detection/quality` | `detection:read` | Latest evaluation report; **404 when none has been run** |
| POST | `/detection/quality/run` | `detection:evaluate` | Run the evaluation now (audited) |

### iocs, notifications, analytics

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/iocs` | `iocs:read` | Indicators (`type`, `search`); searches are audited |
| GET | `/notifications` | `notifications:read` | Notifications (`unreadOnly`) |
| GET | `/notifications/counts` | `notifications:read` | Total and unread counts |
| POST | `/notifications/{id}/read` | `notifications:update` | Mark one read |
| POST | `/notifications/read-all` | `notifications:update` | Mark all read |
| GET | `/analytics/summary` | `analytics:read` | Aggregates for the Analytics page (`windowHours`) |

### telemetry, audit, health

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/telemetry/status` | `telemetry:read` | Collector state, counters, registered sources |
| POST | `/telemetry/tick` | `telemetry:control` | Run one collection cycle |
| GET | `/audit` | `audit:read` | Audit trail (`action`, `targetId`) |
| GET | `/health` | public | Liveness, no internal detail |
| GET | `/health/ready` | public | Aggregate readiness; 503 when unavailable |
| GET | `/health/database` | `telemetry:read` | Database latency and dialect |
| GET | `/health/telemetry` | `telemetry:read` | Collector health, stalled detection |
| GET | `/health/realtime` | `telemetry:read` | Connected WebSocket clients |
| GET | `/health/system` | `telemetry:read` | Every component in one response |

Component health is `healthy`, `degraded` or `unavailable`.

### realtime

`WS /api/v1/ws/stream?token=<jwt>`

The token is validated before the socket is accepted; an invalid one closes with
code **4401** so the client stops retrying. Messages are envelopes:

```json
{ "type": "event.created", "data": { }, "ts": "2026-09-02T03:29:00Z" }
```

Types: `connection.ack`, `event.created`, `event.updated`, `incident.created`,
`incident.updated`, `notification.created`, `heartbeat`, `pong`.

## Example

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@aegisx.dev","password":"AegisX!Demo123"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['accessToken'])")

curl -s -H "Authorization: Bearer $TOKEN" "localhost:8000/api/v1/events?limit=3"
curl -s -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/detection/rules
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  localhost:8000/api/v1/events/EVT-000042/promote
```


---

## Research evaluation (V4)

Read-only. Measured detection quality on labelled corpora, kept separate from
the production detection endpoints.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/evaluation/status` | Whether any results exist; says **why** it is empty when it is |
| GET | `/evaluation/datasets` | Dataset versions results were measured on |
| GET | `/evaluation/datasets/{id}` | Full dataset card: provenance, licence, label schema, limitations |
| GET | `/evaluation/experiments` | Recorded configurations with their latest run |
| GET | `/evaluation/experiments/{id}` | One experiment in full, every run |
| GET | `/evaluation/experiments/{id}/confusion-matrix` | Counts and row-normalized rates |
| GET | `/evaluation/experiments/{id}/threshold-sweep` | The **validation** curve the frozen threshold came from |
| GET | `/evaluation/compare` | Refuses to call experiments comparable across dataset fingerprints |

Permission: `evaluation:read`, held by **viewer** and above — measured quality
is transparency, not privilege.

**There is deliberately no endpoint that runs an experiment.** Running one is
minutes of CPU over a whole corpus; exposing that over HTTP would hand any
authenticated user a resource-exhaustion primitive. Experiments run from the
CLI (`python -m app.evaluation.run_experiments --persist`). A test asserts the
entire router exposes `GET` only.

Every payload carries the provenance of the number it reports — dataset name,
version and fingerprint, split strategy and fingerprint, feature schema version,
ruleset fingerprint, model version and artifact digest — and a `scoreKind` that
keeps an anomaly ranking from being read as a probability.


---

## V5: controlled adaptation — `/api/v1/adaptation`

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| POST | `/adaptation/feedback` | `feedback:submit` | Analyst. Audited |
| POST | `/adaptation/feedback/{id}/correct` | `feedback:submit` | Supersedes; never edits. Audited |
| GET | `/adaptation/feedback` · `/{id}` | `feedback:read` | Viewer and above |
| GET | `/adaptation/datasets` · `/{id}` | `feedback:read` | **GET only** — building a dataset is a CLI act |
| GET | `/adaptation/drift` · `/drift/history` | `drift:read` | Carries an `interpretation` string, rendered verbatim |
| GET | `/adaptation/review-queue` | `feedback:read` | Recommends; cannot label or train |
| POST | `/adaptation/proposals` | `adaptation:propose` | Analyst. Refuses empty evidence and no-op changes |
| GET | `/adaptation/proposals` · `/{id}` | `adaptation:read` | Viewer and above |
| POST | `/adaptation/proposals/{id}/approve` | `adaptation:approve` | **Administrator.** Refuses failed gates and non-human actors |
| POST | `/adaptation/proposals/{id}/reject` | `adaptation:approve` | Administrator. Reason required |
| POST | `/adaptation/proposals/{id}/deploy` | `adaptation:deploy` | Administrator. Validates before mutating |
| POST | `/adaptation/proposals/{id}/rollback` | `adaptation:deploy` | Administrator. Reason required |

**There is no endpoint that trains a model, builds a dataset or runs an
experiment.** Each is minutes of CPU, and over HTTP that is a
resource-exhaustion primitive. All three are CLI operations with a named
operator. Tests assert the absence of such routes.

Six new permissions, on the existing three roles — no new role was introduced:

| Permission | viewer | analyst | admin |
| --- | --- | --- | --- |
| `feedback:read`, `drift:read`, `adaptation:read` | ✅ | ✅ | ✅ |
| `feedback:submit`, `adaptation:propose` | | ✅ | ✅ |
| `adaptation:approve`, `adaptation:deploy` | | | ✅ |
