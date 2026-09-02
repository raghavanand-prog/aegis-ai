# AEGISX Backend (V1)

FastAPI service behind the AEGISX SOC console: telemetry ingestion, normalization,
detection, incident management, audit logging and a realtime WebSocket stream.

```
Telemetry source -> Collector -> Normalizer -> Detection -> PostgreSQL -> WebSocket -> React UI
```

## Requirements

* **Python 3.11+ (3.10 minimum)** - the app refuses to start on 3.9, where
  Pydantic cannot resolve `str | None` annotations. macOS system Python is 3.9.
* PostgreSQL 14+ (the test suite uses SQLite and needs no database server)

## Setup

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then edit it
createdb aegisx               # or use infrastructure/docker-compose.yml
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Interactive API docs: <http://localhost:8000/docs>

On first start, if the `users` table is empty and `SEED_DEMO_USER=true`, a bootstrap
analyst account is created from `DEMO_USER_EMAIL` / `DEMO_USER_PASSWORD`. Change that
password before sharing the instance; seeding is refused outright when
`ENVIRONMENT=production`.

## Layout

```
app/
  main.py            FastAPI app, CORS, lifespan (starts the collector)
  core/              settings, database engine, password hashing + JWT, bootstrap
  models/            SQLAlchemy models: User, Event, Incident, IOC, Notification, AuditLog
  schemas/           Pydantic request/response models (camelCase on the wire)
  repositories/      all query construction
  services/          business logic: ingestion, promotion, analytics, auth, audit
  telemetry/         source abstraction, synthetic generator, normalizer, collector
  detection/         rule engine (severity, risk score, MITRE mapping)
  api/v1/            HTTP + WebSocket routes
  ws/                connection manager and broadcast fan-out
  tests/             pytest suite
alembic/             migrations
```

It is a modular monolith on purpose. Splitting ingestion from the API is a scaling
decision that V1 has not earned yet.

## Telemetry

The built-in `SyntheticTelemetrySource` produces vendor-shaped records for Microsoft
Defender, Sysmon, Entra ID, a firewall, DNS, Linux auditd/sshd and an EDR agent.
Everything it emits is deliberately identifiable as fake: `SYN-` hostnames, RFC 5737
documentation IP ranges (198.51.100.0/24, 203.0.113.0/24) and a `"synthetic": true`
marker on every record. Scenario weights are benign-heavy, so the stream has
realistic base rates rather than a 50/50 attack mix.

Adding a real source means subclassing `TelemetrySource`. Any source that sets
`is_external = True` is **refused** unless `TELEMETRY_ALLOW_EXTERNAL_SOURCES=true`,
so this service cannot start talking to a production system by accident.

Collector controls:

| Variable | Meaning |
| --- | --- |
| `TELEMETRY_ENABLED` | Run the ingestion loop at all |
| `TELEMETRY_INTERVAL_SECONDS` | Seconds between collection ticks |
| `TELEMETRY_EVENTS_PER_TICK` | Records pulled from each source per tick |
| `TELEMETRY_ALLOW_EXTERNAL_SOURCES` | Permit sources that reach outside this process |

## Detection

`app/detection/rules.py` holds twelve deterministic rules. Each has a **stable id
and version** (`DET-PS-001` v1.0), declares the ground-truth labels it targets,
and returns a **human-readable reason** when it fires - which is what makes every
stored detection explainable months later. V1 ids (`AEGIS-R0xx`) survive as
`legacyId`.

Each rule contributes a risk score and MITRE ATT&CK techniques; the highest
matching severity wins and the score is capped at 100. Rules read only fields a
real collector would populate, so they apply unchanged to real telemetry, and the
severity a client submits is advisory - detection decides what gets stored.

No machine learning is involved. See `docs/DETECTION.md`.

## Detection evaluation

```bash
python -m app.evaluation.run_detection_eval
python -m app.evaluation.run_detection_eval --seed 7 --samples-per-class 200
python -m app.evaluation.run_detection_eval --fail-under-f1 0.85 --fail-over-fpr 0.10
```

Runs the rules against a deterministic labelled dataset and reports precision,
recall, F1, false positive / negative rates, per-class and per-rule breakdowns,
and latency. Reports land in `app/evaluation/reports/` (gitignored) and are served
at `GET /api/v1/detection/quality`. Methodology: `docs/EVALUATION.md`.

## Authorization

Three roles - `admin`, `analyst`, `viewer` - and one explicit permission matrix in
`app/core/rbac.py`, enforced by a dependency on every route and served at
`GET /api/v1/auth/permissions`. Denied requests are audited.

## Observability

Structured JSON logs (`LOG_FORMAT=json`, or `console` locally) with request id,
acting user, operation, duration and result. Health endpoints report `healthy`,
`degraded` or `unavailable` per component: `/health`, `/health/ready` (both
public and thin), `/health/database`, `/health/telemetry`, `/health/realtime`,
`/health/system`.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | Exchange credentials for a bearer token |
| GET | `/api/v1/auth/me` | Current user |
| POST | `/api/v1/auth/logout` | Audit the logout |
| POST | `/api/v1/auth/users` | Create a user (admin only) |
| GET | `/api/v1/events` | Paginated events (`search`, `severity`, `status`, `source`, `sourceType`) |
| GET | `/api/v1/events/{id}` | One event (records an audit entry) |
| POST | `/api/v1/events` | Ingest an event from an external collector |
| PATCH | `/api/v1/events/{id}/status` | Update triage status |
| POST | `/api/v1/events/{id}/promote` | Promote to an incident |
| GET/POST | `/api/v1/incidents` | List / create incidents |
| GET/PATCH | `/api/v1/incidents/{id}` | Read / update an incident |
| POST | `/api/v1/incidents/{id}/response` | Record a response action |
| GET | `/api/v1/iocs` | Indicators extracted from telemetry |
| GET | `/api/v1/notifications` | Notifications (`/counts`, `/{id}/read`, `/read-all`) |
| GET | `/api/v1/analytics/summary` | Aggregates for the Analytics page |
| GET | `/api/v1/audit` | Audit trail (admin only) |
| GET | `/api/v1/telemetry/status` | Collector health |
| POST | `/api/v1/telemetry/tick` | Run one collection cycle (admin only) |
| GET | `/api/v1/health`, `/health/ready` | Liveness (public) and readiness |
| WS | `/api/v1/ws/stream?token=...` | Live event/incident/notification stream |

Identifiers on the wire are the human readable ones (`EVT-000042`, `INC-1024`); the
integer primary keys never leave the backend.

## Security notes

* Passwords are stored as PBKDF2-HMAC-SHA256 with a per-user random salt and 390k
  iterations. Argon2id is the intended V2 upgrade.
* Login answers identically for an unknown account and a wrong password, and runs a
  dummy hash on the unknown-account path so response time does not leak existence.
* Every secret comes from the environment. `ENVIRONMENT=production` refuses to start
  with the default JWT secret, a short secret, or demo-user seeding enabled.
* The WebSocket validates its JWT before accepting the connection (browsers cannot
  set headers on a WS handshake, so the token is a query parameter - it is therefore
  visible in server logs; a short-lived stream ticket is the V2 fix).
* `POST /incidents/{id}/response` records an action; it does not execute anything.
  Automated response stays out until there is a reviewed action framework behind it.

## Tests and lint

```bash
pytest          # 125 tests, SQLite, no database server needed
ruff check .    # lint
```

Coverage spans password hashing and login behaviour, RBAC enforcement and audited
denials, session revocation and password rotation, rate limiting, security headers
and safe error shapes, detection rules and their explanations, the evaluation
framework and its metric formulas, telemetry generation and normalization
(including regression tests for bugs the evaluation found), database constraints
and indexes, the event API, the promotion flow, analytics aggregation and the
WebSocket stream.
