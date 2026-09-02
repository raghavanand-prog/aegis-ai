# Development Setup

Two supported paths: containers (least setup) or local processes (fastest
iteration). Both end with events streaming into the console.

## Requirements

| | Version | Notes |
| --- | --- | --- |
| Python | **3.11+** (3.10 minimum) | 3.9 **will not work** - Pydantic cannot resolve `str \| None` annotations there. macOS system Python is 3.9; install a newer one |
| Node.js | 22+ | |
| PostgreSQL | 14+ | Not needed for the test suite (SQLite) or the detection evaluation |
| Docker | any recent | Only for the container path |

## Path A - containers

```bash
cp .env.example .env          # edit if you want different ports or credentials
docker compose -f infrastructure/docker-compose.yml up --build
```

* Console: <http://localhost:5173>
* API docs: <http://localhost:8000/docs>

Migrations run automatically when the backend container starts.

## Path B - local processes

**Backend**

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env           # then edit DATABASE_URL and JWT_SECRET_KEY
createdb aegisx
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

**Frontend** (second terminal)

```bash
cd frontend
npm install
cp .env.example .env.local     # VITE_API_URL=http://localhost:8000/api/v1
npm run dev
```

Sign in with the bootstrap account from `backend/.env`
(`analyst@aegisx.dev` / `AegisX!Demo123` by default). Events appear on the
Events page within a few seconds. **Change that password before sharing the
instance**, and note that seeding is refused outright when
`ENVIRONMENT=production`.

## Everyday commands

```bash
# Backend
cd backend
pytest                                        # full suite (SQLite, no server needed)
pytest app/tests/test_evaluation.py -v        # one module
ruff check .                                  # lint
ruff check . --fix                            # autofix
alembic upgrade head                          # apply migrations
alembic downgrade -1                          # roll one back
alembic revision -m "describe change"         # new migration
python -m app.evaluation.run_detection_eval   # measure the detection engine

# Frontend
cd frontend
npm run dev            # dev server
npm run test           # component tests (vitest)
npm run test:watch     # watch mode
npm run test:coverage  # coverage report
npm run lint           # eslint
npm run typecheck      # tsc -b --noEmit
npm run build          # production build
npm run verify         # lint + typecheck + test + build, the same order CI uses
```

## Layout

```
backend/
  app/
    api/v1/          HTTP routes and the WebSocket endpoint
    core/            config, database, security, RBAC, middleware, logging
    detection/       deterministic rules (versioned, explainable)
    evaluation/      labelled dataset, metrics, runner, CLI, reports
    models/          SQLAlchemy models, indexes and constraints
    repositories/    all query construction
    schemas/         Pydantic request/response models
    services/        business logic
    telemetry/       source abstraction, synthetic generator, normalizer, collector
    tests/           pytest suite
  alembic/           migrations
frontend/
  src/
    services/api/    typed API client and mappers
    services/realtime/  WebSocket client and cache sync
    features/        auth, events, incidents, analytics, notifications, dashboard, threats
    components/      shared UI, error boundaries, state components
    test/            vitest setup and render helpers
docs/                architecture, detection, evaluation, security, threat model, API
infrastructure/      docker-compose stack
```

## Conventions

* **Repositories own queries.** Services orchestrate; routes validate. A service
  containing SQL or a route containing business logic is a review comment.
* **Detection is pure.** `app/detection` performs no I/O, so rules are testable
  without a database and comparable against a future model.
* **The API is camelCase, Python is snake_case.** Pydantic aliases translate at
  the boundary; no manual mapping in components.
* **Components never call axios.** Everything goes through `services/api`.
* **New behaviour needs a test.** Bugs found during development get a regression
  test named after the bug (see `test_normalizer_regression.py`).

## Troubleshooting

**`pydantic` errors about `str | None` on startup** - the virtualenv is Python
3.9. Recreate it with 3.11+. The application refuses to start on 3.9 with an
explicit message rather than failing deep inside model construction.

**`Database schema is missing`** - run `alembic upgrade head`.

**429 responses while testing by hand** - the login endpoint allows 10 requests
per minute per client. Wait, or set `AUTH_RATE_LIMIT_REQUESTS` higher in
`backend/.env` for local work.

**Detection Engine Evaluation panel says nothing has been measured** - that is
correct until you run `python -m app.evaluation.run_detection_eval`. The panel
never invents numbers.

**Frontend cannot reach the API** - check `VITE_API_URL` in `frontend/.env.local`
and that the origin appears in `CORS_ORIGINS` in `backend/.env`.


---

## Research evaluation (V4)

```bash
cd backend

# One-off: fetch the public corpus (230 MB, third-party licensed, gitignored)
python -m app.evaluation.datasets.unsw_nb15.fetch

# Rules vs ML vs hybrid, plus the ablation matrix
python -m app.evaluation.run_experiments --dataset unsw-nb15 --persist
python -m app.evaluation.run_experiments --dataset aegisx-synthetic --persist

# Correlation, AI analyst, threat intelligence, degraded mode
python -m app.evaluation.run_system_eval
```

`--persist` indexes results so the research API and `/dashboard/research` can
read them; the JSON report under `app/evaluation/reports/` remains the archival
artifact either way.

Every evaluation CLI accepts `--max-seconds` (default 900, `0` disables) and
exits 142 with thread stacks on expiry rather than hanging.

Full reproduction instructions, including expected fingerprints and the
numerical tolerance to expect, are in `docs/REPRODUCIBILITY.md`.
