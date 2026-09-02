# AEGISX

AI-assisted Security Operations Center platform. Live telemetry is ingested,
normalized, scored by a **hybrid detection stack** — deterministic rules plus an
unsupervised anomaly model — correlated into behavioural sequences, enriched
with external reputation, persisted in PostgreSQL, streamed to the browser over
WebSockets, and explained by an **evidence-grounded AI analyst** for a human to
act on.

```
Telemetry source
      │
Collector ──► Normalizer ──► Feature extraction
      │                            │
      ├──► Detection rules (versioned, explainable)
      ├──► Isolation Forest (anomaly score, versioned, explainable)
      │                            │
      ▼                            ▼
        Hybrid risk scoring  (transparent weights, per-signal breakdown)
      │
PostgreSQL (events, incidents, IOCs, ML inferences, sequences, AI analyses, audit)
      │
      ├──► Background enrichment: threat intelligence ──► correlation ──► rescore
      │
FastAPI REST + WebSocket   ── RBAC on every route, structured logs, health probes
      │
React SOC console (events, incidents, correlation, analytics, AI investigation)
      │
AI analyst ──► evidence package ──► grounding check ──► analyst workspace
```

## What is real, and what is not

This section is the point of the project, so it goes near the top.

**Real**: PostgreSQL persistence; JWT auth with PBKDF2 and token-version
revocation; server-side RBAC (admin/analyst/viewer); 12 versioned rules with
per-match explanations; a **trained Isolation Forest** with a versioned feature
schema, an immutable model registry, artifact digest verification and
reproducible training; hybrid risk scoring where every point is attributed to a
named signal; a correlation engine producing behavioural sequences with stated
rationale; a provider-based threat-intelligence layer with caching, budgets and
SSRF-safe indicator validation; an AI analyst whose output is checked against
the evidence it was given; reproducible measurement of rules vs ML vs both;
live authenticated WebSocket streaming; analytics computed from stored rows;
audit logging; rate limiting and security headers.

**Not real (deliberately)**: telemetry is synthetic and marked
`isSynthetic: true`; external telemetry sources are refused unless explicitly
enabled; response actions are recorded but never executed; the default AI
provider is a deterministic offline template, labelled as such everywhere; no
threat-intelligence provider is configured by default.

**Not claimed**: real-world detection accuracy, real attack detection, or any
measurement on real traffic. Every number in this repository comes from
synthetic data and says so.

## Quick start

Containers:

```bash
cp .env.example .env
docker compose -f infrastructure/docker-compose.yml up --build
```

Local (needs **Python 3.11+**, Node 22+, PostgreSQL):

```bash
# terminal 1
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && createdb aegisx && alembic upgrade head
python -m app.ml.training.train_anomaly_model   # optional; rules-only without it
uvicorn app.main:app --reload --port 8000

# terminal 2
cd frontend
npm install && cp .env.example .env.local
npm run dev
```

Console <http://localhost:5173>, API docs <http://localhost:8000/docs>. Sign in
with the bootstrap account from `backend/.env` (`analyst@aegisx.dev` /
`AegisX!Demo123` by default) and **change that password before sharing the
instance**.

Skipping the training step is a supported configuration: the platform runs
rules-only and every ML surface explains that no model is loaded.

## The flow

1. The collector pulls synthetic telemetry from seven vendor-shaped sources,
   including V3 **campaigns** that emit bursts of related records sharing one
   principal or host.
2. The normalizer maps each record onto one canonical event schema.
3. Twelve versioned rules assign severity, MITRE techniques and the reason each
   fired.
4. The feature extractor builds a 45-feature vector; the anomaly model scores it.
5. Hybrid scoring combines rule, ML and context signals into one risk score
   **with every contribution recorded**.
6. The event is stored, indicators extracted, notification raised, and the event
   broadcast live.
7. On a background worker: threat-intelligence enrichment, then correlation.
   Related events become a `SecuritySequence` with a stated rationale, and the
   event is rescored.
8. An analyst opens the sequence or the incident in the **investigation
   workspace**, reads the evidence by kind, and can ask the AI analyst to
   explain it.
9. The AI answer is checked against the evidence package before storage, and
   shown with its provenance and any grounding warnings.

## Explainability

Every risk score answers *"why?"* without reading the source:

```
RISK SCORE  75/100  High          Weighted sum of 3 signals

  Rule Detection · DET-AUTH-001                                   +45
  23 authentication failures for e.davis from 203.0.113.110 (threshold 5)

  Behavioural Sequence · SEQ-000001                               +26
  This event is part of a correlated sequence of related activity
  (correlation confidence 0.87)

  Event Context · event-context                                    +4
  Source address is outside the internal estate
```

Five kinds of evidence, kept visually and semantically distinct everywhere:
**Rule Detection**, **ML Anomaly**, **External Reputation**, **Behavioural
Sequence**, **AI Analyst**. The weights are published at `GET /api/v1/ml/scoring`.

Three words that are never used interchangeably: an **anomaly score** is a
ranking, a **correlation confidence** is derived from how many things line up,
and an **AI confidence** is the model's own uncritical opinion. None of them is
a probability.

## Measuring detection

```bash
cd backend
python -m app.evaluation.run_detection_eval          # rules (V2)
python -m app.ml.evaluation.run_ml_eval --sweep      # rules vs ML vs both (V3)
```

Rules, dataset v1.0 seed 1337 (1,950 events):

| Precision | Recall | F1 | FPR | FNR | Mean latency |
| --- | --- | --- | --- | --- | --- |
| 91.8% | 92.3% | 92.1% | 5.5% | 7.7% | 0.004 ms/event |

Hybrid, same dataset, threshold 0.65:

| Configuration | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- |
| rules | 91.8% | 92.3% | 92.1% | 5.5% |
| ml | 60.4% | 74.2% | 66.6% | 32.5% |
| hybrid | 67.2% | **100%** | 80.4% | 32.5% |

ML closes the `LATERAL_MOVEMENT` blind spot the rules do not cover — hybrid
recall reaches 100% — at a false-positive cost the rules alone do not have. On
*this* dataset there is no threshold that gives the recall without the noise,
and [docs/EVALUATION.md](docs/EVALUATION.md) explains why: the dataset was built
to exercise rule thresholds, not to contain statistical novelty, and it is out
of distribution for the model.

On the distribution the model *is* trained for, a live run scored 460 events,
flagged 44, and **23 of those matched no rule at all** — burst and
entity-diversity behaviour that the rules cannot see. That is the honest case
for the second detector.

## Tests and checks

```bash
cd backend  && pytest && ruff check .          # 301 tests
cd backend  && python -m app.evaluation.run_detection_eval
cd frontend && npm run verify                  # lint + typecheck + 33 tests + build
```

CI runs all of the above plus an Alembic upgrade/downgrade/upgrade cycle against
PostgreSQL and a build of both container images, with an F1 floor and a
false-positive-rate ceiling on the detection evaluation.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, data model, realtime, failure behaviour |
| [docs/DETECTION.md](docs/DETECTION.md) | Rules, identity and versioning, scoring, explainability |
| [docs/ml-architecture.md](docs/ml-architecture.md) | Features, the model, risk scoring, degradation |
| [docs/ai-architecture.md](docs/ai-architecture.md) | Evidence packages, prompt injection, grounding, providers |
| [docs/correlation.md](docs/correlation.md) | Patterns, sequences, MITRE provenance, the enrichment path |
| [docs/threat-intelligence.md](docs/threat-intelligence.md) | Provider abstraction, SSRF, caching, budgets |
| [docs/model-lifecycle.md](docs/model-lifecycle.md) | Training, registry, activation, rollback, artifacts |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Dataset design, metrics, hybrid results, caveats |
| [docs/SECURITY.md](docs/SECURITY.md) | Authentication, RBAC matrix, hardening |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threats, mitigations, residual risk |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Setup, commands, conventions, troubleshooting |
| [docs/API.md](docs/API.md) | Endpoint map, conventions, examples |

## Roadmap

V3 deliberately stops short of anything self-modifying. There is no automatic
retraining, no adaptive threshold, no autonomous deployment and no autonomous
response — building those before there is a reproducible baseline to measure
against would mean changing the detector and the yardstick at the same time.

V4's highest-value work is a labelled corpus the ML measurement can stand on:
either a purpose-built generator containing genuine behavioural novelty, or a
public dataset (CIC-IDS, UNSW-NB15) adapted through the existing normalizer.
Everything V3 records — model version, feature schema version, dataset version,
inference timestamp, detection source, anomaly score, risk signals, correlation
ids, AI provider and prompt version — exists so that experiment is reproducible.
