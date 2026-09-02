# AEGISX V3 → V4 HANDOFF

> Written at the end of the V3 session for a **fresh Claude Code session**.
> Verified against the repository on 2026-09-02, not from conversation memory.
> **Trust the repository over this document.** Where they disagree, the code wins.

---

## 1. Project Status

**Purpose.** AEGISX is a Security Operations Center platform whose defining goal is
*honest, explainable, reproducible detection*. Its distinguishing property is not
feature count — it is that every number can be traced to its source, every empty
panel says why it is empty, and nothing claims capability it does not have.

| Milestone | Status | Notes |
| --- | --- | --- |
| **V1** | IMPLEMENTED + VERIFIED | Full-stack SOC: telemetry → normalize → rules → PostgreSQL → WebSocket → React |
| **V2** | IMPLEMENTED + VERIFIED | Hardening, RBAC, audit, health, structured logs, rate limits, detection evaluation |
| **V3** | IMPLEMENTED + PARTIALLY VERIFIED | Hybrid ML detection, correlation, threat intel, AI analyst |

### Is V3 complete?

**Functionally yes; verification is partial by environment, not by omission.**
Every V3 vertical slice is implemented end-to-end and exercised. Three things
were *not* verifiable on the development machine:

- **NOT VERIFIED** — PostgreSQL (not installed; Docker daemon not running). All
  live runs and the Alembic up/down/up cycle used SQLite, which is a supported
  configuration. CI covers PostgreSQL.
- **NOT VERIFIED** — real VirusTotal API (no key). Client implemented and unit
  tested against a stub.
- **NOT VERIFIED** — real OpenAI/Anthropic APIs (no key). Clients implemented;
  all end-to-end AI runs used the built-in deterministic `mock` provider.

### Unresolved at handoff

1. ~~**The entire backend, docs and CI are UNTRACKED in git.**~~ **RESOLVED
   2026-09-02** — commit `a272545` checkpointed the verified V3 tree (380 files)
   and pushed it to `origin/main`. See §20.
2. **Six V2 docs were not updated for V3** (`ARCHITECTURE`, `DETECTION`, `API`,
   `SECURITY`, `DEVELOPMENT`, `THREAT_MODEL`). They contain no *false* ML claims
   (checked), but they describe a V2-shaped system.
3. **Dead V1 mock subtree still on disk** — `IncidentDrawer.tsx` has no importers
   and is the sole thing referencing 8 hard-coded mock components. See §15.
4. `GET /detection/rules` still returns `usesMachineLearning: false`. Accurate for
   *that endpoint* (the rule engine has no model), but easy to misread now.

---

## 2. Current Architecture

The pipeline as actually implemented. **This differs from the naive linear
diagram** — threat intelligence and correlation are *not* inline.

```
                     ── FAST PATH (synchronous, in the collector/request thread) ──
telemetry source
      │
   normalize                          app/telemetry/normalizer.py
      │
   feature extraction                 app/ml/features/          (45 features, v1.0)
      │
      ├── deterministic rules         app/detection/rules.py    (12 versioned rules)
      ├── ML inference                app/ml/inference/engine.py (Isolation Forest)
      └── event context               off-hours / external source
      │
   hybrid risk scoring                app/scoring/risk.py       → riskSignals[]
      │
   persist (Event + MLInference)      → IOC extraction → notification
      │
   WebSocket broadcast                app/ws/manager.py
      │
   enqueue enrichment ─────────────┐
                                   │
      ── SLOW PATH (one bounded worker thread) ─────────────────────────────────
                                   ▼
                          threat intelligence   app/threatintel/service.py
                                   │
                             correlation        app/correlation/engine.py
                                   │              → SecuritySequence
                                   │
                           rescore + rebroadcast (only if enrichment found something)

      ── ANALYST-DRIVEN (never automatic) ──────────────────────────────────────
   SecuritySequence ──(analyst promotes)──► Incident
                                               │
                                          AI analyst        app/ai/service.py
                                               │  evidence → prompt → grounding
                                               ▼
                                    investigation workspace  (frontend, 8 tabs)
```

### Boundaries that matter

- **ML is on the fast path** — a sub-millisecond in-process call that needs
  events in arrival order for its rolling behavioural context. Network calls are
  what get deferred, not arithmetic.
- **Correlation never creates an incident.** It opens a sequence and notifies
  above a risk threshold. Promotion is an analyst action.
- **The AI layer has no authority.** No tools, no DB access; it cannot change an
  incident's severity, status or risk score. A test asserts this.
- **`app/ml` never imports FastAPI; `app/api` never runs inference.** Route
  handlers call the engine/registry only.

---

## 3. Repository Structure

```
backend/app/
  core/          config, database (RLock — see §15), rbac, security, middleware, logging
  models/        13 SQLAlchemy models (§4)
  repositories/  all query construction; services never build SQL
  schemas/       Pydantic, camelCase wire format; common.py stamps UTC (§15)
  services/      event_service (pipeline hub), incident_service, enrichment_service,
                 analytics_service, notification, audit, auth, serializers
  telemetry/     base, collector, normalizer, sources/synthetic.py (+V3 campaigns)
  detection/     rules.py — 12 versioned deterministic rules (V2, unchanged)
  scoring/       risk.py — hybrid weighted strategy, published via API
  ml/            features/{context,extractor}  models/isolation_forest  registry/
                 inference/engine  training/{corpus,train_anomaly_model}
                 evaluation/{hybrid_runner,run_ml_eval}  schemas.py  artifacts/(gitignored)
  correlation/   patterns.py  mitre.py  engine.py
  threatintel/   base  validation  service  providers/{virustotal,null}
  ai/            sanitize  evidence  prompts  grounding  base  service
                 providers/{mock,hosted}
  evaluation/    labels, datasets/labeled_dataset, metrics/, runners/,
                 reports/, run_detection_eval, watchdog.py  (V2 + V3 watchdog)
  api/v1/        15 routers (§5)
  tests/         20 modules, 301 tests
  alembic/versions/  0001, 0002, 0003

frontend/src/
  features/detection/       signalVocabulary.ts + SignalBadge, RiskBreakdown,
                            MLFindingCard, UnavailablePanel     ← shared V3 primitives
  features/incidents/components/workspace/
                            InvestigationWorkspace.tsx (8 tabs)
                            EvidenceTab, IntelTab, MitreTab, SequenceTab
  features/incidents/components/AIAnalystPanel.tsx
  features/analytics/components/MLAnalyticsPanel.tsx  (+ V2 DetectionQualityPanel)
  features/events/components/EventDetailsDrawer.tsx   (risk breakdown + ML)
  pages/dashboard/SequencesPage.tsx                    (correlation queue)
  services/api/  mlTypes.ts, ml.ts, ai.ts, threatIntel.ts, sequences.ts (+V1/V2)
```

**Config files:** `backend/.env.example` (all V3 vars documented), `.env.example`
(container stack), `backend/pyproject.toml` (ruff + pytest),
`.github/workflows/ci.yml`, `frontend/{package.json,vite.config.ts,vitest.config.ts}`.

---

## 4. Database

### V1/V2 models

| Model | Purpose | Key fields / relationships |
| --- | --- | --- |
| **Event** | One normalized telemetry record | `event_id` (`EVT-000042`), timestamp, source/type, severity, status, `risk_score`, **`risk_level`** (V3), **`risk_signals`** (V3, JSON), entities (hostname/username/source_ip/destination/process/command_line), `raw_log`, `normalized_data`, `mitre_techniques`, `detection_rules`, `detections`, `is_synthetic`. → `incident`, `iocs` (M2M), **`ml_inferences`**, **`sequences`** (M2M) |
| **Incident** | Analyst-facing case | `incident_id` (`INC-1024`), severity, status, analyst/assignee, `risk_score`, **`risk_signals`** (V3), `mitre_techniques`, `timeline`. → `events`, `iocs`, **`sequences`**, **`ai_analyses`** |
| **IOC** | Indicator | unique `(type, value)`, confidence, `sighting_count`, first/last seen. → events, incidents, **`threat_intel`** |
| **User** | Account | email, PBKDF2 hash, role, `token_version` (revocation) |
| **Notification** | Analyst alert | severity, category, `is_read`, optional user/event/incident |
| **AuditLog** | Append-only trail | timestamp, user (denormalized username), action, target, ip, details |

### V3 models

| Model | Purpose | Key fields / relationships |
| --- | --- | --- |
| **MLModel** (`ml_models`) | Model registry — reproducibility | unique `(name, version)`; `model_type`, **`feature_schema_version`**, `dataset_version`, `dataset_fingerprint`, `training_samples`, `parameters`, `metrics`, `feature_names`, `artifact_path`, **`artifact_sha256`**, `status` (active/archived/failed), `created_by`, `trained_at`, `activated_at` |
| **MLInference** (`ml_inferences`) | One model verdict on one event | unique `(event_id, model_name, model_version)`; `anomaly_score` (0..1, CHECK), `is_anomaly`, `threshold` **as of that row**, `features` (full vector), `top_contributors`, `latency_ms`, `inferred_at`. → `event` |
| **ThreatIntelResult** (`threat_intel_results`) | Cached verdict **and** the cache itself | unique `(provider, ioc_type, ioc_value)`; **`status` and `reputation` are separate** (a failure is never a clean verdict), confidence, malicious/suspicious/harmless/undetected counts, `last_analysis_at`, `looked_up_at`, `expires_at`, `error`, `details`. → `ioc` |
| **SecuritySequence** (`security_sequences`) | Correlated group of events | `sequence_id` (`SEQ-000007`), `pattern`, `correlation_key`, severity, status (Open/Promoted/Dismissed), `risk_score`, `confidence` (0..1 CHECK), start/end time, `event_count`, `techniques` (with provenance), `entities`, **`rationale`**, `risk_signals`. → `events` (M2M via `sequence_events`), `incident` |
| **AIAnalysis** (`ai_analyses`) | Stored AI output | `kind`, `provider`, `model`, **`prompt_version`**, `analysis_version`, structured fields (summary, why_it_matters, risk_assessment, likely_behaviour, supporting_evidence, mitre_techniques, investigation_steps, containment_actions, confidence, uncertainty), **`evidence_fingerprint`**, `evidence_summary`, **`grounded`** + `grounding_warnings`, `raw_response` (≤20 KB), `latency_ms`, `tokens_used`, `requested_by`. → `incident` |

**No evaluation-related models exist.** Evaluation reports are JSON files on disk
(`app/evaluation/reports/`), not database rows. *This is a likely V4 gap.*

### Migrations

```
0001_initial        ← None                users, incidents, events, iocs, notifications, audit
0002_v2_hardening   ← 0001_initial        detection explanations, token_version, SOC indexes, CHECKs
0003_v3_hybrid      ← 0002_v2_hardening   5 new tables + events.risk_signals/risk_level
                                          + incidents.risk_signals + 2 entity indexes
```

**Latest revision: `0003_v3_hybrid`.** Upgrade → downgrade → upgrade verified
clean **on SQLite only**.

---

## 5. API

**65 HTTP operations** — re-measured 2026-09-02 from the live OpenAPI schema
(64 under `/api/v1` plus the root `GET /`). Only routes that exist are listed,
but the groups below cover the V2/V3 surface only: `notifications` (4),
`iocs` (1), `telemetry` (2) and `audit` (1) also exist and are not detailed here.

**auth** (7) `POST /auth/login` · `POST /auth/logout` · `POST /auth/logout-all` ·
`GET /auth/me` · `GET /auth/permissions` · `POST /auth/users` · `POST /auth/change-password`

**events** (5) `GET /events` (filters incl. **`isAnomaly`**) · `GET /events/{id}` ·
`POST /events` · `PATCH /events/{id}/status` · `POST /events/{id}/promote`

**incidents** (5) `GET /incidents` · `POST /incidents` · `GET|PATCH /incidents/{id}` ·
`POST /incidents/{id}/response`

**ml** (11) `GET /ml/status` · `/ml/features` · `/ml/scoring` · `/ml/models` ·
`/ml/models/{id}` · `/ml/registry/summary` · `/ml/events/{event_id}` ·
`/ml/incidents/{incident_id}` · `POST /ml/models/{id}/activate` ·
`/ml/models/{id}/deactivate` · `/ml/models/rollback`

**correlation** (5) `GET /sequences` · `/sequences/patterns` · `/sequences/{id}` ·
`POST /sequences/{id}/promote` · `/sequences/{id}/dismiss`

**threat-intel** (4) `GET /threat-intel/status` · `GET /threat-intel` ·
`GET /threat-intel/ioc/{value}` (200 + `notLookedUp` when out of scope) ·
`POST /threat-intel/ioc/{value}/enrich` (400 when out of scope)

**ai** (6) `GET /ai/status` · `GET /ai/incidents/{id}/analyses` ·
`GET /ai/incidents/{id}/evidence` · `POST /ai/incidents/{id}/{analyze|explain|recommend}`

**analytics** (1) `GET /analytics/summary` — V2 aggregates **plus** `ml`,
`correlation`, `threatIntel` sections

**evaluation** (3, under detection) `GET /detection/rules` · `GET /detection/quality`
(404 when never run) · `POST /detection/quality/run`
— **no HTTP endpoint exposes the hybrid ML evaluation; it is CLI-only.** *Likely V4 gap.*

**health** (9) `/health` · `/health/ready` (public) · `/health/database` ·
`/health/telemetry` · `/health/realtime` · **`/health/ml`** · **`/health/ai`** ·
**`/health/enrichment`** · `/health/system`

**realtime** `WS /ws/stream` — `event.created|updated`, `incident.*`,
`notification.created`, **`sequence.created|updated`**, `heartbeat`

---

## 6. ML

| Property | Value |
| --- | --- |
| Model | `isolation_forest` / `sklearn.ensemble.IsolationForest` |
| Registered version | `1.0` (versions immutable; activation archives incumbent) |
| Feature schema version | **`1.0`** |
| Features | **45**, grouped: temporal(5), event-class one-hot(8), auth(4), network(8), process(6), entity/behaviour(11), payload(3) |
| Training dataset | `aegisx-ml-training` v1.0, seed 4242, 6000 samples, 14 simulated days |
| Threshold | **0.65** (`ML_ANOMALY_THRESHOLD`; lives in config, not the model) |
| Contamination | 0.08 |

**Training** (`python -m app.ml.training.train_anomaly_model`) — explicit operator
action, **never on startup**. Corpus built from the *same* synthetic generator and
normalizer that feed production, with deterministic timestamps spread over
simulated days. Unlabelled. 80/20 fit/holdout. Artifact written → SHA-256 taken →
**re-loaded before registration** so a half-trained model cannot become active.

**Inference** — `InferenceEngine.score()` returns an `InferenceResult` or **`None`**.
`None` when: ML disabled · no active model · artifact missing/corrupt · **digest
mismatch** · feature-schema or feature-order mismatch · any scoring exception. The
rolling context is updated regardless, so an outage leaves no hole in history.

**Registry & verification** — `ml_models` table; artifact path components validated
(rejected, not sanitised); resolved path must be inside `ML_MODEL_DIR`; SHA-256
checked on every load.

**Anomaly score semantics — critical.** A **ranking**, 0..1, produced by a
monotonic logistic transform of scikit-learn's raw isolation score around the
trained median. It is **not a probability and not a confidence**. The codebase
keeps three words strictly distinct: *anomaly score* (ranking), *correlation
confidence* (derived from how many independent things line up), *AI confidence*
(the model's own uncalibrated word). A test asserts `InferenceResult.to_dict()`
emits neither "probability" nor "confidence".

**No detection output is a feature.** A test asserts no feature name contains
`rule`, `detection`, `severity`, `risk` or `mitre` — so the ML signal is
independent of the rules it complements.

**Explainability** — Isolation Forest gives no per-prediction attribution. AEGISX
reports *"features furthest from normal"* (σ from training mean, with direction)
and labels it exactly that, never as a cause.

### Evaluated on

- **Synthetic data: YES** (both the training corpus and the labelled evaluation dataset)
- **Public dataset: NO**
- **Real-world data: NO**

No claim of real-world accuracy is made anywhere in the repo.

---

## 7. V3 Evaluation Results

Reproduced 2026-09-02 from a **clean database with documented defaults**
(`train_anomaly_model` no flags → `run_ml_eval --sweep`).
Dataset: `aegisx-detection-eval` v1.0, seed 1337, fingerprint `8f63dec664a823b0`,
**1,950 events (780 malicious / 1,170 benign)**. Ruleset fingerprint `da203c91430a47a1`.

### Rules

| TP | TN | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 720 | 1106 | 64 | 60 | 91.8% | 92.3% | 92.1% | 5.5% | 7.7% |

Latency: mean **0.0039 ms/event**, p95 0.0066 ms, ~258,954 events/s (rule
evaluation only — excludes ingestion, normalization, storage).
Uncovered class: **`LATERAL_MOVEMENT`** (deliberate, no rule targets it).

### ML (threshold 0.65)

| TP | TN | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 579 | NOT AVAILABLE | 380 | 201 | 60.4% | 74.2% | 66.6% | 32.5% | 25.8% |

*(TN not emitted in the comparison table; it is in the JSON report's `overall`.)*
ML latency: NOT AVAILABLE in this run's text output (computed per-configuration in
`hybrid_runner`, present in the JSON report).

### Hybrid (either fires)

| TP | TN | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 780 | NOT AVAILABLE | 380 | 0 | 67.2% | **100.0%** | 80.4% | 32.5% | 0.0% |

### Threshold sweep

| Threshold | ML prec | ML recall | ML FPR | Hybrid F1 | ML-only TPs |
| --- | --- | --- | --- | --- | --- |
| 0.55 | 40.6% | 100% | 97.5% | 57.8% | 60 |
| 0.60 | 47.0% | 86.8% | 65.3% | 67.1% | 60 |
| **0.65** | 60.4% | 74.2% | 32.5% | 80.4% | 60 |
| 0.70 | 69.9% | 50.9% | 14.6% | 89.2% | 54 |
| 0.75 | n/a | 0.0% | 0.0% | 92.1% | **0** |

**Interpretation (do not overstate).** ML contributes exactly the 60
`LATERAL_MOVEMENT` samples the rules cannot see — hybrid recall reaches 100% — at
a false-positive cost the rules alone do not have. **There is no threshold on this
dataset that gives the recall without the noise.**

**Why these ML numbers are a lower bound.** The labelled dataset was built to
exercise *rule thresholds* (4 failures vs a threshold of 5), contains independent
samples with no shared history (so behavioural features are near-constant), and
uses a different entity namespace than the training corpus — it is **out of
distribution for the model**. Every report emits these caveats.

**ML rows are artifact-specific.** Retraining with different `--samples`/`--seed`
moves them by several points; the rules rows and the conclusion do not.

### Threshold-selection methodology

**Not** chosen from the table above. Chosen from a held-out corpus drawn from the
distribution the model actually serves, measured by the training run itself:

| Threshold | Ordinary traffic flagged |
| --- | --- |
| 0.55 | 31.3% |
| 0.60 | 9.3% |
| **0.65** | **1.08%** |
| 0.70 | 0.08% |

0.65 flags ~1 event in 100. The training run's independent recommendation was
**0.652**. This table is printed by every training run.

### Live behaviour (synthetic telemetry, real backend)

460 events scored, 44 flagged (8.7%), **23 matched no rule at all** — dominated by
burst/entity-diversity features on `auth_success`. Still synthetic; not evidence
about real attacks.

---

## 8. Correlation

**Patterns** (`app/correlation/patterns.py`):

| Id | Groups on | Fires when | Infers |
| --- | --- | --- | --- |
| `COR-AUTH-001` | user, else source IP | ≥2 auth failures; much stronger with a following success | T1110 |
| `COR-HOST-001` | host | ≥3 distinct activity stages (auth/execution/privilege/network/malware) | — |
| `COR-LAT-001` | user | one principal → ≥3 distinct hosts/destinations | T1021 |
| `COR-NET-001` | source IP | varied sustained activity (min 4 events) | — |

**Sequence model:** `SecuritySequence` + `sequence_events` M2M. Relational by
choice — no graph database.

**Window:** `CORRELATION_WINDOW_MINUTES` = 30 (default); `CORRELATION_MIN_EVENTS`
= 3; `MAX_WINDOW_EVENTS` = 200 hard cap per query.

**Entities:** hostname, username, source_ip (grouping keys); hosts, users,
sourceIps, destinationIps, processes recorded on the sequence.

**MITRE provenance** (`app/correlation/mitre.py`) — three strengths kept distinct:
`mapped` (a rule declared it) > `inferred` (correlation derived it from sequence
shape) > `contextual` (merely present). Strongest wins on merge.
**The ML model contributes no techniques at all.**

**Risk contribution:** correlation adds up to **30**, scaled by pattern confidence.
Sequence scoring uses the **strongest** member rule contribution, not the sum.

**Limitations:** entity-based and time-bounded only; no cross-entity pivoting; no
attack-graph reconstruction; patterns are hand-written (deliberate).

**Bug fixed in V3:** sequences absorbed *every* event for a matching entity, so a
"credential attack sequence" keyed on a user swallowed unrelated DNS/AV events,
inflating count and score. Now the pattern's own `key_for` filters membership.
Regression test: `test_sequence_membership_is_limited_to_the_pattern_candidates`.

---

## 9. Threat Intelligence

**Provider abstraction** — `ThreatIntelProvider` ABC (`app/threatintel/base.py`).
Registered: `virustotal`, `none` (NullProvider). No VirusTotal-shaped field exists
in models, services or API.

**VirusTotal client** — `/api/v3/{ip_addresses|domains|files|urls}`, key in
`x-apikey` header, redirects refused. Maps 404→`not_found`, 429→`rate_limited`,
401/403→credential error (message never echoes the key), timeout→`timeout`.
Vote-count parsing: ≥3 malicious → `malicious`; ≥1 malicious+suspicious →
`suspicious`; zero engines → **`unknown`, not harmless**.

**Supported IOC types:** `ip`, `domain`, `url`, `hash`.

**Caching** — the DB row *is* the cache. TTL depends on outcome: success/not_found
= `THREAT_INTEL_CACHE_TTL_HOURS` (24h); any failure = **15 min** so an outage
self-heals.

**Budget** — `THREAT_INTEL_DAILY_BUDGET` (400) per-process daily ceiling.

**SSRF protection** — `app/threatintel/validation.py`: strict allowlist grammar per
type; refuses malformed values, private/loopback/link-local/reserved/multicast, and
**documentation ranges (RFC 5737/3849) with their own message**. Consequence worth
knowing: the synthetic generator uses `203.0.113.0/24` and `198.51.100.0/24`, so
**enrichment stays quiet on purely synthetic telemetry** — correct, and documented.

**API-key handling** — server-side only, from env; absent from every payload, log
line and error message. The browser never contacts a provider.

> **IMPLEMENTED CLIENT: yes.**
> **REAL PROVIDER VERIFIED: NO.** No live VirusTotal call has ever been made from
> this repository. Behaviour is covered by 21 unit tests against a stub plus
> response-parsing tests.

---

## 10. AI Analyst

**Provider abstraction** — `AIAnalystProvider` ABC. Registered: `mock`, `openai`,
`anthropic`; `none` disables.

**`mock` is not a stub.** It parses the evidence package out of the prompt and
writes a genuinely grounded analysis — real identifiers, techniques only from
`mitreContext`, `insufficient_evidence` when true, containment refused on
synthetic data. Labelled `isTemplateProvider: true` everywhere; the UI says
"Generated by the built-in deterministic template analyst, not a language model."

**Evidence package** (`app/ai/evidence.py`) — incident, events, ruleFindings,
mlFindings (with `scoreKind: "anomaly_score (ranking, NOT a probability)"`),
threatIntelligence, iocs, correlatedSequences (with `whyTheseEventsWereGrouped`),
mitreContext (with provenance), timeline, risk signals, and **`knownGaps`** —
absence handed to the model explicitly ("reputation is unknown, **not clean**").
Raw logs deliberately excluded. Capped: 25 events / 25 IOCs / 5 sequences /
30 timeline / 20 techniques / 1,500 chars per field. Carries a fingerprint.

**Prompt structure** (`app/ai/prompts.py`, `PROMPT_VERSION` 1.0) — system prompt
declares the evidence block untrusted **before** opening it; evidence fenced
between `<<<AEGISX_EVIDENCE_JSON_BEGIN>>>` / `_END>>>`; strict JSON output schema.

**Sanitization** (`app/ai/sanitize.py`) — NFKC normalise, strip zero-width/bidi,
strip chat role markers and template delimiters, rewrite known injection phrasings
to `[neutralised: …]` (rewritten, not deleted, so the analyst still sees it).
Flagged fields surface as `injectionAttemptsDetected`.

**Grounding verification** (`app/ai/grounding.py`) — every cited technique must
exist in `mitreContext` with matching provenance (prose-only mentions checked
too); every `supportingEvidence` ref must resolve; unsupported threat-intel claims
flagged; `high` confidence on insufficient evidence flagged. **Ungrounded analyses
are stored *with* warnings and shown, never silently dropped or accepted.**

**Persistence** — `ai_analyses`, structured fields + capped raw response +
provenance (provider/model/promptVersion/analysisVersion/evidenceFingerprint).

**Prompt-injection defence is three-layer**: structural (fencing), lexical
(sanitizer), and **capability** — the analyst has no tools, no write access, no
authority. The third is the one that actually matters.

**UI integration** — "AI Analyst" tab in the investigation workspace: three actions
(analyze/explain/recommend), optional question, provenance header, grounding
warnings rendered **above** the text, claims paired with evidence refs, technique
provenance badges, budget remaining, external-data warning.

> **IMPLEMENTED: yes**, all providers.
> **REAL PROVIDER VERIFIED: NO.** Every end-to-end AI run used `mock`. OpenAI and
> Anthropic clients have never been executed against a live API.

---

## 11. Frontend

**Investigation workspace** (`features/incidents/components/workspace/InvestigationWorkspace.tsx`)
— replaced the V1 drawer entirely. Fetches the incident itself (list rows may be
stale summaries). 8 tabs with count badges:

| Tab | Content |
| --- | --- |
| Overview | Risk breakdown, description, counters, ML availability notice |
| Timeline | Real incident timeline entries |
| Evidence | Risk breakdown, evidence-kind legend, ML findings per event, linked events with anomaly badges |
| Threat Intel | Per-indicator verdicts; distinguishes *no verdict* / *not looked up* / *harmless*; enrich button (analyst only) |
| Correlation | Sequences with **"why these events were grouped"**, signals, entities |
| MITRE | Techniques grouped by provenance, with the "ML contributes no techniques" note |
| AI Analyst | Full panel (§10) |
| Raw | Raw incident JSON |

**Event drawer** — `RiskBreakdown` + `DetectionExplanations` + `MLFindingCard`, and
a triage summary that distinguishes *scored-and-normal* from *never-scored*.
Covered by `EventDetailsDrawer.test.tsx`.

**Shared V3 primitives** (`features/detection/`) — `signalVocabulary.ts` defines the
five evidence kinds (Rule Detection / ML Anomaly / External Reputation /
Behavioural Sequence / AI Analyst) with fixed colour, icon and meaning; plus
`SignalBadge`, `RiskBreakdown`, `MLFindingCard`, `UnavailablePanel` (the
"say why it's empty" component).

**Analytics** — V2 panels + `DetectionQualityPanel` (rules) + **`MLAnalyticsPanel`**
(scored/anomalies/rate/ML-assisted, rule-vs-ML overlap, anomalies over time, score
distribution, anomalies by source) — all from stored rows.

**Routes** `/login` · `/dashboard` · `/dashboard/threats` · `/dashboard/incidents` ·
`/dashboard/events` · **`/dashboard/sequences`** · `/dashboard/analytics` ·
`/dashboard/settings`

---

## 12. Security

- **Authentication** — JWT, PBKDF2-HMAC-SHA256, `token_version` claim enables
  instant revocation without a token store.
- **RBAC** — server-enforced on every route. V3 permissions: `ml:read`,
  `ml:manage`, `sequences:read`, `threatintel:read`, `threatintel:enrich`,
  `ai:read`, `ai:request`, `ai:configure`. **Analysts cannot deploy models**
  (`ml:manage` is admin-only); viewers cannot spend budget or reach outward.
  Denials are audited.
- **Audit logging** — append-only; V3 actions: model trained/activated/
  deactivated/rollback, AI requested/generated/failed, threat-intel lookup,
  sequence created/promoted. AI requests record the caller's IP.
- **API keys** — server-side only; never in payloads, logs or error messages.
- **SSRF** — strict indicator validation before any outbound request; redirects
  refused (§9).
- **Prompt injection** — three layers (§10).
- **Model artifact verification** — SHA-256 checked on every load; mismatch refuses
  to load.
- **Path validation** — model name/version validated as single safe path
  components; resolved path confined to `ML_MODEL_DIR`.
- **Rate limiting / budgets** — V2 request rate limiter; V3 per-process daily
  ceilings for threat intel (400) and AI (200); bounded enrichment queue that
  drops rather than grows.
- Untrusted-input posture: event data is never treated as instruction; response
  actions are recorded, never executed.

---

## 13. Environment

```bash
# Backend  (Python 3.11+; repo venv used during V3 was ../.venv)
cd backend
pip install -r requirements.txt
alembic upgrade head
python -m app.ml.training.train_anomaly_model      # optional; rules-only without it
uvicorn app.main:app --reload --port 8000

# Frontend (Node 22+)
cd frontend
npm install && npm run dev                          # http://localhost:5173

# Tests / lint / build
cd backend  && pytest                               # 301 tests
cd backend  && ruff check .
cd frontend && npm run verify                       # lint + typecheck + 33 tests + build

# Evaluation (all now accept --max-seconds; default 900s ceiling)
python -m app.evaluation.run_detection_eval          # rules
python -m app.ml.evaluation.run_ml_eval --sweep      # rules vs ML vs hybrid
```

**Environment variables** (names and purpose only — no secrets here; see
`backend/.env.example`):

| Group | Variables |
| --- | --- |
| App/DB | `ENVIRONMENT`, `DEBUG`, `DATABASE_URL`, `DB_ECHO` |
| Security | `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `CORS_ORIGINS` |
| Telemetry | `TELEMETRY_ENABLED`, `TELEMETRY_INTERVAL_SECONDS`, `TELEMETRY_EVENTS_PER_TICK`, `TELEMETRY_ALLOW_EXTERNAL_SOURCES` |
| **ML** | `ML_ENABLED`, `ML_MODEL_DIR`, `ML_CONTAMINATION`, `ML_RANDOM_STATE`, `ML_ANOMALY_THRESHOLD` |
| **Correlation** | `CORRELATION_ENABLED`, `CORRELATION_WINDOW_MINUTES`, `CORRELATION_MIN_EVENTS`, `CORRELATION_INCIDENT_RISK` |
| **Enrichment** | `ENRICHMENT_ENABLED`, `ENRICHMENT_QUEUE_SIZE` |
| **Threat intel** | `THREAT_INTEL_ENABLED`, `THREAT_INTEL_PROVIDER`, `VIRUSTOTAL_API_KEY`, `THREAT_INTEL_TIMEOUT_SECONDS`, `THREAT_INTEL_CACHE_TTL_HOURS`, `THREAT_INTEL_DAILY_BUDGET` |
| **AI** | `AI_ENABLED`, `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, `AI_BASE_URL`, `AI_TIMEOUT_SECONDS`, `AI_MAX_OUTPUT_TOKENS`, `AI_MAX_EVIDENCE_EVENTS`, `AI_DAILY_REQUEST_BUDGET` |
| Eval/logging | `EVALUATION_REPORTS_DIR`, `LOG_FORMAT`, `LOG_LEVEL`, `LOG_REQUEST_BODIES` |
| Bootstrap | `SEED_DEMO_USER`, `DEMO_USER_EMAIL`, `DEMO_USER_PASSWORD`, `DEMO_USER_NAME` |

Defaults are safe offline: `ML_ENABLED=true`, `AI_PROVIDER=mock`,
`THREAT_INTEL_PROVIDER=none`.

---

## 14. Verification

**Environment used:** macOS, Python 3.11.16, Node 26.5.1, **SQLite** (no
PostgreSQL installed, **Docker daemon not running**), **stub/mock external
providers only**.

### Backend
| Check | Result |
| --- | --- |
| `pytest` | **301 passed** |
| `ruff check .` | clean |
| Type checking | N/A — no mypy/pyright configured in this repo |
| Migrations up→down→up | PASS **(SQLite only)** |

### Frontend
| Check | Result |
| --- | --- |
| `vitest run` | **33 passed** (6 files) |
| `eslint .` | clean |
| `tsc -b --noEmit` | clean |
| `vite build` | PASS (~1.08 MB bundle; chunk-size warning, pre-existing) |

### Integration (live, real backend + real frontend, SQLite)
| Area | Result |
| --- | --- |
| Browser smoke test | PASS — login, dashboard, events, correlation, analytics, workspace |
| Real backend | PASS — uvicorn + vite, real HTTP |
| WebSocket | PASS — `connection.ack` + live `event.created` confirmed directly |
| ML | PASS — model loaded at startup, 460 events scored live, 44 flagged |
| Correlation | PASS — sequences opened live with rationale; enrichment queue 0 drops |
| AI | PASS **with `mock` provider only** — grounded analysis with real citations |
| Threat intelligence | **NOT EXERCISED** — no provider configured; synthetic IPs are out of scope by design |
| Degraded mode | PASS — ML/AI/intel/enrichment all off: ingestion, rules, incidents, analytics keep working; every surface states its reason |

---

## 15. Known Bugs / Limitations

### The five V3 issues — all RESOLVED (verified present in source)

| # | Issue | Status | Fix |
| --- | --- | --- | --- |
| 1 | **Database self-deadlock** — `get_session_factory` held a non-reentrant `Lock` then called `get_engine`, which took it again. Invisible from the API (startup builds the engine first); hung any CLI on the cold path at 0% CPU. | **RESOLVED** | `threading.RLock` in `app/core/database.py`. Regression test `test_session_factory_does_not_self_deadlock` (validated: it *fails* if reverted to `Lock`). |
| 2 | **Naive timestamps** — SQLite drops tz, so the API emitted naive ISO strings the browser read as local time (events shown hours off). | **RESOLVED** | `as_utc()` + wildcard field serializer on `CamelModel`; hand-rolled `to_dict` serializers routed through it. |
| 3 | **Score/breakdown mismatch** — incident showed risk 30 with signals summing to 26 (score from highest member event, signals from the sequence). | **RESOLVED** | `incident_service.recompute_risk()` builds both from one union. Test asserts they agree. |
| 4 | **ML disabled-state had no reason** — `ML_ENABLED=false` gave `available:false, reason:null`, the blank panel the design forbids. | **RESOLVED** | `InferenceEngine.unavailable_reason` derives it. Test covers both never-loaded and disabled. |
| 5 | **Correlation over-grouping** — sequences absorbed unrelated events for the same entity. | **RESOLVED** | Membership filtered through the pattern's own `key_for`. Test covers it. |

### Open issues / limitations

**Repository hygiene — RESOLVED 2026-09-02 (commit `a272545`)**
- ~~The backend, docs, CI, and root config are UNTRACKED in git.~~ All of it is
  now committed and pushed to `origin/main`: 380 files, 43,293 insertions.
  `.env`, local databases, virtualenvs, caches, model artifacts and generated
  evaluation reports remain gitignored and were verified absent from the commit.
- ~~`frontend/src/pages/login/LoginPage.tsx` shows as deleted but uncommitted.~~
  Committed as a **rename** to `features/auth/pages/LoginPage.tsx` (R063).
- ~~Stray empty file `frontend/frontend@0.0.0`.~~ Deleted, along with two other
  0-byte shell-redirect artifacts (`frontend/vite`, a stray root-level
  `src/features/auth/pages/ForgotPasswordPage.tsx`). All three were empty.

**Dead code**
- `features/incidents/components/IncidentDrawer.tsx` has **no importers** and is
  the only thing referencing 8 hard-coded mock components (`AICopilot`,
  `IncidentTimeline`, `MitrePanel`, `EvidencePanel`, `IOCPanel`,
  `InvestigationPanel`, `ResponsePlaybook`, `AnalystNotes`). Superseded by the
  workspace; safe to delete after confirming.
- `features/events/workspace/InvestigationWorkspace.tsx` is an empty V1 file.

**Documentation drift**
- Six V2 docs not updated for V3 (§1). No false ML claims found, but incomplete.
- `GET /detection/rules` returns `usesMachineLearning: false` — true of the rule
  engine, potentially misleading now.

**Measurement**
- ML evaluated **only on synthetic data**. No public dataset, no real traffic.
- The labelled dataset is **out of distribution for the model** (built for rule
  thresholds, independent samples, different entity namespace) — ML metrics there
  are a lower bound and must not be quoted as the model's detection rate.
- ML metrics are **artifact-specific** — they move with `--samples`/`--seed`.
- Hybrid evaluation is **CLI-only**; no API endpoint, no persisted DB records.
- Confusion-matrix TN is absent from the hybrid text report (present in JSON).

**Verification gaps**
- PostgreSQL: NOT VERIFIED locally (CI only). Docker: unavailable.
- VirusTotal: client never executed against the live API.
- OpenAI/Anthropic: clients never executed against a live API.

**Design limitations (intentional)**
- Telemetry is 100% synthetic, marked `isSynthetic: true`.
- Threat intel is silent on synthetic telemetry (documentation ranges refused).
- Response actions recorded, never executed.
- In-process rate limiting and budgets are **per worker** — they multiply across
  uvicorn workers. A shared store (Redis) is the answer at >1 process.
- Enrichment queue drops under sustained overload (reported, not silent).

---

## 16. Important Architectural Decisions (PRESERVE THESE)

1. **Modular monolith.** FastAPI + PostgreSQL + SQLAlchemy + React. **No
   microservices, no Kafka, no graph DB, no distributed model serving** unless the
   repository genuinely demands it. A bounded thread queue was chosen over a
   broker deliberately.
2. **Rules remain first-class detection.** ML did not replace them and must not.
3. **ML is an additional, independent detector.** It must never consume rule
   outputs as features — a test enforces this.
4. **ML alone cannot reach High risk.** `ML_MAX_CONTRIBUTION` (25) is below the
   High band (70) by construction. This is what stops an anomaly detector
   becoming an alert cannon.
5. **A band may raise a rule-assigned severity, never lower it.**
6. **AI is not a detector.** No tools, no write access, no authority; it cannot
   alter severity/status/risk.
7. **Threat intelligence is provider-abstracted.** No vendor-shaped fields leak
   into models/services/API.
8. **Optional subsystem failure must never break ingestion.** ML/AI/threat-intel
   failures degrade to a stated reason; rules, persistence, incidents, analytics
   and the live stream continue.
9. **"Empty" must always carry a reason.** "No anomalies found" and "no model
   running" are different facts and must never render identically.
10. **API keys stay server-side.** The browser talks only to the AEGISX backend.
11. **Three words are never interchangeable**: anomaly score ≠ confidence ≠
    probability.
12. **Model versions are immutable**; artifacts are digest-verified; training is
    an explicit operator action, never on startup.
13. **MITRE provenance is preserved** (mapped / inferred / contextual). The ML
    model contributes no techniques.
14. **Correlation never auto-creates incidents.** Promotion is an analyst action.
15. **No autonomous behaviour.** See §18.
16. **Never fabricate a metric.** If it was not measured, the surface says so.

---

## 17. V4 Starting Point

**Do not implement V4 from this document.** Inspect the repository first — this
section states *intent*, not a plan.

Intended V4 direction is **scientific evaluation**:

- dataset integration (public corpus, e.g. CIC-IDS / UNSW-NB15, through the
  existing normalizer) — this is the single highest-value item, because current
  ML metrics rest on a dataset that is out of distribution for the model
- reproducible experiments; dataset & model version tracking
- rule vs ML vs hybrid comparison (exists as a CLI; **no API, no DB persistence**)
- confusion matrices, precision/recall/F1, FPR/FNR, detection latency
- ablation studies; threshold analysis (a sweep exists — extend it)
- research dashboard
- AI evaluation (grounding rates, citation accuracy — nothing exists yet)
- reproducibility guarantees

**What V3 already provides to build on:** every inference records model version,
feature schema version, threshold in force, and the full feature vector; every
model records dataset version + fingerprint + artifact digest; every AI analysis
records provider, model, prompt version and evidence fingerprint; the hybrid
runner already computes per-configuration confusion matrices and per-class
breakdowns; report JSON is schema-versioned.

**Known gaps a V4 session will likely hit first:** no evaluation DB models; no
HTTP surface for hybrid results; no AI-quality metrics; no ablation harness; ML
evaluation dataset unsuited to the model.

---

## 18. V5 Boundary — NOT V4

Explicitly out of scope for V4:

- automatic / scheduled retraining
- active learning, analyst-feedback-driven model updates
- adaptive or self-tuning thresholds
- autonomous model deployment to production
- self-modifying detection rules
- autonomous response (execution of containment)
- any self-learning production detector

V3 deliberately established a fixed, reproducible baseline **so that these can
later be measured against something**. Building them before the V4 measurement
foundation exists would mean changing the detector and the yardstick at once.

---

## 19. Recommended First Steps For New Claude Session

1. **Read this handoff** — then treat it as a hypothesis, not fact.
2. ~~**Address git first.**~~ Done — the V3 baseline is committed and pushed
   (`a272545`), so V4 work is already diffable against it.
3. **Inspect the repository** — `backend/app/`, `frontend/src/`, `docs/`.
4. **Verify this handoff against source.** Spot-check §4 (models), §5 (routes),
   §6 (ML constants), §7 (rerun the evaluations).
5. **Inspect current tests** — `backend/app/tests/` (20 modules), frontend
   `*.test.tsx` (6 files).
6. **Inspect the evaluation implementation** — `app/evaluation/` (V2) and
   `app/ml/evaluation/` (V3 hybrid runner + CLI).
7. **Identify gaps** against the V4 intent (§17).
8. **Plan V4** before writing code.
9. **Implement incrementally**, preserving §16.
10. **Test** — backend + frontend — and **browser-verify against the real backend**.
    Unit tests did not catch 4 of the 5 V3 bugs; live verification did.

---

## 20. Final State Summary

| Area | Status | Notes |
| --- | --- | --- |
| V1 | COMPLETE / VERIFIED | Full-stack SOC foundation |
| V2 | COMPLETE / VERIFIED | Hardening, RBAC, audit, rule evaluation |
| V3 | COMPLETE / PARTIALLY VERIFIED | All slices implemented; external providers & PostgreSQL unverified locally |
| ML | IMPLEMENTED / VERIFIED (synthetic only) | IsolationForest v1.0, 45 features, threshold 0.65 chosen by measurement |
| Correlation | IMPLEMENTED / VERIFIED | 4 patterns, live sequences with rationale |
| Threat Intel | IMPLEMENTED / **NOT PROVIDER-VERIFIED** | Client + stub tests only; never called live |
| AI Analyst | IMPLEMENTED / VERIFIED with `mock` only | Hosted providers never executed live |
| Evaluation | IMPLEMENTED / VERIFIED | Rules + hybrid CLI; **no API, no DB persistence** |
| PostgreSQL | **NOT VERIFIED LOCALLY** | SQLite used throughout; CI covers PG; Docker unavailable |
| Browser Verification | PASS | Real backend + frontend, full V3 flow + degraded mode |

```
V3 checkpoint commit: a272545  "feat: commit AEGISX V1-V3 backend, frontend, docs and CI"
                       380 files, 43,293 insertions — pushed to origin/main
Current branch:        main  (tracking origin/main, 0 ahead / 0 behind)
Working tree:          CLEAN
Latest migration:      0003_v3_hybrid
Backend test count:    301 passed
Frontend test count:   33 passed
Backend lint:          ruff clean
Frontend checks:       eslint + tsc + vite build clean
```

### Background task status at handoff

The task **"Wait for hybrid evaluation to finish"** (`b48m2spqj`) was a shell
poller: `until grep -q "====" /tmp/hybrid_eval.txt; do sleep 3; done`.

- **Still running:** NO — terminated; output file records `[killed]`.
- **Waiting for:** PID 9024, a `run_ml_eval` run started 14:17.
- **`/tmp/hybrid_eval.txt`:** created 14:17, **0 bytes**, since removed.
- **Evaluation completed?** That run: NO. It **deadlocked** on its first database
  touch (issue #1, §15) — zero CPU, zero bytes. It was killed during diagnosis,
  which made the poller's condition permanently unsatisfiable, with no liveness
  check and no timeout.
- **Hung or failed?** Hung (deadlock), then killed.
- **Safe to terminate?** Yes — already done. No stray processes remain.
- **Resolution:** root cause fixed (`RLock`) + regression test; a portable
  watchdog (`app/evaluation/watchdog.py`) added and wired into all three
  long-running CLIs as `--max-seconds` (default 900, exit 142 with thread stacks
  on expiry, `0` disables); CI steps bounded at 600s. The evaluation was
  subsequently re-run successfully from a clean database — those are the numbers
  in §7.
```
