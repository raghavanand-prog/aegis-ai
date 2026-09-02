# AEGISX V4 → V5 HANDOFF

> Written at the end of the V4 session for a **fresh Claude Code session**.
> Verified against the repository on 2026-09-02, not from conversation memory.
> **Trust the repository over this document.** Where they disagree, the code wins.

Every claim below is tagged:

- **[MEASURED]** — a number produced by a committed, reproducible command.
- **[IMPLEMENTATION]** — a fact about the code, verifiable by reading it.
- **[LIMITATION]** — something not established, not measured, or not true.
- **[INFERENCE]** — a judgement or recommendation. Argue with these freely.

---

## 1. Milestone status

| Milestone | Status | Notes |
| --- | --- | --- |
| **V1** | COMPLETE / VERIFIED | Full-stack SOC: telemetry → normalize → rules → PostgreSQL → WebSocket → React |
| **V2** | COMPLETE / VERIFIED | Hardening, RBAC, audit, health, structured logs, rate limits, rule evaluation |
| **V3** | COMPLETE / PARTIALLY VERIFIED | Hybrid ML detection, correlation, threat intel, AI analyst. External providers and PostgreSQL unverified locally. |
| **V4** | COMPLETE / VERIFIED | Scientific evaluation layer: public dataset, reproducible experiments, leakage controls, persistence, API, research dashboard, research report |

### Is V4 complete?

**Yes, with named gaps.** Every item in the V4 definition of done was implemented
and verified except the ones listed in §21, which are environmental (no
PostgreSQL, no paid API keys) rather than omissions.

---

## 2. Checkpoint commits

```
V3 baseline:      a272545  "feat: commit AEGISX V1-V3 backend, frontend, docs and CI"   ← INTACT, never amended
V3 docs follow-up: 24f6fee
V4 checkpoint:    1c031d0  "feat(v4): feature-vector grouping, and the research report"
```

V4 is seven ordinary commits on top of the V3 baseline. **66 files changed,
+10,628 / −70.** Nothing was rebased, amended or force-pushed.

```
b85686b  reproducible synthetic corpus and UNSW-NB15 dataset abstraction
2f32e6d  leakage-safe splits, experiment framework and baseline suite
0b8f47a  persist evaluation results and expose a read-only research API
d8a444d  correlation, AI-analyst, threat-intel and degraded-mode evaluation
fb23e5a  research and evaluation dashboard
4f4c527  dataset card, model card, methodology, reproducibility; refresh V2 docs
1c031d0  feature-vector grouping, and the research report
```

---

## 3. Architecture **[IMPLEMENTATION]**

Unchanged from V3 in every respect that matters. Still a modular monolith:
FastAPI + PostgreSQL + SQLAlchemy + React. **No microservices, no Kafka, no
Redis, no graph DB, no distributed model serving.**

V4 added a measurement layer *around* the system, not inside it:

```
PRODUCTION (unchanged)
  telemetry → normalize → feature extraction → rules + ML → hybrid risk scoring
           → persist → WebSocket → enqueue enrichment
           → [slow path] threat intel → correlation → rescore
           → [analyst-driven] promote → incident → AI analyst

EVALUATION (V4, conceptually separate)
  dataset → deterministic adapter → PRODUCTION normalizer → normalized event
          → PRODUCTION feature extractor → detector → prediction
          → ground truth → metrics → experiment result
```

**The evaluation path reuses the production normalizer and feature extractor
deliberately.** A metric computed over features the running system does not
produce would measure something that was never deployed. There is no second
feature pipeline.

**Nothing in `app/evaluation` participates in detection**, and no HTTP endpoint
can start an experiment.

New dependencies: `pandas==3.0.5`, `pyarrow==25.0.1` — used only by the
evaluation package. Nothing on the ingestion or API path imports them.

### New modules

```
backend/app/evaluation/
  datasets/base.py            DatasetProvenance, LabelSchema, EvaluationSample, EvaluationDataset
  datasets/adapters.py        V3 synthetic corpus → V4 abstraction
  datasets/unsw_nb15/         labels.py, adapter.py, loader.py, fetch.py
  splits.py                   stratified_group + temporal, group-aware, deterministic
  experiments/detectors.py    Detector protocol + 6 detectors, score-kind vocabulary
  experiments/runner.py       protocol enforcement, leakage_audit, experiment identity
  experiments/suite.py        baseline + ablation matrices
  metrics/ranking.py          ROC-AUC, PR-AUC, MCC, balanced accuracy, bootstrap
  correlation_eval.py         campaign-membership ground truth
  system_eval.py              AI grounding, threat intel, degraded mode
  run_experiments.py          CLI
  run_system_eval.py          CLI
backend/app/models/evaluation.py           3 tables
backend/app/repositories/evaluation_repository.py
backend/app/services/evaluation_service.py
backend/app/api/v1/evaluation.py           8 read-only endpoints
backend/alembic/versions/0004_v4_evaluation.py
frontend/src/features/research/            page + 6 components + hooks
frontend/src/services/api/evaluation.ts
```

### One V3 production file was modified

`backend/app/telemetry/sources/synthetic.py`. **[MEASURED]** `build_corpus()`
called twice with the same seed produced *different* fingerprints, despite
`corpus.py:97` documenting byte-identical output. Root cause was threefold:
`_internal_ip`/`_external_ip` drew from the **global** `random` module rather
than the seeded instance; `uuid.uuid4()` supplied hashes and blobs; and
`isoformat()` omitted the microsecond field when it happened to be zero, leaking
wall-clock noise into `raw_log_length_scaled`.

All three are fixed with regression tests
(`test_seeded_source_is_reproducible`, `test_generated_timestamps_have_a_fixed_width`,
`test_training_corpus_is_reproducible`). The corpus now fingerprints identically
across runs: **`f0fbefc8d38a8a53`**.

**Consequence, documented not hidden:** a V4 retrain with identical documented
parameters gives 1.25% flagged at threshold 0.65 and a recommended threshold of
0.654, where V3 recorded 1.08% and 0.652. The historical V3 figures are left as
written — they are a symptom of the defect, not a number to restate.

---

## 4. The V4 research question

> Does the AEGISX hybrid detection architecture provide measurable value over
> its individual detection components, and under what conditions?

**[MEASURED] answer: conditional.** Yes on endpoint/identity telemetry, where
rules carry detection and ML adds classes rules cannot see. **No on
network-flow telemetry**, where rules are structurally silent, the unsupervised
model ranks below chance, and the risk ceiling caps every event at Low.

---

## 5. Datasets **[IMPLEMENTATION] + [MEASURED]**

### UNSW-NB15 (public, real capture)

| Field | Value |
| --- | --- |
| Source | https://huggingface.co/datasets/Mouwiya/UNSW-NB15 |
| Citation | Moustafa, N. & Slay, J. (2015), MilCIS 2015 |
| Licence | Free for academic research with attribution |
| Version | `1.0-full` — 2,280,090 records, **not** the 175k partition |
| **Dataset fingerprint** (200k subsample, salt `aegisx-v4`) | **`f24e4a1e47b7753e`** |
| Realised samples | 200,526 (22,325 malicious, 11.13%) |
| Distinct duplicate groups | 136,075 |
| Committed? | **No.** 230 MB, gitignored under `backend/data/`. |

File digests, verified on every load (mismatch refuses to evaluate):

```
train-00000-of-00002.parquet  2aada2a26d061111f4e8fb84e716f5f11264fee71abe04697d42cb89e488d047
train-00001-of-00002.parquet  7c6699ae967567977dee9e9193543b515255f4e1671ca79bf9ae65e7866ffef1
```

The full capture was chosen over the standard 175k partition because it retains
`srcip`, `dsport`, `proto`, `service` and `Stime`. Without those, AEGISX's 11
entity/behaviour features are constant and a temporal split is impossible.

**[MEASURED] dataset properties found by inspection, not assumed:**

- Label quality is strong: across all 2,280,090 records, **zero** benign rows
  carry a category and **zero** malicious rows lack one.
- **1,053,500 rows (46.2%)** belong to an exact-duplicate group (350,371 groups).
  No group has a conflicting binary label.
- **117 groups (0.09%, 3,055 rows)** of byte-identical *malicious* flows carry up
  to seven different attack families. Real ambiguity in the source taxonomy.
- Strongly non-stationary: 2015-01-22 is 2.11% malicious, 2015-02-18 is 19.33%.
- Only **43 source / 47 destination addresses** across 2.28M flows — a testbed.
- Largest flow in the entire corpus: **13.7 MB**.

Fourteen literal `attack_cat` values are mapped explicitly in
`unsw_nb15/labels.py`. Whitespace and plural variants are folded
(`' Fuzzers '` → `fuzzers`, `Backdoors` → `backdoor`); unknown literals are
**refused, not coerced**. **Nothing is excluded.** Categories are deliberately
**not** mapped onto the AEGISX `Label` enum — the taxonomies describe different
telemetry and merging them would invent semantics.

### aegisx-detection-eval (synthetic, retained)

| Field | Value |
| --- | --- |
| Fingerprint | **`c0f04f3ccb2a63b8`** |
| Size | 1,950 samples (780 malicious / 1,170 benign, 40% positive) |
| Ruleset fingerprint | **`da203c91430a47a1`** |

**[IMPLEMENTATION]** The only corpus that can exercise AEGISX's rules, and
therefore the only one on which rules-vs-ML-vs-hybrid is meaningful.

**[MEASURED] limitation:** only 101 of 1,950 rows (5.2%) share an exact feature
vector and none span categories, so the supervised F1 of 1.000 on it reflects
**template separability, not leakage**. The corpus still cannot distinguish a
good supervised detector from an excellent one.

---

## 6. Experimental methodology **[IMPLEMENTATION]**

```
train split       → fit the detector (labels only where the detector is supervised)
validation split  → sweep thresholds, choose one, FREEZE it
test split        → evaluate ONCE, at the frozen threshold
```

Enforced structurally, not by convention: `select_threshold()` is never passed
the test split. A threshold landing at a grid edge is flagged
`atGridBoundary: true` with a warning that the true optimum may lie outside.

**Splits.** Two strategies, both deterministic and group-aware; neither is a
default "right answer". `stratified_group` measures like-for-like performance;
`temporal` measures distribution shift. Grouping keys on the **binary** label,
because that is the axis detectors are scored on and the only one duplicates
always agree about.

**Features are extracted once, over the whole corpus in chronological order.**
This is faithful, not a shortcut: behavioural features summarise what an entity
did *before* the current event, so replaying in arrival order is exactly what
ingestion does. Extracting per split would hand every test sample an empty
history it would never have in service.

**Leakage.** Eleven controls asserted in `test_evaluation_leakage.py` (17 tests),
plus a **measured** leakage audit in every report: the share of test samples
sharing an exact feature vector with a training sample. A number, not a claim —
"we checked, there is no leakage" is what an inflated result would also say.

**Score vocabulary**, carried into every stored result, API response and UI row:
`rule_hit` (no ordering) · `anomaly_score` (ranking, **not** a probability) ·
`probability` (the only genuine one) · `risk_score` (policy output, not a model
output).

**Metrics refuse to mislead.** An undefined metric is `null`, never 0. ROC-AUC
and PR-AUC return `null` with a reason for unordered scores rather than the 0.5
a naive implementation prints. PR-AUC is published against the positive rate.
Both AUCs are verified against scikit-learn to 1e-9.

---

## 7. Final measured results — UNSW-NB15, source grouping **[MEASURED]**

Split fingerprint `5cfefd1cdc832a81`. Train 120,663 / validation 39,797 /
test 40,066.

| Detector | Score kind | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | FPR | MCC | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | rule hit | — | 0 | 35,194 | 0 | 4,457 | — | 0.0% | — | 0.0% | — | — | — |
| Isolation Forest | anomaly ranking | 0.42 | 4,457 | 498 | 34,696 | 0 | 11.4% | 100.0% | 20.4% | 98.6% | 0.040 | **0.420** | 0.114 |
| Supervised (HGB) | probability | 0.60 | 4,250 | 35,136 | 58 | 207 | 98.7% | 95.4% | **97.0%** | 0.2% | 0.966 | 0.9997 | 0.998 |
| Hybrid (union) | rule hit | 0.65 | 215 | 34,054 | 1,140 | 4,242 | 15.9% | 4.8% | 7.4% | 3.2% | 0.028 | — | — |
| Hybrid (production risk) | risk 0-100 | 5.0 | 215 | 34,054 | 1,140 | 4,242 | 15.9% | 4.8% | 7.4% | 3.2% | 0.028 | 0.508 | 0.113 |

PR-AUC baseline (positive rate) = **0.109**.

**Leakage audit fired: 50.80% validation, 51.02% test.** This is what forced §8.

Seed variance (n=3, percentile bootstrap over test F1):

| Detector | Mean | 95% CI | sd |
| --- | --- | --- | --- |
| Supervised (HGB) | 0.9690 | [0.9682, 0.9698] | 0.0008 |
| Isolation Forest | 0.2014 | [0.1991, 0.2044] | 0.0037 |
| Hybrid | 0.0800 | [0.0740, 0.0861] | 0.0061 |

Latency (detection engine only, laptop + SQLite, **not** a production claim):
rules 0.0026 ms · IF 1.82 ms · supervised 4.36 ms · hybrid 1.84 ms.
Alerts per 1,000 events: rules 0.0 · IF **987.4** · supervised 108.7 · hybrid 34.2.

---

## 8. Strict leakage-free results **[MEASURED]**

`--group-by features` regroups on the AEGISX feature vector itself, so a
memorised vector provably cannot cross into test. 200,526 samples → **78,265
groups**. Split fingerprint `f21e897527b0f499`. Train 123,876 / validation
39,607 / test 37,043 (9.92% positive).

| Detector | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | FPR | MCC | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | — | 0 | 33,370 | 0 | 3,673 | — | 0.0% | — | 0.0% | — | — | — |
| Isolation Forest | 0.41 | 3,673 | 0 | 33,370 | 0 | 9.9% | 100.0% | 18.0% | 100.0% | — | **0.423** | 0.107 |
| Supervised (HGB) | 0.35 | 3,596 | 33,256 | 114 | 77 | 96.9% | 97.9% | **97.4%** | 0.3% | 0.971 | 0.9998 | 0.998 |
| Hybrid (union) | 0.65 | 285 | 31,996 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 4.1% | 0.053 | — | — |
| Hybrid (production risk) | 5.0 | 285 | 31,996 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 4.1% | 0.053 | 0.518 | 0.102 |

**Leakage audit: 0.00% validation, 0.00% test.**

**The decisive finding, and it went against expectation.** Supervised F1 *rose*
from 0.970 to **0.974** under the strictly leakage-free split. The 51% overlap
was **not** doing the work — the model was learning the class boundary, not
memorising rows. §7 is a valid upper bound; §8 is the number to quote.

Feature grouping also surfaced a hard floor, reported on the split plan itself:
**44 groups covering 300 samples (0.15%) carry both labels** — the schema maps
them onto one point. Best-case irreducible error **92 samples (0.046%)**, a floor
on any detector built on these features. The supervised model's 191 errors sit
at roughly twice that floor.

### The four findings that matter

1. **[MEASURED] The rules detect nothing on flow telemetry.** Zero TP, zero FP,
   precision undefined. Ten of twelve rules read endpoint/identity/process fields
   a flow record does not carry; the port-scan rule needs a policy decision a
   passive capture never made; the exfiltration rule needs 500 MB against a
   13.7 MB largest flow. **A scope result, predicted in the dataset card before
   the run — not a quality result.**

2. **[MEASURED] The Isolation Forest ranks below chance.** ROC-AUC 0.423 means
   attacks are ranked as *less* anomalous than benign traffic. It flags 1,000
   alerts per 1,000 events to reach 100% recall. **[INFERENCE]** the unsupervised
   premise fails here because 11 of 45 features need entity diversity (43
   addresses) and rarity (19.3% malicious on day two) — attacks are not rare.

3. **[MEASURED] The feature schema is not the problem.** Same 45 features, same
   split, same protocol: supervised F1 0.974, ROC-AUC 0.9998.

4. **[MEASURED] The safety guardrail becomes a ceiling.** ML contributes ≤25 risk
   points; the High band starts at 70. Verified directly: anomaly 1.00 → +25 risk
   → **Low band**. **With rules silent, AEGISX cannot raise any event above Low
   risk on flow-only telemetry.** The ablation makes it visible: at the Medium
   band (50), the production risk path detects **nothing**. This is a V3 design
   decision working exactly as specified.

### Ablation **[MEASURED]** (strict split)

| Configuration | TP | FP | FN | Precision | Recall | F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | 0 | 0 | 3,673 | — | 0.0% | — | — |
| ML only (0.65) | 285 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 0.053 |
| Rules + ML (0.65) | 285 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 0.053 |
| Rules + ML via risk (band 50) | 0 | 0 | 3,673 | — | 0.0% | — | — |

**Rules contribute exactly zero** — "Rules + ML" is identical to "ML only" to
the last sample.

---

## 9. Results — synthetic corpus **[MEASURED]**

The corpus where the hybrid question is actually answerable.

| Detector | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | — | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 0.852 |
| Isolation Forest | 0.41 | 156 | 0 | 234 | 0 | 40.0% | 100.0% | 57.1% | — |
| Supervised (HGB) | 0.95 | 156 | 234 | 0 | 0 | 100.0% | 100.0% | 100.0% | 1.000 |
| Hybrid (union) | 0.65 | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 0.852 |
| Hybrid (production risk) | 30 | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 0.852 |

Ablation: ML only at 0.65 → 1.9% recall. **[LIMITATION]** This corpus was built
to exercise *rule thresholds* and is out of distribution for a model trained on
the runtime generator; the ML figure is a lower bound, the same caveat V3
published. Leakage audit 3.6% / 4.9%, both under the 5% concern threshold.

---

## 10. Correlation findings **[MEASURED]**

Ground truth is **campaign membership**: 24 injected campaigns + 200 unrelated
events.

| Metric | Value |
| --- | --- |
| Campaigns detected | 15 / 24 (62.5%) |
| Sequences opened | 26 |
| Spurious | 1 (3.9%) |
| Mean sequence purity | 54.3% |
| Mean sequence size | 10.08 |
| Mean confidence | 0.629 |
| Alert reduction | 262 events → 26 sequences (**10.08×**) |
| Latency | mean 1.75 ms, p95 4.19 ms, p99 4.95 ms (DB included) |

| Pattern | Detected | Mean purity |
| --- | --- | --- |
| Credential attack | **8 / 8** | 70.7% |
| Lateral movement | 4 / 8 | 27.8% |
| Host intrusion | 3 / 8 | 48.4% |

**[LIMITATION]** Purity of 54% means a matched sequence holds roughly as many
unrelated events as campaign events. Part of that is the evaluation setup: the
generator draws from a small pool of users and hosts, so background traffic
legitimately shares an entity and an entity-scoped correlator cannot separate
them. Lower bound on purity, upper bound on what entity scoping can achieve on
a namespace this small. **Not comparable to learned attack-graph inference.**

---

## 11. AI analyst evaluation **[MEASURED] + [LIMITATION]**

| Metric | Value |
| --- | --- |
| Provider | `mock` — the built-in deterministic template analyst |
| Cases completed | 5 / 5 |
| Grounded | **5 / 5 (100%)** |
| Unsupported MITRE technique warnings | 0 |
| Unresolved evidence reference warnings | 0 |
| Overconfident analyses | 0 |
| Latency | mean 1.85 ms |

**[IMPLEMENTATION]** Evaluated on **grounding, not prose** — judging writing
quality would need a judge whose own reliability is unestablished. The harness
uses the production grounding verifier.

**[LIMITATION]** This measures the evidence/sanitization/grounding/persistence
pipeline. It measures **no language model's behaviour**. OpenAI and Anthropic
clients are implemented and have **never been executed against a live API**.

---

## 12. Threat-intelligence evaluation **[MEASURED] + [LIMITATION]**

| Metric | Value |
| --- | --- |
| Provider configured | none |
| Enrichment success / cache hit rate / provider latency | **NOT AVAILABLE** |
| SSRF probes refused | **6 / 6** |

Refused: RFC 5737 documentation ranges, RFC 1918 private, loopback, the **cloud
metadata endpoint** (169.254.169.254), and a malformed domain. The
documentation-range refusals are the *measured* reason enrichment stays silent
on synthetic telemetry.

**[LIMITATION]** No live provider call has ever been made from this repository.
Any figure about VirusTotal's accuracy would be fabricated.

---

## 13. Degraded-mode results **[MEASURED]**

| Scenario | Normalized | Rule detections | Ingestion survived |
| --- | --- | --- | --- |
| No model ever loaded | 60 / 60 | 15 | YES |
| Corrupt model artifact | 60 / 60 | 15 | YES |
| Artifact digest mismatch | 60 / 60 | 15 | YES |
| Threat intel unconfigured | 60 / 60 | 15 | YES |
| AI analyst state query | 60 / 60 | 15 | YES |

Corrupt artifacts and digest mismatches are **refused**, not loaded. An unloaded
engine returns `None` with a stated reason, so "no anomalies found" and "no
model running" never render identically.

---

## 14. Reproducibility **[IMPLEMENTATION]**

```bash
cd backend
pip install -r requirements.txt
alembic upgrade head

python -m app.evaluation.datasets.unsw_nb15.fetch     # 230 MB, digest-verified

python -m app.evaluation.run_experiments --dataset unsw-nb15 --split stratified_group --seeds 3 --persist
python -m app.evaluation.run_experiments --dataset unsw-nb15 --split stratified_group --group-by features --persist
python -m app.evaluation.run_experiments --dataset unsw-nb15 --split temporal --persist
python -m app.evaluation.run_experiments --dataset aegisx-synthetic --persist
python -m app.evaluation.run_system_eval
```

Verify these fingerprints before comparing any number:

| Property | Value |
| --- | --- |
| UNSW-NB15 dataset | `f24e4a1e47b7753e` |
| Synthetic dataset | `c0f04f3ccb2a63b8` |
| Ruleset | `da203c91430a47a1` |
| Training corpus | `f0fbefc8d38a8a53` |
| Feature schema | `1.0` (45 features) |

An **experiment id is a hash of the whole configuration** — the same setup
always produces the same id. Every CLI takes `--max-seconds` (default 900, `0`
disables), exiting 142 with thread stacks rather than hanging. Full tolerances
in `docs/REPRODUCIBILITY.md`.

**[MEASURED] runtime cost** on a development laptop (observed elapsed): the
3-seed UNSW baseline+ablation run took **~60 minutes**; the single-seed
feature-grouped run took **~22 minutes**. The dominant cost is per-sample
`predict` calls, which are made one at a time on purpose so that per-event
detection latency is a real measurement rather than a batch average. Budget
accordingly, and use `--max-seconds`.

---

## 15. API surface **[IMPLEMENTATION]**

**73 operations across 70 paths** (was 65 at V3). Eight are new, all under
`/api/v1/evaluation`, all `GET`:

| Path | Purpose |
| --- | --- |
| `/evaluation/status` | Whether results exist; says **why** when empty |
| `/evaluation/datasets` · `/datasets/{id}` | Dataset versions and full cards |
| `/evaluation/experiments` · `/experiments/{id}` | Configurations and full detail |
| `/evaluation/experiments/{id}/confusion-matrix` | Counts + row-normalized |
| `/evaluation/experiments/{id}/threshold-sweep` | The **validation** curve |
| `/evaluation/compare` | Refuses to compare across dataset fingerprints |

Permission `evaluation:read` (28 permissions total), granted to **viewer** and
above — measured quality is transparency, not privilege.

**There is deliberately no endpoint that runs an experiment.**
`test_no_endpoint_can_start_an_experiment` asserts the whole router is GET-only.
Running one is minutes of CPU over a full corpus; over HTTP that is a
resource-exhaustion primitive.

---

## 16. Database **[IMPLEMENTATION]**

Latest revision **`0004_v4_evaluation`**. Verified upgrade → downgrade → upgrade
and full upgrade → base → upgrade, **on SQLite only**.

| Table | Purpose |
| --- | --- |
| `evaluation_datasets` | Unique on (name, version, **fingerprint**) — different hashes are different data and must not be pooled |
| `evaluation_experiments` | Unique on `experiment_id` (a config hash), so re-running appends a run rather than duplicating |
| `evaluation_runs` | One row per execution — repeated seeds are what every variance claim rests on |

Metric columns are **nullable** on purpose: precision with no predictions is
undefined, and a 0 would record a measurement never made. Sweeps, per-class
breakdowns and normalized matrices stay in JSON columns — read whole, never
filtered on. **The JSON report on disk remains the archival artifact; these rows
are the index over it.**

---

## 17. Frontend **[IMPLEMENTATION]**

New route `/dashboard/research` + sidebar entry "Research". Components:
`DetectorComparison`, `ConfusionMatrixPanel`, `PerClassPanel`,
`ThresholdAnalysis`, `ReproducibilityPanel`, `DatasetCardPanel`, plus
`metricFormat.ts`.

Design rules enforced by tests:

- An undefined metric renders `n/a`, **never 0%**.
- ROC/PR-AUC columns show `—` with a tooltip for unordered scores.
- Every row shows its score kind; the threshold panel repeats the caution that
  an anomaly score is a ranking, not a probability.
- The threshold curve is labelled as the **validation** curve, marking the
  chosen threshold "chosen on validation".
- Confusion matrices show counts, row-normalized rates and each row's support,
  and state which normalization is in use.
- Per-class bars under 20 samples are greyed and marked indicative only.
- The leakage audit sits next to the provenance, not hidden.
- Empty states carry the command that would populate them.

**[MEASURED]** Browser-verified live against a real backend: research dashboard
renders persisted results, and the V3 pages (events with live telemetry,
correlation) remain intact.

---

## 18. Verification at checkpoint **[MEASURED]**

| Check | Result |
| --- | --- |
| `pytest` | **374 passed** (was 301 at V3; 25 test modules) |
| `ruff check .` | clean |
| `vitest run` | **40 passed** (was 33; 7 files) |
| `eslint .` | clean |
| `tsc -b --noEmit` | clean |
| `vite build` | PASS (~1.11 MB bundle; chunk-size warning pre-existing) |
| Migrations up→down→up | PASS (SQLite) |
| Migrations up→base→up | PASS (SQLite) |
| Browser smoke test | PASS (real backend + frontend) |

New V4 test modules: `test_evaluation_leakage.py` (17),
`test_evaluation_metrics.py` (17), `test_evaluation_experiments.py` (10),
`test_evaluation_api.py` (14), `test_evaluation_subsystems.py` (12),
`ResearchPage.test.tsx` (7).

---

## 19. Known limitations **[LIMITATION]**

1. **No production traffic.** A 2015 testbed capture and a synthetic generator.
   No claim of real-world detection accuracy is made anywhere.
2. **The rules were never exercised on UNSW-NB15.** Their zero is a telemetry
   mismatch. Rule quality figures come from a synthetic corpus built to exercise
   them — a favourable setting.
3. **The supervised model is a reference, not a product.** It consumes training
   labels, which production detectors do not. It bounds what the feature schema
   supports; it is not deployable as-is.
4. **51% source-grouped feature-vector overlap** on UNSW. §8 re-ran everything at
   0.00% and conclusions held, but the overlap is a real property of applying
   this schema to flow data and matters for any other model tried on it.
5. **The synthetic corpus is too easy** for a supervised result to be informative.
6. **Correlation purity is bounded by the evaluation setup**, not only the
   correlator.
7. **AI results are mock-provider results.** Hosted providers never executed.
8. **Threat intelligence is unmeasured.** No provider, by design.
9. **Latency is laptop-and-SQLite.** Not a production throughput claim.
10. **Per-class rates for rare families are unreliable** (`worms` has 9 training
    samples); 117 duplicate groups carry ambiguous attack categories.
11. **Temporal split implemented and tested, but not published as a result.** The
    strategy, its warnings and its rationale exist in code and are unit-tested; a
    full temporal UNSW run was **not** completed in the V4 session. It is a
    one-command gap — see §14.
12. **`--include-registered` implemented but not exercised** in published runs.
    Reported IF numbers are the *fitted* model, not the deployed artifact.
13. In-process rate limits and budgets are **per worker** and multiply across
    uvicorn processes.

---

## 20. Remaining verification gaps **[LIMITATION]**

- **PostgreSQL: NOT VERIFIED LOCALLY.** SQLite throughout; CI covers PG. Docker
  unavailable on the development machine.
- **VirusTotal: never called live.**
- **OpenAI/Anthropic: never called live.**
- **Temporal-split UNSW results: not produced** (§19.11).
- **Registered-artifact evaluation: not produced** (§19.12).
- No mypy/pyright is configured in this repository.

---

## 21. V5 starting recommendations **[INFERENCE]**

These are judgements from the V4 evidence, not measurements. Argue with them.

1. **Close the two one-command gaps first** — the temporal UNSW run and
   `--include-registered`. Both are cheap and both are already implemented.
2. **The flow-telemetry result demands a decision, not a tuning pass.** Either
   extend the adapter so flow telemetry populates the aggregate fields the rules
   read (`distinct_ports`, `deny_count`, windowed byte volumes), or accept that
   flow data needs its own detector. The supervised result establishes the
   feature schema is adequate either way. **Do not** respond by lowering the
   anomaly threshold; §7 shows that path leads to 987 alerts per 1,000 events.
3. **Revisit the risk ceiling deliberately, or document it as intended.** ML ≤25
   against a High band of 70 means an ML-only environment can never escalate.
   That is correct for a rules-first SOC and wrong for a sensor class rules
   cannot see. It is a policy decision, and V4 turned it into a measured one.
4. **A supervised detector is now defensible** on the V4 evidence — F1 0.974
   leakage-free, with an interpretable tabular model and no new dependency. If
   V5 pursues it, it needs its own model card, registry entry, digest
   verification and threshold protocol, exactly as the Isolation Forest has.
5. **Correlation's lateral-movement pattern (4/8, 27.8% purity) is the weakest
   measured component.** It now has a harness to improve against.
6. **Get PostgreSQL and one live AI provider verified.** Three V3 claims and two
   V4 ones rest on unexercised code paths.

---

## 22. V5 boundary — explicitly NOT implemented in V4

None of the following exists in the repository. V4 is measurement only.

- automatic or scheduled retraining
- active learning
- analyst-feedback-driven model updates
- adaptive or self-tuning thresholds
- self-modifying detection rules
- autonomous model deployment
- autonomous response or containment
- any self-learning production detector

V4 deliberately built the yardstick first. Building these before it existed
would have meant changing the detector and the measure at once — which is how a
project stops being able to tell whether it is improving.

---

## 23. Preserve these architectural decisions

Unchanged from V3 §16, all still enforced and now several of them *measured*:

1. Modular monolith. 2. Rules remain first-class. 3. ML is independent of rule
outputs (asserted by test). 4. ML alone cannot reach High (measured: max +25 vs
band 70). 5. A band may raise severity, never lower it. 6. AI is not a detector
— no tools, no write access, no authority. 7. Threat intel is
provider-abstracted. 8. Optional subsystem failure never breaks ingestion
(measured, five scenarios). 9. "Empty" always carries a reason. 10. API keys stay
server-side. 11. anomaly score ≠ confidence ≠ probability. 12. Model versions are
immutable and digest-verified. 13. MITRE provenance preserved; ML contributes no
techniques. 14. Correlation never auto-creates incidents. 15. No autonomous
behaviour. 16. **Never fabricate a metric** — if it was not measured, the surface
says `NOT AVAILABLE` and why.

V4 adds three of its own:

17. **The test split is read once, after the threshold is frozen.**
18. **Residual leakage is measured and published, not asserted away.**
19. **A result without its dataset fingerprint, split, feature schema and
    threshold is not a result.**

---

## 24. Recommended first steps for a new session

1. Read this handoff — then treat it as a hypothesis, not fact.
2. Read `docs/RESEARCH_REPORT.md` for the full measured results, and
   `docs/DATASET_CARD.md` §1 "What this dataset cannot evaluate" **before**
   quoting any number.
3. Inspect the repository: `backend/app/evaluation/`, `backend/app/models/evaluation.py`,
   `frontend/src/features/research/`.
4. Spot-check this document against source: §15 (routes), §16 (migration), §5
   (fingerprints — all four are one command each).
5. Fetch the corpus and reproduce one experiment before changing anything.
6. Plan V5 against §21, respecting §22.
