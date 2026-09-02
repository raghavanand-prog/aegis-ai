# ML architecture

AEGISX V3 is a **hybrid** detection platform. Deterministic rules remain the
backbone; an unsupervised anomaly model is a second, independent signal beside
them. Neither replaces the other, and the platform works with the model
switched off.

```
telemetry ─► normalize ─► feature extraction ─► Isolation Forest ─► anomaly score
                    │                                                     │
                    └──► deterministic rules ──────────────────┐          │
                                                               ▼          ▼
                                                       hybrid risk scoring
                                                               │
                                                    risk_score + riskSignals[]
```

## Why Isolation Forest, and not a classifier

AEGISX has synthetic telemetry and a labelled *evaluation* dataset. It does not
have a large, trustworthy, labelled corpus of real attacks. A supervised
classifier trained on synthetic labels would learn the generator rather than the
threat, and would report a headline accuracy that means nothing outside this
repository.

Isolation Forest needs no labels. It learns what ordinary traffic looks like and
ranks how easily each new event is isolated from it. That is an honest fit for
the data actually available, and it complements the rules rather than
duplicating them: rules catch what we already know to look for, the model
catches what is merely *unusual*.

## Anomaly score, confidence, probability

These three are **not interchangeable**, and AEGISX never uses one word for
another.

| Term | What it is here | What it is not |
| --- | --- | --- |
| **Anomaly score** | A normalized 0..1 ranking of how far an event sits from the learned baseline. | Not a probability of compromise. Not a confidence. |
| **Correlation confidence** | 0..1, derived from how many independent things line up in a sequence. | Not a model output. Not a probability. |
| **AI confidence** | The AI analyst's own stated word (`high`/`medium`/`low`/`insufficient_evidence`). | Not calibrated. Not a measurement. |

scikit-learn's `score_samples` returns an unbounded log-scale isolation score.
`IsolationForestDetector.anomaly_score` maps it through a fixed logistic
transform around the model's own trained median, which is **monotonic** — the
ranking scikit-learn produces is preserved exactly, only the presentation
changes. Isolation Forest offers no calibrated probability, and inventing one
would be a fabricated statistic.

## Feature engineering

`app/ml/features/` holds one implementation used by training, by evaluation and
by live inference. That is the whole point: a feature computed one way when the
model is fitted and another way when it scores production traffic produces a
detector that looks excellent in evaluation and is useless in the SOC.

**45 features, schema version 1.0**, in six groups:

| Group | Examples |
| --- | --- |
| Temporal | hour as a circle (`hour_sin`/`hour_cos`), day of week, off-hours, weekend |
| Event shape | one flag per event class (authentication, process, network, dns, malware, file, privilege, other) |
| Authentication | failure count, is-failure, is-success, the principal's rolling failure ratio |
| Network | destination port, uncommon-port flag, bytes in/out, distinct ports, connection count, internal/external source and destination |
| Process | is-process-event, command length, command entropy, LOLBin flag, shell flag, process rarity |
| Entity & behaviour | host/user/address event counts, first-seen flags, host↔user diversity, address↔destination diversity, events per minute |
| Payload volume | files modified, DNS query count, raw log length |

Four rules the extractor holds to:

1. **No detection output is ever a feature.** Rule matches, rule severity and
   the rule risk score are excluded. Feeding the rules' verdict to the anomaly
   detector would make the two signals correlated by construction, and the
   "hybrid" score would be measuring the rules twice. A test asserts no feature
   name contains `rule`, `detection`, `severity`, `risk` or `mitre`.
2. **Deterministic.** No randomness, no clock reads — anything time-dependent
   comes from the event's own timestamp or from the rolling context.
3. **Bounded.** Every value is log-scaled or clipped, so one absurd field in a
   malformed record cannot dominate the vector.
4. **Explainable.** Feature names are plain English, because they are shown to
   an analyst as the reason an event was flagged.

### The rolling behavioural context

The most useful features are not properties of one event — "is this a rare
process on this host", "how many distinct users has this host seen", "how bursty
is this address" — they are properties of what came before it.
`BehaviorContext` keeps those counters in a bounded, time-windowed, in-memory
structure. It is read *before* the event being scored is folded into it, so a
feature never counts the event it describes.

Note on entropy: it does **not** reliably mark encoded payloads as high entropy.
Base64-encoded PowerShell is UTF-16LE underneath, so it is dense in repeated `A`
characters and scores *lower* than a varied command line. The feature measures
character variety and nothing more; rule `DET-PS-001` is what actually catches
encoded commands. A test locks this behaviour down so nobody "fixes" it towards
an intuition the maths does not support.

## Explaining a single prediction

Isolation Forest exposes no per-prediction feature attribution. AEGISX therefore
reports **"features furthest from normal"** — the features whose values sat
furthest from the training mean, in standard deviations, with direction. That is
an honest description of the input, and the UI labels it exactly that way rather
than calling it a cause.

## Hybrid risk scoring

`app/scoring/risk.py`. Every weight is a named module-level constant with a
comment saying why, and the whole strategy is served at `GET /api/v1/ml/scoring`
so a score can be reproduced by hand.

| Signal | Contribution |
| --- | --- |
| Rule | The rule's own declared risk value (`RULE_WEIGHT` = 1.0) |
| ML | Up to **25**, scaled linearly from anomaly score 0.5 → 1.0 |
| Threat intel | 30 malicious / 15 suspicious / 0 otherwise |
| Correlation | Up to 30, scaled by correlation confidence |
| Context | +3 off-hours, +4 external source |

Bands: Low < 50 ≤ Medium < 70 ≤ High < 85 ≤ Critical.

Two decisions worth stating plainly:

**ML alone cannot reach High.** The ML ceiling (25) is deliberately below the
High threshold (70). An anomaly raises the score and appears in the UI as its
own signal, but it takes corroboration — a rule, a malicious reputation, or a
correlated sequence — to make an event high risk. That is what stops an anomaly
detector becoming an alert cannon.

**The band can raise a rule's severity, never lower it.** A rule saying "this is
a credential dump" has made a categorical statement about what happened, and an
arithmetic band is not entitled to overrule it.

Every contribution is stored on the event as `riskSignals[]`, and the UI renders
the score and the breakdown together. An analyst can always answer *"why is this
high risk?"*.

## Inference in the pipeline

ML scoring runs **synchronously**, on the fast path, before the event is
persisted:

```
normalize → rules → ML inference → risk scoring → persist → IOCs
          → notification → WebSocket → [queue background enrichment]
```

It stays there deliberately: it is a single in-process scikit-learn call
measured in fractions of a millisecond, it needs events in arrival order to keep
the rolling context coherent, and its score is part of the event's risk from the
moment the event exists. Network calls (threat intelligence) and window queries
(correlation) are what get deferred — see [correlation.md](correlation.md).

## Degradation

`InferenceEngine.score()` returns `None`, and the SOC carries on, when:

* ML is disabled by configuration;
* no active model is registered;
* the artifact is missing, unreadable, or its SHA-256 no longer matches the
  registry (a tampered model is a detection engine that lies);
* the artifact's feature schema version or feature ordering differs from the
  running build — scoring a vector the model was never fitted on would produce a
  confident number that means nothing;
* anything unexpected happens during scoring.

In every case the reason is recorded and surfaced by `GET /api/v1/ml/status`,
`GET /api/v1/health/ml`, and the ML panels in the UI. `None` is a first-class
answer, not an error condition. The rolling context is still updated, so an
outage leaves no hole in the history later features depend on.

**"No anomalies found" and "no model is running" are different facts.** Every
surface that can show an empty ML result carries the reason it is empty.

## Measured behaviour

Reproduce with `python -m app.ml.evaluation.run_ml_eval --sweep`. See
[EVALUATION.md](EVALUATION.md) for the full results, the caveats, and why the
threshold is 0.65.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `ML_ENABLED` | `true` | Master switch. Off = rules-only. |
| `ML_MODEL_DIR` | `app/ml/artifacts` | Where artifacts are read and written. |
| `ML_CONTAMINATION` | `0.08` | Expected anomaly proportion during fitting. |
| `ML_RANDOM_STATE` | `1337` | Fit determinism. |
| `ML_ANOMALY_THRESHOLD` | `0.65` | Score at or above which an event is flagged. Chosen from measurement. |
