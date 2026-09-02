# Model Card — AEGISX Anomaly Detector

> **The anomaly score is a ranking, not a probability.**
> A score of 0.70 does not mean "70% likely malicious". It means the event sits
> further from what the model considers normal than an event scoring 0.60. It is
> not a probability, not a confidence, and not calibrated. Nothing in AEGISX
> treats it as one, and a test asserts that `InferenceResult.to_dict()` emits
> neither the word "probability" nor "confidence".

---

## 1. Model

| Property | Value |
| --- | --- |
| Name | `isolation_forest` |
| Registered version | `1.0` (versions are immutable; activating a new one archives the incumbent) |
| Type | `sklearn.ensemble.IsolationForest` |
| Library | scikit-learn 1.7.2 (pinned — an artifact is only reproducible against the version that wrote it) |
| Feature schema version | `1.0` |
| Features | 45 — temporal (5), event-class one-hot (8), auth (4), network (8), process (6), entity/behaviour (11), payload (3) |
| Contamination | 0.08 |
| Estimators | 200 |
| Production threshold | **0.65** (`ML_ANOMALY_THRESHOLD` — lives in configuration, not in the model) |

## 2. Purpose

An **additional, independent detector** alongside the deterministic rules. It
exists to catch activity no rule describes. It does not replace rules and is
architecturally prevented from dominating them:

- `ML_MAX_CONTRIBUTION` is 25; the High risk band starts at 70. **ML alone
  cannot raise an event to High.** This is what stops an anomaly detector from
  becoming an alert cannon.
- **No detection output is an ML feature.** A test asserts no feature name
  contains `rule`, `detection`, `severity`, `risk` or `mitre`, so the ML signal
  is independent of the rules it complements.
- **The model contributes no MITRE techniques.** Attribution comes from rules
  (`mapped`) or correlation (`inferred`), never from an anomaly score.

## 3. Training data

| Property | Value |
| --- | --- |
| Dataset | `aegisx-ml-training` v1.0 |
| Fingerprint | `f0fbefc8d38a8a53` (V4; see §7) |
| Seed | 4242 |
| Samples | 6,000 generated, 4,800 fitted, 1,200 held out |
| Span | 14 simulated days, anchored to a fixed epoch |
| Labels | **None.** Isolation Forest is unsupervised. |
| Realism | **Synthetic.** Built by the same generator and normalizer that feed production. |

Training is an **explicit operator action** (`python -m
app.ml.training.train_anomaly_model`), never triggered on startup. The artifact
is written, hashed, and **re-loaded before registration**, so a half-written
model cannot become active.

## 4. Threshold selection

0.65 was **not** chosen from evaluation results. It was chosen from a held-out
corpus drawn from the distribution the model actually serves, measured by the
training run itself:

| Threshold | Ordinary traffic flagged (held out) |
| --- | --- |
| 0.55 | 28.92% |
| 0.60 | 9.33% |
| **0.65** | **1.25%** |
| 0.70 | 0.08% |

0.65 flags roughly one event in eighty. The training run's independent
recommendation is **0.654**. This table is printed by every training run.

## 5. Evaluation status

| Corpus | Status |
| --- | --- |
| Synthetic (`aegisx-detection-eval`) | **EVALUATED.** Out of distribution for this model; results are a lower bound. |
| Public real capture (UNSW-NB15) | **EVALUATED** in V4 — both the deployed artifact and a model refitted on that corpus. |
| Real production traffic | **NOT EVALUATED.** No claim of real-world accuracy is made anywhere in AEGISX. |

The V4 result that matters most for interpreting this model: on UNSW-NB15, with
identical features and an identical split, a **supervised** gradient-boosting
model reaches F1 ≈ 0.97 while this **unsupervised** Isolation Forest reaches
F1 ≈ 0.20. The 45-feature schema carries the signal; unsupervised isolation does
not recover it on this telemetry. See `docs/RESEARCH_REPORT.md`.

## 6. Known failure modes

- **Out-of-distribution telemetry.** Scored against a corpus from a different
  telemetry class, the model ranks poorly. Anomaly detection generalises across
  distributions badly, and the V4 numbers quantify how badly rather than hiding it.
- **Degenerate entity features.** Eleven features summarise per-entity
  behaviour. On a corpus with few distinct entities (UNSW-NB15 has 43 source
  addresses) they carry almost no information.
- **Independent samples.** The behavioural features need arrival-ordered history.
  A corpus of unrelated samples flattens them toward constants.
- **No per-prediction attribution.** Isolation Forest has no coefficients.
  AEGISX reports *"features furthest from normal"* (σ from the training mean,
  with direction) and labels it exactly that — never as a cause.
- **Anomalous ≠ malicious.** The model finds unusual things. Unusual and
  malicious overlap, imperfectly.

## 7. Reproducibility, and a documented discrepancy

Every inference records the model version, feature schema version, the threshold
in force at that moment, and the full feature vector. Every model records its
dataset version, dataset fingerprint and artifact SHA-256. The digest is
verified on **every** load; a mismatch refuses to load.

**Discrepancy against the V3 handoff, recorded rather than corrected away.**
V3 documented 1.08% flagged at 0.65 and a recommended threshold of 0.652. A V4
retrain with identical documented parameters produced 1.25% and 0.654.

The cause was found and fixed: the V3 synthetic generator drew source addresses
from the **global** `random` module rather than its seeded instance, took
identifiers from `uuid.uuid4()`, and emitted variable-width timestamps that
leaked wall-clock noise into `raw_log_length_scaled`. `build_corpus()` called
twice with the same seed produced different fingerprints, despite the code
documenting byte-identical output. All three are fixed with regression tests,
and the corpus now fingerprints identically across runs (`f0fbefc8d38a8a53`).

The historical V3 figures are left as written. They are a symptom of the defect,
not a number to be quietly restated.

## 8. Intended use

- Ranking events for analyst attention alongside rule detections.
- Surfacing activity no rule describes.

## 9. Out of scope

- Autonomous blocking, containment or any automated response.
- Any use where the score is read as a probability or a calibrated confidence.
- Deployment against production telemetry without re-evaluation on that
  telemetry — the V4 results show directly that performance does not transfer
  across telemetry classes.

## 10. Artifact verification

| Control | Behaviour |
| --- | --- |
| Digest | SHA-256 checked on every load; mismatch refuses to load |
| Path | Model name and version validated as single safe path components; resolved path confined to `ML_MODEL_DIR` |
| Schema | Feature-schema and feature-order mismatch refuses to score |
| Failure | Any scoring exception returns `None`, and the rolling context is still updated so an outage leaves no hole in history |

Artifacts are gitignored and regenerated by an operator; they are not
distributed with the repository.
