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


---

## V5: adaptive lifecycle

V5 adds controlled adaptation around this model. The model itself is unchanged —
still an unsupervised Isolation Forest over the 45-feature production schema.

### Lifecycle states

`candidate` → `evaluating` → `approved` → `active` → `archived` | `rolled_back`,
plus `rejected` and `failed`. Only `active`, `approved` and `archived` may serve;
`archived` is included because it is the rollback target. A candidate cannot be
activated without an approved proposal — enforced in `registry.activate_model`.

### How feedback reaches this model **[IMPLEMENTATION]**

Analyst labels cannot train an unsupervised model. Two mechanisms use them
without changing what the detector is:

- **Threshold adaptation (Arm 1).** Labels choose an operating point on the
  existing score distribution, clamped to `MAX_THRESHOLD_STEP = 0.05`.
- **Feedback augmentation (Arm 2, redesigned in V6).** Analyst-verified
  **benign** observed events are added to the training corpus, teaching the
  density model that this traffic is normal.

Neither makes this model supervised. Where a supervised model appears in
evaluation it is a reference or a diagnostic ceiling, and is not deployable.

> **Correction (V6 §5.5).** Arm 2 was previously described here as
> *training-corpus curation* — removing analyst-identified malicious rows from
> the fit set. **That could not run in production.** Curation purifies the fit
> set, and production's fit set is the unlabelled runtime telemetry corpus, not
> observed events, so analyst labels had nothing there to purify. Worse,
> `train_candidate` recorded `feedback_dataset_id` as metadata and never used
> it, so feedback had never influenced production training at all. V6 §6
> inverted the mechanism to the one described above and wired it in (§10).

**Bounds on what feedback may contribute** (V6 §§9, 11):

- Admission is positive-listed: only training-eligible, benign-projecting
  labels. `confirmed_malicious`, `true_positive`, `suspicious` and `uncertain`
  are refused.
- A per-group cap (`baseline_relative`, tolerance **1.5**) bounds how far any
  one `event_type` may exceed its own history. A global volume cap alone does
  not stop a targeted attack — measured.
- `feedback/baseline_monitor.py` flags a group whose submissions dwarf its
  history, and is **advisory**: it blocks nothing.

### Measured effect **[MEASURED]**

> **Read V6 §4 and §5 before quoting the V5 table below.** The static baseline
> it compares against was produced by re-fitting this detector on a corpus whose
> fit split is **40% malicious**, and which its own provenance calls out of
> distribution for this model. Production does not fit that corpus. The
> comparator was wrong by roughly 17×.

**The baseline as production actually configures it** (V6 §5, 10 seeds, same
corpus and split, same frozen 0.65 threshold, fitted on 6,000 unlabelled
telemetry rows):

| | Precision | Recall | F1 | FPR | ROC-AUC |
| --- | --- | --- | --- | --- | --- |
| Production configuration | 0.590 | 0.731 | **0.6526** | 0.340 | 0.7615 |
| + redesigned Arm 2 | 0.634 | 0.679 | 0.6554 | **0.2624** | 0.7862 |

Arm 2's effect is a **23% relative reduction in false positives** (d −1.81),
trading recall for precision. Reporting it as an F1 result would misdescribe it.

**The V5 experimental comparison, retained as measured** (fingerprint
`c0f04f3ccb2a63b8`, split `d349ea18a04e06c0`, 5% simulated label noise) — now at
50 seeds (V6 §1) rather than 3:

| | Precision | Recall | F1 | CI95 |
| --- | --- | --- | --- | --- |
| Static (misconfigured baseline) | 0.996 | 0.020 | 0.0389 | [0.0365, 0.0411] |
| Both arms | 0.862 | 0.152 | 0.2570 | [0.2406, 0.2726] |
| *Random-label control* | 0.691 | 0.058 | 0.1068 | [0.0997, 0.1145] |

The effect over the control is real and now settled: **Cohen's d 3.43**,
non-overlapping intervals, mechanism 31% / feedback content 69%. What V6 changed
is not whether the effect exists but what it was measured against — fitting at
production-like contamination reaches F1 0.2653 with **no adaptation at all**.

### Known limitations added in V5 **[LIMITATION]**

- ~~Adaptation does **not** improve detection of behaviour the model has never
  seen (recall 0.000 → 0.0085 on withheld categories, 1 of 9 runs).~~
  **Corrected in V6 §2.4.** Measured across all thirteen attack categories
  rather than three, adaptation helps on **4 of 13** — PORT_SCAN recall
  0.2575 → 0.9500, SUSPICIOUS_DNS 0.0744 → 0.5685, BRUTE_FORCE 0.0292 → 0.4236 —
  and cannot help on the other nine, whose events the detector scores inside or
  below the benign mass. V5's three categories were never recorded, so its
  0.0085 figure is **not reproducible**. The nine-category failure is a
  representation limit, not a feedback limit (V6 §3).
- All feedback in the published results is **simulated**.
- The artifact shipped as the V4 deployed model (`053d1ff3…`) is not
  reproducible from current code; it predates the determinism fix.
- Artifact immutability is now enforced **on disk** as well as in the database
  (V5 registry fix). Before that, a rebuilt database allowed training to
  overwrite a deployed model.
