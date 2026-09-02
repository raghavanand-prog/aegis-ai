# Detection Evaluation

The most important thing V2 adds is the ability to answer *"how good is the
detection engine, actually?"* with a number that can be reproduced.

Everything here measures the **deterministic rule engine**. These are not model
metrics; there is no model.

## Why a labelled dataset

Accuracy cannot be computed from live telemetry, because nothing in a live
stream says which events were genuinely malicious. Evaluating a detector
against its own output is circular and always flatters it. So AEGISX ships a
separate dataset where every sample carries a ground-truth label assigned at
generation time, independent of anything the engine does.

The dataset lives in `backend/app/evaluation/datasets/labeled_dataset.py` and is
kept deliberately separate from the runtime synthetic telemetry generator
(`app/telemetry/sources/synthetic.py`). Runtime telemetry is unlabelled and must
never be used to compute accuracy.

## How the dataset is generated

* **Deterministic.** A seed (default `1337`) drives all randomness, so the same
  seed always produces the same events. Two runs are therefore comparable, and a
  metric change means the engine changed, not the data.
* **Vendor-shaped, then normalized.** Samples are produced as raw records in the
  shape of the source product and pushed through the real normalizer, so
  evaluation exercises normalization + detection - the actual path an event
  takes.
* **Benign-heavy.** Benign samples outnumber malicious ones roughly 1.5 : 1. A
  50/50 mix produces flattering precision that collapses on a real stream.
* **Adversarial benign cases.** The benign set deliberately includes:
  * four failed logins (brute-force threshold is five)
  * nineteen scanned ports (reconnaissance threshold is twenty)
  * a backup job writing 150 files (ransomware threshold is 200 + encryption)
  * ordinary, non-encoded PowerShell
  * an administrator legitimately running `certutil`
  * a nightly backup upload just under the exfiltration threshold
  These are what make the false-positive rate mean something.
* **An uncovered class.** `LATERAL_MOVEMENT` has no matching rule. Its samples
  are guaranteed false negatives, and the report names it as a blind spot
  rather than dropping it.

Classes: `BENIGN`, `BRUTE_FORCE`, `PORT_SCAN`, `SUSPICIOUS_POWERSHELL`,
`CREDENTIAL_ACCESS`, `MALWARE`, `SUSPICIOUS_DNS`, `RANSOMWARE`,
`PRIVILEGE_ESCALATION`, `DATA_EXFILTRATION`, `ANOMALOUS_SIGNIN`,
`LOLBIN_EXECUTION`, `SUSPICIOUS_DOWNLOAD`, `LATERAL_MOVEMENT`.

## Running it

```bash
cd backend
python -m app.evaluation.run_detection_eval                  # text + JSON, writes a report
python -m app.evaluation.run_detection_eval --format text    # summary only
python -m app.evaluation.run_detection_eval --seed 7 --samples-per-class 200
python -m app.evaluation.run_detection_eval --fail-under-f1 0.85 --fail-over-fpr 0.10
```

Reports are written to `app/evaluation/reports/` as a timestamped JSON file plus
`latest.json` (both gitignored - they are reproducible output, not source).

The API serves the latest report at `GET /api/v1/detection/quality`, and the
Analytics page renders it under **Detection Engine Evaluation**. When no
evaluation has been run the endpoint returns 404 and the panel says so: an
un-measured system shows nothing rather than zeros.

## What is measured

A sample counts as **detected** when at least one rule fires - the same
condition that raises an alert in production.

| Metric | Meaning |
| --- | --- |
| True positives | malicious sample, engine fired |
| False positives | benign sample, engine fired |
| True negatives | benign sample, engine silent |
| False negatives | malicious sample, engine silent |
| Precision | TP / (TP + FP) - of everything flagged, how much was real |
| Recall | TP / (TP + FN) - of everything malicious, how much was caught |
| F1 | harmonic mean of precision and recall |
| False positive rate | FP / (FP + TN) - the number that decides whether analysts can live with it |
| False negative rate | FN / (FN + TP) |
| Accuracy, specificity | reported, but misleading alone on an unbalanced set |

Also reported: **per class** (so a strong average cannot hide a blind class),
**per rule** (fires, how many landed on benign samples, rule precision,
attribution accuracy), **latency** (mean/p50/p95/p99/max over rule evaluation
only, plus throughput), and **volume** (events processed, alerts generated,
detections fired, incident candidates at High/Critical).

Two honesty rules are built into the metric code:

* An undefined rate is `null`, never `0.0` - "no data" and "zero" must not look
  the same on a dashboard.
* Results below 100 samples overall (or 20 per class) are flagged
  `sufficientData: false`, and the UI shows a warning instead of a confident
  percentage.

## Measured baseline

Dataset `aegisx-detection-eval` v1.0, seed 1337, 60 samples per malicious class:
**1,950 events** (780 malicious, 1,170 benign).

| Metric | Value |
| --- | --- |
| Precision | 91.8% |
| Recall | 92.3% |
| F1 | 92.1% |
| False positive rate | 5.5% |
| False negative rate | 7.7% |
| Accuracy | 93.6% |
| TP / FP / TN / FN | 720 / 64 / 1106 / 60 |
| Latency (mean / p95) | 0.004 ms / 0.006 ms per event |

Reproduce with `python -m app.evaluation.run_detection_eval`. If your numbers
differ, the ruleset or the dataset changed - compare the `rulesetFingerprint`
and `dataset.fingerprint` fields in the report.

Reading the result honestly:

* Recall is capped at ~92% **by design**: `LATERAL_MOVEMENT` has no rule, and
  those 60 samples are all false negatives. The engine catches every class it
  claims to cover.
* All 64 false positives come from one rule, `DET-EXEC-002`, firing on
  legitimate administrator use of a living-off-the-land binary. That is the
  single highest-value tuning target for V3, and now it is a measurement rather
  than an opinion.
* Latency is rule evaluation only. It excludes ingestion, normalization and
  storage, and the report says so in its own payload.

## A bug this framework already caught

The first evaluation run reported precision 84.1% and a false positive rate of
11.6%, with `DET-EXFIL-001` at 45% rule precision. The cause was not the rule:
the EDR normalizer classified *every* non-ransomware EDR record as
`data_exfiltration`, so a benign backup agent arrived at the engine already
labelled as exfiltration.

Fixing the normalizer (classify from what the record reports, not by
elimination) moved the measured numbers to precision 91.8% and FPR 5.5%. The
regression is locked in by `app/tests/test_normalizer_regression.py`.

That is the argument for measurement in one paragraph: the bug had been in V1
the whole time, and no amount of looking at the dashboard would have revealed
it.

## What the rule evaluation is not

* Not a measurement on real traffic. The dataset is synthetic and labelled;
  real-world performance requires real data, which is V4 work.
* Not a claim about detecting unknown attacks. Deterministic rules catch what
  they were written to catch, which is precisely why the uncovered class is in
  the dataset.

---

# V3: hybrid evaluation (rules vs ML vs both)

V3 adds a second detector, and the only question worth asking about it is:
**does it catch anything the rules do not, and what does that cost?**

```bash
cd backend
python -m app.ml.evaluation.run_ml_eval --sweep
```

Three configurations run over the same labelled samples, in the same order:
`rules` (the V2 measurement), `ml` (anomaly score ≥ threshold, rules not
consulted) and `hybrid` (either fires — what the running platform does). The
model is **loaded from the registry exactly as the running system loads it** and
is never fitted on this dataset.

## Measured result

Dataset v1.0 seed 1337 (1,950 events), `isolation_forest@1.0`, threshold 0.65:

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| rules | 720 | 64 | 60 | 91.8% | 92.3% | 92.1% | 5.5% |
| ml | 579 | 380 | 201 | 60.4% | 74.2% | 66.6% | 32.5% |
| hybrid | 780 | 380 | 0 | 67.2% | 100% | 80.4% | 32.5% |

Reproduced end to end from a clean database with the documented defaults
(`train_anomaly_model` with no flags, then `run_ml_eval --sweep`). The ML rows
are a property of one specific artifact: retrain with a different
`--samples`/`--seed` and they move by several points, while the rules rows and
the shape of the conclusion do not.

**Read this honestly.** ML adds 60 true positives — the entire
`LATERAL_MOVEMENT` class, which no rule covers — and hybrid recall reaches 100%.
It does so at a false-positive rate the rules alone do not have. On *this
dataset*, the anomaly model cannot be given an operating point that improves on
the rules overall.

### Threshold sweep

| Threshold | ML precision | ML recall | ML FPR | Hybrid F1 | ML-only TPs |
| --- | --- | --- | --- | --- | --- |
| 0.55 | 40.6% | 100% | 97.5% | 57.8% | 60 |
| 0.60 | 47.0% | 86.8% | 65.3% | 67.1% | 60 |
| 0.65 | 60.4% | 74.2% | 32.5% | 80.4% | 60 |
| 0.70 | 69.9% | 50.9% | 14.6% | 89.2% | 54 |
| 0.75 | n/a | 0.0% | 0.0% | 92.1% | **0** |

The cliff between 0.70 and 0.75 is the finding: below it the model contributes
the lateral-movement class at a heavy cost; above it, it contributes nothing at
all. There is no operating point on this dataset that gives the recall without
the noise.

## Why those numbers, and why they are a lower bound

The labelled dataset was written to exercise **rule thresholds** — four failed
logins against a threshold of five, nineteen scanned ports against twenty. It
was never designed to contain statistically novel behaviour, and it is a set of
independent samples with no shared history, so the behavioural features (which
are the model's most useful ones) are close to constant. It is also drawn from a
different entity namespace than the training corpus, which makes almost every
sample look "new" to the model.

In short: **the evaluation dataset is out of distribution for this model.** Any
ML recall or FPR figure here is a property of that mismatch as much as of the
detector. This is stated in the report itself, in every run, as a caveat.

Those caveats are why the threshold was **not** chosen from this table.

## How the threshold was actually chosen

From a held-out corpus the model has never seen, drawn from the distribution it
actually serves — measured, reproducibly, by the training run:

| Threshold | Ordinary traffic flagged |
| --- | --- |
| 0.55 | 31.3% |
| 0.60 | 9.3% |
| **0.65** | **1.08%** |
| 0.70 | 0.08% |

0.65 flags roughly one event in a hundred. At 0.60 the badge would appear on one
event in ten and mean nothing. The shipped default agrees with the training
run's own recommendation (0.652, the score above which ~1% of ordinary traffic
sits) - two independent measurements landing in the same place.

This table is printed by every training run, so the operating point can be
re-checked against whatever artifact is actually deployed rather than trusted
from documentation.

## What the model does on live telemetry

From a live run of the real backend (460 events from the synthetic collector,
`isolation_forest@1.0`, threshold 0.65):

* 460 events scored, 44 flagged (8.7%)
* **23 of the 44 matched no rule at all**
* those 23 were dominated by `auth_success` events whose top drivers were
  `host_events_per_minute`, `source_ip_events_per_minute`,
  `source_ip_distinct_destinations` and `user_distinct_hosts`

That is the burst-and-diversity shape of the lateral-movement and
credential-attack campaigns the V3 generator emits — the behaviour the rules
cannot see, found by the features built for it. It is the honest case for
running a second detector, and unlike the table above it is measured on the
distribution the model was trained for.

It is still synthetic telemetry. It is not evidence about real attacks.

## What the hybrid evaluation is not

* Not a claim that the ML model is production-ready. It is a measured, tuned,
  explainable second signal, capped so it cannot dominate a risk score.
* Not a comparison anyone should quote out of context. The `ml` row is measured
  on a dataset built for the rules.
* Not a substitute for a real labelled corpus. Producing one — or adapting a
  public dataset such as CIC-IDS or UNSW-NB15 through the existing normalizer —
  is the single highest-value piece of V4 work.
