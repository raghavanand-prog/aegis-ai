# AEGISX V5 Research Report

> Every number here was produced by a committed, reproducible command. The
> design was written first (`docs/V5_EXPERIMENTAL_DESIGN.md`) and its
> predictions are reported as they came out, including the three that were
> wrong.

---

## 1. Experimental setup **[MEASURED]**

| | |
| --- | --- |
| Corpus | `aegisx-detection-eval` v1.0, fingerprint `c0f04f3ccb2a63b8` |
| Split | V4 `stratified_group` splitter, fingerprint `d349ea18a04e06c0` |
| Fit / test | 1,560 / 390 samples (156 malicious in test) |
| Detector | Isolation Forest, contamination 0.08, 200 estimators |
| Baseline threshold | 0.65, frozen |
| Seeds | 1337, 4242, 99 |
| Environment | macOS, Python 3.11.16, scikit-learn 1.7.2, SQLite |

**A design correction found while building the harness.** A naive chronological
split of this corpus places **zero malicious samples** in the held-out portion,
making recall undefined and every comparison meaningless. V4's group-aware
stratified splitter is used instead. The harness agrees with V4 on a known
quantity: the static ML-only baseline reproduces **1.9% recall at threshold
0.65**, matching `RESEARCH_REPORT.md` §4's ablation exactly.

---

## 2. Static vs adaptive **[MEASURED]**

Means over 3 seeds. `sd` is the population standard deviation of F1.

| Condition | Noise | Precision | Recall | F1 | F1 sd | FPR | Alerts |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **static V4** | — | 1.000 | 0.019 | **0.038** | 0.000 | 0.000 | 3.0 |
| threshold only (Arm 1) | 5% | 0.698 | 0.053 | 0.099 | 0.006 | 0.016 | 12.0 |
| curation only (Arm 2) | 5% | 1.000 | 0.030 | 0.058 | 0.006 | 0.000 | 4.7 |
| **both arms** | 0% | 0.810 | 0.165 | **0.270** | 0.086 | 0.023 | 31.0 |
| **both arms** | 5% | 0.815 | 0.141 | **0.238** | 0.090 | 0.017 | 26.0 |
| **both arms** | 15% | 0.772 | 0.141 | **0.236** | 0.084 | 0.024 | 27.7 |
| *control:* random labels | any | 0.798 | 0.058 | **0.107** | 0.027 | 0.013 | 12.0 |
| *control:* no-feedback retrain | — | 1.000 | 0.024 | 0.046 | 0.012 | 0.000 | 3.7 |

### 2.1 The control fires — P3 falsified

**Shuffled labels also improve on the static baseline** (F1 0.038 → 0.107).
Prediction P3 said the control would show no improvement. It was wrong, and the
consequence is that the headline number cannot be attributed to feedback alone:

| Component | ΔF1 | Share |
| --- | --- | --- |
| Mechanism (retrain + threshold movement), from the random control | +0.069 | 34% |
| **Feedback content**, both arms above the control | **+0.131** | **66%** |
| Total, static → both arms at 5% noise | +0.200 | 100% |

So feedback content carries roughly two thirds of the effect and the machinery
itself carries a third. Reporting 0.038 → 0.238 as "feedback improved detection
6×" would have been a 34% overstatement, and only the control makes that
visible.

### 2.2 What adaptation actually changes

The static detector is nearly inert on this corpus: **3 alerts, 1.9% recall,
perfect precision**. Adaptation trades precision (1.000 → 0.815) and false
positives (0.0% → 1.7%) for recall (1.9% → 14.1%), raising alert volume from
3 to 26. That is a genuine change in operating behaviour, not a metric artefact
— but it is a *recall* result, not the false-positive reduction P1 predicted.

**P1 was mis-framed and is withdrawn.** The 33.3% FPR it referenced came from
the *deployed* artifact over the full corpus (Phase A §19.12), not the fitted
model on this split, whose FPR is 0.0%. There was no false-positive problem to
solve in this configuration. The prediction compared two different measurements
and should not have been written.

### 2.3 Variance is large relative to the effect **[LIMITATION]**

Both-arms F1 ranges **0.117 – 0.333** across three seeds (sd ≈ 0.09). The gap
over the random control (+0.131) is about 1.5 standard deviations. With three
seeds that is **suggestive, not conclusive**. A stronger claim needs more seeds,
and this report does not make one.

### 2.4 Arm 2 alone is weak — P2 confirmed

Curation alone reaches F1 0.058 against threshold-only's 0.099, as predicted.
Notably it preserves precision 1.000 and FPR 0.000: purifying the fit set
sharpens the boundary without moving the operating point. Together the arms
reach 0.238, well above the sum of their separate gains — the curated model
gives the threshold search a better score distribution to choose from.

### 2.5 Label noise barely matters — P5 falsified

F1 0.270 → 0.238 → 0.236 across 0%, 5% and 15% requested noise. Prediction P5
said 15% noise would degrade adaptation below the static baseline. It stays
**6.2× above it**. Curation is robust to label noise because dropping a few
wrongly-labelled rows from a 1,560-sample fit set changes the density estimate
very little.

---

## 3. New behaviour and catastrophic forgetting **[MEASURED]**

One attack category withheld from the fit set entirely; 3 categories × 3 seeds.
Recall, means over 9 runs:

| | Withheld (unseen) behaviour | Historical behaviour |
| --- | --- | --- |
| Static | 0.0000 | 0.0100 |
| Adapted | **0.0085** | **0.1789** |

Two findings, and the second is not the one that was predicted.

**Adaptation does not help against genuinely novel behaviour.** Recall on the
withheld category goes 0.000 → 0.0085; **one of nine runs** detected anything at
all. Curating the fit set sharpens the boundary around behaviour the feedback
covered; it cannot teach a pattern the model has never seen. **RQ4 is answered
no**, measurably.

**There is no catastrophic forgetting.** Historical recall *improves* 18-fold
(0.0100 → 0.1789) rather than degrading. **P7 predicted gains on new behaviour
would cost historical recall; it was wrong in both directions** — there were no
gains on new behaviour to trade, and the historical side improved.

---

## 4. Adaptation latency **[MEASURED]**

One full cycle through the real service code paths, not a simulation of them:

| Stage | Seconds |
| --- | --- |
| Drift detection | 0.0020 |
| Feedback submission (200 verdicts) | 0.0147 |
| Feedback dataset build | 0.0069 |
| Candidate training | 0.5703 |
| Candidate evaluation | 2.3774 |
| Proposal creation | 0.0008 |
| Approval | 0.0004 |
| Deployment | 0.0009 |
| **Rollback** | **0.0011** |
| **Machine total** | **2.9745** |

Evaluation dominates at 80% of the cycle, which is the correct place for the
time to go — it is the step that decides whether the candidate is safe.

**Human approval time is not measured and is not estimated.** There is no
analyst population; any number would be invented. The 0.0004 s above is the
database transition, not a decision.

**[LIMITATION]** Single process, one laptop, SQLite. Relative measurements, not
throughput claims.

---

## 5. Safety machinery under test **[MEASURED]**

Both exercised during the latency run rather than in isolation:

- **Scenario 6 — candidate regression.** The gates **rejected** the candidate
  unaided, citing false-positive rate and F1. **P6 confirmed.**
- **Scenario 7 — rollback.** Rollback completed in 1.1 ms and the incumbent
  `isolation_forest@1.0` was correctly restored as the active model.

Additionally, from the phase test suites: deployment refuses a candidate whose
artifact digest no longer matches, leaving the incumbent serving (§52); a
candidate cannot be activated without an approved proposal; and the AI cannot be
recorded as an approver.

---

## 6. Research questions answered

| RQ | Answer |
| --- | --- |
| **RQ1** Can analyst feedback reduce false positives? | **Not tested as framed.** The baseline had FPR 0.0% here. Adaptation *raises* FPR to 1.7% while raising recall. |
| **RQ2** Can controlled adaptation preserve recall? | **Yes — it increases it**, 1.9% → 14.1%, of which two thirds is attributable to feedback content. |
| **RQ3** Can drift detection identify meaningful distribution changes? | **Yes**, on real measured shift (Phase A: UNSW temporal, PSI 0.459 on `dbytes`, 0.00% test leakage). |
| **RQ4** Does adaptation improve performance on new behaviour? | **No.** 0.000 → 0.0085 recall on withheld categories; 1 of 9 runs. |
| **RQ5** Does adaptation regress previously known behaviour? | **No.** Historical recall improved 0.010 → 0.179. |
| **RQ6** Can human approval maintain safety while allowing useful adaptation? | **Yes** on the machinery: gates rejected a regressing candidate, rollback restored the incumbent, and no path deploys without approval. |
| **RQ7** What is the operational cost? | 2.97 s machine time per cycle, 80% in evaluation; alert volume 3 → 26 events per 390. |

---

## 7. Limitations **[LIMITATION]**

1. **Feedback is simulated.** No analyst population exists. The simulator models
   noise, partial coverage, abstention and false-positive bias, but it is a
   model of an analyst, not an analyst.
2. **The corpus is synthetic.** Nothing here is evidence about real attack
   traffic.
3. **Three seeds.** Variance is large relative to the effect (§2.3).
4. **Scenarios 2 and 4 are induced**, not observed. Only the UNSW drift evidence
   is real distribution shift.
5. **No detection claim on UNSW.** V4 established the deployed detector is
   indistinguishable from random on that telemetry.
6. **Latency is laptop-and-SQLite**, single process.
7. **Human approval latency is unmeasured**, deliberately.
8. Everything inherited from V4 §19 still applies.

---

## 8. Reproducing this report

```bash
export DATABASE_URL="sqlite:///aegisx.db"

# §2 static vs adaptive matrix
python -m app.adaptation.experiments.run_adaptation_eval --seeds 3 --max-seconds 2400
```

§3 uses `scenarios.run_new_behaviour`, §4 the service code paths directly. The
JSON report is written to `app/evaluation/reports/v5-adaptation-*.json` with the
dataset and split fingerprints above.

---

## 9. Conclusion

Controlled adaptation measurably changed detection behaviour on this corpus:
F1 0.038 → 0.238, recall 1.9% → 14.1%, with no historical regression and with
every safety control holding. **Two thirds of that gain is attributable to
feedback content and one third to the mechanism**, a distinction only the random
control made visible.

It did **not** help against behaviour the model had never seen, and the effect
carries seed variance large enough that three runs cannot settle its size. Three
of seven pre-registered predictions were wrong. Those are the results, reported
as they came out.
