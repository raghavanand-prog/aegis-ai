# AEGISX V5 — Experimental Design

> Written **before** any V5 experiment was run, so that the predictions below
> can be wrong. No results appear in this document.
>
> Tags as in V4: **[MEASURED]**, **[IMPLEMENTATION]**, **[LIMITATION]**,
> **[INFERENCE]**.

---

## 1. The question

> Can AEGISX safely adapt its detection and triage behaviour using analyst
> feedback and observed distribution changes while maintaining measurable
> performance, provenance, stability and human control?

Note what is *not* being asked. Not "is adaptation good". Not "can the AI
improve itself". The claim under test is narrow and falsifiable: that a
controlled, human-approved adaptation loop produces a measurable change in
detection quality, and that the safety machinery around it holds.

---

## 2. The problem this design has to solve first

The production detector is an **Isolation Forest — an unsupervised model.**
Analyst feedback is labels. Labels do not train an unsupervised model, so
"feedback-driven adaptation" cannot mean the obvious thing, and pretending
otherwise would be the central dishonesty available to this project.

Two mechanisms genuinely use feedback without turning the detector into
something it is not:

**Arm 1 — Threshold adaptation.**
Feedback supplies labelled examples. Those choose an operating point on the
existing score distribution. The model is untouched; only the decision boundary
moves, bounded by `MAX_THRESHOLD_STEP = 0.05` and subject to the safety gates.

**Arm 2 — Training-corpus curation.**
Isolation Forest assumes its fitting data is mostly normal. Contaminate that
assumption and the model degrades. Analyst feedback identifies which observed
events were genuinely benign and which were malicious, so feedback can *purify
the fit set* — retraining on data an analyst has verified is ordinary. This uses
labels in a way an unsupervised model can actually consume.

**Neither arm makes the detector supervised.** Where a supervised model appears
it is the V4 reference model, labelled as such, and it is never presented as
deployable.

**[LIMITATION]** If both arms fail to move any metric, the honest conclusion is
that feedback-driven adaptation of an unsupervised anomaly detector does not
work on this data — and that is a publishable result, not a failure to fix.

---

## 3. Substrate

| | Corpus | Why |
| --- | --- | --- |
| **Primary** | `aegisx-detection-eval` (1,950 synthetic endpoint/identity events) | The only corpus where the rules fire and where the deployed model has measurable signal (**[MEASURED]** F1 0.663, FPR 33.3%). Feedback can move a metric here. |
| **Secondary** | UNSW-NB15 (2,280,090 real flows) | Real, measured distribution shift for the drift scenarios. **[MEASURED]** malicious rate 4.83% → 18.98%, test leakage 0.00% on the temporal split. |

**[LIMITATION]** No detection-improvement claim will be made on UNSW. V4
established the deployed detector is indistinguishable from random there
(PR-AUC 0.114 against a 0.109 baseline) and the rules cannot fire on flow
telemetry at all. UNSW answers RQ3 only.

---

## 4. Synthetic analyst feedback, with modelled error

There is no analyst population, so feedback is generated. The design decision
that matters is that it is **not** simply ground truth renamed.

Each simulated analyst verdict is drawn as:

| Parameter | Values | Purpose |
| --- | --- | --- |
| Label noise rate | **0%, 5%, 15%** | 0% is the unrealistic ceiling. 5% is a plausible SOC. 15% tests whether the loop survives a bad week. |
| Coverage | 10%, 25%, 50% of events reviewed | Analysts do not review everything. |
| Abstention | ~10% labelled `uncertain` | Exercises the vocabulary's refusal to count hesitation as a verdict. |
| Bias | Over-reporting `false_positive` on high-volume benign clusters | The realistic failure mode: analysts label what annoys them. |

**[LIMITATION]** This is a model of an analyst, not an analyst. Every result
downstream inherits that. It is stated in the report, not buried.

---

## 5. Controls

Without these, any improvement is unattributable.

| Control | What it rules out |
| --- | --- |
| **Random-label feedback** — same volume, labels shuffled | If adaptation "improves" on shuffled labels, the gain came from retraining or threshold movement, **not** from feedback. This is the single most important control in the design. |
| **No-feedback retrain** — retrain on the same corpus with a new seed, no feedback | Separates "adaptation helped" from "any new model helps". |
| **Threshold-only sweep** — move the threshold without feedback | Separates Arm 1's gain from a gain any operating-point change would give. |
| **Static V4 baseline** — deployed model, frozen threshold | The comparison of record. |

**[INFERENCE]** I expect the random-label control to be the result that most
constrains what V5 may claim.

---

## 6. Scenarios (§46)

| # | Scenario | Construction | Primary RQ |
| --- | --- | --- | --- |
| 1 | Stable environment | Corpus unchanged; feedback from same distribution | RQ2, RQ5 |
| 2 | False-positive drift | Benign cluster inflated until it dominates alert volume | RQ1 |
| 3 | Feature distribution drift | **Real** — UNSW temporal split | RQ3 |
| 4 | New behavioural pattern | Held-out attack class withheld from the fit set, introduced at test | RQ4 |
| 5 | Feedback-driven adaptation | Arms 1 and 2, full loop, all noise rates | RQ1, RQ2 |
| 6 | Candidate regression | Deliberately degraded candidate submitted for promotion | RQ6 |
| 7 | Rollback | Deploy a regressing candidate, detect, roll back | RQ6 |

Scenarios 2 and 4 are **induced**, and will be labelled as simulated wherever
they are reported. Scenario 3 is observed. That distinction is not cosmetic:
only scenario 3 supports a claim about real drift.

---

## 7. Metrics

Per V4's framework, unchanged, reused rather than reimplemented:

precision · recall · F1 · FPR · FNR · MCC · alert volume · per-event latency.

Undefined metrics report `null`, never 0. Every result carries dataset
fingerprint, split fingerprint, feature schema version, threshold and model
digest, or it is not a result.

**Seeds: 3 minimum per configuration**, with percentile bootstrap intervals, as
V4 did. A single-run difference will not be reported as an effect.

---

## 8. Catastrophic forgetting (§33)

The trap: a model that improves on recent feedback while quietly losing older
behaviours. Every adapted candidate is evaluated on **both**:

1. the adaptation window (recent/drifted data), and
2. the **original V4 historical benchmark**, unchanged.

A candidate that improves on (1) and regresses on (2) beyond the gate policy is
recorded as catastrophic forgetting and **rejected**. Reporting only (1) is the
error this section exists to prevent.

---

## 9. Adaptation latency (§47)

Measured, per stage, wall-clock:

drift detection · feedback dataset build · candidate training · candidate
evaluation · gate evaluation · deployment · rollback.

**Human approval time is NOT measured and will not be estimated.** There is no
analyst population, so any number would be invented. The report will state the
machine-time total and name approval as an unmeasured human-latency term.

**[LIMITATION]** All timings are laptop-and-SQLite, single process. They are
relative measurements, not throughput claims — the same caveat V4 carried.

---

## 10. Pre-registered predictions

Recorded now so they can be wrong. **[INFERENCE]** throughout.

| # | Prediction | What would falsify it |
| --- | --- | --- |
| P1 | Arm 1 reduces FPR materially from the measured 33.3% | FPR unchanged, or recall collapses to buy it |
| P2 | Arm 2 produces a smaller effect than Arm 1 | Curation dominates |
| P3 | The random-label control shows **no** improvement | It improves — in which case feedback is not the cause, and RQ1 is answered "no" |
| P4 | Drift detection fires on scenario 3 before any metric degrades | Metrics degrade first, making drift a lagging indicator |
| P5 | 15% label noise degrades adaptation below the static baseline | It survives, suggesting robustness |
| P6 | The gates reject the scenario-6 candidate without human help | It passes — a gate policy failure worth reporting loudly |
| P7 | Adaptation gains on new behaviour (scenario 4) cost historical recall | No trade-off appears |

**A result that contradicts a prediction is the finding.** These are not targets.

---

## 11. What this design cannot establish

- Real-world detection accuracy. Synthetic corpus and a 2015 testbed capture.
- That real analysts behave like the model in §4.
- Production throughput.
- Anything about scenarios 2 and 4 as *observed* phenomena; they are induced.
- Whether adaptation helps a *supervised* detector — out of scope.

---

## 12. Compute budget

Synthetic runs are seconds each; UNSW drift evidence is already measured and
will be reused rather than re-run. Estimated total **under one CPU-hour**, run
bounded with the existing watchdog, one experiment at a time.
