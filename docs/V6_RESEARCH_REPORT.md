# AEGISX V6 Research Report

> Every number here was produced by a committed, reproducible command, and the
> artifact it came from is committed beside it. Tags as in V4/V5:
> **[MEASURED]**, **[IMPLEMENTATION]**, **[LIMITATION]**, **[INFERENCE]**.
>
> This report is written as V6 progresses. Sections appear when their track has
> run, not before.

---

## 1. Track 1 — the V5 effect at 50 seeds **[MEASURED]**

V5 reported three seeds and explicitly declined to call the effect size
settled: the both-arms F1 spread was 0.117–0.333, and the gap over the
random-label control was roughly 1.5 standard deviations. Track 1 answers that
with fifty.

| | |
| --- | --- |
| Corpus | `aegisx-detection-eval` v1.0, fingerprint `c0f04f3ccb2a63b8` |
| Split | V4 `stratified_group`, fingerprint `d349ea18a04e06c0` |
| Fit / test | 1,560 / 390 (156 malicious in test) |
| Seeds | **50**, `experiments/seeds.py` plan, first three are V5's |
| Artifact | `backend/app/evaluation/reports/v5-adaptation-20260903T071427Z.json` |
| Command | `python -m app.adaptation.experiments.run_adaptation_eval --seeds 50 --max-seconds 5400` |
| Runtime | ~20 min, single process, macOS, SQLite |

### 1.1 Results

Means over 50 seeds. `CI95` is a percentile bootstrap interval on the mean.

| Condition | Noise | Precision | Recall | F1 | sd | CI95 | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| static V4 | — | 0.996 | 0.020 | **0.0389** | 0.0083 | [0.036, 0.041] | 0.0001 |
| threshold only | 0% | 0.694 | 0.058 | 0.1069 | 0.0228 | [0.101, 0.114] | 0.0181 |
| threshold only | 5% | 0.685 | 0.059 | 0.1075 | 0.0219 | [0.101, 0.114] | 0.0187 |
| threshold only | 15% | 0.695 | 0.058 | 0.1063 | 0.0215 | [0.101, 0.112] | 0.0179 |
| curation only | 0% | 1.000 | 0.034 | 0.0654 | 0.0152 | [0.061, 0.070] | 0.0000 |
| curation only | 5% | 1.000 | 0.031 | 0.0606 | 0.0135 | [0.057, 0.064] | 0.0000 |
| curation only | 15% | 1.000 | 0.028 | 0.0553 | 0.0111 | [0.052, 0.059] | 0.0000 |
| **both arms** | 0% | 0.880 | 0.169 | **0.2826** | 0.0475 | [0.268, 0.296] | 0.0154 |
| **both arms** | 5% | 0.862 | 0.152 | **0.2570** | 0.0549 | [0.241, 0.273] | 0.0154 |
| **both arms** | 15% | 0.825 | 0.122 | **0.2110** | 0.0512 | [0.197, 0.225] | 0.0168 |
| *control:* random labels | — | 0.691 | 0.058 | **0.1068** | 0.0271 | [0.100, 0.115] | 0.0182 |
| *control:* no-feedback retrain | — | 1.000 | 0.020 | 0.0384 | 0.0072 | [0.036, 0.041] | 0.0000 |

### 1.2 RQ1 — the effect survives, and sharpens

**The V5 effect is real and larger than three seeds could establish.**

| Comparison (F1, 5% noise) | Δ mean | Cohen's d |
| --- | --- | --- |
| both arms vs **random-label control** | +0.1502 | **3.43** |
| both arms vs static V4 | +0.2180 | 5.50 |
| random control vs static V4 | +0.0679 | 3.35 |

The both-arms and control intervals do not overlap ([0.241, 0.273] against
[0.100, 0.115]). V5's caution — a gap of about 1.5 standard deviations — is
resolved: at fifty seeds it is **3.4**, and the standard deviation itself fell
from 0.0855 to 0.0549 as the mean stabilised.

**The mechanism/content decomposition holds.** V5 computed 34% mechanism, 66%
feedback content from three seeds. At fifty:

| Component | ΔF1 | Share |
| --- | --- | --- |
| Mechanism (retrain + threshold movement), from the random control | +0.0679 | **31%** |
| **Feedback content**, both arms above the control | **+0.1502** | **69%** |
| Total, static → both arms at 5% noise | +0.2180 | 100% |

A three-point shift on a figure V5 derived by hand from console output. It is
now computed into the artifact, so it is reproducible rather than recomputed.

### 1.3 A V5 conclusion that does not survive **[MEASURED]**

V5 §2.5 reported F1 0.270 → 0.238 → 0.236 across 0%, 5% and 15% noise and
concluded that **"label noise barely matters"**, attributing the robustness to
curation: *"Curation is robust to label noise because dropping a few wrongly-
labelled rows from a 1,560-sample fit set changes the density estimate very
little."*

At fifty seeds that reading is wrong. The degradation is monotone and material:

| Condition | 0% → 15% F1 | Cohen's d |
| --- | --- | --- |
| both arms | 0.2826 → 0.2110 | **1.44** |
| curation only | 0.0654 → 0.0553 | 0.75 |
| threshold only | 0.1069 → 0.1063 | 0.03 |

The 0% and 15% both-arms intervals do not overlap. **Label noise degrades
adaptation**, and the component V5 named as the robust one — curation — is the
component that degrades (d = 0.75); threshold selection is the noise-insensitive
one (d = 0.03).

Two things are worth separating here, because only one of V5's claims falls:

- **P5 remains falsified.** P5 predicted 15% noise would push adaptation *below*
  the static baseline. It does not: 0.2110 is still **5.4×** static's 0.0389.
- **V5's stated explanation was wrong.** "Noise barely matters" and "curation is
  robust to label noise" were three-seed artifacts — sd 0.0844 at 15% noise was
  large enough to hide a real 0.07 F1 decline. V6 Track 2 inherits this as its
  starting point rather than its conclusion.

Note also that V5's 15%-noise mean (0.2355) falls **outside** the 50-seed
interval [0.197, 0.225]. That is precisely the seed-luck the V5 report warned
about, landing on one of its own numbers.

### 1.4 What Track 1 does not establish **[LIMITATION]**

1. Feedback is still simulated. Fifty seeds of a simulated analyst is fifty
   draws from a model of an analyst, not evidence about analysts.
2. The corpus is still synthetic. Nothing here is evidence about real traffic.
3. Fifty seeds settle the *effect size on this corpus and split*. They say
   nothing about a different corpus, and nothing about novel behaviour (§2).
4. Latency remains laptop-and-SQLite, single process.

---

## 2. Track 3 — the novel-behaviour confound, investigated **[MEASURED]**

### 2.1 The confound

`scenarios.run_new_behaviour` withholds one attack category from the fit set,
then simulates feedback from `fit_labels` — which is derived from that same
reduced fit set. **No verdict about the withheld category ever reaches the
adaptation loop.** The threshold is likewise selected only from fit-set scores.
The function's docstring claimed "adaptation then happens on feedback that
includes it"; the code did not. Now reported as `verdictsAboutWithheld`, and
measured as structurally zero.

It is a property of the **evaluation procedure** — not the adaptation
mechanism, not the simulator (which labels whatever it is handed), not the
dataset, and not the split.

### 2.2 The controlled experiment

Same dataset, same seeds, same adaptation configuration, **one variable**:
whether the analyst ever labelled an instance of the withheld category.

Held-out samples of the withheld category are partitioned into an *adaptation
window* the analyst may label and a *scoring set* neither arm labels, so the
corrected arm cannot simply leak test labels. Both arms score on the identical
scoring set (asserted by test).

```bash
cd backend
export DATABASE_URL="sqlite:///aegisx.db"
python -m app.adaptation.experiments.run_novel_behaviour_eval --seeds 10 --max-seconds 3600
```

13 categories × 10 seeds × 2 arms = 260 runs. Seeds from the standing plan;
noise 0.05, coverage 0.5, window fraction 0.5. Artifact:
`app/evaluation/reports/v6-novel-behaviour-20260903T074713Z.json`.

### 2.3 The confound is **benign** — and the reason matters

Supplying feedback about the withheld category changed **nothing**, in every
category, to six decimal places:

| Category | separable | withheld arm | supplied arm | Δ |
| --- | --- | --- | --- | --- |
| PORT_SCAN | yes | 0.9500 | 0.9500 | **0.0** |
| SUSPICIOUS_DNS | yes | 0.5685 | 0.5685 | **0.0** |
| BRUTE_FORCE | yes | 0.4236 | 0.4236 | **0.0** |
| SUSPICIOUS_POWERSHELL | yes | 0.0786 | 0.0786 | **0.0** |
| the other nine | no | 0.0000 | 0.0000 | **0.0** |

**Root cause: the threshold arm is already saturated.** In **256 of 260 runs**
the selected threshold sits exactly on the clamp floor, `DEFAULT_THRESHOLD −
MAX_THRESHOLD_STEP = 0.60` (the only other value observed is 0.605). The ~780
fit-set verdicts drive the threshold to the boundary; the 2–4 additional
verdicts about the withheld category have nowhere left to push it.

So novel-behaviour feedback cannot matter **given the current clamp**, and the
V5 result is not corrupted by the confound. **[LIMITATION]** This is a
conditional finding: it says the confound is inert while `MAX_THRESHOLD_STEP`
binds, not that novel-category feedback is worthless in general. A larger step
would have to be re-tested.

### 2.4 A larger problem than the confound: V5's conclusion is wrong

V5 §3 reported novel-behaviour recall 0.000 → 0.0085 over 3 categories × 3
seeds, "1 of 9 runs", and concluded **"RQ4 is answered no, measurably"**.

Across all thirteen categories, that generalisation does not hold:

| Category | static | adapted | gain |
| --- | --- | --- | --- |
| PORT_SCAN | 0.2575 | **0.9500** | +0.693 |
| SUSPICIOUS_DNS | 0.0744 | **0.5685** | +0.494 |
| BRUTE_FORCE | 0.0292 | **0.4236** | +0.394 |
| SUSPICIOUS_POWERSHELL | 0.0000 | 0.0786 | +0.079 |
| ANOMALOUS_SIGNIN, CREDENTIAL_ACCESS, DATA_EXFILTRATION, LATERAL_MOVEMENT, LOLBIN_EXECUTION, MALWARE, PRIVILEGE_ESCALATION, RANSOMWARE, SUSPICIOUS_DOWNLOAD | 0.0000 | 0.0000 | 0.000 |
| **mean, all 13** | **0.0278** | **0.1554** | +0.128 |
| **mean, the 4 separable** | **0.0903** | **0.5051** | +0.415 |

**Adaptation does help against novel behaviour — in 4 of 13 categories, and
substantially.** It cannot help in the other 9. The determining factor is
whether the model separates the unseen category at all:

| Category | novel median score | benign median | ≥ 0.60 floor |
| --- | --- | --- | --- |
| PORT_SCAN | 0.625 | 0.505 | 15/15, 16/16, 10/16 |
| RANSOMWARE | 0.501 | 0.499 | 0/9, 0/9, 0/14 |
| LATERAL_MOVEMENT | **0.440** | 0.499 | 0/11, 0/11, 0/15 |

Lateral movement scores *below the benign median* — the detector rates novel
attacks as more normal than normal traffic. No threshold recovers that.

**[LIMITATION]** V5's 0.0085 figure could not be reproduced, because **the three
categories it used were never recorded**. Running V5's own function today gives
PORT_SCAN recall 0.533 (seed 1337) and 1.000 (seed 4242). No 3-category subset
of the measured results averages 0.0085, so the figure cannot be reconstructed;
it is consistent with a draw from the nine non-separable categories, but that is
inference, not verification. **The V5 measurement is retained unchanged as a
historical result. The corrected interpretation is recorded here, separately.**

### 2.5 Which hypotheses survive

| # | Hypothesis | Verdict |
| --- | --- | --- |
| 1 | Isolation Forest's representation is insufficient | **Confirmed, and it is the binding constraint** — 9 of 13 categories are unreachable at any threshold |
| 2 | The feature space does not capture the new behaviour | **Confirmed**, same evidence; lateral movement lands below the benign median |
| 3 | Curation cannot teach unseen patterns | **True but inert** — curation only removes fit-set rows and the category is not in the fit set, so it cannot act at all |
| 4 | Threshold adaptation cannot solve representation failure | **Confirmed and quantified** — it fully solves the 4 separable categories and none of the other 9 |
| 5 | Detector class is limiting adaptation | **Supported**, and now the highest-value V6 question |

### 2.6 Impact on Track 2

**None. Track 2 is safe to proceed on the original methodology.**

The confound is a property of `run_new_behaviour`. Every Track 1 number,
including the noise sensitivity in §1.3, comes from `run_condition`, which
withholds no category and offers feedback over the entire fit set — so the
confound has no precondition there. This is now asserted by test
(`TestTrack1IsNotAffectedByTheConfound`) rather than left to be re-derived by
reading. The noise-sensitivity finding stands unchanged.

### 2.7 Two further code-level issues found

1. **`run_condition`'s docstring claimed the split is chronological.** It is
   stratified group-aware; V5's own report explains a chronological split was
   rejected for putting zero malicious samples in test. Corrected.
2. **The corpus has duplicate feature vectors across the split.** 5.1% of test
   rows at seed 1337 (17 benign, 3 malicious) share a feature vector with a fit
   row. Samples and groups are disjoint — `test_no_sample_appears_in_two_splits`
   already covers that — so this is feature-space coarseness, **not leakage**,
   but the detector does meet vectors in test that it fitted on. Pinned by test
   as a known corpus property.

## 3. Hypothesis 5 — detector class versus feature space **[MEASURED]**

Track 3 left one question open: nine of thirteen withheld categories are
unreachable under the production Isolation Forest. Is that a fact about
**Isolation Forest** (hypothesis 5) or about the **feature space** (hypothesis
2)? They imply different work — swap the detector, or engineer features.

### 3.1 Design

Corpus, split, seed and withheld category held fixed; **only the detector
varies**. Separability is **ROC-AUC**, not recall: §2.3 showed recall here is
dominated by the threshold clamp, which would confound a detector comparison
with an operating-point artefact. AUC is also rank-based, so the detectors'
scores never need a common scale.

```bash
python -m app.adaptation.experiments.run_detector_comparison --seeds 10 --max-seconds 5400
```

13 categories × 4 detectors × 10 seeds. Artifact:
`app/evaluation/reports/v6-detector-comparison-20260903T080411Z.json`.

**[LIMITATION]** This uses an enlarged corpus (160 samples per attack class),
because V4's `roc_auc` refuses to report below `MIN_PER_CLASS` = 20 a side and
the Track 1 corpus leaves only ~15 held-out samples per category. The guard is
right, so the corpus was enlarged rather than the guard weakened. Different
dataset fingerprint from §1; **not comparable row-for-row.**

**Nothing in this experiment is deployed, proposed or registered.** The registry
is never imported — asserted against the parsed module, not its prose. The
supervised entry is marked `deployable=False` and `requires_labels=True`; a test
enforces that anything requiring labels is not deployable.

### 3.2 Result — hypothesis 5 is confirmed

Novel-category ROC-AUC, means over 10 seeds. 0.5 is indistinguishable from
benign; **below 0.5 means the detector ranks novel attacks *beneath* benign
traffic.**

| Withheld category | Isolation Forest | LOF | One-Class SVM | Supervised ceiling |
| --- | --- | --- | --- | --- |
| LATERAL_MOVEMENT | **0.083** | 0.999 | 0.010 | 1.000 |
| PRIVILEGE_ESCALATION | **0.288** | 1.000 | 0.987 | 1.000 |
| SUSPICIOUS_DOWNLOAD | **0.403** | 0.927 | 0.555 | 1.000 |
| LOLBIN_EXECUTION | **0.428** | 0.934 | 0.405 | 1.000 |
| CREDENTIAL_ACCESS | **0.475** | 0.999 | 0.580 | 1.000 |
| RANSOMWARE | 0.504 | 0.996 | 0.999 | 1.000 |
| ANOMALOUS_SIGNIN | 0.613 | 0.974 | 0.021 | 1.000 |
| MALWARE | 0.626 | 1.000 | 0.389 | 1.000 |
| DATA_EXFILTRATION | 0.823 | 1.000 | 1.000 | 1.000 |
| SUSPICIOUS_POWERSHELL | 0.874 | 0.999 | 0.999 | 1.000 |
| SUSPICIOUS_DNS | 0.995 | 0.980 | 1.000 | 1.000 |
| BRUTE_FORCE | 0.996 | 0.995 | 1.000 | 1.000 |
| PORT_SCAN | 0.997 | 0.980 | 1.000 | 1.000 |
| **mean** | **0.623** | **0.983** | 0.688 | 1.000 |
| **categories below 0.5** | **5 of 13** | **0 of 13** | 4 of 13 | 0 of 13 |

**The information is in the features.** The supervised ceiling reaches AUC 1.000
on every withheld category, having never seen any of them. **Hypothesis 2 is
rejected: the feature space is not the limit.**

**Isolation Forest cannot extract it.** Mean AUC 0.623, and on five categories it
is *systematically inverted* — LATERAL_MOVEMENT at 0.083 means it reliably ranks
novel attacks as more normal than normal traffic. That is worse than useless.

**A different unsupervised detector can.** LOF reaches 0.983 mean on identical
features with identical labels-free fitting. Checked for degeneracy at a real
operating point: on LATERAL_MOVEMENT at a 5% false-positive threshold, **LOF
recall is 1.000 where Isolation Forest's is 0.000.**

**Hypothesis 5 is confirmed. The detector class is the binding constraint.**

### 3.3 But no candidate here is a deployable replacement **[LIMITATION]**

Two findings cut against reading the table as "switch to LOF".

**LOF is good at unseen categories and poor at seen ones.** Its *historical* AUC
— attacks that were in its fit set — is only **0.592**, against 1.000 for the
supervised ceiling. The pattern is close to tautological for a density-based
detector: a category excluded from the fit set looks like low-density novelty; a
category included in it has been learned as normal. High novel AUC is partly a
restatement of what was withheld.

**The fit set is 40% malicious.** Measured: 1,664 of 4,160 fit samples — and the
same 40% holds in the Track 1 corpus (624 of 1,560), against a configured
`contamination=0.08`. **The corpus violates the detector's central assumption
that its fitting data is mostly normal.**

> **Correction (§4).** This paragraph originally said the corpus "violates the
> detector's central assumption by a factor of 5", implying the `contamination`
> *parameter* was mis-set. The direction is right, the named mechanism was
> wrong: `contamination` never reaches `anomaly_score`, which squashes the raw
> score about the **median of the training scores**; the parameter only sets
> scikit-learn's `offset_` for `predict()`. The binding problem is the fitting
> data itself. §4 measures it directly.

That reframes several earlier results:

- It explains why Isolation Forest's historical AUC is 0.526, barely above
  chance, on attacks it *did* fit.
- It explains why V5's Arm 2 (curation) helped at all — purifying a fit set that
  is 40% malicious is a large correction, not a marginal one.
- It means **no detector comparison on this corpus is a clean statement about
  production behaviour**, because in production the fitting data would be
  overwhelmingly benign.

**[INFERENCE]** The honest conclusion is narrower than the headline table:
Isolation Forest is demonstrably the wrong detector *for this corpus*, the
features carry the signal, and the most promising direction is curation combined
with a density-based detector — not a like-for-like swap. Establishing that
requires a fit set whose contamination resembles production, which this corpus
does not provide.

### 3.4 Impact on Track 2

None. This is a read-only comparison; the production detector, the registry and
the adaptation loop are untouched. Track 2 remains safe to proceed.

## 4. Fit-set contamination — the largest finding so far **[MEASURED]**

### 4.1 What was found

The labelled evaluation corpus's fit split is **40% malicious** (624 of 1,560).
Three facts make that consequential:

1. **The production model is not trained on it.** `train_anomaly_model` fits the
   runtime telemetry generator's corpus, whose suspicious scenarios run at about
   **12%** (238 of 2,000, from its scenario mix).
2. **The corpus's own provenance says so** — *"out of distribution for the
   anomaly model trained on the runtime telemetry generator; ML metrics on this
   corpus are a lower bound."* It was built to exercise **rule** thresholds.
3. **V4 and V5 nonetheless re-fitted an Isolation Forest on it** and reported the
   result as the **static baseline** every adaptation gain is measured against.

An unsupervised density estimator fitted where two fifths of the mass is attack
traffic has learned attacks as normal.

### 4.2 The controlled sweep

Corpus, split, seed, detector, threshold and test set fixed; the fit split is
resampled to a **constant 900 rows** at each level so sample count cannot be
confounded with contamination. 10 seeds.

```bash
python -m app.adaptation.experiments.run_contamination_eval --seeds 10 --max-seconds 3600
```

Artifact: `app/evaluation/reports/v6-contamination-20260903T081901Z.json`.

| Fit-set malicious % | ROC-AUC | F1 @ 0.65 | recall | precision | alerts |
| --- | --- | --- | --- | --- | --- |
| **40%** *(as V4/V5 used it)* | 0.5721 | 0.0237 | 0.010 | 0.938 | 1.6 |
| 30% | 0.7014 | 0.0443 | 0.021 | 0.963 | 3.3 |
| 20% | 0.8240 | 0.0947 | 0.051 | 1.000 | 7.9 |
| **12%** *(production-like)* | 0.9000 | **0.2653** | 0.154 | 0.997 | 24.1 |
| 8% *(configured contamination)* | 0.9337 | **0.3390** | 0.207 | 1.000 | 32.3 |
| 4% | **0.9547** | **0.3865** | 0.244 | 0.998 | 38.2 |
| 0% | 0.9274 | 0.0645 | 0.034 | 0.961 | 5.5 |

**Separability rises monotonically as contamination falls**, ROC-AUC 0.572 →
0.955. The detector was never as blind as V4/V5 measured; it was fitted on the
wrong data.

**The 0% row is not a regression in separability** — AUC stays at 0.927. F1
collapses because the *frozen 0.65 threshold* no longer matches an all-benign
training median. That is itself a finding: the 0.65 operating point is tuned to
a contaminated score distribution.

### 4.3 What this does to the V5 adaptation result **[MEASURED]**

Track 1 measured full adaptation (both arms, 5% noise, 50 seeds) at **F1
0.2570**. From the sweep, with **no adaptation at all**:

| | F1 |
| --- | --- |
| V5 static baseline, as reported | 0.0389 |
| **V5 both arms, 50 seeds** | **0.2570** |
| Fitting at 12% contamination, no adaptation | **0.2653** |
| Fitting at 8% contamination, no adaptation | **0.3390** |
| Fitting at 4% contamination, no adaptation | **0.3865** |

**Simply fitting on production-like data matches the entire adaptation loop, and
fitting cleaner beats it.** The V5 gain is real and was honestly measured, but a
large part of what adaptation achieved was repairing a fit set that should not
have been 40% malicious.

This is not a claim that adaptation is worthless — the two are not exclusive, and
adaptation operates where a clean fit set is not simply available. It is a claim
that **the static baseline was a misconfigured comparator**, which inflates every
"× improvement" framing derived from it.

### 4.4 It also explains Track 1's noise sensitivity **[MEASURED]**

§1.3 found that label noise degrades adaptation (F1 0.2826 → 0.2570 → 0.2110,
d = 1.44) and that **curation** is the noise-sensitive component — contradicting
V5's claim that curation is robust to noise. The mechanism was unexplained.

It is contamination. Curation drops rows an analyst called malicious, so it *is*
a contamination reduction, and label noise decides how much survives:

| Noise | fit malicious % before | after curation | fit size after |
| --- | --- | --- | --- |
| 0% | 40.0% | **26.6%** | 1,275 |
| 5% | 40.0% | **27.8%** | 1,267 |
| 15% | 40.0% | **30.4%** | 1,250 |

Read against §4.2, where AUC and F1 change steeply across exactly that 26–30%
band: more noise leaves more contamination, and more contamination costs
detection. The causal chain is complete, and it is the same variable throughout.

Note also that curation only reaches ~27%, well short of the 8–12% where the
detector performs best. **Curation is a partial, indirect fix for a problem that
can be fixed directly.**

### 4.5 Limitations **[LIMITATION]**

1. The corpus is synthetic, and by its own provenance out of distribution for
   this model. These numbers bound an experimental artefact, not production.
2. The 40% row uses a 900-row fit set and is **not** identical to V5's static
   baseline, which used the full 1,560-row split (F1 0.0389). The sweep is
   internally valid; cross-comparison to §1 is indicative, not exact.
3. Production's ~12% figure counts *suspicious scenarios* in an unlabelled
   generator, not verified malicious events. It is an estimate of composition,
   not a measured contamination rate.
4. Nothing here is deployed. The production model is unchanged.

### 4.6 What should follow **[INFERENCE]**

The V4/V5 evaluation substrate, not the adaptation machinery, is now the
weakest link. Before Track 2 spends more seeds characterising feedback quality
against a misconfigured baseline, the baseline should be re-established on a fit
set whose composition resembles production. Track 2's question — how feedback
quality affects adaptation — is worth asking, but its answer will be about
contamination repair unless the substrate is fixed first.

## 5. Reproducing

```bash
cd backend
export DATABASE_URL="sqlite:///aegisx.db"

# section 1
python -m app.adaptation.experiments.run_adaptation_eval --seeds 50 --max-seconds 5400

# section 2
python -m app.adaptation.experiments.run_novel_behaviour_eval --seeds 10 --max-seconds 3600

# section 3
python -m app.adaptation.experiments.run_detector_comparison --seeds 10 --max-seconds 5400

# section 4
python -m app.adaptation.experiments.run_contamination_eval --seeds 10 --max-seconds 3600
```

Timestamped reports under `app/evaluation/reports/` are committed as immutable
evidence; the `latest-*` pointers are not, being mutable by construction.
