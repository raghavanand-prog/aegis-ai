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

## 5. The baseline, re-established **[MEASURED]**

§4 showed the V4/V5 static baseline was produced by re-fitting on a
40%-malicious corpus. This section measures the baseline in the configuration
**production actually uses**, so every later comparison has an honest comparator.

### 5.1 What production actually does

`train_anomaly_model` fits the **runtime telemetry generator's** corpus — 6,000
unlabelled vectors over 14 simulated days, ~12% suspicious scenarios,
`contamination=0.08`, 200 estimators. The labelled corpus is used **only for
scoring**. V4 and V5's experiments re-fitted on the labelled corpus instead.

Scoring here holds Track 1's corpus, split (`d349ea18a04e06c0`) and frozen 0.65
threshold fixed, so the number is directly comparable to the static baseline it
replaces. **Only the fitting data changes.** Measured fit/scoring overlap: **0**.

```bash
python -m app.adaptation.experiments.run_production_baseline_eval --seeds 10 --max-seconds 3600
```

Artifact: `app/evaluation/reports/v6-production-baseline-20260903T082627Z.json`.

### 5.2 The re-established baseline, 10 seeds

| | threshold | Precision | Recall | F1 | FPR | alerts |
| --- | --- | --- | --- | --- | --- | --- |
| **Production configuration** | 0.650 | 0.590 | 0.731 | **0.6526** | 0.340 | 193.5 |
| + Arm 1 threshold adaptation | 0.648 | 0.598 | 0.753 | **0.6627** | 0.348 | 198.9 |

ROC-AUC **0.7615** (sd 0.0212).

**This independently reproduces V4 §19.12**, which measured the deployed artifact
at F1 0.663 and 33.3% FPR. Two different code paths, the same answer — good
evidence the measurement is sound.

### 5.3 What it does to every prior comparison

| Configuration | F1 |
| --- | --- |
| V5 static baseline — refit on 40%-malicious corpus | 0.0389 |
| V5 both arms, 50 seeds (§1) | 0.2570 |
| Refit at 12% contamination, no adaptation (§4) | 0.2653 |
| **Production configuration, no adaptation** | **0.6526** |
| Production configuration + Arm 1 | **0.6627** |

**The full V5 adaptation loop reaches about 39% of the F1 that the unmodified
production configuration already achieves.** The V5 numbers were correctly
measured; the baseline they were measured against was misconfigured by a factor
of roughly seventeen.

**This is not "adaptation is worthless".** Two honest qualifications:

1. **The operating points differ sharply.** Production runs high-recall /
   high-FPR (R 0.73, FPR 34%); V5's adapted model ran high-precision /
   low-recall (P 0.86, R 0.15, FPR 1.7%). F1 strongly favours production; an
   operator drowning in 193 alerts per 390 events might not. These are different
   policies, not simply better and worse.
2. **Distribution shift is real but smaller than contamination.** The production
   fit is *out of distribution* for this test set — a different generator —
   giving AUC 0.762, while an in-distribution refit at 4% contamination reaches
   0.955 (§4.2). Both effects are present; contamination is the larger.

### 5.4 Arm 1 barely helps a correctly-fitted model **[MEASURED]**

Threshold adaptation moves the operating point from 0.650 to **0.648** and F1
from 0.6526 to 0.6627 — **+0.010**. Against a correctly-fitted model the frozen
threshold is already near-optimal, and there is very little for Arm 1 to
recover. Compare Track 1, where the same arm was worth far more precisely
because the model underneath it was misfitted.

### 5.5 Arm 2 is not applicable in production **[IMPLEMENTATION]**

Curation purifies the fit set. **Production's fit set is unlabelled runtime
telemetry, not observed events**, so analyst labels have nothing there to
purify.

V5's Arm 2 implicitly assumes the fit set and the observed event stream are the
same collection. In the experiments they were — which is exactly why curation
appeared to work, since it was removing the 40% contamination §4 identified. In
production they are different collections, and the arm as designed has no
surface to act on.

**[INFERENCE]** This is the most consequential architectural finding in V6 so
far. Of V5's two adaptation arms, one is worth +0.010 F1 against a correct
baseline and the other cannot run in the production configuration at all. Making
Arm 2 real would mean feeding observed, analyst-labelled events into the
training corpus — which is a genuine design change, not a tuning question, and
should be designed deliberately rather than inherited.

### 5.6 Limitations **[LIMITATION]**

1. Both corpora are synthetic. This re-establishes an *experimental* baseline.
2. The ~12% production figure counts suspicious *scenarios* in an unlabelled
   generator, not verified malicious events.
3. A 34% false-positive rate is not obviously an acceptable operating point;
   "better F1" is not "deployable".
4. Nothing here is deployed or registered. The production model is unchanged.

## 6. Arm 2, redesigned **[MEASURED]**

§5.5 established that V5's Arm 2 cannot run in the production configuration:
curation purifies the fit set, and production's fit set is unlabelled telemetry
rather than observed events. This redesigns it so it has a surface to act on.

### 6.1 The design

V5's arm *removed* analyst-identified malicious rows from a corpus of observed
events. The redesign *adds* analyst-verified **benign** observed events to the
telemetry corpus:

```
telemetry corpus (unlabelled, 6,000 rows)
  + observed events an analyst verified benign
  − anything called malicious, suspicious or uncertain
  bounded by max_feedback_fraction
```

An Isolation Forest consumes "here is more traffic that is normal" natively —
that is what a fit set *is*. And it targets the weakness §5 measured, a **34%
false-positive rate**, using the most abundant signal a real SOC produces:
false-positive triage.

**This is a poisoning surface and is treated as one.** Adding analyst-supplied
rows to training data means a mistaken or hostile analyst could teach the model
that an attack is normal. Three bounds, each asserted by test:

1. **Admission is positive-listed** — a row enters only if its label is
   training-eligible *and* projects to benign. `confirmed_malicious`,
   `true_positive`, `suspicious` and `uncertain` are all refused.
2. **The feedback share is capped**, bounding the blast radius of bad labels
   however many arrive. Measured: at a 0.05 cap the bound binds (315 rows,
   4.99%); at 0.20 the natural volume is 399 rows (6.2%) and the cap does not
   bind. **It is a safety bound, not a tuning knob.**
3. **The telemetry corpus is augmented, never replaced.**

An adversarial regression test labels *every* event benign, including genuinely
malicious ones, and asserts the cap still holds.

```bash
python -m app.adaptation.experiments.run_arm2_eval --seeds 10 --max-seconds 3600
```

Artifact: `app/evaluation/reports/v6-arm2-20260903T083516Z.json`.

### 6.2 Result — it does what it was designed to do

10 seeds, 6,000 telemetry rows + 399 feedback rows (6.2%), of which 9 were
mislabelled by the simulated analyst. CI95 is a percentile bootstrap.

| Metric | Production baseline | + redesigned Arm 2 | Cohen's d |
| --- | --- | --- | --- |
| **False-positive rate** | 0.3397 [0.315, 0.370] | **0.2624** [0.240, 0.284] | **−1.81** |
| Precision | 0.5903 [0.568, 0.612] | **0.6345** [0.613, 0.658] | +1.21 |
| Recall | 0.7308 [0.708, 0.756] | 0.6795 [0.655, 0.706] | −1.23 |
| ROC-AUC | 0.7615 [0.749, 0.775] | **0.7862** [0.776, 0.797] | +1.24 |
| F1 | 0.6526 [0.633, 0.674] | 0.6554 [0.638, 0.678] | **+0.09** |

**False positives fall by 7.7 points — a 23% relative reduction — with
non-overlapping intervals and a large effect size.** Alert volume drops from
193.5 to 167.4 per 390 events. Separability genuinely improves (AUC +0.025), so
this is not purely an operating-point shift.

**F1 barely moves, and reporting this as an F1 result would misdescribe it.**
The arm trades recall (−0.051) for precision (+0.044), which roughly cancels in
F1. Whether that trade is good is an operator's judgement, not a metric's: it is
26 fewer alerts per 390 events at the cost of missing about 5% more attacks.

### 6.3 This answers V5's RQ1, which V5 could not test

V5 asked *"Can analyst feedback reduce false positives?"* and had to answer
**"Not tested as framed"** — its misconfigured baseline had FPR 0.0%, so there
was no false-positive problem to solve. Against a correctly-fitted baseline at
34% FPR, the answer is **yes, measurably**: 0.3397 → 0.2624, d = −1.81.

The question was always the right one. It needed a correct baseline to become
answerable.

### 6.4 Limitations **[LIMITATION]**

1. Feedback is simulated; there is no analyst population.
2. Both corpora are synthetic.
3. The recall cost is real and is not obviously acceptable — this is a policy
   trade, not a free improvement.
4. The poisoning bound is tested against a naive all-benign adversary. A
   targeted adversary who labels only the events resembling their intended
   attack is not modelled, and would be a more informative test.
5. Nothing is deployed. Reaching production still requires an approved proposal
   and `activate_model`.

## 7. Track 2 — feedback quality **[MEASURED]**

Track 2 was designed against V5's Arm 2, which §6 replaced. That narrows the
question usefully: the redesigned arm admits analyst-verified **benign** rows
into training data, so the conditions that matter are the ones pushing analysts
toward "benign" — simultaneously a quality problem and a poisoning vector.

Ground truth, analyst labels and model predictions stay separate throughout, as
V5 required. `nominal` reproduces the Track 1 settings and is the control.

```bash
python -m app.adaptation.experiments.run_feedback_quality_eval --seeds 10 --max-seconds 5400
```

10 seeds, 10 conditions. Artifact:
`app/evaluation/reports/v6-feedback-quality-20260903T084844Z.json`.

### 7.1 Results

Deltas against the production baseline (FPR 0.3397, recall 0.7308). Negative
ΔFPR is good; negative Δrecall is a cost.

| Condition | rows | poisoned | realised error | ΔFPR | Δrecall |
| --- | --- | --- | --- | --- | --- |
| clean | 472 | 0 | 0.0% | **−0.0859** | −0.0692 |
| **benign_biased** | 490 | 83.5 | 13.2% | **−0.1103** | **−0.0705** |
| nominal | 421 | 14.2 | 4.4% | −0.0774 | −0.0513 |
| high_noise | 403 | 42.6 | 13.8% | −0.0761 | −0.0429 |
| conflicting | 436 | 9.4 | 3.1% | −0.0748 | −0.0551 |
| severe_noise | 379 | 84.3 | 27.5% | −0.0727 | −0.0500 |
| malicious_biased | 318 | 14.2 | 17.4% | −0.0269 | −0.0167 |
| uncertain_heavy | 284 | 10.0 | 2.9% | −0.0145 | −0.0083 |
| **delayed** | 148 | 14.2 | 4.4% | **+0.0218** | −0.0026 |
| **sparse** | 87 | 3.1 | 3.9% | **+0.0714** | +0.0154 |

### 7.2 Label noise barely matters — and this reverses Track 1

ΔFPR is −0.0774 at nominal, −0.0761 at 15% noise and **−0.0727 at 27.5%
realised error**. The arm absorbs severe label noise almost intact.

That is the **opposite** of §1.3, where noise degraded V5's curation arm with
d = 1.44. Both findings are correct, and §4 explains why they differ: V5's
curation *removed* rows from a 40%-contaminated fit set, so every mislabelled
row left contamination behind. The redesigned arm *adds* rows to a 6,000-row
telemetry corpus, where a few dozen mislabelled rows are diluted below the level
that moves a density estimate.

**Noise sensitivity was a property of the broken configuration, not of feedback
adaptation.** Track 2's original framing — how much noise can adaptation
tolerate — turns out to be the wrong question for a correctly-configured system.

### 7.3 The finding that matters: FPR hides the poisoning vector

**`benign_biased` produces the *best* false-positive reduction of any condition**
(−0.1103, better than `clean`), while carrying 83.5 mislabelled malicious rows
into training data.

It also produces the **worst recall loss** (−0.0705).

| Condition | ΔFPR | ΔF1 | ΔROC-AUC | Δrecall |
| --- | --- | --- | --- | --- |
| nominal | −0.0774 | +0.0028 | +0.0248 | −0.0513 |
| **benign_biased** | **−0.1103** | **+0.0046** | **+0.0348** | **−0.0705** |

**FPR, F1 and ROC-AUC all say benign bias is an improvement. Only recall reveals
the cost.** A safety gate or dashboard watching false-positive rate, F1 or AUC
would score analysts-clearing-alerts-under-pressure as the best feedback the
system had ever received.

**[INFERENCE]** This is the most operationally important result in V6. It says
the metric an FPR-reduction feature most naturally reports is precisely the
metric that cannot detect its characteristic failure. Any gate on this arm must
include a recall floor.

Why the cap holds anyway: 83.5 poisoned rows sit in ~6,490 total (1.3%), inside
what the density estimate tolerates. The bound from §6.1 is doing its job — but
it is doing it against *diffuse* poisoning.

### 7.4 Volume is a precondition, not a dial

**`sparse` and `delayed` make the model worse, not merely less good.** Sparse
feedback (87 rows) *raises* FPR by 0.0714 and drops precision to 0.550 while
alert volume climbs to 212.6. Delayed feedback (148 rows) raises FPR by 0.0218.

Below roughly 300 rows the augmentation stops helping and starts perturbing the
fit. That is a deployment precondition with a number attached: **this arm should
not run until enough verified-benign feedback has accumulated**, and a system
that enabled it on day one would degrade the detector it was meant to improve.

`malicious_biased` (318 rows) and `uncertain_heavy` (284 rows) sit just above the
threshold and deliver correspondingly weak benefit — consistent with volume, not
bias, being the binding variable for those two.

### 7.5 Limitations **[LIMITATION]**

1. Poisoning here is **diffuse** — randomly chosen malicious events. A targeted
   adversary labelling one attack category benign is not modelled and would be a
   more informative test. §6.4 flags the same gap; it remains the most important
   untested case.
2. Feedback is simulated. There is no analyst population, and the conditions are
   models of analyst failure modes rather than observations of them.
3. Both corpora are synthetic.
4. The ~300-row threshold is specific to this corpus and telemetry size; it is
   an existence proof that a threshold exists, not a transferable constant.
5. Nothing is deployed.

## 8. Targeted poisoning — the recall floor is not enough **[MEASURED]**

§6.4 and §7.5 both flagged this as the most important untested case. §7 measured
*diffuse* poisoning and concluded that recall was the one aggregate metric that
exposed it. This tests whether that holds against an adversary who concentrates.

### 8.1 Threat model

A **compromised, coerced or simply careless analyst with ordinary feedback
permissions**. No privileged access, no code execution, nothing RBAC would
refuse. They label events of one chosen attack category benign and let the
adaptation pipeline carry it into the fit set.

**Every existing control is respected.** Only benign-projecting labels are
admitted; the feedback cap holds; deployment still requires an approved
proposal. The question is not whether the controls run — it is whether they are
*sufficient*.

```bash
python -m app.adaptation.experiments.run_targeted_poisoning_eval --seeds 8 --max-seconds 5400
```

Artifact: `app/evaluation/reports/v6-targeted-poisoning-20260903T090030Z.json`.

### 8.2 Result — the aggregate hides it beneath its own noise

| Target | poisoned rows | Δ target recall | Δ aggregate recall | attenuation |
| --- | --- | --- | --- | --- |
| **MALWARE** | 22.0 | **−0.2026** | −0.0232 | **8.7×** |
| PORT_SCAN | 22.5 | −0.0706 | −0.0144 | 4.9× |
| BRUTE_FORCE | 25.4 | −0.0007 | −0.0024 | n/a |
| RANSOMWARE | 23.6 | 0.0000 | −0.0080 | n/a |
| SUSPICIOUS_DNS | 23.8 | 0.0000 | +0.0088 | n/a |

For MALWARE, over 8 seeds:

| | baseline | poisoned | Cohen's d |
| --- | --- | --- | --- |
| **Target recall** | 0.8079 [0.703, 0.912] | **0.6052** [0.334, 0.836] | −0.67 |
| Aggregate recall | 0.6795 [0.652, 0.711] | 0.6563 [0.621, 0.691] | −0.46 |

**The aggregate recall intervals overlap.** And the decisive number:

> Aggregate recall's **seed-to-seed standard deviation is 0.0426**. The attack
> moves aggregate recall by **−0.0232** — **less than half the noise floor.**

**An aggregate recall floor cannot detect this attack.** To catch a 20-point
collapse in one category it would have to trigger on a 2-point aggregate move,
which is well inside normal seed variance and would fire constantly on nothing.
The mitigation §7.3 recommended is **insufficient as stated**, and this section
supersedes it.

Note also that **ΔFPR is negative in four of five targets** — the attack
continues to look like an improvement on the metric the arm exists to optimise.

### 8.3 Why the cap does not help

The feedback cap bounds **volume**. Targeted poisoning is a **concentration**
attack: it needed only **22 rows** — 0.34% of the fit set, far inside a cap set
at 20%. A volume control cannot bound concentration, and no setting of
`max_feedback_fraction` short of zero would have stopped this.

**[INFERENCE]** The natural defence is a **per-category (or per-analyst) cap**
rather than a global one, plus per-category recall tracking. Neither is
implemented; both are recommendations, not results.

### 8.4 What limits the attack

Reported because they are genuine mitigating factors, not to soften the finding:

1. **It only works on categories the detector already detects well.** MALWARE
   (baseline recall 0.81) and PORT_SCAN (0.45) are damaged; RANSOMWARE (1.00,
   strongly separated) is untouched, and SUSPICIOUS_DNS (0.05) and BRUTE_FORCE
   (0.01) have no recall left to remove. **[INFERENCE]** An adversary must
   therefore attack the categories the SOC is *best* at, which is where a
   defender is most likely to notice operationally.
2. **It needs high reach over its target.** A reach sweep on MALWARE: at 0.25
   reach (6 rows) target recall is 0.834 and at 0.5 (12 rows) it is 0.857 —
   both at or above the 0.808 baseline, i.e. no damage. Only full reach (22
   rows) bites, at 0.605. The attack is not cheap; a partial adversary achieves
   nothing.

### 8.5 Limitations **[LIMITATION]**

1. Per-category recall is measured over a few dozen held-out samples, so its
   intervals are wide ([0.334, 0.836] for poisoned MALWARE). **The attenuation
   ratio and the noise-floor comparison are the robust parts of this result; the
   per-category point estimates are not.**
2. Only five categories were targeted, at one reach value for the main sweep.
3. The adversary is modelled as labelling one category. A patient adversary
   spreading a small attack across several categories, or across time, is not
   modelled.
4. Feedback is simulated; both corpora are synthetic.
5. Nothing is deployed, and no defence is implemented.

## 9. A defence that works — the per-group cap **[MEASURED]**

§8 left targeted poisoning as a documented, undefended vulnerability. This
implements and tests the defence it recommended.

### 9.1 Why the obvious defence fails

Measured honest behaviour, admitted-benign rows per `event_type` over 8 seeds:

| | | | |
| --- | --- | --- | --- |
| auth_success | 114.6 | credential_access | 1.6 |
| firewall_allow | 84.5 | **malware_detected** | **1.4** |
| process_creation | 58.5 | data_exfiltration | 1.2 |
| antivirus_scan | 46.9 | ransomware_behavior | 1.1 |

Under attack, `malware_detected` supplies **22**.

The discriminating signal is **not** that a group is large — `auth_success`
legitimately supplies 114 — but that **a group almost never legitimately called
benign suddenly is**. So a flat per-group ceiling cannot work: any value
permitting 114 also permits 22.

Grouping is by `event_type`, which the **normalizer** produces before any
detection or labelling. It is deliberately *not* the ground-truth attack
category — production does not have that, and a defence keyed on it could not
ship.

### 9.2 Three policies, measured

Target MALWARE, 8 seeds, full adversary reach. The `baseline_relative` policy
admits up to `tolerance × baseline` rows per group (tolerance 3.0, chosen before
measuring), with a floor of 2 for unseen groups. Its baseline is learned from
**held-out honest seeds** — learning it from the attacked stream would teach it
the attack as normal.

| Policy | poisoned rows | Δ target recall | honest feedback rows | honest-augmented FPR |
| --- | --- | --- | --- | --- |
| **global** (status quo) | 22.0 | **−0.2026** | 421 | 0.2537 |
| per_group_absolute = 25 | 21.9 | −0.0271 | **200** | **0.3504** |
| **baseline_relative** | **4.0** | **+0.0101** | 421 | 0.2537 |

Against §5's telemetry-only baseline of **FPR 0.3397**:

- **`baseline_relative` neutralises the attack at no cost.** Poisoned rows fall
  22 → 4 (−82%), target recall under attack goes to **+0.0101** — statistically
  indistinguishable from the unattacked model — and it keeps **all 421** honest
  feedback rows and the full FPR benefit (0.3397 → 0.2537).
- **`per_group_absolute` is the worst of both.** It does not stop the attack
  (21.9 of 22 poisoned rows admitted, because 22 < the ceiling of 25) *and* it
  destroys half the honest feedback (421 → 200), leaving FPR at **0.3504 —
  worse than using no feedback at all.** The naive defence is actively harmful.

**[LIMITATION]** `per_group_absolute`'s Δ target recall (−0.027) is not
comparable to the others: capping also weakens the *unattacked* arm it is
measured against, which moves its own baseline (target recall 0.9286 rather than
0.8079). Its poisoned-row count and honest-feedback cost are the interpretable
figures.

### 9.3 What this defence depends on **[LIMITATION]**

1. **A trusted baseline.** `baseline_relative` needs honest per-group rates. An
   adversary patient enough to poison the baseline itself — contributing
   slightly elevated `malware_detected` benign labels over many cycles until the
   baseline rises — would defeat it. This is a real weakness, not a hypothetical
   one, and it is **not tested here**.
2. **`event_type` tracks attack category almost perfectly in this corpus** (
   MALWARE → `malware_detected`, PORT_SCAN → `firewall_deny`). On real telemetry
   an attack spans many event types and a defender's grouping is correspondingly
   blunter. **This result flatters the defence**, and the honest reading is that
   the *mechanism* is sound rather than that the effect size transfers.
3. Only MALWARE was used for the policy comparison.
4. The tolerance of 3.0 and floor of 2 were chosen before measuring, but not
   tuned or swept.
5. Nothing is deployed. This is an experimental cap, not a change to the
   production adaptation path.

### 9.4 Status of the §8 vulnerability

**Mitigated in the experimental pipeline, not closed in production.** The cap
lives in `app/adaptation/experiments/feedback_caps.py` and is exercised by the
targeted-poisoning harness. Wiring it into the production adaptation path,
together with the per-category recall tracking §8.2 showed is necessary, remains
outstanding work.

## 10. Wired into the production path **[IMPLEMENTATION]**

§§6–9 were measured in the experiment harness. This section is the code change
that puts them on the path a real candidate takes.

### 10.1 What was actually wrong

`train_candidate` accepted `feedback_dataset_id` and recorded it in the model's
parameters. **It did nothing else with it.** The fit set was the telemetry
corpus and nothing but the telemetry corpus, so analyst feedback had never
influenced production candidate training — consistent with §5.5, and stronger:
not merely inapplicable, but unwired.

### 10.2 Three changes

**1. The cap moved into production.**
`app/adaptation/experiments/feedback_caps.py` → `app/adaptation/feedback/caps.py`.
Policy code cannot live under `experiments/` if the production trainer calls it.
Import-only move; the §9 experiments still pass against the new location.

**2. A per-category recall gate.** `GatePolicy` gains
`max_per_category_recall_drop` (0.10) and `min_category_samples` (10);
`evaluation.py` now scores every candidate and baseline per attack category and
feeds both into the gate and into the report's new `perCategory` block.

The bound is **looser** than the aggregate recall bound (0.05) on purpose:
per-category recall is measured over far fewer samples and §8.5 measured
intervals as wide as [0.334, 0.836]. A tighter bound would veto on noise.

When no per-category data is supplied the check is **advisory, not a veto** —
every pre-V6 caller passes none, so vetoing would reject every candidate
outright. The absence is surfaced to the approver rather than counted as a pass,
which is what `GateCheck.advisory` already existed for. A category measured on
the incumbent but missing from the candidate **fails**: the candidate has not
been shown safe on it.

**3. `app/adaptation/feedback/augmentation.py`** turns a feedback dataset into
rows a candidate may be fitted on, and `train_candidate` appends them.

| Property | Behaviour |
| --- | --- |
| Admission | `binary_label is False` only — verified benign. `true_positive` and `confirmed_malicious` refused |
| Target type | events only; incidents and sequences have no single vector, skipped and **counted** |
| Vector source | the stored `MLInference` row — the vector the model actually scored |
| Vector order | rebuilt in `feature_names` order, never the stored JSON key order |
| Incomplete vector | refused, never padded |
| Cap | `caps.apply`, default `global` (pre-V6 behaviour preserved) |
| Provenance | admitted count, per-group counts, cap policy and every skip reason recorded on the model |

**The vector comes from the stored inference, not from the event's columns.**
Re-deriving would risk training on a vector that was never the one the analyst's
verdict referred to, and the mismatch would be silent.

### 10.3 The safe policy is the default

`cap_policy` defaults to **`baseline_relative`** — the policy §9 measured stops
targeted poisoning. `global`, which §9 measured admitting 21.9 of 22 poisoned
rows, is now an explicit opt-out. With no `feedback_dataset_id` the fit set is
telemetry alone, unchanged from V5 and asserted by test.

```bash
python -m app.adaptation.candidates.train_candidate --feedback-dataset-id 7
```

**Flipping the default was not a one-line change**, and the reason is worth
recording. `baseline_relative` needs per-group rates; with none supplied every
group falls to the floor. Measured: **6 rows admitted of 220**. §7.4 measured
that feedback that sparse makes the model *worse* than no feedback at all, so a
naive flip would have silently gutted the arm it protects.

Two things make the default safe:

1. **Rates are derived when not supplied**, from prior feedback datasets
   *excluding the batch being admitted* — the production analogue of §9's
   held-out honest seeds. A baseline computed over the dataset under review
   would learn that batch's own spike as normal. `baselineRatesDerived` is
   recorded on the model, so an approver knows which happened.
2. **A cold start is refused, not degraded.** With no feedback history there is
   nothing to be relative to, and admitting a handful of rows is worse than
   admitting none. The error names the opt-out rather than leaving the operator
   to find it.

**[INFERENCE]** A first batch with no history is a legitimate reason to choose
`global`: there is no established baseline for an attacker to hide beneath
either. The point is that it is now a decision an operator makes deliberately,
not one they inherit.


### 10.4 What is still not closed **[LIMITATION]**

1. **The baseline is only as trustworthy as the history it reads.** §9.3's
   patient adversary — raising the baseline across several datasets — defeats
   it, and is still untested. Making the derived baseline the default makes this
   **more** load-bearing, not less: it is now consulted on every run.
2. **No live analyst feedback exists**, so the wiring is exercised by tests and
   synthetic corpora, not by use.
3. `activate_model` behind an approved proposal remains the only write into
   production detection state. None of this changes that; V5's deployment,
   registry-immutability and proposal suites pass unchanged.

## 11. Reproducing

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

# section 5
python -m app.adaptation.experiments.run_production_baseline_eval --seeds 10 --max-seconds 3600

# section 6
python -m app.adaptation.experiments.run_arm2_eval --seeds 10 --max-seconds 3600

# section 7
python -m app.adaptation.experiments.run_feedback_quality_eval --seeds 10 --max-seconds 5400

# section 8
python -m app.adaptation.experiments.run_targeted_poisoning_eval --seeds 8 --max-seconds 5400

# section 9 - one run per policy
python -m app.adaptation.experiments.run_targeted_poisoning_eval --seeds 8 --targets MALWARE --cap-policy baseline_relative --max-seconds 3600
```

Timestamped reports under `app/evaluation/reports/` are committed as immutable
evidence; the `latest-*` pointers are not, being mutable by construction.
