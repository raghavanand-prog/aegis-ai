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

## 2. Track 3 — a confound in the V5 novel-behaviour result **[IMPLEMENTATION]**

Recorded here before Track 3 runs, because it changes how V5 §3 should be read.

`scenarios.run_new_behaviour` withholds one attack category from the fit set,
then simulates feedback from `fit_labels` — which is derived from the fit set
the category was just removed from. **No verdict about the withheld category
ever reaches the adaptation loop.** The threshold is likewise chosen only from
fit-set scores. The function's own docstring says "adaptation then happens on
feedback that includes it"; the code does not.

V5 §3 reported recall 0.000 → 0.0085 on withheld categories and concluded
"**RQ4 is answered no**, measurably". The measurement stands. The conclusion is
stronger than the harness supports: the experiment cannot distinguish

- *curation cannot teach a pattern the model has never seen* (V5's reading, and
  mechanically plausible — curation only removes rows), from
- *the loop was never told the pattern existed*.

**[LIMITATION]** Additionally, `run_new_behaviour` has no test and no CLI
runner. Nothing in the repository calls it. V5 §3's numbers were produced by an
ad-hoc invocation that was never committed, so they are not reproducible from a
committed command.

Track 3 will run both variants — feedback withheld, and feedback supplied — and
report the pair. **[INFERENCE]** The V5 conclusion may well survive; the point
is that it has not yet been tested as stated.

---

## 3. Reproducing

```bash
cd backend
export DATABASE_URL="sqlite:///aegisx.db"
python -m app.adaptation.experiments.run_adaptation_eval --seeds 50 --max-seconds 5400
```

Timestamped reports under `app/evaluation/reports/` are committed as immutable
evidence; the `latest-*` pointers are not, being mutable by construction.
