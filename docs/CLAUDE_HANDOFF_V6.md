# AEGISX V6 → V7 HANDOFF

> Written at the end of the V6 session for a **fresh Claude Code session**.
> Every claim below was checked against the repository immediately before
> writing, not recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged:

- **[MEASURED]** — a number from a committed, reproducible command, whose
  artifact is committed beside it.
- **[IMPLEMENTATION]** — a fact about the code, verifiable by reading it.
- **[LIMITATION]** — something not established, not measured, or not true.
- **[INFERENCE]** — a judgement. Argue with these freely.

---

## 1. Read this first

The V5 handoff named the wrong checkpoint and said the work was unpushed when it
was not. The Phase A audit of V4 found the same class of error. **Verify §2
before trusting anything else here**, and do the same to this document.

**V6 is not complete against its own brief.** It answered the research questions
it started with and then followed the evidence somewhere the brief did not
anticipate. **Twelve of the brief's twenty definition-of-done items are done;
eight are not**, two of those blocked on the environment. §9 lists them without
softening.

---

## 2. Checkpoint **[MEASURED]**

```
V4 checkpoint:  65a8671   ← intact, verified
V5 checkpoint:  52eea0d   ← intact, verified
V6 checkpoint:  055abfd
```

**Pushed.** `origin/main` is at `055abfd`, identical to `HEAD`; working tree
clean, no divergence. Fast-forward `52eea0d..055abfd`, nothing amended, rebased
or force-pushed.

**14 commits. 53 files changed, +48,367 / −34.** The insertion count is
dominated by committed JSON experiment artifacts, which is deliberate — see §4.

```
5496a22  seed plan, and commit experiment artifacts as immutable evidence
85b0f79  record per-seed results, intervals and control effect sizes
8c56f21  track 1 - the V5 adaptation effect at 50 seeds
47f1de8  track 3 - the novel-behaviour confound is benign, the V5 conclusion is not
1a0e48c  hypothesis 5 - the detector class is the limit, not the features
cb88972  fit-set contamination, not adaptation, explains most of the V5 gain
be989d4  re-establish the baseline in the configuration production uses
6ca75ef  redesign Arm 2 so it can act in the production configuration
1af1b20  track 2 - feedback quality, and the metric that hides the poisoning
c2e5618  targeted poisoning defeats the recall floor section 7.3 recommended
a0eb01b  a per-group feedback cap that blunts targeted poisoning
769a3a3  commit the three per-policy artifacts behind section 9.2
593d325  move the feedback cap into production, add the per-category gate
055abfd  wire the feedback augmentation and its cap into candidate training
```

---

## 3. The one thing to understand about V6

**Every V5 number reproduced exactly.** V5 was not dishonest and its results
were not wrong as measurements.

What V6 found is that **the substrate those measurements sat on was
misconfigured**. V4 and V5 established their static baseline by re-fitting an
Isolation Forest on the labelled evaluation corpus, whose fit split is **40%
malicious** — and whose own provenance already said it was *"out of distribution
for the anomaly model trained on the runtime telemetry generator"*. Production
does not fit that corpus; `train_anomaly_model` fits unlabelled runtime
telemetry at roughly 12% suspicious.

So the comparator that made adaptation look like a 6× improvement was wrong by
roughly 17×, and most of what "adaptation" achieved was contamination repair.

| Configuration | F1 |
| --- | --- |
| V5 static baseline, as reported | 0.0389 |
| V5 both arms, 50 seeds | 0.2570 |
| Refit at 12% contamination, **no adaptation** | 0.2653 |
| **Production configuration, no adaptation** | **0.6526** |

**[MEASURED]** all four. The last independently reproduces V4 §19.12 (F1 0.663,
33.3% FPR) by a different code path, which is the strongest evidence available
that the measurement is sound.

**[INFERENCE]** If you read one thing before changing code, read
`docs/V6_RESEARCH_REPORT.md` §4 and §5. Everything after them is downstream.

---

## 4. Results **[MEASURED]**

All from committed artifacts under `backend/app/evaluation/reports/`.
Corpus `c0f04f3ccb2a63b8`, split `d349ea18a04e06c0` unless stated.

**Track 1 — the V5 effect at 50 seeds.** It survives and sharpens.

| Condition (5% noise) | F1 | sd | CI95 |
| --- | --- | --- | --- |
| static V4 | 0.0389 | 0.0083 | [0.0365, 0.0411] |
| both arms | 0.2570 | 0.0549 | [0.2406, 0.2726] |
| random-label control | 0.1068 | 0.0271 | [0.0997, 0.1145] |

Both arms vs control: Δ 0.1502, **Cohen's d 3.43**, non-overlapping intervals.
V5's caution — a gap of ~1.5 sd over three seeds — is resolved. Mechanism/content
split 31%/69%, against V5's 34%/66% by hand.

**Contamination is the mechanism** behind most of it:

| fit-set malicious % | ROC-AUC | F1 @ 0.65 |
| --- | --- | --- |
| 40% (as V4/V5 used it) | 0.5721 | 0.0237 |
| 12% (production-like) | 0.9000 | 0.2653 |
| 4% | 0.9547 | 0.3865 |

**Production baseline**: AUC 0.7615, F1 0.6526, FPR 0.3397, fitted on 6,000
unlabelled telemetry rows, scored on the same split and frozen 0.65 threshold.

**Redesigned Arm 2**: FPR **0.3397 → 0.2624**, d −1.81, from 399 feedback rows
(6.2% of the fit set). F1 moves +0.003 — it trades recall for precision, and
reporting it as an F1 result would misdescribe it.

**Targeted poisoning**: 22 rows of one event type cost 0.2026 of that category's
recall while aggregate recall moved 0.0232 — **below its own seed noise of
0.0426**. The `baseline_relative` cap cuts admitted poison to 4.0 rows and
restores target recall, at no cost to honest feedback.

---

## 5. Corrections to earlier documents

V6 corrected four V5 conclusions and one of its own. In every case the original
measurement is **retained** and the correction recorded **separately** — nothing
was rewritten to look better.

| Where | What changed |
| --- | --- |
| V5 §2.5 "label noise barely matters" | False at 50 seeds: F1 0.2826 → 0.2110 across 0–15% noise, d 1.44. And the attribution was backwards — curation degrades (d 0.75), threshold selection does not (d 0.03) |
| V5 §3 "RQ4 answered no" | Too strong. Adaptation *does* help on 4 of 13 novel categories (PORT_SCAN 0.2575 → 0.9500). V5's three categories were never recorded, so its 0.0085 **cannot be reproduced** |
| V5 §3 harness | `run_new_behaviour` never gives the loop feedback about the withheld category. Measured as benign in effect — the threshold clamp saturates in 256/260 runs — but the conclusion it supported was stronger than the harness allowed |
| V5 Arm 2 | Not merely inapplicable in production: `train_candidate` recorded `feedbackDatasetId` as metadata and **never used it** |
| **V6 §3.3, mine** | Said the corpus violates the `contamination` *parameter* "by a factor of 5". Direction right, mechanism wrong — `contamination` never reaches `anomaly_score`. Corrected in place with a visible note |
| **V6 §7.3, mine** | Recommended an aggregate recall floor. §8 measured that it cannot work. §8 supersedes it |

---

## 6. What changed in the production path **[IMPLEMENTATION]**

Three changes reach code a real candidate touches. Everything else in V6 is
experiment harness.

1. **`app/adaptation/feedback/caps.py`** (moved from `experiments/`). Three cap
   policies. `baseline_relative` is the one §9 measured as effective.
2. **`app/adaptation/candidates/gates.py`** — `max_per_category_recall_drop`
   (0.10) and `min_category_samples` (10), plus `_per_category_check`.
   `evaluation.py` now scores per attack category and reports `perCategory`.
   **Advisory when per-category data is absent**, a hard veto when supplied.
3. **`app/adaptation/feedback/augmentation.py`** — turns a feedback dataset into
   fittable rows; `train_candidate` appends them. Admission is positive-listed
   on `binary_label is False`; vectors come from the stored `MLInference` row,
   rebuilt in `feature_names` order; non-event targets and incomplete vectors
   are skipped **and counted**.

**No `feedback_dataset_id` means telemetry alone**, exactly as V5 — asserted by
test. `cap_policy` defaults to **`baseline_relative`**, the policy V6 §9
measured stops targeted poisoning; `global` is an explicit opt-out. The default
derives its per-group baseline from prior feedback datasets, excluding the batch
being admitted, and **refuses a cold start** rather than degrading silently —
with no baseline every group falls to the floor, a measured 6 rows of 220, and
§7.4 measured feedback that sparse is worse than none.

**No new migrations. No schema change. No frontend change.** Head is still
`0009_v5_proposals`; migrations round-trip base→head→base→head on SQLite.

---

## 7. Verification at checkpoint **[MEASURED]**

Run immediately before writing this, on `055abfd`:

| Check | Result |
| --- | --- |
| `pytest` | **660 passed** (535 at V5) |
| `ruff check .` | clean |
| `vitest run` | **50 passed**, 8 files |
| `eslint .` | clean (exit 0) |
| `tsc -b --noEmit` | clean (exit 0) |
| `vite build` | PASS (chunk-size warning, pre-existing) |
| Migrations base→head→base→head | PASS (SQLite), head `0009_v5_proposals` |

45 test modules. New in V6: `test_adaptation_arm2.py`,
`test_adaptation_augmentation.py`, `test_adaptation_candidate_detectors.py`,
`test_adaptation_contamination.py`, `test_adaptation_feedback_caps.py`,
`test_adaptation_feedback_quality.py`, `test_adaptation_production_baseline.py`,
`test_adaptation_targeted_poisoning.py`.

---

## 8. Reproducing everything

```bash
cd backend
export DATABASE_URL="sqlite:///aegisx.db"

python -m app.adaptation.experiments.run_adaptation_eval           --seeds 50 --max-seconds 5400
python -m app.adaptation.experiments.run_novel_behaviour_eval      --seeds 10 --max-seconds 3600
python -m app.adaptation.experiments.run_detector_comparison       --seeds 10 --max-seconds 5400
python -m app.adaptation.experiments.run_contamination_eval        --seeds 10 --max-seconds 3600
python -m app.adaptation.experiments.run_production_baseline_eval  --seeds 10 --max-seconds 3600
python -m app.adaptation.experiments.run_arm2_eval                 --seeds 10 --max-seconds 3600
python -m app.adaptation.experiments.run_feedback_quality_eval     --seeds 10 --max-seconds 5400
python -m app.adaptation.experiments.run_targeted_poisoning_eval   --seeds 8  --max-seconds 5400 \
    --targets MALWARE --cap-policy baseline_relative
```

Total well under one CPU-hour. **[IMPLEMENTATION]** `app/adaptation/experiments/seeds.py`
holds one standing seed plan in which a longer plan *extends* a shorter one, so
`--seeds 3` still reproduces V5 exactly and every V6 run stays comparable with
the last.

**Report retention changed in V6.** Timestamped reports are now **committed** as
immutable evidence; only the mutable `latest-*` pointers are ignored. V4 and V5
published every number from gitignored local files.

---

## 9. What V6 did NOT do **[LIMITATION]**

Twelve of the brief's twenty definition-of-done items are done. **These eight
are not** — items 5, 6, 7, 8, 9, 10, 11 and 17 of the brief:

1. **No telemetry-source integration.** `backend/app/telemetry/` is untouched —
   0 files changed. Track 4 was never started.
2. **No telemetry-source abstraction work.** The `TelemetrySource` ABC from V1
   is unchanged. **The Phase A audit found `telemetry/normalizer.py` hard-codes
   vendor schemas (`_normalize_defender` and friends); that leak is documented
   and unfixed.** Adding a source by appending another branch would deepen it.
3. **No PostgreSQL validation.** Docker daemon was down for the whole session;
   no `psql`, no `pg_isready`. Everything is SQLite.
4. **No live external provider.** No `.env`, no API key. `threatintel/providers/`
   still has `virustotal.py` + `null.py`; nothing live was called.
5. **No four-eyes decision.** `self_approved` is still recorded and not
   prevented, exactly as V5 left it.
6. **No approval-latency measurement or simulation.**
7. **No dashboard work.** `frontend/` is untouched — 0 files changed. Adaptive
   SOC observability is exactly as V5 left it, and none of V6's new
   provenance (`perCategory`, `augmentation`) is visible in the UI.
8. **Documentation debt.** Only `docs/V6_RESEARCH_REPORT.md` was added.
   `REPRODUCIBILITY.md`, `ADAPTATION_CARD.md`, `MODEL_CARD.md` and
   `ARCHITECTURE.md` now describe a system that has changed underneath them.

Also unresolved, and load-bearing:

9. **The patient baseline-poisoning adversary is untested.** §9's defence
   learns its baseline from feedback history; an adversary who raises that
   baseline across several datasets defeats it. **This is now more load-bearing,
   not less**: since `baseline_relative` became the default, the baseline is
   consulted on every run.
10. **`event_type` tracks attack category almost perfectly in this corpus**, so
    §9's result **flatters the defence**. The mechanism is sound; the effect size
    is unlikely to transfer to real telemetry where an attack spans many event
    types.
11. **All feedback is still simulated.** No analyst population exists. This was
    V5's first recommendation and it remains unaddressed.
12. Everything inherited from V4 §19 and V3 still applies.

---

## 10. Recommended next steps **[INFERENCE]**

Argue with the ordering; it is a judgement, not a finding.

1. **Pay the documentation debt** (§9.8) before more code lands. Four documents
   currently describe a system that no longer exists.
2. **Rebuild the evaluation substrate.** The V4/V5 corpus is a rule-testing
   corpus that was pressed into service as ML training data. Until a corpus
   exists whose contamination resembles production, every detection number on it
   bounds an artefact.
3. **Then the telemetry track (Tracks 4/5)** — but fix the normalizer leak
   first, or adding a source deepens it.
4. **Real analyst feedback**, still the highest-value thing available and still
   not done.
5. PostgreSQL and one live provider, whenever the environment permits.

**[INFERENCE]** Do *not* treat §3's table as a reason to abandon adaptation. It
says the baseline was wrong, not that feedback is worthless — the redesigned
Arm 2 delivers a measured 23% relative FPR reduction against a *correct*
baseline (§4). What it does mean is that any future claim of the form
"adaptation improved X by N×" must name the baseline it improved on.

---

## 11. Preserve these decisions

All of V3 §16, V4's three and V5's eight (20–27) still hold and were verified by
the V5 deployment, registry-immutability and proposal suites passing unchanged.
V6 adds:

28. **A result and the artifact behind it are committed together.** V4 and V5
    published from gitignored files; a result reproducible only from an
    undocumented local file is not reproducible.
29. **A longer seed plan extends a shorter one.** Resampling would invalidate
    every published comparison.
30. **A correction is recorded beside the original, never in place of it.** Six
    conclusions were corrected in V6, including two of V6's own.
31. **Aggregate metrics can hide a targeted attack.** A single-category recall
    collapse divides by the number of categories and disappears beneath seed
    noise. Gate per category.
32. **A volume cap does not bound a concentration attack.** 22 rows inside a 20%
    cap were enough. Cap per group.
33. **Report the defence that failed.** `per_group_absolute` neither stopped the
    attack nor preserved honest feedback; publishing only `baseline_relative`
    would have made the design look inevitable.
34. **Name the metric that hides the failure mode.** Benign-bias poisoning
    improves FPR, F1 and ROC-AUC while costing recall. An FPR-reduction feature
    that reports FPR cannot see its own characteristic failure.

---

## 12. First steps for a new session

1. Verify §2 and §7 yourself. Both were wrong in the V5 handoff.
2. Read `docs/V6_RESEARCH_REPORT.md` §4 and §5 before any code.
3. Read `docs/V5_EXPERIMENTAL_DESIGN.md` for how pre-registration was done here,
   then §5 above for which of its conclusions did not survive.
4. Inspect `backend/app/adaptation/feedback/{caps,augmentation}.py` and
   `candidates/gates.py` — the only V6 code on the production path.
5. Spot-check with
   `python -m app.adaptation.experiments.run_production_baseline_eval --seeds 3`.
   It should land near F1 0.65, not 0.04. If it lands near 0.04, something is
   fitting the labelled corpus again and §3 is repeating itself.
