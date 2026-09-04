# AEGISX V6 → V7 HANDOFF

> Written at the end of the V6 session for a **fresh Claude Code session**.
> Every claim was checked against the repository immediately before writing, not
> recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged **[MEASURED]**, **[IMPLEMENTATION]**, **[LIMITATION]**,
**[INFERENCE]** — as in V4 and V5.

---

## 1. Read this first

**V6 did not go where its brief pointed.** It was scoped as ten tracks of new
capability. It became an audit of V4 and V5's methodology, because the first
thing it measured did not hold up, and neither did the thing after that.

**Thirteen of the brief's twenty definition-of-done items are done. Seven are
not** — §10 lists them without softening. Two of those are blocked on the
environment; five were simply not reached.

**The headline for a new session is §3, and §5 lists every correction.** Most quantitative claims in V4, V5 and
V6 have been revised, several of them twice. What survived is listed in §4.

Verify §2 and §7 yourself before trusting anything here. The V5 handoff named the
wrong checkpoint and claimed the work was unpushed when it was not; the V4 audit
found the same class of error before it.

---

## 2. Checkpoint **[MEASURED]**

```
V4 checkpoint:  65a8671   ← intact, verified
V5 checkpoint:  52eea0d   ← intact, verified
V6 checkpoint:  d8e54b4
```

**Pushed.** `origin/main` is at `d8e54b4`, identical to `HEAD`; working tree
clean, no divergence. Nothing amended, rebased or force-pushed.

**28 commits. 78 files changed, +53,784 / −54.** The insertion count is
dominated by 25 committed JSON experiment artifacts — deliberate, see §7.

---

## 3. What V6 found

**Every V5 number reproduced exactly.** V5 was not dishonest and its
measurements were not wrong. What V6 found is that **the substrate and the
scoring method those measurements sat on were both broken**, in ways that
inflated every magnitude in the report.

Three compounding problems, each measured:

**(a) The corpus.** V4 and V5 fitted an Isolation Forest on the labelled
evaluation corpus, whose fit split is **40% malicious** and whose own provenance
already said it was *"out of distribution for the anomaly model"*. It was built
to exercise **rule thresholds**. §4 measured that contamination degrades
discrimination badly (ROC-AUC 0.53 → 0.93 as it falls).

**(b) The threshold.** `anomaly_score` is calibrated to the **median of each
model's own training scores**, so a frozen 0.65 names a *different operating
point for every model*. §14 measured 0.65 sitting at the 53.6th percentile for
one model and the **99.2nd** for another. Comparing differently-fitted models at
a fixed threshold compares their calibrations. **Ten of eleven comparison sites
in this project did exactly that.**

**(c) My own errors.** §13 corrected V6's claim that production trains at ~12%
suspicious — it is **42.7%**. I had eyeballed normalized `event_type` names and
missed two attack scenarios.

**The consequence for V5's headline:**

| framing | static → both arms |
| --- | --- |
| **V5 as published** (F1 @ frozen 0.65) | 0.038 → 0.238, **6.3×** |
| at matched operating points (§16) | **1.31×** AUC, 1.46× recall at fixed alert budget |
| **on a corrected substrate** (§18) | **ΔAUC +0.0058**, against a random-label control of +0.0031 |

**[INFERENCE]** The most defensible reading is that **the V5 adaptation
programme was contamination repair.** It worked because the substrate was
broken. On one that is not, there is little left for it to do. That is not a
failure of the machinery — §§8–9 show its safety controls genuinely work — it is
a statement about which problem it was solving.

---

## 4. What survived **[MEASURED]**

Everything below survived both the threshold audit (§§14–17) and the substrate
migration (§§18–20) in the research report.

| Finding | Evidence |
| --- | --- |
| **Contamination degrades discrimination** | ROC-AUC 0.53 → 0.93 as fit-set malicious share falls 40% → 4%; replicated on an independent corpus (§13.3) |
| **Adaptation helps where the detector is weakest** | Per-category ΔAUC largest on the hardest scenario, smallest on the easiest — on both corpora (§17.2, §20.1). The only substantive finding to survive everything |
| **Targeted poisoning costs real capability** | Target-category ΔAUC −0.0685 undefended (§17.4) |
| **The per-group cap defends — conditionally** | Neutralises the attack (ΔAUC +0.0002) **where the grouping key isolates the target**; removes only 40% of poison where it does not (§19.2, §20.3) |
| **Arm 2 improves capability** | ΔROC-AUC +0.0339 → +0.0421 across substrates (§19.4). The one V6 result claiming operational value |
| **V5's random-label control works** | It is what made every correction above detectable. The single best methodological decision in the project's history |

**Died under audit:** V5's Arm 1 (contributes *exactly zero* capability —
identical AUC to static by construction); §7.3, §7.4, §11.2, §11.3; and V6's own
§2.4, §5, §6 and §9 framings. §5 below lists all fifteen corrections with what replaced them.

---

## 5. Corrections made in V6 **[MEASURED]**

**Fifteen conclusions were corrected — six of V5's and nine of V6's own.** In
every case the original measurement is retained and the correction recorded
beside it; nothing was rewritten to look better.

### V5's

| Where | What changed |
| --- | --- |
| §2.5 "label noise barely matters" | False at 50 seeds: F1 0.2826 → 0.2110 across 0–15% noise, d 1.44. The attribution was also backwards — curation degrades (d 0.75), threshold selection does not (d 0.03) |
| §3 "RQ4 answered no" | Too strong; and V5's three categories were never recorded, so its 0.0085 **cannot be reproduced** |
| §3 harness | `run_new_behaviour` never gives the loop feedback about the withheld category. Measured benign in effect — the threshold clamp saturates — but the conclusion exceeded the harness |
| Arm 2 | Not merely inapplicable in production: `train_candidate` recorded `feedback_dataset_id` and **never used it** |
| **Arm 1** | Reported as working (F1 0.038 → 0.099). Contributes **exactly zero** capability — identical AUC, best-F1 and recall-at-budget to static, by construction |
| **The 6.3× headline** | Real and attributable to feedback, but ~7× inflated by the frozen threshold (§16), and **~0 on a corrected substrate** (§18) |

### V6's own

| Where | What changed |
| --- | --- |
| §3.3 | Said the corpus violates the `contamination` *parameter*. Direction right, mechanism wrong — `contamination` never reaches `anomaly_score` |
| §4.1 / §5.1 | Said production trains at ~12% suspicious. It is **42.7%**; I had eyeballed `event_type` names and missed two attack scenarios |
| §5 | Read the production configuration's F1 0.6526 as a better-configured detector. **82.6% is threshold placement**, and its advantage is partly an artefact of the corpus being *out of distribution* for it |
| §6 | Described Arm 2 as "trading recall for precision". At matched operating points it is **strictly better** on both threshold-free measures |
| §2.4 | Said adaptation helps 4 of 13 novel categories. The **opposite**: those three were already at AUC ≈0.997 and gained nothing, while the "unhelpable" ones gain +0.19 to +0.21 |
| §7.3 | Said benign bias costs recall and that recall reveals poisoning. At matched points it costs **no** recall and has the largest capability gain |
| §7.4 | "Sparse feedback makes the model worse" — **died on migration**; it helps there (+0.0149). §7 now has no surviving published conclusion |
| §9 | The per-group cap is **conditional on the grouping key isolating the target** — 96% of poison removed where a scenario owns its `event_type`, 40% where it hides |
| §11.2 | The allowance ratchet **died on migration**, replaced by something worse: a hidden target faces an allowance of ~597 at cycle zero and needs no ratchet |

**[INFERENCE]** The pattern is consistent and is the most useful thing V6 can
hand forward: **findings about mechanism survived; findings about magnitude did
not.** Every quantity in this project was, to some degree, a property of the
corpus and the threshold it was measured with.

---

## 6. Architecture **[IMPLEMENTATION]**

Still a modular monolith. **No new tables, no new migrations, no schema change** —
head is `0009_v5_proposals`, nine migrations, unchanged from V5.

**The V5 invariant holds.** `registry.activate_model`, behind an approved
proposal, remains the only write into production detection state. V5's
deployment, registry-immutability and proposal suites pass unchanged.

Three modules reach the production path:

| Module | Why it exists |
| --- | --- |
| `adaptation/feedback/augmentation.py` | V5's Arm 2 could not run in production and `train_candidate` never used `feedback_dataset_id`. This adds analyst-verified benign events to the telemetry corpus |
| `adaptation/feedback/caps.py` | A global volume cap cannot bound a **concentration** attack (§8) |
| `adaptation/feedback/baseline_monitor.py` | The cap bounds a campaign but cannot see one. **Advisory** |

`candidates/gates.py` gained two checks: **per-category recall** (§10) and
**discrimination / ROC-AUC** (§15) — the second because the first is
threshold-dependent and could reject a better model for a calibration shift.
Both are **advisory when unmeasured**, never a silent pass.

`app/telemetry/` has exactly one V6 change: `RawTelemetry.scenario`, provenance
that never reaches the normalized candidate (asserted by test).

**Defaults:** no `feedback_dataset_id` → telemetry alone, as V5. `cap_policy`
defaults to `baseline_relative`, `DEFAULT_TOLERANCE` to **1.5**, and a cold start
is **refused** rather than silently degraded.

---

## 7. Verification at checkpoint **[MEASURED]**

Run immediately before writing this, on `d8e54b4`:

| Check | Result |
| --- | --- |
| `pytest` | **733 passed** (535 at V5) |
| `ruff check .` | clean |
| `vitest run` | **50 passed**, 8 files |
| `tsc -b --noEmit` | clean (exit 0) |
| `eslint .` | clean (exit 0) |
| `vite build` | PASS (chunk warning, pre-existing) |
| Migrations base→head→base→head | PASS (SQLite), head `0009_v5_proposals` |

50 test modules, **13 added in V6** (`git diff --name-only --diff-filter=A 52eea0d..HEAD -- backend/app/tests/`).

---

## 8. Reproducing

```bash
cd backend && export DATABASE_URL="sqlite:///aegisx.db"

python -m app.adaptation.experiments.run_adaptation_eval              --seeds 50
python -m app.adaptation.experiments.run_novel_behaviour_eval         --seeds 10
python -m app.adaptation.experiments.run_detector_comparison          --seeds 10
python -m app.adaptation.experiments.run_contamination_eval           --seeds 10
python -m app.adaptation.experiments.run_production_baseline_eval     --seeds 10
python -m app.adaptation.experiments.run_arm2_eval                    --seeds 10
python -m app.adaptation.experiments.run_feedback_quality_eval        --seeds 10
python -m app.adaptation.experiments.run_targeted_poisoning_eval      --seeds 8
python -m app.adaptation.experiments.run_patient_poisoning_eval       --seeds 8
python -m app.adaptation.experiments.run_matched_operating_point_eval --seeds 20 --substrate telemetry
```

Pass `--max-seconds 5400`; the 900 s default is too small. Total under one
CPU-hour.

**Report retention changed in V6.** Timestamped reports are **committed** as
immutable evidence — 25 of them. Only the mutable `latest-*` pointers are
ignored. V4 and V5 published every number from gitignored files.

**Seeds** come from one standing plan (`experiments/seeds.py`) in which a longer
plan *extends* a shorter one, so `--seeds 3` still reproduces V5 exactly.

**Substrates.** `prepare_corpus(substrate=...)` selects `rule-testing` (V4/V5,
the default, nothing moves) or `telemetry` (§13's rebuild).

---

## 9. Two methodological rules V7 should not lose **[INFERENCE]**

Earned the hard way, and both would have prevented most of this session:

1. **Report a threshold-free measure beside every fixed-threshold one.**
   ROC-AUC and recall-at-a-matched-alert-budget are portable between models;
   F1 at a constant is not, and F1 is additionally prevalence-dependent so it is
   not comparable across corpora either.
2. **State a corpus's contamination and prevalence before quoting any metric on
   it.** Both were properties nobody had checked, and both silently set the
   magnitude of every result.

---

## 10. What V6 did NOT do **[LIMITATION]**

Thirteen of twenty definition-of-done items are done. **These seven are not** —
items 5, 6, 7, 8, 9, 10 and 11 of the brief:

1. **No telemetry-source integration.** Track 4 never started.
2. **No telemetry-source abstraction work.** The Phase A audit found
   `telemetry/normalizer.py` hard-codes vendor schemas (`_normalize_defender`);
   **that leak is documented and unfixed.** Adding a source by appending another
   branch would deepen it.
3. **No PostgreSQL validation.** Docker was unavailable for the whole session.
   Everything is SQLite on a laptop.
4. **No live external provider.** No `.env`, no API key; nothing live was called.
5. **No four-eyes decision.** `self_approved` is still recorded, not prevented.
6. **No approval-latency measurement or simulation.**
7. **No dashboard work.** `frontend/` is untouched — 0 files changed. None of
   V6's provenance (`perCategory`, `augmentation`, `baselineAssessment`) is
   visible in the UI.

Also load-bearing:

8. **All feedback is simulated.** No analyst population exists. V5's first
   recommendation, still unaddressed — and now the *only* outstanding item that
   would change what is known (§10).
9. **The cap is conditional.** §19.2 measured it removing 96% of poison where a
   scenario owns its `event_type` and **40%** where it hides in a high-volume
   group. §20.3 is worse: a hidden target faces an allowance of ~597 at cycle
   zero and needs no patience at all.
10. **Nothing detects a campaign automatically.** `baseline_monitor` is advisory
    and its bands were calibrated against a *greedy* adversary; a slower one may
    not flag.
11. **Seed counts fell** as the session went on — 50 early, 3–4 for §§19–20.
    Directions there are clear; point estimates are not settled.
12. **Both corpora are synthetic.** **Nothing in this project is evidence about
    real attack traffic.** The audit did not change that; it only established
    that the numbers were also artefacts of measurement choices.
13. Everything inherited from V4 §19 and V3 still applies.

---

## 11. Recommended next steps **[INFERENCE]**

1. **Get real analyst feedback.** Every result rests on a simulator, and §§14–20
   established that magnitudes here are properties of the corpus and the
   threshold rather than of the system. **More experiments against a simulator
   on a synthetic corpus will keep producing numbers that do not survive the
   next methodological check.** This is the only outstanding item that would
   change what is *known*.
2. **Fix the cap's grouping-key dependence** (§9.9 above). A per-analyst cap
   would bound a compromised actor regardless of which group they target, and is
   the obvious complement to the per-group one.
3. **Fix the normalizer leak, then do the telemetry track.** In that order.
4. **Surface V6's provenance in the dashboard.** Three new evidence blocks are
   recorded on candidates and invisible to approvers.
5. PostgreSQL and one live provider, whenever the environment permits.

**[INFERENCE]** Resist starting Track 4 or the agent work first. The project's
constraint is not features; it is that its measurement substrate only just
became trustworthy.

---

## 12. Preserve these decisions

All of V3 §16, V4's three and V5's eight (20–27) still hold. V6 adds:

28. **A result and the artifact behind it are committed together.**
29. **A longer seed plan extends a shorter one.** Resampling invalidates every
    published comparison.
30. **A correction is recorded beside the original, never in place of it.**
    Fifteen conclusions were corrected in V6, nine of them V6's own.
31. **Aggregate metrics can hide a targeted attack.** Gate per category.
32. **A volume cap does not bound a concentration attack.** Cap per group — and
    know that a per-group cap is only as good as its grouping key.
33. **Report the defence that failed.** `per_group_absolute` neither stopped the
    attack nor preserved honest feedback; publishing only the policy that worked
    would have made the design look inevitable.
34. **A fixed threshold is not comparable across models fitted on different
    data.** Report a threshold-free measure beside it.
35. **F1 is prevalence-dependent.** It is not comparable across corpora. AUC is.
36. **Measure the naive version before building the clever one.** The obvious
    baseline-growth monitor watched admitted volume; measurement showed a working
    cap erases that signal, which is why the shipped monitor reads submissions.

---

## 13. First steps for a new session

1. Verify §2 and §7 yourself. Both were wrong in the V5 handoff.
2. Read `docs/V6_RESEARCH_REPORT.md` **§§4, 5, 14 and 18** before any code.
   Everything else is downstream of those four.
3. Read **§5 of this handoff** — fifteen corrected conclusions, with what
   replaced each.
4. Inspect `adaptation/feedback/{augmentation,caps,baseline_monitor}.py` and
   `candidates/gates.py`. The only V6 code on the production path.
5. Spot-check:
   `python -m app.adaptation.experiments.run_production_baseline_eval --seeds 3`
   → F1 ≈ 0.65. If it lands near 0.04, something is fitting the labelled corpus
   again and §3(a) is repeating itself.
