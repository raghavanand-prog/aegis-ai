# AEGISX V5 → V6 HANDOFF

> Written at the end of the V5 session for a **fresh Claude Code session**.
> Verified against the repository, not from conversation memory.
> **Trust the repository over this document.** Where they disagree, the code wins.

Claims are tagged:

- **[MEASURED]** — a number from a committed, reproducible command.
- **[IMPLEMENTATION]** — a fact about the code, verifiable by reading it.
- **[LIMITATION]** — something not established, not measured, or not true.
- **[INFERENCE]** — a judgement. Argue with these freely.

---

## 1. Milestone status

| Milestone | Status | Notes |
| --- | --- | --- |
| **V1** | COMPLETE / VERIFIED | Full-stack SOC |
| **V2** | COMPLETE / VERIFIED | Hardening, RBAC, audit |
| **V3** | COMPLETE / PARTIALLY VERIFIED | Hybrid ML, correlation, threat intel, AI analyst. External providers and PostgreSQL still unverified locally |
| **V4** | COMPLETE / VERIFIED | Scientific evaluation layer |
| **V5** | COMPLETE / VERIFIED | Controlled adaptive SOC |

### Is V5 complete?

**Yes, with named gaps.** Every item in the V5 definition of done is
implemented and verified except the environmental ones inherited from V3/V4
(no PostgreSQL locally, no paid API keys) and the honest research limitations
in §8.

---

## 2. Checkpoint commits

```
V4 checkpoint:  65a8671   ← INTACT, never amended
V5 checkpoint:  da35666
```

**14 ordinary commits on top of V4. 73 files changed, +9,956 / −9.** Nothing
rebased, amended or force-pushed.

```
d866de0  phase A audit, V4 baseline verification and V5 architecture
379b761  analyst feedback system
faa43ab  versioned feedback datasets
6b437cb  drift detection
f45c6e4  active-learning candidate selection
ddb96b8  fix(ml): enforce artifact immutability on disk, not only in the database
a6c55f5  controlled candidate training
211e818  candidate evaluation and promotion gates
57e3a35  adaptation proposals and the approval workflow
e50855d  shadow evaluation, gated deployment and rollback
c3e7896  AI-assisted adaptation recommendations
dc91cf5  adaptive SOC dashboard
d1c5ffb  experimental design, pre-registered
da35666  adaptation experiments and research report
```

**[LIMITATION]** Not pushed. `origin/main` is still at `65a8671`.

---

## 3. What the Phase A audit found in V4

Read this before trusting any V4 number.

1. **Handoff §2 named the wrong checkpoint.** It said `1c031d0`; the tip was
   `65a8671`.
2. **The documented reproduction command could not complete.** **[MEASURED]**
   The 900 s watchdog default is too small for the UNSW suite on this hardware
   (IF ~220 s, supervised ~610 s), so it fired mid-suite and wrote no report.
   *That is why no V4 experiment artifacts existed.* Use `--max-seconds 3600`.
   Corrected in `REPRODUCIBILITY.md`.
3. **`RESEARCH_REPORT.md` mixed two splits.** **[MEASURED]** §1/§2.2 carried
   provenance from a different run than §2's results — §2's own confusion
   matrices summed to 39,651 test samples against §1's stated 40,066. Every
   detector result reproduced exactly; only the provenance was stale. Corrected
   in place with a visible correction note. **No measured result changed.**
4. **Model immutability was database-only.** **[MEASURED]** With a rebuilt
   database, `next_version` reissued `1.0` and training overwrote the deployed
   artifact (`053d1ff3…` → `016c6dbf…`). **Fixed in `ddb96b8`**, with the
   original scenario as a regression test.

Also closed, both previously unpublished:

- **§19.11 temporal split** **[MEASURED]** — real distribution shift, attack
  density 2.21% → 13.1% → 20.22%, **0.00% test leakage**. Isolation Forest MCC
  goes **negative** (−0.162); supervised degrades 0.970 → 0.919.
- **§19.12 registered artifact** **[MEASURED]** — the deployed model scores
  F1 0.663 at 33.3% FPR on the synthetic corpus, **better** than the fitted
  model's degenerate F1 0.571 at 100% FPR.

**[LIMITATION]** The V4 deployed artifact `053d1ff3…` is **not reproducible**
from current code; it predates the determinism fix. Training itself *is*
byte-for-byte deterministic (three runs, two isolated).

---

## 4. Architecture **[IMPLEMENTATION]**

Unchanged where it matters. Still a modular monolith — no microservices, no
Kafka, no Redis, no graph DB, no distributed serving. V5 added no new runtime
dependency.

`backend/app/adaptation/`: `feedback/`, `drift/`, `active_learning/`,
`candidates/`, `proposals/`, `deployment/`, `ai/`, `experiments/`.

**The only write into production detection state is the pre-existing
`registry.activate_model`,** reachable solely through an approved proposal.
Everything else in the package is advisory, asserted by test.

Migrations **0005–0009**: `analyst_feedback`, `feedback_datasets`,
`feedback_dataset_members`, `drift_measurements`, `adaptation_proposals`, and a
widened `ml_models.status`. Candidate evaluation **reuses** V4's
`evaluation_experiments`/`evaluation_runs`.

RBAC: **six new permissions on the existing three roles.** No new role.
`adaptation:approve` and `adaptation:deploy` are administrator-only.

---

## 5. The design decision that shaped V5 **[IMPLEMENTATION]**

The production detector is an **unsupervised** Isolation Forest; feedback is
labels. Labels do not train it. Substituting a supervised model and calling the
result "adaptation" was the available dishonesty, and was refused. Two arms use
labels legitimately:

- **Arm 1, threshold adaptation** — labels choose an operating point, clamped to
  `MAX_THRESHOLD_STEP = 0.05`.
- **Arm 2, corpus curation** — IF assumes its fit set is mostly normal; feedback
  says which observed events were malicious, so the fit set can be purified.

Neither makes the detector supervised.

---

## 6. Measured results **[MEASURED]**

Corpus `c0f04f3ccb2a63b8`, split `d349ea18a04e06c0`, 3 seeds, 5% label noise:

| Condition | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- |
| Static V4 | 1.000 | 0.019 | 0.038 | 0.000 |
| Both arms | 0.815 | 0.141 | **0.238** | 0.017 |
| *Random-label control* | 0.798 | 0.058 | **0.107** | 0.013 |

**The control fires.** Mechanism 34%, feedback content 66%. Reporting
0.038 → 0.238 as a feedback result would overstate by a third.

Other results: no catastrophic forgetting (historical recall 0.010 → 0.179);
**no benefit on unseen behaviour** (0.000 → 0.0085, 1 of 9 runs); full cycle
2.97 s machine time, rollback 1.1 ms; gates rejected a regressing candidate
unaided.

**Three of seven pre-registered predictions were wrong** and are reported as
wrong. A fourth (P1) was mis-framed and withdrawn.

---

## 7. Verification at checkpoint **[MEASURED]**

| Check | Result |
| --- | --- |
| `pytest` | **535 passed** (374 at V4) |
| `ruff check .` | clean |
| `vitest run` | **48 passed** (40 at V4) |
| `eslint .` | clean |
| `tsc -b --noEmit` | clean |
| `vite build` | PASS (chunk warning pre-existing) |
| Migrations up→down→up | PASS (SQLite) |
| Migrations base→head | PASS (SQLite) |

New test modules: `test_adaptation_feedback.py`, `_feedback_api.py`,
`_datasets.py`, `_drift.py`, `_active_learning.py`, `_candidates.py`,
`_gates.py`, `_proposals.py`, `_deployment.py`, `_ai.py`, `_experiments.py`,
`test_ml_registry_immutability.py`, `AdaptivePage.test.tsx`.

---

## 8. Known limitations **[LIMITATION]**

1. **All feedback in published results is simulated.** No analyst population.
2. **Three seeds.** Both-arms F1 ranges 0.117–0.333; the effect size is not
   settled.
3. **Adaptation does not help on novel behaviour** — measured, not suspected.
4. **Scenarios 2 and 4 are induced.** Only UNSW drift is observed.
5. **No detection claim on UNSW.** V4 established the detector is
   indistinguishable from random there.
6. **Non-model proposals record a decision without applying a change.** A
   threshold or rule recommendation is applied by a person; the code says so
   rather than claiming an effect it does not have.
7. **Human approval latency is unmeasured**, deliberately.
8. **Self-approval is possible** with three roles. Recorded on the row and shown
   in the UI, not prevented.
9. Latency is laptop-and-SQLite, single process.
10. Everything inherited from V4 §19 and V3 still applies: no production
    traffic, no live AI provider, no threat-intel provider, PostgreSQL
    unverified locally.

---

## 9. V6 starting recommendations **[INFERENCE]**

1. **Get real feedback from real analysts.** Every V5 result rests on a
   simulator. This is worth more than any new subsystem.
2. **More seeds before quoting the effect size.** Three cannot settle it, and
   the current report deliberately does not claim it is settled.
3. **Decide what to do about novel behaviour.** V5 measured that curation-based
   adaptation cannot teach an unseen pattern. That is a detector-class question,
   not a tuning one.
4. **Consider making non-model proposals actually apply.** Threshold changes
   currently record an approved decision a person then carries out.
5. **Four-eyes approval** if self-approval matters operationally. The data to
   enforce it is already recorded.
6. Still outstanding from V4: PostgreSQL verified locally, one live AI provider.

---

## 10. Preserve these decisions

All sixteen from V3 §16 and the three V4 added. V5 adds:

20. **The only write into production detection state is `activate_model`,
    behind an approved proposal.**
21. **Human approval is human.** `ai:`, `system:` and `automation:` actors are
    refused as approvers.
22. **An unmeasured metric never passes a safety gate.**
23. **Feedback is append-only.** Corrections supersede; nothing is edited.
24. **A dataset is a materialised snapshot, never a query.**
25. **Drift is a signal, not a verdict on the model** — and never a retrain.
26. **The prose is the model's; the numbers are not.** AI argues direction,
    values are computed from evidence and clamped.
27. **Controls are published with results.** The random-label control is the
    reason the V5 headline is stated honestly.

---

## 11. Recommended first steps for a new session

1. Read this handoff, then treat it as a hypothesis.
2. Read `docs/V5_EXPERIMENTAL_DESIGN.md` **before** `docs/V5_RESEARCH_REPORT.md`
   — the design was pre-registered and three predictions failed.
3. Inspect `backend/app/adaptation/`, `backend/app/models/adaptation.py`,
   `frontend/src/features/adaptive/`.
4. Spot-check §7 by running the suites; spot-check §6 with
   `python -m app.adaptation.experiments.run_adaptation_eval --seeds 3`.
5. Do **not** start V6 features before §9.1 and §9.2.
