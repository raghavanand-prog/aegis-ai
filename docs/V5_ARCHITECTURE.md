# AEGISX V5 — Adaptive SOC / Controlled Learning Layer

> Architecture proposal and implementation plan, written at the start of the V5
> session against the repository at V4 checkpoint `65a8671`.
> Claims are tagged as in the V4 handoff: **[MEASURED]**, **[IMPLEMENTATION]**,
> **[LIMITATION]**, **[INFERENCE]**.

---

## 1. What V5 is

V5 turns AEGISX from *static detection + scientific evaluation* into a
**controlled adaptive SOC**: the system may detect that its environment or its
performance has changed, learn from structured analyst feedback, generate
evidence-backed adaptation proposals, validate them with the V4 framework, and
deploy approved changes with full provenance and rollback.

**V5 is not autonomy.** The system may `DETECT → LEARN → PROPOSE → VALIDATE →
REQUEST APPROVAL → DEPLOY`. It may never `DETECT → LEARN → DEPLOY`.

---

## 2. Phase A audit result **[MEASURED]**

Verified against the repository on 2026-09-03, not from the handoff.

### V4 is intact

| Check | Handoff §18 claims | Measured now |
| --- | --- | --- |
| `pytest` | 374 passed | **374 passed** |
| `vitest run` | 40 passed (7 files) | **40 passed (7 files)** |
| `ruff check .` | clean | **clean** |
| Migrations `base → head` | PASS (SQLite) | **PASS (SQLite)** |

Working tree clean, synced with `origin/main`. V3 baseline `a272545` intact.
No rebase, amend or force-push in the history.

### Four discrepancies between the handoff/report and the repository

1. **Checkpoint reference is stale.** Handoff §2 names `1c031d0` as the V4
   checkpoint. The actual tip is `65a8671` ("docs: checkpoint aegisx v4
   scientific evaluation"), one commit later. The handoff was written before its
   own final docs commit.

2. **The documented reproduction command cannot complete.** `REPRODUCIBILITY.md`
   §4 gives `run_experiments` without `--max-seconds`. The default ceiling is
   900s; on this machine Isolation Forest takes 218s and supervised HGB 609s, so
   the watchdog fires mid-suite and **no report artifact is written**. This is
   why no V4 experiment artifacts existed on disk. Fix in Phase M: document
   `--max-seconds 3600`.

3. **The research report mixes two different splits.** **[MEASURED]**
   `RESEARCH_REPORT.md` §1 and §2.2 describe a split that is not the one that
   produced §2's results. §2's own confusion matrices sum to 39,651 test samples
   while §1 states 40,066 — an internal contradiction on the same page.

   | | §1 / §2.2 as published | §2 metric table (arithmetic) | Regenerated |
   | --- | --- | --- | --- |
   | Test samples | 40,066 | **39,651** | **39,651** |
   | Test malicious | 4,375 | **4,457** | **4,457** |
   | Train / validation | 120,663 / 39,797 | — | **120,452 / 40,423** |
   | Split fingerprint | `5cfefd1cdc832a81` | — | **`a74749098152ca3c`** |
   | Leakage (test) | 51.02% | — | **51.80% (20,541/39,651)** |

   **Every detector result in §2 reproduces exactly**, digit for digit,
   including all confusion-matrix cells and the ablation table. The science is
   sound; the provenance stitched onto it is stale. Under V4's own rule 19 — *a
   result without its dataset fingerprint, split, feature schema and threshold
   is not a result* — the provenance must be corrected, and the findings left
   untouched.

4. **Model artifact immutability is enforced in the database only.**
   **[MEASURED]** `registry.next_version()` derives the next version from
   `ml_models` rows alone, and `IsolationForestDetector.save()` writes
   unconditionally. With a rebuilt or lost database, training re-issues `v1.0`
   and **silently overwrites a digest-verified production artifact**. Observed
   directly: the artifact digest moved from `053d1ff3…` to `016c6dbf…`.
   This contradicts the intent of §16/§17 and is a V5 hardening target.

### Training determinism **[MEASURED]**

Three independent runs, two in isolated artifact directories, produce the
**byte-identical** artifact `016c6dbf37f53d03…`, 0.75% flagged at 0.65,
recommended threshold 0.648. Training is fully reproducible.

Two consequences:

- `REPRODUCIBILITY.md` §3 and handoff §3 document 1.25% flagged / threshold
  0.654. **That does not reproduce.** The figure is stale.
- The V4 **deployed** artifact `053d1ff3…` is **not reproducible from current
  code**. It was trained by an earlier code state, almost certainly before the
  determinism fix described in handoff §3. It is an orphan artifact, preserved
  outside the repository but not regenerable.

Artifacts are gitignored, so the git checkpoint is unaffected by this.

### Gaps closed in Phase A

**§19.11 — temporal split** **[MEASURED]**. Never previously published. Split
fingerprint `c3a3830a9db1bce2`. Attack density runs 2.21% → 13.1% → 20.22%
across train/validation/test — **real, measured distribution shift**, a property
of the capture's two periods. Test leakage **0.00%** (0/79,798).

| Detector | Precision | Recall | F1 | FPR | MCC |
| --- | --- | --- | --- | --- | --- |
| Rules only | — | 0.0% | — | 0.0% | — |
| Isolation Forest | 8.3% | 9.5% | 0.089 | 26.4% | **−0.162** |
| Supervised HGB | 90.4% | 93.6% | 0.919 | 2.5% | 0.899 |

Under shift the production detector's MCC goes **negative**: its predictions are
anti-correlated with truth, worse than guessing. The supervised reference
degrades gracefully (0.970 → 0.919).

**§19.12 — registered artifact** **[MEASURED]**. Never previously published.
The *deployed* artifact outperforms the *fitted* one on the synthetic corpus and
is not degenerate:

| Detector (synthetic) | Precision | Recall | F1 | FPR | MCC |
| --- | --- | --- | --- | --- | --- |
| Rules only | 89.5% | 92.9% | 91.2% | 7.3% | 0.852 |
| Isolation Forest (fitted) | 40.0% | 100.0% | 57.1% | **100.0%** | — |
| **Isolation Forest (registered)** | 59.8% | 74.4% | **66.3%** | 33.3% | 0.402 |
| Supervised HGB | 100.0% | 100.0% | 100.0% | 0.0% | 1.000 |

`RESEARCH_REPORT.md` §4 reproduces exactly, leakage audit included.

---

## 3. What V5 inherits **[IMPLEMENTATION]**

| Capability | Where | V5 use |
| --- | --- | --- |
| Immutable, digest-verified model registry | `ml/registry/registry.py` | Candidate lifecycle; needs on-disk immutability fix |
| `activate` / `deactivate` / `rollback` | `api/v1/ml.py`, `ml:manage` | The **only** write into production, now approval-gated |
| Experiment/run persistence, leakage audit | `app/evaluation/`, `0004` | Candidate evaluation — reused, not duplicated |
| Audit log (actor, target, details) | `models/audit.py` | Adaptation audit trail |
| AI grounding, sanitization, injection detection | `ai/grounding.py`, `ai/sanitize.py` | AI proposals pass through unchanged |
| Risk ceiling `ML_MAX_CONTRIBUTION = 25` | `scoring/risk.py` | Threshold proposals must respect it |

Absent entirely, and therefore built in V5: analyst feedback, feedback dataset
versioning, drift detection, active learning, candidate lifecycle, safety gates,
proposals, approval, shadow evaluation.

---

## 4. Architecture

V4 added a measurement layer *around* production. V5 adds a proposal loop around
it, on the same principle: **the production detection path is not edited.**

```
PRODUCTION (unchanged)                    ADAPTATION (V5, advisory)
  ...→ rules + ML → risk → incident  ──▶  analyst feedback (labels + provenance)
       │                                        ↓
       │  features, inferences ──────────▶ drift monitor ──▶ drift signal
       │                                        ↓
       └──────────────────────────────▶ active learning ──▶ review queue
                                                ↓
                                    feedback dataset (versioned, fingerprinted)
                                                ↓
                                    candidate training (CLI only, offline)
                                                ↓
                                    V4 experiment framework ──▶ evaluation
                                                ↓
                                          safety gates
                                                ↓
                                      adaptation proposal
                                                ↓
                                    shadow scoring (no production effect)
                                                ↓
                                      HUMAN APPROVAL (admin)
                                                ↓
                        existing registry.activate_model() ──▶ deployment
                                                ↓
                                    monitoring ──▶ rollback
```

The single write into production is the **existing** `activate_model()`,
reachable only through an approved proposal. Nothing else in `app/adaptation/`
may mutate detection state — asserted by test, exactly as V4 asserts that no
endpoint can start an experiment.

### Package

```
backend/app/adaptation/
  feedback/         label vocabulary, provenance, submission, versioned datasets
  drift/            PSI · Wasserstein (numeric) · chi-square (categorical)
  active_learning/  candidate selection → review queue only, never training
  candidates/       training CLI, promotion gates, shadow scoring
  proposals/        proposal entity, lifecycle, generators
  experiments/      the seven V5 scenarios
```

### Database — `0005_v5_adaptation`

`analyst_feedback` (append-only; corrections supersede, never mutate),
`feedback_datasets` (unique on name + version + **fingerprint**, mirroring
`evaluation_datasets`), `feedback_dataset_members`, `drift_measurements`,
`adaptation_proposals`, `adaptation_deployments` (carrying `rollback_target`).

Candidate models reuse `ml_models` with additional statuses. Candidate
evaluation reuses `evaluation_experiments` / `evaluation_runs` — no duplication
of V4 provenance structures.

### RBAC — existing three roles, six new permissions

| Permission | viewer | analyst | admin |
| --- | --- | --- | --- |
| `feedback:read`, `drift:read`, `adaptation:read` | ✅ | ✅ | ✅ |
| `feedback:submit`, `adaptation:propose` | | ✅ | ✅ |
| `adaptation:approve`, `adaptation:deploy` | | | ✅ |

No new role. Proposer and approver are recorded as distinct actors even when
they are the same person, so separation of duties can be audited and later
enforced without a schema change.

### API

`/api/v1/adaptation/*`. Mutating endpoints (submit, propose, approve, reject,
deploy, rollback) enforce RBAC and write an audit row.

**No HTTP training endpoint**, on V4's precedent: training is minutes of CPU,
which over HTTP is a resource-exhaustion primitive. Training is CLI only.

### Frontend

`features/adaptive/` at `/dashboard/adaptive`: Overview · Feedback · Drift ·
Models · Proposals · Experiments · Audit, using the existing design system and
its rules (`n/a` never rendered as 0%, every result carries its provenance,
empty states carry the command that populates them).

---

## 5. Evaluation design

Substrate decision: **synthetic corpus primary, UNSW secondary.** V4 established
that the rules cannot fire on UNSW flow telemetry and that Isolation Forest is
indistinguishable from random there; feedback cannot move a metric on a detector
that has no signal. The synthetic corpus is where rules fire, the deployed model
scores F1 0.663 at **33.3% FPR**, and analyst feedback is therefore meaningful.

UNSW contributes the **drift** evidence, and it is real rather than simulated:
the temporal split measured above carries genuine distribution shift with a
leakage-free test split. RQ3 is answerable against measured shift.

Seven scenarios per the V5 brief §46: stable environment · false-positive drift ·
feature distribution drift · new behavioural pattern · feedback-driven
adaptation · candidate model regression · rollback.

### Limitations to state up front **[LIMITATION]**

- **Feedback is synthetic.** There is no analyst population. Labels are derived
  from ground truth with **explicitly modelled analyst error**, so that "do not
  treat every analyst label as automatically correct" is exercised rather than
  asserted.
- **Drift in scenarios 2 and 4 is induced**, and labelled as such. Only the
  UNSW temporal shift is observed rather than constructed.
- Everything inherited from V4 §19: no production traffic, no live AI provider,
  no threat-intelligence provider, SQLite-and-laptop latency, PostgreSQL
  unverified locally.

---

## 6. Implementation plan

| Phase | Content |
| --- | --- |
| **A** | Repository audit, baseline regeneration, §19.11 + §19.12 closed, this document |
| **B** | Analyst feedback: model, service, API, RBAC, audit, tests |
| **C** | Feedback dataset versioning and fingerprinting |
| **D** | Drift detection: data · prediction · concept kept conceptually distinct |
| **E** | Active-learning selection → review queue only |
| **F** | Controlled retraining, candidate isolation, digest verification |
| **G** | Candidate evaluation via the V4 framework, configurable safety gates |
| **H** | Adaptation proposals and approval workflow |
| **I** | Shadow evaluation, gated deployment, rollback |
| **J** | AI-assisted proposals through the existing grounding pipeline |
| **K** | Adaptive SOC dashboard |
| **L** | V5 scientific evaluation — static vs adaptive |
| **M** | Documentation, provenance corrections, `CLAUDE_HANDOFF_V5.md`, research report |
| **N** | Full verification against the V5 definition of done |

D and E depend only on B/C. F–I are strictly sequential. Verification
(`pytest` · `ruff` · `vitest` · `eslint` · `tsc` · `vite build`) runs at every
phase boundary, not only at N.

---

## 7. Hard boundaries

V5 must not implement autonomous containment, endpoint isolation, firewall
blocking, credential disabling, autonomous model or rule deployment, autonomous
threshold changes, self-modifying production code, or unrestricted agents.

Human approval is mandatory for every production-affecting change. AI output is
advisory and passes through the existing grounding and sanitization pipeline; it
may never approve its own proposal or write to production model state.
