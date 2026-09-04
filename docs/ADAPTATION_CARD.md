# Adaptation Card

The standard record for any production-affecting adaptation in AEGISX. One card
per deployed change, so that months later "why does the platform behave this
way" has a complete answer.

Every field maps to a column on `adaptation_proposals`; the card is a rendering
of the row, not a separate artifact that can drift from it.

---

## Template

| Field | Source | Notes |
| --- | --- | --- |
| **Proposal ID** | `id` | |
| **What changed** | `proposal_type`, `affected_component` | |
| **Title** | `title` | |
| **Why** | `reason` | |
| **Before state** | `before_state` | Captured at creation, not derived later |
| **Proposed after state** | `after_state` | |
| **Evidence** | `evidence` | A proposal without this is refused |
| **Dataset** | `feedback_dataset_id` | Name, version and **fingerprint** |
| **Model** | `candidate_model_id` | Identity and artifact digest |
| **Validation** | `validation` | Gate results, or `not_validated` stated plainly |
| **Expected impact** | `expected_impact` | Estimate; labelled as such |
| **Risk assessment** | `risk_assessment` | |
| **Proposed by** | `proposed_by`, `proposed_by_role` | `ai:` prefix where AI-drafted; the role is the one held at the time |
| **Approved by** | `approved_by`, `approved_by_role` | Never an `ai:`/`system:` actor — refused. The role must grant `adaptation:approve` |
| **Rejected by / when** | `rejected_by`, `rejected_by_role`, `rejected_at` | A refusal is a decision and records its time (V7) |
| **Self-approved** | `self_approved` | **Prevented since V7**, not merely recorded. Always `false` for anything approved from V7 on; rows decided earlier may carry `true` and keep it |
| **Deployed by / at** | `deployed_by`, `deployed_at` | |
| **Rollback target** | `rollback_state` | Captured at deployment |
| **Rolled back by / why** | `rolled_back_by`, `rollback_reason` | |

---

## Feedback provenance (V6)

Where the candidate was trained with a feedback dataset, the model's
`parameters.augmentation` block carries what that feedback contributed and what
was refused. An approver reads these beside the fields above; none of it is
inferable from the proposal row alone.

| Field | Notes |
| --- | --- |
| `admitted` | Rows that reached the fit set |
| `groupCounts` | Admitted rows per `event_type` |
| `capPolicy` | `baseline_relative` by default; `global` is an explicit opt-out that V6 §9 measured does **not** stop a targeted attack |
| `baselineRatesDerived` | Whether the per-group baseline was learned from prior datasets or supplied by the caller |
| `skipped.notBenign` | Refused: the label did not project benign |
| `skipped.nonEvent` | Incidents and sequences have no single feature vector |
| `skipped.noInference` / `.incompleteVector` | No stored vector, or one missing a feature — refused, never padded |
| `skipped.byCap` | Rows either cap axis declined |
| `actorCounts` | **V7.** Admitted rows per submitting analyst — the second cap axis |
| `actorCapPolicy` | **V7.** `null` when the actor axis is off, which is the default |
| `baselineAssessment` | Advisory campaign check (below) |

### The second cap axis (V7)

V6 §19.2 measured the per-group cap removing 96% of poison where a scenario
owned its `event_type` and **40%** where it hid in a high-volume group; §20.3
found a hidden target facing an allowance of ~597 at cycle zero, needing no
patience at all. The V6 handoff called the cap "conditional on its grouping key".

That is not a tuning problem. *Any* single-axis cap is only as good as its key,
and `event_type` is partly attacker-influenced, so the evasion is to move.

`caps.apply` now takes an optional independent **actor** axis alongside the
group axis, and both must admit. The two are evaded by opposite behaviours:
concentrating to stay under an actor cap means concentrating into a group, and
spreading to stay under a group cap means spreading from one account. A campaign
across ten event types divides its per-group footprint by ten and leaves its
per-actor footprint exactly where it was.

**Off by default**, so every published V5/V6 result reproduces unchanged.

**What it does not claim:** it bounds a *compromised actor*, not a colluding set
of them. An adversary holding several analyst accounts divides their per-actor
footprint the same way moving between groups divided the per-group one. That is
the honest residual; it is a harder attack to mount than the one V6 measured.

---

## Analyst feedback (V7)

Feedback is evidence. A verdict is a conclusion drawn from evidence. Until V7
there was nothing between them: `datasets.build` selected every current
training-eligible row, so two analysts who disagreed about one event contributed
**two members with opposite `binary_label`** and a model was fitted on both
answers, silently.

`adaptation/feedback/adjudication.py` is that missing step.

| Rule | Why |
| --- | --- |
| One analyst, one voice | Their latest active row. Otherwise one person outvotes a colleague by being verbose |
| Abstentions are counted as abstentions | `suspicious` and `uncertain` carry no position; counting either as a side records hesitation as ground truth |
| Disagreement fails closed | Any dissent under the default policy is `CONFLICTED`, which is **not** training-eligible. A conflicted target needs a human, not arithmetic |
| Confidence is reported, never decisive | Self-reported. Letting it settle a disagreement lets one over-confident analyst overrule two careful ones |

Statuses: `unanimous`, `majority` (opt-in policy only), `conflicted`,
`insufficient`. Only the first two are training-eligible, and only with a
non-null binary projection.

**There is no flag to turn adjudication off.** A caller who could request the
unadjudicated selection would be asking to train on a contradiction. What was
excluded is recorded in the snapshot's `selection.adjudication` block — a
snapshot that quietly dropped a disputed target would hide the disagreement as
effectively as one that trained on it.

Feedback rows also now carry `analyst_id` (FK to `users`, `ON DELETE SET NULL`)
and `analyst_role` — the role held **when the claim was made**, recorded rather
than joined, because roles change and a join would retroactively restate every
past claim in terms of today's permissions. Both are nullable, and a null is a
fact: simulated feedback has no account, and minting one would make a generated
claim indistinguishable from a human's.

### Reading `baselineAssessment`

`flagged` names event types whose benign-labelled **submissions** far exceed
their own history — the signature of a campaign feeding the baseline rather than
fighting the cap (V6 §12).

- **It blocks nothing.** The cap does the bounding; this exists because a
  patient campaign is otherwise invisible, every batch being within policy.
- **An empty `flagged` list is a result**, not a missing check. Where the
  monitor could not run, `unavailableReason` says why and training proceeded.
- **A flag is not a finding of fact.** Investigate the analysts contributing to
  the group. And note V6 §12.4.1: the bands were calibrated against a *greedy*
  adversary, so a slower campaign may not flag at all.

---

## Worked example — the V5 Phase L cycle **[MEASURED]**

| Field | Value |
| --- | --- |
| What changed | `model_update` on `ml.model.isolation_forest` |
| Why | Adaptation cycle following recorded analyst feedback |
| Before | `isolation_forest@1.0` (active) |
| Proposed after | `isolation_forest@2.0` (candidate) |
| Evidence | Feedback dataset of 200 verdicts |
| Validation | **Gates FAILED** — false-positive rate, F1 |
| Outcome | Deployed for the rollback drill, then **rolled back in 1.1 ms** |
| Rollback target | `isolation_forest@1.0`, restored and verified active |

This is the useful kind of card: it records an adaptation that **did not work**.
The gates named the reason, the rollback restored the incumbent, and both facts
survive in the row.

---

## Rules

1. **No card without evidence.** Enforced: `proposals.create` refuses empty
   evidence.
2. **No card claims validation it does not have.** An unevaluated proposal
   records `not_validated`, and the dashboard shows it on the proposal's face.
3. **Rejections and rollbacks are kept.** Nothing is deleted. A refused
   adaptation is a measured result; a rolled-back one is the most informative
   row in the table.
4. **The approver is a person.** Actors prefixed `ai:`, `system:` or
   `automation:` are refused at the service layer.
5. **What feedback contributed is recorded, including what was refused** (V6).
   A candidate whose dataset contributed a third of what its sample count
   implies has a training provenance the card would otherwise state wrongly.
6. **An advisory check that did not run says so.** `unavailableReason` rather
   than a missing field: absent evidence must not read as clean evidence.
