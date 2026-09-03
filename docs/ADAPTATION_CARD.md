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
| **Proposed by** | `proposed_by` | `ai:` prefix where AI-drafted |
| **Approved by** | `approved_by` | Never an `ai:`/`system:` actor — refused |
| **Self-approved** | `self_approved` | Recorded, not prevented |
| **Deployed by / at** | `deployed_by`, `deployed_at` | |
| **Rollback target** | `rollback_state` | Captured at deployment |
| **Rolled back by / why** | `rolled_back_by`, `rollback_reason` | |

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
