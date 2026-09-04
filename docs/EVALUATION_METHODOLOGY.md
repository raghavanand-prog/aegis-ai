# Evaluation Methodology (V4)

How AEGISX measures itself, and why each choice was made. The goal is not
impressive numbers; it is numbers that survive scrutiny.

---

## 1. The pipeline

```
dataset  →  deterministic adapter  →  PRODUCTION normalizer  →  normalized event
                                                                      │
                                                    PRODUCTION feature extractor
                                                                      │
                                          detector  →  prediction  →  ground truth
                                                                      │
                                                       metrics  →  experiment result
```

The evaluation path reuses the **production** normalizer and the **production**
feature extractor. There is deliberately no second feature pipeline: a metric
computed over features the running system does not produce measures something
that was never deployed.

Evaluation stays conceptually separate from detection. The production path is
`telemetry → normalize → detect → score → persist → correlate/enrich →
investigate`; nothing in `app/evaluation` participates in it.

## 2. The protocol

```
train split       →  fit the detector (labels only where the detector is supervised)
validation split  →  sweep thresholds, choose one, FREEZE it
test split        →  evaluate ONCE, at the frozen threshold
```

This is enforced structurally, not by convention. `select_threshold()` is never
passed the test split, and each detector's test split is evaluated exactly once,
after the threshold is fixed. The frozen value is stored next to the validation
metric that chose it.

Choosing a threshold from test results and then reporting those same results is
the most common way an evaluation reports a number it did not earn.

**Grid boundaries are flagged.** When the winning threshold sits at the edge of
the search grid, the result records `atGridBoundary: true` and a warning that
the true optimum may lie outside the grid, because such a value is not really an
optimum.

## 3. Splits

Two strategies, both deterministic, both group-aware. Neither is preferred by
default:

| Strategy | Question it answers |
| --- | --- |
| `stratified_group` | How does the detector perform on traffic from the same distribution as training? |
| `temporal` | How does a detector fitted on the past behave on the future? |

The choice is declared in the split plan, recorded on the experiment, and made
**before** the metrics are seen. On a non-stationary capture the temporal split
scores materially worse; reporting only the flattering one would be dishonest,
so both are run.

**Both are now also published.** That sentence was aspirational until V8: the
temporal run existed and its artifact was committed at V6, but its detector
results appeared in no report, so in practice only the flattering split was
readable. They are in `docs/RESEARCH_REPORT.md` §2.6, and they are worse — the
production risk path ranks *below chance* under shift, and the Isolation
Forest's MCC at the frozen threshold is negative while its ROC-AUC improves.
That combination is what a misplaced threshold looks like, and it is the reason
this document insists the split strategy is chosen before the metrics are seen.

**Group integrity is non-negotiable.** Every sample sharing a group key lands in
exactly one split. On UNSW-NB15, 46% of rows are exact duplicates of another
row; without this, a detector would be tested on flows it had already memorised.

Grouping keys on the **binary** label rather than the attack category, because
that is the axis detectors are scored on and the only one duplicates always
agree about. See `docs/DATASET_CARD.md` §1 for the 117 groups where they do not
agree on category.

## 4. Feature extraction and causality

Features are extracted **once**, over the whole corpus in chronological order.

This is not a shortcut. AEGISX's behavioural features summarise what an entity
did *before* the current event, so replaying the corpus in arrival order is
exactly what ingestion does. No feature can see the future, and a test sample
legitimately sees the history that preceded it — as it would in production.

Extracting per split would be *less* faithful: it would hand every test sample
an empty history it would never have in service.

## 5. Leakage controls

| Control | Where |
| --- | --- |
| Labels are assigned at generation/load and never inferred from detector output | `labels.py`, `loader.py` |
| No detection output is an ML feature | asserted in `test_evaluation_leakage.py` |
| Feature vectors are unchanged when a label is attached to the candidate | asserted |
| Feature vectors are unchanged when detection results are attached | asserted |
| Dataset bookkeeping (ids, split names, provenance) cannot reach a feature | asserted |
| The dataset's own engineered features stop at the adapter | asserted |
| Duplicate groups never cross a split boundary | asserted for both strategies |
| The test split never influences threshold selection | structural + asserted |
| Splits partition the dataset, losing nothing | asserted |

**Residual leakage is measured, not asserted away.** Group keys stop *known*
duplicates. They cannot stop two genuinely distinct records from landing on the
same feature vector. Every report therefore carries a **leakage audit**: the
share of test samples sharing an exact feature vector with a training sample. A
number, not a claim — because "we checked, there is no leakage" is exactly what
an inflated result would also say.

## 6. Baselines

| Baseline | Role |
| --- | --- |
| **Rules only** | The V2/V3 deterministic engine, unmodified. |
| **Isolation Forest (fitted)** | Fitted on this experiment's training split. Measures what the architecture can do on this data. |
| **Isolation Forest (registered)** | The digest-verified artifact the running system would load, **not refitted**. Measures what is actually deployed. |
| **Supervised (HistGradientBoosting)** | Upper reference over the *same* AEGISX features. |
| **Hybrid (union)** | The V3 definition: a rule fired OR the score crossed the threshold. |
| **Hybrid (risk band)** | AEGISX's production weighted risk scoring, thresholded on the risk score. The only configuration that measures the deployed decision path end to end. |

`HistGradientBoostingClassifier` was chosen over XGBoost/LightGBM because it is
already in the pinned scikit-learn, is strong on tabular data, and adds no
dependency. Deep learning is deliberately absent: nothing about 45 tabular
features calls for it.

The supervised model consumes training labels, which the production detectors do
not. It is **not** an alternative to them — it bounds what the feature schema
supports, which is the only way to tell how much of a gap is the features and
how much is the learning setup.

## 7. Metrics, and when they mean nothing

Always: TP, TN, FP, FN, accuracy, precision, recall, F1, specificity, FPR, FNR.

Where meaningful: ROC-AUC, PR-AUC, balanced accuracy, MCC.

Rules this implementation follows:

- **An undefined metric is `null`, never 0.** Precision with no predictions is
  undefined. A zero would record a measurement that was never made.
- **ROC-AUC and PR-AUC require an ordering.** For a binary rule indicator they
  return `null` with a reason, not the 0.5 a naive implementation prints.
- **PR-AUC is published against the positive rate**, never against 0.5. On an
  11%-positive corpus, 0.5 is not the baseline.
- **MCC is reported because accuracy misleads here.** A detector that flags
  nothing scores 89% accuracy on UNSW-NB15 and MCC of `null`/0.
- **Below 20 samples of either class, ranking metrics are withheld** and
  per-class rates are marked indicative only.
- Both AUC implementations are verified against scikit-learn to 1e-9.

### Score vocabulary — never interchangeable

| Kind | Meaning |
| --- | --- |
| `rule_hit` | Binary indicator. No ordering. |
| `anomaly_score` | Isolation Forest ranking, 0..1. **Not a probability.** |
| `probability` | A supervised classifier's class-1 estimate. The only genuine probability here. |
| `risk_score` | AEGISX's 0..100 weighted policy output. Not a model output at all. |

The kind travels with every detector, into every stored result, and onto every
API response and UI row.

## 8. Confusion matrices

Reported as raw counts **and** row-normalized rates, with each row's support.
Row normalization answers "of the actual attacks, what fraction was caught" —
which is not precision, computed down the predicted column. An unlabelled
normalized matrix routinely gets read as whichever number flatters the system,
so the normalization is always stated.

All values are persisted machine-readably. Nothing depends on reading a chart.

## 9. Ablation

Rules only · ML only · Rules + ML (union) · Rules + ML (production risk scoring).

Component thresholds are held **fixed at production values** in the ablation
rather than swept, so the hybrid is not optimised against a target its
components were not.

Correlation and threat intelligence are absent from the UNSW ablation on
purpose: both need persisted events and entity history a flow corpus does not
provide. They are evaluated separately, on a corpus that can support them,
rather than appearing as a row of zeroes that would read like a measurement.

**What an ablation can conclude:** that removing a component is associated with
a metric change, *under this dataset and this split*. Not that the component
would help on other telemetry, and nothing about interactions beyond the
combinations actually run.

## 10. Correlation

Ground truth is **campaign membership**, not a per-event label: the question is
whether the correlator recovered the attack. Alongside detection rate, the
harness reports **sequence purity** — the fraction of a sequence's members that
truly belong to the campaign it was matched to — because purity is what catches
over-grouping, the V3 bug where a sequence keyed on a user swallowed unrelated
events.

Spurious sequences are reported as a **rate to be read**, not counted as errors:
a sequence over background traffic can be legitimate.

Hand-written entity-scoped correlation is **not** comparable to learned
attack-graph inference, and no result here should be read as evidence about one.

## 11. AI analyst

Evaluated on **grounding, not prose**. Judging writing quality would need a
judge whose own reliability is unestablished. The harness uses the production
grounding verifier: unsupported MITRE techniques, unresolved evidence
references, confidence claimed on evidence the package itself declares
insufficient, and latency.

Results are labelled with the provider that produced them. The built-in
deterministic template provider is labelled **MOCK**, and a mock result measures
the evidence/grounding pipeline — never a language model's behaviour. The core
test suite requires no paid API.

## 12. Statistical validation

Where repeated seeds are run, a **percentile bootstrap** interval over the
per-seed metric is reported with its standard deviation and n.

With fewer than three observations no interval is reported: a "confidence
interval" over two points is decoration, not statistics. Methods are used where
they answer a question, not to make the project look academic.

## 13. Provenance

Every result is traceable to: dataset name, version and fingerprint; split
strategy, fingerprint and seed; feature schema version; ruleset fingerprint;
model name, version and artifact SHA-256; the frozen threshold; and the full
detector configuration.

An experiment id is a hash of that configuration, so the same setup always lands
on the same identity and a changed setup cannot silently overwrite an earlier
result.

`"Accuracy = 94%"` without that provenance is not a result, and no AEGISX
surface emits one.

## 14. What is never done

- No metric is reported that was not measured. Unmeasurable figures are
  `NOT AVAILABLE` with the reason.
- No threshold is chosen from test results.
- No poor result is hidden, and no historical claim is rewritten to match a
  better one.
- No dataset semantics are manufactured to make a subsystem look evaluable.
