# AEGISX V4 Research Report

**Question.** Does the AEGISX hybrid detection architecture provide measurable
value over its individual detection components, and under what conditions?

**Short answer.** Yes on endpoint/identity telemetry, where rules carry the
detection and ML adds the classes rules cannot see. **No on network-flow
telemetry**, where the rules are structurally silent, the unsupervised anomaly
model performs *worse than random ranking*, and the architecture's own safety
guardrail means no event can be raised above Low risk. A supervised model over
the same 45 features reaches F1 ≈ 0.97 on that same data, which locates the
problem in the detection method rather than in the feature schema.

Every figure below was produced by a committed, reproducible command. Where
something was not measured, this report says so.

---

## 1. Experimental setup

| | |
| --- | --- |
| Corpora | UNSW-NB15 v1.0-full (2,280,090 real flows) · aegisx-detection-eval v1.0 (1,950 synthetic events) |
| Protocol | fit on train → sweep thresholds on validation → **freeze** → evaluate test once |
| Splits | Group-aware, stratified on the binary label. Duplicate groups never cross a boundary. |
| Features | The **production** 45-feature extractor, schema v1.0, replayed in chronological order |
| Environment | macOS, Python 3.11.16, scikit-learn 1.7.2, SQLite |

**UNSW-NB15 subsample** (deterministic, hash-keyed on duplicate group):

| | Samples | Malicious | Distinct groups |
| --- | --- | --- | --- |
| Total | 200,526 | 22,325 (11.13%) | 136,075 |
| Train | 120,452 | 13,414 (11.14%) | 81,645 |
| Validation | 40,423 | 4,454 (11.02%) | 27,215 |
| Test | 39,651 | 4,457 (11.24%) | 27,215 |

Dataset fingerprint `f24e4a1e47b7753e` · split fingerprint `a74749098152ca3c` ·
ruleset fingerprint `da203c91430a47a1` · feature schema `1.0`.

> **Provenance correction (V5 Phase A, 2026-09-03).** As first published, the
> split sizes and split fingerprint in this table came from a *different run*
> than the results in §2 — §2's own confusion matrices sum to 39,651 test
> samples against the 40,066 originally stated here, an internal contradiction
> on one page. The regenerated run reproduces every detector result in §2 and §4
> exactly, digit for digit, and the split figures above are now the ones that
> actually produced them. **No measured result changed**; only the provenance
> attached to it was corrected. Artifact:
> `v4-experiments-unsw-nb15-stratified_group-source-20260903T033255Z.json`.

---

## 2. Results — UNSW-NB15 (real network flows)

Test split, threshold frozen on validation. `—` means the metric is undefined
for that detector, not zero.

| Detector | Score kind | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | FPR | MCC | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | rule hit | — | 0 | 35,194 | 0 | 4,457 | — | 0.0% | — | 0.0% | — | — | — |
| Isolation Forest (fitted) | anomaly ranking | 0.42 | 4,457 | 498 | 34,696 | 0 | 11.4% | 100.0% | 20.4% | 98.6% | 0.040 | **0.420** | 0.114 |
| Supervised (HGB) | probability | 0.60 | 4,250 | 35,136 | 58 | 207 | **98.7%** | **95.4%** | **97.0%** | 0.2% | 0.966 | 0.9997 | 0.998 |
| Hybrid (rules OR ML) | rule hit | 0.65 | 215 | 34,054 | 1,140 | 4,242 | 15.9% | 4.8% | 7.4% | 3.2% | 0.028 | — | — |
| Hybrid (production risk) | risk 0-100 | 5.0 | 215 | 34,054 | 1,140 | 4,242 | 15.9% | 4.8% | 7.4% | 3.2% | 0.028 | 0.508 | 0.113 |

PR-AUC baseline (the positive rate) is **0.109**. A PR-AUC of 0.114 is
therefore indistinguishable from flagging at random.

### 2.1 Four findings, none of them flattering

**The rules detect nothing, and that is a scope result, not a quality result.**
Zero true positives, zero false positives, precision undefined. Ten of the
twelve rules read endpoint, identity or process fields that a flow record does
not carry. The port-scan rule needs a policy decision a passive capture never
made — reading TCP `state` as a firewall deny would have manufactured evidence,
so the adapter refuses to. The exfiltration rule needs 500 MB; **the largest
flow in the entire corpus is 13.7 MB**. This was predicted in the dataset card
before the run, not discovered afterwards.

**The Isolation Forest ranks worse than random.** ROC-AUC **0.420**. Below 0.5
means malicious flows are ranked as *less* anomalous than benign ones — the
ordering is mildly inverted. At the F1-optimal threshold it flags 98.7% of all
traffic (987 alerts per 1,000 events) to reach 100% recall, which is not a
detector but an alarm attached to everything.

Why: 11 of the 45 features summarise per-entity behaviour, and this capture is a
testbed with **43 source addresses** across 200k flows, so entity novelty is
near-constant. Worse, the corpus is 19.3% malicious on its second capture day —
attack traffic is not *rare* here, and rarity is the only thing an isolation
forest can detect. The unsupervised premise does not hold on this data.

**The feature schema is not the problem.** A supervised model over the **same 45
features**, the same split and the same protocol reaches F1 0.970, ROC-AUC
0.9997 and PR-AUC 0.998 against a 0.109 baseline. The signal is present and the
features carry it; unsupervised isolation does not recover it.

**The hybrid degenerates, and the safety guardrail becomes a ceiling.** With
rules silent, "rules OR ML" is just ML, and the production risk path is
arithmetically identical to it — measured, and confirmed by construction: ML
contributes at most 25 risk points, and the High band starts at 70. Verified
directly:

```
anomaly 0.65 -> +8 risk -> Low        anomaly 0.95 -> +22 risk -> Low
anomaly 1.00 -> +25 risk -> Low
```

**On flow-only telemetry, AEGISX cannot raise any event above Low risk,
whatever the model says.** The guardrail that stops an anomaly detector becoming
an alert cannon also caps the platform when rules cannot contribute. This is the
most operationally important finding in V4, and it follows from a V3 design
decision working exactly as specified.

### 2.2 The leakage audit fires

Every report carries a measured leakage audit. On this run it fired:

| Split | Samples sharing an exact training feature vector |
| --- | --- |
| Validation | 20,011 / 40,423 (**49.50%**) |
| Test | 20,541 / 39,651 (**51.80%**) |

*(Corrected in V5 Phase A along with the split table in §1; the conclusion —
roughly half the test split is potentially answerable from memory — is
unchanged.)*

Group keys stop the *dataset's* duplicates. They cannot stop AEGISX's feature
extractor from mapping two genuinely distinct flows onto one point — and the
adapter deliberately forwards only what a firewall sensor reports, discarding
UNSW's 40+ engineered columns. Half the test split is therefore potentially
answerable from memory, so **the 0.970 above must be read as an upper bound
until a stricter split says otherwise**.

The stricter experiment was run: regrouping on the feature vector itself
(`--group-by features`) reduces 200,526 samples to **78,265 distinct groups**
and guarantees no memorised vector crosses the boundary. Results in §3 — where,
against expectation, the bound turns out not to be binding.

That regrouping also surfaced a hard limit, measured rather than assumed:

| | |
| --- | --- |
| Feature vectors carrying **both** labels | 44 |
| Samples on such a vector | 300 (0.15%) |
| Irreducible errors (best-case majority rule) | 92 (**0.046%**) |

So the feature schema's Bayes-error floor on this corpus is ~0.05% — small.
The schema is coarse enough to collide often, but almost never in a way that
confuses benign with malicious.

### 2.3 Variance across seeds

Three seeds, percentile bootstrap over test F1:

| Detector | Mean F1 | 95% CI | sd |
| --- | --- | --- | --- |
| Supervised (HGB) | 0.9690 | [0.9682, 0.9698] | 0.0008 |
| Isolation Forest | 0.2014 | [0.1991, 0.2044] | 0.0037 |
| Hybrid | 0.0800 | [0.0740, 0.0861] | 0.0061 |

The separation between supervised and unsupervised is far larger than seed
variance, so it is not a sampling artefact.

### 2.4 Ablation

| Configuration | TP | FP | FN | Precision | Recall | F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | 0 | 0 | 4,375 | — | 0.0% | — | — |
| ML only (0.65) | 245 | 1,482 | 4,130 | 14.2% | 5.6% | 8.0% | 0.022 |
| Rules + ML (0.65) | 245 | 1,482 | 4,130 | 14.2% | 5.6% | 8.0% | 0.022 |
| Rules + ML via risk scoring (band 50) | 0 | 0 | 4,375 | — | 0.0% | — | — |

**Rules contribute exactly zero** — "Rules + ML" is identical to "ML only" to the
last sample. And at the Medium risk band (50), the production path detects
**nothing at all**, because ML alone cannot reach 50. The ablation makes the
ceiling from §2.1 visible as a measurement.

### 2.5 Latency

Detection-engine time only; excludes ingestion, normalization and storage.
Measured on a development laptop against SQLite. **Not a production throughput
claim.**

| Detector | Mean | p95 | Alerts / 1,000 events |
| --- | --- | --- | --- |
| Rules | 0.0026 ms | 0.0028 ms | 0.0 |
| Isolation Forest | 1.82 ms | 1.89 ms | 987.4 |
| Supervised (HGB) | 4.36 ms | 5.31 ms | 108.7 |
| Hybrid (risk) | 1.84 ms | 1.90 ms | 34.2 |

The alert-volume column is the analyst-workload half of the trade-off: the
Isolation Forest's 100% recall costs 987 alerts per 1,000 events, which no SOC
can staff.

---

## 3. Results — UNSW-NB15 with feature-vector grouping

The strict experiment: groups keyed on the AEGISX feature vector itself, so a
memorised vector provably cannot cross into test. 200,526 samples collapse to
**78,265 distinct groups**. Split fingerprint `f21e897527b0f499`.
Train 123,876 · validation 39,607 · test 37,043 (9.92% positive).

| Detector | Score kind | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | FPR | MCC | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | rule hit | — | 0 | 33,370 | 0 | 3,673 | — | 0.0% | — | 0.0% | — | — | — |
| Isolation Forest | anomaly ranking | 0.41 | 3,673 | 0 | 33,370 | 0 | 9.9% | 100.0% | 18.0% | 100.0% | — | **0.423** | 0.107 |
| Supervised (HGB) | probability | 0.35 | 3,596 | 33,256 | 114 | 77 | **96.9%** | **97.9%** | **97.4%** | 0.3% | 0.971 | 0.9998 | 0.998 |
| Hybrid (rules OR ML) | rule hit | 0.65 | 285 | 31,996 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 4.1% | 0.053 | — | — |
| Hybrid (production risk) | risk 0-100 | 5.0 | 285 | 31,996 | 1,374 | 3,388 | 17.2% | 7.8% | 10.7% | 4.1% | 0.053 | 0.518 | 0.102 |

**Leakage audit: 0.00% on validation and 0.00% on test.** Zero test samples
share a feature vector with any training sample.

### The important result: §2 was not inflated

The supervised F1 rises from 0.970 to **0.974** under the strictly
leakage-free split. The 51% overlap in §2 was **not** doing the work — the model
was learning the class boundary, not memorising rows. This is worth stating
plainly because the prior expectation was the opposite, and the audit that
raised the alarm is the same audit that cleared it.

Every other conclusion is unchanged and slightly sharper: the rules still detect
nothing, the Isolation Forest's ROC-AUC is still below chance (**0.423**) and it
now flags **1,000 alerts per 1,000 events** — literally everything — to reach
100% recall.

The split also surfaced the schema's hard floor, reported as a warning on the
plan itself:

> 44 group(s) covering 300 sample(s) carry both labels: the feature schema maps
> them onto one point. Best-case irreducible error is 92 sample(s) (0.046%), a
> floor on the error of any detector built on these features.

The supervised model's 191 errors are about twice that floor, so it is operating
near — though not at — the limit of what these 45 features permit.

Ablation under the strict split is identical in shape to §2.4: rules contribute
exactly zero, "Rules + ML" equals "ML only" to the sample, and the production
risk path at the Medium band detects nothing.

Latency: rules 0.0027 ms, Isolation Forest 1.93 ms, supervised 8.60 ms,
hybrid 1.86 ms (mean, detection engine only).

---

## 4. Results — aegisx-detection-eval (synthetic endpoint/identity)

This is the corpus on which the hybrid question is actually answerable, because
it is the only one that can exercise the rules.

| Detector | Thresh. | TP | TN | FP | FN | Precision | Recall | F1 | FPR | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | — | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 7.3% | 0.852 |
| Isolation Forest (fitted) | 0.41 | 156 | 0 | 234 | 0 | 40.0% | 100.0% | 57.1% | 100.0% | — |
| Supervised (HGB) | 0.95 | 156 | 234 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0.0% | 1.000 |
| Hybrid (rules OR ML) | 0.65 | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 7.3% | 0.852 |
| Hybrid (production risk) | 30 | 145 | 217 | 17 | 11 | 89.5% | 93.0% | 91.2% | 7.3% | 0.852 |

Ablation:

| Configuration | Precision | Recall | F1 | MCC |
| --- | --- | --- | --- | --- |
| Rules only | 89.5% | 93.0% | 91.2% | 0.852 |
| ML only (0.65) | 100.0% | 1.9% | 3.8% | 0.108 |
| Rules + ML (0.65) | 89.5% | 93.0% | 91.2% | 0.852 |
| Rules + ML via risk (band 50) | 100.0% | 53.2% | 69.5% | 0.637 |

**Read these with the caveats, not without them.** The supervised 1.000 is not
a triumph: this corpus is generated from per-class templates and is
near-perfectly separable. Measured, only 101 of 1,950 rows (5.2%) share an exact
feature vector and none span categories, so it is template separability rather
than leakage — but the corpus still **cannot distinguish a good supervised
detector from an excellent one**. Leakage audit: 3.6% validation, 4.9% test,
both below the 5% concern threshold.

The ML contribution here is small (1.9% recall at the production threshold)
because this corpus was built to exercise *rule thresholds* and is out of
distribution for a model trained on the runtime generator. That is the same
caveat V3 published, now measured under the V4 protocol.

---

## 5. Correlation evaluation

Ground truth is campaign membership: 24 injected campaigns interleaved with 200
unrelated events.

| Metric | Value |
| --- | --- |
| Campaigns detected | 15 / 24 (62.5%) |
| Sequences opened | 26 |
| Spurious sequences | 1 (3.9%) |
| Mean sequence purity | 54.3% |
| Mean sequence size | 10.08 events |
| Mean confidence | 0.629 |
| Alert reduction | 262 events → 26 sequences (**10.08×**) |
| Correlation latency | mean 1.75 ms, p95 4.19 ms, p99 4.95 ms (DB included) |

By campaign type:

| Pattern | Detected | Mean purity |
| --- | --- | --- |
| Credential attack | **8 / 8** | 70.7% |
| Lateral movement | 4 / 8 | 27.8% |
| Host intrusion | 3 / 8 | 48.4% |

The credential pattern — the one AEGISX was designed around — recovers every
campaign. Lateral movement recovers half, at low purity.

Mean purity of 54% means a matched sequence contains roughly as many unrelated
events as campaign events. Part of that is the evaluation setup rather than the
correlator: the synthetic generator draws from a small pool of users and hosts,
so background traffic legitimately shares an entity with a campaign, and an
entity-scoped correlator cannot separate them. The figure is a lower bound on
purity and an upper bound on what entity scoping can achieve on a namespace this
small.

**This is not comparable to learned attack-graph inference** and is not evidence
about real attacks.

---

## 6. AI analyst evaluation

| Metric | Value |
| --- | --- |
| Provider | `mock` — **the built-in deterministic template analyst, not a language model** |
| Cases completed | 5 / 5 |
| Grounded analyses | **5 / 5 (100%)** |
| Unsupported MITRE technique warnings | 0 |
| Unresolved evidence reference warnings | 0 |
| Overconfident analyses | 0 |
| Latency | mean 1.85 ms |

**What this measures:** the evidence-assembly, sanitization, grounding and
persistence pipeline. **What it does not measure:** any language model's
behaviour. OpenAI and Anthropic clients are implemented and have **never been
executed against a live API** — no grounding claim about a hosted model is made
anywhere.

---

## 7. Threat-intelligence evaluation

| Metric | Value |
| --- | --- |
| Provider configured | none |
| Enrichment success / cache hit rate / provider latency | **NOT AVAILABLE** |
| SSRF validation probes refused | **6 / 6** |

Refused: RFC 5737 documentation ranges (203.0.113.10, 198.51.100.42), RFC 1918
private (10.0.0.5), loopback (127.0.0.1), the **cloud metadata endpoint**
(169.254.169.254), and a malformed domain.

The documentation-range refusals are also the measured reason enrichment stays
silent on synthetic telemetry — a behaviour, not an assumption. No live provider
call has ever been made from this repository, so any figure about VirusTotal's
accuracy would be fabricated.

---

## 8. Degraded-mode evaluation

The V3 guarantee under test: an optional subsystem failing must never become an
ingestion failure.

| Scenario | Events normalized | Rule detections | Ingestion survived |
| --- | --- | --- | --- |
| No model ever loaded | 60 / 60 | 15 | ✅ |
| Corrupt model artifact | 60 / 60 | 15 | ✅ |
| Artifact digest mismatch | 60 / 60 | 15 | ✅ |
| Threat intelligence unconfigured | 60 / 60 | 15 | ✅ |
| AI analyst state query | 60 / 60 | 15 | ✅ |

Every unavailable state carries a reason. A corrupt artifact and a digest
mismatch are both **refused**, not loaded. An unloaded engine returns `None`
from `score()` with a stated reason, so "no anomalies found" and "no model
running" never render identically.

---

## 9. Reproducing this report

```bash
python -m app.evaluation.datasets.unsw_nb15.fetch
python -m app.evaluation.run_experiments --dataset unsw-nb15 --split stratified_group --seeds 3 --persist
python -m app.evaluation.run_experiments --dataset unsw-nb15 --split stratified_group --group-by features --persist
python -m app.evaluation.run_experiments --dataset aegisx-synthetic --persist
python -m app.evaluation.run_system_eval
```

Verify: dataset fingerprint `f24e4a1e47b7753e`, synthetic fingerprint
`c0f04f3ccb2a63b8`, ruleset fingerprint `da203c91430a47a1`, feature schema
`1.0`. See `docs/REPRODUCIBILITY.md` for tolerances.

---

## 10. Limitations

1. **No production traffic.** Both corpora are a 2015 testbed capture and a
   synthetic generator. No claim of real-world detection accuracy is made.
2. **The rules were never exercised on UNSW-NB15.** Their zero is a telemetry
   mismatch. The rule quality figures come from a synthetic corpus built to
   exercise them, which is a favourable setting.
3. **The supervised model is a reference, not a product.** It consumes training
   labels, which AEGISX's production detectors do not. It bounds what the
   feature schema supports; it is not an alternative that could be deployed
   as-is.
4. **51% source-grouped feature-vector overlap** on UNSW. §3 re-ran the whole
   comparison with that overlap driven to 0.00% and the conclusions held, so §3
   is the number to quote — but the overlap is a real property of applying this
   feature schema to flow data and would matter for any other model tried on it.
5. **The synthetic corpus is too easy** for a supervised model to be informative.
6. **Correlation purity is bounded by the evaluation setup**, not only by the
   correlator.
7. **AI results are mock-provider results.** Hosted providers never executed.
8. **Threat intelligence is unmeasured.** No provider, by design.
9. **Latency is laptop-and-SQLite.** Not a production throughput claim.
10. **PostgreSQL not verified locally** — SQLite throughout; CI covers Postgres.
11. **Per-class rates for rare families are unreliable** (`worms` has 9 training
    samples), and 117 duplicate groups carry ambiguous attack categories.

## 11. What V4 did not do

No automatic or scheduled retraining, no active learning, no
analyst-feedback-driven model updates, no adaptive or self-tuning thresholds,
no autonomous deployment, no autonomous response, no self-modifying rules. V4 is
measurement. Those belong to V5, and building them before the yardstick existed
would have meant changing the detector and the measure at once.

## 12. Recommendation

On the evidence here, AEGISX should **not** be pointed at flow-only telemetry as
configured: the rules cannot fire, the anomaly model ranks below chance, and the
risk ceiling caps every alert at Low. Two options are supported by the
measurement — extend the adapter so flow telemetry populates the aggregate
fields the rules read, or treat flow data as a domain requiring its own
detector. The supervised result establishes that the feature schema is adequate
either way.
