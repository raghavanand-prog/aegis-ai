# Dataset Card — AEGISX V4 Evaluation Corpora

Two corpora are used, for different reasons. Neither replaces the other, and
results from one must never be pooled with results from the other.

| Corpus | Telemetry class | What it can fairly evaluate |
| --- | --- | --- |
| **UNSW-NB15** | Network flows (real capture) | ML and supervised detection on real traffic |
| **aegisx-detection-eval** | Endpoint / identity / process (synthetic) | Rules, and the rules-vs-ML-vs-hybrid comparison |

---

## 1. UNSW-NB15

### Provenance

| Field | Value |
| --- | --- |
| Source | https://huggingface.co/datasets/Mouwiya/UNSW-NB15 |
| Original publisher | Australian Centre for Cyber Security, UNSW Canberra |
| Citation | Moustafa, N. & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems.* MilCIS 2015. |
| Licence | Free for academic research use with attribution. Redistribution terms are the publisher's, not AEGISX's. |
| Version used | `1.0-full` (the complete 2,280,090-record capture, not the 175k partition) |
| Collection | IXIA PerfectStorm traffic generator, 2015, two capture periods |
| Committed to git? | **No.** 230 MB of third-party licensed data. Fetched by an explicit operator step. |

**File digests** (verified on every load; a mismatch refuses to evaluate):

```
train-00000-of-00002.parquet  2aada2a26d061111f4e8fb84e716f5f11264fee71abe04697d42cb89e488d047
train-00001-of-00002.parquet  7c6699ae967567977dee9e9193543b515255f4e1671ca79bf9ae65e7866ffef1
```

Fetch with:

```bash
python -m app.evaluation.datasets.unsw_nb15.fetch
```

### Why this dataset

Assessed before selection, not after:

| Criterion | Finding |
| --- | --- |
| Label quality | **Strong.** Across all 2,280,090 records, zero benign rows carry an attack category and zero malicious rows lack one. `label` and `attack_cat` never disagree. |
| Feature structure | Flow-level with **real source/destination addresses, ports, protocol, service and timestamps** — the reason the full capture was chosen over the standard 175k partition, which strips them. |
| Class balance | 11.08% malicious (252,752 / 2,280,090). Realistically skewed; PR-AUC is reported against this rate, never against 0.5. |
| Temporal characteristics | Real timestamps spanning 2015-01-22 to 2015-02-18, enabling a genuine temporal split. |
| Duplicates | **Severe and material** — see below. |
| Compatibility with AEGISX | Partial, honestly. See "What this dataset cannot evaluate". |

The 175k partition CSV was rejected: without IPs or timestamps, AEGISX's 11
entity/behaviour features would be constant, and a temporal split impossible.

### Labels

Nine attack families plus benign. The raw column is not clean, and every
transformation is recorded explicitly in
`app/evaluation/datasets/unsw_nb15/labels.py`:

| Raw literal (verbatim) | Normalized | Count |
| --- | --- | --- |
| *(NULL)* | `benign` | 2,027,338 |
| `Generic` | `generic` | 159,161 |
| `Exploits` | `exploits` | 39,390 |
| `' Fuzzers '` | `fuzzers` | 15,448 |
| `DoS` | `dos` | 15,618 |
| `' Reconnaissance '` | `reconnaissance` | 10,176 |
| `' Fuzzers'` | `fuzzers` | 5,051 |
| `Analysis` | `analysis` | 2,474 |
| `Backdoor` | `backdoor` | 1,702 |
| `' Shellcode '` | `shellcode` | 1,066 |
| `Reconnaissance` | `reconnaissance` | 1,759 |
| `Backdoors` | `backdoor` | 534 |
| `Shellcode` | `shellcode` | 223 |
| `Worms` | `worms` | 150 |

**Excluded: nothing.** Every record carries a usable label and every record is
eligible for evaluation.

**Folded:** whitespace and plural variants of the same documented family
(`' Fuzzers '` → `fuzzers`, `Backdoors` → `backdoor`). Unknown literals are
*refused*, not coerced, so a value this project has never seen cannot be
silently absorbed into an existing class.

**Not mapped to the AEGISX `Label` enum.** That enum describes the
endpoint/identity classes of the synthetic corpus. "Generic" (a cryptographic
block-cipher attack) and "Fuzzers" have no AEGISX counterpart, and inventing
one would fabricate a result. The taxonomies stay separate.

### Duplicates and label ambiguity — both measured

**1,053,500 rows (46.2%)** belong to an exact-duplicate feature group; there
are 350,371 such distinct groups. Splits are therefore **group-keyed**: every
copy of a flow lands in one split, so a model cannot be tested on a row it
memorised.

Two facts about those groups, established by inspection:

- **No group has a conflicting binary label.** Duplicates add no label noise on
  the axis detectors are scored on.
- **117 groups (0.09%, 3,055 rows) carry more than one attack category** — the
  same byte-identical malicious flow labelled as up to seven different families
  (`analysis`, `backdoor`, `dos`, `exploits`, `fuzzers`, `generic`,
  `reconnaissance`). This is real ambiguity in the source taxonomy.

Grouping therefore keys on the **binary** label. Splitting those groups apart to
tidy the categories would let a memorised flow cross into test — trading a real
inflated metric for a cosmetic one. Per-class detection rates for the affected
families carry corresponding uncertainty, and the split plan reports it.

### Splits

Both are implemented; neither is the default "right" one.

| Strategy | What it measures |
| --- | --- |
| `stratified_group` | Like-for-like: train and test from the same distribution. Group-aware, stratified on the binary label. |
| `temporal` | Distribution shift: fitted on the past, evaluated on the future. Groups ordered by earliest observation. |

**The capture is strongly non-stationary**, which is why both are reported:

| Capture day | Records | Malicious |
| --- | --- | --- |
| 2015-01-22 | 1,052,863 | 2.11% |
| 2015-01-23 | 34,340 | 0.00% |
| 2015-02-18 | 1,192,887 | 19.33% |

A temporal split trains at a ~2% base rate and tests at ~19%. That is a
legitimate and interesting experiment, but it is a *different* experiment from
the random split, and reporting only whichever scored better would be
dishonest.

### What this dataset cannot evaluate

Stated up front rather than discovered in the results:

- **AEGISX's deterministic rules.** They are endpoint-, identity- and
  process-oriented. On flow-only telemetry, ten of the twelve cannot fire for
  want of the fields they read; the port-scan rule cannot fire because a
  passive capture contains no policy decision (reading TCP `state` as a
  firewall deny would manufacture evidence); and the exfiltration rule cannot
  fire because **the largest flow in the corpus is 13.7 MB against a 500 MB
  threshold**. The expected rules baseline here is *zero detections*, and that
  is a property of the telemetry, not a measured failure of the rules.
- **The hybrid comparison.** With rules silent, "rules OR ML" degenerates to
  "ML". The hybrid question is answered on the synthetic corpus instead.
- **Behavioural correlation.** Flow records give no multi-stage campaign
  structure.
- **Entity novelty features.** The capture is a testbed with **43 source and 47
  destination addresses** across 2.28M flows, so `source_ip_is_new` and its
  relatives are near-degenerate.
- **Threat intelligence.** No live provider; the addresses are 2015 testbed
  addresses, not current indicators.

### Sampling

Experiments default to an approximate ceiling of 200,000 samples, selected by a
**deterministic hash of the duplicate group key** rather than by shuffling.
Consequences:

- The subset is a pure function of the data — independent of read order, pandas
  version or worker count.
- Every copy of a duplicated flow is selected or rejected together.
- The realised count is not exactly the requested maximum (200,526 at the
  default). Forcing an exact number would either break determinism or truncate
  the tail of the capture; the realised count is recorded in `sampling`.

---

## 2. aegisx-detection-eval (synthetic)

| Field | Value |
| --- | --- |
| Source | `app/evaluation/datasets/labeled_dataset.py`, generated in-process |
| Licence | Part of AEGISX; no third-party terms |
| Version | 1.0, seed 1337 |
| Size | 1,950 samples (780 malicious / 1,170 benign, 40% positive) |
| Taxonomy | The AEGISX `Label` enum: 13 attack classes plus benign |

Retained because it is the **only corpus that can exercise AEGISX's rules**, and
therefore the only one on which rules-vs-ML-vs-hybrid is a meaningful
comparison.

Documented properties that limit what it can support:

- **Synthetic.** Nothing here is evidence about real-world attack traffic.
- **Out of distribution for the anomaly model**, which is trained on the runtime
  telemetry generator. ML metrics on this corpus are a lower bound and must not
  be quoted as the model's detection rate.
- **Near-perfectly separable for a supervised model.** Samples are generated
  from per-class templates; measured, only 101 of 1,950 rows (5.2%) share an
  exact feature vector and none span categories, so a supervised F1 of 1.000
  here reflects template separability, not leakage. **The corpus cannot
  distinguish a good supervised detector from an excellent one** — which is
  precisely why a public corpus was needed.
- `LATERAL_MOVEMENT` is included deliberately with **no corresponding rule**, so
  the evaluation reports what the rule set cannot see instead of quietly
  excluding it.
- Benign samples include deliberate near-misses (four failed logins against a
  threshold of five, nineteen scanned ports against twenty) and activity that
  legitimately looks suspicious (an administrator running `certutil`, a backup
  job moving large volumes), so the false-positive rate is not flattered.

---

## 3. Distribution mismatch

The two corpora describe different telemetry classes and must not be pooled.
The evaluation API enforces the weaker version of this rule at the query level:
`/evaluation/compare` refuses to call two experiments comparable when their
dataset fingerprints differ, returning them with a warning instead of a verdict.

Neither corpus is production traffic from a real organisation. **No claim of
real-world detection accuracy is made anywhere in AEGISX.**
