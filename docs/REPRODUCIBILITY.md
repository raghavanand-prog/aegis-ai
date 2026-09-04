# Reproducibility Guide

Everything needed to take a number out of AEGISX's research section and get the
same number back.

---

## 1. Environment

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Python 3.11+
pip install -r requirements.txt
```

Versions are pinned deliberately. scikit-learn in particular: a model artifact
is only reproducible against the version that wrote it, and the loader verifies
the artifact digest.

```bash
export DATABASE_URL="sqlite:///aegisx.db"    # or a PostgreSQL URL
alembic upgrade head                          # through 0004_v4_evaluation
```

## 2. Obtain the corpus

UNSW-NB15 is 230 MB of third-party licensed data and is **not** committed.

```bash
python -m app.evaluation.datasets.unsw_nb15.fetch
```

The fetch verifies each shard against a recorded SHA-256. A file that does not
match is refused, and every experiment re-verifies before loading — evaluating
against unidentified bytes is refused rather than warned about.

```
train-00000-of-00002.parquet  2aada2a26d061111f4e8fb84e716f5f11264fee71abe04697d42cb89e488d047
train-00001-of-00002.parquet  7c6699ae967567977dee9e9193543b515255f4e1671ca79bf9ae65e7866ffef1
```

The synthetic corpus needs no fetch; it is generated deterministically in
process.

## 3. Reproduce the V3 model (optional)

Only needed to evaluate the *deployed* artifact (`--include-registered`). The
fitted baselines do not require it.

```bash
python -m app.ml.training.train_anomaly_model
```

Expected, and verifiable from the run's own output:

| Property | Value |
| --- | --- |
| Corpus fingerprint | `f0fbefc8d38a8a53` |
| Samples | 6,000 (4,800 fitted, 1,200 held out) |
| Seed | 4242 |
| Contamination | 0.08 |
| Recommended threshold | 0.648 |
| Flagged at 0.65 | 0.75% of held-out traffic |

> **Corrected in V5 Phase A.** This table previously read 0.654 / 1.25%. Those
> figures do not reproduce. Three independent runs — two in isolated artifact
> directories — produce the byte-identical artifact `016c6dbf37f53d03…` with
> 0.75% flagged and a recommended threshold of 0.648. Training **is** fully
> deterministic; the published numbers were stale.
>
> Note also that the artifact shipped as the V4 deployed model
> (`053d1ff3…`) is **not** reproducible from current code. It predates the
> determinism fix described in the V4 handoff §3 and is an orphan.

A different corpus fingerprint means the generator changed. Investigate before
comparing any number against a published one.

## 4. Run the experiments

**`--max-seconds 3600` is part of the command, not an optional extra.** The
watchdog's 900 s default cannot complete a UNSW run and the run then writes
*nothing* — see the measurement below. Every UNSW command here carries it.

```bash
# Primary comparison: random, group-aware, stratified split   (~32 min)
python -m app.evaluation.run_experiments \
  --dataset unsw-nb15 --split stratified_group --seed 1337 --persist \
  --max-seconds 3600

# Distribution shift: chronological split over the same corpus  (~32 min)
python -m app.evaluation.run_experiments \
  --dataset unsw-nb15 --split temporal --seed 1337 --persist \
  --max-seconds 3600

# Rules vs ML vs hybrid, on the only corpus that can exercise the rules
python -m app.evaluation.run_experiments \
  --dataset aegisx-synthetic --seed 1337 --persist

# Variance across seeds (bootstrap intervals need at least three)
python -m app.evaluation.run_experiments \
  --dataset unsw-nb15 --seeds 3 --persist --max-seconds 10800
```

**Measured runtime [MEASURED, V8].** The temporal run above was timed end to
end at the V8 checkpoint on an Apple Silicon laptop (macOS 26.6.2 arm64,
Python 3.11.16, scikit-learn 1.7.2):

| Stage | Wall clock |
| --- | --- |
| Rules | 1.1 s |
| Isolation Forest | 267.8 s |
| Supervised (HGB) | 535.1 s |
| Hybrid | 204.8 s |
| Hybrid (risk) | 265.4 s |
| Ablation (rules 0.6 s + 3 configurations) | 618.6 s |
| Corpus load, feature extraction, leakage audit, report write | 18.3 s |
| **Total** | **1,911.07 s (31 min 51 s)** |

So the 900 s default is **2.1× too small** and 3600 s leaves ~1.9× headroom.
`--seeds 3` repeats the baseline suite three times and wants ~3 hours, hence
`--max-seconds 10800` above.

Nothing partial is produced when the ceiling fires: the report is written once,
at the end, so a watchdog kill leaves **no artifact at all** rather than a
half-populated one. That is the intended failure mode — a truncated report that
looked complete would be far worse — but it does mean a run that dies at 900 s
costs the full 900 s and returns nothing.

Correlation, AI analyst, threat intelligence and degraded mode:

```bash
python -m app.evaluation.run_system_eval
```

### V5 and V6 adaptation experiments

Every number in `docs/V6_RESEARCH_REPORT.md` comes from one of these, and each
writes a committed artifact under `app/evaluation/reports/`.

```bash
export DATABASE_URL="sqlite:///aegisx.db"

# §1  the V5 adaptation effect, 50 seeds
python -m app.adaptation.experiments.run_adaptation_eval          --seeds 50 --max-seconds 5400
# §2  novel behaviour, per category, feedback withheld vs supplied
python -m app.adaptation.experiments.run_novel_behaviour_eval     --seeds 10 --max-seconds 3600
# §3  detector class vs feature space (threshold-free, ROC-AUC)
python -m app.adaptation.experiments.run_detector_comparison      --seeds 10 --max-seconds 5400
# §4  fit-set contamination sweep
python -m app.adaptation.experiments.run_contamination_eval       --seeds 10 --max-seconds 3600
# §5  the baseline as production configures it
python -m app.adaptation.experiments.run_production_baseline_eval --seeds 10 --max-seconds 3600
# §6  the redesigned Arm 2
python -m app.adaptation.experiments.run_arm2_eval                --seeds 10 --max-seconds 3600
# §7  feedback quality, ten conditions
python -m app.adaptation.experiments.run_feedback_quality_eval    --seeds 10 --max-seconds 5400
# §8, §9  targeted poisoning, one run per cap policy
python -m app.adaptation.experiments.run_targeted_poisoning_eval  --seeds 8 --max-seconds 5400 \
    --targets MALWARE --cap-policy baseline_relative
# §11 the patient adversary, and the tolerance sweep
python -m app.adaptation.experiments.run_patient_poisoning_eval   --seeds 8 --max-seconds 5400
```

Total well under one CPU-hour. Seeds come from one standing plan
(`app/adaptation/experiments/seeds.py`) in which a longer plan **extends** a
shorter one, so `--seeds 3` still reproduces V5 exactly and every run stays
comparable with the last.

Every CLI accepts `--max-seconds` (default 900; `0` disables). On expiry it
exits 142 with thread stacks rather than hanging silently — the V3 deadlock
taught that lesson.

> **The default is too small for the UNSW suite.** First observed in V5 Phase A;
> **timed end to end in V8 at 1,911 s** for the full temporal run (§4). The
> watchdog fires mid-suite and **no report is written**. Pass
> `--max-seconds 3600` for any full UNSW run — it is written into the §4
> commands for exactly this reason. This is why no V4 experiment artifacts
> existed on disk at the V5 handoff.
>
> The default is left at 900 s deliberately. It is correct for the adaptation
> experiments and for CI, and raising it globally would mean a genuinely hung
> run burns an hour before anyone is told. The cost of the current design is
> that the ceiling must be passed explicitly for the one suite that exceeds it.

## 5. Verify you reproduced it

Each result carries the identity of everything that could change it. Compare, in
this order:

1. **Dataset fingerprint** — different data, nothing else matters.
2. **Split fingerprint** — same data, different partition.
3. **Feature schema version** — different features, incomparable numbers.
4. **Ruleset fingerprint** — the rules changed.
5. **Model version + artifact SHA-256** — a different model.
6. **Frozen threshold** and **experiment id**.

An experiment id is a hash of the whole configuration. **The same configuration
always produces the same id**; if your id matches a published one, you ran the
same experiment, and the metrics should match within the tolerance below.

Reference values for the default configuration:

| Property | Value |
| --- | --- |
| UNSW-NB15 dataset fingerprint (200k sample, salt `aegisx-v4`) | `f24e4a1e47b7753e` |
| Samples realised | 200,526 (22,325 malicious, 11.13%) |
| Distinct duplicate groups | 136,075 |
| Synthetic corpus fingerprint | `c0f04f3ccb2a63b8` |
| Ruleset fingerprint | `da203c91430a47a1` |
| Feature schema | `1.0` (45 features) |

## 6. Numerical tolerance

| Component | Expectation |
| --- | --- |
| Dataset loading, splitting, feature extraction | **Bit-exact.** Fingerprints must match exactly. |
| Rule evaluation | **Bit-exact.** Deterministic. |
| Isolation Forest, same seed and scikit-learn version | Exact |
| HistGradientBoosting, same seed and version | Exact |
| Across scikit-learn versions | **Not guaranteed.** Compare fingerprints, not floats. |
| Across seeds | Genuinely varies — this is why `--seeds` and bootstrap intervals exist |
| Latency figures | **Never reproducible.** Hardware-dependent, reported as measured on the machine named in `environment`. |

If fingerprints match and metrics do not, the software changed, not the data.
That is a finding worth investigating, not smoothing over.

## 7. Inspect raw results

- **JSON reports** — `app/evaluation/reports/`, schema-versioned, one file per
  run plus a `latest-*.json` pointer per report family. These are the archival
  artifact.

  > **Retention changed in V6.** Timestamped reports are now **committed to the
  > repository**; only the mutable `latest-*` pointers are ignored. V4 and V5
  > published every number from files that `.gitignore` excluded, so no
  > published result could be checked against the run that produced it — against
  > this document's own rule that a result must not depend on an undocumented
  > local file. A pointer rewritten on every run is the opposite of an immutable
  > artifact, which is why it stays ignored.
- **Database** — `--persist` indexes results in `evaluation_datasets`,
  `evaluation_experiments` and `evaluation_runs`. The rows are an index over the
  files, not a replacement for them.
- **API** — `GET /api/v1/evaluation/experiments`, `.../{id}`,
  `.../{id}/confusion-matrix`, `.../{id}/threshold-sweep`, `/compare`,
  `/datasets`. Read only.
- **UI** — `/dashboard/research`.

## 8. Understand the limitations before quoting anything

Read `docs/DATASET_CARD.md` §1 "What this dataset cannot evaluate" first.

The short version: **AEGISX's deterministic rules cannot fire on UNSW-NB15's
flow telemetry.** A rules baseline of zero detections there is a property of the
telemetry, not a measured failure of the rules, and the hybrid comparison on
that corpus degenerates to ML alone. The rules-vs-ML-vs-hybrid question is
answered on the synthetic corpus.

Neither corpus is production traffic. **No claim of real-world detection
accuracy is made anywhere in AEGISX.**

## 9. Full verification

```bash
cd backend  && pytest                 # backend suite
cd backend  && ruff check .
cd frontend && npm run verify         # eslint + tsc + vitest + build

# migrations: partial downgrade exercises the V4/V5 revisions in isolation
alembic upgrade head && alembic downgrade 0003_v3_hybrid && alembic upgrade head
# full round-trip exercises every revision
alembic upgrade head && alembic downgrade base && alembic upgrade head
```

Measured at the **V8** checkpoint: **835 backend tests** collected and passing
(`pytest` exit 0; 15 of them are the PostgreSQL module, which skips and says so
when `AEGISX_TEST_POSTGRES_URL` is unset), **56 frontend tests**, ruff/eslint/tsc
clean, `vite build` passing with a pre-existing chunk-size warning, migrations
round-tripping to head `0011_v7_approval_governance`.

*(V6 measured 688 backend / 50 frontend at head `0009_v5_proposals`. Those
figures stood in this document until V8 and are kept here as history.)*

**PostgreSQL was validated in V7** — 11 migrations, CHECK constraints, foreign
keys, `ON DELETE SET NULL`, JSONB path queries, transactional rollback and the
approval state transitions, against PostgreSQL 16.15. It needs Docker:

```bash
docker compose -f infrastructure/docker-compose.yml up -d postgres
AEGISX_TEST_POSTGRES_URL=postgresql+psycopg://aegisx:aegisx@localhost:5432/aegisx pytest
```

Every *research* figure in this document is still SQLite on a laptop; the
PostgreSQL validation covers the schema and the transactional behaviour, not the
experiments.
