# AEGISX V8 → V9 HANDOFF

> Written at the end of the V8 session for a **fresh Claude Code session**.
> Every claim below was checked against the repository or a command's output
> immediately before writing, not recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged **[MEASURED]**, **[IMPLEMENTATION]**, **[LIMITATION]**,
**[INFERENCE]** — as in V4–V7.

---

## 1. Executive summary

V8 was scoped as evidence and reproducibility closure, not feature work, and
that is what it did. **No V4/V5/V6/V7 measured result changed.**

The session's most useful finding is uncomfortable and worth stating first:
**three of the ten gaps the V8 brief listed were already closed, and the brief's
description of the repository was wrong on several points.** The work that
mattered was not building what the brief asked for; it was discovering that
several experiments had *already been run and simply never published*, and that
two thirds of the research report was still backed by files `.gitignore`
excluded.

What V8 actually changed:

- **The temporal UNSW-NB15 evaluation is published** (§4). It had been run at V6
  and its artifact committed; its detector results appeared in no report. They
  are not flattering.
- **The deployed model artifact is evaluated and published** (§5). Same story:
  `--include-registered` *was* passed on the V6 synthetic run and the result was
  recorded and never published, so the only Isolation Forest number a reader
  ever saw on that corpus described a refit stand-in, not the shipped model.
- **Every published result now has a committed artifact** (§8). §3 and §§5–8 had
  none. Both were re-run; both reproduced exactly.
- **Two real defects were found by doing the reproductions** (§6): an unstable
  experiment id for registered models, and a reproduction instruction that
  tells the reader to check a fingerprint the run does not produce.
- **Augmentation provenance reaches approvers** (§9), and **approval latency is
  measured for the half a machine can honestly measure** (§10).

**§13 lists what V8 did not do, without softening.**

---

## 2. Checkpoint **[MEASURED]**

```
V4 checkpoint:        65a8671
V5 checkpoint:        52eea0d
V6 checkpoint:        b7fa9cc
V7 implementation:    da0a8c6
V7 checkpoint:        630cb4d   docs(v7): record the checkpoint …
V8 implementation:    c5e293b   research(v8): back every published result …
V8 handoff:           3cdecab   docs(v8): the handoff, and what the brief got wrong
V8 closure commit:    this commit — the child of 3cdecab, which closes V8
```

Following V7's decision 45: a document cannot contain the SHA of the commit that
adds it. `c5e293b` and `3cdecab` are real and checkoutable; this closure commit
is identified by its relationship to them. `git log --oneline -5` resolves all
three.

**V8 is CLOSED at this commit.** §18 records the closure verification.

**V8 starting checkpoint, verified at session start:** `HEAD`, `origin/main` and
`origin/HEAD` were all at `630cb4d`, working tree clean. V7's §2 was correct.

**The three V8 implementation commits:**

| SHA | Subject |
| --- | --- |
| `a4076ee` | `research(v8): publish the temporal UNSW results, and time the run that produces them` |
| `3a56a1a` | `feat(v8): evaluate the deployed artifact, and put provenance in front of approvers` |
| `c5e293b` | `research(v8): back every published result with a committed artifact` |

Nothing amended, rebased or force-pushed.

---

## 3. Corrections to the V8 brief **[MEASURED]**

The brief that opened this session described the repository inaccurately in
several places. Recording them because the next brief will otherwise inherit
them.

| Brief said | Repository says |
| --- | --- |
| "V7 ended with 553 tests passing" | **835.** V7's own handoff says 835; `pytest --collect-only` counts 835 at `630cb4d`. |
| "No full temporal UNSW-NB15 run was published" | The **run existed** — committed at V6 `5496a22` as an immutable artifact. Its *results* were never published. Different problem, different fix. |
| "`--include-registered` … was NOT exercised in the published runs" | It **was**, on the synthetic corpus, and the result sits in the committed V6 artifact. Again: run, not published. |
| "Model version immutability is currently database-only … rebuilding the DB can cause v1.0 to be issued again" | **Fixed at V5**, commit `ddb96b8`. The digest transition `053d1ff3 → 016c6dbf` the brief cites is the *historical incident that motivated that fix*, not an open bug. Verified against the original scenario (§7). |
| "Documented retrain figures do not reproduce" | They **do**. V5 Phase A corrected them (0.654/1.25% → 0.648/0.75%) and the corrected figures reproduce byte-for-byte (§7). |
| "§1 states 40,066 test samples" (report inconsistency) | Already corrected in **V5 Phase A**. §1 has said 39,651 since, with the contradiction recorded as history. Verified against the artifact. |

**[INFERENCE]** The pattern is consistent: several V8 "gaps" were work that had
been *done but not written up*. That is a real failure mode and worth naming —
an experiment whose results are not published is, for every practical purpose,
an experiment that was not run.

---

## 4. Temporal UNSW-NB15 evaluation **[MEASURED]**

Published as `docs/RESEARCH_REPORT.md` §2.6. Re-run at this checkpoint;
**identical to the V6 artifact in every field except its timestamp, command
string and measured latencies.**

Split (`temporal`, fingerprint `c3a3830a9db1bce2`, seed 1337):

| | Samples | Malicious | Attack density |
| --- | --- | --- | --- |
| Train | 88,417 | 1,958 | 2.21% |
| Validation | 32,311 | 4,234 | 13.10% |
| Test | 79,798 | 16,133 | 20.22% |

The shift is real, not induced — the capture's second day is far more hostile
than its first. **Test leakage 0.00%** (validation 5.71%).

| Detector | Thresh. | F1 | FPR | MCC | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- |
| Rules only | — | — | 0.0% | — | — | — |
| Isolation Forest | 0.65 | 8.9% | 26.4% | **−0.1615** | 0.6511 | 0.2429 |
| Supervised (HGB) | 0.95 | 91.9% | 2.5% | 0.8988 | 0.9902 | 0.9472 |
| Hybrid (risk) | 5.0 | 8.9% | 26.4% | −0.1615 | **0.4125** | 0.1901 |

PR-AUC baseline 0.2022.

**The finding worth the 32 minutes.** The Isolation Forest's ROC-AUC *rises*
under distribution shift — 0.4198 on the random split to 0.6511 here — while its
MCC at the frozen threshold *falls* to −0.1615, worse than random as a decision.
Both are true at once, and a negative MCC beside an above-chance AUC is the
signature of a **misplaced threshold, not a failed ranking**: the threshold was
frozen on a 13.10%-prevalence validation split and applied to a 20.22% test
split. This is V6 §14's finding arriving on real measured drift rather than on a
simulator.

The production risk path is the one unambiguous regression: ROC-AUC **0.4125**,
below chance, PR-AUC 0.1901 against a 0.2022 baseline.

---

## 5. The deployed artifact **[MEASURED]**

Published as §4.1. "Registered" means: `registry.get_active()` returns the row,
the artifact is loaded from `artifact_path`, its SHA-256 is verified against the
recorded digest, and its feature schema is checked against the running build.
Anything else refuses and reports why.

Artifact evaluated: `isolation_forest@1.0`, digest
`016c6dbf37f53d03db41835e88adc80b3a787ba3386f38ab5db206bab8333fb8`, trained on
the runtime telemetry corpus `f0fbefc8d38a8a53` (6,000 samples, 4,800 fitted).

| | Fitted | Registered |
| --- | --- | --- |
| Threshold | 0.41 | 0.64 |
| F1 | 57.1% | **66.3%** |
| FPR | **100.0%** | 33.3% |
| MCC | — (undefined) | **0.402** |
| ROC-AUC | 0.529 | **0.763** |
| PR-AUC (baseline 0.400) | 0.4929 | **0.7417** |

**The deployed artifact is the better detector on this corpus, on every
threshold-free measure.** The fitted model is degenerate — it flags all 390 test
events. The cause is distributional: the fitted model is asked to find rarity in
a corpus ~40% malicious by construction, while the registered artifact was
fitted at an 8% anomaly rate with a threshold calibrated there.

**This does not rehabilitate the anomaly detector.** MCC 0.402 with a third of
benign traffic flagged is not deployable alone, the rules beat it outright
(MCC 0.852), and §4 above shows the same class ranking below chance on network
flow. What it corrects is narrower: **the published table understated the model
AEGISX actually ships.** Both rows are now in §4 of the report; the fitted row
is unchanged.

**[NOT RUN]** `--include-registered` has still never been run on UNSW-NB15.
Recorded as not-run rather than inferred.

---

## 6. Two defects found by doing the reproductions **[MEASURED]**

### 6.1 The experiment id was unstable for registered models

Re-running against the byte-identical artifact reproduced every metric and
produced a **different experiment id**: `EXP-2d582f5b6b84fcb7` →
`EXP-b24021cee9b9a35c`. `docs/REPRODUCIBILITY.md` §5 promises the opposite, and
it failed in the worst direction — **a faithful reproduction looked like a
different experiment.**

Cause: `experiment_id` hashed the whole registry row, including its database row
id and its training and activation timestamps. A reproduction re-registers the
same artifact into a rebuilt database and necessarily gets new ones. Only the
registered detector was affected; a fitted detector carries no registry row.

Fixed in `evaluation/experiments/runner.py` by normalising that bookkeeping out
before hashing. Verified: the same artifact registered twice at different times
now yields `EXP-ea9af25f010b4144` both times; a different digest or version
still changes the id; and **all five fitted detector ids are unchanged from the
V6 artifact** — no published identity moved.

### 6.2 The reproduction instruction names a fingerprint the run does not produce

§9 and `REPRODUCIBILITY.md` §5 tell a reader to verify against dataset
fingerprint `f24e4a1e47b7753e`. The `--group-by features` run produces
**`36ff61fc57cc77d3`**, and that is correct — `fingerprint()` deliberately hashes
each sample's *grouping*, so regrouping the identical corpus must change it.

The defect is the instruction: a reader following it sees a mismatch and
concludes the corpus changed, when it is identical. Both values are now
recorded in both documents.

---

## 7. Model artifact lifecycle **[MEASURED]**

**Audited, not rewritten.** The fix the V8 brief asked for landed at V5
(`ddb96b8`) and the invariant holds. Verified against the exact original failure
scenario rather than by reading the code:

| Check | Result |
| --- | --- |
| Train into an empty artifact dir + empty DB | v1.0, digest `016c6dbf37f53d03…` |
| Digest vs the production `isolation_forest-v1.0.joblib` | **byte-identical** |
| REPRODUCIBILITY.md §3 figures (fingerprint `f0fbefc8d38a8a53`, 6,000/4,800, seed 4242, contamination 0.08, threshold 0.648, 0.75% flagged) | **all reproduce** |
| Delete the database, keep v1.0 on disk, retrain | allocates **v2.0** |
| v1.0's digest after that retrain | **unchanged** |

How it works: `next_version` takes the maximum of the database *and the
filesystem* — an artifact on disk is evidence a version existed, and it is the
evidence that survives a database rebuilt from migrations — and every writer goes
through `reserve_artifact_path`, which refuses a path that already exists.

**[LIMITATION]** The V4-era deployed artifact `053d1ff3…` remains
**unreproducible and gone**. It predates the determinism fix and was overwritten
during a database rebuild before V5 closed the hole. Any V4-era statement about
"the deployed model" refers to an artifact that no longer exists. This is
recorded in `REPRODUCIBILITY.md` §3 and now in the report's §9.2.

---

## 8. Reproduction **[MEASURED]**

### 8.1 The command can now actually finish

The documented `run_experiments` command block omitted `--max-seconds`, so a
reader copy-pasting it got a run that dies at the 900 s default **having written
nothing** — while the prose warning about exactly that sat further down the page,
and every committed artifact had been produced with `--max-seconds 3600`.

Rather than raise the default blindly, the run was timed:

| Stage | Wall clock |
| --- | --- |
| Rules | 1.1 s |
| Isolation Forest | 267.8 s |
| Supervised (HGB) | 535.1 s |
| Hybrid | 204.8 s |
| Hybrid (risk) | 265.4 s |
| Ablation (rules + 3 configurations) | 618.6 s |
| Load, feature extraction, leakage audit, write | 18.3 s |
| **Total** | **1,911.07 s (31 min 51 s)** |

So 900 s is **2.1× too small** and 3600 s leaves ~1.9× headroom. The flag is now
in the commands themselves.

**The default is left at 900 s deliberately** — it is correct for the adaptation
suite and for CI, and raising it globally would mean a genuinely hung run burns
an hour before anyone is told. That reasoning is now written down rather than
implied. Nothing partial is produced when the ceiling fires: the report is
written once at the end, so a kill leaves no artifact rather than a
half-populated one.

### 8.2 Every published result now has a committed artifact

§3 and §§5–8 had **none** — they were published from files `.gitignore` excluded,
against the project's own rule. Both re-run at this checkpoint; both reproduced.

`docs/RESEARCH_REPORT.md` §9.1 is a provenance audit classifying every result:

| § | Status |
| --- | --- |
| 1, 2, 2.1–2.5 (UNSW source-grouped) | **VERIFIED** — every figure checked against the committed artifact |
| 2.6 (UNSW temporal) | **REPRODUCED** |
| 3 (UNSW feature-grouped) | **REPRODUCED** |
| 4, 4.1 (synthetic, fitted + registered) | **REPRODUCED** |
| 5–8 (correlation, AI analyst, threat intel, degraded) | **REPRODUCED** |

**Nothing is left UNREPRODUCED.**

**Latency is the documented exception and does not reproduce** —
`REPRODUCIBILITY.md` §6 has always said so. Correlation measured 1.138 ms mean
here against the published 1.75 ms; AI analyst 1.79 ms against 1.85 ms. **The
published figures are kept as originally measured**: replacing a number measured
on one machine with a number measured on another is not a correction. Every
non-latency figure is the same number.

---

## 9. Dashboard provenance **[IMPLEMENTATION]**

V7 §11.10: `actorCounts`, `groupCounts` and `baselineAssessment` lived on the
candidate *model's* `parameters` and reached no approver. So an approver could
see how a candidate **scored** but not what it was **trained on** — which is the
half an adversary controls. A poisoned candidate that scores well is the case
the evidence panel exists to catch, and the panel could not show the poisoning.

`ProposalRead` gained `augmentation` and `augmentationStatus`, read **through
the candidate model** rather than copied onto the proposal at creation time. A
copy would go stale on retrain, and stale provenance is the more dangerous
direction: it would show an approver a composition that no longer describes the
artifact they are about to deploy.

`CandidateEvidence.tsx` gained a **"Trained on — feedback admitted"** section:
admitted count, cap policy and actor-cap state, per-analyst and per-group
composition with shares, the baseline monitor's assessment, and the
not-admitted breakdown including the cap's refusals.

The **four** reasons provenance can be absent stay distinguishable —
`no_candidate_model`, `candidate_model_unavailable`, `not_recorded`,
`recorded` — because "no feedback was admitted" and "nobody recorded what was
admitted" are opposite facts and one shared dash would hide both. A proposal
whose candidate model has *vanished* still opens the panel: "this is
unevidenced" is the most important thing an approver can be told about it.

---

## 10. Approval latency **[MEASURED]** **[LIMITATION]**

Unmeasured since V5. Now measured — for the half a machine can honestly measure,
and explicitly not for the other half.

`python -m app.adaptation.experiments.run_approval_latency_eval --iterations 50`
runs in ~1 s against a temporary database it creates and discards. 50 iterations,
milliseconds:

| Stage | mean | p50 | p95 | max |
| --- | --- | --- | --- | --- |
| create | 0.3620 | 0.0782 | 0.1385 | 13.9706 |
| refused self-approval | 0.0077 | 0.0020 | 0.0036 | 0.2835 |
| approve | 0.0678 | 0.0558 | 0.0799 | 0.5372 |
| deploy | 0.0579 | 0.0535 | 0.0671 | 0.1803 |
| rollback | 0.0554 | 0.0518 | 0.0627 | 0.1765 |
| **end-to-end** | 0.5431 | **0.2399** | 0.3638 | 14.8646 |

Read p50: the first iteration pays SQLAlchemy's mapper warm-up (13.97 ms), which
inflates every mean and describes process start.

**The four-eyes refusal costs ~0.002 ms** — roughly 40× less than the `create` it
prevents, because it fails before doing any work. A safety check cheaper than
the operation it guards has no throughput argument against it.

> **Human analyst decision latency remains `UNMEASURED`**, as in V5, V6 and V7.
> No analyst population exists. Timing the feedback simulator was considered and
> rejected: it models an analyst's *verdicts*, not how long a person takes to
> reach one, so timing it would report a property of a `sleep` somebody chose,
> dressed as a finding about human behaviour. The report file carries
> `humanLatencyStatus: "UNMEASURED"` so the two cannot be confused, and a test
> asserts no stage is named for a human decision.

**[LIMITATION]** Laptop, SQLite, single process, a database of a handful of
rows. Excludes HTTP, auth, serialization and all contention: a floor, not a
throughput claim.

---

## 11. Provider verification — still UNVERIFIED **[LIMITATION]**

**No provider was called. No credentials exist in this environment.** `.env`
holds 16 keys, all platform configuration; there is no `OPENAI_*`,
`ANTHROPIC_*` or `VIRUSTOTAL_*` API key, and none in the shell environment.

`app/ops/verify_providers.py` was exercised in both modes and behaves as V7
designed:

| Mode | Output | Exit |
| --- | --- | --- |
| default | AI analyst `mock` → `SKIPPED`; threat intel `none` → `UNVERIFIED` | 0 |
| `--live` | same, plus *"1 provider(s) could not be verified: no credentials. Nothing is claimed about them."* | **2** |

No credential was printed; keys are reported present/absent and by length only.
**Status is unchanged and correct: UNVERIFIED.** Nothing in V8 claims otherwise.

---

## 12. Verification at checkpoint **[MEASURED]**

| Check | Result |
| --- | --- |
| `pytest` (SQLite) | **857 passed**, exit 0 (835 at V7, +22) |
| `ruff check .` | clean |
| `vitest run` | **61 passed**, 9 files (56 at V7, +5) |
| `npm run verify` (eslint + tsc + vitest + build) | clean; pre-existing chunk-size warning |
| Migrations base→head→base→head (SQLite) | PASS, head `0011_v7_approval_governance` |
| PostgreSQL | **not re-run in V8** — see §13.2 |

The 22 new backend tests:

```
test_adaptation_approval_latency.py              11
test_adaptation_augmentation_provenance.py        7
test_evaluation_experiments.py (added)            4   experiment-id stability
```

**V7's traps still apply and cost time again if ignored.** `conftest.py` deletes
the shared `/tmp` database at import, so **never run two `pytest` processes
concurrently**. `POST /api/v1/events` finishes after the response returns via
background enrichment.

---

## 13. What V8 did NOT do **[LIMITATION]**

1. **Still no real analyst feedback.** Fourth session running as the top
   recommendation. Every magnitude in this project remains a property of a
   generator.
2. **PostgreSQL was not re-validated.** V7 validated it against 16.15 and V8
   changed nothing in the schema — no migration was added — so the V7 result
   stands. But it was not re-run here, and this document does not claim it was.
   `test_database_postgres.py` skips without a server and says so.
3. **No live external provider.** §11.
4. **`--include-registered` never run on UNSW-NB15.** §5.
5. **Seed variance exists only for §2.3**, on three seeds. The temporal split,
   the feature-grouped split and the registered-model evaluation are all
   single-seed. A temporal result at one seed is weaker evidence than the
   confidence it invites.
6. **The V4 artifact `053d1ff3…` is still gone** and always will be. §7.
7. **Model artifacts remain uncommitted**, so the digest rather than the file is
   the published identity. Sound, but it means reproducing §4.1 requires
   retraining first.
8. **The actor cap is still off by default**, and its honest-throughput cost on
   real feedback is still unmeasured. V7 §11.8 unchanged.
9. **No agent layer, no cloud integration, no adaptive detection.** Explicitly
   out of V8 scope and left alone.
10. Everything inherited from V7 §11, V6 §10, V4 §19 and V3 still applies.

---

## 14. Preserve these decisions

All of V3 §16, V4's three, V5's eight, V6's nine (28–36) and V7's nine (37–45)
still hold. V8 adds:

46. **An experiment whose results are not published is an experiment that was
    not run.** Three V8 "gaps" were work already done and never written up. The
    artifact on disk did nobody any good, and the next brief inherited the
    belief that the work was outstanding.
47. **Verify the brief against the repository before executing it.** Six of this
    session's premises were stale (§3). Building what a stale brief asks for
    means rewriting something that already works.
48. **An identity must hash what a thing *is*, never when it was recorded.**
    Row ids and timestamps in an experiment id made a faithful reproduction look
    like a different experiment.
49. **Reproduce a result before citing it, and reproduce the *instruction* too.**
    Both V8 defects were invisible from reading the code and obvious the moment
    the documented command was actually run.
50. **Measure the runtime before changing the timeout.** The answer was 1,911 s;
    a blind bump would have hidden that the default is right for every other
    suite.
51. **A number you refuse to fabricate is a result.** Human approval latency
    stays `UNMEASURED` in a report that measures everything around it, and says
    what would close it.
52. **A coincidence in a measurement is a bug.** The first latency run reported
    the four-eyes refusal and `create` with identical latency to four decimal
    places. That is not a finding; it was a timing variable that never got
    reassigned.

---

## 15. Reproducing

```bash
cd backend && export DATABASE_URL="sqlite:///aegisx.db"
alembic upgrade head                      # required for run_system_eval

# --max-seconds 3600 is part of the command; the 900s default writes nothing.
python -m app.evaluation.run_experiments --dataset unsw-nb15 \
  --split temporal --seed 1337 --persist --max-seconds 3600            # §2.6, ~32 min
python -m app.evaluation.run_experiments --dataset unsw-nb15 \
  --split stratified_group --group-by features --seed 1337 --persist --max-seconds 3600
python -m app.ml.training.train_anomaly_model                          # registers + activates
python -m app.evaluation.run_experiments --dataset aegisx-synthetic \
  --seed 1337 --include-registered --persist                           # §4.1, ~18 s
python -m app.evaluation.run_system_eval                               # §§5-8, ~2 s
python -m app.adaptation.experiments.run_approval_latency_eval --iterations 50
python -m app.ops.verify_providers --live                              # exits 2, correctly

pytest                                     # 857, serial - see §12
ruff check .
cd ../frontend && npm run verify           # 61 tests
```

Fingerprints to check: UNSW `f24e4a1e47b7753e` (source grouping) /
`36ff61fc57cc77d3` (`--group-by features` — see §6.2), synthetic
`c0f04f3ccb2a63b8`, training corpus `f0fbefc8d38a8a53`, ruleset
`da203c91430a47a1`, feature schema `1.0`, deployed artifact
`016c6dbf37f53d03…`.

---

## 16. Recommended V9 scope **[INFERENCE]**

1. **Get real analyst feedback.** Unchanged, and now the only item that would
   change what is *known* rather than what is *documented*. V8 removed the last
   excuse on the evidence side: every published number is now reproducible from
   a committed artifact, so a real corpus can be dropped into a substrate that
   is known-good.
2. **Seed variance on the temporal split** before anyone quotes §2.6's MCC as a
   magnitude. One seed is enough to establish the *shape* — ranking up, decision
   inverted — and not enough to quote the number.
3. **Threshold selection under prevalence shift** is the research question V8
   surfaced and did not answer. §2.6 shows a frozen threshold failing on real
   drift while the ranking improves; that is an argument for a
   prevalence-aware or quantile-anchored operating point, and it is measurable
   on data already in the repository.
4. **`--include-registered` on UNSW**, for completeness. ~32 min.
5. Then, and only then, V9 adaptive detection.

**[INFERENCE]** V7 ended with "the substrate is now trustworthy and still
synthetic." V8's version is narrower: **the substrate is trustworthy,
reproducible, and still synthetic.** The evidence problem is closed. The data
problem is not, and no amount of further engineering closes it.

---

## 17. First steps for a new session

1. **Verify §2 and §12 yourself.** `git log --oneline -4`, `git status`,
   `pytest`. Four consecutive handoffs named the wrong checkpoint before V7
   changed the convention.
2. **Check this document's claims against the brief you were given.** V8's most
   valuable half-hour was discovering the brief was stale (§3). Do that first,
   not after implementing something that already exists.
3. **Run the suite serially** (§12) before changing anything.
4. Read `docs/RESEARCH_REPORT.md` §9.1 — the provenance audit is the fastest way
   to see what is actually established and how.
5. Spot-check the refactor digest:
   `pytest app/tests/test_telemetry_normalizer_characterization.py` → 3 passed.

---

## 18. V8 closure **[MEASURED]**

**V8 IS CLOSED.** No further V8 experiment will be run, and no V8 result is
outstanding.

### 18.1 Interrupted work — what was actually stopped

Seven background tasks were stopped by the operator at the end of the session.
Checked rather than assumed, because a stopped task and an interrupted
experiment are not the same thing:

| Task ids | What they were | Artifact written |
| --- | --- | --- |
| `bj2on1h6q`, `bztvfphb7`, `bt5n6xbfh`, `bzap0o95y`, `bo8c1gzyc`, `bbz8yzbl5`, `b7utdxhdt` | `until ! pgrep …; do sleep; done` **polling wait-loops** — duplicate waiters on runs that had already finished | none; each produced **zero bytes of output** |

**No experiment was interrupted.** The experiment and verification processes ran
to completion and exited 0:

| Task | Run | Exit |
| --- | --- | --- |
| `bctz3cu5s` | temporal UNSW (1,911 s) | 0 |
| `by1j86cvn` | feature-grouped UNSW | 0 |
| `bvva0167t`, `b9a1ov69b`, `bcj6umrir`, `b398kfdd8` | full `pytest` + `ruff` | 0 |

This is verifiable without trusting the task panel: `run_experiments` writes its
report **once, at the end**, so an interrupted run leaves *no artifact at all*
rather than a truncated one. All five V8-era artifacts exist, parse, and carry
complete result sets — 5 or 6 baselines plus 4 ablation configurations each, the
system evaluation's four subsystems, and the latency report's 50 iterations.

### 18.2 Closure verification — from committed artifacts, no run repeated

47 checks re-verified every V8 finding against the committed artifacts:

| Area | Result |
| --- | --- |
| Temporal split reproduces V6 (identical bar timestamps/timing) | PASS |
| Temporal densities 2.21 / 13.10 / 20.22%, test leakage 0.00% | PASS |
| Isolation Forest MCC −0.1615, ROC-AUC 0.6511; risk path 0.4125 | PASS |
| Fitted vs deployed distinction (FPR 100% vs 33.3%, AUC 0.529 vs 0.763) | PASS |
| Deployed artifact digest `016c6dbf37f53d03…`, identity `isolation_forest@1.0` | PASS |
| Experiment identity: 5 fitted ids unchanged from V6; registered id now stable | PASS |
| Feature-grouped: 78,265 groups, 0.00% leakage both splits, supervised F1 0.9741 | PASS |
| Historical stratified result unchanged (39,651 test, F1 0.970, AUC 0.4198, 51.80% leakage) | PASS |
| System eval §§5–8 (15/24 campaigns, 54.31% purity, 10.08×, SSRF 6/6) | PASS |
| Approval latency: `humanLatencyStatus == UNMEASURED`, no stage named for a human | PASS |

### 18.3 History was not rewritten **[MEASURED]**

`git diff --name-status 630cb4d..HEAD` over `app/evaluation/reports/` shows
**every artifact change is an addition (`A`)**. No pre-V8 artifact was modified
or deleted; the only `M` is `.gitignore`, extended to ignore `latest-v7-*` and
`latest-v8-*` pointers under the existing V6 retention policy.

Across the whole of V8, `docs/RESEARCH_REPORT.md` lost exactly **three lines**,
all of them *commands* in §9 replaced by versions carrying `--max-seconds 3600`.
**No published metric, table row or finding was removed or altered.**
`docs/EVALUATION_METHODOLOGY.md` lost none. `docs/REPRODUCIBILITY.md`'s removals
are stale verification counts and a stale watchdog note, and the superseded V6
figures are kept inline as history rather than deleted.

**Scientific conclusions changed: NO.**

### 18.4 Status of every claim at closure

| Claim | Status |
| --- | --- |
| Temporal UNSW detector results | **REPRODUCED** (V6 artifact + V8 artifact, identical) |
| Feature-grouped UNSW (§3) | **REPRODUCED** |
| Synthetic corpus, fitted detectors (§4) | **REPRODUCED** |
| Deployed/registered artifact (§4.1) | **REPRODUCED** |
| Correlation, AI analyst, threat intel, degraded mode (§§5–8) | **REPRODUCED** |
| UNSW stratified source-grouped (§1, §2) | **VERIFIED** (checked against artifact; not re-run) |
| Model artifact determinism + rebuilt-DB immutability | **VERIFIED** (byte-identical `016c6dbf37f53d03…`; retrain allocated v2.0) |
| Approval workflow system latency | **MEASURED** (50 iterations) |
| Human analyst decision latency | **UNMEASURED** — no analyst population exists |
| External provider (AI analyst, threat intel) | **UNVERIFIED** — no credentials; `--live` exits 2 |
| PostgreSQL | **NOT RUN in V8.** V7 validated 16.15; V8 added no migration, and its 15 PostgreSQL tests skipped in every run |
| `--include-registered` on UNSW-NB15 | **NOT RUN** |
| Seed variance on temporal / feature-grouped / registered | **NOT RUN** — all single-seed |
| Live AWS CloudTrail | **NOT RUN** — fixtures only, as in V7 |
| V4 deployed artifact `053d1ff3…` | **UNREPRODUCIBLE** — destroyed pre-V5, permanently |

**Interrupted: none.**

### 18.5 Verification at closure **[MEASURED]**

Bounded, as scoped. No experiment was re-run for a green checkmark.

| Check | Result |
| --- | --- |
| Full `pytest` at `c5e293b` | **857 passed**, exit 0 |
| Code changed after that run | **none** — docs only (`git diff --name-only c5e293b..HEAD`) |
| Targeted V8 tests (latency, provenance, experiment-id, normalizer digest) | **35 passed**, exit 0 |
| `ruff check .` | clean |
| `vitest run` | **61 passed**, 9 files |
| Migrations base→head→base→head (SQLite) | PASS, head `0011_v7_approval_governance` |
| Committed report artifacts parsing with complete result sets | **26 / 26** |

### 18.6 Environment requirements and traps

- **Python 3.11.16, scikit-learn 1.7.2.** The venv is at the **repository root**
  (`.venv`), not `backend/.venv` — `backend/.venv` is a stale Python 3.9 shell
  with no dependencies and will fail confusingly.
- **`run_system_eval` needs a schema.** Run `alembic upgrade head` first;
  without it, it dies with `no such table: events`.
- **`--max-seconds 3600` is mandatory for any UNSW run.** The 900 s default
  cannot finish and writes nothing.
- **Never run two `pytest` processes concurrently.** `conftest.py` deletes the
  shared `/tmp` database at import; concurrent runs destroy each other and
  produce dozens of `readonly database` errors that look like a code defect.
- **`POST /api/v1/events` keeps writing after the response returns**, via
  background enrichment. Create events through `event_repository` in tests.
- **Do not use foreground polling loops to wait on long runs.** Every one of the
  seven stopped tasks was such a loop. Launch the run in the background and read
  its artifact when it lands.
