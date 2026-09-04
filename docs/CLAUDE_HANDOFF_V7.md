# AEGISX V7 → V8 HANDOFF

> Written at the end of the V7 session for a **fresh Claude Code session**.
> Every claim below was checked against the repository or a command's output
> immediately before writing, not recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged **[MEASURED]**, **[IMPLEMENTATION]**, **[LIMITATION]**,
**[INFERENCE]** — as in V4, V5 and V6.

---

## 1. Read this first

**V7 did what its brief asked.** Unlike V6, it did not become an audit of itself.
Ten phases were scoped; **ten were executed**, and two of the three items V6
listed as environment-blocked are now actually done.

The single most important thing to know: **V7 changed no research conclusion.**
Every number in `docs/V6_RESEARCH_REPORT.md` and the V4/V5 reports stands exactly
as published. V7 ran **no new experiments** — deliberately, under the brief's
rule 15 — and the one place where behaviour could have silently drifted, the
normalizer, is pinned by a digest recorded at the V6 checkpoint *before* any V7
code existed (§6).

What V7 did instead was turn V6's corrected foundation into something
operationally defensible: analyst feedback that cannot silently become ground
truth, four-eyes approval that is enforced rather than recorded, a cap that an
attacker cannot evade by changing groups, a telemetry abstraction that does not
require editing the ingestion path to add a source, a real cloud source flowing
end to end, V6's evidence visible to the person who has to approve things, and
PostgreSQL validated for the first time in the project's history.

**§11 lists what V7 did not do, without softening.**

---

## 2. Checkpoint **[MEASURED]**

```
V4 checkpoint:  65a8671
V5 checkpoint:  52eea0d
V6 checkpoint:  b7fa9cc   ← see the correction below
V7 implementation:  da0a8c6   feat(v7): operationalize the V6 foundation
V7 checkpoint:      this commit — the child of da0a8c6, which adds this document
```

**Correction to the V6 handoff.** It states "V6 checkpoint: `d8e54b4`" and
"`origin/main` is at `d8e54b4`". At the start of this session `HEAD` and
`origin/main` were both at **`b7fa9cc`** — one commit later, *"docs(v6): rewrite
the handoff for the final state"*, which is the handoff document itself. `d8e54b4`
is intact and is the last commit of V6's research work; it simply is not where
the branch was.

This is benign, and it is the **third consecutive handoff to name the wrong
checkpoint** — V4's audit found it, V5 did it, V6 warned about it and then did
it again. The cause is structural and no amount of care fixes it: **a document
cannot contain the SHA of the commit that adds that document.** Every previous
handoff tried to name one number and was therefore wrong by exactly one commit.

V7 names **two**: the implementation commit, which is a real SHA that can be
checked out, and the handoff commit, identified by its relationship to it rather
than by a number it cannot know. `git log --oneline -2` resolves both in one
command. Decision 45 in §12.

**Push status:** pushed to `origin/main`; `HEAD == origin/main`.
**Working tree:** clean.
Nothing amended, rebased or force-pushed.

---

## 3. What V7 changed, in one table **[IMPLEMENTATION]**

| Phase | V6 state | V7 state |
| --- | --- | --- |
| 1. Analyst feedback | Rows carried provenance, but conflicting claims from two analysts both became training members with **opposite labels** | `adaptation/feedback/adjudication.py`: one analyst one voice, abstentions counted as abstentions, disagreement fails closed. `analyst_id` FK + `analyst_role` recorded at claim time |
| 2. Four-eyes | *"`self_approved` is still recorded, not prevented."* | `proposals.approve` **refuses**. Acting role checked against the permission matrix in the service, not just the HTTP edge. `rejected_at` added |
| 3. Cap grouping key | Single axis (`event_type`); 40% of poison removed where a target hid in a busy group | Independent **actor** axis; both must admit. Off by default so every published result reproduces |
| 4. Telemetry abstraction | Seven vendor mappings inline in `normalizer.py`; silent fallback to a foreign vendor's parser | `canonical.py` contract + `adapters/` registry. Normalizer resolves and attaches provenance; resolution recorded as `exact`/`fallback` |
| 5. Source integration | None. Track 4 never started | AWS CloudTrail, fixture-backed and labelled simulated, flowing file → adapter → canonical → normalizer → features → detection → stored alert |
| 6. Dashboard | `frontend/` untouched; `perCategory`, `rocAuc` invisible to approvers | `CandidateEvidence` panel on the existing proposal queue; acting roles and four-eyes state on the row |
| 7. PostgreSQL | Never validated; Docker unavailable all session | **Validated.** 11 migrations, constraints, FKs, JSONB, transactions and state transitions against PostgreSQL 16.15 |
| 8. External provider | Nothing live called | Still nothing live called — **no credentials exist**. `app/ops/verify_providers.py` added so the next attempt is one command and its output is the evidence |
| 9. Operational testing | — | Full suite, both backends, watchdogs, no orphans |
| 10. Documentation | — | This file, plus `ARCHITECTURE.md`, `SECURITY.md`, `ADAPTATION_CARD.md` |

---

## 4. The four security-relevant changes, in detail **[IMPLEMENTATION]**

### 4.1 Feedback is no longer automatically truth

Before V7, `datasets.build` selected every current training-eligible row. Two
analysts disagreeing about one event produced **two dataset members with opposite
`binary_label`**, and nothing raised, excluded or recorded anything. A model was
fitted on both answers.

`adjudication.py` sits between the record and the training set. Four rules, each
because the obvious alternative is wrong:

- **One analyst, one voice** (their latest active row). Otherwise a single person
  outvotes a colleague by being verbose.
- **Abstentions count as abstentions.** `suspicious` and `uncertain` carry no
  position; counting either as a side records hesitation as ground truth.
- **Disagreement fails closed.** Any dissent → `CONFLICTED` → not
  training-eligible. A conflicted target needs a human, not arithmetic.
- **Confidence is reported, never decisive.** It is self-reported; letting it
  break ties lets one over-confident analyst overrule two careful ones.

There is deliberately **no flag to disable it**. What was excluded is recorded in
the snapshot's `selection.adjudication` block — a snapshot that quietly dropped a
disputed target would hide the disagreement as effectively as one that trained
on it.

**This moved no published number:** `datasets.build` is called only from tests
and the API. No V4/V5/V6 experiment uses it — they build feedback in memory.

### 4.2 Four-eyes is enforced

`proposals.approve` now refuses when the approver is the proposer, compared
case- and whitespace-insensitively (actors are email addresses; a literal
comparison could be walked around with the shift key). The acting role must
grant `adaptation:approve`, checked **in the service** against the existing
permission matrix — the API is one caller, and a boundary that lives in a
FastAPI dependency is a boundary only for traffic arriving over HTTP.

Because `registry.activate_model` is reachable only through `mark_deployed` on an
APPROVED proposal, refusing here is what makes the separation reach production.

`self_approved` is **kept**, always `false` for anything approved from V7
onwards. Rows decided before V7 may legitimately carry `true`, and no CHECK
constraint was added that would make that history unrepresentable — backdating
a guarantee the system did not offer is the dishonest option.

A proposer *may* still reject their own proposal. The asymmetry is deliberate:
four-eyes guards the direction of travel that changes what AEGISX detects.

### 4.3 The cap has a second axis

V6 §19.2 measured the per-group cap removing 96% of poison where a scenario owned
its `event_type` and **40%** where it hid in a high-volume group; §20.3 found a
hidden target facing an allowance of ~597 at cycle zero.

That is not a tuning problem. Any single-axis cap is only as good as its key, and
`event_type` is partly attacker-influenced, so the evasion is to move.
`caps.apply` now takes an optional independent **actor** dimension; both axes
must admit, and a candidate refused by either charges neither. The two are evaded
by opposite behaviours: concentrating to stay under the actor cap means
concentrating into a group, and spreading to evade the group cap means spreading
from one account. A campaign across ten event types divides its per-group
footprint by ten and leaves its per-actor footprint unchanged.

**No experiment was run for this**, deliberately. The property is an invariant
about allowance arithmetic, not a magnitude about a corpus, so it is proven by
adversarial unit test (`test_adaptation_actor_cap.py`, 15 tests covering honest
feedback, concentrated attack, cross-group attack, an attacker minting new
grouping keys, multiple analysts, and refusal-does-not-charge-the-other-axis).
Running a seeded experiment would have produced a number that is a property of
the simulator, which is exactly what V6 spent a session establishing.

**[LIMITATION]** It bounds a *compromised actor*, not a colluding set of them.
An adversary holding several analyst accounts divides their per-actor footprint
the same way moving between groups divided the per-group one. That residual is
stated in the module docstring and in `ADAPTATION_CARD.md`.

### 4.4 The normalizer no longer knows any vendor

The V6 leak — *"`telemetry/normalizer.py` hard-codes vendor schemas; that leak is
documented and unfixed"* — is closed. The seven mappings moved to
`telemetry/adapters/`, one module per vendor, behind a registry.
`telemetry/canonical.py` defines `CanonicalEvent` as a frozen dataclass with a
fixed field set, so "a vendor key leaked into the contract" is a checkable
condition rather than a review question.

A second problem V6 did not name was worse: `FALLBACK_BY_TYPE` **silently** gave
an unrecognised source of a known class to a foreign vendor's mapper. A new
endpoint product was parsed by the Sysmon mapper and produced plausible,
confident, quite possibly wrong events, with nothing anywhere recording it. The
fallback is kept (removing it would break the collector contract) but
`resolution` is now recorded on every event as `exact` or `fallback`, and
adapters added since V7 declare no fallback class — so a genuinely new source is
refused rather than guessed at.

---

## 5. Telemetry source integration **[IMPLEMENTATION]** **[LIMITATION]**

**AWS CloudTrail, fixture-backed, explicitly labelled simulated.**

Chosen because it is the first adapter written *against* the canonical contract
rather than moved into it, and it is shaped unlike anything already mapped: no
hostname, no process, no command line, the principal an ARN, the signal in an API
name rather than a vendor severity. If a vendor field were going to leak, a
source this different is where it would happen.

The path is real end to end: `CloudTrailFileSource` reads the CloudTrail
`{"Records": [...]}` envelope from `.json`/`.json.gz`, the adapter maps it, and
it reaches the same collector, normalizer, feature extractor and detection engine
every other source uses. Real rules fire — `DET-PRIV-001` on `AttachUserPolicy`,
`DET-CRED-001` on `GetSecretValue`, `DET-EXFIL-001` on a large `GetObject` — and
benign baseline activity fires nothing.

Two honesty choices worth preserving:

- A **denied API call is not a failed sign-in.** It maps to `cloud_api_denied`,
  and **no existing rule fires on it**. Stretching it onto `auth_failure` would
  have made a cloud-detection capability appear to exist because a rule happened
  to match.
- The adapter asserts **no MITRE technique**, because CloudTrail asserts none.
  Inferring one from the API name would put attribution nobody made in front of
  an analyst.

**[LIMITATION]** **Nothing here has ever talked to AWS.** No credentials, no
network call, no account. The fixtures are hand-written to the public CloudTrail
schema using RFC 5737 / AWS documentation reserved addresses. Every record is
`is_synthetic=True` and `health()` reports `simulated: true`. A live source
replaces `CloudTrailFileSource` — the S3/CloudWatch client and its credential
handling — and reuses `CloudTrailAdapter` unchanged. That split is the point of
Phase 4.

---

## 6. The refactor safety argument **[MEASURED]**

Phase 4 rewrote the code path every event in the system passes through, and every
measured result in `docs/` rests on what it produces. So the digest came first:

`app/tests/test_telemetry_normalizer_characterization.py` hashes the full
canonical output of (a) sixteen hand-written vendor records covering all seven
V6 sources and (b) a 120-record seeded run of `SyntheticTelemetrySource` — the
generator every V3–V6 result was produced from.

```
vendor fixtures digest:  d5886cabbbef7ca5
seeded corpus digest:    ed9298988568bf3f
```

**Both were recorded at `b7fa9cc` before any V7 code existed, and both are
unchanged after the refactor.** The mappings were moved, not rewritten; the
`candidate()` helper was kept verbatim precisely so the digest could tell a move
from a behaviour change.

If that test fails after a future change, the change altered what the detection
engine sees. That may be intended — but it is never incidental.

---

## 7. Verification at checkpoint **[MEASURED]**

Run immediately before writing this:

| Check | Result |
| --- | --- |
| `pytest` (with `AEGISX_TEST_POSTGRES_URL` set) | **835 passed**, 0 failed, 0 skipped, in 261s |
| `pytest` (SQLite only) | 820 passed, **15 skipped** — the PostgreSQL module, which says why |
| `ruff check .` | clean |
| `vitest run` | **56 passed**, 9 files (50 / 8 at V6) |
| `tsc -b --noEmit` | clean (exit 0) |
| `eslint .` | clean (exit 0) |
| `vite build` | PASS (chunk warning, pre-existing since V3) |
| Migrations base→head→base→head (SQLite) | PASS, head `0011_v7_approval_governance` |
| Migrations base→head→base→head (PostgreSQL 16.15) | PASS |
| Browser: proposal evidence + four-eyes badge | PASS (§10) |
| Orphan processes after the session | none (`uvicorn`, `vite` both reaped) |

**733 tests at V6 → 835 at V7 (+102).** Nine test modules added, all backend
except one:

```
test_adaptation_adjudication.py                  24
test_adaptation_four_eyes.py                     16
test_adaptation_actor_cap.py                     15
test_telemetry_source_abstraction.py             20
test_telemetry_cloudtrail_end_to_end.py           9
test_telemetry_normalizer_characterization.py     3
test_database_postgres.py                        15  (skipped without a server)
CandidateEvidence.test.tsx                        6  (frontend)
```

### A trap worth naming

`app/tests/conftest.py` deletes `/tmp/aegisx_test.db` at import and the suite
shares it. **Two concurrent `pytest` invocations destroy each other**, producing
dozens of `sqlite3.OperationalError: attempt to write a readonly database`
failures that look like a code defect and are not. This cost real time in V7.
Run the suite serially.

Two related traps, both found the hard way in V7:

**An API test commits**, because the endpoint does, while the `db` fixture rolls
back. A committed feedback row is then picked up by any later module that builds
a dataset with no filters (`test_adaptation_datasets`,
`test_adaptation_augmentation`). The pre-existing API tests get away with this
only because they sort alphabetically *after* the modules that would notice —
which is a trap for whoever adds the next module near the front of the alphabet.

**`POST /api/v1/events` does not finish when the response returns.**
`event_service.ingest_candidate` submits the event to
`enrichment_service.worker`, a background thread that runs threat-intel
enrichment *and correlation* on its own session and commits on its own schedule.
An API-ingested event therefore keeps being written to after the test that made
it has ended, which on a shared SQLite database is a race with everything that
follows. `test_adaptation_adjudication.py` creates its event through
`event_repository` instead, for exactly this reason.

**[LIMITATION]** `test_adaptation_feedback_api.py` still ingests through the API.
It has not misbehaved, but it is the same shape and the protection is only
alphabetical ordering.

---

## 8. Database **[MEASURED]** **[IMPLEMENTATION]**

**Head moved `0009_v5_proposals` → `0011_v7_approval_governance`.** Two
migrations, both additive, both nullable, no backfill.

| Migration | Adds |
| --- | --- |
| `0010_v7_feedback_identity` | `analyst_feedback.analyst_id` (FK → `users`, `ON DELETE SET NULL`), `.analyst_role` |
| `0011_v7_approval_governance` | `adaptation_proposals.{proposed_by_role, approved_by_role, rejected_by_role, rejected_at}` |

**Nothing is backfilled, deliberately.** The role an actor held when they acted
was never captured, and inferring it from their current role would manufacture
provenance. Pre-V7 rows keep nulls and are identifiable by them.

**PostgreSQL 16.15, validated for the first time** (Docker was unavailable for
all of V6). All 11 migrations apply; base→head→base→head round-trips. Confirmed
against the real backend rather than SQLite:

- CHECK constraints enforced (`users.role`, `confidence` range, proposal status,
  no self-supersede)
- **Foreign keys enforced** — SQLite does not enforce them by default, so
  `analyst_id`'s constraint had never actually been exercised before
- `ON DELETE SET NULL` keeps a deleted account's feedback, with `analyst_role`
  surviving the account
- JSON columns are genuinely **JSONB**, and path queries work
  (`validation->'gates'->>'passed'`)
- Real transactional rollback
- Four-eyes and rejection-timestamp transitions behave identically

`test_database_postgres.py` **skips** when `AEGISX_TEST_POSTGRES_URL` is unset,
and says why. It never approximates: a green run without a server would let the
next handoff claim validation that never happened.

```bash
docker compose -f infrastructure/docker-compose.yml up -d postgres
AEGISX_TEST_POSTGRES_URL=postgresql+psycopg://aegisx:aegisx@localhost:5432/aegisx pytest
```

---

## 9. External providers — UNVERIFIED **[LIMITATION]**

**No provider was called. No credentials exist in this environment.**
`backend/.env` holds 16 keys, all platform configuration; there is no
`OPENAI_*`, `ANTHROPIC_*` or `VIRUSTOTAL_*`, and none in the shell environment.

This is the same position V6 was in. What V7 adds is `app/ops/verify_providers.py`
so the next attempt is one command whose *output* is the evidence, rather than a
paragraph asserting that someone once tried:

```bash
python -m app.ops.verify_providers          # configuration only
python -m app.ops.verify_providers --live   # one real call per configured provider
```

It reports `UNVERIFIED` without a key and **exits non-zero under `--live`**, so
"we checked and it works" and "we could not check" cannot look the same to a CI
job. It never prints a credential — keys are reported present/absent and by
length only, because a prefix is enough to identify an account with some
providers. There is deliberately no code path that reports success without
having made a call.

Current output: AI analyst `mock` → `SKIPPED` (answers locally, proves the code
path and never the integration); threat intel `none` → `UNVERIFIED`.

---

## 10. Dashboard **[IMPLEMENTATION]**

V6 left `frontend/` untouched and closed by noting that three evidence blocks
were *"recorded on candidates and invisible to approvers"*. An approver saw a
title, a rationale and a pass/fail badge — precisely the amount of information
that makes a safety gate ceremonial.

`CandidateEvidence.tsx` is a collapsed panel on the existing proposal card. Three
choices, each a V6 methodological finding made visual:

- **ROC-AUC first and largest**, above anything read at a threshold. V6 §14
  measured a frozen 0.65 sitting at the 53.6th percentile for one model and the
  99.2nd for another.
- **Per-category recall as a table, not an average.** V6 §8 measured a targeted
  attack costing 0.0685 of one category's AUC while the aggregate barely moved.
  An approver who sees only the mean cannot see the attack.
- **Corpus name, version, fingerprint and prevalence beside the numbers**, not in
  a detail view.

An unmeasured metric renders as `—`, never `0.0000` (V4's rule).

The proposal row also now shows each actor's role and a green **"Four-eyes
satisfied"** badge. `Self-approved` is kept but relabelled *"(pre-V7)"* — it can
now only appear on decisions recorded before the invariant existed.

**Browser-tested end to end** against a live backend and dev server: sign in →
Adaptive → Proposals → *Show evidence* renders ΔAUC +0.0338, the
`data_exfiltration` regression at −0.1364 in red, and the corpus fingerprint;
approving as a second actor turns the row `approved` and shows the four-eyes
badge. No console errors. Existing V3/V4/V5 UI untouched — `ProposalQueue` gained
a component and three fields, nothing was redesigned.

---

## 11. What V7 did NOT do **[LIMITATION]**

1. **No live external provider.** No credentials. §9.
2. **No new experiments, and therefore no new measured magnitudes.** Deliberate.
   Every quantitative claim in this document is V6's, cited as V6's.
3. **Still no real analyst feedback.** V7 built the *foundation* for it —
   identity, role, adjudication, conflict representation — but no analyst
   population exists and every result in the project still rests on a simulator.
   **This remains the only outstanding item that would change what is known.**
   It was V5's first recommendation, V6's first recommendation, and it is V8's.
4. **Both corpora are still synthetic.** Nothing in this project is evidence
   about real attack traffic. CloudTrail did not change that — its fixtures are
   hand-written.
5. **The actor cap bounds one compromised actor, not collusion.** §4.3.
6. **The `baseline_relative` cap still depends on a trustworthy history.** V6
   §9.3's limitation is unchanged; V7 did not attempt it.
7. **`baseline_monitor` is still advisory** and its bands are still calibrated
   against a greedy adversary.
8. **The actor cap is off by default.** Turning it on in production is a policy
   decision with an honest-throughput cost nobody has measured on real feedback,
   and measuring it against the simulator would produce a number about the
   simulator.
9. **No approval-latency measurement.** V6 listed this; V7 did not reach it.
10. **The augmentation provenance is not in the dashboard.** `actorCounts`,
    `groupCounts` and `baselineAssessment` live on the *model's* `parameters`,
    not the proposal's `validation`, and surfacing them needs an API change the
    phase did not justify. The evidence panel covers the evaluation blocks only.
11. **CloudTrail is not wired into the running collector by default.** It is
    registered and tested; the default collector still runs the synthetic source
    alone.
12. Everything inherited from V6 §10, V4 §19 and V3 still applies.

---

## 12. Preserve these decisions

All of V3 §16, V4's three, V5's eight (20–27) and V6's nine (28–36) still hold.
V7 adds:

37. **Characterize before you refactor.** A digest recorded *before* the change,
    over the real output of the real path, is what lets a large refactor claim it
    changed nothing — and lets a future change prove it meant to.
38. **A security boundary belongs in the service, not the transport.** The API is
    one caller. An experiment harness, a CLI and eventually an agent are others.
39. **Feedback is evidence; a verdict is a conclusion.** Keep the types separate,
    and let the conclusion be "the analysts do not agree".
40. **A defence with one key is only as good as that key.** Add an axis the
    attacker carries with them rather than tightening the one they can shed.
41. **Record how a parser was chosen.** A silent fallback produces confident
    wrong answers and leaves no trace that anything was guessed.
42. **A skipped check must say it was skipped, and fail loudly when asked to
    verify.** `UNVERIFIED` and `VERIFIED` must never be reachable by the same
    code path.
43. **A null can be a fact.** Simulated feedback has no account; minting one
    would make a generated claim indistinguishable from a human's.
44. **Do not backfill provenance that was never captured.** Guessing it
    retroactively rewrites the audit trail while looking like tidying.
45. **A handoff names the implementation commit, not itself.** Three consecutive
    handoffs named the wrong checkpoint because a document cannot contain the
    SHA of the commit that adds it. Record the implementation SHA — which is
    real, checkoutable, and known when the document is written — and identify
    the handoff commit as its child.

---

## 13. Reproducing

Unchanged from V6 §8 — every experiment command, seed plan and substrate
selection still works exactly as documented, and the committed report artifacts
are untouched. V7 ran none of them.

The V7-specific commands:

```bash
cd backend && export DATABASE_URL="sqlite:///aegisx.db"

pytest                                        # 835 tests, serial — see §7
python -m app.ops.verify_providers            # provider status, no calls

# PostgreSQL (needs Docker)
docker compose -f infrastructure/docker-compose.yml up -d postgres
AEGISX_TEST_POSTGRES_URL=postgresql+psycopg://aegisx:aegisx@localhost:5432/aegisx pytest

# The CloudTrail path, end to end
pytest app/tests/test_telemetry_cloudtrail_end_to_end.py
```

---

## 14. Recommended V8 scope **[INFERENCE]**

1. **Get real analyst feedback.** Third session running that this is the top
   recommendation. V7 removed the excuse: the model now records identity, role
   and time, represents disagreement, and refuses to train on a contradiction.
   What is missing is people. Even a handful of genuine verdicts on real alerts
   would be worth more than any further work against the simulator, because
   **every magnitude in this project is currently a property of a generator**.
2. **Decide whether the actor cap ships on.** It is implemented, tested and off.
   Turning it on is a policy call that wants honest-throughput data, which wants
   item 1.
3. **Surface augmentation provenance** (§11.10) — it needs a small API change to
   expose the candidate model's `parameters.augmentation` to the approver.
4. **One live provider**, whenever a key exists. `app/ops/verify_providers.py`
   makes it a single command.
5. **Approval latency**, still unmeasured since V5.
6. **Then, and only then, the agent layer.** The seams are in place —
   `TelemetrySource`/`TelemetryAdapter` is the `DataSource` shape, and
   `proposals.approve` is the `ApprovalGate` — but an agent built on a simulator
   would inherit every magnitude problem V6 spent a session finding.

**[INFERENCE]** The project's constraint has moved. V6 ended with "its
measurement substrate only just became trustworthy". V7's is narrower and
harder: **the substrate is now trustworthy and still synthetic.** No amount of
further engineering changes that; only data does.

---

## 15. First steps for a new session

1. **Verify §2 and §7 yourself.** Three consecutive handoffs named the wrong
   checkpoint. Run `git log --oneline -3` and `git status` before trusting a word
   of this.
2. **Run the suite serially** (§7's trap) before changing anything.
3. Read V6's §§3–5 — the corrections V6 made are still the most important thing
   about this project's history, and V7 changed none of them.
4. Inspect the four V7 modules on the production path:
   `adaptation/feedback/adjudication.py`, `adaptation/feedback/caps.py`
   (the actor axis), `adaptation/proposals/service.py` (`approve`), and
   `telemetry/adapters/`.
5. Spot-check the refactor digest:
   `pytest app/tests/test_telemetry_normalizer_characterization.py`
   → 3 passed. If it fails, something changed what the detection engine sees.
