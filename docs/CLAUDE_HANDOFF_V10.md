# AEGISX V10 → V11 HANDOFF

> Written at the end of the V10 session for a **fresh Claude Code session**.
> Every number below was read from a command's output or the repository
> immediately before writing, not recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged **[MEASURED]**, **[IMPLEMENTATION]**, **[SIMULATED]**,
**[LIMITATION]**, **[INFERENCE]**, **[NOT IMPLEMENTED]** — the V4–V9
convention, unchanged.

---

## 1. Executive summary

**Read this section before planning anything.**

The V10 session opened with a brief commissioning "Phase E — Evidence-Bound
Response Actions & Approval Governance": a response-action domain object,
evidence-bound approvals reusing `expectedEvidenceDigest`, an approval state
machine, four-eyes, RBAC, audit, replay safety, and no execution.

**All of it already existed.** It was built as V9's own Phase E and merged in
PR #1. The brief was written against a snapshot 23 commits stale — it named
`dc4d844` as V9's tip, which is real but sits 24 commits behind the merged
head. `docs/CLAUDE_HANDOFF_V9.md` §4.4 is titled *"Phase E — response
approval **[IMPLEMENTATION]**"*, and `app/core/actors.py` line 18 says in as many words that
"Phase E needed the same check a third time".

Implementing the brief as written would have meant building a second approval
system beside the first, which the brief itself forbade.

So V10 was rescoped, with the operator's approval, to **close the six real
gaps** an audit of the brief against the code actually found. That is what
this document records. It is a small phase by line count and the audit is the
most valuable thing in it.

| # | Gap | Commit |
| --- | --- | --- |
| 1 | `withdrawn` was in the enum, the CHECK constraint and `TERMINAL_STATUSES` with **no code path able to produce it** | `3782eb6` |
| 2 | A refused decision was audited with the caller's *claimed* digest only, never the server's | `8d97e1d` |
| 3 | No `GET` for a single response action — callers fetched the list and filtered client-side | `4c1d26e` |
| 4 | No consequence classification; all five actions were governed identically with nothing said about them | `b859367` |
| 5 | Only the `tampered` rung of the drift ladder was tested at the approval layer | `72f8a73` |
| 6 | `import app.evidence` raised ImportError in a cold interpreter (V9 §12) | `090169d` |
| 7 | *(found while fixing 1)* A comment on `evidence_binding_id` stated the **opposite** of what the code did | `3782eb6` |
| — | The console was behind its own API after 1 and 4 | `a598b0c` |

**No V4/V5/V6/V7/V8 measured result changed.** V10 added no experiment, ran no
evaluation, and touched no model. Nothing in `RESEARCH_REPORT.md`,
`V5_RESEARCH_REPORT.md` or `V6_RESEARCH_REPORT.md` was edited.

**The platform still decides and does not act.** No executor, no cloud SDK, no
agent. §11 says this without softening.

---

## 2. Checkpoint **[MEASURED]**

```
branch          claude/aegis-x-v10-phase-e-2y273g
base            4692dae  "V9: from evaluation platform to security operations (#1)"
commits         7 (4692dae..HEAD)
files changed   25   +1,733 / -34
migration head  0015_v9_cloud_posture      (UNCHANGED — no migration was needed)
openapi paths   96 → 98
```

New backend module, the only one V10 adds:

```
app/core/sanitize.py     moved from app/ai/sanitize.py — see §9
```

---

## 3. The approval model, as it now stands **[IMPLEMENTATION]**

V10 did not redesign this. It is recorded here because the V10 brief proves a
reader can arrive believing it does not exist.

### 3.1 The object

`ResponseActionRequest` (`app/models/response_action.py`, table
`response_action_requests`, migration `0014_v9_response_action_approval`). One
row per request: what was asked, why, by whom, and — once decided — what was
decided and which evidence binding it rests on.

### 3.2 The state machine

```
                 ┌──────────────► approved    (a second person signed it off)
                 │
   requested ────┼──────────────► rejected    (an authorised person refused)
                 │
                 └──────────────► withdrawn   (the requester stood it down)  ← V10
```

All three outcomes are terminal, and terminal means terminal: a decided
request refuses every further decision with 409. There is no reversal in
place — raise a new request that references the old one. `withdrawn` had been
declared since V9 and was unreachable until `3782eb6`.

### 3.3 The three decisions, and why they differ

| Decision | Who | Four eyes | Freshness | Permission |
| --- | --- | --- | --- | --- |
| `approve` | **not** the requester, and human | required | **mandatory** | `incidents:respond_approve` |
| `reject` | anyone with the authority | n/a | none | `incidents:respond_approve` |
| `withdraw` | **only** the requester | inverted | none, **and no field for it** | `incidents:respond` |

Two asymmetries are load-bearing and should not be "tidied up":

**Both refusing directions skip freshness.** Blocking a rejection or a
withdrawal because the evidence moved would trap the request pending forever,
and ending a containment request is the fail-safe direction — the failure mode
of getting it wrong is that nothing is contained.

**Approval and withdrawal are not mirror images.** Approval *forbids* one
actor; withdrawal *requires* that same one. An administrator who disagrees
with a pending request rejects it under their own name rather than retracting
it under the requester's, so the record never says somebody changed their mind
when they did not.

`ResponseActionWithdraw` has **no** `expectedEvidenceDigest` field at all —
absent, not optional. A field accepted and ignored would advertise a
protection that is not there. A pure test asserts passing one raises
`TypeError`.

---

## 4. Evidence binding **[IMPLEMENTATION]**

Unchanged from V9 and worth restating, because the V10 brief asked for it to
be built.

A response decision reuses Phase D wholesale: the same `snapshot_for`, the
same `check_expected_digest`, the same `bind` writing the same
`DecisionEvidenceBinding` row. There is **one** evidence-integrity mechanism,
not two, and an approved containment action appears in
`GET /incidents/{id}/decisions` beside the lifecycle transition it justifies,
with drift classified by the same `classify_drift`.

Three decision types are bound, distinguished so a reader never has to infer
which happened:

```
response_action.approval
response_action.rejection
response_action.withdrawal      ← V10
```

**All three outcomes bind evidence.** V9's model comment claimed only
approvals did, while `reject_action` had bound evidence since the day it was
written. That comment is corrected in `3782eb6`, with a note saying what it
used to say — a stale comment about what a security-critical record rests on
is worse than no comment.

### 4.1 The drift ladder, at approval time **[MEASURED]**

The V9 ladder is `unchanged < extended < refreshed < tampered`, and removal is
**not** a refresh. V10 tested all four rungs against an approval for the first
time. The answer is the same at every rung, because the approval compares
digests for **exact equality** rather than consulting the verdict:

| Rung | After a decision (`verify`) | Before one (approval) |
| --- | --- | --- |
| `unchanged` | benign | approves |
| `extended` | **benign** | **refuses** |
| `refreshed` | material | refuses |
| `tampered` | serious | refuses |

The `extended` row is the interesting one. New evidence is benign *after* a
decision and is not benign *before* one: evidence that arrived since the
analyst read the page is evidence the approver has not seen.

**These five tests passed on first run.** That is recorded rather than dressed
up: `72f8a73` closed a coverage gap, not a behaviour gap. They were then
checked for teeth by disabling the comparison inside `check_expected_digest` —
four of the five fail with it off, and the fifth is the `unchanged` control,
which *should* be insensitive to the guard. That 4-of-5 signature is the
evidence the others test freshness rather than testing that approval is
generally difficult.

---

## 5. Four eyes **[IMPLEMENTATION]**

Enforced in `app/response/approval.py`, which is pure — no session, no ORM, no
request — because the API is one caller among several. A test drives the
service directly with a wrong actor and asserts nothing is mutated *without a
rollback*, because a service that is only safe when its caller remembers to
clean up is not safe.

Actor comparison goes through the single shared rule in `app/core/actors.py`,
case- and whitespace-folded. Machines (`ai:`, `system:`, `automation:`) may
request containment and may never decide it.

**A stated limit:** a machine that raised a request cannot withdraw it either,
because it holds no role and withdrawal re-checks authority. This traps
nothing — an administrator can still reject it — and there is a named test
saying so.

---

## 6. RBAC **[IMPLEMENTATION]**

No new permission was added in V10. The existing split is used:

```
incidents:respond            raise a request; withdraw your own    analyst+
incidents:respond_approve    approve or reject one                 admin only
```

Analysts deliberately do **not** hold `incidents:respond_approve`, so an
analyst cannot satisfy four-eyes by logging in twice. Authority is checked in
the domain layer *and* at the FastAPI boundary; the doubling is deliberate.

---

## 7. Consequence classification **[IMPLEMENTATION]**

`ResponseActionConsequence` in `app/response/actions.py`:

```
reversible   isolate_endpoint, revoke_session, block_indicator
disruptive   disable_account, quarantine_file
```

Every declared action is consequential — none is a read-only recommendation —
so "is this consequential?" is not the useful question, and there is
deliberately **no harmless tier**. An empty tier would be decoration, and
worse: a tier that exists invites a later action to be filed under it to avoid
the approval. The useful question is how hard the thing is to undo.

**It decides nothing, and that is the point.** A classification sitting beside
a control is a standing invitation to make the control conditional on it. A
structural test asserts `app.response.approval` never so much as *mentions*
the word, and that none of `check_approval`, `check_rejection` or
`check_withdrawal` takes a consequence or an action type. Confirmed by
breaking it: making the freshness check skip for reversible actions fails that
test.

Two properties worth preserving:

- **Derived, never stored.** A stored copy would be a second place for the
  answer to live and a second place for it to be wrong. No migration.
- **Output-only.** A test raises a `disable_account` request claiming
  `"consequence": "reversible"` and gets `"disruptive"` back. A client that
  could state its own consequence would be classifying its own blast radius.
- **Exhaustive at import.** A sixth action added without a classification
  raises at import, not at the moment somebody approves one, and never
  defaults to the milder tier.

---

## 8. Audit **[IMPLEMENTATION]**

Actions recorded:

```
response_action.requested
response_action.approved
response_action.rejected
response_action.refused        a decision that was turned away
response_action.withdrawn      ← V10
decision.evidence_stale        the lifecycle equivalent
```

`8d97e1d` fixed a defect present on **both** paths. `EvidenceDriftError` knew
the expected and the current digest, interpolated both into its message
truncated to sixteen characters, then discarded the structured values. Both
routers audited only `reviewedDigest` — the caller's own claim.

That is half a record. *"The approver said they reviewed X"* is not checkable;
it becomes a record only beside *"the server held Y"*, and Y is the half nobody
can reconstruct afterwards, because by the time an auditor reads the row the
evidence has moved on again.

Now recorded: `reviewedDigest` **and** `currentDigest` on a refusal, and
`evidenceDigest` on a successful approval (it was reachable by joining through
the binding row, which is a join a reader should not need to know to make).

**A stated limit:** `currentDigest` is `null` when the evidence had no part in
the refusal — a self-approval is turned away before the evidence is weighed,
and stamping a digest there would imply it was one of the reasons. There is a
named test asserting the null.

A guard test asserts **no audit detail may carry a dict or a list**, so audit
records cannot quietly become a second copy of the evidence that bypasses the
evidence endpoint's own authorization. It passed on first run; writing it down
is the value.

---

## 9. The import cycle, and the layering that caused it **[IMPLEMENTATION]**

V9 §12 recorded that `import app.evidence` failed in a cold interpreter and
called it pre-existing and harmless "because the app and the tests import
through `app.main`". Both halves were true. It was still worth fixing: a
pure-domain test that has to boot the application first is not a pure-domain
test.

**The cause was not import ordering. It was a layering inversion.**

As it was before `090169d`. The offending import no longer exists in the tree,
so read this against `4692dae`:

```
app.evidence.models --> app.ai --> app.correlation
  --> app.services --> decision_service --> app.evidence.service
    --> app.evidence.binding --> app.evidence.models   (half-defined)
```

The evidence domain reached *up* into the AI package for a text scrubber, and
Python runs a package's `__init__` before any submodule — so asking for one
pure helper pulled provider abstractions, prompt templates, grounding and the
correlation engine in behind it.

`sanitize.py` never belonged to the AI layer. It depends on nothing but `re`
and `unicodedata`, and **three of its four callers are not AI code** — the
evidence domain, cloud findings and adaptation proposals all scrub the same
attacker-influenceable telemetry for the same reason. Scrubbing untrusted text
is a general defensive concern.

It moved to `app/core/sanitize.py`. The scrubbing logic is **byte-identical**;
only the docstring changed. `app.ai` still re-exports the three names, so its
public surface is unchanged. No deferred import anywhere.

Two things about the guard tests:

- **They run in a subprocess.** An import cycle is invisible once `sys.modules`
  is warm — by the time pytest has collected anything, `app.main` is imported
  and every one of these would pass whether the cycle existed or not.
- **The layering rule parses imports rather than grepping.** The first cut
  grepped for `"app.ai"` and failed on `models.py` explaining *in prose* that
  evidence is packaged for a prompt by `app.ai.evidence`. A test that cannot
  tell a dependency from a sentence punishes you for documenting the design.

Eight low-level modules are now asserted importable cold; four could not be.

---

## 10. API changes **[MEASURED]**

```
GET  /incidents/{id}/response-actions/{ref}            new  (4c1d26e)
POST /incidents/{id}/response-actions/{ref}/withdraw   new  (3782eb6)
```

OpenAPI paths **96 → 98**. Every response-action body gains a read-only
`consequence` field.

The single-read route renders through the **same `_render`** the list uses,
with a test asserting byte-identical bodies for the same row: two renderers
onto one row is how a reviewer ends up believing the wrong thing about a
pending containment action. References stay scoped to their incident — one
belonging to a neighbouring incident resolves to 404, not to somebody else's
pending containment action.

**There is still no execute route**, and two tests assert the OpenAPI surface
offers no execution.

---

## 11. What V10 did NOT do **[NOT IMPLEMENTED]**

Without softening:

- **Nothing is executed.** No response action reaches any system. There is no
  executor, no provider registry for actions, no result. `executed` is always
  `false`.
- **No cloud provider integration.** Cloud posture is still **[SIMULATED]**;
  V9 §9 stands unchanged.
- **No agents, no autonomous remediation, no LLM orchestration, no autonomous
  retraining.** None was started.
- **No new research result.** V10 ran no experiment and produced no metric
  about detection quality. Every research claim in the repository is still
  V4–V8's.
- **No new migration.** Verified, not assumed — see §13.
- **The V7 `POST /incidents/{id}/response` placeholder is still unchanged**,
  and is still a single-party free-text note. V9 §4.4 explains why.
- **Endpoint, identity and network findings remain reserved kinds** with no
  producer.
- **No SSO, MFA, refresh tokens or penetration testing.**
- **The metrics endpoint is still not scraped by anything.**

---

## 12. Tests **[MEASURED]**

New in V10, by file (test *functions*; parametrised cases expand further):

```
app/tests/test_response_approval.py       +23
app/tests/test_response_actions_api.py    +33
app/tests/test_decision_binding_api.py     +1
app/tests/test_evidence_domain.py          +2
frontend .../ResponseActions.test.tsx      +10
```

### 12.1 Verification **[MEASURED]**

**The full serial backend run finished after §12 was first committed.** That
commit (`e43cbb5`) said so at the time rather than being left to look complete,
which is V9 §11's precedent; this section replaces the pending note with the
result. Nothing below is recalled.

```
backend, one serial run, -q -rs

    collected   1344      (72 test files)
    passed      1344
    skipped        0
    failed         0
    errors         0
    exit code      0

ruff check .                                   clean
alembic base -> head -> base -> head           clean, PostgreSQL and SQLite
migration head                                 0015_v9_cloud_posture (unchanged)
openapi paths                                  98   (was 96)

frontend, npm run verify
    eslint                                     clean
    tsc -b --noEmit                            clean
    vitest                                     134 passed, 15 files
    production build                           succeeded
```

**Zero skips is the part that matters.** `test_database_postgres.py` collects
25 tests, and V9 §12 warns that it silently skips its whole module against a
dead server while the run still exits 0. A `-rs` run prints a short-test-summary
section for skips; this run printed none, so those 25 ran.

The count was cross-checked two ways because the run's own summary line did not
survive the output capture: counting progress characters (1344) and summing
`--collect-only -q` per-file counts (1344). They agree. A first count said 1346
and was wrong — the regex was also matching the `../.venv/...` path in the
warnings block. The wrong number is recorded here because "cross-checked and
they agreed" is only worth writing down if the cross-check could have
disagreed, and this one did.

V9's last full run was **1261 passed, 0 skipped**. V10 adds 83 collected cases
from 59 new test functions; the difference is parametrisation.

Three guards were checked for teeth by breaking them deliberately and
restoring them — the diffs are clean, and each experiment is named in the
commit that added the guard:

1. Making the freshness check conditional on consequence → fails the
   structural test in `TestConsequenceIsNotAGate`.
2. Disabling the digest comparison in `check_expected_digest` → fails four of
   the five drift-ladder tests, and correctly not the control.
3. The RED phase of every TDD cycle, recorded in each commit message.

---

## 13. Migrations **[MEASURED]**

**Head is unchanged at `0015_v9_cloud_posture`. V10 adds no migration**, and
that was verified rather than assumed:

- `withdrawn` was **already** permitted by `ck_response_requests_status`,
  confirmed by reading the constraint back off live PostgreSQL:
  `CHECK (status = ANY ('requested','approved','rejected','withdrawn'))`.
- `audit_logs.action` is an unconstrained `String(64)`, so a new audit action
  needs no schema change.
- `consequence` is derived at render time and stored nowhere.

Foreign keys were checked for weakening and are intact:
`evidence_binding_id → decision_evidence_bindings ON DELETE SET NULL`,
`incident_id → incidents ON DELETE CASCADE`. `parameters` is `jsonb` on
PostgreSQL — V9's PostgreSQL-only trap still holds.

---

## 14. PostgreSQL **[MEASURED]**

**Actually run this session**, not claimed.

The container was fresh: V9's data directory did *not* survive, and neither
the `aegisx` role nor any database existed. Both were created:

```bash
pg_ctlcluster 16 main start
su - postgres -c "psql -c \"CREATE ROLE aegisx WITH LOGIN PASSWORD 'aegisx' CREATEDB;\""
su - postgres -c "psql -c 'CREATE DATABASE aegisx_v10 OWNER aegisx;'"
```

Round-trip on PostgreSQL: **base → head → base → head, clean in both
directions**, with only `alembic_version` surviving at base. Same round-trip
on SQLite: clean.

---

## 15. Frontend **[IMPLEMENTATION]**

`a598b0c` closed a gap V10 itself opened: after `3782eb6` and `b859367` the
console was behind its own API — an analyst could raise a containment request
in the browser and had no way to retract it.

Two design decisions to preserve:

- **The consequence badge is not green for `reversible`.** Green reads as
  "fine to wave through", the exact misreading that putting a classification
  next to a control invites. Reversible is neutral grey, disruptive is amber,
  and both tooltips end with *"Needs the same approval as any other
  containment action."* A test asserts the Decide button is still present on a
  reversible action, so the UI cannot drift into implying a discount.
- **Withdraw appears only on your own pending request**, and only for a role
  that could have raised one. An administrator viewing somebody else's request
  is offered Refuse, not Withdraw. As with every control in that panel this is
  usability, not enforcement.

A withdrawal is also distinguished from a refusal in the decided line, because
an analyst standing down is not an administrator refusing.

---

## 16. Corrections to earlier documents

Per the V9 Phase K lesson — documents do not go wrong, they go stale, and
staleness is invisible:

- **V9 §12** said the circular import was "worth fixing in V10". It is fixed;
  see §9 here. That paragraph in the V9 handoff is now historical and has been
  left as written, because it describes what a reader of the git history
  before `090169d` will encounter.
- **V9 §14** recommended five things for V10. Item 1 (the circular import) is
  done. Items 2–5 are not; see §17.
- **No V4–V8 conclusion was edited.** Historical results remain historical.

---

## 17. What remains for V11+ **[INFERENCE]**

This is a suggestion, not a finding.

1. **A real cloud posture source.** The single largest honesty gap in the
   repository: cloud security is entirely simulated, and it is the capability
   the project most wants to claim. `app/cloud/scanner.py` is the only
   provider-specific file; the checks, resource identity and correlation are
   designed to stay unchanged. There is a written plan for this in
   `docs/V11_PLAN.md`, which was *not* the scope this session ran — it covers
   the AWS account, a read-only OIDC role in Terraform, `Stubber`-based
   offline tests, and DevSecOps CI gates. It was written as `V10_PLAN.md` and
   renamed once V10 turned out to be this session's work instead; the sentence
   is corrected here rather than left pointing at a filename that no longer
   exists.
2. **Execution, if and only if it is governed.** The approval boundary is now
   as trustworthy as it is going to get without an executor behind it. One
   would need: an action provider contract, a dry-run mode, a kill switch, an
   execution audit distinct from the approval audit, and a rollback story.
   Anything less should stay unbuilt. **Note the interface is already
   provider-neutral** — nothing in the approval path names a vendor, a cloud
   or a model.
3. **The remaining reserved evidence kinds** — endpoint, identity, network.
4. **Scrape the metrics.** Still observed by nothing.
5. **Dependency, container, SAST and IaC scanning in CI.** `SECURITY.md` still
   admits this is missing.

---

## 18. Environment requirements and traps **[MEASURED]**

Read this before running anything.

**Never run two pytest processes at once.** They share `/tmp/aegisx_test.db`
and corrupt it. Inherited from V8 and V9 and still true.

**A fresh container has no venv, no `node_modules`, and no PostgreSQL role.**
All three had to be created this session:

```bash
python3 -m venv .venv
.venv/bin/pip install --no-compile -r backend/requirements.txt
.venv/bin/pip install --no-compile ruff          # not in requirements.txt
cd frontend && npm install
pg_ctlcluster 16 main start
```

`pip install` fails with an `AssertionError` on `pyc_path` without
`--no-compile`.

**The PostgreSQL test database is not migrated by the fixture.** After adding
a migration, apply it by hand or `test_the_head_revision_is_applied` fails.

**A green exit code is not sufficient evidence the PostgreSQL tests ran** —
check the skip count.

**Full run command:**

```bash
cd backend
rm -f /tmp/aegisx_test.db
DATABASE_URL="sqlite:///aegisx.db" \
AEGISX_TEST_POSTGRES_URL="postgresql+psycopg://aegisx:aegisx@127.0.0.1:5432/aegisx_v10" \
  ../.venv/bin/python -m pytest -q -rs
```

It takes roughly 35–40 minutes. Do not poll it in a tight loop.

---

## 19. Preserve these decisions

V9's list of ten still stands. V10 adds five:

11. **`withdrawn` is reachable, and only by the requester.** Withdrawal is
    four-eyes inverted, not a second approval path. It only ever writes
    `withdrawn`, so no ordering of calls reaches `approved` without a second
    person.
12. **Both refusing directions skip freshness on purpose.** Trapping a request
    as pending forever is the worse failure.
13. **The consequence classification decides nothing.** If a policy layer ever
    wants to key on it, that is a new thing that has to argue for itself — not
    a quiet weakening of the checks that exist.
14. **An audit records both digests, not just the claim.** One of them is not
    reconstructible later.
15. **`sanitize` lives in `app.core`, below the AI layer.** Putting it back
    under `app.ai` restores the import cycle.

---

## 20. First steps for a new session

```bash
# 1. Build the environment — a fresh container has none of it.
python3 -m venv .venv && .venv/bin/pip install --no-compile -r backend/requirements.txt
.venv/bin/pip install --no-compile ruff
cd frontend && npm install && cd ..

# 2. PostgreSQL will be down, and the role may not exist. See §14.
pg_ctlcluster 16 main start && pg_isready -h 127.0.0.1 -p 5432

# 3. Confirm the migration head.
cd backend && DATABASE_URL="sqlite:///aegisx.db" \
  ../.venv/bin/python -m alembic heads      # expect 0015_v9_cloud_posture

# 4. Run the suite ONCE. Never two at a time. See §18.

# 5. Frontend.
cd ../frontend && npm run verify
```

Then read, in this order: `app/response/approval.py` (the three decisions and
their asymmetries), `app/response/actions.py` (the consequence taxonomy and
why it gates nothing), `app/services/decision_service.py` (evidence binding),
`app/incidents/lifecycle.py`, `app/core/actors.py`. Each module's docstring
states what it refuses to do and why.

**And before scoping V11: check the repository against the brief you are
given.** This session's brief commissioned work that had already shipped, and
the audit that caught it took under an hour. That check is cheap and it was
the highest-value thing V10 did.
