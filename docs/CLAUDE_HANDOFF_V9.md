# AEGISX V9 → V10 HANDOFF

> Written at the end of the V9 session for a **fresh Claude Code session**.
> Every number below was read from a command's output or the repository
> immediately before writing, not recalled.
> **Trust the repository over this document.** Where they disagree, the code
> wins.

Claims are tagged **[MEASURED]**, **[IMPLEMENTATION]**, **[SIMULATED]**,
**[LIMITATION]**, **[INFERENCE]**, **[NOT IMPLEMENTED]** — extending the
V4–V8 convention with the two tags V9 needed.

---

## 1. Executive summary

V9 was scoped as the move from a research and evaluation platform to a
**Security Operations** platform, on the theme
**OBSERVE → INVESTIGATE → DECIDE → APPROVE → ACT**, with human approval
mandatory for anything consequential.

**No V4/V5/V6/V7/V8 measured result changed.** V9 added no experiment, ran no
evaluation, and touched no model. Nothing in `docs/RESEARCH_REPORT.md`,
`V5_RESEARCH_REPORT.md` or `V6_RESEARCH_REPORT.md` was edited.

What V9 built, phase by phase, each approved separately and each stopped at
for review:

| Phase | What it added |
| --- | --- |
| A | Audit; deletion of five dead V1 mock components |
| B | The incident lifecycle as an enforced rule, not a suggestion |
| C | Investigation evidence as a projection with provenance |
| D | Decisions bound to the evidence they were taken on |
| E | Response actions with a four-eyes approval |
| F | Provider health that reports the truth |
| G | Cloud security posture **[SIMULATED]** |
| H | Metrics that cannot grow without limit |
| K | This document, and the docs it corrects |

Phases I (frontend integration) and the PostgreSQL validation ran between E
and F at the operator's request.

**The single most important thing to carry forward:** the platform decides and
**does not act**. There is no executor, no cloud SDK, no agent. §10 says this
without softening.

---

## 2. Checkpoint **[MEASURED]**

```
branch          claude/aegis-x-v9-master-19yw6t
commits         24 (origin/main..HEAD)
files changed   101   +15,705 / -460
migration head  0015_v9_cloud_posture
openapi paths   96
```

New backend packages, none of which existed at V8:

```
app/incidents/      lifecycle.py                     the transition rule
app/evidence/       models, provider, registry,      evidence as a projection
                    collectors, service, binding
app/response/       actions.py, approval.py          four-eyes approval rules
app/cloud/          resources, findings, checks,     posture  [SIMULATED]
                    scanner, fixtures/
app/observability/  metrics.py, instruments.py       bounded metrics
app/core/actors.py                                   one shared actor rule
app/services/       health_service.py                subsystem probes
                    decision_service.py
                    response_action_service.py
                    cloud_posture_service.py
```

Domain counts, read from the code:

```
incident states        7      lifecycle edges     14
evidence providers     8      evidence kinds      11 (7 produced, 4 reserved)
cloud posture checks   9      rbac permissions    39
```

---

## 3. Verification at checkpoint **[MEASURED]**

Each phase ended with a full backend run against SQLite **and** PostgreSQL in
the same invocation. Counts are from the run's own output:

| After phase | Backend | Result |
| --- | --- | --- |
| I | 1153 | 1153 passed, 0 skipped, exit 0 |
| F | 1171 | 1171 passed, 0 skipped, exit 0 |
| G | 1226 | 1226 passed, 0 skipped, exit 0 |
| H | see §11 | run in progress when this section was written |

Frontend at Phase G: **124 tests / 15 files**, `npm run verify` exit 0
(vitest + `tsc -b` + `vite build`). It was 83 tests / 11 files at the start of
V9.

`ruff check .` clean throughout.

**One skipped-test scare worth recording.** A Phase I run reported 25 skips
against the previous run's zero. The cause was not code: the PostgreSQL server
in this container had died, and `test_database_postgres.py` skips its whole
module when the server is unreachable. See §12 — this will happen again.

---

## 4. What each phase actually changed

### 4.1 Phase B — the lifecycle **[IMPLEMENTATION]**

`app/incidents/lifecycle.py` is a pure transition table: 7 states, 14 edges, no
ORM, no session, no HTTP. It answers which transitions are legal, which need a
reason, and which permission each requires.

Enforcement is in the **service layer**, not the router, because the API is one
caller. Two self-inflicted defects were found and fixed while building it, both
proven to bite by reintroducing them:

- `user=None` resolved to the actor string `"system"`, which does not match the
  `system:` prefix, so it read as a *human* actor and inherited ADMIN authority
  — it could close incidents. Fixed by `_lifecycle_actor()` returning
  `"system:aegisx"`.
- The transition was validated *after* other fields were mutated, relying on
  the router's rollback for correctness. Validation now precedes any mutation.

An existing test encoded the old permissive behaviour (`Open → Contained` in
one step) and was rerouted through a legal path; its assertion substance is
unchanged.

### 4.2 Phase C — evidence **[IMPLEMENTATION]**

Evidence is a **read-only projection** of rows the platform already holds, not
a copied table. There is no create, no update, no delete, and no endpoint that
would perform one — which is the strongest available form of "an analyst must
not be able to silently rewrite historical evidence": not a policy that could
be forgotten, but the absence of a door.

The honest part is the integrity taxonomy. Evidence does **not** claim uniform
immutability, because two of its sources are rewritten in place:

| Source | Integrity | Why |
| --- | --- | --- |
| Event | `write_once` | Written at ingestion, not rewritten |
| MLInference | `append_only` | Unique per (event, model, version) |
| AIAnalysis | `append_only` | New row per request |
| SecuritySequence | `mutable` | Extended as related events arrive |
| IOC | `mutable` | `sighting_count` incremented in place |
| ThreatIntelResult | `mutable` | **Re-lookup overwrites the verdict** |

That last row is the one to read twice. A threat-intelligence verdict behind a
past decision can change with nothing to show for it but a digest.

### 4.3 Phase D — decisions bound to evidence **[IMPLEMENTATION]**

A consequential transition records a `DecisionEvidenceBinding`: a manifest
digest over the identity and content of every evidence item at the moment the
decision was taken. `verify` compares then against now and returns a drift
verdict on the ladder `unchanged < extended < refreshed < tampered`.

`refreshed` is deliberately its own verdict rather than being folded into
`tampered`: mechanically it is routine (a threat-intel row was re-looked-up),
materially it can be serious (the verdict a decision rested on has changed).

`expectedEvidenceDigest` is **optional** on a lifecycle transition, for clients
that predate it, and **mandatory** on a response approval, where there is no
compatibility to preserve.

### 4.4 Phase E — response approval **[IMPLEMENTATION]** **[NOT IMPLEMENTED: execution]**

The brief asked whether to integrate with the existing
`POST /incidents/{id}/response` placeholder. **The decision was not to.** That
endpoint records a single-party free-text note; dressing it in four-eyes
machinery would have implied a governance property it does not have. It is
untouched and still present.

The new object is `ResponseActionRequest`: five action *names*, a required
justification, and a decision by a second person holding
`incidents:respond_approve` — a permission analysts deliberately do **not**
hold, so an analyst cannot satisfy four-eyes by logging in twice.

**Nothing is executed.** There is no provider, no executor, no result column.
`executed` is always `false` and every response carries an `executionNote`
saying so.

A real V7 gap was found and closed here: the non-human actor check was
case-defeatable. `app/core/actors.py` is now the single shared rule, with all
three consumers proven to agree.

### 4.5 Phase F — provider health **[IMPLEMENTATION]**

`EvidenceProvider.health()` had existed since Phase C with a docstring
promising that *a failure is never reported as an absence* — and **no provider
implemented it**. On this machine that meant `aegisx.ml` and
`aegisx.threatintel` reported healthy while returning nothing, which reads as
"the model looked and found no anomalies".

Two further holes were closed:

- `collect_all` called `health()` *outside* its try block, so the one method
  whose job is to report brokenness could take the evidence page down with a
  500. Confirmed by reintroducing it.
- `EvidenceProvider.describe()` called `health()` itself, which would have been
  a second unguarded copy of the same hazard.

The subsystem probes moved from the health router into
`app/services/health_service.py` so provider health and `/health/system` cannot
disagree about the same subsystem. **All eight moved bodies were verified
AST-identical to the originals** — a first hand-reconstruction of
`telemetry_health` had invented a settings key and renamed three response
fields, which that check caught.

### 4.6 Phase G — cloud posture **[SIMULATED]**

Read §9 before believing anything here is a cloud integration.

Nine posture checks over storage, identity, network and logging. The checks are
ordinary pure functions; what is fixture-backed is the **input**. A real
scanner replaces `app/cloud/scanner.py` and reuses every check unchanged —
the same split `CloudTrailFileSource` has had since V7.

The security-critical part is resource identity. An ARN is parsed into fields
and compared field by field, never as a string, so a resource *name* — the one
field an attacker can influence — cannot smuggle a different account.

The correlation rule has two branches, and **the second exists because a test
failed, not because it was designed in**:

- An **account-scoped** ARN is accepted only when its account matches the
  account the event was recorded in. Without this, anyone who can get a string
  into a CloudTrail request parameter could name a resource in an unrelated
  account and have that account's posture rendered on their incident.
- An **accountless** ARN — an S3 bucket — is accepted on the name alone,
  because S3 omits the account precisely because bucket names are globally
  unique. Requiring an account there would mean no bucket ever correlates.

Both branches are covered; removing the account check fails two tests.

`cloud_finding` left the reserved evidence kinds when it gained a producer.
That was forced by the Phase C guard, whose message states the rule: *either it
is real, in which case it is no longer reserved, or it is fabricated.*

### 4.7 Phase H — metrics **[IMPLEMENTATION]**

Structured logging and request correlation already existed since V2. There were
**no metrics at all**, and `/metrics` was already named in the middleware's
quiet-paths list, pointing at an endpoint that did not exist.

The design decision that matters is **bounded cardinality**. Instrumenting by
`request.url.path` would make every incident id a permanent series; HTTP
metrics use the matched **route template**, unmatched requests collapse to a
single `unmatched` series, and each metric has a ceiling that drops new label
combinations and *counts the drop* rather than growing or failing silently.

No dependency was added. `prometheus_client` is a good library, but the
exposition format is about a hundred lines and a metrics library is not where a
security platform should spend its first unnecessary supply-chain edge.

`/api/v1/metrics` **requires a session**. That departs from the usual open
`/metrics`, deliberately: request rates and incident volumes describe how much
security activity an organisation handles and when it stops.

Running the tests for the first time found a real bug: the label read
`/incidents` where the endpoint is `/api/v1/incidents`, because this FastAPI
version keeps an included router nested rather than copying its routes onto the
app, and `root_path` is empty. Cardinality was never at risk — the value was
still a bounded template — but the label would not have matched any endpoint a
dashboard author would type.

---

## 5. Migrations **[MEASURED]**

| Revision | Adds | Downgrade |
| --- | --- | --- |
| `0012_v9_incident_lifecycle` | Widens the incident status CHECK constraint | Refuses — narrowing would strand rows in the new states |
| `0013_v9_decision_evidence` | `decision_evidence_bindings` | Drops the table |
| `0014_v9_response_action_approval` | `response_action_requests` | Drops the table |
| `0015_v9_cloud_posture` | `cloud_posture_findings` | Drops the table |

All four validated on SQLite **and** PostgreSQL: upgrade → downgrade →
re-upgrade, with index and column types inspected afterwards.

**A defect worth remembering.** `0013` and `0014` originally declared bare
`sa.JSON()` columns while their models declared JSONB. On SQLite that is a
no-op; on PostgreSQL the columns came out `json`, losing GIN indexing and the
containment operators. **Only the PostgreSQL validation could catch it, and it
did.** `0015` uses the shared
`JSONType = sa.JSON().with_variant(JSONB, "postgresql")` and its `detail`
column was confirmed `jsonb`.

---

## 6. Frontend **[IMPLEMENTATION]**

`IncidentStatus` had listed four states while the backend had returned seven
since Phase B. Nothing crashed, which is why it survived — the types were
simply wrong about the running system.

Added: `LifecycleControl`, `ResponseActions`, `ProviderHealthPanel`,
`CloudPosturePanel`, and the API clients behind them.

Two decisions worth keeping:

- **The lifecycle graph is not restated in TypeScript.** The workspace asks
  `GET /incidents/{id}/transitions`. A second copy would drift, and the copy
  that drifts is the one users see.
- **Transitions the user may not take are shown disabled, not hidden.** Hiding
  them teaches an analyst that closing an incident is not something the system
  does, rather than something somebody else does.

The evidence tab needed no change for cloud findings: it renders an evidence
item by kind generically.

---

## 7. Security properties added **[IMPLEMENTATION]**

| Property | Where enforced |
| --- | --- |
| Illegal lifecycle transitions refused | `incident_service`, not the router |
| Terminal states sealed | `lifecycle.is_terminal` |
| Reason required on edges that end or undo work | `lifecycle.requires_reason` |
| Evidence cannot be created, edited or deleted | No such function exists |
| Decisions record the evidence they rested on | `decision_service.bind` |
| Stale-evidence decisions refused with 409 | `check_expected_digest` |
| Four-eyes on containment approval | `response/approval.py` |
| Non-human actors cannot approve | `core/actors.py`, one shared rule |
| Approval parameters cannot change after request | `parameters_digest` |
| Cross-account cloud correlation refused | `cloud_posture_service._belongs_to` |
| Metrics carry no user, incident or account identifier | `observability/instruments.py` |
| Metrics endpoint requires a session | `api/v1/metrics.py` |

Every one is enforced in the service or domain layer. The frontend mirrors them
for usability only; a hand-crafted request is refused identically.

---

## 8. New permissions **[MEASURED]**

```
incidents:close             admin      closing is terminal
incidents:respond_approve   admin      deliberately NOT analyst — see §4.4
cloud:read                  viewer     understanding an incident is not a privilege
cloud:scan                  admin      writes rows the whole SOC reads
```

---

## 9. Cloud posture is SIMULATED **[SIMULATED]**

Stated separately because it is the claim most easily misread.

- There is **no cloud SDK in this project**. A test asserts `boto3`,
  `botocore`, `azure` and `google` are not importable.
- No credentials exist, and nothing on the posture path opens a socket.
- Findings are computed by local checks from a configuration snapshot committed
  to this repository, hand-written to the shape the AWS APIs return.
- Every stored row carries `is_simulated`, NOT NULL with **no server default**,
  so the schema refuses a row that does not say what it is.
- Every API response carries a `note` saying no cloud account was contacted.
- The evidence provider is **never healthy** — a healthy cloud posture provider
  would be claiming a capability the platform does not have.

The checks carry **no CIS, NIST or ISO control identifiers**. AEGISX has not
been assessed against any framework, and a benchmark number beside a finding
reads as a mapping somebody validated. The `control` field names the hardening
theme in words instead.

---

## 10. What V9 did NOT do **[NOT IMPLEMENTED]**

Without softening:

- **Nothing is executed.** No response action reaches any system. There is no
  executor, no provider registry for actions, no result.
- **No cloud provider integration.** See §9.
- **No agents, no autonomous remediation, no multi-agent system, no autonomous
  retraining.** All were explicitly out of scope and none was started.
- **No Kubernetes security.** Not started.
- **No new research result.** V9 ran no experiment and produced no metric about
  detection quality. Every research claim in the repository is still V4–V8's.
- **The V7 `POST /incidents/{id}/response` placeholder is unchanged**, and is
  still a single-party free-text note. §4.4 explains why it was left alone.
- **Endpoint, identity and network findings remain reserved kinds** with no
  producer.
- **No SSO, MFA, refresh tokens or penetration testing** — the V1 gaps in
  `SECURITY.md` are still open.
- **The metrics endpoint is not scraped by anything.** No Prometheus, no
  Grafana, no dashboard exists.

---

## 11. Verification of Phase H **[LIMITATION]**

At the time this section was written the Phase H full-suite run had not
finished. What *was* verified:

- All 35 Phase H tests pass (`test_observability_metrics.py`,
  `test_observability_api.py`).
- The route-template guard bites: mutating the label back to the raw request
  path fails three tests, including the one asserting no incident or event id
  reaches a series.
- `ruff check .` clean.

**A new session must re-run the full backend suite before treating Phase H as
verified.** See §12 for how.

---

## 12. Environment requirements and traps **[MEASURED]**

Read this before running anything.

**Never run two pytest processes at once.** They share
`/tmp/aegisx_test.db` and corrupt it. This trap is inherited from the V8
handoff and was hit once in this session anyway, by running `--collect-only`
during a full run. If a run must be abandoned, kill it, delete the database,
and start again — do not start a second one alongside.

**PostgreSQL dies between sessions in this container.** The data directory
survives; the server does not. Every phase in this session had to restart it:

```bash
pg_ctlcluster 16 main start     # "Removed stale pid file" is normal
pg_isready -h 127.0.0.1 -p 5432
```

Without it, `test_database_postgres.py` **skips its whole module** and a run
reports 25 fewer tests while still exiting 0. A green exit code is not
sufficient evidence the PostgreSQL tests ran — check the skip count.

**The PostgreSQL test database is not migrated by the fixture.** The `engine`
fixture only connects. After adding a migration, apply it by hand or
`test_the_head_revision_is_applied` will fail:

```bash
DATABASE_URL="postgresql+psycopg://aegisx:aegisx@127.0.0.1:5432/aegisx_v9fresh" \
  python -m alembic upgrade head
```

**Full run command:**

```bash
cd backend
rm -f /tmp/aegisx_test.db
DATABASE_URL="sqlite:///aegisx.db" \
AEGISX_TEST_POSTGRES_URL="postgresql+psycopg://aegisx:aegisx@127.0.0.1:5432/aegisx_v9fresh" \
  ../.venv/bin/python -m pytest -q -rs
```

It takes roughly 35–40 minutes. Do not poll it in a tight loop.

**A fresh container has no venv and no node_modules.** `pip install` fails with
an `AssertionError` on `pyc_path`; use `pip install --no-compile`.

**Importing `app.evidence` before `app.main`** raises a circular-import error
(`app.evidence.models` → `app.ai` → `app.correlation` → `app.services` →
`decision_service` → `app.evidence.service`). **Pre-existing, not introduced by
V9**; it does not affect the app or the tests, which import through `app.main`.
Worth fixing in V10.

---

## 13. Preserve these decisions

Things a later session should not undo without understanding why they are here:

1. **Evidence is a projection, not a table.** There is no write path to abuse.
2. **Security invariants live in the service/domain layer**, because the API is
   one caller. Never rely only on a FastAPI dependency or a UI check.
3. **One shared actor rule** (`core/actors.py`). The V7 bug was two
   implementations disagreeing about case.
4. **One shared health mechanism** (`services/health_service.py`). Provider
   health and `/health/system` must not be able to disagree.
5. **The lifecycle graph exists once**, in Python, and is served to the UI.
6. **`refreshed` is not `tampered`**, and neither is `unchanged`.
7. **Metrics labels are bounded by construction**, not by hope.
8. **Simulated things say so**, in the schema, the API response and the UI.
9. **Severity is not a score.** Posture severities are never summed or averaged
   into a grade.
10. **No benchmark identifiers** on checks that were never assessed.

---

## 14. Recommended V10 scope **[INFERENCE]**

This is a suggestion, not a finding.

1. **Run the Phase H suite and close §11.** First thing.
2. **Fix the circular import** in §12 — small, and it makes the package
   importable in isolation for pure-domain tests.
3. **Execution, if and only if it is governed.** The approval object exists and
   records who approved what on which evidence. An executor would need: an
   action provider contract, a dry-run mode, a kill switch, an execution audit
   distinct from the approval audit, and a rollback story. Anything less should
   stay unbuilt.
4. **A real cloud posture source.** Replace `scanner.py` only; the checks and
   the correlation stay. This is the phase that makes §9 shrink.
5. **The remaining reserved kinds** — endpoint, identity, network findings —
   now have a proven pattern to follow.
6. **Scrape the metrics.** They are not observed by anything today.

---

## 15. First steps for a new session

```bash
# 1. Start PostgreSQL - it will be down.
pg_ctlcluster 16 main start && pg_isready -h 127.0.0.1 -p 5432

# 2. Confirm the migration head.
cd backend && DATABASE_URL="sqlite:///aegisx.db" \
  ../.venv/bin/python -m alembic heads      # expect 0015_v9_cloud_posture

# 3. Run the suite ONCE. Never two at a time.
rm -f /tmp/aegisx_test.db
DATABASE_URL="sqlite:///aegisx.db" \
AEGISX_TEST_POSTGRES_URL="postgresql+psycopg://aegisx:aegisx@127.0.0.1:5432/aegisx_v9fresh" \
  ../.venv/bin/python -m pytest -q -rs

# 4. Frontend.
cd ../frontend && npm run verify
```

Then read, in this order: `app/incidents/lifecycle.py`,
`app/evidence/provider.py`, `app/response/approval.py`,
`app/cloud/resources.py`, `app/observability/metrics.py`. Each module's
docstring states what it refuses to do and why; those are the constraints V9
was built around.
