# AEGISX V11 — PLAN

> **This is a plan, not a record.** Nothing in it is implemented. Every claim
> about AWS behaviour marked **[VERIFY]** must be checked against AWS's own
> documentation before it is relied on — this document was written without an
> AWS account attached, and a plan that guesses at IAM semantics is worse than
> no plan.
>
> Written at the end of the V9 session as `V10_PLAN.md`, and renamed when
> V10 shipped something else: the approval-boundary work merged in #2. The
> scope described here was never V10's, so the file is named for the version
> that will actually do it. Supersedes `CLAUDE_HANDOFF_V9.md` §14, which
> sketched this in five lines.

Tags as in V4–V9: **[MEASURED]**, **[IMPLEMENTATION]**, **[SIMULATED]**,
**[LIMITATION]**, **[INFERENCE]**, **[NOT IMPLEMENTED]**, plus **[VERIFY]** for
a claim this document is not entitled to make yet.

---

## 1. The problem V11 exists to solve

V9 built a security operations platform whose cloud security capability is
**entirely simulated** — honestly labelled, carefully bounded, and still
simulated. Nine posture checks run against a configuration snapshot committed
to this repository. There is no AWS SDK in the project, no credential, and no
socket opened on that path.

Everything else in AEGISX is real. This one area is not, and it is the area the
project most wants to claim.

**V11's goal: make it real, without loosening a single thing V9 got right.**

The seam already exists. `app/cloud/scanner.py` is the only provider-specific
file in the cloud package:

```
  scanner.py  ──▶  ResourceSnapshot  ──▶  checks.py  ──▶  CloudFinding
  ^^^^^^^^^^                              (9 checks)      │
  the ONLY file                                           ▼
  V11 replaces                              resources.py (ARN identity)
                                                          │
                                                          ▼
                                        cloud_posture_service (correlation)
                                                          │
                                                          ▼
                                    CloudPostureEvidenceProvider (evidence)
```

That split was a deliberate V9 decision, made so that a live source changes one
class and nothing else. V11 is where it either pays off or turns out to have
been wishful — and finding out which is itself worth the phase.

---

## 2. Prerequisites

1. **V10 is merged.** V11 branches from the resulting `main`. Never stack on
   merged history.
2. **An AWS account you control**, with a **budget alarm set before anything
   else is created**. A student account without a budget alarm is a bill
   waiting to happen. Posture reads are cheap, but "cheap" is not "free" and
   "cheap" is not "bounded".

---

## 3. The test that will fight this, correctly

`app/tests/test_cloud_posture_api.py::test_no_cloud_sdk_is_installed` asserts
that `boto3`, `botocore`, `azure` and `google` are **not importable**. Adding
`boto3` must fail it.

That is the guard doing its job, exactly as the Phase C reserved-kinds guard did
when `cloud_finding` gained a producer. Its message should be read the same way:
*either the claim is still true, or the claim changes deliberately.*

**First task of V11 is retiring that assertion honestly** — narrowing it to the
SDKs still absent (`azure`, `google`) and replacing the `boto3` case with the
tighter guarantee V11 actually offers: see §5.3.

Do **not** delete the test.

---

## 4. Phase A — AWS foundation **[VERIFY throughout]**

The phase with the most learning in it, and the one the operator drives.

### A.1 Budget alarm, first

Before any role, any resource, any code. A low threshold with an email alert.

### A.2 A read-only role, not a user

No IAM user. No access keys. A **role** assumed through federation.

*Why:* an access key is a permanent secret. It lives on a laptop, in a shell
history, in a `.env` that eventually gets committed. A federated role issues a
short-lived credential scoped to one repository — if it leaks it has usually
already expired, and it only ever worked from one place.

### A.3 Which managed policy **[VERIFY]**

Proposed starting point: the AWS-managed **`SecurityAudit`** policy rather than
`ReadOnlyAccess`.

The reasoning to check: `SecurityAudit` is intended for reading *configuration*,
whereas `ReadOnlyAccess` is broader and — this is the part to verify — may
permit reading object *contents* in some services. A posture scanner has no
business reading the inside of a bucket; it needs to know the bucket's settings.

**Verify the actual permission set before adopting it.** Do not trust the name,
and do not trust this document. If `SecurityAudit` turns out broader than
needed, write a narrower customer-managed policy listing only the API calls
§5.1 actually makes — which is the better answer anyway, just more work.

### A.4 GitHub OIDC federation **[VERIFY]**

A trust policy allowing GitHub Actions to assume the role, conditioned on the
repository **and** the branch or environment. The conditions are the security
control; the role is just the thing they protect. Each condition key should be
understood before it is written, not pasted.

For local development: AWS SSO or a named profile. Never a key in the repo.

---

## 5. Phase C — the live scanner **[IMPLEMENTATION]**

(Phase B is §6; it is listed after because it is easier to explain once the
scanner's needs are known. Implement B before C.)

### 5.1 Scope: only what the nine checks need

The checks require exactly this configuration and nothing else:

| Check family | Needs |
| --- | --- |
| S3 (3 checks) | bucket list, public access block, default encryption, access logging |
| IAM (4 checks) | roles and their trust policies, attached policies, users, MFA devices, access key ages |
| EC2/network (1 check) | security groups and their ingress rules |
| CloudTrail (1 check) | trails and their logging status |

Nothing else is read. A scanner that fetches more than its checks consume is
collecting data it has no purpose for, which is the opposite of what a security
tool should model.

### 5.2 Constraints to hold

- **Bounded.** Pagination caps, per-call timeouts, a resource ceiling and a
  clear failure state — the same discipline as `observability/metrics.py` and
  `evidence/binding.py`. An account with ten thousand buckets must degrade, not
  hang.
- **Never raises into the caller.** The `EvidenceProvider` contract already
  requires this; a live scanner has far more ways to fail than a file reader
  (throttling, expired credentials, a region that is not enabled) and every one
  of them reports through `health()` rather than an exception.
- **Feature-flagged, defaulting off.** With no credential configured the
  platform behaves exactly as V9 does today: the fixture scanner, clearly
  labelled simulated.
- **Partial results are labelled partial.** If four of nine check families read
  successfully and IAM was throttled, the result is not "five findings"; it is
  "five findings, IAM unavailable". V9 built `degraded` for precisely this.

### 5.3 Read-only by construction, and tested

Replace the deleted `boto3` assertion with a stronger one: **no mutating API
name appears anywhere in `app/cloud/`.** A grep-style test over the package
source for `Create*`, `Put*`, `Delete*`, `Update*`, `Attach*`, `Detach*`,
`Modify*`, `Revoke*`, `Terminate*`.

This is a weaker guarantee than "no SDK installed" and it should be described as
weaker. It is, however, the honest one available once the SDK is present, and
it fails loudly if somebody later reaches for a write call.

The IAM policy is the real control. The test is the second line.

### 5.4 No network in the test suite

`botocore`'s `Stubber` with recorded responses. The suite stays offline,
deterministic and fast. A test that needs credentials is a test that does not
run in CI and rots.

**Record the fixtures from a real account once**, scrub them, and commit them —
that also gives the existing fixture scanner better data than hand-written JSON.

---

## 6. Phase B — Terraform, and scanning it **[IMPLEMENTATION]**

The role from Phase A is defined as code in `infrastructure/terraform/`, not
clicked together in the console.

*Why it matters here specifically:* the thing being defined is a grant of access
to a cloud account. If it is created by hand, nobody can review it, nobody can
tell when it changed, and "least privilege" is an assertion rather than a diff.

Then `checkov` or `tfsec` scans that Terraform in CI. The interlock is the
point: **the IaC that grants cloud access is itself gated by the security
pipeline.**

Implement this before Phase C so the role exists, reviewably, before anything
assumes it.

---

## 7. Phase D — `is_simulated` starts meaning something

Today it is always `true` and the column is, in effect, a constant. After
Phase C:

- a live scan writes `is_simulated=False`;
- `cloud_posture_health()` can return **healthy** for the first time, instead of
  the permanent "degraded: cloud posture is simulated";
- the UI distinguishes live findings from fixture ones;
- `docs/CLAUDE_HANDOFF_V9.md` §9 shrinks to a paragraph about the fallback.

Live and simulated findings must remain distinguishable **in the same table at
the same time**, because a developer will run both. They already are — that is
what the column is for.

---

## 8. Phase E — the rest of DevSecOps **[IMPLEMENTATION]**

`SECURITY.md` already admits: *"No dependency or container scanning in CI yet."*
V11 closes it.

| Gate | Covers |
| --- | --- |
| `pip-audit`, `npm audit` | Known-vulnerable dependencies |
| Trivy | Both Dockerfiles |
| `bandit` or `semgrep` | Python SAST |
| `checkov` or `tfsec` | The Terraform from Phase B |

**Decide the failure policy deliberately**, and write down the reasoning: a gate
that blocks on every advisory will be disabled within a month; one that blocks
on nothing is decoration. A defensible starting point is *fail on high and
critical with a documented, expiring allowlist* — but it is a real decision, not
a default to copy.

---

## 9. Phase F — documentation and the V11 handoff

`docs/CLAUDE_HANDOFF_V11.md`, in the established form. The V9 documents that
describe cloud posture as simulated must be corrected in the same phase that
makes them untrue — that is the V9 Phase K lesson: documents do not go wrong,
they go stale, and staleness is invisible.

---

## 10. What V11 will NOT do **[NOT IMPLEMENTED]**

Stated now so it cannot drift later:

- **No writes to any cloud account.** Read-only, enforced by IAM policy and
  checked by a test. AEGISX does not remediate.
- **Still no execution of response actions.** That remains V9's boundary. If it
  is ever crossed it needs its own version, with a dry-run mode, a kill switch,
  an execution audit distinct from the approval audit, and a rollback story.
  Anything less stays unbuilt.
- **No Azure, no GCP.** One cloud, done properly. `CloudProvider` already has
  the enum members; `resources.py` deliberately parses AWS ARNs only and returns
  `None` — matching nothing — for anything it cannot identify.
- **No agents, no autonomous remediation, no autonomous retraining.**
- **No new research claim.** V11 is engineering. Any detection-quality claim
  needs the V4–V8 evaluation machinery and its own pre-registered design.
- **No secrets in the repository.** Not encrypted, not in an `.env.example` that
  looks real, not in a fixture.

---

## 11. Success criteria **[MEASURED, when it happens]**

V11 is done when all of these hold:

1. A live posture scan against a real AWS account produces findings with
   `is_simulated=False`, and they correlate to incidents through the **unchanged**
   V9 path.
2. `app/cloud/checks.py`, `resources.py`, `cloud_posture_service.py` and the
   evidence provider are **unmodified** by Phase C. If they had to change, the
   V9 seam was wrong and that finding should be written down rather than
   quietly patched over.
3. The full test suite runs **offline**, with no credential, and passes.
4. No mutating AWS API name appears anywhere in `app/cloud/`.
5. The IAM role is defined in Terraform, scanned in CI, and grants no write.
6. CI fails on a high or critical dependency, container, SAST or IaC finding.
7. `SECURITY.md` no longer says scanning is missing, and §9 of the V9 handoff no
   longer describes the platform's only cloud capability.

---

## 12. Risks, honestly

| Risk | Mitigation |
| --- | --- |
| Cost on a student account | Budget alarm before the first resource; posture reads only; no compute created |
| A leaked credential | OIDC only; no access keys; no secret in the repository |
| Over-broad IAM grant | Verify the managed policy's real contents (§4.3); prefer a narrow customer-managed policy |
| Tests that need the internet | `Stubber` with recorded, scrubbed fixtures; suite stays offline |
| Scope creep into remediation | §10, and the fact that the write path does not exist |
| The V9 seam turns out leaky | Criterion 2 makes that a reportable finding rather than a silent refactor |

---

## 13. First move

Create the account and **set the budget alarm**. Create nothing by hand after
that — the role is Terraform's job in Phase B, so that it is reviewable from the
first commit rather than reconstructed later from memory.
