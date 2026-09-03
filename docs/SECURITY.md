# Security Model

> **Scope note.** Written for V2 and still accurate for everything it describes.
> V3 added ML artifact digest verification, SSRF protection on outbound
> enrichment, three-layer prompt-injection defence and per-process budgets; V4
> added the `evaluation:read` permission and a read-only research API. The V3
> and V4 additions are summarised at the end of this file.

What AEGISX V2 actually enforces, and what it does not. Nothing here claims the
system is production-secure; it describes the controls that exist and names the
gaps that remain.

## Authentication

* Passwords are stored as **PBKDF2-HMAC-SHA256**, 390,000 iterations, 16-byte
  per-user random salt, encoded as `pbkdf2_sha256$iterations$salt$hash`.
  Verification is constant-time. Argon2id is the intended upgrade.
* Login answers identically for an unknown account and a wrong password, and the
  unknown-account path still performs a hash comparison so response time does
  not reveal whether an account exists.
* Failed and successful logins are both audited, with the client address.
* `POST /auth/login` has its own tight rate-limit bucket (10 per minute per
  client by default) separate from the general API limit.

## Sessions

* JWT, HS256, signed with `JWT_SECRET_KEY`. Claims: `sub`, `iat`, `nbf`, `exp`,
  `iss`, `type`, `jti`, `email`, `role`, `tv`.
* `tv` is the user's **token version**. Every request checks it against the
  stored value, so:
  * `POST /auth/logout-all` revokes every token already issued,
  * a password change revokes every session automatically.
  This gives real revocation without a server-side session store.
* `POST /auth/logout` is stateless - it writes the audit entry; the client
  discards its token.
* Default lifetime is 8 hours (`ACCESS_TOKEN_EXPIRE_MINUTES`).

**Known weakness:** the token lives in `localStorage`, readable by any script on
the origin. An httpOnly refresh cookie plus a short-lived in-memory access token
is the fix; it is not in V2.

## Authorization (RBAC)

Three roles and one explicit permission matrix
(`backend/app/core/rbac.py`, served at `GET /api/v1/auth/permissions`).

| | viewer | analyst | admin |
| --- | --- | --- | --- |
| Read events, incidents, IOCs, analytics, detection, notifications, telemetry status | ✓ | ✓ | ✓ |
| Ingest events, update event status, promote to incident | | ✓ | ✓ |
| Create / update incidents, record response actions, mark notifications read | | ✓ | ✓ |
| Run detection evaluation, trigger telemetry, read audit, manage users, change system config | | | ✓ |

Enforcement is server-side on every route via a permission dependency. The
console hides controls a role cannot use, but that is usability: a hidden button
and a hand-crafted request are refused the same way. Denied requests are audited
with the role, the required permission and the path.

## Request handling

* **Validation**: every request body and query parameter is a Pydantic model
  with bounded lengths and enumerated values; unknown fields are rejected.
* **Value constraints in the database**: severity, status and role vocabularies
  and risk-score ranges are CHECK constraints, so a bug in the application layer
  cannot persist a value the UI cannot render.
* **Body size**: requests over 1 MiB are refused before parsing.
* **Rate limiting**: sliding window per client address, 300/minute by default,
  10/minute on authentication. *Counters are per process*: with multiple workers
  the effective limit multiplies. A shared store is required before running more
  than one process.
* **Security headers** on every response: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive
  `Content-Security-Policy` (the API serves JSON, so it may load nothing),
  `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store`, and HSTS when served over TLS.
* **CORS**: explicit origins from configuration, explicit methods and headers.
  A wildcard origin is refused outright in production.

## Error handling

* Unhandled exceptions return `{"detail": "Internal server error", "requestId": …}`
  and nothing else. The detail goes to the structured log under the same request
  id.
* Validation failures return field names and messages but **never echo submitted
  values** - the default FastAPI handler would put a password into the response
  and the logs the first time a login payload failed validation.
* Health probes report component types, never connection strings.

## Audit trail

Append-only; no endpoint updates or deletes an entry. Recorded actions:

`user.login`, `user.login_failed`, `user.logout`, `user.password_changed`,
`user.sessions_revoked`, `user.created`, `user.role_changed`, `event.viewed`,
`event.promoted`, `event.status_changed`, `incident.created`,
`incident.status_changed`, `incident.assigned`, `incident.response_action`,
`ioc.viewed`, `detection.evaluation_run`, `system.settings_changed`,
`auth.access_denied`.

Entries carry timestamp, user id and email (denormalized so the trail survives
user deletion), action, target type and id, client address and a metadata
object. Secrets, passwords and tokens are never written to it.

## Secrets and configuration

* All configuration comes from the environment / `.env`; `.env` files are
  gitignored and only `.env.example` is committed.
* Production refuses to start with the default JWT secret, a secret shorter than
  32 characters, demo-user seeding enabled, a wildcard CORS origin, rate limiting
  disabled, security headers disabled, or request-body logging enabled.
* The frontend receives no secrets. `VITE_*` variables are inlined into the
  bundle at build time and are therefore public by definition; the only one used
  is the API URL.
* Demo credentials appear only in `.env.example`, docker-compose defaults and
  documentation, and only for the local bootstrap account.

## Telemetry safety

* The synthetic generator is the only source enabled by default. Everything it
  emits is marked `synthetic: true`, uses `SYN-`/`EVAL-` hostnames and RFC 5737
  documentation IP ranges.
* Any source that reaches outside the process must set `is_external = True`, and
  registering one is **refused** unless `TELEMETRY_ALLOW_EXTERNAL_SOURCES=true`.
  AEGISX cannot start talking to a production system by accident.
* Response actions are recorded, never executed. There is no code path that
  isolates a host or blocks an address.

## Not implemented

Stated plainly, because a security document that only lists wins is marketing:

* No MFA, no SSO, no password complexity policy beyond a length minimum.
* No refresh tokens or token rotation.
* No per-source authentication on `POST /events` beyond a user session - a real
  collector needs its own credential and quota.
* No encryption at rest beyond what the database provides; no field-level
  encryption.
* No dependency or container scanning in CI yet.
* No penetration testing. Nothing here has been tested by anyone but its author.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the attacks these controls are and
are not designed to stop.


---

## V3 additions

| Control | Behaviour |
| --- | --- |
| Model artifact verification | SHA-256 checked on **every** load; a mismatch refuses to load |
| Model path validation | Name and version validated as single safe path components; resolved path confined to `ML_MODEL_DIR` |
| SSRF protection | Strict allowlist grammar per indicator type; private, loopback, link-local, reserved, multicast and RFC 5737/3849 documentation ranges refused; redirects refused |
| Prompt injection | Three layers — structural fencing, lexical sanitization, and **capability**: the AI analyst has no tools, no write access and no authority. The third is the one that matters. |
| API keys | Server-side only; absent from every payload, log line and error message. The browser never contacts a provider. |
| Budgets | Per-process daily ceilings for threat intel (400) and AI (200); bounded enrichment queue that drops rather than grows |

V3 permissions: `ml:read`, `ml:manage` (admin only — analysts cannot deploy
models), `sequences:read`, `threatintel:read`, `threatintel:enrich`, `ai:read`,
`ai:request`, `ai:configure`.

## V4 additions

| Control | Behaviour |
| --- | --- |
| `evaluation:read` | Granted to **viewer** and above. Measured quality is transparency, not privilege. |
| No experiment execution over HTTP | The evaluation router exposes **GET only**, asserted by a test. Running an experiment is minutes of CPU over a whole corpus; over HTTP that is a resource-exhaustion primitive. |
| Datasets are untrusted input | Parquet is read as data. No dataset content is executed, and no arbitrary pickled Python object is loaded from an untrusted source. |
| Dataset digest verification | Every shard is SHA-256 verified on load; a mismatch refuses to evaluate rather than warning |
| Bounded CLIs | Every evaluation CLI takes `--max-seconds` (default 900), exiting 142 with thread stacks rather than hanging |

Degraded-mode behaviour is now **measured**, not asserted: five scenarios (no
model, corrupt artifact, digest mismatch, no threat intel, AI unavailable) each
confirm that ingestion, normalization and rule detection continue. See
`app/evaluation/system_eval.py`.


---

## V5: controlled adaptation

Adaptation adds a path that can change what the platform detects, so it adds
controls rather than relaxing them.

| Control | Enforcement |
| --- | --- |
| No autonomous production change | `registry.activate_model` refuses any model not in a servable state; a candidate reaches production only through an approved proposal |
| Human approval is human | `proposals.approve` refuses actors prefixed `ai:`, `system:`, `automation:` |
| Separation of duties | Proposer and approver are distinct columns; `self_approved` is recorded when they match |
| No training over HTTP | No endpoint trains a model or builds a dataset; asserted by test |
| Artifact immutability | `reserve_artifact_path` refuses an existing path; `next_version` consults disk as well as the database |
| Artifact integrity | Digest verified before evaluation and before deployment; a mismatch refuses and leaves the incumbent serving |
| Untrusted feedback | Analyst comments pass the existing sanitizer before reaching a prompt; injection attempts are reported as findings |
| MITRE provenance | AI-cited techniques the evidence does not support are recorded as ungrounded, never as attribution |
| Fail-safe | Deployment validates before it mutates; on refusal the transaction rolls back and the approved model keeps serving |
| Audit | Every proposal transition writes an audit row with actor, before/after state and rollback target |

### The one finding worth naming

**[MEASURED]** Before V5, model immutability was enforced against the database
only. With a rebuilt database — an empty `ml_models` table and a `v1.0` artifact
still on disk — `next_version` returned `1.0` and training overwrote the
digest-verified deployed model. Observed directly: `053d1ff3…` → `016c6dbf…`.
Fixed, with the original scenario reproduced as a regression test.
