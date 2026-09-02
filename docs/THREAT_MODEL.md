# Threat Model

> **Scope note.** Written for V2. V3 introduced three new outward- or
> upward-facing surfaces (outbound threat-intel lookups, an LLM prompt path, and
> a loadable model artifact) and V4 introduced a fourth (third-party dataset
> files read from disk). Those are covered at the end of this file; the V2
> analysis below remains accurate for what it describes.

Scope: AEGISX V2 as it actually exists - an internal SOC console for
authenticated analysts, ingesting synthetic telemetry, deployed on a trusted
network by the person developing it.

Documenting a mitigation is not the same as being secure. Several rows below say
"not mitigated", which is the point of writing this down.

## Assets

1. Analyst accounts and sessions (access to the whole SOC picture).
2. Event, incident and IOC data (what the organisation knows about its attacks).
3. The audit trail (the record of who did what).
4. The detection rules and their thresholds (knowing them is knowing how to
   evade them).
5. The database and its credentials.

## Trust assumptions

* The analysts using the console are authorised and not actively hostile;
  insider abuse is bounded by RBAC and the audit trail, not prevented.
* The telemetry the platform receives is honest. **This is safe for the
  synthetic generator and false for any real source** - see "Malicious
  telemetry" below.
* The host, the database and the network between them are not already
  compromised.

## Threats

| # | Threat | Mitigation in V2 | Residual risk |
| --- | --- | --- | --- |
| 1 | **Credential brute force** against the login endpoint | Dedicated 10/min rate limit bucket; identical responses and timing for unknown vs wrong password; every attempt audited | Per-process limiter; a distributed attempt from many addresses is not stopped. No account lockout |
| 2 | **Credential theft / session hijack** | Short-lived JWTs; token version allows instant bulk revocation; password change revokes all sessions | Token in `localStorage` is XSS-readable; no MFA; a stolen token is valid until it expires or is revoked |
| 3 | **Unauthorized API access** | Every route requires a permission; denials audited; UI hiding is not the boundary | A valid token for a low role still reads all events - there is no per-tenant or per-asset scoping |
| 4 | **Privilege escalation** | Role is a signed token claim validated against the stored user; role vocabulary is a database CHECK constraint; only admins may create users or change roles | An admin account compromise is total. No approval flow for role changes |
| 5 | **WebSocket abuse** | Token validated before the socket is accepted; invalid tokens closed with 4401 so clients stop retrying; heartbeat and server-side cleanup of dead sockets | Token appears in the WebSocket URL and therefore in server/proxy logs; no per-connection quota, so a valid token can open many sockets |
| 6 | **Injection (SQL)** | All queries built through SQLAlchemy with bound parameters; no string-built SQL anywhere | Unchanged risk if raw SQL is ever added |
| 7 | **Injection (XSS) in the console** | React escapes by default; no `dangerouslySetInnerHTML`; raw telemetry rendered as text in `<pre>` | Telemetry content is attacker-influenced; a future rich renderer would need explicit sanitisation |
| 8 | **Malicious telemetry / data poisoning** | Synthetic source only; external sources refused without explicit opt-in; ingestion validates and bounds every field; detection severity is decided by the engine, not by the submitter | **Not mitigated for a real source.** Anyone who can call `POST /events` with an analyst token can flood the queue or forge benign-looking events. Per-source credentials, quotas and provenance are required before any real collector is attached |
| 9 | **Evasion of detection** | Documented and measured: the evaluation reports exactly which classes are covered and which are not | Rules are single-event and threshold-based; staying under a threshold or using an uncovered technique (e.g. lateral movement) is undetected by construction |
| 10 | **Secret exposure** | Secrets only from environment; `.env` gitignored; production refuses insecure defaults; no secret reaches the frontend bundle; audit and logs never record credentials | A committed `.env` or a leaked container environment is still fatal; no secret manager integration |
| 11 | **Database compromise** | Passwords hashed with PBKDF2; value constraints limit what can be written; least-privilege database user is a deployment concern | Event and incident content is stored in plaintext; anyone with database access reads everything |
| 12 | **Analyst account compromise** | Full audit trail of actions taken; `logout-all` for rapid revocation; role limits blast radius | Detection of a compromised analyst account depends on someone reading the audit trail - nothing alerts on it |
| 13 | **Denial of service** | Rate limiting, 1 MiB body cap, paginated endpoints with bounded page sizes, telemetry interval configurable | Single process, single database; no queue or backpressure. A determined flood degrades the service |
| 14 | **Supply chain** | Pinned backend requirements; `npm ci` from a committed lockfile; CI builds both images | No dependency vulnerability scanning, no SBOM, no image signing |

## Assumptions that would invalidate this model

* Exposing AEGISX to the public internet. The rate limiting, session model and
  lack of MFA are calibrated for an internal tool.
* Attaching a real telemetry source without adding per-source authentication -
  see threat 8.
* Running multiple backend workers or replicas. The rate limiter and the
  WebSocket connection registry are per process.
* Storing real incident data. Nothing in the storage model is designed for
  regulated data: no field-level encryption, no retention policy, no redaction.

## Next work, in priority order

1. Per-source authentication and quotas on ingestion (threat 8).
2. Move the access token out of `localStorage` (threat 2).
3. Shared-store rate limiting and connection accounting (threats 1, 5, 13).
4. Correlation rules so evasion by staying under thresholds is harder (threat 9).
5. Dependency and container scanning in CI (threat 14).


---

## V3 and V4 surfaces

| Surface | Threat | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Outbound threat-intel lookup | SSRF into internal services or cloud metadata | Strict per-type allowlist grammar; private/loopback/link-local/reserved/documentation ranges refused; redirects refused | Provider itself is trusted once reached; never exercised against a live provider |
| LLM prompt path | Prompt injection via attacker-controlled event data | Structural fencing, lexical sanitization, and **no capability**: no tools, no write access, no authority over severity/status/risk | An injected string can still influence prose the analyst reads; it cannot change any stored verdict |
| Model artifact | Loading a tampered or swapped model | SHA-256 verified on every load; path confined to `ML_MODEL_DIR`; name/version validated as safe path components | An operator with write access to both the artifact and the registry row could still swap both |
| Third-party dataset files (V4) | Malicious content in a downloaded corpus | Read as data via parquet; digest-verified against recorded SHA-256; no dataset content executed; no arbitrary pickle load | A corpus that hashes correctly but is mislabelled at source would yield wrong metrics, not code execution |
| Evaluation API (V4) | Resource exhaustion by triggering experiments | **No execution endpoint exists**; the router is GET-only, asserted by a test | An operator can still exhaust their own machine from the CLI, which is bounded by `--max-seconds` |

**Not mitigated, and worth stating plainly:** in-process rate limits and budgets
are per worker and multiply across uvicorn processes; a shared store is the
answer above one process. The enrichment queue drops under sustained overload
(reported, never silent).
