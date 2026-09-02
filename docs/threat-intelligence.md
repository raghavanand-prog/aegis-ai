# Threat intelligence

Provider-based by design. The platform depends on the `ThreatIntelProvider`
abstraction, never on any one vendor — there is no VirusTotal-shaped field
anywhere in the models, the services or the API. Adding AbuseIPDB, GreyNoise or
NVD is one class and one dictionary entry.

```
indicator ─► validate ─► cache? ─► budget? ─► provider ─► store ─► attach
```

## The key never reaches the browser

The frontend never talks to a reputation provider. It asks the AEGISX backend;
the backend asks the provider with a key that exists only server-side. No
endpoint on the threat-intel router returns the key, no log line contains it,
and a provider 401/403 is reported as "rejected the configured credentials" and
nothing more.

That is the entire reason these endpoints exist rather than the browser calling
VirusTotal directly.

## Indicator validation, and SSRF

Indicator values originate in telemetry, which is untrusted input, and they end
up in an outbound HTTP request path. `app/threatintel/validation.py` validates
them against a strict allowlist grammar — not escaping, *validating*: an
indicator that does not match its type's grammar is refused.

The specific risk this closes: without it, a crafted log line carrying a
"domain" of `169.254.169.254/latest/meta-data` or `localhost:8000/api/v1/...`
would have the backend make that request on the attacker's behalf, from inside
the network. Redirects are also refused, so a response cannot steer the client
at an address validation already rejected.

Three categories are refused, each with its own reason:

| Category | Why |
| --- | --- |
| Malformed for its type | Not a valid address / domain / hash / URL. |
| Private, loopback, link-local, reserved, multicast | Sending internal addressing to a third party leaks the estate's topology, and no provider has anything useful to say about `10.0.0.5`. |
| **Documentation ranges** (RFC 5737, RFC 3849) | AEGISX's synthetic generator uses these for "external". Looking one up would ask a real provider about an address that does not exist — meaningless verdicts, real quota. |

### Consequence worth knowing before you demo

Because the synthetic telemetry generator uses `203.0.113.0/24` and
`198.51.100.0/24`, **threat intelligence stays quiet on purely synthetic
telemetry**. That is correct behaviour, not a bug, and the UI says so per
indicator rather than leaving a blank panel. To see enrichment work end to end
you need telemetry carrying genuinely routable indicators — an external
collector posting to `POST /events`, or a hash, which has no address ranges to
worry about.

## Reading is not an action

* `GET /threat-intel/ioc/{value}` — an out-of-scope indicator returns **200**
  with an empty result list and `notLookedUp` explaining why. Reading is not an
  action, so being out of scope is an answer here. (Returning 400 made the
  investigation UI fire a request per indicator that it knew would be refused.)
* `POST /threat-intel/ioc/{value}/enrich` — an out-of-scope indicator is
  refused with **400**. Actively asking to send one outward is a different
  matter, and worth refusing loudly.

## Caching

Not an optimisation — a correctness requirement. Reputation services rate-limit
aggressively (VirusTotal's free tier allows four requests a minute), a busy SOC
stream produces the same handful of indicators repeatedly, and every avoided
request is one that cannot fail.

Cache entries carry the **outcome**, not just the verdict, and their lifetime
depends on it:

| Outcome | Cached for |
| --- | --- |
| `ok`, `not_found` | `THREAT_INTEL_CACHE_TTL_HOURS` (default 24h) |
| `timeout`, `rate_limited`, `error`, `unavailable` | 15 minutes |

Caching a failure for a day would turn a thirty-second provider blip into a day
of missing enrichment.

## A failure is never a clean bill of health

This is the single most important rule in this layer. `status` and `reputation`
are separate fields:

```json
{ "status": "timeout",  "reputation": "unknown", "isActionable": false,
  "error": "Provider timed out" }
```

`unknown` reputation with a non-`ok` status means **"we could not find out"**,
which is a completely different fact from "this indicator is harmless". The API
exposes `isActionable`, the UI renders the two states differently, the evidence
package hands the model an explicit note, and the AI grounding check flags an
analysis that claims a verdict which does not exist.

## Budget

A per-process daily ceiling (`THREAT_INTEL_DAILY_BUDGET`, default 400). A
runaway enrichment loop against a metered API is a real way to lose money and
get an account suspended, so the limit is enforced here rather than trusted to
the provider's own. Remaining budget is reported by
`GET /threat-intel/status`.

## Enrichment never breaks ingestion

Lookups run on the background enrichment worker, after the event is already
persisted and broadcast. Providers must not raise: every failure mode comes back
as a stored, inspectable result row. With no provider configured, event
ingestion, rule detection, ML scoring, correlation and incidents all work
unchanged.

## RBAC

Reading a cached verdict is a **viewer** action (`threatintel:read`). Triggering
a lookup reaches outside the estate and spends metered quota — **analyst**
(`threatintel:enrich`), and it is audited with the caller's address.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `THREAT_INTEL_ENABLED` | `true` | Master switch. |
| `THREAT_INTEL_PROVIDER` | `none` | `none` or `virustotal`. |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Server-side only. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `6.0` | |
| `THREAT_INTEL_CACHE_TTL_HOURS` | `24` | Successful verdicts only. |
| `THREAT_INTEL_DAILY_BUDGET` | `400` | Per-process outbound ceiling. |
