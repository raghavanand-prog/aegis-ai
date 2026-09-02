# Detection Engine

AEGISX detects with **hand-written, deterministic rules**. There is no machine
learning anywhere in V1 or V2: no model, no training, no inference. Anything in
the product that sounds like it might be a model (the "Derived Insights" panel)
is arithmetic over stored aggregates and labels itself as such.

That is a design decision, not a limitation to hide. Deterministic rules are
explainable by construction, cheap to evaluate, and - most importantly - they
give the honest baseline that any future model has to beat.

## Pipeline

```
raw vendor record
      │
      ▼
normalizer            canonical event: entities, event_type, base severity
      │
      ▼
rule engine           every rule is offered the candidate
      │
      ▼
DetectionResult       severity, risk score, MITRE techniques, explanations
      │
      ▼
event row             detection_rules (ids) + detections (full explanations)
```

The engine reads only fields a real collector would populate, so the same rules
run unchanged against synthetic telemetry, the labelled evaluation dataset, and
a future real source.

## Rule identity and versioning

Every rule has a stable id and a semantic version:

```
DET-PS-001  version 1.0  "Suspicious PowerShell"
```

* **Ids are permanent.** A rule id is never reused for different logic.
* **Behaviour changes bump the version.** If the condition, severity or risk
  weight changes, the version changes with it.
* **Stored detections carry both**, so an event from six months ago still says
  which version of which rule produced it.
* **`legacyId` maps back to V1.** The V1 ids (`AEGIS-R001`…`R012`) are retained
  on each rule and exposed in the API, so detections written before the V2
  rename remain interpretable.

The rule catalogue is served at `GET /api/v1/detection/rules` and includes a
`rulesetFingerprint` - a hash over every rule's id, version, severity, risk and
techniques. Evaluation reports record the fingerprint they measured, so a
report produced by a different ruleset is flagged as stale instead of quietly
compared.

## The rules

| Id | Ver | Name | Severity | Risk | MITRE | Targets |
| --- | --- | --- | --- | --- | --- | --- |
| DET-AUTH-001 | 1.0 | Credential brute force | High | 45 | T1110 | BRUTE_FORCE |
| DET-AUTH-002 | 1.0 | Anomalous sign-in | High | 45 | T1078 | ANOMALOUS_SIGNIN |
| DET-CRED-001 | 1.0 | Credential dumping | Critical | 80 | T1003.001 | CREDENTIAL_ACCESS |
| DET-DNS-001 | 1.0 | Suspicious DNS beaconing | High | 50 | T1071.004 | SUSPICIOUS_DNS |
| DET-EXEC-001 | 1.0 | Remote payload download | Medium | 30 | T1105 | SUSPICIOUS_DOWNLOAD |
| DET-EXEC-002 | 1.0 | Living-off-the-land binary | Medium | 30 | T1218 | LOLBIN_EXECUTION |
| DET-EXFIL-001 | 1.0 | Large outbound transfer | Critical | 70 | T1041 | DATA_EXFILTRATION |
| DET-MAL-001 | 1.0 | Malware detected | High | 55 | T1204.002 | MALWARE |
| DET-NET-001 | 1.0 | Network reconnaissance | Medium | 35 | T1046 | PORT_SCAN |
| DET-PRIV-001 | 1.0 | Privilege escalation | High | 55 | T1548 | PRIVILEGE_ESCALATION |
| DET-PS-001 | 1.0 | Suspicious PowerShell | High | 50 | T1059.001, T1027 | SUSPICIOUS_POWERSHELL |
| DET-RANSOM-001 | 1.0 | Ransomware behaviour | Critical | 90 | T1486 | RANSOMWARE |

Thresholds live in `app/detection/rules.py` as named constants
(`BRUTE_FORCE_MIN_FAILURES = 5`, `PORT_SCAN_MIN_PORTS = 20`,
`RANSOMWARE_MIN_FILES = 200`, `EXFIL_MIN_BYTES = 500_000_000`, …) so the rules,
the documentation and the evaluation dataset all reference the same numbers.

## Scoring

* **Severity** is the highest severity among matching rules, never lower than
  the severity the normalizer assigned.
* **Risk score** is the sum of each matching rule's risk contribution, capped at
  100. It is a triage aid, not a probability - nothing here is calibrated.
* **Severity a client submits is advisory.** `POST /events` accepts a severity
  field, but the engine's verdict is what gets stored: an ingesting collector
  does not get to decide how serious its own event is.

## Explainability

Every match produces a `Detection`, stored on the event and returned by the API:

```json
{
  "ruleId": "DET-CRED-001",
  "ruleVersion": "1.0",
  "ruleName": "Credential dumping",
  "reason": "procdump64.exe opened LSASS memory with access mask 0x1010 - the standard step for stealing credentials",
  "severity": "Critical",
  "riskContribution": 80,
  "mitreTechniques": ["T1003.001"],
  "matchedAt": "2026-09-02T03:29:00Z"
}
```

The reason is produced by the matcher itself and quotes the values that
triggered it (the failure count, the process, the byte volume). An analyst
should never have to read rule source to understand an alert; the event drawer
in the console renders these directly.

## Failure behaviour

A rule that raises is skipped and the remaining rules still run. Losing an
event because one matcher has a bug is worse than missing one detection, and
`test_a_broken_rule_cannot_drop_telemetry` keeps that true.

## Known weaknesses (measured, not guessed)

* **No lateral movement coverage.** No rule targets remote-execution tooling.
  The evaluation dataset includes a `LATERAL_MOVEMENT` class specifically so
  this gap shows up as false negatives rather than being quietly excluded.
* **DET-EXEC-002 fires on process name alone**, so an administrator running
  `certutil` legitimately is a false positive. Measured rule precision is around
  70%. This has deliberately **not** been "fixed" by adding conditions: V2's job
  was to measure the rules, and tuning them is a V3 change made with evidence
  and a version bump, not a reflex.
* **Rules are single-event.** Nothing correlates across events, so a slow
  campaign that never crosses a per-event threshold is invisible. Correlation is
  V3 work.

See [EVALUATION.md](EVALUATION.md) for how these statements are measured.
