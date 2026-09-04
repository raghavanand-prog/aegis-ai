"""A behavioural fingerprint of the normalizer, taken before it was refactored.

V7 Phase 4 moved every vendor mapper out of ``telemetry/normalizer.py`` into
per-source adapters behind a registry. That refactor touches the code path every
event in the system passes through, and the four years of measured results in
``docs/`` all rest on what it produces.

So this test does not check that normalization is *correct* - other tests do
that, and ``test_normalizer_regression.py`` holds the defects worth naming. It
checks that the refactor changed **nothing**, by hashing the full canonical
output of a seeded corpus across every registered source and pinning the digest.

If this fails after a change to the adapters, the change altered what the
detection engine sees. That may be intended, but it is never incidental: update
the digest deliberately, in a commit that says which field moved and why.

The digest was recorded at ``b7fa9cc`` (the V6 checkpoint) before any V7 code
existed.
"""

from __future__ import annotations

import hashlib
import json

from app.models.enums import SourceType
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

#: Every source with a dedicated mapper, and one representative raw record each.
#: Hand-written rather than generated so the fixture states the vendor shape
#: explicitly - a generated one would drift with the generator.
VENDOR_RECORDS: tuple[tuple[str, SourceType, dict], ...] = (
    (
        "Microsoft Defender",
        SourceType.ENDPOINT,
        {
            "ActionType": "AntivirusDetection",
            "ThreatName": "Trojan:Win32/Emotet",
            "FileName": "invoice_4821.exe",
            "DeviceName": "SYN-WIN-004",
            "AccountName": "j.smith",
            "InitiatingProcessFileName": "outlook.exe",
            "SHA256": "a" * 64,
            "RemediationAction": "Quarantined",
            "Severity": "High",
        },
    ),
    (
        "Microsoft Defender",
        SourceType.ENDPOINT,
        {
            "ActionType": "ScanCompleted",
            "ScanType": "Quick",
            "DeviceName": "SYN-WIN-004",
            "FilesScanned": 20481,
            "ThreatsFound": 0,
        },
    ),
    (
        "Sysmon",
        SourceType.ENDPOINT,
        {
            "EventID": 10,
            "Computer": "SYN-WIN-002",
            "User": "svc.sql",
            "SourceImage": "C:\\Windows\\Temp\\mimi.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1410",
        },
    ),
    (
        "Sysmon",
        SourceType.ENDPOINT,
        {
            "EventID": 1,
            "Computer": "SYN-WIN-002",
            "User": "j.smith",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -enc " + "Q" * 64,
            "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
            "ProcessId": 4242,
        },
    ),
    (
        "Entra ID",
        SourceType.IDENTITY,
        {
            "userPrincipalName": "a.jones@aegisx.dev",
            "ipAddress": "203.0.113.44",
            "impossibleTravel": True,
            "riskEventType": "impossibleTravel",
            "riskLevelDuringSignIn": "high",
            "location": {"countryOrRegion": "RU"},
            "previousLocation": {"countryOrRegion": "GB"},
        },
    ),
    (
        "Entra ID",
        SourceType.IDENTITY,
        {
            "userPrincipalName": "a.jones@aegisx.dev",
            "ipAddress": "198.51.100.9",
            "resultType": "50126",
            "resultDescription": "Invalid username or password",
            "failureCount": 7,
            "location": {"countryOrRegion": "GB"},
        },
    ),
    (
        "Entra ID",
        SourceType.IDENTITY,
        {
            "userPrincipalName": "a.jones@aegisx.dev",
            "ipAddress": "10.10.20.15",
            "resultType": "0",
            "appDisplayName": "Office 365",
            "location": {"countryOrRegion": "GB"},
            "riskLevelDuringSignIn": "none",
        },
    ),
    (
        "Perimeter Firewall",
        SourceType.FIREWALL,
        {
            "action": "deny",
            "src_ip": "203.0.113.77",
            "dst_ip": "10.10.20.5",
            "dst_port": 3389,
            "protocol": "tcp",
            "deny_count": 412,
            "distinct_ports": 37,
            "rule": "DENY-INBOUND-RDP",
        },
    ),
    (
        "Perimeter Firewall",
        SourceType.FIREWALL,
        {
            "action": "allow",
            "src_ip": "10.10.20.31",
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_out": 18422,
            "rule": "ALLOW-OUTBOUND-HTTPS",
        },
    ),
    (
        "DNS Resolver",
        SourceType.DNS,
        {
            "query": "a1b2c3d4e5.cdn-metrics.io",
            "query_type": "A",
            "client_ip": "10.10.20.31",
            "resolved_ip": "198.51.100.200",
            "response_code": "NOERROR",
            "periodic": True,
            "query_count": 288,
            "interval_seconds": 300,
        },
    ),
    (
        "DNS Resolver",
        SourceType.DNS,
        {
            "query": "www.example.com",
            "query_type": "A",
            "client_ip": "10.10.20.31",
            "resolved_ip": "93.184.216.34",
            "response_code": "NOERROR",
            "periodic": False,
        },
    ),
    (
        "Linux Auditd",
        SourceType.OPERATING_SYSTEM,
        {
            "facility": "sudo",
            "user": "deploy",
            "host": "syn-lnx-001",
            "command": "/bin/bash -c 'cat /etc/shadow'",
            "privilege_change": True,
            "result": "success",
        },
    ),
    (
        "Linux Auditd",
        SourceType.OPERATING_SYSTEM,
        {
            "facility": "sshd",
            "user": "deploy",
            "host": "syn-lnx-001",
            "src_ip": "10.10.20.44",
            "auth_method": "publickey",
            "result": "accepted",
        },
    ),
    (
        "EDR Agent",
        SourceType.EDR,
        {
            "detection_name": "Ransom.Behaviour.MassEncrypt",
            "hostname": "SYN-WIN-007",
            "user": "j.smith",
            "process": "C:\\Users\\j.smith\\AppData\\locky.exe",
            "command_line": "locky.exe --run",
            "files_modified": 3184,
            "encryption_suspected": True,
            "tactic": "Impact",
            "technique": "T1486",
            "severity": "Critical",
        },
    ),
    (
        "EDR Agent",
        SourceType.EDR,
        {
            "detection_name": "Exfil.LargeTransfer",
            "hostname": "SYN-WIN-007",
            "user": "svc.backup",
            "process": "C:\\Program Files\\sync\\agent.exe",
            "dst_ip": "203.0.113.90",
            "bytes_out": 900_000_000,
            "encryption_suspected": False,
            "tactic": "Exfiltration",
            "technique": "T1041",
            "severity": "High",
        },
    ),
    (
        "EDR Agent",
        SourceType.EDR,
        {
            "detection_name": "FileActivity.BulkWrite",
            "hostname": "SYN-WIN-007",
            "user": "svc.backup",
            "process": "C:\\Program Files\\backup\\agent.exe",
            "files_modified": 150,
            "encryption_suspected": False,
            "tactic": "None",
            "severity": "Low",
        },
    ),
)

#: The sources that existed at b7fa9cc, when the digests below were taken.
V6_SOURCES: frozenset[str] = frozenset(
    {
        "Microsoft Defender",
        "Sysmon",
        "Entra ID",
        "Perimeter Firewall",
        "DNS Resolver",
        "Linux Auditd",
        "EDR Agent",
    }
)

#: Fields whose value is the wall clock or a pass-through of it. Excluded from
#: the digest because they are properties of when the test ran, not of the
#: mapping under test.
_VOLATILE = ("timestamp",)


def _stable(candidate: dict) -> dict:
    return {key: value for key, value in sorted(candidate.items()) if key not in _VOLATILE}


def _digest(candidates: list[dict]) -> str:
    payload = json.dumps(candidates, sort_keys=True, default=str).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def _normalize_all() -> list[dict]:
    return [
        _stable(
            normalize(
                RawTelemetry(
                    source=source,
                    source_type=source_type,
                    raw=raw,
                    raw_log=f"[{source}] characterization",
                    is_synthetic=True,
                )
            )
        )
        for source, source_type, raw in VENDOR_RECORDS
    ]


class TestTheCanonicalOutputIsUnchanged:
    #: Recorded at b7fa9cc, before any V7 code existed. See the module docstring
    #: before changing it.
    EXPECTED_DIGEST = "d5886cabbbef7ca5"

    def test_every_vendor_record_still_normalizes_identically(self) -> None:
        assert _digest(_normalize_all()) == self.EXPECTED_DIGEST

    def test_the_fixture_covers_every_source_that_existed_at_v6(self) -> None:
        """A digest over a subset would let an unexercised mapper change freely.

        Scoped to the sources that existed when the digest was taken. Sources
        added after it - CloudTrail is the first - have no pre-refactor output
        to be unchanged from, and folding them in would mean recomputing the
        digest every time a source is added, which is exactly how a
        characterization test stops characterizing anything.
        """
        from app.telemetry.normalizer import NORMALIZERS

        covered = {source for source, _, _ in VENDOR_RECORDS}
        assert covered == V6_SOURCES
        assert covered <= set(NORMALIZERS), "a V6 source lost its adapter"


class TestASeededCorpusIsUnchanged:
    """The generator path, as distinct from the hand-written fixtures.

    ``SyntheticTelemetrySource`` is the source every V3-V6 result was produced
    from, and a seeded run of it is reproducible by construction. This pins the
    whole pipeline from generation through normalization.
    """

    EXPECTED_DIGEST = "ed9298988568bf3f"

    def test_a_seeded_batch_normalizes_identically(self) -> None:
        source = SyntheticTelemetrySource(seed=1337)
        candidates = [_stable(normalize(record)) for record in source.collect(120)]

        assert len(candidates) == 120
        assert _digest(candidates) == self.EXPECTED_DIGEST
