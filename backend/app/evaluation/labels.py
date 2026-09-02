"""Ground-truth labels for detection evaluation.

Every evaluation sample carries exactly one label. ``BENIGN`` means the sample
represents normal activity that should NOT raise a detection; every other label
names an attack technique class that should.

Labels are the ground truth. They are assigned when the sample is generated,
never inferred from what the detection engine did with it - otherwise the
measurement would be circular and meaningless.
"""

from __future__ import annotations

from enum import Enum


class Label(str, Enum):
    BENIGN = "BENIGN"

    BRUTE_FORCE = "BRUTE_FORCE"
    PORT_SCAN = "PORT_SCAN"
    SUSPICIOUS_POWERSHELL = "SUSPICIOUS_POWERSHELL"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    MALWARE = "MALWARE"
    SUSPICIOUS_DNS = "SUSPICIOUS_DNS"
    RANSOMWARE = "RANSOMWARE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    ANOMALOUS_SIGNIN = "ANOMALOUS_SIGNIN"
    LOLBIN_EXECUTION = "LOLBIN_EXECUTION"
    SUSPICIOUS_DOWNLOAD = "SUSPICIOUS_DOWNLOAD"

    # Deliberately included with NO corresponding rule. The V1 rule set cannot
    # see lateral movement, and the evaluation should say so out loud rather
    # than quietly excluding the class and reporting a flattering recall.
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"

    @property
    def is_malicious(self) -> bool:
        return self is not Label.BENIGN


MALICIOUS_LABELS = tuple(label for label in Label if label.is_malicious)
