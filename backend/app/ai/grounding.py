"""Grounding verification.

Telling a model "only use the supplied evidence" is necessary and not
sufficient. This module checks the answer against the package it was given and
records what does not line up.

What is checked:

* every MITRE technique cited must appear in the evidence's ``mitreContext``,
  and the provenance claimed for it must match what the platform recorded;
* every ``supportingEvidence`` entry must reference an identifier that actually
  exists in the package - an event id, a rule id, a sequence id, an indicator,
  a host, or an account;
* an answer claiming a threat-intelligence verdict when no actionable verdict
  is present is flagged;
* an answer claiming high confidence on an evidence package that the builder
  already judged insufficient is flagged.

A failed check does **not** discard the analysis. It is stored with
``grounded=False`` and the specific warnings attached, and the UI shows them
next to the text. Silently dropping the answer would hide the failure; silently
keeping it would hide the fabrication. Showing both is the only honest option.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.ai.evidence import EvidencePackage

TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class GroundingReport:
    grounded: bool = True
    warnings: list[str] = field(default_factory=list)
    #: Techniques the model cited that the evidence does not contain.
    unsupported_techniques: list[str] = field(default_factory=list)
    #: Evidence references that match nothing in the package.
    unresolved_references: list[str] = field(default_factory=list)

    def add(self, warning: str) -> None:
        self.warnings.append(warning)
        self.grounded = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "grounded": self.grounded,
            "warnings": self.warnings,
            "unsupportedTechniques": self.unsupported_techniques,
            "unresolvedReferences": self.unresolved_references,
        }


def _known_identifiers(package: EvidencePackage) -> set[str]:
    """Everything an answer is allowed to point at."""
    identifiers: set[str] = {package.incident.get("id", "")}

    for event in package.events:
        for key in ("id", "hostname", "username", "sourceIp", "destinationIp", "process"):
            value = event.get(key)
            if value:
                identifiers.add(str(value))

    identifiers.update(str(f.get("ruleId")) for f in package.rule_findings if f.get("ruleId"))
    identifiers.update(str(f.get("model")) for f in package.ml_findings if f.get("model"))
    identifiers.update(str(s.get("id")) for s in package.sequences if s.get("id"))
    identifiers.update(str(s.get("pattern")) for s in package.sequences if s.get("pattern"))
    identifiers.update(str(i.get("value")) for i in package.iocs if i.get("value"))
    identifiers.update(
        str(t.get("indicator")) for t in package.threat_intelligence if t.get("indicator")
    )
    identifiers.update(str(t.get("technique")) for t in package.mitre_context)
    identifiers.update(str(t.get("provider")) for t in package.threat_intelligence)

    return {value for value in identifiers if value}


def verify(analysis: dict[str, Any], package: EvidencePackage) -> GroundingReport:
    """Check one parsed analysis against the evidence it was given."""
    report = GroundingReport()

    known_techniques = {
        str(entry.get("technique")): str(entry.get("provenance", ""))
        for entry in package.mitre_context
    }
    identifiers = _known_identifiers(package)

    # --- MITRE techniques --------------------------------------------------
    cited: list[dict[str, Any]] = analysis.get("mitreTechniques") or []
    for entry in cited:
        if not isinstance(entry, dict):
            continue
        technique = str(entry.get("technique", "")).strip()
        if not technique:
            continue
        if technique not in known_techniques:
            report.unsupported_techniques.append(technique)
            report.add(
                f"{technique} is cited in the analysis but does not appear in the "
                "evidence package. It was not observed by any rule or correlation."
            )
            continue
        claimed = str(entry.get("provenance", "")).strip().lower()
        actual = known_techniques[technique].lower()
        if claimed and actual and claimed != actual:
            report.add(
                f"{technique} is described as '{claimed}' but the platform recorded it "
                f"as '{actual}'."
            )

    # Techniques mentioned only in prose still need to exist.
    prose = " ".join(
        str(analysis.get(field_name, ""))
        for field_name in ("summary", "whyItMatters", "riskAssessment", "likelyBehaviour")
    )
    for technique in set(TECHNIQUE_PATTERN.findall(prose)):
        if technique not in known_techniques and technique not in report.unsupported_techniques:
            report.unsupported_techniques.append(technique)
            report.add(
                f"{technique} is mentioned in the narrative but is not present in the "
                "evidence package."
            )

    # --- Evidence references ----------------------------------------------
    for entry in analysis.get("supportingEvidence") or []:
        if not isinstance(entry, dict):
            continue
        reference = str(entry.get("evidenceRef", "")).strip()
        if not reference:
            report.add("A supporting-evidence entry cites no identifier at all.")
            continue
        # Substring both ways: a model may cite "EVT-000042" against an
        # identifier stored as "EVT-000042", or a hostname inside a longer
        # phrase. Anything matching nothing is a fabricated citation.
        if not any(
            reference == known or reference in known or known in reference
            for known in identifiers
        ):
            report.unresolved_references.append(reference)
            report.add(
                f"Supporting evidence cites {reference!r}, which does not appear "
                "anywhere in the evidence package."
            )

    # --- Threat intelligence claims ---------------------------------------
    actionable_intel = [t for t in package.threat_intelligence if t.get("isActionable")]
    if not actionable_intel:
        lowered = prose.lower()
        if any(
            phrase in lowered
            for phrase in (
                "threat intelligence confirms",
                "threat intel confirms",
                "known malicious indicator",
                "flagged as malicious by",
                "reputation is malicious",
            )
        ):
            report.add(
                "The analysis claims an external threat-intelligence verdict, but no "
                "actionable verdict is present in the evidence."
            )

    # --- Confidence vs available evidence ---------------------------------
    confidence = str(analysis.get("confidence", "")).strip().lower()
    if confidence == "high" and not package.is_sufficient:
        report.add(
            "The analysis claims high confidence, but the evidence package contains "
            "no rule, ML, threat-intelligence or correlation findings to support it."
        )

    return report
