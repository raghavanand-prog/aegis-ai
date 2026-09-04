"""A labelled corpus drawn from the distribution production actually fits.

**The problem this exists to fix.** V6 §4 measured that the labelled evaluation
corpus's fit split is **40% malicious**, and its own provenance says it is *"out
of distribution for the anomaly model trained on the runtime telemetry
generator"*. It was built to exercise **rule thresholds** and was then pressed
into service as ML training data. Fitting an Isolation Forest there produced the
near-inert static baseline that V4 and V5 measured every adaptation gain
against - a comparator §5 showed was wrong by roughly 17x.

This corpus is drawn from the **runtime telemetry generator**, the one
``train_anomaly_model`` actually fits, and is labelled from that generator's own
scenario intent.

**The labelling is the substance, so it is explicit and justified per scenario.**
``SCENARIO_LABELS`` is exhaustive over the generator's scenario list and a test
fails if the two diverge, so a scenario added later cannot silently default to
benign and quietly deflate the malicious rate of every future corpus.

**Rare is not malicious.** Four scenarios exist specifically to be anomalous
*without* being attacks - the generator calls ``_sysmon_rare_process`` "simply
rare... not a LOLBin, not encoded, downloads nothing" and ``_dns_rare_domain``
"deliberately not a DGA label... merely unfamiliar". Labelling those malicious
would fabricate ground truth in precisely the direction that flatters an anomaly
detector, by rewarding it for flagging ordinary novelty. They are benign here,
which makes this corpus **harder** than the one it replaces: a density model will
flag them and be charged a false positive for it, exactly as a real SOC would
experience.

**Labels come from the generator, never from a detector.** No rule output, no
model score and no analyst verdict participates, so the measurement is not
circular.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
    LabelSchema,
)
from app.telemetry.normalizer import NormalizationError, normalize
from app.telemetry.sources.synthetic import SyntheticTelemetrySource

DATASET_NAME = "aegisx-telemetry-labelled"
DATASET_VERSION = "1.0"

#: Matches the training corpus builder, so a model fitted on that distribution
#: meets the same temporal structure here.
DEFAULT_SPAN_DAYS = 14
_HOUR_WEIGHTS = [
    1, 1, 1, 1, 1, 2, 4, 8, 14, 18, 20, 20, 18, 19, 20, 18, 14, 10, 7, 5, 4, 3, 2, 1,
]

#: Below this a split cannot hold enough of each class to mean anything.
MINIMUM_SAMPLES = 200

#: Default prevalence of the built corpus.
#:
#: **This is a design parameter, not an observed base rate.** The generator is
#: attack-heavy by design - measured at 42.7% malicious, which is *worse* than
#: the 40% rule-testing corpus this was built to improve on, because a demo
#: generator that emitted 1% attacks would show nothing. Inheriting that mix
#: would reproduce the very problem V6 §4 identified.
#:
#: 0.10 is chosen as a plausible SOC-like prevalence and sits in the region
#: where §4.2 measured the detector performing well (ROC-AUC 0.90 at 12%, 0.93
#: at 8%). It is stated on every corpus so a reader cannot mistake it for a
#: measured base rate.
DEFAULT_MALICIOUS_RATE = 0.10


class Label(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


#: Exhaustive over ``SyntheticTelemetrySource.SCENARIOS``. Asserted by test.
SCENARIO_LABELS: dict[str, Label] = {
    # --- ordinary traffic ------------------------------------------------
    "_defender_benign_scan": Label.BENIGN,
    "_sysmon_process": Label.BENIGN,
    "_entra_signin_success": Label.BENIGN,
    "_firewall_allow": Label.BENIGN,
    "_dns_query": Label.BENIGN,
    "_linux_ssh": Label.BENIGN,
    # --- unusual, but the generator states they are not attacks ----------
    "_sysmon_rare_process": Label.BENIGN,
    "_firewall_unusual_port": Label.BENIGN,
    "_dns_rare_domain": Label.BENIGN,
    "_entra_rare_source": Label.BENIGN,
    # --- named attacks ---------------------------------------------------
    "_defender_malware": Label.MALICIOUS,
    "_sysmon_encoded_powershell": Label.MALICIOUS,
    "_sysmon_lsass_access": Label.MALICIOUS,
    "_entra_failed_logins": Label.MALICIOUS,
    "_entra_impossible_travel": Label.MALICIOUS,
    "_firewall_port_scan": Label.MALICIOUS,
    "_dns_beaconing": Label.MALICIOUS,
    "_linux_sudo_abuse": Label.MALICIOUS,
    "_edr_ransomware": Label.MALICIOUS,
    "_edr_exfiltration": Label.MALICIOUS,
    # --- multi-record campaigns ------------------------------------------
    "_campaign_credential_attack": Label.MALICIOUS,
    "_campaign_lateral_movement": Label.MALICIOUS,
    "_campaign_host_intrusion": Label.MALICIOUS,
}

#: Why each label is what it is. A label map without stated reasons is an
#: assertion, and these decide what every number on this corpus means.
LABEL_RATIONALE: dict[str, str] = {
    "_defender_benign_scan": "A completed antivirus scan. Routine endpoint hygiene.",
    "_sysmon_process": "Ordinary process creation from the common process set.",
    "_entra_signin_success": "A successful interactive sign-in.",
    "_firewall_allow": "Permitted traffic on expected ports.",
    "_dns_query": "Resolution of a domain already common in this environment.",
    "_linux_ssh": "An accepted SSH session by a known user.",
    "_sysmon_rare_process": (
        "BENIGN by the generator's own statement: 'simply rare', not a LOLBin, "
        "not encoded, downloads nothing. Rarity is not malice, and scoring it "
        "malicious would reward an anomaly model for flagging novelty."
    ),
    "_firewall_unusual_port": (
        "BENIGN. An uncommon destination port with no attack behaviour attached; "
        "one of the four scenarios written so the anomaly model has something to "
        "find that the rules cannot."
    ),
    "_dns_rare_domain": (
        "BENIGN by the generator's own statement: 'deliberately not a DGA "
        "label... a plausible-looking name that is merely unfamiliar'."
    ),
    "_entra_rare_source": (
        "BENIGN. A sign-in from an address not seen before, without the "
        "impossible-travel geometry that makes the malicious variant an attack."
    ),
    "_defender_malware": "An antivirus malware detection with a named threat.",
    "_sysmon_encoded_powershell": "Base64-encoded PowerShell: an execution technique.",
    "_sysmon_lsass_access": "LSASS memory access, a credential-theft technique.",
    "_entra_failed_logins": (
        "MALICIOUS. Five to sixty failed authentications from an external "
        "address carrying a medium sign-in risk - a brute-force attempt, and the "
        "same behaviour the labelled corpus categorises as BRUTE_FORCE. This is "
        "the least clear-cut label in the map and is called out as such."
    ),
    "_entra_impossible_travel": "Two sign-ins geographically impossible to reconcile.",
    "_firewall_port_scan": "Sequential connection attempts across many ports.",
    "_dns_beaconing": "Periodic resolution of algorithmically generated labels.",
    "_linux_sudo_abuse": "Privilege escalation through sudo misuse.",
    "_edr_ransomware": "EDR detection of mass file encryption behaviour.",
    "_edr_exfiltration": "EDR detection of a large outbound transfer.",
    "_campaign_credential_attack": "Repeated failures then a success from one address.",
    "_campaign_lateral_movement": "Related activity moving between hosts.",
    "_campaign_host_intrusion": "Multi-stage activity against a single host.",
}

TELEMETRY_LABEL_SCHEMA = LabelSchema(
    name="aegisx-telemetry-labels",
    version="1.0",
    mapping={scenario: label.value for scenario, label in SCENARIO_LABELS.items()},
    malicious_categories=tuple(
        scenario
        for scenario, label in SCENARIO_LABELS.items()
        if label is Label.MALICIOUS
    ),
    benign_category=Label.BENIGN.value,
    excluded={},
    notes=(
        "Labels come from the generator's scenario, assigned before any detector "
        "sees the record. No rule output, model score or analyst verdict "
        "participates, so the measurement is not circular.",
        "The four 'rare but ordinary' scenarios are labelled BENIGN on the "
        "generator's own statement that they are not attacks. This makes the "
        "corpus harder than the labelled rule-testing corpus it complements: an "
        "anomaly model will flag them and be charged a false positive.",
        "_entra_failed_logins is the least clear-cut label in the map. It is "
        "malicious here; a reader who disagrees should re-run with it flipped "
        "rather than discount the corpus.",
        "Synthetic. Nothing here is evidence about real-world attack traffic.",
    ),
)


def _timestamps(count: int, *, span_days: int, rng) -> list[datetime]:
    """Deterministic timestamps across a span, weighted to business hours.

    The generator stamps everything "now", which leaves every temporal feature
    constant. The training corpus builder solves this the same way, and matching
    it is what keeps this corpus in that distribution.
    """
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    stamps = []
    for index in range(count):
        day = int(index * span_days / max(count, 1))
        hour = rng.choices(range(24), weights=_HOUR_WEIGHTS, k=1)[0]
        stamps.append(
            start
            + timedelta(
                days=day,
                hours=hour,
                minutes=rng.randrange(60),
                seconds=rng.randrange(60),
            )
        )
    return stamps


def telemetry_labelled_dataset(
    *,
    seed: int = 1337,
    samples: int = 6000,
    span_days: int = DEFAULT_SPAN_DAYS,
    malicious_rate: float | None = DEFAULT_MALICIOUS_RATE,
) -> EvaluationDataset:
    """Build the corpus. Labels come from the scenario, never from a detector.

    ``malicious_rate`` sets prevalence explicitly. Pass ``None`` to keep the
    generator's own mix, which is attack-heavy - useful for measuring that fact,
    not for fitting a density model.
    """
    if samples < MINIMUM_SAMPLES:
        raise ValueError(
            f"{samples} samples is too small; a split needs at least "
            f"{MINIMUM_SAMPLES} to hold enough of each class to mean anything"
        )

    if malicious_rate is not None and not 0.0 < malicious_rate < 1.0:
        raise ValueError(
            f"malicious_rate must lie in (0, 1); got {malicious_rate}"
        )

    import random

    source = SyntheticTelemetrySource(seed=seed)
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not secrecy

    # Over-collect so resampling to a target prevalence has both classes to
    # draw from. The generator is cheap; a corpus that silently fell short of
    # its requested rate would not be.
    harvest = samples if malicious_rate is None else samples * 6
    pool: list[tuple[str, Any]] = []
    while len(pool) < harvest:
        for raw in source.collect(1):
            pool.append((raw.scenario, raw))
            if len(pool) >= harvest:
                break

    if malicious_rate is None:
        collected = pool[:samples]
    else:
        malicious = [row for row in pool if SCENARIO_LABELS[row[0]] is Label.MALICIOUS]
        benign = [row for row in pool if SCENARIO_LABELS[row[0]] is Label.BENIGN]
        wanted_malicious = round(samples * malicious_rate)
        wanted_benign = samples - wanted_malicious
        # Defensive: 6x over-collection makes this unreachable for any sane
        # request, and it is deliberately not covered by a test that would have
        # to generate hundreds of thousands of records to trip it. Refusing
        # still beats silently returning a corpus whose prevalence is not the
        # one that was asked for.
        if wanted_malicious > len(malicious) or wanted_benign > len(benign):
            raise ValueError(
                f"the generator cannot supply {wanted_benign} benign and "
                f"{wanted_malicious} malicious records at {samples} samples; it "
                f"produced {len(benign)} and {len(malicious)}"
            )
        collected = rng.sample(benign, wanted_benign) + rng.sample(
            malicious, wanted_malicious
        )
        # Interleave, so the chronological stamps below do not put every attack
        # at the end of the span.
        rng.shuffle(collected)

    stamps = _timestamps(len(collected), span_days=span_days, rng=rng)

    evaluation_samples: list[EvaluationSample] = []
    skipped = 0
    for index, ((scenario, raw), stamp) in enumerate(zip(collected, stamps, strict=True)):
        try:
            candidate = normalize(raw)
        except NormalizationError:
            skipped += 1
            continue
        candidate["timestamp"] = stamp.isoformat()
        label = SCENARIO_LABELS[scenario]
        evaluation_samples.append(
            EvaluationSample(
                id=f"TEL-{index:06d}",
                category=scenario,
                is_malicious=label is Label.MALICIOUS,
                candidate=candidate,
                timestamp=candidate["timestamp"],
                group_key=None,
                original_label=scenario,
            )
        )

    provenance = DatasetProvenance(
        source="app.telemetry.sources.synthetic (generated in-process)",
        license="Part of AEGISX; no third-party terms apply.",
        citation="AEGISX labelled telemetry corpus, V6.",
        description=(
            "The runtime telemetry generator's own distribution, labelled from "
            "its scenario intent. Built because the V4/V5 labelled corpus is a "
            "rule-testing corpus whose fit split is 40% malicious and which its "
            "own provenance calls out of distribution for the anomaly model."
        ),
        file_digests={},
        notes=(
            "Synthetic. Nothing here is evidence about real attack traffic.",
            "This is the distribution train_anomaly_model fits, so a model "
            "fitted here is in-distribution for it - which the V4/V5 labelled "
            "corpus is not.",
            f"{skipped} records were dropped as unnormalizable.",
            (
                "Prevalence is a DESIGN PARAMETER of this corpus, not an "
                f"observed base rate: malicious_rate={malicious_rate}. The "
                "generator's own mix is 42.7% malicious - attack-heavy by "
                "design, and worse than the 40% rule-testing corpus this was "
                "built to improve on. Pass malicious_rate=None to measure that "
                "rather than to fit on it."
            ),
        ),
    )

    return EvaluationDataset(
        name=DATASET_NAME,
        version=DATASET_VERSION,
        provenance=provenance,
        label_schema=TELEMETRY_LABEL_SCHEMA,
        samples=evaluation_samples,
        sampling={
            "seed": seed,
            "requested": samples,
            "spanDays": span_days,
            "maliciousRate": malicious_rate,
            "labelMapDigest": label_map_digest(),
        },
    )


def label_map_digest() -> str:
    """Stable hash over the label decisions.

    A corpus fingerprint covers the data. This covers the *judgement*, so a
    result cannot be silently re-interpreted by editing a label.
    """
    digest = hashlib.sha256()
    for scenario in sorted(SCENARIO_LABELS):
        digest.update(scenario.encode())
        digest.update(b"\x00")
        digest.update(SCENARIO_LABELS[scenario].value.encode())
        digest.update(b"\x01")
    return digest.hexdigest()[:16]
