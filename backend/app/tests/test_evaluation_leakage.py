"""Data-leakage defences for the V4 evaluation pipeline.

Every test here asserts something that, if it stopped being true, would make
every published AEGISX metric wrong while leaving the test suite green. They
are deliberately blunt and deliberately paranoid.

The failure modes being guarded:

* a label, or anything derived from one, becoming a feature
* a detection output (rule, risk score, severity) becoming an ML feature
* the same observation appearing in training and in test
* the final test set influencing threshold selection
* dataset bookkeeping (ids, provenance, split names) reaching a feature vector
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.evaluation.datasets.base import (
    DatasetProvenance,
    EvaluationDataset,
    EvaluationSample,
    LabelSchema,
)
from app.evaluation.splits import (
    SPLIT_NAMES,
    STRATIFIED_GROUP,
    TEMPORAL,
    SplitError,
    build_split,
)
from app.ml.features.extractor import FEATURE_NAMES, FeatureExtractor
from app.telemetry.base import RawTelemetry
from app.telemetry.normalizer import normalize
from app.models.enums import SourceType

BASE_TIME = datetime(2015, 1, 22, 12, 0, tzinfo=timezone.utc)


def _candidate(index: int, *, malicious: bool) -> dict:
    record = RawTelemetry(
        source="Perimeter Firewall",
        source_type=SourceType.FIREWALL,
        raw={
            "action": "allow",
            "src_ip": f"10.0.0.{index % 200 + 1}",
            "dst_ip": "203.0.113.10",
            "dst_port": 443 if not malicious else 4444,
            "protocol": "tcp",
            "bytes_out": 1000 + index,
            "rule": "observed-flow",
        },
        raw_log=f"[FLOW] tcp flow {index}",
        received_at=BASE_TIME + timedelta(seconds=index),
        is_synthetic=False,
    )
    return normalize(record)


def _dataset(*, samples: int = 240, duplicate_every: int = 4) -> EvaluationDataset:
    """A dataset with deliberate exact duplicates, mirroring UNSW-NB15."""
    built: list[EvaluationSample] = []
    for index in range(samples):
        # Every `duplicate_every`-th sample repeats the previous group key, so
        # the split has something real to keep together. The label is a property
        # of the group, because duplicates of one observation share its answer.
        group_index = index // duplicate_every
        malicious = group_index % 5 == 0
        group = f"grp-{group_index}"
        built.append(
            EvaluationSample(
                id=f"S-{index:05d}",
                category="attack" if malicious else "benign",
                is_malicious=malicious,
                candidate=_candidate(index, malicious=malicious),
                timestamp=BASE_TIME + timedelta(seconds=index),
                group_key=group,
                original_label="Attack" if malicious else "",
            )
        )
    return EvaluationDataset(
        name="leakage-fixture",
        version="1.0",
        provenance=DatasetProvenance(
            source="test", license="n/a", citation="n/a", description="fixture"
        ),
        label_schema=LabelSchema(
            name="fixture",
            version="1.0",
            mapping={"": "benign", "Attack": "attack"},
            malicious_categories=("attack",),
            benign_category="benign",
        ),
        samples=built,
    )


# --------------------------------------------------------------- group safety


@pytest.mark.parametrize("strategy", [STRATIFIED_GROUP, TEMPORAL])
def test_no_sample_appears_in_two_splits(strategy: str) -> None:
    plan = build_split(_dataset(), strategy=strategy)
    seen: set[str] = set()
    for name in SPLIT_NAMES:
        ids = {sample.id for sample in plan.splits()[name].samples}
        assert not (ids & seen), f"{strategy}: samples in two splits: {sorted(ids & seen)[:5]}"
        seen |= ids
    assert len(seen) == len(_dataset()), "splits must partition the dataset, losing nothing"


@pytest.mark.parametrize("strategy", [STRATIFIED_GROUP, TEMPORAL])
def test_duplicate_groups_never_cross_a_split_boundary(strategy: str) -> None:
    """The single most important guard: a memorised row must not reach test."""
    plan = build_split(_dataset(), strategy=strategy)
    owner: dict[str, str] = {}
    for name in SPLIT_NAMES:
        for sample in plan.splits()[name].samples:
            previous = owner.setdefault(sample.grouping, name)
            assert previous == name, (
                f"{strategy}: group {sample.grouping} spans {previous} and {name}"
            )


def test_conflicting_labels_inside_a_group_are_refused() -> None:
    dataset = _dataset(samples=40, duplicate_every=4)
    dataset.samples[1].category = "attack"
    dataset.samples[1].is_malicious = True
    dataset.samples[0].category = "benign"
    dataset.samples[0].is_malicious = False
    with pytest.raises(SplitError, match="conflicting labels"):
        build_split(dataset, strategy=STRATIFIED_GROUP)


# ----------------------------------------------------------- reproducibility


@pytest.mark.parametrize("strategy", [STRATIFIED_GROUP, TEMPORAL])
def test_splits_are_reproducible(strategy: str) -> None:
    first = build_split(_dataset(), strategy=strategy, seed=99)
    second = build_split(_dataset(), strategy=strategy, seed=99)
    assert first.fingerprint() == second.fingerprint()


def test_a_different_seed_produces_a_different_random_split() -> None:
    first = build_split(_dataset(), strategy=STRATIFIED_GROUP, seed=1)
    second = build_split(_dataset(), strategy=STRATIFIED_GROUP, seed=2)
    assert first.fingerprint() != second.fingerprint()


def test_temporal_split_ignores_the_seed() -> None:
    """Chronology is not random; a seed must not silently change it."""
    first = build_split(_dataset(), strategy=TEMPORAL, seed=1)
    second = build_split(_dataset(), strategy=TEMPORAL, seed=2)
    assert first.fingerprint() == second.fingerprint()


def test_temporal_split_puts_the_past_in_train() -> None:
    plan = build_split(_dataset(), strategy=TEMPORAL)
    train_end = plan.train.time_range()[1]
    test_start = plan.test.time_range()[0]
    assert train_end is not None and test_start is not None
    assert train_end <= test_start, "test must not begin before training ends"


# ------------------------------------------------------------ feature safety


def test_no_feature_is_named_after_a_detection_output() -> None:
    """ML must stay independent of the rules it complements.

    V3 asserts this for the rule vocabulary. V4 extends it to the evaluation
    vocabulary, because a leaked label is the one bug that makes every number
    look excellent.
    """
    # V3's set (detection outputs) plus V4's (ground truth and bookkeeping).
    forbidden = (
        "rule",
        "detection",
        "severity",
        "risk",
        "mitre",
        "label",
        "ground_truth",
        "groundtruth",
        "target",
        "is_malicious",
        "attack_cat",
        "split",
        "dataset",
    )
    for name in FEATURE_NAMES:
        lowered = name.lower()
        for token in forbidden:
            assert token not in lowered, f"feature {name!r} contains forbidden token {token!r}"

    # `class_*` features are deliberately allowed: they one-hot the *event
    # class* the sensor reported (authentication, process, dns...), which is an
    # observable available at inference time, not the ground-truth answer. The
    # distinction matters enough to assert it rather than leave it implied.
    assert any(name.startswith("class_") for name in FEATURE_NAMES)


def test_features_do_not_change_when_the_label_changes() -> None:
    """The strongest form of the claim: the label is not an input.

    Two samples identical in every observable respect but opposite in label must
    produce identical feature vectors. If they do not, something about the
    ground truth is reaching the extractor.
    """
    candidate = _candidate(7, malicious=False)

    benign = dict(candidate)
    malicious = dict(candidate)
    # Attach the label everywhere a careless implementation might put it.
    malicious["label"] = "malicious"
    malicious["category"] = "exploits"
    malicious["is_malicious"] = True
    malicious["normalized_data"] = dict(malicious["normalized_data"])
    malicious["normalized_data"]["attack_cat"] = "exploits"
    malicious["normalized_data"]["label"] = 1

    left = FeatureExtractor().extract(benign, observe=False)
    right = FeatureExtractor().extract(malicious, observe=False)
    assert left.values == right.values


def test_features_do_not_change_when_a_detection_result_is_attached() -> None:
    """Rule output must not become an ML input, even if a caller attaches it."""
    candidate = _candidate(11, malicious=True)

    plain = dict(candidate)
    detected = dict(candidate)
    detected["detections"] = [{"ruleId": "R-EXFIL", "severity": "Critical"}]
    detected["detection_rules"] = ["R-EXFIL"]
    detected["risk_score"] = 95
    detected["risk_level"] = "Critical"
    detected["severity"] = "Critical"
    detected["mitre_techniques"] = ["T1048"]

    left = FeatureExtractor().extract(plain, observe=False)
    right = FeatureExtractor().extract(detected, observe=False)
    # `severity` is a normalizer output, not a detection output, and the
    # extractor is entitled to read it. Everything else must be inert.
    detected["severity"] = plain["severity"]
    right_without_severity = FeatureExtractor().extract(detected, observe=False)
    assert left.values == right_without_severity.values, (
        "attaching detection results changed the feature vector"
    )
    assert left.values == right.values or right.values != right_without_severity.values


def test_dataset_bookkeeping_cannot_reach_a_feature() -> None:
    """Ids, provenance and split names are not observations."""
    candidate = _candidate(3, malicious=False)
    polluted = dict(candidate)
    polluted["id"] = "S-00003"
    polluted["sample_id"] = "S-00003"
    polluted["group_key"] = "grp-0"
    polluted["split"] = "test"
    polluted["dataset"] = "unsw-nb15"
    polluted["original_label"] = "Exploits"

    assert (
        FeatureExtractor().extract(candidate, observe=False).values
        == FeatureExtractor().extract(polluted, observe=False).values
    )


def test_unsw_adapter_does_not_forward_engineered_features() -> None:
    """The dataset's own 40+ features must stop at the adapter boundary.

    If they reached the candidate, AEGISX's ML numbers would silently become
    measurements of UNSW's feature engineering instead of its own.
    """
    from app.evaluation.datasets.unsw_nb15 import adapter

    row = {
        "srcip": "59.166.0.1",
        "sport": "1024",
        "dstip": "149.171.126.6",
        "dsport": "53",
        "proto": "udp",
        "state": "CON",
        "service": "dns",
        "dur": 0.001,
        "sbytes": 132,
        "dbytes": 164,
        "Spkts": 2,
        "Dpkts": 2,
        "Stime": 1421927377,
        "attack_cat": None,
        "label": 0,
        # Engineered columns that must not survive the adapter.
        "ct_state_ttl": 7,
        "ct_srv_src": 3,
        "sttl": 31,
        "Sload": 528000.0,
        "is_ftp_login": 1,
    }
    sample = adapter.to_sample(row, index=0, category="benign", is_malicious=False)
    flattened = repr(sample.candidate)
    for column in ("ct_state_ttl", "ct_srv_src", "sttl", "Sload", "is_ftp_login"):
        assert column not in flattened, f"{column} leaked into the normalized candidate"


def test_unsw_adapter_never_manufactures_a_policy_decision() -> None:
    """A TCP reset is not a firewall deny, and must not become one."""
    from app.evaluation.datasets.unsw_nb15 import adapter

    for state in ("RST", "INT", "FIN", "CON", "REQ"):
        row = {
            "srcip": "59.166.0.1",
            "sport": "1024",
            "dstip": "149.171.126.6",
            "dsport": "80",
            "proto": "tcp",
            "state": state,
            "service": "http",
            "dur": 0.5,
            "sbytes": 500,
            "dbytes": 500,
            "Spkts": 5,
            "Dpkts": 5,
            "Stime": 1421927377,
            "attack_cat": " Fuzzers ",
            "label": 1,
        }
        sample = adapter.to_sample(row, index=0, category="fuzzers", is_malicious=True)
        assert sample.candidate["event_type"] == "firewall_allow"
        assert sample.candidate["normalized_data"]["action"] == "allow"
        assert "deny_count" not in sample.candidate["normalized_data"]
        assert "distinct_ports" not in sample.candidate["normalized_data"]


def test_group_key_excludes_the_label() -> None:
    """Grouping must be decided by the observation, never by its answer."""
    from app.evaluation.datasets.unsw_nb15 import adapter

    base = {
        "srcip": "59.166.0.1",
        "sport": "1024",
        "dstip": "149.171.126.6",
        "dsport": "53",
        "proto": "udp",
        "state": "CON",
        "service": "dns",
        "dur": 0.001,
        "sbytes": 132,
        "dbytes": 164,
        "Spkts": 2,
        "Dpkts": 2,
        "Stime": 1421927377,
    }
    benign = dict(base, attack_cat=None, label=0)
    malicious = dict(base, attack_cat="Generic", label=1)
    assert adapter.group_key(benign) == adapter.group_key(malicious)
