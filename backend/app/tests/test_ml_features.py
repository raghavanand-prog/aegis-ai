"""Feature extraction tests.

The properties these lock down are the ones that, if they break, produce a
model that scores confidently and means nothing:

* the vector's width and ordering ARE the schema;
* extraction is deterministic;
* no detection output leaks into a feature (which would make the ML signal a
  restatement of the rules);
* context is read before the event is folded into it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.ml.features import FEATURE_COUNT, FEATURE_NAMES, BehaviorContext, FeatureExtractor
from app.ml.features.extractor import _entropy, _is_internal, _log_scale
from app.ml.schemas import FEATURE_SCHEMA_VERSION

BASE_TIME = datetime(2026, 3, 2, 14, 30, tzinfo=timezone.utc)


def candidate(**overrides) -> dict:
    base = {
        "event_type": "auth_failure",
        "source": "Entra ID",
        "source_type": "identity",
        "title": "Sign-in failure",
        "hostname": "SYN-WIN-001",
        "username": "a.sharma",
        "source_ip": "203.0.113.10",
        "destination_ip": None,
        "destination_port": None,
        "process": None,
        "command_line": "",
        "raw_log": "[Entra] failure",
        "timestamp": BASE_TIME,
        "normalized_data": {"failure_count": 3},
    }
    base.update(overrides)
    return base


def test_vector_width_matches_the_declared_schema() -> None:
    vector = FeatureExtractor().extract(candidate())
    assert len(vector) == FEATURE_COUNT
    assert vector.names == FEATURE_NAMES
    assert vector.schema_version == FEATURE_SCHEMA_VERSION


def test_extraction_is_deterministic() -> None:
    first = FeatureExtractor().extract(candidate())
    second = FeatureExtractor().extract(candidate())
    assert first.values == second.values


def test_same_extractor_gives_the_same_answer_for_a_repeated_event() -> None:
    """A second identical event differs only through the context, never through
    randomness."""
    extractor = FeatureExtractor()
    first = extractor.extract(candidate(), observe=False)
    second = extractor.extract(candidate(), observe=False)
    assert first.values == second.values


def test_no_detection_output_is_a_feature() -> None:
    """Rule verdicts must not reach the model.

    If they did, the anomaly score would partly restate the rules and the
    'independent second signal' claim would be false.
    """
    forbidden = ("rule", "detection", "severity", "risk", "mitre")
    for name in FEATURE_NAMES:
        assert not any(word in name for word in forbidden), name


def test_context_is_read_before_the_event_is_recorded() -> None:
    """The first event for a host must not count itself."""
    extractor = FeatureExtractor()
    first = extractor.extract(candidate(), observe=True).as_dict()
    assert first["host_event_count_scaled"] == 0.0
    assert first["host_is_new"] == 1.0

    second = extractor.extract(candidate(), observe=True).as_dict()
    assert second["host_event_count_scaled"] > 0.0
    assert second["host_is_new"] == 0.0


def test_process_rarity_falls_as_a_process_becomes_routine() -> None:
    extractor = FeatureExtractor()
    scores = []
    for _ in range(5):
        vector = extractor.extract(
            candidate(event_type="process_creation", process="odbcconf.exe"), observe=True
        )
        scores.append(vector.as_dict()["process_rarity"])
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > scores[-1]


def test_off_hours_and_weekend_flags() -> None:
    night = FeatureExtractor().extract(
        candidate(timestamp=datetime(2026, 3, 2, 3, 0, tzinfo=timezone.utc))
    ).as_dict()
    assert night["is_off_hours"] == 1.0
    assert night["is_weekend"] == 0.0

    weekend = FeatureExtractor().extract(
        candidate(timestamp=datetime(2026, 3, 7, 12, 0, tzinfo=timezone.utc))
    ).as_dict()
    assert weekend["is_weekend"] == 1.0


def test_hour_is_encoded_as_a_circle() -> None:
    """23:00 and 00:00 must be neighbours, not opposites."""
    late = FeatureExtractor().extract(
        candidate(timestamp=datetime(2026, 3, 2, 23, 0, tzinfo=timezone.utc))
    ).as_dict()
    early = FeatureExtractor().extract(
        candidate(timestamp=datetime(2026, 3, 3, 0, 0, tzinfo=timezone.utc))
    ).as_dict()
    distance = abs(late["hour_sin"] - early["hour_sin"]) + abs(
        late["hour_cos"] - early["hour_cos"]
    )
    assert distance < 0.5


def test_internal_and_external_addresses_are_distinguished() -> None:
    assert _is_internal("10.0.0.5")
    assert _is_internal("192.168.1.1")
    assert _is_internal("172.16.0.1")
    assert _is_internal("198.51.100.7")
    assert not _is_internal("203.0.113.9")
    assert not _is_internal(None)


def test_entropy_is_bounded_and_ranks_by_character_variety() -> None:
    """Entropy measures character variety, and nothing more than that.

    Asserted explicitly because the tempting reading - "encoded payloads score
    high" - is false: UTF-16LE base64 is dense in repeated 'A' characters and
    scores LOW. Locking the real behaviour down stops someone later "fixing"
    the feature towards an intuition the maths does not support.
    """
    repetitive = _entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ordinary = _entropy("chrome.exe --profile-directory=Default")
    varied = _entropy("x7Qz!m2R#pL9$wF4^bN8&hJ1*kD6@sG3")

    assert repetitive < ordinary < varied
    for value in (repetitive, ordinary, varied):
        assert 0.0 <= value <= 1.0
    assert _entropy("") == 0.0


def test_log_scale_is_bounded_and_monotonic() -> None:
    assert _log_scale(0, 1000) == 0.0
    assert _log_scale(10**12, 1000) == 1.0
    assert _log_scale(10, 1000) < _log_scale(100, 1000)


def test_malformed_values_do_not_break_extraction() -> None:
    """A bad record must produce a vector, not an exception - dropping telemetry
    because one field is wrong is worse than one imperfect feature."""
    vector = FeatureExtractor().extract(
        {
            "event_type": None,
            "normalized_data": "not-a-dict",
            "destination_port": "not-a-port",
            "timestamp": "nonsense",
            "command_line": None,
        }
    )
    assert len(vector) == FEATURE_COUNT
    assert all(isinstance(value, float) for value in vector.values)


def test_unknown_event_type_lands_in_the_other_class() -> None:
    vector = FeatureExtractor().extract(
        candidate(event_type="something_new_entirely")
    ).as_dict()
    assert vector["class_other"] == 1.0
    assert vector["class_authentication"] == 0.0


# ------------------------------------------------------------------- context
def test_context_window_expires_old_observations() -> None:
    context = BehaviorContext(window_minutes=10)
    old = BASE_TIME - timedelta(hours=2)
    context.observe("host", "SYN-WIN-001", timestamp=old)
    snapshot = context.snapshot("host", "SYN-WIN-001", BASE_TIME)
    assert snapshot["count"] == 0
    # Still remembered as previously seen: "not new" outlives the window.
    assert snapshot["is_new"] == 0.0


def test_context_tracks_distinct_companions() -> None:
    context = BehaviorContext()
    for user in ("a.sharma", "j.smith", "e.davis"):
        context.observe("host", "SYN-WIN-001", timestamp=BASE_TIME, companion=user)
    assert context.snapshot("host", "SYN-WIN-001", BASE_TIME)["distinct_companions"] == 3


def test_context_tracks_failure_ratio() -> None:
    context = BehaviorContext()
    for _ in range(3):
        context.observe("user", "a.sharma", timestamp=BASE_TIME, outcome="failure")
    context.observe("user", "a.sharma", timestamp=BASE_TIME, outcome="success")
    assert context.snapshot("user", "a.sharma", BASE_TIME)["failure_ratio"] == 0.75


def test_context_reset_clears_everything() -> None:
    context = BehaviorContext()
    context.observe("host", "SYN-WIN-001", timestamp=BASE_TIME)
    context.reset()
    assert context.snapshot("host", "SYN-WIN-001", BASE_TIME)["count"] == 0
    assert context.observation_count == 0


def test_unknown_entity_kind_is_ignored_rather_than_raising() -> None:
    context = BehaviorContext()
    context.observe("nonsense", "value", timestamp=BASE_TIME)
    assert context.observation_count == 0


def test_training_corpus_is_reproducible() -> None:
    """A seed must pin the corpus, otherwise no experiment built on it reproduces.

    ``build_corpus`` documents byte-identical output for a given seed. Until the
    generator was fixed it produced a different fingerprint on every call.
    """
    from app.ml.training.corpus import build_corpus

    first = build_corpus(samples=400)
    second = build_corpus(samples=400)

    assert first.fingerprint() == second.fingerprint()
    assert first.vectors == second.vectors
