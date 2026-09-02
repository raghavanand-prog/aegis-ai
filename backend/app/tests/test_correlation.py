"""Correlation engine tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.correlation import engine as correlation_engine
from app.correlation import mitre
from app.correlation.patterns import PATTERNS_BY_ID
from app.models.enums import SequenceStatus
from app.models.event import Event
from app.repositories.event_repository import event_repository

NOW = datetime.now(timezone.utc)


def make_event(db, **overrides) -> Event:
    payload = {
        "timestamp": NOW,
        "source": "Entra ID",
        "source_type": "identity",
        "event_type": "auth_failure",
        "title": "Sign-in failure",
        "severity": "Medium",
        "status": "New",
        "risk_score": 10,
        "risk_level": "Low",
        "risk_signals": [],
        "hostname": None,
        "username": "corr.user",
        "source_ip": "203.0.113.77",
        "normalized_data": {},
        "mitre_techniques": [],
        "detection_rules": [],
        "detections": [],
    }
    payload.update(overrides)
    return event_repository.create(db, Event(**payload))


@pytest.fixture()
def clean(db):
    """Each test owns its own principal so windows never overlap."""
    yield db
    db.rollback()


# ------------------------------------------------------------------ grouping
def test_a_single_event_opens_no_sequence(clean) -> None:
    event = make_event(clean, username="lonely.user")
    clean.flush()
    assert correlation_engine.correlate_event(clean, event, broadcast=False) == []


def test_repeated_failures_and_a_success_open_a_sequence(clean) -> None:
    user = "brute.target"
    events = [
        make_event(clean, username=user, timestamp=NOW - timedelta(minutes=5 - index))
        for index in range(4)
    ]
    success = make_event(
        clean, username=user, event_type="auth_success", title="Sign-in success"
    )
    clean.flush()

    sequences = correlation_engine.correlate_event(clean, success, broadcast=False)
    auth = [s for s in sequences if s.pattern == "COR-AUTH-001"]
    assert auth, "the credential pattern should have opened a sequence"

    sequence = auth[0]
    assert sequence.sequence_id.startswith("SEQ-")
    assert sequence.event_count == len(events) + 1
    assert sequence.confidence > 0.5
    assert "successful sign-in" in sequence.title.lower()
    # The rationale is what an analyst reads instead of the source code.
    assert any("failure" in reason for reason in sequence.rationale)


def test_a_sequence_is_extended_rather_than_duplicated(clean) -> None:
    user = "extend.user"
    for index in range(4):
        event = make_event(
            clean, username=user, timestamp=NOW - timedelta(minutes=6 - index)
        )
    clean.flush()
    first = [
        s
        for s in correlation_engine.correlate_event(clean, event, broadcast=False)
        if s.pattern == "COR-AUTH-001"
    ]
    assert first
    # Snapshot the values: SQLAlchemy's identity map returns the same instance
    # on the second pass, so holding the object and comparing later compares a
    # row with itself.
    first_id, first_count = first[0].id, first[0].event_count

    later = make_event(clean, username=user, event_type="auth_success")
    clean.flush()
    second = [
        s
        for s in correlation_engine.correlate_event(clean, later, broadcast=False)
        if s.pattern == "COR-AUTH-001"
    ]
    assert second
    assert second[0].id == first_id, "the existing sequence should be extended"
    assert second[0].event_count > first_count


def test_sequence_membership_is_limited_to_the_pattern_candidates(clean) -> None:
    """A credential sequence must not absorb every unrelated event the same
    account happened to produce - that inflates the count, the score and the
    story it tells."""
    user = "mixed.user"
    for index in range(4):
        make_event(clean, username=user, timestamp=NOW - timedelta(minutes=8 - index))
    # Unrelated activity for the same principal.
    make_event(clean, username=user, event_type="dns_query", title="DNS query")
    make_event(clean, username=user, event_type="antivirus_scan", title="AV scan")
    success = make_event(clean, username=user, event_type="auth_success")
    clean.flush()

    sequences = correlation_engine.correlate_event(clean, success, broadcast=False)
    auth = [s for s in sequences if s.pattern == "COR-AUTH-001"][0]

    member_types = {event.event_type for event in auth.events}
    assert member_types <= {"auth_failure", "auth_success"}
    assert "dns_query" not in member_types


def test_host_pattern_needs_several_distinct_activity_stages(clean) -> None:
    host = "SYN-HOST-STAGE"
    # Four events, but all the same stage - not a multi-stage story.
    for index in range(4):
        event = make_event(
            clean,
            hostname=host,
            username=None,
            event_type="auth_failure",
            timestamp=NOW - timedelta(minutes=index),
        )
    clean.flush()
    sequences = correlation_engine.correlate_event(clean, event, broadcast=False)
    assert not [s for s in sequences if s.pattern == "COR-HOST-001"]

    for event_type in ("process_creation", "privilege_escalation", "firewall_allow"):
        event = make_event(
            clean, hostname=host, username=None, event_type=event_type, title=event_type
        )
    clean.flush()
    sequences = correlation_engine.correlate_event(clean, event, broadcast=False)
    host_sequences = [s for s in sequences if s.pattern == "COR-HOST-001"]
    assert host_sequences
    assert "stages" in host_sequences[0].rationale[0]


def test_lateral_movement_needs_several_distinct_hosts(clean) -> None:
    """The rule set has no lateral-movement rule; correlation is what closes
    that measured gap."""
    user = "lateral.user"
    for index, host in enumerate(("LNX-01", "LNX-02", "LNX-03", "LNX-04")):
        event = make_event(
            clean,
            username=user,
            hostname=host,
            event_type="ssh_login",
            title="SSH login",
            timestamp=NOW - timedelta(minutes=4 - index),
        )
    clean.flush()

    sequences = correlation_engine.correlate_event(clean, event, broadcast=False)
    lateral = [s for s in sequences if s.pattern == "COR-LAT-001"]
    assert lateral
    assert len(lateral[0].entities["hosts"]) >= 3
    # The technique is inferred from the shape, and must say so.
    inferred = [t for t in lateral[0].techniques if t["provenance"] == mitre.INFERRED]
    assert any(t["technique"] == "T1021" for t in inferred)


def test_events_outside_the_window_are_not_correlated(clean) -> None:
    user = "stale.user"
    for index in range(5):
        make_event(clean, username=user, timestamp=NOW - timedelta(hours=6 + index))
    recent = make_event(clean, username=user, event_type="auth_success")
    clean.flush()

    sequences = correlation_engine.correlate_event(clean, recent, broadcast=False)
    assert not [s for s in sequences if s.pattern == "COR-AUTH-001"]


# -------------------------------------------------------------------- scoring
def test_sequence_score_uses_the_strongest_rule_not_the_sum(clean) -> None:
    """Twenty failed logins from one rule is one finding seen twenty times.
    Summing would let repetition alone manufacture a critical."""
    user = "score.user"
    detection = {
        "ruleId": "DET-AUTH-001",
        "ruleVersion": "1.0",
        "ruleName": "Credential brute force",
        "reason": "many failures",
        "severity": "High",
        "riskContribution": 45,
        "mitreTechniques": ["T1110"],
        "matchedAt": NOW.isoformat(),
    }
    for index in range(5):
        make_event(
            clean,
            username=user,
            detections=[detection],
            detection_rules=["DET-AUTH-001"],
            timestamp=NOW - timedelta(minutes=5 - index),
        )
    success = make_event(clean, username=user, event_type="auth_success")
    clean.flush()

    sequence = [
        s
        for s in correlation_engine.correlate_event(clean, success, broadcast=False)
        if s.pattern == "COR-AUTH-001"
    ][0]

    rule_signals = [s for s in sequence.risk_signals if s["type"] == "rule"]
    assert len(rule_signals) == 1
    assert rule_signals[0]["contribution"] == 45
    assert sequence.risk_score < 5 * 45


def test_sequence_carries_an_explainable_signal_breakdown(clean) -> None:
    user = "explain.user"
    for index in range(4):
        make_event(clean, username=user, timestamp=NOW - timedelta(minutes=4 - index))
    success = make_event(clean, username=user, event_type="auth_success")
    clean.flush()

    sequence = [
        s
        for s in correlation_engine.correlate_event(clean, success, broadcast=False)
        if s.pattern == "COR-AUTH-001"
    ][0]

    assert sequence.risk_signals
    assert any(s["type"] == "correlation" for s in sequence.risk_signals)
    assert sequence.risk_score == min(
        sum(s["contribution"] for s in sequence.risk_signals), 100
    )


def test_serialized_sequence_exposes_no_internal_ids(clean) -> None:
    user = "serial.user"
    for index in range(4):
        make_event(clean, username=user, timestamp=NOW - timedelta(minutes=4 - index))
    success = make_event(clean, username=user, event_type="auth_success")
    clean.flush()

    sequence = correlation_engine.correlate_event(clean, success, broadcast=False)[0]
    payload = correlation_engine.to_dict(sequence)

    assert payload["id"].startswith("SEQ-")
    assert payload["status"] == SequenceStatus.OPEN.value
    assert all(event_id.startswith("EVT-") for event_id in payload["eventIds"])
    assert isinstance(payload["confidence"], float)


# --------------------------------------------------------------------- MITRE
def test_technique_provenance_is_ranked_mapped_over_inferred() -> None:
    merged = mitre.merge(
        [
            mitre.technique("T1110", mitre.CONTEXTUAL, "EVT-1"),
            mitre.technique("T1110", mitre.MAPPED, "DET-AUTH-001"),
            mitre.technique("T1110", mitre.INFERRED, "COR-AUTH-001"),
        ]
    )
    assert len(merged) == 1
    assert merged[0]["provenance"] == mitre.MAPPED


def test_merge_drops_blank_techniques() -> None:
    assert mitre.merge([mitre.technique("", mitre.MAPPED, "x")]) == []


def test_patterns_declare_only_inferred_techniques() -> None:
    """A pattern derives techniques from the shape of a sequence. Claiming they
    were directly observed would be a false attribution."""
    for pattern in PATTERNS_BY_ID.values():
        for value in pattern.inferred_techniques:
            assert value.startswith("T")


def test_the_ml_model_contributes_no_techniques() -> None:
    """Isolation Forest has no concept of an attack technique. Nothing in the
    correlation layer may attribute one to it."""
    import inspect

    from app.correlation import engine, patterns

    for module in (engine, patterns, mitre):
        source = inspect.getsource(module)
        # No code path may build a technique entry sourced from the model.
        assert 'technique(' not in source or 'isolation_forest' not in source
