"""PostgreSQL validation (V7 Phase 7).

V6 could not run this: "No PostgreSQL validation. Docker was unavailable for the
whole session. Everything is SQLite on a laptop." Docker was available in V7, so
these run for real.

**They are skipped, not faked, when no PostgreSQL is reachable.** A test that
silently passed without a server would be worse than no test: it would let the
next handoff claim validation that never happened, which is the exact class of
error the V6 audit existed to correct.

To run them::

    docker compose -f infrastructure/docker-compose.yml up -d postgres
    AEGISX_TEST_POSTGRES_URL=postgresql+psycopg://aegisx:aegisx@localhost:5432/aegisx \\
        pytest app/tests/test_database_postgres.py

What is checked here is what differs between SQLite and PostgreSQL and could
therefore pass on a laptop and fail in production: CHECK constraints (SQLite
enforces them, but the dialect renders differently), foreign keys with
``ON DELETE SET NULL`` (SQLite does not enforce foreign keys at all unless
``PRAGMA foreign_keys`` is on), JSONB rather than JSON text, real transactional
rollback, and the batch-mode migrations added in V7 - which take the
table-rebuild path on SQLite and a plain ``ALTER`` on PostgreSQL, so the two
backends genuinely execute different DDL.
"""

from __future__ import annotations

import json
import os

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import DBAPIError, IntegrityError

POSTGRES_URL = os.environ.get("AEGISX_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason=(
        "No PostgreSQL. Set AEGISX_TEST_POSTGRES_URL to run these. Skipped "
        "rather than approximated: a green run without a server would be a "
        "false claim of validation."
    ),
)


@pytest.fixture(scope="module")
def engine():
    engine = sa.create_engine(POSTGRES_URL, future=True)
    try:
        with engine.connect() as connection:
            connection.execute(sa.text("select 1"))
    except Exception as exc:  # noqa: BLE001 - unreachable server is a skip
        pytest.skip(f"PostgreSQL at AEGISX_TEST_POSTGRES_URL is unreachable: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def inspector(engine):
    return sa.inspect(engine)


def _refuses(engine, sql: str, **params) -> bool:
    """Whether the database refuses a statement. Used to assert constraints."""
    try:
        with engine.begin() as connection:
            connection.execute(sa.text(sql), params)
    except (IntegrityError, DBAPIError):
        return True
    return False


class TestTheSchemaMigratesOnPostgres:
    def test_the_head_revision_is_applied(self, engine) -> None:
        with engine.connect() as connection:
            version = connection.execute(
                sa.text("select version_num from alembic_version")
            ).scalar()

        assert version == "0011_v7_approval_governance"

    def test_the_v7_feedback_identity_columns_exist(self, inspector) -> None:
        columns = {c["name"]: c for c in inspector.get_columns("analyst_feedback")}

        assert columns["analyst_id"]["nullable"] is True
        assert columns["analyst_role"]["nullable"] is True

    def test_the_v7_approval_columns_exist(self, inspector) -> None:
        columns = {c["name"]: c for c in inspector.get_columns("adaptation_proposals")}

        for name in (
            "proposed_by_role",
            "approved_by_role",
            "rejected_by_role",
            "rejected_at",
        ):
            assert name in columns, name
            assert columns[name]["nullable"] is True, name

    def test_json_columns_are_jsonb_not_text(self, inspector) -> None:
        """``JSONType`` declares a JSONB variant for PostgreSQL. If that binding
        broke, everything would still work on SQLite and every JSON query in
        production would degrade to a string comparison."""
        for table, column in (
            ("adaptation_proposals", "validation"),
            ("feedback_datasets", "selection"),
            ("ml_models", "parameters"),
        ):
            found = {c["name"]: str(c["type"]) for c in inspector.get_columns(table)}
            assert found[column].upper() == "JSONB", f"{table}.{column} is {found[column]}"


class TestConstraintsAreEnforced:
    def test_the_role_check_constraint_holds(self, engine) -> None:
        assert _refuses(
            engine,
            "insert into users (email, full_name, hashed_password, role, is_active,"
            " token_version, created_at, updated_at) values ('pg.role@aegisx.dev',"
            " 'X', 'x', 'superuser', true, 1, now(), now())",
        )

    def test_the_confidence_range_check_holds(self, engine) -> None:
        statement = (
            "insert into analyst_feedback (target_type, target_id, label, confidence,"
            " mitre_techniques, analyst, source, feature_schema_version, submitted_at)"
            " values ('event', 1, 'benign', :confidence, '[]', 'pg@aegisx.dev',"
            " 'simulation', 'v1', now())"
        )

        assert _refuses(engine, statement, confidence=1.5)
        assert not _refuses(engine, statement, confidence=0.8)

    def test_the_proposal_status_check_holds(self, engine) -> None:
        assert _refuses(
            engine,
            "insert into adaptation_proposals (proposal_type, status, title, reason,"
            " affected_component, before_state, after_state, evidence, validation,"
            " expected_impact, rollback_state, proposed_by, self_approved, created_at)"
            " values ('threshold_update', 'activated', 't', 'r', 'c', '{}', '{}',"
            " '{}', '{}', '{}', '{}', 'a', false, now())",
        )

    def test_a_feedback_row_cannot_supersede_itself(self, engine) -> None:
        """SQLite enforces this too, but only because the constraint was written
        portably. Worth confirming on the backend that would actually run it."""
        with engine.begin() as connection:
            row_id = connection.execute(
                sa.text(
                    "insert into analyst_feedback (target_type, target_id, label,"
                    " mitre_techniques, analyst, source, feature_schema_version,"
                    " submitted_at) values ('event', 77, 'benign', '[]',"
                    " 'pg@aegisx.dev', 'simulation', 'v1', now()) returning id"
                )
            ).scalar()

        assert _refuses(
            engine,
            "update analyst_feedback set supersedes_id = id where id = :row_id",
            row_id=row_id,
        )


class TestForeignKeysBehaveAsDeclared:
    def test_an_unknown_analyst_id_is_refused(self, engine) -> None:
        """SQLite does not enforce foreign keys at all by default, so this
        constraint has never actually been exercised before V7."""
        assert _refuses(
            engine,
            "insert into analyst_feedback (target_type, target_id, label,"
            " mitre_techniques, analyst, analyst_id, source, feature_schema_version,"
            " submitted_at) values ('event', 2, 'benign', '[]', 'pg@aegisx.dev',"
            " 999999, 'simulation', 'v1', now())",
        )

    def test_deleting_an_account_keeps_its_feedback(self, engine) -> None:
        """``ON DELETE SET NULL``, and the reason for it: deleting an account
        must not delete the record of what that account concluded."""
        with engine.begin() as connection:
            user_id = connection.execute(
                sa.text(
                    "insert into users (email, full_name, hashed_password, role,"
                    " is_active, token_version, created_at, updated_at) values"
                    " ('pg.delete@aegisx.dev', 'X', 'x', 'analyst', true, 1, now(),"
                    " now()) returning id"
                )
            ).scalar()
            feedback_id = connection.execute(
                sa.text(
                    "insert into analyst_feedback (target_type, target_id, label,"
                    " mitre_techniques, analyst, analyst_id, analyst_role, source,"
                    " feature_schema_version, submitted_at) values ('event', 3,"
                    " 'benign', '[]', 'pg.delete@aegisx.dev', :user_id, 'analyst',"
                    " 'simulation', 'v1', now()) returning id"
                ),
                {"user_id": user_id},
            ).scalar()

        with engine.begin() as connection:
            connection.execute(
                sa.text("delete from users where id = :user_id"), {"user_id": user_id}
            )

        with engine.connect() as connection:
            row = connection.execute(
                sa.text(
                    "select analyst, analyst_id, analyst_role from analyst_feedback"
                    " where id = :feedback_id"
                ),
                {"feedback_id": feedback_id},
            ).one()

        assert row.analyst == "pg.delete@aegisx.dev"
        assert row.analyst_id is None
        # The role the claim was made under survives the account. That is the
        # whole reason it is a column rather than a join.
        assert row.analyst_role == "analyst"


class TestTransactionsAndJson:
    def test_a_failed_transaction_leaves_nothing_behind(self, engine) -> None:
        marker = "pg.rollback.component"
        try:
            with engine.begin() as connection:
                connection.execute(
                    sa.text(
                        "insert into adaptation_proposals (proposal_type, status,"
                        " title, reason, affected_component, before_state,"
                        " after_state, evidence, validation, expected_impact,"
                        " rollback_state, proposed_by, self_approved, created_at)"
                        " values ('threshold_update', 'pending', 't', 'r', :marker,"
                        " '{}', '{}', '{}', '{}', '{}', '{}', 'a', false, now())"
                    ),
                    {"marker": marker},
                )
                raise RuntimeError("deliberate failure inside the transaction")
        except RuntimeError:
            pass

        with engine.connect() as connection:
            count = connection.execute(
                sa.text(
                    "select count(*) from adaptation_proposals"
                    " where affected_component = :marker"
                ),
                {"marker": marker},
            ).scalar()

        assert count == 0

    def test_jsonb_is_queryable_by_path(self, engine) -> None:
        """The V6 provenance the dashboard now reads lives inside these columns.
        On SQLite they are text and a path query is impossible."""
        marker = "pg.jsonb.component"
        validation = json.dumps({"gates": {"passed": True}, "rocAuc": {"candidate": 0.91}})

        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "insert into adaptation_proposals (proposal_type, status, title,"
                    " reason, affected_component, before_state, after_state,"
                    " evidence, validation, expected_impact, rollback_state,"
                    " proposed_by, proposed_by_role, self_approved, created_at)"
                    " values ('threshold_update', 'pending', 't', 'r', :marker,"
                    " '{}', '{}', '{}', cast(:validation as jsonb), '{}', '{}',"
                    " 'analyst@aegisx.dev', 'analyst', false, now())"
                ),
                {"marker": marker, "validation": validation},
            )

        with engine.connect() as connection:
            passed = connection.execute(
                sa.text(
                    "select validation->'gates'->>'passed' from adaptation_proposals"
                    " where affected_component = :marker"
                ),
                {"marker": marker},
            ).scalar()
            auc = connection.execute(
                sa.text(
                    "select (validation->'rocAuc'->>'candidate')::float"
                    " from adaptation_proposals where affected_component = :marker"
                ),
                {"marker": marker},
            ).scalar()

        assert passed == "true"
        assert auc == pytest.approx(0.91)


class TestApprovalStateTransitionsOnPostgres:
    def test_four_eyes_holds_against_the_real_backend(self, engine) -> None:
        """The invariant is enforced in Python, but the row it writes is written
        here. Worth one end-to-end pass on the backend production would use."""
        from sqlalchemy.orm import Session

        from app.adaptation.proposals import service as proposals
        from app.models.enums import ProposalStatus, ProposalType

        with Session(engine) as session:
            proposal = proposals.create(
                session,
                proposal_type=ProposalType.THRESHOLD_UPDATE,
                title="Raise the anomaly threshold to 0.7",
                reason="Postgres state-transition check.",
                affected_component="pg.four_eyes",
                before_state={"threshold": 0.65},
                after_state={"threshold": 0.7},
                evidence={"feedbackIds": [1]},
                proposed_by="analyst@aegisx.dev",
                proposed_by_role="analyst",
            )

            with pytest.raises(ValueError, match="cannot also approve"):
                proposals.approve(
                    session,
                    proposal.id,
                    approved_by="analyst@aegisx.dev",
                    approver_role="admin",
                )

            approved = proposals.approve(
                session,
                proposal.id,
                approved_by="admin@aegisx.dev",
                approver_role="admin",
            )
            assert approved.status == ProposalStatus.APPROVED.value
            assert approved.self_approved is False
            assert approved.approved_by_role == "admin"

            session.rollback()

    def test_a_rejection_records_its_timestamp(self, engine) -> None:
        from sqlalchemy.orm import Session

        from app.adaptation.proposals import service as proposals
        from app.models.enums import ProposalType

        with Session(engine) as session:
            proposal = proposals.create(
                session,
                proposal_type=ProposalType.THRESHOLD_UPDATE,
                title="Raise the anomaly threshold to 0.7",
                reason="Postgres rejection check.",
                affected_component="pg.rejection",
                before_state={"threshold": 0.65},
                after_state={"threshold": 0.7},
                evidence={"feedbackIds": [1]},
                proposed_by="analyst@aegisx.dev",
                proposed_by_role="analyst",
            )
            rejected = proposals.reject(
                session,
                proposal.id,
                rejected_by="admin@aegisx.dev",
                reason="Evidence is one week of one host.",
                rejector_role="admin",
            )

            assert rejected.rejected_at is not None
            assert rejected.rejected_by_role == "admin"

            session.rollback()


class TestFeedbackPersistenceOnPostgres:
    def test_a_snapshot_and_its_members_persist(self, engine) -> None:
        from sqlalchemy.orm import Session

        from app.adaptation.feedback import datasets
        from app.adaptation.feedback import service as feedback_service
        from app.adaptation.feedback.labels import FeedbackLabel, FeedbackTargetType

        with Session(engine) as session:
            for target_id, label in ((9101, FeedbackLabel.BENIGN), (9102, FeedbackLabel.TRUE_POSITIVE)):
                feedback_service.submit(
                    session,
                    target_type=FeedbackTargetType.EVENT,
                    target_id=target_id,
                    label=label,
                    analyst="pg.snapshot@aegisx.dev",
                    source="simulation",
                )

            dataset = datasets.build(
                session,
                name="pg-validation",
                version="1.0",
                created_by="test",
                analysts=["pg.snapshot@aegisx.dev"],
            )

            assert dataset.sample_count == 2
            assert dataset.fingerprint
            # The adjudication provenance survives the JSONB round trip.
            assert dataset.selection["adjudication"]["policy"] == "unanimous"
            assert dataset.selection["adjudication"]["conflictedTargets"] == []

            session.rollback()
