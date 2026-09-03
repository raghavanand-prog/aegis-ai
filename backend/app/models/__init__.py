"""SQLAlchemy models.

Importing this package registers every mapper on ``Base.metadata`` which is
what Alembic autogeneration and ``create_all`` rely on.
"""

from app.models.adaptation import (
    AnalystFeedback,
    DriftMeasurement,
    FeedbackDataset,
    FeedbackDatasetMember,
)
from app.models.ai_analysis import AIAnalysis
from app.models.audit import AuditLog
from app.models.base import Base, JSONType, TimestampMixin, utcnow
from app.models.evaluation import (
    EvaluationDatasetRecord,
    Experiment,
    ExperimentRun,
)
from app.models.event import Event
from app.models.incident import Incident
from app.models.ioc import IOC, event_iocs, incident_iocs
from app.models.ml import MLInference, MLModel
from app.models.notification import Notification
from app.models.sequence import SecuritySequence, sequence_events
from app.models.threat_intel import ThreatIntelResult
from app.models.user import User

__all__ = [
    "AIAnalysis",
    "AnalystFeedback",
    "DriftMeasurement",
    "FeedbackDataset",
    "FeedbackDatasetMember",
    "AuditLog",
    "Base",
    "EvaluationDatasetRecord",
    "Event",
    "Experiment",
    "ExperimentRun",
    "IOC",
    "Incident",
    "JSONType",
    "MLInference",
    "MLModel",
    "Notification",
    "SecuritySequence",
    "ThreatIntelResult",
    "TimestampMixin",
    "User",
    "event_iocs",
    "incident_iocs",
    "sequence_events",
    "utcnow",
]
