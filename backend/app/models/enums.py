"""Domain enumerations.

Values are deliberately identical to the strings the AEGISX frontend already
renders (``Critical``, ``Open``, ...) so no translation layer is needed.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[self.value]


class EventStatus(str, Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"


class IncidentStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    CONTAINED = "Contained"
    RESOLVED = "Resolved"


class SourceType(str, Enum):
    """Class of telemetry a source produces."""

    ENDPOINT = "endpoint"
    EDR = "edr"
    IDENTITY = "identity"
    NETWORK = "network"
    DNS = "dns"
    FIREWALL = "firewall"
    OPERATING_SYSTEM = "os"
    CLOUD = "cloud"
    APPLICATION = "application"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "hash"
    EMAIL = "email"
    PROCESS = "process"


class NotificationSeverity(str, Enum):
    """Lowercase variant used by the notification drawer in the UI."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationCategory(str, Enum):
    EVENT = "event"
    INCIDENT = "incident"
    ASSIGNMENT = "assignment"
    RESPONSE = "response"
    SYSTEM = "system"


class MLModelStatus(str, Enum):
    """Lifecycle of a registered model artifact."""

    #: Serving inference right now. At most one per model name.
    ACTIVE = "active"
    #: Registered and reproducible, but not serving.
    ARCHIVED = "archived"
    #: Training produced an artifact that failed validation.
    FAILED = "failed"


class ThreatIntelStatus(str, Enum):
    """Outcome of a single provider lookup - never silently conflated."""

    OK = "ok"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNAVAILABLE = "unavailable"


class ThreatIntelReputation(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    HARMLESS = "harmless"
    UNKNOWN = "unknown"


class SequenceStatus(str, Enum):
    OPEN = "Open"
    PROMOTED = "Promoted"
    DISMISSED = "Dismissed"


class SignalType(str, Enum):
    """Where a contribution to a risk score came from.

    Kept distinct so the UI can label each one honestly instead of merging
    everything into one unexplained number.
    """

    RULE = "rule"
    ML = "ml"
    THREAT_INTEL = "threat_intel"
    CORRELATION = "correlation"
    CONTEXT = "context"


class AIAnalysisKind(str, Enum):
    ANALYZE = "analyze"
    EXPLAIN = "explain"
    RECOMMEND = "recommend"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AuditAction(str, Enum):
    LOGIN = "user.login"
    LOGIN_FAILED = "user.login_failed"
    LOGOUT = "user.logout"
    PASSWORD_CHANGED = "user.password_changed"  # noqa: S105 - audit action name, not a secret
    SESSIONS_REVOKED = "user.sessions_revoked"
    USER_CREATED = "user.created"
    USER_ROLE_CHANGED = "user.role_changed"
    EVENT_VIEWED = "event.viewed"
    EVENT_PROMOTED = "event.promoted"
    EVENT_STATUS_CHANGED = "event.status_changed"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"
    INCIDENT_ASSIGNED = "incident.assigned"
    RESPONSE_ACTION = "incident.response_action"
    IOC_VIEWED = "ioc.viewed"
    DETECTION_EVALUATION_RUN = "detection.evaluation_run"
    # --- V3: AI / ML / enrichment -----------------------------------------
    ML_MODEL_TRAINED = "ml.model_trained"
    ML_MODEL_ACTIVATED = "ml.model_activated"
    ML_MODEL_DEACTIVATED = "ml.model_deactivated"
    ML_MODEL_ROLLBACK = "ml.model_rollback"
    ML_EVALUATION_RUN = "ml.evaluation_run"
    AI_ANALYSIS_REQUESTED = "ai.analysis_requested"
    AI_ANALYSIS_GENERATED = "ai.analysis_generated"
    AI_ANALYSIS_FAILED = "ai.analysis_failed"
    THREAT_INTEL_LOOKUP = "threatintel.lookup"
    SEQUENCE_CREATED = "correlation.sequence_created"
    SEQUENCE_PROMOTED = "correlation.sequence_promoted"
    # --- V5: controlled adaptation ----------------------------------------
    ADAPTATION_FEEDBACK_SUBMITTED = "adaptation.feedback_submitted"
    ADAPTATION_FEEDBACK_CORRECTED = "adaptation.feedback_corrected"
    SETTINGS_CHANGED = "system.settings_changed"
    ACCESS_DENIED = "auth.access_denied"
