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
    """The incident lifecycle.

        Open -> Triaged -> Investigating -> Containment Pending -> Contained
                                                                -> Resolved -> Closed

    The four V1 values keep their exact spelling. They are what every stored
    incident carries and what the frontend renders, and renaming ``Open`` to
    ``New`` to match a diagram would have made every existing row unreadable by
    its own status field for no gain - ``Open`` already means "raised, nobody
    has assessed it yet".

    The edges, the authority each one needs and the reasons it must carry live
    in :mod:`app.incidents.lifecycle`, not here. This enum says what a state is
    called; it deliberately says nothing about which ones may follow which.
    """

    #: Raised. Nobody has assessed it.
    OPEN = "Open"
    #: Assessed and queued. Severity and scope have been confirmed by a person.
    TRIAGED = "Triaged"
    #: Actively worked.
    INVESTIGATING = "Investigating"
    #: Containment has been decided but is not yet in effect. From V9 this is
    #: where an incident waits while a response action is approved and executed;
    #: until that framework exists it is set and cleared by hand.
    CONTAINMENT_PENDING = "Containment Pending"
    #: The threat is stopped. Not the same as fixed.
    CONTAINED = "Contained"
    #: Remediated. The work is done and the record is still open to correction.
    RESOLVED = "Resolved"
    #: Sealed. Terminal, and the only state with no way out - reopening a closed
    #: incident would rewrite a decision somebody signed. Raise a new incident
    #: instead, the same rule V5 applied to a rejected proposal.
    CLOSED = "Closed"


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

    # --- V5: the controlled adaptation lifecycle --------------------------
    # A candidate exists as an artifact and a record and nothing else. It has
    # no route to serving except through evaluation, safety gates and an
    # administrator's approval, and `may_serve` is the single place that says so.
    #: Trained, registered, and deliberately inert.
    CANDIDATE = "candidate"
    #: Under evaluation against the deployed model.
    EVALUATING = "evaluating"
    #: Passed its gates and been approved by a human. Eligible to be activated.
    APPROVED = "approved"
    #: Evaluated and refused. Kept, never deleted - a rejection is a result.
    REJECTED = "rejected"
    #: Was deployed, then withdrawn. Distinct from archived: this one failed in
    #: production, and that is worth being able to see later.
    ROLLED_BACK = "rolled_back"


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
    # V9: reading one specific evidence item and its provenance. The
    # evidence *list* is not audited - that is how the workspace opens.
    EVIDENCE_VIEWED = "evidence.viewed"
    # V9: the evidence a consequential decision was taken on was recorded,
    # and the refusal that fires when a decision would be taken against
    # evidence that moved since the decider reviewed it.
    DECISION_EVIDENCE_BOUND = "decision.evidence_bound"
    DECISION_EVIDENCE_STALE = "decision.evidence_stale"
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
    ADAPTATION_PROPOSAL_CREATED = "adaptation.proposal_created"
    ADAPTATION_PROPOSAL_APPROVED = "adaptation.proposal_approved"
    ADAPTATION_PROPOSAL_REJECTED = "adaptation.proposal_rejected"
    ADAPTATION_PROPOSAL_DEPLOYED = "adaptation.proposal_deployed"
    ADAPTATION_PROPOSAL_ROLLED_BACK = "adaptation.proposal_rolled_back"
    SETTINGS_CHANGED = "system.settings_changed"
    ACCESS_DENIED = "auth.access_denied"


class ProposalType(str, Enum):
    """What an adaptation proposal asks to change.

    Every one of these is a *request*. None of them is applied by being
    created, and the two recommendation types deliberately never modify a
    production rule or correlation pattern directly - they propose wording an
    engineer reviews.
    """

    MODEL_UPDATE = "model_update"
    THRESHOLD_UPDATE = "threshold_update"
    FEATURE_CONFIG_UPDATE = "feature_config_update"
    DETECTION_RULE_RECOMMENDATION = "detection_rule_recommendation"
    CORRELATION_PATTERN_RECOMMENDATION = "correlation_pattern_recommendation"


class ProposalStatus(str, Enum):
    """The adaptation approval lifecycle.

        pending -> approved -> deployed -> rolled_back
                -> rejected

    Nothing skips a step, and there is no transition that a machine may take on
    a proposal's behalf.
    """

    #: Raised, awaiting a human decision.
    PENDING = "pending"
    #: A named approver signed it off. Not yet in production.
    APPROVED = "approved"
    #: Refused, with a reason. Kept, because a refusal is a result.
    REJECTED = "rejected"
    #: Applied to production.
    DEPLOYED = "deployed"
    #: Applied and then withdrawn.
    ROLLED_BACK = "rolled_back"
    #: Replaced by a later proposal covering the same component.
    SUPERSEDED = "superseded"
