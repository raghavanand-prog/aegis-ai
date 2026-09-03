"""Role-based access control.

Authorization is enforced in the backend. The frontend hiding a button is a
usability choice, never a security control: every protected route depends on a
permission check that runs before the handler.

Three roles, one explicit permission matrix. Deliberately small - a full
policy engine would be more machinery than this system can justify, and the
matrix is easy to read in a review, which matters more.
"""

from __future__ import annotations

from enum import Enum

from app.models.enums import UserRole


class Permission(str, Enum):
    # Events
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"
    EVENTS_UPDATE = "events:update"
    EVENTS_PROMOTE = "events:promote"

    # Incidents
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_RESPOND = "incidents:respond"

    # Threat intelligence / indicators
    IOCS_READ = "iocs:read"

    # Analytics and detection engineering
    ANALYTICS_READ = "analytics:read"
    DETECTION_READ = "detection:read"
    DETECTION_EVALUATE = "detection:evaluate"

    # Research evaluation (V4). Read-only: these endpoints publish measured
    # results, and nothing here can start an experiment. Running one is a CLI
    # operation on purpose - it is minutes of CPU over a whole corpus, which is
    # not something an HTTP request should be able to trigger.
    EVALUATION_READ = "evaluation:read"

    # Analyst feedback and controlled adaptation (V5). Reading what the SOC
    # concluded about its own detections is transparency, in the same spirit as
    # evaluation:read. Submitting a claim is an analyst action, because a
    # feedback row is evidence that will later shape a training set.
    FEEDBACK_READ = "feedback:read"
    FEEDBACK_SUBMIT = "feedback:submit"
    DRIFT_READ = "drift:read"
    ADAPTATION_READ = "adaptation:read"
    ADAPTATION_PROPOSE = "adaptation:propose"
    # Approval and deployment are administrator-only and deliberately separate
    # from proposing. An adaptation reaches production through a decision made
    # by someone other than the process that suggested it.
    ADAPTATION_APPROVE = "adaptation:approve"
    ADAPTATION_DEPLOY = "adaptation:deploy"

    # Machine learning (V3)
    ML_READ = "ml:read"
    ML_MANAGE = "ml:manage"

    # Event correlation (V3)
    SEQUENCES_READ = "sequences:read"

    # Threat intelligence enrichment (V3)
    THREAT_INTEL_READ = "threatintel:read"
    THREAT_INTEL_ENRICH = "threatintel:enrich"

    # AI analyst (V3)
    AI_READ = "ai:read"
    AI_REQUEST = "ai:request"
    AI_CONFIGURE = "ai:configure"

    # Notifications
    NOTIFICATIONS_READ = "notifications:read"
    NOTIFICATIONS_UPDATE = "notifications:update"

    # Platform
    TELEMETRY_READ = "telemetry:read"
    TELEMETRY_CONTROL = "telemetry:control"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"
    SYSTEM_CONFIGURE = "system:configure"


#: Read-only access to the SOC picture.
VIEWER_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.EVENTS_READ,
        Permission.INCIDENTS_READ,
        Permission.IOCS_READ,
        Permission.ANALYTICS_READ,
        Permission.DETECTION_READ,
        Permission.NOTIFICATIONS_READ,
        Permission.TELEMETRY_READ,
        # V3: a viewer sees what the platform concluded, including ML findings
        # and any AI analysis an analyst already requested. They cannot spend
        # money or reach out to a third party.
        Permission.ML_READ,
        Permission.SEQUENCES_READ,
        Permission.THREAT_INTEL_READ,
        Permission.AI_READ,
        # V4: measured evaluation results are transparency, not privilege.
        # Anyone who can see what the platform concluded may see how well it
        # actually performs.
        Permission.EVALUATION_READ,
        # V5: feedback is part of the SOC picture - a viewer may see what
        # analysts concluded, and may not add to it.
        Permission.FEEDBACK_READ,
        Permission.DRIFT_READ,
        Permission.ADAPTATION_READ,
    }
)

#: Everything an analyst needs to work an incident end to end.
ANALYST_PERMISSIONS: frozenset[Permission] = VIEWER_PERMISSIONS | frozenset(
    {
        Permission.EVENTS_INGEST,
        Permission.EVENTS_UPDATE,
        Permission.EVENTS_PROMOTE,
        Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE,
        Permission.INCIDENTS_RESPOND,
        Permission.NOTIFICATIONS_UPDATE,
        # V3: an analyst may trigger outbound enrichment and ask the AI analyst
        # for an explanation. Deploying a model is deliberately not on this
        # list - that changes what the whole platform detects.
        Permission.THREAT_INTEL_ENRICH,
        Permission.AI_REQUEST,
        # V5: an analyst records verdicts on their own alerts. Approving or
        # deploying an adaptation built from them is deliberately not here.
        Permission.FEEDBACK_SUBMIT,
        Permission.ADAPTATION_PROPOSE,
    }
)

#: Platform administration on top of analyst duties.
ADMIN_PERMISSIONS: frozenset[Permission] = ANALYST_PERMISSIONS | frozenset(
    {
        Permission.DETECTION_EVALUATE,
        Permission.TELEMETRY_CONTROL,
        Permission.AUDIT_READ,
        Permission.USERS_MANAGE,
        Permission.SYSTEM_CONFIGURE,
        Permission.ML_MANAGE,
        Permission.AI_CONFIGURE,
        # V5: approving and deploying an adaptation changes what the whole
        # platform detects, which is the same class of act as activating a model.
        Permission.ADAPTATION_APPROVE,
        Permission.ADAPTATION_DEPLOY,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    UserRole.VIEWER.value: VIEWER_PERMISSIONS,
    UserRole.ANALYST.value: ANALYST_PERMISSIONS,
    UserRole.ADMIN.value: ADMIN_PERMISSIONS,
}


def permissions_for(role: str) -> frozenset[Permission]:
    """Permissions granted to a role. Unknown roles get nothing."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: str, permission: Permission) -> bool:
    return permission in permissions_for(role)


def permission_matrix() -> dict[str, list[str]]:
    """Serializable view of the matrix, used by the API and the docs."""
    return {
        role: sorted(permission.value for permission in permissions)
        for role, permissions in ROLE_PERMISSIONS.items()
    }
