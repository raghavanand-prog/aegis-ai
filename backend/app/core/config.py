"""Application configuration.

All configuration is environment driven. Nothing secret is ever hard coded and
nothing secret is ever sent to the frontend.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

#: backend/ - artifact paths and other on-disk defaults resolve against this.
BACKEND_ROOT = Path(__file__).resolve().parents[2]

INSECURE_DEFAULT_SECRET = "dev-only-insecure-secret-change-me"  # noqa: S105 - the sentinel production refuses to start with


class Settings(BaseSettings):
    """Runtime settings, loaded from the environment / `.env` file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application -------------------------------------------------------
    app_name: str = "AEGISX SOC Platform"
    app_version: str = "1.0.0"
    api_v1_prefix: str = "/api/v1"
    environment: str = "development"
    debug: bool = True

    # --- Database ----------------------------------------------------------
    database_url: str = "postgresql+psycopg://aegisx:aegisx@localhost:5432/aegisx"
    db_echo: bool = False

    # --- Security ----------------------------------------------------------
    jwt_secret_key: str = INSECURE_DEFAULT_SECRET
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Telemetry ---------------------------------------------------------
    telemetry_enabled: bool = True
    telemetry_interval_seconds: float = 5.0
    telemetry_events_per_tick: int = 1
    # Safety switch: collectors that talk to anything outside this process are
    # refused unless an operator explicitly opts in.
    telemetry_allow_external_sources: bool = False

    # --- Realtime ----------------------------------------------------------
    ws_require_auth: bool = True
    ws_heartbeat_seconds: float = 25.0

    # --- Rate limiting -----------------------------------------------------
    # In-process sliding window, applied per client address. It is per worker:
    # with several uvicorn workers the effective limit multiplies, which is why
    # a shared store (Redis) is the answer once this runs on more than one
    # process. Documented rather than pretended away.
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 300
    rate_limit_window_seconds: int = 60
    # Authentication is limited far more tightly: it is the endpoint worth
    # brute forcing.
    auth_rate_limit_requests: int = 10
    auth_rate_limit_window_seconds: int = 60

    # --- Request hardening -------------------------------------------------
    max_request_bytes: int = 1_048_576  # 1 MiB
    security_headers_enabled: bool = True
    # Only sent when the app is served over TLS; harmless otherwise.
    hsts_max_age_seconds: int = 31_536_000

    # --- Machine learning (V3) ---------------------------------------------
    # ML is an *additional* detection signal. Every switch below can be turned
    # off and the SOC keeps working on deterministic rules alone.
    ml_enabled: bool = True
    #: Where trained model artifacts are written and read from. Artifacts are
    #: deliberately not committed to git; see docs/model-lifecycle.md.
    ml_model_dir: str = "app/ml/artifacts"
    #: Expected proportion of anomalies in the training data. Isolation Forest
    #: uses it to place its decision threshold.
    ml_contamination: float = 0.08
    ml_random_state: int = 1337
    #: Normalized anomaly score (0..1) at or above which a scored event is
    #: labelled anomalous. Kept separate from the model so it can be tuned
    #: without retraining.
    #:
    #: 0.65 is chosen from measurement, not taste: on a held-out corpus the
    #: model has never seen, it flags ~1% of ordinary telemetry. 0.62 flags
    #: ~7% and 0.60 flags ~13%, which would make the anomaly badge in the UI
    #: mean nothing. Reproduce with `python -m app.ml.evaluation.run_ml_eval
    #: --sweep`; the numbers are in docs/ml-architecture.md.
    ml_anomaly_threshold: float = 0.65

    # --- Event correlation (V3) --------------------------------------------
    correlation_enabled: bool = True
    #: How far back the correlator looks for related activity.
    correlation_window_minutes: int = 30
    #: Minimum number of related events before a sequence is opened.
    correlation_min_events: int = 3
    #: Sequences above this risk score are surfaced as incident candidates.
    correlation_incident_risk: int = 70

    # --- Threat intelligence (V3) ------------------------------------------
    threat_intel_enabled: bool = True
    #: "none" disables lookups entirely; "virustotal" needs an API key.
    threat_intel_provider: str = "none"
    virustotal_api_key: str = ""
    threat_intel_timeout_seconds: float = 6.0
    #: Cached verdicts are reused for this long before another lookup is made.
    threat_intel_cache_ttl_hours: int = 24
    #: Hard ceiling on outbound lookups per process per day. Protects both the
    #: provider quota and the bill.
    threat_intel_daily_budget: int = 400

    # --- AI analyst (V3) ----------------------------------------------------
    ai_enabled: bool = True
    #: "mock" (deterministic, offline, no network), "openai", "anthropic",
    #: or "none" to disable the analyst entirely.
    ai_provider: str = "mock"
    ai_api_key: str = ""
    ai_model: str = ""
    ai_base_url: str = ""
    ai_timeout_seconds: float = 45.0
    ai_max_output_tokens: int = 2000
    #: Caps how much evidence is packed into one prompt. Bounds both cost and
    #: the amount of untrusted event text the model ever sees.
    ai_max_evidence_events: int = 25
    #: Hard ceiling on AI requests per process per day.
    ai_daily_request_budget: int = 200

    # --- Background enrichment (V3) ----------------------------------------
    # Ingestion must never wait on threat intelligence or correlation, so both
    # run on a small in-process worker queue rather than in the request path.
    enrichment_enabled: bool = True
    enrichment_queue_size: int = 2000

    # --- Detection evaluation ----------------------------------------------
    # Where `python -m app.evaluation.run_detection_eval` writes its reports and
    # where the API reads the latest one from. Empty means the package default
    # (backend/app/evaluation/reports).
    evaluation_reports_dir: str = ""

    # --- Research datasets (V4) --------------------------------------------
    # Where public evaluation corpora live on disk. Datasets are large, are
    # licensed by third parties and are never committed, so this points at a
    # gitignored directory that an operator populates with the documented
    # fetch step. Empty means the package default (backend/data/datasets).
    evaluation_data_dir: str = ""

    # --- Logging -----------------------------------------------------------
    # "json" for machine-readable structured logs (the production default),
    # "console" for readable local development output.
    log_format: str = "json"
    log_level: str = "INFO"
    log_request_bodies: bool = False  # never enable where real telemetry flows

    # --- Bootstrap account -------------------------------------------------
    seed_demo_user: bool = True
    demo_user_email: str = "analyst@aegisx.dev"
    demo_user_password: str = "AegisX!Demo123"  # noqa: S105 - dev bootstrap default, refused in production
    demo_user_name: str = "Aegis Analyst"

    @field_validator("telemetry_events_per_tick")
    @classmethod
    def _sane_batch(cls, value: int) -> int:
        if value < 1:
            raise ValueError("TELEMETRY_EVENTS_PER_TICK must be >= 1")
        return min(value, 50)

    @field_validator("telemetry_interval_seconds")
    @classmethod
    def _sane_interval(cls, value: float) -> float:
        if value < 0.1:
            raise ValueError("TELEMETRY_INTERVAL_SECONDS must be >= 0.1")
        return value

    @field_validator("ml_anomaly_threshold")
    @classmethod
    def _sane_threshold(cls, value: float) -> float:
        if not 0.0 < value < 1.0:
            raise ValueError("ML_ANOMALY_THRESHOLD must be strictly between 0 and 1")
        return value

    @field_validator("ml_contamination")
    @classmethod
    def _sane_contamination(cls, value: float) -> float:
        if not 0.0 < value <= 0.5:
            raise ValueError("ML_CONTAMINATION must be in (0, 0.5]")
        return value

    @field_validator("ai_provider", "threat_intel_provider")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.strip().lower()

    @property
    def ml_artifact_dir(self) -> Path:
        """Absolute artifact directory, resolved against the backend package."""
        candidate = Path(self.ml_model_dir)
        if candidate.is_absolute():
            return candidate
        return BACKEND_ROOT / candidate

    @property
    def evaluation_dataset_dir(self) -> Path:
        """Absolute dataset directory, resolved against the backend package."""
        candidate = Path(self.evaluation_data_dir or "data/datasets")
        if candidate.is_absolute():
            return candidate
        return BACKEND_ROOT / candidate

    @property
    def ai_configured(self) -> bool:
        """True when the analyst can actually answer a request.

        The mock provider needs nothing; a hosted provider needs a key. This is
        what the API reports as `available`, so the UI never offers a button
        that is guaranteed to fail.
        """
        if not self.ai_enabled or self.ai_provider in {"none", ""}:
            return False
        if self.ai_provider == "mock":
            return True
        return bool(self.ai_api_key)

    @property
    def threat_intel_configured(self) -> bool:
        if not self.threat_intel_enabled or self.threat_intel_provider in {"none", ""}:
            return False
        if self.threat_intel_provider == "virustotal":
            return bool(self.virustotal_api_key)
        return False

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def validate_runtime(self) -> None:
        """Fail fast on insecure production configuration."""
        if self.is_production:
            if self.jwt_secret_key == INSECURE_DEFAULT_SECRET or len(self.jwt_secret_key) < 32:
                raise RuntimeError(
                    "JWT_SECRET_KEY must be set to a strong random value in production."
                )
            if self.seed_demo_user:
                raise RuntimeError("SEED_DEMO_USER must be disabled in production.")
            if not self.rate_limit_enabled:
                raise RuntimeError("RATE_LIMIT_ENABLED must stay on in production.")
            if not self.security_headers_enabled:
                raise RuntimeError("SECURITY_HEADERS_ENABLED must stay on in production.")
            if "*" in self.cors_origin_list:
                raise RuntimeError("CORS_ORIGINS must name explicit origins in production.")
            if self.log_request_bodies:
                raise RuntimeError("LOG_REQUEST_BODIES must be off in production.")
            if self.ai_enabled and self.ai_provider == "mock":
                logger.warning(
                    "AI_PROVIDER=mock in production: the AI analyst will return a "
                    "deterministic template, not model output."
                )
        elif self.jwt_secret_key == INSECURE_DEFAULT_SECRET:
            logger.warning(
                "Using the built-in development JWT secret. Set JWT_SECRET_KEY before "
                "exposing this instance to anyone else."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
