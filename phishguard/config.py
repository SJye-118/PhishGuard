"""
PhishGuard Enterprise — Application Configuration.

Loads all configuration from environment variables using pydantic-settings.
Priority order (highest first):
  1. Actual environment variables
  2. .env file (local development)
  3. Field defaults defined below
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL. Use rediss:// for TLS.",
    )

    # ── Model ────────────────────────────────────────────────────────────────
    model_path: str = Field(
        default="./artefacts/phishguard_model.joblib",
        description="Path to the trained model .joblib file.",
    )

    # ── Brand protection ─────────────────────────────────────────────────────
    brand_list_size: int = Field(
        default=1000, ge=100, le=10000,
        description="Number of top Tranco domains loaded as brand keywords.",
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: str = Field(
        default="INFO",
        description="Verbosity: DEBUG | INFO | WARNING | ERROR | CRITICAL",
    )

    # ── URL validation ───────────────────────────────────────────────────────
    max_url_length: int = Field(
        default=2048, ge=100, le=8192,
        description="Maximum URL string length accepted by the API.",
    )

    # ── Timeouts (milliseconds) ──────────────────────────────────────────────
    rdap_timeout_ms: int = Field(
        default=1500, ge=500, le=5000,
        description="Hard timeout for RDAP domain registration queries.",
    )
    ssl_timeout_ms: int = Field(
        default=1500, ge=500, le=5000,
        description="Hard timeout for TLS/SSL certificate inspection.",
    )

    # ── Cache ────────────────────────────────────────────────────────────────
    cache_ttl_seconds: int = Field(
        default=86400, ge=60,
        description="Redis TTL for cached classification results.",
    )

    # ── Veto logic ───────────────────────────────────────────────────────────
    veto_age_threshold_days: int = Field(
        default=14, ge=1, le=90,
        description="Domain age (days) below which the atomic veto is evaluable.",
    )

    # ── CORS — FIX H-03 ──────────────────────────────────────────────────────
    cors_allowed_origins: str = Field(
        default="",
        description=(
            "Comma-separated list of allowed CORS origins in production. "
            "Example: https://app.phishguard.io,https://dashboard.phishguard.io "
            "Leave empty to block all cross-origin browser requests (secure default). "
            "Development mode always allows localhost:3000 and localhost:8000."
        ),
    )

    # ── Application metadata ─────────────────────────────────────────────────
    app_version: str = Field(default="1.0.0")
    environment: Literal["development", "staging", "production"] = Field(
        default="development",
    )

    # ── Optional integrations ────────────────────────────────────────────────
    sentry_dsn: str | None = Field(default=None)

    # ── Validators ───────────────────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        normalised = v.upper()
        if normalised not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Invalid log_level: '{v}'")
        return normalised

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, v: str) -> str:
        if not (v.startswith("redis://") or v.startswith("rediss://")):
            raise ValueError(
                f"REDIS_URL must start with 'redis://' or 'rediss://'. Got: '{v}'"
            )
        return v

    # ── Computed properties ──────────────────────────────────────────────────

    @property
    def rdap_timeout_seconds(self) -> float:
        return self.rdap_timeout_ms / 1000.0

    @property
    def ssl_timeout_seconds(self) -> float:
        return self.ssl_timeout_ms / 1000.0

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ALLOWED_ORIGINS into a list, filtering empty strings."""
        if self.environment == "development":
            return ["http://localhost:3000", "http://localhost:8000"]
        if not self.cors_allowed_origins.strip():
            return []
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()