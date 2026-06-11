"""
PhishGuard Enterprise — Pydantic Request/Response Schemas.

This module is the single source of truth for the API contract.
FastAPI reads these schemas at startup to auto-generate the full
OpenAPI 3.0 specification accessible at /openapi.json and /docs.

Design decisions:
  - All enums use str as the mixin so JSON serialisation works
    without calling .value explicitly.
  - Optional fields use explicit `= None` defaults so omission
    from a partial response is clearly intentional.
  - Field descriptions appear in the Swagger UI automatically.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field


# ── Enumerations ────────────────────────────────────────────────────────────

class RiskTier(str, Enum):
    """Categorical risk classification tier.

    Maps to composite risk score bands:
      LOW      →  0–29   (likely safe)
      MEDIUM   → 30–59   (elevated suspicion)
      HIGH     → 60–84   (strong risk signals present)
      CRITICAL → 85–100  (confirmed high-risk / veto triggered)
      UNKNOWN  →  N/A    (engine not yet operational — Phase 1 stub)
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    """Binary classification verdict.

    SAFE       → Low probability of phishing.
    SUSPICIOUS → Elevated risk; manual review recommended.
    MALICIOUS  → High confidence phishing indicator or veto triggered.
    UNKNOWN    → Engine not yet operational (Phase 1 stub).
    """

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class RDAPStatus(str, Enum):
    """Result status of the RDAP domain registration query.

    SUCCESS     → Registration date retrieved successfully.
    TIMEOUT     → Query exceeded the 1,500ms hard timeout; age set to -1.
    PARSE_ERROR → RDAP response received but could not be parsed; age = -1.
    NO_REGISTRY → No RDAP registrar found for this TLD; age = -1.
    NOT_QUERIED → RDAP was not attempted (Phase 1 / cache hit).
    """

    SUCCESS = "success"
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"
    NO_REGISTRY = "no_registry"
    NOT_QUERIED = "not_queried"


class SSLStatus(str, Enum):
    """Result status of the TLS/SSL certificate inspection.

    VALID       → Certificate is valid, trusted, and not expired.
    INVALID     → Certificate is self-signed, expired, or untrusted.
    TIMEOUT     → Inspection exceeded the 1,500ms hard timeout.
    UNREACHABLE → TCP connection to port 443 was refused or timed out.
    NOT_QUERIED → SSL check was not attempted (Phase 1 / cache hit).
    """

    VALID = "valid"
    INVALID = "invalid"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    NOT_QUERIED = "not_queried"


# ── Request Schemas ─────────────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    """Request body for POST /api/v1/classify.

    Accepts any raw URL string. The engine strips the scheme, path,
    and query string to extract the registered domain for analysis.

    Example:
        {"url": "https://paypal.secure-login.updates-verify.com/account"}
    """

    url: Annotated[
        str,
        Field(
            min_length=1,
            max_length=2048,
            description=(
                "Raw URL or domain string to classify for phishing risk. "
                "Scheme, path, and query string are stripped automatically. "
                "Maximum length: 2,048 characters."
            ),
            examples=[
                "https://paypal.secure-login.updates-verify.com/account",
                "https://www.google.com",
                "evil-domain.xyz",
            ],
        ),
    ]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"url": "https://paypal.secure-login.updates-verify.com/account"}
            ]
        }
    }


class BatchClassifyRequest(BaseModel):
    """Request body for POST /api/v1/classify/batch.

    FIX C-02: Each URL string is validated against the same constraints as
    ClassifyRequest (min_length=1, max_length=2048). Previously only the
    list length was validated, allowing empty strings and oversized URLs
    to reach the engine silently.
    """

    urls: Annotated[
        list[
            Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=2048,
                    description="Individual URL string — same constraints as /classify.",
                ),
            ]
        ],
        Field(
            min_length=1,
            max_length=50,
            description=(
                "List of 1–50 URL strings to classify. "
                "Each URL follows the same constraints as /classify."
            ),
            examples=[
                ["https://paypal.secure-login.updates-verify.com", "https://www.google.com"]
            ],
        ),
    ]
    
# ── Response Schemas ────────────────────────────────────────────────────────

class ClassifyResponse(BaseModel):
    """Response body for POST /api/v1/classify.

    Contains the full classification verdict including the composite
    risk score, risk tier, binary verdict, all intermediate signal
    values, and a human-readable justification array.
    """

    domain: str = Field(
        description=(
            "The extracted registered domain after normalisation. "
            "Scheme, subdomain, path, and query string are removed."
        ),
        examples=["updates-verify.com"],
    )

    risk_score: int = Field(
        ge=0,
        le=100,
        description=(
            "Composite risk score from 0 (no risk) to 100 (maximum risk). "
            "Derived from weighted ML probability + forensic signals + veto."
        ),
        examples=[94, 12, 55],
    )

    risk_tier: RiskTier = Field(
        description="Categorical risk tier derived from risk_score.",
        examples=["CRITICAL", "LOW", "MEDIUM"],
    )

    verdict: Verdict = Field(
        description="Binary classification verdict.",
        examples=["MALICIOUS", "SAFE", "SUSPICIOUS"],
    )

    veto_triggered: bool = Field(
        description=(
            "True if the atomic veto override was activated. "
            "The veto fires when domain_age_days < threshold AND "
            "brand_match is not null simultaneously."
        ),
        examples=[True, False],
    )

    ml_probability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Raw ML model output probability (0.0–1.0). "
            "Null if the ML engine is not yet operational."
        ),
        examples=[0.31, 0.97, None],
    )

    domain_age_days: int | None = Field(
        default=None,
        ge=-1,
        description=(
            "Domain registration age in full days. "
            "-1 if RDAP query timed out or data was unavailable. "
            "Null if not yet queried (Phase 1)."
        ),
        examples=[3, 365, -1, None],
    )

    ssl_valid: bool | None = Field(
        default=None,
        description=(
            "TLS certificate validity. "
            "True = valid and trusted. False = invalid/expired/self-signed. "
            "Null if the SSL check timed out or was not performed."
        ),
        examples=[True, False, None],
    )

    brand_match: str | None = Field(
        default=None,
        description=(
            "The brand keyword detected in the registered domain, if any. "
            "Null if no brand match was found. "
            "Sourced from the dynamically loaded Tranco brand list."
        ),
        examples=["paypal", "google", None],
    )

    justification: list[str] = Field(
        description=(
            "Human-readable explanation of every signal that contributed "
            "to the verdict, ordered by severity (veto triggers first)."
        ),
        examples=[
            [
                "VETO: Domain age 3 days is below the 14-day threshold",
                "VETO: Brand keyword 'paypal' detected in registered domain",
                "SSL certificate invalid or absent",
                "ML structural score: 0.31 (overridden by atomic veto)",
            ]
        ],
    )

    cache_hit: bool = Field(
        description=(
            "True if this result was served from Redis cache. "
            "Cached results have processing_time_ms below 20ms typically."
        ),
        examples=[False, True],
    )

    processing_time_ms: int = Field(
        ge=0,
        description="Total server-side processing time in milliseconds.",
        examples=[412, 18, 638],
    )

    rdap_status: RDAPStatus = Field(
        description="Result status of the RDAP domain registration query.",
        examples=["success", "timeout", "not_queried"],
    )

    ssl_status: SSLStatus = Field(
        description="Result status of the TLS/SSL certificate inspection.",
        examples=["valid", "invalid", "not_queried"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "domain": "updates-login.com",
                    "risk_score": 94,
                    "risk_tier": "CRITICAL",
                    "verdict": "MALICIOUS",
                    "veto_triggered": True,
                    "ml_probability": 0.31,
                    "domain_age_days": 3,
                    "ssl_valid": False,
                    "brand_match": "paypal",
                    "justification": [
                        "VETO: Domain age 3 days is below the 14-day threshold",
                        "VETO: Brand keyword 'paypal' detected in registered domain",
                        "SSL certificate invalid or absent",
                        "ML structural score: 0.31 (overridden by atomic veto)",
                    ],
                    "cache_hit": False,
                    "processing_time_ms": 412,
                    "rdap_status": "success",
                    "ssl_status": "invalid",
                }
            ]
        }
    }


class BatchClassifyResponse(BaseModel):
    """Response body for POST /api/v1/classify/batch."""

    results: list[ClassifyResponse] = Field(
        description=(
            "Classification results in the same order as the input URL list."
        ),
    )

    total: int = Field(
        ge=0,
        description="Total number of URLs classified in this batch request.",
        examples=[2, 50],
    )

    processing_time_ms: int = Field(
        ge=0,
        description="Total server-side processing time for the entire batch.",
        examples=[1240],
    )


class HealthResponse(BaseModel):
    """Response body for GET /health.

    Used by uptime monitoring services, load balancers, and the
    Docker HEALTHCHECK directive to verify service availability.
    """

    status: str = Field(
        description="Overall service status. 'ok' or 'degraded'.",
        examples=["ok", "degraded"],
    )

    version: str = Field(
        description="Application semantic version string.",
        examples=["1.0.0"],
    )

    environment: str = Field(
        description="Current runtime environment.",
        examples=["production", "staging", "development"],
    )

    model_loaded: bool = Field(
        description=(
            "True if the ML model artefact file exists at MODEL_PATH. "
            "False in Phase 1 before the model is trained."
        ),
        examples=[True, False],
    )

    redis_connected: bool = Field(
        description=(
            "True if a successful Redis PING was received. "
            "False in Phase 1 before the Redis client is integrated."
        ),
        examples=[True, False],
    )

    uptime_seconds: float = Field(
        description="Seconds elapsed since the application started.",
        examples=[3600.42],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": "ok",
                    "version": "1.0.0",
                    "environment": "production",
                    "model_loaded": True,
                    "redis_connected": True,
                    "uptime_seconds": 86400.0,
                }
            ]
        }
    }