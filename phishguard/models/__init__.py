"""Pydantic schema models — the single source of truth for the OpenAPI contract."""

from phishguard.models.schemas import (
    BatchClassifyRequest,
    BatchClassifyResponse,
    ClassifyRequest,
    ClassifyResponse,
    HealthResponse,
    RDAPStatus,
    RiskTier,
    SSLStatus,
    Verdict,
)

__all__ = [
    "ClassifyRequest",
    "ClassifyResponse",
    "BatchClassifyRequest",
    "BatchClassifyResponse",
    "HealthResponse",
    "RiskTier",
    "Verdict",
    "RDAPStatus",
    "SSLStatus",
]