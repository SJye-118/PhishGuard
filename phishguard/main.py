"""
PhishGuard Enterprise — FastAPI Application Entry Point.

Phase 1 status: URL validation and schema layer operational.
The ML engine, forensic layer, and Redis cache activate in Phases 5–8.

Fixes applied in this version:
  C-03 — 422 handler now imports RequestValidationError explicitly
  H-01 — classify_batch uses asyncio.gather (concurrent from Phase 1)
  H-03 — CORS origins loaded from settings.cors_origins_list
  M-02 — health_check derives status from actual component checks
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError      # FIX C-03
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from phishguard.config import Settings, get_settings
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
from phishguard.utils.logging_config import get_logger, setup_logging
from phishguard.utils.url_parser import extract_url_info

# ── Initialisation ────────────────────────────────────────────────────────────
settings: Settings = get_settings()
setup_logging(settings.log_level)
log = get_logger("main")

_start_time: float = 0.0


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _start_time
    _start_time = time.monotonic()
    log.info(
        "phishguard_startup",
        extra={
            "version": settings.app_version,
            "environment": settings.environment,
            "log_level": settings.log_level,
            "phase": "1 — Architecture Foundation",
        },
    )
    yield
    log.info(
        "phishguard_shutdown",
        extra={"uptime_seconds": round(time.monotonic() - _start_time, 2)},
    )


# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard Enterprise",
    description="""
## Real-time Phishing Detection API

Combines explainable machine learning with deterministic forensic intelligence.

### Current Phase
**Phase 1 — Architecture Foundation**: URL validation and schema layer operational.
The ML engine and forensic layer activate in Phases 5–7.

### Source Code
[github.com/yourusername/phishguard-enterprise](https://github.com/yourusername/phishguard-enterprise)
""",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    license_info={"name": "MIT License", "identifier": "MIT"},
)


# ── Middleware ────────────────────────────────────────────────────────────────

# FIX H-03: CORS origins come from settings, not hardcoded conditional
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Processing-Time-Ms"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Emit a structured JSON log for every HTTP request."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    log.info(
        "http_request",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": str(request.url.path),
            "status_code": response.status_code,
            "duration_ms": elapsed_ms,
            "client_host": request.client.host if request.client else "unknown",
        },
    )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Processing-Time-Ms"] = str(elapsed_ms)
    return response


# ── Exception Handlers ────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": _status_to_error_code(exc.status_code),
            "detail": exc.detail,
            "request_id": request.headers.get("X-Request-ID", "unknown"),
        },
    )


# FIX C-03: register against RequestValidationError, not the bare 422 int;
#            call exc.errors() directly — no fragile getattr fallback
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "detail": exc.errors(),
            "request_id": request.headers.get("X-Request-ID", "unknown"),
        },
    )


def _status_to_error_code(status_code: int) -> str:
    return {
        400: "bad_request", 401: "unauthorised", 403: "forbidden",
        404: "not_found",   422: "validation_error", 429: "rate_limit_exceeded",
        500: "internal_error", 503: "service_unavailable",
    }.get(status_code, "error")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Infrastructure"],
    summary="Service liveness and readiness check",
)
async def health_check() -> HealthResponse:
    """Return service health status.

    FIX M-02: status is now derived from actual component checks.
    'ok' only when all checks pass; 'degraded' otherwise.
    """
    uptime = time.monotonic() - _start_time

    # Phase 1: file-exists check. Phase 5 replaces with live model load check.
    model_loaded = os.path.isfile(settings.model_path)

    # Phase 1: Redis not yet integrated. Phase 8 replaces with active PING.
    redis_connected = False

    # FIX M-02: derive overall status from component checks, not hardcoded True
    overall_status = "ok" if model_loaded else "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.app_version,
        environment=settings.environment,
        model_loaded=model_loaded,
        redis_connected=redis_connected,
        uptime_seconds=round(uptime, 2),
    )


@app.post(
    "/api/v1/classify",
    response_model=ClassifyResponse,
    tags=["Classification"],
    summary="Classify a URL for phishing risk",
)
async def classify_url(
    payload: ClassifyRequest,
    request: Request,
) -> ClassifyResponse:
    """Classify a single URL for phishing risk.

    Phase 1: Returns a schema-correct stub response confirming URL parsing works.
    Full verdict engine (ML + RDAP + SSL + Veto) activates in Phases 5–7.
    """
    start = time.monotonic()
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    try:
        url_info = extract_url_info(payload.url)
        domain: str = str(url_info["registered_domain"])

        log.info(
            "classify_request",
            extra={
                "request_id":    request_id,
                "domain":        domain,
                "is_ip_address": url_info["is_ip_address"],
                "is_punycode":   url_info["is_punycode"],
                "has_path":      url_info["has_path"],
                "cache_key":     url_info["cache_key"],
            },
        )

        processing_time_ms = int((time.monotonic() - start) * 1000)

        return ClassifyResponse(
            domain=domain,
            risk_score=0,
            risk_tier=RiskTier.UNKNOWN,
            verdict=Verdict.UNKNOWN,
            veto_triggered=False,
            ml_probability=None,
            domain_age_days=None,
            ssl_valid=None,
            brand_match=None,
            justification=[
                "Phase 1 — URL parsing and schema validation operational.",
                f"Extracted registered domain: {domain}.",
                "ML engine activates in Phase 5. "
                "Forensic layer in Phase 6. Ensemble fusion in Phase 7.",
            ],
            cache_hit=False,
            processing_time_ms=processing_time_ms,
            rdap_status=RDAPStatus.NOT_QUERIED,
            ssl_status=SSLStatus.NOT_QUERIED,
        )

    except ValueError as exc:
        log.warning(
            "classify_invalid_input",
            extra={"request_id": request_id, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    except Exception as exc:
        log.error(
            "classify_unexpected_error",
            extra={"request_id": request_id, "error": str(exc)},
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. The request has been logged.",
        ) from exc


@app.post(
    "/api/v1/classify/batch",
    response_model=BatchClassifyResponse,
    tags=["Classification"],
    summary="Classify multiple URLs for phishing risk",
)
async def classify_batch(
    payload: BatchClassifyRequest,
    request: Request,
) -> BatchClassifyResponse:
    """Classify a batch of up to 50 URLs concurrently.

    FIX H-01: Uses asyncio.gather so all URLs are classified in parallel.
    When the real engine is wired in Phase 8, a 50-URL batch will take
    max(single_url_latency) rather than 50 × single_url_latency.
    """
    start = time.monotonic()

    # FIX H-01: concurrent execution — all coroutines start simultaneously
    tasks = [
        classify_url(ClassifyRequest(url=url_str), request)
        for url_str in payload.urls
    ]
    results: list[ClassifyResponse] = list(await asyncio.gather(*tasks))

    return BatchClassifyResponse(
        results=results,
        total=len(results),
        processing_time_ms=int((time.monotonic() - start) * 1000),
    )