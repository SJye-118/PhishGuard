"""
PhishGuard Enterprise — Structured JSON Logging.

Every log statement emitted by the application is formatted as a single
JSON object on one line. This enables downstream log aggregation tools
(CloudWatch, GCP Logging, Datadog) to parse fields without regex.

Usage:
    from phishguard.utils.logging_config import get_logger

    log = get_logger("forensics.rdap")

    log.info("rdap_query_success", extra={
        "domain": "example.com",
        "domain_age_days": 42,
        "elapsed_ms": 380,
    })

Output:
    {
      "timestamp": "2026-06-01T14:23:11.482Z",
      "level": "INFO",
      "logger": "phishguard.forensics.rdap",
      "event": "rdap_query_success",
      "domain": "example.com",
      "domain_age_days": 42,
      "elapsed_ms": 380
    }
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

# Fields present on every LogRecord that we do NOT want to repeat
# in the structured output — they are noisy internal Python internals.
_INTERNAL_FIELDS: frozenset[str] = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text",
    "filename", "funcName", "id", "levelname", "levelno",
    "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated",
    "stack_info", "thread", "threadName", "taskName",
})


class _JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects.

    The `message` field carries the log event name (e.g. "rdap_timeout").
    All extra fields passed via the `extra` kwarg appear as top-level keys.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a LogRecord to a JSON string.

        Args:
            record: The log record produced by a logger call.

        Returns:
            A single-line JSON string ending without a newline.
        """
        log_object: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        # Append any extra fields provided by the caller
        for key, value in record.__dict__.items():
            if key not in _INTERNAL_FIELDS and not key.startswith("_"):
                log_object[key] = value

        # Append formatted exception traceback if present
        if record.exc_info:
            log_object["exception"] = self.formatException(record.exc_info)

        # Use default=str to handle non-serialisable types gracefully
        return json.dumps(log_object, default=str)


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configure the root PhishGuard logger and return it.

    Should be called once at application startup. Subsequent calls to
    get_logger() return child loggers that inherit this configuration.

    Args:
        log_level: Logging verbosity. One of DEBUG | INFO | WARNING |
                   ERROR | CRITICAL. Case-insensitive.

    Returns:
        The configured root application logger.
    """
    logger = logging.getLogger("phishguard")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid adding duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JSONFormatter())
        logger.addHandler(handler)

    # Do not propagate to the root Python logger (avoids duplicate output)
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a named child logger under the PhishGuard namespace.

    Args:
        name: Dot-separated sub-name appended to 'phishguard.'.
              Example: 'forensics.rdap' → logger 'phishguard.forensics.rdap'.

    Returns:
        A Logger instance that inherits the JSON formatter from the root.
    """
    return logging.getLogger(f"phishguard.{name}")