"""
PhishGuard Enterprise — Shared Data Pipeline Utilities.

This module provides utilities used by all data fetch scripts:
  - HTTP download with exponential backoff retry
  - SHA-256 checksum computation and sidecar file management
  - Backup file discovery for graceful degradation
  - Data volume floor assertions for quality gates

Design principles:
  - All functions are pure and independently testable.
  - All network operations raise descriptive exceptions on failure
    so callers can implement their own recovery strategy.
  - All file operations use pathlib.Path throughout for consistency.

Imported by:
  scripts/fetch_tranco.py
  scripts/fetch_phishtank.py
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Generator

import requests

logger = logging.getLogger(__name__)

# ── HTTP headers sent with every download request ────────────────────────────
# A descriptive User-Agent is good practice and prevents some rate limiters
# from treating the script as a generic scraper.
_DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": (
        "PhishGuard-Enterprise/1.0 "
        "(https://github.com/yourusername/phishguard-enterprise; "
        "open-source student research project)"
    ),
    "Accept-Encoding": "gzip, deflate",
}


# ════════════════════════════════════════════════════════════════════════════
# HTTP Download
# ════════════════════════════════════════════════════════════════════════════

def download_with_retry(
    url: str,
    *,
    timeout_seconds: int = 120,
    max_attempts: int = 3,
    base_delay_seconds: float = 2.0,
    extra_headers: dict[str, str] | None = None,
) -> requests.Response:
    """Download a URL with exponential backoff retry logic.

    Attempts the download up to max_attempts times. Between each failed
    attempt, waits for an exponentially increasing delay:
        Attempt 1 → immediate
        Attempt 2 → sleep base_delay_seconds (2s)
        Attempt 3 → sleep base_delay_seconds * 2 (4s)
        Attempt N → sleep base_delay_seconds * 2^(N-2)

    The full response body is loaded into memory (stream=False) because
    both Tranco ZIP and PhishTank bz2 require in-memory decompression.
    File sizes are typically 5–20MB, which is safe to buffer.

    Args:
        url: The URL to download.
        timeout_seconds: Hard timeout per attempt in seconds.
        max_attempts: Maximum number of download attempts before giving up.
        base_delay_seconds: Initial retry delay in seconds (doubles each retry).
        extra_headers: Additional HTTP headers to merge with defaults.

    Returns:
        A requests.Response with the full body loaded (stream=False).

    Raises:
        RuntimeError: If all attempts are exhausted, with details of
                      the last encountered exception.
    """
    headers = {**_DEFAULT_HEADERS, **(extra_headers or {})}
    last_exception: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "download_attempt",
                extra={
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "url": url,
                },
            )
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout_seconds,
                stream=False,  # Load full body — needed for in-memory decompression
            )
            response.raise_for_status()
            logger.info(
                "download_success",
                extra={
                    "url": url,
                    "status_code": response.status_code,
                    "content_length_bytes": len(response.content),
                    "attempt": attempt,
                },
            )
            return response

        except requests.HTTPError as exc:
            last_exception = exc
            status = exc.response.status_code if exc.response is not None else "unknown"
            # 4xx errors (except 429 Too Many Requests) are unlikely to
            # recover on retry — log and re-raise immediately.
            if (
                exc.response is not None
                and 400 <= exc.response.status_code < 500
                and exc.response.status_code != 429
            ):
                raise RuntimeError(
                    f"HTTP {status} error for {url} — "
                    "not retrying on client error responses."
                ) from exc

        except requests.ConnectionError as exc:
            last_exception = exc
            logger.warning(
                "download_connection_error",
                extra={"url": url, "attempt": attempt, "error": str(exc)},
            )

        except requests.Timeout as exc:
            last_exception = exc
            logger.warning(
                "download_timeout",
                extra={
                    "url": url,
                    "attempt": attempt,
                    "timeout_seconds": timeout_seconds,
                },
            )

        except requests.RequestException as exc:
            last_exception = exc
            logger.warning(
                "download_request_error",
                extra={"url": url, "attempt": attempt, "error": str(exc)},
            )

        # Sleep before next attempt (no sleep after the final attempt)
        if attempt < max_attempts:
            delay = min(base_delay_seconds * (2 ** (attempt - 1)), 60.0)
            logger.info(
                "download_retry_backoff",
                extra={"attempt": attempt, "sleep_seconds": delay, "url": url},
            )
            time.sleep(delay)

    raise RuntimeError(
        f"All {max_attempts} download attempts failed for '{url}'. "
        f"Last error: {last_exception}"
    ) from last_exception


# ════════════════════════════════════════════════════════════════════════════
# SHA-256 Checksum Utilities
# ════════════════════════════════════════════════════════════════════════════

def compute_sha256(file_path: Path, chunk_size: int = 65_536) -> str:
    """Compute the SHA-256 hex digest of a file without loading it fully.

    Uses chunked reading so large files (>1GB) are handled safely.

    Args:
        file_path: Path to the file to hash.
        chunk_size: Read buffer size in bytes. Default: 64KB.

    Returns:
        Lowercase hexadecimal SHA-256 digest string (64 characters).

    Raises:
        FileNotFoundError: If file_path does not exist.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in _iter_file_chunks(f, chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def _iter_file_chunks(
    file_obj, chunk_size: int
) -> Generator[bytes, None, None]:
    """Yield successive chunks from an open binary file."""
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        yield chunk


def save_checksum(file_path: Path) -> str:
    """Compute the SHA-256 digest of a file and save it to a sidecar file.

    The sidecar file follows the BSD checksum convention:
        <64-char-hex-digest>  <filename>

    Example sidecar content for tranco_raw.csv.sha256:
        a379a6f6ee...  tranco_raw.csv

    Args:
        file_path: Path to the file to checksum.

    Returns:
        The computed SHA-256 hex digest string.
    """
    digest = compute_sha256(file_path)
    checksum_path = _checksum_path_for(file_path)
    checksum_path.write_text(
        f"{digest}  {file_path.name}\n",
        encoding="utf-8",
    )
    logger.info(
        "checksum_saved",
        extra={
            "file": file_path.name,
            "sha256_prefix": digest[:16] + "...",
            "sidecar": checksum_path.name,
        },
    )
    return digest


def verify_checksum(file_path: Path) -> bool:
    """Verify a file against its stored SHA-256 sidecar checksum.

    Args:
        file_path: Path to the file to verify.

    Returns:
        True if the file's computed digest matches the stored digest.
        False if the sidecar does not exist or the digest does not match.
    """
    checksum_path = _checksum_path_for(file_path)
    if not checksum_path.exists():
        return False

    try:
        stored_line = checksum_path.read_text(encoding="utf-8").strip()
        stored_digest = stored_line.split()[0]
    except (IndexError, OSError):
        return False

    computed = compute_sha256(file_path)
    return computed == stored_digest


def _checksum_path_for(file_path: Path) -> Path:
    """Return the expected sidecar checksum path for a given file.

    Convention: <filename>.<extension>.sha256
    Examples:
        tranco_raw.csv    → tranco_raw.csv.sha256
        phishtank_raw.json → phishtank_raw.json.sha256
    """
    return file_path.parent / (file_path.name + ".sha256")


# ════════════════════════════════════════════════════════════════════════════
# Backup File Discovery
# ════════════════════════════════════════════════════════════════════════════

def find_latest_backup(directory: Path, glob_pattern: str) -> Path | None:
    """Find the most recent backup file matching a glob pattern.

    Relies on ISO 8601 date format (YYYY-MM-DD) in filenames so that
    lexicographic sort equals chronological sort.

    Args:
        directory: Directory to search.
        glob_pattern: Glob pattern relative to directory.
                      Examples: "tranco_*.csv", "phishtank_*.json"

    Returns:
        Path to the most recent matching file, or None if no matches.
    """
    matches = sorted(directory.glob(glob_pattern), reverse=True)
    if matches:
        logger.debug(
            "backup_found",
            extra={"backup": matches[0].name, "total_backups": len(matches)},
        )
        return matches[0]
    return None


# ════════════════════════════════════════════════════════════════════════════
# Data Quality Assertions
# ════════════════════════════════════════════════════════════════════════════

def assert_min_rows(
    count: int,
    min_required: int,
    source_name: str,
    file_path: Path | None = None,
) -> None:
    """Assert that a dataset meets the minimum row count floor.

    This is a data quality gate. A count below the floor indicates
    a corrupted download, API schema change, or filtering bug.

    Args:
        count: Actual number of rows/entries in the dataset.
        min_required: Minimum acceptable row count.
        source_name: Human-readable name for the data source (for logging).
        file_path: Optional file path for inclusion in the error message.

    Raises:
        DataVolumeError: If count is below min_required.
    """
    if count < min_required:
        location = f" (file: {file_path})" if file_path else ""
        raise DataVolumeError(
            f"Data volume assertion FAILED for '{source_name}'{location}: "
            f"received {count:,} rows but minimum required is {min_required:,}. "
            "This may indicate a corrupted download or upstream API change. "
            "The previous backup will be used if available."
        )
    logger.info(
        "volume_assertion_passed",
        extra={
            "source": source_name,
            "count": count,
            "min_required": min_required,
        },
    )


class DataVolumeError(ValueError):
    """Raised when a downloaded dataset fails the minimum row count assertion.

    Inherits from ValueError so callers can catch it alongside other
    data validation errors without catching all exceptions broadly.
    """