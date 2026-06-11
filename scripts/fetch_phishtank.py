"""
PhishGuard Enterprise — PhishTank Verified Phishing Feed Fetcher.

Phase 2 — Data Sourcing.

Downloads the PhishTank verified phishing URL feed and saves it as
data/raw/phishtank_raw.json for consumption by the Phase 3 normalisation
pipeline.

Output file format (data/raw/phishtank_raw.json):
  - JSON array of entry objects
  - All entries are filtered to verified=yes AND online=yes
  - Each entry has these fields:
      phish_id         : str  — PhishTank submission ID (empty for OpenPhish)
      url              : str  — Full phishing URL (e.g. "http://evil.com/paypal/login")
      submission_time  : str  — ISO 8601 datetime string (empty for OpenPhish)
      verification_time: str  — ISO 8601 datetime string (empty for OpenPhish)
      target           : str  — Impersonation target (e.g. "PayPal", empty for OpenPhish)
      source           : str  — "phishtank" or "openphish"
  - Minimum 20,000 entries guaranteed before saving

IMPORTANT — Asymmetry Leak note for Phase 3:
  Every entry's `url` field contains a FULL URL with path, query string,
  and scheme (e.g. "http://evil.com/paypal/login/verify?token=abc").
  Phase 3 MUST strip these to the registered domain only before training.
  The ML model is a Domain-Only Classifier.

Data attribution:
  PhishTank — https://www.phishtank.com
  Operated by Cisco Talos Intelligence Group.
  License: CC BY-SA 3.0

  OpenPhish — https://openphish.com (fallback source)
  Free community feed — no registration required.

Environment variables:
  PHISHTANK_API_KEY : PhishTank API key (optional, improves rate limits).
                      Register free at https://www.phishtank.com/api_info.php
  USE_OPENPHISH     : Set to "true" to use OpenPhish as the primary source.

DVC pipeline stage: fetch_phishtank
Invocation: python -m scripts.fetch_phishtank
       Via DVC: dvc repro fetch_phishtank
"""

from __future__ import annotations

import bz2
import json
import logging
import os
import shutil
from datetime import date, timedelta
from pathlib import Path

from scripts._common import (
    DataVolumeError,
    assert_min_rows,
    download_with_retry,
    find_latest_backup,
    save_checksum,
)

# ── Constants ────────────────────────────────────────────────────────────────

# PhishTank download URLs
_PHISHTANK_URL_AUTHENTICATED = (
    "https://data.phishtank.com/data/{api_key}/online-valid.json.bz2"
)
_PHISHTANK_URL_PUBLIC = (
    "https://data.phishtank.com/data/online-valid.json.bz2"
)

# OpenPhish free feed (one URL per line, updated every ~6 hours)
_OPENPHISH_URL = "https://openphish.com/feed.txt"

DATA_RAW_DIR = Path("data/raw")
OUTPUT_FILE = DATA_RAW_DIR / "phishtank_raw.json"

# Minimum verified+online entries after filtering
MIN_ROW_COUNT = 20_000

# Backup retention
BACKUP_RETENTION_DAYS = 7

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Source list builder
# ════════════════════════════════════════════════════════════════════════════

def _build_source_list() -> list[tuple[str, str]]:
    """Build the ordered list of (source_name, url) to attempt.

    Priority order:
      1. PhishTank with API key  (if PHISHTANK_API_KEY env var is set)
      2. PhishTank without key   (always attempted unless USE_OPENPHISH=true)
      3. OpenPhish               (fallback, or primary if USE_OPENPHISH=true)

    Returns:
        Ordered list of (name, url) tuples. The first that succeeds is used.
    """
    use_openphish_primary = (
        os.environ.get("USE_OPENPHISH", "false").strip().lower() == "true"
    )

    if use_openphish_primary:
        logger.info(
            "phishtank_source_override",
            extra={"reason": "USE_OPENPHISH=true"},
        )
        return [("OpenPhish", _OPENPHISH_URL)]

    sources: list[tuple[str, str]] = []

    api_key = os.environ.get("PHISHTANK_API_KEY", "").strip()
    if api_key:
        authenticated_url = _PHISHTANK_URL_AUTHENTICATED.format(api_key=api_key)
        sources.append(("PhishTank (authenticated)", authenticated_url))
        logger.debug("phishtank_api_key_found")
    else:
        logger.info(
            "phishtank_no_api_key",
            extra={
                "note": (
                    "PHISHTANK_API_KEY not set — using public endpoint. "
                    "Rate limits may apply. Register free at "
                    "https://www.phishtank.com/api_info.php"
                )
            },
        )

    sources.append(("PhishTank (public)", _PHISHTANK_URL_PUBLIC))
    sources.append(("OpenPhish (fallback)", _OPENPHISH_URL))

    return sources


# ════════════════════════════════════════════════════════════════════════════
# Main entry point
# ════════════════════════════════════════════════════════════════════════════

def fetch_phishtank() -> Path:
    """Download, filter, validate, and save the phishing URL dataset.

    Tries each source in the priority list. On success:
        1. Filters entries to verified + online only (PhishTank).
        2. Asserts entry count >= MIN_ROW_COUNT.
        3. Saves as a JSON array to data/raw/phishtank_raw.json.
        4. Computes and saves SHA-256 sidecar checksum.
        5. Creates a dated backup copy.
        6. Removes backups older than BACKUP_RETENTION_DAYS.

    If all sources fail, falls back to the most recent dated backup.

    Returns:
        Path to the saved (or restored) phishtank_raw.json file.

    Raises:
        RuntimeError: If all sources fail AND no backup exists.
    """
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)

    sources = _build_source_list()
    last_exc: Exception | None = None

    for source_name, url in sources:
        logger.info(
            "phishtank_source_attempt",
            extra={"source": source_name, "url": url},
        )
        try:
            entries = _download_and_parse(source_name, url)
            assert_min_rows(len(entries), MIN_ROW_COUNT, source_name, OUTPUT_FILE)

            _save_entries(entries, OUTPUT_FILE)
            digest = save_checksum(OUTPUT_FILE)
            _create_dated_backup(OUTPUT_FILE)
            _cleanup_old_backups()

            logger.info(
                "phishtank_fetch_complete",
                extra={
                    "source": source_name,
                    "entries": len(entries),
                    "sha256_prefix": digest[:16] + "...",
                    "output": str(OUTPUT_FILE),
                },
            )
            return OUTPUT_FILE

        except DataVolumeError as exc:
            logger.warning(
                "phishtank_volume_assertion_failed",
                extra={"source": source_name, "error": str(exc)},
            )
            last_exc = exc
            OUTPUT_FILE.unlink(missing_ok=True)
            continue

        except Exception as exc:
            logger.warning(
                "phishtank_source_failed",
                extra={
                    "source": source_name,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            last_exc = exc
            continue

    logger.error(
        "phishtank_all_sources_failed",
        extra={"sources_tried": [s for s, _ in sources]},
    )
    return _restore_from_backup()


# ════════════════════════════════════════════════════════════════════════════
# Download and parse dispatchers
# ════════════════════════════════════════════════════════════════════════════

def _download_and_parse(source_name: str, url: str) -> list[dict[str, str]]:
    """Download and parse phishing entries from a source URL.

    Dispatch is case-insensitive to guard against minor naming drift
    between _build_source_list() and this function.

    Args:
        source_name: Human-readable source identifier.
        url: The download URL.

    Returns:
        List of normalised entry dicts.

    Raises:
        ValueError: If no parser exists for the source_name.
        RuntimeError: If the download fails after all retries.
    """
    response = download_with_retry(url, timeout_seconds=120)
    name_lower = source_name.lower()

    # FIX H-02: case-insensitive dispatch prevents silent wrong-parser selection
    if "phishtank" in name_lower:
        return _parse_phishtank(response.content)
    elif "openphish" in name_lower:
        return _parse_openphish(response.text)
    else:
        raise ValueError(
            f"No parser registered for source: '{source_name}'. "
            f"Expected a name containing 'phishtank' or 'openphish'. "
            f"Update _download_and_parse() if adding a new source."
        )

# ════════════════════════════════════════════════════════════════════════════
# PhishTank parser
# ════════════════════════════════════════════════════════════════════════════

def _parse_phishtank(content: bytes) -> list[dict[str, str]]:
    """Parse a PhishTank bz2-compressed (or plain) JSON feed.

    PhishTank provides a JSON array of all submitted phishing entries.
    We filter to entries where BOTH conditions are true:
      - verified == "yes"   (manually confirmed as phishing by community)
      - online  == "yes"    (still live at time of data generation)

    This dual filter ensures we only train on confirmed, active phishing.

    Full PhishTank entry structure (we extract a subset):
      {
        "phish_id":          "7383428",
        "url":               "http://evil.com/paypal/login",
        "phish_detail_url":  "https://phishtank.org/phish_detail.php?...",
        "submission_time":   "2026-01-01T00:00:00+00:00",
        "verified":          "yes",
        "verification_time": "2026-01-01T00:01:00+00:00",
        "online":            "yes",
        "target":            "PayPal"
      }

    Args:
        content: Raw bytes from the PhishTank download (bz2 or plain JSON).

    Returns:
        List of filtered, normalised entry dicts.

    Raises:
        ValueError: On JSON parse failure or unexpected response structure.
    """
    # ── Decompress bz2 ────────────────────────────────────────────────────
    try:
        raw_bytes = bz2.decompress(content)
        logger.debug("phishtank_bz2_decompressed", extra={"original_bytes": len(content)})
    except OSError:
        # Some configurations serve uncompressed JSON — try as-is
        logger.debug(
            "phishtank_bz2_decompress_failed",
            extra={"note": "Attempting direct JSON parse of raw content"},
        )
        raw_bytes = content

    # ── Parse JSON ────────────────────────────────────────────────────────
    try:
        raw_entries: object = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"PhishTank JSON parse failed: {exc}. "
            f"Received {len(content):,} bytes (compressed), "
            f"{len(raw_bytes):,} bytes (decompressed). "
            "The upstream server may have returned an error document."
        ) from exc

    if not isinstance(raw_entries, list):
        raise ValueError(
            f"PhishTank response is not a JSON array. "
            f"Got type: {type(raw_entries).__name__}. "
            "PhishTank API may have changed its response format."
        )

    # ── Filter and normalise ──────────────────────────────────────────────
    retained: list[dict[str, str]] = []
    skipped_unverified = 0
    skipped_offline = 0

    for entry in raw_entries:
        verified = str(entry.get("verified", "")).strip().lower()
        online = str(entry.get("online", "")).strip().lower()

        if verified != "yes":
            skipped_unverified += 1
            continue
        if online != "yes":
            skipped_offline += 1
            continue

        url = str(entry.get("url", "")).strip()
        if not url:
            continue

        retained.append({
            "phish_id": str(entry.get("phish_id", "")),
            "url": url,
            "submission_time": str(entry.get("submission_time", "")),
            "verification_time": str(entry.get("verification_time", "")),
            "target": str(entry.get("target", "")),
            "source": "phishtank",
        })

    logger.info(
        "phishtank_filter_complete",
        extra={
            "total_entries": len(raw_entries),
            "retained": len(retained),
            "skipped_unverified": skipped_unverified,
            "skipped_offline": skipped_offline,
        },
    )
    return retained


# ════════════════════════════════════════════════════════════════════════════
# OpenPhish parser
# ════════════════════════════════════════════════════════════════════════════

def _parse_openphish(text: str) -> list[dict[str, str]]:
    """Parse an OpenPhish plain-text URL feed.

    OpenPhish provides one raw URL per line. Entries are algorithmically
    detected phishing URLs — not manually verified — but the feed is
    actively maintained and updated every ~6 hours.

    Normalised entries have the same structure as PhishTank entries so
    Phase 3 processes both sources identically. Fields not available in
    OpenPhish (phish_id, submission_time, verification_time, target) are
    stored as empty strings.

    Args:
        text: Raw response text with one URL per line.

    Returns:
        List of normalised entry dicts with source="openphish".
    """
    entries: list[dict[str, str]] = []
    skipped = 0

    for line in text.strip().splitlines():
        url = line.strip()

        if not url:
            skipped += 1
            continue

        # Only include HTTP/HTTPS URLs — skip comment lines or other data
        if not url.startswith(("http://", "https://")):
            skipped += 1
            continue

        entries.append({
            "phish_id": "",
            "url": url,
            "submission_time": "",
            "verification_time": "",
            "target": "",
            "source": "openphish",
        })

    logger.info(
        "openphish_parse_complete",
        extra={"retained": len(entries), "skipped_lines": skipped},
    )
    return entries


# ════════════════════════════════════════════════════════════════════════════
# File I/O helpers
# ════════════════════════════════════════════════════════════════════════════

def _save_entries(entries: list[dict[str, str]], output_path: Path) -> None:
    """Serialise the entry list to a JSON file.

    Uses indent=2 for human readability. ensure_ascii=False preserves
    any non-ASCII characters in domain names or target strings.

    Args:
        entries: List of normalised phishing entry dicts.
        output_path: Destination file path.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    logger.info(
        "phishtank_json_saved",
        extra={"entries": len(entries), "path": str(output_path)},
    )


def _create_dated_backup(source_path: Path) -> Path:
    """Copy the current output to a dated backup file.

    Naming: data/raw/phishtank_YYYY-MM-DD.json
    ISO 8601 ensures lexicographic == chronological order.

    Args:
        source_path: Path to the output file to back up.

    Returns:
        Path of the created backup file.
    """
    today = date.today().isoformat()
    backup_path = DATA_RAW_DIR / f"phishtank_{today}.json"
    shutil.copy2(source_path, backup_path)
    logger.info(
        "phishtank_backup_created",
        extra={"backup": backup_path.name},
    )
    return backup_path


def _cleanup_old_backups() -> None:
    """Remove PhishTank backup files older than BACKUP_RETENTION_DAYS."""
    cutoff = date.today() - timedelta(days=BACKUP_RETENTION_DAYS)

    for backup in DATA_RAW_DIR.glob("phishtank_????-??-??.json"):
        try:
            date_str = backup.stem.replace("phishtank_", "")
            file_date = date.fromisoformat(date_str)
            if file_date < cutoff:
                backup.unlink()
                logger.info(
                    "phishtank_backup_removed",
                    extra={
                        "backup": backup.name,
                        "age_days": (date.today() - file_date).days,
                    },
                )
        except ValueError:
            pass


def _restore_from_backup() -> Path:
    """Restore the most recent PhishTank backup as the current output.

    Returns:
        Path to the restored output file.

    Raises:
        RuntimeError: If no backup exists. Unrecoverable — pipeline halts.
    """
    backup = find_latest_backup(DATA_RAW_DIR, "phishtank_????-??-??.json")

    if backup is None:
        raise RuntimeError(
            "All phishing data sources FAILED and no backup exists in data/raw/. "
            "This is the first run with no fallback available. "
            "Actions to resolve:\n"
            "  1. Check internet connectivity.\n"
            "  2. Verify PhishTank: https://data.phishtank.com/data/online-valid.json.bz2\n"
            "  3. Verify OpenPhish: https://openphish.com/feed.txt\n"
            "  4. Set USE_OPENPHISH=true to use OpenPhish as primary source.\n"
            "  5. Register a free API key at https://www.phishtank.com/api_info.php"
        )

    logger.warning(
        "phishtank_restoring_from_backup",
        extra={"backup": backup.name},
    )
    shutil.copy2(backup, OUTPUT_FILE)
    return OUTPUT_FILE


# ════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        output = fetch_phishtank()
        print(f"SUCCESS: PhishTank data saved to {output}")
        sys.exit(0)
    except RuntimeError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)