"""
PhishGuard Enterprise — Tranco Top-1M Data Fetcher.

Phase 2 — Data Sourcing.

Downloads the Tranco Top-1M domain list, validates it, and saves it
to data/raw/tranco_raw.csv for consumption by the Phase 3 normalisation
pipeline.

Output file format (data/raw/tranco_raw.csv):
  - CSV with header row: rank,domain
  - rank: integer (1-based, ascending by global traffic rank)
  - domain: registered apex domain string (e.g. "google.com")
  - No path, scheme, or subdomain components
  - Minimum 900,000 rows guaranteed before saving

Example rows:
  rank,domain
  1,google.com
  2,youtube.com
  3,facebook.com

This is the benign training class (label 0) in Phase 3.

Data attribution:
  Tranco Top One Million — https://tranco-list.eu
  License: CC BY 4.0
  Cite the Tranco paper in any publication using this data.

DVC pipeline stage: fetch_tranco
Invocation: python -m scripts.fetch_tranco
       Via DVC: dvc repro fetch_tranco
"""

from __future__ import annotations

import csv
import io
import logging
import shutil
import zipfile
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

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"

DATA_RAW_DIR = Path("data/raw")
OUTPUT_FILE = DATA_RAW_DIR / "tranco_raw.csv"

# Minimum row count data quality gate (from params.yaml / documentation)
MIN_ROW_COUNT = 900_000

# Backup retention: keep the last 7 days of successful downloads
BACKUP_RETENTION_DAYS = 7

# Column names added as the CSV header row.
# The raw Tranco CSV has no header — we add one for self-documenting output
# so Phase 3 can use pd.read_csv() without supplying names= explicitly.
CSV_HEADER = ["rank", "domain"]

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# Main entry point
# ════════════════════════════════════════════════════════════════════════════

def fetch_tranco() -> Path:
    """Download, validate, and save the Tranco Top-1M domain list.

    Full execution sequence:
        1. Create data/raw/ directory if it does not exist.
        2. Download the ZIP archive from tranco-list.eu with retry logic.
        3. Extract the CSV file from the ZIP archive in memory.
        4. Add a header row (rank,domain) to make the file self-describing.
        5. Save to data/raw/tranco_raw.csv.
        6. Assert row count >= MIN_ROW_COUNT (900,000).
        7. Compute and save SHA-256 sidecar checksum.
        8. Copy to a dated backup: data/raw/tranco_YYYY-MM-DD.csv.
        9. Remove backup files older than BACKUP_RETENTION_DAYS.

    If any step from 2–5 fails, the function falls back to the most
    recent dated backup copy and returns that instead.

    Returns:
        Path to the saved (or restored) tranco_raw.csv file.

    Raises:
        RuntimeError: If all download attempts fail AND no backup exists.
                      This is an unrecoverable state — the pipeline halts.
    """
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)

    logger.info(
        "tranco_fetch_start",
        extra={"url": TRANCO_DOWNLOAD_URL, "output": str(OUTPUT_FILE)},
    )

    try:
        # ── Step 1: Download ─────────────────────────────────────────────
        response = download_with_retry(TRANCO_DOWNLOAD_URL, timeout_seconds=120)

        # ── Step 2: Extract CSV from ZIP ─────────────────────────────────
        csv_content = _extract_csv_from_zip(response.content)

        # ── Step 3: Save with header ─────────────────────────────────────
        row_count = _save_csv_with_header(csv_content, OUTPUT_FILE)

        # ── Step 4: Volume assertion ──────────────────────────────────────
        assert_min_rows(row_count, MIN_ROW_COUNT, "Tranco", OUTPUT_FILE)

        # ── Step 5: Checksum ─────────────────────────────────────────────
        digest = save_checksum(OUTPUT_FILE)

        # ── Step 6: Backup ───────────────────────────────────────────────
        _create_dated_backup(OUTPUT_FILE)

        # ── Step 7: Clean old backups ─────────────────────────────────────
        _cleanup_old_backups()

        logger.info(
            "tranco_fetch_complete",
            extra={
                "rows": row_count,
                "sha256_prefix": digest[:16] + "...",
                "output": str(OUTPUT_FILE),
            },
        )
        return OUTPUT_FILE

    except DataVolumeError as exc:
        logger.error(
            "tranco_volume_assertion_failed",
            extra={"error": str(exc)},
        )
        # Volume failure: the download succeeded but data is suspect.
        # Delete the under-filled file and restore from backup.
        OUTPUT_FILE.unlink(missing_ok=True)
        return _restore_from_backup()

    except Exception as exc:
        logger.error(
            "tranco_fetch_failed",
            extra={"error": str(exc), "error_type": type(exc).__name__},
        )
        return _restore_from_backup()


# ════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════════════

def _extract_csv_from_zip(zip_bytes: bytes) -> str:
    """Extract the CSV content from the Tranco ZIP archive.

    The Tranco ZIP always contains exactly one CSV file (top-1m.csv).
    We extract it into memory as a UTF-8 string without writing the
    ZIP to disk — this avoids leaving a temporary file behind.

    Args:
        zip_bytes: Raw bytes of the downloaded ZIP archive.

    Returns:
        Full CSV content as a UTF-8 decoded string.

    Raises:
        ValueError: If the ZIP contains no CSV files.
        zipfile.BadZipFile: If the bytes are not a valid ZIP archive.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            csv_names = [
                name for name in zf.namelist() if name.lower().endswith(".csv")
            ]

            if not csv_names:
                raise ValueError(
                    f"No CSV file found in Tranco ZIP archive. "
                    f"Archive contents: {zf.namelist()}"
                )

            if len(csv_names) > 1:
                logger.warning(
                    "tranco_zip_multiple_csvs",
                    extra={"csv_files": csv_names, "using": csv_names[0]},
                )

            csv_filename = csv_names[0]
            logger.debug(
                "tranco_zip_extracting",
                extra={"filename": csv_filename},
            )
            return zf.read(csv_filename).decode("utf-8", errors="replace")

    except zipfile.BadZipFile as exc:
        raise ValueError(
            f"Downloaded Tranco file is not a valid ZIP archive "
            f"({len(zip_bytes):,} bytes received). "
            "The upstream server may have returned an error page."
        ) from exc


def _save_csv_with_header(csv_content: str, output_path: Path) -> int:
    """Parse the raw Tranco CSV, add a header row, and write to disk.

    The raw Tranco CSV has no header row — it is plain rank,domain pairs.
    This function adds the header ['rank', 'domain'] so downstream
    code can read the file with pd.read_csv() without specifying names.

    Empty rows and rows with fewer than 2 columns are discarded silently.
    Only the first two columns are retained (rank and domain) even if
    the source changes to include additional columns in the future.

    Args:
        csv_content: Raw CSV text from the Tranco ZIP.
        output_path: Destination file path for the processed CSV.

    Returns:
        Number of data rows written (not counting the header row).
    """
    reader = csv.reader(io.StringIO(csv_content))
    data_rows: list[list[str]] = []

    for row in reader:
        # Skip empty rows and rows without both rank and domain
        if len(row) >= 2:
            rank_str = row[0].strip()
            domain_str = row[1].strip().lower()
            if rank_str and domain_str:
                data_rows.append([rank_str, domain_str])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)   # Header: rank,domain
        writer.writerows(data_rows)   # Data rows

    logger.info(
        "tranco_csv_saved",
        extra={"rows": len(data_rows), "path": str(output_path)},
    )
    return len(data_rows)


def _create_dated_backup(source_path: Path) -> Path:
    """Copy the current output file to a dated backup filename.

    Backup naming: data/raw/tranco_YYYY-MM-DD.csv
    ISO 8601 date format ensures lexicographic = chronological sort,
    which makes find_latest_backup() reliable.

    Args:
        source_path: Path to the current output file to back up.

    Returns:
        Path of the created backup file.
    """
    today = date.today().isoformat()  # YYYY-MM-DD
    backup_path = DATA_RAW_DIR / f"tranco_{today}.csv"
    shutil.copy2(source_path, backup_path)
    logger.info(
        "tranco_backup_created",
        extra={"backup": backup_path.name},
    )
    return backup_path


def _cleanup_old_backups() -> None:
    """Delete Tranco backup files older than BACKUP_RETENTION_DAYS.

    Only files matching the pattern tranco_YYYY-MM-DD.csv are touched.
    Files with non-date suffixes are left untouched.
    """
    cutoff = date.today() - timedelta(days=BACKUP_RETENTION_DAYS)

    for backup in DATA_RAW_DIR.glob("tranco_????-??-??.csv"):
        try:
            date_str = backup.stem.replace("tranco_", "")
            file_date = date.fromisoformat(date_str)
            if file_date < cutoff:
                backup.unlink()
                logger.info(
                    "tranco_backup_removed",
                    extra={"backup": backup.name, "age_days": (date.today() - file_date).days},
                )
        except ValueError:
            # Filename does not match expected date pattern — skip it
            logger.debug(
                "tranco_backup_skip_non_date",
                extra={"filename": backup.name},
            )


def _restore_from_backup() -> Path:
    """Restore the most recent Tranco backup as the current output file.

    Args: None

    Returns:
        Path to the restored output file (OUTPUT_FILE).

    Raises:
        RuntimeError: If no backup file exists. This is unrecoverable.
    """
    backup = find_latest_backup(DATA_RAW_DIR, "tranco_????-??-??.csv")

    if backup is None:
        raise RuntimeError(
            "Tranco download FAILED and no backup file exists in data/raw/. "
            "This is the first run with no fallback available. "
            "Actions to resolve:\n"
            "  1. Check internet connectivity.\n"
            "  2. Verify https://tranco-list.eu is reachable.\n"
            "  3. Try again: python -m scripts.fetch_tranco\n"
            "  4. Manually download from https://tranco-list.eu/top-1m.csv.zip"
        )

    logger.warning(
        "tranco_restoring_from_backup",
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
        output = fetch_tranco()
        print(f"SUCCESS: Tranco data saved to {output}")
        sys.exit(0)
    except RuntimeError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(1)