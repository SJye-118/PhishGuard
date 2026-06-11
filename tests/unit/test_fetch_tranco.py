"""
Unit tests for scripts.fetch_tranco.
All HTTP calls are mocked. File I/O uses pytest's tmp_path fixture.
"""

from __future__ import annotations

import csv
import io
import zipfile
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.fetch_tranco import (
    _extract_csv_from_zip,
    _save_csv_with_header,
    fetch_tranco,
)

# Import the real constant only for reference in the module-level helpers
REAL_MIN_ROW_COUNT = 900_000


# ── Fixtures and helpers ─────────────────────────────────────────────────────

def _make_tranco_csv(rows: int = 100) -> str:
    """Generate a realistic Tranco CSV string without header."""
    lines = [f"{i},{chr(ord('a') + (i % 26))}domain{i}.com" for i in range(1, rows + 1)]
    return "\n".join(lines)


def _make_tranco_zip(csv_content: str, filename: str = "top-1m.csv") -> bytes:
    """Package CSV content into an in-memory ZIP archive."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, csv_content)
    return buffer.getvalue()


def _make_mock_response(content: bytes, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.content = content
    mock.raise_for_status = MagicMock()
    return mock


# ══════════════════════════════════════════════════════════════════════════════
# _extract_csv_from_zip  (unchanged — no MIN_ROW_COUNT dependency)
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractCsvFromZip:

    def test_extracts_csv_from_valid_zip(self) -> None:
        csv_content = "1,google.com\n2,youtube.com\n"
        result = _extract_csv_from_zip(_make_tranco_zip(csv_content))
        assert "google.com" in result

    def test_result_is_a_utf8_string(self) -> None:
        result = _extract_csv_from_zip(_make_tranco_zip("1,example.com\n"))
        assert isinstance(result, str)

    def test_raises_value_error_when_no_csv_in_zip(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "not a csv")
        with pytest.raises(ValueError, match="No CSV file"):
            _extract_csv_from_zip(buf.getvalue())

    def test_raises_value_error_for_invalid_zip_bytes(self) -> None:
        with pytest.raises(ValueError, match="not a valid ZIP"):
            _extract_csv_from_zip(b"this is not a zip file")

    def test_handles_unicode_domains(self) -> None:
        result = _extract_csv_from_zip(_make_tranco_zip("1,münchen.de\n"))
        assert isinstance(result, str)


# ══════════════════════════════════════════════════════════════════════════════
# _save_csv_with_header  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveCsvWithHeader:

    def test_adds_rank_domain_header_row(self, tmp_path: Path) -> None:
        output = tmp_path / "tranco_raw.csv"
        _save_csv_with_header("1,google.com\n2,youtube.com\n", output)
        with open(output, newline="", encoding="utf-8") as f:
            assert next(csv.reader(f)) == ["rank", "domain"]

    def test_returns_correct_data_row_count(self, tmp_path: Path) -> None:
        output = tmp_path / "out.csv"
        count = _save_csv_with_header(_make_tranco_csv(50), output)
        assert count == 50

    def test_header_not_counted_in_row_count(self, tmp_path: Path) -> None:
        output = tmp_path / "out.csv"
        count = _save_csv_with_header("1,example.com\n", output)
        assert count == 1

    def test_empty_rows_filtered(self, tmp_path: Path) -> None:
        output = tmp_path / "out.csv"
        count = _save_csv_with_header("1,google.com\n\n\n2,youtube.com\n", output)
        assert count == 2

    def test_domain_is_lowercased(self, tmp_path: Path) -> None:
        output = tmp_path / "out.csv"
        _save_csv_with_header("1,GOOGLE.COM\n", output)
        with open(output, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["domain"] == "google.com"


# ══════════════════════════════════════════════════════════════════════════════
# fetch_tranco  — FIX C-01: mock MIN_ROW_COUNT to avoid 901k-row generation
# ══════════════════════════════════════════════════════════════════════════════

class TestFetchTranco:
    """
    Uses monkeypatch to set MIN_ROW_COUNT=10 inside the module under test.
    This means _make_small_zip() only needs 15 rows to pass the threshold.
    The logical behaviour of the volume gate is still fully exercised.
    """

    # ── autouse fixture: replace the module-level constant ───────────────────
    @pytest.fixture(autouse=True)
    def mock_min_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Drop MIN_ROW_COUNT to 10 for every test in this class."""
        monkeypatch.setattr("scripts.fetch_tranco.MIN_ROW_COUNT", 10)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _make_small_zip(self, rows: int = 15) -> bytes:
        """15 rows easily passes the mocked threshold of 10."""
        return _make_tranco_zip(_make_tranco_csv(rows))

    def _patch_paths(self, mocker, tmp_path: Path):
        mocker.patch("scripts.fetch_tranco.DATA_RAW_DIR", tmp_path)
        mocker.patch("scripts.fetch_tranco.OUTPUT_FILE", tmp_path / "tranco_raw.csv")

    # ── tests ─────────────────────────────────────────────────────────────────
    def test_successful_fetch_returns_output_path(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            return_value=_make_mock_response(self._make_small_zip()),
        )
        result = fetch_tranco()
        assert result == tmp_path / "tranco_raw.csv"
        assert (tmp_path / "tranco_raw.csv").exists()

    def test_successful_fetch_creates_checksum_sidecar(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            return_value=_make_mock_response(self._make_small_zip()),
        )
        fetch_tranco()
        assert (tmp_path / "tranco_raw.csv.sha256").exists()

    def test_successful_fetch_creates_dated_backup(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            return_value=_make_mock_response(self._make_small_zip()),
        )
        fetch_tranco()
        assert (tmp_path / f"tranco_{date.today().isoformat()}.csv").exists()

    def test_uses_backup_when_download_fails(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        (tmp_path / "tranco_2026-01-01.csv").write_text("rank,domain\n1,google.com\n")
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            side_effect=RuntimeError("connection refused"),
        )
        result = fetch_tranco()
        assert result == tmp_path / "tranco_raw.csv"
        assert (tmp_path / "tranco_raw.csv").exists()

    def test_raises_when_no_backup_available(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            side_effect=RuntimeError("all attempts failed"),
        )
        with pytest.raises(RuntimeError, match="no backup"):
            fetch_tranco()

    def test_low_row_count_triggers_backup_not_crash(self, tmp_path, mocker) -> None:
        """5 rows < mocked MIN_ROW_COUNT of 10 → falls back to backup."""
        self._patch_paths(mocker, tmp_path)
        (tmp_path / "tranco_2026-01-01.csv").write_text("rank,domain\n1,google.com\n")
        too_small = _make_tranco_zip(_make_tranco_csv(rows=5))
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            return_value=_make_mock_response(too_small),
        )
        result = fetch_tranco()
        assert result == tmp_path / "tranco_raw.csv"

    def test_output_csv_has_correct_header(self, tmp_path, mocker) -> None:
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_tranco.download_with_retry",
            return_value=_make_mock_response(self._make_small_zip()),
        )
        fetch_tranco()
        with open(tmp_path / "tranco_raw.csv", newline="", encoding="utf-8") as f:
            assert next(csv.reader(f)) == ["rank", "domain"]