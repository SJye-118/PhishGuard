
"""
Unit tests for scripts._common — shared data pipeline utilities.

All tests are self-contained with no network calls or real file I/O
beyond what pytest's tmp_path fixture provides.

Coverage targets:
  - compute_sha256: known content, empty file, binary content
  - save_checksum: sidecar file created, content format correct
  - verify_checksum: match, mismatch, missing sidecar
  - find_latest_backup: ordering, no matches, empty dir
  - assert_min_rows: passes at min, passes above, fails below
  - download_with_retry: success first attempt, retry on error,
                          exhausted retries, 4xx immediate fail
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts._common import (
    DataVolumeError,
    assert_min_rows,
    compute_sha256,
    download_with_retry,
    find_latest_backup,
    save_checksum,
    verify_checksum,
)


# ══════════════════════════════════════════════════════════════════════════════
# compute_sha256
# ══════════════════════════════════════════════════════════════════════════════

class TestComputeSha256:
    """Tests for SHA-256 digest computation."""

    def test_known_content_produces_correct_digest(self, tmp_path: Path) -> None:
        """Verify against a pre-computed SHA-256 digest."""
        content = b"hello, phishguard"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "test.txt"
        f.write_bytes(content)
        assert compute_sha256(f) == expected

    def test_empty_file_produces_known_digest(self, tmp_path: Path) -> None:
        """SHA-256 of empty content is a known constant."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_sha256(f) == expected

    def test_binary_content_handled(self, tmp_path: Path) -> None:
        """Binary data with null bytes must not crash the hasher."""
        content = bytes(range(256)) * 100
        f = tmp_path / "binary.bin"
        f.write_bytes(content)
        result = compute_sha256(f)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_content_produces_different_digest(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"content_a")
        f2.write_bytes(b"content_b")
        assert compute_sha256(f1) != compute_sha256(f2)

    def test_same_content_produces_same_digest(self, tmp_path: Path) -> None:
        f1 = tmp_path / "x.txt"
        f2 = tmp_path / "y.txt"
        content = b"identical content"
        f1.write_bytes(content)
        f2.write_bytes(content)
        assert compute_sha256(f1) == compute_sha256(f2)

    def test_raises_when_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            compute_sha256(tmp_path / "nonexistent.txt")


# ══════════════════════════════════════════════════════════════════════════════
# save_checksum and verify_checksum
# ══════════════════════════════════════════════════════════════════════════════

class TestChecksumSidecar:
    """Tests for sidecar checksum file creation and verification."""

    def test_save_creates_sidecar_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_bytes(b"rank,domain\n1,google.com\n")
        save_checksum(f)
        sidecar = tmp_path / "data.csv.sha256"
        assert sidecar.exists()

    def test_sidecar_contains_hex_digest_and_filename(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_bytes(b"test content")
        save_checksum(f)
        sidecar = tmp_path / "data.csv.sha256"
        content = sidecar.read_text()
        parts = content.strip().split()
        assert len(parts) == 2
        assert len(parts[0]) == 64                   # SHA-256 hex digest length
        assert parts[1] == "data.csv"                # Filename without directory

    def test_save_returns_correct_digest(self, tmp_path: Path) -> None:
        content = b"checksum test content"
        f = tmp_path / "file.json"
        f.write_bytes(content)
        returned_digest = save_checksum(f)
        expected_digest = hashlib.sha256(content).hexdigest()
        assert returned_digest == expected_digest

    def test_verify_passes_for_unmodified_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_bytes(b"original content")
        save_checksum(f)
        assert verify_checksum(f) is True

    def test_verify_fails_for_modified_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_bytes(b"original content")
        save_checksum(f)
        f.write_bytes(b"tampered content")
        assert verify_checksum(f) is False

    def test_verify_returns_false_when_no_sidecar(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_bytes(b"some content")
        # No save_checksum call — sidecar does not exist
        assert verify_checksum(f) is False

    def test_sidecar_naming_convention(self, tmp_path: Path) -> None:
        """Sidecar should be <filename>.sha256, not replace the extension."""
        f = tmp_path / "tranco_raw.csv"
        f.write_bytes(b"data")
        save_checksum(f)
        # Sidecar should be tranco_raw.csv.sha256, NOT tranco_raw.sha256
        assert (tmp_path / "tranco_raw.csv.sha256").exists()
        assert not (tmp_path / "tranco_raw.sha256").exists()


# ══════════════════════════════════════════════════════════════════════════════
# find_latest_backup
# ══════════════════════════════════════════════════════════════════════════════

class TestFindLatestBackup:
    """Tests for backup discovery and chronological ordering."""

    def test_returns_none_for_empty_directory(self, tmp_path: Path) -> None:
        result = find_latest_backup(tmp_path, "tranco_*.csv")
        assert result is None

    def test_returns_none_when_no_pattern_matches(self, tmp_path: Path) -> None:
        (tmp_path / "other_file.csv").touch()
        result = find_latest_backup(tmp_path, "tranco_*.csv")
        assert result is None

    def test_returns_single_matching_file(self, tmp_path: Path) -> None:
        backup = tmp_path / "tranco_2026-01-01.csv"
        backup.touch()
        result = find_latest_backup(tmp_path, "tranco_*.csv")
        assert result == backup

    def test_returns_most_recent_of_multiple_backups(self, tmp_path: Path) -> None:
        """ISO 8601 dates: lexicographic order == chronological order."""
        (tmp_path / "tranco_2026-01-01.csv").touch()
        (tmp_path / "tranco_2026-01-03.csv").touch()
        (tmp_path / "tranco_2026-01-02.csv").touch()
        result = find_latest_backup(tmp_path, "tranco_*.csv")
        assert result is not None
        assert result.name == "tranco_2026-01-03.csv"

    def test_glob_pattern_is_specific_to_source(self, tmp_path: Path) -> None:
        """Tranco pattern must not match PhishTank backups and vice versa."""
        (tmp_path / "tranco_2026-01-05.csv").touch()
        (tmp_path / "phishtank_2026-01-10.json").touch()

        tranco_result = find_latest_backup(tmp_path, "tranco_????-??-??.csv")
        phishtank_result = find_latest_backup(tmp_path, "phishtank_????-??-??.json")

        assert tranco_result is not None
        assert tranco_result.name == "tranco_2026-01-05.csv"
        assert phishtank_result is not None
        assert phishtank_result.name == "phishtank_2026-01-10.json"

    def test_does_not_return_non_matching_files(self, tmp_path: Path) -> None:
        """Current output file must not be returned as a backup."""
        (tmp_path / "tranco_raw.csv").touch()         # Current output
        (tmp_path / "tranco_2026-01-01.csv").touch()  # Backup
        result = find_latest_backup(tmp_path, "tranco_????-??-??.csv")
        assert result is not None
        assert result.name == "tranco_2026-01-01.csv"


# ══════════════════════════════════════════════════════════════════════════════
# assert_min_rows
# ══════════════════════════════════════════════════════════════════════════════

class TestAssertMinRows:
    """Tests for the data volume floor assertion."""

    def test_passes_when_count_equals_minimum(self) -> None:
        # Should not raise
        assert_min_rows(900_000, 900_000, "Tranco")

    def test_passes_when_count_exceeds_minimum(self) -> None:
        assert_min_rows(1_000_000, 900_000, "Tranco")

    def test_raises_when_count_below_minimum(self) -> None:
        with pytest.raises(DataVolumeError) as exc_info:
            assert_min_rows(500_000, 900_000, "Tranco")
        assert "500,000" in str(exc_info.value)
        assert "900,000" in str(exc_info.value)
        assert "Tranco" in str(exc_info.value)

    def test_raises_with_source_name_in_message(self) -> None:
        with pytest.raises(DataVolumeError) as exc_info:
            assert_min_rows(100, 20_000, "PhishTank")
        assert "PhishTank" in str(exc_info.value)

    def test_raises_with_file_path_in_message_when_provided(
        self, tmp_path: Path
    ) -> None:
        fake_path = tmp_path / "data.csv"
        with pytest.raises(DataVolumeError) as exc_info:
            assert_min_rows(100, 20_000, "Tranco", file_path=fake_path)
        assert "data.csv" in str(exc_info.value)

    def test_zero_count_raises(self) -> None:
        with pytest.raises(DataVolumeError):
            assert_min_rows(0, 1, "TestSource")

    def test_error_inherits_from_value_error(self) -> None:
        """DataVolumeError must be catchable as ValueError for caller convenience."""
        with pytest.raises(ValueError):
            assert_min_rows(0, 1, "TestSource")


# ══════════════════════════════════════════════════════════════════════════════
# download_with_retry
# ══════════════════════════════════════════════════════════════════════════════

class TestDownloadWithRetry:
    """Tests for HTTP download with exponential backoff retry."""

    def _make_mock_response(
        self,
        status_code: int = 200,
        content: bytes = b"data",
    ) -> MagicMock:
        """Create a mock requests.Response with specified attributes."""
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = status_code
        mock_resp.content = content
        mock_resp.raise_for_status = MagicMock()
        if status_code >= 400:
            http_error = requests.HTTPError(response=mock_resp)
            mock_resp.raise_for_status.side_effect = http_error
        return mock_resp

    def test_returns_response_on_first_success(self, mocker) -> None:
        mock_get = mocker.patch("scripts._common.requests.get")
        mock_get.return_value = self._make_mock_response(200, b"csv data")

        response = download_with_retry("https://example.com/data.csv")

        assert response.content == b"csv data"
        assert mock_get.call_count == 1

    def test_retries_on_connection_error_then_succeeds(self, mocker) -> None:
        mock_get = mocker.patch("scripts._common.requests.get")
        mock_sleep = mocker.patch("scripts._common.time.sleep")

        mock_get.side_effect = [
            requests.ConnectionError("connection refused"),
            self._make_mock_response(200, b"success"),
        ]

        response = download_with_retry(
            "https://example.com",
            max_attempts=3,
            base_delay_seconds=1.0,
        )

        assert response.content == b"success"
        assert mock_get.call_count == 2
        # Sleep called once between attempt 1 and attempt 2
        mock_sleep.assert_called_once_with(1.0)

    def test_retries_on_timeout_then_succeeds(self, mocker) -> None:
        mock_get = mocker.patch("scripts._common.requests.get")
        mock_sleep = mocker.patch("scripts._common.time.sleep")

        mock_get.side_effect = [
            requests.Timeout("request timed out"),
            requests.Timeout("request timed out"),
            self._make_mock_response(200, b"finally"),
        ]

        response = download_with_retry(
            "https://example.com",
            max_attempts=3,
            base_delay_seconds=2.0,
        )

        assert response.content == b"finally"
        assert mock_get.call_count == 3
        # Delays: 2.0s after attempt 1, 4.0s after attempt 2
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(2.0)
        mock_sleep.assert_any_call(4.0)

    def test_raises_runtime_error_after_all_attempts_exhausted(self, mocker) -> None:
        mock_get = mocker.patch("scripts._common.requests.get")
        mocker.patch("scripts._common.time.sleep")

        mock_get.side_effect = requests.ConnectionError("always fails")

        with pytest.raises(RuntimeError) as exc_info:
            download_with_retry("https://example.com", max_attempts=3)

        assert "3" in str(exc_info.value)
        assert mock_get.call_count == 3

    def test_does_not_retry_on_4xx_client_error(self, mocker) -> None:
        """A 404 Not Found indicates a configuration error — retry is pointless."""
        mock_get = mocker.patch("scripts._common.requests.get")
        mocker.patch("scripts._common.time.sleep")

        mock_get.return_value = self._make_mock_response(404)

        with pytest.raises(RuntimeError) as exc_info:
            download_with_retry("https://example.com/notfound", max_attempts=3)

        assert "404" in str(exc_info.value)
        # Must not retry on 4xx
        assert mock_get.call_count == 1

    def test_retries_on_429_too_many_requests(self, mocker) -> None:
        """429 Too Many Requests is a rate limit — retrying after backoff makes sense."""
        mock_get = mocker.patch("scripts._common.requests.get")
        mocker.patch("scripts._common.time.sleep")

        # 429 response object
        rate_limit_resp = MagicMock(spec=requests.Response)
        rate_limit_resp.status_code = 429
        rate_limit_resp.raise_for_status.side_effect = requests.HTTPError(
            response=rate_limit_resp
        )

        mock_get.side_effect = [
            rate_limit_resp,
            self._make_mock_response(200, b"ok"),
        ]

        response = download_with_retry("https://example.com", max_attempts=3)
        assert response.content == b"ok"
        assert mock_get.call_count == 2

    def test_no_sleep_after_final_failed_attempt(self, mocker) -> None:
        """Sleep must not be called after the last attempt — it's wasted time."""
        mock_get = mocker.patch("scripts._common.requests.get")
        mock_sleep = mocker.patch("scripts._common.time.sleep")

        mock_get.side_effect = requests.Timeout("always")

        with pytest.raises(RuntimeError):
            download_with_retry(
                "https://example.com",
                max_attempts=2,
                base_delay_seconds=5.0,
            )

        # Only 1 sleep: between attempt 1 and attempt 2
        # No sleep after final attempt 2
        assert mock_sleep.call_count == 1

    def test_exponential_backoff_delay_values(self, mocker) -> None:
        """Verify exact delay values for 4-attempt configuration."""
        mock_get = mocker.patch("scripts._common.requests.get")
        mock_sleep = mocker.patch("scripts._common.time.sleep")

        mock_get.side_effect = requests.Timeout("always fails")

        with pytest.raises(RuntimeError):
            download_with_retry(
                "https://example.com",
                max_attempts=4,
                base_delay_seconds=2.0,
            )

        sleep_calls = [call.args[0] for call in mock_sleep.call_args_list]
        # After attempt 1: 2.0s, after attempt 2: 4.0s, after attempt 3: 8.0s
        assert sleep_calls == [2.0, 4.0, 8.0]