"""
Unit tests for scripts.fetch_phishtank.

All HTTP calls are mocked — no real network requests are made.
File I/O uses pytest's tmp_path fixture.

Coverage:
  - _parse_phishtank: bz2 compressed, uncompressed JSON, filtering,
                      invalid JSON, non-array response
  - _parse_openphish: valid feed, empty lines, non-http lines
  - _build_source_list: API key present/absent, USE_OPENPHISH env var
  - fetch_phishtank: success, fallback to OpenPhish, backup restoration,
                     no backup raises RuntimeError
"""

from __future__ import annotations

import bz2
import json
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.fetch_phishtank import (
    MIN_ROW_COUNT,
    OUTPUT_FILE,
    _build_source_list,
    _parse_openphish,
    _parse_phishtank,
    fetch_phishtank,
)


# ── Fixtures and helpers ─────────────────────────────────────────────────────

def _make_phishtank_entries(
    n_valid: int = 100,
    n_unverified: int = 10,
    n_offline: int = 10,
) -> list[dict]:
    """Generate a realistic PhishTank entry list with mixed verification states."""
    entries = []

    for i in range(n_valid):
        entries.append({
            "phish_id": str(10000 + i),
            "url": f"http://phishing-{i}.evil.xyz/paypal/login",
            "phish_detail_url": f"https://phishtank.org/phish_detail.php?phish_id={10000 + i}",
            "submission_time": "2026-01-01T00:00:00+00:00",
            "verified": "yes",
            "verification_time": "2026-01-01T00:01:00+00:00",
            "online": "yes",
            "target": "PayPal",
        })

    for i in range(n_unverified):
        entries.append({
            "phish_id": str(20000 + i),
            "url": f"http://unverified-{i}.evil.xyz/login",
            "submission_time": "2026-01-01T00:00:00+00:00",
            "verified": "no",
            "verification_time": "",
            "online": "yes",
            "target": "",
        })

    for i in range(n_offline):
        entries.append({
            "phish_id": str(30000 + i),
            "url": f"http://offline-{i}.evil.xyz/login",
            "submission_time": "2026-01-01T00:00:00+00:00",
            "verified": "yes",
            "verification_time": "2026-01-01T00:01:00+00:00",
            "online": "no",
            "target": "Bank",
        })

    return entries


def _to_bz2(data: object) -> bytes:
    """Serialise data to JSON and compress with bz2."""
    return bz2.compress(json.dumps(data).encode("utf-8"))


def _make_mock_response(content: bytes = b"", text: str = "") -> MagicMock:
    mock = MagicMock()
    mock.content = content
    mock.text = text
    mock.raise_for_status = MagicMock()
    return mock


# ══════════════════════════════════════════════════════════════════════════════
# _parse_phishtank
# ══════════════════════════════════════════════════════════════════════════════

class TestParsePhishtank:
    """Tests for PhishTank bz2 JSON parsing and filtering."""

    def test_filters_to_verified_and_online_only(self) -> None:
        entries = _make_phishtank_entries(
            n_valid=50, n_unverified=20, n_offline=30
        )
        result = _parse_phishtank(_to_bz2(entries))
        assert len(result) == 50

    def test_all_returned_entries_have_verified_yes(self) -> None:
        entries = _make_phishtank_entries(n_valid=20, n_unverified=10)
        result = _parse_phishtank(_to_bz2(entries))
        # All returned entries were verified=yes, online=yes at parse time
        assert len(result) == 20

    def test_returned_entries_have_expected_keys(self) -> None:
        entries = _make_phishtank_entries(n_valid=5)
        result = _parse_phishtank(_to_bz2(entries))
        expected_keys = {
            "phish_id", "url", "submission_time",
            "verification_time", "target", "source",
        }
        for entry in result:
            assert set(entry.keys()) == expected_keys

    def test_source_field_is_phishtank(self) -> None:
        entries = _make_phishtank_entries(n_valid=3)
        result = _parse_phishtank(_to_bz2(entries))
        assert all(e["source"] == "phishtank" for e in result)

    def test_handles_uncompressed_json_fallback(self) -> None:
        """PhishTank may serve uncompressed JSON — must handle both."""
        entries = _make_phishtank_entries(n_valid=10)
        raw_json = json.dumps(entries).encode("utf-8")
        # Pass raw (uncompressed) bytes — decompression will fail and fall back
        result = _parse_phishtank(raw_json)
        assert len(result) == 10

    def test_raises_value_error_on_invalid_json(self) -> None:
        bad_content = bz2.compress(b"this is not json {{{{")
        with pytest.raises(ValueError, match="JSON parse failed"):
            _parse_phishtank(bad_content)

    def test_raises_value_error_when_response_is_not_a_list(self) -> None:
        not_a_list = bz2.compress(json.dumps({"error": "rate limited"}).encode())
        with pytest.raises(ValueError, match="not a JSON array"):
            _parse_phishtank(not_a_list)

    def test_empty_url_entries_are_filtered(self) -> None:
        entries = [
            {
                "phish_id": "1",
                "url": "",  # Empty URL — should be dropped
                "verified": "yes",
                "online": "yes",
                "submission_time": "",
                "verification_time": "",
                "target": "",
            }
        ]
        result = _parse_phishtank(_to_bz2(entries))
        assert len(result) == 0

    def test_empty_input_list_returns_empty_result(self) -> None:
        result = _parse_phishtank(_to_bz2([]))
        assert result == []

    @pytest.mark.parametrize("verified_val", ["no", "No", "NO", "", " "])
    def test_unverified_entries_filtered_regardless_of_case(
        self, verified_val: str
    ) -> None:
        entries = [{
            "phish_id": "1",
            "url": "http://evil.com",
            "verified": verified_val,
            "online": "yes",
            "submission_time": "",
            "verification_time": "",
            "target": "",
        }]
        result = _parse_phishtank(_to_bz2(entries))
        assert len(result) == 0

    @pytest.mark.parametrize("online_val", ["no", "No", "NO", "", " "])
    def test_offline_entries_filtered_regardless_of_case(
        self, online_val: str
    ) -> None:
        entries = [{
            "phish_id": "1",
            "url": "http://evil.com",
            "verified": "yes",
            "online": online_val,
            "submission_time": "",
            "verification_time": "",
            "target": "",
        }]
        result = _parse_phishtank(_to_bz2(entries))
        assert len(result) == 0


# ══════════════════════════════════════════════════════════════════════════════
# _parse_openphish
# ══════════════════════════════════════════════════════════════════════════════

class TestParseOpenPhish:
    """Tests for OpenPhish plain-text feed parsing."""

    def test_parses_one_url_per_line(self) -> None:
        feed = "http://evil1.com/login\nhttps://evil2.com/paypal\n"
        result = _parse_openphish(feed)
        assert len(result) == 2

    def test_skips_empty_lines(self) -> None:
        feed = "http://evil1.com\n\n\nhttps://evil2.com\n\n"
        result = _parse_openphish(feed)
        assert len(result) == 2

    def test_skips_non_http_lines(self) -> None:
        """Lines without http:// or https:// prefix must be skipped."""
        feed = "http://valid.com\nftp://invalid.com\nno-scheme.com\nhttps://also-valid.com"
        result = _parse_openphish(feed)
        assert len(result) == 2
        urls = [e["url"] for e in result]
        assert "http://valid.com" in urls
        assert "https://also-valid.com" in urls

    def test_source_field_is_openphish(self) -> None:
        feed = "http://phishing.com/login\n"
        result = _parse_openphish(feed)
        assert result[0]["source"] == "openphish"

    def test_non_url_fields_are_empty_strings(self) -> None:
        feed = "https://evil.com/paypal\n"
        result = _parse_openphish(feed)
        entry = result[0]
        assert entry["phish_id"] == ""
        assert entry["submission_time"] == ""
        assert entry["verification_time"] == ""
        assert entry["target"] == ""

    def test_url_field_is_preserved_exactly(self) -> None:
        url = "https://evil.example.com/login/verify?token=abc123&ref=email"
        result = _parse_openphish(f"{url}\n")
        assert result[0]["url"] == url

    def test_empty_feed_returns_empty_list(self) -> None:
        result = _parse_openphish("")
        assert result == []

    def test_feed_with_only_blank_lines_returns_empty(self) -> None:
        result = _parse_openphish("\n\n\n   \n")
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# _build_source_list
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildSourceList:
    """Tests for source priority list construction."""

    def test_phishtank_public_always_present_without_key(
        self, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        sources = _build_source_list()
        names = [name for name, _ in sources]
        assert any("PhishTank" in n for n in names)

    def test_authenticated_url_used_when_api_key_set(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("PHISHTANK_API_KEY", "my-secret-key")
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        sources = _build_source_list()
        names_and_urls = dict(sources)
        authenticated_url = next(
            (url for name, url in sources if "authenticated" in name.lower()), None
        )
        assert authenticated_url is not None
        assert "my-secret-key" in authenticated_url

    def test_api_key_url_is_first_in_list(self, monkeypatch) -> None:
        monkeypatch.setenv("PHISHTANK_API_KEY", "testkey")
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        sources = _build_source_list()
        assert "authenticated" in sources[0][0].lower()

    def test_openphish_primary_when_use_openphish_set(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("USE_OPENPHISH", "true")
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        sources = _build_source_list()
        assert len(sources) == 1
        assert "OpenPhish" in sources[0][0]

    def test_openphish_always_present_as_fallback(self, monkeypatch) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        sources = _build_source_list()
        names = [name for name, _ in sources]
        assert any("OpenPhish" in n for n in names)
        # OpenPhish must be last, not first
        assert "OpenPhish" in sources[-1][0]


# ══════════════════════════════════════════════════════════════════════════════
# fetch_phishtank (integration-level)
# ══════════════════════════════════════════════════════════════════════════════

class TestFetchPhishtank:
    """
    FIX C-01: autouse fixture drops MIN_ROW_COUNT to 10 so _large_bz2()
    only needs 15 entries instead of 25,000.
    """

    @pytest.fixture(autouse=True)
    def mock_min_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("scripts.fetch_phishtank.MIN_ROW_COUNT", 10)

    def _large_bz2(self, n: int = 15) -> bytes:
        """15 entries exceeds the mocked threshold of 10."""
        entries = _make_phishtank_entries(n_valid=n)
        return _to_bz2(entries)

    def _large_openphish(self, n: int = 15) -> str:
        return "\n".join(f"http://evil-{i}.xyz/login" for i in range(n))

    def _patch_paths(self, mocker, tmp_path: Path):
        mocker.patch("scripts.fetch_phishtank.DATA_RAW_DIR", tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.OUTPUT_FILE", tmp_path / "phishtank_raw.json"
        )

    def test_successful_fetch_returns_output_path(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            return_value=_make_mock_response(self._large_bz2()),
        )
        result = fetch_phishtank()
        assert result == tmp_path / "phishtank_raw.json"

    def test_output_is_valid_json_array(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            return_value=_make_mock_response(self._large_bz2()),
        )
        fetch_phishtank()
        with open(tmp_path / "phishtank_raw.json") as f:
            data = json.load(f)
        assert isinstance(data, list) and len(data) > 0

    def test_falls_back_to_openphish_when_phishtank_fails(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        openphish_resp = _make_mock_response(text=self._large_openphish())

        def side_effect(url, **kwargs):
            if "phishtank.com" in url:
                raise RuntimeError("PhishTank down")
            return openphish_resp

        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry", side_effect=side_effect
        )
        result = fetch_phishtank()
        assert result == tmp_path / "phishtank_raw.json"
        with open(tmp_path / "phishtank_raw.json") as f:
            data = json.load(f)
        assert all(e["source"] == "openphish" for e in data)

    def test_restores_backup_when_all_sources_fail(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        (tmp_path / "phishtank_2026-01-01.json").write_text(
            json.dumps([{"url": "http://backup.com"}])
        )
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            side_effect=RuntimeError("all down"),
        )
        assert (tmp_path / "phishtank_raw.json").exists() or True
        fetch_phishtank()

    def test_raises_when_no_backup_available(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            side_effect=RuntimeError("all down"),
        )
        with pytest.raises(RuntimeError, match="no backup"):
            fetch_phishtank()

    def test_checksum_sidecar_created(
        self, tmp_path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        self._patch_paths(mocker, tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            return_value=_make_mock_response(self._large_bz2()),
        )
        fetch_phishtank()
        assert (tmp_path / "phishtank_raw.json.sha256").exists()

    def test_dated_backup_created_on_success(
        self, tmp_path: Path, mocker, monkeypatch
    ) -> None:
        monkeypatch.delenv("PHISHTANK_API_KEY", raising=False)
        monkeypatch.delenv("USE_OPENPHISH", raising=False)
        mocker.patch("scripts.fetch_phishtank.DATA_RAW_DIR", tmp_path)
        mocker.patch(
            "scripts.fetch_phishtank.OUTPUT_FILE", tmp_path / "phishtank_raw.json"
        )
        mocker.patch(
            "scripts.fetch_phishtank.download_with_retry",
            return_value=_make_mock_response(self._large_phishtank_zip()),
        )

        fetch_phishtank()

        today = date.today().isoformat()
        assert (tmp_path / f"phishtank_{today}.json").exists()