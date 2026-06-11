"""
Unit tests for phishguard.utils.url_parser.

Tests cover:
  - URL normalisation (scheme injection)
  - Domain extraction (including the critical deceptive subdomain case)
  - IPv4 address detection
  - Punycode / IDN detection
  - Cache key computation
  - Full url_info dictionary extraction

Every test is independent with no external I/O or network calls.
tldextract uses a bundled snapshot of the Public Suffix List for tests.
"""

from __future__ import annotations

import hashlib

import pytest

from phishguard.utils.url_parser import (
    compute_cache_key,
    extract_domain,
    extract_url_info,
    is_ip_address,
    is_punycode_encoded,
    normalise_url,
)


# ══════════════════════════════════════════════════════════════════════════════
# normalise_url
# ══════════════════════════════════════════════════════════════════════════════

class TestNormaliseUrl:
    """Tests for scheme injection and whitespace stripping."""

    def test_adds_https_to_bare_domain(self) -> None:
        assert normalise_url("example.com") == "https://example.com"

    def test_preserves_existing_https(self) -> None:
        assert normalise_url("https://example.com") == "https://example.com"

    def test_preserves_existing_http(self) -> None:
        assert normalise_url("http://example.com") == "http://example.com"

    def test_strips_leading_and_trailing_whitespace(self) -> None:
        assert normalise_url("  example.com  ") == "https://example.com"

    def test_preserves_path_after_adding_scheme(self) -> None:
        result = normalise_url("example.com/login/verify")
        assert result == "https://example.com/login/verify"

    def test_preserves_query_string_after_adding_scheme(self) -> None:
        result = normalise_url("example.com?ref=email")
        assert result == "https://example.com?ref=email"

    def test_handles_ftp_scheme(self) -> None:
        assert normalise_url("ftp://files.example.com") == "ftp://files.example.com"


# ══════════════════════════════════════════════════════════════════════════════
# extract_domain
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractDomain:
    """Tests for registered domain extraction.

    The most critical test is test_deceptive_subdomain_chain — this is the
    exact attack pattern that naive string-splitting on '.' would miss.
    """

    def test_apex_domain_unchanged(self) -> None:
        assert extract_domain("https://example.com") == "example.com"

    def test_www_subdomain_stripped(self) -> None:
        assert extract_domain("https://www.example.com") == "example.com"

    def test_deep_path_stripped(self) -> None:
        """Path must never influence the registered domain."""
        result = extract_domain("https://evil.com/paypal/login/verify")
        assert result == "evil.com"

    def test_query_string_stripped(self) -> None:
        result = extract_domain("https://evil.com?redirect=paypal.com")
        assert result == "evil.com"

    @pytest.mark.parametrize(
        "url,expected",
        [
            # THE critical test — deceptive subdomain chain
            (
                "https://signin.paypal.com.updates-verify.info",
                "updates-verify.info",
            ),
            # Deep chain with many subdomain levels
            (
                "https://www.secure.login.paypal.com.evil-host.xyz/account",
                "evil-host.xyz",
            ),
        ],
    )
    def test_deceptive_subdomain_chain(self, url: str, expected: str) -> None:
        """Critical: tldextract must use the PSL to find the REAL registered domain.

        A naive split on '.' would return 'paypal' as the domain — wrong.
        tldextract uses the Mozilla Public Suffix List to find the correct
        boundary, returning the actual registrant-controlled domain.
        """
        assert extract_domain(url) == expected

    def test_compound_tld_co_uk(self) -> None:
        """tldextract must correctly handle compound TLDs like .co.uk."""
        result = extract_domain("https://example.co.uk")
        assert result == "example.co.uk"

    def test_compound_tld_com_au(self) -> None:
        assert extract_domain("https://www.example.com.au") == "example.com.au"

    def test_result_is_always_lowercase(self) -> None:
        assert extract_domain("https://EXAMPLE.COM") == "example.com"

    def test_raw_ip_address_returned_directly(self) -> None:
        """IP addresses bypass tldextract and are returned as-is."""
        result = extract_domain("http://192.168.1.1/login")
        assert result == "192.168.1.1"

    @pytest.mark.parametrize(
        "url",
        [
            "example.com",
            "EXAMPLE.COM",
            "http://example.com",
            "https://www.example.com/path?q=1#fragment",
        ],
    )
    def test_all_forms_of_example_com_resolve_consistently(self, url: str) -> None:
        """Different representations of the same domain must resolve identically."""
        assert extract_domain(url) == "example.com"


# ══════════════════════════════════════════════════════════════════════════════
# is_ip_address
# ══════════════════════════════════════════════════════════════════════════════

class TestIsIpAddress:
    """Tests for IPv4 address detection."""

    @pytest.mark.parametrize(
        "value",
        ["192.168.1.1", "10.0.0.1", "255.255.255.255", "0.0.0.0", "8.8.8.8"],
    )
    def test_valid_ipv4_addresses(self, value: str) -> None:
        assert is_ip_address(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "256.0.0.1",       # Octet out of range
            "192.168.1",       # Only three octets
            "example.com",     # Domain, not IP
            "192.168.1.1.5",   # Five octets
            "abc.def.ghi.jkl", # Non-numeric
            "",                # Empty string
        ],
    )
    def test_invalid_or_non_ip_values(self, value: str) -> None:
        assert is_ip_address(value) is False


# ══════════════════════════════════════════════════════════════════════════════
# is_punycode_encoded
# ══════════════════════════════════════════════════════════════════════════════

class TestIsPunycodeEncoded:
    """Tests for IDN homograph / Punycode detection."""

    def test_punycode_domain_detected(self) -> None:
        # xn--pypl-roa.com is a Punycode encoding of pаypal.com (Cyrillic а)
        assert is_punycode_encoded("xn--pypl-roa.com") is True

    def test_punycode_in_subdomain_detected(self) -> None:
        assert is_punycode_encoded("xn--googl-zra.com") is True

    def test_standard_ascii_domain_not_punycode(self) -> None:
        assert is_punycode_encoded("example.com") is False

    def test_domain_with_hyphens_not_punycode(self) -> None:
        """Hyphens alone do not make a Punycode domain — must have xn-- prefix."""
        assert is_punycode_encoded("my-domain.com") is False

    def test_uppercase_xn_prefix_detected(self) -> None:
        """Punycode detection must be case-insensitive."""
        assert is_punycode_encoded("XN--PYPL-ROA.COM") is True


# ══════════════════════════════════════════════════════════════════════════════
# compute_cache_key
# ══════════════════════════════════════════════════════════════════════════════

class TestComputeCacheKey:
    """Tests for Redis cache key generation."""

    def test_key_has_version_prefix(self) -> None:
        key = compute_cache_key("example.com")
        assert key.startswith("v1:")

    def test_key_has_correct_total_length(self) -> None:
        # "v1:" (3) + SHA-256 hex digest (64) = 67 characters
        key = compute_cache_key("example.com")
        assert len(key) == 67

    def test_key_is_case_insensitive(self) -> None:
        """Cache keys for the same domain in different cases must be identical."""
        assert compute_cache_key("Example.COM") == compute_cache_key("example.com")

    def test_key_is_deterministic(self) -> None:
        """Same input must always produce the same key."""
        assert compute_cache_key("example.com") == compute_cache_key("example.com")

    def test_different_domains_produce_different_keys(self) -> None:
        assert compute_cache_key("evil.com") != compute_cache_key("example.com")

    def test_sha256_digest_is_correct(self) -> None:
        """Manually verify the SHA-256 calculation."""
        domain = "example.com"
        expected_digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()
        assert compute_cache_key(domain) == f"v1:{expected_digest}"


# ══════════════════════════════════════════════════════════════════════════════
# extract_url_info
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractUrlInfo:
    """Tests for the full URL info dictionary extraction."""

    def test_returns_expected_keys(self) -> None:
        info = extract_url_info("https://example.com")
        expected_keys = {
            "original_url", "normalised_url", "scheme", "hostname",
            "registered_domain", "subdomain", "suffix", "is_ip_address",
            "is_punycode", "has_path", "has_query", "cache_key",
        }
        assert set(info.keys()) == expected_keys

    def test_original_url_preserved(self) -> None:
        url = "https://www.example.com/login?ref=email"
        info = extract_url_info(url)
        assert info["original_url"] == url

    def test_registered_domain_extracted(self) -> None:
        info = extract_url_info("https://www.example.com/path")
        assert info["registered_domain"] == "example.com"

    def test_has_path_true_for_non_root(self) -> None:
        info = extract_url_info("https://example.com/login")
        assert info["has_path"] is True

    def test_has_path_false_for_root(self) -> None:
        info = extract_url_info("https://example.com")
        assert info["has_path"] is False

    def test_has_query_true(self) -> None:
        info = extract_url_info("https://example.com?q=test")
        assert info["has_query"] is True

    def test_ip_address_detected(self) -> None:
        info = extract_url_info("http://192.168.1.1/login")
        assert info["is_ip_address"] is True

    def test_punycode_detected(self) -> None:
        info = extract_url_info("https://xn--pypl-roa.com/login")
        assert info["is_punycode"] is True

    def test_cache_key_matches_registered_domain_hash(self) -> None:
        info = extract_url_info("https://www.example.com")
        expected_key = compute_cache_key("example.com")
        assert info["cache_key"] == expected_key

    def test_deceptive_url_extracts_real_domain(self) -> None:
        """Integration of normalise → extract → cache key for the attack pattern."""
        info = extract_url_info(
            "https://signin.paypal.com.updates-verify.info/account?token=abc"
        )
        assert info["registered_domain"] == "updates-verify.info"
        assert info["has_path"] is True
        assert info["has_query"] is True
        assert info["is_ip_address"] is False