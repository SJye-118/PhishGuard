"""
Unit tests for phishguard.models.schemas.

Tests verify that:
  - Valid inputs are accepted without error
  - Invalid inputs are rejected with Pydantic ValidationError
  - Enum values are correctly defined
  - Response model fields have correct types and constraints
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from phishguard.models.schemas import (
    BatchClassifyRequest,
    ClassifyRequest,
    ClassifyResponse,
    HealthResponse,
    RDAPStatus,
    RiskTier,
    SSLStatus,
    Verdict,
)


# ══════════════════════════════════════════════════════════════════════════════
# ClassifyRequest
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifyRequest:
    """Input validation tests for the single URL classification request."""

    def test_valid_url_string_accepted(self) -> None:
        req = ClassifyRequest(url="https://example.com")
        assert req.url == "https://example.com"

    def test_bare_domain_accepted(self) -> None:
        """Bare domains without scheme must be accepted — engine normalises them."""
        req = ClassifyRequest(url="example.com")
        assert req.url == "example.com"

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ClassifyRequest(url="")
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_short" for e in errors)

    def test_url_exactly_at_max_length_accepted(self) -> None:
        req = ClassifyRequest(url="a" * 2048)
        assert len(req.url) == 2048

    def test_url_one_over_max_length_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ClassifyRequest(url="a" * 2049)
        errors = exc_info.value.errors()
        assert any(e["type"] == "string_too_long" for e in errors)

    def test_url_field_required(self) -> None:
        with pytest.raises(ValidationError):
            ClassifyRequest()  # type: ignore[call-arg]

    def test_non_string_url_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ClassifyRequest(url=12345)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "url",
        [
            "https://paypal.com",
            "http://192.168.1.1/login",
            "xn--pypl-roa.com",
            "https://signin.paypal.com.updates-verify.evil.info/account?token=123",
            "evil-domain.xyz",
        ],
    )
    def test_various_valid_url_formats_accepted(self, url: str) -> None:
        req = ClassifyRequest(url=url)
        assert req.url == url


# ══════════════════════════════════════════════════════════════════════════════
# BatchClassifyRequest
# ══════════════════════════════════════════════════════════════════════════════

class TestBatchClassifyRequest:
    """Input validation tests for the batch classification request."""

    def test_single_url_list_accepted(self) -> None:
        req = BatchClassifyRequest(urls=["https://example.com"])
        assert len(req.urls) == 1

    def test_multiple_urls_accepted(self) -> None:
        req = BatchClassifyRequest(urls=["https://a.com", "https://b.com"])
        assert len(req.urls) == 2

    def test_exactly_50_urls_accepted(self) -> None:
        req = BatchClassifyRequest(urls=["https://example.com"] * 50)
        assert len(req.urls) == 50

    def test_51_urls_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            BatchClassifyRequest(urls=["https://example.com"] * 51)
        errors = exc_info.value.errors()
        assert any("urls" in str(e.get("loc", "")) for e in errors)

    def test_empty_list_rejected(self) -> None:
        with pytest.raises(ValidationError):
            BatchClassifyRequest(urls=[])

    def test_urls_field_required(self) -> None:
        with pytest.raises(ValidationError):
            BatchClassifyRequest()  # type: ignore[call-arg]


# ══════════════════════════════════════════════════════════════════════════════
# Risk Tier and Verdict enumerations
# ══════════════════════════════════════════════════════════════════════════════

class TestRiskTierEnum:
    """Verify all risk tier values are defined correctly."""

    def test_all_expected_values_present(self) -> None:
        values = {tier.value for tier in RiskTier}
        assert values == {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}

    def test_enum_members_are_strings(self) -> None:
        for tier in RiskTier:
            assert isinstance(tier.value, str)

    def test_string_comparison_works(self) -> None:
        """str mixin allows direct string comparison without .value."""
        assert RiskTier.CRITICAL == "CRITICAL"
        assert RiskTier.LOW == "LOW"


class TestVerdictEnum:
    """Verify all verdict values are defined correctly."""

    def test_all_expected_values_present(self) -> None:
        values = {v.value for v in Verdict}
        assert values == {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}

    def test_string_comparison_works(self) -> None:
        assert Verdict.MALICIOUS == "MALICIOUS"
        assert Verdict.SAFE == "SAFE"


class TestRDAPStatusEnum:
    """Verify RDAP status enum values."""

    def test_all_statuses_present(self) -> None:
        values = {s.value for s in RDAPStatus}
        expected = {"success", "timeout", "parse_error", "no_registry", "not_queried"}
        assert values == expected


class TestSSLStatusEnum:
    """Verify SSL status enum values."""

    def test_all_statuses_present(self) -> None:
        values = {s.value for s in SSLStatus}
        expected = {"valid", "invalid", "timeout", "unreachable", "not_queried"}
        assert values == expected


# ══════════════════════════════════════════════════════════════════════════════
# ClassifyResponse
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifyResponse:
    """Verify that ClassifyResponse accepts and enforces all field constraints."""

    def _make_valid_response(self, **overrides: object) -> dict[str, object]:
        """Build a complete, valid response dict for use in tests."""
        base: dict[str, object] = {
            "domain": "example.com",
            "risk_score": 50,
            "risk_tier": RiskTier.MEDIUM,
            "verdict": Verdict.SUSPICIOUS,
            "veto_triggered": False,
            "ml_probability": 0.55,
            "domain_age_days": 30,
            "ssl_valid": True,
            "brand_match": None,
            "justification": ["ML score: 0.55"],
            "cache_hit": False,
            "processing_time_ms": 400,
            "rdap_status": RDAPStatus.SUCCESS,
            "ssl_status": SSLStatus.VALID,
        }
        base.update(overrides)
        return base

    def test_valid_response_accepted(self) -> None:
        resp = ClassifyResponse(**self._make_valid_response())
        assert resp.domain == "example.com"
        assert resp.risk_score == 50

    def test_risk_score_below_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ClassifyResponse(**self._make_valid_response(risk_score=-1))

    def test_risk_score_above_100_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ClassifyResponse(**self._make_valid_response(risk_score=101))

    def test_risk_score_boundary_values_accepted(self) -> None:
        ClassifyResponse(**self._make_valid_response(risk_score=0))
        ClassifyResponse(**self._make_valid_response(risk_score=100))

    def test_ml_probability_above_1_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ClassifyResponse(**self._make_valid_response(ml_probability=1.1))

    def test_ml_probability_none_accepted(self) -> None:
        """None is valid during Phase 1 when the engine is not yet active."""
        resp = ClassifyResponse(**self._make_valid_response(ml_probability=None))
        assert resp.ml_probability is None

    def test_domain_age_minus_one_accepted(self) -> None:
        """-1 is the documented sentinel value for RDAP timeout."""
        resp = ClassifyResponse(**self._make_valid_response(domain_age_days=-1))
        assert resp.domain_age_days == -1

    def test_ssl_valid_none_accepted(self) -> None:
        """None is valid when SSL check was not performed."""
        resp = ClassifyResponse(**self._make_valid_response(ssl_valid=None))
        assert resp.ssl_valid is None

    def test_justification_empty_list_accepted(self) -> None:
        resp = ClassifyResponse(**self._make_valid_response(justification=[]))
        assert resp.justification == []

    def test_veto_triggered_flag(self) -> None:
        resp_veto = ClassifyResponse(**self._make_valid_response(veto_triggered=True))
        assert resp_veto.veto_triggered is True