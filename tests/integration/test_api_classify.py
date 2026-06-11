"""
Integration tests for POST /api/v1/classify and /api/v1/classify/batch.

Phase 1 integration tests verify:
  - Valid URLs are accepted and return HTTP 200
  - Invalid URLs (empty, too long) are rejected with HTTP 422
  - Response schema fields are all present with correct types
  - URL parsing produces the correct registered domain in the response
  - Batch endpoint accepts up to 50 URLs and enforces the limit
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
class TestClassifyEndpoint:
    """Tests for POST /api/v1/classify."""

    def test_valid_url_returns_200(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/classify",
            json={"url": "https://example.com"},
        )
        assert response.status_code == 200

    def test_response_contains_required_fields(self, client: TestClient) -> None:
        """All ClassifyResponse fields must be present in the response."""
        required_keys = {
            "domain", "risk_score", "risk_tier", "verdict",
            "veto_triggered", "justification", "cache_hit",
            "processing_time_ms", "rdap_status", "ssl_status",
        }
        response = client.post("/api/v1/classify", json={"url": "https://example.com"})
        data = response.json()
        assert required_keys.issubset(set(data.keys()))

    def test_domain_field_is_normalised_registered_domain(self, client: TestClient) -> None:
        """The domain field must contain the extracted registered domain, not the full URL."""
        response = client.post(
            "/api/v1/classify",
            json={"url": "https://www.example.com/path?query=1"},
        )
        assert response.json()["domain"] == "example.com"

    def test_deceptive_subdomain_resolves_to_correct_domain(self, client: TestClient) -> None:
        """Critical Phase 1 test: the subdomain chain attack must resolve correctly."""
        response = client.post(
            "/api/v1/classify",
            json={"url": "https://signin.paypal.com.updates-verify.info/account"},
        )
        assert response.status_code == 200
        assert response.json()["domain"] == "updates-verify.info"

    def test_risk_score_is_integer_in_range(self, client: TestClient) -> None:
        data = client.post("/api/v1/classify", json={"url": "https://example.com"}).json()
        assert isinstance(data["risk_score"], int)
        assert 0 <= data["risk_score"] <= 100

    def test_phase1_rdap_status_is_not_queried(self, client: TestClient) -> None:
        """In Phase 1, no RDAP queries are made."""
        data = client.post("/api/v1/classify", json={"url": "https://example.com"}).json()
        assert data["rdap_status"] == "not_queried"

    def test_phase1_ssl_status_is_not_queried(self, client: TestClient) -> None:
        """In Phase 1, no SSL checks are performed."""
        data = client.post("/api/v1/classify", json={"url": "https://example.com"}).json()
        assert data["ssl_status"] == "not_queried"

    def test_justification_is_non_empty_list(self, client: TestClient) -> None:
        data = client.post("/api/v1/classify", json={"url": "https://example.com"}).json()
        assert isinstance(data["justification"], list)
        assert len(data["justification"]) > 0

    def test_processing_time_is_non_negative(self, client: TestClient) -> None:
        data = client.post("/api/v1/classify", json={"url": "https://example.com"}).json()
        assert data["processing_time_ms"] >= 0

    def test_empty_url_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": ""})
        assert response.status_code == 422

    def test_url_too_long_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": "a" * 2049})
        assert response.status_code == 422

    def test_missing_url_field_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={})
        assert response.status_code == 422

    def test_non_string_url_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": 12345})
        assert response.status_code == 422

    def test_ip_address_url_accepted(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": "http://192.168.1.1/login"})
        assert response.status_code == 200
        assert response.json()["domain"] == "192.168.1.1"

    def test_bare_domain_without_scheme_accepted(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": "example.com"})
        assert response.status_code == 200

    def test_response_has_x_request_id_header(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify", json={"url": "https://example.com"})
        assert "x-request-id" in response.headers

    def test_custom_request_id_echoed_in_response(self, client: TestClient) -> None:
        custom_id = "test-request-id-12345"
        response = client.post(
            "/api/v1/classify",
            json={"url": "https://example.com"},
            headers={"X-Request-ID": custom_id},
        )
        assert response.headers.get("x-request-id") == custom_id

    @pytest.mark.parametrize(
        "url,expected_domain",
        [
            ("https://www.google.com", "google.com"),
            ("https://mail.google.co.uk", "google.co.uk"),
            ("http://192.168.0.1/path", "192.168.0.1"),
            ("evil-domain.xyz", "evil-domain.xyz"),
        ],
    )
    def test_domain_extraction_parametrised(
        self, client: TestClient, url: str, expected_domain: str
    ) -> None:
        data = client.post("/api/v1/classify", json={"url": url}).json()
        assert data["domain"] == expected_domain


@pytest.mark.integration
class TestBatchClassifyEndpoint:
    """Tests for POST /api/v1/classify/batch."""

    def test_single_url_batch_returns_200(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/classify/batch",
            json={"urls": ["https://example.com"]},
        )
        assert response.status_code == 200

    def test_batch_results_count_matches_input(self, client: TestClient) -> None:
        urls = ["https://example.com", "https://google.com", "https://evil.xyz"]
        data = client.post("/api/v1/classify/batch", json={"urls": urls}).json()
        assert data["total"] == 3
        assert len(data["results"]) == 3

    def test_batch_results_are_in_input_order(self, client: TestClient) -> None:
        """Results must appear in the same order as the input URL list."""
        urls = ["https://alpha.com", "https://beta.com", "https://gamma.com"]
        data = client.post("/api/v1/classify/batch", json={"urls": urls}).json()
        assert data["results"][0]["domain"] == "alpha.com"
        assert data["results"][1]["domain"] == "beta.com"
        assert data["results"][2]["domain"] == "gamma.com"

    def test_batch_of_50_urls_accepted(self, client: TestClient) -> None:
        urls = ["https://example.com"] * 50
        response = client.post("/api/v1/classify/batch", json={"urls": urls})
        assert response.status_code == 200
        assert response.json()["total"] == 50

    def test_batch_of_51_urls_rejected(self, client: TestClient) -> None:
        urls = ["https://example.com"] * 51
        response = client.post("/api/v1/classify/batch", json={"urls": urls})
        assert response.status_code == 422

    def test_empty_urls_list_rejected(self, client: TestClient) -> None:
        response = client.post("/api/v1/classify/batch", json={"urls": []})
        assert response.status_code == 422

    def test_batch_response_has_processing_time(self, client: TestClient) -> None:
        data = client.post(
            "/api/v1/classify/batch",
            json={"urls": ["https://example.com"]},
        ).json()
        assert "processing_time_ms" in data
        assert data["processing_time_ms"] >= 0