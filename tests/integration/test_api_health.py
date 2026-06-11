"""
Integration tests for GET /health.

Verifies the health endpoint returns the correct HTTP status,
response schema, and field types when the application is running.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
class TestHealthEndpoint:
    """Tests for the /health liveness endpoint."""

    def test_health_returns_200(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_json_content_type(self, client: TestClient) -> None:
        response = client.get("/health")
        assert "application/json" in response.headers["content-type"]

    def test_health_status_field_is_ok(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "ok"

    def test_health_version_field_present(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_environment_field_present(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert data["environment"] in {"development", "staging", "production"}

    def test_health_uptime_is_positive_number(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert isinstance(data["uptime_seconds"], float)
        assert data["uptime_seconds"] >= 0.0

    def test_health_boolean_fields_present(self, client: TestClient) -> None:
        data = client.get("/health").json()
        assert "model_loaded" in data
        assert "redis_connected" in data
        assert isinstance(data["model_loaded"], bool)
        assert isinstance(data["redis_connected"], bool)

    def test_health_phase1_redis_not_connected(self, client: TestClient) -> None:
        """Phase 1: Redis integration is in Phase 8. Expect False."""
        data = client.get("/health").json()
        assert data["redis_connected"] is False

    def test_health_response_matches_schema(self, client: TestClient) -> None:
        """All required keys from HealthResponse schema must be present."""
        required_keys = {
            "status", "version", "environment",
            "model_loaded", "redis_connected", "uptime_seconds",
        }
        data = client.get("/health").json()
        assert required_keys.issubset(set(data.keys()))