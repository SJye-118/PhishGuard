"""
PhishGuard Enterprise — Shared pytest Fixtures.

Fixtures defined here are available to every test file automatically.
No import is required in test files.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from phishguard.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    """Return a TestClient wrapping the FastAPI application.

    Session-scoped so the app starts up once for the entire test run,
    avoiding repeated lifespan execution overhead.
    """
    with TestClient(app) as test_client:
        yield test_client


# ── Sample URL fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def phishing_url_deep_path() -> str:
    """A typical PhishTank-style URL with brand keyword in a deep path."""
    return "https://evil-domain.xyz/paypal/login/verify/account?ref=email"


@pytest.fixture
def phishing_url_deceptive_subdomain() -> str:
    """A URL using a deceptive subdomain chain — the critical tldextract test."""
    return "https://signin.paypal.com.updates-verify.info/account"


@pytest.fixture
def phishing_url_ip_address() -> str:
    """A URL using a raw IP address instead of a domain name."""
    return "http://192.168.1.1/paypal/login"


@pytest.fixture
def phishing_url_punycode() -> str:
    """A URL using Punycode encoding for an IDN homograph attack."""
    return "https://xn--pypl-roa.com/login"


@pytest.fixture
def benign_url_google() -> str:
    """A well-known, clearly legitimate domain."""
    return "https://www.google.com"


@pytest.fixture
def benign_url_compound_tld() -> str:
    """A legitimate domain with a compound TLD (.co.uk)."""
    return "https://example.co.uk"


@pytest.fixture
def benign_url_no_scheme() -> str:
    """A domain string submitted without a URL scheme."""
    return "example.com"