"""
PhishGuard Enterprise — URL Normalisation and Domain Extraction.

This module is the system's single entry point for all URL processing.
It is intentionally dependency-light: only tldextract (which reads the
live Mozilla Public Suffix List) and Python's stdlib urllib.parse.

Key responsibilities:
  1. Add a scheme if none is present (so urlparse works reliably).
  2. Extract the REGISTERED DOMAIN only — subdomain, path, and query
     string are deliberately discarded. The ML model is a Domain-Only
     Classifier; path structure must never influence the verdict.
  3. Detect raw IP addresses (which bypass the DNS system).
  4. Compute the SHA-256 cache key used by Redis lookups.
  5. Detect Punycode-encoded IDN homograph domains.

Critical design note — the Asymmetry Leak Illusion:
  PhishTank provides deep-path URLs: https://evil.com/paypal/login/verify
  Tranco provides apex domains:        amazon.com

  If the ML model ever sees the full URL path, it learns to distinguish
  datasets by URL *depth* — not by actual phishing patterns. This module
  enforces domain-only extraction to close that loophole.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse
import ipaddress 

import tldextract

# ── Constants ────────────────────────────────────────────────────────────────

# Recognised URL schemes that urlparse handles reliably.
_KNOWN_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp", "ftps"})

# Regex for a bare IPv4 address: four dot-separated octets.
_IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# Punycode prefix defined by RFC 3492 for IDN-encoded labels.
_PUNYCODE_PREFIX: str = "xn--"

# Version prefix on all Redis cache keys.
# Increment to "v2:" if the response schema changes incompatibly,
# which will invalidate all existing cached results automatically.
_CACHE_KEY_VERSION: str = "v1"


# ── Public API ───────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    """Add a scheme to a bare domain or URL if none is present.

    Without a scheme, Python's urlparse treats the entire string as a
    path component, making hostname extraction unreliable.

    Args:
        url: Raw URL or domain string as submitted by the API caller.

    Returns:
        URL string with a scheme guaranteed to be present.

    Examples:
        >>> normalise_url("example.com")
        'https://example.com'
        >>> normalise_url("http://example.com/login")
        'http://example.com/login'
    """
    stripped = url.strip()
    scheme = stripped.split("://")[0].lower() if "://" in stripped else ""
    if scheme not in _KNOWN_SCHEMES:
        return f"https://{stripped}"
    return stripped


def extract_domain(url: str) -> str:
    """Extract only the registered domain from any URL string.

    This is the core normalisation step for the ML Domain-Only Classifier.
    Subdomain, scheme, path, query string, and fragment are all discarded.
    tldextract handles compound TLDs (.co.uk, .com.au) using the live
    Mozilla Public Suffix List.

    Args:
        url: Raw URL or domain string.

    Returns:
        Lowercase registered domain string (e.g. 'example.com').
        Falls back to the lowercase hostname if tldextract cannot parse.

    Examples:
        >>> extract_domain("https://signin.paypal.com.updates-verify.info/account")
        'updates-verify.info'
        >>> extract_domain("https://www.google.co.uk")
        'google.co.uk'
        >>> extract_domain("http://192.168.1.1/login")
        '192.168.1.1'
    """
    normalised = normalise_url(url)
    parsed = urlparse(normalised)
    hostname: str = (parsed.hostname or normalised).lower()

    # Raw IP addresses have no TLD — return them directly.
    if is_ip_address(hostname):
        return hostname

    extracted = tldextract.extract(hostname)

    if extracted.registered_domain:
        return extracted.registered_domain.lower()

    # Fallback: if tldextract cannot identify a registered domain
    # (e.g. a private TLD or an unknown suffix), return the hostname.
    return hostname.lower()


def is_ip_address(value: str) -> bool:
    """Check whether a string is a valid IPv4 or IPv6 address.

    FIX M-01: Previously only handled IPv4 via regex. IPv6 URLs like
    http://[::1]/paypal/login were not flagged as IP addresses, allowing
    attackers to bypass domain-based detection with IPv6 notation.

    Now uses Python's stdlib ipaddress module which handles both
    families correctly. IPv6 bracket notation ([::1]) is stripped before
    parsing as required by RFC 3986.

    Args:
        value: String to test (hostname component, not a full URL).

    Returns:
        True if value is a valid IPv4 or IPv6 address.

    Examples:
        >>> is_ip_address("192.168.1.1")
        True
        >>> is_ip_address("::1")
        True
        >>> is_ip_address("[::1]")   # bracket notation stripped automatically
        True
        >>> is_ip_address("256.0.0.1")
        False
        >>> is_ip_address("example.com")
        False
    """
    # Strip IPv6 bracket notation: [::1] → ::1 (RFC 3986 §3.2.2)
    cleaned = value.strip().strip("[]")
    if not cleaned:
        return False
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False

def is_punycode_encoded(domain: str) -> bool:
    """Check whether a domain contains Punycode-encoded IDN labels.

    Punycode (RFC 3492) allows Unicode characters in domain labels by
    encoding them as ASCII strings starting with 'xn--'. Attackers use
    this mechanism to embed Unicode homoglyphs of brand names.

    Example: xn--pypl-4na.com decodes to pаypal.com (Cyrillic а).

    Args:
        domain: Registered domain string.

    Returns:
        True if any label of the domain starts with the 'xn--' prefix.
    """
    return any(label.lower().startswith(_PUNYCODE_PREFIX) for label in domain.split("."))


def compute_cache_key(domain: str) -> str:
    """Compute the Redis cache key for a given registered domain.

    The key is a version-prefixed SHA-256 hex digest of the lowercase
    domain string. SHA-256 is used (not MD5) for collision resistance.

    The version prefix ('v1:') allows full cache invalidation without
    flushing Redis: bumping to 'v2:' causes all existing keys to be
    treated as misses while old entries expire naturally via TTL.

    Args:
        domain: Registered domain string (e.g. 'example.com').

    Returns:
        Cache key string: 'v1:<64-char-hex-digest>'.

    Examples:
        >>> compute_cache_key("example.com")
        'v1:a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947'
    """
    digest = hashlib.sha256(domain.lower().encode("utf-8")).hexdigest()
    return f"{_CACHE_KEY_VERSION}:{digest}"


def extract_url_info(url: str) -> dict[str, object]:
    """Extract comprehensive URL decomposition for logging and analysis.

    This is the primary entry point called by the API request handler.
    It returns a dictionary containing all derived fields needed by the
    ensemble engine and the structured request log.

    Args:
        url: Raw URL string submitted by the API caller.

    Returns:
        Dictionary with the following keys:
          original_url       — the URL exactly as submitted
          normalised_url     — URL with scheme added if missing
          scheme             — 'http', 'https', etc.
          hostname           — full hostname including subdomain
          registered_domain  — tldextract registered domain only
          subdomain          — subdomain component (may be empty)
          suffix             — TLD suffix (e.g. 'com', 'co.uk')
          is_ip_address      — True if hostname is a raw IPv4 address
          is_punycode        — True if any label starts with 'xn--'
          has_path           — True if the URL contains a non-root path
          has_query          — True if the URL contains a query string
          cache_key          — Redis cache key for the registered domain

    Examples:
        >>> info = extract_url_info("https://signin.paypal.com.evil.info/account?ref=1")
        >>> info["registered_domain"]
        'evil.info'
        >>> info["has_path"]
        True
    """
    normalised = normalise_url(url)
    parsed = urlparse(normalised)
    hostname: str = (parsed.hostname or normalised).lower()

    extracted = tldextract.extract(hostname)
    registered_domain = (
        extracted.registered_domain.lower() if extracted.registered_domain else hostname
    )

    # IP addresses are their own registered domain
    if is_ip_address(hostname):
        registered_domain = hostname

    return {
        "original_url": url,
        "normalised_url": normalised,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": extracted.subdomain,
        "suffix": extracted.suffix,
        "is_ip_address": is_ip_address(hostname),
        "is_punycode": is_punycode_encoded(hostname),
        "has_path": bool(parsed.path and parsed.path not in {"", "/"}),
        "has_query": bool(parsed.query),
        "cache_key": compute_cache_key(registered_domain),
    }