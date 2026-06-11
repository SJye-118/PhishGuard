"""
PhishGuard Enterprise — Tranco Brand Protection List Loader.

STATUS: Phase 6 stub.

Dynamically loads the top N Tranco domains at startup to use as the
brand keyword protection list. Never uses a hardcoded static list.

Why dynamic loading matters:
  A hardcoded list becomes stale within weeks. Tranco reflects real
  global traffic, so the brand list automatically evolves with the web.
"""

from __future__ import annotations


def load_brand_list(tranco_path: str, top_n: int = 1000) -> set[str]:
    """Load the top N registered domains from the Tranco dataset.

    Args:
        tranco_path: Path to the tranco_raw.csv file.
        top_n: Number of top domains to load as brand keywords.

    Returns:
        Set of lowercase registered domain strings.

    Raises:
        NotImplementedError: Until Phase 6 is implemented.
    """
    raise NotImplementedError("Brand loader implemented in Phase 6.")