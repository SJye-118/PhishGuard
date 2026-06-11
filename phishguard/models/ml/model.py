"""
PhishGuard Enterprise — Model Loader and Inference Wrapper.

STATUS: Phase 5 stub.

Loads the serialised scikit-learn model from artefacts/ and
exposes a predict() function for use by the ensemble engine.
"""

from __future__ import annotations


def load_model(model_path: str) -> None:
    """Load the serialised model from disk.

    Args:
        model_path: Path to the .joblib artefact file.

    Raises:
        NotImplementedError: Until Phase 5 is implemented.
    """
    raise NotImplementedError("Model loading implemented in Phase 5.")


def predict(domain: str) -> float:
    """Return the ML phishing probability for a domain.

    Args:
        domain: Registered domain string.

    Returns:
        Probability score between 0.0 (benign) and 1.0 (malicious).

    Raises:
        NotImplementedError: Until Phase 5 is implemented.
    """
    raise NotImplementedError("Model inference implemented in Phase 5.")