"""
PhishGuard Enterprise — Model Evaluation.

STATUS: Phase 5 stub.

Evaluates the trained model on the held-out test split and writes
precision, recall, F1, and ROC-AUC to metrics/metrics.json.
CI compares these metrics against promotion_gates in params.yaml.

DVC stage: evaluate
Command:   python -m phishguard.ml.evaluate
"""

from __future__ import annotations


def evaluate() -> None:
    """Evaluate the trained model against the held-out test split.

    Raises:
        NotImplementedError: Until Phase 5 is implemented.
    """
    raise NotImplementedError(
        "Model evaluation is implemented in Phase 5. "
        "Run: dvc repro evaluate   (after Phase 5 is complete)"
    )


if __name__ == "__main__":
    evaluate()