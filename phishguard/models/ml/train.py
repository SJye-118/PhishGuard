"""
PhishGuard Enterprise — Model Training Entry Point.

STATUS: Phase 5 stub.

Called by the DVC 'train' pipeline stage:
    dvc repro train

Trains a RandomForestClassifier on the feature matrix produced by
Phase 4, evaluates against the held-out test split, and serialises
the model artefact to artefacts/phishguard_model.joblib.
"""

from __future__ import annotations


def train() -> None:
    """Execute the full model training pipeline.

    Raises:
        NotImplementedError: Until Phase 5 is implemented.
    """
    raise NotImplementedError("Model training implemented in Phase 5.")


if __name__ == "__main__":
    train()