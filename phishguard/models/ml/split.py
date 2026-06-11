"""
PhishGuard Enterprise — Train/Test Split.

STATUS: Phase 5 stub.

Splits data/features/features_extracted.csv into stratified
train.csv and test.csv using a time-aware ordering.

DVC stage: split
Command:   python -m phishguard.ml.split
"""

from __future__ import annotations


def split() -> None:
    """Execute the train/test split pipeline.

    Raises:
        NotImplementedError: Until Phase 5 is implemented.
    """
    raise NotImplementedError(
        "Train/test split is implemented in Phase 5. "
        "Run: dvc repro split   (after Phase 5 is complete)"
    )


if __name__ == "__main__":
    split()