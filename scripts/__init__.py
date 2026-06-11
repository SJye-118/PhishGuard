"""
PhishGuard Enterprise — Data Pipeline Scripts Package.

Scripts in this package are executed by DVC pipeline stages.
Run from the project root using the module flag:

    python -m scripts.fetch_tranco
    python -m scripts.fetch_phishtank

Or via DVC (recommended):

    dvc repro fetch_tranco
    dvc repro fetch_phishtank
    dvc repro               # Run all stages in dependency order
"""