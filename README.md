# PhishGuard Enterprise

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-green.svg)](https://fastapi.tiangolo.com)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A production-grade, open-source phishing detection API combining explainable
machine learning with deterministic forensic intelligence.

Built as a portfolio project demonstrating real-world software engineering
practices: asynchronous API design, ML pipelines, CI/CD automation, Docker
containerisation, data governance, and operational monitoring across a full
12-phase development lifecycle.

---

## What It Does

PhishGuard accepts a raw URL string and returns:
- A **risk score** from 0–100
- A **risk tier**: LOW / MEDIUM / HIGH / CRITICAL
- A **verdict**: SAFE / SUSPICIOUS / MALICIOUS
- A **justification array** explaining every signal that influenced the verdict

```json
{
  "domain": "updates-login.com",
  "risk_score": 94,
  "risk_tier": "CRITICAL",
  "verdict": "MALICIOUS",
  "veto_triggered": true,
  "ml_probability": 0.31,
  "domain_age_days": 3,
  "ssl_valid": false,
  "brand_match": "paypal",
  "justification": [
    "VETO: Domain age 3 days is below the 14-day threshold",
    "VETO: Brand keyword 'paypal' detected in registered domain",
    "SSL certificate invalid or absent",
    "ML structural score: 0.31 (overridden by atomic veto)"
  ],
  "cache_hit": false,
  "processing_time_ms": 412
}
```

---

## Architecture

Request
│
▼
[Layer 0]  API Gateway         ← Input validation, Redis cache lookup
│
▼
[Layer 1]  ML Advisory Engine  ← Structural pattern recognition (RandomForest)
[Layer 2]  Forensic Engine     ← Live RDAP domain age + TLS inspection  } concurrent
[Layer 3]  Impersonation Check ← Brand keyword matching (Tranco-sourced)
│
▼
[Layer 4]  Atomic Veto Logic   ← Deterministic override (age < 14d + brand match)
│
▼
Response   risk_score + risk_tier + verdict + justification[]


The key innovation: the **atomic veto**. A standard ML model sees
`paypal-login.com` and `john-blog.com` as structurally near-identical.
The veto layer detects brand keywords combined with newly registered domains
and forces a CRITICAL verdict — regardless of what the ML model scores.

---

## Development Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | Scope & Architecture | ✅ Complete |
| 2 | Data Sourcing | 🔜 Next |
| 3 | Dataset Normalisation | 🔜 Upcoming |
| 4 | Feature Engineering | 🔜 Upcoming |
| 5 | ML Modelling | 🔜 Upcoming |
| 6 | Forensic Layer | 🔜 Upcoming |
| 7 | Ensemble Fusion & Veto Logic | 🔜 Upcoming |
| 8 | Async API Layer | 🔜 Upcoming |
| 9 | Containerisation | 🔜 Upcoming |
| 10 | CI/CD & Deployment | 🔜 Upcoming |
| 11 | MLOps & Retraining | 🔜 Upcoming |
| 12 | Monitoring & Drift Detection | 🔜 Upcoming |

---

## Tech Stack (100% Free & Open Source)

| Layer | Technology | License |
|-------|-----------|---------|
| API | FastAPI + Uvicorn | MIT / BSD |
| Validation | Pydantic v2 | MIT |
| Cache | Redis 7 (self-hosted) | BSD |
| ML | scikit-learn | BSD |
| Domain parsing | tldextract | BSD |
| HTTP client | aiohttp | Apache 2.0 |
| Data versioning | DVC | Apache 2.0 |
| Container | Docker | Apache 2.0 |
| CI/CD | GitHub Actions | Free (public repos) |
| Security scanning | Trivy | Apache 2.0 |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- pyenv (recommended)

### 1. Clone and set up the environment

```bash
git clone https://github.com/yourusername/phishguard-enterprise.git
cd phishguard-enterprise

# Pin Python version
pyenv install 3.11.9
pyenv local 3.11.9

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum set REDIS_URL if not using Docker Compose
```

### 3. Start the local stack

```bash
# Starts Redis + API server
docker compose up -d

# Or run the API directly (requires Redis running separately)
uvicorn phishguard.main:app --reload --port 8000
```

### 4. Test the API

```bash
# Health check
curl http://localhost:8000/health

# Classify a URL
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal.secure-login.updates-verify.com"}'

# Interactive docs
open http://localhost:8000/docs
```

### 5. Run the test suite

```bash
pytest tests/ -v --cov=phishguard --cov-report=term-missing
```

---

## Project Structure

phishguard/
├── config.py          # Environment variable management (pydantic-settings)
├── main.py            # FastAPI application entry point
├── engine.py          # Ensemble fusion and atomic veto logic (Phase 7)
├── models/
│   └── schemas.py     # Pydantic request/response schemas = OpenAPI contract
├── ml/                # Machine learning pipeline (Phases 4-5)
├── forensics/         # RDAP and SSL inspection (Phase 6)
├── cache/             # Redis client (Phase 8)
└── utils/
├── url_parser.py  # URL normalisation and domain extraction
└── logging_config.py  # Structured JSON logging

---

## Data Attribution

This project uses:
- **PhishTank** training data — [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/)
  — operated by Cisco Talos Intelligence Group.
- **Tranco Top-1M** domain list — [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
  — cite the [original paper](https://tranco-list.eu/) in any publication.

---

## Contributing

Pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and
ensure all CI checks pass before requesting review.

## License

MIT — see [LICENSE](LICENSE). The trained model binary is separately noted as
a derivative of PhishTank data (CC BY-SA 3.0) and attributed accordingly.
