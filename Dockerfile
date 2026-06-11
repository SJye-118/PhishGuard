# ═════════════════════════════════════════════════════════════════
# PhishGuard Enterprise — Multi-Stage Production Dockerfile
#
# Stage 1 (builder): Installs all dependencies including build tools.
# Stage 2 (runtime): Copies only the installed packages — no build
#                    tools, no training data, no secrets.
#
# Run as a non-root user (security_user, UID 1001) in production.
# ═════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

LABEL maintainer="PhishGuard Enterprise Contributors"
LABEL description="PhishGuard Enterprise — Build Stage"

WORKDIR /build

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into an isolated prefix
# This allows Stage 2 to copy only the installed packages
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Pre-download the tldextract Public Suffix List cache
# This ensures the first request doesn't trigger a live download
RUN python -c "import tldextract; tldextract.extract('example.com')"

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="PhishGuard Enterprise Contributors"
LABEL description="PhishGuard Enterprise — Production Runtime"
LABEL org.opencontainers.image.source="https://github.com/yourusername/phishguard-enterprise"
LABEL org.opencontainers.image.licenses="MIT"

# Create a non-root group and user for security isolation
RUN groupadd --gid 1001 security_group \
    && useradd \
        --uid 1001 \
        --gid security_group \
        --no-create-home \
        --shell /bin/false \
        security_user

WORKDIR /app

# Copy installed Python packages from the builder stage (not build tools)
COPY --from=builder /install /usr/local

# Copy the tldextract cache from the builder stage
COPY --from=builder /root/.cache /home/security_user/.cache

# Copy application source code
COPY phishguard/ ./phishguard/

# Create the artefacts directory — the model file is mounted or copied here
# The directory must exist; the file is not baked into the image
RUN mkdir -p /app/artefacts && chown -R security_user:security_group /app

# Drop to non-root user
USER security_user

# Expose the API port
EXPOSE 8000

# Liveness health check
# --interval=30s  Check every 30 seconds
# --timeout=10s   Fail the check if no response within 10 seconds
# --start-period=15s  Allow 15 seconds for startup before first check
# --retries=3     Mark unhealthy after 3 consecutive failures
HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=15s \
    --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start Uvicorn with 2 workers
# --workers 2 : Suitable for containers with 1–2 vCPUs
# --host 0.0.0.0 : Accept connections from outside the container
# --port 8000 : Internal container port
CMD ["uvicorn", "phishguard.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--access-log"]