FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nmap \
    masscan \
    netcat-openbsd \
    dnsutils \
    whois \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy package metadata first for better dependency-layer caching
COPY pyproject.toml README.md LICENSE ./

# Keep packaging tools current so the runtime image does not ship known toolchain vulnerabilities.
RUN python -m pip install --no-cache-dir --upgrade "pip>=26.1" "setuptools>=83.0.0"

# Copy application code
COPY networkforgeai/ ./networkforgeai/

# Install the authoritative package dependency graph
RUN python -m pip install --no-cache-dir ".[runtime,llm]"

# Create necessary directories
RUN mkdir -p /app/workspaces /app/reports /app/logs /app/config

# Set permissions for read-only root filesystem
RUN chmod -R 555 /app/networkforgeai /app/config

# Default command (override with actual scan command)
CMD ["python", "-m", "networkforgeai.cli", "--help"]
