FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nmap \
    netcat-openbsd \
    dnsutils \
    whois \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY networkforgeai/ ./networkforgeai/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/workspaces /app/reports /app/logs /app/config

# Set permissions for read-only root filesystem
RUN chmod -R 555 /app/networkforgeai /app/config

# Default command (override with actual scan command)
CMD ["python", "-m", "networkforgeai.cli", "--help"]
