# Dockerfile for Cloud Infrastructure Platform CI/CD
FROM python:3.9-slim

LABEL maintainer="DevOps Team <devops@example.com>"
LABEL description="Cloud Infrastructure Platform CI/CD Container"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    gnupg \
    libpq-dev \
    netcat-openbsd \
    nodejs \
    npm \
    openssh-client \
    postgresql-client \
    sudo \
    unzip \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt \
    && pip install -r requirements-dev.txt \
    && pip install pytest pytest-cov bandit safety flake8 pylint

# Install Node.js dependencies for front-end builds
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# Install security scanning tools
RUN pip install semgrep
RUN npm install -g snyk

# Copy CI scripts
COPY deployment/ci/scripts /ci-scripts
RUN chmod +x /ci-scripts/*

# Copy application code
COPY . .

# Add entrypoint script
COPY deployment/ci/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["help"]