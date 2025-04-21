# Enhanced Makefile for robustness and clarity

# Variables
PYTHON := python3
VENV := venv
PIP := $(VENV)/bin/pip
FLASK := $(VENV)/bin/flask
PYTEST := $(VENV)/bin/pytest
SPHINX := $(VENV)/bin/sphinx-build
FLAKE8 := $(VENV)/bin/flake8
ENVIRONMENT ?= development

# Default target
.PHONY: help
help:
    @echo "Cloud Infrastructure Platform Makefile"
    @echo ""
    @echo "Usage:"
    @echo "  make help                    Show this help message"
    @echo "  make install                 Install dependencies"
    @echo "  make dev-install             Install development dependencies"
    @echo "  make run                     Run development server"
    @echo "  make test                    Run tests"
    @echo "  make coverage                Run tests with coverage report"
    @echo "  make lint                    Run code linters"
    @echo "  make clean                   Remove build artifacts"
    @echo "  make docs                    Build documentation"
    @echo "  make deploy ENV=production   Deploy to specified environment"
    @echo "  make setup-nginx             Set up NGINX configuration"
    @echo "  make setup-ssl               Set up SSL certificates"
    @echo "  make security-audit          Run security audit"
    @echo "  make db-backup               Backup database"
    @echo "  make db-migrate              Run database migrations"
    @echo "  make static                  Collect and optimize static files"
    @echo ""
    @echo "Environment: $(ENVIRONMENT) (override with ENV=production|staging|development)"

# Virtual Environment
$(VENV)/bin/activate: requirements.txt
    @echo "Setting up virtual environment..."
    $(PYTHON) -m venv $(VENV) || { echo "Failed to create virtual environment"; exit 1; }
    $(PIP) install --upgrade pip || { echo "Failed to upgrade pip"; exit 1; }
    $(PIP) install -r requirements.txt || { echo "Failed to install dependencies"; exit 1; }
    touch $(VENV)/bin/activate

# Installation
.PHONY: install
install: $(VENV)/bin/activate

.PHONY: dev-install
dev-install: $(VENV)/bin/activate
    @echo "Installing development dependencies..."
    $(PIP) install -r requirements-dev.txt || { echo "Failed to install development dependencies"; exit 1; }

# Run Development Server
.PHONY: run
run: $(VENV)/bin/activate
    @echo "Starting development server..."
    export FLASK_APP=app.py && \
    export FLASK_ENV=$(ENVIRONMENT) && \
    $(FLASK) run --host=0.0.0.0 || { echo "Failed to start development server"; exit 1; }

# Testing
.PHONY: test
test: $(VENV)/bin/activate
    @echo "Running tests..."
    $(PYTEST) tests/ || { echo "Tests failed"; exit 1; }

.PHONY: coverage
coverage: $(VENV)/bin/activate
    @echo "Running tests with coverage..."
    $(PYTEST) --cov=. --cov-report=html --cov-report=term tests/ || { echo "Coverage tests failed"; exit 1; }

# Linting
.PHONY: lint
lint: $(VENV)/bin/activate
    @echo "Running linters..."
    $(FLAKE8) . || { echo "Flake8 linting failed"; exit 1; }
    $(VENV)/bin/pylint app.py api core models services || { echo "Pylint linting failed"; exit 1; }

# Cleaning
.PHONY: clean
clean:
    @echo "Cleaning up build artifacts..."
    rm -rf __pycache__ */__pycache__ */*/__pycache__ .pytest_cache htmlcov .coverage dist build docs/_build || true
    find . -type d -name "*.egg-info" -exec rm -rf {} + || true
    find . -type f -name "*.pyc" -delete || true
    find . -type f -name "*.pyo" -delete || true
    find . -type f -name "*.pyd" -delete || true
    find . -type f -name ".coverage.*" -delete || true

# Documentation
.PHONY: docs
docs: $(VENV)/bin/activate
    @echo "Building documentation..."
    $(PIP) install -e . || { echo "Failed to install project in editable mode"; exit 1; }
    $(SPHINX) -b html docs/ docs/_build/html || { echo "Failed to build documentation"; exit 1; }

# Static Files
.PHONY: static
static:
    @echo "Collecting and optimizing static files..."
    bash scripts/deployment/collect_static.sh || { echo "Failed to collect static files"; exit 1; }

# Database
.PHONY: db-init
db-init: $(VENV)/bin/activate
    @echo "Initializing database..."
    export FLASK_APP=app.py && \
    $(FLASK) db init || { echo "Failed to initialize database"; exit 1; }

.PHONY: db-migrate
db-migrate: $(VENV)/bin/activate
    @echo "Running database migrations..."
    export FLASK_APP=app.py && \
    $(FLASK) db migrate -m "$(MESSAGE)" || { echo "Failed to run database migrations"; exit 1; }

.PHONY: db-upgrade
db-upgrade: $(VENV)/bin/activate
    @echo "Upgrading database..."
    export FLASK_APP=app.py && \
    $(FLASK) db upgrade || { echo "Failed to upgrade database"; exit 1; }

.PHONY: db-backup
db-backup:
    @echo "Backing up database..."
    bash scripts/database/database-manager.sh backup --env $(ENVIRONMENT) || { echo "Failed to backup database"; exit 1; }

.PHONY: db-restore
db-restore:
    @echo "Restoring database..."
    bash scripts/database/database-manager.sh restore --env $(ENVIRONMENT) --file $(FILE) || { echo "Failed to restore database"; exit 1; }

# Deployment
.PHONY: deploy
deploy:
    @echo "Deploying to $(ENVIRONMENT) environment..."
    bash scripts/deployment/deploy.sh $(ENVIRONMENT) || { echo "Deployment failed"; exit 1; }

# Infrastructure
.PHONY: infra-plan
infra-plan:
    @echo "Planning infrastructure changes..."
    bash deployment/infrastructure/scripts/plan.sh $(ENVIRONMENT) || { echo "Infrastructure planning failed"; exit 1; }

.PHONY: infra-apply
infra-apply:
    @echo "Applying infrastructure changes..."
    bash deployment/infrastructure/scripts/apply.sh $(ENVIRONMENT) || { echo "Infrastructure application failed"; exit 1; }

# NGINX Setup
.PHONY: setup-nginx
setup-nginx:
    @echo "Setting up NGINX configuration..."
    sudo bash deployment/nginx/scripts/install-configs.sh --environment $(ENVIRONMENT) || { echo "NGINX setup failed"; exit 1; }

.PHONY: setup-ssl
setup-ssl:
    @echo "Setting up SSL certificates..."
    sudo bash deployment/nginx/scripts/setup-ssl.sh --environment $(ENVIRONMENT) || { echo "SSL setup failed"; exit 1; }

.PHONY: setup-modsecurity
setup-modsecurity:
    @echo "Updating ModSecurity rules..."
    sudo bash deployment/security/update-modsecurity-rules.sh || { echo "ModSecurity setup failed"; exit 1; }

# Security
.PHONY: security-audit
security-audit:
    @echo "Running security audit..."
    sudo bash deployment/security/security-audit.sh || { echo "Security audit failed"; exit 1; }

.PHONY: security-check
security-check:
    @echo "Checking for security updates..."
    bash scripts/security/check_security_updates.sh || { echo "Security check failed"; exit 1; }

.PHONY: verify-files
verify-files:
    @echo "Verifying files..."
    python scripts/security/verify_files.py --environment $(ENVIRONMENT) || { echo "File verification failed"; exit 1; }

# DR Testing
.PHONY: dr-test
dr-test:
    @echo "Performing disaster recovery test..."
    bash scripts/deployment/dr-failover.sh --dry-run --target secondary || { echo "DR test failed"; exit 1; }

# Monitoring
.PHONY: update-monitoring
update-monitoring:
    @echo "Updating monitoring configuration..."
    bash scripts/monitoring/update-monitoring.sh --primary-region primary || { echo "Monitoring update failed"; exit 1; }

# Compliance
.PHONY: compliance-report
compliance-report:
    @echo "Generating compliance report..."
    bash scripts/compliance/generate-report.sh --type $(TYPE) --environment $(ENVIRONMENT) || { echo "Compliance report generation failed"; exit 1; }

# Docker
.PHONY: docker-build
docker-build:
    @echo "Building Docker image..."
    docker build -t cloud-platform:latest . || { echo "Docker build failed"; exit 1; }

.PHONY: docker-run
docker-run:
    @echo "Running Docker container..."
    docker run -p 5000:5000 -e FLASK_ENV=$(ENVIRONMENT) cloud-platform:latest || { echo "Docker run failed"; exit 1; }
