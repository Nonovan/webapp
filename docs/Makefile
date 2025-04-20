# Cloud Infrastructure Platform Makefile
# Provides commands for development, testing, and deployment

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
    $(PYTHON) -m venv $(VENV)
    $(PIP) install --upgrade pip
    $(PIP) install -r requirements.txt
    touch $(VENV)/bin/activate

# Installation
.PHONY: install
install: $(VENV)/bin/activate

.PHONY: dev-install
dev-install: $(VENV)/bin/activate
    $(PIP) install -r requirements-dev.txt

# Run Development Server
.PHONY: run
run: $(VENV)/bin/activate
    export FLASK_APP=app.py && \
    export FLASK_ENV=$(ENVIRONMENT) && \
    $(FLASK) run --host=0.0.0.0

# Testing
.PHONY: test
test: $(VENV)/bin/activate
    $(PYTEST) tests/

.PHONY: coverage
coverage: $(VENV)/bin/activate
    $(PYTEST) --cov=. --cov-report=html --cov-report=term tests/

# Linting
.PHONY: lint
lint: $(VENV)/bin/activate
    $(FLAKE8) .
    $(VENV)/bin/pylint app.py api core models services

# Cleaning
.PHONY: clean
clean:
    rm -rf __pycache__
    rm -rf */__pycache__
    rm -rf */*/__pycache__
    rm -rf .pytest_cache
    rm -rf htmlcov
    rm -rf .coverage
    rm -rf dist
    rm -rf build
    rm -rf docs/_build
    find . -type d -name "*.egg-info" -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete
    find . -type f -name "*.pyo" -delete
    find . -type f -name "*.pyd" -delete
    find . -type f -name ".coverage.*" -delete

# Documentation
.PHONY: docs
docs: $(VENV)/bin/activate
    $(PIP) install -e .
    $(SPHINX) -b html docs/ docs/_build/html

# Static Files
.PHONY: static
static:
    bash scripts/deployment/collect_static.sh

# Database
.PHONY: db-init
db-init: $(VENV)/bin/activate
    export FLASK_APP=app.py && \
    $(FLASK) db init

.PHONY: db-migrate
db-migrate: $(VENV)/bin/activate
    export FLASK_APP=app.py && \
    $(FLASK) db migrate -m "$(MESSAGE)"

.PHONY: db-upgrade
db-upgrade: $(VENV)/bin/activate
    export FLASK_APP=app.py && \
    $(FLASK) db upgrade

.PHONY: db-backup
db-backup:
    bash scripts/database/database-manager.sh backup --env $(ENVIRONMENT)

.PHONY: db-restore
db-restore:
    bash scripts/database/database-manager.sh restore --env $(ENVIRONMENT) --file $(FILE)

# Deployment
.PHONY: deploy
deploy:
    @echo "Deploying to $(ENVIRONMENT) environment"
    bash scripts/deployment/deploy.sh $(ENVIRONMENT)

# Infrastructure
.PHONY: infra-plan
infra-plan:
    bash deployment/infrastructure/scripts/plan.sh $(ENVIRONMENT)

.PHONY: infra-apply
infra-apply:
    bash deployment/infrastructure/scripts/apply.sh $(ENVIRONMENT)

# NGINX Setup
.PHONY: setup-nginx
setup-nginx:
    sudo bash deployment/nginx/scripts/install-configs.sh --environment $(ENVIRONMENT)

.PHONY: setup-ssl
setup-ssl:
    sudo bash deployment/nginx/scripts/setup-ssl.sh --environment $(ENVIRONMENT)

.PHONY: setup-modsecurity
setup-modsecurity:
    sudo bash deployment/security/update-modsecurity-rules.sh

# Security
.PHONY: security-audit
security-audit:
    sudo bash deployment/security/security-audit.sh

.PHONY: security-check
security-check:
    bash scripts/security/check_security_updates.sh

.PHONY: verify-files
verify-files:
    python scripts/security/verify_files.py --environment $(ENVIRONMENT)

# DR Testing
.PHONY: dr-test
dr-test:
    bash scripts/deployment/dr-failover.sh --dry-run --target secondary

# Monitoring
.PHONY: update-monitoring
update-monitoring:
    bash scripts/monitoring/update-monitoring.sh --primary-region primary

# Compliance
.PHONY: compliance-report
compliance-report:
    bash scripts/compliance/generate-report.sh --type $(TYPE) --environment $(ENVIRONMENT)

# Docker
.PHONY: docker-build
docker-build:
    docker build -t cloud-platform:latest .

.PHONY: docker-run
docker-run:
    docker run -p 5000:5000 -e FLASK_ENV=$(ENVIRONMENT) cloud-platform:latest