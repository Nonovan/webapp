#!/bin/bash
# CI/CD Container Entrypoint Script
set -e

# Function to display help
show_help() {
    echo "Cloud Infrastructure Platform CI/CD Container"
    echo ""
    echo "Available commands:"
    echo "  test              Run all tests"
    echo "  test:unit         Run unit tests"
    echo "  test:integration  Run integration tests"
    echo "  test:e2e          Run end-to-end tests"
    echo "  security          Run security scans"
    echo "  build             Build deployment package"
    echo "  deploy:staging    Deploy to staging environment"
    echo "  deploy:production Deploy to production environment"
    echo "  help              Show this help message"
}

# Environment setup
export PATH="$PATH:/ci-scripts"
export PYTHONPATH="$PYTHONPATH:/app"

# Run requested command
case "$1" in
    test)
        echo "Running all tests..."
        pytest tests/
        ;;
    test:unit)
        echo "Running unit tests..."
        pytest tests/unit/
        ;;
    test:integration)
        echo "Running integration tests..."
        pytest tests/integration/
        ;;
    test:e2e)
        echo "Running end-to-end tests..."
        pytest tests/e2e/
        ;;
    security)
        echo "Running security scans..."
        mkdir -p /app/security-reports
        
        echo "Running dependency check..."
        python /ci-scripts/dependency_check.py
        
        echo "Running SAST scan..."
        python /ci-scripts/sast_scan.py
        
        echo "Running additional security checks..."
        bandit -r . -x tests/,venv/
        safety check -r requirements.txt
        ;;
    build)
        echo "Building deployment package..."
        python /ci-scripts/build_package.py
        ;;
    deploy:staging)
        echo "Deploying to staging environment..."
        bash deployment/scripts/deploy.sh staging
        ;;
    deploy:production)
        echo "Deploying to production environment..."
        bash deployment/scripts/deploy.sh production
        ;;
    help)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac