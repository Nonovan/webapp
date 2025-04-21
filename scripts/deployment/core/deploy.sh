#!/bin/bash
#
# Script: deploy.sh
# Description: Deploys the Cloud Infrastructure Platform to the specified environment
# Usage: ./deploy.sh [environment]
#
# Copyright (c) 2025 My Company
# Licensed under MIT License
#

set -e  # Exit immediately if a command fails

# Default settings
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

log "Starting deployment to ${ENVIRONMENT} environment"

# Check for required tools
for cmd in git python pip; do
    if ! command -v $cmd &>/dev/null; then
        log "ERROR: Required command '$cmd' not found"
        exit 1
    fi
fi

# Activate virtual environment
if [ -f "${PROJECT_ROOT}/venv/bin/activate" ]; then
    log "Activating virtual environment"
    source "${PROJECT_ROOT}/venv/bin/activate"
else
    log "WARNING: Virtual environment not found at ${PROJECT_ROOT}/venv/bin/activate"
fi

# Run pre-deployment checks
log "Running pre-deployment checks"
"${SCRIPT_DIR}/pre_deploy_check.sh" "${ENVIRONMENT}" || {
    log "ERROR: Pre-deployment checks failed. Aborting deployment."
    exit 1
}

# Update code from repository
if [ "$ENVIRONMENT" == "production" ] || [ "$ENVIRONMENT" == "staging" ]; then
    log "Updating code from repository"
    git pull origin ${GIT_BRANCH:-main}
fi

# Install/update dependencies
log "Installing/updating dependencies"
pip install -r "${PROJECT_ROOT}/requirements.txt" || {
    log "ERROR: Failed to install dependencies"
    exit 1
}

# Run database migrations
log "Running database migrations"
cd "$PROJECT_ROOT" && FLASK_APP=app.py FLASK_ENV=${ENVIRONMENT} flask db upgrade || {
    log "ERROR: Database migration failed"
    exit 1
}

# Collect static files
log "Collecting static files"
"${SCRIPT_DIR}/collect_static.sh" || {
    log "ERROR: Failed to collect static files"
}

# Apply security hardening if needed
if [ "$ENVIRONMENT" == "production" ] || [ "$ENVIRONMENT" == "staging" ]; then
    log "Applying security settings"
    "${SCRIPT_DIR}/security_setup.sh" "${ENVIRONMENT}"
fi

# Restart application services
log "Restarting application services"
if command -v supervisorctl &>/dev/null; then
    supervisorctl restart all
elif command -v systemctl &>/dev/null; then
    systemctl restart cloud-platform.service
    systemctl restart nginx.service
else
    log "WARNING: Could not determine service manager to restart services"
fi

# Run post-deployment checks
log "Running post-deployment checks"
"${SCRIPT_DIR}/post_deploy_check.sh" "${ENVIRONMENT}" || {
    log "WARNING: Post-deployment checks had warnings"
}

log "Deployment to ${ENVIRONMENT} completed successfully"