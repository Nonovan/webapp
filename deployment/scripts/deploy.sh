#!/bin/bash
# Deploy Cloud Infrastructure Platform to production environment
# Usage: ./scripts/deploy.sh [environment]

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_ROOT}/logs/deployment_$(date +%Y%m%d_%H%M%S).log"

# Ensure logs directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log "Starting deployment to ${ENVIRONMENT} environment"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    log "Loading ${ENVIRONMENT} environment variables"
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
else
    log "ERROR: Environment file ${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env not found"
    exit 1
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