#!/bin/bash
# Pre-deployment checks for Cloud Infrastructure Platform
# Usage: ./pre_deploy_check.sh [environment]

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EXIT_CODE=0

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

check_fail() {
    log "FAILED: $1"
    EXIT_CODE=1
}

log "Running pre-deployment checks for ${ENVIRONMENT} environment"

# Check for required tools
for cmd in git pip python flask; do
    if ! command -v $cmd &>/dev/null; then
        check_fail "Required command '$cmd' not found"
    fi
done

# Check virtual environment
if [ ! -f "${PROJECT_ROOT}/venv/bin/activate" ]; then
    check_fail "Virtual environment not found at ${PROJECT_ROOT}/venv/bin/activate"
fi

# Check environment configuration file
if [ ! -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    check_fail "Environment file ${ENVIRONMENT}.env not found"
fi

# Check git status
if [ "$ENVIRONMENT" == "production" ] || [ "$ENVIRONMENT" == "staging" ]; then
    cd "$PROJECT_ROOT"
    if [[ -n $(git status --porcelain) ]]; then
        check_fail "Git working directory is not clean"
    fi
fi

# Run tests
if [ "$ENVIRONMENT" == "production" ]; then
    log "Running tests"
    cd "$PROJECT_ROOT" && python -m pytest tests || check_fail "Test suite failed"
fi

# Check database connection
log "Checking database connection"
cd "$PROJECT_ROOT" && FLASK_APP=app.py FLASK_ENV=${ENVIRONMENT} flask db-check || check_fail "Database connection check failed"

# Check disk space
MIN_SPACE_MB=500
AVAIL_SPACE_MB=$(df -m / | tail -1 | awk '{print $4}')
if [ "$AVAIL_SPACE_MB" -lt "$MIN_SPACE_MB" ]; then
    check_fail "Insufficient disk space: ${AVAIL_SPACE_MB}MB available, ${MIN_SPACE_MB}MB required"
fi

# Syntax check for important configuration files
for config_file in $(find "$PROJECT_ROOT"/config -name "*.py"); do
    python -m py_compile "$config_file" || check_fail "Syntax error in $config_file"
done

# Check for appropriate permissions
if [ "$ENVIRONMENT" == "production" ] || [ "$ENVIRONMENT" == "staging" ]; then
    if [ ! -w "/var/log/cloud-platform" ]; then
        check_fail "Application log directory is not writable"
    fi
fi

# Check SSL certificate validity (for production)
if [ "$ENVIRONMENT" == "production" ]; then
    log "Checking SSL certificate validity"
    SSL_CERT="/etc/ssl/certs/cloud-platform.crt"
    if [ -f "$SSL_CERT" ]; then
        EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$SSL_CERT" | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
        
        if [ $DAYS_LEFT -lt 30 ]; then
            check_fail "SSL certificate will expire in $DAYS_LEFT days"
        else
            log "SSL certificate valid for $DAYS_LEFT days"
        fi
    else
        check_fail "SSL certificate not found at $SSL_CERT"
    fi
fi

# Security check for critical files
log "Checking security of critical files"
CONFIG_FILE="/etc/cloud-platform/config.ini"
if [ -f "$CONFIG_FILE" ]; then
    FILE_PERMS=$(stat -c '%a' "$CONFIG_FILE")
    if [[ "$FILE_PERMS" != "640" && "$FILE_PERMS" != "600" ]]; then
        check_fail "Config file has insecure permissions: $FILE_PERMS (should be 640 or 600)"
    fi
fi

if [ $EXIT_CODE -eq 0 ]; then
    log "All pre-deployment checks passed"
else
    log "Pre-deployment checks failed"
fi

exit $EXIT_CODE