#!/bin/bash
# Post-deployment verification for Cloud Infrastructure Platform
# Usage: ./post_deploy_check.sh [environment]

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

log "Running post-deployment checks for ${ENVIRONMENT} environment"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
fi

# Check application health endpoint
APP_URL=${APP_URL:-"http://localhost:5000"}
log "Checking application health endpoint at $APP_URL/api/health"
HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$APP_URL/api/health")
if [ "$HEALTH_CHECK" != "200" ]; then
    check_fail "Health check endpoint returned $HEALTH_CHECK"
fi

# Check if all expected services are running
if command -v systemctl &>/dev/null; then
    for service in cloud-platform nginx postgresql; do
        if ! systemctl is-active --quiet $service; then
            check_fail "Service $service is not running"
        fi
    done
fi

# Verify database migrations were applied
log "Verifying database migrations"
cd "$PROJECT_ROOT" && FLASK_APP=app.py FLASK_ENV=${ENVIRONMENT} flask db-check --migrations || check_fail "Database migration verification failed"

# Check for critical errors in logs since deployment
LOG_FILE="/var/log/cloud-platform/app.log"
if [ -f "$LOG_FILE" ]; then
    ERROR_COUNT=$(grep -c -i "critical\|error\|exception" "$LOG_FILE" --max-count=10)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        log "WARNING: Found $ERROR_COUNT errors in application log"
        grep -i "critical\|error\|exception" "$LOG_FILE" --max-count=5
        # Don't fail deployment for log errors, but warn
    fi
fi

# Performance quick check
log "Running quick performance check"
RESPONSE_TIME=$(curl -s -w "%{time_total}\n" -o /dev/null "$APP_URL/api/health")
if (( $(echo "$RESPONSE_TIME > 2" | bc -l) )); then
    log "WARNING: Health endpoint response time is slow: ${RESPONSE_TIME}s"
fi

# Check static files
log "Checking static files"
if [ ! -d "${PROJECT_ROOT}/instance/static" ]; then
    check_fail "Static files directory not found"
fi

# Check security headers if in production
if [ "$ENVIRONMENT" == "production" ]; then
    log "Checking security headers"
    SECURITY_HEADERS=$(curl -s -I "$APP_URL" | grep -i "strict-transport-security\|content-security-policy\|x-frame-options")
    if [ -z "$SECURITY_HEADERS" ]; then
        check_fail "Security headers are not configured correctly"
    fi
fi

# Check file permissions
if [ "$ENVIRONMENT" == "production" ]; then
    log "Checking file permissions"
    
    # Check permissions on config files
    CONFIG_FILE="/etc/cloud-platform/config.ini"
    if [ -f "$CONFIG_FILE" ]; then
        FILE_PERMS=$(stat -c '%a' "$CONFIG_FILE")
        FILE_OWNER=$(stat -c '%U' "$CONFIG_FILE")
        
        if [[ "$FILE_PERMS" != "640" && "$FILE_PERMS" != "600" ]]; then
            check_fail "Config file has insecure permissions: $FILE_PERMS (should be 640 or 600)"
        fi
        
        if [ "$FILE_OWNER" != "root" ]; then
            check_fail "Config file has incorrect ownership: $FILE_OWNER (should be root)"
        fi
    fi
fi

if [ $EXIT_CODE -eq 0 ]; then
    log "All post-deployment checks passed"
else
    log "Post-deployment checks failed"
fi

exit $EXIT_CODE