#!/bin/bash
# Smoke test script for Cloud Infrastructure Platform
# Runs basic tests to verify core functionality after deployment
# Usage: ./smoke-test.sh [environment]

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
EXIT_CODE=0
TEST_COUNT=0
PASS_COUNT=0

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

test_fail() {
    log "❌ FAILED: $1"
    EXIT_CODE=1
}

test_pass() {
    log "✅ PASSED: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_exit_code="${3:-0}"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    log "Running test: $test_name"
    
    eval "$test_cmd"
    local actual_exit_code=$?
    
    if [ "$actual_exit_code" -eq "$expected_exit_code" ]; then
        test_pass "$test_name"
    else
        test_fail "$test_name (exit code: $actual_exit_code, expected: $expected_exit_code)"
    fi
}

log "Starting smoke tests for ${ENVIRONMENT} environment"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
fi

# Set default URL if not defined in environment file
APP_URL=${APP_URL:-"http://localhost:5000"}
log "Testing application at $APP_URL"

# Test 1: API health endpoint
run_test "API Health Endpoint" "curl -s -o /dev/null -w '%{http_code}' ${APP_URL}/api/health | grep -q 200"

# Test 2: Authentication endpoints
run_test "Authentication API Available" "curl -s -o /dev/null -w '%{http_code}' ${APP_URL}/api/auth/status | grep -q 200"

# Test 3: Static files
run_test "Static Files Accessible" "curl -s -o /dev/null -w '%{http_code}' ${APP_URL}/static/css/main.css | grep -q 200"

# Test 4: Database connection
run_test "Database Connection" "cd $PROJECT_ROOT && FLASK_APP=app.py FLASK_ENV=${ENVIRONMENT} flask db-check"

# Test 5: Core services running
if command -v systemctl &>/dev/null; then
    for service in cloud-platform nginx postgresql; do
        run_test "$service Service Running" "systemctl is-active --quiet $service"
    done
fi

# Test 6: API version endpoint
run_test "API Version Endpoint" "curl -s ${APP_URL}/api/version | grep -q version"

# Test 7: Security headers (production only)
if [ "$ENVIRONMENT" == "production" ]; then
    run_test "Security Headers" "curl -s -I ${APP_URL} | grep -q 'Strict-Transport-Security'"
fi

# Test 8: Error handling
run_test "Error Handling" "curl -s -o /dev/null -w '%{http_code}' ${APP_URL}/api/nonexistent | grep -q 404"

# Summary
log "Smoke tests completed: $PASS_COUNT/$TEST_COUNT tests passed"

if [ $EXIT_CODE -eq 0 ]; then
    log "✅ All smoke tests passed!"
else
    log "❌ Some smoke tests failed. Please check the logs."
fi

exit $EXIT_CODE