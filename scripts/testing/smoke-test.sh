#!/bin/bash
# Smoke test script for Cloud Infrastructure Platform
# Runs basic tests to verify core functionality after deployment or failover
# Usage: ./smoke-test.sh [environment] [--region primary|secondary] [--verbose]

set -e

# Default values
ENVIRONMENT=${1:-production}
REGION="primary"
VERBOSE=false
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
EXIT_CODE=0
TEST_COUNT=0
PASS_COUNT=0

# Parse arguments
shift_count=0
if [ ! -z "$1" ]; then
    if [ "$1" != "--region" ] && [ "$1" != "--verbose" ]; then
        shift_count=1
    fi
fi

# Add DR mode parameter
DR_MODE=false

# Update parameter parsing in the while loop
while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --region)
            REGION="${2}"
            if [ "$REGION" != "primary" ] && [ "$REGION" != "secondary" ]; then
                echo "Error: Region must be 'primary' or 'secondary'"
                exit 1
            fi
            shift
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Load environment-specific configuration
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
fi

# Determine endpoints based on region
if [ "$REGION" = "primary" ]; then
    API_ENDPOINT="${PRIMARY_API_ENDPOINT:-https://api.cloud-platform.example.com}"
    WEB_ENDPOINT="${PRIMARY_WEB_ENDPOINT:-https://cloud-platform.example.com}"
    DB_HOST="${PRIMARY_DB_HOST:-primary-db.internal}"
else
    API_ENDPOINT="${SECONDARY_API_ENDPOINT:-https://api-dr.cloud-platform.example.com}"
    WEB_ENDPOINT="${SECONDARY_WEB_ENDPOINT:-https://dr.cloud-platform.example.com}"
    DB_HOST="${SECONDARY_DB_HOST:-secondary-db.internal}"
fi

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

debug_log() {
    if [ "$VERBOSE" = true ]; then
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        echo "[$timestamp] DEBUG: $1"
    fi
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
    
    # Capture both stdout and stderr when in verbose mode
    if [ "$VERBOSE" = true ]; then
        debug_log "Command: $test_cmd"
        output=$(eval "$test_cmd" 2>&1)
        local actual_exit_code=$?
        debug_log "Output: $output"
    else
        eval "$test_cmd" >/dev/null 2>&1
        local actual_exit_code=$?
    fi
    
    if [ "$actual_exit_code" -eq "$expected_exit_code" ]; then
        test_pass "$test_name"
    else
        test_fail "$test_name (exit code: $actual_exit_code, expected: $expected_exit_code)"
    fi
}

log "Starting smoke tests for ${ENVIRONMENT} environment in ${REGION} region"
log "Using API endpoint: ${API_ENDPOINT}"

# Test 1: Basic connectivity to API health endpoint
run_test "API Health Check" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/health | grep -q 200"

# Test 2: Web UI is accessible
run_test "Web UI Accessibility" "curl -s -o /dev/null -w '%{http_code}' ${WEB_ENDPOINT} | grep -q 200"

# Test 3: Authentication service is working
run_test "Authentication Service" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/auth/status | grep -q 200"

# Test 4: Database Connectivity (using the database verification script)
if [ -x "${PROJECT_ROOT}/scripts/database/db_verify.sh" ]; then
    run_test "Database Connectivity" "${PROJECT_ROOT}/scripts/database/db_verify.sh --host ${DB_HOST} --environment ${ENVIRONMENT} --quick-check"
else
    log "⚠️ WARNING: Database verification script not found, skipping database test"
fi

# Test 5: Cloud Provider Services Integration
run_test "Cloud Provider Integration" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/cloud/status | grep -q 200"

# Test 6: Monitoring System Check
run_test "Monitoring System" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/health/metrics | grep -q 200"

# Test 7: ICS Integration Check (if enabled)
if [ "${ICS_ENABLED:-false}" = "true" ]; then
    run_test "ICS Integration" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/ics/status | grep -q 200"
else
    log "ℹ️ INFO: ICS integration not enabled, skipping ICS test"
fi

# Test 8: Static asset availability
run_test "Static Assets" "curl -s -o /dev/null -w '%{http_code}' ${WEB_ENDPOINT}/static/css/main.css | grep -q 200"

# Test 9: File integrity (for security)
if [ -x "${PROJECT_ROOT}/scripts/security/verify_files.py" ]; then
    run_test "File Integrity" "python3 ${PROJECT_ROOT}/scripts/security/verify_files.py --environment ${ENVIRONMENT} --region ${REGION}"
else
    log "⚠️ WARNING: File integrity verification script not found, skipping integrity test"
fi

# Test 10: DR-specific test - Database replication status
if [ "$REGION" = "secondary" ]; then
    if [ -x "${PROJECT_ROOT}/scripts/database/check_replication.sh" ]; then
        run_test "Database Replication" "${PROJECT_ROOT}/scripts/database/check_replication.sh --environment ${ENVIRONMENT}"
    else
        log "⚠️ WARNING: Database replication check script not found, skipping replication test"
    fi
fi

# Summarize results
log "Tests completed: $TEST_COUNT, Passed: $PASS_COUNT, Failed: $((TEST_COUNT - PASS_COUNT))"

if [ $EXIT_CODE -eq 0 ]; then
    log "✅ All smoke tests PASSED in ${ENVIRONMENT} environment (${REGION} region)"
    
    # Record successful test in DR log if this is part of DR process
    if [ -n "${DR_PROCESS}" ] && [ "${DR_PROCESS}" = "true" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),SMOKE_TEST,${ENVIRONMENT},${REGION},SUCCESS" >> /var/log/cloud-platform/dr-events.log
    fi
else
    log "❌ Smoke tests FAILED in ${ENVIRONMENT} environment (${REGION} region)"
    
    # Record failed test in DR log if this is part of DR process
    if [ -n "${DR_PROCESS}" ] && [ "${DR_PROCESS}" = "true" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),SMOKE_TEST,${ENVIRONMENT},${REGION},FAILURE" >> /var/log/cloud-platform/dr-events.log
    fi
fi

# If in DR mode, log the status to DR events log
if [ "$DR_MODE" = true ]; then
    mkdir -p "/var/log/cloud-platform"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),SMOKE_TEST,${ENVIRONMENT},${REGION},$([ $EXIT_CODE -eq 0 ] && echo 'SUCCESS' || echo 'FAILURE')" >> "/var/log/cloud-platform/dr-events.log"
    log "Smoke test result logged to DR events log"
fi

exit $EXIT_CODE