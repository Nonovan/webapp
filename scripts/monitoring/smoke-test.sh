#!/bin/bash
# Smoke test script for Cloud Infrastructure Platform
# Runs basic tests to verify core functionality after deployment or failover
# Usage: ./smoke-test.sh [environment] [--region primary|secondary] [--verbose] [--dr-mode]

set -e

# Default values
ENVIRONMENT=${1:-production}
REGION="primary"
VERBOSE=false
DR_MODE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
EXIT_CODE=0
TEST_COUNT=0
PASS_COUNT=0
SKIP_COUNT=0

# Parse arguments - shift the first argument if it's the environment name
shift_count=0
if [[ ! -z "$1" && "$1" != --* ]]; then
    shift_count=1  # Skip the environment parameter in the while loop
fi

while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --region)
            REGION="${2}"
            if [[ "$REGION" != "primary" && "$REGION" != "secondary" ]]; then
                echo "Error: Region must be 'primary' or 'secondary'"
                exit 1
            fi
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --region primary|secondary   Set region to test"
            echo "  --verbose, -v               Enable verbose output"
            echo "  --dr-mode                   Log to DR events system"
            echo "  --help, -h                  Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Load environment-specific configuration
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    [[ "$VERBOSE" = true ]] && echo "Loaded environment configuration from $ENV_FILE"
fi

# Determine endpoints based on region
if [[ "$REGION" = "primary" ]]; then
    API_ENDPOINT="${PRIMARY_API_ENDPOINT:-https://api.cloud-platform.example.com}"
    WEB_ENDPOINT="${PRIMARY_WEB_ENDPOINT:-https://cloud-platform.example.com}"
    DB_HOST="${PRIMARY_DB_HOST:-primary-db.internal}"
else
    API_ENDPOINT="${SECONDARY_API_ENDPOINT:-https://api-dr.cloud-platform.example.com}"
    WEB_ENDPOINT="${SECONDARY_WEB_ENDPOINT:-https://dr.cloud-platform.example.com}"
    DB_HOST="${SECONDARY_DB_HOST:-secondary-db.internal}"
fi

# Logging functions
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

debug_log() {
    if [[ "$VERBOSE" = true ]]; then
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

test_skip() {
    log "ℹ️ SKIPPED: $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# Function to run a test and track its result
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_exit_code="${3:-0}"
    local critical="${4:-true}"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    log "Running test: $test_name"
    
    if [[ "$VERBOSE" = true ]]; then
        debug_log "Command: $test_cmd"
        output=$(eval "$test_cmd" 2>&1)
        local actual_exit_code=$?
        debug_log "Output: $output"
    else
        # Only show output if the test fails
        output=$(eval "$test_cmd" 2>&1)
        local actual_exit_code=$?
    fi
    
    if [[ "$actual_exit_code" -eq "$expected_exit_code" ]]; then
        test_pass "$test_name"
    else
        test_fail "$test_name (exit code: $actual_exit_code, expected: $expected_exit_code)"
        [[ "$VERBOSE" = true ]] || echo "$output"  # Show output on failure
    fi
}

log "Starting smoke tests for ${ENVIRONMENT} environment in ${REGION} region"
log "Using API endpoint: ${API_ENDPOINT}"

# ---------------------
# Core Functionality Tests - These are the critical tests that must pass
# ---------------------

# Test 1: Basic connectivity to API health endpoint
run_test "API Health Check" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/health | grep -q 200"

# Test 2: Web UI is accessible
run_test "Web UI Accessibility" "curl -s -o /dev/null -w '%{http_code}' ${WEB_ENDPOINT} | grep -q 200"

# Test 3: Authentication service is working
run_test "Authentication Service" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/auth/status | grep -q 200"

# Test 4: Database Connectivity (using the database verification script)
if [[ -x "${PROJECT_ROOT}/scripts/database/database-manager.sh" ]]; then
    run_test "Database Connectivity" "${PROJECT_ROOT}/scripts/database/database-manager.sh verify-db --env ${ENVIRONMENT} --host ${DB_HOST} --quick-check"
elif [[ -x "${PROJECT_ROOT}/scripts/database/db_verify.sh" ]]; then
    run_test "Database Connectivity" "${PROJECT_ROOT}/scripts/database/db_verify.sh --host ${DB_HOST} --environment ${ENVIRONMENT} --quick-check"
else
    test_skip "Database verification (no verification script found)"
fi

# Test 5: Core API endpoint test
run_test "Core API" "curl -s -o /dev/null -w '%{http_code}' ${API_ENDPOINT}/api/version | grep -q 200"

# ---------------------
# Secondary Functionality Tests - Important but not critical
# ---------------------

# Test: Static assets
run_test "Static Assets" "curl -s -o /dev/null -w '%{http_code}' ${WEB_ENDPOINT}/static/css/main.css | grep -q 200" 0 false

# Test: DB Replication (only for secondary region)
if [[ "$REGION" = "secondary" ]]; then
    if [[ -x "${PROJECT_ROOT}/scripts/database/database-manager.sh" ]]; then
        run_test "Database Replication" "${PROJECT_ROOT}/scripts/database/database-manager.sh check-replication --env ${ENVIRONMENT}" 0 false
    elif [[ -x "${PROJECT_ROOT}/scripts/database/check_replication.sh" ]]; then
        run_test "Database Replication" "${PROJECT_ROOT}/scripts/database/check_replication.sh --environment ${ENVIRONMENT}" 0 false
    else
        test_skip "Database replication check (no verification script found)"
    fi
fi

# Summarize results
log "-----------------------------------------"
log "Tests completed: $TEST_COUNT, Passed: $PASS_COUNT, Failed: $((TEST_COUNT - PASS_COUNT - SKIP_COUNT)), Skipped: $SKIP_COUNT"

if [[ $EXIT_CODE -eq 0 ]]; then
    log "✅ All smoke tests PASSED in ${ENVIRONMENT} environment (${REGION} region)"
else
    log "❌ Smoke tests FAILED in ${ENVIRONMENT} environment (${REGION} region)"
fi

# If in DR mode, log the status to DR events log
if [[ "$DR_MODE" = true ]]; then
    mkdir -p "/var/log/cloud-platform"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),SMOKE_TEST,${ENVIRONMENT},${REGION},$([ $EXIT_CODE -eq 0 ] && echo 'SUCCESS' || echo 'FAILURE')" >> "/var/log/cloud-platform/dr-events.log"
    log "Smoke test result logged to DR events log"
fi

exit $EXIT_CODE