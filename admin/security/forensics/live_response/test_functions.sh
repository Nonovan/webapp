#!/bin/bash
# Test helper functions for Live Response Forensic Tools

# Load common utility functions if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/common_functions.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/common_functions.sh"
else
    echo "WARN: common_functions.sh not found, using basic logging." >&2
    # Define minimal logging if common_functions is missing
    log_info() { echo "[INFO] $*"; }
    log_warn() { echo "[WARN] $*" >&2; }
    log_error() { echo "[ERROR] $*" >&2; }
    log_debug() { echo "[DEBUG] $*"; }
    log_success() { echo "[SUCCESS] $*"; }
fi

# --- Test Tracking Variables ---
TEST_COUNT=0
TEST_PASS_COUNT=0
TEST_FAIL_COUNT=0
CURRENT_TEST_NAME=""

# --- Basic Assertion Functions ---

# Assert that two strings are equal
# Arguments:
#   $1: Actual value
#   $2: Expected value
#   $3: Test description (optional)
assert_equals() {
    local actual="$1"
    local expected="$2"
    local description="${3:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ "$actual" == "$expected" ]]; then
        log_success "PASS: $test_name"
        ((TEST_PASS_COUNT++))
        return 0
    else
        log_error "FAIL: $test_name"
        log_error "  Expected: '$expected'"
        log_error "  Actual:   '$actual'"
        ((TEST_FAIL_COUNT++))
        return 1
    fi
}

# Assert that a command executes successfully (exit code 0)
# Arguments:
#   $1: Command to execute (as a string)
#   $2: Test description (optional)
assert_success() {
    local cmd="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local output
    local exit_code=0

    ((TEST_COUNT++))
    log_debug "Running command: $cmd"
    output=$(eval "$cmd" 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "PASS: $test_name"
        ((TEST_PASS_COUNT++))
        return 0
    else
        log_error "FAIL: $test_name (Exit code: $exit_code)"
        log_error "  Command: $cmd"
        log_error "  Output: $output"
        ((TEST_FAIL_COUNT++))
        return 1
    fi
}

# Assert that a command fails (non-zero exit code)
# Arguments:
#   $1: Command to execute (as a string)
#   $2: Test description (optional)
assert_fail() {
    local cmd="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local output
    local exit_code=0

    ((TEST_COUNT++))
    log_debug "Running command: $cmd"
    output=$(eval "$cmd" 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_success "PASS: $test_name (Exit code: $exit_code)"
        ((TEST_PASS_COUNT++))
        return 0
    else
        log_error "FAIL: $test_name (Expected non-zero exit code, got 0)"
        log_error "  Command: $cmd"
        log_error "  Output: $output"
        ((TEST_FAIL_COUNT++))
        return 1
    fi
}

# Assert that a file exists
# Arguments:
#   $1: File path
#   $2: Test description (optional)
assert_file_exists() {
    local file_path="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ -f "$file_path" ]]; then
        log_success "PASS: $test_name (File exists: $file_path)"
        ((TEST_PASS_COUNT++))
        return 0
    else
        log_error "FAIL: $test_name (File does not exist: $file_path)"
        ((TEST_FAIL_COUNT++))
        return 1
    fi
}

# --- Test Runner Functions ---

# Function to run a single test function
# Arguments:
#   $1: Name of the test function to run
run_test_function() {
    local test_func="$1"
    CURRENT_TEST_NAME="$test_func"
    log_info "--- Running test: $test_func ---"

    if declare -f "$test_func" > /dev/null; then
        # Execute the test function in a subshell to isolate environment changes
        ( "$test_func" )
        local result=$?
        if [[ $result -ne 0 ]]; then
             log_warn "Test function $test_func exited with status $result"
             # Note: Individual assertions track failures, this catches early exits
        fi
    else
        log_error "FAIL: Test function '$test_func' not found."
        ((TEST_FAIL_COUNT++))
        ((TEST_COUNT++)) # Count this as a failed test execution attempt
    fi
    CURRENT_TEST_NAME=""
    echo # Add a newline for readability
}

# Function to run all functions in the current script starting with "test_"
run_all_tests() {
    log_info "============================="
    log_info "Starting Live Response Tests"
    log_info "============================="
    TEST_COUNT=0
    TEST_PASS_COUNT=0
    TEST_FAIL_COUNT=0

    # Find all functions starting with test_
    local test_functions
    test_functions=$(declare -F | awk '/^declare -f test_/ {print $3}')

    for func in $test_functions; do
        run_test_function "$func"
    done

    log_info "============================="
    log_info "Test Summary"
    log_info "============================="
    log_info "Total tests run: $TEST_COUNT"
    log_success "Passed: $TEST_PASS_COUNT"
    if [[ $TEST_FAIL_COUNT -gt 0 ]]; then
        log_error "Failed: $TEST_FAIL_COUNT"
        return 1
    else
        log_info "Failed: 0"
        return 0
    fi
}

# Example usage (can be removed or adapted):
# test_example_pass() {
#     assert_equals "hello" "hello" "String equality"
#     assert_success "echo 'Success'" "Command success"
#     assert_file_exists "$0" "This script file exists"
# }
#
# test_example_fail() {
#     assert_equals "hello" "world" "String inequality"
#     assert_fail "echo 'Should fail but succeeds'" "Command failure expected"
#     assert_file_exists "/non/existent/file" "Non-existent file"
# }
#
# # To run tests if this script is executed directly:
# if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
#     # Initialize common functions if needed (e.g., for logging setup)
#     if declare -f init_common_functions > /dev/null; then
#         init_common_functions
#     fi
#     run_all_tests
#     exit $?
# fi

log_debug "test_functions.sh sourced."
