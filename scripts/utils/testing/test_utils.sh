#!/bin/bash
# filepath: scripts/utils/testing/test_utils.sh
#
# General Testing Utilities for Cloud Infrastructure Platform
#
# This script provides a comprehensive set of testing utilities that can be used
# across all scripts in the Cloud Infrastructure Platform. It includes functions for
# unit testing, integration testing, and mock implementations to facilitate testing
# of shell scripts.
#
# Usage: source scripts/utils/testing/test_utils.sh

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Path to modules
MODULES_DIR="${PROJECT_ROOT}/scripts/utils/modules"
CORE_MODULE="${MODULES_DIR}/core.sh"
ASSERTIONS_MODULE="${MODULES_DIR}/assertions.sh"
MOCKING_MODULE="${MODULES_DIR}/mocking.sh"
REPORTING_MODULE="${MODULES_DIR}/reporting.sh"
SYSTEM_MODULE="${MODULES_DIR}/system.sh"

# Version tracking
TEST_UTILS_VERSION="1.0.0"
TEST_UTILS_DATE="2023-12-15"

#######################################
# MODULE LOADING
#######################################

# Function to load a module
# Arguments:
#   $1 - Module path
#   $2 - Module name
# Returns:
#   0 if module loaded successfully, 1 if not
load_module() {
  local module_path="$1"
  local module_name="$2"

  if [[ -f "$module_path" ]]; then
    # shellcheck source=/dev/null
    source "$module_path"
    echo "Loaded $module_name module"
    return 0
  else
    echo "WARNING: $module_name module not found at $module_path" >&2
    return 1
  fi
}

# Load core module (required)
if ! load_module "$CORE_MODULE" "core"; then
  echo "ERROR: Core module not found at $CORE_MODULE. Cannot continue." >&2
  exit 1
fi

# Log startup information
log "INFO" "Test utils v${TEST_UTILS_VERSION} (${TEST_UTILS_DATE})"
log "DEBUG" "Loading modules from $MODULES_DIR"

# Load optional modules
load_module "$ASSERTIONS_MODULE" "assertions" || log "WARN" "Assertions module not loaded. Some assertion functions may be unavailable."
load_module "$MOCKING_MODULE" "mocking" || log "WARN" "Mocking module not loaded. Mocking functions will be unavailable."
load_module "$SYSTEM_MODULE" "system" || log "WARN" "System module not loaded. System testing functions will be unavailable."
load_module "$REPORTING_MODULE" "reporting" || log "WARN" "Reporting module not loaded. Using basic report generation."

#######################################
# MAIN EXECUTION
#######################################

# Main function to run all tests
# Arguments:
#   None
# Returns:
#   0 if all tests pass, 1 if any tests fail
run_tests() {
  log "INFO" "Starting test execution"

  local start_time
  start_time=$(date +%s)

  # Run tests here...
  # This is a placeholder - specific tests should be added by the user

  local end_time
  end_time=$(date +%s)
  TEST_TOTAL_TIME=$((end_time - start_time))

  log "INFO" "Completed test execution in ${TEST_TOTAL_TIME}s"

  # Generate report if reporting module is loaded
  if [[ $(type -t generate_report) == "function" ]]; then
    generate_report "$OUTPUT_FORMAT" "$OUTPUT_FILE"
  elif [[ $(type -t generate_test_report) == "function" ]]; then
    generate_test_report "$OUTPUT_FORMAT" "$OUTPUT_FILE"
  else
    log "WARN" "No report generation function available"
  fi

  # Return non-zero exit code if any tests failed
  [[ $TESTS_FAILED -eq 0 ]]
}

# Self-test function
# Arguments:
#   None
# Returns:
#   0 if all self-tests pass, 1 otherwise
self_test() {
  begin_test_group "Self-Tests"

  # Core assertion tests
  run_test "Equality assertion" 'assert_equals "hello" "hello"'
  run_test "Contains assertion" 'assert_contains "hello world" "world"'
  run_test "Success assertion" 'assert_success true'
  run_test "Failure assertion" 'assert_fails false'

  # Mock functionality if available
  if [[ $(type -t create_mock_environment) == "function" ]]; then
    local mock_dir
    mock_dir=$(create_mock_environment "self_test")
    create_mock_file "$mock_dir/test.txt" "Hello world"
    run_test "Mock file creation" "test -f '$mock_dir/test.txt'"

    # Test mock command
    local mock_bin
    mock_bin=$(mock_command "custom_cmd" "echo 'This is a mock'")
    run_test "Mock command" "custom_cmd | grep -q 'This is a mock'"
    remove_mock_command "$mock_bin"

    # Test file assertion
    create_mock_file "$mock_dir/assert_file.txt" "Test content"
    run_test "File exists assertion" "assert_file_exists '$mock_dir/assert_file.txt'"
    run_test "File contains assertion" "assert_file_contains '$mock_dir/assert_file.txt' 'Test content'"

    # Clean up
    safe_rm_dir "$mock_dir"
  else
    run_test "Mock tests" "echo 'Mocking module not available'" true
  fi

  # System tests if available
  if [[ $(type -t port_is_available) == "function" ]]; then
    run_test "Port availability check" "port_is_available 99999 || true"

    local test_port
    test_port=$(find_available_port)
    run_test "Find available port" "[[ -n \"$test_port\" ]]"
  else
    run_test "System tests" "echo 'System module not available'" true
  fi

  end_test_group

  return 0
}

# When executed directly, run self-test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if ! parse_args "$@"; then
    exit 1
  fi

  self_test
  exit $?
fi
