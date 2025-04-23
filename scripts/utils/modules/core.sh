#!/bin/bash
# filepath: scripts/utils/modules/core.sh
#
# Core testing functionality for Cloud Infrastructure Platform
#
# This module provides the foundation of the testing framework including
# test group management, test execution, and basic utilities.
#
# Part of: Cloud Infrastructure Platform - Testing Framework
#
# Usage: source "$(dirname "$0")/core.sh"
#
# Version: 1.0.0
# Date: 2023-12-20

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
readonly CORE_MODULE_VERSION="1.0.0"
readonly CORE_MODULE_DATE="2023-12-20"

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Output formatting
readonly BOLD='\033[1m'
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Test counters (global variables that should be accessible to all modules)
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
CURRENT_GROUP=""
TEST_GROUPS=()
TEST_RESULTS=()
COVERAGE_DATA=()

# Test timing data
TEST_START_TIME=0
TEST_TOTAL_TIME=0

# Test output settings with better default assignments
VERBOSE=${VERBOSE:-false}
QUIET=${QUIET:-false}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"text"}
OUTPUT_FILE=${OUTPUT_FILE:-""}
EXIT_ON_FAILURE=${EXIT_ON_FAILURE:-false}

# Timeout settings
readonly DEFAULT_TEST_TIMEOUT=60  # Default timeout in seconds for tests
readonly DEFAULT_COMMAND_TIMEOUT=30  # Default timeout in seconds for commands

# Security settings
readonly SECURE_TEMP_PERMS="700"  # Secure permissions for temporary directories

#######################################
# HELPER FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns:
#   0 if command exists, 1 otherwise
command_exists() {
  if [[ -z "${1:-}" ]]; then
    log "ERROR" "command_exists: No command specified"
    return 1
  fi
  command -v "$1" &> /dev/null
}

# Log a message with timestamp and level
# Arguments:
#   $1 - Log level (INFO, SUCCESS, WARN, ERROR, DEBUG)
#   $2 - Message to log
# Returns:
#   None
log() {
  local level="${1:-INFO}"
  local message="${2:-}"
  local color=""

  case "$level" in
    "INFO")    color="$BLUE";;
    "SUCCESS") color="$GREEN";;
    "WARN")    color="$YELLOW";;
    "ERROR")   color="$RED";;
    "DEBUG")   color="$CYAN";;
    *)         color="$NC";;
  esac

  # Skip debug messages unless verbose mode is enabled
  if [[ "$level" == "DEBUG" && "$VERBOSE" != "true" ]]; then
    return 0
  fi

  # Skip all messages if quiet mode is enabled, except for errors
  if [[ "$QUIET" == "true" && "$level" != "ERROR" ]]; then
    return 0
  fi

  echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message${NC}" >&2
}

# Create a temporary directory with proper error handling and secure permissions
# Arguments:
#   $1 - Optional prefix for the temp directory (default: 'test_utils')
# Returns:
#   Path to the temporary directory or exits with error
create_temp_dir() {
  local prefix="${1:-test_utils}"
  local temp_dir

  # Sanitize prefix for safety
  prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_-')

  # Create temp directory with fallbacks
  temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t "${prefix}_XXXXXX" 2>/dev/null)

  if [[ ! -d "$temp_dir" ]]; then
    log "ERROR" "Failed to create temporary directory"
    return 1
  fi

  # Secure the directory with restrictive permissions
  chmod "$SECURE_TEMP_PERMS" "$temp_dir" 2>/dev/null || log "WARN" "Failed to set secure permissions on temporary directory: $temp_dir"

  echo "$temp_dir"
}

# Safely remove a directory with validation
# Arguments:
#   $1 - Directory path to remove
# Returns:
#   0 on success, 1 on failure
safe_rm_dir() {
  local dir="${1:-}"

  # Validate input
  if [[ -z "$dir" ]]; then
    log "ERROR" "safe_rm_dir: No directory specified"
    return 1
  fi

  # Safety check - don't delete system directories or current directory
  if [[ "$dir" == "/" || "$dir" == "/home" || "$dir" == "/usr" || "$dir" == "." ]]; then
    log "ERROR" "safe_rm_dir: Refusing to remove potentially dangerous path: $dir"
    return 1
  fi

  # Only remove directories under /tmp or with specific prefixes for safety
  if [[ -d "$dir" && ("$dir" == /tmp/* || "$dir" == */tmp/*) ]]; then
    rm -rf "$dir" 2>/dev/null || {
      log "WARN" "Failed to remove directory: $dir"
      return 1
    }
    return 0
  else
    log "ERROR" "safe_rm_dir: Path is not a directory or not in a safe location: $dir"
    return 1
  fi
}

# Run a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2... - Command to run and its arguments
# Returns:
#   Exit status of the command or 124 if timed out
run_with_timeout() {
  local timeout="${1:-$DEFAULT_COMMAND_TIMEOUT}"
  shift

  # Check if timeout command is available
  if command_exists timeout; then
    timeout "$timeout" "$@"
    return $?
  elif command_exists gtimeout; then
    # For macOS with GNU coreutils installed
    gtimeout "$timeout" "$@"
    return $?
  else
    # Fallback with no timeout
    log "WARN" "timeout command not available, running without timeout"
    "$@"
    return $?
  fi
}

#######################################
# TEST FRAMEWORK CORE
#######################################

# Begin a test group
# Arguments:
#   $1 - Group name
# Returns:
#   0 on success, 1 on error
begin_test_group() {
  local group_name="${1:-}"

  if [[ -z "$group_name" ]]; then
    log "ERROR" "begin_test_group: No group name specified"
    return 1
  fi

  CURRENT_GROUP="$group_name"
  TEST_GROUPS+=("$CURRENT_GROUP")
  log "INFO" "Starting test group: $CURRENT_GROUP"

  return 0
}

# End current test group
# Arguments:
#   None
# Returns:
#   None
end_test_group() {
  local group_name="${CURRENT_GROUP:-Unknown group}"
  log "INFO" "Finished test group: $group_name"
  CURRENT_GROUP=""
}

# Run a test function and record results
# Arguments:
#   $1 - Test name
#   $2 - Test function or command to run
#   $3 - Optional flag to skip the test (default: false)
#   $4 - Optional timeout in seconds (default: DEFAULT_TEST_TIMEOUT)
# Returns:
#   0 on test pass, 1 on test fail
run_test() {
  local test_name="${1:-}"
  local test_cmd="${2:-}"
  local should_skip="${3:-false}"
  local test_timeout="${4:-$DEFAULT_TEST_TIMEOUT}"

  # Input validation
  if [[ -z "$test_name" ]]; then
    log "ERROR" "run_test: No test name specified"
    return 1
  fi

  if [[ -z "$test_cmd" ]]; then
    log "ERROR" "run_test: No test command specified for: $test_name"
    return 1
  fi

  local full_test_name="${CURRENT_GROUP:+$CURRENT_GROUP: }$test_name"
  local test_result="PASS"
  local test_message=""
  local test_start
  test_start=$(date +%s.%N 2>/dev/null || date +%s)
  local test_exit_code=0

  ((TESTS_TOTAL++))

  log "INFO" "Running test: $full_test_name"

  if [[ "$should_skip" == "true" ]]; then
    ((TESTS_SKIPPED++))
    test_result="SKIP"
    test_message="Test skipped"
    log "WARN" "⚠️ SKIPPED: $full_test_name - $test_message"
  else
    # Create isolated test directory with secure permissions
    local test_dir
    test_dir=$(create_temp_dir "test_${test_name// /_}")

    if [[ -z "$test_dir" || ! -d "$test_dir" ]]; then
      log "ERROR" "Failed to create test directory for: $full_test_name"
      return 1
    }

    # Run the test in a subshell to isolate it
    local output_file="$test_dir/output.txt"
    local error_file="$test_dir/error.txt"

    # Use timeout and eval with appropriate error handling
    if run_with_timeout "$test_timeout" bash -c "set -o pipefail; eval '$test_cmd'" > "$output_file" 2> "$error_file"; then
      ((TESTS_PASSED++))
      log "SUCCESS" "✅ PASSED: $full_test_name"
      test_result="PASS"
    else
      test_exit_code=$?
      ((TESTS_FAILED++))

      # Check if it was a timeout
      if [[ $test_exit_code -eq 124 ]]; then
        test_message="Test timed out after ${test_timeout}s"
      else
        test_message="$(cat "$error_file" 2>/dev/null || echo 'No error message')"
      fi

      log "ERROR" "❌ FAILED: $full_test_name"
      log "ERROR" "Error message: $test_message"
      log "ERROR" "Exit code: $test_exit_code"

      if [[ "$VERBOSE" == "true" ]]; then
        log "DEBUG" "Command output: $(cat "$output_file" 2>/dev/null || echo 'No output')"
      fi

      test_result="FAIL"

      if [[ "$EXIT_ON_FAILURE" == "true" ]]; then
        safe_rm_dir "$test_dir"
        log "ERROR" "Exiting due to test failure"
        exit 1
      fi
    fi

    # Clean up
    safe_rm_dir "$test_dir"
  fi

  # Calculate test duration
  local test_end
  test_end=$(date +%s.%N 2>/dev/null || date +%s)
  local duration
  # Use bc if available, otherwise fall back to integer math
  if command_exists bc; then
    duration=$(echo "$test_end - $test_start" | bc 2>/dev/null || echo "0")
  else
    duration=$((test_end - test_start))
  fi

  # Store test result
  TEST_RESULTS+=("$full_test_name|$test_result|$duration|$test_message")

  # Track file coverage if relevant
  if [[ "$test_cmd" == *"source "* ]]; then
    local file
    file=$(echo "$test_cmd" | grep -o "source [^ ]*" | cut -d' ' -f2)
    COVERAGE_DATA+=("$file")
  fi

  # Return appropriate status code
  [[ "$test_result" == "PASS" || "$test_result" == "SKIP" ]]
}

#######################################
# CLI INTERFACE
#######################################

# Parse command line arguments
# Arguments:
#   $@ - Command line arguments
# Returns:
#   0 on success, 1 on failure
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --verbose|-v)
        VERBOSE=true
        shift
        ;;
      --quiet|-q)
        QUIET=true
        shift
        ;;
      --output|-o)
        if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
          OUTPUT_FILE="$2"
          shift 2
        else
          log "ERROR" "Option --output requires an argument"
          return 1
        fi
        ;;
      --format|-f)
        if [[ -n "${2:-}" && "${2:-}" =~ ^(text|json|junit)$ ]]; then
          OUTPUT_FORMAT="$2"
          shift 2
        else
          log "ERROR" "Option --format requires an argument: text, json, or junit"
          return 1
        fi
        ;;
      --exit-on-failure|-x)
        EXIT_ON_FAILURE=true
        shift
        ;;
      --help|-h)
        show_usage
        exit 0
        ;;
      *)
        log "ERROR" "Unknown option: $1"
        show_usage
        return 1
        ;;
    esac
  done

  return 0
}

# Show script usage
# Arguments:
#   None
# Returns:
#   None
show_usage() {
  cat <<EOF
USAGE: $(basename "$0") [OPTIONS]

General Testing Utilities for Cloud Infrastructure Platform v$CORE_MODULE_VERSION

OPTIONS:
  --verbose, -v             Show more detailed output
  --quiet, -q               Show minimal output
  --output, -o FILE         Save test results to FILE
  --format, -f FORMAT       Output format: text, json, or junit
  --exit-on-failure, -x     Exit immediately on first test failure
  --help, -h                Show this help message

EXAMPLES:
  # Run tests and show detailed output
  $(basename "$0") --verbose

  # Generate a JUnit XML report
  $(basename "$0") --format junit --output results.xml

  # Run silently but exit on first failure
  $(basename "$0") --quiet --exit-on-failure
EOF
}

# Self-test to verify core functionality works
# Arguments:
#   None
# Returns:
#   0 on success, 1 on failure
core_self_test() {
  # Only run if executed directly
  if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    return 0
  fi

  local original_verbose="$VERBOSE"
  VERBOSE=true

  log "INFO" "Running core module self-test"

  # Test logging functions
  log "INFO" "Testing INFO log level"
  log "SUCCESS" "Testing SUCCESS log level"
  log "WARN" "Testing WARN log level"
  log "ERROR" "Testing ERROR log level"
  log "DEBUG" "Testing DEBUG log level"

  # Test temporary directory creation
  local temp_dir
  temp_dir=$(create_temp_dir "core_test") || {
    log "ERROR" "Failed to create temporary directory"
    return 1
  }
  log "SUCCESS" "Created temporary directory: $temp_dir"

  # Test temporary directory removal
  safe_rm_dir "$temp_dir" || {
    log "ERROR" "Failed to remove temporary directory: $temp_dir"
    return 1
  }
  log "SUCCESS" "Removed temporary directory: $temp_dir"

  # Test test group functions
  begin_test_group "Self-Test Group"
  log "INFO" "Current test group: $CURRENT_GROUP"

  # Test run_test with success
  run_test "Success test" "true" || {
    log "ERROR" "Failed to run success test"
    return 1
  }

  # Test run_test with failure (should not exit since we capture the return)
  local exit_on_failure_orig="$EXIT_ON_FAILURE"
  EXIT_ON_FAILURE=false
  run_test "Failure test" "false" || log "SUCCESS" "Correctly detected test failure"
  EXIT_ON_FAILURE="$exit_on_failure_orig"

  # Test run_test with skip
  run_test "Skip test" "true" true || {
    log "ERROR" "Failed to run skip test"
    return 1
  }

  end_test_group
  log "SUCCESS" "Test group ended, current group: '$CURRENT_GROUP'"

  # Restore original verbose setting
  VERBOSE="$original_verbose"

  log "SUCCESS" "Core module self-test completed successfully"
  return 0
}

#######################################
# EXPORT PUBLIC API
#######################################

# Export all public functions and variables
export -f command_exists
export -f log
export -f create_temp_dir
export -f safe_rm_dir
export -f run_with_timeout
export -f begin_test_group
export -f end_test_group
export -f run_test
export -f parse_args
export -f show_usage
export -f core_self_test

# Export constants and variables
export BOLD RED GREEN YELLOW BLUE CYAN NC
export TESTS_TOTAL TESTS_PASSED TESTS_FAILED TESTS_SKIPPED
export CURRENT_GROUP TEST_GROUPS TEST_RESULTS COVERAGE_DATA
export TEST_START_TIME TEST_TOTAL_TIME
export VERBOSE QUIET OUTPUT_FORMAT OUTPUT_FILE EXIT_ON_FAILURE
export CORE_MODULE_VERSION CORE_MODULE_DATE
export DEFAULT_TEST_TIMEOUT DEFAULT_COMMAND_TIMEOUT
export SECURE_TEMP_PERMS

# Execute self-test if the script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  core_self_test
  exit $?
fi
