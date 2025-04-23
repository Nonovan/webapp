#!/bin/bash
# filepath: scripts/utils/modules/core.sh
#
# Core testing functionality for Cloud Infrastructure Platform
#
# This module provides the foundation of the testing framework including
# test group management, test execution, and basic utilities.
#
# Usage: source "$(dirname "$0")/core.sh"

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
CORE_MODULE_VERSION="1.0.0"
CORE_MODULE_DATE="2023-12-15"

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Output formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

#######################################
# HELPER FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns:
#   0 if command exists, 1 otherwise
command_exists() {
  command -v "$1" &> /dev/null
}

# Log a message if not in quiet mode
# Arguments:
#   $1 - Log level (INFO, SUCCESS, WARN, ERROR, DEBUG)
#   $2 - Message to log
# Returns:
#   None
log() {
  local level="$1"
  local message="$2"
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

# Create a temporary directory with proper error handling
# Returns:
#   Path to the temporary directory or exits with error
create_temp_dir() {
  local temp_dir
  temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'test_utils_temp')

  if [[ ! -d "$temp_dir" ]]; then
    log "ERROR" "Failed to create temporary directory"
    exit 1
  fi

  echo "$temp_dir"
}

# Safely remove a directory
# Arguments:
#   $1 - Directory path to remove
# Returns:
#   None
safe_rm_dir() {
  local dir="$1"

  if [[ -d "$dir" && "$dir" == /tmp/* ]]; then
    rm -rf "$dir" 2>/dev/null || log "WARN" "Failed to remove directory: $dir"
  fi
}

#######################################
# TEST FRAMEWORK CORE
#######################################

# Begin a test group
# Arguments:
#   $1 - Group name
# Returns:
#   None
begin_test_group() {
  CURRENT_GROUP="$1"
  TEST_GROUPS+=("$CURRENT_GROUP")
  log "INFO" "Starting test group: $CURRENT_GROUP"
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
# Returns:
#   None - Updates global test counters
run_test() {
  local test_name="$1"
  local test_cmd="$2"
  local should_skip="${3:-false}"

  local full_test_name="${CURRENT_GROUP:+$CURRENT_GROUP: }$test_name"
  local test_result="PASS"
  local test_message=""
  local test_start
  test_start=$(date +%s.%N 2>/dev/null || date +%s)

  ((TESTS_TOTAL++))

  log "INFO" "Running test: $full_test_name"

  if [[ "$should_skip" == "true" ]]; then
    ((TESTS_SKIPPED++))
    test_result="SKIP"
    test_message="Test skipped"
    log "WARN" "⚠️ SKIPPED: $full_test_name - $test_message"
  else
    # Create isolated test directory
    local test_dir
    test_dir=$(create_temp_dir)

    # Run the test in a subshell to isolate it
    local output_file="$test_dir/output.txt"
    local error_file="$test_dir/error.txt"

    # Use eval with appropriate error handling
    if ( set -o pipefail; eval "$test_cmd" > "$output_file" 2> "$error_file" ); then
      ((TESTS_PASSED++))
      log "SUCCESS" "✅ PASSED: $full_test_name"
      test_result="PASS"
    else
      ((TESTS_FAILED++))
      test_message="$(cat "$error_file" 2>/dev/null || echo 'No error message')"
      log "ERROR" "❌ FAILED: $full_test_name"
      log "ERROR" "Error message: $test_message"

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
  duration=$(echo "$test_end - $test_start" | bc 2>/dev/null || echo "0")

  # Store test result
  TEST_RESULTS+=("$full_test_name|$test_result|$duration|$test_message")

  # Track file coverage if relevant
  if [[ "$test_cmd" == *"source "* ]]; then
    local file
    file=$(echo "$test_cmd" | grep -o "source [^ ]*" | cut -d' ' -f2)
    COVERAGE_DATA+=("$file")
  fi
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
        if [[ -n "$2" && "$2" != -* ]]; then
          OUTPUT_FILE="$2"
          shift 2
        else
          log "ERROR" "Option --output requires an argument"
          return 1
        fi
        ;;
      --format|-f)
        if [[ -n "$2" && "$2" =~ ^(text|json|junit)$ ]]; then
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

# Export all public functions and variables
export -f command_exists
export -f log
export -f create_temp_dir
export -f safe_rm_dir
export -f begin_test_group
export -f end_test_group
export -f run_test
export -f parse_args
export -f show_usage

# Export constants and variables
export BOLD RED GREEN YELLOW BLUE CYAN NC
export TESTS_TOTAL TESTS_PASSED TESTS_FAILED TESTS_SKIPPED
export CURRENT_GROUP TEST_GROUPS TEST_RESULTS COVERAGE_DATA
export TEST_START_TIME TEST_TOTAL_TIME
export VERBOSE QUIET OUTPUT_FORMAT OUTPUT_FILE EXIT_ON_FAILURE
export CORE_MODULE_VERSION CORE_MODULE_DATE
