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

# Version tracking
TEST_UTILS_VERSION="1.0.0"
TEST_UTILS_DATE="2023-12-15"

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Path to common functions
COMMON_FUNCTIONS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

# Path to modules
MODULES_DIR="${PROJECT_ROOT}/scripts/utils/modules"
REPORTING_MODULE="${MODULES_DIR}/reporting.sh"

#######################################
# ENVIRONMENT & CONFIGURATION
#######################################

# Test output formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
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
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"text"}  # Options: text, json, junit
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
# ASSERTION METHODS
#######################################

# Assert that two values are equal
# Arguments:
#   $1 - Actual value
#   $2 - Expected value
#   $3 - Optional message
# Returns:
#   0 if values are equal, 1 otherwise
assert_equals() {
  local actual="$1"
  local expected="$2"
  local message="${3:-Values should be equal}"

  if [[ "$actual" == "$expected" ]]; then
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Expected: '$expected'" >&2
    echo "Actual  : '$actual'" >&2
    return 1
  fi
}

# Assert that a value contains a substring
# Arguments:
#   $1 - String to search in
#   $2 - Substring to search for
#   $3 - Optional message
# Returns:
#   0 if string contains substring, 1 otherwise
assert_contains() {
  local string="$1"
  local substring="$2"
  local message="${3:-String should contain substring}"

  if [[ "$string" == *"$substring"* ]]; then
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "String  : '$string'" >&2
    echo "Expected to contain: '$substring'" >&2
    return 1
  fi
}

# Assert that a command succeeds
# Arguments:
#   $@ - Command and its arguments
# Returns:
#   0 if command succeeds, 1 otherwise
assert_success() {
  local exit_code=0
  local output
  output=$("$@" 2>&1) || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    return 0
  else
    echo "Command was expected to succeed but failed with exit code $exit_code" >&2
    echo "Command: $*" >&2
    echo "Output: $output" >&2
    return 1
  fi
}

# Assert that a command fails
# Arguments:
#   $@ - Command and its arguments
# Returns:
#   0 if command fails, 1 otherwise
assert_fails() {
  local exit_code=0
  local output
  output=$("$@" 2>&1) || exit_code=$?

  if [[ $exit_code -ne 0 ]]; then
    return 0
  else
    echo "Command was expected to fail but succeeded" >&2
    echo "Command: $*" >&2
    echo "Output: $output" >&2
    return 1
  fi
}

# Assert that a file exists
# Arguments:
#   $1 - File path
#   $2 - Optional message
# Returns:
#   0 if file exists, 1 otherwise
assert_file_exists() {
  local file="$1"
  local message="${2:-File should exist}"

  if [[ -f "$file" ]]; then
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File does not exist: $file" >&2
    return 1
  fi
}

# Assert that a directory exists
# Arguments:
#   $1 - Directory path
#   $2 - Optional message
# Returns:
#   0 if directory exists, 1 otherwise
assert_dir_exists() {
  local dir="$1"
  local message="${2:-Directory should exist}"

  if [[ -d "$dir" ]]; then
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Directory does not exist: $dir" >&2
    return 1
  fi
}

# Assert that a file contains a specific string
# Arguments:
#   $1 - File path
#   $2 - String to search for
#   $3 - Optional message
# Returns:
#   0 if file contains string, 1 otherwise
assert_file_contains() {
  local file="$1"
  local search_string="$2"
  local message="${3:-File should contain the specified string}"

  if [[ ! -f "$file" ]]; then
    echo "Assertion failed: File does not exist" >&2
    echo "File path: $file" >&2
    return 1
  fi

  if grep -q "$search_string" "$file"; then
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File: $file" >&2
    echo "Does not contain: '$search_string'" >&2
    return 1
  fi
}

#######################################
# MOCKING FRAMEWORK
#######################################

# Create a mock directory for testing
# Arguments:
#   $1 - Name to identify the mock environment
# Returns:
#   Path to the mock directory
create_mock_environment() {
  local name="$1"
  local mock_dir
  mock_dir=$(create_temp_dir)

  echo "$mock_dir"
}

# Create a mock file with specified content
# Arguments:
#   $1 - Path to the mock file
#   $2 - Content for the file
# Returns:
#   0 on success, 1 on failure
create_mock_file() {
  local file_path="$1"
  local content="$2"

  mkdir -p "$(dirname "$file_path")" || {
    echo "Failed to create directory for mock file: $(dirname "$file_path")" >&2
    return 1
  }

  echo "$content" > "$file_path" || {
    echo "Failed to write content to mock file: $file_path" >&2
    return 1
  }

  if [[ "$file_path" == *.sh ]]; then
    chmod +x "$file_path" || {
      echo "Failed to make mock script executable: $file_path" >&2
      return 1
    }
  fi

  return 0
}

# Create a mock function that replaces a real command
# Arguments:
#   $1 - Command to mock
#   $2 - Script content to execute instead
# Returns:
#   Path to the mock directory
mock_command() {
  local cmd="$1"
  local script="$2"
  local mock_dir
  mock_dir=$(create_temp_dir)

  # Create mock script
  echo "#!/bin/bash" > "$mock_dir/$cmd"
  echo "$script" >> "$mock_dir/$cmd"
  chmod +x "$mock_dir/$cmd"

  # Add to PATH to ensure it's used
  export PATH="$mock_dir:$PATH"

  echo "$mock_dir"
}

# Remove a mock command
# Arguments:
#   $1 - Path returned by mock_command
# Returns:
#   0 on success, 1 on failure
remove_mock_command() {
  local mock_dir="$1"

  if [[ -d "$mock_dir" ]]; then
    safe_rm_dir "$mock_dir"
  fi

  # Restore original PATH
  export PATH=$(echo "$PATH" | sed "s|${mock_dir}:||")

  return 0
}

#######################################
# SYSTEM TESTING UTILITIES
#######################################

# Check if a port is available
# Arguments:
#   $1 - Port number to check
# Returns:
#   0 if port is available, 1 if in use or error
port_is_available() {
  local port="$1"

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "Invalid port number: $port" >&2
    return 1
  fi

  ! (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

# Find an available port
# Returns:
#   An available port number
find_available_port() {
  local port=0
  local max_attempts=50
  local attempt=0

  while [[ $port -eq 0 || ! $(port_is_available "$port") ]]; do
    port=$((10000 + RANDOM % 50000))
    ((attempt++))

    if [[ $attempt -ge $max_attempts ]]; then
      echo "Failed to find available port after $max_attempts attempts" >&2
      return 1
    fi
  done

  echo "$port"
}

# Wait for a service to be ready on a specific port
# Arguments:
#   $1 - Host
#   $2 - Port
#   $3 - Timeout in seconds (optional, default: 30)
# Returns:
#   0 if service becomes available, 1 on timeout
wait_for_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-30}"
  local start_time
  start_time=$(date +%s)

  while true; do
    if (echo > "/dev/tcp/$host/$port") 2>/dev/null; then
      return 0
    fi

    local current_time
    current_time=$(date +%s)
    if (( current_time - start_time >= timeout )); then
      log "ERROR" "Timed out waiting for $host:$port to become available"
      return 1
    fi

    sleep 1
  done
}

#######################################
# REPORTING INTEGRATION
#######################################

# Load reporting module if available
# Otherwise provide basic report generation functionality
load_reporting_module() {
  if [[ -f "$REPORTING_MODULE" ]]; then
    # shellcheck source=../modules/reporting.sh
    source "$REPORTING_MODULE"
    log "DEBUG" "Loaded reporting module from $REPORTING_MODULE"
    return 0
  else
    log "WARN" "Reporting module not found at $REPORTING_MODULE"
    log "WARN" "Using basic reporting functionality"
    return 1
  fi
}

# Generate a test report
# Arguments:
#   $1 - Output format (text, json, junit)
#   $2 - Output file path (optional)
# Returns:
#   0 on success, 1 on failure
generate_test_report() {
  local format="${1:-$OUTPUT_FORMAT}"
  local output_file="${2:-$OUTPUT_FILE}"

  # If reporting module is available, use it
  if load_reporting_module; then
    # The reporting module will use our global test data variables
    # No need to pass them explicitly
    generate_report "$format" "$output_file"
    return $?
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

General Testing Utilities for Cloud Infrastructure Platform v$TEST_UTILS_VERSION

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
  generate_test_report

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

  run_test "Equality assertion" 'assert_equals "hello" "hello"'
  run_test "Contains assertion" 'assert_contains "hello world" "world"'
  run_test "Success assertion" 'assert_success true'
  run_test "Failure assertion" 'assert_fails false'

  # Test mock functionality
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

  end_test_group
}

# Export all public functions for sourcing
export -f begin_test_group
export -f end_test_group
export -f run_test
export -f assert_equals
export -f assert_contains
export -f assert_success
export -f assert_fails
export -f assert_file_exists
export -f assert_dir_exists
export -f assert_file_contains
export -f create_mock_environment
export -f create_mock_file
export -f mock_command
export -f remove_mock_command
export -f port_is_available
export -f find_available_port
export -f wait_for_port
export -f generate_test_report
export -f command_exists
export -f log
export -f create_temp_dir
export -f safe_rm_dir

# When executed directly, run self-test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if ! parse_args "$@"; then
    exit 1
  fi

  log "INFO" "Test utils v${TEST_UTILS_VERSION} (${TEST_UTILS_DATE})"
  self_test
  exit $?
fi
