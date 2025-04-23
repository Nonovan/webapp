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

# Set strict mode
set -o pipefail

# Version tracking
TEST_UTILS_VERSION="1.0.0"
TEST_UTILS_DATE="2023-08-15"

# Script locations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Path to common functions
COMMON_FUNCTIONS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

# Test output formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

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

# Test output settings
VERBOSE=${VERBOSE:-false}
QUIET=${QUIET:-false}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"text"}  # Options: text, json, junit
OUTPUT_FILE=${OUTPUT_FILE:-""}
EXIT_ON_FAILURE=${EXIT_ON_FAILURE:-false}

#######################################
# HELPER FUNCTIONS
#######################################

# Check if a command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Log a message if not in quiet mode
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
    return
  fi

  # Skip all messages if quiet mode is enabled, except for errors
  if [[ "$QUIET" == "true" && "$level" != "ERROR" ]]; then
    return
  fi

  echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message${NC}" >&2
}

#######################################
# TEST FRAMEWORK CORE
#######################################

# Begin a test group
begin_test_group() {
  CURRENT_GROUP="$1"
  TEST_GROUPS+=("$CURRENT_GROUP")
  log "INFO" "Starting test group: $CURRENT_GROUP"
}

# End current test group
end_test_group() {
  local group_name="${CURRENT_GROUP:-Unknown group}"
  log "INFO" "Finished test group: $group_name"
  CURRENT_GROUP=""
}

# Run a test function and record results
# Arguments:
#   $1 - Test name
#   $2 - Test function or command to run
run_test() {
  local test_name="$1"
  local test_cmd="$2"
  local should_skip="${3:-false}"

  local full_test_name="${CURRENT_GROUP:+$CURRENT_GROUP: }$test_name"
  local test_result="PASS"
  local test_message=""
  local test_start=$(date +%s.%N)

  ((TESTS_TOTAL++))

  log "INFO" "Running test: $full_test_name"

  if [[ "$should_skip" == "true" ]]; then
    ((TESTS_SKIPPED++))
    test_result="SKIP"
    test_message="Test skipped"
    log "WARN" "⚠️ SKIPPED: $full_test_name - $test_message"
  else
    # Create isolated test directory
    local test_dir="/tmp/test_utils_${TESTS_TOTAL}_$(date +%s)"
    mkdir -p "$test_dir"

    # Run the test in a subshell to isolate it
    local output_file="$test_dir/output.txt"
    local error_file="$test_dir/error.txt"

    if ( eval "$test_cmd" > "$output_file" 2> "$error_file" ); then
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
        rm -rf "$test_dir"
        log "ERROR" "Exiting due to test failure"
        exit 1
      fi
    fi

    # Clean up
    rm -rf "$test_dir"
  fi

  # Calculate test duration
  local test_end=$(date +%s.%N)
  local duration=$(echo "$test_end - $test_start" | bc)

  # Store test result
  TEST_RESULTS+=("$full_test_name|$test_result|$duration|$test_message")

  # Track file coverage if relevant
  if [[ "$test_cmd" == *"source "* ]]; then
    local file=$(echo "$test_cmd" | grep -o "source [^ ]*" | cut -d' ' -f2)
    COVERAGE_DATA+=("$file")
  fi
}

# Assert that two values are equal
# Arguments:
#   $1 - Actual value
#   $2 - Expected value
#   $3 - Optional message
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
  local mock_dir="/tmp/test_utils_mock_${name}_$(date +%s)"

  mkdir -p "$mock_dir"
  echo "$mock_dir"
}

# Create a mock file with specified content
# Arguments:
#   $1 - Path to the mock file
#   $2 - Content for the file
create_mock_file() {
  local file_path="$1"
  local content="$2"

  mkdir -p "$(dirname "$file_path")"
  echo "$content" > "$file_path"

  if [[ "$file_path" == *.sh ]]; then
    chmod +x "$file_path"
  fi
}

# Create a mock function that replaces a real command
# Arguments:
#   $1 - Command to mock
#   $2 - Script content to execute instead
mock_command() {
  local cmd="$1"
  local script="$2"
  local mock_dir="/tmp/test_utils_mock_bin_$(date +%s)"

  mkdir -p "$mock_dir"

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
remove_mock_command() {
  local mock_dir="$1"

  if [[ -d "$mock_dir" ]]; then
    rm -rf "$mock_dir"
  fi

  # Restore original PATH
  export PATH=$(echo "$PATH" | sed "s|${mock_dir}:||")
}

#######################################
# SYSTEM TESTING UTILITIES
#######################################

# Check if a port is available
# Arguments:
#   $1 - Port number to check
port_is_available() {
  local port="$1"
  ! (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

# Find an available port
# Returns:
#   An available port number
find_available_port() {
  local port=0

  while [[ $port -eq 0 || ! $(port_is_available "$port") ]]; do
    port=$((10000 + RANDOM % 50000))
  done

  echo "$port"
}

# Wait for a service to be ready on a specific port
# Arguments:
#   $1 - Host
#   $2 - Port
#   $3 - Timeout in seconds (optional, default: 30)
wait_for_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-30}"
  local start_time=$(date +%s)

  while true; do
    if (echo > "/dev/tcp/$host/$port") 2>/dev/null; then
      return 0
    fi

    local current_time=$(date +%s)
    if (( current_time - start_time >= timeout )); then
      log "ERROR" "Timed out waiting for $host:$port to become available"
      return 1
    fi

    sleep 1
  done
}

#######################################
# REPORTING FUNCTIONS
#######################################

# Generate a test report
# Arguments:
#   $1 - Output format (text, json, junit)
#   $2 - Output file path (optional)
generate_test_report() {
  local format="${1:-$OUTPUT_FORMAT}"
  local output_file="${2:-$OUTPUT_FILE}"

  case "$format" in
    "json")
      generate_json_report "$output_file"
      ;;
    "junit")
      generate_junit_report "$output_file"
      ;;
    *)
      generate_text_report "$output_file"
      ;;
  esac
}

# Generate a text report
# Arguments:
#   $1 - Output file path (optional)
generate_text_report() {
  local output_file="$1"
  local temp_file

  # Use a temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_file=$(mktemp)
  else
    temp_file="/dev/stdout"
  fi

  {
    echo "========================================"
    echo "TEST RESULTS"
    echo "========================================"
    echo "Total Tests: $TESTS_TOTAL"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    echo "Skipped: $TESTS_SKIPPED"
    echo "Time: ${TEST_TOTAL_TIME}s"
    echo "========================================"

    # Group results by test group
    local current_group=""
    for result in "${TEST_RESULTS[@]}"; do
      IFS='|' read -r name status duration message <<< "$result"

      # Extract group from full test name
      local group=""
      if [[ "$name" == *": "* ]]; then
        group="${name%%: *}"
      fi

      # Print group header if it's a new group
      if [[ "$group" != "$current_group" && -n "$group" ]]; then
        echo
        echo "Group: $group"
        echo "----------------------------------------"
        current_group="$group"
      fi

      # Print test result
      local test_name="${name#*: }"
      local status_color
      case "$status" in
        "PASS") status_color="[PASS]  " ;;
        "FAIL") status_color="[FAIL]  " ;;
        "SKIP") status_color="[SKIP]  " ;;
      esac

      echo "$status_color $test_name (${duration}s)"
      if [[ -n "$message" && "$status" != "PASS" ]]; then
        echo "         $message"
      fi
    done

    echo
    echo "========================================"
    echo "COVERAGE INFO"
    echo "========================================"

    # Get unique files covered
    local covered_files=()
    for file in "${COVERAGE_DATA[@]}"; do
      if [[ ! " ${covered_files[*]} " =~ " ${file} " ]]; then
        covered_files+=("$file")
      fi
    done

    echo "Files covered: ${#covered_files[@]}"
    for file in "${covered_files[@]}"; do
      echo "- $file"
    done

  } > "$temp_file"

  # If output file is specified, move temp file to output file
  if [[ -n "$output_file" && "$temp_file" != "/dev/stdout" ]]; then
    mkdir -p "$(dirname "$output_file")"
    mv "$temp_file" "$output_file"
  fi
}

# Generate a JSON report
# Arguments:
#   $1 - Output file path (optional)
generate_json_report() {
  local output_file="$1"
  local temp_file

  # Use a temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_file=$(mktemp)
  else
    temp_file="/dev/stdout"
  fi

  {
    echo "{"
    echo "  \"summary\": {"
    echo "    \"total\": $TESTS_TOTAL,"
    echo "    \"passed\": $TESTS_PASSED,"
    echo "    \"failed\": $TESTS_FAILED,"
    echo "    \"skipped\": $TESTS_SKIPPED,"
    echo "    \"time\": $TEST_TOTAL_TIME"
    echo "  },"
    echo "  \"tests\": ["

    local first=true
    for result in "${TEST_RESULTS[@]}"; do
      IFS='|' read -r name status duration message <<< "$result"

      if [[ "$first" == "true" ]]; then
        first=false
      else
        echo ","
      fi

      local group=""
      local test_name="$name"
      if [[ "$name" == *": "* ]]; then
        group="${name%%: *}"
        test_name="${name#*: }"
      fi

      echo -n "    {"
      echo -n "\"group\": \"$group\", "
      echo -n "\"name\": \"$test_name\", "
      echo -n "\"status\": \"$status\", "
      echo -n "\"duration\": $duration, "
      echo -n "\"message\": \"${message//\"/\\\"}\""
      echo -n "}"
    done

    echo
    echo "  ],"

    echo "  \"coverage\": ["

    first=true
    for file in $(echo "${COVERAGE_DATA[@]}" | tr ' ' '\n' | sort -u); do
      if [[ "$first" == "true" ]]; then
        first=false
      else
        echo ","
      fi

      echo -n "    \"$file\""
    done

    echo
    echo "  ]"
    echo "}"

  } > "$temp_file"

  # If output file is specified, move temp file to output file
  if [[ -n "$output_file" && "$temp_file" != "/dev/stdout" ]]; then
    mkdir -p "$(dirname "$output_file")"
    mv "$temp_file" "$output_file"
  fi
}

# Generate a JUnit XML report
# Arguments:
#   $1 - Output file path (optional)
generate_junit_report() {
  local output_file="$1"
  local temp_file

  # Use a temp file if output file is specified
  if [[ -n "$output_file" ]]; then
    temp_file=$(mktemp)
  else
    temp_file="/dev/stdout"
  fi

  {
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    echo "<testsuites name=\"Cloud Infrastructure Platform Tests\" time=\"$TEST_TOTAL_TIME\" tests=\"$TESTS_TOTAL\" failures=\"$TESTS_FAILED\" skipped=\"$TESTS_SKIPPED\">"

    # Group tests by test group
    local groups=()
    local group_tests=()

    for result in "${TEST_RESULTS[@]}"; do
      IFS='|' read -r name status duration message <<< "$result"

      local group="ungrouped"
      local test_name="$name"
      if [[ "$name" == *": "* ]]; then
        group="${name%%: *}"
        test_name="${name#*: }"
      fi

      if [[ ! " ${groups[*]} " =~ " ${group} " ]]; then
        groups+=("$group")
      fi

      group_tests+=("$group|$test_name|$status|$duration|$message")
    done

    # Output each test suite (group)
    for group in "${groups[@]}"; do
      local group_failures=0
      local group_skipped=0
      local group_total=0
      local group_time=0

      # Count metrics for this group
      for entry in "${group_tests[@]}"; do
        IFS='|' read -r g name status duration message <<< "$entry"

        if [[ "$g" != "$group" ]]; then
          continue
        fi

        ((group_total++))
        group_time=$(echo "$group_time + $duration" | bc)

        if [[ "$status" == "FAIL" ]]; then
          ((group_failures++))
        elif [[ "$status" == "SKIP" ]]; then
          ((group_skipped++))
        fi
      done

      echo "  <testsuite name=\"$group\" tests=\"$group_total\" failures=\"$group_failures\" skipped=\"$group_skipped\" time=\"$group_time\">"

      # Output test cases for this group
      for entry in "${group_tests[@]}"; do
        IFS='|' read -r g name status duration message <<< "$entry"

        if [[ "$g" != "$group" ]]; then
          continue
        fi

        echo "    <testcase name=\"$name\" classname=\"$group\" time=\"$duration\">"

        if [[ "$status" == "FAIL" ]]; then
          echo "      <failure message=\"${message//\"/\&quot;}\" type=\"failure\"></failure>"
        elif [[ "$status" == "SKIP" ]]; then
          echo "      <skipped message=\"${message//\"/\&quot;}\"></skipped>"
        fi

        echo "    </testcase>"
      done

      echo "  </testsuite>"
    done

    echo "</testsuites>"

  } > "$temp_file"

  # If output file is specified, move temp file to output file
  if [[ -n "$output_file" && "$temp_file" != "/dev/stdout" ]]; then
    mkdir -p "$(dirname "$output_file")"
    mv "$temp_file" "$output_file"
  fi
}

#######################################
# CLI INTERFACE
#######################################

# Parse command line arguments
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
        if [[ -n "$2" ]]; then
          OUTPUT_FILE="$2"
          shift 2
        else
          log "ERROR" "Option --output requires an argument"
          exit 1
        fi
        ;;
      --format|-f)
        if [[ -n "$2" && "$2" =~ ^(text|json|junit)$ ]]; then
          OUTPUT_FORMAT="$2"
          shift 2
        else
          log "ERROR" "Option --format requires an argument: text, json, or junit"
          exit 1
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
        exit 1
        ;;
    esac
  done
}

# Show script usage
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
EOF
}

#######################################
# MAIN EXECUTION
#######################################

# Main function to run all tests
run_tests() {
  log "INFO" "Starting test execution"

  local start_time=$(date +%s)

  # Run tests here...

  local end_time=$(date +%s)
  TEST_TOTAL_TIME=$((end_time - start_time))

  log "INFO" "Completed test execution in ${TEST_TOTAL_TIME}s"
  generate_test_report

  # Return non-zero exit code if any tests failed
  [[ $TESTS_FAILED -eq 0 ]]
}

# Self-test function
self_test() {
  begin_test_group "Self-Tests"

  run_test "Equality assertion" 'assert_equals "hello" "hello"'
  run_test "Contains assertion" 'assert_contains "hello world" "world"'
  run_test "Success assertion" 'assert_success true'
  run_test "Failure assertion" 'assert_fails false'

  # Test mock functionality
  local mock_dir=$(create_mock_environment "self_test")
  create_mock_file "$mock_dir/test.txt" "Hello world"
  run_test "Mock file creation" "test -f '$mock_dir/test.txt'"

  # Test mock command
  local mock_bin=$(mock_command "custom_cmd" "echo 'This is a mock'")
  run_test "Mock command" "custom_cmd | grep -q 'This is a mock'"
  remove_mock_command "$mock_bin"

  # Clean up
  rm -rf "$mock_dir"

  end_test_group
}

# Export all public functions
export -f begin_test_group
export -f end_test_group
export -f run_test
export -f assert_equals
export -f assert_contains
export -f assert_success
export -f assert_fails
export -f assert_file_exists
export -f assert_dir_exists
export -f create_mock_environment
export -f create_mock_file
export -f mock_command
export -f remove_mock_command
export -f port_is_available
export -f find_available_port
export -f wait_for_port
export -f generate_test_report

# When executed directly, run self-test and example usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  parse_args "$@"
  log "INFO" "Test utils v${TEST_UTILS_VERSION} (${TEST_UTILS_DATE})"
  self_test
  exit $?
fi
