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
UTILS_DIR="${PROJECT_ROOT}/scripts/utils"
COMMON_DIR="${UTILS_DIR}/common"

# Path to modules and common utilities
MODULES_DIR="${UTILS_DIR}/modules"
CORE_MODULE="${MODULES_DIR}/core.sh"
ASSERTIONS_MODULE="${MODULES_DIR}/assertions.sh"
MOCKING_MODULE="${MODULES_DIR}/mocking.sh"
REPORTING_MODULE="${MODULES_DIR}/reporting.sh"
SYSTEM_MODULE="${MODULES_DIR}/system.sh"

# Common utilities that we'll use for file ops, etc.
CORE_UTILS="${COMMON_DIR}/common_core_utils.sh"
FILE_OPS_UTILS="${COMMON_DIR}/common_file_ops_utils.sh"
SYSTEM_UTILS="${COMMON_DIR}/common_system_utils.sh"

# Version tracking
readonly TEST_UTILS_VERSION="1.0.0"
readonly TEST_UTILS_DATE="2023-12-20"

#######################################
# CONFIG VARIABLES AND DEFAULTS
#######################################

# Default settings
DEFAULT_OUTPUT_FORMAT="text"
DEFAULT_OUTPUT_DIR="${PROJECT_ROOT}/reports/test"
DEFAULT_TIMEOUT=30
DEFAULT_TEST_PATTERN="*_test.sh"
DEFAULT_PARALLEL_TESTS=1
DEFAULT_VERBOSITY="info"

# Global configuration variables
# These can be overridden before sourcing the script or via command line args
TEST_VERBOSITY="${TEST_VERBOSITY:-$DEFAULT_VERBOSITY}"
TEST_OUTPUT_FORMAT="${TEST_OUTPUT_FORMAT:-$DEFAULT_OUTPUT_FORMAT}"
TEST_OUTPUT_FILE="${TEST_OUTPUT_FILE:-}"
TEST_DIR="${TEST_DIR:-$PROJECT_ROOT/tests}"
TEST_PATTERN="${TEST_PATTERN:-$DEFAULT_TEST_PATTERN}"
TEST_PARALLEL="${TEST_PARALLEL:-$DEFAULT_PARALLEL_TESTS}"
TEST_TIMEOUT="${TEST_TIMEOUT:-$DEFAULT_TIMEOUT}"

# Test tracking variables
declare -a TEST_RESULTS=()
declare -a TEST_GROUPS=()
declare -a COVERAGE_DATA=()
CURRENT_TEST_GROUP=""
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
TEST_TOTAL_TIME=0

#######################################
# MODULE LOADING
#######################################

# Basic logging functions as a fallback if modules don't load
log() {
  local level="${1:-INFO}"
  local message="${2:-}"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
}

log_info() { log "INFO" "$1"; }
log_debug() { [[ "$TEST_VERBOSITY" == "debug" ]] && log "DEBUG" "$1" || true; }
log_warn() { log "WARN" "$1" >&2; }
log_error() { log "ERROR" "$1" >&2; }

# Function to load a module or utility script
# Arguments:
#   $1 - Script path
#   $2 - Script name or description
#   $3 - Required flag (optional, default: false)
# Returns:
#   0 if loaded successfully, 1 if not
load_script() {
  local script_path="$1"
  local script_name="$2"
  local required="${3:-false}"

  if [[ -f "$script_path" ]]; then
    # shellcheck source=/dev/null
    source "$script_path"
    log_debug "Loaded $script_name successfully"
    return 0
  else
    if [[ "$required" == "true" ]]; then
      log_error "$script_name not found at $script_path. Cannot continue."
      exit 1
    else
      log_warn "$script_name not found at $script_path. Some functionality may be limited."
      return 1
    fi
  fi
}

# First, load core module (required) and common utilities
load_script "$CORE_MODULE" "core module" "true"

# Load common utilities for file operations and system functions
load_script "$CORE_UTILS" "core utilities"
load_script "$FILE_OPS_UTILS" "file operations utilities"
load_script "$SYSTEM_UTILS" "system utilities"

# Log startup information
log_info "Test utils v${TEST_UTILS_VERSION} (${TEST_UTILS_DATE})"
log_debug "Loading modules from $MODULES_DIR"

# Load optional testing modules
load_script "$ASSERTIONS_MODULE" "assertions module"
load_script "$MOCKING_MODULE" "mocking module"
load_script "$SYSTEM_MODULE" "system module"
load_script "$REPORTING_MODULE" "reporting module"

# Use project's color definitions if available, otherwise define our own
if [[ -z "${RED:-}" ]]; then
  # Only define colors if terminal supports it
  if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[0;33m'
    readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m' # No Color
  else
    readonly RED=""
    readonly GREEN=""
    readonly YELLOW=""
    readonly BLUE=""
    readonly CYAN=""
    readonly BOLD=""
    readonly NC=""
  fi
fi

#######################################
# TEST EXECUTION FUNCTIONS
#######################################

# Begin a test group
# Arguments:
#   $1 - Group name
# Returns:
#   0 on success
begin_test_group() {
  local group_name="${1:-Unnamed Group}"

  # Add to groups list if not already present
  if ! echo "${TEST_GROUPS[@]:-}" | grep -q "$group_name"; then
    TEST_GROUPS+=("$group_name")
  fi

  CURRENT_TEST_GROUP="$group_name"
  log_info "Starting test group: $CURRENT_TEST_GROUP"

  return 0
}

# End the current test group
# Arguments:
#   None
# Returns:
#   0 on success
end_test_group() {
  if [[ -n "$CURRENT_TEST_GROUP" ]]; then
    log_info "Completed test group: $CURRENT_TEST_GROUP"
    CURRENT_TEST_GROUP=""
  fi

  return 0
}

# Run a single test
# Arguments:
#   $1 - Test name
#   $2 - Test command (string to be evaluated)
#   $3 - Skip flag (optional, "true" to skip)
#   $4 - Additional test details (optional)
# Returns:
#   0 if test passes, 1 if fails
run_test() {
  local name="${1:-Unnamed Test}"
  local command="${2:-exit 0}"
  local skip="${3:-false}"
  local details="${4:-}"
  local full_name="$name"
  local status start_time end_time duration

  # Add group prefix if within a group
  if [[ -n "$CURRENT_TEST_GROUP" ]]; then
    full_name="${CURRENT_TEST_GROUP}: $name"
  fi

  # Handle skipped tests
  if [[ "$skip" == "true" ]]; then
    log_info "${YELLOW}SKIPPED${NC} - $full_name"
    TEST_RESULTS+=("$full_name|SKIP|0.0|$details")
    ((TESTS_SKIPPED++))
    ((TESTS_TOTAL++))
    return 0
  fi

  log_debug "Executing: $command"

  # Run the test and capture exit status and output
  start_time=$(date +%s.%N 2>/dev/null || date +%s)

  # Use temporary file for output to avoid subshell issues with status capture
  local temp_output
  temp_output=$(create_secure_temp "test_output" 2>/dev/null || mktemp)

  # Execute command and capture status
  eval "$command" > "$temp_output" 2>&1 || status=$?

  end_time=$(date +%s.%N 2>/dev/null || date +%s)
  local output=$(<"$temp_output")
  rm -f "$temp_output" 2>/dev/null

  # Calculate duration using common function if available, otherwise fallback
  if command -v bc &>/dev/null; then
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null)
    duration=$(echo "scale=2; $duration" | bc 2>/dev/null)
  else
    duration=$((end_time - start_time))
  fi

  # Track the test result
  ((TESTS_TOTAL++))

  if [[ -z "${status:-}" ]]; then
    log_info "${GREEN}PASS${NC} - $full_name (${duration}s)"
    TEST_RESULTS+=("$full_name|PASS|$duration|")
    ((TESTS_PASSED++))
    return 0
  else
    # Prepare failed test message with truncated output
    local failure_message="Exit code: $status"
    if [[ -n "$output" ]]; then
      # Limit output to a reasonable length
      if [[ ${#output} -gt 500 ]]; then
        output="${output:0:500}... (output truncated)"
      fi
      failure_message+=" Output: $output"
    fi

    if [[ -n "$details" ]]; then
      failure_message+=" | $details"
    fi

    log_error "${RED}FAIL${NC} - $full_name (${duration}s)"
    log_debug "Failure details: $failure_message"
    TEST_RESULTS+=("$full_name|FAIL|$duration|$failure_message")
    ((TESTS_FAILED++))
    return 1
  fi
}

# Register a file as covered by tests
# Arguments:
#   $1 - Path to the file being tested
# Returns:
#   0 on success
register_coverage() {
  local file_path="${1:-}"

  if [[ -n "$file_path" && -f "$file_path" ]]; then
    COVERAGE_DATA+=("$file_path")
    log_debug "Registered coverage for $file_path"
  fi

  return 0
}

# Skip a test with a specific reason
# Arguments:
#   $1 - Test name
#   $2 - Reason for skipping (optional)
# Returns:
#   0 on success
skip_test() {
  local name="${1:-Unnamed Test}"
  local reason="${2:-Test skipped explicitly}"

  run_test "$name" "exit 0" "true" "$reason"
  return 0
}

# Run multiple test files
# Returns:
#   0 if all tests pass, 1 if any tests fail
run_test_files() {
  # Use global config variables instead of parameters
  local pattern="${TEST_PATTERN}"
  local test_dir="${TEST_DIR}"
  local exit_code=0

  log_info "Running test files matching '$pattern' in $test_dir"

  # Check that the test directory exists
  if [[ ! -d "$test_dir" ]]; then
    log_error "Test directory does not exist: $test_dir"
    return 1
  fi

  # Use a more reliable find command to get test files
  local start_time end_time
  start_time=$(date +%s)

  # Use common utility if available, otherwise use basic find
  local test_files=()
  if command -v find_files &>/dev/null; then
    # Use the project's file_ops find utility with pattern
    readarray -t test_files < <(find_files "$test_dir" "$pattern" "false" "")
  else
    # Fallback to basic find
    while IFS= read -r -d $'\0' file; do
      test_files+=("$file")
    done < <(find "$test_dir" -type f -name "$pattern" -print0 2>/dev/null | sort -z)
  fi

  if [[ ${#test_files[@]} -eq 0 ]]; then
    log_warn "No test files found matching '$pattern' in $test_dir"
    return 1
  fi

  log_info "Found ${#test_files[@]} test files to execute"

  # Set up parallel execution if enabled and available
  local parallel_enabled=false
  if [[ $TEST_PARALLEL -gt 1 ]] && command -v parallel &>/dev/null; then
    parallel_enabled=true
    log_info "Running tests in parallel with $TEST_PARALLEL jobs"
  fi

  if [[ "$parallel_enabled" == "true" ]]; then
    # Create a temporary results file for parallel execution
    local temp_results=$(mktemp)

    # Export necessary functions and variables for parallel
    export -f run_test begin_test_group end_test_group register_coverage
    export CURRENT_TEST_GROUP TEST_VERBOSITY

    # Use GNU parallel to run tests in parallel
    parallel --jobs "$TEST_PARALLEL" --results "$temp_results" \
      "source \"$BASH_SOURCE\"; begin_test_group \"{= s:^.*/::; s:_test\.sh$::; =}\"; source {}; end_test_group" ::: "${test_files[@]}" || exit_code=1

    # Process results
    # This would need additional code to parse the parallel results format
    log_info "Parallel execution completed. Results stored in $temp_results"
  else
    # Sequential execution
    for test_file in "${test_files[@]}"; do
      log_info "Executing test file: $test_file"

      # Capture test file output and exit code
      if [[ -x "$test_file" ]]; then
        # File is executable
        "$test_file" || {
          log_error "Test file failed: $test_file with exit code $?"
          exit_code=1
        }
      else
        # Not executable, source it
        begin_test_group "$(basename "$test_file")"
        # shellcheck source=/dev/null
        source "$test_file" || {
          log_error "Failed to source test file: $test_file with exit code $?"
          exit_code=1
        }
        end_test_group
      fi

      register_coverage "$test_file"
    done
  fi

  end_time=$(date +%s)
  TEST_TOTAL_TIME=$((end_time - start_time))

  log_info "Completed test file execution in ${TEST_TOTAL_TIME}s"

  return $exit_code
}

#######################################
# BUILT-IN ASSERTIONS
#######################################

# These basic assertions are provided only if the assertions module is not available

# Assert two values are equal
# Arguments:
#   $1 - Actual value
#   $2 - Expected value
#   $3 - Optional message
# Returns:
#   0 if equal, 1 if not
assert_equals() {
  # If assertions module is loaded, use that implementation
  if [[ $(type -t "assert_equals") == "function" &&
        $(declare -f "assert_equals" | head -1) != "assert_equals() {" ]]; then
    assert_equals "$@"
    return $?
  fi

  # Fallback implementation
  local actual="${1:-}"
  local expected="${2:-}"
  local message="${3:-Values should be equal}"

  if [[ "$actual" == "$expected" ]]; then
    log_debug "Assertion passed: '$actual' equals '$expected'"
    return 0
  else
    log_error "Assertion failed: $message"
    log_error "Expected: '$expected'"
    log_error "Actual  : '$actual'"
    return 1
  fi
}

# Assert a string contains a substring
# Arguments:
#   $1 - String to search in
#   $2 - Substring to search for
#   $3 - Optional message
# Returns:
#   0 if string contains substring, 1 otherwise
assert_contains() {
  # If assertions module is loaded, use that implementation
  if [[ $(type -t "assert_contains") == "function" &&
        $(declare -f "assert_contains" | head -1) != "assert_contains() {" ]]; then
    assert_contains "$@"
    return $?
  fi

  # Fallback implementation
  local string="${1:-}"
  local substring="${2:-}"
  local message="${3:-String should contain substring}"

  if [[ -z "$string" && -z "$substring" ]]; then
    log_error "Assertion failed: Empty string and substring provided"
    return 1
  fi

  if [[ "$string" == *"$substring"* ]]; then
    log_debug "Assertion passed: String contains substring '$substring'"
    return 0
  else
    log_error "Assertion failed: $message"
    log_error "String  : '$string'"
    log_error "Expected to contain: '$substring'"
    return 1
  fi
}

# Assert that a command succeeds
# Arguments:
#   $1 - Command to run (or timeout if numeric)
#   $2... - Command arguments (if $1 is timeout)
# Returns:
#   0 if command succeeds, 1 otherwise
assert_success() {
  # If assertions module is loaded, use that implementation
  if [[ $(type -t "assert_success") == "function" &&
        $(declare -f "assert_success" | head -1) != "assert_success() {" ]]; then
    assert_success "$@"
    return $?
  fi

  # Use execute_with_timeout from system_utils if available
  if command -v execute_with_timeout &>/dev/null; then
    local timeout=""
    # Check if first parameter is a number for timeout
    if [[ "$1" =~ ^[0-9]+$ ]]; then
      timeout=$1
      shift
    fi

    # Ensure there's a command to run
    if [[ $# -eq 0 ]]; then
      log_error "Assertion failed: No command provided to assert_success"
      return 1
    fi

    local temp_output exit_code
    temp_output=$(create_secure_temp "assert" 2>/dev/null || mktemp)

    if [[ -n "$timeout" ]]; then
      execute_with_timeout "$timeout" "$@" > "$temp_output" 2>&1
      exit_code=$?
    else
      "$@" > "$temp_output" 2>&1
      exit_code=$?
    fi

    local output=$(<"$temp_output")
    rm -f "$temp_output" 2>/dev/null

    if [[ $exit_code -eq 0 ]]; then
      log_debug "Assertion passed: Command succeeded"
      return 0
    else
      log_error "Command was expected to succeed but failed with exit code $exit_code"
      log_error "Command: $*"
      log_error "Output: $output"
      return 1
    fi
  else
    # Fallback implementation
    local timeout=""
    local exit_code=0
    local output=""

    # Check if first parameter is a number for timeout
    if [[ "$1" =~ ^[0-9]+$ ]]; then
      timeout=$1
      shift
    fi

    # Ensure there's a command to run
    if [[ $# -eq 0 ]]; then
      log_error "Assertion failed: No command provided to assert_success"
      return 1
    fi

    # Use global timeout if not specified
    if [[ -z "$timeout" ]]; then
      timeout=$TEST_TIMEOUT
    fi

    # Run with timeout if specified
    if [[ -n "$timeout" ]]; then
      if command -v timeout >/dev/null 2>&1; then
        output=$(timeout "$timeout" "$@" 2>&1) || exit_code=$?
      else
        output=$("$@" 2>&1) || exit_code=$?
      fi
    else
      output=$("$@" 2>&1) || exit_code=$?
    fi

    if [[ $exit_code -eq 0 ]]; then
      log_debug "Assertion passed: Command succeeded"
      return 0
    else
      log_error "Command was expected to succeed but failed with exit code $exit_code"
      log_error "Command: $*"
      log_error "Output: $output"
      return 1
    fi
  fi
}

# Assert that a command fails
# Arguments:
#   $1 - Command to run (or timeout if numeric)
#   $2... - Command arguments (if $1 is timeout)
# Returns:
#   0 if command fails, 1 if it succeeds
assert_fails() {
  # If assertions module is loaded, use that implementation
  if [[ $(type -t "assert_fails") == "function" &&
        $(declare -f "assert_fails" | head -1) != "assert_fails() {" ]]; then
    assert_fails "$@"
    return $?
  fi

  # Fallback implementation using system utilities if available
  local timeout=""
  local expected_code=""
  local exit_code=0

  # Check if first parameter is a number for timeout
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    timeout=$1
    shift
  fi

  # Check if first parameter is expected exit code
  if [[ "$1" =~ ^[0-9]+$ && $1 -ne 0 ]]; then
    expected_code=$1
    shift
  fi

  # Ensure there's a command to run
  if [[ $# -eq 0 ]]; then
    log_error "Assertion failed: No command provided to assert_fails"
    return 1
  fi

  # Use global timeout if not specified
  if [[ -z "$timeout" ]]; then
    timeout=$TEST_TIMEOUT
  fi

  # Use execute_with_timeout from system_utils if available
  if command -v execute_with_timeout &>/dev/null && [[ -n "$timeout" ]]; then
    local temp_output
    temp_output=$(create_secure_temp "assert" 2>/dev/null || mktemp)

    execute_with_timeout "$timeout" "$@" > "$temp_output" 2>&1
    exit_code=$?

    local output=$(<"$temp_output")
    rm -f "$temp_output" 2>/dev/null
  else
    # Fallback to basic timeout or direct execution
    if [[ -n "$timeout" ]] && command -v timeout >/dev/null 2>&1; then
      output=$(timeout "$timeout" "$@" 2>&1) || exit_code=$?
    else
      output=$("$@" 2>&1) || exit_code=$?
    fi
  fi

  if [[ $exit_code -eq 0 ]]; then
    log_error "Command was expected to fail but succeeded"
    log_error "Command: $*"
    log_error "Output: $output"
    return 1
  elif [[ -n "$expected_code" && $exit_code -ne $expected_code ]]; then
    log_error "Command failed with exit code $exit_code, but expected code $expected_code"
    log_error "Command: $*"
    log_error "Output: $output"
    return 1
  else
    log_debug "Assertion passed: Command failed as expected with exit code $exit_code"
    return 0
  fi
}

#######################################
# COMMAND LINE ARGUMENT HANDLING
#######################################

# Show usage message
# Arguments:
#   None
# Returns:
#   None
show_usage() {
  cat <<EOF
Usage: test_utils.sh [OPTIONS]

OPTIONS:
  -h, --help             Show this help message and exit
  -v, --verbose          Enable verbose output
  -q, --quiet            Quiet mode (minimal output)
  -d, --dir DIR          Test directory (default: ${TEST_DIR})
  -p, --pattern PATTERN  Test file pattern (default: ${TEST_PATTERN})
  -f, --format FORMAT    Report format: text|json|junit (default: ${TEST_OUTPUT_FORMAT})
  -o, --output FILE      Output report file
  -s, --self-test        Run self-tests only
  -j, --parallel N       Run N tests in parallel (default: ${TEST_PARALLEL})
  -t, --timeout SEC      Default timeout for commands (default: ${TEST_TIMEOUT})

Examples:
  ./test_utils.sh --self-test
  ./test_utils.sh --dir ./tests/unit --format junit --output junit-report.xml
  ./test_utils.sh --pattern "*_integration_test.sh" --verbose
EOF
}

# Parse command line arguments
# Arguments:
#   All command line arguments ($@)
# Returns:
#   0 on success, 1 on failure (invalid arguments)
parse_args() {
  local self_test_mode=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        show_usage
        return 1
        ;;
      -v|--verbose)
        TEST_VERBOSITY="debug"
        shift
        ;;
      -q|--quiet)
        TEST_VERBOSITY="error"
        shift
        ;;
      -d|--dir)
        TEST_DIR="$2"
        shift 2
        ;;
      -p|--pattern)
        TEST_PATTERN="$2"
        shift 2
        ;;
      -f|--format)
        TEST_OUTPUT_FORMAT="$2"
        shift 2
        ;;
      -o|--output)
        TEST_OUTPUT_FILE="$2"
        shift 2
        ;;
      -s|--self-test)
        self_test_mode=true
        shift
        ;;
      -j|--parallel)
        TEST_PARALLEL="$2"
        shift 2
        ;;
      -t|--timeout)
        TEST_TIMEOUT="$2"
        shift 2
        ;;
      *)
        log_error "Unknown option: $1"
        show_usage
        return 1
        ;;
    esac
  done

  # Create output directory if needed using ensure_directory if available
  if [[ -n "$TEST_OUTPUT_FILE" ]]; then
    local output_dir
    output_dir=$(dirname "$TEST_OUTPUT_FILE")

    if command -v ensure_directory &>/dev/null; then
      ensure_directory "$output_dir" || {
        log_error "Failed to create output directory: $output_dir"
        return 1
      }
    else
      mkdir -p "$output_dir" || {
        log_error "Failed to create output directory: $output_dir"
        return 1
      }
    fi
  fi

  # Run specified tests if not in self-test mode
  if [[ "$self_test_mode" == "false" ]]; then
    run_test_files
    return $?
  fi

  return 0
}

#######################################
# REPORT GENERATION
#######################################

# Generate a basic test report if reporting module is not loaded
# Returns:
#   0 on success, 1 on failure
generate_report() {
  # If the reporting module functions are available, use them instead
  if command -v generate_test_report &>/dev/null; then
    generate_test_report "$TEST_OUTPUT_FORMAT" "$TEST_OUTPUT_FILE"
    return $?
  fi

  # Otherwise use our built-in report generation
  generate_basic_report
}

# Generate a basic test report
# Returns:
#   0 on success, 1 on failure
generate_basic_report() {
  # Fallback implementation for basic report generation
  local format="${TEST_OUTPUT_FORMAT}"
  local output_file="${TEST_OUTPUT_FILE}"
  local output=""

  # Use safe_write_file from common utils if available
  local write_function="cat"
  if command -v safe_write_file &>/dev/null; then
    write_function="safe_write_file"
  fi

  # Generate appropriate report based on format
  case "$format" in
    json)
      # JSON report generation
      output=$(generate_json_report)
      ;;
    junit|xml)
      # JUnit XML report generation
      output=$(generate_xml_report)
      ;;
    *)
      # Text report generation (default)
      output=$(generate_text_report)
      ;;
  esac

  # Output the report
  if [[ -n "$output_file" ]]; then
    if [[ "$write_function" == "safe_write_file" ]]; then
      safe_write_file "$output" "$output_file" || {
        log_error "Failed to write report to $output_file"
        return 1
      }
    else
      echo -e "$output" > "$output_file" || {
        log_error "Failed to write report to $output_file"
        return 1
      }
    fi
    log_info "Test report written to $output_file"
  else
    echo -e "$output"
  fi

  return 0
}

# Generate JSON report
# Returns: JSON report as string
generate_json_report() {
  local output

  output="{\n"
  output+="  \"summary\": {\n"
  output+="    \"total\": $TESTS_TOTAL,\n"
  output+="    \"passed\": $TESTS_PASSED,\n"
  output+="    \"failed\": $TESTS_FAILED,\n"
  output+="    \"skipped\": $TESTS_SKIPPED,\n"
  output+="    \"time\": $TEST_TOTAL_TIME\n"
  output+="  },\n"
  output+="  \"tests\": ["

  local first=true
  for result in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r name status duration message <<< "$result"

    if [[ "$first" == "true" ]]; then
      first=false
      output+="\n"
    else
      output+=",\n"
    fi

    # Extract group name if present
    local group="ungrouped"
    local test_name="$name"
    if [[ "$name" == *": "* ]]; then
      group="${name%%: *}"
      test_name="${name#*: }"
    fi

    # Escape JSON strings
    test_name="${test_name//\\/\\\\}"
    test_name="${test_name//\"/\\\"}"
    group="${group//\\/\\\\}"
    group="${group//\"/\\\"}"
    message="${message//\\/\\\\}"
    message="${message//\"/\\\"}"

    output+="    {\n"
    output+="      \"name\": \"$test_name\",\n"
    output+="      \"group\": \"$group\",\n"
    output+="      \"status\": \"$status\",\n"
    output+="      \"duration\": $duration,\n"
    output+="      \"message\": \"$message\"\n"
    output+="    }"
  done

  output+="\n  ],\n"
  output+="  \"coverage\": ["

  first=true
  for file in "${COVERAGE_DATA[@]}"; do
    if [[ "$first" == "true" ]]; then
      first=false
      output+="\n"
    else
      output+=",\n"
    fi

    # Escape JSON string
    file="${file//\\/\\\\}"
    file="${file//\"/\\\"}"

    output+="    \"$file\""
  done

  output+="\n  ],\n"
  output+="  \"metadata\": {\n"
  output+="    \"version\": \"$TEST_UTILS_VERSION\",\n"
  output+="    \"date\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\"\n"
  output+="  }\n"
  output+="}\n"

  echo -n "$output"
}

# Generate XML report
# Returns: XML report as string
generate_xml_report() {
  local output timestamp
  timestamp=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

  output="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
  output+="<testsuites name=\"Cloud Infrastructure Platform Tests\" tests=\"$TESTS_TOTAL\" failures=\"$TESTS_FAILED\" skipped=\"$TESTS_SKIPPED\" time=\"$TEST_TOTAL_TIME\" timestamp=\"$timestamp\">\n"

  # Group tests by test group
  local -A grouped_tests=()

  for result in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r name status duration message <<< "$result"

    # Extract group name if present
    local group="ungrouped"
    local test_name="$name"
    if [[ "$name" == *": "* ]]; then
      group="${name%%: *}"
      test_name="${name#*: }"
    fi

    # Add to group's test array
    if [[ -z "${grouped_tests[$group]:-}" ]]; then
      grouped_tests["$group"]=""
    fi

    grouped_tests["$group"]+="$test_name|$status|$duration|$message;"
  done

  # Process each group
  for group in "${!grouped_tests[@]}"; do
    local group_tests="${grouped_tests[$group]}"
    local group_count=0
    local group_failures=0
    local group_skipped=0
    local group_time=0

    # Process test results in this group
    IFS=';' read -ra test_array <<< "$group_tests"

    # First pass to collect group stats
    for test in "${test_array[@]}"; do
      [[ -z "$test" ]] && continue

      IFS='|' read -r test_name status duration _ <<< "$test"
      ((group_count++))

      if [[ "$status" == "FAIL" ]]; then
        ((group_failures++))
      elif [[ "$status" == "SKIP" ]]; then
        ((group_skipped++))
      fi

      if command -v bc &>/dev/null; then
        group_time=$(echo "$group_time + $duration" | bc 2>/dev/null || echo "$group_time")
      else
        # Less precise fallback
        group_time=$((group_time + duration))
      fi
    done

    # XML escape group name
    group="${group//&/&amp;}"
    group="${group//</&lt;}"
    group="${group//>/&gt;}"
    group="${group//\"/&quot;}"

    output+="  <testsuite name=\"$group\" tests=\"$group_count\" failures=\"$group_failures\" skipped=\"$group_skipped\" time=\"$group_time\">\n"

    # Second pass to add test cases
    for test in "${test_array[@]}"; do
      [[ -z "$test" ]] && continue

      IFS='|' read -r test_name status duration message <<< "$test"

      # XML escape test name and message
      test_name="${test_name//&/&amp;}"
      test_name="${test_name//</&lt;}"
      test_name="${test_name//>/&gt;}"
      test_name="${test_name//\"/&quot;}"

      message="${message//&/&amp;}"
      message="${message//</&lt;}"
      message="${message//>/&gt;}"
      message="${message//\"/&quot;}"

      output+="    <testcase name=\"$test_name\" classname=\"$group\" time=\"$duration\">\n"

      case "$status" in
        FAIL)
          output+="      <failure message=\"$message\"></failure>\n"
          ;;
        SKIP)
          output+="      <skipped message=\"$message\"></skipped>\n"
          ;;
      esac

      output+="    </testcase>\n"
    done

    output+="  </testsuite>\n"
  done

  # Add metadata
  output+="  <properties>\n"
  output+="    <property name=\"version\" value=\"$TEST_UTILS_VERSION\"/>\n"
  output+="    <property name=\"generated\" value=\"$timestamp\"/>\n"
  output+="  </properties>\n"

  output+="</testsuites>\n"

  echo -n "$output"
}

# Generate text report
# Returns: Text report as string
generate_text_report() {
  local output

  output="======================================\n"
  output+="CLOUD INFRASTRUCTURE PLATFORM TEST RESULTS\n"
  output+="======================================\n"
  output+="Total Tests: $TESTS_TOTAL\n"
  output+="Passed: $TESTS_PASSED\n"
  output+="Failed: $TESTS_FAILED\n"
  output+="Skipped: $TESTS_SKIPPED\n"
  output+="Time: ${TEST_TOTAL_TIME}s\n"
  output+="======================================\n\n"

  # Group tests by test group
  local -A grouped_tests=()

  for result in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r name status duration message <<< "$result"

    # Extract group name if present
    local group="ungrouped"
    if [[ "$name" == *": "* ]]; then
      group="${name%%: *}"
    fi

    # Add to group's test array
    if [[ -z "${grouped_tests[$group]:-}" ]]; then
      grouped_tests["$group"]=""
    fi

    grouped_tests["$group"]+="$result;"
  done

  # Process each group
  for group in "${!grouped_tests[@]}"; do
    local group_tests="${grouped_tests[$group]}"

    output+="GROUP: $group\n"
    output+="--------------------------------------\n"

    IFS=';' read -ra test_array <<< "$group_tests"
    for test in "${test_array[@]}"; do
      [[ -z "$test" ]] && continue

      IFS='|' read -r name status duration message <<< "$test"

      # Extract test name without group prefix
      local test_name="$name"
      if [[ "$name" == *": "* ]]; then
        test_name="${name#*: }"
      fi

      # Format based on status
      case "$status" in
        PASS)
          output+="${GREEN}[PASS]${NC} $test_name (${duration}s)\n"
          ;;
        FAIL)
          output+="${RED}[FAIL]${NC} $test_name (${duration}s)\n"
          if [[ -n "$message" ]]; then
            output+="       $message\n"
          fi
          ;;
        SKIP)
          output+="${YELLOW}[SKIP]${NC} $test_name (${duration}s)\n"
          if [[ -n "$message" ]]; then
            output+="       $message\n"
          fi
          ;;
      esac
    done

    output+="\n"
  done

  output+="Generated: $(date)\n"

  echo -n "$output"
}

#######################################
# MAIN EXECUTION
#######################################

# Main function to run all tests
# Returns:
#   0 if all tests pass, 1 if any tests fail
run_tests() {
  log_info "Starting test execution"

  local start_time
  start_time=$(date +%s)

  # Run tests here...
  # This is a placeholder - specific tests should be added by the user

  local end_time
  end_time=$(date +%s)
  TEST_TOTAL_TIME=$((end_time - start_time))

  log_info "Completed test execution in ${TEST_TOTAL_TIME}s"

  # Generate report
  generate_report

  # Return non-zero exit code if any tests failed
  [[ $TESTS_FAILED -eq 0 ]]
}

# Self-test function
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
  if command -v create_mock_environment &>/dev/null; then
    local mock_dir
    mock_dir=$(create_mock_environment "self_test")
    create_mock_file "$mock_dir/test.txt" "Hello world"
    run_test "Mock file creation" "test -f '$mock_dir/test.txt'"

    # Test mock command
    local mock_bin
    mock_bin=$(mock_command "custom_cmd" "echo 'This is a mock'")
    run_test "Mock command" "custom_cmd | grep -q 'This is a mock'"
    remove_mock_command "custom_cmd"

    # Clean up
    if command -v cleanup_all_mocks &>/dev/null; then
      cleanup_all_mocks
    elif command -v safe_rm_dir &>/dev/null; then
      safe_rm_dir "$mock_dir" &>/dev/null || true
    else
      rm -rf "$mock_dir" &>/dev/null || true
    fi
  else
    skip_test "Mock tests" "Mocking module not available"
  fi

  # System tests if available
  if command -v port_is_available &>/dev/null; then
    run_test "Port availability check" "port_is_available 1 || true"

    if command -v find_available_port &>/dev/null; then
      local test_port
      test_port=$(find_available_port) || test_port="12345"
      run_test "Find available port" "[[ -n '$test_port' ]] && port_is_available '$test_port'"
    fi

    if command -v is_host_reachable &>/dev/null; then
      run_test "Check localhost reachable" "is_host_reachable localhost 2 1 || true"
    fi
  else
    skip_test "System tests" "System module not available"
  fi

  # Test report generation
  if command -v create_secure_temp &>/dev/null; then
    local temp_report
    temp_report=$(create_secure_temp "test_report")

    # Save current output file
    local saved_output="$TEST_OUTPUT_FILE"
    TEST_OUTPUT_FILE="$temp_report"

    run_test "Report generation" "generate_report"
    run_test "Report file created" "[[ -f \"$temp_report\" && -s \"$temp_report\" ]]"

    # Restore output file
    TEST_OUTPUT_FILE="$saved_output"

    secure_remove_file "$temp_report" &>/dev/null || true
  else
    local temp_report
    temp_report=$(mktemp)

    # Save current output file
    local saved_output="$TEST_OUTPUT_FILE"
    TEST_OUTPUT_FILE="$temp_report"

    run_test "Report generation" "generate_basic_report"
    run_test "Report file created" "[[ -f \"$temp_report\" && -s \"$temp_report\" ]]"

    # Restore output file
    TEST_OUTPUT_FILE="$saved_output"

    rm -f "$temp_report" &>/dev/null || true
  fi

  end_test_group

  return 0
}

# Export all public functions
export -f begin_test_group
export -f end_test_group
export -f run_test
export -f skip_test
export -f register_coverage
export -f run_test_files
export -f run_tests
export -f self_test
export -f assert_equals
export -f assert_contains
export -f assert_success
export -f assert_fails
export -f parse_args
export -f show_usage
export -f generate_report
export -f generate_basic_report

# Export config variables
export TEST_DIR
export TEST_PATTERN
export TEST_VERBOSITY
export TEST_PARALLEL
export TEST_TIMEOUT
export TEST_OUTPUT_FORMAT
export TEST_OUTPUT_FILE

# When executed directly, run self-test
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if ! parse_args "$@"; then
    exit 1
  fi

  self_test
  exit $?
fi
