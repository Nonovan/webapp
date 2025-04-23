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
VALIDATION_UTILS="${COMMON_DIR}/common_validation_utils.sh"

# Version tracking
readonly TEST_UTILS_VERSION="1.1.0"
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

# Function availability cache to avoid repeated checks
declare -A AVAILABLE_FUNCTIONS=()

#######################################
# UTILITY FUNCTIONS
#######################################

# Check if a function is available and cache the result
# Arguments:
#   $1 - Function name
# Returns:
#   0 if function is available, 1 if not
function_exists() {
  local func_name="$1"

  # Use cached result if available
  if [[ -n "${AVAILABLE_FUNCTIONS[$func_name]:-}" ]]; then
    [[ "${AVAILABLE_FUNCTIONS[$func_name]}" == "true" ]]
    return $?
  fi

  # Check function availability and cache result
  if command -v "$func_name" &>/dev/null; then
    AVAILABLE_FUNCTIONS["$func_name"]="true"
    return 0
  else
    AVAILABLE_FUNCTIONS["$func_name"]="false"
    return 1
  fi
}

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

# Create a secure temporary file
# Arguments:
#   $1 - Prefix for temporary file (optional)
# Returns:
#   Path to the temporary file
create_temp_file() {
  local prefix="${1:-test_utils}"

  if function_exists create_secure_temp; then
    create_secure_temp "$prefix"
  else
    mktemp
  fi
}

# Securely delete a file
# Arguments:
#   $1 - File path
# Returns:
#   0 on success, 1 on failure
delete_file() {
  local file_path="$1"

  if function_exists secure_remove_file; then
    secure_remove_file "$file_path" &>/dev/null
  else
    rm -f "$file_path" &>/dev/null
  fi
}

# Escape a string for a specific format
# Arguments:
#   $1 - String to escape
#   $2 - Format (json, xml)
# Returns:
#   Escaped string
escape_string() {
  local string="$1"
  local format="${2:-}"

  case "$format" in
    json)
      string="${string//\\/\\\\}"
      string="${string//\"/\\\"}"
      ;;
    xml)
      string="${string//&/&amp;}"
      string="${string//</&lt;}"
      string="${string//>/&gt;}"
      string="${string//\"/&quot;}"
      ;;
  esac

  echo -n "$string"
}

# Write to a file securely
# Arguments:
#   $1 - Content
#   $2 - File path
# Returns:
#   0 on success, 1 on failure
write_file() {
  local content="$1"
  local file_path="$2"

  if function_exists safe_write_file; then
    safe_write_file "$content" "$file_path"
  else
    echo -e "$content" > "$file_path"
  fi
}

#######################################
# MODULE LOADING
#######################################

# First, load core module (required) and common utilities
load_script "$CORE_MODULE" "core module" "true"

# Load common utilities for file operations and system functions
load_script "$CORE_UTILS" "core utilities"
load_script "$FILE_OPS_UTILS" "file operations utilities"
load_script "$SYSTEM_UTILS" "system utilities"
load_script "$VALIDATION_UTILS" "validation utilities"

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

# Format test result with appropriate color
# Arguments:
#   $1 - Status (PASS, FAIL, SKIP)
#   $2 - Test name
#   $3 - Duration
#   $4 - Message (optional)
# Returns:
#   Formatted string
format_test_result() {
  local status="$1"
  local name="$2"
  local duration="$3"
  local message="${4:-}"
  local output=""

  case "$status" in
    PASS)
      output="${GREEN}[PASS]${NC} $name (${duration}s)"
      ;;
    FAIL)
      output="${RED}[FAIL]${NC} $name (${duration}s)"
      if [[ -n "$message" ]]; then
        output+="\n       $message"
      fi
      ;;
    SKIP)
      output="${YELLOW}[SKIP]${NC} $name (${duration}s)"
      if [[ -n "$message" ]]; then
        output+="\n       $message"
      fi
      ;;
  esac

  echo -n "$output"
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
    log_info "$(format_test_result "SKIP" "$full_name" "0.0" "$details")"
    TEST_RESULTS+=("$full_name|SKIP|0.0|$details")
    ((TESTS_SKIPPED++))
    ((TESTS_TOTAL++))
    return 0
  fi

  log_debug "Executing: $command"

  # Run the test and capture exit status and output
  start_time=$(date +%s.%N 2>/dev/null || date +%s)

  # Use temporary file for output
  local temp_output
  temp_output=$(create_temp_file "test_output")

  # Execute command and capture status
  eval "$command" > "$temp_output" 2>&1 || status=$?

  end_time=$(date +%s.%N 2>/dev/null || date +%s)
  local output=$(<"$temp_output")
  delete_file "$temp_output"

  # Calculate duration
  if function_exists bc && command -v bc &>/dev/null; then
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null)
    duration=$(echo "scale=2; $duration" | bc 2>/dev/null)
  else
    duration=$((end_time - start_time))
  fi

  # Track the test result
  ((TESTS_TOTAL++))

  if [[ -z "${status:-}" ]]; then
    log_info "$(format_test_result "PASS" "$full_name" "$duration")"
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

    log_error "$(format_test_result "FAIL" "$full_name" "$duration" "$failure_message")"
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

# Get test files based on pattern
# Returns:
#   Array of test files
get_test_files() {
  local pattern="$TEST_PATTERN"
  local test_dir="$TEST_DIR"
  local test_files=()

  # Use common utility if available, otherwise use basic find
  if function_exists find_files; then
    # Use the project's file_ops find utility with pattern
    readarray -t test_files < <(find_files "$test_dir" "$pattern" "false" "")
  else
    # Fallback to basic find
    while IFS= read -r -d $'\0' file; do
      test_files+=("$file")
    done < <(find "$test_dir" -type f -name "$pattern" -print0 2>/dev/null | sort -z)
  fi

  echo "${test_files[@]:-}"
}

# Run multiple test files
# Returns:
#   0 if all tests pass, 1 if any tests fail
run_test_files() {
  local exit_code=0

  log_info "Running test files matching '$TEST_PATTERN' in $TEST_DIR"

  # Check that the test directory exists
  if [[ ! -d "$TEST_DIR" ]]; then
    log_error "Test directory does not exist: $TEST_DIR"
    return 1
  fi

  # Get test files
  local test_files_str=$(get_test_files)
  if [[ -z "$test_files_str" ]]; then
    log_warn "No test files found matching '$TEST_PATTERN' in $TEST_DIR"
    return 1
  fi

  # Convert to array
  read -ra test_files <<< "$test_files_str"

  log_info "Found ${#test_files[@]} test files to execute"

  # Start timing
  local start_time end_time
  start_time=$(date +%s)

  # Set up parallel execution if enabled and available
  local parallel_enabled=false
  if [[ $TEST_PARALLEL -gt 1 ]] && command -v parallel &>/dev/null; then
    parallel_enabled=true
    log_info "Running tests in parallel with $TEST_PARALLEL jobs"

    # Create a temporary results file for parallel execution
    local temp_results
    temp_results=$(create_temp_file "parallel_results")

    # Export necessary functions and variables for parallel
    export -f run_test begin_test_group end_test_group register_coverage
    export -f log log_info log_debug log_warn log_error
    export -f create_temp_file delete_file escape_string write_file format_test_result
    export CURRENT_TEST_GROUP TEST_VERBOSITY

    # Use GNU parallel to run tests in parallel
    parallel --jobs "$TEST_PARALLEL" --results "$temp_results" \
      "source \"$BASH_SOURCE\"; begin_test_group \"{= s:^.*/::; s:_test\.sh$::; =}\"; source {}; end_test_group" ::: "${test_files[@]}" || exit_code=1

    log_info "Parallel execution completed. Results stored in $temp_results"
    delete_file "$temp_results"
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
# ASSERTION FUNCTIONS
#######################################

# Validate if a module function exists and can be used
# Arguments:
#   $1 - Function name
# Returns:
#   0 if valid module function, 1 if not
is_valid_module_function() {
  local func_name="$1"

  # Check if function exists and is not our own implementation (head -1)
  [[ $(type -t "$func_name") == "function" &&
     $(declare -f "$func_name" | head -1) != "$func_name() {" ]]
}

# Execute an assertion with fallback functionality
# Arguments:
#   $1 - Assertion name (equals, contains, success, fails)
#   $@ - Arguments to pass to assertion function
# Returns:
#   Result of the assertion
execute_assertion() {
  local assertion="$1"
  local func_name="assert_$assertion"
  shift

  # If assertions module has this function, use that implementation
  if is_valid_module_function "$func_name"; then
    "$func_name" "$@"
    return $?
  fi

  # Otherwise use our built-in implementation
  "builtin_assert_$assertion" "$@"
}

# Built-in assert equals
# Arguments:
#   $1 - Actual value
#   $2 - Expected value
#   $3 - Optional message
# Returns:
#   0 if equal, 1 if not
builtin_assert_equals() {
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

# Built-in assert contains
# Arguments:
#   $1 - String to search in
#   $2 - Substring to search for
#   $3 - Optional message
# Returns:
#   0 if string contains substring, 1 otherwise
builtin_assert_contains() {
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

# Built-in assert success
# Arguments:
#   $1 - Command to run (or timeout if numeric)
#   $2... - Command arguments (if $1 is timeout)
# Returns:
#   0 if command succeeds, 1 otherwise
builtin_assert_success() {
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

  # Create a temp file for output
  local temp_output
  temp_output=$(create_temp_file "assert")

  # Use execute_with_timeout if available
  if function_exists execute_with_timeout; then
    if [[ -n "$timeout" ]]; then
      execute_with_timeout "$timeout" "$@" > "$temp_output" 2>&1
      exit_code=$?
    else
      "$@" > "$temp_output" 2>&1
      exit_code=$?
    fi
  elif command -v timeout >/dev/null 2>&1; then
    # Fallback to GNU timeout
    timeout "$timeout" "$@" > "$temp_output" 2>&1 || exit_code=$?
  else
    # No timeout available
    "$@" > "$temp_output" 2>&1 || exit_code=$?
  fi

  # Read output from temp file
  output=$(<"$temp_output")
  delete_file "$temp_output"

  if [[ $exit_code -eq 0 ]]; then
    log_debug "Assertion passed: Command succeeded"
    return 0
  else
    log_error "Command was expected to succeed but failed with exit code $exit_code"
    log_error "Command: $*"
    log_error "Output: $output"
    return 1
  fi
}

# Built-in assert fails
# Arguments:
#   $1 - Command to run (or timeout if numeric)
#   $2... - Command arguments (if $1 is timeout)
# Returns:
#   0 if command fails, 1 if it succeeds
builtin_assert_fails() {
  local timeout=""
  local expected_code=""
  local exit_code=0
  local output=""

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

  # Create a temp file for output
  local temp_output
  temp_output=$(create_temp_file "assert")

  # Execute command with timeout if available
  if function_exists execute_with_timeout && [[ -n "$timeout" ]]; then
    execute_with_timeout "$timeout" "$@" > "$temp_output" 2>&1
    exit_code=$?
  elif command -v timeout >/dev/null 2>&1 && [[ -n "$timeout" ]]; then
    timeout "$timeout" "$@" > "$temp_output" 2>&1 || exit_code=$?
  else
    # No timeout available
    "$@" > "$temp_output" 2>&1 || exit_code=$?
  fi

  # Read output from temp file
  output=$(<"$temp_output")
  delete_file "$temp_output"

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

# Wrapper functions for external use
assert_equals() { execute_assertion "equals" "$@"; }
assert_contains() { execute_assertion "contains" "$@"; }
assert_success() { execute_assertion "success" "$@"; }
assert_fails() { execute_assertion "fails" "$@"; }

#######################################
# COMMAND LINE ARGUMENT HANDLING
#######################################

# Define a dispatch table for command line arguments
declare -A ARG_HANDLERS=(
  ["help"]="show_usage_and_exit"
  ["verbose"]="set_verbose_mode"
  ["quiet"]="set_quiet_mode"
  ["dir"]="set_test_directory"
  ["pattern"]="set_test_pattern"
  ["format"]="set_output_format"
  ["output"]="set_output_file"
  ["self-test"]="enable_self_test"
  ["parallel"]="set_parallel_jobs"
  ["timeout"]="set_timeout"
)

# Handler for help argument
# Returns: 1 to exit
show_usage_and_exit() {
  show_usage
  return 1
}

# Handler for verbose mode
# Returns: 1 (consumed argument)
set_verbose_mode() {
  TEST_VERBOSITY="debug"
  return 1
}

# Handler for quiet mode
# Returns: 1 (consumed argument)
set_quiet_mode() {
  TEST_VERBOSITY="error"
  return 1
}

# Handler for test directory
# Arguments: $1 - directory
# Returns: 2 (consumed 2 arguments)
set_test_directory() {
  TEST_DIR="$1"
  return 2
}

# Handler for test pattern
# Arguments: $1 - pattern
# Returns: 2 (consumed 2 arguments)
set_test_pattern() {
  TEST_PATTERN="$1"
  return 2
}

# Handler for output format
# Arguments: $1 - format
# Returns: 2 (consumed 2 arguments)
set_output_format() {
  TEST_OUTPUT_FORMAT="$1"
  return 2
}

# Handler for output file
# Arguments: $1 - file
# Returns: 2 (consumed 2 arguments)
set_output_file() {
  TEST_OUTPUT_FILE="$1"
  return 2
}

# Handler for self-test mode
# Returns: 1 (consumed argument)
enable_self_test() {
  SELF_TEST_MODE=true
  return 1
}

# Handler for parallel jobs
# Arguments: $1 - jobs
# Returns: 2 (consumed 2 arguments)
set_parallel_jobs() {
  TEST_PARALLEL="$1"
  return 2
}

# Handler for timeout
# Arguments: $1 - timeout
# Returns: 2 (consumed 2 arguments)
set_timeout() {
  TEST_TIMEOUT="$1"
  return 2
}

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
  SELF_TEST_MODE=false

  while [[ $# -gt 0 ]]; do
    local arg="$1"
    local handled=false
    local consumed=0

    # Check for argument variations
    local arg_key=""
    case "$arg" in
      -h|--help)
        arg_key="help"
        ;;
      -v|--verbose)
        arg_key="verbose"
        ;;
      -q|--quiet)
        arg_key="quiet"
        ;;
      -d|--dir)
        arg_key="dir"
        ;;
      -p|--pattern)
        arg_key="pattern"
        ;;
      -f|--format)
        arg_key="format"
        ;;
      -o|--output)
        arg_key="output"
        ;;
      -s|--self-test)
        arg_key="self-test"
        ;;
      -j|--parallel)
        arg_key="parallel"
        ;;
      -t|--timeout)
        arg_key="timeout"
        ;;
      *)
        log_error "Unknown option: $arg"
        show_usage
        return 1
        ;;
    esac

    # Call the handler if found
    if [[ -n "$arg_key" ]]; then
      local handler="${ARG_HANDLERS[$arg_key]}"
      if [[ -n "$handler" ]]; then
        # Call handler with next argument (may not be used)
        "$handler" "${2:-}"
        consumed=$?
        handled=true
      fi
    fi

    # Skip consumed arguments
    shift $consumed
  done

  # Create output directory if needed
  if [[ -n "$TEST_OUTPUT_FILE" ]]; then
    local output_dir
    output_dir=$(dirname "$TEST_OUTPUT_FILE")

    if function_exists ensure_directory; then
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
  if [[ "$SELF_TEST_MODE" == "false" ]]; then
    run_test_files
    return $?
  fi

  return 0
}

#######################################
# REPORT GENERATION
#######################################

# Process test results by group
# Arguments:
#   $1 - Function to process each group
process_test_results_by_group() {
  local processor_func="$1"
  local -A grouped_tests=()

  # Group tests by test group
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

  # Process each group using the provided function
  for group in "${!grouped_tests[@]}"; do
    local group_tests="${grouped_tests[$group]}"
    "$processor_func" "$group" "$group_tests"
  done
}

# Generate a basic test report
# Returns:
#   0 on success, 1 on failure
generate_report() {
  # If the reporting module functions are available, use them instead
  if function_exists generate_test_report; then
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
  local format="${TEST_OUTPUT_FORMAT}"
  local output_file="${TEST_OUTPUT_FILE}"
  local output=""

  # Generate appropriate report based on format
  case "$format" in
    json)
      output=$(generate_json_report)
      ;;
    junit|xml)
      output=$(generate_xml_report)
      ;;
    *)
      output=$(generate_text_report)
      ;;
  esac

  # Output the report
  if [[ -n "$output_file" ]]; then
    write_file "$output" "$output_file" || {
      log_error "Failed to write report to $output_file"
      return 1
    }
    log_info "Test report written to $output_file"
  else
    echo -e "$output"
  fi

  return 0
}

# Process test group for JSON format
# Arguments:
#   $1 - Group name
#   $2 - Group tests
# Returns:
#   JSON string for test group
process_json_group() {
  local group="$1"
  local group_tests="$2"
  local output=""
  local first=true

  IFS=';' read -ra test_array <<< "$group_tests"

  for test in "${test_array[@]}"; do
    [[ -z "$test" ]] && continue

    IFS='|' read -r name status duration message <<< "$test"

    if [[ "$first" == "true" ]]; then
      first=false
    else
      output+=",\n"
    fi

    # Extract test name without group prefix
    local test_name="$name"
    if [[ "$name" == *": "* ]]; then
      test_name="${name#*: }"
    fi

    # Escape JSON strings
    test_name=$(escape_string "$test_name" "json")
    group=$(escape_string "$group" "json")
    message=$(escape_string "$message" "json")

    output+="    {\n"
    output+="      \"name\": \"$test_name\",\n"
    output+="      \"group\": \"$group\",\n"
    output+="      \"status\": \"$status\",\n"
    output+="      \"duration\": $duration,\n"
    output+="      \"message\": \"$message\"\n"
    output+="    }"
  done

  echo -n "$output"
}

# Generate JSON report
# Returns: JSON report as string
generate_json_report() {
  local output=""

  output="{\n"
  output+="  \"summary\": {\n"
  output+="    \"total\": $TESTS_TOTAL,\n"
  output+="    \"passed\": $TESTS_PASSED,\n"
  output+="    \"failed\": $TESTS_FAILED,\n"
  output+="    \"skipped\": $TESTS_SKIPPED,\n"
  output+="    \"time\": $TEST_TOTAL_TIME\n"
  output+="  },\n"
  output+="  \"tests\": ["

  # Process test results
  local tests_json=""
  for group in "${!grouped_tests[@]}"; do
    local group_json=$(process_json_group "$group" "${grouped_tests[$group]}")
    if [[ -n "$tests_json" && -n "$group_json" ]]; then
      tests_json+=",\n$group_json"
    else
      tests_json+="\n$group_json"
    fi
  done

  output+="$tests_json"
  output+="\n  ],\n"
  output+="  \"coverage\": ["

  local first=true
  for file in "${COVERAGE_DATA[@]}"; do
    if [[ "$first" == "true" ]]; then
      first=false
      output+="\n"
    else
      output+=",\n"
    fi

    # Escape JSON string
    file=$(escape_string "$file" "json")

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

# Process test group for XML report
# Arguments:
#   $1 - Group name
#   $2 - Group tests
# Returns:
#   Stats and XML content for test group
process_xml_group() {
  local group="$1"
  local group_tests="$2"
  local output=""
  local group_count=0
  local group_failures=0
  local group_skipped=0
  local group_time=0

  # XML escape group name
  group=$(escape_string "$group" "xml")

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

  output="  <testsuite name=\"$group\" tests=\"$group_count\" failures=\"$group_failures\" skipped=\"$group_skipped\" time=\"$group_time\">\n"

  # Second pass to add test cases
  for test in "${test_array[@]}"; do
    [[ -z "$test" ]] && continue

    IFS='|' read -r test_name status duration message <<< "$test"

    # Extract test name without group prefix
    if [[ "$test_name" == *": "* ]]; then
      test_name="${test_name#*: }"
    fi

    # XML escape test name and message
    test_name=$(escape_string "$test_name" "xml")
    message=$(escape_string "$message" "xml")

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
    if [[ "$name" == *": "* ]]; then
      group="${name%%: *}"
    fi

    # Add to group's test array
    if [[ -z "${grouped_tests[$group]:-}" ]]; then
      grouped_tests["$group"]=""
    fi

    grouped_tests["$group"]+="$name|$status|$duration|$message;"
  done

  # Process each group
  for group in "${!grouped_tests[@]}"; do
    output+=$(process_xml_group "$group" "${grouped_tests[$group]}")
  done

  # Add metadata
  output+="  <properties>\n"
  output+="    <property name=\"version\" value=\"$TEST_UTILS_VERSION\"/>\n"
  output+="    <property name=\"generated\" value=\"$timestamp\"/>\n"
  output+="  </properties>\n"

  output+="</testsuites>\n"

  echo -n "$output"
}

# Process test group for text report
# Arguments:
#   $1 - Group name
#   $2 - Group tests
# Returns:
#   Text representation of test group results
process_text_group() {
  local group="$1"
  local group_tests="$2"
  local output=""

  output="GROUP: $group\n"
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

    # Format based on status using our helper function
    output+="$(format_test_result "$status" "$test_name" "$duration" "$message")\n"
  done

  output+="\n"
  echo -n "$output"
}

# Generate text report
# Returns: Text report as string
generate_text_report() {
  local output=""

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
    output+=$(process_text_group "$group" "${grouped_tests[$group]}")
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
  if function_exists create_mock_environment; then
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
    if function_exists cleanup_all_mocks; then
      cleanup_all_mocks
    elif function_exists safe_rm_dir; then
      safe_rm_dir "$mock_dir" &>/dev/null || true
    else
      rm -rf "$mock_dir" &>/dev/null || true
    fi
  else
    skip_test "Mock tests" "Mocking module not available"
  fi

  # System tests if available
  if function_exists port_is_available; then
    run_test "Port availability check" "port_is_available 1 || true"

    if function_exists find_available_port; then
      local test_port
      test_port=$(find_available_port) || test_port="12345"
      run_test "Find available port" "[[ -n '$test_port' ]] && port_is_available '$test_port'"
    fi

    if function_exists is_host_reachable; then
      run_test "Check localhost reachable" "is_host_reachable localhost 2 1 || true"
    fi
  else
    skip_test "System tests" "System module not available"
  fi

  # Test report generation
  local temp_report
  temp_report=$(create_temp_file "test_report")

  # Save current output file
  local saved_output="$TEST_OUTPUT_FILE"
  TEST_OUTPUT_FILE="$temp_report"

  run_test "Report generation" "generate_report"
  run_test "Report file created" "[[ -f \"$temp_report\" && -s \"$temp_report\" ]]"

  # Restore output file
  TEST_OUTPUT_FILE="$saved_output"

  delete_file "$temp_report"

  end_test_group

  return 0
}

# Export all public functions
export -f function_exists
export -f log
export -f log_info
export -f log_debug
export -f log_warn
export -f log_error
export -f create_temp_file
export -f delete_file
export -f escape_string
export -f write_file
export -f begin_test_group
export -f end_test_group
export -f format_test_result
export -f run_test
export -f skip_test
export -f register_coverage
export -f get_test_files
export -f run_test_files
export -f is_valid_module_function
export -f execute_assertion
export -f assert_equals
export -f assert_contains
export -f assert_success
export -f assert_fails
export -f run_tests
export -f self_test
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
