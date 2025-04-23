#!/bin/bash
# filepath: scripts/utils/testing/test_utils.sh
# General Testing Utilities for Cloud Infrastructure Platform
#
# This script provides a comprehensive set of testing utilities that can be used
# across all scripts in the Cloud Infrastructure Platform. It serves as a thin
# integration layer that leverages specialized modules when available.
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
TESTING_DIR="${UTILS_DIR}/testing"
CORE_MODULE="${MODULES_DIR}/core.sh"
ASSERTIONS_MODULE="${MODULES_DIR}/assertions.sh"
MOCKING_MODULE="${MODULES_DIR}/mocking.sh"
REPORTING_MODULE="${MODULES_DIR}/reporting.sh"
SYSTEM_MODULE="${MODULES_DIR}/system.sh"
TEST_HELPERS="${TESTING_DIR}/test_helpers.sh"

# Common utilities that we'll use for file ops, etc.
CORE_UTILS="${COMMON_DIR}/common_core_utils.sh"
FILE_OPS_UTILS="${COMMON_DIR}/common_file_ops_utils.sh"
SYSTEM_UTILS="${COMMON_DIR}/common_system_utils.sh"
VALIDATION_UTILS="${COMMON_DIR}/common_validation_utils.sh"

# Version tracking
readonly TEST_UTILS_VERSION="1.0.0"
readonly TEST_UTILS_DATE="2024-08-15"

#######################################
# CONFIG VARIABLES AND DEFAULTS
#######################################

# Group related configuration in associative arrays
declare -A CONFIG=(
  [output_format]="text"
  [output_dir]="${PROJECT_ROOT}/reports/test"
  [timeout]=30
  [test_pattern]="*_test.sh"
  [parallel]=1
  [verbosity]="info"
)

# Default settings
DEFAULT_OUTPUT_FORMAT="${CONFIG[output_format]}"
DEFAULT_OUTPUT_DIR="${CONFIG[output_dir]}"
DEFAULT_TIMEOUT="${CONFIG[timeout]}"
DEFAULT_TEST_PATTERN="${CONFIG[test_pattern]}"
DEFAULT_PARALLEL_TESTS="${CONFIG[parallel]}"
DEFAULT_VERBOSITY="${CONFIG[verbosity]}"

# Global configuration variables
# These can be overridden before sourcing the script or via command line args
TEST_VERBOSITY="${TEST_VERBOSITY:-$DEFAULT_VERBOSITY}"
TEST_OUTPUT_FORMAT="${TEST_OUTPUT_FORMAT:-$DEFAULT_OUTPUT_FORMAT}"
TEST_OUTPUT_FILE="${TEST_OUTPUT_FILE:-}"
TEST_DIR="${TEST_DIR:-$PROJECT_ROOT/tests}"
TEST_PATTERN="${TEST_PATTERN:-$DEFAULT_TEST_PATTERN}"
TEST_PARALLEL="${TEST_PARALLEL:-$DEFAULT_PARALLEL_TESTS}"
TEST_TIMEOUT="${TEST_TIMEOUT:-$DEFAULT_TIMEOUT}"

# Test tracking variables - these are used if specialized modules aren't available
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
# BASIC LOGGING FUNCTIONS
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

#######################################
# MODULE LOADING
#######################################

# Load a module or utility script
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

# Load test helpers module
load_script "$TEST_HELPERS" "test helpers" "true"

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
    # Define terminal colors in an associative array
    declare -A COLORS=(
      [red]='\033[0;31m'
      [green]='\033[0;32m'
      [yellow]='\033[0;33m'
      [blue]='\033[0;34m'
      [cyan]='\033[0;36m'
      [bold]='\033[1m'
      [nc]='\033[0m'
    )

    # Extract to variables for compatibility
    readonly RED="${COLORS[red]}"
    readonly GREEN="${COLORS[green]}"
    readonly YELLOW="${COLORS[yellow]}"
    readonly BLUE="${COLORS[blue]}"
    readonly CYAN="${COLORS[cyan]}"
    readonly BOLD="${COLORS[bold]}"
    readonly NC="${COLORS[nc]}"
  else
    # No color support
    declare -A COLORS=([red]="" [green]="" [yellow]="" [blue]="" [cyan]="" [bold]="" [nc]="")
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

# Begin a test group - delegates to core module if available
# Arguments:
#   $1 - Group name
# Returns:
#   0 on success
begin_test_group() {
  local group_name="${1:-Unnamed Group}"

  # Use core module function if available
  if function_exists begin_test_group && ! function_equals begin_test_group; then
    begin_test_group "$group_name"
    return $?
  fi

  # Add to groups list if not already present
  if function_exists filter_array; then
    filter_array "$group_name" "${TEST_GROUPS[@]:-}"
    if [[ ${#RETURN_ARRAY[@]} -eq 0 ]]; then
      TEST_GROUPS+=("$group_name")
    fi
  else
    # Simple implementation if filter_array isn't available
    local found=false
    for group in "${TEST_GROUPS[@]:-}"; do
      if [[ "$group" == "$group_name" ]]; then
        found=true
        break
      fi
    done

    if [[ $found == false ]]; then
      TEST_GROUPS+=("$group_name")
    fi
  fi

  CURRENT_TEST_GROUP="$group_name"
  log_info "Starting test group: $CURRENT_TEST_GROUP"

  return 0
}

# End the current test group - delegates to core module if available
# Arguments:
#   None
# Returns:
#   0 on success
end_test_group() {
  # Use core module function if available
  if function_exists end_test_group && ! function_equals end_test_group; then
    end_test_group
    return $?
  fi

  if [[ -n "$CURRENT_TEST_GROUP" ]]; then
    log_info "Completed test group: $CURRENT_TEST_GROUP"
    CURRENT_TEST_GROUP=""
  fi

  return 0
}

# Check if a function is defined
# Arguments:
#   $1 - Function name
# Returns:
#   0 if defined, 1 if not
function_exists() {
  declare -F "$1" >/dev/null
}

# Check if two functions are identical
# Arguments:
#   $1 - Function name
# Returns:
#   0 if the function is identical to this implementation, 1 otherwise
function_equals() {
  # Get first line of function definition to check if it's our own implementation
  local func_head
  func_head=$(declare -f "$1" | head -1)
  # If the function begins with its name followed by (), it's our own implementation
  [[ $func_head == "$1()" ]]
}

# Run a single test - delegates to test_helpers if available
# Arguments:
#   $1 - Test name
#   $2 - Test command (string to be evaluated)
#   $3 - Skip flag (optional, "true" to skip)
#   $4 - Additional test details (optional)
# Returns:
#   0 if test passes, 1 if fails
run_test() {
  # If test_helpers has this function, use that implementation
  if function_exists run_test && ! function_equals run_test; then
    run_test "$@"
    return $?
  }

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

  # Create temporary file for output
  local temp_output
  if function_exists create_temp_file; then
    temp_output=$(create_temp_file "test_output")
  else
    temp_output=$(mktemp)
  fi

  # Execute command and capture status
  eval "$command" > "$temp_output" 2>&1 || status=$?

  end_time=$(date +%s.%N 2>/dev/null || date +%s)
  local output=$(<"$temp_output")

  if function_exists delete_file; then
    delete_file "$temp_output"
  else
    rm -f "$temp_output"
  fi

  # Calculate duration
  if command -v bc &>/dev/null; then
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

# Skip a test with a specific reason
# Arguments:
#   $1 - Test name
#   $2 - Reason for skipping (optional)
# Returns:
#   0 on success
skip_test() {
  run_test "$1" "exit 0" "true" "${2:-Test skipped explicitly}"
}

# Register a file as covered by tests
# Arguments:
#   $1 - Path to the file being tested
# Returns:
#   0 on success
register_coverage() {
  # If test_helpers has this function, use that implementation
  if function_exists register_coverage && ! function_equals register_coverage; then
    register_coverage "$@"
    return $?
  }

  local file_path="${1:-}"

  if [[ -n "$file_path" && -f "$file_path" ]]; then
    COVERAGE_DATA+=("$file_path")
    log_debug "Registered coverage for $file_path"
  fi

  return 0
}

# Get test files based on pattern
# Returns:
#   Array of test files
get_test_files() {
  # If test_helpers has this function, use that implementation
  if function_exists get_test_files && ! function_equals get_test_files; then
    get_test_files
    return $?
  }

  local pattern="${TEST_PATTERN}"
  local test_dir="${TEST_DIR}"
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

# Run tests in parallel
# Arguments:
#   $@ - Array of test files
# Returns:
#   0 if successful, 1 if error
run_parallel_tests() {
  # If test_helpers has this function, use that implementation
  if function_exists run_parallel_tests && ! function_equals run_parallel_tests; then
    run_parallel_tests "$@"
    return $?
  }

  local -a test_files=("$@")
  local exit_code=0

  log_info "Running tests in parallel with $TEST_PARALLEL jobs"

  # Create a temporary results file for parallel execution
  local temp_results
  if function_exists create_temp_file; then
    temp_results=$(create_temp_file "parallel_results")
  else
    temp_results=$(mktemp)
  fi

  # Export necessary functions and variables for parallel
  export -f run_test begin_test_group end_test_group register_coverage
  export -f log log_info log_debug log_warn log_error
  export -f function_exists function_equals
  export CURRENT_TEST_GROUP TEST_VERBOSITY

  # Execute in parallel
  if command -v parallel &>/dev/null; then
    parallel --jobs "$TEST_PARALLEL" --results "$temp_results" "source \"$BASH_SOURCE\"; begin_test_group \"{= s:^.*/::; s:_test\.sh$::; =}\"; source {}; end_test_group" ::: "${test_files[@]}" || exit_code=1
  else
    log_error "GNU parallel not found. Cannot run tests in parallel."
    exit_code=1
  fi

  log_info "Parallel execution completed. Results stored in $temp_results"
  rm -f "$temp_results"

  return $exit_code
}

# Run sequential tests
# Arguments:
#   $@ - Array of test files
# Returns:
#   0 if successful, 1 if error
run_sequential_tests() {
  # If test_helpers has this function, use that implementation
  if function_exists run_sequential_tests && ! function_equals run_sequential_tests; then
    run_sequential_tests "$@"
    return $?
  }

  local -a test_files=("$@")
  local exit_code=0

  for test_file in "${test_files[@]}"; do
    log_info "Executing test file: $test_file"

    # Capture test file output and exit code
    if [[ -x "$test_file" ]]; then
      # File is executable - execute it directly
      "$test_file" || {
        log_error "Test file failed: $test_file with exit code $?"
        exit_code=1
      }
    else
      # Not executable, source it
      begin_test_group "$(basename "${test_file%.*}")"
      # shellcheck source=/dev/null
      source "$test_file" || {
        log_error "Failed to source test file: $test_file with exit code $?"
        exit_code=1
      }
      end_test_group
    fi

    register_coverage "$test_file"
  done

  return $exit_code
}

# Run multiple test files
# Returns:
#   0 if all tests pass, 1 if any tests fail
run_test_files() {
  # If test_helpers has this function, use that implementation
  if function_exists run_test_files && ! function_equals run_test_files; then
    run_test_files
    return $?
  }

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
  local -a test_files
  read -ra test_files <<< "$test_files_str"

  log_info "Found ${#test_files[@]} test files to execute"

  # Start timing
  local start_time end_time
  start_time=$(date +%s)

  # Use parallel execution if enabled and available
  if [[ $TEST_PARALLEL -gt 1 ]] && command -v parallel &>/dev/null; then
    run_parallel_tests "${test_files[@]}" || exit_code=1
  else
    # Sequential execution
    run_sequential_tests "${test_files[@]}" || exit_code=1
  fi

  end_time=$(date +%s)
  TEST_TOTAL_TIME=$((end_time - start_time))

  log_info "Completed test file execution in ${TEST_TOTAL_TIME}s"

  return $exit_code
}

#######################################
# ASSERTION FUNCTIONS - DELEGATING TO ASSERTIONS MODULE
#######################################

# Execute an assertion function from the assertions module
# Arguments:
#   $1 - Assertion name (equals, contains, success, fails, etc.)
#   $@ - Arguments to pass to assertion function
# Returns:
#   Result of the assertion
execute_assertion() {
  local assertion="$1"
  local func_name="assert_$assertion"
  shift

  # If assertions module has this function, use it
  if function_exists "$func_name"; then
    "$func_name" "$@"
    return $?
  else
    # Assertion is not available
    log_error "Assertion function $func_name not available."
    return 1
  fi
}

# Wrapper functions for assertions - delegates to assertions module
assert_equals() { execute_assertion "equals" "$@"; }
assert_not_equals() { execute_assertion "not_equals" "$@"; }
assert_contains() { execute_assertion "contains" "$@"; }
assert_not_contains() { execute_assertion "not_contains" "$@"; }
assert_success() { execute_assertion "success" "$@"; }
assert_fails() { execute_assertion "fails" "$@"; }
assert_file_exists() { execute_assertion "file_exists" "$@"; }
assert_file_not_exists() { execute_assertion "file_not_exists" "$@"; }
assert_dir_exists() { execute_assertion "dir_exists" "$@"; }
assert_dir_not_exists() { execute_assertion "dir_not_exists" "$@"; }
assert_file_contains() { execute_assertion "file_contains" "$@"; }
assert_file_not_contains() { execute_assertion "file_not_contains" "$@"; }
assert_file_matches() { execute_assertion "file_matches" "$@"; }
assert_var_defined() { execute_assertion "var_defined" "$@"; }
assert_var_not_empty() { execute_assertion "var_not_empty" "$@"; }
assert_path_permissions() { execute_assertion "path_permissions" "$@"; }

#######################################
# COMMAND EXECUTION UTILITIES - DELEGATING TO SYSTEM MODULE
#######################################

# Run command with timeout - delegates to system module
# Arguments:
#   $1 - Timeout in seconds
#   $2... - Command to execute
# Returns:
#   Exit code of the command or timeout error
run_with_timeout() {
  # If system module has execute_with_timeout, use it
  if function_exists execute_with_timeout; then
    execute_with_timeout "$@"
    return $?
  elif command -v timeout &>/dev/null; then
    # Standard GNU timeout command
    timeout "$@"
    return $?
  else
    # No timeout available, just run the command without a timeout
    shift  # Remove timeout parameter
    "$@"
    return $?
  fi
}

# Get an available port - delegates to system module
# Returns:
#   Available port number
find_available_port() {
  if function_exists find_available_port && ! function_equals find_available_port; then
    find_available_port
    return $?
  fi

  # Fallback implementation
  local port=0
  # Try a common range (8000-9000) and find first available port
  for ((port=8000; port<9000; port++)); do
    if ! command -v nc &>/dev/null || ! nc -z localhost "$port" &>/dev/null; then
      echo "$port"
      return 0
    fi
  done

  echo "8080"  # Default fallback
  return 1
}

# Check if a port is available - delegates to system module
# Arguments:
#   $1 - Port number
# Returns:
#   0 if available, 1 if not
port_is_available() {
  if function_exists port_is_available && ! function_equals port_is_available; then
    port_is_available "$@"
    return $?
  fi

  # Fallback implementation
  local port="$1"
  if command -v nc &>/dev/null; then
    ! nc -z localhost "$port" &>/dev/null
    return $?
  else
    # Without nc, try a quick listener
    (echo > /dev/tcp/127.0.0.1/"$port") &>/dev/null && return 1 || return 0
  fi
}

#######################################
# STRING HANDLING - DELEGATING TO STRING UTILS
#######################################

# Escape a string for a specific format - delegates to string_utils or format_utils
# Arguments:
#   $1 - String to escape
#   $2 - Format (json, xml, csv, regex, shell)
# Returns:
#   Escaped string
escape_string() {
  # If string_utils has this function, use it
  if function_exists escape_string && ! function_equals escape_string; then
    escape_string "$@"
    return $?
  elif function_exists escape_json && function_exists escape_xml; then
    # Format-specific escape functions are available
    local string="$1"
    local format="${2:-shell}"

    case "$format" in
      json) escape_json "$string" ;;
      xml) escape_xml "$string" ;;
      csv) escape_csv_field "$string" ;;
      *) echo "$string" ;;
    esac
    return $?
  else
    # Minimal implementation for common formats
    local string="$1"
    local format="${2:-shell}"

    case "$format" in
      json)
        # Basic JSON escaping
        string="${string//\\/\\\\}"
        string="${string//\"/\\\"}"
        string="${string//	/\\t}"
        string="${string//$'\n'/\\n}"
        string="${string//$'\r'/\\r}"
        ;;
      xml)
        # Basic XML escaping
        string="${string//&/&amp;}"
        string="${string//</&lt;}"
        string="${string//>/&gt;}"
        string="${string//\"/&quot;}"
        ;;
    esac

    echo -n "$string"
  fi
}

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

# Handler functions for command line arguments
show_usage_and_exit() {
  show_usage
  return 1
}

set_verbose_mode() {
  TEST_VERBOSITY="debug"
  return 1
}

set_quiet_mode() {
  TEST_VERBOSITY="error"
  return 1
}

set_test_directory() {
  TEST_DIR="$1"
  return 2
}

set_test_pattern() {
  TEST_PATTERN="$1"
  return 2
}

set_output_format() {
  TEST_OUTPUT_FORMAT="$1"
  return 2
}

set_output_file() {
  TEST_OUTPUT_FILE="$1"
  return 2
}

enable_self_test() {
  SELF_TEST_MODE=true
  return 1
}

set_parallel_jobs() {
  TEST_PARALLEL="$1"
  return 2
}

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
    ensure_output_directory || return 1
  fi

  # Run specified tests if not in self-test mode
  if [[ "$SELF_TEST_MODE" == "false" ]]; then
    run_test_files
    return $?
  fi

  return 0
}

# Ensure output directory exists
# Returns: 0 on success, 1 on failure
ensure_output_directory() {
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

  return 0
}

#######################################
# REPORT GENERATION - DELEGATING TO REPORTING MODULE
#######################################

# Generate a test report - delegates to reporting module
# Returns:
#   0 on success, 1 on failure
generate_report() {
  # If the reporting module functions are available, use them
  if function_exists generate_test_report; then
    generate_test_report "$TEST_OUTPUT_FORMAT" "$TEST_OUTPUT_FILE"
    return $?
  fi

  # If test_helpers has this function, use it
  if function_exists generate_report && ! function_equals generate_report; then
    generate_report "$TEST_OUTPUT_FORMAT" "$TEST_OUTPUT_FILE"
    return $?
  }

  # Fall back to simple summary output
  local output=""

  output="======================================\n"
  output+="TEST RESULTS SUMMARY\n"
  output+="======================================\n"
  output+="Total Tests: $TESTS_TOTAL\n"
  output+="Passed: $TESTS_PASSED\n"
  output+="Failed: $TESTS_FAILED\n"
  output+="Skipped: $TESTS_SKIPPED\n"
  output+="Duration: ${TEST_TOTAL_TIME}s\n"
  output+="======================================\n\n"

  # Output detailed results if available
  if [[ ${#TEST_RESULTS[@]} -gt 0 ]]; then
    output+="DETAILED RESULTS\n"
    output+="======================================\n"

    for result in "${TEST_RESULTS[@]}"; do
      local name status duration message
      IFS='|' read -r name status duration message <<< "$result"

      local status_marker
      case "$status" in
        PASS) status_marker="✓" ;;
        FAIL) status_marker="✗" ;;
        SKIP) status_marker="⦸" ;;
        *) status_marker="?" ;;
      esac

      output+="$status_marker $name ($duration"s")\n"
      if [[ -n "$message" ]]; then
        output+="  $message\n"
      fi
    done
  fi

  # Output the report
  if [[ -n "$TEST_OUTPUT_FILE" ]]; then
    if function_exists write_file; then
      write_file "$output" "$TEST_OUTPUT_FILE" || {
        log_error "Failed to write report to $TEST_OUTPUT_FILE"
        return 1
      }
    else
      echo -e "$output" > "$TEST_OUTPUT_FILE" || {
        log_error "Failed to write report to $TEST_OUTPUT_FILE"
        return 1
      }
    }

    log_info "Basic test report written to $TEST_OUTPUT_FILE"
  else
    echo -e "$output"
  fi

  return 0
}

#######################################
# SELF-TEST
#######################################

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

  # Generate a small test report
  local temp_report
  if function_exists create_temp_file; then
    temp_report=$(create_temp_file "test_report")
  else
    temp_report=$(mktemp)
  fi

  local saved_output="$TEST_OUTPUT_FILE"
  TEST_OUTPUT_FILE="$temp_report"

  run_test "Report generation" "generate_report"

  # Verify the report exists and has content
  run_test "Report file created" "test -f \"$temp_report\" && test -s \"$temp_report\""

  # Restore and clean up
  TEST_OUTPUT_FILE="$saved_output"
  if function_exists delete_file; then
    delete_file "$temp_report"
  else
    rm -f "$temp_report"
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
export -f get_test_files
export -f run_test_files
export -f run_parallel_tests
export -f run_sequential_tests
export -f function_exists
export -f function_equals
export -f execute_assertion
export -f assert_equals
export -f assert_not_equals
export -f assert_contains
export -f assert_not_contains
export -f assert_success
export -f assert_fails
export -f assert_file_exists
export -f assert_file_not_exists
export -f assert_dir_exists
export -f assert_dir_not_exists
export -f assert_file_contains
export -f assert_file_not_contains
export -f assert_file_matches
export -f assert_var_defined
export -f assert_var_not_empty
export -f assert_path_permissions
export -f run_tests
export -f self_test
export -f parse_args
export -f show_usage
export -f ensure_output_directory
export -f generate_report
export -f run_with_timeout
export -f find_available_port
export -f port_is_available
export -f escape_string

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
