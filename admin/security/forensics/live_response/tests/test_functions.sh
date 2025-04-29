#!/bin/bash
# filepath: admin/security/forensics/live_response/test_functions.sh
# Test helper functions for Live Response Forensic Tools
#
# This script provides test utilities specifically for forensic tools testing,
# with assertions designed for validating forensic evidence collection and
# chain of custody requirements.

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
TEST_SKIP_COUNT=0
CURRENT_TEST_NAME=""
TEST_START_TIME=""
TEST_RESULTS=()
TEST_VERBOSITY=${TEST_VERBOSITY:-"info"} # debug, info, warn, error

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
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name"
        log_error "  Expected: '$expected'"
        log_error "  Actual:   '$actual'"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|Expected: '$expected', Actual: '$actual'")
        return 1
    fi
}

# Assert that two strings are not equal
# Arguments:
#   $1: Actual value
#   $2: Not expected value
#   $3: Test description (optional)
assert_not_equals() {
    local actual="$1"
    local not_expected="$2"
    local description="${3:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ "$actual" != "$not_expected" ]]; then
        log_success "PASS: $test_name"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name"
        log_error "  Expected to be different from: '$not_expected'"
        log_error "  Actual: '$actual'"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|Expected to be different from: '$not_expected', Actual: '$actual'")
        return 1
    fi
}

# Assert that a string contains a substring
# Arguments:
#   $1: String to search in
#   $2: Substring to search for
#   $3: Test description (optional)
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local description="${3:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ "$haystack" == *"$needle"* ]]; then
        log_success "PASS: $test_name"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name"
        log_error "  String does not contain: '$needle'"
        log_error "  In: '$haystack'"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|String does not contain: '$needle'")
        return 1
    fi
}

# Assert that a string does not contain a substring
# Arguments:
#   $1: String to search in
#   $2: Substring that should not be present
#   $3: Test description (optional)
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local description="${3:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ ! "$haystack" == *"$needle"* ]]; then
        log_success "PASS: $test_name"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name"
        log_error "  String should not contain: '$needle'"
        log_error "  In: '$haystack'"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|String should not contain: '$needle'")
        return 1
    fi
}

# Assert that a command executes successfully (exit code 0)
# Arguments:
#   $1: Command to execute (as a string)
#   $2: Test description (optional)
#   $3: Timeout in seconds (optional, default: 30)
assert_success() {
    local cmd="$1"
    local description="${2:-}"
    local timeout="${3:-30}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local output
    local exit_code=0
    local start_time end_time duration

    ((TEST_COUNT++))
    log_debug "Running command (timeout: ${timeout}s): $cmd"

    # Use start_time if available or fallback to basic timing
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    if command -v timeout &>/dev/null; then
        # Use GNU timeout if available
        output=$(timeout "$timeout" bash -c "$cmd" 2>&1) || exit_code=$?
        # Handle timeout specifically (exit code 124)
        if [[ $exit_code -eq 124 ]]; then
            log_error "FAIL: $test_name (Command timed out after ${timeout}s)"
            log_error "  Command: $cmd"
            ((TEST_FAIL_COUNT++))
            TEST_RESULTS+=("$test_name|FAIL|${timeout}|Command timed out after ${timeout}s")
            return 1
        fi
    else
        # Fallback without timeout
        output=$(eval "$cmd" 2>&1) || exit_code=$?
    fi

    # Calculate duration
    end_time=$(date +%s.%N 2>/dev/null || date +%s)
    if command -v bc &>/dev/null; then
        duration=$(echo "$end_time - $start_time" | bc)
    else
        duration=$((end_time - start_time))
    fi

    if [[ $exit_code -eq 0 ]]; then
        log_success "PASS: $test_name (${duration}s)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|${duration}|")
        return 0
    else
        log_error "FAIL: $test_name (Exit code: $exit_code, ${duration}s)"
        log_error "  Command: $cmd"
        log_error "  Output: $output"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|${duration}|Exit code: $exit_code, Output: ${output:0:200}${#output>200?...:}")
        return 1
    fi
}

# Assert that a command fails (non-zero exit code)
# Arguments:
#   $1: Command to execute (as a string)
#   $2: Test description (optional)
#   $3: Timeout in seconds (optional, default: 30)
assert_fail() {
    local cmd="$1"
    local description="${2:-}"
    local timeout="${3:-30}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local output
    local exit_code=0
    local start_time end_time duration

    ((TEST_COUNT++))
    log_debug "Running command (expecting failure, timeout: ${timeout}s): $cmd"

    # Use start_time if available or fallback to basic timing
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    if command -v timeout &>/dev/null; then
        # Use GNU timeout if available
        output=$(timeout "$timeout" bash -c "$cmd" 2>&1) || exit_code=$?
        # Handle timeout specifically (exit code 124) - this is a success for assert_fail
        if [[ $exit_code -eq 124 ]]; then
            log_success "PASS: $test_name (Command timed out after ${timeout}s, as expected)"
            ((TEST_PASS_COUNT++))
            TEST_RESULTS+=("$test_name|PASS|${timeout}|Command timed out after ${timeout}s")
            return 0
        fi
    else
        # Fallback without timeout
        output=$(eval "$cmd" 2>&1) || exit_code=$?
    fi

    # Calculate duration
    end_time=$(date +%s.%N 2>/dev/null || date +%s)
    if command -v bc &>/dev/null; then
        duration=$(echo "$end_time - $start_time" | bc)
    else
        duration=$((end_time - start_time))
    fi

    if [[ $exit_code -ne 0 ]]; then
        log_success "PASS: $test_name (Exit code: $exit_code, ${duration}s)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|${duration}|")
        return 0
    else
        log_error "FAIL: $test_name (Expected non-zero exit code, got 0, ${duration}s)"
        log_error "  Command: $cmd"
        log_error "  Output: $output"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|${duration}|Expected non-zero exit code, got 0")
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
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name (File does not exist: $file_path)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|File does not exist: $file_path")
        return 1
    fi
}

# Assert that a file does not exist
# Arguments:
#   $1: File path
#   $2: Test description (optional)
assert_file_not_exists() {
    local file_path="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ ! -f "$file_path" ]]; then
        log_success "PASS: $test_name (File does not exist: $file_path)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name (File exists: $file_path)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|File exists: $file_path")
        return 1
    fi
}

# Assert that a directory exists
# Arguments:
#   $1: Directory path
#   $2: Test description (optional)
assert_dir_exists() {
    local dir_path="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ -d "$dir_path" ]]; then
        log_success "PASS: $test_name (Directory exists: $dir_path)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name (Directory does not exist: $dir_path)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|Directory does not exist: $dir_path")
        return 1
    fi
}

# Assert that a file contains a specific string or pattern
# Arguments:
#   $1: File path
#   $2: String or pattern to search for
#   $3: Test description (optional)
#   $4: Use regex matching (optional, default: false)
assert_file_contains() {
    local file_path="$1"
    local pattern="$2"
    local description="${3:-}"
    local use_regex="${4:-false}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local grep_cmd="grep"
    local grep_args=()

    # Check if file exists first
    if [[ ! -f "$file_path" ]]; then
        ((TEST_COUNT++))
        log_error "FAIL: $test_name (File does not exist: $file_path)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|File does not exist: $file_path")
        return 1
    fi

    # Set up grep arguments
    if [[ "$use_regex" == "true" ]]; then
        grep_args=(-E)
    else
        grep_args=(-F)
    fi

    ((TEST_COUNT++))
    if $grep_cmd "${grep_args[@]}" -- "$pattern" "$file_path" >/dev/null 2>&1; then
        log_success "PASS: $test_name (File contains pattern: $pattern)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name (File does not contain pattern: $pattern)"
        log_error "  File content (first 5 lines):"
        head -n 5 "$file_path" | while IFS= read -r line; do
            log_error "    $line"
        done
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|File does not contain pattern: $pattern")
        return 1
    fi
}

# Assert that a variable is defined
# Arguments:
#   $1: Variable name (without $)
#   $2: Test description (optional)
assert_var_defined() {
    local var_name="$1"
    local description="${2:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"

    ((TEST_COUNT++))
    if [[ -n "${!var_name+x}" ]]; then
        log_success "PASS: $test_name (Variable $var_name is defined)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name (Variable $var_name is not defined)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|Variable $var_name is not defined")
        return 1
    fi
}

# Skip a test with a message
# Arguments:
#   $1: Test name or description
#   $2: Skip reason (optional)
skip_test() {
    local test_name="${CURRENT_TEST_NAME:-$1}"
    local reason="${2:-No reason provided}"

    log_warn "SKIP: $test_name ($reason)"
    ((TEST_COUNT++))
    ((TEST_SKIP_COUNT++))
    TEST_RESULTS+=("$test_name|SKIP|0|$reason")
    return 0
}

# --- File Verification Functions ---

# Verify file hash matches expected value
# Arguments:
#   $1: File path
#   $2: Expected hash (SHA256 by default)
#   $3: Hash algorithm (optional, default: sha256)
#   $4: Test description (optional)
assert_file_hash() {
    local file_path="$1"
    local expected_hash="$2"
    local algorithm="${3:-sha256}"
    local description="${4:-}"
    local test_name="${CURRENT_TEST_NAME}${description:+: $description}"
    local actual_hash=""

    # Check file exists
    if [[ ! -f "$file_path" ]]; then
        ((TEST_COUNT++))
        log_error "FAIL: $test_name (File does not exist: $file_path)"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|File does not exist: $file_path")
        return 1
    fi

    # Calculate hash based on algorithm
    case "$algorithm" in
        md5)
            if command -v md5sum &>/dev/null; then
                actual_hash=$(md5sum "$file_path" | cut -d ' ' -f1)
            elif command -v md5 &>/dev/null; then
                # macOS
                actual_hash=$(md5 -q "$file_path")
            else
                log_error "FAIL: $test_name (md5sum/md5 not available)"
                ((TEST_COUNT++))
                ((TEST_FAIL_COUNT++))
                TEST_RESULTS+=("$test_name|FAIL|0|md5sum/md5 command not available")
                return 1
            fi
            ;;
        sha1)
            if command -v sha1sum &>/dev/null; then
                actual_hash=$(sha1sum "$file_path" | cut -d ' ' -f1)
            elif command -v shasum &>/dev/null; then
                # macOS fallback
                actual_hash=$(shasum -a 1 "$file_path" | cut -d ' ' -f1)
            else
                log_error "FAIL: $test_name (sha1sum/shasum not available)"
                ((TEST_COUNT++))
                ((TEST_FAIL_COUNT++))
                TEST_RESULTS+=("$test_name|FAIL|0|sha1sum/shasum command not available")
                return 1
            fi
            ;;
        sha256|*)
            if command -v sha256sum &>/dev/null; then
                actual_hash=$(sha256sum "$file_path" | cut -d ' ' -f1)
            elif command -v shasum &>/dev/null; then
                # macOS fallback
                actual_hash=$(shasum -a 256 "$file_path" | cut -d ' ' -f1)
            else
                log_error "FAIL: $test_name (sha256sum/shasum not available)"
                ((TEST_COUNT++))
                ((TEST_FAIL_COUNT++))
                TEST_RESULTS+=("$test_name|FAIL|0|sha256sum/shasum command not available")
                return 1
            fi
            ;;
    esac

    ((TEST_COUNT++))
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        log_success "PASS: $test_name ($algorithm hash matches: $expected_hash)"
        ((TEST_PASS_COUNT++))
        TEST_RESULTS+=("$test_name|PASS|0|")
        return 0
    else
        log_error "FAIL: $test_name ($algorithm hash mismatch)"
        log_error "  Expected: $expected_hash"
        log_error "  Actual:   $actual_hash"
        ((TEST_FAIL_COUNT++))
        TEST_RESULTS+=("$test_name|FAIL|0|$algorithm hash mismatch. Expected: $expected_hash, Actual: $actual_hash")
        return 1
    fi
}

# --- Test Runner Functions ---

# Function to run a single test function
# Arguments:
#   $1: Name of the test function to run
run_test_function() {
    local test_func="$1"
    local start_time end_time duration
    CURRENT_TEST_NAME="$test_func"

    log_info "--- Running test: $test_func ---"

    # Start timing
    start_time=$(date +%s.%N 2>/dev/null || date +%s)
    TEST_START_TIME="$start_time"

    if declare -f "$test_func" > /dev/null; then
        # Execute the test function in a subshell to isolate environment changes
        ( "$test_func" )
        local result=$?
        if [[ $result -ne 0 ]]; then
            log_warn "Test function $test_func exited with status $result"
            # Individual assertions track failures, but this catches early exits
        fi
    else
        log_error "FAIL: Test function '$test_func' not found."
        ((TEST_FAIL_COUNT++))
        ((TEST_COUNT++)) # Count this as a failed test execution attempt
        TEST_RESULTS+=("$test_func|FAIL|0|Test function not found")
    fi

    # End timing
    end_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Calculate duration
    if command -v bc &>/dev/null; then
        duration=$(echo "$end_time - $start_time" | bc)
    else
        duration=$((end_time - start_time))
    fi

    log_debug "Test completed in ${duration}s"

    CURRENT_TEST_NAME=""
    echo # Add a newline for readability
}

# Function to run all functions in the current script starting with "test_"
# Arguments:
#   $1: Specific test or pattern to run (optional)
run_all_tests() {
    local test_pattern="${1:-test_*}"
    local start_time end_time duration

    log_info "============================="
    log_info "Starting Live Response Tests"
    log_info "============================="
    TEST_COUNT=0
    TEST_PASS_COUNT=0
    TEST_FAIL_COUNT=0
    TEST_SKIP_COUNT=0
    TEST_RESULTS=()

    # Start timing
    start_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Find all functions starting with test_
    local test_functions

    if [[ "$test_pattern" == "test_*" ]]; then
        # Run all test functions
        test_functions=$(declare -F | awk '/^declare -f test_/ {print $3}' | sort)
    else
        # Run specific test(s) matching pattern
        test_functions=$(declare -F | awk '/^declare -f test_/ {print $3}' | grep -E "$test_pattern" | sort)
        if [[ -z "$test_functions" ]]; then
            log_error "No test functions match pattern: $test_pattern"
            return 1
        fi
    fi

    for func in $test_functions; do
        run_test_function "$func"
    done

    # End timing
    end_time=$(date +%s.%N 2>/dev/null || date +%s)

    # Calculate duration
    if command -v bc &>/dev/null; then
        duration=$(echo "$end_time - $start_time" | bc)
    else
        duration=$((end_time - start_time))
    fi

    log_info "============================="
    log_info "Test Summary"
    log_info "============================="
    log_info "Total tests run: $TEST_COUNT"
    log_success "Passed: $TEST_PASS_COUNT"
    if [[ $TEST_SKIP_COUNT -gt 0 ]]; then
        log_warn "Skipped: $TEST_SKIP_COUNT"
    fi
    if [[ $TEST_FAIL_COUNT -gt 0 ]]; then
        log_error "Failed: $TEST_FAIL_COUNT"
        log_info "Total time: ${duration}s"
        return 1
    else
        log_info "Failed: 0"
        log_info "Total time: ${duration}s"
        return 0
    fi
}

# Generate report in specified format
# Arguments:
#   $1: Format (text, json, junit)
#   $2: Output file (optional)
generate_test_report() {
    local format="${1:-text}"
    local output_file="$2"
    local output=""

    case "$format" in
        json)
            output="{\n"
            output+="  \"summary\": {\n"
            output+="    \"total\": $TEST_COUNT,\n"
            output+="    \"passed\": $TEST_PASS_COUNT,\n"
            output+="    \"failed\": $TEST_FAIL_COUNT,\n"
            output+="    \"skipped\": $TEST_SKIP_COUNT\n"
            output+="  },\n"
            output+="  \"tests\": ["

            local first=true
            for result in "${TEST_RESULTS[@]}"; do
                IFS='|' read -r name status duration message <<< "$result"

                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    output+=","
                fi

                output+="\n    {\n"
                output+="      \"name\": \"$name\",\n"
                output+="      \"status\": \"$status\",\n"
                output+="      \"duration\": $duration"

                if [[ -n "$message" ]]; then
                    output+=",\n      \"message\": \"$message\"\n"
                else
                    output+="\n"
                fi

                output+="    }"
            done

            output+="\n  ]\n}\n"
            ;;

        junit|xml)
            output="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            output+="<testsuites>\n"
            output+="  <testsuite name=\"LiveResponseTests\" tests=\"$TEST_COUNT\" failures=\"$TEST_FAIL_COUNT\" errors=\"0\" skipped=\"$TEST_SKIP_COUNT\">\n"

            for result in "${TEST_RESULTS[@]}"; do
                IFS='|' read -r name status duration message <<< "$result"

                output+="    <testcase name=\"$name\" time=\"$duration\">"

                case "$status" in
                    FAIL)
                        output+="\n      <failure message=\"$message\"></failure>\n    "
                        ;;
                    SKIP)
                        output+="\n      <skipped message=\"$message\"></skipped>\n    "
                        ;;
                esac

                output+="</testcase>\n"
            done

            output+="  </testsuite>\n"
            output+="</testsuites>\n"
            ;;

        *)  # Default to text
            output="====================================\n"
            output+="LIVE RESPONSE TEST RESULTS SUMMARY\n"
            output+="====================================\n"
            output+="Total Tests:  $TEST_COUNT\n"
            output+="Passed:       $TEST_PASS_COUNT\n"
            output+="Failed:       $TEST_FAIL_COUNT\n"
            output+="Skipped:      $TEST_SKIP_COUNT\n"
            output+="====================================\n\n"

            for result in "${TEST_RESULTS[@]}"; do
                IFS='|' read -r name status duration message <<< "$result"

                case "$status" in
                    PASS)
                        output+="[PASS] $name ($duration s)\n"
                        ;;
                    FAIL)
                        output+="[FAIL] $name ($duration s)\n"
                        if [[ -n "$message" ]]; then
                            output+="       $message\n"
                        fi
                        ;;
                    SKIP)
                        output+="[SKIP] $name\n"
                        if [[ -n "$message" ]]; then
                            output+="       Reason: $message\n"
                        fi
                        ;;
                esac
            done
            ;;
    esac

    # Output to file or stdout
    if [[ -n "$output_file" ]]; then
        echo -e "$output" > "$output_file"
        log_info "Test report written to: $output_file"
    else
        echo -e "$output"
    fi
}

# Parse command line arguments
# Arguments:
#   All command line arguments ($@)
parse_args() {
    local test_pattern="test_*"
    local report_format="text"
    local report_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                TEST_VERBOSITY="debug"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -p|--pattern)
                test_pattern="$2"
                shift 2
                ;;
            -f|--format)
                report_format="$2"
                shift 2
                ;;
            -o|--output)
                report_file="$2"
                shift 2
                ;;
            *)
                if [[ "$1" == test_* ]]; then
                    test_pattern="$1"
                else
                    echo "Error: Unknown option: $1"
                    show_usage
                    return 1
                fi
                shift
                ;;
        esac
    done

    run_all_tests "$test_pattern"
    local run_status=$?

    if [[ -n "$report_format" ]]; then
        generate_test_report "$report_format" "$report_file"
    fi

    return $run_status
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [test_pattern]

Run tests for forensic tools.

OPTIONS:
  -h, --help             Show this help message
  -v, --verbose          Show detailed output
  -p, --pattern PATTERN  Run only tests matching pattern
  -f, --format FORMAT    Report format: text, json, junit
  -o, --output FILE      Output file for test results

Examples:
  $(basename "$0")                    # Run all tests
  $(basename "$0") --verbose          # Run all tests with verbose output
  $(basename "$0") test_memory         # Run only tests matching 'test_memory'
  $(basename "$0") -f junit -o results.xml  # Run tests and output results in JUnit format
EOF
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
# To run tests if this script is executed directly:
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Initialize common functions if needed (e.g., for logging setup)
    if declare -f init_common_functions > /dev/null; then
        init_common_functions
    fi
    parse_args "$@"
    exit $?
fi

log_debug "test_functions.sh sourced."
