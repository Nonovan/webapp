#!/bin/bash
# filepath: scripts/utils/modules/assertions.sh
#
# Assertion utilities for Cloud Infrastructure Platform testing framework
#
# This module provides assertion functions for testing expected outcomes
# in both unit and integration tests.
#
# Part of: Cloud Infrastructure Platform - Testing Framework
#
# Usage: source "$(dirname "$0")/assertions.sh"
#
# Version: 1.0.0
# Date: 2023-12-20

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
readonly ASSERTIONS_MODULE_VERSION="1.0.0"
readonly ASSERTIONS_MODULE_DATE="2023-12-20"

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Load core module if not already loaded
CORE_MODULE="${MODULES_DIR}/core.sh"
if [[ ! $(type -t log) == "function" ]] && [[ -f "$CORE_MODULE" ]]; then
  # shellcheck source=./core.sh
  source "$CORE_MODULE"
fi

# Basic logging function if core module isn't available
if [[ ! $(type -t log) == "function" ]]; then
  log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
  }
fi

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
  local actual="${1:-}"
  local expected="${2:-}"
  local message="${3:-Values should be equal}"

  if [[ "$actual" == "$expected" ]]; then
    if [[ $(type -t log) == "function" && $(type -t log_debug) != "function" ]]; then
      log "DEBUG" "Assertion passed: $actual equals $expected"
    elif [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: $actual equals $expected"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Expected: '$expected'" >&2
    echo "Actual  : '$actual'" >&2
    return 1
  fi
}

# Assert that two values are not equal
# Arguments:
#   $1 - Actual value
#   $2 - Unexpected value
#   $3 - Optional message
# Returns:
#   0 if values are not equal, 1 if they are
assert_not_equals() {
  local actual="${1:-}"
  local unexpected="${2:-}"
  local message="${3:-Values should not be equal}"

  if [[ "$actual" != "$unexpected" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: $actual is not equal to $unexpected"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Value: '$actual'" >&2
    echo "Should not equal: '$unexpected'" >&2
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
  local string="${1:-}"
  local substring="${2:-}"
  local message="${3:-String should contain substring}"

  if [[ -z "$string" && -z "$substring" ]]; then
    echo "Assertion failed: Empty string and substring provided" >&2
    return 1
  fi

  if [[ "$string" == *"$substring"* ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: String contains substring '$substring'"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "String  : '$string'" >&2
    echo "Expected to contain: '$substring'" >&2
    return 1
  fi
}

# Assert that a value does not contain a substring
# Arguments:
#   $1 - String to search in
#   $2 - Substring that should not be present
#   $3 - Optional message
# Returns:
#   0 if string does not contain substring, 1 otherwise
assert_not_contains() {
  local string="${1:-}"
  local substring="${2:-}"
  local message="${3:-String should not contain substring}"

  if [[ -z "$substring" ]]; then
    echo "Assertion failed: Empty substring provided" >&2
    return 1
  fi

  if [[ "$string" != *"$substring"* ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: String does not contain substring '$substring'"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "String  : '$string'" >&2
    echo "Should not contain: '$substring'" >&2
    return 1
  fi
}

# Assert that a value matches a regex pattern
# Arguments:
#   $1 - Value to check
#   $2 - Regex pattern to match against
#   $3 - Optional message
# Returns:
#   0 if value matches the pattern, 1 otherwise
assert_matches() {
  local value="${1:-}"
  local pattern="${2:-}"
  local message="${3:-Value should match the pattern}"

  if [[ -z "$pattern" ]]; then
    echo "Assertion failed: Empty pattern provided" >&2
    return 1
  fi

  if [[ "$value" =~ $pattern ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Value matches pattern '$pattern'"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Value  : '$value'" >&2
    echo "Pattern: '$pattern'" >&2
    return 1
  fi
}

# Assert that a command succeeds with timeout
# Arguments:
#   $1 - Timeout in seconds (optional, default 10)
#   $2... - Command and its arguments
# Returns:
#   0 if command succeeds, 1 otherwise
assert_success() {
  local timeout=10

  # Check if first parameter is a number for timeout
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    timeout="$1"
    shift
  fi

  # Ensure there's a command to run
  if [[ $# -eq 0 ]]; then
    echo "Assertion failed: No command provided to assert_success" >&2
    return 1
  fi

  local exit_code=0
  local output

  # Use timeout command if available
  if command -v timeout >/dev/null 2>&1; then
    output=$(timeout "$timeout" "$@" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
      echo "Command timed out after $timeout seconds" >&2
      echo "Command: $*" >&2
      return 1
    fi
  else
    # Fallback if timeout command is not available
    output=$("$@" 2>&1) || exit_code=$?
  fi

  if [[ $exit_code -eq 0 ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Command succeeded"
    fi
    return 0
  else
    echo "Command was expected to succeed but failed with exit code $exit_code" >&2
    echo "Command: $*" >&2
    echo "Output: $output" >&2
    return 1
  fi
}

# Assert that a command fails with timeout
# Arguments:
#   $1 - Timeout in seconds (optional, default 10)
#   $2 - Expected exit code (optional, any non-zero if not specified)
#   $3... - Command and its arguments
# Returns:
#   0 if command fails, 1 otherwise
assert_fails() {
  local timeout=10
  local expected_code=""

  # Check if first parameter is a number for timeout
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    timeout="$1"
    shift
  fi

  # Check if first parameter is expected exit code
  if [[ "$1" =~ ^[0-9]+$ && $1 -ne 0 ]]; then
    expected_code="$1"
    shift
  fi

  # Ensure there's a command to run
  if [[ $# -eq 0 ]]; then
    echo "Assertion failed: No command provided to assert_fails" >&2
    return 1
  fi

  local exit_code=0
  local output

  # Use timeout command if available
  if command -v timeout >/dev/null 2>&1; then
    output=$(timeout "$timeout" "$@" 2>&1) || exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
      # Timeout is considered a failure, which is what we expect
      if [[ -n "$expected_code" && "$expected_code" -ne 124 ]]; then
        echo "Command timed out with code 124, but expected code $expected_code" >&2
        echo "Command: $*" >&2
        return 1
      fi
      if [[ $(type -t log_debug) == "function" ]]; then
        log_debug "Assertion passed: Command timed out as expected"
      fi
      return 0
    fi
  else
    # Fallback if timeout command is not available
    output=$("$@" 2>&1) || exit_code=$?
  fi

  if [[ $exit_code -eq 0 ]]; then
    echo "Command was expected to fail but succeeded" >&2
    echo "Command: $*" >&2
    echo "Output: $output" >&2
    return 1
  elif [[ -n "$expected_code" && $exit_code -ne $expected_code ]]; then
    echo "Command failed with exit code $exit_code, but expected code $expected_code" >&2
    echo "Command: $*" >&2
    echo "Output: $output" >&2
    return 1
  else
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Command failed as expected with exit code $exit_code"
    fi
    return 0
  fi
}

# Assert that a file exists
# Arguments:
#   $1 - File path
#   $2 - Optional message
# Returns:
#   0 if file exists, 1 otherwise
assert_file_exists() {
  local file="${1:-}"
  local message="${2:-File should exist}"

  if [[ -z "$file" ]]; then
    echo "Assertion failed: No file path provided" >&2
    return 1
  fi

  if [[ -f "$file" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: File exists: $file"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File does not exist: $file" >&2
    return 1
  fi
}

# Assert that a file does not exist
# Arguments:
#   $1 - File path
#   $2 - Optional message
# Returns:
#   0 if file does not exist, 1 if it does
assert_file_not_exists() {
  local file="${1:-}"
  local message="${2:-File should not exist}"

  if [[ -z "$file" ]]; then
    echo "Assertion failed: No file path provided" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: File does not exist: $file"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File exists: $file" >&2
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
  local dir="${1:-}"
  local message="${2:-Directory should exist}"

  if [[ -z "$dir" ]]; then
    echo "Assertion failed: No directory path provided" >&2
    return 1
  fi

  if [[ -d "$dir" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Directory exists: $dir"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Directory does not exist: $dir" >&2
    return 1
  fi
}

# Assert that a directory does not exist
# Arguments:
#   $1 - Directory path
#   $2 - Optional message
# Returns:
#   0 if directory does not exist, 1 if it does
assert_dir_not_exists() {
  local dir="${1:-}"
  local message="${2:-Directory should not exist}"

  if [[ -z "$dir" ]]; then
    echo "Assertion failed: No directory path provided" >&2
    return 1
  fi

  if [[ ! -d "$dir" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Directory does not exist: $dir"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Directory exists: $dir" >&2
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
  local file="${1:-}"
  local search_string="${2:-}"
  local message="${3:-File should contain the specified string}"

  if [[ -z "$file" ]]; then
    echo "Assertion failed: No file path provided" >&2
    return 1
  fi

  if [[ -z "$search_string" ]]; then
    echo "Assertion failed: No search string provided" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "Assertion failed: File does not exist" >&2
    echo "File path: $file" >&2
    return 1
  fi

  if grep -q -- "$search_string" "$file"; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: File contains search string: $file"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File: $file" >&2
    echo "Does not contain: '$search_string'" >&2
    return 1
  fi
}

# Assert that a file does not contain a specific string
# Arguments:
#   $1 - File path
#   $2 - String that should not be present
#   $3 - Optional message
# Returns:
#   0 if file does not contain string, 1 if it does
assert_file_not_contains() {
  local file="${1:-}"
  local search_string="${2:-}"
  local message="${3:-File should not contain the specified string}"

  if [[ -z "$file" ]]; then
    echo "Assertion failed: No file path provided" >&2
    return 1
  fi

  if [[ -z "$search_string" ]]; then
    echo "Assertion failed: No search string provided" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "Assertion failed: File does not exist" >&2
    echo "File path: $file" >&2
    return 1
  fi

  if ! grep -q -- "$search_string" "$file"; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: File does not contain search string: $file"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File: $file" >&2
    echo "Should not contain but does: '$search_string'" >&2
    return 1
  fi
}

# Assert that a file matches a regex pattern
# Arguments:
#   $1 - File path
#   $2 - Regex pattern
#   $3 - Optional message
# Returns:
#   0 if file content matches pattern, 1 otherwise
assert_file_matches() {
  local file="${1:-}"
  local pattern="${2:-}"
  local message="${3:-File should match the specified pattern}"

  if [[ -z "$file" ]]; then
    echo "Assertion failed: No file path provided" >&2
    return 1
  fi

  if [[ -z "$pattern" ]]; then
    echo "Assertion failed: No pattern provided" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "Assertion failed: File does not exist" >&2
    echo "File path: $file" >&2
    return 1
  fi

  if grep -q -E -- "$pattern" "$file"; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: File matches pattern: $file"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "File: $file" >&2
    echo "Does not match pattern: '$pattern'" >&2
    return 1
  fi
}

# Assert that a variable is defined
# Arguments:
#   $1 - Variable name (without $)
#   $2 - Optional message
# Returns:
#   0 if variable is defined, 1 otherwise
assert_var_defined() {
  local var_name="${1:-}"
  local message="${2:-Variable should be defined}"

  if [[ -z "$var_name" ]]; then
    echo "Assertion failed: No variable name provided" >&2
    return 1
  fi

  if [[ -n "${!var_name+x}" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Variable $var_name is defined"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Variable not defined: $var_name" >&2
    return 1
  fi
}

# Assert that a variable is not empty
# Arguments:
#   $1 - Variable name (without $)
#   $2 - Optional message
# Returns:
#   0 if variable is defined and not empty, 1 otherwise
assert_var_not_empty() {
  local var_name="${1:-}"
  local message="${2:-Variable should not be empty}"

  if [[ -z "$var_name" ]]; then
    echo "Assertion failed: No variable name provided" >&2
    return 1
  fi

  if [[ -n "${!var_name+x}" && -n "${!var_name}" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Variable $var_name is not empty"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    if [[ -n "${!var_name+x}" ]]; then
      echo "Variable is defined but empty: $var_name" >&2
    else
      echo "Variable is not defined: $var_name" >&2
    fi
    return 1
  fi
}

# Assert that a path has specific permissions
# Arguments:
#   $1 - Path to check
#   $2 - Expected permission mode (e.g. 644, 755)
#   $3 - Optional message
# Returns:
#   0 if permissions match, 1 otherwise
assert_path_permissions() {
  local path="${1:-}"
  local expected_perms="${2:-}"
  local message="${3:-Path should have specified permissions}"
  local actual_perms=""

  if [[ -z "$path" ]]; then
    echo "Assertion failed: No path provided" >&2
    return 1
  fi

  if [[ -z "$expected_perms" ]]; then
    echo "Assertion failed: No permissions specified" >&2
    return 1
  fi

  if [[ ! -e "$path" ]]; then
    echo "Assertion failed: Path does not exist: $path" >&2
    return 1
  fi

  # Get permissions, handling platform differences
  if [[ "$(uname)" == "Darwin" ]]; then
    # macOS requires different stat format
    actual_perms=$(stat -f "%Lp" "$path" 2>/dev/null)
  else
    # Linux/Unix standard format
    actual_perms=$(stat -c "%a" "$path" 2>/dev/null)
  fi

  if [[ "$actual_perms" == "$expected_perms" ]]; then
    if [[ $(type -t log_debug) == "function" ]]; then
      log_debug "Assertion passed: Path has expected permissions ($expected_perms): $path"
    fi
    return 0
  else
    echo "Assertion failed: $message" >&2
    echo "Path: $path" >&2
    echo "Expected permissions: $expected_perms" >&2
    echo "Actual permissions: $actual_perms" >&2
    return 1
  fi
}

# Self-test function
# Arguments:
#   None
# Returns:
#   0 if all tests pass, 1 if any fail
assertions_self_test() {
  local result=0
  local failures=0
  local total=0

  echo "Running assertions self-test..."

  # Create temporary test directory and files
  local test_dir
  test_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'assert_test')
  local test_file="$test_dir/test_file.txt"
  echo "Hello world" > "$test_file"
  touch "$test_dir/empty_file.txt"
  chmod 644 "$test_file"

  TEST_VAR="value"
  EMPTY_VAR=""

  # Test assert_equals
  ((total++))
  if assert_equals "hello" "hello"; then
    echo "✓ assert_equals with matching values"
  else
    echo "✗ assert_equals with matching values"
    ((failures++))
  fi

  ((total++))
  if ! assert_equals "hello" "world" &>/dev/null; then
    echo "✓ assert_equals with different values"
  else
    echo "✗ assert_equals with different values"
    ((failures++))
  fi

  # Test assert_not_equals
  ((total++))
  if assert_not_equals "hello" "world"; then
    echo "✓ assert_not_equals with different values"
  else
    echo "✗ assert_not_equals with different values"
    ((failures++))
  fi

  ((total++))
  if ! assert_not_equals "hello" "hello" &>/dev/null; then
    echo "✓ assert_not_equals with matching values"
  else
    echo "✗ assert_not_equals with matching values"
    ((failures++))
  fi

  # Test assert_contains
  ((total++))
  if assert_contains "hello world" "world"; then
    echo "✓ assert_contains with contained substring"
  else
    echo "✗ assert_contains with contained substring"
    ((failures++))
  fi

  ((total++))
  if ! assert_contains "hello world" "universe" &>/dev/null; then
    echo "✓ assert_contains with missing substring"
  else
    echo "✗ assert_contains with missing substring"
    ((failures++))
  fi

  # Test assert_not_contains
  ((total++))
  if assert_not_contains "hello world" "universe"; then
    echo "✓ assert_not_contains with absent substring"
  else
    echo "✗ assert_not_contains with absent substring"
    ((failures++))
  fi

  ((total++))
  if ! assert_not_contains "hello world" "world" &>/dev/null; then
    echo "✓ assert_not_contains with present substring"
  else
    echo "✗ assert_not_contains with present substring"
    ((failures++))
  fi

  # Test assert_matches
  ((total++))
  if assert_matches "hello123" "^hello[0-9]+$"; then
    echo "✓ assert_matches with matching pattern"
  else
    echo "✗ assert_matches with matching pattern"
    ((failures++))
  fi

  ((total++))
  if ! assert_matches "hello" "^[0-9]+$" &>/dev/null; then
    echo "✓ assert_matches with non-matching pattern"
  else
    echo "✗ assert_matches with non-matching pattern"
    ((failures++))
  fi

  # Test assert_success
  ((total++))
  if assert_success true; then
    echo "✓ assert_success with successful command"
  else
    echo "✗ assert_success with successful command"
    ((failures++))
  fi

  # Test assert_fails
  ((total++))
  if assert_fails false; then
    echo "✓ assert_fails with failing command"
  else
    echo "✗ assert_fails with failing command"
    ((failures++))
  fi

  # Test assert_file_exists
  ((total++))
  if assert_file_exists "$test_file"; then
    echo "✓ assert_file_exists with existing file"
  else
    echo "✗ assert_file_exists with existing file"
    ((failures++))
  fi

  ((total++))
  if ! assert_file_exists "$test_dir/nonexistent.txt" &>/dev/null; then
    echo "✓ assert_file_exists with non-existing file"
  else
    echo "✗ assert_file_exists with non-existing file"
    ((failures++))
  fi

  # Test assert_file_not_exists
  ((total++))
  if assert_file_not_exists "$test_dir/nonexistent.txt"; then
    echo "✓ assert_file_not_exists with non-existing file"
  else
    echo "✗ assert_file_not_exists with non-existing file"
    ((failures++))
  fi

  ((total++))
  if ! assert_file_not_exists "$test_file" &>/dev/null; then
    echo "✓ assert_file_not_exists with existing file"
  else
    echo "✗ assert_file_not_exists with existing file"
    ((failures++))
  fi

  # Test assert_dir_exists
  ((total++))
  if assert_dir_exists "$test_dir"; then
    echo "✓ assert_dir_exists with existing directory"
  else
    echo "✗ assert_dir_exists with existing directory"
    ((failures++))
  fi

  ((total++))
  if ! assert_dir_exists "$test_dir/nonexistent" &>/dev/null; then
    echo "✓ assert_dir_exists with non-existing directory"
  else
    echo "✗ assert_dir_exists with non-existing directory"
    ((failures++))
  fi

  # Test assert_file_contains
  ((total++))
  if assert_file_contains "$test_file" "Hello"; then
    echo "✓ assert_file_contains with matching content"
  else
    echo "✗ assert_file_contains with matching content"
    ((failures++))
  fi

  ((total++))
  if ! assert_file_contains "$test_file" "Goodbye" &>/dev/null; then
    echo "✓ assert_file_contains with non-matching content"
  else
    echo "✗ assert_file_contains with non-matching content"
    ((failures++))
  fi

  # Test assert_file_not_contains
  ((total++))
  if assert_file_not_contains "$test_file" "Goodbye"; then
    echo "✓ assert_file_not_contains with absent content"
  else
    echo "✗ assert_file_not_contains with absent content"
    ((failures++))
  fi

  ((total++))
  if ! assert_file_not_contains "$test_file" "Hello" &>/dev/null; then
    echo "✓ assert_file_not_contains with present content"
  else
    echo "✗ assert_file_not_contains with present content"
    ((failures++))
  fi

  # Test assert_var_defined
  ((total++))
  if assert_var_defined "TEST_VAR"; then
    echo "✓ assert_var_defined with defined variable"
  else
    echo "✗ assert_var_defined with defined variable"
    ((failures++))
  fi

  ((total++))
  if ! assert_var_defined "UNDEFINED_VAR" &>/dev/null; then
    echo "✓ assert_var_defined with undefined variable"
  else
    echo "✗ assert_var_defined with undefined variable"
    ((failures++))
  fi

  # Test assert_var_not_empty
  ((total++))
  if assert_var_not_empty "TEST_VAR"; then
    echo "✓ assert_var_not_empty with non-empty variable"
  else
    echo "✗ assert_var_not_empty with non-empty variable"
    ((failures++))
  fi

  ((total++))
  if ! assert_var_not_empty "EMPTY_VAR" &>/dev/null; then
    echo "✓ assert_var_not_empty with empty variable"
  else
    echo "✗ assert_var_not_empty with empty variable"
    ((failures++))
  fi

  # Test assert_path_permissions
  ((total++))
  local perms="644"
  # On macOS, the permissions might be different
  if [[ "$(uname)" == "Darwin" ]]; then
    perms=$(stat -f "%Lp" "$test_file")
  else
    perms=$(stat -c "%a" "$test_file")
  fi

  if assert_path_permissions "$test_file" "$perms"; then
    echo "✓ assert_path_permissions with correct permissions"
  else
    echo "✗ assert_path_permissions with correct permissions"
    ((failures++))
  fi

  ((total++))
  if ! assert_path_permissions "$test_file" "777" &>/dev/null; then
    echo "✓ assert_path_permissions with incorrect permissions"
  else
    echo "✗ assert_path_permissions with incorrect permissions"
    ((failures++))
  fi

  # Clean up test directory
  rm -rf "$test_dir"
  unset TEST_VAR EMPTY_VAR

  # Report results
  if [[ $failures -gt 0 ]]; then
    echo "Self-test completed with $failures/$total failures"
    return 1
  else
    echo "Self-test completed successfully: $total tests passed"
    return 0
  fi
}

# Export all public functions
export -f assert_equals
export -f assert_not_equals
export -f assert_contains
export -f assert_not_contains
export -f assert_matches
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
export -f assertions_self_test

# Export constants
export ASSERTIONS_MODULE_VERSION
export ASSERTIONS_MODULE_DATE

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  assertions_self_test
  exit $?
fi
