#!/bin/bash
# filepath: scripts/utils/modules/assertions.sh
#
# Assertion utilities for Cloud Infrastructure Platform testing framework
#
# This module provides assertion functions for testing expected outcomes
# in both unit and integration tests.
#
# Usage: source "$(dirname "$0")/assertions.sh"

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
ASSERTIONS_MODULE_VERSION="1.0.0"
ASSERTIONS_MODULE_DATE="2023-12-15"

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
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" >&2
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

  ((total++))
  if assert_success true; then
    echo "✓ assert_success with successful command"
  else
    echo "✗ assert_success with successful command"
    ((failures++))
  fi

  ((total++))
  if assert_fails false; then
    echo "✓ assert_fails with failing command"
  else
    echo "✗ assert_fails with failing command"
    ((failures++))
  fi

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
export -f assert_contains
export -f assert_success
export -f assert_fails
export -f assert_file_exists
export -f assert_dir_exists
export -f assert_file_contains
export -f assertions_self_test

# Export constants
export ASSERTIONS_MODULE_VERSION
export ASSERTIONS_MODULE_DATE

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  assertions_self_test
  exit $?
fi
