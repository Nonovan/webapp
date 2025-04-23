#!/bin/bash
# filepath: scripts/utils/modules/mocking.sh
#
# Mocking framework for Cloud Infrastructure Platform testing
#
# This module provides utilities for creating mock environments, files,
# and commands to facilitate testing of shell scripts with dependencies.
#
# Usage: source "$(dirname "$0")/mocking.sh"

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
MOCKING_MODULE_VERSION="1.0.0"
MOCKING_MODULE_DATE="2023-12-15"

# Script locations with more robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Load core module if not already loaded
CORE_MODULE="${MODULES_DIR}/core.sh"
if [[ ! $(type -t create_temp_dir) == "function" ]] && [[ -f "$CORE_MODULE" ]]; then
  # shellcheck source=./core.sh
  source "$CORE_MODULE"
fi

# Basic implementations if core module isn't available
if [[ ! $(type -t create_temp_dir) == "function" ]]; then
  create_temp_dir() {
    local temp_dir
    temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'mock_temp')
    echo "$temp_dir"
  }
fi

if [[ ! $(type -t safe_rm_dir) == "function" ]]; then
  safe_rm_dir() {
    local dir="$1"
    if [[ -d "$dir" && "$dir" == /tmp/* ]]; then
      rm -rf "$dir" 2>/dev/null
    fi
  }
fi

if [[ ! $(type -t log) == "function" ]]; then
  log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" >&2
  }
fi

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

# Create mock environment variables
# Arguments:
#   $1 - Name of environment variable
#   $2 - Value to set
# Returns:
#   0 on success, 1 on failure
mock_env_var() {
  local var_name="$1"
  local var_value="$2"

  # Store original value if it exists
  if [[ -n "${!var_name+x}" ]]; then
    eval "export ${var_name}_ORIGINAL=\"${!var_name}\""
  else
    eval "export ${var_name}_ORIGINAL=\"\""
  fi

  # Set mock value
  eval "export $var_name=\"$var_value\""
  return 0
}

# Restore mocked environment variables
# Arguments:
#   $1 - Name of environment variable to restore
# Returns:
#   0 on success, 1 on failure
restore_env_var() {
  local var_name="$1"
  local original_var="${var_name}_ORIGINAL"

  if [[ -n "${!original_var+x}" ]]; then
    if [[ -z "${!original_var}" ]]; then
      unset "$var_name"
    else
      eval "export $var_name=\"${!original_var}\""
    fi
    unset "$original_var"
  fi

  return 0
}

# Self-test function
# Arguments:
#   None
# Returns:
#   0 if all tests pass, 1 if any fail
mocking_self_test() {
  local result=0
  local failures=0
  local total=0

  echo "Running mocking self-test..."

  # Test mock environment
  ((total++))
  local mock_dir
  mock_dir=$(create_mock_environment "test_env")
  if [[ -d "$mock_dir" ]]; then
    echo "✓ create_mock_environment creates directory"
  else
    echo "✗ create_mock_environment creates directory"
    ((failures++))
  fi

  # Test mock file
  ((total++))
  local test_file="$mock_dir/test_file.txt"
  if create_mock_file "$test_file" "test content" && [[ -f "$test_file" ]]; then
    echo "✓ create_mock_file creates file"
  else
    echo "✗ create_mock_file creates file"
    ((failures++))
  fi

  # Test mock command
  ((total++))
  local mock_bin
  mock_bin=$(mock_command "test_cmd" "echo 'mocked command'")
  if [[ -x "$mock_bin/test_cmd" ]]; then
    echo "✓ mock_command creates executable command"
  else
    echo "✗ mock_command creates executable command"
    ((failures++))
  fi

  # Test mock command execution
  ((total++))
  local output
  output=$(test_cmd 2>/dev/null)
  if [[ "$output" == "mocked command" ]]; then
    echo "✓ mock command executes correctly"
  else
    echo "✗ mock command executes correctly"
    ((failures++))
  fi

  # Clean up
  remove_mock_command "$mock_bin"
  safe_rm_dir "$mock_dir"

  # Test environment variable mocking
  ((total++))
  mock_env_var "TEST_MOCK_VAR" "mocked_value"
  if [[ "$TEST_MOCK_VAR" == "mocked_value" ]]; then
    echo "✓ mock_env_var sets variable"
  else
    echo "✗ mock_env_var sets variable"
    ((failures++))
  fi

  ((total++))
  restore_env_var "TEST_MOCK_VAR"
  if [[ -z "${TEST_MOCK_VAR+x}" ]]; then
    echo "✓ restore_env_var restores variable"
  else
    echo "✗ restore_env_var restores variable"
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
export -f create_mock_environment
export -f create_mock_file
export -f mock_command
export -f remove_mock_command
export -f mock_env_var
export -f restore_env_var
export -f mocking_self_test

# Export constants
export MOCKING_MODULE_VERSION
export MOCKING_MODULE_DATE

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  mocking_self_test
  exit $?
fi
