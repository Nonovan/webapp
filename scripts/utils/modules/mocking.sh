#!/bin/bash
# filepath: scripts/utils/modules/mocking.sh
#
# Mocking framework for Cloud Infrastructure Platform testing
#
# This module provides utilities for creating mock environments, files,
# and commands to facilitate testing of shell scripts with dependencies.
#
# Part of: Cloud Infrastructure Platform - Testing Framework
#
# Usage: source "$(dirname "$0")/mocking.sh"
#
# Version: 1.0.0
# Date: 2023-12-20

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
readonly MOCKING_MODULE_VERSION="1.0.0"
readonly MOCKING_MODULE_DATE="2023-12-20"

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
    if [[ ! -d "$temp_dir" ]]; then
      echo "ERROR: Failed to create temporary directory" >&2
      return 1
    fi
    echo "$temp_dir"
  }
fi

if [[ ! $(type -t safe_rm_dir) == "function" ]]; then
  safe_rm_dir() {
    local dir="${1:-}"
    if [[ -z "$dir" ]]; then
      echo "ERROR: No directory specified for removal" >&2
      return 1
    fi
    if [[ -d "$dir" && "$dir" == /tmp/* ]]; then
      rm -rf "$dir" 2>/dev/null || {
        echo "WARNING: Failed to remove directory: $dir" >&2
        return 1
      }
    else
      echo "ERROR: Not removing directory outside of /tmp: $dir" >&2
      return 1
    fi
    return 0
  }
fi

if [[ ! $(type -t log) == "function" ]]; then
  log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
  }
fi

if [[ ! $(type -t debug) == "function" ]]; then
  debug() {
    local message="${1:-}"
    log "DEBUG" "$message"
  }
fi

if [[ ! $(type -t warn) == "function" ]]; then
  warn() {
    local message="${1:-}"
    log "WARN" "$message"
  }
fi

if [[ ! $(type -t error_exit) == "function" ]]; then
  error_exit() {
    local message="${1:-An error occurred}"
    log "ERROR" "$message"
    return 1
  }
fi

# Mock state tracking for easier cleanup
declare -A MOCK_COMMANDS_MAP
declare -A MOCK_ENV_VARS_MAP
declare -A MOCK_FILES_MAP
declare -a MOCK_DIRS_ARRAY

#######################################
# MOCKING FRAMEWORK
#######################################

# Create a mock directory for testing
# Arguments:
#   $1 - Name to identify the mock environment
#   $2 - Optional permissions (default: 755)
# Returns:
#   Path to the mock directory
create_mock_environment() {
  local name="${1:-mock_env}"
  local perms="${2:-755}"
  local mock_dir

  # Sanitize name to avoid command injection or path traversal
  name=$(echo "$name" | tr -cd 'a-zA-Z0-9_-')

  mock_dir=$(create_temp_dir "mock_${name}")
  if [[ $? -ne 0 || ! -d "$mock_dir" ]]; then
    error_exit "Failed to create mock environment directory"
    return 1
  fi

  # Set directory permissions
  chmod "$perms" "$mock_dir" 2>/dev/null || {
    warn "Failed to set permissions $perms on mock directory: $mock_dir"
  }

  # Track mock directory for potential cleanup
  MOCK_DIRS_ARRAY+=("$mock_dir")

  debug "Created mock environment at: $mock_dir"
  echo "$mock_dir"
}

# Create a mock file with specified content
# Arguments:
#   $1 - Path to the mock file
#   $2 - Content for the file
#   $3 - Permissions (optional, default 644 or 755 for scripts)
# Returns:
#   0 on success, 1 on failure
create_mock_file() {
  local file_path="${1:-}"
  local content="${2:-}"
  local perms=""

  # Validate inputs
  if [[ -z "$file_path" ]]; then
    error_exit "No file path provided to create_mock_file"
    return 1
  fi

  # Determine default permissions based on file extension
  if [[ "$file_path" == *.sh ]]; then
    perms="${3:-755}"
  else
    perms="${3:-644}"
  fi

  # Create parent directory if it doesn't exist
  mkdir -p "$(dirname "$file_path")" || {
    error_exit "Failed to create directory for mock file: $(dirname "$file_path")"
    return 1
  }

  # Create file with explicit error handling
  if ! printf "%s" "$content" > "$file_path" 2>/dev/null; then
    error_exit "Failed to write content to mock file: $file_path"
    return 1
  fi

  # Set permissions based on file type
  if ! chmod "$perms" "$file_path" 2>/dev/null; then
    warn "Failed to set permissions $perms on mock file: $file_path"
    # Continue despite permission warning
  fi

  # Track mock file for potential cleanup
  MOCK_FILES_MAP["$file_path"]=1

  debug "Created mock file at: $file_path with permissions $perms"
  return 0
}

# Create a mock function that replaces a real command
# Arguments:
#   $1 - Command to mock
#   $2 - Script content to execute instead
#   $3 - Optional timeout in seconds (default: none)
# Returns:
#   Path to the mock directory
mock_command() {
  local cmd="${1:-}"
  local script="${2:-echo 'This is a mock'}"
  local timeout="${3:-}"
  local mock_dir

  # Validate inputs
  if [[ -z "$cmd" ]]; then
    error_exit "No command name provided to mock_command"
    return 1
  fi

  # Sanitize command name to avoid injection
  cmd=$(echo "$cmd" | tr -cd 'a-zA-Z0-9_-')

  # Create mock directory
  mock_dir=$(create_temp_dir "mock_cmd")
  if [[ $? -ne 0 || ! -d "$mock_dir" ]]; then
    error_exit "Failed to create directory for mock command"
    return 1
  fi

  # Create mock script with proper shebang and error handling
  {
    echo "#!/bin/bash"
    echo "# Mock command created by mock_command for: $cmd"
    echo "set -o pipefail"

    # Add timeout wrapper if requested
    if [[ -n "$timeout" && "$timeout" =~ ^[0-9]+$ ]]; then
      echo "# Add timeout protection"
      if command -v timeout >/dev/null 2>&1; then
        echo "exec timeout $timeout /bin/bash -c '${script//\'/\'\\\'\'}'"
      else
        # Fallback if timeout command isn't available
        echo "# Warning: timeout command not available, proceeding without timeout protection"
        echo "$script"
      fi
    else
      echo "$script"
    fi
  } > "$mock_dir/$cmd"

  if ! chmod 755 "$mock_dir/$cmd" 2>/dev/null; then
    error_exit "Failed to make mock script executable: $mock_dir/$cmd"
    safe_rm_dir "$mock_dir"
    return 1
  fi

  # Add to PATH to ensure it's used, saving old PATH for restore
  MOCK_COMMANDS_MAP["$cmd"]="$mock_dir|$PATH"
  export PATH="$mock_dir:$PATH"

  debug "Created mock command '$cmd' in $mock_dir"
  echo "$mock_dir"
}

# Remove a mock command
# Arguments:
#   $1 - Command name or path returned by mock_command
# Returns:
#   0 on success, 1 on failure
remove_mock_command() {
  local input="${1:-}"
  local mock_dir=""
  local cmd=""
  local original_path=""

  if [[ -z "$input" ]]; then
    error_exit "No command or directory specified for removal"
    return 1
  fi

  # Determine if input is a directory path or command name
  if [[ -d "$input" ]]; then
    # Input is a directory path
    mock_dir="$input"
    # Try to find which command this directory belongs to
    for key in "${!MOCK_COMMANDS_MAP[@]}"; do
      if [[ "${MOCK_COMMANDS_MAP[$key]}" == "$mock_dir|"* ]]; then
        cmd="$key"
        original_path="${MOCK_COMMANDS_MAP[$key]#*|}"
        break
      fi
    done
  else
    # Input is a command name
    cmd="$input"
    if [[ -n "${MOCK_COMMANDS_MAP[$cmd]:-}" ]]; then
      IFS='|' read -r mock_dir original_path <<< "${MOCK_COMMANDS_MAP[$cmd]}"
    else
      warn "No mock found for command: $cmd"
      return 1
    fi
  fi

  # Remove the mock directory if found
  if [[ -d "$mock_dir" ]]; then
    if ! safe_rm_dir "$mock_dir"; then
      warn "Failed to remove mock directory: $mock_dir"
    fi
  fi

  # Restore original PATH if we have the command and original_path
  if [[ -n "$cmd" && -n "$original_path" ]]; then
    export PATH="$original_path"
    unset "MOCK_COMMANDS_MAP[$cmd]"
    debug "Removed mock command: $cmd"
  else
    # If we only have the directory, try to restore PATH by removing it
    export PATH=$(echo "$PATH" | sed "s|$mock_dir:||")
    warn "Restored PATH but couldn't identify mock command"
  fi

  return 0
}

# Create mock environment variables
# Arguments:
#   $1 - Name of environment variable
#   $2 - Value to set
#   $3 - Optional flag to append rather than replace (true/false, default: false)
# Returns:
#   0 on success, 1 on failure
mock_env_var() {
  local var_name="${1:-}"
  local var_value="${2:-}"
  local append="${3:-false}"

  # Validate inputs
  if [[ -z "$var_name" ]]; then
    error_exit "No variable name provided to mock_env_var"
    return 1
  fi

  # Store original value if it exists and we haven't stored it already
  if [[ -z "${MOCK_ENV_VARS_MAP[$var_name]:-}" ]]; then
    if [[ -n "${!var_name+x}" ]]; then
      MOCK_ENV_VARS_MAP["$var_name"]="${!var_name}"
    else
      MOCK_ENV_VARS_MAP["$var_name"]="__UNDEFINED__"
    fi
  fi

  # Set mock value, either append or replace
  if [[ "$append" == "true" && -n "${!var_name+x}" ]]; then
    eval "export $var_name=\"${!var_name}${var_value}\""
    debug "Appended to environment variable $var_name"
  else
    eval "export $var_name=\"${var_value}\""
    debug "Set environment variable $var_name='${var_value}'"
  fi

  return 0
}

# Restore mocked environment variables
# Arguments:
#   $1 - Name of environment variable to restore
#   $2 - Optional flag to restore all if no name provided (true/false, default: false)
# Returns:
#   0 on success, 1 on failure
restore_env_var() {
  local var_name="${1:-}"
  local restore_all="${2:-false}"

  # Restore all mocked environment variables if requested
  if [[ "$restore_all" == "true" || -z "$var_name" ]]; then
    for var in "${!MOCK_ENV_VARS_MAP[@]}"; do
      local original_value="${MOCK_ENV_VARS_MAP[$var]}"

      if [[ "$original_value" == "__UNDEFINED__" ]]; then
        unset "$var"
        debug "Restored environment variable $var (was undefined)"
      else
        eval "export $var=\"$original_value\""
        debug "Restored environment variable $var='$original_value'"
      fi
    done

    # Clear the tracked variables
    declare -A MOCK_ENV_VARS_MAP=()
    return 0
  fi

  # Restore specific variable
  if [[ -n "${MOCK_ENV_VARS_MAP[$var_name]:-}" ]]; then
    local original_value="${MOCK_ENV_VARS_MAP[$var_name]}"

    if [[ "$original_value" == "__UNDEFINED__" ]]; then
      unset "$var_name"
      debug "Restored environment variable $var_name (was undefined)"
    else
      eval "export $var_name=\"$original_value\""
      debug "Restored environment variable $var_name='$original_value'"
    fi

    # Remove from tracking
    unset "MOCK_ENV_VARS_MAP[$var_name]"
    return 0
  else
    warn "No original value found for environment variable: $var_name"
    return 1
  fi
}

# Mock a function within the current shell
# Arguments:
#   $1 - Function name to mock
#   $2 - Function implementation (bash code)
# Returns:
#   0 on success, 1 on failure
mock_function() {
  local func_name="${1:-}"
  local implementation="${2:-echo 'This is a mock function'}"

  # Validate inputs
  if [[ -z "$func_name" ]]; then
    error_exit "No function name provided to mock_function"
    return 1
  fi

  # Check if function already exists and backup if it does
  if declare -f "$func_name" >/dev/null 2>&1; then
    local original_def
    original_def=$(declare -f "$func_name")
    # Store original function definition with a unique suffix
    eval "${func_name}_original() ${original_def#$func_name}"
    MOCK_ENV_VARS_MAP["${func_name}_function"]="original"
  else
    # Function doesn't exist, mark it as non-existent
    MOCK_ENV_VARS_MAP["${func_name}_function"]="non-existent"
  fi

  # Define the mock function
  eval "$func_name() { $implementation; }"
  debug "Created mock function: $func_name"

  return 0
}

# Restore a mocked function
# Arguments:
#   $1 - Function name to restore
# Returns:
#   0 on success, 1 on failure
restore_function() {
  local func_name="${1:-}"

  # Validate inputs
  if [[ -z "$func_name" ]]; then
    error_exit "No function name provided to restore_function"
    return 1
  fi

  # Check if this function was mocked
  local status="${MOCK_ENV_VARS_MAP["${func_name}_function"]:-}"

  if [[ -z "$status" ]]; then
    warn "Function $func_name was not mocked, nothing to restore"
    return 1
  elif [[ "$status" == "original" ]]; then
    # If original function exists, restore it
    if declare -f "${func_name}_original" >/dev/null 2>&1; then
      local original_def
      original_def=$(declare -f "${func_name}_original")
      # Restore original function definition
      eval "$func_name() ${original_def#${func_name}_original}"
      # Remove the backup function
      unset -f "${func_name}_original"
      debug "Restored original function: $func_name"
    else
      warn "Original function ${func_name}_original not found"
      return 1
    fi
  elif [[ "$status" == "non-existent" ]]; then
    # If function didn't exist, remove it
    unset -f "$func_name"
    debug "Removed mock function: $func_name (was non-existent)"
  fi

  # Remove tracking entry
  unset "MOCK_ENV_VARS_MAP[${func_name}_function]"

  return 0
}

# Clean up all mocks created by this module
# Arguments:
#   $1 - Optional flag to force cleanup even if some operations fail (true/false, default: false)
# Returns:
#   0 on success, 1 if any cleanup operation fails
cleanup_all_mocks() {
  local force="${1:-false}"
  local exit_code=0

  debug "Cleaning up all mocks..."

  # Restore all environment variables
  restore_env_var "" "true" || exit_code=$?

  # Restore PATH and remove all mock command directories
  for cmd in "${!MOCK_COMMANDS_MAP[@]}"; do
    IFS='|' read -r mock_dir original_path <<< "${MOCK_COMMANDS_MAP[$cmd]}"
    if [[ -d "$mock_dir" ]]; then
      safe_rm_dir "$mock_dir" || exit_code=$?
    fi
    # Last command will set the PATH to the most recent original
    # This is an imperfect solution but better than nothing
    if [[ -n "$original_path" ]]; then
      export PATH="$original_path"
    fi
  done
  declare -A MOCK_COMMANDS_MAP=()

  # Clean up all tracked mock directories
  for dir in "${MOCK_DIRS_ARRAY[@]}"; do
    if [[ -d "$dir" ]]; then
      safe_rm_dir "$dir" || exit_code=$?
    fi
  done
  MOCK_DIRS_ARRAY=()

  # Return success if force is true, otherwise return stored exit code
  if [[ "$force" == "true" ]]; then
    debug "Forced cleanup completed (ignored errors)"
    return 0
  else
    if [[ $exit_code -eq 0 ]]; then
      debug "Cleanup completed successfully"
    else
      warn "Cleanup completed with errors"
    fi
    return $exit_code
  fi
}

# Self-test function to verify mocking functionality
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

  # Test mock file with permissions
  ((total++))
  local test_script="$mock_dir/test_script.sh"
  if create_mock_file "$test_script" "echo 'test script'" 755 && [[ -x "$test_script" ]]; then
    echo "✓ create_mock_file creates executable script"
  else
    echo "✗ create_mock_file creates executable script"
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

  # Test mock command removal
  ((total++))
  remove_mock_command "test_cmd"
  if ! command -v test_cmd >/dev/null 2>&1; then
    echo "✓ remove_mock_command successfully removes command"
  else
    echo "✗ remove_mock_command failed to remove command"
    ((failures++))
  fi

  # Test environment variable mocking
  ((total++))
  mock_env_var "TEST_MOCK_VAR" "mocked_value"
  if [[ "$TEST_MOCK_VAR" == "mocked_value" ]]; then
    echo "✓ mock_env_var sets variable"
  else
    echo "✗ mock_env_var sets variable"
    ((failures++))
  fi

  # Test environment variable restore
  ((total++))
  restore_env_var "TEST_MOCK_VAR"
  if [[ -z "${TEST_MOCK_VAR+x}" ]]; then
    echo "✓ restore_env_var restores variable"
  else
    echo "✗ restore_env_var restores variable"
    ((failures++))
  fi

  # Test function mocking
  ((total++))
  test_original_function() { echo "original"; }
  mock_function "test_original_function" "echo 'mocked function'"
  local func_output
  func_output=$(test_original_function)
  if [[ "$func_output" == "mocked function" ]]; then
    echo "✓ mock_function replaces function correctly"
  else
    echo "✗ mock_function failed to replace function"
    ((failures++))
  fi

  # Test function restoration
  ((total++))
  restore_function "test_original_function"
  func_output=$(test_original_function)
  if [[ "$func_output" == "original" ]]; then
    echo "✓ restore_function restores original function"
  else
    echo "✗ restore_function failed to restore original function"
    ((failures++))
  fi
  unset -f test_original_function

  # Test cleanup
  ((total++))
  local cleanup_test_var="before_cleanup"
  mock_env_var "cleanup_test_var" "during_cleanup"
  local cleanup_dir
  cleanup_dir=$(create_mock_environment "cleanup_test")
  cleanup_all_mocks
  if [[ "$cleanup_test_var" == "before_cleanup" && ! -d "$cleanup_dir" ]]; then
    echo "✓ cleanup_all_mocks removes all mocks"
  else
    echo "✗ cleanup_all_mocks failed to clean up properly"
    ((failures++))
  fi

  # Clean up any remaining test artifacts
  safe_rm_dir "$mock_dir" 2>/dev/null

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
export -f mock_function
export -f restore_function
export -f cleanup_all_mocks
export -f mocking_self_test

# Export constants
export MOCKING_MODULE_VERSION
export MOCKING_MODULE_DATE

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  mocking_self_test
  exit $?
fi
