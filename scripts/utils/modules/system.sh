#!/bin/bash
# filepath: scripts/utils/modules/system.sh
#
# System testing utilities for Cloud Infrastructure Platform
#
# This module provides utilities for testing system-level components
# such as ports, network connectivity, and processes.
#
# Usage: source "$(dirname "$0")/system.sh"

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
SYSTEM_MODULE_VERSION="1.0.0"
SYSTEM_MODULE_DATE="2023-12-15"

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

# Check if a process is running
# Arguments:
#   $1 - Process name or pattern
# Returns:
#   0 if process is running, 1 if not
is_process_running() {
  local process="$1"
  pgrep -f "$process" &>/dev/null
}

# Get process ID by name
# Arguments:
#   $1 - Process name or pattern
# Returns:
#   Process ID(s) or empty if not found
get_process_id() {
  local process="$1"
  pgrep -f "$process" 2>/dev/null || true
}

# Wait for a process to start
# Arguments:
#   $1 - Process name or pattern
#   $2 - Timeout in seconds (optional, default: 30)
# Returns:
#   0 if process starts, 1 on timeout
wait_for_process() {
  local process="$1"
  local timeout="${2:-30}"
  local start_time
  start_time=$(date +%s)

  while true; do
    if is_process_running "$process"; then
      return 0
    fi

    local current_time
    current_time=$(date +%s)
    if (( current_time - start_time >= timeout )); then
      log "ERROR" "Timed out waiting for process: $process"
      return 1
    fi

    sleep 1
  done
}

# Self-test function
# Arguments:
#   None
# Returns:
#   0 if all tests pass, 1 if any fail
system_self_test() {
  local result=0
  local failures=0
  local total=0

  echo "Running system module self-test..."

  # Test port availability
  ((total++))
  local unavailable_port=22  # SSH is typically in use
  local available_port

  if ! port_is_available "$unavailable_port" 2>/dev/null; then
    echo "✓ port_is_available correctly identifies in-use port"
  else
    echo "✗ port_is_available failed to identify in-use port (assuming port 22 is in use)"
    ((failures++))
  fi

  # Test finding available port
  ((total++))
  available_port=$(find_available_port)
  if [[ -n "$available_port" ]]; then
    echo "✓ find_available_port returns a port ($available_port)"
  else
    echo "✗ find_available_port failed to find an available port"
    ((failures++))
  fi

  # Test process checks
  ((total++))
  if is_process_running "$$" || is_process_running "bash"; then
    echo "✓ is_process_running correctly identifies this shell process"
  else
    echo "✗ is_process_running failed to identify this shell process"
    ((failures++))
  fi

  ((total++))
  local pid
  pid=$(get_process_id "$$" || get_process_id "bash")
  if [[ -n "$pid" ]]; then
    echo "✓ get_process_id returns a PID"
  else
    echo "✗ get_process_id failed to find this shell process"
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
export -f port_is_available
export -f find_available_port
export -f wait_for_port
export -f is_process_running
export -f get_process_id
export -f wait_for_process
export -f system_self_test

# Export constants
export SYSTEM_MODULE_VERSION
export SYSTEM_MODULE_DATE

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  system_self_test
  exit $?
fi
