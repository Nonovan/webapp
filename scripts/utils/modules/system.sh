#!/bin/bash
# filepath: scripts/utils/modules/system.sh
#
# System testing utilities for Cloud Infrastructure Platform
#
# This module provides utilities for testing system-level components
# such as ports, network connectivity, and processes.
#
# Part of: Cloud Infrastructure Platform - Testing Framework
#
# Usage: source "$(dirname "$0")/system.sh"
#
# Version: 1.0.1
# Date: 2023-12-20

# Set strict mode for better error detection
set -o pipefail
set -o nounset

# Version tracking
readonly SYSTEM_MODULE_VERSION="1.0.1"
readonly SYSTEM_MODULE_DATE="2023-12-20"

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

# Basic logging functions if core module isn't available
if [[ ! $(type -t log) == "function" ]]; then
  log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
  }

  # Common log levels
  log_info() { log "INFO" "$1"; }
  log_debug() { log "DEBUG" "$1"; }
  log_warn() { log "WARN" "$1"; }
  log_error() { log "ERROR" "$1"; }
fi

# Default settings
DEFAULT_PORT_CHECK_TIMEOUT=5    # Default timeout in seconds for port checks
DEFAULT_PROCESS_CHECK_TIMEOUT=30 # Default timeout in seconds for process checks
DEFAULT_PORT_RANGE_START=10000  # Default start of dynamic port range
DEFAULT_PORT_RANGE_END=60000    # Default end of dynamic port range
DEFAULT_LOCALHOST="127.0.0.1"   # Default localhost address

#######################################
# SYSTEM TESTING UTILITIES
#######################################

# Check if a port is available on a specific host
# Arguments:
#   $1 - Port number to check
#   $2 - Host to check (optional, default: 127.0.0.1)
#   $3 - Timeout in seconds (optional, default: 5)
# Returns:
#   0 if port is available, 1 if in use or error
port_is_available() {
  local port="$1"
  local host="${2:-$DEFAULT_LOCALHOST}"
  local timeout="${3:-$DEFAULT_PORT_CHECK_TIMEOUT}"

  # Validate port number
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    log_error "Invalid port number: $port"
    return 1
  fi

  # Validate port range
  if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
    log_error "Port number out of valid range (1-65535): $port"
    return 1
  fi

  # Attempt to connect to see if port is in use
  if timeout "$timeout" bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
    # Port is in use
    log_debug "Port $port is in use on $host"
    return 1
  else
    # Port is available
    log_debug "Port $port is available on $host"
    return 0
  fi
}

# Find an available port within a range
# Arguments:
#   $1 - Starting port number (optional, default: random in range 10000-60000)
#   $2 - Host to check (optional, default: 127.0.0.1)
#   $3 - Maximum attempts (optional, default: 50)
# Returns:
#   An available port number or error
find_available_port() {
  local start_port="${1:-0}"
  local host="${2:-$DEFAULT_LOCALHOST}"
  local max_attempts="${3:-50}"
  local attempt=0
  local port=0

  # If no start port specified, use random port in default range
  if [[ "$start_port" -eq 0 ]]; then
    start_port=$((DEFAULT_PORT_RANGE_START + RANDOM % (DEFAULT_PORT_RANGE_END - DEFAULT_PORT_RANGE_START)))
  fi

  port="$start_port"

  # Try to find an available port
  while [[ $attempt -lt $max_attempts ]]; do
    if port_is_available "$port" "$host"; then
      echo "$port"
      return 0
    fi

    # Increment port or choose a new random port
    if [[ "$start_port" -eq 0 ]]; then
      # Random port strategy
      port=$((DEFAULT_PORT_RANGE_START + RANDOM % (DEFAULT_PORT_RANGE_END - DEFAULT_PORT_RANGE_START)))
    else
      # Sequential port strategy
      ((port++))

      # Ensure we stay in valid range
      if [[ "$port" -gt 65535 ]]; then
        log_error "Reached maximum port number while searching for available port"
        return 1
      fi
    fi

    ((attempt++))
  done

  log_error "Failed to find available port after $max_attempts attempts"
  return 1
}

# Wait for a service to be ready on a specific port with timeout
# Arguments:
#   $1 - Host to check
#   $2 - Port to check
#   $3 - Timeout in seconds (optional, default: 30)
#   $4 - Retry interval in seconds (optional, default: 1)
# Returns:
#   0 if service becomes available, 1 on timeout
wait_for_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-30}"
  local retry_interval="${4:-1}"
  local start_time
  start_time=$(date +%s)
  local end_time=$((start_time + timeout))
  local current_time="$start_time"
  local elapsed=0

  # Validate port number
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
    log_error "Invalid port number: $port"
    return 1
  fi

  log_debug "Waiting for port $port on $host to become available (timeout: ${timeout}s)"

  while [[ "$current_time" -lt "$end_time" ]]; do
    if timeout 2 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
      elapsed=$((current_time - start_time))
      log_info "Port $port on $host is now available after ${elapsed}s"
      return 0
    fi

    sleep "$retry_interval"
    current_time=$(date +%s)
  done

  elapsed=$((current_time - start_time))
  log_error "Timed out waiting for $host:$port to become available after ${elapsed}s"
  return 1
}

# Check if a port is open on a specific host
# Arguments:
#   $1 - Host to check
#   $2 - Port to check
#   $3 - Timeout in seconds (optional, default: 5)
# Returns:
#   0 if port is open, 1 if closed or error
port_is_open() {
  local host="$1"
  local port="$2"
  local timeout="${3:-$DEFAULT_PORT_CHECK_TIMEOUT}"

  # Validate port number
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
    log_error "Invalid port number: $port"
    return 1
  fi

  # Use different methods based on available tools
  if command -v nc &>/dev/null; then
    # Use netcat if available
    if nc -z -w "$timeout" "$host" "$port" 2>/dev/null; then
      log_debug "Port $port is open on $host (using nc)"
      return 0
    fi
  elif command -v timeout &>/dev/null; then
    # Use timeout and bash /dev/tcp
    if timeout "$timeout" bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
      log_debug "Port $port is open on $host (using /dev/tcp)"
      return 0
    fi
  else
    # Use pure bash with SIGALRM workaround
    (
      # Set trap to handle connection timeout
      trap 'exit 1' ALRM
      # Set alarm for timeout seconds
      sleep "$timeout" && kill -ALRM $$ 2>/dev/null &
      sleep_pid=$!
      # Try the connection
      echo > "/dev/tcp/$host/$port" 2>/dev/null
      connect_result=$?
      # Kill the sleep process
      kill $sleep_pid 2>/dev/null || true
      exit $connect_result
    )
    if [[ $? -eq 0 ]]; then
      log_debug "Port $port is open on $host (using pure bash)"
      return 0
    fi
  fi

  log_debug "Port $port is closed on $host"
  return 1
}

# Check if a process is running
# Arguments:
#   $1 - Process name or pattern
#   $2 - Exact match flag (optional, default: false)
# Returns:
#   0 if process is running, 1 if not
is_process_running() {
  local process="$1"
  local exact_match="${2:-false}"
  local pids

  if [[ -z "$process" ]]; then
    log_error "No process name or pattern provided"
    return 1
  fi

  if [[ "$exact_match" == "true" ]]; then
    # Use exact match
    pids=$(pgrep -f "^${process}$" 2>/dev/null)
  else
    # Use pattern match
    pids=$(pgrep -f "$process" 2>/dev/null)
  fi

  if [[ -n "$pids" ]]; then
    log_debug "Process '$process' is running with PIDs: $pids"
    return 0
  else
    log_debug "Process '$process' is not running"
    return 1
  fi
}

# Get process ID by name or pattern
# Arguments:
#   $1 - Process name or pattern
#   $2 - Exact match flag (optional, default: false)
# Returns:
#   Process ID(s) or empty if not found
get_process_id() {
  local process="$1"
  local exact_match="${2:-false}"
  local pids

  if [[ -z "$process" ]]; then
    log_error "No process name or pattern provided"
    return 1
  fi

  if [[ "$exact_match" == "true" ]]; then
    # Use exact match
    pids=$(pgrep -f "^${process}$" 2>/dev/null || echo "")
  else
    # Use pattern match
    pids=$(pgrep -f "$process" 2>/dev/null || echo "")
  fi

  echo "$pids"
}

# Wait for a process to start
# Arguments:
#   $1 - Process name or pattern
#   $2 - Timeout in seconds (optional, default: 30)
#   $3 - Exact match flag (optional, default: false)
#   $4 - Retry interval in seconds (optional, default: 1)
# Returns:
#   0 if process starts, 1 on timeout
wait_for_process() {
  local process="$1"
  local timeout="${2:-$DEFAULT_PROCESS_CHECK_TIMEOUT}"
  local exact_match="${3:-false}"
  local retry_interval="${4:-1}"
  local start_time
  start_time=$(date +%s)
  local end_time=$((start_time + timeout))
  local current_time="$start_time"
  local elapsed=0

  if [[ -z "$process" ]]; then
    log_error "No process name or pattern provided"
    return 1
  }

  log_debug "Waiting for process '$process' to start (timeout: ${timeout}s)"

  while [[ "$current_time" -lt "$end_time" ]]; do
    if is_process_running "$process" "$exact_match"; then
      elapsed=$((current_time - start_time))
      log_info "Process '$process' started after ${elapsed}s"
      return 0
    fi

    sleep "$retry_interval"
    current_time=$(date +%s)
  done

  elapsed=$((current_time - start_time))
  log_error "Timed out waiting for process '$process' after ${elapsed}s"
  return 1
}

# Wait for a process to stop
# Arguments:
#   $1 - Process name or pattern
#   $2 - Timeout in seconds (optional, default: 30)
#   $3 - Exact match flag (optional, default: false)
#   $4 - Retry interval in seconds (optional, default: 1)
# Returns:
#   0 if process stops, 1 on timeout
wait_for_process_to_stop() {
  local process="$1"
  local timeout="${2:-$DEFAULT_PROCESS_CHECK_TIMEOUT}"
  local exact_match="${3:-false}"
  local retry_interval="${4:-1}"
  local start_time
  start_time=$(date +%s)
  local end_time=$((start_time + timeout))
  local current_time="$start_time"
  local elapsed=0

  if [[ -z "$process" ]]; then
    log_error "No process name or pattern provided"
    return 1
  }

  log_debug "Waiting for process '$process' to stop (timeout: ${timeout}s)"

  while [[ "$current_time" -lt "$end_time" ]]; do
    if ! is_process_running "$process" "$exact_match"; then
      elapsed=$((current_time - start_time))
      log_info "Process '$process' stopped after ${elapsed}s"
      return 0
    fi

    sleep "$retry_interval"
    current_time=$(date +%s)
  done

  elapsed=$((current_time - start_time))
  log_error "Timed out waiting for process '$process' to stop after ${elapsed}s"
  return 1
}

# Get system resource information
# Arguments:
#   $1 - Resource type: memory, cpu, disk (optional, default: all)
# Returns:
#   Formatted system resource information
get_system_resources() {
  local resource_type="${1:-all}"
  local output=""

  case "$resource_type" in
    memory)
      if command -v free &>/dev/null; then
        output=$(free -m)
      else
        output=$(cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree')
      fi
      ;;
    cpu)
      output=$(top -bn1 | grep -E '^(%Cpu|CPU)')
      ;;
    disk)
      output=$(df -h)
      ;;
    all)
      output="=== MEMORY ===\n"
      output+="$(get_system_resources memory)\n\n"
      output+="=== CPU ===\n"
      output+="$(get_system_resources cpu)\n\n"
      output+="=== DISK ===\n"
      output+="$(get_system_resources disk)"
      ;;
    *)
      log_error "Unknown resource type: $resource_type (valid: memory, cpu, disk, all)"
      return 1
      ;;
  esac

  echo -e "$output"
}

# Check if a host is reachable (ping)
# Arguments:
#   $1 - Host to check
#   $2 - Timeout in seconds (optional, default: 5)
#   $3 - Number of ping packets (optional, default: 3)
# Returns:
#   0 if host is reachable, 1 if not
is_host_reachable() {
  local host="$1"
  local timeout="${2:-5}"
  local count="${3:-3}"

  if [[ -z "$host" ]]; then
    log_error "No host specified"
    return 1
  fi

  if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
    log_debug "Host $host is reachable"
    return 0
  else
    log_debug "Host $host is not reachable"
    return 1
  fi
}

# Check if current user is root
# Returns:
#   0 if user is root, 1 if not
is_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 0
  else
    return 1
  fi
}

# Safely execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2... - Command and arguments to run
# Returns:
#   Exit code of the command or 124 on timeout
run_with_timeout() {
  local timeout="$1"
  shift

  # Validate timeout
  if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
    log_error "Invalid timeout value: $timeout"
    return 1
  fi

  # Check for available timeout command
  if command -v timeout &>/dev/null; then
    timeout "$timeout" "$@"
    return $?
  elif command -v gtimeout &>/dev/null; then
    # macOS with coreutils installed
    gtimeout "$timeout" "$@"
    return $?
  else
    # Fallback implementation with limited capability
    log_warn "timeout command not found, using fallback implementation"
    (
      # Set trap to handle timeout
      trap 'exit 124' ALRM
      # Set alarm
      sleep "$timeout" && kill -ALRM $$ 2>/dev/null &
      sleep_pid=$!
      # Run the command
      "$@"
      cmd_result=$?
      # Kill the sleep process
      kill $sleep_pid 2>/dev/null || true
      exit $cmd_result
    )
    return $?
  fi
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
  if ! port_is_available "$unavailable_port" 2>/dev/null; then
    echo "✓ port_is_available correctly identifies in-use port"
  else
    echo "✗ port_is_available failed to identify in-use port (assuming port 22 is in use)"
    ((failures++))
  fi

  # Test finding available port
  ((total++))
  local available_port
  available_port=$(find_available_port)
  if [[ -n "$available_port" && "$available_port" =~ ^[0-9]+$ ]]; then
    echo "✓ find_available_port returns a valid port ($available_port)"
  else
    echo "✗ find_available_port failed to find an available port"
    ((failures++))
  fi

  # Test port_is_open
  ((total++))
  if port_is_open "localhost" "22" 2>/dev/null; then
    echo "✓ port_is_open correctly identifies open port"
  else
    echo "✗ port_is_open failed to identify open port (assuming port 22 is open)"
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

  # Test system resource checks
  ((total++))
  if output=$(get_system_resources "memory") && [[ -n "$output" ]]; then
    echo "✓ get_system_resources returns memory information"
  else
    echo "✗ get_system_resources failed to retrieve memory information"
    ((failures++))
  fi

  # Test host reachability
  ((total++))
  if is_host_reachable "localhost" 2 1; then
    echo "✓ is_host_reachable correctly identifies localhost as reachable"
  else
    echo "✗ is_host_reachable failed to identify localhost as reachable"
    ((failures++))
  fi

  # Test run_with_timeout
  ((total++))
  if run_with_timeout 2 sleep 1; then
    echo "✓ run_with_timeout successfully executes command within timeout"
  else
    echo "✗ run_with_timeout failed to execute command within timeout"
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
export -f port_is_open
export -f is_process_running
export -f get_process_id
export -f wait_for_process
export -f wait_for_process_to_stop
export -f get_system_resources
export -f is_host_reachable
export -f is_root
export -f run_with_timeout
export -f system_self_test

# Export constants
export SYSTEM_MODULE_VERSION
export SYSTEM_MODULE_DATE
export DEFAULT_PORT_CHECK_TIMEOUT
export DEFAULT_PROCESS_CHECK_TIMEOUT
export DEFAULT_PORT_RANGE_START
export DEFAULT_PORT_RANGE_END
export DEFAULT_LOCALHOST

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  system_self_test
  exit $?
fi
