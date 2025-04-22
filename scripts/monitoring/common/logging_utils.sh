#!/bin/bash
# -----------------------------------------------------------------------------
# logging_utils.sh - Standard logging functions with consistent formatting
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# Usage: source "$(dirname "$0")/../common/logging_utils.sh"
# -----------------------------------------------------------------------------

# Set strict error handling
set -o pipefail

# Set default log level if not defined
: "${LOG_LEVEL:=INFO}"

# Define log colors
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Define log levels with numeric values for comparison
declare -A LOG_LEVELS
LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARNING]=2 [ERROR]=3 [CRITICAL]=4)

# Set default log file path if not defined
: "${LOG_FILE:=/var/log/cloud-platform/monitoring.log}"

# Set default logging options
: "${LOG_TO_CONSOLE:=true}"
: "${LOG_INCLUDE_TIMESTAMP:=true}"
: "${LOG_MAX_SIZE:=10485760}" # 10MB default max log size

# Ensure log directory exists
ensure_log_directory() {
  local log_dir
  log_dir=$(dirname "${LOG_FILE}")

  if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir" 2>/dev/null || {
      echo "WARNING: Could not create log directory: $log_dir. Using /tmp instead."
      LOG_FILE="/tmp/monitoring-$(date +%Y%m%d).log"
    }
  fi
}

# Rotate log if it exceeds max size
rotate_log_if_needed() {
  if [[ -f "${LOG_FILE}" ]]; then
    local current_size
    current_size=$(stat -c %s "${LOG_FILE}" 2>/dev/null || stat -f %z "${LOG_FILE}" 2>/dev/null || echo 0)

    if [[ $current_size -gt $LOG_MAX_SIZE ]]; then
      local timestamp
      timestamp=$(date +%Y%m%d-%H%M%S)
      mv "${LOG_FILE}" "${LOG_FILE}.${timestamp}"

      # Delete old rotated logs if we have more than 5
      find "$(dirname "${LOG_FILE}")" -name "$(basename "${LOG_FILE}").*" -type f | \
        sort -r | tail -n +6 | xargs rm -f 2>/dev/null || true
    fi
  fi
}

# Determine if we should output to a log file
should_log_to_file() {
  [[ -n "${LOG_FILE}" ]]
}

# Check if the current log level should be displayed
should_display_log() {
  local level="$1"
  local log_level_value="${LOG_LEVELS[$level]}"
  local current_level_value="${LOG_LEVELS[$LOG_LEVEL]}"

  # Check if both values are valid numbers and compare them
  if [[ -n "$log_level_value" && -n "$current_level_value" ]]; then
    [[ $log_level_value -ge $current_level_value ]]
    return $?
  fi

  # Default to showing the message if LOG_LEVEL is invalid
  return 0
}

# Format log messages consistently
format_log_message() {
  local level="$1"
  local message="$2"
  local timestamp
  local hostname
  local pid

  if [[ "${LOG_INCLUDE_TIMESTAMP}" == "true" ]]; then
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    pid=$$
    hostname=$(hostname -s 2>/dev/null || echo "unknown")
    echo "[$timestamp] [$level] [$hostname] [PID:$pid] $message"
  else
    echo "[$level] $message"
  fi
}

# Generic logging function
# Usage: _log LEVEL "message"
_log() {
  local level="$1"
  local message="$2"
  local formatted_message

  # Skip if this log level shouldn't be displayed
  if ! should_display_log "$level"; then
    return 0
  fi

  # Format the message
  formatted_message=$(format_log_message "$level" "$message")

  # Write to log file if enabled
  if should_log_to_file; then
    ensure_log_directory
    rotate_log_if_needed
    echo "$formatted_message" >> "${LOG_FILE}" 2>/dev/null || {
      echo "WARNING: Could not write to log file: ${LOG_FILE}" >&2
    }
  fi

  # Display on console with colors if we're in a terminal and console logging is enabled
  if [[ "${LOG_TO_CONSOLE}" == "true" ]]; then
    if [[ -t 1 ]]; then
      # Terminal with colors
      case "$level" in
        DEBUG)    echo -e "${GRAY}$formatted_message${NC}" ;;
        INFO)     echo -e "${GREEN}$formatted_message${NC}" ;;
        WARNING)  echo -e "${YELLOW}$formatted_message${NC}" ;;
        ERROR)    echo -e "${RED}$formatted_message${NC}" ;;
        CRITICAL) echo -e "${BOLD}${RED}$formatted_message${NC}" ;;
        *)        echo "$formatted_message" ;;
      esac
    else
      # Not a terminal, output without colors
      echo "$formatted_message"
    fi
  fi
}

# Public logging functions
log_debug() {
  _log "DEBUG" "$1"
}

log_info() {
  _log "INFO" "$1"
}

log_warning() {
  _log "WARNING" "$1"
}

log_error() {
  _log "ERROR" "$1"
}

log_critical() {
  _log "CRITICAL" "$1"
}

# Generic log function that accepts a level parameter
# Usage: log "message" "LEVEL"
log() {
  local message="$1"
  local level="${2:-INFO}"

  # Convert to uppercase
  level=$(echo "$level" | tr '[:lower:]' '[:upper:]')

  # Use the appropriate logging function
  case "$level" in
    DEBUG)    log_debug "$message" ;;
    INFO)     log_info "$message" ;;
    WARNING)  log_warning "$message" ;;
    ERROR)    log_error "$message" ;;
    CRITICAL) log_critical "$message" ;;
    *)        log_info "$message" ;; # Default to INFO for unknown levels
  esac
}

# Helper function to log the start of a script
log_script_start() {
  local script_name
  script_name=$(basename "$0")
  log_info "========== Starting $script_name =========="

  # Log script environment information for debugging
  if should_display_log "DEBUG"; then
    log_debug "Operating System: $(uname -s)"
    log_debug "Hostname: $(hostname -f 2>/dev/null || hostname)"
    log_debug "User: $(whoami)"
    log_debug "Current Directory: $(pwd)"
    log_debug "Script Path: $0"
    log_debug "Log Level: $LOG_LEVEL"
    log_debug "Log File: $LOG_FILE"
  fi
}

# Helper function to log the end of a script
log_script_end() {
  local script_name
  script_name=$(basename "$0")
  local status="${1:-completed}"
  local duration=""

  # Calculate duration if SCRIPT_START_TIME is set
  if [[ -n "${SCRIPT_START_TIME}" ]]; then
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - SCRIPT_START_TIME))

    # Format duration string
    if [[ $elapsed -lt 60 ]]; then
      duration=" (${elapsed}s)"
    else
      local minutes=$((elapsed / 60))
      local seconds=$((elapsed % 60))
      duration=" (${minutes}m ${seconds}s)"
    fi
  fi

  log_info "========== $script_name $status$duration =========="
}

# Function to configure logging
configure_logging() {
  local custom_log_level="$1"
  local custom_log_file="$2"
  local custom_log_to_console="$3"

  # Set custom log level if valid
  if [[ -n "$custom_log_level" ]]; then
    # Convert to uppercase for case-insensitive comparison
    custom_log_level=$(echo "$custom_log_level" | tr '[:lower:]' '[:upper:]')

    if [[ -n "${LOG_LEVELS[$custom_log_level]}" ]]; then
      LOG_LEVEL="$custom_log_level"
    else
      echo "Invalid log level: $custom_log_level. Using default: $LOG_LEVEL"
    fi
  fi

  # Set custom log file if provided
  if [[ -n "$custom_log_file" ]]; then
    LOG_FILE="$custom_log_file"
  fi

  # Set console logging preference if provided
  if [[ -n "$custom_log_to_console" ]]; then
    LOG_TO_CONSOLE="$custom_log_to_console"
  fi

  # Set script start time for duration calculation
  SCRIPT_START_TIME=$(date +%s)

  # Ensure log directory exists
  ensure_log_directory
}

# Helper function to parse common logging arguments
parse_logging_args() {
  local args=("$@")
  local i=0

  while [[ $i -lt ${#args[@]} ]]; do
    case "${args[$i]}" in
      --log-level)
        LOG_LEVEL="${args[$i+1]}"
        i=$((i+2))
        ;;
      --log-file)
        LOG_FILE="${args[$i+1]}"
        i=$((i+2))
        ;;
      --log-console)
        LOG_TO_CONSOLE="${args[$i+1]}"
        i=$((i+2))
        ;;
      *)
        i=$((i+1))
        ;;
    esac
  done

  configure_logging "$LOG_LEVEL" "$LOG_FILE" "$LOG_TO_CONSOLE"
}

# Log utility version for debugging
readonly LOGGING_UTILS_VERSION="1.2.0"

# Set script start time for duration tracking
SCRIPT_START_TIME=$(date +%s)

# Log script initiation if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  log_script_start
  log_info "Logging utility v${LOGGING_UTILS_VERSION} loaded successfully"
  log_debug "This is a DEBUG message"
  log_info "This is an INFO message"
  log_warning "This is a WARNING message"
  log_error "This is an ERROR message"
  log_critical "This is a CRITICAL message"
  log_script_end
fi
