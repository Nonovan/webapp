#!/bin/bash
# -----------------------------------------------------------------------------
# logging_utils.sh - Standard logging functions with consistent formatting
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# Usage: source "$(dirname "$0")/../common/logging_utils.sh"
# -----------------------------------------------------------------------------

# Set default log level if not defined
: "${LOG_LEVEL:=INFO}"

# Define log colors
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m' # No Color

# Define log levels with numeric values for comparison
declare -A LOG_LEVELS
LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARNING]=2 [ERROR]=3 [CRITICAL]=4)

# Set default log file if not defined
: "${LOG_FILE:=/var/log/monitoring.log}"

# Determine if we should output to a log file
should_log_to_file() {
  [[ -n "${LOG_FILE}" && -w "$(dirname "${LOG_FILE}")" ]]
}

# Check if the current log level should be displayed
should_display_log() {
  local log_level_value="${LOG_LEVELS[$1]}"
  local current_level_value="${LOG_LEVELS[$LOG_LEVEL]}"

  [[ -n "$log_level_value" && -n "$current_level_value" && $log_level_value -ge $current_level_value ]]
}

# Generic logging function
# Usage: _log LEVEL "message"
_log() {
  local level="$1"
  local message="$2"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local pid=$$
  local formatted_message="[$timestamp] [$level] [PID:$pid] $message"

  # Write to log file if enabled
  if should_log_to_file; then
    echo "$formatted_message" >> "${LOG_FILE}"
  fi

  # Display on console with colors if we're in a terminal
  if [[ -t 1 ]] && should_display_log "$level"; then
    case "$level" in
      DEBUG)    echo -e "${BLUE}$formatted_message${NC}" ;;
      INFO)     echo -e "${GREEN}$formatted_message${NC}" ;;
      WARNING)  echo -e "${YELLOW}$formatted_message${NC}" ;;
      ERROR)    echo -e "${RED}$formatted_message${NC}" ;;
      CRITICAL) echo -e "${PURPLE}$formatted_message${NC}" ;;
      *)        echo "$formatted_message" ;;
    esac
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

# Helper function to log the start of a script
log_script_start() {
  local script_name=$(basename "$0")
  log_info "========== Starting $script_name =========="
}

# Helper function to log the end of a script
log_script_end() {
  local script_name=$(basename "$0")
  local status="$1"
  if [[ -z "$status" ]]; then
    status="completed"
  fi
  log_info "========== $script_name $status =========="
}

# Function to configure logging
configure_logging() {
  local custom_log_level="$1"
  local custom_log_file="$2"

  if [[ -n "$custom_log_level" ]]; then
    if [[ -n "${LOG_LEVELS[$custom_log_level]}" ]]; then
      LOG_LEVEL="$custom_log_level"
    else
      echo "Invalid log level: $custom_log_level. Using default: $LOG_LEVEL"
    fi
  fi

  if [[ -n "$custom_log_file" ]]; then
    LOG_FILE="$custom_log_file"
  fi
}

# Log script initiation if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  log_script_start
  log_info "Logging utility loaded successfully"
  log_debug "This is a DEBUG message"
  log_info "This is an INFO message"
  log_warning "This is a WARNING message"
  log_error "This is an ERROR message"
  log_critical "This is a CRITICAL message"
  log_script_end
fi
