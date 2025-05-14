#!/bin/bash
# filepath: scripts/security/common/logging.sh
#
# Standardized logging functionality for security scripts
# Part of Cloud Infrastructure Platform security module
#
# This script provides consistent logging capabilities across security scripts
# with multi-level severity, context tagging, and multiple output destinations.
#
# Usage: source scripts/security/common/logging.sh

# Ensure script is not executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script should be sourced, not executed directly."
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ===== Version information =====
readonly SECURITY_LOGGING_VERSION="0.1.1"
readonly SECURITY_LOGGING_DATE="2024-08-17"

# ===== Logging Configuration =====

# Set default values if not already defined
: "${SECURITY_LOG_LEVEL:=INFO}"
: "${SECURITY_LOG_DIR:=/var/log/cloud-platform/security}"
: "${SECURITY_LOG_FILE:=${SECURITY_LOG_DIR}/security.log}"
: "${SECURITY_LOG_MAX_SIZE:=10485760}"  # 10MB
: "${SECURITY_LOG_ROTATE_COUNT:=5}"
: "${SECURITY_LOG_USE_SYSLOG:=false}"
: "${SECURITY_LOG_USE_STDOUT:=true}"
: "${SECURITY_LOG_DATE_FORMAT:=%Y-%m-%d %H:%M:%S}"
: "${SECURITY_LOG_MASK_PATTERN:=password|token|key|secret|credential|auth}"

# Define log levels with numeric values for comparison
declare -A LOG_LEVEL_VALUES
LOG_LEVEL_VALUES=([DEBUG]=0 [INFO]=1 [WARNING]=2 [ERROR]=3 [CRITICAL]=4)
readonly LOG_LEVEL_VALUES

# Define ANSI color codes for console output
readonly LOG_COLOR_DEBUG="\033[0;36m"    # Cyan
readonly LOG_COLOR_INFO="\033[0;32m"     # Green
readonly LOG_COLOR_WARNING="\033[0;33m"  # Yellow
readonly LOG_COLOR_ERROR="\033[0;31m"    # Red
readonly LOG_COLOR_CRITICAL="\033[1;31m" # Bold Red
readonly LOG_COLOR_RESET="\033[0m"       # Reset

# ===== Function Definitions =====

# Get the numeric value of a log level
# Arguments:
#   $1: Log level string (DEBUG, INFO, etc.)
# Returns:
#   Numeric value of the log level, or 1 (INFO) if not found
_get_log_level_value() {
    local level="${1:-INFO}"
    echo "${LOG_LEVEL_VALUES[$level]:-1}"
}

# Check if log directory exists and is writable, create if needed
# Returns:
#   0 if successful, 1 otherwise
_ensure_log_directory() {
    # Create log directory if it doesn't exist
    if [[ ! -d "$SECURITY_LOG_DIR" ]]; then
        mkdir -p "$SECURITY_LOG_DIR" 2>/dev/null || {
            echo "ERROR: Failed to create log directory: $SECURITY_LOG_DIR" >&2
            return 1
        }

        # Set secure permissions on the log directory
        chmod 750 "$SECURITY_LOG_DIR" 2>/dev/null || {
            echo "WARNING: Failed to set secure permissions on log directory: $SECURITY_LOG_DIR" >&2
        }
    fi

    # Check if directory is writable
    if [[ ! -w "$SECURITY_LOG_DIR" ]]; then
        echo "ERROR: Log directory is not writable: $SECURITY_LOG_DIR" >&2
        return 1
    fi

    return 0
}

# Initialize the log file with proper permissions
# Returns:
#   0 if successful, 1 otherwise
_initialize_log_file() {
    # Ensure log directory exists
    _ensure_log_directory || return 1

    # Create log file if it doesn't exist
    if [[ ! -f "$SECURITY_LOG_FILE" ]]; then
        touch "$SECURITY_LOG_FILE" 2>/dev/null || {
            echo "ERROR: Failed to create log file: $SECURITY_LOG_FILE" >&2
            return 1
        }

        # Set secure permissions on the log file
        chmod 640 "$SECURITY_LOG_FILE" 2>/dev/null || {
            echo "WARNING: Failed to set secure permissions on log file: $SECURITY_LOG_FILE" >&2
        }
    fi

    # Check if file is writable
    if [[ ! -w "$SECURITY_LOG_FILE" ]]; then
        echo "ERROR: Log file is not writable: $SECURITY_LOG_FILE" >&2
        return 1
    }

    return 0
}

# Rotate log file if it exceeds maximum size
# Returns:
#   0 if successful, 1 otherwise
_rotate_log_file() {
    # Check if log file exists
    [[ ! -f "$SECURITY_LOG_FILE" ]] && return 0

    # Check if rotation is needed based on file size
    local file_size
    file_size=$(stat -c %s "$SECURITY_LOG_FILE" 2>/dev/null || echo 0)

    # If file size is below threshold, no rotation needed
    [[ "$file_size" -lt "$SECURITY_LOG_MAX_SIZE" ]] && return 0

    # Perform rotation
    for ((i=SECURITY_LOG_ROTATE_COUNT-1; i>=0; i--)); do
        local j=$((i+1))
        local current="${SECURITY_LOG_FILE}.${i}"
        local next="${SECURITY_LOG_FILE}.${j}"

        # If current rotation exists, move it to next rotation
        [[ -f "$current" ]] && mv "$current" "$next" 2>/dev/null
    done

    # Move current log to .1
    mv "$SECURITY_LOG_FILE" "${SECURITY_LOG_FILE}.1" 2>/dev/null || {
        echo "WARNING: Failed to rotate log file: $SECURITY_LOG_FILE" >&2
        return 1
    }

    # Create new log file with proper permissions
    _initialize_log_file || return 1

    return 0
}

# Mask sensitive information in log messages
# Arguments:
#   $1: Message to process
# Returns:
#   Message with sensitive information masked
mask_sensitive() {
    local message="$1"
    local pattern="$SECURITY_LOG_MASK_PATTERN"

    # Replace sensitive information with asterisks
    echo "$message" | sed -E "s/($pattern)[=:][^[:space:]]*/\1=******/gi"
}

# Main logging function
# Arguments:
#   $1: Message to log
#   $2: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) - defaults to INFO
#   $3: Context information (optional)
# Returns:
#   0 if successful, non-zero on error
_log() {
    local message="$1"
    local level="${2:-INFO}"
    local context="$3"
    local timestamp
    local log_entry

    # Check if the message should be logged based on configured level
    if [[ $(_get_log_level_value "$level") -lt $(_get_log_level_value "$SECURITY_LOG_LEVEL") ]]; then
        return 0
    fi

    # Generate timestamp
    timestamp=$(date +"$SECURITY_LOG_DATE_FORMAT")

    # Format log entry
    if [[ -n "$context" ]]; then
        log_entry="[$timestamp] [$level] $message | $context"
    else
        log_entry="[$timestamp] [$level] $message"
    fi

    # Output to stdout if enabled
    if [[ "$SECURITY_LOG_USE_STDOUT" == "true" ]]; then
        # Use appropriate color based on log level
        case "$level" in
            DEBUG)
                echo -e "${LOG_COLOR_DEBUG}${log_entry}${LOG_COLOR_RESET}" >&2
                ;;
            INFO)
                echo -e "${LOG_COLOR_INFO}${log_entry}${LOG_COLOR_RESET}" >&2
                ;;
            WARNING)
                echo -e "${LOG_COLOR_WARNING}${log_entry}${LOG_COLOR_RESET}" >&2
                ;;
            ERROR)
                echo -e "${LOG_COLOR_ERROR}${log_entry}${LOG_COLOR_RESET}" >&2
                ;;
            CRITICAL)
                echo -e "${LOG_COLOR_CRITICAL}${log_entry}${LOG_COLOR_RESET}" >&2
                ;;
            *)
                echo -e "${log_entry}" >&2
                ;;
        esac
    fi

    # Output to log file
    if _initialize_log_file; then
        # Rotate log file if needed
        _rotate_log_file

        # Append to log file
        echo "$log_entry" >> "$SECURITY_LOG_FILE" || {
            echo "ERROR: Failed to write to log file: $SECURITY_LOG_FILE" >&2
            return 1
        }
    fi

    # Output to syslog if enabled
    if [[ "$SECURITY_LOG_USE_SYSLOG" == "true" ]] && command -v logger >/dev/null 2>&1; then
        # Map log levels to syslog priorities
        local priority
        case "$level" in
            DEBUG)
                priority="debug"
                ;;
            INFO)
                priority="info"
                ;;
            WARNING)
                priority="warning"
                ;;
            ERROR)
                priority="err"
                ;;
            CRITICAL)
                priority="crit"
                ;;
            *)
                priority="info"
                ;;
        esac

        # Log to syslog with tag
        logger -p "security.$priority" -t "cloud-platform-security" "$message" || {
            echo "WARNING: Failed to write to syslog" >&2
        }
    fi

    return 0
}

# ===== Public Logging Functions =====

# Log a debug message
# Arguments:
#   $1: Message to log
#   $2: Context information (optional)
# Returns:
#   Result of _log function
log_debug() {
    _log "$1" "DEBUG" "$2"
    return $?
}

# Log an informational message
# Arguments:
#   $1: Message to log
#   $2: Context information (optional)
# Returns:
#   Result of _log function
log_info() {
    _log "$1" "INFO" "$2"
    return $?
}

# Log a warning message
# Arguments:
#   $1: Message to log
#   $2: Context information (optional)
# Returns:
#   Result of _log function
log_warning() {
    _log "$1" "WARNING" "$2"
    return $?
}

# Log an error message
# Arguments:
#   $1: Message to log
#   $2: Context information (optional)
# Returns:
#   Result of _log function
log_error() {
    _log "$1" "ERROR" "$2"
    return $?
}

# Log a critical message
# Arguments:
#   $1: Message to log
#   $2: Context information (optional)
# Returns:
#   Result of _log function
log_critical() {
    _log "$1" "CRITICAL" "$2"
    return $?
}

# Get version information for the logging module
# Arguments: None
# Returns:
#   Version string in format "version (date)"
get_logging_version() {
    echo "${SECURITY_LOGGING_VERSION} (${SECURITY_LOGGING_DATE})"
}

# Set the logging level
# Arguments:
#   $1: New log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
# Returns:
#   0 if successful, 1 if invalid level
set_log_level() {
    local new_level="$1"

    # Validate log level
    if [[ -z "${LOG_LEVEL_VALUES[$new_level]}" ]]; then
        log_error "Invalid log level: $new_level. Valid levels are: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        return 1
    fi

    SECURITY_LOG_LEVEL="$new_level"
    log_debug "Log level set to $new_level"
    return 0
}

# Configure log file path
# Arguments:
#   $1: New log file path
# Returns:
#   0 if successful, 1 if directory cannot be created or is not writable
set_log_file() {
    local new_file="$1"

    # Save current log file path
    local old_file="$SECURITY_LOG_FILE"

    # Try setting new log file
    SECURITY_LOG_FILE="$new_file"
    if ! _initialize_log_file; then
        # Restore old log file path if failed
        SECURITY_LOG_FILE="$old_file"
        return 1
    fi

    log_debug "Log file set to $new_file"
    return 0
}

# Enable or disable logging to syslog
# Arguments:
#   $1: true to enable, false to disable
# Returns:
#   0 always
set_syslog_logging() {
    SECURITY_LOG_USE_SYSLOG="$1"
    [[ "$1" == "true" ]] && log_debug "Syslog logging enabled" || log_debug "Syslog logging disabled"
    return 0
}

# Enable or disable logging to stdout
# Arguments:
#   $1: true to enable, false to disable
# Returns:
#   0 always
set_stdout_logging() {
    SECURITY_LOG_USE_STDOUT="$1"
    [[ "$1" == "true" ]] && log_debug "Console logging enabled" || log_debug "Console logging disabled"
    return 0
}

# Log initialization message
log_debug "Logging utility initialized. Version: $(get_logging_version)"
log_debug "Log file: $SECURITY_LOG_FILE"
log_debug "Log level: $SECURITY_LOG_LEVEL"

# Export public functions
export -f log_debug log_info log_warning log_error log_critical
export -f mask_sensitive get_logging_version
export -f set_log_level set_log_file set_syslog_logging set_stdout_logging
