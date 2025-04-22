#!/bin/bash
# filepath: scripts/utils/common/common_core_functions.sh
# Core utility functions for Cloud Infrastructure Platform
# These functions are commonly needed by most scripts

# Check that this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    exit 1
fi

# Check if required variables are defined
if [[ -z "$SCRIPT_DIR" || -z "$DEFAULT_LOG_DIR" ]]; then
    echo "Warning: This module should be loaded through common_functions.sh"
    # Define fallback values
    SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)}"
    DEFAULT_LOG_DIR="${DEFAULT_LOG_DIR:-/var/log/cloud-platform}"
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
fi

# Define default file permissions
DEFAULT_FILE_PERMS="644"
DEFAULT_DIR_PERMS="755"
DEFAULT_LOG_FILE_PERMS="640"  # More restrictive for log files
DEFAULT_LOG_DIR_PERMS="750"   # More restrictive for log directories

# Define log file settings
DEFAULT_LOG_MAX_SIZE="10M"    # Maximum log file size before rotation
DEFAULT_LOG_BACKUPS=5         # Number of rotated backups to keep

# Define error message prefixes for consistency
ERROR_PREFIX="Error:"
WARNING_PREFIX="Warning:"
INFO_PREFIX="Info:"
DEBUG_PREFIX="Debug:"

#######################################
# LOGGING FUNCTIONS
#######################################

# Ensure log directory exists with proper permissions
# Arguments:
#   $1 - Log directory path
# Returns:
#   0 on success, 1 on failure
ensure_log_directory() {
    local log_dir="$1"

    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || {
            echo -e "${RED}${ERROR_PREFIX} Failed to create log directory: $log_dir${NC}"
            return 1
        }

        chmod "$DEFAULT_LOG_DIR_PERMS" "$log_dir" 2>/dev/null || {
            echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on log directory: $log_dir${NC}"
            # Continue despite permission warning
        }

        debug "Created log directory: $log_dir with permissions $DEFAULT_LOG_DIR_PERMS"
    fi

    # Check if directory is writable
    if [[ ! -w "$log_dir" ]]; then
        echo -e "${RED}${ERROR_PREFIX} Log directory is not writable: $log_dir${NC}"
        return 1
    }

    return 0
}

# Check if log file needs rotation based on size
# Arguments:
#   $1 - Log file path
#   $2 - Max size (optional, defaults to DEFAULT_LOG_MAX_SIZE)
# Returns:
#   0 if rotation needed, 1 if not
needs_rotation() {
    local log_file="$1"
    local max_size="${2:-$DEFAULT_LOG_MAX_SIZE}"

    # If file doesn't exist, no rotation needed
    if [[ ! -f "$log_file" ]]; then
        return 1
    }

    local size_in_bytes
    local max_size_in_bytes

    # Get file size in bytes
    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            size_in_bytes=$(stat -f%z "$log_file" 2>/dev/null)
        else
            # Linux
            size_in_bytes=$(stat -c%s "$log_file" 2>/dev/null)
        fi
    else
        # Fallback using ls
        size_in_bytes=$(ls -l "$log_file" 2>/dev/null | awk '{ print $5 }')
    fi

    # Parse max size string to bytes (e.g., 10M, 1G)
    if [[ "$max_size" =~ ^([0-9]+)([KMG]?)$ ]]; then
        local num="${BASH_REMATCH[1]}"
        local unit="${BASH_REMATCH[2]}"

        case "$unit" in
            K) max_size_in_bytes=$((num * 1024)) ;;
            M) max_size_in_bytes=$((num * 1024 * 1024)) ;;
            G) max_size_in_bytes=$((num * 1024 * 1024 * 1024)) ;;
            *) max_size_in_bytes=$num ;;
        esac
    else
        # Default to 10MB if invalid format
        max_size_in_bytes=$((10 * 1024 * 1024))
    fi

    # Compare sizes
    if (( size_in_bytes > max_size_in_bytes )); then
        return 0  # Rotation needed
    else
        return 1  # No rotation needed
    fi
}

# Rotate a log file if it exceeds the maximum size
# Arguments:
#   $1 - Log file path
#   $2 - Max size (optional, defaults to DEFAULT_LOG_MAX_SIZE)
#   $3 - Number of backups to keep (optional, defaults to DEFAULT_LOG_BACKUPS)
# Returns:
#   0 on success, 1 on failure
rotate_log_file() {
    local log_file="$1"
    local max_size="${2:-$DEFAULT_LOG_MAX_SIZE}"
    local max_backups="${3:-$DEFAULT_LOG_BACKUPS}"

    # Check if file exists
    if [[ ! -f "$log_file" ]]; then
        return 0  # Nothing to rotate
    }

    # Check if rotation is needed
    if ! needs_rotation "$log_file" "$max_size"; then
        return 0  # No rotation needed
    }

    debug "Rotating log file: $log_file (exceeded max size: $max_size)"

    # Remove oldest backup if we have reached max backups
    if [[ -f "${log_file}.${max_backups}" ]]; then
        rm -f "${log_file}.${max_backups}" || {
            warn "Failed to remove oldest log backup: ${log_file}.${max_backups}"
        }
    fi

    # Shift all existing backups
    for (( i=max_backups-1; i>=1; i-- )); do
        local j=$((i + 1))
        if [[ -f "${log_file}.${i}" ]]; then
            mv "${log_file}.${i}" "${log_file}.${j}" 2>/dev/null || {
                warn "Failed to rotate log backup: ${log_file}.${i} -> ${log_file}.${j}"
            }
        fi
    done

    # Move current log to .1
    mv "$log_file" "${log_file}.1" 2>/dev/null || {
        warn "Failed to rotate current log file: $log_file -> ${log_file}.1"
        return 1
    }

    # Create new empty log file with correct permissions
    touch "$log_file" 2>/dev/null && chmod "$DEFAULT_LOG_FILE_PERMS" "$log_file" 2>/dev/null || {
        error_exit "Failed to create new log file after rotation: $log_file"
        return 1
    }

    log "Log file rotated successfully: $log_file"
    return 0
}

# Initialize a log file with proper permissions
# Arguments:
#   $1 - Log file path
# Returns:
#   0 on success, 1 on failure
init_log_file() {
    local log_file="$1"

    # Ensure log directory exists with proper permissions
    local log_dir=$(dirname "$log_file")
    ensure_log_directory "$log_dir" || return 1

    # If file doesn't exist, create it with proper permissions
    if [[ ! -f "$log_file" ]]; then
        touch "$log_file" 2>/dev/null || {
            echo -e "${RED}${ERROR_PREFIX} Failed to create log file: $log_file${NC}"
            return 1
        }

        chmod "$DEFAULT_LOG_FILE_PERMS" "$log_file" 2>/dev/null || {
            echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on log file: $log_file${NC}"
            # Continue despite permission warning
        }

        debug "Created log file: $log_file with permissions $DEFAULT_LOG_FILE_PERMS"
    } else {
        # If file exists but isn't writable, try to fix permissions
        if [[ ! -w "$log_file" ]]; then
            chmod u+w "$log_file" 2>/dev/null || {
                echo -e "${RED}${ERROR_PREFIX} Log file exists but is not writable: $log_file${NC}"
                return 1
            }
            debug "Fixed permissions on existing log file: $log_file"
        }
    }

    return 0
}

# Log a message with timestamp and optional log level
# Arguments:
#   $1 - Message to log
#   $2 - Log level (INFO, WARNING, ERROR, DEBUG) - defaults to INFO
#   $3 - Log file (optional - defaults to stdout)
#   $4 - Max log file size (optional - defaults to DEFAULT_LOG_MAX_SIZE)
# Returns:
#   0 on success, 1 on failure
log() {
    local message="$1"
    local level="${2:-INFO}"
    local log_file="${3:-}"
    local max_size="${4:-$DEFAULT_LOG_MAX_SIZE}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local status=0

    # Format based on log level
    case "$level" in
        INFO)
            local colored_level="${GREEN}INFO${NC}"
            local prefix="$INFO_PREFIX"
            ;;
        WARNING)
            local colored_level="${YELLOW}WARNING${NC}"
            local prefix="$WARNING_PREFIX"
            ;;
        ERROR)
            local colored_level="${RED}ERROR${NC}"
            local prefix="$ERROR_PREFIX"
            ;;
        DEBUG)
            local colored_level="${BLUE}DEBUG${NC}"
            local prefix="$DEBUG_PREFIX"
            ;;
        *)
            local colored_level="$level"
            local prefix=""
            ;;
    esac

    # Format the log message - add prefix to message for non-empty prefixes
    local prefixed_message="$message"
    if [[ -n "$prefix" && "$message" != "$prefix"* ]]; then
        prefixed_message="$prefix $message"
    fi

    local log_message="[$timestamp] [${colored_level}] $prefixed_message"
    local plain_message="[$timestamp] [$level] $prefixed_message"

    # Output to console if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo -e "$log_message"
    fi

    # Output to log file if specified
    if [[ -n "$log_file" ]]; then
        # Before writing, check if we need to initialize/rotate the log file
        if [[ ! -f "$log_file" ]]; then
            init_log_file "$log_file" || status=1
        } else {
            # Check for rotation if file exists
            rotate_log_file "$log_file" "$max_size" || status=1
        }

        if [[ $status -eq 0 ]]; then
            # Ensure log directory exists (initial write or after rotation)
            local log_dir=$(dirname "$log_file")
            ensure_log_directory "$log_dir" || status=1

            if [[ $status -eq 0 ]]; then
                # Append to log file
                echo "$plain_message" >> "$log_file" 2>/dev/null || {
                    echo -e "${RED}${ERROR_PREFIX} Failed to write to log file: $log_file${NC}"
                    status=1
                }
            }
        }
    } elif [[ -n "$DEFAULT_LOG_FILE" ]]; then
        # Use default log file if set
        log "$message" "$level" "$DEFAULT_LOG_FILE" "$max_size"
        status=$?
    }

    return $status
}

# Configure default log file to use for all logging functions
# Arguments:
#   $1 - Default log file path
#   $2 - Create directory if it doesn't exist (true/false, defaults to true)
#   $3 - Max log file size (optional - defaults to DEFAULT_LOG_MAX_SIZE)
# Returns:
#   0 on success, 1 on failure
set_default_log_file() {
    local log_file="$1"
    local create_dir="${2:-true}"
    local max_size="${3:-$DEFAULT_LOG_MAX_SIZE}"

    if [[ -z "$log_file" ]]; then
        unset DEFAULT_LOG_FILE
        return 0
    }

    if [[ "$create_dir" == "true" ]]; then
        local log_dir=$(dirname "$log_file")
        ensure_log_directory "$log_dir" || return 1
    }

    # Initialize log file
    init_log_file "$log_file" || return 1

    # Check for rotation
    rotate_log_file "$log_file" "$max_size" || return 1

    export DEFAULT_LOG_FILE="$log_file"
    debug "Set default log file to: $DEFAULT_LOG_FILE"

    return 0
}

# Log an error message and exit
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
#   $3 - Log file (optional, defaults to DEFAULT_LOG_FILE if set)
# Returns:
#   Does not return if called directly, exits with specified code
#   Returns exit code if sourced
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    local log_file="${3:-${DEFAULT_LOG_FILE:-}}"

    # Ensure message has error prefix
    if [[ "$message" != "$ERROR_PREFIX"* ]]; then
        message="$ERROR_PREFIX $message"
    }

    # Use log function which already handles log directory creation
    log "$message" "ERROR" "$log_file"

    # Only exit if this is a script, not sourced
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        exit "$exit_code"
    } else {
        return "$exit_code"
    }
}

# Export logging functions and constants
export -f ensure_log_directory
export -f init_log_file
export -f needs_rotation
export -f rotate_log_file
export -f set_default_log_file
export -f log
export -f error_exit
export -f warn
export -f debug
export -f important
export DEFAULT_LOG_FILE_PERMS
export DEFAULT_LOG_DIR_PERMS
export DEFAULT_LOG_MAX_SIZE
export DEFAULT_LOG_BACKUPS
