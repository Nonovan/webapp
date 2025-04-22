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

# Log a warning message
# Arguments:
#   $1 - Warning message
#   $2 - Log file (optional, defaults to DEFAULT_LOG_FILE if set)
# Returns:
#   0 on success, 1 if logging fails
warn() {
    local message="$1"
    local log_file="${2:-${DEFAULT_LOG_FILE:-}}"

    # Ensure message has warning prefix
    if [[ "$message" != "$WARNING_PREFIX"* ]]; then
        message="$WARNING_PREFIX $message"
    fi

    log "$message" "WARNING" "$log_file"
    return $?
}

# Log a debug message (only when DEBUG=true)
# Arguments:
#   $1 - Debug message
#   $2 - Log file (optional, defaults to DEFAULT_LOG_FILE if set)
# Returns:
#   0 on success, 1 if logging fails
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local message="$1"
        local log_file="${2:-${DEFAULT_LOG_FILE:-}}"

        # Ensure message has debug prefix
        if [[ "$message" != "$DEBUG_PREFIX"* ]]; then
            message="$DEBUG_PREFIX $message"
        fi

        log "$message" "DEBUG" "$log_file"
        return $?
    fi
    return 0
}

# Log an important message (highlighted)
# Arguments:
#   $1 - Important message
#   $2 - Log file (optional, defaults to DEFAULT_LOG_FILE if set)
# Returns:
#   0 on success, 1 if logging fails
important() {
    local message="$1"
    local log_file="${2:-${DEFAULT_LOG_FILE:-}}"

    # Ensure message has info prefix
    if [[ "$message" != "$INFO_PREFIX"* ]]; then
        message="$INFO_PREFIX $message"
    fi

    log "${BOLD}${message}${NC}" "INFO" "$log_file"
    return $?
}

#######################################
# ENVIRONMENT FUNCTIONS
#######################################

# Define environment file permissions
DEFAULT_ENV_FILE_PERMS="600"  # Restrictive - contains sensitive information
DEFAULT_ENV_DIR_PERMS="750"   # Restrictive directory permissions

# Ensure environment directory exists with proper permissions
# Arguments:
#   $1 - Environment directory path
# Returns:
#   0 on success, 1 on failure
ensure_env_directory() {
    local env_dir="$1"

    if [[ ! -d "$env_dir" ]]; then
        mkdir -p "$env_dir" 2>/dev/null || {
            error_exit "Failed to create environment directory: $env_dir"
            return 1
        }

        chmod "$DEFAULT_ENV_DIR_PERMS" "$env_dir" 2>/dev/null || {
            warn "Failed to set permissions on environment directory: $env_dir (continuing anyway)"
        }

        debug "Created environment directory: $env_dir with permissions $DEFAULT_ENV_DIR_PERMS"
    fi

    # Check if directory is writable
    if [[ ! -w "$env_dir" ]]; then
        error_exit "Environment directory is not writable: $env_dir"
        return 1
    }

    return 0
}

# Save environment variables to file
# Arguments:
#   $1 - Environment name (e.g., production, staging)
#   $2 - Associative array name containing variables to save
#   $3 - Custom environment file path (optional)
# Returns:
#   0 on success, 1 on failure
save_env() {
    local environment="$1"
    local array_name="$2"
    local custom_env_file="${3:-}"
    local env_file
    local content=""

    # Validate parameters
    if [[ -z "$environment" || -z "$array_name" ]]; then
        error_exit "save_env: Missing required parameters"
        return 1
    }

    # Check if array exists
    eval "declare -p $array_name &>/dev/null" || {
        error_exit "save_env: Array $array_name does not exist"
        return 1
    }

    # Use custom file if provided, otherwise use default location
    if [[ -n "$custom_env_file" ]]; then
        env_file="$custom_env_file"
    else
        ensure_env_directory "$ENV_FILE_DIR" || return 1
        env_file="${ENV_FILE_DIR}/${environment}.env"
    }

    # Generate file content
    content="# Environment configuration for: $environment\n"
    content+="# Generated: $(date "+%Y-%m-%d %H:%M:%S")\n\n"

    # Get all key-value pairs from array
    local keys values
    eval "keys=(\"\${!$array_name[@]}\")"

    # Sort keys alphabetically for consistency
    IFS=$'\n' sorted_keys=($(sort <<<"${keys[*]}"))
    unset IFS

    # Add each key-value pair to content
    for key in "${sorted_keys[@]}"; do
        eval "value=\"\${$array_name[$key]}\""
        content+="$key=\"$value\"\n"
    done

    # Write to file with restricted permissions
    safe_write_file "$content" "$env_file" true "$DEFAULT_ENV_FILE_PERMS" || {
        error_exit "Failed to save environment configuration to file: $env_file"
        return 1
    }

    log "Successfully saved environment configuration to $env_file"
    return 0
}

# Validate if environment is valid
# Arguments:
#   $1 - Environment to validate
#   $2 - Array of valid environments (optional)
# Returns:
#   0 if valid, 1 if invalid
validate_environment() {
    local environment="$1"
    shift
    local valid_envs=("${@:-development staging production dr-recovery}")

    local valid=false
    for env in "${valid_envs[@]}"; do
        if [[ "$environment" == "$env" ]]; then
            valid=true
            break
        fi
    done

    if [[ "$valid" == "false" ]]; then
        error_exit "Invalid environment: $environment. Valid environments: ${valid_envs[*]}"
        return 1
    fi

    return 0
}

# Get the current environment from ENV variable or hostname
# Arguments:
#   None
# Returns:
#   Outputs detected environment name to stdout
#   0 on success
detect_environment() {
    # If ENV is set, use it
    if [[ -n "${ENV:-}" ]]; then
        echo "$ENV"
        return 0
    fi

    # Try to detect from hostname
    local hostname=$(hostname -f 2>/dev/null || hostname)
    if [[ "$hostname" =~ (^|[-\.])prod($|[-\.]) || "$hostname" =~ production ]]; then
        echo "production"
    elif [[ "$hostname" =~ (^|[-\.])stg($|[-\.]) || "$hostname" =~ staging ]]; then
        echo "staging"
    elif [[ "$hostname" =~ (^|[-\.])dev($|[-\.]) || "$hostname" =~ development ]]; then
        echo "development"
    elif [[ "$hostname" =~ (^|[-\.])dr($|[-\.]) ]]; then
        echo "dr-recovery"
    elif [[ -f "${ENV_FILE_DIR}/environment_map.txt" ]]; then
        # Try to find in environment mapping file
        grep -i "^$hostname=" "${ENV_FILE_DIR}/environment_map.txt" | cut -d'=' -f2 || echo "$DEFAULT_ENVIRONMENT"
    else
        echo "$DEFAULT_ENVIRONMENT"
    fi

    debug "Detected environment based on hostname: $hostname"
    return 0
}





# Export logging functions and constants
export -f ensure_log_directory
export -f log
export -f error_exit
export -f warn
export -f debug
export -f important
export DEFAULT_LOG_FILE_PERMS
export DEFAULT_LOG_DIR_PERMS

# Export environment functions and constants
export -f ensure_env_directory
export -f save_env
export -f validate_environment
export -f detect_environment
export DEFAULT_ENV_FILE_PERMS
export DEFAULT_ENV_DIR_PERMS

# Export error message prefixes
export ERROR_PREFIX
export WARNING_PREFIX
export INFO_PREFIX
export DEBUG_PREFIX
