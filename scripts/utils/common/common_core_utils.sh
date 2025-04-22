#!/bin/bash
# filepath: scripts/utils/common/common_core_utils.sh
# Core utility functions for Cloud Infrastructure Platform
# These functions are commonly needed by most scripts
#
# Provides logging and environment management functions
# that can be reused across multiple scripts.

# Version tracking
CORE_UTILS_VERSION="1.1.0"
CORE_UTILS_DATE="2024-07-18"

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
DEFAULT_SECRET_FILE_PERMS="600"  # Restrictive - contains sensitive information

# Define log file settings
DEFAULT_LOG_MAX_SIZE="10M"    # Maximum log file size before rotation
DEFAULT_LOG_BACKUPS=5         # Number of rotated backups to keep

# Define error message prefixes for consistency
ERROR_PREFIX="Error:"
WARNING_PREFIX="Warning:"
INFO_PREFIX="Info:"
DEBUG_PREFIX="Debug:"

# Get version information for these utilities
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_core_utils_version() {
    echo "${CORE_UTILS_VERSION} (${CORE_UTILS_DATE})"
}

#######################################
# LOGGING FUNCTIONS
#######################################

# Initialize a log file with proper permissions
# Arguments:
#   $1 - Log file path
# Returns:
#   0 on success, 1 on failure
init_log_file() {
    local log_file="$1"
    local log_dir

    log_dir=$(dirname "$log_file")

    # Ensure log directory exists
    ensure_log_directory "$log_dir" || return 1

    # Create empty file with correct permissions
    touch "$log_file" 2>/dev/null || {
        echo -e "${RED}${ERROR_PREFIX} Failed to create log file: $log_file${NC}"
        return 1
    }

    chmod "$DEFAULT_LOG_FILE_PERMS" "$log_file" 2>/dev/null || {
        echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on log file: $log_file${NC}"
        # Continue despite permission warning
    }

    return 0
}

# Rotate a log file if it exceeds specified size
# Arguments:
#   $1 - Log file path
#   $2 - Max size (e.g., 10M, 1G)
# Returns:
#   0 on success, 1 on failure
rotate_log_file() {
    local log_file="$1"
    local max_size="$2"

    # Check if log file exists
    if [[ ! -f "$log_file" ]]; then
        return 0  # Nothing to rotate
    fi

    # Parse max_size
    local size_num size_unit
    size_num=$(echo "$max_size" | sed -e 's/[^0-9].*$//')
    size_unit=$(echo "$max_size" | sed -e 's/^[0-9]*//')

    # Convert to bytes
    local max_bytes
    case "$size_unit" in
        K|k) max_bytes=$((size_num * 1024)) ;;
        M|m) max_bytes=$((size_num * 1024 * 1024)) ;;
        G|g) max_bytes=$((size_num * 1024 * 1024 * 1024)) ;;
        *)   max_bytes="$size_num" ;;
    esac

    # Get current file size
    local file_size
    if command -v stat &>/dev/null; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            file_size=$(stat -f%z "$log_file" 2>/dev/null)
        else
            # Linux
            file_size=$(stat -c%s "$log_file" 2>/dev/null)
        fi
    else
        # Fallback: get size using ls -l
        file_size=$(ls -l "$log_file" 2>/dev/null | awk '{print $5}')
    fi

    # Check if we need to rotate
    if [[ -z "$file_size" || "$file_size" -lt "$max_bytes" ]]; then
        return 0  # No rotation needed
    fi

    # Perform rotation
    local i
    for ((i=DEFAULT_LOG_BACKUPS; i>0; i--)); do
        local j=$((i-1))
        if [[ "$j" -eq 0 ]]; then
            # Rotate current file
            if ! mv "$log_file" "${log_file}.1" 2>/dev/null; then
                echo -e "${YELLOW}${WARNING_PREFIX} Failed to rotate log file: $log_file${NC}"
                return 1
            fi
        else
            # Rotate backup files
            if [[ -f "${log_file}.$j" ]]; then
                if ! mv "${log_file}.$j" "${log_file}.$i" 2>/dev/null; then
                    echo -e "${YELLOW}${WARNING_PREFIX} Failed to rotate log backup: ${log_file}.$j${NC}"
                    # Continue with other rotations
                fi
            fi
        fi
    done

    # Create new empty log file
    init_log_file "$log_file" || return 1

    return 0
}

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
    fi

    return 0
}

# Write content to a file safely with proper permissions
# Arguments:
#   $1 - Content to write
#   $2 - File to write to
#   $3 - Use temporary file for atomic write (boolean, optional - defaults to true)
#   $4 - File permissions (optional - defaults to DEFAULT_FILE_PERMS)
# Returns:
#   0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local file="$2"
    local use_temp="${3:-true}"
    local perms="${4:-$DEFAULT_FILE_PERMS}"
    local dir

    dir=$(dirname "$file")

    # Ensure directory exists
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" 2>/dev/null || {
            echo -e "${RED}${ERROR_PREFIX} Failed to create directory: $dir${NC}"
            return 1
        }
        chmod "$DEFAULT_DIR_PERMS" "$dir" 2>/dev/null || {
            echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on directory: $dir${NC}"
            # Continue despite permission warning
        }
    fi

    if [[ "$use_temp" == "true" ]]; then
        # Write to temporary file and move atomically
        local temp_file
        temp_file=$(mktemp) || {
            echo -e "${RED}${ERROR_PREFIX} Failed to create temporary file${NC}"
            return 1
        }

        echo -e "$content" > "$temp_file" || {
            echo -e "${RED}${ERROR_PREFIX} Failed to write to temporary file${NC}"
            rm -f "$temp_file"
            return 1
        }

        chmod "$perms" "$temp_file" 2>/dev/null || {
            echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on temporary file${NC}"
            # Continue despite permission warning
        }

        mv "$temp_file" "$file" || {
            echo -e "${RED}${ERROR_PREFIX} Failed to move temporary file to: $file${NC}"
            rm -f "$temp_file"
            return 1
        }
    else
        # Write directly
        echo -e "$content" > "$file" || {
            echo -e "${RED}${ERROR_PREFIX} Failed to write to file: $file${NC}"
            return 1
        }

        chmod "$perms" "$file" 2>/dev/null || {
            echo -e "${YELLOW}${WARNING_PREFIX} Failed to set permissions on file: $file${NC}"
            # Continue despite permission warning
        }
    fi

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
    case "${level^^}" in
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
    local plain_message="[$timestamp] [${level^^}] $prefixed_message"

    # Output to console if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo -e "$log_message"
    fi

    # Output to log file if specified
    if [[ -n "$log_file" ]]; then
        # Before writing, check if we need to initialize/rotate the log file
        if [[ ! -f "$log_file" ]]; then
            init_log_file "$log_file" || status=1
        else
            # Check for rotation if file exists
            rotate_log_file "$log_file" "$max_size" || status=1
        fi

        if [[ $status -eq 0 ]]; then
            # Append to log file
            echo "$plain_message" >> "$log_file" 2>/dev/null || {
                echo -e "${RED}${ERROR_PREFIX} Failed to write to log file: $log_file${NC}"
                status=1
            }
        fi
    elif [[ -n "$DEFAULT_LOG_FILE" ]]; then
        # Use default log file if set
        log "$message" "$level" "$DEFAULT_LOG_FILE" "$max_size"
        status=$?
    fi

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
    fi

    # Use log function which already handles log directory creation
    log "$message" "ERROR" "$log_file"

    # Only exit if this is a script, not sourced
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        exit "$exit_code"
    else
        return "$exit_code"
    fi
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
    fi

    return 0
}

# Load environment variables from file
# Arguments:
#   $1 - Environment file path
# Returns:
#   0 on success, 1 on failure
load_env() {
    local env_file="$1"

    if [[ ! -f "$env_file" ]]; then
        error_exit "Environment file does not exist: $env_file"
        return 1
    fi

    if [[ ! -r "$env_file" ]]; then
        error_exit "Environment file is not readable: $env_file"
        return 1
    }

    # Source the environment file
    set -a
    source "$env_file" 2>/dev/null || {
        error_exit "Failed to load environment file: $env_file"
        set +a
        return 1
    }
    set +a

    debug "Loaded environment variables from $env_file"
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
        env_file="${ENV_FILE_DIR:-${SCRIPT_DIR}/env}/${environment}.env"
        ensure_env_directory "$(dirname "$env_file")" || return 1
    }

    # Generate file content
    content="# Environment configuration for: $environment\n"
    content+="# Generated: $(date "+%Y-%m-%d %H:%M:%S")\n\n"

    # Get all key-value pairs from array
    local keys
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
    elif [[ -f "${ENV_FILE_DIR:-${SCRIPT_DIR}/env}/environment_map.txt" ]]; then
        # Try to find in environment mapping file
        local envmap="${ENV_FILE_DIR:-${SCRIPT_DIR}/env}/environment_map.txt"
        grep -i "^$hostname=" "$envmap" | cut -d'=' -f2 || echo "${DEFAULT_ENVIRONMENT:-development}"
    else
        echo "${DEFAULT_ENVIRONMENT:-development}"
    fi

    debug "Detected environment based on hostname: $hostname"
    return 0
}

# Export core functions and constants
export -f get_core_utils_version

# Export logging functions and constants
export -f init_log_file
export -f rotate_log_file
export -f ensure_log_directory
export -f safe_write_file
export -f log
export -f error_exit
export -f warn
export -f debug
export -f important
export DEFAULT_LOG_FILE_PERMS
export DEFAULT_LOG_DIR_PERMS
export DEFAULT_LOG_MAX_SIZE
export DEFAULT_LOG_BACKUPS

# Export environment functions and constants
export -f ensure_env_directory
export -f load_env
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
