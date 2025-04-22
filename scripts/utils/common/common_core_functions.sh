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

# Load environment-specific variables from file
# Arguments:
#   $1 - Environment name (e.g., production, staging)
#   $2 - Custom environment file path (optional)
# Returns:
#   0 on success, 1 on failure
load_env() {
    local environment="${1:-$DEFAULT_ENVIRONMENT}"
    local custom_env_file="${2:-}"
    local env_file

    # Use custom file if provided, otherwise use default location
    if [[ -n "$custom_env_file" && -f "$custom_env_file" ]]; then
        env_file="$custom_env_file"
    else
        env_file="${ENV_FILE_DIR}/${environment}.env"
    fi

    # Check if file exists
    if [[ ! -f "$env_file" ]]; then
        warn "Environment file not found: $env_file"
        return 1
    fi

    # Source the environment file
    # shellcheck source=/dev/null
    source "$env_file" || {
        error_exit "Failed to load environment from file: $env_file" 1
    }

    log "Successfully loaded environment configuration from $env_file"
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

    debug "Detected environment: $(echo $DEFAULT_ENVIRONMENT)"
    return 0
}

#######################################
# VALIDATION FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns:
#   0 if exists, 1 if not
command_exists() {
    local cmd="$1"
    command -v "$cmd" &>/dev/null
    local result=$?

    if [[ $result -ne 0 ]]; then
        debug "Command not found: $cmd"
    fi

    return $result
}

# Check if a file exists and is readable
# Arguments:
#   $1 - File path
#   $2 - Error message (optional)
# Returns:
#   0 if exists, 1 if not
file_exists() {
    local file="$1"
    local error_msg="${2:-$ERROR_PREFIX File does not exist or is not readable: $file}"

    if [[ ! -r "$file" ]]; then
        log "$error_msg" "ERROR"
        return 1
    fi

    return 0
}

# Validate if a string is a valid IP address
# Arguments:
#   $1 - String to validate
#   $2 - Type (4 for IPv4, 6 for IPv6, both if not specified)
# Returns: 0 if valid, 1 if not
is_valid_ip() {
    local ip="$1"
    local type="${2:-both}"

    case "$type" in
        4|ipv4)
            # IPv4 validation
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local IFS='.'
                read -ra ip_array <<< "$ip"

                for octet in "${ip_array[@]}"; do
                    if (( octet < 0 || octet > 255 )); then
                        debug "$ERROR_PREFIX Invalid IPv4 address: $ip (octet out of range)"
                        return 1
                    fi
                done

                return 0
            fi
            debug "$ERROR_PREFIX Invalid IPv4 format: $ip"
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (simplified)
            if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                return 0
            fi
            debug "$ERROR_PREFIX Invalid IPv6 format: $ip"
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                debug "$ERROR_PREFIX Invalid IP address (neither IPv4 nor IPv6): $ip"
                return 1
            fi
            ;;
        *)
            error_exit "Invalid IP type specified: $type. Use 4, 6, or both"
            return 1
            ;;
    esac
}

# Check if a value is a number
# Arguments:
#   $1 - Value to check
#   $2 - Allow floating point (true/false, defaults to false)
# Returns: 0 if numeric, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"

    if [[ "$allow_float" == "true" ]]; then
        if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            return 0
        else
            debug "$ERROR_PREFIX Not a valid floating point number: $value"
            return 1
        fi
    else
        if [[ "$value" =~ ^[0-9]+$ ]]; then
            return 0
        else
            debug "$ERROR_PREFIX Not a valid integer: $value"
            return 1
        fi
    fi
}

# Validate required parameters
# Arguments:
#   Variable number of parameter names to check
# Returns: 0 if all parameters exist, 1 if any are missing
validate_required_params() {
    local missing=0
    local missing_params=""

    for param in "$@"; do
        if [[ -z "${!param:-}" ]]; then
            missing=$((missing + 1))
            missing_params="$missing_params $param"
        fi
    done

    if (( missing > 0 )); then
        error_exit "Required parameter(s) missing:$missing_params"
        return 1
    fi

    return 0
}

# Validate a URL format
# Arguments:
#   $1 - URL to validate
# Returns: 0 if valid, 1 if not
is_valid_url() {
    local url="$1"

    # Basic URL validation - requires http:// or https:// prefix
    if [[ "$url" =~ ^https?:// ]]; then
        return 0
    fi

    debug "$ERROR_PREFIX Invalid URL format: $url (must start with http:// or https://)"
    return 1
}

# Validate email format
# Arguments:
#   $1 - Email to validate
# Returns: 0 if valid, 1 if not
is_valid_email() {
    local email="$1"

    # Basic email validation
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi

    debug "$ERROR_PREFIX Invalid email format: $email"
    return 1
}

#######################################
# FILE OPERATIONS
#######################################

# Create a backup of a file
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
# Returns: Path to backup file on success, 1 on failure
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${TIMESTAMP}.bak"

    # Ensure backup directory exists
    mkdir -p "$backup_dir" 2>/dev/null || {
        error_exit "Failed to create backup directory: $backup_dir"
        return 1
    }

    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        error_exit "Cannot backup file, source does not exist: $file"
        return 1
    fi

    # Create backup
    cp -p "$file" "$backup_file" 2>/dev/null || {
        error_exit "Failed to create backup of $file to $backup_file"
        return 1
    }

    log "Created backup of $file at $backup_file" "INFO"

    echo "$backup_file"
    return 0
}

# Create directory if it doesn't exist
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to DEFAULT_DIR_PERMS)
# Returns: 0 if created or already exists, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-$DEFAULT_DIR_PERMS}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" 2>/dev/null || {
            error_exit "Failed to create directory: $dir"
            return 1
        }

        chmod "$perms" "$dir" 2>/dev/null || {
            error_exit "Failed to set permissions $perms on directory: $dir"
            return 1
        }

        debug "Created directory: $dir with permissions $perms"
    fi

    return 0
}

# Safely write content to a file with error handling
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to DEFAULT_FILE_PERMS)
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-$DEFAULT_FILE_PERMS}"
    local temp_file

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || {
        error_exit "Failed to ensure parent directory exists for: $output_file"
        return 1
    }

    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        backup_file "$output_file" >/dev/null || {
            warn "Failed to back up existing file: $output_file (continuing anyway)"
        }
    fi

    # Write to temporary file first to prevent partial writes
    temp_file=$(mktemp) || {
        error_exit "Failed to create temporary file"
        return 1
    }

    echo "$content" > "$temp_file" || {
        error_exit "Failed to write content to temporary file"
        rm -f "$temp_file"
        return 1
    }

    # Set permissions on temporary file before moving
    chmod "$perms" "$temp_file" || {
        warn "Failed to set permissions on temporary file (continuing anyway)"
    }

    # Move temporary file to destination
    mv "$temp_file" "$output_file" || {
        error_exit "Failed to write to final destination: $output_file"
        rm -f "$temp_file"
        return 1
    }

    log "Successfully wrote content to $output_file" "INFO"
    return 0
}

# Get file age in seconds
# Arguments:
#   $1 - File path
# Returns: File age in seconds or -1 if file not found/error
file_age() {
    local file="$1"
    local file_time
    local current_time

    if [[ ! -f "$file" ]]; then
        warn "Cannot get age of non-existent file: $file"
        echo "-1"
        return 1
    fi

    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_time=$(stat -f %m "$file" 2>/dev/null) || {
                error_exit "Failed to get file modification time: $file"
                echo "-1"
                return 1
            }
        else
            # Linux version
            file_time=$(stat -c %Y "$file" 2>/dev/null) || {
                error_exit "Failed to get file modification time: $file"
                echo "-1"
                return 1
            }
        fi
    else
        # Fallback method using ls
        file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
        if [[ -z "$file_time" ]]; then
            error_exit "Failed to get file modification time using fallback method: $file"
            echo "-1"
            return 1
        fi
    fi

    current_time=$(date +%s)
    echo $((current_time - file_time))
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

# Export environment functions
export -f load_env
export -f validate_environment
export -f detect_environment

# Export validation functions
export -f command_exists
export -f file_exists
export -f is_valid_ip
export -f is_number
export -f validate_required_params
export -f is_valid_url
export -f is_valid_email

# Export file operations functions
export -f backup_file
export -f ensure_directory
export -f safe_write_file
export -f file_age

# Export error message prefixes
export ERROR_PREFIX
export WARNING_PREFIX
export INFO_PREFIX
export DEBUG_PREFIX
