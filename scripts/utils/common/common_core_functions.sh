#!/bin/bash
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

#######################################
# LOGGING FUNCTIONS
#######################################

# Log a message with timestamp and optional log level
# Arguments:
#   $1 - Message to log
#   $2 - Log level (INFO, WARNING, ERROR, DEBUG) - defaults to INFO
#   $3 - Log file (optional - defaults to stdout)
log() {
    local message="$1"
    local level="${2:-INFO}"
    local log_file="${3:-}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    # Format based on log level
    case "$level" in
        INFO)
            local colored_level="${GREEN}INFO${NC}"
            ;;
        WARNING)
            local colored_level="${YELLOW}WARNING${NC}"
            ;;
        ERROR)
            local colored_level="${RED}ERROR${NC}"
            ;;
        DEBUG)
            local colored_level="${BLUE}DEBUG${NC}"
            ;;
        *)
            local colored_level="$level"
            ;;
    esac

    # Format the log message
    local log_message="[$timestamp] [${colored_level}] $message"
    local plain_message="[$timestamp] [$level] $message"

    # Output to console if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo -e "$log_message"
    fi

    # Output to log file if specified
    if [[ -n "$log_file" ]]; then
        echo "$plain_message" >> "$log_file"
    fi
}

# Log an error message and exit
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
#   $3 - Log file (optional)
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    local log_file="${3:-}"

    log "$message" "ERROR" "$log_file"
    exit "$exit_code"
}

# Log a warning message
# Arguments:
#   $1 - Warning message
#   $2 - Log file (optional)
warn() {
    local message="$1"
    local log_file="${2:-}"

    log "$message" "WARNING" "$log_file"
}

# Log a debug message (only when DEBUG=true)
# Arguments:
#   $1 - Debug message
#   $2 - Log file (optional)
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local message="$1"
        local log_file="${2:-}"

        log "$message" "DEBUG" "$log_file"
    fi
}

# Log an important message (highlighted)
# Arguments:
#   $1 - Important message
#   $2 - Log file (optional)
important() {
    local message="$1"
    local log_file="${2:-}"

    log "${BOLD}${message}${NC}" "INFO" "$log_file"
}

#######################################
# ENVIRONMENT FUNCTIONS
#######################################

# Load environment-specific variables from file
# Arguments:
#   $1 - Environment name (e.g., production, staging)
#   $2 - Custom environment file path (optional)
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
    source "$env_file"
    log "Loaded environment configuration from $env_file"
    return 0
}

# Validate if environment is valid
# Arguments:
#   $1 - Environment to validate
#   $2 - Array of valid environments (optional)
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
        log "Invalid environment: $environment" "ERROR"
        log "Valid environments: ${valid_envs[*]}" "ERROR"
        return 1
    fi

    return 0
}

# Get the current environment from ENV variable or hostname
# Returns the detected environment
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
}

#######################################
# VALIDATION FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns: 0 if exists, 1 if not
command_exists() {
    command -v "$1" &>/dev/null
    return $?
}

# Check if a file exists and is readable
# Arguments:
#   $1 - File path
#   $2 - Error message (optional)
# Returns: 0 if exists, 1 if not
file_exists() {
    local file="$1"
    local error_msg="${2:-File does not exist or is not readable: $file}"

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
                        return 1
                    fi
                done

                return 0
            fi
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (simplified)
            if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                return 0
            fi
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            log "Invalid IP type specified: $type. Use 4, 6, or both" "ERROR"
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
        [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
        return $?
    else
        [[ "$value" =~ ^[0-9]+$ ]]
        return $?
    fi
}

# Validate required parameters
# Arguments:
#   Variable number of parameter names to check
# Returns: 0 if all parameters exist, 1 if any are missing
validate_required_params() {
    local missing=0

    for param in "$@"; do
        if [[ -z "${!param:-}" ]]; then
            log "Required parameter missing: $param" "ERROR"
            missing=$((missing + 1))
        fi
    done

    if (( missing > 0 )); then
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
    return 1
}

#######################################
# FILE OPERATIONS
#######################################

# Create a backup of a file
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
# Returns: Path to backup file
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${TIMESTAMP}.bak"

    # Ensure backup directory exists
    mkdir -p "$backup_dir"

    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        warn "Cannot backup file, source does not exist: $file"
        return 1
    fi

    # Create backup
    cp -p "$file" "$backup_file" || {
        warn "Failed to create backup of $file"
        return 1
    }

    log "Backed up $file to $backup_file" "INFO"

    echo "$backup_file"
}

# Create directory if it doesn't exist
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to 755)
# Returns: 0 if created or already exists, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-755}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            log "Failed to create directory: $dir" "ERROR"
            return 1
        }
        chmod "$perms" "$dir" || {
            log "Failed to set permissions $perms on directory: $dir" "ERROR"
            return 1
        }
        log "Created directory: $dir with permissions $perms" "INFO"
    fi

    return 0
}

# Safely write content to a file with error handling
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to 644)
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-644}"
    local temp_file

    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || return 1

    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        backup_file "$output_file" >/dev/null || {
            log "Failed to back up existing file: $output_file" "WARNING"
        }
    fi

    # Write to temporary file first to prevent partial writes
    temp_file=$(mktemp) || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }

    echo "$content" > "$temp_file" || {
        log "Failed to write content to temporary file" "ERROR"
        rm -f "$temp_file"
        return 1
    }

    # Set permissions on temporary file before moving
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }

    # Move temporary file to destination
    mv "$temp_file" "$output_file" || {
        log "Failed to write to $output_file" "ERROR"
        rm -f "$temp_file"
        return 1
    }

    log "Successfully wrote to $output_file" "INFO"
    return 0
}

# Get file age in seconds
# Arguments:
#   $1 - File path
# Returns: File age in seconds or -1 if file not found
file_age() {
    local file="$1"
    local file_time
    local current_time

    if [[ ! -f "$file" ]]; then
        echo "-1"
        return 1
    fi

    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_time=$(stat -f %m "$file")
        else
            # Linux version
            file_time=$(stat -c %Y "$file")
        fi
    else
        # Fallback method using ls
        file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
        if [[ -z "$file_time" ]]; then
            echo "-1"
            return 1
        fi
    fi

    current_time=$(date +%s)
    echo $((current_time - file_time))
}

# Export all functions
export -f log
export -f error_exit
export -f warn
export -f debug
export -f important
export -f load_env
export -f validate_environment
export -f detect_environment
export -f command_exists
export -f file_exists
export -f is_valid_ip
export -f is_number
export -f validate_required_params
export -f is_valid_url
export -f is_valid_email
export -f backup_file
export -f ensure_directory
export -f safe_write_file
export -f file_age
