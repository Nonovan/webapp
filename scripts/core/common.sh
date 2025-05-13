#!/bin/bash
# filepath: scripts/core/common.sh
#
# Core shell utility functions for Cloud Infrastructure Platform
#
# This script provides fundamental utilities for shell scripts across the platform
# including logging, error handling, environment detection, file operations,
# and various helper functions.
#
# Usage: source "$(dirname "$0")/common.sh"
#
# Version: 0.0.1
# Date: 2024-08-20

# Ensure the script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script should be sourced, not executed directly."
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

#######################################
# CONFIGURATION AND CONSTANTS
#######################################

# Version tracking
readonly COMMON_VERSION="0.0.1"
readonly COMMON_DATE="2024-08-20"

# Determine script location with robust path handling
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"

# Default directories - can be overridden by environment variables
DEFAULT_LOG_DIR="${DEFAULT_LOG_DIR:-/var/log/cloud-platform}"
DEFAULT_CONFIG_DIR="${DEFAULT_CONFIG_DIR:-$PROJECT_ROOT/config}"
DEFAULT_TEMP_DIR="${DEFAULT_TEMP_DIR:-/tmp/cloud-platform}"
DEFAULT_BACKUP_DIR="${DEFAULT_BACKUP_DIR:-/var/backups/cloud-platform}"

# Environments
ENV_PRODUCTION="production"
ENV_STAGING="staging"
ENV_DEVELOPMENT="development"
ENV_TESTING="testing"
DEFAULT_ENVIRONMENT="${DEFAULT_ENVIRONMENT:-$ENV_DEVELOPMENT}"

# Default exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_CONFIG_ERROR=2
readonly EXIT_PERMISSION_ERROR=3
readonly EXIT_DEPENDENCY_ERROR=4
readonly EXIT_TIMEOUT_ERROR=5

# Default file permissions
readonly DEFAULT_FILE_PERMS="644"
readonly DEFAULT_DIR_PERMS="755"
readonly DEFAULT_LOG_FILE_PERMS="640"  # More restrictive for log files
readonly DEFAULT_SECRET_FILE_PERMS="600"  # Restrictive - contains sensitive information

# Terminal colors and formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly GRAY='\033[0;37m'
readonly BOLD='\033[1m'
readonly UNDERLINE='\033[4m'
readonly NC='\033[0m' # No Color

# Log levels and prefixes
readonly LOG_LEVEL_DEBUG=0
readonly LOG_LEVEL_INFO=1
readonly LOG_LEVEL_WARNING=2
readonly LOG_LEVEL_ERROR=3
readonly LOG_LEVEL_CRITICAL=4

# Set default values for configuration options
VERBOSE="${VERBOSE:-false}"
QUIET="${QUIET:-false}"
LOG_LEVEL="${LOG_LEVEL:-$LOG_LEVEL_INFO}"
LOG_TIMESTAMP_FORMAT="%Y-%m-%d %H:%M:%S"
LOG_TO_FILE="${LOG_TO_FILE:-false}"
LOG_FILE="${LOG_FILE:-}"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

#######################################
# DEPENDENCY CHECKING
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns:
#   0 if command exists, 1 if not
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# Check for required dependencies
# Arguments:
#   $@ - List of commands to check
# Returns:
#   0 if all found, 1 if any missing
check_dependencies() {
    local missing=0
    local missing_cmds=""

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing=$((missing + 1))
            missing_cmds="$missing_cmds $cmd"
        fi
    done

    if [[ $missing -gt 0 ]]; then
        log_error "Missing required dependencies:$missing_cmds"
        return $EXIT_DEPENDENCY_ERROR
    fi

    return $EXIT_SUCCESS
}

# Basic dependencies all scripts need
check_dependencies grep sed date awk || {
    echo -e "${RED}ERROR: Missing basic dependencies. Cannot continue.${NC}" >&2
    # Don't exit when sourced
    return $EXIT_DEPENDENCY_ERROR 2>/dev/null || exit $EXIT_DEPENDENCY_ERROR
}

#######################################
# LOGGING FUNCTIONS
#######################################

# Initialize log file with proper permissions
# Arguments:
#   $1 - Log file path
# Returns:
#   0 on success, 1 on failure
init_log_file() {
    local log_file="$1"
    local log_dir

    log_dir=$(dirname "$log_file")

    # Ensure log directory exists
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || {
            echo -e "${RED}ERROR: Failed to create log directory: $log_dir${NC}" >&2
            return $EXIT_PERMISSION_ERROR
        }

        chmod "${DEFAULT_DIR_PERMS}" "$log_dir" 2>/dev/null || {
            echo -e "${YELLOW}WARNING: Failed to set permissions on log directory: $log_dir${NC}" >&2
            # Continue despite permission warning
        }
    fi

    # Create or truncate file with correct permissions
    if [[ -f "$log_file" ]]; then
        # File exists, check if it's writable
        if [[ ! -w "$log_file" ]]; then
            echo -e "${RED}ERROR: Log file is not writable: $log_file${NC}" >&2
            return $EXIT_PERMISSION_ERROR
        fi
    else
        # Create new file
        touch "$log_file" 2>/dev/null || {
            echo -e "${RED}ERROR: Failed to create log file: $log_file${NC}" >&2
            return $EXIT_PERMISSION_ERROR
        }

        chmod "${DEFAULT_LOG_FILE_PERMS}" "$log_file" 2>/dev/null || {
            echo -e "${YELLOW}WARNING: Failed to set permissions on log file: $log_file${NC}" >&2
            # Continue despite permission warning
        }
    fi

    return $EXIT_SUCCESS
}

# Log a message with timestamp and level
# Arguments:
#   $1 - Message to log
#   $2 - Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) - defaults to INFO
# Returns:
#   0 on success, 1 on failure
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    local level_num
    local out_message

    # Convert log level to numeric value
    case "${level^^}" in
        DEBUG)
            level_num=$LOG_LEVEL_DEBUG
            level_color="${GRAY}"
            ;;
        INFO)
            level_num=$LOG_LEVEL_INFO
            level_color="${GREEN}"
            ;;
        WARNING)
            level_num=$LOG_LEVEL_WARNING
            level_color="${YELLOW}"
            ;;
        ERROR)
            level_num=$LOG_LEVEL_ERROR
            level_color="${RED}"
            ;;
        CRITICAL)
            level_num=$LOG_LEVEL_CRITICAL
            level_color="${RED}${BOLD}"
            ;;
        *)
            level_num=$LOG_LEVEL_INFO
            level_color="${GREEN}"
            ;;
    esac

    # Check if this log should be shown based on level
    if [[ $level_num -lt $LOG_LEVEL ]]; then
        return $EXIT_SUCCESS
    fi

    # Don't show any logs if QUIET is true, unless it's ERROR or CRITICAL
    if [[ "${QUIET}" == "true" && $level_num -lt $LOG_LEVEL_ERROR ]]; then
        return $EXIT_SUCCESS
    fi

    # Format timestamp
    timestamp=$(date +"${LOG_TIMESTAMP_FORMAT}")

    # Format message for console output (with color)
    out_message="[${timestamp}] [${level_color}${level}${NC}] ${message}"

    # Format message for log file (plain text without colors)
    local file_message="[${timestamp}] [${level}] ${message}"

    # Output to console
    echo -e "${out_message}" >&2

    # Output to log file if specified
    if [[ "${LOG_TO_FILE}" == "true" && -n "${LOG_FILE}" ]]; then
        # Initialize log file if it doesn't exist
        if [[ ! -f "${LOG_FILE}" ]]; then
            init_log_file "${LOG_FILE}" || return $EXIT_PERMISSION_ERROR
        fi

        # Append to log file
        echo "${file_message}" >> "${LOG_FILE}" 2>/dev/null || {
            echo -e "${RED}ERROR: Failed to write to log file: ${LOG_FILE}${NC}" >&2
            return $EXIT_PERMISSION_ERROR
        }
    fi

    return $EXIT_SUCCESS
}

# Convenience functions for specific log levels
log_debug() {
    if [[ "${VERBOSE}" == "true" ]]; then
        log "$1" "DEBUG"
    fi
}

log_info() {
    log "$1" "INFO"
}

log_warning() {
    log "$1" "WARNING"
}

log_error() {
    log "$1" "ERROR"
}

log_critical() {
    log "$1" "CRITICAL"
}

#######################################
# ERROR HANDLING FUNCTIONS
#######################################

# Exit with an error message
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
# Returns:
#   None - exits the script
error_exit() {
    local message="$1"
    local exit_code="${2:-$EXIT_FAILURE}"

    log_error "$message"

    # If this is sourced, return instead of exit
    if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
        return "$exit_code"
    else
        exit "$exit_code"
    fi
}

# Create a cleanup trap to ensure resources are released
# Arguments:
#   $1 - Function or commands to execute on exit
# Returns:
#   None
setup_cleanup_trap() {
    local cleanup_command="$1"

    if [[ -n "$cleanup_command" ]]; then
        # shellcheck disable=SC2064
        trap "$cleanup_command" EXIT
        log_debug "Cleanup trap set: $cleanup_command"
    fi
}

# Execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2... - Command to execute
# Returns:
#   Command exit code or timeout error
execute_with_timeout() {
    local timeout="$1"
    shift
    local command=("$@")

    if command_exists timeout; then
        timeout "$timeout" "${command[@]}"
        return $?
    else
        # Fallback for systems without the timeout command
        # Start command in background
        ("${command[@]}") &
        local pid=$!

        # Wait for command to complete or timeout
        local count=0
        while [[ $count -lt $timeout && -d "/proc/$pid" ]]; do
            sleep 1
            count=$((count + 1))
        done

        # If process is still running, kill it
        if [[ -d "/proc/$pid" ]]; then
            kill -TERM "$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
            return $EXIT_TIMEOUT_ERROR
        fi

        # Get command exit code
        wait "$pid"
        return $?
    fi
}

#######################################
# ENVIRONMENT DETECTION
#######################################

# Detect environment (production, staging, development)
# Arguments:
#   None
# Returns:
#   Environment name as string
detect_environment() {
    # Check for explicit environment variable
    if [[ -n "${ENVIRONMENT:-}" ]]; then
        echo "${ENVIRONMENT}"
        return $EXIT_SUCCESS
    fi

    # Check if we're running in a CI/CD environment
    if [[ -n "${CI:-}" ]]; then
        echo "$ENV_TESTING"
        return $EXIT_SUCCESS
    }

    # Try to detect from hostname
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)

    if [[ "$hostname" =~ (^|[-\.])prod($|[-\.]) || "$hostname" =~ production ]]; then
        echo "$ENV_PRODUCTION"
    elif [[ "$hostname" =~ (^|[-\.])stg($|[-\.]) || "$hostname" =~ staging ]]; then
        echo "$ENV_STAGING"
    elif [[ "$hostname" =~ (^|[-\.])dev($|[-\.]) || "$hostname" =~ development ]]; then
        echo "$ENV_DEVELOPMENT"
    elif [[ "$hostname" =~ (^|[-\.])test($|[-\.]) ]]; then
        echo "$ENV_TESTING"
    else
        # Default to development if unable to detect
        echo "${DEFAULT_ENVIRONMENT}"
    fi
}

# Check if running in production environment
# Arguments:
#   None
# Returns:
#   0 if production, 1 otherwise
is_production() {
    [[ "$(detect_environment)" == "$ENV_PRODUCTION" ]]
}

# Check if running in development environment
# Arguments:
#   None
# Returns:
#   0 if development, 1 otherwise
is_development() {
    [[ "$(detect_environment)" == "$ENV_DEVELOPMENT" ]]
}

#######################################
# FILE OPERATIONS
#######################################

# Create a temporary file safely
# Arguments:
#   $1 - File prefix (optional)
# Returns:
#   Path to temporary file
create_temp_file() {
    local prefix="${1:-cloud_platform}"
    local temp_file

    # Sanitize prefix for safety
    prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_-')

    # Create temp file with fallbacks
    temp_file=$(mktemp 2>/dev/null || mktemp -t "${prefix}.XXXXXXXXXX" 2>/dev/null) || {
        error_exit "Failed to create temporary file"
        return $EXIT_FAILURE
    }

    # Ensure file has secure permissions
    chmod "${DEFAULT_SECRET_FILE_PERMS}" "$temp_file" 2>/dev/null

    echo "$temp_file"
}

# Create a temporary directory safely
# Arguments:
#   $1 - Directory prefix (optional)
# Returns:
#   Path to temporary directory
create_temp_dir() {
    local prefix="${1:-cloud_platform}"
    local temp_dir

    # Sanitize prefix for safety
    prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_-')

    # Create temp directory with fallbacks
    temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t "${prefix}.XXXXXXXXXX" 2>/dev/null) || {
        error_exit "Failed to create temporary directory"
        return $EXIT_FAILURE
    }

    # Ensure directory has secure permissions
    chmod "${DEFAULT_DIR_PERMS}" "$temp_dir" 2>/dev/null

    echo "$temp_dir"
}

# Ensure a directory exists, creating it if necessary
# Arguments:
#   $1 - Directory path
# Returns:
#   0 on success, 1 on failure
ensure_directory() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" 2>/dev/null || {
            log_error "Failed to create directory: $dir"
            return $EXIT_FAILURE
        }
        log_debug "Created directory: $dir"
    fi

    return $EXIT_SUCCESS
}

# Check if a file is readable and has valid format
# Arguments:
#   $1 - File path
#   $2 - Expected file extension (optional)
# Returns:
#   0 if file is valid, 1 otherwise
validate_file() {
    local file="$1"
    local extension="${2:-}"

    # Check if file exists and is readable
    if [[ ! -f "$file" || ! -r "$file" ]]; then
        log_error "File does not exist or is not readable: $file"
        return $EXIT_FAILURE
    fi

    # Check extension if specified
    if [[ -n "$extension" ]]; then
        if [[ "$file" != *."$extension" ]]; then
            log_error "Invalid file extension: $file (expected .$extension)"
            return $EXIT_FAILURE
        fi
    fi

    return $EXIT_SUCCESS
}

# Read a configuration file safely
# Arguments:
#   $1 - Configuration file path
#   $2 - Variable prefix (optional)
# Returns:
#   0 on success, 1 on failure
load_config_file() {
    local config_file="$1"
    local prefix="${2:-}"

    # Validate file
    validate_file "$config_file" || return $?

    log_debug "Loading configuration from $config_file"

    # Process each line
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# || -z "$key" ]] && continue

        # Remove leading/trailing whitespace
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Set variable with prefix if specified
        if [[ -n "$prefix" ]]; then
            export "${prefix}${key}=${value}"
        else
            export "${key}=${value}"
        fi

        log_debug "Config: $key = $value"
    done < "$config_file"

    return $EXIT_SUCCESS
}

#######################################
# UTILITY FUNCTIONS
#######################################

# Check if a value is a number
# Arguments:
#   $1 - Value to check
#   $2 - Allow float (true/false, default: false)
# Returns:
#   0 if value is a number, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"

    if [[ "$allow_float" == "true" ]]; then
        [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
    else
        [[ "$value" =~ ^[0-9]+$ ]]
    fi
}

# Check if running as root user
# Arguments:
#   None
# Returns:
#   0 if running as root, 1 if not
is_root() {
    if [[ $EUID -ne 0 ]]; then
        return $EXIT_FAILURE
    fi
    return $EXIT_SUCCESS
}

# Check if a port is in use
# Arguments:
#   $1 - Port number
# Returns:
#   0 if port is in use, 1 if not
is_port_in_use() {
    local port="$1"

    if ! is_number "$port"; then
        log_error "Invalid port number: $port"
        return $EXIT_FAILURE
    fi

    # Try nc first, then fall back to other tools
    if command_exists nc; then
        nc -z localhost "$port" >/dev/null 2>&1
        return $?
    elif command_exists netstat; then
        netstat -tuln | grep -q ":$port " >/dev/null 2>&1
        return $?
    elif command_exists ss; then
        ss -tuln | grep -q ":$port " >/dev/null 2>&1
        return $?
    else
        log_warning "No tool available to check port: $port"
        return $EXIT_FAILURE
    fi
}

# Generate a random string
# Arguments:
#   $1 - Length of the string (default: 16)
#   $2 - Character set (default: alphanumeric)
# Returns:
#   Random string
generate_random_string() {
    local length="${1:-16}"
    local charset="${2:-alnum}"
    local result

    case "$charset" in
        alnum)
            # Alphanumeric characters (A-Z, a-z, 0-9)
            result=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length" 2>/dev/null)
            ;;
        hex)
            # Hexadecimal characters (0-9, A-F)
            result=$(tr -dc '0-9A-F' < /dev/urandom | head -c "$length" 2>/dev/null)
            ;;
        alpha)
            # Alphabetic characters (A-Z, a-z)
            result=$(tr -dc 'A-Za-z' < /dev/urandom | head -c "$length" 2>/dev/null)
            ;;
        numeric)
            # Numeric characters (0-9)
            result=$(tr -dc '0-9' < /dev/urandom | head -c "$length" 2>/dev/null)
            ;;
        *)
            # Default to alphanumeric
            result=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length" 2>/dev/null)
            ;;
    esac

    # Fall back to less secure but more portable method if tr failed
    if [[ -z "$result" ]]; then
        log_warning "Using fallback method for random string generation"
        result=$(openssl rand -base64 "$((length * 2))" 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$length")
    fi

    # Final fallback
    if [[ -z "$result" ]]; then
        log_warning "Using insecure method for random string generation"
        result=$(date +%s%N | sha256sum | head -c "$length")
    fi

    echo "$result"
}

# Parse command-line arguments
# Arguments:
#   $@ - Arguments to parse
# Returns:
#   0 on success, 1 on failure
parse_arguments() {
    # Default values
    SHOW_HELP=false
    SHOW_VERSION=false

    # Process options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                SHOW_HELP=true
                ;;
            --version|-v)
                SHOW_VERSION=true
                ;;
            --verbose)
                VERBOSE=true
                ;;
            --quiet|-q)
                QUIET=true
                ;;
            --log-file)
                if [[ -n "$2" ]]; then
                    LOG_FILE="$2"
                    LOG_TO_FILE=true
                    shift
                else
                    log_error "Missing value for --log-file"
                    return $EXIT_FAILURE
                fi
                ;;
            --log-level)
                if [[ -n "$2" ]]; then
                    case "${2^^}" in
                        DEBUG)
                            LOG_LEVEL=$LOG_LEVEL_DEBUG
                            ;;
                        INFO)
                            LOG_LEVEL=$LOG_LEVEL_INFO
                            ;;
                        WARNING)
                            LOG_LEVEL=$LOG_LEVEL_WARNING
                            ;;
                        ERROR)
                            LOG_LEVEL=$LOG_LEVEL_ERROR
                            ;;
                        CRITICAL)
                            LOG_LEVEL=$LOG_LEVEL_CRITICAL
                            ;;
                        *)
                            log_error "Invalid log level: $2"
                            return $EXIT_FAILURE
                            ;;
                    esac
                    shift
                else
                    log_error "Missing value for --log-level"
                    return $EXIT_FAILURE
                fi
                ;;
            *)
                # Handle positional arguments or unknown options
                log_error "Unknown option: $1"
                return $EXIT_FAILURE
                ;;
        esac
        shift
    done

    # Show help if requested
    if [[ "$SHOW_HELP" == "true" ]]; then
        show_help
        return $EXIT_SUCCESS
    fi

    # Show version if requested
    if [[ "$SHOW_VERSION" == "true" ]]; then
        echo "Common Shell Utilities for Cloud Infrastructure Platform v${COMMON_VERSION}"
        return $EXIT_SUCCESS
    fi

    return $EXIT_SUCCESS
}

# Show help message
# Arguments:
#   None
# Returns:
#   None
show_help() {
    cat <<EOF
Common Shell Utilities for Cloud Infrastructure Platform v${COMMON_VERSION}

USAGE:
    source $(basename "${BASH_SOURCE[0]}")

    # After sourcing, the following functions are available:
    log_info "Information message"
    log_error "Error message"
    log_debug "Debug message"
    error_exit "Error message with exit"

    # Environment detection
    env=$(detect_environment)
    if is_production; then
        # Production-specific code
    fi

    # Temporary files and directories
    temp_file=$(create_temp_file)
    temp_dir=$(create_temp_dir)

OPTIONS:
    --help, -h        Show this help message
    --version, -v     Show version information
    --verbose         Enable verbose output
    --quiet, -q       Suppress non-error output
    --log-file FILE   Write logs to FILE
    --log-level LEVEL Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

FUNCTIONS:
    Logging:
        log, log_info, log_debug, log_warning, log_error, log_critical

    Error Handling:
        error_exit, setup_cleanup_trap, execute_with_timeout

    Environment:
        detect_environment, is_production, is_development

    File Operations:
        create_temp_file, create_temp_dir, ensure_directory,
        validate_file, load_config_file

    Utilities:
        command_exists, check_dependencies, is_number,
        is_root, is_port_in_use, generate_random_string

EOF
}

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string
get_version() {
    echo "${COMMON_VERSION} (${COMMON_DATE})"
}

#######################################
# INITIALIZATION
#######################################

# Initialize the script
# Arguments:
#   $@ - Arguments from caller
# Returns:
#   0 on success, non-zero on failure
init() {
    # Parse arguments if provided
    if [[ $# -gt 0 ]]; then
        parse_arguments "$@" || return $?
    fi

    # Initialize log file if specified
    if [[ "${LOG_TO_FILE}" == "true" && -n "${LOG_FILE}" ]]; then
        init_log_file "${LOG_FILE}" || {
            LOG_TO_FILE=false
            log_warning "Failed to initialize log file. Logging to stdout only."
        }
    fi

    # Log initialization
    log_debug "Common shell utilities initialized (version ${COMMON_VERSION})"
    log_debug "Environment: $(detect_environment)"

    return $EXIT_SUCCESS
}

# Run initialization if arguments are provided
if [[ $# -gt 0 ]]; then
    init "$@"
fi

# Export public functions and constants
export COMMON_VERSION COMMON_DATE
export ENV_PRODUCTION ENV_STAGING ENV_DEVELOPMENT ENV_TESTING
export LOG_LEVEL_DEBUG LOG_LEVEL_INFO LOG_LEVEL_WARNING LOG_LEVEL_ERROR LOG_LEVEL_CRITICAL
export EXIT_SUCCESS EXIT_FAILURE EXIT_CONFIG_ERROR EXIT_PERMISSION_ERROR EXIT_DEPENDENCY_ERROR EXIT_TIMEOUT_ERROR
export DEFAULT_FILE_PERMS DEFAULT_DIR_PERMS DEFAULT_LOG_FILE_PERMS DEFAULT_SECRET_FILE_PERMS

export -f command_exists check_dependencies
export -f log log_debug log_info log_warning log_error log_critical
export -f error_exit setup_cleanup_trap execute_with_timeout
export -f detect_environment is_production is_development
export -f create_temp_file create_temp_dir ensure_directory validate_file load_config_file
export -f is_number is_root is_port_in_use generate_random_string
export -f parse_arguments show_help get_version

# Return success when sourced
return $EXIT_SUCCESS
