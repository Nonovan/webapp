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
# Date: 2024-09-02

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
readonly COMMON_DATE="2024-09-02"

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
readonly EXIT_UNSUPPORTED_ERROR=6

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

# Component availability tracking
COMPONENT_STATUS="{}"
declare -A AVAILABLE_COMPONENTS=(
  ["logger"]="false"
  ["config_loader"]="false"
  ["environment"]="false"
  ["error_handler"]="false"
  ["notification"]="false"
  ["security"]="false"
  ["system"]="false"
  ["crypto"]="false"
  ["file_integrity"]="false"
  ["permissions"]="false"
  ["cloud_provider"]="false"
  ["resource_monitor"]="false"
)

# Python core initialization status
PYTHON_CORE_INITIALIZED=false
PYTHON_COMPONENTS_STATUS="{}"

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

    # Mark logger as available after first successful log
    AVAILABLE_COMPONENTS["logger"]="true"

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

    # Mark environment as available
    AVAILABLE_COMPONENTS["environment"]="true"
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

    # Mark config loader as available
    AVAILABLE_COMPONENTS["config_loader"]="true"

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

#######################################
# COMPONENT MANAGEMENT FUNCTIONS
#######################################

# Get the availability status of a component
# Arguments:
#   $1 - Component name
# Returns:
#   "true" if available, "false" if not
is_component_available() {
    local component="$1"

    if [[ -n "${AVAILABLE_COMPONENTS[$component]}" ]]; then
        echo "${AVAILABLE_COMPONENTS[$component]}"
    else
        echo "false"
    fi
}

# Mark a component as available
# Arguments:
#   $1 - Component name
# Returns:
#   0 on success, 1 on failure
mark_component_available() {
    local component="$1"

    if [[ -n "$component" ]]; then
        AVAILABLE_COMPONENTS["$component"]="true"
        log_debug "Component marked as available: $component"
        return $EXIT_SUCCESS
    else
        log_error "No component name provided"
        return $EXIT_FAILURE
    fi
}

# Get status of all components
# Arguments:
#   None
# Returns:
#   JSON-like string with component statuses
get_component_status() {
    local components_json="{"
    local first=true

    for component in "${!AVAILABLE_COMPONENTS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            components_json+=", "
        fi
        components_json+="\"$component\": ${AVAILABLE_COMPONENTS[$component]}"
    done

    components_json+="}"
    echo "$components_json"
}

# Initialize a component with dependency checking
# Arguments:
#   $1 - Component name
#   $2 - Command to initialize component
#   $3... - Dependencies (component names)
# Returns:
#   0 on success, 1 on failure
initialize_component() {
    local component="$1"
    local init_command="$2"
    shift 2
    local dependencies=("$@")

    # Skip if already initialized
    if [[ "$(is_component_available "$component")" == "true" ]]; then
        log_debug "Component already initialized: $component"
        return $EXIT_SUCCESS
    fi

    # Check dependencies
    local missing_deps=()
    for dep in "${dependencies[@]}"; do
        if [[ "$(is_component_available "$dep")" != "true" ]]; then
            missing_deps+=("$dep")
        fi
    done

    # If missing dependencies, log and return
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_warning "Cannot initialize $component, missing dependencies: ${missing_deps[*]}"
        return $EXIT_DEPENDENCY_ERROR
    fi

    # Initialize the component
    log_debug "Initializing component: $component"

    # Execute the initialization command
    eval "$init_command"
    local result=$?

    if [[ $result -eq 0 ]]; then
        mark_component_available "$component"
        log_info "Component initialized: $component"
        return $EXIT_SUCCESS
    else
        log_error "Failed to initialize component: $component"
        return $EXIT_FAILURE
    fi
}

#######################################
# PYTHON INTEGRATION FUNCTIONS
#######################################

# Initialize Python core components
# Arguments:
#   $1 - Configuration file (optional)
#   $2 - Environment (optional - defaults to detected environment)
#   $3 - Log level (optional - defaults to current log level)
# Returns:
#   0 on success, 1 on failure
initialize_python_core() {
    local config_file="${1:-}"
    local environment="${2:-$(detect_environment)}"
    local log_level="${3:-}"
    local result
    local python_log_level

    # Map bash log level to Python log level if not specified
    if [[ -z "$log_level" ]]; then
        case $LOG_LEVEL in
            $LOG_LEVEL_DEBUG) python_log_level="DEBUG" ;;
            $LOG_LEVEL_INFO) python_log_level="INFO" ;;
            $LOG_LEVEL_WARNING) python_log_level="WARNING" ;;
            $LOG_LEVEL_ERROR) python_log_level="ERROR" ;;
            $LOG_LEVEL_CRITICAL) python_log_level="CRITICAL" ;;
            *) python_log_level="INFO" ;;
        esac
    else
        python_log_level="$log_level"
    fi

    # Check for Python
    if ! command_exists python3 && ! command_exists python; then
        log_error "Python not found, cannot initialize core Python components"
        return $EXIT_DEPENDENCY_ERROR
    fi

    # Prepare Python command
    local python_cmd
    if command_exists python3; then
        python_cmd="python3"
    else
        python_cmd="python"
    fi

    # Prepare script
    local temp_script
    temp_script=$(create_temp_file "init_py")

    # Create a Python script to initialize the core components and return the status
    cat > "$temp_script" << EOF
import sys
import os
import json

# Set environment variables for initialization
os.environ["ENVIRONMENT"] = "$environment"

try:
    # Add project root to Python path if needed
    project_root = "$PROJECT_ROOT"
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Import core initialization
    from scripts.core import setup_script_environment, get_component_status

    # Initialize core components
    success = setup_script_environment(
        config_file="$config_file",
        environment="$environment",
        log_level="$python_log_level"
    )

    # Get component status
    status = get_component_status()

    # Output results as JSON for bash to parse
    print(json.dumps({
        "success": success,
        "status": status
    }))
    sys.exit(0)
except Exception as e:
    # Handle any exceptions
    print(json.dumps({
        "success": False,
        "status": {},
        "error": str(e)
    }))
    sys.exit(1)
EOF

    # Run the Python script and capture output
    result=$("$python_cmd" "$temp_script" 2>/dev/null)
    local exit_code=$?

    # Clean up temp file
    rm -f "$temp_script"

    # Check for execution error
    if [[ $exit_code -ne 0 || -z "$result" ]]; then
        log_error "Failed to initialize Python core components"
        return $EXIT_FAILURE
    fi

    # Parse result
    local success
    success=$(echo "$result" | grep -o '"success": true\|"success": false' | cut -d' ' -f2)

    # Store component status
    PYTHON_COMPONENTS_STATUS=$(echo "$result" | grep -o '"status": {.*}' | cut -d':' -f2-)

    # Check for success
    if [[ "$success" == "true" ]]; then
        PYTHON_CORE_INITIALIZED=true
        log_info "Python core components initialized successfully"
    else
        local error
        error=$(echo "$result" | grep -o '"error": "[^"]*"' | cut -d'"' -f4)
        log_error "Failed to initialize Python core components: $error"
        return $EXIT_FAILURE
    fi

    return $EXIT_SUCCESS
}

# Get Python component status
# Arguments:
#   $1 - Component name (optional, returns status for all components if not specified)
# Returns:
#   Status string (true/false) or JSON status object
get_python_component_status() {
    local component="$1"

    if [[ "$PYTHON_CORE_INITIALIZED" != "true" ]]; then
        if [[ -n "$component" ]]; then
            echo "false"
        else
            echo "{}"
        fi
        return $EXIT_FAILURE
    fi

    if [[ -n "$component" ]]; then
        # Extract specific component status (true/false)
        local status
        status=$(echo "$PYTHON_COMPONENTS_STATUS" | grep -o "\"$component\": true\|\"$component\": false" | cut -d' ' -f2)
        if [[ -n "$status" ]]; then
            echo "$status"
        else
            echo "false"
        fi
    else
        # Return full status
        echo "$PYTHON_COMPONENTS_STATUS"
    fi

    return $EXIT_SUCCESS
}

# Load configuration through Python core
# Arguments:
#   $1 - Configuration file (optional)
#   $2 - Environment (optional)
# Returns:
#   0 on success, 1 on failure; configuration is set to environment variables with CONFIG_ prefix
load_python_config() {
    local config_file="${1:-}"
    local environment="${2:-$(detect_environment)}"
    local result
    local temp_script

    # Check for Python
    if ! command_exists python3 && ! command_exists python; then
        log_error "Python not found, cannot load configuration"
        return $EXIT_DEPENDENCY_ERROR
    fi

    # Prepare Python command
    local python_cmd
    if command_exists python3; then
        python_cmd="python3"
    else
        python_cmd="python"
    fi

    # Initialize Python core if not already done
    if [[ "$PYTHON_CORE_INITIALIZED" != "true" ]]; then
        log_info "Initializing Python core components before loading configuration"
        initialize_python_core "$config_file" "$environment" || return $?
    fi

    # Prepare script
    temp_script=$(create_temp_file "config_loader_py")

    # Create a Python script to load configuration and export as environment variables
    cat > "$temp_script" << EOF
import sys
import os
import json

# Set environment variables for initialization
os.environ["ENVIRONMENT"] = "$environment"

try:
    # Add project root to Python path if needed
    project_root = "$PROJECT_ROOT"
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Import core configuration loader
    from scripts.core import load_configuration

    # Load configuration
    config = load_configuration("$config_file", "$environment")

    if config is None:
        print(json.dumps({
            "success": False,
            "error": "Failed to load configuration"
        }))
        sys.exit(1)

    # Convert config to dictionary with flattened keys for bash
    env_vars = {}
    config_dict = config.get_all()

    def flatten_dict(d, parent_key=''):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}_{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)

    flattened = flatten_dict(config_dict)

    # Prepare for bash export (with CONFIG_ prefix)
    for key, value in flattened.items():
        env_key = f"CONFIG_{key.upper()}"
        if isinstance(value, bool):
            env_vars[env_key] = str(value).lower()
        elif value is None:
            env_vars[env_key] = ""
        else:
            env_vars[env_key] = str(value)

    # Output as JSON
    print(json.dumps({
        "success": True,
        "env_vars": env_vars
    }))

    sys.exit(0)
except Exception as e:
    # Handle any exceptions
    print(json.dumps({
        "success": False,
        "error": str(e)
    }))
    sys.exit(1)
EOF

    # Run the Python script and capture output
    result=$("$python_cmd" "$temp_script" 2>/dev/null)
    local exit_code=$?

    # Clean up temp file
    rm -f "$temp_script"

    # Check for execution error
    if [[ $exit_code -ne 0 || -z "$result" ]]; then
        log_error "Failed to load configuration from Python core"
        return $EXIT_FAILURE
    fi

    # Parse result
    local success
    success=$(echo "$result" | grep -o '"success": true\|"success": false' | cut -d' ' -f2)

    # Check for success
    if [[ "$success" == "true" ]]; then
        # Extract and set environment variables
        local env_vars
        env_vars=$(echo "$result" | grep -o '"env_vars": {.*}' | cut -d':' -f2-)

        # Process each key-value pair with a simple parser
        local temp_vars
        temp_vars=$(echo "$env_vars" | sed 's/{//;s/}//;s/"//g;s/,/\n/g')

        while IFS=: read -r key value; do
            # Remove leading/trailing whitespace
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Export as environment variable
            export "$key=$value"
            log_debug "Config loaded: $key=$value"
        done <<< "$temp_vars"

        log_info "Configuration loaded successfully from Python core"
        mark_component_available "config_loader"
    else
        local error
        error=$(echo "$result" | grep -o '"error": "[^"]*"' | cut -d'"' -f4)
        log_error "Failed to load configuration: $error"
        return $EXIT_FAILURE
    fi

    return $EXIT_SUCCESS
}

#######################################
# MODULE INITIALIZATION
#######################################

# Initialize security components
# Arguments:
#   $1 - Security level (default: normal)
#   $2 - Skip unavailable components (default: true)
# Returns:
#   Returns a list of successfully initialized components
initialize_security_components() {
    local security_level="${1:-normal}"
    local skip_unavailable="${2:-true}"
    local success=true
    local errors=()
    local initialized=()

    log_info "Initializing security components with security level: $security_level"

    # Initialize basic crypto (no dependencies)
    if initialize_component "crypto" "initialize_crypto_component" ; then
        initialized+=("crypto")
    else
        errors+=("Failed to initialize crypto component")
        [[ "$skip_unavailable" != "true" ]] && success=false
    fi

    # Initialize file integrity (depends on crypto)
    if initialize_component "file_integrity" "initialize_file_integrity_component" "crypto"; then
        initialized+=("file_integrity")
    else
        errors+=("Failed to initialize file integrity component")
        [[ "$skip_unavailable" != "true" ]] && success=false
    fi

    # Initialize permissions module (depends on file_integrity)
    if initialize_component "permissions" "initialize_permissions_component" "file_integrity"; then
        initialized+=("permissions")
    else
        errors+=("Failed to initialize permissions component")
        [[ "$skip_unavailable" != "true" ]] && success=false
    fi

    # Mark main security component as available if all essentials are initialized
    if [[ " ${initialized[*]} " =~ " crypto " &&
          " ${initialized[*]} " =~ " file_integrity " &&
          " ${initialized[*]} " =~ " permissions " ]]; then
        mark_component_available "security"
        log_info "Security components initialized successfully"
    else
        log_warning "Security components partially initialized"
    fi

    if [[ "$success" == "true" ]]; then
        log_info "All security components initialized successfully"
    else
        log_warning "Some security components failed to initialize"
        for error in "${errors[@]}"; do
            log_warning "$error"
        done
    fi

    return $EXIT_SUCCESS
}

# Initialize crypto component
# This is typically called by initialize_security_components
# Arguments:
#   None
# Returns:
#   0 on success, non-zero on failure
initialize_crypto_component() {
    log_info "Initializing crypto component"

    # Check for required commands
    if ! check_dependencies openssl; then
        log_warning "OpenSSL not found, crypto functionality will be limited"
    fi

    # Set up crypto environment
    export CRYPTO_INITIALIZED=true
    export CRYPTO_LEVEL=${SECURITY_LEVEL:-normal}

    # Mark as successful
    return $EXIT_SUCCESS
}

# Initialize file integrity component
# This is typically called by initialize_security_components
# Arguments:
#   None
# Returns:
#   0 on success, non-zero on failure
initialize_file_integrity_component() {
    log_info "Initializing file integrity component"

    # Check for required dependencies
    if ! check_dependencies sha256sum find; then
        log_error "Required commands for file integrity not available"
        return $EXIT_DEPENDENCY_ERROR
    fi

    # Create integrity database directory if needed
    local integrity_db_dir="$PROJECT_ROOT/.secure/integrity"
    ensure_directory "$integrity_db_dir" || {
        log_error "Failed to create integrity database directory"
        return $EXIT_FAILURE
    }

    # Mark as successful
    return $EXIT_SUCCESS
}

# Initialize permissions component
# This is typically called by initialize_security_components
# Arguments:
#   None
# Returns:
#   0 on success, non-zero on failure
initialize_permissions_component() {
    log_info "Initializing permissions component"

    # Check for required dependencies
    if ! check_dependencies chmod chown find; then
        log_error "Required commands for permissions management not available"
        return $EXIT_DEPENDENCY_ERROR
    }

    # Mark as successful
    return $EXIT_SUCCESS
}

# Initialize system components
# Arguments:
#   $1 - Skip unavailable components (default: true)
# Returns:
#   0 on success, 1 on failure
initialize_system_components() {
    local skip_unavailable="${1:-true}"
    local success=true
    local errors=()
    local initialized=()

    log_info "Initializing system components"

    # Initialize resource monitor (no dependencies)
    if initialize_component "resource_monitor" "initialize_resource_monitor_component"; then
        initialized+=("resource_monitor")
    else
        errors+=("Failed to initialize resource monitor component")
        [[ "$skip_unavailable" != "true" ]] && success=false
    fi

    # Initialize cloud provider (depends on config_loader)
    if initialize_component "cloud_provider" "initialize_cloud_provider_component" "config_loader"; then
        initialized+=("cloud_provider")
    else
        errors+=("Failed to initialize cloud provider component")
        # Don't fail if skip_unavailable is true
        [[ "$skip_unavailable" != "true" ]] && success=false
    fi

    # Mark main system component as available if all essentials are initialized
    if [[ " ${initialized[*]} " =~ " resource_monitor " ]]; then
        mark_component_available "system"
        log_info "System components initialized successfully"
    else
        log_warning "System components partially initialized"
    fi

    if [[ "$success" == "true" ]]; then
        log_info "All system components initialized successfully"
    else
        log_warning "Some system components failed to initialize"
        for error in "${errors[@]}"; do
            log_warning "$error"
        done
    fi

    return $EXIT_SUCCESS
}

# Initialize resource monitor component
# This is typically called by initialize_system_components
# Arguments:
#   None
# Returns:
#   0 on success, non-zero on failure
initialize_resource_monitor_component() {
    log_info "Initializing resource monitor component"

    # Check for required dependencies
    if ! command_exists top || ! command_exists ps; then
        log_warning "Resource monitoring will have limited functionality"
    }

    # Create monitoring directory if needed
    local monitoring_dir="$PROJECT_ROOT/logs/monitoring"
    ensure_directory "$monitoring_dir" || {
        log_error "Failed to create monitoring directory"
        return $EXIT_FAILURE
    }

    # Mark as successful
    return $EXIT_SUCCESS
}

# Initialize cloud provider component
# This is typically called by initialize_system_components
# Arguments:
#   None
# Returns:
#   0 on success, non-zero on failure
initialize_cloud_provider_component() {
    log_info "Initializing cloud provider component"

    # Check cloud provider tools
    local cloud_provider_available=false

    if command_exists aws; then
        log_debug "AWS CLI found"
        cloud_provider_available=true
    fi

    if command_exists az; then
        log_debug "Azure CLI found"
        cloud_provider_available=true
    fi

    if command_exists gcloud; then
        log_debug "Google Cloud CLI found"
        cloud_provider_available=true
    fi

    if [[ "$cloud_provider_available" == "false" ]]; then
        log_warning "No cloud provider CLI tools found"
    }

    # Mark as successful even without cloud tools
    # (we'll handle unavailability later)
    return $EXIT_SUCCESS
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
    SHOW_STATUS=false
    INIT_PYTHON_CORE=false
    CONFIG_FILE=""
    SECURITY_LEVEL="normal"

    # Process options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                SHOW_HELP=true
                ;;
            --version|-v)
                SHOW_VERSION=true
                ;;
            --status|-s)
                SHOW_STATUS=true
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
            --init-python-core)
                INIT_PYTHON_CORE=true
                ;;
            --security-level)
                if [[ -n "$2" ]]; then
                    SECURITY_LEVEL="$2"
                    shift
                else
                    log_error "Missing value for --security-level"
                    return $EXIT_FAILURE
                fi
                ;;
            --config)
                if [[ -n "$2" ]]; then
                    CONFIG_FILE="$2"
                    shift
                else
                    log_error "Missing value for --config"
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

    # Show status if requested
    if [[ "$SHOW_STATUS" == "true" ]]; then
        show_status
        return $EXIT_SUCCESS
    }

    return $EXIT_SUCCESS
}

# Display component status
# Arguments:
#   None
# Returns:
#   None
show_status() {
    echo "Core Component Status:"
    echo "-------------------"
    for component in $(echo "${!AVAILABLE_COMPONENTS[@]}" | tr ' ' '\n' | sort); do
        status="${AVAILABLE_COMPONENTS[$component]}"
        if [[ "$status" == "true" ]]; then
            echo -e "${GREEN}✓${NC} $component: Available"
        else
            echo -e "${RED}✗${NC} $component: Unavailable"
        fi
    done

    if [[ "$PYTHON_CORE_INITIALIZED" == "true" ]]; then
        echo -e "\nPython Components:"
        echo "----------------"
        python_status=$(get_python_component_status)
        # Extract each component and status from the JSON-like string
        while read -r line; do
            if [[ "$line" =~ \"([^\"]+)\":\ (true|false) ]]; then
                component="${BASH_REMATCH[1]}"
                status="${BASH_REMATCH[2]}"
                if [[ "$status" == "true" ]]; then
                    echo -e "${GREEN}✓${NC} $component: Available"
                else
                    echo -e "${RED}✗${NC} $component: Unavailable"
                fi
            fi
        done < <(echo "$python_status" | sed 's/[{,}]//g')
    else
        echo -e "\nPython Core: ${RED}Not Initialized${NC}"
    fi
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

    # Component initialization
    initialize_security_components
    initialize_system_components

    # Component availability
    if [[ $(is_component_available "permissions") == "true" ]]; then
        # Use permission-related functions
    fi

    # Python integration
    initialize_python_core "config/app.yaml" "production" "INFO"
    if [[ $(get_python_component_status "logger") == "true" ]]; then
        log_info "Logger is available"
    fi

OPTIONS:
    --help, -h            Show this help message
    --version, -v         Show version information
    --status, -s          Show component availability status
    --verbose             Enable verbose output
    --quiet, -q           Suppress non-error output
    --log-file FILE       Write logs to FILE
    --log-level LEVEL     Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    --init-python-core    Initialize Python core components
    --config FILE         Specify configuration file
    --security-level LVL  Set security level (low, normal, high, paranoid)

FUNCTIONS:
    Component Management:
        is_component_available, mark_component_available, get_component_status
        initialize_security_components, initialize_system_components

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

    Python Integration:
        initialize_python_core, get_python_component_status,
        load_python_config

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

    # Initialize Python core if requested
    if [[ "$INIT_PYTHON_CORE" == "true" ]]; then
        log_info "Initializing Python core components"
        initialize_python_core "$CONFIG_FILE" || {
            log_warning "Failed to initialize Python core components"
        }
    fi

    # Load configuration from Python core if config file specified
    if [[ -n "$CONFIG_FILE" && "$INIT_PYTHON_CORE" == "true" ]]; then
        log_info "Loading configuration from Python core"
        load_python_config "$CONFIG_FILE" || {
            log_warning "Failed to load configuration from Python core"
        }
    fi

    # Mark error handler as available
    mark_component_available "error_handler"

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
export EXIT_SUCCESS EXIT_FAILURE EXIT_CONFIG_ERROR EXIT_PERMISSION_ERROR EXIT_DEPENDENCY_ERROR EXIT_TIMEOUT_ERROR EXIT_UNSUPPORTED_ERROR
export DEFAULT_FILE_PERMS DEFAULT_DIR_PERMS DEFAULT_LOG_FILE_PERMS DEFAULT_SECRET_FILE_PERMS

export -f command_exists check_dependencies
export -f log log_debug log_info log_warning log_error log_critical
export -f error_exit setup_cleanup_trap execute_with_timeout
export -f detect_environment is_production is_development
export -f create_temp_file create_temp_dir ensure_directory validate_file load_config_file
export -f is_number is_root is_port_in_use generate_random_string

# Export component management functions
export -f is_component_available mark_component_available get_component_status
export -f initialize_security_components initialize_system_components
export -f show_status

# Export Python integration functions
export -f initialize_python_core get_python_component_status load_python_config

# Export script handling functions
export -f parse_arguments show_help get_version

# Return success when sourced
return $EXIT_SUCCESS
