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
log() {
    # [Implementation]
}

# Log an error message and exit
error_exit() {
    # [Implementation]
}

# Log a warning message
warn() {
    # [Implementation]
}

# Log a debug message
debug() {
    # [Implementation]
}

# Log an important message (highlighted)
important() {
    # [Implementation]
}

#######################################
# ENVIRONMENT FUNCTIONS
#######################################

# Load environment-specific variables from file
load_env() {
    # [Implementation]
}

# Validate if environment is valid
validate_environment() {
    # [Implementation]
}

# Get the current environment
detect_environment() {
    # [Implementation]
}

#######################################
# VALIDATION FUNCTIONS
#######################################

# Check if a command exists
command_exists() {
    # [Implementation]
}

# Check if a file exists and is readable
file_exists() {
    # [Implementation]
}

# Validate if a string is a valid IP address
is_valid_ip() {
    # [Implementation]
}

# Check if a value is a number
is_number() {
    # [Implementation]
}

# Validate required parameters
validate_required_params() {
    # [Implementation]
}

# Validate a URL format
is_valid_url() {
    # [Implementation]
}

# Validate email format
is_valid_email() {
    # [Implementation]
}

#######################################
# FILE OPERATIONS
#######################################

# Create a backup of a file
backup_file() {
    # [Implementation]
}

# Create directory if it doesn't exist
ensure_directory() {
    # [Implementation]
}

# Safely write content to a file with error handling
safe_write_file() {
    # [Implementation]
}

# Get file age in seconds
file_age() {
    # [Implementation]
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
