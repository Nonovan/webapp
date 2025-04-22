#!/bin/bash
# -----------------------------------------------------------------------------
# env_setup.sh - Environment Configuration Setup Script
#
# Part of Cloud Infrastructure Platform
#
# This script configures the environment for the application by setting up
# environment variables, creating required directories, and validating
# configuration parameters.
#
# Usage: ./env_setup.sh [--env <environment>] [--config-dir <path>]
# -----------------------------------------------------------------------------

# Exit immediately if a command exits with a non-zero status
set -e

# Set strict error handling
set -o pipefail

# Script version for tracking changes and compatibility
readonly SCRIPT_VERSION="1.0.0"

# Default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
CONFIG_DIR="${CONFIG_DIR:-${PROJECT_ROOT}/config}"
ENV="${ENV:-development}"
LOG_DIR="/var/log/cloud-platform"
CONFIG_FILE=""
VERBOSE=false
FORCE=false

# Import logging utilities if available
if [[ -f "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../monitoring/common/logging_utils.sh"
else
    # Minimal logging if logging_utils is not available
    log_info() { echo "[INFO] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${VERBOSE}" == "true" ]] && echo "[DEBUG] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
fi

# Function to display usage
usage() {
    cat <<EOF
Environment Setup Script for Cloud Infrastructure Platform v${SCRIPT_VERSION}

Usage: $0 [options]

Options:
  -e, --env <environment>     Specify environment (default: development)
                              Valid values: development, staging, production, dr-recovery
  -c, --config-dir <path>     Specify configuration directory (default: \$PROJECT_ROOT/config)
  -f, --file <path>           Specify a specific .env file to use
  -v, --verbose               Enable verbose output
  --force                     Force overwrite of existing environment variables
  -h, --help                  Display this help message

Examples:
  $0 --env production         # Set up production environment
  $0 --file /path/to/.env     # Use specific .env file
  $0 --verbose                # Show detailed output

This script sets up environment variables for the application based on the
specified environment or configuration file.
EOF
    exit 1
}

# Function to load environment variables from a file
load_env_file() {
    local env_file="$1"

    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file not found: $env_file"
        return 1
    fi

    log_info "Loading environment variables from: $env_file"

    # Read the file line by line
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Extract variable and value
        if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
            local var_name="${BASH_REMATCH[1]}"
            local var_value="${BASH_REMATCH[2]}"

            # Remove quotes if present
            var_value="${var_value#\"}"
            var_value="${var_value%\"}"
            var_value="${var_value#\'}"
            var_value="${var_value%\'}"

            # Check if variable already exists in environment
            if [[ -n "${!var_name}" && "${FORCE}" != "true" ]]; then
                log_debug "Skipping $var_name (already set)"
            else
                export "$var_name"="$var_value"
                log_debug "Set $var_name=${var_value}"
            fi
        fi
    done < "$env_file"

    return 0
}

# Function to set up default environment variables
setup_default_env() {
    # Core application settings with safer defaults
    : "${APP_ENV:=${ENV}}"
    : "${APP_PORT:=3000}"
    : "${APP_HOST:=localhost}"
    : "${APP_URL:=http://${APP_HOST}:${APP_PORT}}"
    : "${LOG_LEVEL:=info}"

    # Database connection settings (with more secure defaults)
    : "${DB_HOST:=localhost}"
    : "${DB_PORT:=5432}"
    : "${DB_USER:=cloud_platform}"
    : "${DB_NAME:=cloud_platform_${ENV}}"

    # We don't set a default password - it must be provided
    if [[ -z "${DB_PASSWORD}" && "${ENV}" != "development" ]]; then
        log_warning "DB_PASSWORD is not set. This is only acceptable in development environment."
    fi

    # Security settings
    : "${SESSION_SECRET:=$(openssl rand -hex 32)}"
    : "${JWT_SECRET:=$(openssl rand -hex 32)}"
    : "${ENCRYPTION_KEY:=$(openssl rand -hex 32)}"

    # API settings
    : "${API_RATE_LIMIT:=100}"
    : "${API_RATE_WINDOW:=60}"

    # Export all variables
    export APP_ENV APP_PORT APP_HOST APP_URL LOG_LEVEL
    export DB_HOST DB_PORT DB_USER DB_NAME
    export SESSION_SECRET JWT_SECRET ENCRYPTION_KEY
    export API_RATE_LIMIT API_RATE_WINDOW

    log_debug "Default environment variables set up"
}

# Function to create required directories
setup_directories() {
    log_info "Setting up required directories"

    # Create log directory if it doesn't exist
    mkdir -p "${LOG_DIR}" 2>/dev/null || {
        log_warning "Failed to create log directory: ${LOG_DIR}"
        log_info "Creating fallback log directory in /tmp"
        mkdir -p "/tmp/cloud-platform/logs"
        export LOG_DIR="/tmp/cloud-platform/logs"
    }

    # Create application specific directories
    local dirs=(
        "/tmp/cloud-platform/uploads"
        "/tmp/cloud-platform/cache"
        "/tmp/cloud-platform/temp"
    )

    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir" 2>/dev/null || log_warning "Failed to create directory: $dir"
        fi
    done

    # Set proper permissions for security
    if [[ "$(id -u)" -eq 0 ]]; then
        chmod -R 750 "${LOG_DIR}" 2>/dev/null || log_warning "Failed to set permissions on log directory"
        chown -R "$(whoami):$(id -gn)" "${LOG_DIR}" 2>/dev/null || log_warning "Failed to set ownership on log directory"
    fi

    log_debug "Directory setup complete"
}

# Function to verify required variables are set
verify_environment() {
    local required_vars=("APP_ENV" "DB_HOST" "DB_PORT" "DB_USER")
    local missing_vars=()

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done

    if [[ "${#missing_vars[@]}" -gt 0 ]]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        return 1
    fi

    # Additional environment-specific checks
    if [[ "$APP_ENV" == "production" || "$APP_ENV" == "staging" ]]; then
        if [[ -z "$DB_PASSWORD" ]]; then
            log_error "DB_PASSWORD is required for ${APP_ENV} environment"
            return 1
        fi

        if [[ -z "$SESSION_SECRET" || "$SESSION_SECRET" == "$(openssl rand -hex 32)" ]]; then
            log_warning "SESSION_SECRET is using a temporary value. This should be set permanently in ${APP_ENV} environment"
        fi
    fi

    return 0
}

# Function to print environment variables for verification
print_environment() {
    log_info "Environment configuration:"

    # Print core settings (without revealing secrets)
    log_info "APP_ENV=$APP_ENV"
    log_info "APP_PORT=$APP_PORT"
    log_info "APP_HOST=$APP_HOST"
    log_info "APP_URL=$APP_URL"
    log_info "LOG_LEVEL=$LOG_LEVEL"

    # Print database settings (password hidden)
    log_info "DB_HOST=$DB_HOST"
    log_info "DB_PORT=$DB_PORT"
    log_info "DB_USER=$DB_USER"
    log_info "DB_NAME=$DB_NAME"
    if [[ -n "$DB_PASSWORD" ]]; then
        log_info "DB_PASSWORD=********"
    else
        log_info "DB_PASSWORD=<not set>"
    fi

    # Security settings are not printed for security reasons
    log_info "SESSION_SECRET=********"
    log_info "JWT_SECRET=********"
    log_info "ENCRYPTION_KEY=********"

    # Show directory locations
    log_info "LOG_DIR=$LOG_DIR"
    log_info "PROJECT_ROOT=$PROJECT_ROOT"
    log_info "CONFIG_DIR=$CONFIG_DIR"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -e|--env)
            ENV="$2"
            shift
            shift
            ;;
        -c|--config-dir)
            CONFIG_DIR="$2"
            shift
            shift
            ;;
        -f|--file)
            CONFIG_FILE="$2"
            shift
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $key"
            usage
            ;;
    esac
done

# Main execution flow
log_info "Starting environment setup for ${ENV} environment"

# Set a specific environment file if provided, otherwise determine based on environment
if [[ -z "$CONFIG_FILE" ]]; then
    # Look for environment-specific file first
    if [[ -f "${CONFIG_DIR}/env/${ENV}.env" ]]; then
        CONFIG_FILE="${CONFIG_DIR}/env/${ENV}.env"
    elif [[ -f "${PROJECT_ROOT}/.env.${ENV}" ]]; then
        CONFIG_FILE="${PROJECT_ROOT}/.env.${ENV}"
    elif [[ -f "${PROJECT_ROOT}/.env" ]]; then
        CONFIG_FILE="${PROJECT_ROOT}/.env"
    else
        log_warning "No environment file found. Using default values."
    fi
fi

# Load environment variables from file if it exists
if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    load_env_file "$CONFIG_FILE" || {
        log_error "Failed to load environment variables from ${CONFIG_FILE}"
        exit 1
    }
fi

# Set up default values for any unset environment variables
setup_default_env

# Create required directories
setup_directories

# Verify that all required variables are set
verify_environment || {
    log_error "Environment verification failed"
    exit 1
}

# Print environment variables for verification
print_environment

log_info "Environment setup complete."
exit 0
