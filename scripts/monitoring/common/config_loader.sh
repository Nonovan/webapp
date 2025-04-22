#!/bin/bash
# -----------------------------------------------------------------------------
# config_loader.sh - Loads environment-specific configuration files
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# This script provides functions to load and manage configuration from INI files.
# It supports environment-specific configurations, section-based organization,
# and exporting configuration to environment variables.
#
# Usage: source "$(dirname "$0")/../common/config_loader.sh"
# -----------------------------------------------------------------------------

# Set strict error handling
set -o pipefail

# Script version for tracking changes and compatibility
readonly CONFIG_LOADER_VERSION="1.0.0"

# Import logging utilities if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/logging_utils.sh"
else
    # Minimal logging if logging_utils is not available
    log_info() { echo "[INFO] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${DEBUG:-0}" -eq 1 || "${VERBOSE:-false}" == "true" ]] && echo "[DEBUG] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
fi

# Default locations with more robust path handling
CONFIG_DIR="${CONFIG_DIR:-${SCRIPT_DIR}/../../config}"
ENV_CONFIG_DIR="${ENV_CONFIG_DIR:-${SCRIPT_DIR}/../../../deployment/environments}"
DEFAULT_CONFIG_FILE="${DEFAULT_CONFIG_FILE:-${CONFIG_DIR}/monitoring.ini}"
DEFAULT_ENV="${DEFAULT_ENV:-development}"

# Ensure the CONFIG_DIR exists
if [[ ! -d "$CONFIG_DIR" ]]; then
    log_warning "Config directory does not exist: $CONFIG_DIR"
    # Try to create it if we have permissions
    mkdir -p "$CONFIG_DIR" 2>/dev/null || log_warning "Failed to create config directory"
fi

# Global associative array to store configuration
declare -A CONFIG

# -----------------------------------------------------------------------------
# CONFIGURATION PARSING FUNCTIONS
# -----------------------------------------------------------------------------

# Function to parse INI format into associative array
# Arguments:
#   $1 - Configuration file path
#   $2 - Target section to load (optional, loads all sections if not specified)
# Returns:
#   0 if successful, 1 if error occurred
parse_ini_file() {
    local file="$1"
    local target_section="$2"
    local current_section=""
    local line_number=0
    local errors=0

    if [[ ! -f "$file" ]]; then
        log_error "Configuration file not found: $file"
        return 1
    fi

    log_debug "Parsing configuration file: $file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_number++))

        # Trim whitespace
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip comments and empty lines
        [[ -z "$line" || "$line" == \#* ]] && continue

        # Check for section header
        if [[ "$line" =~ ^\[(.*)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            log_debug "Entering section: $current_section"
            continue
        fi

        # Process key-value pairs
        if [[ "$line" =~ ^([^=]+)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Trim whitespace from key and value
            key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # If we're targeting a specific section and this isn't it, skip
            if [[ -n "$target_section" && "$current_section" != "$target_section" ]]; then
                continue
            }

            # Store in CONFIG with section prefix if we're in a section
            if [[ -n "$current_section" ]]; then
                CONFIG["${current_section}.${key}"]="$value"
                log_debug "Config: ${current_section}.${key}=${value}"
            else
                CONFIG["$key"]="$value"
                log_debug "Config: ${key}=${value}"
            fi
        else
            # Line doesn't match key=value format and isn't a section header
            if [[ -n "$line" ]]; then
                log_warning "Ignoring invalid line $line_number in $file: $line"
                ((errors++))
            fi
        fi
    done < "$file"

    if [[ $errors -gt 0 ]]; then
        log_warning "Found $errors invalid lines while parsing $file"
    fi

    return 0
}

# Function to get a configuration value
# Arguments:
#   $1 - Configuration key (with optional section prefix)
#   $2 - Default value if key not found (optional)
# Returns:
#   Configuration value or default value
get_config() {
    local key="$1"
    local default_value="$2"

    if [[ -n "${CONFIG[$key]}" ]]; then
        echo "${CONFIG[$key]}"
    elif [[ -n "$default_value" ]]; then
        echo "$default_value"
    else
        log_debug "Configuration key not found: $key"
        return 1
    fi
}

# Function to set a configuration value
# Arguments:
#   $1 - Configuration key (with optional section prefix)
#   $2 - Value to set
# Returns:
#   None
set_config() {
    local key="$1"
    local value="$2"

    CONFIG["$key"]="$value"
    log_debug "Config set: ${key}=${value}"
}

# Function to check if a configuration key exists
# Arguments:
#   $1 - Configuration key (with optional section prefix)
# Returns:
#   0 if key exists, 1 otherwise
has_config() {
    local key="$1"

    if [[ -n "${CONFIG[$key]}" ]]; then
        return 0
    else
        return 1
    fi
}

# -----------------------------------------------------------------------------
# CONFIGURATION LOADING FUNCTIONS
# -----------------------------------------------------------------------------

# Function to load environment-specific configuration
# Arguments:
#   $1 - Environment name (default: $DEFAULT_ENV)
# Returns:
#   0 if successful, 1 if critical error occurred
load_env_config() {
    local env="${1:-$DEFAULT_ENV}"
    local env_file="${ENV_CONFIG_DIR}/${env}.ini"
    local result=0

    log_info "Loading environment configuration for: $env"

    # Clear existing configuration if requested
    if [[ "${RESET_CONFIG:-false}" == "true" ]]; then
        log_debug "Clearing existing configuration"
        unset CONFIG
        declare -gA CONFIG
    fi

    # Load default config first
    if [[ -f "$DEFAULT_CONFIG_FILE" ]]; then
        parse_ini_file "$DEFAULT_CONFIG_FILE" || result=1
    else
        log_warning "Default config file not found: $DEFAULT_CONFIG_FILE"
    fi

    # Then load environment-specific config
    if [[ -f "$env_file" ]]; then
        parse_ini_file "$env_file" || result=1
        log_info "Environment configuration loaded: $env_file"
    else
        log_warning "Environment configuration file not found: $env_file"
    fi

    # Set current environment in config
    set_config "environment" "$env"

    return $result
}

# Function to load an additional configuration file
# Arguments:
#   $1 - Configuration filename or full path
#   $2 - Target section to load (optional)
# Returns:
#   0 if successful, 1 if error occurred
load_additional_config() {
    local filename="$1"
    local section="$2"
    local file_path=""

    # Check if file exists as provided
    if [[ -f "$filename" ]]; then
        file_path="$filename"
    # Check in CONFIG_DIR
    elif [[ -f "${CONFIG_DIR}/${filename}" ]]; then
        file_path="${CONFIG_DIR}/${filename}"
    # Check with .ini extension
    elif [[ -f "${CONFIG_DIR}/${filename}.ini" ]]; then
        file_path="${CONFIG_DIR}/${filename}.ini"
    else
        log_error "Cannot find configuration file: $filename"
        return 1
    fi

    log_info "Loading additional configuration from: $file_path"
    if parse_ini_file "$file_path" "$section"; then
        return 0
    else
        log_error "Failed to parse additional configuration file: $file_path"
        return 1
    fi
}

# Function to export all config to environment variables
# Arguments:
#   $1 - Environment variable prefix (default: MONITOR_)
# Returns:
#   None
export_config_to_env() {
    local prefix="${1:-MONITOR_}"

    log_debug "Exporting configuration to environment variables with prefix: $prefix"

    for key in "${!CONFIG[@]}"; do
        # Replace dots with underscores and convert to uppercase
        local env_var="${prefix}$(echo "${key}" | tr '[:lower:].' '[:upper:]_')"
        export "${env_var}"="${CONFIG[$key]}"
        log_debug "Exported: ${env_var}=${CONFIG[$key]}"
    done
}

# Function to load configuration from environment variables
# Arguments:
#   $1 - Environment variable prefix to match (default: MONITOR_)
# Returns:
#   None
load_config_from_env() {
    local prefix="${1:-MONITOR_}"

    log_debug "Loading configuration from environment variables with prefix: $prefix"

    # Get all environment variables that match the prefix
    while IFS='=' read -r name value; do
        if [[ $name == ${prefix}* ]]; then
            # Convert environment variable name to config key (lowercase, replace underscores with dots)
            local key="${name#$prefix}"
            key=$(echo "$key" | tr '[:upper:]_' '[:lower:].')

            # Set the configuration value
            CONFIG["$key"]="$value"
            log_debug "Loaded from env: ${key}=${value}"
        fi
    done < <(env)
}

# Function to save configuration to a file
# Arguments:
#   $1 - Output file path
#   $2 - Section filter (optional, saves only keys from this section)
# Returns:
#   0 if successful, 1 if error occurred
save_config() {
    local output_file="$1"
    local section_filter="$2"
    local sections=()
    local root_keys=()

    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$output_file")" 2>/dev/null || {
        log_error "Failed to create directory for config file: $output_file"
        return 1
    }

    # First pass: identify all sections and root keys
    for key in "${!CONFIG[@]}"; do
        if [[ "$key" == *"."* ]]; then
            local section="${key%%.*}"
            if [[ -z "$section_filter" || "$section" == "$section_filter" ]]; then
                if ! [[ " ${sections[*]} " =~ " ${section} " ]]; then
                    sections+=("$section")
                fi
            fi
        else
            if [[ -z "$section_filter" ]]; then
                root_keys+=("$key")
            fi
        fi
    done

    # Start writing the file
    : > "$output_file" || {
        log_error "Failed to write to config file: $output_file"
        return 1
    }

    # Add a file header
    echo "# Configuration file generated by config_loader.sh" > "$output_file"
    echo "# Generated on $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Write root keys first
    if [[ ${#root_keys[@]} -gt 0 ]]; then
        for key in "${root_keys[@]}"; do
            echo "${key}=${CONFIG[$key]}" >> "$output_file"
        done
        echo "" >> "$output_file"
    fi

    # Write each section
    for section in "${sections[@]}"; do
        echo "[$section]" >> "$output_file"

        # Find all keys in this section
        for key in "${!CONFIG[@]}"; do
            if [[ "$key" == "${section}."* ]]; then
                local param="${key#${section}.}"
                echo "${param}=${CONFIG[$key]}" >> "$output_file"
            fi
        done

        echo "" >> "$output_file"
    done

    log_info "Configuration saved to: $output_file"
    return 0
}

# -----------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -----------------------------------------------------------------------------

# Function to display all loaded configuration
# Arguments:
#   $1 - Section filter (optional, displays only keys from this section)
#   $2 - Format (optional, 'ini' or 'plain', default: 'plain')
# Returns:
#   None
display_config() {
    local section_filter="$1"
    local format="${2:-plain}"

    if [[ "$format" == "ini" ]]; then
        # Group by sections for ini format
        echo "# Current Configuration"

        # First display root keys
        local found_root=false
        for key in "${!CONFIG[@]}"; do
            if [[ "$key" != *"."* ]]; then
                if [[ -z "$section_filter" ]]; then
                    echo "${key}=${CONFIG[$key]}"
                    found_root=true
                fi
            fi
        done

        [[ "$found_root" == "true" ]] && echo ""

        # Then display sections
        local current_section=""
        for key in $(echo "${!CONFIG[@]}" | tr ' ' '\n' | sort); do
            if [[ "$key" == *"."* ]]; then
                local section="${key%%.*}"
                local param="${key#*.}"

                if [[ -z "$section_filter" || "$section" == "$section_filter" ]]; then
                    if [[ "$section" != "$current_section" ]]; then
                        [[ -n "$current_section" ]] && echo ""
                        echo "[$section]"
                        current_section="$section"
                    fi

                    echo "${param}=${CONFIG[$key]}"
                fi
            fi
        done
    else
        # Simple key-value display for plain format
        echo "=== Current Configuration ==="
        for key in $(echo "${!CONFIG[@]}" | tr ' ' '\n' | sort); do
            if [[ -n "$section_filter" ]]; then
                if [[ "$key" == "${section_filter}."* ]]; then
                    echo "${key}=${CONFIG[$key]}"
                fi
            else
                echo "${key}=${CONFIG[$key]}"
            fi
        done
        echo "==========================="
    fi
}

# Function to get all configuration keys
# Arguments:
#   $1 - Section filter (optional, returns only keys from this section)
# Returns:
#   List of configuration keys, one per line
get_config_keys() {
    local section_filter="$1"

    for key in "${!CONFIG[@]}"; do
        if [[ -n "$section_filter" ]]; then
            if [[ "$key" == "${section_filter}."* ]]; then
                echo "$key"
            fi
        else
            echo "$key"
        fi
    done | sort
}

# Function to get all configuration sections
# Returns:
#   List of unique section names, one per line
get_config_sections() {
    local sections=()

    for key in "${!CONFIG[@]}"; do
        if [[ "$key" == *"."* ]]; then
            local section="${key%%.*}"
            if ! [[ " ${sections[*]} " =~ " ${section} " ]]; then
                sections+=("$section")
            fi
        fi
    done

    # Output sorted sections
    (IFS=$'\n'; echo "${sections[*]}" | sort)
}

# -----------------------------------------------------------------------------
# MAIN LOADING FUNCTION
# -----------------------------------------------------------------------------

# Main function to load all configuration
# Arguments:
#   $1 - Environment name (default: $DEFAULT_ENV)
#   $2 - Additional config file to load (optional)
# Returns:
#   0 if successful, 1 if critical error occurred
load_config() {
    local env="${1:-$DEFAULT_ENV}"
    local additional_config="$2"
    local result=0

    # Load environment configuration
    load_env_config "$env" || result=1

    # Load additional configuration file if specified
    if [[ -n "$additional_config" ]]; then
        load_additional_config "$additional_config" || result=1
    fi

    # Set some defaults if not defined
    : "${CONFIG[log.level]:=INFO}"
    : "${CONFIG[log.file]:=/var/log/cloud-platform/monitoring.log}"

    # Create log directory if it doesn't exist (best effort)
    mkdir -p "$(dirname "${CONFIG[log.file]}")" 2>/dev/null || true

    # Configure logging if available
    if declare -f configure_logging >/dev/null; then
        configure_logging "${CONFIG[log.level]}" "${CONFIG[log.file]}"
    fi

    log_info "Configuration loaded successfully for environment: $env"
    return $result
}

# -----------------------------------------------------------------------------
# EXECUTION WHEN CALLED DIRECTLY
# -----------------------------------------------------------------------------

# Execute if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # If run directly, display usage and help information
    cat <<EOF
Configuration Loader Utility v${CONFIG_LOADER_VERSION}

This script provides functions to load and manage configuration from INI files.

Usage: source $(basename "$0")
Then call: load_config [environment] [additional_config_file]

Examples:
  source ./$(basename "$0")
  load_config production                      # Load production environment
  load_additional_config security.ini         # Load additional config file
  value=\$(get_config database.host localhost) # Get config with default value
  echo "Database host: \$value"                # Display the value
  display_config database                     # Show all database.* settings
  export_config_to_env APP_                   # Export all config to APP_* env vars
  save_config /tmp/current_config.ini         # Save current config to file

Available functions:
  load_config [env] [additional_file]        - Load all configuration
  load_env_config [env]                      - Load environment config
  load_additional_config <file> [section]    - Load additional config file
  get_config <key> [default_value]           - Get a config value
  set_config <key> <value>                   - Set a config value
  has_config <key>                           - Check if a key exists
  display_config [section] [format]          - Display loaded config
  export_config_to_env [prefix]              - Export config to env vars
  load_config_from_env [prefix]              - Load config from env vars
  save_config <file> [section]               - Save config to a file
  get_config_keys [section]                  - List all config keys
  get_config_sections                        - List all config sections
EOF
fi

# Export public functions
export -f parse_ini_file
export -f get_config
export -f set_config
export -f has_config
export -f load_env_config
export -f load_additional_config
export -f export_config_to_env
export -f load_config_from_env
export -f save_config
export -f display_config
export -f get_config_keys
export -f get_config_sections
export -f load_config
