#!/bin/bash
# -----------------------------------------------------------------------------
# config_loader.sh - Loads environment-specific configuration files
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# Usage: source "$(dirname "$0")/../common/config_loader.sh"
# -----------------------------------------------------------------------------

# Import logging utilities if available
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
if [[ -f "$SCRIPT_DIR/logging_utils.sh" ]]; then
  source "$SCRIPT_DIR/logging_utils.sh"
else
  # Minimal logging if logging_utils is not available
  log_info() { echo "[INFO] $1"; }
  log_error() { echo "[ERROR] $1" >&2; }
  log_debug() { [[ "${DEBUG:-0}" -eq 1 ]] && echo "[DEBUG] $1"; }
fi

# Default locations
: "${CONFIG_DIR:=${SCRIPT_DIR}/../../config}"
: "${ENV_CONFIG_DIR:=${SCRIPT_DIR}/../../../deployment/environments}"
: "${DEFAULT_CONFIG_FILE:=${CONFIG_DIR}/monitoring.ini}"
: "${DEFAULT_ENV:=development}"

# Global associative array to store configuration
declare -A CONFIG

# Function to parse INI format into associative array
# Usage: parse_ini_file FILE [SECTION]
parse_ini_file() {
  local file="$1"
  local target_section="$2"
  local current_section=""

  if [[ ! -f "$file" ]]; then
    log_error "Configuration file not found: $file"
    return 1
  fi

  log_debug "Parsing configuration file: $file"

  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    # Trim whitespace
    key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # Skip comments and empty lines
    [[ -z "$key" || "$key" == \#* ]] && continue

    # Check for section header
    if [[ "$key" =~ ^\[(.*)\]$ ]]; then
      current_section="${BASH_REMATCH[1]}"
      continue
    fi

    # If we're targeting a specific section and this isn't it, skip
    if [[ -n "$target_section" && "$current_section" != "$target_section" ]]; then
      continue
    fi

    # Store in CONFIG with section prefix if we're in a section
    if [[ -n "$current_section" ]]; then
      CONFIG["${current_section}.${key}"]="$value"
      log_debug "Config: ${current_section}.${key}=${value}"
    else
      CONFIG["$key"]="$value"
      log_debug "Config: ${key}=${value}"
    fi
  done < "$file"
}

# Function to get a configuration value
# Usage: get_config KEY [DEFAULT_VALUE]
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
# Usage: set_config KEY VALUE
set_config() {
  local key="$1"
  local value="$2"

  CONFIG["$key"]="$value"
  log_debug "Config set: ${key}=${value}"
}

# Function to load environment-specific configuration
# Usage: load_env_config ENVIRONMENT
load_env_config() {
  local env="${1:-$DEFAULT_ENV}"
  local env_file="${ENV_CONFIG_DIR}/${env}.ini"

  log_info "Loading environment configuration for: $env"

  # Load default config first
  if [[ -f "$DEFAULT_CONFIG_FILE" ]]; then
    parse_ini_file "$DEFAULT_CONFIG_FILE"
  else
    log_warning "Default config file not found: $DEFAULT_CONFIG_FILE"
  fi

  # Then load environment-specific config
  if [[ -f "$env_file" ]]; then
    parse_ini_file "$env_file"
    log_info "Environment configuration loaded: $env_file"
  else
    log_warning "Environment configuration file not found: $env_file"
  fi

  # Set current environment in config
  set_config "environment" "$env"
}

# Function to load an additional configuration file
# Usage: load_additional_config FILENAME [SECTION]
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
  parse_ini_file "$file_path" "$section"
}

# Function to export all config to environment variables
# Usage: export_config_to_env [PREFIX]
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

# Function to display all loaded configuration
# Usage: display_config [SECTION]
display_config() {
  local target_section="$1"

  echo "=== Current Configuration ==="
  for key in "${!CONFIG[@]}"; do
    if [[ -n "$target_section" ]]; then
      if [[ "$key" == ${target_section}.* ]]; then
        echo "${key}=${CONFIG[$key]}"
      fi
    else
      echo "${key}=${CONFIG[$key]}"
    fi
  done
  echo "==========================="
}

# Main function to load all configuration
# Usage: load_config [ENVIRONMENT]
load_config() {
  local env="${1:-$DEFAULT_ENV}"
  load_env_config "$env"

  # Set some defaults if not defined
  : "${CONFIG[log.level]:=INFO}"
  : "${CONFIG[log.file]:=/var/log/monitoring.log}"

  # Configure logging if available
  if declare -f configure_logging >/dev/null; then
    configure_logging "${CONFIG[log.level]}" "${CONFIG[log.file]}"
  fi

  log_info "Configuration loaded successfully for environment: $env"
  return 0
}

# Execute if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  # If run directly, display usage
  echo "Configuration Loader Utility"
  echo "Usage: source $(basename "$0")"
  echo "Then call: load_config [environment]"
  echo ""
  echo "Example:"
  echo "  source ./$(basename "$0")"
  echo "  load_config production"
  echo "  value=$(get_config database.host localhost)"
  echo "  echo \"Database host: \$value\""
fi
