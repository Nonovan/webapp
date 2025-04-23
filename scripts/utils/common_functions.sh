#!/bin/bash
# filepath: scripts/utils/common_functions.sh
# Common Utility Functions for Cloud Infrastructure Platform
# Usage: source scripts/utils/common_functions.sh [modules]
#
# This file serves as the main entry point that can load all or specific function modules.
# Available modules: core, system, advanced, file_ops, validation, health, all (default)

# Version tracking
COMMON_FUNCTIONS_VERSION="1.0.0"
COMMON_FUNCTIONS_DATE="2024-07-31"

# Determine script location for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define common constants used across modules
DEFAULT_LOG_DIR="/var/log/cloud-platform"
DEFAULT_BACKUP_DIR="/var/backups/cloud-platform"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
ENV_FILE_DIR="${PROJECT_ROOT}/deployment/environments"
DEFAULT_ENVIRONMENT="production"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Text colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Module paths
COMMON_DIR="${SCRIPT_DIR}/common"

# Define available modules and their paths
# ENHANCEMENT #1: Added brief module descriptions to make each module's purpose clearer
declare -A MODULE_PATHS=(
  ["core"]="${COMMON_DIR}/common_core_utils.sh"          # Core logging and essential functions
  ["system"]="${COMMON_DIR}/common_system_utils.sh"      # System information and OS operations
  ["advanced"]="${COMMON_DIR}/common_advanced_utils.sh"  # Advanced system administration utilities
  ["file_ops"]="${COMMON_DIR}/common_file_ops_utils.sh"  # File operations and manipulation
  ["validation"]="${COMMON_DIR}/common_validation_utils.sh" # Input validation and sanitization
  ["health"]="${COMMON_DIR}/common_health_utils.sh"      # Health checks and monitoring
)

# Basic utility functions for this script
script_error() {
  echo -e "${RED}Error: $*${NC}" >&2
  return 1
}

script_warning() {
  echo -e "${YELLOW}Warning: $*${NC}" >&2
}

script_info() {
  if [[ "${QUIET:-false}" != "true" ]]; then
    echo -e "${GREEN}Info: $*${NC}"
  fi
}

# Get script version information
get_common_functions_version() {
  echo "${COMMON_FUNCTIONS_VERSION} (${COMMON_FUNCTIONS_DATE})"
}

# Function to check if basic command dependencies are available
check_dependencies() {
  local missing_deps=0
  local missing_list=""

  # Check for basic commands that we need
  for cmd in grep sed awk basename dirname; do
    if ! command -v "$cmd" &>/dev/null; then
      ((missing_deps++))
      missing_list="$missing_list $cmd"
    fi
  done

  if [[ $missing_deps -gt 0 ]]; then
    script_warning "Missing basic dependencies:$missing_list"
    return 1
  fi

  return 0
}

# Enhanced log directory creation with proper error handling
setup_log_directory() {
  # Try to create log directory with appropriate error handling
  if ! mkdir -p "$DEFAULT_LOG_DIR" 2>/dev/null; then
    script_warning "Could not create log directory at ${DEFAULT_LOG_DIR}"

    # Fall back to a directory we can write to
    if [[ -w "/tmp" ]]; then
      DEFAULT_LOG_DIR="/tmp/cloud-platform-logs"
      mkdir -p "$DEFAULT_LOG_DIR" 2>/dev/null || {
        script_error "Failed to create fallback log directory at ${DEFAULT_LOG_DIR}"
        return 1
      }
      script_info "Using fallback log directory: ${DEFAULT_LOG_DIR}"
    else
      script_error "Cannot create any log directory"
      return 1
    fi
  fi

  # Set secure permissions if we can
  if [[ -d "$DEFAULT_LOG_DIR" ]]; then
    chmod 750 "$DEFAULT_LOG_DIR" 2>/dev/null ||
      script_warning "Could not set secure permissions on log directory"
  fi

  return 0
}

# Function to check if a module exists
module_exists() {
  local module="$1"
  [[ -n "${MODULE_PATHS[$module]}" && -f "${MODULE_PATHS[$module]}" ]]
}

# Function to load specific modules with retry logic
load_module() {
  local module="$1"
  local retries="${2:-2}"
  local module_file="${MODULE_PATHS[$module]}"
  local attempt=1

  # Validate module parameter
  if [[ -z "$module" ]]; then
    script_error "No module name provided to load_module"
    return 1
  fi

  # Check if module exists in our map
  if [[ -z "$module_file" ]]; then
    script_error "Unknown module: ${module}"
    return 1
  fi

  # Check if module file exists
  if [[ ! -f "$module_file" ]]; then
    script_error "Module file not found: ${module} (${module_file})"
    return 1
  fi

  # Try loading the module with retries
  while ((attempt <= retries)); do
    # shellcheck source=/dev/null
    if source "$module_file" 2>/dev/null; then
      script_info "Loaded module: ${module}"
      return 0
    else
      if ((attempt < retries)); then
        script_warning "Attempt $attempt/$retries to load module ${module} failed, retrying..."
        sleep 1
      else
        script_error "Failed to load module after $retries attempts: ${module} (${module_file})"
      fi
      ((attempt++))
    fi
  done

  return 1
}

# Function to unload a module
unload_module() {
  local module="$1"
  local module_file="${MODULE_PATHS[$module]}"

  if [[ -z "$module" ]]; then
    script_error "No module name provided to unload_module"
    return 1
  fi

  if [[ -z "$module_file" ]]; then
    script_error "Unknown module: ${module}"
    return 1
  fi

  if [[ ! -f "$module_file" ]]; then
    script_error "Module file not found: ${module} (${module_file})"
    return 1
  fi

  # Get all functions from the module
  local functions
  functions=$(grep -E '^[a-zA-Z0-9_]+\(\)' "$module_file" 2>/dev/null | sed 's/().*$//')

  local unload_count=0
  for func in $functions; do
    if declare -F "$func" &>/dev/null; then
      unset -f "$func"
      ((unload_count++))
    fi
  done

  script_info "Unloaded $unload_count functions from module: ${module}"
  return 0
}

# Function to list available modules
list_available_modules() {
  echo "Available modules:"
  # Try to get module version if available
  for module in "${!MODULE_PATHS[@]}"; do
    local status="missing"
    local version=""
    local description=""

    if [[ -f "${MODULE_PATHS[$module]}" ]]; then
      status="found"

      # Try to extract version information
      if grep -q "_VERSION=" "${MODULE_PATHS[$module]}" 2>/dev/null; then
        version=$(grep -E "^[A-Z_]+_VERSION=" "${MODULE_PATHS[$module]}" | head -1 | cut -d= -f2 | tr -d '"')
        if [[ -n "$version" ]]; then
          version=" (v$version)"
        fi
      fi

      # Try to extract module description
      description=$(grep -A2 "^# " "${MODULE_PATHS[$module]}" | grep -v "#" | head -1 | sed 's/^#//' | xargs)
      if [[ -n "$description" ]]; then
        description=" - $description"
      fi
    fi

    echo "  - ${module}${version} (${status})${description}"
  done
  echo "  - all (loads all available modules)"
}

# ENHANCEMENT #2: Added parallel loading capability for non-dependent modules
# Function to load modules in parallel when possible
load_modules_parallel() {
  local modules=("$@")
  local pids=()
  local results=()
  local i=0
  local max_parallel=${PARALLEL_LOAD_MAX:-3} # Limit parallel processes

  # Skip if no modules to load
  if [[ ${#modules[@]} -eq 0 ]]; then
    return 0
  fi

  # If dependencies can't be skipped, use sequential loading
  if [[ "$SKIP_DEPENDENCIES" != "true" ]]; then
    for module in "${modules[@]}"; do
      load_module_with_dependencies "$module" || ((LOAD_FAILED++))
      ((MODULES_LOADED++))
    done
    return 0
  fi

  # Use parallel loading for independent modules
  script_info "Loading ${#modules[@]} modules in parallel mode (max $max_parallel concurrent)"

  # Create a temporary directory for status files
  local temp_dir
  temp_dir=$(mktemp -d) || {
    script_error "Failed to create temporary directory for parallel loading"
    # Fall back to sequential loading
    for module in "${modules[@]}"; do
      load_module "$module" || ((LOAD_FAILED++))
      ((MODULES_LOADED++))
    done
    return 0
  }

  for module in "${modules[@]}"; do
    # Only run max_parallel jobs at once
    if [[ ${#pids[@]} -ge $max_parallel ]]; then
      # Wait for any job to finish before starting a new one
      wait -n 2>/dev/null || true
      # Clean up finished jobs
      for ((j=0; j<${#pids[@]}; j++)); do
        if ! kill -0 "${pids[$j]}" 2>/dev/null; then
          # Check result file
          if [[ -f "${temp_dir}/result_${j}" ]] && [[ "$(cat "${temp_dir}/result_${j}")" == "0" ]]; then
            ((MODULES_LOADED++))
          else
            ((LOAD_FAILED++))
          fi
          # Remove job from array
          unset "pids[$j]"
          unset "results[$j]"
        fi
      done
      # Reindex arrays
      pids=("${pids[@]}")
      results=("${results[@]}")
    fi

    # Launch module loading in background
    (
      if load_module "$module"; then
        echo "0" > "${temp_dir}/result_$i"
      else
        echo "1" > "${temp_dir}/result_$i"
      fi
    ) &

    pids[$i]=$!
    results[$i]="${temp_dir}/result_$i"
    ((i++))
  done

  # Wait for remaining jobs
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  # Process final results
  for ((j=0; j<i; j++)); do
    if [[ -f "${temp_dir}/result_${j}" ]] && [[ "$(cat "${temp_dir}/result_${j}")" == "0" ]]; then
      ((MODULES_LOADED++))
    else
      ((LOAD_FAILED++))
    fi
  done

  # Clean up
  rm -rf "$temp_dir"

  return 0
}

# Function to load dependencies between modules automatically
load_module_with_dependencies() {
  local module="$1"
  local dependency_loaded=false

  # Core module is a dependency for most others
  if [[ "$module" != "core" && ! $(declare -F log) ]]; then
    script_info "Module $module depends on core, loading core first..."
    load_module "core" || {
      script_error "Failed to load core dependency for $module"
      return 1
    }
    dependency_loaded=true
  fi

  # Module-specific dependencies
  case "$module" in
    advanced)
      # Advanced depends on system
      if ! declare -F get_system_info &>/dev/null; then
        script_info "Module $module depends on system, loading system first..."
        load_module "system" || {
          script_error "Failed to load system dependency for $module"
          return 1
        }
        dependency_loaded=true
      fi
      ;;
    file_ops)
      # No specific dependencies beyond core
      ;;
    validation)
      # No specific dependencies beyond core
      ;;
    health)
      # Health might depend on file_ops
      if ! declare -F create_temp_dir &>/dev/null && module_exists "file_ops"; then
        script_info "Module $module may use file_ops, loading file_ops first..."
        load_module "file_ops" || script_warning "Could not load optional file_ops dependency for $module"
        # Continue even if this fails as it's not a hard dependency
      fi
      ;;
  esac

  # Finally load the requested module
  load_module "$module" || return 1

  return 0
}

# Show detailed help information
show_help() {
  cat <<HELP
Usage: source $(basename "$0") [OPTIONS] [modules]

Load utility functions for the Cloud Infrastructure Platform.
If no modules are specified, all available modules will be loaded.

Options:
  --help, -h     Show this help
  --list, -l     List available modules
  --version, -v  Show version information
  --quiet, -q    Suppress informational messages
  --no-deps      Skip automatic dependency resolution
  --parallel     Load modules in parallel when possible
  --config FILE  Use custom configuration file

Available modules can be specified as a comma-separated list:
  core,system,advanced,file_ops,validation,health

Examples:
  source $(basename "$0") core,file_ops
  source $(basename "$0") --quiet all
  source $(basename "$0") --no-deps validation
  source $(basename "$0") --parallel file_ops,validation,health

Version: $(get_common_functions_version)
HELP
}

# ENHANCEMENT #3: Added configuration file support
# Function to load configuration from file
load_config_file() {
  local config_file="$1"

  if [[ ! -f "$config_file" ]]; then
    script_warning "Configuration file not found: $config_file"
    return 1
  }

  script_info "Loading configuration from $config_file"

  # Read configuration file
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    # Skip comments and empty lines
    [[ "$key" =~ ^[[:space:]]*# || -z "$key" ]] && continue

    # Remove leading/trailing whitespace
    key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    case "$key" in
      DEFAULT_LOG_DIR)
        DEFAULT_LOG_DIR="$value"
        ;;
      DEFAULT_BACKUP_DIR)
        DEFAULT_BACKUP_DIR="$value"
        ;;
      DEFAULT_ENVIRONMENT)
        DEFAULT_ENVIRONMENT="$value"
        ;;
      MODULES)
        # Will be processed in the main script
        CONFIG_MODULES="$value"
        ;;
      QUIET)
        if [[ "$value" == "true" ]]; then
          QUIET=true
        fi
        ;;
      SKIP_DEPENDENCIES)
        if [[ "$value" == "true" ]]; then
          SKIP_DEPENDENCIES=true
        fi
        ;;
      PARALLEL_LOAD)
        if [[ "$value" == "true" ]]; then
          PARALLEL_LOAD=true
        fi
        ;;
      PARALLEL_LOAD_MAX)
        if [[ "$value" =~ ^[0-9]+$ ]]; then
          PARALLEL_LOAD_MAX="$value"
        fi
        ;;
      *)
        script_warning "Unknown configuration key: $key"
        ;;
    esac
  done < "$config_file"

  return 0
}

# Check bash version - minimum 4.0 required for associative arrays
if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
  script_error "This script requires Bash 4.0 or newer. You have ${BASH_VERSION}"
  return 1 2>/dev/null || exit 1
fi

# Check for dependencies first
check_dependencies || script_warning "Some basic dependencies are missing. Script may not work correctly."

# Setup log directory with better error handling
setup_log_directory || script_warning "Log directory setup failed, logging to stdout/stderr only"

# Process command line options
QUIET=false
SKIP_DEPENDENCIES=false
PARALLEL_LOAD=false
PARALLEL_LOAD_MAX=3
CONFIG_FILE=""
CONFIG_MODULES=""

# Process options
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      show_help
      # Don't execute the rest of the script when sourced
      return 0 2>/dev/null || exit 0
      ;;
    --list|-l)
      list_available_modules
      # Don't execute the rest of the script when sourced
      return 0 2>/dev/null || exit 0
      ;;
    --version|-v)
      echo "$(basename "$0") version $(get_common_functions_version)"
      # Don't execute the rest of the script when sourced
      return 0 2>/dev/null || exit 0
      ;;
    --quiet|-q)
      QUIET=true
      shift
      ;;
    --no-deps)
      SKIP_DEPENDENCIES=true
      shift
      ;;
    --parallel)
      PARALLEL_LOAD=true
      shift
      ;;
    --config)
      if [[ -n "$2" ]]; then
        CONFIG_FILE="$2"
        shift 2
      else
        script_error "Missing argument for --config"
        return 1 2>/dev/null || exit 1
      fi
      ;;
    *)
      # Not an option, assume it's the module list
      break
      ;;
  esac
done

# Load configuration file if specified
if [[ -n "$CONFIG_FILE" ]]; then
  load_config_file "$CONFIG_FILE"
fi

# Determine which modules to load
LOAD_FAILED=0
MODULES_LOADED=0

# If modules specified in config and no command line modules, use config modules
if [[ -n "$CONFIG_MODULES" && $# -eq 0 ]]; then
  set -- "$CONFIG_MODULES"
fi

if [[ $# -gt 0 && "$1" != "all" ]]; then
  # Parse comma-separated list of modules to load
  IFS=',' read -ra MODULES <<< "$1"

  if [[ "$PARALLEL_LOAD" == "true" ]]; then
    # Filter out modules that exist
    VALID_MODULES=()
    for module in "${MODULES[@]}"; do
      if module_exists "$module"; then
        VALID_MODULES+=("$module")
      else
        script_error "Module not found: ${module}"
        ((LOAD_FAILED++))
      fi
    done

    # Load modules in parallel
    load_modules_parallel "${VALID_MODULES[@]}"
  else
    # Load modules sequentially
    for module in "${MODULES[@]}"; do
      if module_exists "$module"; then
        if [[ "$SKIP_DEPENDENCIES" == "true" ]]; then
          load_module "$module" || ((LOAD_FAILED++))
        else
          load_module_with_dependencies "$module" || ((LOAD_FAILED++))
        fi
        ((MODULES_LOADED++))
      else
        script_error "Module not found: ${module}"
        ((LOAD_FAILED++))
      fi
    done
  fi

  # If no valid modules were specified, show help
  if [[ $MODULES_LOADED -eq 0 ]]; then
    script_warning "No valid modules specified."
    list_available_modules
  fi
else
  # Default: load all available modules
  script_info "Loading all available modules..."

  # Always load core module first since others may depend on it
  if module_exists "core"; then
    load_module "core" || ((LOAD_FAILED++))
    ((MODULES_LOADED++))
  else
    script_warning "Core module not found, other modules may fail to load correctly"
  fi

  # Collect remaining modules
  REMAINING_MODULES=()
  for module in "${!MODULE_PATHS[@]}"; do
    if [[ "$module" != "core" && -f "${MODULE_PATHS[$module]}" ]]; then
      REMAINING_MODULES+=("$module")
    elif [[ "$module" != "core" ]]; then
      script_warning "Skipping missing module: ${module}"
    fi
  done

  # Load remaining modules either in parallel or sequentially
  if [[ "$PARALLEL_LOAD" == "true" && ${#REMAINING_MODULES[@]} -gt 0 ]]; then
    load_modules_parallel "${REMAINING_MODULES[@]}"
  else
    for module in "${REMAINING_MODULES[@]}"; do
      if [[ "$SKIP_DEPENDENCIES" == "true" ]]; then
        load_module "$module" || ((LOAD_FAILED++))
      else
        load_module_with_dependencies "$module" || ((LOAD_FAILED++))
      fi
      ((MODULES_LOADED++))
    done
  fi
fi

# Check for core module specifically as many functions depend on it
if ! declare -f log &>/dev/null; then
  script_warning "Core module functions not available. Some functionality may be limited."
fi

# Display final status if any modules failed to load
if [[ $LOAD_FAILED -gt 0 ]]; then
  script_warning "${LOAD_FAILED} module(s) failed to load."
fi

# Display success message
if [[ $MODULES_LOADED -gt 0 && $LOAD_FAILED -eq 0 ]]; then
  script_info "Successfully loaded ${MODULES_LOADED} module(s)"
fi

# Export common environment variables that might be needed by scripts
export SCRIPT_DIR
export PROJECT_ROOT
export ENV_FILE_DIR
export DEFAULT_LOG_DIR
export DEFAULT_BACKUP_DIR
export DEFAULT_ENVIRONMENT
export TIMESTAMP
export COMMON_FUNCTIONS_VERSION
export COMMON_FUNCTIONS_DATE

# Clean up any temporary variables we don't need to export
unset module module_file MODULES MODULES_LOADED LOAD_FAILED
unset CONFIG_FILE CONFIG_MODULES
