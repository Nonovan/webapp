#!/bin/bash
# filepath: /Users/ivans/Workspace/myproject/scripts/utils/common_functions.sh
# Common Utility Functions for Cloud Infrastructure Platform
# Usage: source /scripts/utils/common_functions.sh [modules]
#
# This file serves as the main entry point that can load all or specific function modules.
# Available modules: core, system, advanced, all (default)

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

# Ensure the log directory exists
mkdir -p "$DEFAULT_LOG_DIR"

# Function to load specific modules
load_module() {
    local module="$1"
    local module_file="${SCRIPT_DIR}/lib/${module}_functions.sh"

    if [[ -f "$module_file" ]]; then
        # shellcheck source=/dev/null
        source "$module_file"
        return 0
    else
        echo "Module not found: ${module}" >&2
        return 1
    fi
}

# Determine which modules to load
if [[ $# -gt 0 && "$1" != "all" ]]; then
    # Parse comma-separated list of modules to load
    IFS=',' read -ra MODULES <<< "$1"

    for module in "${MODULES[@]}"; do
        load_module "$module"
    done
else
    # Default: load all modules
    load_module "core"
    load_module "system"
    load_module "advanced"
fi
