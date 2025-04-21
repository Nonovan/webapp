#!/bin/bash
# Environment Configuration Sync Script for Cloud Infrastructure Platform
# This script syncs configurations between environments while respecting environment-specific settings
# Usage: ./env_sync.sh --source <env> --target <env> [options]
#
# Copyright (c) 2023-2024 Cloud Infrastructure Platform

# Strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SOURCE_ENV="production"
TARGET_ENV=""
CONFIG_DIR="${PROJECT_ROOT}/config"
LOG_FILE="/var/log/cloud-platform/env_sync.log"
BACKUP_DIR="/var/backups/cloud-platform/config_sync"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
DRY_RUN=false
FORCE=false
EXCLUDE_PATTERNS=()
INCLUDE_PATTERNS=()
VERBOSE=false
SPECIAL_HANDLING=true
SYNC_SECRETS=false
PRESERVE_ENV_VALUES=true
INTERACTIVE=true

# Create necessary directories
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"

# Load common functions if available
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
else
    # Basic logging function if common functions unavailable
    log() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local message="$1"
        local level="${2:-INFO}"
        echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    }
    
    error_exit() {
        log "$1" "ERROR"
        exit 1
    }
fi

# Display usage information
usage() {
    cat <<EOF
Environment Configuration Sync Script for Cloud Infrastructure Platform

Usage: $(basename "$0") --source <env> --target <env> [options]

Required:
  --source, -s ENV          Source environment (default: production)
                            Valid values: development, staging, production, dr-recovery
  --target, -t ENV          Target environment
                            Valid values: development, staging, production, dr-recovery

Options:
  --include PATTERN         Include only files matching pattern (can be specified multiple times)
  --exclude PATTERN         Exclude files matching pattern (can be specified multiple times)
  --no-preserve-env         Don't preserve environment-specific values in target config
  --sync-secrets            Also sync secrets (disabled by default)
  --no-special-handling     Disable special handling of certain configuration types
  --non-interactive, -y     Don't prompt for confirmations
  --dry-run                 Show what would be synced without making changes
  --force, -f               Overwrite target files without prompting
  --verbose, -v             Enable verbose output
  --help, -h                Show this help message

Examples:
  $(basename "$0") --source production --target staging
  $(basename "$0") --source production --target staging --include "security*" --exclude "*.bak"
  $(basename "$0") --source staging --target development --dry-run
EOF
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --source|-s)
            SOURCE_ENV="$2"
            shift 2
            ;;
        --target|-t)
            TARGET_ENV="$2"
            shift 2
            ;;
        --include)
            INCLUDE_PATTERNS+=("$2")
            shift 2
            ;;
        --exclude)
            EXCLUDE_PATTERNS+=("$2")
            shift 2
            ;;
        --no-preserve-env)
            PRESERVE_ENV_VALUES=false
            shift
            ;;
        --sync-secrets)
            SYNC_SECRETS=true
            shift
            ;;
        --no-special-handling)
            SPECIAL_HANDLING=false
            shift
            ;;
        --non-interactive|-y)
            INTERACTIVE=false
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            error_exit "Unknown option: $1"
            ;;
    esac
done

# Validate environments
validate_environment() {
    local env=$1
    local valid_envs=("development" "staging" "production" "dr-recovery")
    
    for valid_env in "${valid_envs[@]}"; do
        if [[ "$env" == "$valid_env" ]]; then
            return 0
        fi
    done
    
    error_exit "Invalid environment: $env"
}

validate_environment "$SOURCE_ENV"
if [[ -z "$TARGET_ENV" ]]; then
    error_exit "Target environment must be specified with --target"
fi
validate_environment "$TARGET_ENV"

if [[ "$SOURCE_ENV" == "$TARGET_ENV" ]]; then
    error_exit "Source and target environments cannot be the same"
fi

# Define key environment-specific config files
ENV_SPECIFIC_FILES=(
    "app.ini"
    "database.ini"
    "security.ini"
    "logging.ini"
    "monitoring.ini"
    "api.ini"
    "storage.ini"
    "cache.ini"
    "email.ini"
)

# Define key environment-specific variables to preserve
ENV_SPECIFIC_VARS=(
    "debug"
    "log_level"
    "environment"
    "environment_name"
    "host"
    "port"
    "username"
    "password"
    "database"
    "api_key"
    "secret_key"
    "base_url"
    "allowed_hosts"
    "redis_host"
    "redis_port"
    "cache_ttl"
    "timeout"
    "smtp_host"
    "smtp_port"
    "smtp_user"
    "smtp_password"
    "storage_path"
    "media_url"
    "static_url"
    "monitor_interval"
    "alert_threshold"
    "endpoint"
)

# Check if source environment exists
SOURCE_CONFIG_DIR="${CONFIG_DIR}/${SOURCE_ENV}"
TARGET_CONFIG_DIR="${CONFIG_DIR}/${TARGET_ENV}"

if [[ ! -d "$SOURCE_CONFIG_DIR" ]]; then
    error_exit "Source environment config directory not found: $SOURCE_CONFIG_DIR"
fi

# Create target directory if it doesn't exist
if [[ ! -d "$TARGET_CONFIG_DIR" ]]; then
    log "Creating target environment directory: $TARGET_CONFIG_DIR"
    if [[ "$DRY_RUN" == false ]]; then
        mkdir -p "$TARGET_CONFIG_DIR" || error_exit "Failed to create target directory: $TARGET_CONFIG_DIR"
    fi
fi

# Function to check if a file should be included based on patterns
should_include_file() {
    local file=$(basename "$1")
    
    # If include patterns are specified, file must match at least one
    if [[ ${#INCLUDE_PATTERNS[@]} -gt 0 ]]; then
        local included=false
        for pattern in "${INCLUDE_PATTERNS[@]}"; do
            if [[ "$file" == $pattern ]]; then
                included=true
                break
            fi
        done
        
        if [[ "$included" == false ]]; then
            return 1
        fi
    fi
    
    # Check if file matches any exclude pattern
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        if [[ "$file" == $pattern ]]; then
            return 1
        fi
    done
    
    # By default, don't sync secrets unless explicitly enabled
    if [[ "$SYNC_SECRETS" == false && ( "$file" == *"secret"* || "$file" == *"password"* || "$file" == *"credential"* ) ]]; then
        if [[ "$VERBOSE" == true ]]; then
            log "Skipping secret file: $file (use --sync-secrets to include)" "DEBUG"
        fi
        return 1
    fi
    
    return 0
}

# Function to create a backup of the target file
backup_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    
    local backup_file="${BACKUP_DIR}/$(basename "$file").${TARGET_ENV}.${TIMESTAMP}.bak"
    if [[ "$VERBOSE" == true ]]; then
        log "Creating backup: $backup_file" "DEBUG"
    fi
    
    if [[ "$DRY_RUN" == false ]]; then
        cp "$file" "$backup_file" || error_exit "Failed to create backup: $backup_file"
    fi
}

# Function to copy file with special handling for env-specific config files
sync_file() {
    local source_file="$1"
    local target_file="$2"
    local file_name=$(basename "$source_file")
    local is_special=false
    
    # Check if this is a special file that needs environment-specific handling
    if [[ "$SPECIAL_HANDLING" == true ]]; then
        for special_file in "${ENV_SPECIFIC_FILES[@]}"; do
            if [[ "$file_name" == "$special_file" ]]; then
                is_special=true
                break
            fi
        done
    fi
    
    # Create backup of target file if it exists
    if [[ -f "$target_file" ]]; then
        backup_file "$target_file"
    fi
    
    if [[ "$is_special" == true && "$PRESERVE_ENV_VALUES" == true && -f "$target_file" ]]; then
        log "Syncing special config file: $file_name (preserving environment values)" "INFO"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "[DRY RUN] Would merge $source_file to $target_file preserving environment values" "INFO"
            return 0
        fi
        
        # Create a temporary file for the merged config
        local temp_file=$(mktemp)
        
        # Copy source file as a starting point
        cp "$source_file" "$temp_file"
        
        # For each environment-specific variable, keep the target's value
        for var in "${ENV_SPECIFIC_VARS[@]}"; do
            # Check if variable exists in target
            if grep -q "^${var}\s*=" "$target_file"; then
                local target_value=$(grep "^${var}\s*=" "$target_file" | cut -d'=' -f2- | sed 's/^[ \t]*//')
                
                # Check if variable exists in source
                if grep -q "^${var}\s*=" "$temp_file"; then
                    # Replace value in temp file with target value
                    sed -i "s|^${var}\s*=.*|${var} = ${target_value}|" "$temp_file"
                    if [[ "$VERBOSE" == true ]]; then
                        log "Preserved ${var} = ${target_value}" "DEBUG"
                    fi
                fi
            fi
            
            # Also handle section-specific variables (e.g., [database].host)
            if grep -q "\[.*\]" "$target_file"; then
                # Get all sections
                local sections=$(grep -o "\[.*\]" "$target_file" | tr -d '[]')
                for section in $sections; do
                    # Check if section exists in both files
                    if ! grep -q "^\[${section}\]" "$temp_file"; then
                        continue
                    fi
                    
                    # Check if variable exists in this section in target
                    if grep -A 50 "^\[${section}\]" "$target_file" | grep -q "^${var}\s*="; then
                        local target_sectioned_value=$(grep -A 50 "^\[${section}\]" "$target_file" | grep "^${var}\s*=" | head -1 | cut -d'=' -f2- | sed 's/^[ \t]*//')
                        
                        # Check if variable exists in section in source/temp
                        if grep -A 50 "^\[${section}\]" "$temp_file" | grep -q "^${var}\s*="; then
                            # Get line number of section and variable
                            local section_line=$(grep -n "^\[${section}\]" "$temp_file" | cut -d: -f1)
                            local var_line=$(tail -n +$section_line "$temp_file" | grep -n "^${var}\s*=" | head -1 | cut -d: -f1)
                            var_line=$((section_line + var_line - 1))
                            
                            # Replace value
                            sed -i "${var_line}s|^${var}\s*=.*|${var} = ${target_sectioned_value}|" "$temp_file"
                            if [[ "$VERBOSE" == true ]]; then
                                log "Preserved [${section}].${var} = ${target_sectioned_value}" "DEBUG"
                            fi
                        fi
                    fi
                done
            fi
        done
        
        # Replace target with merged file
        mv "$temp_file" "$target_file"
    else
        # Simple file copy for non-special files or when not preserving env values
        log "Syncing file: $file_name" "INFO"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "[DRY RUN] Would copy $source_file to $target_file" "INFO"
        else
            cp "$source_file" "$target_file" || error_exit "Failed to copy $source_file to $target_file"
        fi
    fi
}

# Function to handle special things like updating environment-specific references
post_process_file() {
    local file="$1"
    local file_name=$(basename "$file")
    
    if [[ "$DRY_RUN" == true || ! -f "$file" ]]; then
        return 0
    fi
    
    # Replace environment references
    if grep -q "$SOURCE_ENV" "$file"; then
        log "Replacing environment references in $file_name" "INFO"
        sed -i "s/${SOURCE_ENV}/${TARGET_ENV}/g" "$file"
    fi
    
    # Handle special files with additional processing
    case "$file_name" in
        # Special handling for specific config files
        "security.ini")
            # Update security settings based on environment
            if [[ "$TARGET_ENV" == "development" ]]; then
                # Less strict settings for development
                sed -i "s/^strict_transport_security\s*=.*/strict_transport_security = false/" "$file" 2>/dev/null || true
                sed -i "s/^content_security_policy_report_only\s*=.*/content_security_policy_report_only = true/" "$file" 2>/dev/null || true
            elif [[ "$TARGET_ENV" == "production" || "$TARGET_ENV" == "dr-recovery" ]]; then
                # Stricter settings for production
                sed -i "s/^strict_transport_security\s*=.*/strict_transport_security = true/" "$file" 2>/dev/null || true
                sed -i "s/^content_security_policy_report_only\s*=.*/content_security_policy_report_only = false/" "$file" 2>/dev/null || true
            fi
            ;;
        "logging.ini")
            # Set appropriate log levels based on environment
            if [[ "$TARGET_ENV" == "development" ]]; then
                sed -i "s/^log_level\s*=.*/log_level = debug/" "$file" 2>/dev/null || true
            elif [[ "$TARGET_ENV" == "staging" ]]; then
                sed -i "s/^log_level\s*=.*/log_level = info/" "$file" 2>/dev/null || true
            elif [[ "$TARGET_ENV" == "production" || "$TARGET_ENV" == "dr-recovery" ]]; then
                sed -i "s/^log_level\s*=.*/log_level = warning/" "$file" 2>/dev/null || true
            fi
            ;;
    esac
}

# Main sync function
sync_environment_configs() {
    log "Starting sync from $SOURCE_ENV to $TARGET_ENV" "INFO"
    
    # Get all files from source directory
    local count=0
    local skipped=0
    
    # Create temporary directory for handling symlinks
    local temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT
    
    # Initial confirmation for non-dry runs
    if [[ "$DRY_RUN" == false && "$INTERACTIVE" == true && "$FORCE" == false ]]; then
        read -p "This will sync configs from $SOURCE_ENV to $TARGET_ENV. Continue? (y/N): " response
        case "$response" in
            [yY][eE][sS]|[yY]) 
                # Continue
                ;;
            *)
                log "Sync cancelled by user" "INFO"
                exit 0
                ;;
        esac
    fi
    
    # Count total files for progress reporting
    local total_files=0
    for source_file in "$SOURCE_CONFIG_DIR"/*; do
        if [[ ! -f "$source_file" ]]; then
            continue
        fi
        
        local file_name=$(basename "$source_file")
        if should_include_file "$file_name"; then
            ((total_files++))
        fi
    done
    
    log "Found $total_files files to process" "INFO"
    
    # Process each file
    local current=0
    for source_file in "$SOURCE_CONFIG_DIR"/*; do
        if [[ ! -f "$source_file" ]]; then
            continue
        fi
        
        local file_name=$(basename "$source_file")
        local target_file="$TARGET_CONFIG_DIR/$file_name"
        
        # Check if file should be included
        if ! should_include_file "$file_name"; then
            if [[ "$VERBOSE" == true ]]; then
                log "Skipping file (excluded by pattern): $file_name" "DEBUG"
            fi
            ((skipped++))
            continue
        fi
        
        ((current++))
        if [[ "$total_files" -gt 10 ]]; then
            log "Processing file $current/$total_files: $file_name" "INFO"
        fi
        
        # Check if target file already exists and if we should overwrite
        if [[ -f "$target_file" && "$FORCE" == false ]]; then
            if [[ "$DRY_RUN" == false && "$INTERACTIVE" == true ]]; then
                read -p "File $file_name already exists in target. Overwrite? (y/N): " response
                case "$response" in
                    [yY][eE][sS]|[yY]) 
                        # Continue with sync
                        ;;
                    *)
                        log "Skipping file (not overwriting): $file_name" "INFO"
                        ((skipped++))
                        continue
                        ;;
                esac
            elif [[ "$DRY_RUN" == true ]]; then
                log "[DRY RUN] Would prompt to overwrite $file_name" "INFO"
            fi
        fi
        
        # Sync the file
        sync_file "$source_file" "$target_file"
        
        # Post-process the file (update environment references)
        if [[ "$DRY_RUN" == false ]]; then
            post_process_file "$target_file"
        fi
        
        ((count++))
    done
    
    log "Sync completed: $count files synced, $skipped files skipped" "INFO"
    
    # Adjust permissions on target directory
    if [[ "$DRY_RUN" == false && -d "$TARGET_CONFIG_DIR" ]]; then
        # Set secure permissions on config files
        log "Setting appropriate permissions on configuration files" "INFO"
        find "$TARGET_CONFIG_DIR" -type f -name "*.ini" -exec chmod 640 {} \; 2>/dev/null || log "Warning: Could not set permissions on INI files" "WARNING"
        find "$TARGET_CONFIG_DIR" -type f -name "*secret*" -exec chmod 600 {} \; 2>/dev/null || log "Warning: Could not set permissions on secret files" "WARNING"
        find "$TARGET_CONFIG_DIR" -type f -name "*.key" -exec chmod 600 {} \; 2>/dev/null || log "Warning: Could not set permissions on key files" "WARNING"
        find "$TARGET_CONFIG_DIR" -type f -name "*.token" -exec chmod 600 {} \; 2>/dev/null || log "Warning: Could not set permissions on token files" "WARNING"
    fi
}

# Function to handle environment-specific settings file
update_env_settings_file() {
    local source_env_file="${PROJECT_ROOT}/deployment/environments/${SOURCE_ENV}.env"
    local target_env_file="${PROJECT_ROOT}/deployment/environments/${TARGET_ENV}.env"
    
    if [[ -f "$source_env_file" ]]; then
        log "Processing environment settings file for ${TARGET_ENV}" "INFO"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "[DRY RUN] Would update environment settings file: $target_env_file" "INFO"
            return 0
        fi
        
        # Backup target env file if it exists
        if [[ -f "$target_env_file" ]]; then
            local backup_file="${BACKUP_DIR}/$(basename "$target_env_file").${TIMESTAMP}.bak"
            cp "$target_env_file" "$backup_file" || error_exit "Failed to create backup: $backup_file"
            log "Created backup of environment file: $backup_file" "INFO"
        fi
        
        # If target doesn't exist, create it from source with environment name updated
        if [[ ! -f "$target_env_file" ]]; then
            cp "$source_env_file" "$target_env_file" || error_exit "Failed to copy $source_env_file to $target_env_file"
            # Update environment name
            sed -i "s/^ENVIRONMENT=.*/ENVIRONMENT=${TARGET_ENV}/" "$target_env_file"
            log "Created new environment file: $target_env_file" "INFO"
        else
            # For existing files, perform a more careful update
            local temp_file=$(mktemp)
            
            # Start with source file
            cp "$source_env_file" "$temp_file"
            
            # Update environment name
            sed -i "s/^ENVIRONMENT=.*/ENVIRONMENT=${TARGET_ENV}/" "$temp_file"
            
            # Keep target-specific values for selected variables
            for var in "DEBUG" "LOG_LEVEL" "DATABASE_URL" "SECRET_KEY" "ALLOWED_HOSTS" "API_KEY" "BASE_URL" "REDIS_URL" "CACHE_TTL" "STORAGE_PATH" "MEDIA_URL" "STATIC_URL"; do
                if grep -q "^${var}=" "$target_env_file"; then
                    local target_value=$(grep "^${var}=" "$target_env_file" | cut -d'=' -f2-)
                    if grep -q "^${var}=" "$temp_file"; then
                        sed -i "s|^${var}=.*|${var}=${target_value}|" "$temp_file"
                        if [[ "$VERBOSE" == true ]]; then
                            log "Preserved ${var}=${target_value}" "DEBUG"
                        fi
                    fi
                fi
            done
            
            # Replace target with updated file
            mv "$temp_file" "$target_env_file"
            log "Updated environment settings file: $target_env_file" "INFO"
        fi
        
        # Set proper permissions
        chmod 640 "$target_env_file" 2>/dev/null || log "Warning: Could not set permissions on environment file" "WARNING"
        
    else
        log "Source environment file not found: $source_env_file" "WARNING"
    fi
}

# Function to sync symbolic links
sync_symlinks() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY RUN] Would sync symbolic links" "INFO"
        return 0
    fi
    
    log "Syncing symbolic links..." "INFO"
    
    # Find all symlinks in source directory
    local symlink_count=0
    for source_link in $(find "$SOURCE_CONFIG_DIR" -type l); do
        local link_name=$(basename "$source_link")
        local target_link="${TARGET_CONFIG_DIR}/${link_name}"
        
        # Skip if excluded
        if ! should_include_file "$link_name"; then
            if [[ "$VERBOSE" == true ]]; then
                log "Skipping symlink (excluded by pattern): $link_name" "DEBUG"
            fi
            continue
        fi
        
        # Get the target of the source symlink
        local link_target=$(readlink "$source_link")
        
        # Create symlink in target directory
        if [[ -L "$target_link" ]]; then
            rm "$target_link" || error_exit "Failed to remove existing symlink: $target_link"
        fi
        
        ln -s "$link_target" "$target_link" || error_exit "Failed to create symlink: $target_link -> $link_target"
        ((symlink_count++))
        
        if [[ "$VERBOSE" == true ]]; then
            log "Created symlink: $target_link -> $link_target" "DEBUG"
        fi
    done
    
    if [[ "$symlink_count" -gt 0 ]]; then
        log "Synced $symlink_count symbolic links" "INFO"
    else
        log "No symbolic links to sync" "INFO"
    fi
}

# Execute the sync
log "Starting environment configuration sync script" "INFO"
log "Source environment: $SOURCE_ENV" "INFO"
log "Target environment: $TARGET_ENV" "INFO"

# Log details about the sync if verbose
if [[ "$VERBOSE" == true ]]; then
    log "Source config directory: $SOURCE_CONFIG_DIR" "DEBUG"
    log "Target config directory: $TARGET_CONFIG_DIR" "DEBUG"
    log "Preserve env values: $PRESERVE_ENV_VALUES" "DEBUG"
    log "Sync secrets: $SYNC_SECRETS" "DEBUG"
    log "Special handling: $SPECIAL_HANDLING" "DEBUG"
    log "Interactive mode: $INTERACTIVE" "DEBUG"
    log "Dry run: $DRY_RUN" "DEBUG"
    log "Force: $FORCE" "DEBUG"
    
    if [[ ${#INCLUDE_PATTERNS[@]} -gt 0 ]]; then
        log "Include patterns: ${INCLUDE_PATTERNS[*]}" "DEBUG"
    fi
    
    if [[ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]]; then
        log "Exclude patterns: ${EXCLUDE_PATTERNS[*]}" "DEBUG"
    fi
fi

# Perform the sync
sync_environment_configs

# Handle symbolic links
sync_symlinks

# Handle environment settings file
update_env_settings_file

# Final report
if [[ "$DRY_RUN" == true ]]; then
    log "DRY RUN COMPLETED: No changes were made" "INFO"
else
    log "Environment sync completed successfully" "INFO"
fi

# Additional steps if needed
if [[ "$DRY_RUN" == false ]]; then
    log "Running post-sync validation checks" "INFO"
    
    # Run config validator if available
    if [[ -x "${PROJECT_ROOT}/scripts/deployment/config_validator.sh" ]]; then
        log "Validating target environment configuration" "INFO"
        "${PROJECT_ROOT}/scripts/deployment/config_validator.sh" --environment "$TARGET_ENV" || \
            log "Validation reported issues with synced configuration. Please review." "WARNING"
    fi
fi

log "Environment sync script finished" "INFO"
exit 0