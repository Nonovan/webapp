#!/bin/bash
# filepath: scripts/backup/restore_db.sh
# ==============================================================================
# Database Restore Script for Cloud Infrastructure Platform
# ==============================================================================
# This script restores database backups for the Cloud Infrastructure Platform.
# It handles:
#  - Restoring compressed and/or encrypted backups
#  - Performing pre-restore checks and validations
#  - Creating safety backups before restoration
#  - Supporting different environments (production, staging, development)
#  - Sending status notifications
# ==============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/db-restore-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cloud-platform"
CONFIG_DIR="${PROJECT_ROOT}/config"
DB_MANAGER="${PROJECT_ROOT}/scripts/database/database-manager.sh"
ENVIRONMENT="production"
BACKUP_FILE=""
NO_OWNER=false
VERIFY=true
SAFETY_BACKUP=true
NOTIFY=false
EMAIL_RECIPIENT=""
FORCE=false

# Ensure log directory exists
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

# Function to log messages
log() {
    local level="${2:-INFO}"
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Function to display usage information
usage() {
    cat <<EOF
Database Restore Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options] <backup_file> <environment>

Arguments:
  <backup_file>           Path to backup file
  <environment>           Target environment (production, staging, development)

Options:
  --env, -e ENV           Specify environment (alternative to positional argument)
  --file, -f FILE         Specify backup file (alternative to positional argument)
  --no-owner, -o          Exclude ownership commands in restore
  --no-verify             Skip backup verification before restore
  --no-safety-backup      Skip creating safety backup of current database
  --notify [EMAIL]        Send notification email with restore status
  --force                 Skip confirmation prompts
  --help, -h              Display this help message

Examples:
  $(basename "$0") backup_production_20240401_120000.sql.gz production
  $(basename "$0") --file backup_production_20240401_120000.sql.gz --env staging --force
  $(basename "$0") --file latest --env development --notify admin@example.com
EOF
    exit 0
}

# Function to select the latest backup for an environment
select_latest_backup() {
    local env="$1"
    local backup_path="${BACKUP_DIR}/${env}"

    if [[ ! -d "$backup_path" ]]; then
        log "No backup directory found for $env at $backup_path" "ERROR"
        exit 1
    fi

    # Find most recent backup (prioritize compressed ones)
    local latest_backup=$(find "$backup_path" -name "backup_*.sql*" -not -name "*.sha256" | sort -r | head -1)

    if [[ -z "$latest_backup" ]]; then
        log "No backups found for environment: $env" "ERROR"
        exit 1
    fi

    echo "$latest_backup"
}

# Function to send notification
send_notification() {
    local status="$1"
    local details="$2"
    local attachment="$3"

    if [[ "$NOTIFY" == "true" && -n "$EMAIL_RECIPIENT" ]]; then
        log "Sending notification email to $EMAIL_RECIPIENT"

        local subject="Database Restore ${status} - ${ENVIRONMENT} Environment"
        local message="Database Restore Report\n\n"
        message+="Environment: ${ENVIRONMENT}\n"
        message+="Backup: $(basename "${BACKUP_FILE}")\n"
        message+="Status: ${status}\n"
        message+="Timestamp: $(date)\n\n"

        if [[ -n "$details" ]]; then
            message+="Details:\n${details}\n"
        fi

        # If our standard notification utility exists, use it
        if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
            ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
                --priority $([ "$status" = "SUCCESS" ] && echo "low" || echo "high") \
                --subject "$subject" \
                --message "$message" \
                --recipient "$EMAIL_RECIPIENT" \
                --attachment "$attachment"
        else
            # Fall back to mail command
            if command -v mail &>/dev/null; then
                echo -e "$message" | mail -s "$subject" -a "$attachment" "$EMAIL_RECIPIENT"
            else
                log "Could not send notification, mail command not available" "WARNING"
            fi
        fi
    fi
}

# Function to record DR event in events log
log_dr_event() {
    local event_type="$1"
    local status="$2"

    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"

    # Log the database restore event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),${event_type},${ENVIRONMENT},restore,${status}" >> "/var/log/cloud-platform/dr-events.log"
    log "Restore event logged to DR events log"
}

# Function to verify database connectivity
verify_connectivity() {
    log "Verifying database connectivity for $ENVIRONMENT"

    if ! "$DB_MANAGER" verify-db --env "$ENVIRONMENT" --quick-check &>/dev/null; then
        log "Cannot connect to the database server. Please check connectivity." "ERROR"
        return 1
    fi

    log "Database connectivity verified"
    return 0
}

# Function to create safety backup before restore
create_safety_backup() {
    log "Creating safety backup of current database"

    local safety_file="${BACKUP_DIR}/${ENVIRONMENT}/pre_restore_${ENVIRONMENT}_${TIMESTAMP}.sql.gz"

    # Create backup directory if it doesn't exist
    mkdir -p "${BACKUP_DIR}/${ENVIRONMENT}"

    # Use database-manager to create backup
    if ! "$DB_MANAGER" backup --env "$ENVIRONMENT" --compress &> "${LOG_DIR}/safety_backup_${TIMESTAMP}.log"; then
        log "Failed to create safety backup. This is risky, consider aborting." "WARNING"

        if [[ "$FORCE" != "true" ]]; then
            echo "Failed to create safety backup. Proceed anyway? (yes/NO)"
            read -r confirm

            if [[ "$confirm" != "yes" ]]; then
                log "Restore aborted by user."
                exit 1
            fi
        fi

        return 1
    fi

    log "Safety backup created at: $safety_file"
    return 0
}

# Function to verify backup integrity
verify_backup_integrity() {
    log "Verifying backup file integrity: $(basename "$BACKUP_FILE")"

    # Check if backup file exists
    if [[ ! -f "$BACKUP_FILE" ]]; then
        log "Backup file not found: $BACKUP_FILE" "ERROR"
        exit 1
    fi

    # Check if file is not empty
    if [[ ! -s "$BACKUP_FILE" ]]; then
        log "Backup file is empty: $BACKUP_FILE" "ERROR"
        exit 1
    fi

    # Use database-manager to verify if it's one of our backups
    if "$DB_MANAGER" verify --file "$BACKUP_FILE" &>/dev/null; then
        log "✓ Backup verification successful"
        return 0
    fi

    # If database-manager verification fails, check with basic tools
    local checksum_file="${BACKUP_FILE}.sha256"
    if [[ -f "$checksum_file" ]]; then
        if sha256sum --check "$checksum_file" &>/dev/null; then
            log "✓ Checksum verification passed"
            return 0
        else
            log "✗ Checksum verification failed" "ERROR"

            if [[ "$FORCE" != "true" ]]; then
                echo "Checksum verification failed. Proceed anyway? (yes/NO)"
                read -r confirm

                if [[ "$confirm" != "yes" ]]; then
                    log "Restore aborted by user."
                    exit 1
                fi
            fi
        fi
    else
        # Basic file type verification
        if file "$BACKUP_FILE" | grep -q "compressed\|SQL\|data"; then
            log "✓ File integrity check passed (basic verification only)"
            return 0
        else
            log "✗ File format verification failed" "ERROR"

            if [[ "$FORCE" != "true" ]]; then
                echo "File format doesn't look like a database backup. Proceed anyway? (yes/NO)"
                read -r confirm

                if [[ "$confirm" != "yes" ]]; then
                    log "Restore aborted by user."
                    exit 1
                fi
            fi
        fi
    fi

    log "Backup verification partially failed but continuing due to user override" "WARNING"
    return 0
}

# Function to restore the database
perform_restore() {
    log "Starting database restore process"

    # Build command string with options
    local cmd="$DB_MANAGER restore --env $ENVIRONMENT --file $BACKUP_FILE"

    # Add options based on parameters
    [[ "$NO_OWNER" == "true" ]] && cmd+=" --no-owner"
    [[ "$FORCE" == "true" ]] && cmd+=" --force"

    # Execute restore
    log "Executing: $cmd"
    local restore_output
    local restore_success=true

    restore_output=$($cmd 2>&1) || restore_success=false

    # Log the output
    echo "$restore_output" >> "$LOG_FILE"

    # Check if restore was successful
    if [[ "$restore_success" == "false" ]]; then
        log "Restore failed!" "ERROR"
        log_dr_event "DB_RESTORE" "FAILURE"
        send_notification "FAILED" "Restore process failed.\n\nOutput:\n$restore_output" "$LOG_FILE"
        exit 1
    fi

    log "Database restore completed successfully"
    log_dr_event "DB_RESTORE" "SUCCESS"

    # Send success notification
    local details="Restored from: $(basename "$BACKUP_FILE")"
    send_notification "SUCCESS" "$details" "$LOG_FILE"

    return 0
}

# Parse command line arguments
# First, check if we have positional arguments
if [[ $# -eq 2 && "${1:0:1}" != "-" && "${2:0:1}" != "-" ]]; then
    BACKUP_FILE="$1"
    ENVIRONMENT="$2"
    shift 2
fi

# Then parse all options
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --env|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --file|-f)
            BACKUP_FILE="$2"
            shift 2
            ;;
        --no-owner|-o)
            NO_OWNER=true
            shift
            ;;
        --no-verify)
            VERIFY=false
            shift
            ;;
        --no-safety-backup)
            SAFETY_BACKUP=false
            shift
            ;;
        --notify)
            NOTIFY=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            log "Unknown option: $1" "ERROR"
            usage
            ;;
    esac
done

# Validate input parameters
if [[ -z "$ENVIRONMENT" ]]; then
    log "No environment specified" "ERROR"
    usage
fi

# Validate environment
valid_env=false
for env in "production" "staging" "development" "ci" "demo"; do
    if [[ "$ENVIRONMENT" == "$env" ]]; then
        valid_env=true
        break
    fi
done

if [[ "$valid_env" == "false" ]]; then
    log "Invalid environment: $ENVIRONMENT" "ERROR"
    exit 1
fi

# Special case for 'latest' as backup file
if [[ -z "$BACKUP_FILE" || "$BACKUP_FILE" == "latest" ]]; then
    log "Selecting latest backup for $ENVIRONMENT"
    BACKUP_FILE=$(select_latest_backup "$ENVIRONMENT")
    log "Selected: $(basename "$BACKUP_FILE")"
fi

# Check that database manager exists
if [[ ! -x "$DB_MANAGER" ]]; then
    log "Database manager script not found or not executable: $DB_MANAGER" "ERROR"
    exit 1
fi

# Environment file specific configurations
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    log "Loading environment configuration from $ENV_FILE"
    # shellcheck source=/dev/null
    source "$ENV_FILE"

    # Override email recipient if defined in environment file
    if [[ "$NOTIFY" == "true" && -z "$EMAIL_RECIPIENT" && -n "${DB_RESTORE_NOTIFY:-}" ]]; then
        EMAIL_RECIPIENT="$DB_RESTORE_NOTIFY"
        log "Using email recipient from environment file: $EMAIL_RECIPIENT"
    fi
else
    log "Environment file not found: $ENV_FILE" "WARNING"
fi

# Extra warning for production
if [[ "$ENVIRONMENT" == "production" && "$FORCE" != "true" ]]; then
    echo "⚠️  WARNING: You are about to restore the PRODUCTION database! ⚠️"
    echo
    echo "This operation will OVERWRITE the current production database with"
    echo "the backup: $(basename "$BACKUP_FILE")"
    echo
    echo "To proceed, type 'RESTORE PRODUCTION' (all uppercase):"
    read -r confirmation

    if [[ "$confirmation" != "RESTORE PRODUCTION" ]]; then
        log "Production restore cancelled by user"
        exit 0
    fi
fi

log "======================================================="
log "Starting database restore process for $ENVIRONMENT environment"
log "Restore configuration:"
log "- Environment: $ENVIRONMENT"
log "- Backup file: $(basename "$BACKUP_FILE")"
log "- Skip owner commands: $([ "$NO_OWNER" == "true" ] && echo "Yes" || echo "No")"
log "- Force mode: $([ "$FORCE" == "true" ] && echo "Enabled" || echo "Disabled")"
log "======================================================="

# Main execution flow
# 1. Verify database connectivity
verify_connectivity

# 2. Create safety backup if requested
if [[ "$SAFETY_BACKUP" == "true" ]]; then
    create_safety_backup
fi

# 3. Verify backup integrity if requested
if [[ "$VERIFY" == "true" ]]; then
    verify_backup_integrity
fi

# 4. Perform database restore
perform_restore

log "Database restore completed successfully"
exit 0
