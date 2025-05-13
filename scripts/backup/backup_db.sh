#!/bin/bash
# filepath: scripts/backup/backup_db.sh
# ==============================================================================
# Database Backup Script for Cloud Infrastructure Platform
# ==============================================================================
# This script creates and manages database backups for the Cloud Infrastructure
# Platform. It handles:
#  - Creating compressed and/or encrypted backups
#  - Implementing proper retention policies
#  - Verifying backup integrity
#  - Supporting different environments (production, staging, development)
#  - Sending backup status notifications
# ==============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/db-backup-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cloud-platform"
CONFIG_DIR="${PROJECT_ROOT}/config"
DB_MANAGER="${PROJECT_ROOT}/scripts/database/database-manager.sh"
ENVIRONMENT="production"
COMPRESS=true
ENCRYPT=false
SCHEMA_ONLY=false
TABLES=""
VERIFY=true
ROTATE=true
NOTIFY=false
EMAIL_RECIPIENT=""
FORCE=false

# Number of hours to keep logs
LOG_RETENTION_HOURS=168  # 7 days

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
Database Backup Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --env, -e ENV           Specify environment (production, staging, development)
                          Default: production
  --compress              Compress backup with gzip (default)
  --no-compress           Disable compression
  --encrypt               Encrypt backup with GPG
  --schema-only           Backup only schema, not data
  --tables TABLES         Comma-separated list of tables to backup
  --no-verify             Skip backup verification
  --no-rotate             Skip old backup rotation
  --notify [EMAIL]        Send notification email with backup status
  --force, -f             Skip confirmation prompts
  --help, -h              Display this help message

Examples:
  $(basename "$0") --env production
  $(basename "$0") --env staging --schema-only --notify admin@example.com
  $(basename "$0") --env development --tables users,accounts,logs --no-compress
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --env|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --compress)
            COMPRESS=true
            shift
            ;;
        --no-compress)
            COMPRESS=false
            shift
            ;;
        --encrypt)
            ENCRYPT=true
            shift
            ;;
        --schema-only)
            SCHEMA_ONLY=true
            shift
            ;;
        --tables)
            TABLES="$2"
            shift 2
            ;;
        --no-verify)
            VERIFY=false
            shift
            ;;
        --no-rotate)
            ROTATE=false
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
        --force|-f)
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

# Check if database-manager.sh exists and is executable
if [[ ! -x "$DB_MANAGER" ]]; then
    log "Database manager script not found or not executable: $DB_MANAGER" "ERROR"
    exit 1
fi

# Function to send notification
send_notification() {
    local status="$1"
    local details="$2"
    local attachment="$3"

    if [[ "$NOTIFY" == "true" && -n "$EMAIL_RECIPIENT" ]]; then
        log "Sending notification email to $EMAIL_RECIPIENT"

        local subject="Database Backup ${status} - ${ENVIRONMENT} Environment"
        local message="Database Backup Report\n\n"
        message+="Environment: ${ENVIRONMENT}\n"
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

# Function to clean up old log files
cleanup_old_logs() {
    log "Cleaning up old log files..."
    find "$LOG_DIR" -name "db-backup-*.log" -type f -mmin +$((LOG_RETENTION_HOURS * 60)) -delete 2>/dev/null || true
}

# Function to record backup event in DR events log
log_dr_event() {
    local event_type="$1"
    local status="$2"

    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"

    # Log the database backup event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),${event_type},${ENVIRONMENT},backup,${status}" >> "/var/log/cloud-platform/dr-events.log"
    log "Backup event logged to DR events log"
}

# Main backup execution function
perform_backup() {
    log "Starting database backup for $ENVIRONMENT environment"

    # Build command string with options
    local cmd="$DB_MANAGER backup --env $ENVIRONMENT"

    # Add options based on parameters
    [[ "$COMPRESS" == "true" ]] && cmd+=" --compress"
    [[ "$COMPRESS" == "false" ]] && cmd+=" --no-compress"
    [[ "$ENCRYPT" == "true" ]] && cmd+=" --encrypt"
    [[ "$SCHEMA_ONLY" == "true" ]] && cmd+=" --schema-only"
    [[ -n "$TABLES" ]] && cmd+=" --tables $TABLES"
    [[ "$FORCE" == "true" ]] && cmd+=" --force"

    # Execute backup
    log "Executing: $cmd"
    local backup_output
    local backup_success=true

    backup_output=$($cmd 2>&1) || backup_success=false

    # Log the output
    echo "$backup_output" >> "$LOG_FILE"

    # Extract backup filename from output if successful
    local backup_file=""
    if [[ "$backup_success" == "true" ]]; then
        # Try to parse the backup filename from output
        if [[ "$COMPRESS" == "true" && "$ENCRYPT" == "true" ]]; then
            backup_file=$(echo "$backup_output" | grep -o "$BACKUP_DIR/$ENVIRONMENT/backup_.*\.gz\.gpg")
        elif [[ "$COMPRESS" == "true" ]]; then
            backup_file=$(echo "$backup_output" | grep -o "$BACKUP_DIR/$ENVIRONMENT/backup_.*\.gz")
        elif [[ "$ENCRYPT" == "true" ]]; then
            backup_file=$(echo "$backup_output" | grep -o "$BACKUP_DIR/$ENVIRONMENT/backup_.*\.gpg")
        else
            backup_file=$(echo "$backup_output" | grep -o "$BACKUP_DIR/$ENVIRONMENT/backup_.*\.sql")
        fi
    fi

    # Check if backup was successful
    if [[ "$backup_success" == "false" ]]; then
        log "Backup failed!" "ERROR"
        log_dr_event "DB_BACKUP" "FAILURE"
        send_notification "FAILED" "Backup process failed. Check log file for details." "$LOG_FILE"
        exit 1
    fi

    if [[ -z "$backup_file" ]]; then
        log "Backup completed but couldn't determine backup file name" "WARNING"
        backup_file="unknown"
    else
        log "Backup completed: $(basename "$backup_file")"
    fi

    # Verify backup if requested
    if [[ "$VERIFY" == "true" && -n "$backup_file" && "$backup_file" != "unknown" ]]; then
        log "Verifying backup integrity"
        if $DB_MANAGER verify --file "$backup_file"; then
            log "Backup verification successful"
        else
            log "Backup verification failed!" "ERROR"
            log_dr_event "DB_BACKUP" "FAILURE"
            send_notification "FAILED" "Backup was created but verification failed: $(basename "$backup_file")" "$LOG_FILE"
            exit 1
        fi
    fi

    # Rotate old backups if requested
    if [[ "$ROTATE" == "true" ]]; then
        log "Rotating old backups"
        $DB_MANAGER rotate --env "$ENVIRONMENT" >> "$LOG_FILE" 2>&1 || log "Warning: Backup rotation failed" "WARNING"
    fi

    # Log successful completion
    log_dr_event "DB_BACKUP" "SUCCESS"

    # Calculate backup size
    local backup_size=""
    if [[ -n "$backup_file" && "$backup_file" != "unknown" && -f "$backup_file" ]]; then
        backup_size=$(du -h "$backup_file" | cut -f1)
    fi

    # Send success notification
    local details="Backup file: $(basename "$backup_file")"
    if [[ -n "$backup_size" ]]; then
        details+="\nSize: $backup_size"
    fi
    details+="\nCompression: $([ "$COMPRESS" == "true" ] && echo "Enabled" || echo "Disabled")"
    details+="\nEncryption: $([ "$ENCRYPT" == "true" ] && echo "Enabled" || echo "Disabled")"

    # Add schema-only information if relevant
    if [[ "$SCHEMA_ONLY" == "true" ]]; then
        details+="\nType: Schema only (no data)"
    fi

    send_notification "SUCCESS" "$details" "$LOG_FILE"
    log "Database backup process completed successfully"
}

# Main execution flow
log "======================================================="
log "Starting database backup process for $ENVIRONMENT environment"
log "Backup configuration:"
log "- Environment: $ENVIRONMENT"
log "- Compression: $([ "$COMPRESS" == "true" ] && echo "Enabled" || echo "Disabled")"
log "- Encryption: $([ "$ENCRYPT" == "true" ] && echo "Enabled" || echo "Disabled")"
log "- Schema only: $([ "$SCHEMA_ONLY" == "true" ] && echo "Yes" || echo "No")"
if [[ -n "$TABLES" ]]; then
    log "- Tables: $TABLES"
fi
log "======================================================="

# Check if backup directory exists
if [[ ! -d "$BACKUP_DIR" ]]; then
    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR/$ENVIRONMENT"
fi

# Environment file specific configurations
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    log "Loading environment configuration from $ENV_FILE"
    # shellcheck source=/dev/null
    source "$ENV_FILE"

    # Override email recipient if defined in environment file
    if [[ "$NOTIFY" == "true" && -z "$EMAIL_RECIPIENT" && -n "${DB_BACKUP_NOTIFY:-}" ]]; then
        EMAIL_RECIPIENT="$DB_BACKUP_NOTIFY"
        log "Using email recipient from environment file: $EMAIL_RECIPIENT"
    fi
else
    log "Environment file not found: $ENV_FILE" "WARNING"
fi

# Check GPG is installed if encryption is requested
if [[ "$ENCRYPT" == "true" ]]; then
    if ! command -v gpg &>/dev/null; then
        log "GPG not found but encryption was requested. Disabling encryption." "WARNING"
        ENCRYPT=false
    fi
fi

# Execute backup
perform_backup

# Clean up old logs
cleanup_old_logs

exit 0
