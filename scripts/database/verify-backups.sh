#!/bin/bash
# Backup Verification Script for Cloud Infrastructure Platform
# Verifies integrity and viability of database backups
# Usage: ./verify-backups.sh [--environment <env>] [--restore-test] [--all-environments] [--notify]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
ALL_ENVIRONMENTS=false
RESTORE_TEST=false
VERBOSE=false
NOTIFY=false
EMAIL_RECIPIENT=""
LOG_DIR="/var/log/cloud-platform"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
LOG_FILE="${LOG_DIR}/backup-verification-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cloud-platform"
TEST_RESTORE_DIR="/tmp/db-restore-test-${TIMESTAMP}"
TEST_CONFIG_FILE="${TEST_RESTORE_DIR}/test_config.ini"
MAX_BACKUPS_TO_CHECK=5
VERIFY_DAYS=7
EXIT_CODE=0

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    
    echo "$message" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" = true && -n "$2" ]]; then
        echo "[$timestamp] [DEBUG] $2" >> "$LOG_FILE"
    fi
}

# Function to display usage
usage() {
    cat <<EOF
Database Backup Verification Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --environment, -e ENV    Specify environment to check (default: production)
  --all-environments, -a   Check backups for all environments
  --restore-test, -r       Perform test restoration of backups
  --verify-days DAYS       Verify backups within specified days (default: 7)
  --notify, -n [EMAIL]     Send notification with results
  --verbose, -v            Enable verbose output
  --help, -h               Show this help message
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --all-environments|-a)
            ALL_ENVIRONMENTS=true
            shift
            ;;
        --restore-test|-r)
            RESTORE_TEST=true
            shift
            ;;
        --verify-days)
            VERIFY_DAYS="$2"
            shift 2
            ;;
        --notify|-n)
            NOTIFY=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
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
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Define array of environments to check
if [[ "$ALL_ENVIRONMENTS" = true ]]; then
    ENVIRONMENTS=("production" "staging" "development" "ci" "demo")
else
    ENVIRONMENTS=("$ENVIRONMENT")
fi

# Load environment-specific configuration
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Check if database-manager.sh exists
DB_MANAGER="${PROJECT_ROOT}/scripts/database/database-manager.sh"
if [[ ! -x "$DB_MANAGER" ]]; then
    log "ERROR: Database manager script not found at $DB_MANAGER"
    exit 1
fi

# Function to verify a single backup
verify_backup() {
    local backup_file="$1"
    local env="$2"
    
    log "Verifying backup: $(basename "$backup_file")"
    
    # Check if file exists
    if [[ ! -f "$backup_file" ]]; then
        log "ERROR: Backup file not found: $backup_file"
        return 1
    fi
    
    # Get file size
    local file_size=$(du -h "$backup_file" | cut -f1)
    log "Backup size: $file_size"
    
    # Check if file is not empty
    if [[ ! -s "$backup_file" ]]; then
        log "ERROR: Backup file is empty: $backup_file"
        return 1
    fi
    
    # Check if checksum file exists
    local checksum_file="${backup_file}.sha256"
    if [[ -f "$checksum_file" ]]; then
        log "Verifying checksum using SHA-256"
        
        if sha256sum --check "$checksum_file" &>/dev/null; then
            log "✅ Checksum verification passed for $(basename "$backup_file")"
        else
            log "❌ Checksum verification FAILED for $(basename "$backup_file")"
            return 1
        fi
    elif [[ -x "$DB_MANAGER" ]]; then
        # Checksum verification using database-manager.sh
        if $DB_MANAGER verify --file "$backup_file" &>/dev/null; then
            log "✅ Checksum verification passed for $(basename "$backup_file")"
        else
            log "❌ Checksum verification FAILED for $(basename "$backup_file")"
            return 1
        fi
    else
        log "WARNING: No checksum file found and cannot verify with database-manager"
        # Proceed without verification - just check file integrity
        if file "$backup_file" | grep -q "compressed\|SQL\|data"; then
            log "✅ File integrity check passed for $(basename "$backup_file")"
        else
            log "❌ File integrity check FAILED for $(basename "$backup_file")"
            return 1
        fi
    fi
    
    # If restore testing is enabled, perform a test restore
    if [[ "$RESTORE_TEST" = true ]]; then
        perform_test_restore "$backup_file" "$env"
        return $?
    fi
    
    return 0
}

# Function to perform a test restoration of backup
perform_test_restore() {
    local backup_file="$1"
    local env="$2"
    
    log "Performing test restoration of backup: $(basename "$backup_file")"
    
    # Create temporary directories
    mkdir -p "$TEST_RESTORE_DIR"
    
    # Create test configuration
    cat > "$TEST_CONFIG_FILE" <<EOF
[test_restore]
host=localhost
port=5432
dbname=verify_restore_${TIMESTAMP}
admin_user=postgres
admin_password=postgres
app_user=app_user
EOF
    
    # Check if PostgreSQL is installed and accessible
    if ! command -v psql &>/dev/null; then
        log "WARNING: PostgreSQL client not installed, skipping test restoration"
        return 0
    fi
    
    if ! psql -U postgres -c "\l" &>/dev/null; then
        log "WARNING: PostgreSQL not accessible, skipping test restoration"
        return 0
    fi
    
    # Create test database
    log "Creating test database: verify_restore_${TIMESTAMP}"
    if ! psql -U postgres -c "CREATE DATABASE verify_restore_${TIMESTAMP};" &>/dev/null; then
        log "ERROR: Failed to create test database"
        return 1
    fi
    
    # Attempt restoration to test database
    local restore_output="${TEST_RESTORE_DIR}/restore_output.log"
    
    log "Restoring backup to test database..."
    
    # Determine backup type and restore method
    if [[ "$backup_file" == *.gz.gpg ]]; then
        # Compressed and encrypted
        if [[ "$VERBOSE" = true ]]; then
            log "" "Detected compressed and encrypted backup format"
        fi
        
        if gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | gunzip | psql -U postgres -d "verify_restore_${TIMESTAMP}" &> "$restore_output"; then
            log "✅ Test restoration successful"
        else
            log "❌ Test restoration FAILED"
            if [[ "$VERBOSE" = true ]]; then
                cat "$restore_output" >> "$LOG_FILE"
            fi
            cleanup_test_db
            return 1
        fi
    elif [[ "$backup_file" == *.gpg ]]; then
        # Encrypted only
        if [[ "$VERBOSE" = true ]]; then
            log "" "Detected encrypted backup format"
        fi
        
        if gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | psql -U postgres -d "verify_restore_${TIMESTAMP}" &> "$restore_output"; then
            log "✅ Test restoration successful"
        else
            log "❌ Test restoration FAILED"
            if [[ "$VERBOSE" = true ]]; then
                cat "$restore_output" >> "$LOG_FILE"
            fi
            cleanup_test_db
            return 1
        fi
    elif [[ "$backup_file" == *.gz ]]; then
        # Compressed only
        if [[ "$VERBOSE" = true ]]; then
            log "" "Detected compressed backup format"
        fi
        
        if gunzip -c "$backup_file" | psql -U postgres -d "verify_restore_${TIMESTAMP}" &> "$restore_output"; then
            log "✅ Test restoration successful"
        else
            log "❌ Test restoration FAILED"
            if [[ "$VERBOSE" = true ]]; then
                cat "$restore_output" >> "$LOG_FILE"
            fi
            cleanup_test_db
            return 1
        fi
    else
        # Plain SQL
        if [[ "$VERBOSE" = true ]]; then
            log "" "Detected plain SQL backup format"
        fi
        
        if psql -U postgres -d "verify_restore_${TIMESTAMP}" -f "$backup_file" &> "$restore_output"; then
            log "✅ Test restoration successful"
        else
            log "❌ Test restoration FAILED"
            if [[ "$VERBOSE" = true ]]; then
                cat "$restore_output" >> "$LOG_FILE"
            fi
            cleanup_test_db
            return 1
        fi
    fi
    
    # Verify database structure in restored database
    local table_count=$(psql -U postgres -d "verify_restore_${TIMESTAMP}" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" -t | tr -d ' ')
    log "Verified $table_count tables in restored database"
    
    # Check for at least one critical table (users)
    local users_table=$(psql -U postgres -d "verify_restore_${TIMESTAMP}" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='users';" -t | tr -d ' ')
    if [[ "$users_table" -eq 1 ]]; then
        log "✅ Critical 'users' table exists in restored database"
    else
        log "❌ Critical 'users' table NOT FOUND in restored database"
        cleanup_test_db
        return 1
    fi
    
    # Cleanup test database
    cleanup_test_db
    return 0
}

# Function to clean up test database
cleanup_test_db() {
    log "Cleaning up test database"
    psql -U postgres -c "DROP DATABASE IF EXISTS verify_restore_${TIMESTAMP};" &>/dev/null
    rm -f "${TEST_RESTORE_DIR}/restore_output.log" &>/dev/null
    rm -rf "$TEST_RESTORE_DIR" &>/dev/null
}

# Function to send email notification
send_notification() {
    local status="$1"
    local details="$2"
    
    if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
        log "Sending notification email to $EMAIL_RECIPIENT"
        
        local subject="Backup Verification Report - ${status}"
        local message="Backup Verification Report\n\n"
        message+="Status: ${status}\n"
        message+="Environments checked: ${ENVIRONMENTS[*]}\n"
        message+="Timestamp: $(date)\n\n"
        message+="Details:\n${details}\n"
        
        # If our standard notification utility exists, use it
        if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
            ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
                --priority $([ "$status" = "SUCCESS" ] && echo "low" || echo "high") \
                --subject "$subject" \
                --message "$message" \
                --recipient "$EMAIL_RECIPIENT" \
                --attachment "$LOG_FILE"
        else
            # Fall back to mail command
            if command -v mail &>/dev/null; then
                echo -e "$message" | mail -s "$subject" -a "$LOG_FILE" "$EMAIL_RECIPIENT"
            else
                log "WARNING: Could not send notification, mail command not available"
            fi
        fi
    fi
}

# Main function to verify backups for an environment
verify_environment_backups() {
    local env="$1"
    local env_dir="${BACKUP_DIR}/${env}"
    local success_count=0
    local fail_count=0
    local processed_count=0
    local details=""
    
    log "==================================================="
    log "Checking backups for environment: $env"
    log "==================================================="
    
    # Check if environment backup directory exists
    if [[ ! -d "$env_dir" ]]; then
        log "WARNING: No backup directory found for $env at $env_dir"
        details+="WARNING: No backup directory found for $env\n"
        return 1
    fi
    
    # Find recent backups (within specified days) and verify them
    local recent_backups
    recent_backups=$(find "$env_dir" -type f -name "backup_*.sql*" -not -name "*.sha256" -mtime -"${VERIFY_DAYS}" | sort -r | head -n "$MAX_BACKUPS_TO_CHECK")
    
    if [[ -z "$recent_backups" ]]; then
        log "WARNING: No recent backups found for $env within the last $VERIFY_DAYS days"
        details+="WARNING: No recent backups found for $env within the last $VERIFY_DAYS days\n"
        return 1
    fi
    
    while read -r backup_file; do
        log "-----------------------------------------------------"
        if verify_backup "$backup_file" "$env"; then
            ((success_count++))
            details+="✅ $(basename "$backup_file") - OK\n"
        else
            ((fail_count++))
            EXIT_CODE=1
            details+="❌ $(basename "$backup_file") - FAILED\n"
        fi
        ((processed_count++))
        log "-----------------------------------------------------"
    done <<< "$recent_backups"
    
    log "Backup verification completed for $env: $success_count successful, $fail_count failed (out of $processed_count checked)"
    
    # Check if no backups were processed
    if [[ $processed_count -eq 0 ]]; then
        log "ERROR: No backups were processed for $env"
        return 1
    fi
    
    # Log detailed summary to the log file
    if [[ "$VERBOSE" = true ]]; then
        log "" "$details"
    else
        echo -e "$details" >> "$LOG_FILE"
    fi
    
    # Return failure if any backup verification failed
    if [[ $fail_count -gt 0 ]]; then
        return 1
    fi
    
    return 0
}

# Main execution flow
log "Starting backup verification process at $(date)"
log "Checking environments: ${ENVIRONMENTS[*]}"

all_env_status=0
details=""
for env in "${ENVIRONMENTS[@]}"; do
    if ! verify_environment_backups "$env"; then
        all_env_status=1
    fi
done

# Final summary
log "==================================================="
status="SUCCESS"
if [[ $EXIT_CODE -ne 0 ]]; then
    status="FAILURE"
fi

log "Backup verification process completed with status: $status"

# Send notification if requested
send_notification "$status" "$details"

# Log to DR events system
mkdir -p "/var/log/cloud-platform"
echo "$(date '+%Y-%m-%d %H:%M:%S'),BACKUP_VERIFICATION,${ENVIRONMENT},all,$status" >> "/var/log/cloud-platform/dr-events.log"
log "Backup verification results logged to DR events log"

# Clean up any temporary files
if [[ -d "$TEST_RESTORE_DIR" ]]; then
    rm -rf "$TEST_RESTORE_DIR"
fi

exit $EXIT_CODE