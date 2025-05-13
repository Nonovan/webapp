#!/bin/bash
# filepath: scripts/backup/verify-backups.sh
# ==============================================================================
# Database Backup Verification Script for Cloud Infrastructure Platform
# ==============================================================================
# This script verifies the integrity and viability of database backups by:
#  - Validating backup file integrity and checksums
#  - Optionally performing test restorations to verify backup content
#  - Supporting different environments (production, staging, development)
#  - Providing comprehensive reporting on backup validation status
#  - Integrating with notification systems for alerts
# ==============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/backup-verification-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cloud-platform"
TEST_RESTORE_DIR="/tmp/db-restore-test-${TIMESTAMP}"
TEST_CONFIG_FILE="${TEST_RESTORE_DIR}/test_config.ini"

# Default settings
ENVIRONMENT="production"
ALL_ENVIRONMENTS=false
RESTORE_TEST=false
VERBOSE=false
NOTIFY=false
EMAIL_RECIPIENT=""
MAX_BACKUPS_TO_CHECK=5
VERIFY_DAYS=7
EXIT_CODE=0
BACKUP_PATTERNS=("backup_*.sql*" "db-backup-*.sql*")
CRITICAL_TABLES=("users" "permissions" "roles" "config" "settings")
ENABLE_DETAILED_VERIFY=false
DRY_RUN=false

# Ensure log directory exists with proper permissions
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR" 2>/dev/null || true
touch "$LOG_FILE"
chmod 640 "$LOG_FILE" 2>/dev/null || true

# Load common functions if available
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    # shellcheck source=/dev/null
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
    COMMON_FUNCTIONS_LOADED=true
else
    COMMON_FUNCTIONS_LOADED=false
fi

# Function to log messages with consistent formatting
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local level="${2:-INFO}"
    local message="[$timestamp] [$level] $1"

    echo "$message" | tee -a "$LOG_FILE"

    if [[ "$VERBOSE" = true && -n "$3" ]]; then
        echo "[$timestamp] [DEBUG] $3" >> "$LOG_FILE"
    fi
}

# Function to log error messages and update exit code
error_log() {
    log "$1" "ERROR" "${2:-}"
    EXIT_CODE=1
}

# Function to cleanup resources on script exit
cleanup() {
    if [[ -d "$TEST_RESTORE_DIR" ]]; then
        log "Cleaning up temporary test directory" "DEBUG"
        rm -rf "$TEST_RESTORE_DIR"
    fi

    # Drop any test databases that might remain
    local test_db="verify_restore_${TIMESTAMP}"
    if command -v psql &>/dev/null; then
        if psql -U postgres -l | grep -q "$test_db"; then
            log "Dropping test database $test_db" "DEBUG"
            psql -U postgres -c "DROP DATABASE IF EXISTS $test_db;" &>/dev/null
        fi
    fi
}

# Register cleanup function to run on script exit
trap cleanup EXIT

# Function to display usage information
usage() {
    cat <<EOF
Database Backup Verification Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --environment, -e ENV     Specify environment to check (default: production)
  --all-environments, -a    Check backups for all environments
  --restore-test, -r        Perform test restoration of backups
  --verify-days DAYS        Verify backups within specified days (default: 7)
  --max-backups NUM         Maximum number of backups to check (default: 5)
  --notify, -n [EMAIL]      Send notification with results
  --verbose, -v             Enable verbose output
  --detailed-verify         Perform detailed integrity verification on backups
  --pattern PATTERN         Additional file pattern to match backups
  --dry-run                 Show what would be done without making changes
  --help, -h                Show this help message

Examples:
  $(basename "$0") --environment staging --restore-test
  $(basename "$0") --all-environments --notify admin@example.com
  $(basename "$0") --verify-days 14 --max-backups 10 --verbose
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
            if [[ "$2" =~ ^[0-9]+$ ]]; then
                VERIFY_DAYS="$2"
                shift 2
            else
                error_log "Invalid value for --verify-days: $2 (must be a number)"
                usage
            fi
            ;;
        --max-backups)
            if [[ "$2" =~ ^[0-9]+$ ]]; then
                MAX_BACKUPS_TO_CHECK="$2"
                shift 2
            else
                error_log "Invalid value for --max-backups: $2 (must be a number)"
                usage
            fi
            ;;
        --notify|-n)
            NOTIFY=true
            if [[ -n "$2" && "$2" != -* ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
            shift
            ;;
        --pattern)
            if [[ -n "$2" ]]; then
                BACKUP_PATTERNS+=("$2")
                shift 2
            else
                error_log "Missing argument for --pattern"
                usage
            fi
            ;;
        --detailed-verify)
            ENABLE_DETAILED_VERIFY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
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
            error_log "Unknown option: $1"
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

    # Override email recipient if defined in environment file and not set from command line
    if [[ "$NOTIFY" == "true" && -z "$EMAIL_RECIPIENT" && -n "${BACKUP_VERIFY_NOTIFY:-}" ]]; then
        EMAIL_RECIPIENT="$BACKUP_VERIFY_NOTIFY"
        log "Using email recipient from environment file: $EMAIL_RECIPIENT"
    fi
else
    log "Environment file $ENV_FILE not found, using defaults" "WARNING"
fi

# Check if database-manager.sh exists
DB_MANAGER="${PROJECT_ROOT}/scripts/database/database-manager.sh"
if [[ ! -x "$DB_MANAGER" ]]; then
    error_log "Database manager script not found or not executable at $DB_MANAGER"
    exit 1
fi

# Function to log to DR events log
log_dr_event() {
    local event_type="$1"
    local environment="$2"
    local component="$3"
    local status="$4"

    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"

    # Log the verification event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),${event_type},${environment},${component},${status}" >> "/var/log/cloud-platform/dr-events.log"
    log "Event logged to DR events log"
}

# Function to perform deep verification on backup files
perform_detailed_verification() {
    local backup_file="$1"
    local result=0

    log "Performing detailed verification on: $(basename "$backup_file")"

    # Only allow execution of specific verification commands
    case "$backup_file" in
        *.gz.gpg)
            # Test decryption and decompression
            if ! gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | gunzip -t 2>/dev/null; then
                log "Detailed verification failed: Could not decrypt and decompress file" "ERROR"
                result=1
            fi
            ;;
        *.gpg)
            # Test decryption
            if ! gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | head -c 100 >/dev/null 2>&1; then
                log "Detailed verification failed: Could not decrypt file" "ERROR"
                result=1
            fi
            ;;
        *.gz)
            # Test decompression
            if ! gunzip -t "$backup_file" 2>/dev/null; then
                log "Detailed verification failed: Could not decompress file" "ERROR"
                result=1
            fi
            ;;
        *.sql)
            # Check for valid SQL content (look for typical PostgreSQL dump headers)
            if ! head -n 20 "$backup_file" | grep -q "PostgreSQL database dump"; then
                log "Detailed verification warning: File may not be a valid PostgreSQL dump" "WARNING"
                # Don't fail just for this
            fi
            ;;
    esac

    # Check file permissions
    local file_perms
    file_perms=$(stat -c "%a" "$backup_file" 2>/dev/null || stat -f "%Lp" "$backup_file" 2>/dev/null)
    if [[ "$file_perms" != "600" && "$file_perms" != "400" ]]; then
        log "Security warning: Backup file has insecure permissions: $file_perms (should be 600 or 400)" "WARNING"
    fi

    return $result
}

# Function to verify a single backup
verify_backup() {
    local backup_file="$1"
    local env="$2"

    log "Verifying backup: $(basename "$backup_file")"

    # Check if file exists
    if [[ ! -f "$backup_file" ]]; then
        error_log "Backup file not found: $backup_file"
        return 1
    fi

    # Get file size and creation time
    local file_size
    local file_date
    file_size=$(du -h "$backup_file" | cut -f1)
    file_date=$(date -r "$backup_file" "+%Y-%m-%d %H:%M:%S")
    log "Backup details: Size=$file_size, Created=$file_date"

    # Check if file is not empty
    if [[ ! -s "$backup_file" ]]; then
        error_log "Backup file is empty: $backup_file"
        return 1
    fi

    # Check if file is readable
    if [[ ! -r "$backup_file" ]]; then
        error_log "Cannot read backup file (permission denied): $backup_file"
        return 1
    }

    # Perform integrity verification
    local integrity_verified=false

    # Check if checksum file exists
    local checksum_file="${backup_file}.sha256"
    if [[ -f "$checksum_file" ]]; then
        log "Verifying checksum using SHA-256"

        if sha256sum --check "$checksum_file" &>/dev/null; then
            log "✅ Checksum verification passed for $(basename "$backup_file")"
            integrity_verified=true
        else
            error_log "❌ Checksum verification FAILED for $(basename "$backup_file")"
            return 1
        fi
    elif [[ -x "$DB_MANAGER" ]]; then
        # Checksum verification using database-manager.sh
        if "$DB_MANAGER" verify --file "$backup_file" &>/dev/null; then
            log "✅ Verification passed with database-manager for $(basename "$backup_file")"
            integrity_verified=true
        else
            error_log "❌ Verification FAILED with database-manager for $(basename "$backup_file")"
            return 1
        fi
    else
        log "WARNING: No checksum file found and cannot verify with database-manager" "WARNING"
        # Proceed with basic file integrity check
        if file "$backup_file" | grep -q "compressed\|SQL\|data\|text\|PostgreSQL"; then
            log "✅ Basic file integrity check passed for $(basename "$backup_file")"
            integrity_verified=true
        else
            error_log "❌ Basic file integrity check FAILED for $(basename "$backup_file")"
            return 1
        fi
    fi

    # Perform detailed verification if requested and basic checks passed
    if [[ "$ENABLE_DETAILED_VERIFY" == "true" && "$integrity_verified" == "true" ]]; then
        if ! perform_detailed_verification "$backup_file"; then
            error_log "❌ Detailed verification FAILED for $(basename "$backup_file")"
            return 1
        else
            log "✅ Detailed verification passed for $(basename "$backup_file")"
        fi
    fi

    # If restore testing is enabled, perform a test restore
    if [[ "$RESTORE_TEST" == "true" && "$DRY_RUN" == "false" ]]; then
        if ! perform_test_restore "$backup_file" "$env"; then
            return 1
        fi
    elif [[ "$RESTORE_TEST" == "true" && "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would perform test restore of $(basename "$backup_file")"
    fi

    return 0
}

# Function to perform a test restoration of backup
perform_test_restore() {
    local backup_file="$1"
    local env="$2"
    local test_db="verify_restore_${TIMESTAMP}"

    log "Performing test restoration of backup: $(basename "$backup_file")"

    # Create temporary directories with secure permissions
    mkdir -p "$TEST_RESTORE_DIR"
    chmod 700 "$TEST_RESTORE_DIR" 2>/dev/null || true

    # Create test configuration with secure permissions
    cat > "$TEST_CONFIG_FILE" <<EOF
[test_restore]
host=localhost
port=5432
dbname=${test_db}
admin_user=postgres
admin_password=postgres
app_user=app_user
EOF
    chmod 600 "$TEST_CONFIG_FILE" 2>/dev/null || true

    # Check if PostgreSQL is installed and accessible
    if ! command -v psql &>/dev/null; then
        log "PostgreSQL client not installed, skipping test restoration" "WARNING"
        return 0
    fi

    if ! psql -U postgres -c "\l" &>/dev/null; then
        log "PostgreSQL not accessible, skipping test restoration" "WARNING"
        return 0
    fi

    # Create test database
    log "Creating test database: $test_db"
    if ! psql -U postgres -c "CREATE DATABASE $test_db;" &>/dev/null; then
        error_log "Failed to create test database"
        return 1
    fi

    # Attempt restoration to test database
    local restore_output="${TEST_RESTORE_DIR}/restore_output.log"
    local restore_start_time restore_end_time restore_duration

    log "Restoring backup to test database..."
    restore_start_time=$(date +%s)

    # Use a dedicated function to reduce duplication in restore code
    restore_db_from_backup() {
        local backup_file="$1"
        local test_db="$2"
        local restore_output="$3"
        local result=0

        # Use function to determine backup type and restore method
        local backup_type
        if [[ "$backup_file" == *.gz.gpg ]]; then
            backup_type="compressed_encrypted"
        elif [[ "$backup_file" == *.gpg ]]; then
            backup_type="encrypted"
        elif [[ "$backup_file" == *.gz ]]; then
            backup_type="compressed"
        else
            backup_type="plain"
        fi

        if [[ "$VERBOSE" == "true" ]]; then
            log "" "Detected backup format: $backup_type"
        fi

        # Execute appropriate restore command based on type
        case "$backup_type" in
            compressed_encrypted)
                gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | gunzip | \
                psql -U postgres -d "$test_db" &> "$restore_output" || result=1
                ;;
            encrypted)
                gpg --batch --quiet --decrypt "$backup_file" 2>/dev/null | \
                psql -U postgres -d "$test_db" &> "$restore_output" || result=1
                ;;
            compressed)
                gunzip -c "$backup_file" | \
                psql -U postgres -d "$test_db" &> "$restore_output" || result=1
                ;;
            plain)
                psql -U postgres -d "$test_db" -f "$backup_file" &> "$restore_output" || result=1
                ;;
        esac

        return $result
    }

    # Perform the restore operation
    if restore_db_from_backup "$backup_file" "$test_db" "$restore_output"; then
        restore_end_time=$(date +%s)
        restore_duration=$((restore_end_time - restore_start_time))
        log "✅ Test restoration successful (completed in ${restore_duration}s)"
    else
        error_log "❌ Test restoration FAILED"
        if [[ -f "$restore_output" ]]; then
            if [[ "$VERBOSE" == "true" ]]; then
                log "" "Restore error: $(tail -n 10 "$restore_output")"
            fi
            # Save error for reporting
            cp "$restore_output" "${LOG_DIR}/restore-error-${TIMESTAMP}.log" 2>/dev/null || true
        fi
        cleanup_test_db "$test_db"
        return 1
    fi

    # Verify database structure in restored database
    log "Validating restored database content..."

    # Get table count
    local table_count
    table_count=$(psql -U postgres -d "$test_db" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" -t | tr -d ' ')

    if [[ "$table_count" -eq 0 ]]; then
        error_log "❌ Restored database has no tables"
        cleanup_test_db "$test_db"
        return 1
    fi

    log "✅ Verified $table_count tables in restored database"

    # Check for critical tables
    local missing_tables=0
    for table in "${CRITICAL_TABLES[@]}"; do
        local table_exists
        table_exists=$(psql -U postgres -d "$test_db" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='$table';" -t | tr -d ' ')
        if [[ "$table_exists" -eq 0 ]]; then
            log "❓ Note: Table '$table' not found in restored database" "WARNING"
        else
            log "✅ Critical table '$table' exists in restored database" "DEBUG"
        fi
    done

    # Perform additional validation checks on restored database
    if [[ -x "${PROJECT_ROOT}/scripts/database/validate_db.sh" ]]; then
        log "Running advanced database validation..."
        if ! "${PROJECT_ROOT}/scripts/database/validate_db.sh" --database "$test_db" --quiet; then
            log "⚠️ Some validation warnings on restored database" "WARNING"
            # Don't fail just for validation warnings
        fi
    fi

    # Cleanup test database
    cleanup_test_db "$test_db"
    return 0
}

# Function to clean up test database
cleanup_test_db() {
    local test_db="$1"
    log "Cleaning up test database"
    psql -U postgres -c "DROP DATABASE IF EXISTS $test_db;" &>/dev/null
}

# Function to send email notification
send_notification() {
    local status="$1"
    local details="$2"

    if [[ "$NOTIFY" != "true" || "$DRY_RUN" == "true" ]]; then
        [[ "$DRY_RUN" == "true" ]] && log "DRY RUN: Would send notification email with status: $status"
        return 0
    fi

    # Ensure we have recipient
    if [[ -z "$EMAIL_RECIPIENT" ]]; then
        log "No email recipient specified for notifications" "WARNING"
        return 1
    }

    log "Sending notification email to $EMAIL_RECIPIENT"

    local subject="Backup Verification Report - ${status} - ${ENVIRONMENT}"
    local message="Backup Verification Report\n\n"
    message+="Status: ${status}\n"
    message+="Environment(s): ${ENVIRONMENTS[*]}\n"
    message+="Time completed: $(date)\n"
    message+="Verified days: ${VERIFY_DAYS}\n"
    message+="Test restoration: $([ "$RESTORE_TEST" = "true" ] && echo "Enabled" || echo "Disabled")\n\n"
    message+="Details:\n${details}\n"

    # If our standard notification utility exists, use it
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        "${PROJECT_ROOT}/scripts/utils/send-notification.sh" \
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
            log "Could not send notification, mail command not available" "WARNING"
            return 1
        fi
    fi

    return 0
}

# Main function to verify backups for an environment
verify_environment_backups() {
    local env="$1"
    local env_dir="${BACKUP_DIR}/${env}"
    local success_count=0
    local fail_count=0
    local processed_count=0
    local details=""
    local results=()

    log "==================================================="
    log "Checking backups for environment: $env"
    log "==================================================="

    # Check if environment backup directory exists
    if [[ ! -d "$env_dir" ]]; then
        error_log "No backup directory found for $env at $env_dir"
        details+="❌ ERROR: No backup directory found for $env\n"
        return 1
    fi

    # Find recent backups (within specified days) across all backup patterns
    local recent_backups=""
    for pattern in "${BACKUP_PATTERNS[@]}"; do
        if [[ -z "$recent_backups" ]]; then
            recent_backups=$(find "$env_dir" -type f -name "$pattern" -not -name "*.sha256" -mtime -"${VERIFY_DAYS}" 2>/dev/null | sort -r)
        else
            recent_backups+=$'\n'$(find "$env_dir" -type f -name "$pattern" -not -name "*.sha256" -mtime -"${VERIFY_DAYS}" 2>/dev/null | sort -r)
        fi
    done

    # Remove duplicate lines and limit to the max number of backups to check
    recent_backups=$(echo "$recent_backups" | grep -v "^$" | sort -u | head -n "$MAX_BACKUPS_TO_CHECK")

    if [[ -z "$recent_backups" ]]; then
        error_log "No recent backups found for $env within the last $VERIFY_DAYS days"
        details+="❌ ERROR: No recent backups found for $env within the last $VERIFY_DAYS days\n"
        return 1
    fi

    log "Found $(echo "$recent_backups" | wc -l | tr -d ' ') backups to verify"

    # Process each backup file
    while read -r backup_file; do
        [[ -z "$backup_file" ]] && continue

        log "-----------------------------------------------------"
        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY RUN: Would verify backup file: $(basename "$backup_file")"
            ((success_count++))
            results+=("✅ $(basename "$backup_file") - OK (DRY RUN)")
        elif verify_backup "$backup_file" "$env"; then
            ((success_count++))
            results+=("✅ $(basename "$backup_file") - OK")
        else
            ((fail_count++))
            EXIT_CODE=1
            results+=("❌ $(basename "$backup_file") - FAILED")
        fi
        ((processed_count++))
        log "-----------------------------------------------------"
    done <<< "$recent_backups"

    # Build detailed report
    for result in "${results[@]}"; do
        details+="$result\n"
    done

    log "Backup verification completed for $env: $success_count successful, $fail_count failed (out of $processed_count checked)"

    # Check if no backups were processed
    if [[ $processed_count -eq 0 ]]; then
        error_log "No backups were processed for $env"
        return 1
    fi

    # Log detailed summary
    if [[ "$VERBOSE" = true ]]; then
        log "Verification details:\n$details"
    elif [[ -n "$details" ]]; then
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
log "Script version: 0.1.1"
log "Configuration:"
log "- Environments: ${ENVIRONMENTS[*]}"
log "- Verify days: $VERIFY_DAYS"
log "- Max backups to check: $MAX_BACKUPS_TO_CHECK"
log "- Test restoration: $([ "$RESTORE_TEST" = "true" ] && echo "Enabled" || echo "Disabled")"
log "- Detailed verification: $([ "$ENABLE_DETAILED_VERIFY" = "true" ] && echo "Enabled" || echo "Disabled")"
log "- Dry run: $([ "$DRY_RUN" = "true" ] && echo "Enabled" || echo "Disabled")"

# Skip actual execution in dry run mode
if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY RUN MODE: No actual verification will be performed"
fi

all_env_status=0
all_env_details=""

for env in "${ENVIRONMENTS[@]}"; do
    env_details=""
    if ! verify_environment_backups "$env"; then
        all_env_status=1
        env_details="❌ Environment $env: Verification FAILED\n"
    else
        env_details="✅ Environment $env: Verification SUCCESSFUL\n"
    fi
    all_env_details+="$env_details"
done

# Final summary
log "==================================================="
status="SUCCESS"
if [[ $EXIT_CODE -ne 0 ]]; then
    status="FAILURE"
fi

log "Backup verification process completed with status: $status"

# Send notification if requested
if [[ "$NOTIFY" == "true" ]]; then
    send_notification "$status" "$all_env_details"
fi

# Log to DR events system
if [[ "$DRY_RUN" != "true" ]]; then
    log_dr_event "BACKUP_VERIFICATION" "${ENVIRONMENT}" "all" "$status"
else
    log "DRY RUN: Would log to DR events system with status: $status"
fi

# Output additional guidance for failures
if [[ "$status" == "FAILURE" ]]; then
    log "⚠️  Some backups failed verification. Actions required:"
    log "   1. Check the verification log at: $LOG_FILE"
    log "   2. Investigate failed backups and potential database issues"
    log "   3. Consider initiating a new backup if needed"

    if [[ -f "${PROJECT_ROOT}/scripts/backup/backup_db.sh" ]]; then
        log "   To create a new backup, run: ${PROJECT_ROOT}/scripts/backup/backup_db.sh --env $ENVIRONMENT"
    fi
fi

exit $EXIT_CODE
