#!/bin/bash
# Database restore script for Cloud Infrastructure Platform
# Usage: ./restore_db.sh backup_file [environment] [--force]

set -e

# Process arguments
if [ -z "$1" ]; then
    echo "Usage: $0 backup_file [environment] [--force]"
    echo "Example: $0 /var/backups/cloud-platform/database/cloud_platform_production_20230515.sql.gz production"
    exit 1
fi

BACKUP_FILE="$1"
# Default to production if no environment specified
ENVIRONMENT=${2:-production}
FORCE=false

# Check for --force flag
shift 2 2>/dev/null || shift 1
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --force)
            FORCE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/cloud-platform/db_restore.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log "Starting database restore for ${ENVIRONMENT} environment using ${BACKUP_FILE}"

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    log "ERROR: Backup file ${BACKUP_FILE} not found"
    exit 1
fi

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [ -f "$ENV_FILE" ]; then
    log "Loading ${ENVIRONMENT} environment variables"
    source "$ENV_FILE"
else
    log "WARNING: Environment file ${ENV_FILE} not found"
    
    # Try to use database config from newer infrastructure if available
    DB_CONFIG_FILE="${PROJECT_ROOT}/deployment/database/db_config.ini"
    if [ -f "$DB_CONFIG_FILE" ]; then
        log "Using database configuration from ${DB_CONFIG_FILE}"
        # Extract values from the INI file
        DB_HOST=$(awk -F "=" "/^\[$ENVIRONMENT\]/,/^\[.*\]/ {if (\$1 ~ /^host/) print \$2}" "$DB_CONFIG_FILE" | tr -d ' ')
        DB_PORT=$(awk -F "=" "/^\[$ENVIRONMENT\]/,/^\[.*\]/ {if (\$1 ~ /^port/) print \$2}" "$DB_CONFIG_FILE" | tr -d ' ')
        DB_NAME=$(awk -F "=" "/^\[$ENVIRONMENT\]/,/^\[.*\]/ {if (\$1 ~ /^dbname/) print \$2}" "$DB_CONFIG_FILE" | tr -d ' ')
        DB_USER=$(awk -F "=" "/^\[$ENVIRONMENT\]/,/^\[.*\]/ {if (\$1 ~ /^admin_user/) print \$2}" "$DB_CONFIG_FILE" | tr -d ' ')
        PGPASSWORD=$(awk -F "=" "/^\[$ENVIRONMENT\]/,/^\[.*\]/ {if (\$1 ~ /^admin_password/) print \$2}" "$DB_CONFIG_FILE" | tr -d ' ')
        
        # Replace environment variables if needed
        if [[ "$PGPASSWORD" == \$* ]]; then
            local var_name="${PGPASSWORD:1}"
            PGPASSWORD="${!var_name}"
        fi
    else
        log "WARNING: Database configuration not found, using defaults"
    fi
fi

# Set database connection details from environment or defaults
DB_USER=${DB_USER:-"postgres"}
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"5432"}
DB_NAME=${DB_NAME:-"cloud_platform"}
export PGPASSWORD=${PGPASSWORD:-${DB_PASSWORD:-"postgres"}}

# Check for required tools
for cmd in psql; do
    if ! command -v $cmd &>/dev/null; then
        log "ERROR: Required command '$cmd' not found"
        exit 1
    fi
done

# Confirm with the user before proceeding
if [ "$FORCE" != "true" ]; then
    echo -e "\n*** WARNING ***"
    echo "This will OVERWRITE the ${DB_NAME} database in the ${ENVIRONMENT} environment."
    echo "All current data will be lost and replaced with data from ${BACKUP_FILE}."
    echo -e "\nTo proceed, type 'RESTORE ${ENVIRONMENT}' (case sensitive):"
    read confirmation

    if [ "$confirmation" != "RESTORE ${ENVIRONMENT}" ]; then
        log "Restore cancelled by user"
        exit 0
    fi
fi

# Get temporary filename for decompressed SQL if needed
if [[ "$BACKUP_FILE" == *.gz ]]; then
    if ! command -v gunzip &>/dev/null; then
        log "ERROR: Required command 'gunzip' not found"
        exit 1
    fi
    TEMP_SQL=$(mktemp)
    log "Decompressing backup file"
    gunzip -c "$BACKUP_FILE" > "$TEMP_SQL"
else
    TEMP_SQL="$BACKUP_FILE"
fi

# Stop the application to prevent connections during restore
if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q cloud-platform; then
    log "Stopping application services"
    systemctl stop cloud-platform.service || log "WARNING: Failed to stop application service"
fi

# Backup current database before restore
if [ "$FORCE" != "true" ]; then
    CURRENT_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    PRE_RESTORE_BACKUP="/var/backups/cloud-platform/database/${DB_NAME}_${ENVIRONMENT}_pre_restore_${CURRENT_TIMESTAMP}.sql.gz"
    log "Creating safety backup of current database to ${PRE_RESTORE_BACKUP}"
    mkdir -p "$(dirname "$PRE_RESTORE_BACKUP")"
    
    # Try to create a safety backup
    if ! pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$PRE_RESTORE_BACKUP" 2>/dev/null; then
        log "WARNING: Failed to create safety backup. Will continue with restore."
    fi
fi

# Restore the database
log "Dropping and recreating database ${DB_NAME}"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE);"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "CREATE DATABASE ${DB_NAME};"

log "Restoring data from backup"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$TEMP_SQL"
RESTORE_STATUS=$?

# Clean up
if [[ "$BACKUP_FILE" == *.gz ]]; then
    rm "$TEMP_SQL"
fi

# Start the application again
if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q cloud-platform; then
    log "Starting application services"
    systemctl start cloud-platform.service
fi

# Apply migrations if needed
if [ $RESTORE_STATUS -eq 0 ] && [ -d "${PROJECT_ROOT}/migrations" ]; then
    log "Checking if migrations need to be applied"
    cd "$PROJECT_ROOT"
    FLASK_APP=app.py FLASK_ENV="${ENVIRONMENT}" flask db current 2>/dev/null || {
        log "Applying current migrations"
        FLASK_APP=app.py FLASK_ENV="${ENVIRONMENT}" flask db upgrade
    }
fi

if [ $RESTORE_STATUS -eq 0 ]; then
    log "Database restore completed successfully"
    echo "✅ Database restore completed successfully!"
else
    log "ERROR: Database restore failed with status $RESTORE_STATUS"
    echo "❌ Database restore failed! Check log for details: $LOG_FILE"
    exit 1
fi

log "NOTE: You may need to restart associated services to ensure proper application functionality"