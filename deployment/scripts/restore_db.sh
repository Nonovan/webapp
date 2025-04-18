#!/bin/bash
# Database restore script for Cloud Infrastructure Platform
# Usage: ./scripts/restore_db.sh backup_file [environment]

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 backup_file [environment]"
    echo "Example: $0 /var/backups/cloud-platform/database/cloud_platform_production_20230515.sql.gz production"
    exit 1
fi

BACKUP_FILE="$1"
# Default to production if no environment specified
ENVIRONMENT=${2:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
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
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    log "Loading ${ENVIRONMENT} environment variables"
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
else
    log "ERROR: Environment file ${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env not found"
    exit 1
fi

# Set database connection details from environment or defaults
DB_USER=${DB_USER:-"postgres"}
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-"5432"}
DB_NAME=${DB_NAME:-"cloud_platform"}

# Check for required tools
for cmd in psql gunzip; do
    if ! command -v $cmd &>/dev/null; then
        log "ERROR: Required command '$cmd' not found"
        exit 1
    fi
done

# Confirm with the user before proceeding
echo -e "\n*** WARNING ***"
echo "This will OVERWRITE the ${DB_NAME} database in the ${ENVIRONMENT} environment."
echo "All current data will be lost and replaced with data from ${BACKUP_FILE}."
echo -e "\nAre you sure you want to continue? (type 'yes' to confirm)"
read confirmation

if [ "$confirmation" != "yes" ]; then
    log "Restore cancelled by user"
    exit 0
fi

# Get temporary filename
TEMP_SQL=$(mktemp)

# Decompress the backup file
log "Decompressing backup file"
gunzip -c "$BACKUP_FILE" > "$TEMP_SQL"

# Stop the application to prevent connections during restore
if command -v systemctl &>/dev/null; then
    log "Stopping application services"
    systemctl stop cloud-platform.service || log "WARNING: Failed to stop application service"
fi

# Restore the database
log "Dropping and recreating database ${DB_NAME}"
PGPASSWORD="$PGPASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME};"
PGPASSWORD="$PGPASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -c "CREATE DATABASE ${DB_NAME};"

log "Restoring data from backup"
PGPASSWORD="$PGPASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$TEMP_SQL"

# Clean up
rm "$TEMP_SQL"

# Start the application again
if command -v systemctl &>/dev/null; then
    log "Starting application services"
    systemctl start cloud-platform.service
fi

log "Database restore completed"
log "NOTE: You may need to apply any migrations that have occurred since the backup was created"