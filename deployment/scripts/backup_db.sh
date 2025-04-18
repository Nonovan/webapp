#!/bin/bash
# Database backup script for Cloud Infrastructure Platform
# Usage: ./scripts/backup_db.sh [environment]

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TODAY=$(date +%Y%m%d)
BACKUP_DIR="/var/backups/cloud-platform/database"
RETENTION_DAYS=30
LOG_FILE="/var/log/cloud-platform/db_backup.log"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

log "Starting database backup for ${ENVIRONMENT} environment"

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
BACKUP_FILENAME="${BACKUP_DIR}/${DB_NAME}_${ENVIRONMENT}_${TODAY}.sql.gz"

# Check if PGPASSWORD is set, warn if not
if [ -z "$PGPASSWORD" ]; then
    log "WARNING: PGPASSWORD not set, password authentication may fail"
fi

# Perform the backup
log "Creating backup ${BACKUP_FILENAME}"
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -F p | gzip > "$BACKUP_FILENAME"

# Check if backup was successful
if [ $? -eq 0 ] && [ -f "$BACKUP_FILENAME" ]; then
    log "Backup created successfully: ${BACKUP_FILENAME}"
    
    # Set secure permissions
    chmod 600 "$BACKUP_FILENAME"
    
    # Calculate backup size
    BACKUP_SIZE=$(du -h "$BACKUP_FILENAME" | cut -f1)
    log "Backup size: ${BACKUP_SIZE}"
    
    # Clean up old backups
    log "Cleaning up backups older than ${RETENTION_DAYS} days"
    find "$BACKUP_DIR" -name "${DB_NAME}_${ENVIRONMENT}_*.sql.gz" -type f -mtime +${RETENTION_DAYS} -delete
else
    log "ERROR: Backup failed"
    exit 1
fi

# Verify backup file integrity
log "Verifying backup integrity"
if gunzip -t "$BACKUP_FILENAME"; then
    log "Backup file integrity verified"
else
    log "ERROR: Backup file integrity check failed"
    exit 1
fi

# Copy to remote backup (if configured)
if [ ! -z "$REMOTE_BACKUP_USER" ] && [ ! -z "$REMOTE_BACKUP_HOST" ] && [ ! -z "$REMOTE_BACKUP_DIR" ]; then
    log "Copying backup to remote server ${REMOTE_BACKUP_HOST}"
    scp "$BACKUP_FILENAME" "${REMOTE_BACKUP_USER}@${REMOTE_BACKUP_HOST}:${REMOTE_BACKUP_DIR}/"
    
    if [ $? -eq 0 ]; then
        log "Remote backup copy successful"
    else
        log "WARNING: Remote backup copy failed"
    fi
fi

log "Database backup process completed"