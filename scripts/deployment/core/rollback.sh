#!/bin/bash
# Rollback script for Cloud Infrastructure Platform
# Reverts to a previous version in case of deployment issues
# Usage: ./rollback.sh [environment] [--version <tag>] [--database] [--force]

set -e

# Default settings
ENVIRONMENT=${1:-production}
ROLLBACK_VERSION=""
ROLLBACK_DATABASE=false
FORCE_ROLLBACK=false
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BACKUP_DIR="/var/backups/cloud-platform"
LOG_FILE="/var/log/cloud-platform/rollback.log"

# Parse additional arguments
shift
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --version)
            ROLLBACK_VERSION="$2"
            shift
            shift
            ;;
        --database)
            ROLLBACK_DATABASE=true
            shift
            ;;
        --force)
            FORCE_ROLLBACK=true
            shift
            ;;
        --help)
            echo "Usage: $0 [environment] [--version <tag>] [--database] [--force]"
            echo ""
            echo "Options:"
            echo "  environment       Target environment (default: production)"
            echo "  --version <tag>   Specific version to rollback to"
            echo "  --database        Include database rollback"
            echo "  --force           Skip confirmation prompts"
            echo ""
            echo "Examples:"
            echo "  $0 production --version v2.1.0"
            echo "  $0 staging --database"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Ensure log directory exists
mkdir -p $(dirname "$LOG_FILE")

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Confirm rollback with user
confirm() {
    if [ "$FORCE_ROLLBACK" = true ]; then
        return 0
    fi
    
    read -p "⚠️ Are you sure you want to roll back $ENVIRONMENT environment? [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            log "Rollback cancelled by user"
            exit 1
            ;;
    esac
}

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file not found: $ENV_FILE"
fi

log "Starting rollback process for ${ENVIRONMENT} environment"

# Get current version for logging
CURRENT_VERSION=$(cd "$PROJECT_ROOT" && git describe --tags 2>/dev/null || git rev-parse --short HEAD)
log "Current version: $CURRENT_VERSION"

# Confirm rollback with user
confirm

# Stop services before rollback
log "Stopping application services"
if command -v supervisorctl &>/dev/null; then
    supervisorctl stop all
elif command -v systemctl &>/dev/null; then
    systemctl stop cloud-platform.service
else
    log "WARNING: Could not determine service manager to stop services"
fi

# Determine rollback version if not specified
if [ -z "$ROLLBACK_VERSION" ]; then
    # Get previous version from deployment log or git history
    log "No specific version provided, determining previous version"
    DEPLOY_LOG="/var/log/cloud-platform/deploy.log"
    
    if [ -f "$DEPLOY_LOG" ]; then
        # Get second-to-last deployment version from log
        ROLLBACK_VERSION=$(grep "Deploying version" "$DEPLOY_LOG" | tail -n 2 | head -n 1 | sed -E 's/.*version: ([^ ]+).*/\1/')
    fi
    
    # If we still don't have a version, get the previous git tag
    if [ -z "$ROLLBACK_VERSION" ]; then
        ROLLBACK_VERSION=$(cd "$PROJECT_ROOT" && git describe --tags --abbrev=0 HEAD~1 2>/dev/null)
    fi
    
    # If we still don't have a version, get the previous commit
    if [ -z "$ROLLBACK_VERSION" ]; then
        ROLLBACK_VERSION=$(cd "$PROJECT_ROOT" && git rev-parse --short HEAD~1)
    fi
    
    if [ -z "$ROLLBACK_VERSION" ]; then
        log "ERROR: Could not determine previous version. Please specify with --version"
        exit 1
    fi
fi

log "Rolling back to version: $ROLLBACK_VERSION"

# Backup current code before rollback
BACKUP_CODE_DIR="${BACKUP_DIR}/code-${CURRENT_VERSION}-$(date +%Y%m%d%H%M%S)"
log "Backing up current code to $BACKUP_CODE_DIR"
mkdir -p "$BACKUP_CODE_DIR"
cp -r "$PROJECT_ROOT"/* "$BACKUP_CODE_DIR/"

# Rollback code
log "Rolling back code to $ROLLBACK_VERSION"
cd "$PROJECT_ROOT"
git fetch --all --tags
git checkout "$ROLLBACK_VERSION" || {
    log "ERROR: Failed to checkout version $ROLLBACK_VERSION"
    log "Available versions:"
    git tag -l | tail -5
    exit 1
}

# Rollback database if requested
if [ "$ROLLBACK_DATABASE" = true ]; then
    log "Rolling back database"
    
    # Find latest database backup before current deployment
    if [ -d "${BACKUP_DIR}/database" ]; then
        # Try to find a backup from right before the current version deployment
        if [ -f "${BACKUP_DIR}/deploy-${CURRENT_VERSION}.log" ]; then
            DB_BACKUP_FILE=$(find "${BACKUP_DIR}/database" -name "${DB_NAME:-cloud_platform}_${ENVIRONMENT}_*.sql.gz" -type f -not -newer "${BACKUP_DIR}/deploy-${CURRENT_VERSION}.log" | sort -r | head -n 1)
        else
            # Otherwise just use the most recent backup
            DB_BACKUP_FILE=$(find "${BACKUP_DIR}/database" -name "${DB_NAME:-cloud_platform}_${ENVIRONMENT}_*.sql.gz" -type f | sort -r | head -n 1)
        fi
    else
        # Legacy backup path structure
        DB_BACKUP_FILE=$(find "$BACKUP_DIR" -name "db-backup-${ENVIRONMENT}-*.sql*" -type f -not -newer "${BACKUP_DIR}/deploy-${CURRENT_VERSION}.log" 2>/dev/null | sort -r | head -n 1)
    fi
    
    if [ -n "$DB_BACKUP_FILE" ]; then
        log "Found database backup: $DB_BACKUP_FILE"
        
        # Backup current database before rollback
        DB_NAME=${DB_NAME:-"cloud_platform"}
        CURRENT_DB_BACKUP="${BACKUP_DIR}/database/${DB_NAME}_${ENVIRONMENT}_pre-rollback_$(date +%Y%m%d%H%M%S).sql.gz"
        
        log "Creating backup of current database to $CURRENT_DB_BACKUP"
        mkdir -p "$(dirname "$CURRENT_DB_BACKUP")"
        
        # Create pre-rollback backup
        if command -v pg_dump &>/dev/null; then
            PGPASSWORD="${DB_PASSWORD:-postgres}" pg_dump -h "${DB_HOST:-localhost}" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" "$DB_NAME" | gzip > "$CURRENT_DB_BACKUP"
        else
            log "WARNING: pg_dump not found, using flask command instead"
            cd "$PROJECT_ROOT" && FLASK_APP=app.py FLASK_ENV="${ENVIRONMENT}" flask db backup --dir="$(dirname "$CURRENT_DB_BACKUP")" --compress
        fi
        
        # Restore from backup
        log "Restoring database from $DB_BACKUP_FILE"
        "${SCRIPT_DIR}/restore_db.sh" "$DB_BACKUP_FILE" "$ENVIRONMENT" --force
        
        if [ $? -ne 0 ]; then
            log "ERROR: Database restore failed. Please check logs."
        else
            log "Database successfully rolled back"
        fi
    else
        log "WARNING: No suitable database backup found. Database will not be rolled back."
    fi
else
    log "Skipping database rollback (use --database to include database)"
    
    # Handle database migrations
    log "Reverting database migrations if needed"
    cd "$PROJECT_ROOT"
    if [ -f "${PROJECT_ROOT}/migrations/versions" ]; then
        FLASK_APP=app.py FLASK_ENV="${ENVIRONMENT}" flask db stamp "$ROLLBACK_VERSION" || {
            log "WARNING: Could not stamp database version. You may need to manually fix migrations."
        }
    else
        log "No migrations directory found, skipping migration rollback"
    fi
fi

# Install dependencies for rollback version
log "Installing dependencies for rolled back version"
if [ -f "${PROJECT_ROOT}/requirements.txt" ]; then
    pip install -r "${PROJECT_ROOT}/requirements.txt"
else
    log "WARNING: requirements.txt not found for version $ROLLBACK_VERSION"
fi

# Start services after rollback
log "Starting application services"
if command -v supervisorctl &>/dev/null; then
    supervisorctl start all
elif command -v systemctl &>/dev/null; then
    systemctl start cloud-platform.service
else
    log "WARNING: Could not determine service manager to start services"
fi

# Restart web server if needed
if command -v systemctl &>/dev/null && systemctl list-unit-files | grep -q nginx; then
    log "Restarting nginx"
    systemctl restart nginx
fi

# Run smoke tests to verify rollback
log "Verifying rollback with smoke tests"
if [ -f "${SCRIPT_DIR}/smoke-test.sh" ]; then
    "${SCRIPT_DIR}/smoke-test.sh" "${ENVIRONMENT}" || {
        log "WARNING: Smoke tests failed after rollback. Please check the application manually."
    }
else
    log "WARNING: smoke-test.sh not found, skipping verification"
fi

log "Rollback to version $ROLLBACK_VERSION completed"

# Final status message
echo ""
echo "=========================================================="
echo "  ROLLBACK COMPLETED: ${ENVIRONMENT} → ${ROLLBACK_VERSION}"
echo "=========================================================="
echo "Rollback log: $LOG_FILE"
if [ "$ROLLBACK_DATABASE" = true ] && [ -n "$DB_BACKUP_FILE" ]; then
    echo "Database was rolled back to: $(basename "$DB_BACKUP_FILE")"
    echo "Pre-rollback database backup: $(basename "$CURRENT_DB_BACKUP")"
fi
echo ""
echo "Please verify that the application is functioning correctly."
echo "If issues persist, contact the development team for assistance."