#!/bin/bash
# ==============================================================================
# Database Backup and Restore Script for Cloud Infrastructure Platform
# ==============================================================================
# This script provides functionality for backing up and restoring PostgreSQL 
# databases used by the Cloud Infrastructure Platform. It supports different
# environments and includes validation, compression, and encryption options.
# ==============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/var/backups/cloud-platform"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONFIG_FILE="${SCRIPT_DIR}/../deployment/database/db_config.ini"
ENVIRONMENTS=("production" "staging" "development" "ci" "demo")
LOG_FILE="/var/log/cloud-platform/db-operations.log"
RETENTION_DAYS={"production":30,"staging":14,"development":7}

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Function to log messages
log() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

# Show usage information
usage() {
    echo "Cloud Infrastructure Platform Database Manager"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  backup    Create a database backup"
    echo "  restore   Restore a database from backup"
    echo "  verify    Verify the integrity of a backup file"
    echo "  list      List available backups"
    echo "  rotate    Remove old backups exceeding retention period"
    echo "  seed      Seed database with initial data"
    echo ""
    echo "Options:"
    echo "  --env ENV           Environment (production, staging, development, ci, demo)"
    echo "  --file FILE         Backup file to restore from or verify"
    echo "  --compress          Compress backup with gzip (default for backup)"
    echo "  --encrypt           Encrypt backup with GPG (requires GPG setup)"
    echo "  --schema-only       Backup/restore only the schema, not the data"
    echo "  --tables TABLES     Comma-separated list of tables to back up"
    echo "  --no-owner          Exclude ownership commands in backup/restore"
    echo "  --force             Skip confirmation prompts"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 backup --env production"
    echo "  $0 restore --env development --file backup_20231101_120000.sql.gz"
    echo "  $0 verify --file backup_20231101_120000.sql.gz"
    echo "  $0 list --env production"
    echo ""
}

# Function to read database configuration
read_db_config() {
    local env=$1
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Config file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Check if environment exists in config file
    if ! grep -q "^\[$env\]" "$CONFIG_FILE"; then
        log "ERROR" "Environment '$env' not found in config file"
        exit 1
    }
    
    # Read configuration values
    local host=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^host/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    local port=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^port/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    local dbname=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^dbname/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    local admin_user=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^admin_user/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    local admin_password=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^admin_password/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    local app_user=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^app_user/) print \$2}" "$CONFIG_FILE" | tr -d ' ')
    
    # Replace environment variables if needed
    if [[ "$admin_password" == \$* ]]; then
        local var_name="${admin_password:1}"
        admin_password="${!var_name}"
    fi
    
    echo "$host|$port|$dbname|$admin_user|$admin_password|$app_user"
}

# Function to create backup
create_backup() {
    local env=$1
    local schema_only=$2
    local compress=$3
    local encrypt=$4
    local tables=$5
    local no_owner=$6
    
    log "INFO" "Creating backup for $env environment..."
    
    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR/$env"
    
    # Read database configuration
    local db_config=$(read_db_config "$env")
    local host=$(echo "$db_config" | cut -d'|' -f1)
    local port=$(echo "$db_config" | cut -d'|' -f2)
    local dbname=$(echo "$db_config" | cut -d'|' -f3)
    local admin_user=$(echo "$db_config" | cut -d'|' -f4)
    local admin_password=$(echo "$db_config" | cut -d'|' -f5)
    
    # Set environment variables for PostgreSQL authentication
    export PGPASSWORD="$admin_password"
    
    # Build pg_dump command with options
    local pg_dump_cmd="pg_dump -h $host -p $port -U $admin_user"
    
    # Add options based on parameters
    if [[ "$schema_only" == "true" ]]; then
        pg_dump_cmd="$pg_dump_cmd --schema-only"
    fi
    
    if [[ "$no_owner" == "true" ]]; then
        pg_dump_cmd="$pg_dump_cmd --no-owner"
    fi
    
    if [[ -n "$tables" ]]; then
        for table in $(echo "$tables" | tr ',' ' '); do
            pg_dump_cmd="$pg_dump_cmd --table=$table"
        done
    fi
    
    # Add database name
    pg_dump_cmd="$pg_dump_cmd $dbname"
    
    # Define backup file path
    local backup_file="$BACKUP_DIR/$env/backup_${env}_${TIMESTAMP}.sql"
    
    # Execute backup with or without compression/encryption
    if [[ "$compress" == "true" && "$encrypt" == "true" ]]; then
        # Compress and encrypt
        $pg_dump_cmd | gzip | gpg --encrypt --recipient cloud-platform-backup > "${backup_file}.gz.gpg"
        log "INFO" "Backup created, compressed and encrypted: ${backup_file}.gz.gpg"
    elif [[ "$compress" == "true" ]]; then
        # Compress only
        $pg_dump_cmd | gzip > "${backup_file}.gz"
        log "INFO" "Backup created and compressed: ${backup_file}.gz"
    elif [[ "$encrypt" == "true" ]]; then
        # Encrypt only
        $pg_dump_cmd | gpg --encrypt --recipient cloud-platform-backup > "${backup_file}.gpg"
        log "INFO" "Backup created and encrypted: ${backup_file}.gpg"
    else
        # Plain backup
        $pg_dump_cmd > "$backup_file"
        log "INFO" "Backup created: $backup_file"
    fi
    
    # Calculate and store checksum
    if [[ "$compress" == "true" && "$encrypt" == "true" ]]; then
        sha256sum "${backup_file}.gz.gpg" > "${backup_file}.gz.gpg.sha256"
    elif [[ "$compress" == "true" ]]; then
        sha256sum "${backup_file}.gz" > "${backup_file}.gz.sha256"
    elif [[ "$encrypt" == "true" ]]; then
        sha256sum "${backup_file}.gpg" > "${backup_file}.gpg.sha256"
    else
        sha256sum "$backup_file" > "${backup_file}.sha256"
    fi
    
    # Clear PostgreSQL password from environment
    unset PGPASSWORD
    
    log "INFO" "Backup for $env completed successfully"
    return 0
}

# Function to restore backup
restore_backup() {
    local env=$1
    local backup_file=$2
    local no_owner=$3
    local force=$4
    
    # Check if backup file exists
    if [[ ! -f "$backup_file" ]]; then
        log "ERROR" "Backup file not found: $backup_file"
        exit 1
    fi
    
    log "INFO" "Preparing to restore $env database from $backup_file"
    
    # Read database configuration
    local db_config=$(read_db_config "$env")
    local host=$(echo "$db_config" | cut -d'|' -f1)
    local port=$(echo "$db_config" | cut -d'|' -f2)
    local dbname=$(echo "$db_config" | cut -d'|' -f3)
    local admin_user=$(echo "$db_config" | cut -d'|' -f4)
    local admin_password=$(echo "$db_config" | cut -d'|' -f5)
    
    # Confirmation prompt unless --force is specified
    if [[ "$force" != "true" ]]; then
        echo "WARNING: This will overwrite the $env database with data from $backup_file"
        echo "To proceed, type 'RESTORE $env' (all uppercase):"
        read -r confirmation
        
        if [[ "$confirmation" != "RESTORE $env" ]]; then
            log "INFO" "Restore operation cancelled by user"
            echo "Restore cancelled"
            exit 0
        fi
    fi
    
    # Set environment variables for PostgreSQL authentication
    export PGPASSWORD="$admin_password"
    
    # Determine file type and prepare restore command
    local restore_cmd="psql -h $host -p $port -U $admin_user -d $dbname"
    
    if [[ "$no_owner" == "true" ]]; then
        restore_cmd="$restore_cmd -o"
    fi
    
    # Execute restore based on file type
    log "INFO" "Restoring database $dbname from backup..."
    
    if [[ "$backup_file" == *.gz.gpg ]]; then
        # Compressed and encrypted
        gpg --decrypt "$backup_file" | gunzip | $restore_cmd
    elif [[ "$backup_file" == *.gpg ]]; then
        # Encrypted only
        gpg --decrypt "$backup_file" | $restore_cmd
    elif [[ "$backup_file" == *.gz ]]; then
        # Compressed only
        gunzip -c "$backup_file" | $restore_cmd
    else
        # Plain SQL
        $restore_cmd < "$backup_file"
    fi
    
    # Clear PostgreSQL password from environment
    unset PGPASSWORD
    
    log "INFO" "Database $dbname restored successfully"
    return 0
}

# Function to verify backup integrity
verify_backup() {
    local backup_file=$1
    
    # Check if backup file exists
    if [[ ! -f "$backup_file" ]]; then
        log "ERROR" "Backup file not found: $backup_file"
        exit 1
    fi
    
    log "INFO" "Verifying backup integrity: $backup_file"
    
    # Check if checksum file exists
    local checksum_file="${backup_file}.sha256"
    if [[ ! -f "$checksum_file" ]]; then
        log "WARNING" "Checksum file not found: $checksum_file"
        log "INFO" "Generating new checksum for verification"
        sha256sum "$backup_file" > "$checksum_file"
        log "INFO" "Checksum file created: $checksum_file"
        return 0
    fi
    
    # Verify checksum
    if sha256sum -c "$checksum_file"; then
        log "INFO" "Backup verification successful: $backup_file"
        echo "Backup integrity verified successfully"
        return 0
    else
        log "ERROR" "Backup verification failed: $backup_file"
        echo "ERROR: Backup file may be corrupted"
        return 1
    fi
}

# Function to list available backups
list_backups() {
    local env=$1
    
    local backup_dir="$BACKUP_DIR"
    if [[ -n "$env" ]]; then
        backup_dir="$BACKUP_DIR/$env"
    fi
    
    # Check if backup directory exists
    if [[ ! -d "$backup_dir" ]]; then
        log "WARNING" "No backups found in: $backup_dir"
        echo "No backups found"
        return 0
    fi
    
    echo "Available backups:"
    echo "--------------------------------------------------"
    if [[ -n "$env" ]]; then
        find "$backup_dir" -type f -name "backup_*.sql*" | grep -v ".sha256$" | sort -r | while read -r file; do
            local filesize=$(du -h "$file" | cut -f1)
            local timestamp=$(stat -c %y "$file")
            echo "$(basename "$file") ($filesize, $timestamp)"
        done
    else
        for env_dir in "${ENVIRONMENTS[@]}"; do
            if [[ -d "$backup_dir/$env_dir" ]]; then
                echo "Environment: $env_dir"
                find "$backup_dir/$env_dir" -type f -name "backup_*.sql*" | grep -v ".sha256$" | sort -r | head -5 | while read -r file; do
                    local filesize=$(du -h "$file" | cut -f1)
                    local timestamp=$(stat -c %y "$file")
                    echo "  $(basename "$file") ($filesize, $timestamp)"
                done
                echo ""
            fi
        done
    fi
    
    return 0
}

# Function to rotate old backups
rotate_backups() {
    local env=$1
    
    if [[ -z "$env" ]]; then
        log "ERROR" "Environment must be specified for backup rotation"
        exit 1
    fi
    
    log "INFO" "Rotating old backups for $env environment"
    
    # Get retention days for environment
    local retention_days=${RETENTION_DAYS[$env]}
    if [[ -z "$retention_days" ]]; then
        retention_days=7  # Default retention period
    fi
    
    local backup_dir="$BACKUP_DIR/$env"
    if [[ ! -d "$backup_dir" ]]; then
        log "WARNING" "No backup directory found: $backup_dir"
        return 0
    fi
    
    # Find and delete old backups
    local deleted_count=0
    find "$backup_dir" -type f -name "backup_*" -mtime +$retention_days | while read -r file; do
        log "INFO" "Removing old backup: $file"
        rm -f "$file"
        deleted_count=$((deleted_count+1))
    done
    
    log "INFO" "Backup rotation completed: $deleted_count files removed"
    return 0
}

# Function to seed database
seed_database() {
    local env=$1
    local force=$2
    
    log "INFO" "Preparing to seed $env database"
    
    # Read database configuration
    local db_config=$(read_db_config "$env")
    local host=$(echo "$db_config" | cut -d'|' -f1)
    local port=$(echo "$db_config" | cut -d'|' -f2)
    local dbname=$(echo "$db_config" | cut -d'|' -f3)
    local admin_user=$(echo "$db_config" | cut -d'|' -f4)
    local admin_password=$(echo "$db_config" | cut -d'|' -f5)
    
    # Seed SQL file path
    local seed_file="${SCRIPT_DIR}/../deployment/database/seed.sql"
    
    # Check if seed file exists
    if [[ ! -f "$seed_file" ]]; then
        log "ERROR" "Seed file not found: $seed_file"
        exit 1
    }
    
    # Confirmation prompt unless --force is specified
    if [[ "$force" != "true" ]]; then
        echo "WARNING: This will seed the $env database with initial data"
        echo "To proceed, type 'SEED $env' (all uppercase):"
        read -r confirmation
        
        if [[ "$confirmation" != "SEED $env" ]]; then
            log "INFO" "Seed operation cancelled by user"
            echo "Seed cancelled"
            exit 0
        fi
    fi
    
    # Set environment variables for PostgreSQL authentication
    export PGPASSWORD="$admin_password"
    
    # Execute seed SQL
    log "INFO" "Seeding database $dbname..."
    if psql -h "$host" -p "$port" -U "$admin_user" -d "$dbname" -f "$seed_file"; then
        log "INFO" "Database $dbname seeded successfully"
        echo "Database seeded successfully"
    else
        log "ERROR" "Failed to seed database $dbname"
        echo "Error: Failed to seed database"
        unset PGPASSWORD
        exit 1
    fi
    
    # Clear PostgreSQL password from environment
    unset PGPASSWORD
    
    return 0
}

# Parse command-line arguments
COMMAND=""
ENV=""
BACKUP_FILE=""
COMPRESS="true"  # Default to compression for backups
ENCRYPT="false"
SCHEMA_ONLY="false"
TABLES=""
NO_OWNER="false"
FORCE="false"

# Parse command
if [ $# -eq 0 ]; then
    usage
    exit 1
fi

COMMAND="$1"
shift

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --env)
            ENV="$2"
            shift 2
            ;;
        --file)
            BACKUP_FILE="$2"
            shift 2
            ;;
        --compress)
            COMPRESS="true"
            shift
            ;;
        --no-compress)
            COMPRESS="false"
            shift
            ;;
        --encrypt)
            ENCRYPT="true"
            shift
            ;;
        --schema-only)
            SCHEMA_ONLY="true"
            shift
            ;;
        --tables)
            TABLES="$2"
            shift 2
            ;;
        --no-owner)
            NO_OWNER="true"
            shift
            ;;
        --force)
            FORCE="true"
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate environment when required
if [[ "$COMMAND" == "backup" || "$COMMAND" == "restore" || "$COMMAND" == "seed" || "$COMMAND" == "rotate" ]]; then
    if [[ -z "$ENV" ]]; then
        log "ERROR" "Environment must be specified with --env"
        exit 1
    fi
    
    # Check if environment is valid
    valid_env=false
    for e in "${ENVIRONMENTS[@]}"; do
        if [[ "$ENV" == "$e" ]]; then
            valid_env=true
            break
        fi
    done
    
    if [[ "$valid_env" == "false" ]]; then
        log "ERROR" "Invalid environment: $ENV"
        exit 1
    fi
fi

# Execute command
case "$COMMAND" in
    backup)
        create_backup "$ENV" "$SCHEMA_ONLY" "$COMPRESS" "$ENCRYPT" "$TABLES" "$NO_OWNER"
        ;;
    restore)
        if [[ -z "$BACKUP_FILE" ]]; then
            log "ERROR" "Restore requires a backup file (--file)"
            exit 1
        fi
        restore_backup "$ENV" "$BACKUP_FILE" "$NO_OWNER" "$FORCE"
        ;;
    verify)
        if [[ -z "$BACKUP_FILE" ]]; then
            log "ERROR" "Verify requires a backup file (--file)"
            exit 1
        fi
        verify_backup "$BACKUP_FILE"
        ;;
    list)
        list_backups "$ENV"
        ;;
    rotate)
        rotate_backups "$ENV"
        ;;
    seed)
        seed_database "$ENV" "$FORCE"
        ;;
    *)
        log "ERROR" "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac

exit 0