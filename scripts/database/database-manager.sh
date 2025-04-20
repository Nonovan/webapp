#!/bin/bash
# ==============================================================================
# Database Backup and Restore Script for Cloud Infrastructure Platform
# ==============================================================================
# This script provides comprehensive functionality for managing PostgreSQL 
# databases used by the Cloud Infrastructure Platform, including:
#  - Backup and restore
#  - Replication monitoring
#  - Database verification
#  - Seed data management
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
REPLICATION_LAG_THRESHOLD=300  # 5 minutes in seconds

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
    echo "  backup           Create a database backup"
    echo "  restore          Restore a database from backup"
    echo "  verify           Verify the integrity of a backup file"
    echo "  list             List available backups"
    echo "  rotate           Remove old backups exceeding retention period"
    echo "  seed             Seed database with initial data"
    echo "  check-replication Check database replication status"
    echo "  verify-db        Verify database connectivity and structure"
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
    echo "  --host HOST         Database host for verification (default: from config)"
    echo "  --quick-check       For verify-db: only check connectivity"
    echo "  --threshold SECONDS  Maximum acceptable replication lag (default: 300s)"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 backup --env production"
    echo "  $0 restore --env development --file backup_20231101_120000.sql.gz"
    echo "  $0 verify --file backup_20231101_120000.sql.gz"
    echo "  $0 check-replication --env production"
    echo "  $0 verify-db --env production --host primary-db.internal"
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

# Get replication hosts from environment file
get_replication_hosts() {
    local env=$1
    local env_file="${SCRIPT_DIR}/../deployment/environments/${env}.env"
    
    if [[ ! -f "$env_file" ]]; then
        log "WARNING" "Environment file not found: $env_file"
        echo "localhost|localhost"
        return
    }
    
    # Source environment file to get variables
    source "$env_file"
    
    # Use environment variables or defaults
    local primary_host=${PRIMARY_DB_HOST:-"primary-db.internal"}
    local secondary_host=${SECONDARY_DB_HOST:-"secondary-db.internal"}
    
    echo "$primary_host|$secondary_host"
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
    else:
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

# Function to check database connectivity
check_db_connectivity() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    
    log "INFO" "Checking connectivity to database at ${host}:${port}..."
    
    # Export password for psql
    export PGPASSWORD="${password}"
    
    if psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "SELECT 1" -q -t > /dev/null 2>&1; then
        log "INFO" "Database connectivity check passed"
        unset PGPASSWORD
        return 0
    else
        log "ERROR" "Failed to connect to database at ${host}:${port}"
        unset PGPASSWORD
        return 1
    fi
}

# Function to check database version
check_db_version() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    
    log "INFO" "Checking database version..."
    
    export PGPASSWORD="${password}"
    VERSION=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "SELECT version();" -q -t 2>/dev/null)
    unset PGPASSWORD
    
    if [ -n "$VERSION" ]; then
        log "INFO" "Database version: $VERSION"
        return 0
    else
        log "ERROR" "Failed to retrieve database version"
        return 1
    fi
}

# Function to check critical tables
check_db_tables() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    
    log "INFO" "Checking critical tables..."
    
    export PGPASSWORD="${password}"
    
    # Check count of critical tables
    TABLE_COUNT=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE';" -q -t 2>/dev/null)
    
    if [ -z "$TABLE_COUNT" ] || [ "$TABLE_COUNT" -eq 0 ]; then
        log "ERROR" "No tables found in database"
        unset PGPASSWORD
        return 1
    else
        log "INFO" "Found $TABLE_COUNT tables in database"
        
        # Check count of specific critical tables
        USER_COUNT=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_name = 'users';" -q -t 2>/dev/null)
        
        if [ "$USER_COUNT" -eq 0 ]; then
            log "ERROR" "Critical table 'users' not found"
            unset PGPASSWORD
            return 1
        fi
        
        unset PGPASSWORD
        return 0
    fi
}

# Function to check database size
check_db_size() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    
    log "INFO" "Checking database size..."
    
    export PGPASSWORD="${password}"
    DB_SIZE=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
        SELECT pg_size_pretty(pg_database_size('$dbname'));" -q -t 2>/dev/null)
    unset PGPASSWORD
    
    if [ -n "$DB_SIZE" ]; then
        log "INFO" "Database size: $DB_SIZE"
        return 0
    else
        log "ERROR" "Failed to retrieve database size"
        return 1
    fi
}

# Function to check replication status of a database node
check_db_replication() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    
    log "INFO" "Checking replication status for $host..."
    
    export PGPASSWORD="${password}"
    
    # Check if this is a replica
    IS_REPLICA=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
        SELECT pg_is_in_recovery();" -q -t 2>/dev/null | tr -d ' ')
    
    if [ "$IS_REPLICA" = "t" ]; then
        log "INFO" "This is a replica database"
        
        # Check replication lag
        LAG_SECONDS=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
            SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" -q -t 2>/dev/null)
        
        if [ -n "$LAG_SECONDS" ]; then
            if (( $(echo "$LAG_SECONDS < $REPLICATION_LAG_THRESHOLD" | bc -l) )); then
                log "INFO" "Replication lag: ${LAG_SECONDS} seconds (within threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
                unset PGPASSWORD
                return 0
            else
                log "ERROR" "Replication lag: ${LAG_SECONDS} seconds (exceeds threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
                unset PGPASSWORD
                return 1
            fi
        else
            log "ERROR" "Failed to retrieve replication lag information"
            unset PGPASSWORD
            return 1
        fi
    elif [ "$IS_REPLICA" = "f" ]; then
        # Check if this is a primary with replicas
        HAS_REPLICAS=$(psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "
            SELECT COUNT(*) FROM pg_stat_replication;" -q -t 2>/dev/null)
        
        if [ -n "$HAS_REPLICAS" ] && [ "$HAS_REPLICAS" -gt 0 ]; then
            log "INFO" "This is a primary database with $HAS_REPLICAS connected replicas"
            unset PGPASSWORD
            return 0
        else
            log "INFO" "This is a primary database with no connected replicas"
            # Not an error condition if we're checking the primary region
            unset PGPASSWORD
            return 0
        fi
    else
        log "ERROR" "Failed to determine replication role"
        unset PGPASSWORD
        return 1
    fi
}

# Function to log to DR events log
log_dr_event() {
    local event_type=$1
    local environment=$2
    local host=$3  
    local status=$4
    
    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"
    
    # Log the database verification event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),${event_type},${environment},${host},${status}" >> "/var/log/cloud-platform/dr-events.log"
    log "INFO" "${event_type} event logged to DR events log"
}

# Function for comprehensive database verification
verify_database() {
    local env=$1
    local host=$2
    local quick_check=$3
    
    log "INFO" "Starting database verification for ${env} environment at ${host}"
    
    # Read database configuration
    local db_config=$(read_db_config "$env")
    local config_host=$(echo "$db_config" | cut -d'|' -f1)
    local port=$(echo "$db_config" | cut -d'|' -f2)
    local dbname=$(echo "$db_config" | cut -d'|' -f3)
    local admin_user=$(echo "$db_config" | cut -d'|' -f4)
    local admin_password=$(echo "$db_config" | cut -d'|' -f5)
    
    # Use specified host if provided
    if [[ -z "$host" ]]; then
        host="$config_host"
    fi
    
    # Always check connectivity first
    if ! check_db_connectivity "$host" "$port" "$dbname" "$admin_user" "$admin_password"; then
        log_dr_event "DB_VERIFY" "$env" "$host" "FAILURE"
        echo "ERROR: Database connectivity check failed."
        return 1
    fi
    
    # If quick check requested, exit after connectivity check
    if [ "$quick_check" = "true" ]; then
        log "INFO" "Quick check successful"
        log_dr_event "DB_VERIFY" "$env" "$host" "SUCCESS"
        echo "Database quick verification passed."
        return 0
    fi
    
    # Track overall status
    local verification_status=0
    
    # Perform full verification
    check_db_version "$host" "$port" "$dbname" "$admin_user" "$admin_password" || verification_status=1
    check_db_tables "$host" "$port" "$dbname" "$admin_user" "$admin_password" || verification_status=1
    check_db_size "$host" "$port" "$dbname" "$admin_user" "$admin_password" || verification_status=1
    check_db_replication "$host" "$port" "$dbname" "$admin_user" "$admin_password" || verification_status=1
    
    # Final status
    if [ $verification_status -eq 0 ]; then
        log "INFO" "Database verification completed successfully"
        log_dr_event "DB_VERIFY" "$env" "$host" "SUCCESS"
        echo "Database verification passed."
        return 0
    else
        log "ERROR" "Database verification failed with errors"
        log_dr_event "DB_VERIFY" "$env" "$host" "FAILURE"
        echo "ERROR: Database verification failed."
        return 1
    fi
}

# Function to check host reachability
check_host_reachable() {
    local host=$1
    local port=$2
    
    log "INFO" "Checking if $host:$port is reachable..."
    
    if nc -z -w 5 "$host" "$port" 2>/dev/null; then
        log "INFO" "$host:$port is reachable"
        return 0
    else
        log "ERROR" "$host:$port is not reachable"
        return 1
    fi
}

# Function to check replication health between primary and secondary
check_replication_health() {
    local env=$1
    local primary_host=""
    local secondary_host=""
    local lag_threshold=$2
    
    if [[ -n "$lag_threshold" ]]; then
        REPLICATION_LAG_THRESHOLD=$lag_threshold
    fi
    
    # Read database configuration
    local db_config=$(read_db_config "$env")
    local port=$(echo "$db_config" | cut -d'|' -f2)
    local dbname=$(echo "$db_config" | cut -d'|' -f3)
    local admin_user=$(echo "$db_config" | cut -d'|' -f4)
    local admin_password=$(echo "$db_config" | cut -d'|' -f5)
    
    # Get replication hosts from environment file
    local repl_hosts=$(get_replication_hosts "$env")
    primary_host=$(echo "$repl_hosts" | cut -d'|' -f1)
    secondary_host=$(echo "$repl_hosts" | cut -d'|' -f2)
    
    log "INFO" "Starting comprehensive replication health check for ${env} environment"
    log "INFO" "Primary host: $primary_host, Secondary host: $secondary_host"
    
    # Track statuses
    local primary_ok=true
    local secondary_ok=true
    local lag_ok=true
    local slots_ok=true
    local connections_ok=true
    local exit_status=0
    
    # Check primary connectivity
    if ! check_host_reachable "$primary_host" "$port"; then
        log "ERROR" "Primary database server is not reachable"
        primary_ok=false
        exit_status=1
    else
        # Check if primary is in primary mode (not in recovery)
        export PGPASSWORD="$admin_password"
        IS_PRIMARY=$(psql -h "$primary_host" -p "$port" -U "$admin_user" -d "$dbname" -c "SELECT pg_is_in_recovery() = false;" -q -t 2>/dev/null | tr -d ' ')
        unset PGPASSWORD
        
        if [ "$IS_PRIMARY" = "t" ]; then
            log "INFO" "Primary server is running in primary mode"
        else
            log "ERROR" "Primary server is not in primary mode (it might be in recovery)"
            primary_ok=false
            exit_status=1
        fi
    fi
    
    # Check secondary connectivity
    if ! check_host_reachable "$secondary_host" "$port"; then
        log "ERROR" "Secondary database server is not reachable"
        secondary_ok=false
        exit_status=1
    else
        # Check if secondary is in replica mode (in recovery)
        export PGPASSWORD="$admin_password"
        IS_REPLICA=$(psql -h "$secondary_host" -p "$port" -U "$admin_user" -d "$dbname" -c "SELECT pg_is_in_recovery();" -q -t 2>/dev/null | tr -d ' ')
        unset PGPASSWORD
        
        if [ "$IS_REPLICA" = "t" ]; then
            log "INFO" "Secondary server is running in replica mode"
        else
            log "ERROR" "Secondary server is not in replica mode (it might be a standalone primary)"
            secondary_ok=false
            exit_status=1
        fi
    fi
    
    # Only continue with more detailed checks if both servers are reachable
    if [ "$primary_ok" = true ] && [ "$secondary_ok" = true ]; then
        # Check replication lag
        export PGPASSWORD="$admin_password"
        LAG_SECONDS=$(psql -h "$secondary_host" -p "$port" -U "$admin_user" -d "$dbname" -c "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" -q -t 2>/dev/null | tr -d ' ')
        unset PGPASSWORD
        
        if [ -z "$LAG_SECONDS" ]; then
            log "ERROR" "Could not determine replication lag"
            lag_ok=false
            exit_status=1
        elif (( $(echo "$LAG_SECONDS < $REPLICATION_LAG_THRESHOLD" | bc -l) )); then
            log "INFO" "Replication lag is ${LAG_SECONDS} seconds (within threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
        else
            log "ERROR" "Replication lag is ${LAG_SECONDS} seconds (exceeds threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
            lag_ok=false
            exit_status=1
        fi
        
        # Check replication slots
        export PGPASSWORD="$admin_password"
        ACTIVE_SLOTS=$(psql -h "$primary_host" -p "$port" -U "$admin_user" -d "$dbname" -c "SELECT count(*) FROM pg_replication_slots WHERE active = true;" -q -t 2>/dev/null | tr -d ' ')
        unset PGPASSWORD
        
        if [ -z "$ACTIVE_SLOTS" ]; then
            log "ERROR" "Could not query replication slots"
            slots_ok=false
            exit_status=1
        elif [ "$ACTIVE_SLOTS" -gt 0 ]; then
            log "INFO" "Found $ACTIVE_SLOTS active replication slots on primary"
        else
            log "ERROR" "No active replication slots found on primary"
            slots_ok=false
            exit_status=1
        fi
        
        # Check replication connections
        export PGPASSWORD="$admin_password"
        REPLICATION_COUNT=$(psql -h "$primary_host" -p "$port" -U "$admin_user" -d "$dbname" -c "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming';" -q -t 2>/dev/null | tr -d ' ')
        unset PGPASSWORD
        
        if [ -z "$REPLICATION_COUNT" ]; then
            log "ERROR" "Could not query replication connections"
            connections_ok=false
            exit_status=1
        elif [ "$REPLICATION_COUNT" -gt 0 ]; then
            log "INFO" "Found $REPLICATION_COUNT active streaming replication connections"
        else
            log "ERROR" "No active streaming replication connections found"
            connections_ok=false
            exit_status=1
        fi
    fi
    
    # Determine overall status
    if [ "$primary_ok" = true ] && [ "$secondary_ok" = true ] && [ "$lag_ok" = true ] && [ "$slots_ok" = true ] && [ "$connections_ok" = true ]; then
        log "INFO" "Replication health check: OK"
        log_dr_event "REPLICATION_CHECK" "$env" "all" "HEALTHY"
        echo "Replication status: HEALTHY"
    else
        log "ERROR" "Replication health check: FAILED"
        # Summarize issues
        if [ "$primary_ok" = false ]; then
            log "ERROR" "- Primary server issue detected"
        fi
        if [ "$secondary_ok" = false ]; then
            log "ERROR" "- Secondary server issue detected"
        fi
        if [ "$lag_ok" = false ]; then
            log "ERROR" "- Replication lag exceeds threshold"
        fi
        if [ "$slots_ok" = false ]; then
            log "ERROR" "- Replication slot issue detected"
        fi
        if [ "$connections_ok" = false ]; then
            log "ERROR" "- Replication connection issue detected"
        fi
        log_dr_event "REPLICATION_CHECK" "$env" "all" "UNHEALTHY"
        echo "Replication status: UNHEALTHY"
    fi
    
    return $exit_status
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
DB_HOST=""
QUICK_CHECK="false"
LAG_THRESHOLD=""

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
        --host)
            DB_HOST="$2"
            shift 2
            ;;
        --quick-check)
            QUICK_CHECK="true"
            shift
            ;;
        --threshold)
            LAG_THRESHOLD="$2"
            shift 2
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
if [[ "$COMMAND" == "backup" || "$COMMAND" == "restore" || "$COMMAND" == "seed" || "$COMMAND" == "rotate" || "$COMMAND" == "check-replication" || "$COMMAND" == "verify-db" ]]; then
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
    verify-db)
        verify_database "$ENV" "$DB_HOST" "$QUICK_CHECK"
        ;;
    check-replication)
        check_replication_health "$ENV" "$LAG_THRESHOLD"
        ;;
    *)
        log "ERROR" "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac

exit $?