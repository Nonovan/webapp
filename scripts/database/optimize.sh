#!/bin/bash
# ==============================================================================
# Database Optimization Script for Cloud Infrastructure Platform
# ==============================================================================
# This script performs comprehensive PostgreSQL database optimization tasks:
# - Runs VACUUM ANALYZE to reclaim space and update statistics
# - Rebuilds indexes to reduce fragmentation
# - Optimizes table storage parameters
# - Updates PostgreSQL configuration based on system resources
# - Provides recommendations for further optimizations
# ==============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${PROJECT_ROOT}/config"
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/db-optimize-$(date +%Y%m%d).log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ENV="production"
DB_HOST=""
DB_PORT=""
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
DRY_RUN=true
VERBOSE=false
FORCE=false
FULL_VACUUM=false
REINDEX=false
ANALYZE_ONLY=false
OPTIMIZE_CONFIG=false
OPTIMIZE_STORAGE=false
ADD_INDEXES=false
MAX_RUNTIME=3600  # Maximum runtime in seconds (1 hour default)
MAINTENANCE_WINDOW=false
START_TIME=""
END_TIME=""

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Function to log messages
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    # If verbose and there's a details parameter, log it
    if [[ "$VERBOSE" == "true" && -n "$3" ]]; then
        echo "  $3" | tee -a "$LOG_FILE"
    fi
}

# Display usage information
usage() {
    cat << EOF
Database Optimization Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --env ENV               Environment (development, staging, production) (default: production)
  --host HOST             Database host (overrides config)
  --port PORT             Database port (overrides config)
  --dbname NAME           Database name (overrides config)
  --user USER             Database user (overrides config)
  --password PASS         Database password (overrides config)
  --password-file FILE    File containing database password
  --full-vacuum           Run VACUUM FULL (more thorough but locks tables)
  --reindex               Rebuild all indexes to reduce fragmentation
  --analyze-only          Only collect statistics without optimization
  --optimize-config       Generate PostgreSQL configuration recommendations
  --optimize-storage      Optimize table storage parameters
  --add-indexes           Run the add_indexes.sh script to optimize indexes
  --maintenance-window    Specify a maintenance window for operations
  --start-time TIME       Start time for maintenance window (HH:MM format)
  --end-time TIME         End time for maintenance window (HH:MM format)
  --apply                 Apply recommended changes (default is dry run)
  --force                 Skip confirmation prompts
  --verbose               Show detailed output
  --help                  Display this help message

Examples:
  $(basename "$0") --analyze-only --env production
  $(basename "$0") --full-vacuum --reindex --apply --env staging
  $(basename "$0") --optimize-config --verbose
  $(basename "$0") --maintenance-window --start-time 01:00 --end-time 05:00 --apply
EOF
}

# Function to load config from database-manager.sh
load_db_config() {
    local env="$1"
    local db_manager="${SCRIPT_DIR}/database-manager.sh"
    
    if [[ -x "$db_manager" ]]; then
        log "INFO" "Loading database configuration from database-manager.sh"
        
        # Try to get config from database-manager.sh
        local db_config=$("$db_manager" get-config --env "$env" 2>/dev/null)
        if [[ $? -eq 0 && -n "$db_config" ]]; then
            DB_HOST=$(echo "$db_config" | cut -d'|' -f1)
            DB_PORT=$(echo "$db_config" | cut -d'|' -f2)
            DB_NAME=$(echo "$db_config" | cut -d'|' -f3)
            DB_USER=$(echo "$db_config" | cut -d'|' -f4)
            DB_PASSWORD=$(echo "$db_config" | cut -d'|' -f5)
            log "INFO" "Database configuration loaded for $ENV environment"
            return 0
        fi
    fi

    # Fall back to environment file if database-manager.sh didn't work
    local env_file="${PROJECT_ROOT}/deployment/environments/${env}.env"
    if [[ -f "$env_file" ]]; then
        log "INFO" "Loading database configuration from $env_file"
        source "$env_file"
        
        DB_HOST="${DB_HOST:-${PRIMARY_DB_HOST:-localhost}}"
        DB_PORT="${DB_PORT:-${PRIMARY_DB_PORT:-5432}}"
        DB_NAME="${DB_NAME:-${DATABASE_NAME:-cloud_platform_${env}}}"
        DB_USER="${DB_USER:-${DATABASE_USER:-postgres}}"
        DB_PASSWORD="${DB_PASSWORD:-${DATABASE_PASSWORD:-}}"
        
        log "INFO" "Database configuration loaded from environment file"
        return 0
    fi
    
    # Last resort: try config file
    local db_config="${CONFIG_DIR}/database.ini"
    if [[ -f "$db_config" ]]; then
        log "INFO" "Loading database configuration from $db_config"
        
        # Use awk to parse INI file for the environment section
        DB_HOST=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^host/) print \$2}" "$db_config" | tr -d ' ')
        DB_PORT=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^port/) print \$2}" "$db_config" | tr -d ' ')
        DB_NAME=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^database/) print \$2}" "$db_config" | tr -d ' ')
        DB_USER=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^username/) print \$2}" "$db_config" | tr -d ' ')
        DB_PASSWORD=$(awk -F "=" "/^\[$env\]/,/^\[.*\]/ {if (\$1 ~ /^password/) print \$2}" "$db_config" | tr -d ' ')
        
        # Set defaults if any values are empty
        DB_HOST="${DB_HOST:-localhost}"
        DB_PORT="${DB_PORT:-5432}"
        DB_NAME="${DB_NAME:-cloud_platform_${env}}"
        DB_USER="${DB_USER:-postgres}"
        
        log "INFO" "Database configuration loaded from config file"
        return 0
    fi
    
    log "ERROR" "Could not load database configuration"
    return 1
}

# Function to execute database queries and return results
run_query() {
    local query="$1"
    local timeout="${2:-60}"  # Default timeout is 60 seconds
    local output
    
    if ! output=$(PGPASSWORD="$DB_PASSWORD" timeout "$timeout" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$query" -t -A 2>/dev/null); then
        log "ERROR" "Query execution failed: $query"
        return 1
    fi
    
    echo "$output"
    return 0
}

# Function to check database connection
check_connection() {
    log "INFO" "Testing connection to database ${DB_HOST}:${DB_PORT}/${DB_NAME}"
    
    if ! command -v psql >/dev/null; then
        log "ERROR" "PostgreSQL client (psql) not installed"
        exit 1
    fi
    
    if run_query "SELECT 1" >/dev/null; then
        log "INFO" "Successfully connected to database"
    else
        log "ERROR" "Failed to connect to database. Check connection details."
        exit 1
    fi
}

# Function to check if we're in maintenance window
check_maintenance_window() {
    if [[ "$MAINTENANCE_WINDOW" != "true" ]]; then
        return 0  # Not using maintenance window, always proceed
    fi
    
    if [[ -z "$START_TIME" || -z "$END_TIME" ]]; then
        log "ERROR" "Maintenance window specified but start/end times are missing"
        return 1
    fi
    
    local current_time=$(date +%H:%M)
    
    # Convert times to minutes for easier comparison
    local current_minutes=$((10#${current_time%:*} * 60 + 10#${current_time#*:}))
    local start_minutes=$((10#${START_TIME%:*} * 60 + 10#${START_TIME#*:}))
    local end_minutes=$((10#${END_TIME%:*} * 60 + 10#${END_TIME#*:}))
    
    # Handle case where maintenance window crosses midnight
    if [[ $start_minutes -gt $end_minutes ]]; then
        if [[ $current_minutes -ge $start_minutes || $current_minutes -lt $end_minutes ]]; then
            log "INFO" "Current time $current_time is within maintenance window ($START_TIME-$END_TIME)"
            return 0
        else
            log "WARNING" "Current time $current_time is outside maintenance window ($START_TIME-$END_TIME)"
            return 1
        fi
    else
        if [[ $current_minutes -ge $start_minutes && $current_minutes -lt $end_minutes ]]; then
            log "INFO" "Current time $current_time is within maintenance window ($START_TIME-$END_TIME)"
            return 0
        else
            log "WARNING" "Current time $current_time is outside maintenance window ($START_TIME-$END_TIME)"
            return 1
        fi
    fi
}

# Function to get database statistics before optimization
get_database_stats() {
    log "INFO" "Collecting database statistics..."
    
    # Get database size
    local db_size=$(run_query "SELECT pg_size_pretty(pg_database_size('$DB_NAME'))")
    log "INFO" "Database size: $db_size"
    
    # Get largest tables
    log "INFO" "Top 10 largest tables:"
    local largest_tables=$(run_query "
        SELECT 
            n.nspname || '.' || c.relname AS table_name,
            pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
            pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
            pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) AS index_size
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r' 
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY pg_total_relation_size(c.oid) DESC
        LIMIT 10
    ")
    
    echo "$largest_tables" | while IFS='|' read -r table_name total_size table_size index_size; do
        if [[ -n "$table_name" ]]; then
            log "INFO" "- $table_name: $total_size (table: $table_size, indexes: $index_size)"
        fi
    done
    
    # Get tables that need vacuuming
    log "INFO" "Tables that need vacuuming:"
    local vacuum_needed=$(run_query "
        SELECT
            n.nspname || '.' || c.relname AS table_name,
            pg_size_pretty(pg_total_relation_size(c.oid)) AS size,
            c.reltuples::numeric AS row_estimate,
            ROUND(100 * n_dead_tup / NULLIF(reltuples, 0), 2) AS dead_tup_ratio
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_stat_user_tables s ON s.relid = c.oid
        WHERE c.relkind = 'r' 
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND c.reltuples > 1000
          AND n_dead_tup > 100
          AND ROUND(100 * n_dead_tup / NULLIF(reltuples, 0), 2) > 10
        ORDER BY n_dead_tup DESC
        LIMIT 10
    ")
    
    if [[ -z "$vacuum_needed" ]]; then
        log "INFO" "No tables with significant dead tuples found"
    else
        echo "$vacuum_needed" | while IFS='|' read -r table_name size row_estimate dead_ratio; do
            if [[ -n "$table_name" ]]; then
                log "INFO" "- $table_name: $dead_ratio% dead tuples (size: $size)"
            fi
        done
    fi
    
    # Get table bloat estimates
    log "INFO" "Tables with potential bloat:"
    local bloated_tables=$(run_query "
        WITH btbl AS (
            SELECT 
                n.nspname AS schema_name,
                c.relname AS table_name,
                c.reltuples::numeric AS row_estimate,
                c.relpages::numeric AS page_count,
                (c.relpages - pg_relation_size(c.oid)/(current_setting('block_size')::numeric)) as bloat_pages
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND c.reltuples > 1000
        )
        SELECT 
            schema_name || '.' || table_name AS full_table_name,
            pg_size_pretty(page_count * current_setting('block_size')::numeric) AS total_size,
            page_count,
            ROUND(100 * bloat_pages / NULLIF(page_count, 0), 2) AS bloat_ratio
        FROM btbl
        WHERE bloat_pages > 10 AND page_count > 10
        ORDER BY bloat_pages DESC
        LIMIT 10
    ")
    
    if [[ -z "$bloated_tables" ]]; then
        log "INFO" "No significantly bloated tables found"
    else
        echo "$bloated_tables" | while IFS='|' read -r table_name size page_count bloat_ratio; do
            if [[ -n "$table_name" ]]; then
                log "INFO" "- $table_name: $bloat_ratio% estimated bloat (size: $size)"
            fi
        done
    fi
    
    # Get index statistics
    log "INFO" "Index statistics:"
    
    # Get unused indexes
    local unused_indexes=$(run_query "
        SELECT
            s.schemaname || '.' || s.relname AS table_name,
            s.indexrelname AS index_name,
            pg_size_pretty(pg_relation_size(i.indexrelid)) AS index_size,
            s.idx_scan AS index_scans
        FROM pg_stat_user_indexes s
        JOIN pg_index i ON s.indexrelid = i.indexrelid
        WHERE s.idx_scan = 0
        AND NOT i.indisprimary
        AND NOT i.indisunique
        ORDER BY pg_relation_size(i.indexrelid) DESC
        LIMIT 10
    ")
    
    if [[ -z "$unused_indexes" ]]; then
        log "INFO" "No unused indexes found"
    else
        log "INFO" "Unused indexes that might be candidates for removal:"
        echo "$unused_indexes" | while IFS='|' read -r table_name index_name index_size index_scans; do
            if [[ -n "$table_name" ]]; then
                log "INFO" "- $index_name on $table_name: $index_size (0 scans)"
            fi
        done
    fi
    
    # Get fragmented indexes
    local fragmented_indexes=$(run_query "
        SELECT
            schemaname || '.' || tablename AS table_name,
            indexrelname AS index_name,
            pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
            idx_scan AS scans
        FROM pg_stat_user_indexes
        JOIN pg_index ON pg_stat_user_indexes.indexrelid = pg_index.indexrelid
        WHERE pg_relation_size(indexrelid) > 10 * 8192
        AND idx_scan > 0
        AND (indisprimary IS FALSE OR indisprimary IS NULL)
        ORDER BY pg_relation_size(indexrelid) DESC
        LIMIT 10
    ")
    
    if [[ -n "$fragmented_indexes" ]]; then
        log "INFO" "Potentially fragmented indexes:"
        echo "$fragmented_indexes" | while IFS='|' read -r table_name index_name index_size scans; do
            if [[ -n "$table_name" ]]; then
                log "INFO" "- $index_name on $table_name: $index_size ($scans scans)"
            fi
        done
    fi
}

# Function to run VACUUM
run_vacuum() {
    if ! check_maintenance_window; then
        log "INFO" "Skipping VACUUM - outside maintenance window"
        return 0
    fi
    
    if [[ "$FULL_VACUUM" == "true" ]]; then
        log "INFO" "Running VACUUM FULL ANALYZE on database"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would run VACUUM FULL ANALYZE on all tables"
            return 0
        fi
        
        # Warn user about VACUUM FULL
        if [[ "$FORCE" != "true" ]]; then
            echo
            echo "WARNING: VACUUM FULL will lock tables for the duration of the operation."
            echo "         This can cause downtime for your application."
            echo "To proceed, type 'VACUUM FULL' (all uppercase):"
            read -r confirmation
            
            if [[ "$confirmation" != "VACUUM FULL" ]]; then
                log "INFO" "VACUUM FULL operation cancelled by user"
                return 1
            fi
        fi
        
        # Get list of tables
        local tables=$(run_query "
            SELECT nspname || '.' || relname 
            FROM pg_class c
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE relkind = 'r'
              AND nspname NOT IN ('pg_catalog', 'information_schema')
              AND nspname NOT LIKE 'pg_toast%'
              AND c.relpages > 10
            ORDER BY c.relpages DESC
        ")
        
        # Vacuum each table separately for better progress tracking
        local total_tables=$(echo "$tables" | wc -l)
        local current=0
        
        echo "$tables" | while read -r table; do
            if [[ -n "$table" ]]; then
                ((current++))
                log "INFO" "[$current/$total_tables] Vacuuming $table..."
                
                if ! run_query "VACUUM FULL ANALYZE $table" 1800; then
                    log "ERROR" "Failed to vacuum $table"
                else
                    log "INFO" "Successfully vacuumed $table"
                fi
            fi
        done
    else
        log "INFO" "Running regular VACUUM ANALYZE on database"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would run VACUUM ANALYZE on all tables"
            return 0
        fi
        
        # Get tables with significant dead tuples first
        local priority_tables=$(run_query "
            SELECT n.nspname || '.' || c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_stat_user_tables s ON s.relid = c.oid
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND c.reltuples > 1000
              AND n_dead_tup > 100
              AND ROUND(100 * n_dead_tup / NULLIF(reltuples, 0), 2) > 10
            ORDER BY n_dead_tup DESC
        ")
        
        # Vacuum priority tables first
        if [[ -n "$priority_tables" ]]; then
            log "INFO" "Vacuuming tables with significant dead tuples first"
            echo "$priority_tables" | while read -r table; do
                if [[ -n "$table" ]]; then
                    log "INFO" "Vacuuming priority table $table..."
                    if ! run_query "VACUUM ANALYZE $table" 600; then
                        log "ERROR" "Failed to vacuum $table"
                    else
                        log "INFO" "Successfully vacuumed $table"
                    fi
                fi
            done
        fi
        
        # Run a general VACUUM ANALYZE on the database
        log "INFO" "Running VACUUM ANALYZE on entire database..."
        if ! run_query "VACUUM ANALYZE" 3600; then
            log "ERROR" "Failed to vacuum database"
            return 1
        else
            log "INFO" "Successfully vacuumed database"
        fi
    fi
    
    return 0
}

# Function to rebuild indexes
rebuild_indexes() {
    if ! check_maintenance_window; then
        log "INFO" "Skipping index rebuild - outside maintenance window"
        return 0
    fi
    
    log "INFO" "Rebuilding indexes to reduce fragmentation"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would rebuild fragmented indexes"
        return 0
    fi
    
    # Get list of fragmented indexes
    local fragmented_indexes=$(run_query "
        SELECT
            schemaname || '.' || indexrelname AS index_name,
            pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
        FROM pg_stat_user_indexes
        WHERE pg_relation_size(indexrelid) > 10 * 8192
        ORDER BY pg_relation_size(indexrelid) DESC
    ")
    
    if [[ -z "$fragmented_indexes" ]]; then
        log "INFO" "No significantly fragmented indexes found"
        return 0
    fi
    
    local total_indexes=$(echo "$fragmented_indexes" | wc -l)
    local current=0
    
    echo "$fragmented_indexes" | while IFS='|' read -r index_name index_size; do
        if [[ -n "$index_name" ]]; then
            ((current++))
            log "INFO" "[$current/$total_indexes] Rebuilding index $index_name ($index_size)..."
            
            if ! run_query "REINDEX INDEX $index_name" 600; then
                log "ERROR" "Failed to rebuild index $index_name"
            else
                log "INFO" "Successfully rebuilt index $index_name"
            fi
        fi
    done
    
    return 0
}

# Function to optimize table storage parameters
optimize_table_storage() {
    if ! check_maintenance_window; then
        log "INFO" "Skipping storage optimization - outside maintenance window"
        return 0
    fi
    
    log "INFO" "Optimizing table storage parameters"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would optimize table storage parameters"
        return 0
    fi
    
    # Get list of large tables with default fillfactor
    local large_tables=$(run_query "
        SELECT
            n.nspname || '.' || c.relname AS table_name,
            pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
            c.reltuples::bigint AS row_count,
            CASE WHEN reloptions IS NULL THEN 'default' 
                 ELSE reloptions::text END AS storage_params
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE c.relkind = 'r'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND pg_relation_size(c.oid) > 100 * 1024 * 1024  -- 100MB
        ORDER BY pg_relation_size(c.oid) DESC
        LIMIT 20
    ")
    
    if [[ -z "$large_tables" ]]; then
        log "INFO" "No large tables found for storage optimization"
        return 0
    fi
    
    echo "$large_tables" | while IFS='|' read -r table_name table_size row_count storage_params; do
        if [[ -n "$table_name" ]]; then
            log "INFO" "Analyzing storage parameters for $table_name ($table_size)..."
            
            # Check for excessive updates/deletes
            local update_stats=$(run_query "
                SELECT 
                    n_tup_upd AS updates,
                    n_tup_del AS deletes,
                    n_tup_ins AS inserts,
                    CASE WHEN n_tup_ins = 0 THEN 0 
                         ELSE ROUND(100.0 * (n_tup_upd + n_tup_del) / n_tup_ins, 2) END AS write_ratio
                FROM pg_stat_user_tables
                WHERE schemaname || '.' || relname = '$table_name'
            ")
            
            if [[ -n "$update_stats" ]]; then
                IFS='|' read -r updates deletes inserts write_ratio <<< "$update_stats"
                
                # Determine fillfactor based on update/delete patterns
                if (( $(echo "$write_ratio > 50" | bc -l) )); then
                    # High update/delete ratio - use lower fillfactor
                    log "INFO" "Table $table_name has high update/delete activity (ratio: $write_ratio)"
                    log "INFO" "Setting fillfactor=70 and custom autovacuum parameters"
                    
                    if ! run_query "ALTER TABLE $table_name SET (fillfactor=70, autovacuum_analyze_threshold=50)" 60; then
                        log "ERROR" "Failed to set storage parameters for $table_name"
                    else
                        log "INFO" "Successfully set storage parameters for $table_name"
                    fi
                elif [[ "$storage_params" == "default" ]]; then
                    # Standard table with default params
                    if (( $(echo "$row_count > 1000000" | bc -l) )); then
                        # Large table - optimize autovacuum
                        log "INFO" "Large table $table_name with $row_count rows"
                        log "INFO" "Setting custom autovacuum parameters for large table"
                        
                        if ! run_query "ALTER TABLE $table_name SET (autovacuum_vacuum_scale_factor=0.01, autovacuum_analyze_scale_factor=0.005)" 60; then
                            log "ERROR" "Failed to set autovacuum parameters for $table_name"
                        else
                            log "INFO" "Successfully set autovacuum parameters for $table_name"
                        fi
                    fi
                fi
            fi
        fi
    done
    
    return 0
}

# Function to check if PostgreSQL configuration is optimized
analyze_postgresql_config() {
    log "INFO" "Analyzing PostgreSQL configuration"
    
    # Get system information
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}') # in KB
    mem_total=$((mem_total / 1024))  # Convert to MB
    
    local cpu_count=$(nproc)
    
    # Get current PostgreSQL configuration
    local current_config=$(run_query "
        SELECT name, setting, unit
        FROM pg_settings
        WHERE name IN (
            'shared_buffers', 'work_mem', 'maintenance_work_mem', 
            'effective_cache_size', 'wal_buffers', 'checkpoint_timeout',
            'max_connections', 'random_page_cost', 'effective_io_concurrency',
            'max_wal_size', 'checkpoint_completion_target'
        )
    ")
    
    # Calculate recommended values
    local shared_buffers=$((mem_total / 4))  # 25% of RAM
    local effective_cache_size=$((mem_total * 3 / 4))  # 75% of RAM
    local work_mem=$((mem_total / cpu_count / 4))  # RAM divided by max connections and 4
    
    if [[ $work_mem -gt 1024 ]]; then
        work_mem=1024  # Cap at 1GB
    fi
    
    local maintenance_work_mem=$((mem_total / 8))
    if [[ $maintenance_work_mem -gt 2048 ]]; then
        maintenance_work_mem=2048  # Cap at 2GB
    fi
    
    log "INFO" "System resources: $mem_total MB RAM, $cpu_count CPUs"
    log "INFO" "Recommended PostgreSQL settings:"
    log "INFO" "- shared_buffers = ${shared_buffers}MB (25% of RAM)"
    log "INFO" "- effective_cache_size = ${effective_cache_size}MB (75% of RAM)"
    log "INFO" "- work_mem = ${work_mem}MB (per connection/operation)"
    log "INFO" "- maintenance_work_mem = ${maintenance_work_mem}MB"
    log "INFO" "- wal_buffers = 16MB"
    log "INFO" "- checkpoint_timeout = 15min"
    log "INFO" "- max_wal_size = 2GB"
    log "INFO" "- random_page_cost = 1.1 (for SSD storage)"
    log "INFO" "- effective_io_concurrency = 200 (for SSD storage)"
    log "INFO" "- checkpoint_completion_target = 0.9"
    
    # Show current settings
    log "INFO" "Current PostgreSQL settings:"
    echo "$current_config" | while IFS='|' read -r name setting unit; do
        if [[ -n "$name" ]]; then
            log "INFO" "- $name = $setting $unit"
        fi
    done
    
    # Generate configuration file
    local config_file="${LOG_DIR}/postgresql_recommended_${TIMESTAMP}.conf"
    
    echo "# PostgreSQL recommended configuration for $ENV environment" > "$config_file"
    echo "# Generated on $(date)" >> "$config_file"
    echo "# Based on system with $mem_total MB RAM and $cpu_count CPUs" >> "$config_file"
    echo "" >> "$config_file"
    echo "# Memory settings" >> "$config_file"
    echo "shared_buffers = ${shared_buffers}MB" >> "$config_file"
    echo "effective_cache_size = ${effective_cache_size}MB" >> "$config_file"
    echo "work_mem = ${work_mem}MB" >> "$config_file"
    echo "maintenance_work_mem = ${maintenance_work_mem}MB" >> "$config_file"
    echo "wal_buffers = 16MB" >> "$config_file"
    echo "" >> "$config_file"
    echo "# Write settings" >> "$config_file"
    echo "checkpoint_timeout = 15min" >> "$config_file"
    echo "checkpoint_completion_target = 0.9" >> "$config_file"
    echo "max_wal_size = 2GB" >> "$config_file"
    echo "" >> "$config_file"
    echo "# Query planning" >> "$config_file"
    echo "random_page_cost = 1.1" >> "$config_file"
    echo "effective_io_concurrency = 200" >> "$config_file"
    echo "" >> "$config_file"
    echo "# Additional settings" >> "$config_file"
    echo "# max_connections = 100     # Adjust based on your application needs" >> "$config_file"
    echo "# max_parallel_workers_per_gather = $cpu_count  # Based on CPU count" >> "$config_file"
    
    log "INFO" "Recommended PostgreSQL configuration saved to $config_file"
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --env)
            ENV="$2"
            shift 2
            ;;
        --host)
            DB_HOST="$2"
            shift 2
            ;;
        --port)
            DB_PORT="$2"
            shift 2
            ;;
        --dbname)
            DB_NAME="$2"
            shift 2
            ;;
        --user)
            DB_USER="$2"
            shift 2
            ;;
        --password)
            DB_PASSWORD="$2"
            shift 2
            ;;
        --password-file)
            if [[ -f "$2" ]]; then
                DB_PASSWORD=$(cat "$2")
                shift 2
            else
                log "ERROR" "Password file not found: $2"
                exit 1
            fi
            ;;
        --full-vacuum)
            FULL_VACUUM=true
            shift
            ;;
        --reindex)
            REINDEX=true
            shift
            ;;
        --analyze-only)
            ANALYZE_ONLY=true
            shift
            ;;
        --optimize-config)
            OPTIMIZE_CONFIG=true
            shift
            ;;
        --optimize-storage)
            OPTIMIZE_STORAGE=true
            shift
            ;;
        --add-indexes)
            ADD_INDEXES=true
            shift
            ;;
        --maintenance-window)
            MAINTENANCE_WINDOW=true
            shift
            ;;
        --start-time)
            START_TIME="$2"
            shift 2
            ;;
        --end-time)
            END_TIME="$2"
            shift 2
            ;;
        --apply)
            DRY_RUN=false
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# If no specific action is selected, default to analyze-only
if [[ "$FULL_VACUUM" == "false" && "$REINDEX" == "false" && "$ANALYZE_ONLY" == "false" && 
      "$OPTIMIZE_CONFIG" == "false" && "$OPTIMIZE_STORAGE" == "false" && "$ADD_INDEXES" == "false" ]]; then
    ANALYZE_ONLY=true
    log "INFO" "No specific action selected, defaulting to analyze-only mode"
fi

# Main execution
log "INFO" "Starting database optimization for ${ENV} environment"

# Load configuration
load_db_config "$ENV" || exit 1

# Check connection to database
check_connection || exit 1

# Get database statistics before optimization
get_database_stats

# If analyze-only, exit here
if [[ "$ANALYZE_ONLY" == "true" ]]; then
    log "INFO" "Analysis complete. Use specific options to perform optimization actions."
    exit 0
fi

# Perform optimization based on options
if [[ "$OPTIMIZE_CONFIG" == "true" ]]; then
    analyze_postgresql_config
fi

if [[ "$FULL_VACUUM" == "true" || "$REINDEX" == "true" || "$OPTIMIZE_STORAGE" == "true" ]]; then
    # Check if we should prompt before making changes
    if [[ "$DRY_RUN" == "false" && "$FORCE" != "true" ]]; then
        operations=""
        [[ "$FULL_VACUUM" == "true" ]] && operations+="VACUUM FULL, "
        [[ "$REINDEX" == "true" ]] && operations+="REINDEX, "
        [[ "$OPTIMIZE_STORAGE" == "true" ]] && operations+="storage optimization, "
        operations=${operations%, }
        
        echo
        echo "WARNING: This will perform $operations on database ${DB_NAME} in ${ENV} environment."
        echo "         These operations can be resource-intensive and may impact performance."
        echo "To proceed, type 'OPTIMIZE DATABASE' (all uppercase):"
        read -r confirmation
        
        if [[ "$confirmation" != "OPTIMIZE DATABASE" ]]; then
            log "INFO" "Optimization cancelled by user"
            exit 0
        fi
    fi
    
    # Run the optimization tasks
    if [[ "$FULL_VACUUM" == "true" ]]; then
        run_vacuum
    fi
    
    if [[ "$REINDEX" == "true" ]]; then
        rebuild_indexes
    fi
    
    if [[ "$OPTIMIZE_STORAGE" == "true" ]]; then
        optimize_table_storage
    fi
fi

# Run add_indexes.sh if requested
if [[ "$ADD_INDEXES" == "true" ]]; then
    if [[ -x "${SCRIPT_DIR}/add_indexes.sh" ]]; then
        log "INFO" "Running add_indexes.sh to optimize indexes"
        
        # Build command
        cmd="${SCRIPT_DIR}/add_indexes.sh --env $ENV"
        
        # Add other parameters
        [[ "$VERBOSE" == "true" ]] && cmd+=" --verbose"
        [[ "$DRY_RUN" == "false" ]] && cmd+=" --apply"
        [[ "$FORCE" == "true" ]] && cmd+=" --force"
        
        if [[ -n "$DB_HOST" ]]; then cmd+=" --host $DB_HOST"; fi
        if [[ -n "$DB_PORT" ]]; then cmd+=" --port $DB_PORT"; fi
        if [[ -n "$DB_NAME" ]]; then cmd+=" --dbname $DB_NAME"; fi
        if [[ -n "$DB_USER" ]]; then cmd+=" --user $DB_USER"; fi
        
        # Handle password securely
        if [[ -n "$DB_PASSWORD" ]]; then
            # Create a temporary password file instead of passing on command line
            temp_pw_file=$(mktemp)
            echo "$DB_PASSWORD" > "$temp_pw_file"
            cmd+=" --password-file $temp_pw_file"
            trap 'rm -f "$temp_pw_file"' EXIT
        fi
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would run: $cmd"
        else
            log "INFO" "Executing: add_indexes.sh to optimize database indexes"
            eval "$cmd"
            
            if [[ $? -ne 0 ]]; then
                log "ERROR" "add_indexes.sh execution failed"
            else
                log "INFO" "add_indexes.sh executed successfully"
            fi
        fi
    else
        log "ERROR" "add_indexes.sh not found or not executable"
    fi
fi

# Get database statistics after optimization if not in dry-run mode
if [[ "$DRY_RUN" == "false" ]]; then
    log "INFO" "Getting database statistics after optimization..."
    get_database_stats
fi

log "INFO" "Database optimization complete"

# Final summary
if [[ "$DRY_RUN" == "true" ]]; then
    log "INFO" "This was a dry run. No changes were made to the database."
    log "INFO" "To apply the recommended changes, run with --apply option."
fi

exit 0