#!/bin/bash
# ==============================================================================
# Database Optimization Script for Cloud Infrastructure Platform
# ==============================================================================
# This script performs comprehensive PostgreSQL database optimization tasks:
# - Runs VACUUM ANALYZE to reclaim space and update statistics
# - Rebuilds indexes to reduce fragmentation
# - Optimizes table storage parameters
# - Analyzes and recommends PostgreSQL configuration based on system resources
# - Provides comprehensive optimization recommendations
# ==============================================================================

set -eo pipefail

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
TEMP_FILES=""

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || {
    echo "Warning: Could not create log directory. Using /tmp for logs."
    LOG_FILE="/tmp/db-optimize-$(date +%Y%m%d).log"
}
touch "$LOG_FILE" 2>/dev/null || {
    echo "Warning: Could not write to log file. Logs will only appear in console."
    LOG_FILE="/dev/null"
}

# Cleanup function
cleanup() {
    # Remove any temporary files
    if [[ -n "$TEMP_FILES" ]]; then
        for file in $TEMP_FILES; do
            [[ -f "$file" ]] && rm -f "$file"
        done
    fi
}

# Set up trap for cleanup
trap cleanup EXIT INT TERM

# Function to log messages
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    if [[ "$SILENT" != "true" ]]; then
        echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"

        # If verbose and there's a details parameter, log it
        if [[ "$VERBOSE" == "true" && -n "$3" ]]; then
            echo "  $3" | tee -a "$LOG_FILE"
        fi
    else
        # In silent mode, only write to log file
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
        if [[ "$VERBOSE" == "true" && -n "$3" ]]; then
            echo "  $3" >> "$LOG_FILE"
        fi
    fi
}

# Function to handle errors
handle_error() {
    local error_msg="$1"
    log "ERROR" "$error_msg"
    exit 1
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
  --silent                Suppress console output (logs still written to file)
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
    log "INFO" "Loading database configuration for environment: $env"

    # Try the database-manager.sh script first
    local db_manager="${SCRIPT_DIR}/database-manager.sh"
    if [[ -x "$db_manager" ]]; then
        log "INFO" "Loading database configuration from database-manager.sh"

        # Try to get config from database-manager.sh
        local db_config
        db_config=$("$db_manager" get-config --env "$env" 2>/dev/null)
        if [[ $? -eq 0 && -n "$db_config" ]]; then
            DB_HOST=$(echo "$db_config" | cut -d'|' -f1)
            DB_PORT=$(echo "$db_config" | cut -d'|' -f2)
            DB_NAME=$(echo "$db_config" | cut -d'|' -f3)
            DB_USER=$(echo "$db_config" | cut -d'|' -f4)
            DB_PASSWORD=$(echo "$db_config" | cut -d'|' -f5)
            log "INFO" "Database configuration loaded from database-manager.sh"
            return 0
        fi
    fi

    # Try to load from core module if available
    if [[ -f "${PROJECT_ROOT}/scripts/core/common.sh" ]]; then
        # shellcheck source=/dev/null
        source "${PROJECT_ROOT}/scripts/core/common.sh"
        if type -t "get_database_credentials" &>/dev/null; then
            log "INFO" "Using core module to load database configuration"
            local db_creds
            if db_creds=$(get_database_credentials "$env"); then
                DB_HOST=$(echo "$db_creds" | cut -d'|' -f1)
                DB_PORT=$(echo "$db_creds" | cut -d'|' -f2)
                DB_NAME=$(echo "$db_creds" | cut -d'|' -f3)
                DB_USER=$(echo "$db_creds" | cut -d'|' -f4)
                DB_PASSWORD=$(echo "$db_creds" | cut -d'|' -f5)
                log "INFO" "Database configuration loaded from core module"
                return 0
            fi
        fi
    fi

    # Fall back to environment file if database-manager.sh didn't work
    local env_file="${PROJECT_ROOT}/deployment/environments/${env}.env"
    if [[ -f "$env_file" ]]; then
        log "INFO" "Loading database configuration from $env_file"
        # shellcheck source=/dev/null
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
        DB_HOST=$(awk -F "=" "/^\\[$env\\]/,/^\\[.*\\]/ {if (\$1 ~ /^host/) print \$2}" "$db_config" | tr -d ' ')
        DB_PORT=$(awk -F "=" "/^\\[$env\\]/,/^\\[.*\\]/ {if (\$1 ~ /^port/) print \$2}" "$db_config" | tr -d ' ')
        DB_NAME=$(awk -F "=" "/^\\[$env\\]/,/^\\[.*\\]/ {if (\$1 ~ /^database/) print \$2}" "$db_config" | tr -d ' ')
        DB_USER=$(awk -F "=" "/^\\[$env\\]/,/^\\[.*\\]/ {if (\$1 ~ /^username/) print \$2}" "$db_config" | tr -d ' ')
        DB_PASSWORD=$(awk -F "=" "/^\\[$env\\]/,/^\\[.*\\]/ {if (\$1 ~ /^password/) print \$2}" "$db_config" | tr -d ' ')

        # Set defaults if any values are empty
        DB_HOST="${DB_HOST:-localhost}"
        DB_PORT="${DB_PORT:-5432}"
        DB_NAME="${DB_NAME:-cloud_platform_${env}}"
        DB_USER="${DB_USER:-postgres}"

        log "INFO" "Database configuration loaded from config file"
        return 0
    fi

    handle_error "Could not load database configuration for environment: $env"
    return 1
}

# Function to execute database queries and return results
run_query() {
    local query="$1"
    local timeout="${2:-60}"  # Default timeout is 60 seconds
    local retry_allowed="${3:-true}"
    local max_retries=3
    local attempt=1
    local output
    local exit_code

    if [[ "$VERBOSE" == "true" ]]; then
        log "DEBUG" "Running query (attempt $attempt/$max_retries): ${query:0:100}${query:100:+...}"
    fi

    # Create a secure password file for this connection
    local pgpass_file
    pgpass_file=$(mktemp)
    chmod 600 "$pgpass_file"
    echo "$DB_HOST:$DB_PORT:$DB_NAME:$DB_USER:$DB_PASSWORD" > "$pgpass_file"
    TEMP_FILES="$TEMP_FILES $pgpass_file"

    # Set timeout command if available
    local timeout_cmd=""
    if command -v timeout >/dev/null; then
        timeout_cmd="timeout $timeout"
    fi

    # Run the query with PGPASSFILE environment variable
    if ! output=$(PGPASSFILE="$pgpass_file" $timeout_cmd psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$query" -t -A 2>/dev/null); then
        rm -f "$pgpass_file"  # Remove temp file immediately after use

        log "ERROR" "Query execution failed: ${query:0:100}${query:100:+...}"

        if [[ "$retry_allowed" == "true" && $attempt -lt $max_retries ]]; then
            attempt=$((attempt+1))
            log "INFO" "Retrying in 3 seconds... (attempt $attempt/$max_retries)"
            sleep 3
            run_query "$query" "$timeout" "$retry_allowed"
            return $?
        fi

        return 1
    fi

    # Remove temp file immediately after use
    rm -f "$pgpass_file"

    echo "$output"
    return 0
}

# Function to check database connection
check_connection() {
    log "INFO" "Testing connection to database ${DB_HOST}:${DB_PORT}/${DB_NAME}"

    if ! command -v psql >/dev/null; then
        handle_error "PostgreSQL client (psql) not installed"
    fi

    if run_query "SELECT 1" 10; then
        log "INFO" "Successfully connected to database"
        return 0
    else
        handle_error "Failed to connect to database. Check connection details."
    fi
}

# Function to check if we're in maintenance window
check_maintenance_window() {
    if [[ "$MAINTENANCE_WINDOW" != "true" ]]; then
        return 0  # Not using maintenance window, always proceed
    fi

    if [[ -z "$START_TIME" || -z "$END_TIME" ]]; then
        handle_error "Maintenance window specified but start/end times are missing"
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
        AND pg_relation_size(i.indexrelid) > 8192
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
        JOIN pg_index ON pg_stat_user_indexes.indexrelid = pg_index.indexrelid
        WHERE pg_relation_size(indexrelid) > 10 * 8192
        AND idx_scan > 0
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

            # Try REINDEX CONCURRENTLY first (PostgreSQL 12+)
            if run_query "REINDEX INDEX CONCURRENTLY $index_name" 1200 "false"; then
                log "INFO" "Successfully rebuilt index $index_name with REINDEX CONCURRENTLY"
            else
                # Fall back to standard REINDEX
                log "INFO" "Falling back to standard REINDEX for $index_name"
                if ! run_query "REINDEX INDEX $index_name" 600; then
                    log "ERROR" "Failed to rebuild index $index_name"
                else
                    log "INFO" "Successfully rebuilt index $index_name"
                fi
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
    echo "# max_parallel_workers = $cpu_count  # Based on CPU count" >> "$config_file"
    echo "# max_parallel_workers_per_gather = $((cpu_count / 2))  # Based on CPU count" >> "$config_file"

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
                TEMP_FILES="$TEMP_FILES $2"
                shift 2
            else
                handle_error "Password file not found: $2"
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
        --silent)
            SILENT=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            handle_error "Unknown option: $1"
            ;;
    esac
done

# Validate environment
valid_env=false
for env in "production" "staging" "development" "ci" "demo"; do
    if [[ "$ENV" == "$env" ]]; then
        valid_env=true
        break
    fi
done

if [[ "$valid_env" == "false" ]]; then
    handle_error "Invalid environment: $ENV. Must be one of: production, staging, development, ci, demo"
fi

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

# Check if PostgreSQL configuration should be analyzed
if [[ "$OPTIMIZE_CONFIG" == "true" ]]; then
    analyze_postgresql_config
fi

# Operations that require confirmation
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

        # Build command with proper security practices
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
            local temp_pw_file=$(mktemp)
            echo "$DB_PASSWORD" > "$temp_pw_file"
            chmod 600 "$temp_pw_file"
            cmd+=" --password-file $temp_pw_file"
            TEMP_FILES="$TEMP_FILES $temp_pw_file"
        fi

        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would run add_indexes.sh to optimize database indexes"
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
