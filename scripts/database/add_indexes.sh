#!/bin/bash
# ==============================================================================
# Database Index Management Script for Cloud Infrastructure Platform
# ==============================================================================
# This script analyzes the database and manages indexes to improve performance
# Functions:
# - Add recommended indexes based on query patterns
# - Remove unused indexes
# - Analyze index usage and performance
# - Generate index recommendations
# ==============================================================================

set -eo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${PROJECT_ROOT}/config"
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/db-indexes-$(date +%Y%m%d).log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ENV="production"
DB_HOST=""
DB_PORT=""
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
DRY_RUN=true
ANALYZE_ONLY=false
FORCE=false
VERBOSE=false
INDEX_SIZE_THRESHOLD=100  # In MB, indexes larger than this will be reviewed
MIN_INDEX_USAGE=10        # Minimum index usage percentage to keep
SILENT=false
EXIT_CODE=0
MAX_RETRIES=3
RETRY_DELAY=3

# Try to load common utilities
if [[ -f "${PROJECT_ROOT}/scripts/core/common.sh" ]]; then
    # shellcheck source=/dev/null
    source "${PROJECT_ROOT}/scripts/core/common.sh"
    CORE_COMMON_LOADED=true
else
    CORE_COMMON_LOADED=false
fi

# Ensure log directory exists
if [[ ! -d "$(dirname "$LOG_FILE")" ]]; then
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || {
        echo "Warning: Could not create log directory $(dirname "$LOG_FILE")"
        LOG_FILE="/tmp/db-indexes-$(date +%Y%m%d).log"
    }
fi
touch "$LOG_FILE" 2>/dev/null || {
    echo "Warning: Could not write to log file $LOG_FILE"
    LOG_FILE="/dev/null"
}

# Function to log messages
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    # Use core logging if available
    if [[ "$CORE_COMMON_LOADED" == "true" ]] && type -t "log_message" &>/dev/null; then
        log_message "$level" "$message" "add_indexes" "database"
    else
        # Fall back to basic logging
        if [[ "$SILENT" != "true" ]]; then
            echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"

            # If verbose and there's a details parameter, log it
            if [[ "$VERBOSE" == "true" && -n "$3" ]]; then
                echo "  $3" | tee -a "$LOG_FILE"
            fi
        else
            # Only log to file in silent mode
            echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
            if [[ "$VERBOSE" == "true" && -n "$3" ]]; then
                echo "  $3" >> "$LOG_FILE"
            fi
        fi
    fi
}

# Function to handle errors
handle_error() {
    local message="$1"
    local exit_code="${2:-1}"

    # Use core error handling if available
    if [[ "$CORE_COMMON_LOADED" == "true" ]] && type -t "report_error" &>/dev/null; then
        report_error "DB_INDEX_ERROR" "$message" "$(basename "$0")" "ERROR"
    else
        log "ERROR" "$message"
    fi

    EXIT_CODE=$exit_code
    if [[ "$3" != "continue" ]]; then
        exit "$exit_code"
    fi
}

# Function to handle cleanup on exit
cleanup() {
    # Clean up any temporary files
    if [[ -n "$TEMP_FILES" ]]; then
        for file in $TEMP_FILES; do
            if [[ -f "$file" ]]; then
                rm -f "$file" 2>/dev/null
            fi
        done
    fi

    if [[ "$EXIT_CODE" -ne 0 ]]; then
        log "WARNING" "Script exited with errors (code $EXIT_CODE)"
    fi

    exit "$EXIT_CODE"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Display usage information
usage() {
    cat << EOF
Database Index Management Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --env ENV               Environment (development, staging, production) (default: production)
  --host HOST             Database host (overrides config)
  --port PORT             Database port (overrides config)
  --dbname NAME           Database name (overrides config)
  --user USER             Database user (overrides config)
  --password PASS         Database password (overrides config)
  --password-file FILE    File containing database password
  --analyze               Only analyze indexes without making changes
  --apply                 Apply recommended changes (default is dry run)
  --force                 Skip confirmation prompts
  --verbose               Show detailed output
  --silent                Suppress console output (logs still written to file)
  --max-retries N         Maximum number of retries for database operations (default: 3)
  --help                  Display this help message

Examples:
  $(basename "$0") --analyze --env production
  $(basename "$0") --apply --host db.example.com --dbname mydb
  $(basename "$0") --analyze --verbose
EOF
}

# Function to load config from database-manager.sh
load_db_config() {
    local env="$1"
    log "INFO" "Loading database configuration for environment: $env"

    # First try to load from core module if available
    if [[ "$CORE_COMMON_LOADED" == "true" ]] && type -t "get_database_credentials" &>/dev/null; then
        log "INFO" "Using core module to load database configuration"
        local db_creds
        if db_creds=$(get_database_credentials "$env"); then
            # Parse output format from core function
            DB_HOST=$(echo "$db_creds" | cut -d'|' -f1)
            DB_PORT=$(echo "$db_creds" | cut -d'|' -f2)
            DB_NAME=$(echo "$db_creds" | cut -d'|' -f3)
            DB_USER=$(echo "$db_creds" | cut -d'|' -f4)
            DB_PASSWORD=$(echo "$db_creds" | cut -d'|' -f5)
            log "INFO" "Database configuration loaded from core module"
            return 0
        fi
    fi

    # Next try database-manager.sh
    local db_manager="${SCRIPT_DIR}/database-manager.sh"
    if [[ -x "$db_manager" ]]; then
        log "INFO" "Loading database configuration from database-manager.sh"

        # Try to get config from database-manager.sh
        local db_config
        if db_config=$("$db_manager" get-config --env "$env" 2>/dev/null); then
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

# Function to execute database queries and return results with retries
run_query() {
    local query="$1"
    local timeout="${2:-30}" # Default timeout in seconds
    local attempt=1
    local output
    local exit_code
    local retry_allowed="${3:-true}"

    while [[ $attempt -le $MAX_RETRIES ]]; do
        if [[ "$VERBOSE" == "true" ]]; then
            log "DEBUG" "Running query (attempt $attempt/$MAX_RETRIES): ${query:0:100}${query:100:+...}"
        fi

        # Create a secure password file for this connection
        local pgpass_file
        pgpass_file=$(mktemp)
        TEMP_FILES="$TEMP_FILES $pgpass_file"
        chmod 600 "$pgpass_file"
        echo "$DB_HOST:$DB_PORT:$DB_NAME:$DB_USER:$DB_PASSWORD" > "$pgpass_file"

        # Set timeout
        local timeout_cmd=""
        if command -v timeout >/dev/null; then
            timeout_cmd="timeout $timeout"
        fi

        # Run the query with PGPASSFILE environment variable
        PGPASSFILE="$pgpass_file" $timeout_cmd psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -c "$query" -t -A 2>/dev/null
        exit_code=$?

        # Remove the temporary pgpass file immediately
        rm -f "$pgpass_file"

        if [[ $exit_code -eq 0 ]]; then
            # Query succeeded
            return 0
        else
            # Query failed, retry if allowed
            if [[ "$retry_allowed" == "true" && $attempt -lt $MAX_RETRIES ]]; then
                log "WARNING" "Query failed (attempt $attempt/$MAX_RETRIES), retrying in $RETRY_DELAY seconds..."
                sleep $RETRY_DELAY
                ((attempt++))
            else
                if [[ "$VERBOSE" == "true" ]]; then
                    log "ERROR" "Query execution failed after $attempt attempts: ${query:0:100}${query:100:+...}"
                else
                    log "ERROR" "Query execution failed after $attempt attempts"
                fi
                return 1
            fi
        fi
    done

    return 1
}

# Function to check database connection
check_connection() {
    log "INFO" "Testing connection to database ${DB_HOST}:${DB_PORT}/${DB_NAME}"

    # Check if psql client is available
    if ! command -v psql >/dev/null; then
        handle_error "PostgreSQL client (psql) not installed"
        exit 1
    fi

    # Test connection with a simple query
    if ! run_query "SELECT 1" 10; then
        handle_error "Failed to connect to database. Check connection details."
        exit 1
    fi

    # Get PostgreSQL version for logging
    local pg_version
    pg_version=$(run_query "SELECT version()" 10)
    log "INFO" "Successfully connected to PostgreSQL: ${pg_version:0:50}..."
}

# Check if pg_stat_statements extension is installed
check_pg_stat_statements() {
    log "INFO" "Checking for pg_stat_statements extension..."

    local result
    result=$(run_query "SELECT COUNT(*) FROM pg_extension WHERE extname = 'pg_stat_statements'")

    if [[ "$result" == "1" ]]; then
        log "INFO" "pg_stat_statements extension is installed"
        return 0
    else
        log "WARNING" "pg_stat_statements extension is not installed - some analysis functions will be limited"

        if [[ "$DRY_RUN" == "false" ]]; then
            log "INFO" "Attempting to install pg_stat_statements extension..."
            if run_query "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" 60; then
                log "INFO" "Successfully installed pg_stat_statements extension"
                return 0
            else
                log "ERROR" "Failed to install pg_stat_statements extension - continuing with limited functionality"
            fi
        fi

        return 1
    fi
}

# Get information about existing indexes
analyze_existing_indexes() {
    log "INFO" "Analyzing existing indexes..."

    # Get total indexes count
    local total_indexes
    total_indexes=$(run_query "SELECT COUNT(*) FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')")
    log "INFO" "Found $total_indexes existing indexes"

    # Get top 10 largest indexes
    log "INFO" "Top 10 largest indexes:"
    local largest_indexes
    largest_indexes=$(run_query "
        SELECT
            schemaname || '.' || tablename as table,
            indexname as index,
            pg_size_pretty(pg_relation_size(indexrelid)) as size,
            pg_relation_size(indexrelid) as size_bytes
        FROM pg_indexes, pg_stat_all_indexes
        WHERE pg_indexes.indexname = pg_stat_all_indexes.indexrelname
        AND schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        ORDER BY pg_relation_size(indexrelid) DESC
        LIMIT 10
    ")

    if [[ -n "$largest_indexes" ]]; then
        echo "$largest_indexes" | while IFS='|' read -r table index size size_bytes; do
            if [[ -n "$table" ]]; then
                log "INFO" "- $index on $table: $size"
            fi
        done
    else
        log "WARNING" "Could not retrieve largest indexes information"
    fi

    # Report potential unused indexes
    log "INFO" "Potentially unused indexes:"
    local unused_indexes
    unused_indexes=$(run_query "
        SELECT
            schemaname || '.' || tablename as table,
            indexname as index,
            pg_size_pretty(pg_relation_size(indexrelid)) as size,
            idx_scan as scans
        FROM pg_indexes, pg_stat_all_indexes
        WHERE pg_indexes.indexname = pg_stat_all_indexes.indexrelname
        AND schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        AND idx_scan < 50
        ORDER BY pg_relation_size(indexrelid) DESC
        LIMIT 10
    ")

    local unused_count=0
    if [[ -n "$unused_indexes" ]]; then
        echo "$unused_indexes" | while IFS='|' read -r table index size scans; do
            if [[ -n "$table" ]]; then
                log "INFO" "- $index on $table: $size (scans: $scans)"
                unused_count=$((unused_count+1))
            fi
        done
    fi

    if [[ $unused_count -eq 0 ]]; then
        log "INFO" "No potentially unused indexes found"
    fi

    # Check for redundant indexes (similar indexes on same columns)
    log "INFO" "Checking for redundant indexes..."

    local redundant_indexes
    redundant_indexes=$(run_query "
        SELECT
            array_agg(idx.indexrelid::regclass::text) as indexes,
            replace(split_part(idx.indkey::text, ' ', 1), ' ', '') as key_columns,
            schemaname || '.' || tablename as table
        FROM
            pg_index idx
        JOIN
            pg_stat_all_indexes stat ON idx.indexrelid = stat.indexrelid
        JOIN
            pg_indexes i ON stat.indexrelname = i.indexname
        WHERE
            schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        GROUP BY
            schemaname, tablename, split_part(idx.indkey::text, ' ', 1)
        HAVING
            COUNT(*) > 1
        ORDER BY
            schemaname, tablename
    ")

    local redundant_count=0
    if [[ -n "$redundant_indexes" ]]; then
        echo "$redundant_indexes" | while IFS='|' read -r indexes columns table; do
            if [[ -n "$table" ]]; then
                log "INFO" "Redundant indexes on $table: $indexes (columns: $columns)"
                redundant_count=$((redundant_count+1))
            fi
        done
    fi

    if [[ $redundant_count -eq 0 ]]; then
        log "INFO" "No redundant indexes found"
    fi
}

# Analyze query patterns and recommend indexes
analyze_query_patterns() {
    log "INFO" "Analyzing query patterns for index recommendations..."

    # Check if pg_stat_statements is available
    if ! run_query "SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'" >/dev/null; then
        log "WARNING" "Cannot analyze query patterns - pg_stat_statements extension not available"
        return 1
    fi

    # Reset pg_stat_statements to get fresh data (optional)
    if [[ "$DRY_RUN" == "false" ]]; then
        run_query "SELECT pg_stat_statements_reset()" >/dev/null
        log "INFO" "Reset pg_stat_statements for fresh analysis"
        log "INFO" "Waiting 10 seconds to collect query data..."
        sleep 10
    fi

    # Get most common WHERE clauses from pg_stat_statements
    log "INFO" "Analyzing most common WHERE clauses from query history..."

    local top_queries
    top_queries=$(run_query "
        SELECT
            substring(query from 1 for 100) as query_sample,
            calls,
            total_exec_time as total_time,
            rows,
            mean_exec_time as mean_time
        FROM pg_stat_statements
        WHERE query ILIKE '%WHERE%'
          AND query NOT ILIKE '%CREATE INDEX%'
          AND query NOT ILIKE '%pg_%'
        ORDER BY total_exec_time DESC
        LIMIT 20
    ")

    if [[ -z "$top_queries" ]]; then
        log "INFO" "No query data found. Run your application for a while to collect query statistics."
    else
        log "INFO" "Top 10 queries by execution time:"
        echo "$top_queries" | head -10 | while IFS='|' read -r query calls total_time rows mean_time; do
            if [[ -n "$query" ]]; then
                log "INFO" "- Query: ${query}... (calls: $calls, avg time: ${mean_time}ms)"
            fi
        done
    fi

    # Extract tables and columns from WHERE clauses
    log "INFO" "Extracting WHERE clause patterns..."

    local where_patterns
    where_patterns=$(run_query "
        SELECT
            regexp_matches(query, 'FROM\\s+([a-zA-Z0-9_\\.]+).*?WHERE\\s+([a-zA-Z0-9_\\.]+)\\s*[=<>]', 'gi') as pattern,
            count(*) as frequency,
            sum(total_exec_time) as total_time
        FROM pg_stat_statements
        WHERE query ILIKE '%WHERE%'
          AND query NOT ILIKE '%CREATE INDEX%'
        GROUP BY pattern
        ORDER BY sum(total_exec_time) DESC
        LIMIT 10
    ")

    if [[ -z "$where_patterns" || "$where_patterns" == "0" ]]; then
        log "INFO" "No common WHERE clause patterns found"
    else
        log "INFO" "Common WHERE clause patterns (potential index candidates):"
        echo "$where_patterns" | while IFS='|' read -r pattern frequency total_time; do
            if [[ -n "$pattern" && "$pattern" != "{" && "$pattern" != "}" ]]; then
                # Extract table and column from pattern
                pattern=$(echo "$pattern" | tr -d '{}')
                table=$(echo "$pattern" | cut -d, -f1 | tr -d '"')
                column=$(echo "$pattern" | cut -d, -f2 | tr -d '"')

                log "INFO" "- Table: $table, Column: $column (freq: $frequency, total time: ${total_time}ms)"
            fi
        done
    fi

    # Analyze JOIN patterns
    log "INFO" "Analyzing JOIN patterns..."

    local join_patterns
    join_patterns=$(run_query "
        SELECT
            regexp_matches(query, 'JOIN\\s+([a-zA-Z0-9_\\.]+)\\s+(?:\\w+\\s+)?ON\\s+\\w+\\.([a-zA-Z0-9_]+)\\s*=\\s*\\w+\\.([a-zA-Z0-9_]+)', 'gi') as pattern,
            count(*) as frequency,
            sum(total_exec_time) as total_time
        FROM pg_stat_statements
        WHERE query ILIKE '%JOIN%ON%'
        GROUP BY pattern
        ORDER BY sum(total_exec_time) DESC
        LIMIT 10
    ")

    if [[ -z "$join_patterns" || "$join_patterns" == "0" ]]; then
        log "INFO" "No common JOIN patterns found"
    else
        log "INFO" "Common JOIN patterns (potential index candidates):"
        echo "$join_patterns" | while IFS='|' read -r pattern frequency total_time; do
            if [[ -n "$pattern" && "$pattern" != "{" && "$pattern" != "}" ]]; then
                # Extract table and join columns from pattern
                pattern=$(echo "$pattern" | tr -d '{}')
                table=$(echo "$pattern" | cut -d, -f1 | tr -d '"')
                column1=$(echo "$pattern" | cut -d, -f2 | tr -d '"')
                column2=$(echo "$pattern" | cut -d, -f3 | tr -d '"')

                log "INFO" "- Table: $table, Join columns: $column1=$column2 (freq: $frequency, total time: ${total_time}ms)"
            fi
        done
    fi
}

# Generate index recommendations based on analysis
generate_recommendations() {
    log "INFO" "Generating index recommendations..."
    local recommendations=""
    local recommendation_file="${LOG_DIR}/index_recommendations_${TIMESTAMP}.sql"

    # 1. Check for missing primary key indexes
    log "INFO" "Checking for tables missing primary keys..."

    local missing_pks
    missing_pks=$(run_query "
        SELECT tablename
        FROM pg_tables
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        AND tablename NOT IN (
            SELECT t.relname
            FROM pg_index i
            JOIN pg_class t ON i.indrelid = t.oid
            WHERE i.indisprimary
            AND t.relkind = 'r'
        )
        ORDER BY tablename
    ")

    if [[ -n "$missing_pks" ]]; then
        log "WARNING" "Tables missing primary keys:"
        echo "$missing_pks" | while read -r table; do
            if [[ -n "$table" ]]; then
                log "WARNING" "- $table should have a primary key"
                recommendations+="-- WARNING: Table '$table' has no primary key\n"
                recommendations+="-- Recommendation: Add a primary key or unique constraint\n\n"
            fi
        done
    else
        log "INFO" "No tables missing primary keys"
    fi

    # 2. Check for foreign keys without indexes
    log "INFO" "Checking for foreign keys without indexes..."

    local unindexed_fks
    unindexed_fks=$(run_query "
        SELECT
            ns.nspname || '.' || t.relname as table,
            a.attname as column
        FROM
            pg_constraint c
            JOIN pg_namespace ns ON ns.oid = c.connamespace
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
        WHERE
            c.contype = 'f'
            AND NOT EXISTS (
                SELECT 1 FROM pg_index i
                WHERE i.indrelid = t.oid
                AND a.attnum = ANY(i.indkey)
                AND i.indisunique = false
                AND array_position(i.indkey, a.attnum) = 0
            )
        ORDER BY table, column
    ")

    if [[ -n "$unindexed_fks" ]]; then
        log "WARNING" "Foreign keys without indexes:"
        echo "$unindexed_fks" | while IFS='|' read -r table column; do
            if [[ -n "$table" ]]; then
                log "WARNING" "- $table.$column (foreign key without index)"

                # Create a safe index name by removing schema prefix for the index name
                local table_name=${table#*.}
                recommendations+="-- Foreign key column without index\n"
                recommendations+="CREATE INDEX idx_fk_${table_name}_${column} ON ${table} (${column});\n\n"
            fi
        done
    else
        log "INFO" "All foreign keys are properly indexed"
    fi

    # 3. Check for columns commonly used in WHERE clauses without indexes
    if check_pg_stat_statements; then
        log "INFO" "Analyzing common WHERE clauses for missing indexes..."

        local missing_where_indexes
        missing_where_indexes=$(run_query "
            WITH common_where AS (
                SELECT
                    regexp_matches(query, 'FROM\\s+([a-zA-Z0-9_\\.]+).*?WHERE\\s+([a-zA-Z0-9_\\.]+)\\s*[=<>]', 'gi') as matches,
                    count(*) as frequency
                FROM pg_stat_statements
                WHERE query ILIKE '%WHERE%'
                  AND query NOT ILIKE '%CREATE INDEX%'
                GROUP BY matches
                HAVING count(*) > 5
                ORDER BY count(*) DESC
            )
            SELECT
                m[1] as table_name,
                m[2] as column_name,
                frequency
            FROM common_where cw, unnest(cw.matches) m
            LIMIT 10
        ")

        if [[ -n "$missing_where_indexes" ]]; then
            log "INFO" "Commonly queried columns that might need indexes:"
            echo "$missing_where_indexes" | while IFS='|' read -r table column frequency; do
                if [[ -n "$table" && -n "$column" ]]; then
                    # Check if this column already has an index
                    local has_index
                    has_index=$(run_query "
                        SELECT COUNT(*)
                        FROM pg_indexes
                        WHERE tablename = '${table#*.}'
                        AND indexdef LIKE '%($column)%' OR indexdef LIKE '%(${column})%' OR indexdef LIKE '%\"${column}\"%'
                    ")

                    if [[ "$has_index" == "0" ]]; then
                        log "INFO" "- $table.$column (appears in $frequency queries, no index found)"

                        # Create a safe index name by removing schema prefix for the index name
                        local table_name=${table#*.}
                        # Escape column name for SQL
                        local column_escaped=$(echo "$column" | sed 's/[^a-zA-Z0-9_]/\_/g')
                        recommendations+="-- Column frequently used in WHERE clauses\n"
                        recommendations+="CREATE INDEX idx_${table_name}_${column_escaped} ON ${table} (\"${column}\");\n\n"
                    else
                        log "INFO" "- $table.$column already has an index"
                    fi
                fi
            done
        else
            log "INFO" "No common WHERE clauses that need additional indexes"
        fi
    fi

    # 4. Check for tables that are frequently joined without indexes
    if check_pg_stat_statements; then
        log "INFO" "Analyzing JOIN patterns for missing indexes..."

        local join_patterns
        join_patterns=$(run_query "
            SELECT
                regexp_matches(query, 'JOIN\\s+([a-zA-Z0-9_\\.]+)\\s+(?:\\w+\\s+)?ON\\s+\\w+\\.([a-zA-Z0-9_]+)\\s*=\\s*\\w+\\.([a-zA-Z0-9_]+)', 'gi') as matches,
                count(*) as frequency
            FROM pg_stat_statements
            WHERE query ILIKE '%JOIN%ON%'
            GROUP BY matches
            HAVING count(*) > 5
            ORDER BY count(*) DESC
            LIMIT 10
        ")

        if [[ -n "$join_patterns" ]]; then
            log "INFO" "Common JOIN patterns that might need indexes:"
            echo "$join_patterns" | while IFS='|' read -r pattern frequency; do
                if [[ -n "$pattern" && "$pattern" != "{" && "$pattern" != "}" ]]; then
                    # Extract table and column from pattern
                    pattern=$(echo "$pattern" | tr -d '{}')
                    table=$(echo "$pattern" | cut -d, -f1 | tr -d '"')
                    column=$(echo "$pattern" | cut -d, -f3 | tr -d '"')

                    # Check if this column already has an index
                    local has_index
                    has_index=$(run_query "
                        SELECT COUNT(*)
                        FROM pg_indexes
                        WHERE tablename = '${table#*.}'
                        AND indexdef LIKE '%($column)%' OR indexdef LIKE '%(${column})%' OR indexdef LIKE '%\"${column}\"%'
                    ")

                    if [[ "$has_index" == "0" ]]; then
                        log "INFO" "- $table.$column (used in JOIN, no index found)"

                        # Create a safe index name by removing schema prefix for the index name
                        local table_name=${table#*.}
                        # Escape column name for SQL
                        local column_escaped=$(echo "$column" | sed 's/[^a-zA-Z0-9_]/\_/g')
                        recommendations+="-- Column used in JOIN operations\n"
                        recommendations+="CREATE INDEX idx_join_${table_name}_${column_escaped} ON ${table} (\"${column}\");\n\n"
                    else
                        log "INFO" "- $table.$column already has an index"
                    fi
                fi
            done
        else
            log "INFO" "No common JOIN patterns that need additional indexes"
        fi
    fi

    # 5. Check for redundant indexes - suggest which to keep and which to remove
    log "INFO" "Generating recommendations for redundant indexes..."

    local redundant_indexes
    redundant_indexes=$(run_query "
        SELECT
            array_agg(idx.indexrelid::regclass::text) as indexes,
            array_agg(s.idx_scan) as scans,
            schemaname || '.' || tablename as table
        FROM
            pg_index idx
        JOIN
            pg_stat_all_indexes s ON idx.indexrelid = s.indexrelid
        JOIN
            pg_indexes i ON s.indexrelname = i.indexname
        WHERE
            schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        GROUP BY
            schemaname, tablename, split_part(idx.indkey::text, ' ', 1)
        HAVING
            COUNT(*) > 1
        ORDER BY
            schemaname, tablename
    ")

    if [[ -n "$redundant_indexes" ]]; then
        log "INFO" "Recommendations for redundant indexes:"
        echo "$redundant_indexes" | while IFS='|' read -r indexes scans table; do
            if [[ -n "$table" && -n "$indexes" ]]; then
                # Convert string arrays to proper arrays
                indexes=${indexes//\{/}
                indexes=${indexes//\}/}
                scans=${scans//\{/}
                scans=${scans//\}/}

                # Convert comma-separated strings to arrays
                IFS=',' read -ra index_array <<< "$indexes"
                IFS=',' read -ra scan_array <<< "$scans"

                # Find index with most scans
                local most_used=""
                local max_scans=0
                for i in "${!index_array[@]}"; do
                    if [[ "${scan_array[$i]}" -gt "$max_scans" ]]; then
                        most_used="${index_array[$i]}"
                        max_scans="${scan_array[$i]}"
                    fi
                done

                # Generate recommendations
                local kept=""
                for i in "${!index_array[@]}"; do
                    if [[ "${index_array[$i]}" == "$most_used" ]]; then
                        kept="${index_array[$i]}"
                    else
                        log "INFO" "- Consider dropping ${index_array[$i]} on $table (keep $most_used)"
                        recommendations+="-- Redundant index (${scan_array[$i]} scans vs ${max_scans} scans)\n"
                        recommendations+="DROP INDEX IF EXISTS ${index_array[$i]};\n\n"
                    fi
                done
            fi
        done
    else
        log "INFO" "No redundant indexes found"
    fi

    # 6. Check for very large indexes that might need to be partitioned or reconsidered
    log "INFO" "Checking for oversized indexes..."

    local large_indexes
    large_indexes=$(run_query "
        SELECT
            schemaname || '.' || tablename as table,
            indexname as index,
            pg_size_pretty(pg_relation_size(indexrelid)) as size,
            pg_relation_size(indexrelid)/(1024*1024) as size_mb,
            idx_scan as scans
        FROM pg_indexes, pg_stat_all_indexes
        WHERE pg_indexes.indexname = pg_stat_all_indexes.indexrelname
        AND schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        AND pg_relation_size(indexrelid) > ($INDEX_SIZE_THRESHOLD * 1024 * 1024)
        ORDER BY pg_relation_size(indexrelid) DESC
    ")

    if [[ -n "$large_indexes" ]]; then
        log "INFO" "Large indexes that might need review:"
        echo "$large_indexes" | while IFS='|' read -r table index size size_mb scans; do
            if [[ -n "$table" ]]; then
                # If index is large but rarely used, suggest dropping it
                if [[ "$scans" -lt 100 ]]; then
                    log "WARNING" "- $index on $table: $size (scans: $scans) - Consider dropping this large, rarely-used index"
                    recommendations+="-- Large index with few scans\n"
                    recommendations+="-- WARNING: Review before dropping!\n"
                    recommendations+="-- DROP INDEX IF EXISTS ${index};\n\n"
                else
                    log "INFO" "- $index on $table: $size (scans: $scans) - Review for potential optimization"
                    recommendations+="-- Large index ($size, scans: $scans)\n"
                    recommendations+="-- Consider partitioning or partial indexing\n\n"
                fi
            fi
        done
    else
        log "INFO" "No oversized indexes found"
    fi

    # Save recommendations to file
    if [[ -n "$recommendations" ]]; then
        # Ensure log directory exists
        mkdir -p "$(dirname "$recommendation_file")" 2>/dev/null || {
            log "WARNING" "Could not create log directory for recommendations. Using /tmp instead."
            recommendation_file="/tmp/index_recommendations_${TIMESTAMP}.sql"
        }

        {
            echo -e "-- Index Recommendations for ${DB_NAME} (${ENV} environment)"
            echo -e "-- Generated on $(date)"
            echo -e "-- WARNING: Review before applying these changes\n"
            echo -e "$recommendations"
        } > "$recommendation_file"

        log "INFO" "Index recommendations saved to $recommendation_file"

        # Print top recommendations
        log "INFO" "Top index recommendations:"
        grep "CREATE INDEX" "$recommendation_file" | head -5 | while read -r line; do
            log "INFO" "  $line"
        done

        if grep -q "DROP INDEX" "$recommendation_file" | grep -v "\-\-"; then
            log "INFO" "Indexes recommended for removal:"
            grep "DROP INDEX" "$recommendation_file" | grep -v "\-\-" | head -5 | while read -r line; do
                log "INFO" "  $line"
            done
        fi

        # Notify security audit if available
        if [[ "$CORE_COMMON_LOADED" == "true" ]] && type -t "log_security_event" &>/dev/null; then
            log_security_event "database_index_recommendations" "Generated index recommendations for $DB_NAME" "info"
        fi

        return 0
    else
        log "INFO" "No index recommendations generated - your schema appears well-optimized"
        return 1
    fi
}

# Apply index recommendations
apply_recommendations() {
    local recommendation_file="${LOG_DIR}/index_recommendations_${TIMESTAMP}.sql"

    if [[ ! -f "$recommendation_file" ]]; then
        log "ERROR" "No recommendation file found at $recommendation_file"
        return 1
    fi

    log "INFO" "Preparing to apply index recommendations..."

    # Count CREATE and DROP statements
    local create_count
    create_count=$(grep -c "CREATE INDEX" "$recommendation_file" | grep -v "\-\-" || echo 0)
    local drop_count
    drop_count=$(grep -c "DROP INDEX" "$recommendation_file" | grep -v "\-\-" || echo 0)

    log "INFO" "Will create $create_count indexes and drop $drop_count indexes"

    # Prompt for confirmation unless forced
    if [[ "$FORCE" != "true" ]]; then
        echo
        echo "WARNING: This will modify database indexes in ${ENV} environment."
        echo "         Creating $create_count new indexes and dropping $drop_count indexes."
        echo "To proceed, type 'APPLY INDEXES' (all uppercase):"
        read -r confirmation

        if [[ "$confirmation" != "APPLY INDEXES" ]]; then
            log "INFO" "Operation cancelled by user"
            return 1
        fi
    fi

    log "INFO" "Applying index recommendations..."

    # Keep track of success/failure counts
    local create_success=0
    local create_fail=0
    local drop_success=0
    local drop_fail=0

    # Execute each CREATE INDEX statement
    if [[ $create_count -gt 0 ]]; then
        log "INFO" "Creating new indexes..."
        grep "CREATE INDEX" "$recommendation_file" | grep -v "\-\-" | while read -r line; do
            log "INFO" "Executing: $line"
            if run_query "$line" 600; then
                log "INFO" "✅ Successfully created index"
                create_success=$((create_success + 1))
            else
                log "ERROR" "❌ Failed to create index"
                create_fail=$((create_fail + 1))
            fi
        done
    fi

    # Execute each DROP INDEX statement
    if [[ $drop_count -gt 0 ]]; then
        log "INFO" "Dropping redundant or unused indexes..."
        grep "DROP INDEX" "$recommendation_file" | grep -v "\-\-" | while read -r line; do
            log "INFO" "Executing: $line"
            if run_query "$line" 300; then
                log "INFO" "✅ Successfully dropped index"
                drop_success=$((drop_success + 1))
            else
                log "ERROR" "❌ Failed to drop index"
                drop_fail=$((drop_fail + 1))
            fi
        done
    fi

    log "INFO" "Analyzing database to update statistics..."
    run_query "ANALYZE" 600

    # Summarize results
    log "INFO" "Index recommendations applied:"
    log "INFO" "- Created: $create_success indexes (failed: $create_fail)"
    log "INFO" "- Dropped: $drop_success indexes (failed: $drop_fail)"

    # Notify security audit if available
    if [[ "$CORE_COMMON_LOADED" == "true" ]] && type -t "log_security_event" &>/dev/null; then
        log_security_event "database_index_update" "Applied index changes to $DB_NAME (created: $create_success, dropped: $drop_success)" "info"
    fi

    if [[ $create_fail -eq 0 && $drop_fail -eq 0 ]]; then
        log "INFO" "Index recommendations applied successfully"
        return 0
    else
        log "WARNING" "Index recommendations applied with some failures"
        return 1
    fi
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
                # Add to temp files for cleanup
                TEMP_FILES="$TEMP_FILES $2"
                shift 2
            else
                handle_error "Password file not found: $2"
            fi
            ;;
        --analyze)
            ANALYZE_ONLY=true
            shift
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
        --max-retries)
            MAX_RETRIES="$2"
            shift 2
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

# Main execution
log "INFO" "Starting database index analysis for ${ENV} environment"

# Load configuration
load_db_config "$ENV" || exit 1

# Check connection to database
check_connection || exit 1

# Always analyze existing indexes
analyze_existing_indexes

# Analyze query patterns from pg_stat_statements
analyze_query_patterns

# Generate index recommendations
generate_recommendations

# Apply recommendations if requested
if [[ "$DRY_RUN" == "false" && "$ANALYZE_ONLY" == "false" ]]; then
    apply_recommendations
elif [[ "$DRY_RUN" == "true" && "$ANALYZE_ONLY" == "true" ]]; then
    log "INFO" "Analysis complete. No changes made."
    log "INFO" "To apply recommendations, run with --apply option."
else
    log "INFO" "Dry run complete. No changes made."
    log "INFO" "To apply recommendations, run with --apply option."
fi

log "INFO" "Script completed successfully."
exit 0
