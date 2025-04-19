#!/bin/bash
# Database verification script for Cloud Infrastructure Platform
# Checks database connectivity and replication status during disaster recovery procedures
# Usage: ./db_verify.sh [--host hostname] [--environment ENV] [--quick-check] [--verbose]

set -e

# Default values
DB_HOST="localhost"
ENVIRONMENT="production"
QUICK_CHECK=false
VERBOSE=false
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPLICATION_LAG_THRESHOLD=300  # 5 minutes in seconds
EXIT_CODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --host)
            DB_HOST="$2"
            shift
            shift
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift
            shift
            ;;
        --quick-check)
            QUICK_CHECK=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $key"
            echo "Usage: $0 [--host hostname] [--environment ENV] [--quick-check] [--verbose]"
            exit 1
            ;;
    esac
done

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
fi

# Set database connection details from environment or defaults
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-"cloud_platform_${ENVIRONMENT}"}
DB_USER=${DB_USER:-"cloud_platform_app"}
DB_PASSWORD=${DB_PASSWORD:-""}

# Enable verbose output if requested
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    if [ "$VERBOSE" = true ] || [ "$2" = "error" ]; then
        echo "[$timestamp] $1"
    fi
}

error() {
    log "ERROR: $1" "error"
    EXIT_CODE=1
}

success() {
    log "SUCCESS: $1"
}

# Function to check basic database connectivity
check_connectivity() {
    log "Checking connectivity to database at ${DB_HOST}:${DB_PORT}..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" -q -t > /dev/null 2>&1; then
        success "Database connectivity check passed"
        return 0
    else
        error "Failed to connect to database at ${DB_HOST}:${DB_PORT}"
        return 1
    fi
}

# Function to check database version
check_version() {
    log "Checking database version..."
    
    VERSION=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT version();" -q -t 2>/dev/null)
    
    if [ -n "$VERSION" ]; then
        success "Database version: $VERSION"
        return 0
    else
        error "Failed to retrieve database version"
        return 1
    fi
}

# Function to check critical tables
check_tables() {
    log "Checking critical tables..."
    
    # Check count of critical tables
    TABLE_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE';" -q -t 2>/dev/null)
    
    if [ -z "$TABLE_COUNT" ] || [ "$TABLE_COUNT" -eq 0 ]; then
        error "No tables found in database"
        return 1
    else
        success "Found $TABLE_COUNT tables in database"
        
        # Check count of specific critical tables
        USER_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_name = 'users';" -q -t 2>/dev/null)
            
        if [ "$USER_COUNT" -eq 0 ]; then
            error "Critical table 'users' not found"
            return 1
        fi
        
        return 0
    fi
}

# Function to check database size
check_database_size() {
    log "Checking database size..."
    
    DB_SIZE=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" -q -t 2>/dev/null)
    
    if [ -n "$DB_SIZE" ]; then
        success "Database size: $DB_SIZE"
        return 0
    else
        error "Failed to retrieve database size"
        return 1
    fi
}

# Function to check replication status
check_replication() {
    log "Checking replication status..."
    
    # Check if this is a replica
    IS_REPLICA=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT pg_is_in_recovery();" -q -t 2>/dev/null)
    
    if [ "$IS_REPLICA" = "t" ]; then
        success "This is a replica database"
        
        # Check replication lag
        LAG_SECONDS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" -q -t 2>/dev/null)
        
        if [ -n "$LAG_SECONDS" ]; then
            if (( $(echo "$LAG_SECONDS < $REPLICATION_LAG_THRESHOLD" | bc -l) )); then
                success "Replication lag: ${LAG_SECONDS} seconds (within threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
                return 0
            else
                error "Replication lag: ${LAG_SECONDS} seconds (exceeds threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
                return 1
            fi
        else
            error "Failed to retrieve replication lag information"
            return 1
        fi
    elif [ "$IS_REPLICA" = "f" ]; then
        # Check if this is a primary with replicas
        HAS_REPLICAS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT COUNT(*) FROM pg_stat_replication;" -q -t 2>/dev/null)
        
        if [ -n "$HAS_REPLICAS" ] && [ "$HAS_REPLICAS" -gt 0 ]; then
            success "This is a primary database with $HAS_REPLICAS connected replicas"
            return 0
        else
            log "This is a primary database with no connected replicas"
            # Not an error condition if we're checking the primary region
            return 0
        fi
    else
        error "Failed to determine replication role"
        return 1
    fi
}

# Function to write to DR events log
log_dr_event() {
    local status=$1
    
    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"
    
    # Log the database verification event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),DB_VERIFY,${ENVIRONMENT},${DB_HOST},${status}" >> "/var/log/cloud-platform/dr-events.log"
}

# Main verification process
log "Starting database verification for ${ENVIRONMENT} environment at ${DB_HOST}"

# Always check connectivity first
check_connectivity || { 
    log_dr_event "FAILURE"
    exit 1
}

# If quick check requested, exit after connectivity check
if [ "$QUICK_CHECK" = true ]; then
    log "Quick check successful"
    log_dr_event "SUCCESS"
    exit 0
fi

# Perform full verification
check_version
check_tables
check_database_size
check_replication

# Final status
if [ $EXIT_CODE -eq 0 ]; then
    log "Database verification completed successfully"
    log_dr_event "SUCCESS"
    exit 0
else
    log "Database verification failed with errors"
    log_dr_event "FAILURE"
    exit 1
fi