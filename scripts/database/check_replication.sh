#!/bin/bash
# Database replication status check for Cloud Infrastructure Platform
# Checks replication lag and status between primary and replica databases
# Usage: ./check_replication.sh [--environment ENV] [--verbose] [--threshold SECONDS]

set -e

# Default values
ENVIRONMENT="production"
VERBOSE=false
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPLICATION_LAG_THRESHOLD=300  # 5 minutes in seconds
EXIT_CODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment)
            ENVIRONMENT="$2"
            shift
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --threshold)
            REPLICATION_LAG_THRESHOLD="$2"
            shift
            shift
            ;;
        --help)
            echo "Usage: $0 [--environment ENV] [--verbose] [--threshold SECONDS]"
            echo ""
            echo "Options:"
            echo "  --environment ENV   Environment to check (default: production)"
            echo "  --verbose           Show detailed output"
            echo "  --threshold SECONDS Maximum acceptable replication lag in seconds (default: 300)"
            exit 0
            ;;
        *)
            echo "Unknown option: $key"
            echo "Usage: $0 [--environment ENV] [--verbose] [--threshold SECONDS]"
            exit 1
            ;;
    esac
done

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
fi

# Set database connection details from environment variables or defaults
PRIMARY_DB_HOST=${PRIMARY_DB_HOST:-"primary-db.internal"}
PRIMARY_DB_PORT=${PRIMARY_DB_PORT:-5432}
SECONDARY_DB_HOST=${SECONDARY_DB_HOST:-"secondary-db.internal"}
SECONDARY_DB_PORT=${SECONDARY_DB_PORT:-5432}
DB_NAME=${DB_NAME:-"cloud_platform_${ENVIRONMENT}"}
DB_USER=${DB_USER:-"cloud_platform_app"}
DB_PASSWORD=${DB_PASSWORD:-""}

# Enable verbose output if requested
log() {
    if [ "$VERBOSE" = true ] || [ "$2" = "always" ]; then
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        echo "[$timestamp] $1"
    fi
}

error() {
    log "ERROR: $1" "always"
    EXIT_CODE=1
}

success() {
    log "SUCCESS: $1" "always"
}

info() {
    log "INFO: $1" "always"
}

# Function to check if a host is reachable
check_host_reachable() {
    local host=$1
    local port=$2
    
    log "Checking if $host:$port is reachable..."
    
    if nc -z -w 5 "$host" "$port" 2>/dev/null; then
        log "$host:$port is reachable"
        return 0
    else
        error "$host:$port is not reachable"
        return 1
    fi
}

# Function to check primary server status
check_primary_status() {
    log "Checking primary database server status..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Check if the server is running and accepting connections
    if ! check_host_reachable "$PRIMARY_DB_HOST" "$PRIMARY_DB_PORT"; then
        error "Primary database server is not reachable"
        return 1
    fi
    
    # Check if the server is in primary mode (not in recovery)
    IS_PRIMARY=$(psql -h "$PRIMARY_DB_HOST" -p "$PRIMARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_is_in_recovery() = false;" 2>/dev/null | tr -d ' ')
    
    if [ "$IS_PRIMARY" = "t" ]; then
        success "Primary server is running in primary mode"
        return 0
    else
        error "Primary server is not in primary mode (it might be in recovery)"
        return 1
    fi
}

# Function to check secondary server status
check_secondary_status() {
    log "Checking secondary database server status..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Check if the server is running and accepting connections
    if ! check_host_reachable "$SECONDARY_DB_HOST" "$SECONDARY_DB_PORT"; then
        error "Secondary database server is not reachable"
        return 1
    }
    
    # Check if the server is in replica mode (in recovery)
    IS_REPLICA=$(psql -h "$SECONDARY_DB_HOST" -p "$SECONDARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ')
    
    if [ "$IS_REPLICA" = "t" ]; then
        success "Secondary server is running in replica mode"
        return 0
    else
        error "Secondary server is not in replica mode (it might be a standalone primary)"
        return 1
    fi
}

# Function to check replication lag
check_replication_lag() {
    log "Checking replication lag..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Ensure we're connected to a replica
    IS_REPLICA=$(psql -h "$SECONDARY_DB_HOST" -p "$SECONDARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ')
    
    if [ "$IS_REPLICA" != "t" ]; then
        error "Secondary server is not in replica mode, cannot check replication lag"
        return 1
    fi
    
    # Check lag in seconds
    LAG_SECONDS=$(psql -h "$SECONDARY_DB_HOST" -p "$SECONDARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" 2>/dev/null | tr -d ' ')
    
    if [ -z "$LAG_SECONDS" ]; then
        error "Could not determine replication lag"
        return 1
    fi
    
    # Check if lag is within acceptable threshold
    if (( $(echo "$LAG_SECONDS < $REPLICATION_LAG_THRESHOLD" | bc -l) )); then
        success "Replication lag is ${LAG_SECONDS} seconds (within threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
        return 0
    else
        error "Replication lag is ${LAG_SECONDS} seconds (exceeds threshold of ${REPLICATION_LAG_THRESHOLD} seconds)"
        return 1
    fi
}

# Function to check replication slots
check_replication_slots() {
    log "Checking replication slots on primary..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Check if there are active replication slots
    ACTIVE_SLOTS=$(psql -h "$PRIMARY_DB_HOST" -p "$PRIMARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT count(*) FROM pg_replication_slots WHERE active = true;" 2>/dev/null | tr -d ' ')
    
    if [ -z "$ACTIVE_SLOTS" ]; then
        error "Could not query replication slots"
        return 1
    elif [ "$ACTIVE_SLOTS" -gt 0 ]; then
        success "Found $ACTIVE_SLOTS active replication slots on primary"
        return 0
    else
        error "No active replication slots found on primary"
        return 1
    fi
}

# Function to check replication connections
check_replication_connections() {
    log "Checking active replication connections..."
    
    # Export password for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Check for active replication connections
    REPLICATION_COUNT=$(psql -h "$PRIMARY_DB_HOST" -p "$PRIMARY_DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming';" 2>/dev/null | tr -d ' ')
    
    if [ -z "$REPLICATION_COUNT" ]; then
        error "Could not query replication connections"
        return 1
    elif [ "$REPLICATION_COUNT" -gt 0 ]; then
        success "Found $REPLICATION_COUNT active streaming replication connections"
        return 0
    else
        error "No active streaming replication connections found"
        return 1
    fi
}

# Function to log to DR events log
log_dr_event() {
    local status=$1
    
    # Create DR log directory if it doesn't exist
    mkdir -p "/var/log/cloud-platform"
    
    # Log the replication check event
    echo "$(date '+%Y-%m-%d %H:%M:%S'),REPLICATION_CHECK,${ENVIRONMENT},${status}" >> "/var/log/cloud-platform/dr-events.log"
    log "Replication check result logged to DR events log"
}

# Function to check overall replication health
check_replication_health() {
    local primary_ok=true
    local secondary_ok=true
    local lag_ok=true
    local slots_ok=true
    local connections_ok=true
    
    info "Starting comprehensive replication health check for ${ENVIRONMENT} environment"
    
    # Check primary status
    if ! check_primary_status; then
        primary_ok=false
    fi
    
    # Check secondary status
    if ! check_secondary_status; then
        secondary_ok=false
    fi
    
    # Only continue with more detailed checks if both servers are reachable
    if [ "$primary_ok" = true ] && [ "$secondary_ok" = true ]; then
        # Check replication lag
        if ! check_replication_lag; then
            lag_ok=false
        fi
        
        # Check replication slots
        if ! check_replication_slots; then
            slots_ok=false
        fi
        
        # Check replication connections
        if ! check_replication_connections; then
            connections_ok=false
        fi
    fi
    
    # Determine overall status
    if [ "$primary_ok" = true ] && [ "$secondary_ok" = true ] && [ "$lag_ok" = true ] && [ "$slots_ok" = true ] && [ "$connections_ok" = true ]; then
        success "Replication health check: OK"
        log_dr_event "HEALTHY"
        return 0
    else
        error "Replication health check: FAILED"
        # Summarize issues
        if [ "$primary_ok" = false ]; then
            error "- Primary server issue detected"
        fi
        if [ "$secondary_ok" = false ]; then
            error "- Secondary server issue detected"
        fi
        if [ "$lag_ok" = false ]; then
            error "- Replication lag exceeds threshold"
        fi
        if [ "$slots_ok" = false ]; then
            error "- Replication slot issue detected"
        fi
        if [ "$connections_ok" = false ]; then
            error "- Replication connection issue detected"
        fi
        log_dr_event "UNHEALTHY"
        return 1
    fi
}

# Run the main check function
check_replication_health
exit $EXIT_CODE