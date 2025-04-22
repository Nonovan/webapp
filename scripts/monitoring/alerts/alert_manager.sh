#!/bin/bash
# Alert Manager for Cloud Infrastructure Platform
#
# This script manages the alert lifecycle including creation, acknowledgment,
# and resolution of alerts across environments. It integrates with the monitoring
# system and notification channels to provide a complete alert management solution.
#
# Usage: ./alert_manager.sh [options]

set -eo pipefail

# Determine script directory and import common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
UTILS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"
COMMON_PATH="${PROJECT_ROOT}/scripts/monitoring/common"
TEMPLATES_DIR="${PROJECT_ROOT}/scripts/monitoring/templates"
ALERTS_DB="/var/lib/cloud-platform/alerts.db"
API_ENDPOINT="http://localhost:5000/api/alerts"

# Default values
ENVIRONMENT="production"
REGION=""
ACTION=""
ALERT_ID=""
ALERT_TYPE=""
RESOURCE_ID=""
SERVICE_NAME=""
SEVERITY="warning"
MESSAGE=""
DETAILS="{}"
ACKNOWLEDGED_BY=""
RESOLUTION_NOTE=""
DRY_RUN=false
VERBOSE=false
OUTPUT_FORMAT="text"
CONFIG_DIR="${PROJECT_ROOT}/scripts/monitoring/config"
TIMEOUT=10
MAX_RETRIES=3
FORCE=false
INTERACTIVE=false

# Import utility functions
if [[ -f "$UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$UTILS_PATH"
else
    echo "ERROR: Required utility functions not found at $UTILS_PATH"
    exit 1
fi

# Source common logging utilities if available
if [[ -f "${COMMON_PATH}/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_PATH}/logging_utils.sh"
else
    # Fallback basic logging functions if the file doesn't exist
    log_info() { echo "[INFO] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] $1"; }
    log_script_start() { log_info "Starting alert management operation"; }
    log_script_end() { log_info "Alert management operation $1"; }
fi

# Source error handling utilities if available
if [[ -f "${COMMON_PATH}/error_handling.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_PATH}/error_handling.sh"
fi

# Source validation utilities if available
if [[ -f "${COMMON_PATH}/validation.sh" ]]; then
    # shellcheck source=/dev/null
    source "${COMMON_PATH}/validation.sh"
else
    # Basic validation function fallbacks
    validate_environment_name() {
        case "$1" in
            development|staging|production|dr-recovery) return 0 ;;
            *) return 1 ;;
        esac
    }
fi

# Function to display usage information
usage() {
    cat <<EOF
Alert Manager for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Actions:
  --create                     Create a new alert
  --acknowledge ID             Acknowledge an existing alert
  --resolve ID                 Resolve an existing alert
  --list                       List alerts (default: active alerts)
  --get ID                     Get details for a specific alert
  --enable SERVICE             Enable alerts for a specific service
  --disable SERVICE            Disable alerts for a specific service
  --test                       Test alert creation and notification
  --batch-file FILE            Process batch operations from a file

Alert Creation Options:
  --type TYPE                  Alert type (e.g., cpu_usage, memory_usage, disk_space)
  --resource-id ID             Resource ID the alert is associated with
  --service SERVICE            Service name the alert is associated with
  --severity LEVEL             Alert severity (critical, warning, info) [default: warning]
  --message "TEXT"             Alert message text
  --details "JSON"             Additional alert details in JSON format

Alert Resolution Options:
  --resolution-note "TEXT"     Note explaining how the alert was resolved
  --acknowledged-by USER       User who acknowledged the alert

Environment Options:
  --environment ENV            Target environment [default: production]
                               Valid values: development, staging, production, dr-recovery
  --region REGION              Target region (e.g., us-west-2)
  --config-file FILE           Path to configuration file

Output Options:
  --format FORMAT              Output format (text, json, csv) [default: text]
  --dry-run                    Show what would happen without making changes
  --verbose                    Show detailed output
  --force                      Force operation without interactive prompts
  --interactive                Enable interactive mode
  --timeout SECONDS            API request timeout in seconds [default: 10]
  --retries COUNT              Number of API retries [default: 3]
  --help                       Show this help message and exit

Examples:
  # Create a critical alert
  $(basename "$0") --create --type cpu_usage --resource-id web-server-01 --service web \\
    --severity critical --message "CPU usage exceeded 95%"

  # Acknowledge an alert
  $(basename "$0") --acknowledge 1234 --acknowledged-by "john.doe"

  # Resolve an alert
  $(basename "$0") --resolve 1234 --resolution-note "Restarted the application server"

  # List all active critical alerts
  $(basename "$0") --list --severity critical

  # Enable alerts for database service
  $(basename "$0") --enable database --environment production
EOF
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            --create)
                ACTION="create"
                shift
                ;;
            --acknowledge)
                ACTION="acknowledge"
                ALERT_ID="$2"
                shift 2
                ;;
            --resolve)
                ACTION="resolve"
                ALERT_ID="$2"
                shift 2
                ;;
            --list)
                ACTION="list"
                shift
                ;;
            --get)
                ACTION="get"
                ALERT_ID="$2"
                shift 2
                ;;
            --enable)
                ACTION="enable"
                SERVICE_NAME="$2"
                shift 2
                ;;
            --disable)
                ACTION="disable"
                SERVICE_NAME="$2"
                shift 2
                ;;
            --test)
                ACTION="test"
                shift
                ;;
            --batch-file)
                ACTION="batch"
                BATCH_FILE="$2"
                shift 2
                ;;
            --type)
                ALERT_TYPE="$2"
                shift 2
                ;;
            --resource-id)
                RESOURCE_ID="$2"
                shift 2
                ;;
            --service)
                SERVICE_NAME="$2"
                shift 2
                ;;
            --severity)
                SEVERITY="$2"
                shift 2
                ;;
            --message)
                MESSAGE="$2"
                shift 2
                ;;
            --details)
                DETAILS="$2"
                shift 2
                ;;
            --resolution-note)
                RESOLUTION_NOTE="$2"
                shift 2
                ;;
            --acknowledged-by)
                ACKNOWLEDGED_BY="$2"
                shift 2
                ;;
            --environment|-e)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --region|-r)
                REGION="$2"
                shift 2
                ;;
            --config-file)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --format|-f)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --interactive)
                INTERACTIVE=true
                shift
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $key"
                usage
                exit 1
                ;;
        esac
    done
}

# Function to validate input parameters based on action
validate_parameters() {
    # Validate environment
    if ! validate_environment_name "$ENVIRONMENT"; then
        log_error "Invalid environment: $ENVIRONMENT"
        echo "Valid environments: development, staging, production, dr-recovery"
        exit 1
    fi

    # Validate timeout and retries
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -lt 1 ]]; then
        log_error "Invalid timeout value: $TIMEOUT. Must be a positive integer."
        exit 1
    fi

    if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]]; then
        log_error "Invalid retries value: $MAX_RETRIES. Must be a non-negative integer."
        exit 1
    fi

    # Validate action-specific parameters
    case "$ACTION" in
        create)
            if [[ -z "$ALERT_TYPE" ]]; then
                log_error "Alert type is required for creating alerts (--type)"
                exit 1
            fi
            if [[ -z "$MESSAGE" ]]; then
                log_error "Alert message is required for creating alerts (--message)"
                exit 1
            fi
            # Validate severity
            case "$SEVERITY" in
                critical|warning|info)
                    # Valid severity
                    ;;
                *)
                    log_error "Invalid severity: $SEVERITY"
                    log_error "Valid severity levels: critical, warning, info"
                    exit 1
                    ;;
            esac
            # Validate JSON details if provided
            if [[ "$DETAILS" != "{}" ]]; then
                if ! echo "$DETAILS" | jq empty &>/dev/null; then
                    log_error "Invalid JSON details format"
                    exit 1
                fi
            fi
            ;;
        acknowledge|resolve|get)
            if [[ -z "$ALERT_ID" || ! "$ALERT_ID" =~ ^[0-9]+$ ]]; then
                log_error "Valid alert ID is required for $ACTION action"
                exit 1
            fi
            ;;
        enable|disable)
            if [[ -z "$SERVICE_NAME" ]]; then
                log_error "Service name is required for $ACTION action"
                exit 1
            fi
            ;;
        batch)
            if [[ -z "$BATCH_FILE" || ! -f "$BATCH_FILE" ]]; then
                log_error "Valid batch file is required"
                exit 1
            fi
            ;;
        list)
            # No specific validation needed for list
            ;;
        test)
            # No specific validation needed for test
            ;;
        *)
            log_error "No action specified"
            usage
            exit 1
            ;;
    esac

    # Validate output format
    case "$OUTPUT_FORMAT" in
        text|json|csv)
            # Valid format
            ;;
        *)
            log_error "Invalid output format: $OUTPUT_FORMAT"
            log_error "Valid formats: text, json, csv"
            exit 1
            ;;
    esac
}

# Function to load configuration
load_config() {
    local config_path=""

    # Use specific config file if provided
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        config_path="$CONFIG_FILE"
    else
        # Use environment-specific config
        config_path="${CONFIG_DIR}/environments/${ENVIRONMENT}.conf"
        if [[ ! -f "$config_path" ]]; then
            config_path="${CONFIG_DIR}/alerts.conf"
        fi
    fi

    # Load configuration file if exists
    if [[ -f "$config_path" ]]; then
        log_info "Loading configuration from $config_path"
        # shellcheck source=/dev/null
        source "$config_path" || log_warning "Failed to load configuration file"
    else
        log_warning "Configuration file not found: $config_path"
    fi

    # Set region from config if not specified on command line
    if [[ -z "$REGION" && -n "${DEFAULT_REGION:-}" ]]; then
        REGION="$DEFAULT_REGION"
        log_info "Using default region from configuration: $REGION"
    fi

    # Apply environment-specific configurations if available
    case "$ENVIRONMENT" in
        production)
            # Production-specific settings
            if [[ -z "$EMAIL_RECIPIENT" && -n "${PROD_EMAIL_ALERTS:-}" ]]; then
                EMAIL_RECIPIENT="$PROD_EMAIL_ALERTS"
                log_debug "Using production email recipient from configuration"
            fi
            ;;
        dr-recovery)
            # DR recovery-specific settings
            if [[ -z "$EMAIL_RECIPIENT" && -n "${DR_EMAIL_ALERTS:-}" ]]; then
                EMAIL_RECIPIENT="$DR_EMAIL_ALERTS"
                log_debug "Using DR email recipient from configuration"
            fi
            ;;
        staging)
            # Staging-specific settings
            if [[ -z "$EMAIL_RECIPIENT" && -n "${STAGING_EMAIL_ALERTS:-}" ]]; then
                EMAIL_RECIPIENT="$STAGING_EMAIL_ALERTS"
                log_debug "Using staging email recipient from configuration"
            fi
            ;;
        development)
            # Development-specific settings - usually minimal notifications
            ;;
    esac
}

# Function to initialize the alerts database
init_alerts_db() {
    # Create the database directory if it doesn't exist
    local db_dir
    db_dir=$(dirname "$ALERTS_DB")
    mkdir -p "$db_dir" 2>/dev/null || {
        log_error "Failed to create database directory: $db_dir"
        exit 1
    }

    # Check if sqlite3 is available
    if ! command -v sqlite3 &>/dev/null; then
        log_error "sqlite3 command not found. Required for database operations."
        exit 1
    }

    # Initialize the database if it doesn't exist
    if [[ ! -f "$ALERTS_DB" ]]; then
        log_info "Initializing alerts database at $ALERTS_DB"

        sqlite3 "$ALERTS_DB" <<EOF
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    resource_id TEXT,
    service_name TEXT,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    environment TEXT NOT NULL,
    region TEXT,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    resolved_by TEXT,
    resolved_at TEXT,
    resolution_note TEXT
);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_environment ON alerts(environment);
CREATE INDEX idx_alerts_service ON alerts(service_name);
CREATE INDEX idx_alerts_resource ON alerts(resource_id);
EOF

        # Check if the database was created successfully
        if [[ ! -f "$ALERTS_DB" ]]; then
            log_error "Failed to create alerts database"
            exit 1
        fi

        # Set appropriate permissions
        chmod 644 "$ALERTS_DB" 2>/dev/null || log_warning "Failed to set permissions on database file"

        # Create initial empty statistics table for reporting
        sqlite3 "$ALERTS_DB" <<EOF
CREATE TABLE alert_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    environment TEXT NOT NULL,
    stat_date TEXT NOT NULL,
    critical_count INTEGER DEFAULT 0,
    warning_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    resolved_count INTEGER DEFAULT 0,
    acknowledged_count INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_alert_stats_env ON alert_stats(environment);
CREATE INDEX idx_alert_stats_date ON alert_stats(stat_date);
EOF
    }

    # Verify database integrity
    if ! sqlite3 "$ALERTS_DB" "PRAGMA integrity_check;" | grep -q "ok"; then
        log_warning "Alert database integrity check failed. Database may be corrupted."

        if [[ "$FORCE" == "true" ]]; then
            log_warning "Continuing with potentially corrupted database due to --force flag"
        else
            log_error "Database integrity check failed. Use --force to proceed anyway."
            exit 1
        fi
    }

    # Update statistics for today
    update_alert_statistics
}

# Function to update alert statistics
update_alert_statistics() {
    # Only run if in production mode and not a dry run
    if [[ "$DRY_RUN" == "true" || "$ENVIRONMENT" == "development" ]]; then
        return 0
    fi

    local today
    today=$(date +%Y-%m-%d)

    # Check if we have a stats record for today
    local has_stats
    has_stats=$(sqlite3 "$ALERTS_DB" "SELECT COUNT(*) FROM alert_stats WHERE environment = '$ENVIRONMENT' AND stat_date = '$today';")

    if [[ "$has_stats" == "0" ]]; then
        # Create a new record
        sqlite3 "$ALERTS_DB" <<EOF
INSERT INTO alert_stats (environment, stat_date, updated_at)
VALUES ('$ENVIRONMENT', '$today', '$(date -u +"%Y-%m-%dT%H:%M:%SZ")');
EOF
    fi

    # Update the statistics
    sqlite3 "$ALERTS_DB" <<EOF
UPDATE alert_stats
SET
    critical_count = (SELECT COUNT(*) FROM alerts WHERE environment = '$ENVIRONMENT' AND severity = 'critical' AND status = 'active'),
    warning_count = (SELECT COUNT(*) FROM alerts WHERE environment = '$ENVIRONMENT' AND severity = 'warning' AND status = 'active'),
    info_count = (SELECT COUNT(*) FROM alerts WHERE environment = '$ENVIRONMENT' AND severity = 'info' AND status = 'active'),
    resolved_count = (SELECT COUNT(*) FROM alerts WHERE environment = '$ENVIRONMENT' AND status = 'resolved' AND date(resolved_at) = '$today'),
    acknowledged_count = (SELECT COUNT(*) FROM alerts WHERE environment = '$ENVIRONMENT' AND status = 'acknowledged'),
    updated_at = '$(date -u +"%Y-%m-%dT%H:%M:%SZ")'
WHERE environment = '$ENVIRONMENT' AND stat_date = '$today';
EOF
}

# Function to create a new alert
create_alert() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log_info "Creating new $SEVERITY alert: $MESSAGE"
    if [[ "$VERBOSE" == "true" ]]; then
        log_debug "Alert type: $ALERT_TYPE"
        log_debug "Resource ID: ${RESOURCE_ID:-N/A}"
        log_debug "Service: ${SERVICE_NAME:-N/A}"
        log_debug "Environment: $ENVIRONMENT"
        log_debug "Region: ${REGION:-N/A}"
        if [[ "$DETAILS" != "{}" ]]; then
            log_debug "Details: $DETAILS"
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would create alert with the above parameters"
        return 0
    fi

    # Try API endpoint first if available
    if should_use_api; then
        create_alert_via_api
        return $?
    fi

    # Fall back to local database
    init_alerts_db

    # Insert alert into database with proper escaping
    local escaped_message
    local escaped_details
    escaped_message=$(echo "$MESSAGE" | sed "s/'/''/g")
    escaped_details=$(echo "$DETAILS" | sed "s/'/''/g")

    local result
    result=$(sqlite3 "$ALERTS_DB" <<EOF
INSERT INTO alerts (
    alert_type, resource_id, service_name, severity, message, details,
    status, created_at, environment, region
) VALUES (
    '$ALERT_TYPE',
    '${RESOURCE_ID:-}',
    '${SERVICE_NAME:-}',
    '$SEVERITY',
    '$escaped_message',
    '$escaped_details',
    'active',
    '$timestamp',
    '$ENVIRONMENT',
    '${REGION:-}'
);
SELECT last_insert_rowid();
EOF
    )

    if [[ -n "$result" && "$result" =~ ^[0-9]+$ ]]; then
        log_info "Alert created successfully with ID: $result"
        ALERT_ID="$result"

        # Send notification for the new alert
        send_alert_notification

        # Update statistics
        update_alert_statistics

        # Output in the requested format
        format_alert_output
    else
        log_error "Failed to create alert"
        return 1
    fi
}

# Function to create alert via API
create_alert_via_api() {
    # Prepare JSON payload
    local payload
    payload=$(cat <<EOF
{
    "alert_type": "$ALERT_TYPE",
    "resource_id": "${RESOURCE_ID:-null}",
    "service_name": "${SERVICE_NAME:-null}",
    "severity": "$SEVERITY",
    "message": "$MESSAGE",
    "details": $DETAILS,
    "environment": "$ENVIRONMENT",
    "region": "${REGION:-null}"
}
EOF
    )

    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Sending alert creation request to API"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            -d "$payload" \
            "$API_ENDPOINT" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            # Extract alert ID from response
            if command -v jq &>/dev/null; then
                ALERT_ID=$(echo "$response" | jq -r '.id')

                # Check for API error
                local error_message
                error_message=$(echo "$response" | jq -r '.error // empty')
                if [[ -n "$error_message" && "$error_message" != "null" ]]; then
                    log_error "API error: $error_message"
                    return 1
                fi
            else
                ALERT_ID=$(echo "$response" | grep -o '"id":[0-9]*' | cut -d':' -f2)
            fi

            if [[ -n "$ALERT_ID" && "$ALERT_ID" != "null" ]]; then
                log_info "Alert created successfully via API with ID: $ALERT_ID"

                # Output in the requested format
                if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                    echo "$response"
                else
                    format_alert_output
                fi
                return 0
            fi
        fi

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to create alert via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to acknowledge an alert
acknowledge_alert() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log_info "Acknowledging alert ID: $ALERT_ID"
    if [[ "$VERBOSE" == "true" ]]; then
        log_debug "Acknowledged by: ${ACKNOWLEDGED_BY:-system}"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would acknowledge alert ID: $ALERT_ID"
        return 0
    fi

    # Try API endpoint first if available
    if should_use_api; then
        acknowledge_alert_via_api
        return $?
    fi

    # Fall back to local database
    init_alerts_db

    # Check if the alert exists and is active
    local status
    status=$(sqlite3 "$ALERTS_DB" "SELECT status FROM alerts WHERE id = $ALERT_ID;")

    if [[ -z "$status" ]]; then
        log_error "Alert ID $ALERT_ID not found"
        return 1
    elif [[ "$status" != "active" ]]; then
        log_warning "Alert ID $ALERT_ID is not active (current status: $status)"

        if [[ "$status" == "acknowledged" ]]; then
            log_warning "Alert already acknowledged"
            return 0
        elif [[ "$status" == "resolved" ]]; then
            log_warning "Cannot acknowledge resolved alert"
            return 1
        fi
    fi

    # Update the alert status
    sqlite3 "$ALERTS_DB" <<EOF
UPDATE alerts SET
    status = 'acknowledged',
    acknowledged_by = '${ACKNOWLEDGED_BY:-system}',
    acknowledged_at = '$timestamp'
WHERE id = $ALERT_ID;
EOF

    log_info "Alert ID $ALERT_ID acknowledged successfully"

    # Update statistics
    update_alert_statistics

    # Output in the requested format
    format_alert_output
}

# Function to acknowledge alert via API
acknowledge_alert_via_api() {
    # Prepare JSON payload
    local payload
    payload=$(cat <<EOF
{
    "status": "acknowledged",
    "acknowledged_by": "${ACKNOWLEDGED_BY:-system}"
}
EOF
    )

    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Sending alert acknowledgment request to API"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X PATCH \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            -d "$payload" \
            "$API_ENDPOINT/$ALERT_ID" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            # Check for success response
            if command -v jq &>/dev/null; then
                local api_status=$(echo "$response" | jq -r '.status')
                local error_message=$(echo "$response" | jq -r '.error // empty')

                if [[ -n "$error_message" && "$error_message" != "null" ]]; then
                    log_error "API error: $error_message"
                    return 1
                }

                if [[ "$api_status" == "acknowledged" ]]; then
                    log_info "Alert ID $ALERT_ID acknowledged successfully via API"

                    # Output in the requested format
                    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                        echo "$response"
                    else
                        format_alert_output
                    fi
                    return 0
                fi
            else
                if echo "$response" | grep -q '"status":"acknowledged"'; then
                    log_info "Alert ID $ALERT_ID acknowledged successfully via API"
                    return 0
                }
            fi
        fi

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to acknowledge alert via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to resolve an alert
resolve_alert() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    log_info "Resolving alert ID: $ALERT_ID"
    if [[ "$VERBOSE" == "true" ]]; then
        log_debug "Resolution note: ${RESOLUTION_NOTE:-None provided}"
        log_debug "Resolved by: ${ACKNOWLEDGED_BY:-system}"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would resolve alert ID: $ALERT_ID"
        return 0
    fi

    # Try API endpoint first if available
    if should_use_api; then
        resolve_alert_via_api
        return $?
    fi

    # Fall back to local database
    init_alerts_db

    # Check if the alert exists and is not already resolved
    local status
    status=$(sqlite3 "$ALERTS_DB" "SELECT status FROM alerts WHERE id = $ALERT_ID;")

    if [[ -z "$status" ]]; then
        log_error "Alert ID $ALERT_ID not found"
        return 1
    elif [[ "$status" == "resolved" ]]; then
        log_warning "Alert ID $ALERT_ID is already resolved"
        return 0
    fi

    # Escape the resolution note for SQL
    local escaped_note
    escaped_note=$(echo "${RESOLUTION_NOTE:-}" | sed "s/'/''/g")

    # Update the alert status
    sqlite3 "$ALERTS_DB" <<EOF
UPDATE alerts SET
    status = 'resolved',
    resolved_by = '${ACKNOWLEDGED_BY:-system}',
    resolved_at = '$timestamp',
    resolution_note = '$escaped_note'
WHERE id = $ALERT_ID;
EOF

    log_info "Alert ID $ALERT_ID resolved successfully"

    # Update statistics
    update_alert_statistics

    # Output in the requested format
    format_alert_output
}

# Function to resolve alert via API
resolve_alert_via_api() {
    # Prepare JSON payload
    local payload
    payload=$(cat <<EOF
{
    "status": "resolved",
    "resolved_by": "${ACKNOWLEDGED_BY:-system}",
    "resolution_note": "${RESOLUTION_NOTE:-}"
}
EOF
    )

    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Sending alert resolution request to API"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X PATCH \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            -d "$payload" \
            "$API_ENDPOINT/$ALERT_ID" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            # Check for success response
            if command -v jq &>/dev/null; then
                local api_status=$(echo "$response" | jq -r '.status')
                local error_message=$(echo "$response" | jq -r '.error // empty')

                if [[ -n "$error_message" && "$error_message" != "null" ]]; then
                    log_error "API error: $error_message"
                    return 1
                }

                if [[ "$api_status" == "resolved" ]]; then
                    log_info "Alert ID $ALERT_ID resolved successfully via API"

                    # Output in the requested format
                    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                        echo "$response"
                    else
                        format_alert_output
                    fi
                    return 0
                fi
            else
                if echo "$response" | grep -q '"status":"resolved"'; then
                    log_info "Alert ID $ALERT_ID resolved successfully via API"
                    return 0
                }
            fi
        fi

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to resolve alert via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to list alerts
list_alerts() {
    local where_clause=""
    local query=""
    local filter_status="${STATUS:-active}"

    # Apply filters based on parameters
    if [[ -n "$SEVERITY" && "$SEVERITY" != "all" ]]; then
        where_clause+=" AND severity = '$SEVERITY'"
    fi

    if [[ -n "$SERVICE_NAME" ]]; then
        where_clause+=" AND service_name = '$SERVICE_NAME'"
    fi

    if [[ -n "$RESOURCE_ID" ]]; then
        where_clause+=" AND resource_id = '$RESOURCE_ID'"
    fi

    if [[ -n "$ENVIRONMENT" && "$ENVIRONMENT" != "all" ]]; then
        where_clause+=" AND environment = '$ENVIRONMENT'"
    fi

    if [[ -n "$REGION" ]]; then
        where_clause+=" AND region = '$REGION'"
    fi

    log_info "Listing $filter_status alerts with filters: ${where_clause:+$where_clause}"

    # Try API endpoint first if available
    if should_use_api; then
        list_alerts_via_api
        return $?
    fi

    # Fall back to local database
    init_alerts_db

    # Build query based on output format
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        query="SELECT json_group_array(json_object(
            'id', id,
            'alert_type', alert_type,
            'resource_id', resource_id,
            'service_name', service_name,
            'severity', severity,
            'message', message,
            'details', details,
            'status', status,
            'created_at', created_at,
            'environment', environment,
            'region', region,
            'acknowledged_by', acknowledged_by,
            'acknowledged_at', acknowledged_at,
            'resolved_by', resolved_by,
            'resolved_at', resolved_at,
            'resolution_note', resolution_note
        )) FROM alerts WHERE status = '$filter_status'${where_clause} ORDER BY created_at DESC;"
    elif [[ "$OUTPUT_FORMAT" == "csv" ]]; then
        echo "id,alert_type,resource_id,service_name,severity,message,status,created_at,environment,region"
        query="SELECT id, alert_type, resource_id, service_name, severity, message, status, created_at, environment, region
        FROM alerts WHERE status = '$filter_status'${where_clause} ORDER BY created_at DESC;"
    else
        query="SELECT id, alert_type, severity, status, created_at, message
        FROM alerts WHERE status = '$filter_status'${where_clause} ORDER BY created_at DESC;"
    fi

    # Execute query
    local result
    result=$(sqlite3 -header -column "$ALERTS_DB" "$query")

    # Check if we got any results
    if [[ -z "$result" || "$(echo "$result" | wc -l)" -le 1 ]]; then
        echo "No alerts found matching the specified criteria."
        return 0
    }

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo "$result"
    elif [[ "$OUTPUT_FORMAT" == "csv" ]]; then
        echo "$result" | sed 's/|/,/g'
    else
        echo "$result"

        # Show count summary
        local count
        count=$(echo "$result" | tail -n +2 | wc -l)
        echo -e "\nTotal: $count alerts"
    fi
}

# Function to list alerts via API
list_alerts_via_api() {
    # Build query parameters
    local filter_status="${STATUS:-active}"
    local query_params="status=$filter_status"

    if [[ -n "$SEVERITY" && "$SEVERITY" != "all" ]]; then
        query_params+="&severity=$SEVERITY"
    fi

    if [[ -n "$SERVICE_NAME" ]]; then
        query_params+="&service_name=$SERVICE_NAME"
    fi

    if [[ -n "$RESOURCE_ID" ]]; then
        query_params+="&resource_id=$RESOURCE_ID"
    fi

    if [[ -n "$ENVIRONMENT" && "$ENVIRONMENT" != "all" ]]; then
        query_params+="&environment=$ENVIRONMENT"
    fi

    if [[ -n "$REGION" ]]; then
        query_params+="&region=$REGION"
    fi

    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Fetching alerts from API with params: $query_params"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X GET \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            "$API_ENDPOINT?$query_params" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            # Check for API error
            if command -v jq &>/dev/null; then
                local error_message
                error_message=$(echo "$response" | jq -r '.error // empty')
                if [[ -n "$error_message" && "$error_message" != "null" ]]; then
                    log_error "API error: $error_message"
                    return 1
                fi

                # Check if the response is an empty array
                if [[ $(echo "$response" | jq '. | length') -eq 0 ]]; then
                    echo "No alerts found matching the specified criteria."
                    return 0
                }
            fi

            # Format and output based on requested format
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                echo "$response"
            elif [[ "$OUTPUT_FORMAT" == "csv" ]]; then
                # Convert JSON to CSV if jq is available
                if command -v jq &>/dev/null; then
                    echo "id,alert_type,resource_id,service_name,severity,message,status,created_at,environment,region"
                    echo "$response" | jq -r '.[] | [.id, .alert_type, .resource_id, .service_name, .severity, .message, .status, .created_at, .environment, .region] | @csv'
                else
                    log_warning "jq command not available for JSON to CSV conversion"
                    echo "$response"
                fi
            else
                # Text format output
                if command -v jq &>/dev/null; then
                    echo "ID     TYPE             SEVERITY  STATUS       CREATED                MESSAGE"
                    echo "----- ---------------- --------- ------------ ---------------------- ------------------------------"
                    echo "$response" | jq -r '.[] | [.id, .alert_type, .severity, .status, .created_at, .message] | "\\(.[:4] | tostring | .[0:5] | .[0:] + " " * (5 - .[0:] | length)) \\(.[:1] | .[0:16] | .[0:] + " " * (16 - .[0:] | length)) \\(.[:2] | .[0:9] | .[0:] + " " * (9 - .[0:] | length)) \\(.[:3] | .[0:12] | .[0:] + " " * (12 - .[0:] | length)) \\(.[:4] | .[0:22] | .[0:] + " " * (22 - .[0:] | length)) \\(.[:5] | .[0:30])"'

                    # Show count summary
                    local count
                    count=$(echo "$response" | jq '. | length')
                    echo -e "\nTotal: $count alerts"
                else
                    log_warning "jq command not available for formatting"
                    echo "$response"
                fi
            fi
            return 0
        fi

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to list alerts via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to get details of a specific alert
get_alert() {
    log_info "Getting details for alert ID: $ALERT_ID"

    # Try API endpoint first if available
    if should_use_api; then
        get_alert_via_api
        return $?
    fi

    # Fall back to local database
    init_alerts_db

    # Build query based on output format
    local query=""

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        query="SELECT json_object(
            'id', id,
            'alert_type', alert_type,
            'resource_id', resource_id,
            'service_name', service_name,
            'severity', severity,
            'message', message,
            'details', details,
            'status', status,
            'created_at', created_at,
            'environment', environment,
            'region', region,
            'acknowledged_by', acknowledged_by,
            'acknowledged_at', acknowledged_at,
            'resolved_by', resolved_by,
            'resolved_at', resolved_at,
            'resolution_note', resolution_note
        ) FROM alerts WHERE id = $ALERT_ID;"
    else
        query="SELECT * FROM alerts WHERE id = $ALERT_ID;"
    fi

    # Execute query
    local result
    result=$(sqlite3 -header -column "$ALERTS_DB" "$query")

    if [[ -z "$result" ]]; then
        log_error "Alert ID $ALERT_ID not found"
        return 1
    fi

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo "$result"
    else
        echo "$result"
    fi
}

# Function to get alert via API
get_alert_via_api() {
    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Fetching alert details from API for ID: $ALERT_ID"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X GET \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            "$API_ENDPOINT/$ALERT_ID" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            # Check if the response contains an error
            if command -v jq &>/dev/null && echo "$response" | jq -e 'has("error")' &>/dev/null; then
                log_error "API returned an error: $(echo "$response" | jq -r '.error')"
                return 1
            fi

            # Output based on requested format
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                echo "$response"
            else
                # Format as text
                if command -v jq &>/dev/null; then
                    echo -e "\nAlert Details:"
                    echo "$response" | jq -r 'to_entries | .[] | "  \(.key): \(.value)"'
                else
                    echo "$response" | tr '{},":' '\n    ' | sed 's/^[ \t]*//'
                fi
            fi
            return 0
        fi

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to get alert details via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to enable/disable alerts for a service
manage_service_alerts() {
    local action_desc="$ACTION"
    local enabled="true"

    if [[ "$ACTION" == "disable" ]]; then
        enabled="false"
        action_desc="disable"
    fi

    log_info "${action_desc^} alerts for service: $SERVICE_NAME in $ENVIRONMENT environment"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would $action_desc alerts for $SERVICE_NAME"
        return 0
    fi

    # Try API endpoint first if available
    if should_use_api; then
        service_alerts_via_api
        return $?
    fi

    # Fall back to local configuration
    local config_file="${CONFIG_DIR}/environments/${ENVIRONMENT}.conf"
    if [[ ! -f "$config_file" ]]; then
        config_file="${CONFIG_DIR}/alerts.conf"

        if [[ ! -f "$config_file" ]]; then
            # Create config file if it doesn't exist
            log_info "Configuration file not found, creating new file at $config_file"
            mkdir -p "$(dirname "$config_file")"
            touch "$config_file" || {
                log_error "Failed to create configuration file: $config_file"
                return 1
            }
        }
    fi

    # Make a backup of the config file
    cp "$config_file" "${config_file}.bak" || {
        log_error "Failed to backup configuration file"
        return 1
    }

    # Check if interactive mode is enabled and ask for confirmation
    if [[ "$INTERACTIVE" == true && "$FORCE" != true ]]; then
        read -p "Are you sure you want to $action_desc alerts for service $SERVICE_NAME? (y/N): " response
        case "$response" in
            [yY][eE][sS]|[yY])
                # Continue with operation
                ;;
            *)
                log_info "Operation cancelled by user"
                return 0
                ;;
        esac
    fi

    # Update the configuration
    local service_var="${SERVICE_NAME}_alerts_enabled"
    if grep -q "^${service_var}=" "$config_file"; then
        # Update existing configuration
        sed -i "s/^${service_var}=.*/${service_var}=${enabled}/" "$config_file"
    else
        # Add new configuration
        echo "${service_var}=${enabled}" >> "$config_file"
    fi

    log_info "Alerts for service $SERVICE_NAME ${action_desc}d successfully"

    # Reload service configuration if running in a production environment
    if [[ "$ENVIRONMENT" == "production" || "$ENVIRONMENT" == "dr-recovery" ]]; then
        log_info "Reloading monitoring service configuration..."

        if command -v systemctl &>/dev/null && systemctl is-active --quiet monitoring.service; then
            systemctl reload monitoring.service || log_warning "Failed to reload monitoring service"
        else
            log_warning "Monitoring service not running or not using systemd"
        fi
    }

    # Update database to reflect service alert status
    if [[ -f "$ALERTS_DB" ]]; then
        if [[ "$enabled" == "false" ]]; then
            log_info "Updating database to reflect disabled service alerts"
            # Add a note to active alerts for this service
            sqlite3 "$ALERTS_DB" <<EOF
UPDATE alerts
SET
    status = 'acknowledged',
    acknowledged_by = 'system',
    acknowledged_at = '$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
    resolution_note = 'Auto-acknowledged: Alerts for service $SERVICE_NAME have been disabled'
WHERE
    service_name = '$SERVICE_NAME' AND
    environment = '$ENVIRONMENT' AND
    status = 'active';
EOF
        }
    }

    return 0
}

# Function to manage service alerts via API
service_alerts_via_api() {
    # Prepare JSON payload
    local payload
    payload=$(cat <<EOF
{
    "service": "$SERVICE_NAME",
    "environment": "$ENVIRONMENT",
    "enabled": $([[ "$ACTION" == "enable" ]] && echo "true" || echo "false")
}
EOF
    )

    # Make API request with retry logic
    local response
    local retry_count=0
    log_debug "Sending service alerts configuration request to API"

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        response=$(curl -s -X PUT \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            -d "$payload" \
            "$API_ENDPOINT/service/configuration" 2>/dev/null)

        local status=$?
        if [[ $status -eq 0 && -n "$response" ]]; then
            if command -v jq &>/dev/null && echo "$response" | jq -e 'has("success") and .success == true' &>/dev/null; then
                log_info "Service alerts configuration updated successfully via API"
                return 0
            elif echo "$response" | grep -q '"success":true'; then
                log_info "Service alerts configuration updated successfully via API"
                return 0
            fi

            # Check for error message
            if command -v jq &>/dev/null; then
                local error_message
                error_message=$(echo "$response" | jq -r '.error // empty')
                if [[ -n "$error_message" && "$error_message" != "null" ]]; then
                    log_error "API error: $error_message"
                    return 1
                }
            }
        }

        # Handle retry
        ((retry_count++))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            local wait_time=$((retry_count * 2))
            log_warning "API request failed (attempt $retry_count/$MAX_RETRIES). Retrying in $wait_time seconds..."
            sleep $wait_time
        fi
    done

    log_error "Failed to update service alerts configuration via API after $MAX_RETRIES attempts"
    log_debug "Last API response: $response"
    return 1
}

# Function to run a test alert
test_alert() {
    log_info "Running alert system test"

    # Generate test alert parameters
    ALERT_TYPE="test_alert"
    RESOURCE_ID="test-resource-$(date +%s)"
    SERVICE_NAME="test"
    SEVERITY="info"
    MESSAGE="This is a test alert generated at $(date)"
    DETAILS="{\"test_run\": true, \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}"

    create_alert
    local create_status=$?

    # If alert was created successfully, also test acknowledgment and resolution
    if [[ $create_status -eq 0 && -n "$ALERT_ID" ]]; then
        log_info "Testing alert acknowledgment"
        ACKNOWLEDGED_BY="test-user"
        acknowledge_alert
        local ack_status=$?

        log_info "Testing alert resolution"
        RESOLUTION_NOTE="Test alert automatically resolved"
        resolve_alert
        local res_status=$?

        if [[ $ack_status -eq 0 && $res_status -eq 0 ]]; then
            log_info "Alert system test completed successfully"
            return 0
        } else {
            log_warning "Alert system test completed with some issues"
            return 1
        }
    } else {
        log_error "Alert system test failed at alert creation step"
        return 1
    }
}

# Function to process batch operations
process_batch() {
    log_info "Processing batch operations from file: $BATCH_FILE"

    if [[ ! -f "$BATCH_FILE" ]]; then
        log_error "Batch file not found: $BATCH_FILE"
        return 1
    fi

    local line_num=0
    local success_count=0
    local fail_count=0
    local total_lines=0

    # First count the number of non-comment, non-empty lines
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            ((total_lines++))
        fi
    done < "$BATCH_FILE"

    log_info "Found $total_lines operations to process"

    # Process each line
    while IFS=, read -r action params; do
        ((line_num++))

        # Skip empty lines and comments
        if [[ -z "$action" || "$action" =~ ^[[:space:]]*# ]]; then
            continue
        fi

        log_info "Processing batch operation $line_num/$total_lines: $action"
        if [[ "$VERBOSE" == "true" ]]; then
            log_debug "Parameters: $params"
        fi

        # Execute according to action
        case "$action" in
            create)
                # Parse parameters: type,resource_id,service,severity,message
                IFS=',' read -r batch_type batch_resource batch_service batch_severity batch_message <<< "$params"

                # Set parameters for action
                ALERT_TYPE="$batch_type"
                RESOURCE_ID="$batch_resource"
                SERVICE_NAME="$batch_service"
                SEVERITY="$batch_severity"
                MESSAGE="$batch_message"
                DETAILS="{}"

                # Execute action
                if create_alert; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            acknowledge)
                # Parse parameters: alert_id,acknowledged_by
                IFS=',' read -r batch_id batch_user <<< "$params"

                # Set parameters for action
                ALERT_ID="$batch_id"
                ACKNOWLEDGED_BY="$batch_user"

                # Execute action
                if acknowledge_alert; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            resolve)
                # Parse parameters: alert_id,resolution_note
                IFS=',' read -r batch_id batch_note <<< "$params"

                # Set parameters for action
                ALERT_ID="$batch_id"
                RESOLUTION_NOTE="$batch_note"

                # Execute action
                if resolve_alert; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            enable|disable)
                # Parse parameters: service_name
                local batch_service="$params"

                # Set parameters for action
                ACTION="$action"
                SERVICE_NAME="$batch_service"

                # Execute action
                if manage_service_alerts; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                ;;
            *)
                log_warning "Unknown action in batch file at line $line_num: $action"
                ((fail_count++))
                ;;
        esac
    done < "$BATCH_FILE"

    log_info "Batch processing completed: $success_count successful operations, $fail_count failures (out of $total_lines total)"

    if [[ $fail_count -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

# Function to format alert output
format_alert_output() {
    # Get alert details for formatting
    local details

    if should_use_api; then
        details=$(curl -s -X GET \
            -H "Authorization: Bearer ${API_TOKEN:-}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            "$API_ENDPOINT/$ALERT_ID" 2>/dev/null)
    else
        details=$(sqlite3 -json "$ALERTS_DB" "SELECT * FROM alerts WHERE id = $ALERT_ID;")
    fi

    if [[ -z "$details" ]]; then
        log_warning "Could not retrieve alert details for formatting"
        return 1
    fi

    case "$OUTPUT_FORMAT" in
        json)
            echo "$details"
            ;;
        csv)
            if command -v jq &>/dev/null; then
                echo "id,alert_type,resource_id,service_name,severity,message,status,created_at,environment,region"
                echo "$details" | jq -r '. | [.id, .alert_type, .resource_id, .service_name, .severity, .message, .status, .created_at, .environment, .region] | @csv'
            else
                # Simplified CSV output without jq
                local id type severity status created message
                id=$(echo "$details" | grep -o '"id":[^,]*' | cut -d':' -f2 | tr -d '"')
                type=$(echo "$details" | grep -o '"alert_type":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                severity=$(echo "$details" | grep -o '"severity":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                status=$(echo "$details" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                created=$(echo "$details" | grep -o '"created_at":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                message=$(echo "$details" | grep -o '"message":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                echo "$id,$type,,$severity,$message,$status,$created"
            fi
            ;;
        *)
            # Text format
            if command -v jq &>/dev/null; then
                echo "$details" | jq -r '"\nAlert Details:\n  ID: \(.id)\n  Type: \(.alert_type)\n  Severity: \(.severity)\n  Status: \(.status)\n  Created: \(.created_at)\n  Message: \(.message)\n  Resource: \(.resource_id // "N/A")\n  Service: \(.service_name // "N/A")\n  Environment: \(.environment)\n  Region: \(.region // "N/A")"'
            else
                # Simplified text output without jq
                local id type severity status created message resource service env region
                id=$(echo "$details" | grep -o '"id":[^,]*' | cut -d':' -f2 | tr -d '"')
                type=$(echo "$details" | grep -o '"alert_type":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                severity=$(echo "$details" | grep -o '"severity":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                status=$(echo "$details" | grep -o '"status":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                created=$(echo "$details" | grep -o '"created_at":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                message=$(echo "$details" | grep -o '"message":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                resource=$(echo "$details" | grep -o '"resource_id":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                service=$(echo "$details" | grep -o '"service_name":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                env=$(echo "$details" | grep -o '"environment":"[^"]*"' | cut -d':' -f2 | tr -d '"')
                region=$(echo "$details" | grep -o '"region":"[^"]*"' | cut -d':' -f2 | tr -d '"')

                echo -e "\nAlert Details:"
                echo "  ID: $id"
                echo "  Type: $type"
                echo "  Severity: $severity"
                echo "  Status: $status"
                echo "  Created: $created"
                echo "  Message: $message"
                echo "  Resource: ${resource:-N/A}"
                echo "  Service: ${service:-N/A}"
                echo "  Environment: $env"
                echo "  Region: ${region:-N/A}"
            fi
            ;;
    esac
}

# Function to send alert notification
send_alert_notification() {
    if [[ -z "$ALERT_ID" ]]; then
        log_warning "Cannot send notification: Alert ID not set"
        return 1
    fi

    log_debug "Preparing to send alert notification for Alert ID: $ALERT_ID"

    # Get environment variables
    local email_recipient="${EMAIL_RECIPIENT:-}"
    local slack_webhook="${SLACK_WEBHOOK_URL:-}"
    local teams_webhook="${TEAMS_WEBHOOK_URL:-}"

    # Skip if no notification channels configured
    if [[ -z "$email_recipient" && -z "$slack_webhook" && -z "$teams_webhook" ]]; then
        log_debug "No notification channels configured, skipping notification"
        return 0
    fi

    # Get alert details for notification
    local alert_details severity_color
    if command -v jq &>/dev/null; then
        if should_use_api; then
            alert_details=$(curl -s -X GET \
                -H "Authorization: Bearer ${API_TOKEN:-}" \
                --connect-timeout "$TIMEOUT" \
                --max-time $((TIMEOUT * 2)) \
                "$API_ENDPOINT/$ALERT_ID" 2>/dev/null)
        else
            alert_details=$(sqlite3 -json "$ALERTS_DB" "SELECT * FROM alerts WHERE id = $ALERT_ID;")
        fi
    fi

    # Set color based on severity
    case "$SEVERITY" in
        critical) severity_color="#FF0000" ;; # Red
        warning)  severity_color="#FFA500" ;; # Orange
        info)     severity_color="#0000FF" ;; # Blue
        *)        severity_color="#808080" ;; # Gray
    esac

    # Use notification script if available
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        local priority="low"
        case "$SEVERITY" in
            critical) priority="high" ;;
            warning) priority="medium" ;;
        esac

        # Build alert message
        local subject="[$SEVERITY] Alert: $MESSAGE"
        local message="Alert Details:
ID: $ALERT_ID
Type: $ALERT_TYPE
Severity: $SEVERITY
Environment: $ENVIRONMENT"

        if [[ -n "$RESOURCE_ID" ]]; then
            message+="\nResource: $RESOURCE_ID"
        fi
        if [[ -n "$SERVICE_NAME" ]]; then
            message+="\nService: $SERVICE_NAME"
        fi
        if [[ -n "$REGION" ]]; then
            message+="\nRegion: $REGION"
        fi
        message+="\nTime: $(date)\nMessage: $MESSAGE"

        # Send notification
        "${PROJECT_ROOT}/scripts/utils/send-notification.sh" \
            --priority "$priority" \
            --subject "$subject" \
            --message "$message" \
            --recipient "$email_recipient" || log_warning "Failed to send notification"

        log_debug "Alert notification sent"
    else
        log_debug "No notification utility script available"

        # Basic email notification fallback
        if [[ -n "$email_recipient" ]] && command -v mail &>/dev/null; then
            log_debug "Sending notification via email to $email_recipient"
            local email_body="Alert ID: $ALERT_ID
Type: $ALERT_TYPE
Severity: $SEVERITY
Message: $MESSAGE
Environment: $ENVIRONMENT"

            if [[ -n "$RESOURCE_ID" ]]; then
                email_body+="\nResource: $RESOURCE_ID"
            fi
            if [[ -n "$SERVICE_NAME" ]]; then
                email_body+="\nService: $SERVICE_NAME"
            fi
            if [[ -n "$REGION" ]]; then
                email_body+="\nRegion: $REGION"
            fi
            email_body+="\nTime: $(date)"

            echo -e "$email_body" | mail -s "[$SEVERITY] Alert: $MESSAGE" "$email_recipient"
            log_debug "Email notification sent to $email_recipient"
        fi

        # Slack notification
        if [[ -n "$slack_webhook" ]] && command -v curl &>/dev/null; then
            log_debug "Sending notification via Slack"
            local slack_payload
            slack_payload=$(cat <<EOF
{
    "attachments": [
        {
            "color": "$severity_color",
            "title": "[$SEVERITY] Alert: $MESSAGE",
            "text": "Alert ID: $ALERT_ID\nType: $ALERT_TYPE\nEnvironment: $ENVIRONMENT\nTime: $(date)",
            "fields": [
                {"title": "Severity", "value": "$SEVERITY", "short": true},
                {"title": "Environment", "value": "$ENVIRONMENT", "short": true}
            ],
            "footer": "Cloud Infrastructure Platform"
        }
    ]
}
EOF
            )

            curl -s -X POST -H "Content-Type: application/json" \
                --connect-timeout "$TIMEOUT" \
                --data "$slack_payload" \
                "$slack_webhook" &>/dev/null || log_warning "Failed to send Slack notification"
        fi

        # Microsoft Teams notification
        if [[ -n "$teams_webhook" ]] && command -v curl &>/dev/null; then
            log_debug "Sending notification via Microsoft Teams"
            local teams_payload
            teams_payload=$(cat <<EOF
{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "${severity_color//#/}",
    "summary": "[$SEVERITY] Alert: $MESSAGE",
    "sections": [
        {
            "activityTitle": "[$SEVERITY] Alert: $MESSAGE",
            "facts": [
                { "name": "Alert ID", "value": "$ALERT_ID" },
                { "name": "Type", "value": "$ALERT_TYPE" },
                { "name": "Severity", "value": "$SEVERITY" },
                { "name": "Environment", "value": "$ENVIRONMENT" },
                { "name": "Time", "value": "$(date)" }
            ],
            "text": "$MESSAGE"
        }
    ]
}
EOF
            )

            curl -s -X POST -H "Content-Type: application/json" \
                --connect-timeout "$TIMEOUT" \
                --data "$teams_payload" \
                "$teams_webhook" &>/dev/null || log_warning "Failed to send Teams notification"
        fi
    fi

    return 0
}

# Function to check if API should be used
should_use_api() {
    # Check if API token is available
    if [[ -n "${API_TOKEN:-}" ]]; then
        # Test API connectivity
        if curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer ${API_TOKEN}" \
            --connect-timeout "$TIMEOUT" \
            --max-time $((TIMEOUT * 2)) \
            "${API_ENDPOINT}/health" 2>/dev/null | grep -q "2[0-9][0-9]"; then
            return 0
        fi
    fi
    return 1
}

# Main execution function
main() {
    # Parse command line arguments
    parse_arguments "$@"

    # Validate parameters
    validate_parameters

    # Load configuration
    load_config

    # Initialize alert tracking system
    if [[ "$ACTION" != "list" && "$ACTION" != "get" ]]; then
        log_script_start
    fi

    # Execute the requested action
    local exit_code=0
    case "$ACTION" in
        create)
            create_alert
            exit_code=$?
            ;;
        acknowledge)
            acknowledge_alert
            exit_code=$?
            ;;
        resolve)
            resolve_alert
            exit_code=$?
            ;;
        list)
            list_alerts
            exit_code=$?
            ;;
        get)
            get_alert
            exit_code=$?
            ;;
        enable|disable)
            manage_service_alerts
            exit_code=$?
            ;;
        test)
            test_alert
            exit_code=$?
            ;;
        batch)
            process_batch
            exit_code=$?
            ;;
        *)
            log_error "No action specified"
            usage
            exit_code=1
            ;;
    esac

    if [[ "$ACTION" != "list" && "$ACTION" != "get" ]]; then
        log_script_end "$([[ $exit_code -eq 0 ]] && echo "completed" || echo "failed")"
    fi

    exit $exit_code
}

# Execute main if script is not being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
