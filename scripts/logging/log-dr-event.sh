#!/bin/bash
# DR Event Logging Script for Cloud Infrastructure Platform
# Purpose: Log disaster recovery events to a standardized format for audit and tracking
# Usage: ./log-dr-event.sh --type <event_type> --status <status> [--region <region>] [--detail <details>]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
LOG_FILE="${LOG_DIR}/dr-events.log"
FORMATTED_DATE=$(date '+%Y-%m-%d %H:%M:%S')
EVENT_TYPE=""
STATUS=""
REGION=""
DETAILS=""
ENVIRONMENT="production"
HOSTNAME=$(hostname)

# Ensure log directory exists
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Function to log messages to stdout
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1"
}

# Function to display usage information
usage() {
    echo "Usage: $0 --type <event_type> --status <status> [--region <region>] [--detail <details>] [--environment <env>]"
    echo ""
    echo "Options:"
    echo "  --type <event_type>       Type of DR event (required)"
    echo "                           Valid types: FAILOVER, RECOVERY, REPLICATION_CHECK,"
    echo "                           HEALTH_CHECK, SMOKE_TEST, INFRASTRUCTURE_DEPLOYMENT,"
    echo "                           DB_VERIFY, FILE_VERIFICATION, MONITORING_UPDATE"
    echo "  --status <status>         Status of the event (required)"
    echo "                           Valid statuses: SUCCESS, FAILURE, STARTED, COMPLETED,"
    echo "                           WARNING, HEALTHY, UNHEALTHY"
    echo "  --region <region>         Region for the event (optional)"
    echo "                           Valid regions: primary, secondary"
    echo "  --detail <details>        Additional details about the event (optional)"
    echo "  --environment <env>       Environment (default: production)"
    echo "  --help                    Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 --type RECOVERY --status COMPLETED --region secondary --detail 'All systems operational'"
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --type)
            EVENT_TYPE="${2^^}" # Convert to uppercase
            shift
            shift
            ;;
        --status)
            STATUS="${2^^}" # Convert to uppercase
            shift
            shift
            ;;
        --region)
            REGION="${2,,}" # Convert to lowercase
            shift
            shift
            ;;
        --detail)
            DETAILS="$2"
            shift
            shift
            ;;
        --environment)
            ENVIRONMENT="${2,,}" # Convert to lowercase
            shift
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log "ERROR: Unknown option: $key"
            usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$EVENT_TYPE" ]; then
    log "ERROR: Event type is required"
    usage
    exit 1
fi

if [ -z "$STATUS" ]; then
    log "ERROR: Status is required"
    usage
    exit 1
fi

# Validate event type
valid_event_types=(
    "FAILOVER" "RECOVERY" "REPLICATION_CHECK" "HEALTH_CHECK" 
    "SMOKE_TEST" "INFRASTRUCTURE_DEPLOYMENT" "DB_VERIFY" 
    "FILE_VERIFICATION" "MONITORING_UPDATE"
)

valid_type=false
for valid_type_value in "${valid_event_types[@]}"; do
    if [ "$EVENT_TYPE" = "$valid_type_value" ]; then
        valid_type=true
        break
    fi
done

if [ "$valid_type" = "false" ]; then
    log "ERROR: Invalid event type: $EVENT_TYPE"
    usage
    exit 1
fi

# Validate status
valid_statuses=(
    "SUCCESS" "FAILURE" "STARTED" "COMPLETED" 
    "WARNING" "HEALTHY" "UNHEALTHY"
)

valid_status=false
for valid_status_value in "${valid_statuses[@]}"; do
    if [ "$STATUS" = "$valid_status_value" ]; then
        valid_status=true
        break
    fi
done

if [ "$valid_status" = "false" ]; then
    log "ERROR: Invalid status: $STATUS"
    usage
    exit 1
fi

# Validate region if provided
if [ -n "$REGION" ]; then
    if [ "$REGION" != "primary" ] && [ "$REGION" != "secondary" ]; then
        log "ERROR: Invalid region: $REGION. Must be 'primary' or 'secondary'"
        usage
        exit 1
    fi
fi

# Create log entry
LOG_ENTRY="${FORMATTED_DATE},${EVENT_TYPE},${ENVIRONMENT}"

# Add region if provided
if [ -n "$REGION" ]; then
    LOG_ENTRY="${LOG_ENTRY},${REGION}"
else
    LOG_ENTRY="${LOG_ENTRY},unknown"
fi

# Add status and hostname
LOG_ENTRY="${LOG_ENTRY},${STATUS},${HOSTNAME}"

# Add details if provided
if [ -n "$DETAILS" ]; then
    # Escape commas in details to avoid breaking CSV format
    ESCAPED_DETAILS=$(echo "$DETAILS" | sed 's/,/;/g')
    LOG_ENTRY="${LOG_ENTRY},\"${ESCAPED_DETAILS}\""
fi

# Make sure log directory is writable
if [ ! -w "$LOG_DIR" ]; then
    log "ERROR: Log directory $LOG_DIR is not writable"
    exit 1
fi

# Write to log file
echo "$LOG_ENTRY" >> "$LOG_FILE" || {
    log "ERROR: Failed to write to log file $LOG_FILE"
    exit 1
}

# Set proper permissions on the log file
chmod 640 "$LOG_FILE" 2>/dev/null || log "WARNING: Failed to set permissions on log file"

# Log success
log "DR event logged: $EVENT_TYPE - $STATUS"

# For certain event types, also log to system journal for better visibility
if [[ "$EVENT_TYPE" == "FAILOVER" || "$EVENT_TYPE" == "RECOVERY" ]]; then
    if command -v logger &> /dev/null; then
        logger -p local0.notice -t "dr-event" "DR Event: $EVENT_TYPE - $STATUS ${REGION:+in $REGION region}"
    fi
fi

# For critical events, notify administrators
if [[ "$EVENT_TYPE" == "FAILOVER" || "$STATUS" == "FAILURE" ]]; then
    NOTIFICATION_SCRIPT="${PROJECT_ROOT}/scripts/utils/send-notification.sh"
    if [ -x "$NOTIFICATION_SCRIPT" ]; then
        priority="high"
        if [ "$STATUS" == "FAILURE" ]; then
            priority="critical"
        fi
        
        "$NOTIFICATION_SCRIPT" \
            --priority "$priority" \
            --subject "DR Event: $EVENT_TYPE - $STATUS ${REGION:+in $REGION region}" \
            --message "Disaster Recovery event logged at $FORMATTED_DATE
Type: $EVENT_TYPE
Status: $STATUS
${REGION:+Region: $REGION}
${DETAILS:+Details: $DETAILS}
Environment: $ENVIRONMENT
Server: $HOSTNAME" \
            || log "WARNING: Failed to send notification"
    fi
fi

# For completed events, determine if a report should be generated
if [[ "$STATUS" == "COMPLETED" && ("$EVENT_TYPE" == "FAILOVER" || "$EVENT_TYPE" == "RECOVERY") ]]; then
    REPORT_SCRIPT="${PROJECT_ROOT}/scripts/reporting/generate-dr-report.sh"
    if [ -x "$REPORT_SCRIPT" ]; then
        log "Generating DR event report..."
        "$REPORT_SCRIPT" \
            --event-type "$EVENT_TYPE" \
            --region "${REGION:-unknown}" \
            --timestamp "$FORMATTED_DATE" \
            || log "WARNING: Failed to generate DR event report"
    fi
fi

exit 0