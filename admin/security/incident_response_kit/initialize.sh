#!/bin/bash
# filepath: admin/security/incident_response_kit/initialize.sh
#
# Incident Response Kit - Incident Initialization Script
#
# This script provides a command-line interface for initializing security incidents.
# It creates the necessary directory structure, performs initial documentation,
# and sets up tracking for the incident response process.
#
# Usage:
#   ./initialize.sh --incident-id IR-2023-001 --type malware --severity high --lead-responder "security-analyst@example.com"
#
# Required arguments:
#   --incident-id        Unique identifier for the incident
#   --type               Type of incident (malware, data_breach, unauthorized_access, etc.)
#
# Optional arguments:
#   --severity           Severity level (critical, high, medium, low) [default: medium]
#   --description        Brief description of the incident
#   --lead-responder     Email/name of the lead responder
#   --evidence-dir       Custom evidence directory
#   --metadata           Additional metadata in key=value format (comma-separated)
#   --no-documentation   Skip creation of initial documentation
#   --no-tracking        Skip incident tracking initialization
#   --no-notification    Skip sending notifications
#   --help               Show this help message
#
# Examples:
#   ./initialize.sh --incident-id IR-2023-001 --type malware --severity high --lead-responder "security-analyst@example.com"
#   ./initialize.sh --incident-id IR-2023-002 --type data_breach --description "Customer database potentially compromised" --metadata "affected_systems=db-01,priority=urgent"
#   ./initialize.sh --incident-id IR-2023-003 --type unauthorized_access --evidence-dir /custom/evidence/path --no-notification

set -eo pipefail

# --- Constants and Configuration ---

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROJECT_ROOT="$(dirname "$ADMIN_DIR")"

# Add the project root to PYTHONPATH to ensure modules can be imported
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH}"

# Default log file location
LOG_DIR="/var/log/cloud-platform/admin/incident_response"
mkdir -p "$LOG_DIR" 2>/dev/null || true
LOG_FILE="${LOG_DIR}/incident_init_$(date +%Y%m%d%H%M%S).log"

# --- Logging Functions ---

log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$1] $2" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "$1"
}

warn() {
    log "WARN" "$1"
}

error() {
    log "ERROR" "$1"
    exit 1
}

# --- Helper Functions ---

# Display usage information
usage() {
    grep '^#' "$0" | grep -v '!/bin/bash' | cut -c 3-
    exit 0
}

# Parse metadata from key=value format to JSON
parse_metadata() {
    local metadata="$1"
    local json_output="{"
    local first=true

    IFS=',' read -ra PAIRS <<< "$metadata"
    for pair in "${PAIRS[@]}"; do
        IFS='=' read -r key value <<< "$pair"
        key=$(echo "$key" | xargs)  # Trim whitespace
        value=$(echo "$value" | xargs)  # Trim whitespace

        if [ "$first" = true ]; then
            first=false
        else
            json_output+=", "
        fi

        # Properly escape double quotes in the value
        value="${value//\"/\\\"}"
        json_output+="\"$key\": \"$value\""
    done

    json_output+="}"
    echo "$json_output"
}

# Verify Python and required modules are available
check_prerequisites() {
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not found. Please install Python 3."
    fi

    # Check if the initialize.py module exists
    if [ ! -f "${SCRIPT_DIR}/initialize.py" ]; then
        error "initialize.py module not found. This script must be run from the incident_response_kit directory."
    }

    info "Prerequisites verified"
}

# --- Main Functions ---

# Function to initialize incident
initialize_incident() {
    local incident_id="$1"
    local incident_type="$2"
    local severity="$3"
    local description="$4"
    local lead_responder="$5"
    local evidence_dir="$6"
    local metadata_json="$7"
    local skip_docs="$8"
    local skip_tracking="$9"
    local skip_notifications="${10}"

    # Build Python command with parameters
    local cmd="import sys, json"
    cmd+="; from admin.security.incident_response_kit.initialize import initialize_incident"
    cmd+="; from admin.security.incident_response_kit import IncidentSeverity"

    # Add try/except block to handle exceptions
    cmd+="; try:"

    # Build function call with parameters
    cmd+=";     result = initialize_incident("
    cmd+=";         incident_id='$incident_id',"
    cmd+=";         incident_type='$incident_type',"
    cmd+=";         severity='$severity',"

    # Only add optional parameters if they're provided
    if [ -n "$description" ]; then
        cmd+=";         description='$description',"
    fi

    if [ -n "$lead_responder" ]; then
        cmd+=";         lead_responder='$lead_responder',"
    fi

    if [ -n "$evidence_dir" ]; then
        cmd+=";         evidence_dir='$evidence_dir',"
    fi

    if [ -n "$metadata_json" ]; then
        cmd+=";         metadata=json.loads('$metadata_json'),"
    fi

    # Add boolean flags for documentation, tracking, and notifications
    if [ "$skip_docs" = true ]; then
        cmd+=";         documentation=False,"
    fi

    if [ "$skip_tracking" = true ]; then
        cmd+=";         tracking=False,"
    fi

    if [ "$skip_notifications" = true ]; then
        cmd+=";         notify=False,"
    fi

    # Close function call
    cmd+=";     )"

    # Print results
    cmd+=";     print(json.dumps(result, default=str))"

    # Add exception handling
    cmd+="; except Exception as e:"
    cmd+=";     print(json.dumps({'success': False, 'error': str(e)}, default=str))"
    cmd+=";     sys.exit(1)"

    # Execute the Python command and capture output
    info "Initializing incident $incident_id..."
    result=$(python3 -c "$cmd")

    # Check if initialization was successful
    if echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); sys.exit(0 if data.get('success') else 1)" 2>/dev/null; then
        info "Successfully initialized incident: $incident_id"

        # Extract and display important information
        evidence_dir=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print(data.get('evidence_dir', 'N/A'))")
        tracking_status=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print('Enabled' if data.get('tracking_initialized') else 'Disabled')")
        notifications=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print('Sent' if data.get('notifications_sent') else 'Not sent')")

        # Show summary
        echo ""
        echo "========== Incident Response Summary =========="
        echo "Incident ID:       $incident_id"
        echo "Type:              $incident_type"
        echo "Severity:          $severity"
        echo "Lead Responder:    ${lead_responder:-Not specified}"
        echo "Evidence Directory: $evidence_dir"
        echo "Tracking Status:   $tracking_status"
        echo "Notifications:     $notifications"
        echo ""
        echo "Documentation files:"
        echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); [print(f'  - {path}') for path in data.get('documentation_paths', [])]"
        echo ""

        # Show errors if any
        errors=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print(len(data.get('errors', [])))")
        if [ "$errors" -gt 0 ]; then
            echo "Warnings/Errors:"
            echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); [print(f'  - {err}') for err in data.get('errors', [])]"
            echo ""
        fi

        echo "Next steps:"
        echo "  1. Review incident documentation"
        echo "  2. Begin evidence collection with: ./collect_evidence.py --incident-id $incident_id --target <target_system>"
        echo "  3. Update incident status with: ./coordination/status_tracker.py --incident-id $incident_id --update-phase containment"
        echo "=============================================="

    else
        # Extract and display error information
        error_msg=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print(data.get('error', 'Unknown error'))")
        error "Failed to initialize incident: $error_msg"
    fi
}

# Function to reopen incident
reopen_incident() {
    local incident_id="$1"
    local reason="$2"
    local user_id="$3"
    local phase="$4"

    # Build Python command with parameters
    local cmd="import sys, json"
    cmd+="; from admin.security.incident_response_kit.initialize import reopen_incident"

    # Add try/except block to handle exceptions
    cmd+="; try:"

    # Build function call with parameters
    cmd+=";     result = reopen_incident("
    cmd+=";         incident_id='$incident_id',"
    cmd+=";         reason='$reason',"

    # Only add optional parameters if they're provided
    if [ -n "$user_id" ]; then
        cmd+=";         user_id='$user_id',"
    fi

    if [ -n "$phase" ]; then
        cmd+=";         phase='$phase',"
    fi

    # Close function call
    cmd+=";     )"

    # Print results
    cmd+=";     print(json.dumps(result, default=str))"

    # Add exception handling
    cmd+="; except Exception as e:"
    cmd+=";     print(json.dumps({'success': False, 'error': str(e)}, default=str))"
    cmd+=";     sys.exit(1)"

    # Execute the Python command and capture output
    info "Reopening incident $incident_id..."
    result=$(python3 -c "$cmd")

    # Check if reopen was successful
    if echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); sys.exit(0 if data.get('success') else 1)" 2>/dev/null; then
        info "Successfully reopened incident: $incident_id"

        # Extract and display important information
        status_updated=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print('Updated' if data.get('status_updated') else 'Not updated')")
        notifications=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print('Sent' if data.get('notifications_sent') else 'Not sent')")

        # Show summary
        echo ""
        echo "========== Incident Reopen Summary =========="
        echo "Incident ID:       $incident_id"
        echo "Reopen Reason:     $reason"
        echo "Reopened By:       ${user_id:-System}"
        echo "New Phase:         ${phase:-identification}"
        echo "Status:            $status_updated"
        echo "Notifications:     $notifications"
        echo ""

        # Show errors if any
        errors=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print(len(data.get('errors', [])))")
        if [ "$errors" -gt 0 ]; then
            echo "Warnings/Errors:"
            echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); [print(f'  - {err}') for err in data.get('errors', [])]"
            echo ""
        fi

        echo "Next steps:"
        echo "  1. Review the incident details"
        echo "  2. Update incident documentation with new findings"
        echo "  3. Continue with appropriate response activities"
        echo "==========================================="

    else
        # Extract and display error information
        error_msg=$(echo "$result" | python3 -c "import sys, json; data = json.loads(sys.stdin.read()); print(data.get('error', 'Unknown error'))")
        error "Failed to reopen incident: $error_msg"
    fi
}

# --- Command Line Argument Parsing ---

# Default values
ACTION="initialize"
INCIDENT_ID=""
INCIDENT_TYPE=""
SEVERITY="medium"
DESCRIPTION=""
LEAD_RESPONDER=""
EVIDENCE_DIR=""
METADATA=""
REOPEN_REASON=""
REOPEN_PHASE=""
SKIP_DOCS=false
SKIP_TRACKING=false
SKIP_NOTIFICATIONS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help)
            usage
            ;;
        --incident-id)
            INCIDENT_ID="$2"
            shift 2
            ;;
        --type)
            INCIDENT_TYPE="$2"
            shift 2
            ;;
        --severity)
            SEVERITY="$2"
            shift 2
            ;;
        --description)
            DESCRIPTION="$2"
            shift 2
            ;;
        --lead-responder)
            LEAD_RESPONDER="$2"
            shift 2
            ;;
        --evidence-dir)
            EVIDENCE_DIR="$2"
            shift 2
            ;;
        --metadata)
            METADATA="$2"
            shift 2
            ;;
        --no-documentation)
            SKIP_DOCS=true
            shift
            ;;
        --no-tracking)
            SKIP_TRACKING=true
            shift
            ;;
        --no-notification)
            SKIP_NOTIFICATIONS=true
            shift
            ;;
        --reopen)
            ACTION="reopen"
            shift
            ;;
        --reason)
            REOPEN_REASON="$2"
            shift 2
            ;;
        --user)
            LEAD_RESPONDER="$2"  # Reuse lead_responder for user_id in reopen
            shift 2
            ;;
        --phase)
            REOPEN_PHASE="$2"
            shift 2
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# --- Main Execution ---

# Check prerequisites
check_prerequisites

# Validate required parameters
if [ -z "$INCIDENT_ID" ]; then
    error "Missing required parameter: --incident-id"
fi

# Run appropriate action
if [ "$ACTION" = "initialize" ]; then
    # Additional validation for initialize
    if [ -z "$INCIDENT_TYPE" ]; then
        error "Missing required parameter: --type"
    fi

    # Parse metadata if provided
    METADATA_JSON=""
    if [ -n "$METADATA" ]; then
        METADATA_JSON=$(parse_metadata "$METADATA")
    fi

    # Run initialization
    initialize_incident "$INCIDENT_ID" "$INCIDENT_TYPE" "$SEVERITY" "$DESCRIPTION" "$LEAD_RESPONDER" "$EVIDENCE_DIR" "$METADATA_JSON" "$SKIP_DOCS" "$SKIP_TRACKING" "$SKIP_NOTIFICATIONS"

elif [ "$ACTION" = "reopen" ]; then
    # Additional validation for reopen
    if [ -z "$REOPEN_REASON" ]; then
        error "Missing required parameter for reopen: --reason"
    fi

    # Run reopen
    reopen_incident "$INCIDENT_ID" "$REOPEN_REASON" "$LEAD_RESPONDER" "$REOPEN_PHASE"
fi

exit 0
