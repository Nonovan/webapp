#!/bin/bash
# Incident Response Automation Script
# Automates key steps in incident response workflows, including evidence collection,
# system isolation, and stakeholder notification based on predefined playbooks and configurations.
#
# Usage: ./incident_response.sh --incident-id <id> [action] [options]
#
# Actions:
#   init          Initialize a new incident environment.
#   collect       Collect evidence from target systems.
#   isolate       Isolate target systems from the network.
#   notify        Send notifications to stakeholders.
#   status        Update or query incident status.
#   run-playbook  Execute steps from a specific incident playbook.
#
# Options:
#   --incident-id <id>    Required. Unique identifier for the incident (e.g., IR-2024-042).
#   --target <host/ip>    Target system for actions like collect or isolate. Can be specified multiple times.
#   --type <type>         Incident type (e.g., malware, ddos, unauthorized_access). Used with 'init' or 'run-playbook'.
#   --severity <level>    Incident severity (critical, high, medium, low). Used with 'init' or 'notify'.
#   --lead <email>        Lead responder email. Used with 'init'.
#   --collect-types <types> Comma-separated list of evidence types (e.g., memory,disk,logs). Used with 'collect'.
#   --output-dir <path>   Directory to store collected evidence. Used with 'collect'. Defaults to configured evidence dir.
#   --isolation-method <method> Isolation method (e.g., acl, vlan, shutdown). Used with 'isolate'.
#   --allow-ip <ip>       IP address allowed to communicate with isolated host. Used with 'isolate'.
#   --duration <time>     Duration for isolation (e.g., 4h, 1d). Used with 'isolate'.
#   --recipients <list>   Comma-separated list of notification recipients or groups. Used with 'notify'.
#   --message <msg>       Notification message content. Used with 'notify'.
#   --channel <chan>      Notification channel (e.g., email, sms, slack). Used with 'notify'. Can be specified multiple times.
#   --phase <phase>       Incident phase (e.g., detection, containment, eradication). Used with 'status'.
#   --status-update <status> New status for the phase (e.g., started, in-progress, completed). Used with 'status'.
#   --notes <notes>       Notes for status update. Used with 'status'.
#   --playbook <name>     Name of the playbook to run (e.g., malware_incident). Used with 'run-playbook'.
#   --step <step_name>    Specific step within the playbook to execute. Used with 'run-playbook'.
#   --force               Bypass confirmation prompts.
#   --help                Show this help message.
#
# Examples:
#   # Initialize a new high-severity malware incident
#   ./incident_response.sh --incident-id IR-2024-001 init --type malware --severity high --lead security-lead@example.com
#
#   # Collect memory and logs from a compromised host
#   ./incident_response.sh --incident-id IR-2024-001 collect --target 192.168.1.100 --collect-types memory,logs
#
#   # Isolate the host using ACLs, allowing access from forensic workstation
#   ./incident_response.sh --incident-id IR-2024-001 isolate --target 192.168.1.100 --isolation-method acl --allow-ip 10.0.0.5 --duration 8h
#
#   # Notify security team about containment status
#   ./incident_response.sh --incident-id IR-2024-001 notify --recipients security-team --message "Host 192.168.1.100 isolated. Evidence collection started." --severity high
#
#   # Update status of containment phase
#   ./incident_response.sh --incident-id IR-2024-001 status --phase containment --status-update completed --notes "Host isolated, memory dump acquired."
#
#   # Run the 'eradication' step from the malware playbook
#   ./incident_response.sh --incident-id IR-2024-001 run-playbook --playbook malware_incident --step eradication

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$ADMIN_DIR")"
IR_KIT_DIR="${ADMIN_DIR}/security/incident_response_kit"
LOG_DIR="/var/log/cloud-platform/admin"
LOG_FILE="${LOG_DIR}/incident_response_$(date +%Y%m%d%H%M%S).log"
DEFAULT_EVIDENCE_DIR="/secure/evidence" # Should ideally be read from IR Kit config

# Tool Paths (relative to IR_KIT_DIR)
INITIALIZE_SCRIPT="${IR_KIT_DIR}/initialize.sh"
COLLECT_SCRIPT="${IR_KIT_DIR}/collect_evidence.py"
ISOLATE_SCRIPT="${IR_KIT_DIR}/network_isolation.py"
NOTIFY_SCRIPT="${IR_KIT_DIR}/coordination/notification_system.py"
STATUS_SCRIPT="${IR_KIT_DIR}/coordination/status_tracker.py"
# Playbook execution might be more complex than a single script call

# Default values
ACTION=""
INCIDENT_ID=""
TARGETS=()
COLLECT_TYPES=""
OUTPUT_DIR=""
ISOLATION_METHOD="acl" # Default isolation method
ALLOW_IPS=()
DURATION=""
RECIPIENTS=""
MESSAGE=""
CHANNELS=()
SEVERITY=""
TYPE=""
LEAD_RESPONDER=""
PHASE=""
STATUS_UPDATE=""
NOTES=""
PLAYBOOK=""
STEP=""
FORCE_MODE=false

# Ensure log directory exists
mkdir -p "$LOG_DIR"

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
usage() {
    grep '^# ' "$0" | cut -c3-
    exit 0
}

confirm_action() {
    if [[ "$FORCE_MODE" == "true" ]]; then
        return 0 # Skip confirmation
    fi
    read -p "$1 [y/N]: " -n 1 -r
    echo # Move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        info "Operation cancelled by user."
        exit 0
    fi
}

# Check if required tools exist
check_tool() {
    local tool_path="$1"
    local tool_name
    tool_name=$(basename "$tool_path")
    if [[ ! -x "$tool_path" ]]; then
        error "Required tool '$tool_name' not found or not executable at '$tool_path'."
    fi
}

# --- Action Handlers ---

handle_init() {
    info "Handling 'init' action for incident $INCIDENT_ID"
    check_tool "$INITIALIZE_SCRIPT"
    if [[ -z "$TYPE" || -z "$SEVERITY" || -z "$LEAD_RESPONDER" ]]; then
        error "Missing required options for 'init': --type, --severity, --lead"
    fi
    confirm_action "Initialize incident $INCIDENT_ID (Type: $TYPE, Severity: $SEVERITY, Lead: $LEAD_RESPONDER)?"

    "$INITIALIZE_SCRIPT" --incident-id "$INCIDENT_ID" --type "$TYPE" --severity "$SEVERITY" --lead-responder "$LEAD_RESPONDER" ||
        error "Incident initialization failed."
    info "Incident $INCIDENT_ID initialized successfully."
}

handle_collect() {
    info "Handling 'collect' action for incident $INCIDENT_ID"
    check_tool "$COLLECT_SCRIPT"
    if [[ ${#TARGETS[@]} -eq 0 || -z "$COLLECT_TYPES" ]]; then
        error "Missing required options for 'collect': --target, --collect-types"
    fi
    local target_list
    target_list=$(IFS=,; echo "${TARGETS[*]}")
    local effective_output_dir="${OUTPUT_DIR:-${DEFAULT_EVIDENCE_DIR}/${INCIDENT_ID}}"

    confirm_action "Collect evidence types '$COLLECT_TYPES' from target(s) '$target_list' for incident $INCIDENT_ID?"

    # Assuming collect_evidence.py can handle multiple targets or needs looping
    for target in "${TARGETS[@]}"; do
        info "Collecting evidence from $target..."
        python "$COLLECT_SCRIPT" --incident-id "$INCIDENT_ID" --target "$target" --collect "$COLLECT_TYPES" --output "$effective_output_dir" ||
            warn "Evidence collection failed for target $target. Continuing..."
    done
    info "Evidence collection process completed for incident $INCIDENT_ID."
}

handle_isolate() {
    info "Handling 'isolate' action for incident $INCIDENT_ID"
    check_tool "$ISOLATE_SCRIPT"
    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        error "Missing required option for 'isolate': --target"
    fi
    local target_list
    target_list=$(IFS=,; echo "${TARGETS[*]}")
    local allow_ip_opts=()
    for ip in "${ALLOW_IPS[@]}"; do
        allow_ip_opts+=(--allow-ip "$ip")
    done
    local duration_opt=""
    [[ -n "$DURATION" ]] && duration_opt="--duration $DURATION"

    confirm_action "Isolate target(s) '$target_list' using method '$ISOLATION_METHOD' for incident $INCIDENT_ID ${duration_opt}?"

    for target in "${TARGETS[@]}"; do
        info "Isolating target $target..."
        # Construct command arguments carefully
        local cmd_args=("--incident-id" "$INCIDENT_ID" "--target" "$target" "--method" "$ISOLATION_METHOD")
        [[ ${#allow_ip_opts[@]} -gt 0 ]] && cmd_args+=("${allow_ip_opts[@]}")
        [[ -n "$DURATION" ]] && cmd_args+=("--duration" "$DURATION")

        python "$ISOLATE_SCRIPT" "${cmd_args[@]}" ||
            warn "Isolation failed for target $target. Continuing..."
    done
    info "Isolation process completed for incident $INCIDENT_ID."
}

handle_notify() {
    info "Handling 'notify' action for incident $INCIDENT_ID"
    check_tool "$NOTIFY_SCRIPT"
    if [[ -z "$RECIPIENTS" || -z "$MESSAGE" ]]; then
        error "Missing required options for 'notify': --recipients, --message"
    fi
    local channel_opts=()
    for chan in "${CHANNELS[@]}"; do
        channel_opts+=(--channel "$chan")
    done
    local severity_opt=""
    [[ -n "$SEVERITY" ]] && severity_opt="--severity $SEVERITY"

    confirm_action "Send notification for incident $INCIDENT_ID to '$RECIPIENTS'?"

    # Construct command arguments carefully
    local cmd_args=("--incident-id" "$INCIDENT_ID" "--recipients" "$RECIPIENTS" "--message" "$MESSAGE")
    [[ ${#channel_opts[@]} -gt 0 ]] && cmd_args+=("${channel_opts[@]}")
    [[ -n "$SEVERITY" ]] && cmd_args+=("--severity" "$SEVERITY")

    python "$NOTIFY_SCRIPT" "${cmd_args[@]}" ||
        error "Notification failed for incident $INCIDENT_ID."
    info "Notification sent successfully for incident $INCIDENT_ID."
}

handle_status() {
    info "Handling 'status' action for incident $INCIDENT_ID"
    check_tool "$STATUS_SCRIPT"

    local cmd_args=("--incident-id" "$INCIDENT_ID")
    if [[ -n "$PHASE" && -n "$STATUS_UPDATE" ]]; then
        # Update status
        cmd_args+=("--update-phase" "$PHASE" "--status" "$STATUS_UPDATE")
        [[ -n "$NOTES" ]] && cmd_args+=("--notes" "$NOTES")
        confirm_action "Update status for incident $INCIDENT_ID, phase '$PHASE' to '$STATUS_UPDATE'?"
        python "$STATUS_SCRIPT" "${cmd_args[@]}" || error "Failed to update status for incident $INCIDENT_ID."
        info "Status updated successfully."
    elif [[ -z "$PHASE" && -z "$STATUS_UPDATE" ]]; then
        # Query status
        info "Querying status for incident $INCIDENT_ID..."
        python "$STATUS_SCRIPT" "${cmd_args[@]}" --generate-report || error "Failed to query status for incident $INCIDENT_ID."
        # Assuming the script prints the report to stdout
    else
        error "For 'status' action, either provide no phase/status options (to query) or both --phase and --status-update (to update)."
    fi
}

handle_playbook() {
    info "Handling 'run-playbook' action for incident $INCIDENT_ID"
    if [[ -z "$PLAYBOOK" ]]; then
        error "Missing required option for 'run-playbook': --playbook"
    fi
    local playbook_path="${IR_KIT_DIR}/playbooks/${PLAYBOOK}.md" # Assuming markdown playbooks
    if [[ ! -f "$playbook_path" ]]; then
        error "Playbook '$PLAYBOOK' not found at '$playbook_path'."
    fi

    # Playbook execution logic is complex. This is a placeholder.
    # It might involve parsing the markdown, identifying steps, and calling relevant scripts/functions.
    # A dedicated playbook runner script might be more appropriate.
    warn "Playbook execution is complex and not fully implemented in this script."
    info "Playbook: $PLAYBOOK"
    [[ -n "$STEP" ]] && info "Requested Step: $STEP"

    if [[ -n "$STEP" ]]; then
        confirm_action "Execute step '$STEP' from playbook '$PLAYBOOK' for incident $INCIDENT_ID?"
        # Placeholder: Map step names to actions
        case "$STEP" in
            initial_containment|isolate_systems)
                info "Mapping playbook step '$STEP' to 'isolate' action..."
                # Need to determine targets based on incident context or playbook instructions
                error "Target determination for playbook steps not implemented. Please use 'isolate' action directly."
                # handle_isolate # Would need TARGETS populated
                ;;
            collect_initial_evidence)
                 info "Mapping playbook step '$STEP' to 'collect' action..."
                 error "Target determination for playbook steps not implemented. Please use 'collect' action directly."
                 # handle_collect # Would need TARGETS and COLLECT_TYPES populated
                ;;
            notify_stakeholders)
                 info "Mapping playbook step '$STEP' to 'notify' action..."
                 error "Recipient/message determination for playbook steps not implemented. Please use 'notify' action directly."
                 # handle_notify # Would need RECIPIENTS and MESSAGE populated
                ;;
            *)
                error "Execution logic for playbook step '$STEP' is not defined."
                ;;
        esac
    else
        info "Displaying playbook content (manual execution required):"
        cat "$playbook_path"
        info "Manual execution of playbook steps is required."
    fi
}

# --- Argument Parsing ---
if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --incident-id)
            INCIDENT_ID="$2"
            shift 2
            ;;
        init|collect|isolate|notify|status|run-playbook)
            if [[ -n "$ACTION" ]]; then error "Only one action can be specified."; fi
            ACTION="$key"
            shift
            ;;
        --target)
            TARGETS+=("$2")
            shift 2
            ;;
        --type)
            TYPE="$2"
            shift 2
            ;;
        --severity)
            SEVERITY="$2"
            shift 2
            ;;
        --lead)
            LEAD_RESPONDER="$2"
            shift 2
            ;;
        --collect-types)
            COLLECT_TYPES="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --isolation-method)
            ISOLATION_METHOD="$2"
            shift 2
            ;;
        --allow-ip)
            ALLOW_IPS+=("$2")
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --recipients)
            RECIPIENTS="$2"
            shift 2
            ;;
        --message)
            MESSAGE="$2"
            shift 2
            ;;
        --channel)
            CHANNELS+=("$2")
            shift 2
            ;;
        --phase)
            PHASE="$2"
            shift 2
            ;;
        --status-update)
            STATUS_UPDATE="$2"
            shift 2
            ;;
        --notes)
            NOTES="$2"
            shift 2
            ;;
        --playbook)
            PLAYBOOK="$2"
            shift 2
            ;;
        --step)
            STEP="$2"
            shift 2
            ;;
        --force)
            FORCE_MODE=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            error "Unknown option or missing value: $1"
            usage
            ;;
    esac
done

# --- Validation ---
if [[ -z "$INCIDENT_ID" ]]; then
    error "Missing required option: --incident-id"
fi
if [[ -z "$ACTION" ]]; then
    error "No action specified (init, collect, isolate, notify, status, run-playbook)."
fi

# --- Main Execution Logic ---
info "Starting Incident Response Script for Incident: $INCIDENT_ID"
info "Action: $ACTION"

case "$ACTION" in
    init)
        handle_init
        ;;
    collect)
        handle_collect
        ;;
    isolate)
        handle_isolate
        ;;
    notify)
        handle_notify
        ;;
    status)
        handle_status
        ;;
    run-playbook)
        handle_playbook
        ;;
    *)
        # This case should not be reached due to earlier check, but included for safety
        error "Invalid action specified: $ACTION"
        ;;
esac

info "Incident Response Script finished for Incident: $INCIDENT_ID"
exit 0
