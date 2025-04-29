#!/bin/bash
# Volatile Data Collection Script for Live Response Forensics
#
# This script collects volatile system information (processes, network, users, etc.)
# from live systems during incident response, adhering to forensic best practices.

# Load common utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_functions.sh"

# Script version
VOLATILE_DATA_VERSION="1.0.0"
VOLATILE_DATA_DATE="2024-08-16"

# --- Configuration ---
DEFAULT_OUTPUT_DIR="/tmp/live_response_output_$$/volatile"
DEFAULT_CATEGORIES="processes,network,users,system_info" # Default categories to collect
DEFAULT_REMOTE_PORT="22"
DEFAULT_PROCESS_ARGS="true"
DEFAULT_PROCESS_ENV="false"

# --- Global Variables ---
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
CATEGORIES="$DEFAULT_CATEGORIES"
TARGET_HOST=""
TARGET_USER="$USER"
SSH_KEY=""
SSH_PORT="$DEFAULT_REMOTE_PORT"
PROCESS_ARGS="$DEFAULT_PROCESS_ARGS"
PROCESS_ENV="$DEFAULT_PROCESS_ENV"
CASE_ID=""
EXAMINER_ID=""

# --- Function Definitions ---

# Display usage information
usage() {
    cat << EOF
Volatile Data Collection Script v${VOLATILE_DATA_VERSION} (${VOLATILE_DATA_DATE})

Usage: $(basename "$0") [OPTIONS]

Options:
  -h, --help                 Show this help message
  -o, --output DIR           Output directory for collected data (default: ${DEFAULT_OUTPUT_DIR})
  -c, --collect CATEGORIES   Comma-separated list of categories to collect (default: ${DEFAULT_CATEGORIES})
                             Available: processes, network, users, system_info, services, modules, etc.
  -t, --target HOST          Remote target hostname or IP address
  -u, --user USER            Remote target user (default: ${TARGET_USER})
  -k, --key FILE             SSH private key file for remote connection
  -p, --port PORT            SSH port for remote connection (default: ${DEFAULT_REMOTE_PORT})
  --process-args           Include process arguments (default: ${DEFAULT_PROCESS_ARGS})
  --no-process-args        Do not include process arguments
  --process-env            Include process environment variables (default: ${DEFAULT_PROCESS_ENV})
  --no-process-env         Do not include process environment variables
  --case-id ID             Case identifier for evidence tracking
  --examiner ID            Examiner identifier for chain of custody
  -v, --verbose              Show more detailed output
  -q, --quiet                Suppress non-error output
  --log FILE                 Log file path
  --audit-log FILE           Audit log file path
  --version                  Show version information and exit
EOF
    exit 0
}

# Show version information
show_version() {
    echo "Volatile Data Collection Script v${VOLATILE_DATA_VERSION} (${VOLATILE_DATA_DATE})"
    echo "Using Common Functions v$(get_common_live_response_version)"
    exit 0
}

# Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help) usage ;;
            --version) show_version ;;
            -o|--output) shift; OUTPUT_DIR="$1" ;;
            -c|--collect) shift; CATEGORIES="$1" ;;
            -t|--target) shift; TARGET_HOST="$1" ;;
            -u|--user) shift; TARGET_USER="$1" ;;
            -k|--key) shift; SSH_KEY="$1" ;;
            -p|--port) shift; SSH_PORT="$1" ;;
            --process-args) PROCESS_ARGS="true" ;;
            --no-process-args) PROCESS_ARGS="false" ;;
            --process-env) PROCESS_ENV="true" ;;
            --no-process-env) PROCESS_ENV="false" ;;
            --case-id) shift; CASE_ID="$1" ;;
            --examiner) shift; EXAMINER_ID="$1" ;;
            -v|--verbose) VERBOSE=true ;;
            -q|--quiet) QUIET=true ;;
            --log) shift; LOG_FILE="$1" ;;
            --audit-log) shift; AUDIT_LOG_FILE="$1" ;;
            *) log_error "Unknown option: $key"; usage ;;
        esac
        shift
    done
}

# --- Collection Functions (Placeholders) ---

collect_processes() {
    local output_subdir="${OUTPUT_DIR}/processes"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting process information..."
    log_coc_event "Start" "Process Collection"

    local ps_path=$(get_tool_path "volatile_data" "ps")
    if [[ -z "$ps_path" ]]; then
        log_error "ps command not found. Cannot collect process information."
        log_coc_event "Fail" "Process Collection" "Tool 'ps' not found"
        return 1
    fi

    local cmd_opts="aux"
    [[ "$PROCESS_ARGS" == "true" ]] && cmd_opts+="ww" # Wide format for full args

    local cmd="$ps_path $cmd_opts"
    local output_file="${output_subdir}/ps_auxww.txt"

    if execute_and_save "$cmd" "$output_file" "Process List (ps auxww)"; then
        # Add more process details collection here (e.g., environment if PROCESS_ENV is true)
        log_coc_event "Completed" "Process Collection" "File: $output_file"
    else
        log_coc_event "Fail" "Process Collection" "Command failed: $cmd"
        return 1
    fi
    return 0
}

collect_network_info() {
    local output_subdir="${OUTPUT_DIR}/network"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting network connection information..."
    log_coc_event "Start" "Network Connection Collection"

    local netstat_path=$(get_tool_path "volatile_data" "netstat")
    local ss_path=$(get_tool_path "volatile_data" "ss")
    local success=false

    if [[ -n "$ss_path" ]]; then
        local cmd="$ss_path -tulpne" # Show TCP, UDP, Listening, Processes, Numeric, Extended
        local output_file="${output_subdir}/ss_tulpne.txt"
        if execute_and_save "$cmd" "$output_file" "Network Connections (ss)"; then
            success=true
        fi
    elif [[ -n "$netstat_path" ]]; then
        log_warn "ss command not found, falling back to netstat."
        local cmd="$netstat_path -anop" # Show All, Numeric, Listening, Processes (may require root)
        local output_file="${output_subdir}/netstat_anop.txt"
        if execute_and_save "$cmd" "$output_file" "Network Connections (netstat)"; then
            success=true
        fi
    else
        log_error "Neither ss nor netstat found. Cannot collect network connections."
        log_coc_event "Fail" "Network Connection Collection" "Tools 'ss' and 'netstat' not found"
        return 1
    fi

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "Network Connection Collection" "Collected network state"
    else
        log_coc_event "Fail" "Network Connection Collection" "Collection command failed"
        return 1
    fi
    return 0
}

collect_users() {
    local output_subdir="${OUTPUT_DIR}/users"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting user information..."
    log_coc_event "Start" "User Information Collection"

    local success=false
    # Collect logged in users (w, who)
    if execute_and_save "w" "${output_subdir}/w.txt" "Logged in users (w)"; then success=true; fi
    if execute_and_save "who" "${output_subdir}/who.txt" "Logged in users (who)"; then success=true; fi
    # Collect last logins (last) - might be large
    if execute_and_save "last -n 50" "${output_subdir}/last_50.txt" "Last 50 logins"; then success=true; fi

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "User Information Collection" "Collected user session data"
    else
        log_coc_event "Fail" "User Information Collection" "Failed to collect user data"
        return 1
    fi
    return 0
}

collect_system_info() {
    local output_subdir="${OUTPUT_DIR}/system_info"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting system information..."
    log_coc_event "Start" "System Information Collection"

    local success=false
    # Collect hostname, uname, uptime, date
    if execute_and_save "hostname" "${output_subdir}/hostname.txt" "Hostname"; then success=true; fi
    if execute_and_save "uname -a" "${output_subdir}/uname_a.txt" "System Version (uname -a)"; then success=true; fi
    if execute_and_save "uptime" "${output_subdir}/uptime.txt" "System Uptime"; then success=true; fi
    if execute_and_save "date -u" "${output_subdir}/date_utc.txt" "Current UTC Date"; then success=true; fi
    # Collect memory info (free)
    if execute_and_save "free -m" "${output_subdir}/free_m.txt" "Memory Usage (free -m)"; then success=true; fi
    # Collect disk info (df)
    if execute_and_save "df -h" "${output_subdir}/df_h.txt" "Disk Usage (df -h)"; then success=true; fi

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "System Information Collection" "Collected basic system info"
    else
        log_coc_event "Fail" "System Information Collection" "Failed to collect system info"
        return 1
    fi
    return 0
}

# --- Main Execution ---
main() {
    # Parse arguments
    parse_arguments "$@"

    # Initialize common functions (logging, CoC, tool paths)
    # Pass log paths and output dir if overridden by args
    init_common_functions "${LOG_FILE:-}" "${AUDIT_LOG_FILE:-}" "${OUTPUT_DIR:-}"

    log_info "Starting Volatile Data Collection v${VOLATILE_DATA_VERSION}"
    log_audit "Volatile Data Collection Started"

    # Ensure base output directory exists
    ensure_output_dir "$OUTPUT_DIR" || error_exit "Failed to create base output directory: $OUTPUT_DIR"

    # Log parameters
    log_debug "Parameters: Output='$OUTPUT_DIR', Target='$TARGET_HOST', Categories='$CATEGORIES'"
    log_debug "Process Args: $PROCESS_ARGS, Process Env: $PROCESS_ENV"

    # Convert categories string to array
    IFS=',' read -ra CATEGORIES_ARRAY <<< "$CATEGORIES"

    local collection_failed=false
    for category in "${CATEGORIES_ARRAY[@]}"; do
        log_info "--- Collecting category: $category ---"
        case "$category" in
            processes) collect_processes || collection_failed=true ;;
            network) collect_network_info || collection_failed=true ;;
            users) collect_users || collection_failed=true ;;
            system_info) collect_system_info || collection_failed=true ;;
            # Add cases for other categories (services, modules, etc.) here
            *) log_warn "Unknown or unsupported category: $category" ;;
        esac
    done

    if [[ "$collection_failed" == "true" ]]; then
        log_error "One or more volatile data collection categories failed."
        log_audit "Volatile Data Collection Completed with Errors"
        # cleanup_on_exit will handle exit code
        exit 1
    else
        log_success "Volatile data collection completed successfully."
        log_audit "Volatile Data Collection Completed Successfully"
        exit 0
    fi
}

# Execute main function
main "$@"
