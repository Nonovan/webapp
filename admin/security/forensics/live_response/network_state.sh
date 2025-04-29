#!/bin/bash
# Network State Collection Script for Live Response Forensics
#
# Captures current network configuration and activity, including connections,
# routing tables, ARP cache, DNS information, and interface details.

# Load common utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source common functions, adjust path if necessary
if [[ -f "${SCRIPT_DIR}/common_functions.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/common_functions.sh"
else
    echo "ERROR: common_functions.sh not found in ${SCRIPT_DIR}!" >&2
    exit 1
fi

# Script version
NETWORK_STATE_VERSION="1.0.0"
NETWORK_STATE_DATE="2024-08-16"

# --- Configuration Defaults ---
DEFAULT_OUTPUT_DIR="${OUTPUT_DIR:-/tmp/live_response_output_$$/network}" # Use common default or specific one
DEFAULT_CONNECTIONS_TYPE="all" # all, established, listening
DEFAULT_COLLECT_ROUTING=true
DEFAULT_COLLECT_ARP=true
DEFAULT_COLLECT_DNS=true
DEFAULT_COLLECT_INTERFACES=true
DEFAULT_PACKET_CAPTURE=false
DEFAULT_CAPTURE_DURATION=60 # seconds
DEFAULT_CAPTURE_PACKETS=10000
DEFAULT_CAPTURE_FILTER=""
DEFAULT_CAPTURE_INTERFACE="any"

# --- Global Variables ---
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
CONNECTIONS_TYPE="$DEFAULT_CONNECTIONS_TYPE"
COLLECT_ROUTING="$DEFAULT_COLLECT_ROUTING"
COLLECT_ARP="$DEFAULT_COLLECT_ARP"
COLLECT_DNS="$DEFAULT_COLLECT_DNS"
COLLECT_INTERFACES="$DEFAULT_COLLECT_INTERFACES"
PACKET_CAPTURE="$DEFAULT_PACKET_CAPTURE"
CAPTURE_DURATION="$DEFAULT_CAPTURE_DURATION"
CAPTURE_PACKETS="$DEFAULT_CAPTURE_PACKETS"
CAPTURE_FILTER="$DEFAULT_CAPTURE_FILTER"
CAPTURE_INTERFACE="$DEFAULT_CAPTURE_INTERFACE"
TARGET_HOST=""
TARGET_USER="$USER"
SSH_KEY=""
SSH_PORT="$DEFAULT_REMOTE_PORT"

# --- Function Definitions ---

# Display usage information
usage() {
    echo "Usage: $0 [--output <dir>] [--target <host>] [--user <user>] [--key <ssh_key>] [--port <ssh_port>]"
    echo "       [--connections <all|established|listening>] [--no-routing] [--no-arp] [--no-dns] [--no-interfaces]"
    echo "       [--capture-packets <count>] [--capture-duration <secs>] [--capture-filter <filter>] [--capture-interface <iface>]"
    echo "       [--case-id <id>] [--examiner <id>] [--verbose] [--quiet] [--log <file>] [--audit-log <file>] [--help] [--version]"
    echo ""
    echo "Options:"
    echo "  --output DIR           Directory to save collected network state (default: $DEFAULT_OUTPUT_DIR)"
    echo "  --target HOST          Remote host to collect data from via SSH"
    echo "  --user USER            Username for remote SSH connection (default: $USER)"
    echo "  --key KEY_FILE         SSH private key file for remote connection"
    echo "  --port PORT            SSH port for remote connection (default: $DEFAULT_REMOTE_PORT)"
    echo "  --connections TYPE     Type of connections to list (default: $DEFAULT_CONNECTIONS_TYPE)"
    echo "  --no-routing           Do not collect routing table information"
    echo "  --no-arp               Do not collect ARP cache information"
    echo "  --no-dns               Do not collect DNS resolver information"
    echo "  --no-interfaces        Do not collect network interface details"
    echo "  --capture-packets COUNT Enable packet capture (tcpdump) for COUNT packets (default: disabled)"
    echo "  --capture-duration SEC Enable packet capture for SEC seconds (overrides --capture-packets if both set)"
    echo "  --capture-filter FILTER BPF filter for packet capture (e.g., 'port 80')"
    echo "  --capture-interface IFACE Interface for packet capture (default: $DEFAULT_CAPTURE_INTERFACE)"
    echo "  --case-id ID           Case identifier for logging"
    echo "  --examiner ID          Examiner identifier for logging"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -q, --quiet            Suppress non-error output"
    echo "  --log FILE             Log file path"
    echo "  --audit-log FILE       Audit log file path (chain of custody)"
    echo "  -h, --help             Show this help message"
    echo "  --version              Show script version"
    exit 0
}

# Display version information
show_version() {
    echo "$(basename "$0") v${NETWORK_STATE_VERSION} (${NETWORK_STATE_DATE})"
    echo "Common Functions: v$(get_common_live_response_version)"
    exit 0
}

# Collect network connections
# Uses ss if available, falls back to netstat
collect_connections() {
    local output_subdir="${OUTPUT_DIR}/connections"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting network connections (type: $CONNECTIONS_TYPE)..."
    log_coc_event "Start" "Network Connections" "Type: $CONNECTIONS_TYPE"

    local ss_path
    local netstat_path
    ss_path=$(get_tool_path "network_state" "ss")
    netstat_path=$(get_tool_path "network_state" "netstat")

    local cmd=""
    local output_file=""
    local ss_opts="-ntupa" # TCP, UDP, listening, all processes, numeric
    local netstat_opts="-anop" # All, numeric, listening/established, processes (Linux), protocol (BSD)

    # Adjust options based on desired connection type
    case "$CONNECTIONS_TYPE" in
        established)
            ss_opts+=" state established"
            netstat_opts="-anop" # Filter later if needed, netstat options vary
            ;;
        listening)
            ss_opts+=" state listening"
            netstat_opts="-anop" # Filter later if needed
            ;;
        *) # all
            # Default options are fine
            ;;
    esac

    if [[ -n "$ss_path" ]]; then
        cmd="$ss_path $ss_opts"
        output_file="${output_subdir}/ss_${CONNECTIONS_TYPE}.txt"
        log_debug "Using ss command: $cmd"
    elif [[ -n "$netstat_path" ]]; then
        cmd="$netstat_path $netstat_opts"
        output_file="${output_subdir}/netstat_${CONNECTIONS_TYPE}.txt"
        log_warn "ss command not found, falling back to netstat. Output format may vary."
        log_debug "Using netstat command: $cmd"
    else
        log_error "Neither ss nor netstat found. Cannot collect connections."
        log_coc_event "Fail" "Network Connections" "Tools ss and netstat not found"
        return 1
    fi

    # Execute command locally or remotely
    local result_content
    if [[ -n "$TARGET_HOST" ]]; then
        result_content=$(execute_remote_command "$cmd")
    else
        result_content=$(eval "$cmd" 2>&1) # Use eval for complex commands like ss with state filter
    fi
    local status=$?

    if [[ $status -eq 0 && -n "$result_content" ]]; then
        write_evidence_file "$output_file" "$result_content" || return 1
        log_success "Network connections saved to $output_file"
        log_coc_event "Complete" "Network Connections" "File: $output_file"
    elif [[ $status -ne 0 ]]; then
        log_error "Failed to execute command: $cmd (Exit code: $status)"
        write_evidence_file "${output_file}.err" "$result_content"
        log_coc_event "Fail" "Network Connections" "Command failed: $cmd"
        return 1
    else
        log_warn "No network connections found or command returned empty output."
        write_evidence_file "$output_file" "# No connections found or command returned empty."
        log_coc_event "Complete" "Network Connections" "No data found"
    fi

    return 0
}

# Collect routing table
collect_routing() {
    local output_subdir="${OUTPUT_DIR}/routing"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting routing table..."
    log_coc_event "Start" "Routing Table"

    local ip_path
    local route_path
    ip_path=$(get_tool_path "network_state" "ip")
    route_path=$(get_tool_path "network_state" "route")

    local cmd=""
    local output_file=""

    if [[ -n "$ip_path" ]]; then
        cmd="$ip_path route show"
        output_file="${output_subdir}/ip_route.txt"
        log_debug "Using ip command: $cmd"
    elif [[ -n "$route_path" ]]; then
        cmd="$route_path -n" # Numeric output
        output_file="${output_subdir}/route_n.txt"
        log_warn "ip command not found, falling back to route."
        log_debug "Using route command: $cmd"
    else
        log_error "Neither ip route nor route found. Cannot collect routing table."
        log_coc_event "Fail" "Routing Table" "Tools ip and route not found"
        return 1
    fi

    execute_and_save "$cmd" "$output_file" "Routing Table"
    return $?
}

# Collect ARP cache
collect_arp() {
    local output_subdir="${OUTPUT_DIR}/arp"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting ARP cache..."
    log_coc_event "Start" "ARP Cache"

    local ip_path
    local arp_path
    ip_path=$(get_tool_path "network_state" "ip")
    arp_path=$(get_tool_path "network_state" "arp")

    local cmd=""
    local output_file=""

    if [[ -n "$ip_path" ]]; then
        cmd="$ip_path neigh show"
        output_file="${output_subdir}/ip_neigh.txt"
        log_debug "Using ip command: $cmd"
    elif [[ -n "$arp_path" ]]; then
        cmd="$arp_path -an" # Numeric output
        output_file="${output_subdir}/arp_an.txt"
        log_warn "ip command not found, falling back to arp."
        log_debug "Using arp command: $cmd"
    else
        log_error "Neither ip neigh nor arp found. Cannot collect ARP cache."
        log_coc_event "Fail" "ARP Cache" "Tools ip and arp not found"
        return 1
    fi

    execute_and_save "$cmd" "$output_file" "ARP Cache"
    return $?
}

# Collect DNS resolver information
collect_dns() {
    local output_subdir="${OUTPUT_DIR}/dns"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting DNS resolver information..."
    log_coc_event "Start" "DNS Information"

    local success=false

    # 1. /etc/resolv.conf
    local resolv_conf="/etc/resolv.conf"
    local output_file="${output_subdir}/resolv_conf.txt"
    if [[ -n "$TARGET_HOST" ]]; then
        execute_remote_command "cat $resolv_conf" > "$output_file.tmp" 2>/dev/null
        if [[ $? -eq 0 && -s "$output_file.tmp" ]]; then
             mv "$output_file.tmp" "$output_file"
             chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file"
             log_success "Saved $resolv_conf to $output_file"
             log_coc_event "Collected" "DNS Information" "File: $output_file (from $resolv_conf)"
             success=true
        else
             rm -f "$output_file.tmp"
             log_debug "Remote $resolv_conf not found or empty."
        fi
    elif [[ -f "$resolv_conf" ]]; then
        cp "$resolv_conf" "$output_file" && chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file"
        log_success "Saved $resolv_conf to $output_file"
        log_coc_event "Collected" "DNS Information" "File: $output_file (from $resolv_conf)"
        success=true
    fi

    # 2. systemd-resolved status (if available)
    local resolvectl_path
    resolvectl_path=$(get_tool_path "network_state" "resolvectl")
    if [[ -n "$resolvectl_path" ]]; then
        cmd="$resolvectl_path status"
        output_file="${output_subdir}/resolvectl_status.txt"
        if execute_and_save "$cmd" "$output_file" "DNS Information (resolvectl)"; then
            success=true
        fi
    fi

    # 3. nscd statistics (if available) - less common for DNS cache
    local nscd_path
    nscd_path=$(get_tool_path "network_state" "nscd")
    if [[ -n "$nscd_path" ]]; then
        cmd="$nscd_path -g" # Get statistics
        output_file="${output_subdir}/nscd_stats.txt"
        if execute_and_save "$cmd" "$output_file" "DNS Information (nscd)"; then
            success=true
        fi
    fi

    if [[ "$success" != true ]]; then
        log_warn "Could not collect significant DNS information."
        log_coc_event "Complete" "DNS Information" "No primary sources found or accessible"
    fi

    return 0
}

# Collect network interface details
collect_interfaces() {
    local output_subdir="${OUTPUT_DIR}/interfaces"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting network interface details..."
    log_coc_event "Start" "Network Interfaces"

    local ip_path
    local ifconfig_path
    ip_path=$(get_tool_path "network_state" "ip")
    ifconfig_path=$(get_tool_path "network_state" "ifconfig")

    local success=false

    if [[ -n "$ip_path" ]]; then
        # Use 'ip addr'
        cmd_addr="$ip_path addr show"
        output_file_addr="${output_subdir}/ip_addr.txt"
        if execute_and_save "$cmd_addr" "$output_file_addr" "Network Interfaces (ip addr)"; then
            success=true
        fi
        # Use 'ip link' for link layer info
        cmd_link="$ip_path link show"
        output_file_link="${output_subdir}/ip_link.txt"
        if execute_and_save "$cmd_link" "$output_file_link" "Network Interfaces (ip link)"; then
            success=true
        fi
    elif [[ -n "$ifconfig_path" ]]; then
        # Use 'ifconfig -a'
        cmd="$ifconfig_path -a"
        output_file="${output_subdir}/ifconfig_a.txt"
        log_warn "ip command not found, falling back to ifconfig."
        if execute_and_save "$cmd" "$output_file" "Network Interfaces (ifconfig)"; then
            success=true
        fi
    else
        log_error "Neither ip nor ifconfig found. Cannot collect interface details."
        log_coc_event "Fail" "Network Interfaces" "Tools ip and ifconfig not found"
        return 1
    fi

    if [[ "$success" != true ]]; then
        log_warn "Failed to collect network interface details."
        return 1
    fi

    return 0
}

# Start packet capture
start_packet_capture() {
    local output_subdir="${OUTPUT_DIR}/capture"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Starting packet capture..."
    log_coc_event "Start" "Packet Capture" "Interface: $CAPTURE_INTERFACE, Duration: ${CAPTURE_DURATION}s, Packets: ${CAPTURE_PACKETS}, Filter: ${CAPTURE_FILTER:-None}"

    local tcpdump_path
    tcpdump_path=$(get_tool_path "network_state" "tcpdump")
    if [[ -z "$tcpdump_path" ]]; then
        log_error "tcpdump command not found. Cannot perform packet capture."
        log_coc_event "Fail" "Packet Capture" "Tool tcpdump not found"
        return 1
    fi

    local timestamp
    timestamp=$(get_timestamp "file")
    local output_file="${output_subdir}/capture_${CAPTURE_INTERFACE}_${timestamp}.pcap"
    local pid_file="${output_subdir}/tcpdump.pid"

    local cmd_opts="-i $CAPTURE_INTERFACE -w $output_file -s 0" # Capture full packets

    # Add count or duration limit
    if [[ "$CAPTURE_DURATION" -gt 0 ]]; then
        # tcpdump doesn't have a direct duration option like tshark, run in background and kill
        cmd_opts+=" -c 999999999" # Effectively unlimited count for duration-based capture
    elif [[ "$CAPTURE_PACKETS" -gt 0 ]]; then
        cmd_opts+=" -c $CAPTURE_PACKETS"
    else
        log_error "Packet capture requested but no duration or packet count specified."
        return 1
    fi

    # Add filter if specified
    if [[ -n "$CAPTURE_FILTER" ]]; then
        cmd_opts+=" $CAPTURE_FILTER"
    fi

    local full_cmd="$tcpdump_path $cmd_opts"

    log_info "Running capture command: $full_cmd"

    # Run tcpdump in the background
    if [[ -n "$TARGET_HOST" ]]; then
        log_error "Background packet capture on remote host not directly supported by this script version."
        log_warn "Consider running tcpdump manually on the target or using a dedicated remote capture tool."
        log_coc_event "Fail" "Packet Capture" "Remote background capture not supported"
        return 1
    else
        # Run locally in background
        eval "$full_cmd" &
        local tcpdump_pid=$!
        echo "$tcpdump_pid" > "$pid_file"
        log_info "Packet capture started in background (PID: $tcpdump_pid). Output: $output_file"

        # If duration based, schedule a kill
        if [[ "$CAPTURE_DURATION" -gt 0 ]]; then
            log_info "Capture will run for ${CAPTURE_DURATION} seconds."
            ( sleep "$CAPTURE_DURATION" && kill "$tcpdump_pid" 2>/dev/null && log_info "Packet capture duration ended, process $tcpdump_pid terminated." && rm -f "$pid_file" ) &
        else
             log_info "Capture will stop after $CAPTURE_PACKETS packets."
             # We need to wait for tcpdump to finish if it's count-based
             wait "$tcpdump_pid"
             local capture_status=$?
             rm -f "$pid_file"
             if [[ $capture_status -eq 0 ]]; then
                 log_success "Packet capture completed successfully."
                 log_coc_event "Complete" "Packet Capture" "File: $output_file, Packets: $CAPTURE_PACKETS"
             else
                 log_error "Packet capture command failed with status $capture_status."
                 log_coc_event "Fail" "Packet Capture" "tcpdump command failed"
                 return 1
             fi
        fi
    fi
    # Note: For duration-based capture, the CoC "Complete" event happens in the background subshell
    return 0
}


# Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help) usage ;;
            --version) show_version ;;
            -o|--output) shift; OUTPUT_DIR="$1" ;;
            -t|--target) shift; TARGET_HOST="$1" ;;
            -u|--user) shift; TARGET_USER="$1" ;;
            -k|--key) shift; SSH_KEY="$1" ;;
            -p|--port) shift; SSH_PORT="$1" ;;
            --connections) shift; CONNECTIONS_TYPE="$1" ;;
            --no-routing) COLLECT_ROUTING=false ;;
            --no-arp) COLLECT_ARP=false ;;
            --no-dns) COLLECT_DNS=false ;;
            --no-interfaces) COLLECT_INTERFACES=false ;;
            --capture-packets) shift; PACKET_CAPTURE=true; CAPTURE_PACKETS="$1" ;;
            --capture-duration) shift; PACKET_CAPTURE=true; CAPTURE_DURATION="$1" ;;
            --capture-filter) shift; CAPTURE_FILTER="$1" ;;
            --capture-interface) shift; CAPTURE_INTERFACE="$1" ;;
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

    # Validate connection type
    case "$CONNECTIONS_TYPE" in
        all|established|listening) ;;
        *) log_error "Invalid connection type: $CONNECTIONS_TYPE. Use 'all', 'established', or 'listening'."; exit 1 ;;
    esac

    # Validate capture settings
    if [[ "$PACKET_CAPTURE" == true ]]; then
        if [[ "$CAPTURE_DURATION" -gt 0 ]]; then
             CAPTURE_PACKETS=0 # Duration takes precedence
             log_debug "Packet capture set by duration (${CAPTURE_DURATION}s)."
        elif [[ "$CAPTURE_PACKETS" -gt 0 ]]; then
             log_debug "Packet capture set by packet count (${CAPTURE_PACKETS})."
        else
             log_error "Packet capture enabled but no duration or packet count specified."
             exit 1
        fi
    fi
}

# --- Main Execution ---
main() {
    # Parse arguments
    parse_arguments "$@"

    # Initialize common functions (logging, CoC, tool paths)
    # Pass log paths and output dir if overridden by args
    init_common_functions "${LOG_FILE:-}" "${AUDIT_LOG_FILE:-}" "${OUTPUT_DIR:-}"

    log_info "Starting Network State Collection v${NETWORK_STATE_VERSION}"
    log_audit "Network State Collection Started"

    # Ensure base output directory exists
    ensure_output_dir "$OUTPUT_DIR" || error_exit "Failed to create base output directory: $OUTPUT_DIR"

    # Log parameters
    log_debug "Parameters: Output='$OUTPUT_DIR', Target='$TARGET_HOST', Connections='$CONNECTIONS_TYPE', Routing='$COLLECT_ROUTING', ARP='$COLLECT_ARP', DNS='$COLLECT_DNS', Interfaces='$COLLECT_INTERFACES', Capture='$PACKET_CAPTURE'"
    if [[ "$PACKET_CAPTURE" == true ]]; then
        log_debug "Capture Details: Duration='$CAPTURE_DURATION', Packets='$CAPTURE_PACKETS', Filter='$CAPTURE_FILTER', Interface='$CAPTURE_INTERFACE'"
    fi

    # Perform collections based on flags
    local collection_failed=false
    if [[ "$COLLECT_INTERFACES" == true ]]; then
        collect_interfaces || collection_failed=true
    fi
    if [[ "$COLLECT_ROUTING" == true ]]; then
        collect_routing || collection_failed=true
    fi
    if [[ "$COLLECT_ARP" == true ]]; then
        collect_arp || collection_failed=true
    fi
    if [[ "$COLLECT_DNS" == true ]]; then
        collect_dns || collection_failed=true
    fi
    # Always collect connections unless explicitly disabled (add --no-connections later if needed)
    collect_connections || collection_failed=true

    # Start packet capture if requested (runs in background for duration-based)
    if [[ "$PACKET_CAPTURE" == true ]]; then
        start_packet_capture || collection_failed=true
    fi

    log_info "Network State Collection Finished."
    if [[ "$collection_failed" == true ]]; then
        log_warn "One or more collection tasks failed. Check logs for details."
        log_audit "Network State Collection Finished with Errors"
        exit 1
    else
        log_audit "Network State Collection Finished Successfully"
        # If capture is duration-based, remind user it might still be running
        if [[ "$PACKET_CAPTURE" == true && "$CAPTURE_DURATION" -gt 0 ]]; then
             log_info "Packet capture is running in the background and will stop after ${CAPTURE_DURATION} seconds."
        fi
        exit 0
    fi
}

# Execute main function
main "$@"
