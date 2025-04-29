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
NETWORK_STATE_VERSION="1.1.0"
NETWORK_STATE_DATE="2024-08-16"

# --- Configuration Defaults ---
DEFAULT_OUTPUT_DIR="${OUTPUT_DIR:-/tmp/live_response_output_$$/network}" # Use common default or specific one
DEFAULT_CONNECTIONS_TYPE="all" # all, established, listening
DEFAULT_COLLECT_ROUTING=true
DEFAULT_COLLECT_ARP=true
DEFAULT_COLLECT_DNS=true
DEFAULT_COLLECT_INTERFACES=true
DEFAULT_COLLECT_FIREWALL=true
DEFAULT_COLLECT_SOCKET_STATS=true
DEFAULT_PACKET_CAPTURE=false
DEFAULT_CAPTURE_DURATION=60 # seconds
DEFAULT_CAPTURE_PACKETS=10000
DEFAULT_CAPTURE_FILTER=""
DEFAULT_CAPTURE_INTERFACE="any"
DEFAULT_CAPTURE_SNAPLEN=0 # Full packet capture
DEFAULT_COLLECT_LISTENING_HISTORY=true # Collect historical data of listening ports
DEFAULT_SUSPICIOUS_PORT_LIST="4444,5555,6666,1080,8080,31337,1723,3389,5900,5800" # Known potentially suspicious ports

# --- Global Variables ---
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
CONNECTIONS_TYPE="$DEFAULT_CONNECTIONS_TYPE"
COLLECT_ROUTING="$DEFAULT_COLLECT_ROUTING"
COLLECT_ARP="$DEFAULT_COLLECT_ARP"
COLLECT_DNS="$DEFAULT_COLLECT_DNS"
COLLECT_INTERFACES="$DEFAULT_COLLECT_INTERFACES"
COLLECT_FIREWALL="$DEFAULT_COLLECT_FIREWALL"
COLLECT_SOCKET_STATS="$DEFAULT_COLLECT_SOCKET_STATS"
PACKET_CAPTURE="$DEFAULT_PACKET_CAPTURE"
CAPTURE_DURATION="$DEFAULT_CAPTURE_DURATION"
CAPTURE_PACKETS="$DEFAULT_CAPTURE_PACKETS"
CAPTURE_FILTER="$DEFAULT_CAPTURE_FILTER"
CAPTURE_INTERFACE="$DEFAULT_CAPTURE_INTERFACE"
CAPTURE_SNAPLEN="$DEFAULT_CAPTURE_SNAPLEN"
COLLECT_LISTENING_HISTORY="$DEFAULT_COLLECT_LISTENING_HISTORY"
SUSPICIOUS_PORT_LIST="$DEFAULT_SUSPICIOUS_PORT_LIST"
TARGET_HOST=""
TARGET_USER="$USER"
SSH_KEY=""
SSH_PORT="$DEFAULT_REMOTE_PORT"
BULK_COLLECTION=false

# --- Function Definitions ---

# Display usage information
usage() {
    echo "Usage: $0 [--output <dir>] [--target <host>] [--user <user>] [--key <ssh_key>] [--port <ssh_port>]"
    echo "       [--connections <all|established|listening>] [--no-routing] [--no-arp] [--no-dns] [--no-interfaces]"
    echo "       [--no-firewall] [--no-socket-stats] [--suspicious-ports <list>]"
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
    echo "  --no-firewall          Do not collect firewall rules"
    echo "  --no-socket-stats      Do not collect detailed socket statistics"
    echo "  --suspicious-ports LIST Comma-separated list of suspicious ports to highlight"
    echo "  --bulk-collection      Enable comprehensive collection of all network data (long-running)"
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

        # If socket stats collection is enabled, gather detailed statistics
        if [[ "$COLLECT_SOCKET_STATS" == "true" ]]; then
            local socket_stats_cmd="$ss_path -s"
            local socket_stats_file="${output_subdir}/socket_stats.txt"
            if execute_and_save "$socket_stats_cmd" "$socket_stats_file" "Socket Statistics"; then
                log_success "Socket statistics collected to $socket_stats_file"
                log_coc_event "Complete" "Socket Statistics" "File: $socket_stats_file"
            fi
        fi
    elif [[ -n "$netstat_path" ]]; then
        cmd="$netstat_path $netstat_opts"
        output_file="${output_subdir}/netstat_${CONNECTIONS_TYPE}.txt"
        log_warn "ss command not found, falling back to netstat. Output format may vary."
        log_debug "Using netstat command: $cmd"

        # Collect socket stats using netstat -s if ss isn't available
        if [[ "$COLLECT_SOCKET_STATS" == "true" ]]; then
            local socket_stats_cmd="$netstat_path -s"
            local socket_stats_file="${output_subdir}/socket_stats.txt"
            if execute_and_save "$socket_stats_cmd" "$socket_stats_file" "Socket Statistics"; then
                log_success "Socket statistics collected to $socket_stats_file"
                log_coc_event "Complete" "Socket Statistics" "File: $socket_stats_file"
            fi
        fi
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

        # Generate connection summary and analyze for suspicious activity
        local summary_file="${output_subdir}/connection_summary.txt"
        {
            echo "NETWORK CONNECTION SUMMARY"
            echo "=========================="
            echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
            echo "Host: ${TARGET_HOST:-$(hostname)}"
            echo ""
            echo "CONNECTION COUNTS:"

            # Count by state
            echo "* By State:"
            if [[ -n "$ss_path" ]]; then
                echo "$result_content" | grep -v "^State" | awk '{print $1}' | sort | uniq -c | sort -nr
            else
                # For netstat format - might need adjustments based on OS
                echo "$result_content" | grep -v "^Active" | awk '{print $6}' | sort | uniq -c | sort -nr
            fi
            echo ""

            # List foreign addresses
            echo "* Top Remote Addresses:"
            if [[ -n "$ss_path" ]]; then
                echo "$result_content" | grep -v "^State" | awk '{print $5}' | grep -v "^[*:]" | \
                  sed 's/:[^:]*$//' | sort | uniq -c | sort -nr | head -10
            else
                echo "$result_content" | grep -v "^Active" | awk '{print $5}' | grep -v "^[*:]" | \
                  sed 's/:[^:]*$//' | sort | uniq -c | sort -nr | head -10
            fi
            echo ""

            # Check for suspicious ports
            IFS=',' read -ra SUSP_PORTS <<< "$SUSPICIOUS_PORT_LIST"
            echo "* Connections on Suspicious Ports:"
            found_suspicious=false
            for port in "${SUSP_PORTS[@]}"; do
                # Look for the port in either local or foreign addresses
                suspicious_lines=$(echo "$result_content" | grep -E ":(${port})\s")
                if [[ -n "$suspicious_lines" ]]; then
                    found_suspicious=true
                    echo "SUSPICIOUS PORT ${port} DETECTED:"
                    echo "$suspicious_lines"
                    echo ""
                fi
            done

            if [[ "$found_suspicious" == "false" ]]; then
                echo "No connections detected on suspicious ports."
            fi

        } > "$summary_file"

        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
        log_success "Network connection summary saved to $summary_file"
        log_coc_event "Analyzed" "Network Connections" "Summary: $summary_file"

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

    # Collect historical port usage if enabled
    if [[ "$COLLECT_LISTENING_HISTORY" == "true" ]]; then
        if [[ -n "$TARGET_HOST" ]]; then
            log_debug "Skipping historical listening port collection on remote host"
        else
            local history_file="${output_subdir}/listening_history.txt"
            {
                echo "HISTORICAL LISTENING PORT ANALYSIS"
                echo "=================================="
                echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
                echo ""

                # Try to find historical evidence of listening ports from auth log
                if [[ -f "/var/log/auth.log" ]]; then
                    echo "SSHD LISTENING HISTORY:"
                    grep "Server listening" /var/log/auth.log 2>/dev/null | tail -10
                    echo ""
                fi

                # Try to get service startup info from systemd journal
                if command -v journalctl &>/dev/null; then
                    echo "SERVICE PORT BINDINGS (from systemd journal):"
                    journalctl -b | grep -i "listening on" | grep -E "port|socket" | tail -20 2>/dev/null
                    echo ""
                fi

                # Check process command lines for listeners
                echo "CURRENT PROCESSES WITH LISTENER OPTIONS:"
                ps aux | grep -E "\-listen|\-port|\-p [0-9]+|--port" | grep -v grep
                echo ""

            } > "$history_file"
            chmod "$DEFAULT_EVIDENCE_PERMS" "$history_file"
            log_success "Listening port history saved to $history_file"
            log_coc_event "Collected" "Listening History" "File: $history_file"
        fi
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

        # Collect routing table with stats if available
        if execute_and_save "$cmd" "$output_file" "Routing Table"; then
            # Also collect details of routing rules if present
            if execute_and_save "$ip_path rule show" "${output_subdir}/ip_rule.txt" "IP Rules"; then
                log_success "IP rules collected"
            fi

            # Collect routing statistics
            if execute_and_save "$ip_path -s route show" "${output_subdir}/ip_route_stats.txt" "Routing Statistics"; then
                log_success "Routing statistics collected"
            fi
        fi

    elif [[ -n "$route_path" ]]; then
        cmd="$route_path -n" # Numeric output
        output_file="${output_subdir}/route_n.txt"
        log_warn "ip command not found, falling back to route."
        log_debug "Using route command: $cmd"

        execute_and_save "$cmd" "$output_file" "Routing Table"

        # Also collect routing statistics if using route command
        if execute_and_save "$route_path -ee -n" "${output_subdir}/route_stats.txt" "Routing Statistics"; then
            log_success "Extended routing information collected"
        fi

    else
        log_error "Neither ip route nor route found. Cannot collect routing table."
        log_coc_event "Fail" "Routing Table" "Tools ip and route not found"
        return 1
    fi

    # Create a summary file for routing information
    local summary_file="${output_subdir}/routing_summary.txt"
    {
        echo "ROUTING SUMMARY"
        echo "==============="
        echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo ""
        echo "DEFAULT ROUTES:"
        if [[ -n "$ip_path" ]]; then
            execute_command "$ip_path route show default" || echo "No default routes found"
        elif [[ -n "$route_path" ]]; then
            execute_command "$route_path -n | grep ^0\\.0\\.0\\.0" || echo "No default routes found"
        fi
        echo ""
        echo "ROUTING TABLE INTEGRITY CHECK:"
        echo "- Looking for potential suspicious routes..."

        # Check for unusual routes (specific IP ranges that might be suspicious)
        # This is just an example and should be tailored to the specific environment
        if [[ -f "$output_file" ]]; then
            grep -E "10\\.0\\.0\\.0/8|172\\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\\.0\\.0/12|192\\.168\\.0\\.0/16" "$output_file" || echo "No private network routes found."
        else
            echo "Could not check routing table file."
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "Routing summary saved to $summary_file"
    log_coc_event "Analyzed" "Routing Table" "Summary: $summary_file"

    return 0
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

        # Get neighbor statistics and state
        execute_and_save "$cmd" "$output_file" "ARP Cache"

        # Also capture neighbor statistics with counters
        execute_and_save "$ip_path -s neigh show" "${output_subdir}/ip_neigh_stats.txt" "ARP Statistics"

    elif [[ -n "$arp_path" ]]; then
        cmd="$arp_path -an" # Numeric output
        output_file="${output_subdir}/arp_an.txt"
        log_warn "ip command not found, falling back to arp."
        log_debug "Using arp command: $cmd"

        # Basic ARP table
        execute_and_save "$cmd" "$output_file" "ARP Cache"

        # Also try verbose output option if available
        execute_and_save "$arp_path -anv" "${output_subdir}/arp_anv.txt" "Detailed ARP Cache"

    else
        log_error "Neither ip neigh nor arp found. Cannot collect ARP cache."
        log_coc_event "Fail" "ARP Cache" "Tools ip and arp not found"
        return 1
    fi

    # Create a summary and analysis file
    local summary_file="${output_subdir}/arp_summary.txt"
    {
        echo "ARP CACHE SUMMARY AND ANALYSIS"
        echo "=============================="
        echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo ""

        # Count entries by state
        if [[ -n "$ip_path" && -f "$output_file" ]]; then
            echo "NEIGHBOR STATES:"
            grep -o "[[:space:]][[:alpha:]]\+$" "$output_file" | sort | uniq -c | sort -nr
            echo ""

            # Look for potential ARP spoofing (duplicate MAC addresses for different IPs)
            echo "CHECKING FOR POTENTIAL ARP ISSUES:"
            echo "- Duplicate MAC addresses (could indicate ARP spoofing):"
            duplicate_macs=$(grep -o "[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+" "$output_file" | sort | uniq -d)
            if [[ -n "$duplicate_macs" ]]; then
                echo "  WARNING: Found duplicate MAC addresses:"
                for mac in $duplicate_macs; do
                    echo "  $mac appears multiple times:"
                    grep "$mac" "$output_file"
                done
            else
                echo "  No duplicate MAC addresses found."
            fi
        elif [[ -n "$arp_path" && -f "$output_file" ]]; then
            echo "ARP ENTRY TYPES:"
            grep -o "type [^ ]\+" "$output_file" | sort | uniq -c | sort -nr
            echo ""

            # Look for potential ARP spoofing
            echo "CHECKING FOR POTENTIAL ARP ISSUES:"
            echo "- Duplicate MAC addresses (could indicate ARP spoofing):"
            duplicate_macs=$(grep -o "[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+:[0-9a-f]\+" "$output_file" | sort | uniq -d)
            if [[ -n "$duplicate_macs" ]]; then
                echo "  WARNING: Found duplicate MAC addresses:"
                for mac in $duplicate_macs; do
                    echo "  $mac appears multiple times:"
                    grep "$mac" "$output_file"
                done
            else
                echo "  No duplicate MAC addresses found."
            fi
        else
            echo "Could not analyze ARP cache structure (no output file available)"
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "ARP summary and analysis saved to $summary_file"
    log_coc_event "Analyzed" "ARP Cache" "Summary: $summary_file"

    return 0
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

            # Also collect DNS statistics
            execute_and_save "$resolvectl_path statistics" "${output_subdir}/resolvectl_statistics.txt" "DNS Statistics"
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

    # 4. Check if dnsmasq is running and collect its leases
    local dnsmasq_leases="/var/lib/misc/dnsmasq.leases"
    if [[ -f "$dnsmasq_leases" && -z "$TARGET_HOST" ]]; then
        cp "$dnsmasq_leases" "${output_subdir}/dnsmasq_leases.txt" && chmod "$DEFAULT_EVIDENCE_PERMS" "${output_subdir}/dnsmasq_leases.txt"
        log_success "Saved dnsmasq leases to ${output_subdir}/dnsmasq_leases.txt"
        success=true
    fi

    # 5. Try to collect DNS cache entries
    if [[ -z "$TARGET_HOST" ]]; then
        # Check if we can query the local DNS cache
        local dig_path=$(get_tool_path "network_state" "dig")
        if [[ -n "$dig_path" ]]; then
            # Try to query commonly visited domains from cache
            local common_domains=("google.com" "microsoft.com" "apple.com" "amazon.com" "facebook.com" "github.com")
            local cache_output="${output_subdir}/dns_cache_query.txt"
            {
                echo "DNS CACHE QUERY RESULTS"
                echo "======================"
                echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
                echo ""

                for domain in "${common_domains[@]}"; do
                    echo "Query for $domain:"
                    $dig_path +short +nocmd +noall +answer +ttl "$domain" 2>/dev/null || echo "No cached result."
                    echo ""
                done

            } > "$cache_output"
            chmod "$DEFAULT_EVIDENCE_PERMS" "$cache_output"
            log_success "DNS cache query results saved to $cache_output"
            success=true
        fi
    fi

    # Create a DNS configuration summary
    local summary_file="${output_subdir}/dns_summary.txt"
    {
        echo "DNS CONFIGURATION SUMMARY"
        echo "========================="
        echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo ""

        echo "NAMESERVERS:"
        if [[ -f "$output_file" ]]; then
            grep "nameserver" "$output_file" 2>/dev/null || echo "No nameservers found in resolv.conf"
        else
            echo "Could not analyze resolv.conf (file not available)"
        fi
        echo ""

        echo "SEARCH DOMAINS:"
        if [[ -f "$output_file" ]]; then
            grep "search" "$output_file" 2>/dev/null || echo "No search domains found in resolv.conf"
        else
            echo "Could not analyze resolv.conf (file not available)"
        fi
        echo ""

        # Add information about DNS resolution capabilities
        echo "DNS RESOLUTION TEST:"
        if [[ -z "$TARGET_HOST" ]]; then
            # Test DNS resolution of known domains
            for test_domain in "google.com" "microsoft.com" "example.com"; do
                echo -n "Resolving $test_domain: "
                if host "$test_domain" &>/dev/null; then
                    echo "SUCCESS"
                else
                    echo "FAILED"
                fi
            done
        else
            echo "DNS resolution test skipped for remote host."
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "DNS summary saved to $summary_file"
    log_coc_event "Analyzed" "DNS Information" "Summary: $summary_file"

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

        # Collect statistics for interfaces
        cmd_stats="$ip_path -s link show"
        output_file_stats="${output_subdir}/ip_link_stats.txt"
        if execute_and_save "$cmd_stats" "$output_file_stats" "Network Interface Statistics"; then
            log_success "Network interface statistics collected to $output_file_stats"
            success=true
        fi

        # Get detailed interface information including driver
        if [[ -z "$TARGET_HOST" ]]; then
            # These commands typically only make sense locally
            local ethtool_path=$(get_tool_path "network_state" "ethtool")
            if [[ -n "$ethtool_path" ]]; then
                # Get list of interfaces to query
                local interfaces
                interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")

                for iface in $interfaces; do
                    output_file_ethtool="${output_subdir}/ethtool_${iface}.txt"
                    {
                        echo "INTERFACE: $iface"
                        echo "=============="
                        echo "DRIVER INFO:"
                        $ethtool_path -i "$iface" 2>/dev/null || echo "No driver info available"
                        echo ""
                        echo "LINK STATUS:"
                        $ethtool_path "$iface" 2>/dev/null || echo "No link status available"
                        echo ""
                        echo "STATISTICS:"
                        $ethtool_path -S "$iface" 2>/dev/null || echo "No statistics available"
                    } > "$output_file_ethtool"
                    chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file_ethtool"
                    log_success "Detailed interface info for $iface saved to $output_file_ethtool"
                done
                success=true
            fi
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

    # Check for promiscuous mode interfaces (potential packet sniffing)
    local summary_file="${output_subdir}/interface_summary.txt"
    {
        echo "INTERFACE SUMMARY AND ANALYSIS"
        echo "=============================="
        echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo ""

        echo "ACTIVE INTERFACES:"
        if [[ -n "$ip_path" ]]; then
            $ip_path -br addr show | grep -v "^lo" || echo "No active interfaces found"
        elif [[ -n "$ifconfig_path" ]]; then
            $ifconfig_path -s | grep -v "^lo" | grep -v "^Iface" || echo "No active interfaces found"
        else
            echo "Could not detect active interfaces (no tools available)"
        fi
        echo ""

        echo "INTERFACE STATUS CHECK:"

        # Check for promiscuous mode
        echo "* Checking for promiscuous mode interfaces (potential sniffing):"
        if [[ -n "$ip_path" && -f "$output_file_link" ]]; then
            grep -E "PROMISC" "$output_file_link" && echo "  WARNING: Interface(s) in promiscuous mode detected!"
        elif [[ -n "$ifconfig_path" && -f "$output_file" ]]; then
            grep -E "PROMISC" "$output_file" && echo "  WARNING: Interface(s) in promiscuous mode detected!"
        else
            echo "  Could not check for promiscuous mode"
        fi

        # Check for unknown interfaces
        echo "* Checking for potentially rogue interfaces:"
        if [[ -n "$ip_path" ]]; then
            interfaces=$($ip_path link show | grep -v "lo:" | grep -E "^[0-9]+:" | awk -F': ' '{print $2}')
            for iface in $interfaces; do
                # Skip virtual interfaces that are expected
                if [[ "$iface" == "docker"* || "$iface" == "veth"* || "$iface" == "br-"* || "$iface" == "virbr"* ]]; then
                    continue
                fi

                # Check for unusual interfaces (highly system dependent)
                if [[ "$iface" != "eth"* && "$iface" != "en"* && "$iface" != "wl"* ]]; then
                    echo "  Note: Unusual interface name detected: $iface"
                fi
            done
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "Interface summary and analysis saved to $summary_file"
    log_coc_event "Analyzed" "Network Interfaces" "Summary: $summary_file"

    if [[ "$success" != true ]]; then
        log_warn "Failed to collect network interface details."
        return 1
    fi

    return 0
}

# Collect firewall configuration and rules
collect_firewall() {
    local output_subdir="${OUTPUT_DIR}/firewall"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting firewall configuration..."
    log_coc_event "Start" "Firewall Configuration"

    local success=false

    # Check for different firewall types
    local iptables_path=$(get_tool_path "network_state" "iptables")
    local nftables_path=$(get_tool_path "network_state" "nft")
    local firewalld_path=$(get_tool_path "network_state" "firewall-cmd")
    local ufw_path=$(get_tool_path "network_state" "ufw")

    # 1. Check iptables if available
    if [[ -n "$iptables_path" ]]; then
        # Save rules from all tables
        for table in filter nat mangle raw; do
            local cmd="$iptables_path -t $table -L -v -n --line-numbers"
            local output_file="${output_subdir}/iptables_${table}.txt"
            if execute_and_save "$cmd" "$output_file" "IPTables ($table)"; then
                log_success "IPTables $table rules saved to $output_file"
                success=true
            fi
        done

        # Also save rules in iptables-save format which is more machine-readable
        local cmd="$iptables_path-save"
        local output_file="${output_subdir}/iptables_save.txt"
        if execute_and_save "$cmd" "$output_file" "IPTables Save Format"; then
            log_success "IPTables save format saved to $output_file"
            success=true
        fi
    fi

    # 2. Check for nftables
    if [[ -n "$nftables_path" ]]; then
        # List all tables, chains, and rules
        local cmd="$nftables_path list ruleset"
        local output_file="${output_subdir}/nftables_ruleset.txt"
        if execute_and_save "$cmd" "$output_file" "NFTables Ruleset"; then
            log_success "NFTables ruleset saved to $output_file"
            success=true
        fi
    fi

    # 3. Check for firewalld
    if [[ -n "$firewalld_path" ]]; then
        # Get firewalld status and configuration
        local cmd="$firewalld_path --state && echo 'FirewallD is running' || echo 'FirewallD is not running'"
        local output_file="${output_subdir}/firewalld_status.txt"
        if execute_and_save "$cmd" "$output_file" "FirewallD Status"; then
            success=true

            # If firewalld is running, get additional configuration
            if grep -q "FirewallD is running" "$output_file"; then
                # List zones
                cmd="$firewalld_path --list-all-zones"
                output_file="${output_subdir}/firewalld_zones.txt"
                if execute_and_save "$cmd" "$output_file" "FirewallD Zones"; then
                    log_success "FirewallD zones saved to $output_file"
                fi

                # Get default zone
                cmd="$firewalld_path --get-default-zone"
                output_file="${output_subdir}/firewalld_default_zone.txt"
                if execute_and_save "$cmd" "$output_file" "FirewallD Default Zone"; then
                    log_success "FirewallD default zone saved to $output_file"
                fi

                # Get active zones
                cmd="$firewalld_path --get-active-zones"
                output_file="${output_subdir}/firewalld_active_zones.txt"
                if execute_and_save "$cmd" "$output_file" "FirewallD Active Zones"; then
                    log_success "FirewallD active zones saved to $output_file"
                fi
            fi
        fi
    fi

    # 4. Check for ufw
    if [[ -n "$ufw_path" ]]; then
        # Get ufw status
        local cmd="$ufw_path status verbose"
        local output_file="${output_subdir}/ufw_status.txt"
        if execute_and_save "$cmd" "$output_file" "UFW Status"; then
            log_success "UFW status saved to $output_file"
            success=true
        fi
    fi

    # Create a firewall summary with potential issues highlighted
    local summary_file="${output_subdir}/firewall_summary.txt"
    {
        echo "FIREWALL CONFIGURATION SUMMARY"
        echo "=============================="
        echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo ""

        echo "DETECTED FIREWALL TECHNOLOGIES:"
        [[ -n "$iptables_path" ]] && echo "- iptables: Available"
        [[ -n "$nftables_path" ]] && echo "- nftables: Available"
        [[ -n "$firewalld_path" ]] && echo "- firewalld: Available"
        [[ -n "$ufw_path" ]] && echo "- ufw: Available"
        [[ -z "$iptables_path" && -z "$nftables_path" && -z "$firewalld_path" && -z "$ufw_path" ]] && \
            echo "No firewall technologies detected!"
        echo ""

        # Basic security analysis
        echo "SECURITY ANALYSIS:"

        # Check for default policies if iptables is used
        if [[ -n "$iptables_path" && -f "${output_subdir}/iptables_filter.txt" ]]; then
            echo "* Default policies:"
            grep "Chain .* policy" "${output_subdir}/iptables_filter.txt" || echo "  Could not determine default policies"

            # Check for potentially insecure rules
            echo "* Checking for potentially insecure rules:"
            grep -E "ACCEPT.*(0\.0\.0\.0|::|anywhere)" "${output_subdir}/iptables_filter.txt" > "${output_subdir}/suspicious_rules.tmp"
            if [[ -s "${output_subdir}/suspicious_rules.tmp" ]]; then
                echo "  WARNING: Potentially overly permissive rules found:"
                cat "${output_subdir}/suspicious_rules.tmp"
            else
                echo "  No obviously insecure rules found."
            fi
            rm -f "${output_subdir}/suspicious_rules.tmp"
        elif [[ -n "$firewalld_path" && -f "${output_subdir}/firewalld_status.txt" ]]; then
            # Simple checks for firewalld
            if grep -q "FirewallD is not running" "${output_subdir}/firewalld_status.txt"; then
                echo "* WARNING: FirewallD is installed but not running!"
            fi

            # Check if SSH is open to public in firewalld
            if [[ -f "${output_subdir}/firewalld_zones.txt" ]]; then
                if grep -A20 "public" "${output_subdir}/firewalld_zones.txt" | grep -q "services:.*ssh"; then
                    echo "* NOTE: SSH is enabled in public zone"
                fi
            fi
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "Firewall summary and analysis saved to $summary_file"
    log_coc_event "Analyzed" "Firewall Configuration" "Summary: $summary_file"

    if [[ "$success" != true ]]; then
        log_warn "Could not collect firewall configuration. No supported firewall detected."
        log_coc_event "Complete" "Firewall Configuration" "No firewall detected"
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

    local cmd_opts="-i $CAPTURE_INTERFACE -w $output_file"

    # Set snap length (0 means full packet)
    cmd_opts+=" -s $CAPTURE_SNAPLEN"

    # Add timestamp precision for better forensic value
    cmd_opts+=" --time-stamp-precision=micro"

    # Add verbose packet info to log file
    local log_file="${output_subdir}/capture_${CAPTURE_INTERFACE}_${timestamp}.log"
    local cmd_log_opts="$cmd_opts -v"

    # Add count or duration limit
    if [[ "$CAPTURE_DURATION" -gt 0 ]]; then
        # tcpdump doesn't have a direct duration option like tshark, run in background and kill
        cmd_opts+=" -c 999999999" # Effectively unlimited count for duration-based capture
        cmd_log_opts+=" -c 999999999"
    elif [[ "$CAPTURE_PACKETS" -gt 0 ]]; then
        cmd_opts+=" -c $CAPTURE_PACKETS"
        cmd_log_opts+=" -c $CAPTURE_PACKETS"
    else
        log_error "Packet capture requested but no duration or packet count specified."
        return 1
    fi

    # Add filter if specified
    if [[ -n "$CAPTURE_FILTER" ]]; then
        cmd_opts+=" $CAPTURE_FILTER"
        cmd_log_opts+=" $CAPTURE_FILTER"
    fi

    local full_cmd="$tcpdump_path $cmd_opts"
    local log_cmd="$tcpdump_path $cmd_log_opts >> $log_file 2>&1"

    log_info "Running capture command: $full_cmd"

    # Run tcpdump in the background
    if [[ -n "$TARGET_HOST" ]]; then
        log_error "Background packet capture on remote host not directly supported by this script version."
        log_warn "Consider running tcpdump manually on the target or using a dedicated remote capture tool."
        log_coc_event "Fail" "Packet Capture" "Remote background capture not supported"
        return 1
    else
        # Run locally in background for packet capture
        eval "$full_cmd" &
        local tcpdump_pid=$!
        echo "$tcpdump_pid" > "$pid_file"
        log_info "Packet capture started in background (PID: $tcpdump_pid). Output: $output_file"

        # Run a second instance with logging enabled (only if bulk collection enabled)
        if [[ "$BULK_COLLECTION" == "true" ]]; then
            eval "$log_cmd" &
            log_info "Packet capture logging started. Log file: $log_file"
        fi

        # If duration based, schedule a kill
        if [[ "$CAPTURE_DURATION" -gt 0 ]]; then
            log_info "Capture will run for ${CAPTURE_DURATION} seconds."
            (
              sleep "$CAPTURE_DURATION"
              # Kill the process if still running
              if [[ -f "$pid_file" ]]; then
                pid=$(cat "$pid_file")
                if kill -0 "$pid" 2>/dev/null; then
                  kill "$pid" 2>/dev/null
                  log_info "Packet capture duration ended, process $pid terminated."

                  # Create a summary of the capture
                  local summary_file="${output_subdir}/capture_summary.txt"
                  if [[ -f "$output_file" ]]; then
                    {
                      echo "PACKET CAPTURE SUMMARY"
                      echo "====================="
                      echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
                      echo "Capture file: $output_file"
                      echo "Interface: $CAPTURE_INTERFACE"
                      echo "Duration: ${CAPTURE_DURATION}s"
                      echo "Filter: ${CAPTURE_FILTER:-None}"
                      echo ""

                      echo "CAPTURE STATISTICS:"
                      # Get basic statistics using tcpdump -r
                      $tcpdump_path -r "$output_file" -qn 2>/dev/null | head -5

                      echo ""
                      echo "PACKET COUNT BY PROTOCOL:"
                      $tcpdump_path -r "$output_file" -qn 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr

                    } > "$summary_file"
                    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
                    log_success "Capture summary saved to $summary_file"
                  fi

                  # Log completed event
                  log_coc_event "Complete" "Packet Capture" "File: $output_file, Duration: ${CAPTURE_DURATION}s"
                fi
                rm -f "$pid_file"
              fi
            ) &
        else
             log_info "Capture will stop after $CAPTURE_PACKETS packets."
             # We need to wait for tcpdump to finish if it's count-based
             wait "$tcpdump_pid"
             local capture_status=$?
             rm -f "$pid_file"
             if [[ $capture_status -eq 0 ]]; then
                 log_success "Packet capture completed successfully."
                 log_coc_event "Complete" "Packet Capture" "File: $output_file, Packets: $CAPTURE_PACKETS"

                 # Create a summary of the capture
                 local summary_file="${output_subdir}/capture_summary.txt"
                 {
                   echo "PACKET CAPTURE SUMMARY"
                   echo "====================="
                   echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
                   echo "Capture file: $output_file"
                   echo "Interface: $CAPTURE_INTERFACE"
                   echo "Packet count: $CAPTURE_PACKETS"
                   echo "Filter: ${CAPTURE_FILTER:-None}"
                   echo ""

                   echo "CAPTURE STATISTICS:"
                   # Get basic statistics using tcpdump -r
                   $tcpdump_path -r "$output_file" -qn 2>/dev/null | head -5

                   echo ""
                   echo "PACKET COUNT BY PROTOCOL:"
                   $tcpdump_path -r "$output_file" -qn 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr

                 } > "$summary_file"
                 chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
                 log_success "Capture summary saved to $summary_file"
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
            --no-firewall) COLLECT_FIREWALL=false ;;
            --no-socket-stats) COLLECT_SOCKET_STATS=false ;;
            --suspicious-ports) shift; SUSPICIOUS_PORT_LIST="$1" ;;
            --bulk-collection) BULK_COLLECTION=true ;;
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

    # If bulk collection is enabled, ensure we collect everything
    if [[ "$BULK_COLLECTION" == true ]]; then
        log_info "Bulk collection mode enabled - collecting all network data"
        COLLECT_ROUTING=true
        COLLECT_ARP=true
        COLLECT_DNS=true
        COLLECT_INTERFACES=true
        COLLECT_FIREWALL=true
        COLLECT_SOCKET_STATS=true
        COLLECT_LISTENING_HISTORY=true

        # Enable packet capture if not already enabled
        if [[ "$PACKET_CAPTURE" != true ]]; then
            PACKET_CAPTURE=true
            CAPTURE_DURATION=300 # 5 minutes by default for bulk collection
            log_info "Enabled packet capture for bulk collection mode"
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

    # Create an execution metadata file for reference
    local metadata_file="${OUTPUT_DIR}/collection_metadata.json"
    {
        echo "{"
        echo "  \"script_version\": \"${NETWORK_STATE_VERSION}\","
        echo "  \"timestamp\": \"$(date -u "+%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"host\": \"${TARGET_HOST:-$(hostname)}\","
        echo "  \"collections\": {"
        echo "    \"connections\": true,"
        echo "    \"routing\": ${COLLECT_ROUTING},"
        echo "    \"arp\": ${COLLECT_ARP},"
        echo "    \"dns\": ${COLLECT_DNS},"
        echo "    \"interfaces\": ${COLLECT_INTERFACES},"
        echo "    \"firewall\": ${COLLECT_FIREWALL},"
        echo "    \"socket_stats\": ${COLLECT_SOCKET_STATS},"
        echo "    \"packet_capture\": ${PACKET_CAPTURE}"
        echo "  },"
        echo "  \"case_id\": \"${CASE_ID:-not_specified}\","
        echo "  \"examiner_id\": \"${EXAMINER_ID:-not_specified}\""
        echo "}"
    } > "$metadata_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$metadata_file"

    # Log parameters
    log_debug "Parameters: Output='$OUTPUT_DIR', Target='$TARGET_HOST', Connections='$CONNECTIONS_TYPE', Routing='$COLLECT_ROUTING', ARP='$COLLECT_ARP', DNS='$COLLECT_DNS', Interfaces='$COLLECT_INTERFACES', Firewall='$COLLECT_FIREWALL', Socket Stats='$COLLECT_SOCKET_STATS', Capture='$PACKET_CAPTURE'"
    if [[ "$PACKET_CAPTURE" == true ]]; then
        log_debug "Capture Details: Duration='$CAPTURE_DURATION', Packets='$CAPTURE_PACKETS', Filter='$CAPTURE_FILTER', Interface='$CAPTURE_INTERFACE', Snaplen='$CAPTURE_SNAPLEN'"
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
    if [[ "$COLLECT_FIREWALL" == true ]]; then
        collect_firewall || collection_failed=true
    fi
    # Always collect connections unless explicitly disabled (add --no-connections later if needed)
    collect_connections || collection_failed=true

    # Start packet capture if requested (runs in background for duration-based)
    if [[ "$PACKET_CAPTURE" == true ]]; then
        start_packet_capture || collection_failed=true
    fi

    # Create a network state summary file
    local summary_file="${OUTPUT_DIR}/network_state_summary.txt"
    {
        echo "NETWORK STATE SUMMARY"
        echo "===================="
        echo "Collection Date: $(date -u "+%Y-%m-%d %H:%M:%S UTC")"
        echo "Host: ${TARGET_HOST:-$(hostname)}"
        echo "Case ID: ${CASE_ID:-Not Specified}"
        echo "Examiner ID: ${EXAMINER_ID:-Not Specified}"
        echo ""

        echo "COLLECTION MODULES EXECUTED:"
        echo "- Network Connections: Enabled (Type: $CONNECTIONS_TYPE)"
        [[ "$COLLECT_INTERFACES" == "true" ]] && echo "- Network Interfaces: Enabled" || echo "- Network Interfaces: Disabled"
        [[ "$COLLECT_ROUTING" == "true" ]] && echo "- Routing Tables: Enabled" || echo "- Routing Tables: Disabled"
        [[ "$COLLECT_ARP" == "true" ]] && echo "- ARP Cache: Enabled" || echo "- ARP Cache: Disabled"
        [[ "$COLLECT_DNS" == "true" ]] && echo "- DNS Information: Enabled" || echo "- DNS Information: Disabled"
        [[ "$COLLECT_FIREWALL" == "true" ]] && echo "- Firewall Rules: Enabled" || echo "- Firewall Rules: Disabled"
        [[ "$PACKET_CAPTURE" == "true" ]] && echo "- Packet Capture: Enabled (Interface: $CAPTURE_INTERFACE, Duration: ${CAPTURE_DURATION}s, Packets: ${CAPTURE_PACKETS})" || echo "- Packet Capture: Disabled"
        echo ""

        # Print overall system network information
        echo "SYSTEM NETWORK SUMMARY:"
        echo "* Hostname: $(hostname)"

        # Get primary IP address using hostname -I if available
        if command -v hostname &> /dev/null; then
            echo "* IP Addresses: $(hostname -I 2>/dev/null || echo "Could not determine")"
        fi

        # Summarize active connections
        if ss -s &> /dev/null; then
            echo "* Connection statistics:"
            ss -s | head -5
        elif netstat -s &> /dev/null; then
            echo "* Connection statistics:"
            netstat -s | head -5
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "Network state summary created: $summary_file"
    log_coc_event "Created" "Network State Summary" "File: $summary_file"

    log_info "Network State Collection Finished."
    if [[ "$collection_failed" == true ]]; then
        log_warn "One or more collection tasks failed. Check logs for details."
        log_audit "Network State Collection Finished with Errors"
        exit 1
    else
        log_audit "Network State Collection Finished Successfully"
        # Inform user about duration-based packet capture if it's running
        if [[ "$PACKET_CAPTURE" == true && "$CAPTURE_DURATION" -gt 0 ]]; then
            log_info "Note: Duration-based packet capture is still running in background."
            log_info "Capture will complete in $CAPTURE_DURATION seconds."
            log_info "Output will be saved to: ${OUTPUT_DIR}/capture/"
        fi
        exit 0
    fi
}

# --- Additional Utility Functions ---

# Check if a network port is potentially suspicious
# Arguments:
#   $1: Port number
# Returns:
#   0 if suspicious, 1 if not
is_suspicious_port() {
    local port="$1"
    local suspicious_ports
    IFS=',' read -ra suspicious_ports <<< "$SUSPICIOUS_PORT_LIST"

    for susp_port in "${suspicious_ports[@]}"; do
        if [[ "$port" == "$susp_port" ]]; then
            return 0
        fi
    done
    return 1
}

# Get a list of active network interfaces (excluding loopback)
# Returns:
#   List of interface names, one per line
get_active_interfaces() {
    local interfaces=""

    if command -v ip &>/dev/null; then
        interfaces=$(ip -o link show | grep -v "LOOPBACK" | awk -F': ' '{print $2}')
    elif command -v ifconfig &>/dev/null; then
        interfaces=$(ifconfig -a | grep -E '^[a-z0-9]+:' | grep -v "^lo:" | cut -d: -f1)
    fi

    echo "$interfaces"
}

# Format a TCP/UDP port list for readability
# Arguments:
#   $1: Format (text or json)
#   $2: Port data (from ss or netstat)
# Returns:
#   Formatted port data
format_port_list() {
    local format="${1:-text}"
    local port_data="$2"
    local output=""

    case "$format" in
        json)
            output+='{"ports":['
            local first=true
            while read -r port_line; do
                if [[ -n "$port_line" ]]; then
                    IFS=' ' read -ra parts <<< "$port_line"
                    local port="${parts[0]}"
                    local count="${parts[1]}"
                    local suspicious="false"
                    is_suspicious_port "$port" && suspicious="true"

                    if [[ "$first" == "true" ]]; then
                        first=false
                    else
                        output+=","
                    fi
                    output+="{\"port\":$port,\"count\":$count,\"suspicious\":$suspicious}"
                fi
            done <<< "$port_data"
            output+="]}"
            ;;
        *)
            # Default text format
            output+="PORT COUNT SUSPICIOUS\n"
            while read -r port_line; do
                if [[ -n "$port_line" ]]; then
                    IFS=' ' read -ra parts <<< "$port_line"
                    local port="${parts[0]}"
                    local count="${parts[1]}"
                    local suspicious=" "
                    is_suspicious_port "$port" && suspicious="*"
                    output+="$port $count $suspicious\n"
                fi
            done <<< "$port_data"
            ;;
    esac

    echo -e "$output"
}

# Stop running packet captures gracefully
# Arguments:
#   $1: Output directory path
stop_packet_captures() {
    local capture_dir="${1:-${OUTPUT_DIR}/capture}"
    local pid_file="${capture_dir}/tcpdump.pid"

    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping active packet capture (PID: $pid)..."
            kill "$pid" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_success "Packet capture stopped gracefully."
                log_coc_event "Stopped" "Packet Capture" "Terminated early by user"
                rm -f "$pid_file"
                return 0
            else
                log_error "Failed to stop packet capture."
                return 1
            fi
        else
            log_warn "Packet capture process (PID: $pid) not running."
            rm -f "$pid_file"
        fi
    else
        log_info "No active packet captures found."
    fi
    return 0
}

# Execute main function when script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Execute main function with all passed arguments
    main "$@"
    exit $?
fi
