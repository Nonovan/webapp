#!/bin/bash
# filepath: scripts/utils/common/common_network_utils.sh
# Network utility functions for Cloud Infrastructure Platform
# This script provides various network-related functions for
# Checking connectivity, resolving hostnames, and retrieving IP addresses.

# Check if required functions are available
for func in is_valid_url is_number command_exists log is_valid_ip execute_with_timeout; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_functions.sh first." >&2
        exit 1
    fi
done

#######################################
# NETWORK OPERATIONS
#######################################

# Check if URL is reachable
# Arguments:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional - defaults to 10)
#   $3 - Additional options for curl/wget (optional)
# Returns:
#   0 if reachable, 1 if not reachable, 2 on error
is_url_reachable() {
    local url="$1"
    local timeout="${2:-10}"
    local options="${3:-}"

    # Sanitize options to prevent command injection
    if [[ -n "$options" ]]; then
        # Remove potentially dangerous characters
        options=$(echo "$options" | tr -cd 'a-zA-Z0-9 =-_.')
    fi

    # Validate URL
    if ! is_valid_url "$url"; then
        log "Invalid URL format: $url" "ERROR"
        return 2
    fi

    # Validate timeout
    if ! is_number "$timeout"; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 2
    fi

    if command_exists curl; then
        # Use curl with explicit error handling
        if curl --output /dev/null --silent --head --fail --max-time "$timeout" $options "$url"; then
            return 0
        fi
    elif command_exists wget; then
        # Use wget with timeout
        if wget --quiet --spider --timeout="$timeout" $options "$url"; then
            return 0
        fi
    else
        log "Neither curl nor wget available to check URL" "WARNING"
        return 2
    fi

    return 1
}

# Get public IP address
# Arguments:
#   None
# Returns:
#   Public IP address on success, error message on failure
get_public_ip() {
    local ip=""
    local timeout=5
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
        "https://checkip.amazonaws.com"
    )

    for service in "${services[@]}"; do
        if command_exists curl; then
            ip=$(curl -s --max-time "$timeout" "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout="$timeout" "$service" 2>/dev/null)
        else
            echo "ERROR: Neither curl nor wget are available"
            return 1
        fi

        # Check if we got a valid IP
        if [[ -n "$ip" ]]; then
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                echo "$ip"
                return 0
            fi
        fi
    done

    log "ERROR: Could not determine public IP address" "ERROR"

    echo "ERROR: Could not determine public IP address"
    return 1
}

# Check if host is reachable via ping
# Arguments:
#   $1 - Host to ping
#   $2 - Number of packets (optional - defaults to 1)
#   $3 - Timeout in seconds (optional - defaults to 2)
# Returns:
#   0 if reachable, 1 if not, 2 on error
ping_host() {
    local host="$1"
    local count="${2:-1}"
    local timeout="${3:-2}"
    local cmd=""

    # Validate host
    if [[ -z "$host" ]]; then
        log "No host provided for ping" "ERROR"
        return 2
    fi

    # Validate count
    if ! is_number "$count" || [[ $count -lt 1 ]]; then
        log "Invalid ping count: $count" "ERROR"
        return 2
    fi

    # Validate timeout
    if ! is_number "$timeout" || [[ $timeout -lt 1 ]]; then
        log "Invalid ping timeout: $timeout" "ERROR"
        return 2
    fi

    # Check if ping is available
    if ! command_exists ping; then
        log "Ping command is not available" "ERROR"
        return 2
    fi

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS uses -t for timeout in seconds
        cmd="ping -c $count -t $timeout $host"
    else
        # Linux uses -W for timeout in seconds
        cmd="ping -c $count -W $timeout $host"
    fi

    # Execute the ping command with timeout
    if execute_with_timeout $((timeout + 2)) $cmd &>/dev/null; then
        return 0
    fi

    return 1
}

# Get primary DNS servers
# Arguments:
#   None
# Returns:
#   List of DNS servers, one per line
get_dns_servers() {
    local servers=""

    if [[ -f /etc/resolv.conf ]]; then
        servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}')
    fi

    # If no servers found, try alternative methods
    if [[ -z "$servers" ]]; then
        if command_exists systemd-resolve; then
            servers=$(systemd-resolve --status 2>/dev/null | grep 'DNS Servers' | awk '{print $3}')
        elif command_exists scutil && [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            servers=$(scutil --dns 2>/dev/null | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u)
        elif command_exists nmcli; then
            # NetworkManager
            servers=$(nmcli device show 2>/dev/null | grep 'IP4.DNS' | awk '{print $2}' | sort -u)
        fi
    fi

    if [[ -z "$servers" ]]; then
        log "Could not determine DNS servers" "WARNING"
    fi

    echo "$servers"
}

# Resolve a hostname to IP address
# Arguments:
#   $1 - Hostname to resolve
#   $2 - Record type (optional, A or AAAA, defaults to A)
#   $3 - DNS server to query (optional)
# Returns:
#   IP address(es), one per line
resolve_hostname() {
    local hostname="$1"
    local record_type="${2:-A}"
    local dns_server="$3"
    local result=""
    local dns_arg=""

    # Validate hostname
    if [[ -z "$hostname" ]]; then
        log "No hostname provided for DNS resolution" "ERROR"
        return 1
    fi

    # Validate record type
    if [[ "$record_type" != "A" && "$record_type" != "AAAA" ]]; then
        log "Invalid DNS record type: $record_type (must be A or AAAA)" "ERROR"
        return 1
    fi

    # Add DNS server argument if provided
    if [[ -n "$dns_server" ]]; then
        if ! is_valid_ip "$dns_server"; then
            log "Invalid DNS server IP: $dns_server" "ERROR"
            return 1
        fi
        dns_arg="@$dns_server"
    fi

    if command_exists dig; then
        if [[ -n "$dns_server" ]]; then
            result=$(dig +short "$record_type" "$hostname" "@$dns_server" 2>/dev/null)
        else
            result=$(dig +short "$record_type" "$hostname" 2>/dev/null)
        fi
    elif command_exists host; then
        if [[ -n "$dns_server" ]]; then
            if [[ "$record_type" == "A" ]]; then
                result=$(host -t "$record_type" "$hostname" "$dns_server" 2>/dev/null | awk '/has address/ {print $4}')
            else
                result=$(host -t "$record_type" "$hostname" "$dns_server" 2>/dev/null | awk '/has IPv6/ {print $5}')
            fi
        else
            if [[ "$record_type" == "A" ]]; then
                result=$(host -t "$record_type" "$hostname" 2>/dev/null | awk '/has address/ {print $4}')
            else
                result=$(host -t "$record_type" "$hostname" 2>/dev/null | awk '/has IPv6/ {print $5}')
            fi
        fi
    elif command_exists nslookup; then
        if [[ -n "$dns_server" ]]; then
            result=$(nslookup -type="$record_type" "$hostname" "$dns_server" 2>/dev/null | awk '/^Address/ && !/#/ {print $2}')
        else
            result=$(nslookup -type="$record_type" "$hostname" 2>/dev/null | awk '/^Address/ && !/#/ {print $2}')
        fi
    else
        log "No DNS resolution tools available" "ERROR"
        return 1
    fi

    if [[ -z "$result" ]]; then
        log "Could not resolve hostname: $hostname (type: $record_type)" "WARNING"
        return 1
    fi

    echo "$result"
    return 0
}

# Get list of active network interfaces
# Arguments:
#   None
# Returns:
#   List of active network interfaces, one per line
get_network_interfaces() {
    local interfaces=""

    if command_exists ip; then
        # Linux with ip command
        interfaces=$(ip -o link show up | awk -F': ' '{print $2}' | grep -v "lo")
    elif command_exists ifconfig; then
        # BSD/macOS or older Linux
        interfaces=$(ifconfig | grep -E "^[a-z0-9]+" | grep -v "lo" | awk -F: '{print $1}')
    elif [[ -d /sys/class/net ]]; then
        # Linux with /sys filesystem
        interfaces=$(find /sys/class/net -type l -not -name lo -exec basename {} \;)
    else
        log "Could not determine network interfaces" "WARNING"
        return 1
    fi

    if [[ -z "$interfaces" ]]; then
        log "No active network interfaces found" "WARNING"
        return 1
    fi

    echo "$interfaces"
    return 0
}

# Get local IP addresses
# Arguments:
#   $1 - IP version (4 or 6, defaults to 4)
#   $2 - Interface name (optional, returns all interfaces if not specified)
# Returns:
#   List of IP addresses, one per line
get_local_ips() {
    local ip_version="${1:-4}"
    local interface="$2"
    local ips=""
    local ip_cmd_args=""
    local ifconfig_grep=""

    # Validate IP version
    if [[ "$ip_version" != "4" && "$ip_version" != "6" ]]; then
        log "Invalid IP version: $ip_version (must be 4 or 6)" "ERROR"
        return 1
    fi

    # Set up args based on IP version
    if [[ "$ip_version" == "4" ]]; then
        ip_cmd_args="a show scope global | grep -w inet"
        ifconfig_grep="inet "
    else
        ip_cmd_args="a show scope global | grep -w inet6"
        ifconfig_grep="inet6 "
    fi

    # Add interface filter if specified
    if [[ -n "$interface" ]]; then
        if command_exists ip; then
            ip_cmd_args="a show dev $interface scope global | grep -w inet"
            if [[ "$ip_version" == "6" ]]; then
                ip_cmd_args="a show dev $interface scope global | grep -w inet6"
            fi
        fi
    fi

    # Get IP addresses
    if command_exists ip; then
        # Linux with ip command
        if [[ -n "$interface" ]]; then
            ips=$(ip $ip_cmd_args | awk '{print $2}' | cut -d/ -f1)
        else
            ips=$(ip $ip_cmd_args | awk '{print $2}' | cut -d/ -f1)
        fi
    elif command_exists ifconfig; then
        # BSD/macOS or older Linux
        if [[ -n "$interface" ]]; then
            ips=$(ifconfig "$interface" | grep "$ifconfig_grep" | awk '{print $2}')
        else
            ips=$(ifconfig | grep "$ifconfig_grep" | awk '{print $2}')
        fi
    else
        log "Could not determine IP addresses - no ip or ifconfig command found" "WARNING"
        return 1
    fi

    if [[ -z "$ips" ]]; then
        if [[ -n "$interface" ]]; then
            log "No IPv$ip_version addresses found for interface: $interface" "WARNING"
        else
            log "No IPv$ip_version addresses found" "WARNING"
        fi
        return 1
    fi

    echo "$ips"
    return 0
}

# Export Network Functions
export -f is_url_reachable
export -f get_public_ip
export -f ping_host
export -f get_dns_servers
export -f resolve_hostname
export -f get_network_interfaces
export -f get_local_ips
