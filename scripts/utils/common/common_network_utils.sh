#!/bin/bash
# filepath: scripts/utils/common/common_network_utils.sh
# Network utility functions for Cloud Infrastructure Platform
# This script provides various network-related functions for
# checking connectivity, resolving hostnames, and retrieving IP addresses.

# Check if required functions are available
for func in is_valid_url is_number command_exists log is_valid_ip execute_with_timeout; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_functions.sh first." >&2
        exit 1
    fi
done

# Script version information
NETWORK_UTILS_VERSION="1.0.3"
NETWORK_UTILS_DATE="2023-09-30"

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_network_utils_version() {
    echo "${NETWORK_UTILS_VERSION} (${NETWORK_UTILS_DATE})"
}

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

    # Sanitize options to prevent command injection using allowlisting
    if [[ -n "$options" ]]; then
        # Define allowed options
        local allowed_options="-H --header -A --user-agent -k --insecure --compressed --http1.0 --http1.1 --http2"
        local sanitized_options=""

        # Parse options and keep only allowed ones
        for opt in $options; do
            if [[ "$allowed_options" == *"$opt"* ]]; then
                sanitized_options+="$opt "
            elif [[ "$opt" == *=* ]]; then
                # Check if option with value is allowed
                local opt_name="${opt%%=*}"
                if [[ "$allowed_options" == *"$opt_name"* ]]; then
                    sanitized_options+="$opt "
                else
                    log "Skipping disallowed option: $opt_name" "WARNING"
                fi
            fi
        done
        options="$sanitized_options"
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

    # Implement circuit breaker pattern with retry logic
    local retry_count=0
    local max_retries=2
    local success=false
    local retry_delay=1

    while [[ $retry_count -le $max_retries && "$success" == "false" ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log "Retry attempt $retry_count for URL: $url" "DEBUG"
            sleep $retry_delay
            # Exponential backoff
            retry_delay=$((retry_delay * 2))
        fi

        if command_exists curl; then
            # Use curl with explicit error handling
            if curl --output /dev/null --silent --head --fail --max-time "$timeout" $options "$url"; then
                success=true
            fi
        elif command_exists wget; then
            # Use wget with timeout
            if wget --quiet --spider --timeout="$timeout" $options "$url"; then
                success=true
            fi
        else
            log "Neither curl nor wget available to check URL" "WARNING"
            return 2
        fi

        retry_count=$((retry_count + 1))
    done

    if [[ "$success" == "true" ]]; then
        return 0
    else
        log "URL not reachable after $retry_count attempts: $url" "DEBUG"
        return 1
    fi
}

# Get public IP address with circuit-breaker pattern
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

    # Service failure tracking
    local failed_services=()
    local retry_after=300 # 5 minutes
    local cache_file="/tmp/cloud-platform-public-ip-cache"
    local cache_time=300 # 5 minutes

    # Check cache first
    if [[ -f "$cache_file" ]]; then
        local cached_ip=""
        local cache_timestamp=0

        # Read cache
        IFS='|' read -r cached_ip cache_timestamp < "$cache_file"
        local current_time=$(date +%s)

        # Check if cache is still valid
        if [[ -n "$cached_ip" && $(( current_time - cache_timestamp )) -lt $cache_time ]]; then
            if is_valid_ip "$cached_ip" 4 || is_valid_ip "$cached_ip" 6; then
                echo "$cached_ip"
                return 0
            fi
        fi
    fi

    # Try circuit-breaker cache to avoid constantly trying failed services
    local circuit_breaker_file="/tmp/cloud-platform-public-ip-failed-services"
    if [[ -f "$circuit_breaker_file" ]]; then
        local current_time=$(date +%s)
        while IFS='|' read -r service timestamp; do
            if [[ $(( current_time - timestamp )) -lt $retry_after ]]; then
                failed_services+=("$service")
                log "Skipping recently failed service: $service" "DEBUG"
            fi
        done < "$circuit_breaker_file"
    fi

    # Try each non-failed service
    for service in "${services[@]}"; do
        # Skip if service is in the failed list
        if [[ " ${failed_services[@]} " =~ " $service " ]]; then
            continue
        fi

        local start_time=$(date +%s)
        if command_exists curl; then
            ip=$(curl -s --max-time "$timeout" "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout="$timeout" "$service" 2>/dev/null)
        else
            log "Neither curl nor wget are available" "ERROR"
            return 1
        fi
        local end_time=$(date +%s)
        local duration=$(( end_time - start_time ))

        # Check if we got a valid IP
        if [[ -n "$ip" ]]; then
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                # Cache the successful result
                echo "$ip|$(date +%s)" > "$cache_file"
                log "Public IP ($ip) retrieved successfully from $service in ${duration}s" "DEBUG"
                echo "$ip"
                return 0
            fi
        fi

        # Mark service as failed
        log "Service $service failed to provide valid IP" "DEBUG"
        echo "$service|$(date +%s)" >> "$circuit_breaker_file"
    done

    log "Could not determine public IP address - all services failed" "ERROR"
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

    # Reasonable upper limits
    if [[ $count -gt 100 ]]; then
        log "Ping count exceeds maximum (100), limiting to 100" "WARNING"
        count=100
    fi

    if [[ $timeout -gt 30 ]]; then
        log "Ping timeout exceeds maximum (30s), limiting to 30s" "WARNING"
        timeout=30
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
    log "Pinging host $host ($count packets with ${timeout}s timeout)" "DEBUG"
    if execute_with_timeout $((timeout + 2)) $cmd &>/dev/null; then
        log "Host $host is reachable" "DEBUG"
        return 0
    fi

    log "Host $host is not reachable" "DEBUG"
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
        elif command_exists cat && [[ -d /var/run/systemd/resolve ]]; then
            # Another fallback for systemd-resolved
            servers=$(cat /var/run/systemd/resolve/resolv.conf 2>/dev/null | grep '^nameserver' | awk '{print $2}')
        elif command_exists ip && [[ -d /proc/sys/net/ipv4/conf ]]; then
            # Fallback for some Linux distributions
            local default_interface
            default_interface=$(ip route show default | awk '{print $5}' | head -1)
            if [[ -n "$default_interface" ]]; then
                # Look for DHCP leases or configuration
                if [[ -d /var/lib/dhcp ]]; then
                    servers=$(grep -h "option domain-name-servers" /var/lib/dhcp/*.leases 2>/dev/null |
                             head -1 | sed 's/.*domain-name-servers //' | sed 's/;//' | tr ',' '\n')
                fi
            fi
        fi
    fi

    if [[ -z "$servers" ]]; then
        log "Could not determine DNS servers" "WARNING"
        # Fall back to common public DNS servers
        servers="1.1.1.1
8.8.8.8"
        log "Using fallback public DNS servers" "INFO"
    fi

    echo "$servers"
}

# Resolve a hostname to IP address with enhanced support and timeout
# Arguments:
#   $1 - Hostname to resolve
#   $2 - Record type (optional, A, AAAA, CNAME, MX, TXT, defaults to A)
#   $3 - DNS server to query (optional)
#   $4 - Timeout in seconds (optional - defaults to 5)
# Returns:
#   IP address(es) or record data, one per line
resolve_hostname() {
    local hostname="$1"
    local record_type="${2:-A}"
    local dns_server="$3"
    local timeout="${4:-5}"
    local result=""
    local dns_arg=""

    # Validate hostname
    if [[ -z "$hostname" ]]; then
        log "No hostname provided for DNS resolution" "ERROR"
        return 1
    fi

    # Validate record type - now supporting more record types
    case "$record_type" in
        A|AAAA|CNAME|MX|TXT|NS|SOA|SRV|PTR)
            # Supported record type
            ;;
        *)
            log "Invalid DNS record type: $record_type (supported types: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR)" "ERROR"
            return 1
            ;;
    esac

    # Add DNS server argument if provided
    if [[ -n "$dns_server" ]]; then
        if ! is_valid_ip "$dns_server"; then
            log "Invalid DNS server IP: $dns_server" "ERROR"
            return 1
        fi
        dns_arg="@$dns_server"
    fi

    # Validate timeout
    if ! is_number "$timeout"; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 1
    fi

    log "Resolving hostname: $hostname (type: $record_type${dns_server:+, server: $dns_server})" "DEBUG"

    # Use dig with timeout if available
    if command_exists dig; then
        if [[ -n "$dns_server" ]]; then
            result=$(execute_with_timeout "$timeout" dig +short "$record_type" "$hostname" "@$dns_server" 2>/dev/null)
        else
            result=$(execute_with_timeout "$timeout" dig +short "$record_type" "$hostname" 2>/dev/null)
        fi
    # Use host with timeout if available
    elif command_exists host; then
        local host_args="-t $record_type $hostname"
        [[ -n "$dns_server" ]] && host_args+=" $dns_server"

        local raw_result
        raw_result=$(execute_with_timeout "$timeout" host $host_args 2>/dev/null)

        # Parse result based on record type
        case "$record_type" in
            A)
                result=$(echo "$raw_result" | awk '/has address/ {print $4}')
                ;;
            AAAA)
                result=$(echo "$raw_result" | awk '/has IPv6/ {print $5}')
                ;;
            CNAME)
                result=$(echo "$raw_result" | awk '/is an alias/ {print $6}')
                ;;
            MX)
                result=$(echo "$raw_result" | awk '/mail is handled by/ {print $7 " " $6}')
                ;;
            TXT)
                result=$(echo "$raw_result" | awk '/descriptive text/ {gsub(/^"|"$/, "", $4); print $4}')
                ;;
            *)
                # Basic extraction for other types
                result=$(echo "$raw_result" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+')
                ;;
        esac
    # Use nslookup with timeout if available
    elif command_exists nslookup; then
        local ns_command="nslookup -type=$record_type $hostname"
        [[ -n "$dns_server" ]] && ns_command+=" $dns_server"

        local raw_result
        raw_result=$(execute_with_timeout "$timeout" $ns_command 2>/dev/null)

        # Parse nslookup output based on record type
        case "$record_type" in
            A|AAAA)
                result=$(echo "$raw_result" | awk '/^Address/ && !/#/ {print $2}')
                ;;
            CNAME)
                result=$(echo "$raw_result" | awk '/canonical name/ {print $4}')
                ;;
            MX)
                result=$(echo "$raw_result" | awk '/mail exchanger/ {print $6 " " $4}')
                ;;
            TXT)
                result=$(echo "$raw_result" | awk '/text =/ {gsub(/^"|"$/, "", $4); print $4}')
                ;;
            *)
                # Basic extraction for other types
                result=$(echo "$raw_result" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+')
                ;;
        esac
    else
        log "No DNS resolution tools available (dig, host, or nslookup)" "ERROR"
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

    # Provide debugging information
    log "Found active interfaces: $(echo $interfaces | tr '\n' ' ')" "DEBUG"

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

    # Validate interface if provided
    if [[ -n "$interface" ]]; then
        local valid=false
        local all_interfaces=$(get_network_interfaces)
        while read -r iface; do
            if [[ "$iface" == "$interface" ]]; then
                valid=true
                break
            fi
        done <<< "$all_interfaces"

        if [[ "$valid" == "false" ]]; then
            log "Invalid or inactive interface: $interface" "ERROR"
            return 1
        fi
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

# Test network connectivity to multiple endpoints
# Arguments:
#   $1 - Comma-separated list of hosts to check
#   $2 - Timeout in seconds (optional - defaults to 5)
# Returns:
#   JSON object with connectivity status for each host
test_connectivity() {
    local hosts="$1"
    local timeout="${2:-5}"
    local results=""
    local first=true

    # Validate timeout
    if ! is_number "$timeout"; then
        log "Invalid timeout value: $timeout" "ERROR"
        echo "{\"error\":\"Invalid timeout value\"}"
        return 1
    fi

    # Validate hosts parameter
    if [[ -z "$hosts" ]]; then
        log "No hosts provided for connectivity test" "ERROR"
        echo "{\"error\":\"No hosts provided\"}"
        return 1
    fi

    # Start JSON output
    results="{"

    # Process each host
    IFS=',' read -ra host_array <<< "$hosts"
    for host in "${host_array[@]}"; do
        # Trim whitespace
        host=$(echo "$host" | xargs)

        # Skip empty hosts
        if [[ -z "$host" ]]; then
            continue
        fi

        # Add comma if not first item
        if [[ "$first" == "true" ]]; then
            first=false
        else
            results+=","
        fi

        # Test connectivity using ping
        if ping_host "$host" 1 "$timeout"; then
            results+="\"$host\":\"success\""
        else
            results+="\"$host\":\"failure\""
        fi
    done

    # Complete JSON output
    results+="}"

    echo "$results"
    return 0
}

# Check network latency to a host
# Arguments:
#   $1 - Host to check
#   $2 - Number of pings (optional - defaults to 3)
#   $3 - Timeout in seconds (optional - defaults to 5)
# Returns:
#   Average latency in milliseconds, or -1 if error
check_latency() {
    local host="$1"
    local count="${2:-3}"
    local timeout="${3:-5}"
    local latency=""

    # Validate host
    if [[ -z "$host" ]]; then
        log "No host provided for latency check" "ERROR"
        echo "-1"
        return 1
    fi

    # Validate count
    if ! is_number "$count" || [[ $count -lt 1 ]]; then
        log "Invalid ping count: $count" "ERROR"
        echo "-1"
        return 1
    fi

    # Validate timeout
    if ! is_number "$timeout" || [[ $timeout -lt 1 ]]; then
        log "Invalid ping timeout: $timeout" "ERROR"
        echo "-1"
        return 1
    fi

    # Check if ping is available
    if ! command_exists ping; then
        log "Ping command is not available" "ERROR"
        echo "-1"
        return 1
    fi

    # Run ping command and extract average latency
    local ping_output
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        ping_output=$(ping -c "$count" -t "$timeout" "$host" 2>/dev/null)
    else
        # Linux
        ping_output=$(ping -c "$count" -W "$timeout" "$host" 2>/dev/null)
    fi

    if [[ $? -ne 0 ]]; then
        log "Failed to ping host: $host" "WARNING"
        echo "-1"
        return 1
    fi

    # Extract average latency (works on both Linux and macOS)
    latency=$(echo "$ping_output" | grep -oE 'min/avg/max[^=]*= [^/]+/([^/]+)/' | awk -F'/' '{print $2}')

    if [[ -z "$latency" ]]; then
        log "Could not determine latency to host: $host" "WARNING"
        echo "-1"
        return 1
    fi

    # Round to integer if needed
    if [[ "$latency" == *"."* ]]; then
        latency=$(printf "%.0f" "$latency")
    fi

    echo "$latency"
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
export -f test_connectivity
export -f check_latency
