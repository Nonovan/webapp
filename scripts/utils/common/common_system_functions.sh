#!/bin/bash
# System utility functions for Cloud Infrastructure Platform
# These functions handle system operations, monitoring, and status checks

# Check that this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    exit 1
fi

# Check if required variables and functions are defined
if [[ -z "$SCRIPT_DIR" || ! $(type -t log) == "function" ]]; then
    echo "Warning: This module requires core_functions to be loaded first"
    exit 1
fi

#######################################
# SYSTEM OPERATIONS
#######################################

# Check if running as root
# Returns: 0 if root, 1 if not
is_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    fi
    return 0
}

# Get system information
# Returns: JSON string with system information
get_system_info() {
    local os_name
    local kernel
    local hostname
    local uptime
    local cpu_info
    local total_memory

    # Get OS name
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    else
        os_name=$(uname -s)
    fi

    kernel=$(uname -r)
    hostname=$(hostname -f 2>/dev/null || hostname)
    uptime=$(uptime -p 2>/dev/null || uptime)

    # Get CPU info
    if [[ -f /proc/cpuinfo ]]; then
        cpu_info=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
        if [[ -z "$cpu_info" ]]; then
            cpu_info="Unknown"
        fi
    else
        cpu_info="Unknown"
    fi

    # Get memory info
    if command_exists free; then
        total_memory=$(free -m | grep Mem: | awk '{print $2}')
        total_memory="${total_memory} MB"
    else
        total_memory="Unknown"
    fi

    echo "{\"hostname\":\"$hostname\",\"os\":\"$os_name\",\"kernel\":\"$kernel\",\"uptime\":\"$uptime\",\"cpu\":\"$cpu_info\",\"memory\":\"$total_memory\"}"
}

# Check available disk space on a path (in MB)
# Arguments:
#   $1 - Path to check
# Returns: Available disk space in MB
check_disk_space() {
    local path="${1:-/}"
    local available

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS version
        available=$(df -m "$path" | awk 'NR==2 {print $4}')
    else
        # Linux version
        available=$(df -BM "$path" | awk 'NR==2 {print $4}' | tr -d 'M')
    fi

    echo "$available"
}

# Check if a port is in use
# Arguments:
#   $1 - Port number
#   $2 - Protocol (tcp, udp, defaults to tcp)
# Returns: 0 if port is in use, 1 if available
is_port_in_use() {
    local port="$1"
    local protocol="${2:-tcp}"

    if ! is_number "$port"; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi

    if command_exists netstat; then
        netstat -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists ss; then
        ss -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists lsof; then
        lsof -i "$protocol:$port" &>/dev/null && return 0
    else
        warn "Neither netstat, ss, nor lsof commands available to check port"
        return 2
    fi

    return 1
}

# Generate a temporary file with proper permissions
# Arguments:
#   $1 - File prefix
#   $2 - Permissions (optional - defaults to 600)
# Returns: Path to temporary file
get_temp_file() {
    local prefix="${1:-tmp}"
    local perms="${2:-600}"
    local temp_file

    temp_file=$(mktemp "/tmp/${prefix}_XXXXXXXX") || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }

    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }

    echo "$temp_file"
}

# Execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2...$n - Command to execute and its arguments
# Returns: Command exit code or 124 for timeout
execute_with_timeout() {
    local timeout="$1"
    shift

    if command_exists timeout; then
        timeout "$timeout" "$@"
        return $?
    else
        # Fallback if timeout command doesn't exist
        local pid
        "$@" &
        pid=$!

        # Wait for specified time
        (sleep "$timeout" && kill -9 $pid 2>/dev/null) &
        local watchdog=$!

        # Wait for process to complete
        wait $pid 2>/dev/null
        local ret=$?

        # Kill the watchdog
        kill -9 $watchdog 2>/dev/null

        return $ret
    fi
}

# Get system load average
# Returns: Current 1-minute load average
get_load_average() {
    if [[ -f /proc/loadavg ]]; then
        awk '{print $1}' /proc/loadavg
    elif command_exists uptime; then
        uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' '
    else
        echo "0.0"
        return 1
    fi
}

# Get total and available memory in MB
# Returns: JSON with memory information
get_memory_info() {
    local total_mem
    local free_mem
    local used_mem

    if [[ -f /proc/meminfo ]]; then
        # Linux
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
        free_mem=$(grep MemAvailable /proc/meminfo 2>/dev/null || grep MemFree /proc/meminfo | awk '{print int($2/1024)}')
        used_mem=$((total_mem - free_mem))
    elif command_exists free; then
        # Alternative using free command
        total_mem=$(free -m | grep Mem: | awk '{print $2}')
        free_mem=$(free -m | grep Mem: | awk '{print $7}')
        used_mem=$((total_mem - free_mem))
    elif command_exists vm_stat; then
        # macOS
        local page_size=$(pagesize 2>/dev/null || echo 4096)
        local pages_free=$(vm_stat | grep 'Pages free' | awk '{print $3}' | tr -d '.')
        local pages_active=$(vm_stat | grep 'Pages active' | awk '{print $3}' | tr -d '.')
        local pages_inactive=$(vm_stat | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')
        local pages_speculative=$(vm_stat | grep 'Pages speculative' | awk '{print $3}' | tr -d '.')
        local pages_wired=$(vm_stat | grep 'Pages wired down' | awk '{print $4}' | tr -d '.')

        total_mem=$(( (pages_free + pages_active + pages_inactive + pages_speculative + pages_wired) * page_size / 1024 / 1024 ))
        free_mem=$(( (pages_free + pages_inactive) * page_size / 1024 / 1024 ))
        used_mem=$(( (pages_active + pages_wired) * page_size / 1024 / 1024 ))
    else
        # Fallback
        total_mem=0
        free_mem=0
        used_mem=0
    fi

    echo "{\"total_mb\":$total_mem,\"used_mb\":$used_mem,\"free_mb\":$free_mem}"
}

#######################################
# NETWORK OPERATIONS
#######################################

# Check if URL is reachable
# Arguments:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional - defaults to 10)
#   $3 - Additional options for curl/wget (optional)
# Returns: 0 if reachable, 1 if not
is_url_reachable() {
    local url="$1"
    local timeout="${2:-10}"
    local options="${3:-}"

    if ! is_valid_url "$url"; then
        log "Invalid URL format: $url" "ERROR"
        return 1
    fi

    if command_exists curl; then
        if curl --output /dev/null --silent --head --fail --max-time "$timeout" $options "$url"; then
            return 0
        fi
    elif command_exists wget; then
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
# Returns: Public IP address or error message
get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )

    for service in "${services[@]}"; do
        if command_exists curl; then
            ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout=5 "$service" 2>/dev/null)
        else
            echo "ERROR: Neither curl nor wget are available"
            return 1
        fi

        # Check if we got a valid IP
        if [[ -n "$ip" && ( $(is_valid_ip "$ip" 4) || $(is_valid_ip "$ip" 6) ) ]]; then
            echo "$ip"
            return 0
        fi
    done

    echo "ERROR: Could not determine public IP address"
    return 1
}

# Check if host is reachable via ping
# Arguments:
#   $1 - Host to ping
#   $2 - Number of packets (optional - defaults to 1)
#   $3 - Timeout in seconds (optional - defaults to 2)
# Returns: 0 if reachable, 1 if not
ping_host() {
    local host="$1"
    local count="${2:-1}"
    local timeout="${3:-2}"

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    else
        # Linux
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    fi

    return 1
}

# Get primary DNS servers
# Returns: List of DNS servers
get_dns_servers() {
    local servers=""

    if [[ -f /etc/resolv.conf ]]; then
        servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}')
    fi

    # If no servers found, try alternative methods
    if [[ -z "$servers" ]]; then
        if command_exists systemd-resolve; then
            servers=$(systemd-resolve --status | grep 'DNS Servers' | awk '{print $3}')
        elif command_exists scutil && [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            servers=$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u)
        fi
    fi

    echo "$servers"
}

# Resolve a hostname to IP address
# Arguments:
#   $1 - Hostname to resolve
#   $2 - Record type (optional, A or AAAA, defaults to A)
# Returns: IP address(es)
resolve_hostname() {
    local hostname="$1"
    local record_type="${2:-A}"

    if command_exists dig; then
        dig +short "$record_type" "$hostname" 2>/dev/null
    elif command_exists host; then
        host -t "$record_type" "$hostname" 2>/dev/null | awk '/has address/ {print $4}; /has IPv6/ {print $5}'
    elif command_exists nslookup; then
        nslookup -type="$record_type" "$hostname" 2>/dev/null | awk '/^Address/ && !/#/ {print $2}'
    else
        log "No DNS resolution tools available" "ERROR"
        return 1
    fi
}



# Export System Functions
export -f is_root
export -f get_system_info
export -f check_disk_space
export -f is_port_in_use
export -f get_temp_file
export -f execute_with_timeout
export -f get_load_average
export -f get_memory_info

#Export Network Functions
export -f is_url_reachable
export -f get_public_ip
export -f ping_host
export -f get_dns_servers
export -f resolve_hostname

