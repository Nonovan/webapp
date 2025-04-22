#!/bin/bash
# filepath: scripts/utils/common/common_system_functions.sh
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
# Arguments:
#   None
# Returns:
#   0 if root, 1 if not
is_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    fi
    return 0
}

# Get system information
# Arguments:
#   None
# Returns:
#   JSON string with system information
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
    elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
        # macOS CPU info
        cpu_info=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
    else
        cpu_info="Unknown"
    fi

    # Get memory info
    if command_exists free; then
        total_memory=$(free -m | grep Mem: | awk '{print $2}')
        total_memory="${total_memory} MB"
    elif [[ -f /proc/meminfo ]]; then
        total_memory=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
        total_memory="${total_memory} MB"
    elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
        # macOS memory info
        total_memory=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
        total_memory=$((total_memory / 1024 / 1024))
        total_memory="${total_memory} MB"
    else
        total_memory="Unknown"
    fi

    echo "{\"hostname\":\"$hostname\",\"os\":\"$os_name\",\"kernel\":\"$kernel\",\"uptime\":\"$uptime\",\"cpu\":\"$cpu_info\",\"memory\":\"$total_memory\"}"
}

# Check available disk space on a path (in MB)
# Arguments:
#   $1 - Path to check (defaults to /)
# Returns:
#   Available disk space in MB
check_disk_space() {
    local path="${1:-/}"
    local available

    if [[ ! -d "$path" ]]; then
        log "Path does not exist: $path" "ERROR"
        echo "0"
        return 1
    fi

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS version
        available=$(df -m "$path" | awk 'NR==2 {print $4}')
    else
        # Linux version
        available=$(df -BM "$path" | awk 'NR==2 {print $4}' | tr -d 'M')
    fi

    # Validate result is a number
    if ! [[ "$available" =~ ^[0-9]+$ ]]; then
        log "Failed to get disk space for: $path" "ERROR"
        echo "0"
        return 1
    fi

    echo "$available"
}

# Check if a port is in use
# Arguments:
#   $1 - Port number
#   $2 - Protocol (tcp, udp, defaults to tcp)
# Returns:
#   0 if port is in use, 1 if available, 2 on error
is_port_in_use() {
    local port="$1"
    local protocol="${2:-tcp}"

    # Validate port number
    if ! is_number "$port"; then
        log "Invalid port number: $port" "ERROR"
        return 2
    fi

    if ((port < 1 || port > 65535)); then
        log "Port number out of range (1-65535): $port" "ERROR"
        return 2
    fi

    # Validate protocol
    if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
        log "Invalid protocol. Must be tcp or udp: $protocol" "ERROR"
        return 2
    fi

    if command_exists netstat; then
        if netstat -tuln | grep -q "$protocol.*:$port "; then
            return 0
        fi
    elif command_exists ss; then
        if ss -tuln | grep -q "$protocol.*:$port "; then
            return 0
        fi
    elif command_exists lsof; then
        if lsof -i "$protocol:$port" &>/dev/null; then
            return 0
        fi
    else
        log "Neither netstat, ss, nor lsof commands available to check port" "WARNING"
        return 2
    fi

    return 1
}

# Generate a temporary file with proper permissions
# Arguments:
#   $1 - File prefix (optional - defaults to tmp)
#   $2 - Permissions (optional - defaults to 600)
# Returns:
#   Path to temporary file on success, empty string on failure
get_temp_file() {
    local prefix="${1:-tmp}"
    local perms="${2:-600}"
    local temp_file
    local temp_dir

    # Determine appropriate temp directory
    if [[ -d /tmp && -w /tmp ]]; then
        temp_dir="/tmp"
    elif [[ -n "$TMPDIR" && -d "$TMPDIR" && -w "$TMPDIR" ]]; then
        temp_dir="$TMPDIR"
    else
        temp_dir="."
    fi

    # Create the temporary file
    temp_file=$(mktemp "${temp_dir}/${prefix}_XXXXXXXX") || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }

    # Set appropriate permissions
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
        # Continue anyway as the file was created
    }

    echo "$temp_file"
}

# Execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2...$n - Command to execute and its arguments
# Returns:
#   Command exit code or 124 for timeout
execute_with_timeout() {
    local timeout="$1"
    shift

    if ! is_number "$timeout"; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 2
    fi

    if [[ $# -eq 0 ]]; then
        log "No command provided to execute_with_timeout" "ERROR"
        return 2
    fi

    if command_exists timeout; then
        timeout "$timeout" "$@"
        return $?
    elif command_exists gtimeout; then
        # On macOS with GNU coreutils installed
        gtimeout "$timeout" "$@"
        return $?
    else
        # Fallback if timeout command doesn't exist
        local pid
        local watchdog_pid
        local ret

        # Start the command in background
        "$@" &
        pid=$!

        # Start watchdog process
        (
            # Wait for specified timeout
            sleep "$timeout"
            # If still running after timeout, kill it
            if kill -0 $pid 2>/dev/null; then
                kill -TERM $pid 2>/dev/null
                sleep 1
                # Force kill if still running
                kill -KILL $pid 2>/dev/null
            fi
        ) &
        watchdog_pid=$!

        # Wait for main process to complete
        wait $pid 2>/dev/null
        ret=$?

        # Kill the watchdog
        kill -KILL $watchdog_pid 2>/dev/null
        wait $watchdog_pid 2>/dev/null

        return $ret
    fi
}

# Get system load average
# Arguments:
#   None
# Returns:
#   Current 1-minute load average
get_load_average() {
    local load="0.0"

    if [[ -f /proc/loadavg ]]; then
        load=$(awk '{print $1}' /proc/loadavg)
    elif command_exists uptime; then
        load=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
    elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
        # macOS alternate method
        load=$(sysctl -n vm.loadavg | awk '{print $2}')
    else
        log "Could not determine load average" "WARNING"
    fi

    # Validate result is a number
    if ! [[ "$load" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        log "Invalid load average value: $load" "WARNING"
        load="0.0"
    fi

    echo "$load"
}

# Get total and available memory in MB
# Arguments:
#   None
# Returns:
#   JSON with memory information
get_memory_info() {
    local total_mem=0
    local free_mem=0
    local used_mem=0

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
    elif command_exists vm_stat && [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        local page_size=$(pagesize 2>/dev/null || echo 4096)
        local pages_free=$(vm_stat | grep 'Pages free' | awk '{print $3}' | tr -d '.')
        local pages_active=$(vm_stat | grep 'Pages active' | awk '{print $3}' | tr -d '.')
        local pages_inactive=$(vm_stat | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')
        local pages_speculative=$(vm_stat | grep 'Pages speculative' | awk '{print $3}' | tr -d '.')
        local pages_wired=$(vm_stat | grep 'Pages wired down' | awk '{print $4}' | tr -d '.')

        # Ensure we have valid numbers
        if [[ -z "$pages_free" || -z "$pages_active" || -z "$pages_inactive" ||
              -z "$pages_speculative" || -z "$pages_wired" ]]; then
            log "Failed to get memory info from vm_stat" "WARNING"
        else
            total_mem=$(( (pages_free + pages_active + pages_inactive + pages_speculative + pages_wired) * page_size / 1024 / 1024 ))
            free_mem=$(( (pages_free + pages_inactive) * page_size / 1024 / 1024 ))
            used_mem=$(( (pages_active + pages_wired) * page_size / 1024 / 1024 ))
        fi
    elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
        # macOS alternative method
        total_mem=$(sysctl -n hw.memsize 2>/dev/null)
        total_mem=$((total_mem / 1024 / 1024))

        # Get VM stats for free memory estimation
        local vm_stat_output=$(vm_stat 2>/dev/null)
        if [[ -n "$vm_stat_output" ]]; then
            local page_size=$(pagesize 2>/dev/null || echo 4096)
            local pages_free=$(echo "$vm_stat_output" | grep 'Pages free' | awk '{print $3}' | tr -d '.')
            local pages_inactive=$(echo "$vm_stat_output" | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')

            free_mem=$(( (pages_free + pages_inactive) * page_size / 1024 / 1024 ))
            used_mem=$((total_mem - free_mem))
        else
            # If VM stats not available, provide just total memory
            free_mem=0
            used_mem=0
        fi
    fi

    # Validate results
    if ! is_number "$total_mem" || ! is_number "$free_mem" || ! is_number "$used_mem"; then
        log "Invalid memory values obtained" "WARNING"
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
# Returns:
#   0 if reachable, 1 if not reachable, 2 on error
is_url_reachable() {
    local url="$1"
    local timeout="${2:-10}"
    local options="${3:-}"

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
        # macOS
        cmd="ping -c $count -t $timeout $host"
    else
        # Linux
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

# Export Network Functions
export -f is_url_reachable
export -f get_public_ip
export -f ping_host
export -f get_dns_servers
export -f resolve_hostname
export -f get_network_interfaces
export -f get_local_ips
