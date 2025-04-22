#!/bin/bash
# filepath: scripts/utils/common/common_system_utils.sh
# System utility functions for Cloud Infrastructure Platform
# These functions handle system operations.

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

# Script version information
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2024-07-17"

# Check if command exists
# Arguments:
#   $1 - Command name
# Returns:
#   0 if command exists, 1 if not
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if value is a number (integer or float)
# Arguments:
#   $1 - Value to check
# Returns:
#   0 if value is a number, 1 if not
is_number() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_script_version() {
    echo "${SCRIPT_VERSION} (${SCRIPT_DATE})"
}

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

    # Get OS name - sanitize output to prevent command injection
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
        # Further sanitize to prevent injection in JSON output
        os_name="${os_name//\"/\\\"}"
    else
        os_name=$(uname -s)
    fi

    kernel=$(uname -r)
    hostname=$(hostname -f 2>/dev/null || hostname)
    # Sanitize hostname for JSON
    hostname="${hostname//\"/\\\"}"

    uptime=$(uptime -p 2>/dev/null || uptime)
    uptime="${uptime//\"/\\\"}"

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
    # Sanitize CPU info for JSON
    cpu_info="${cpu_info//\"/\\\"}"

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

    # Sanitize path for command usage
    path=$(realpath -q "$path" 2>/dev/null || echo "$path")

    # Prevent path traversal vulnerability
    if [[ ! -d "$path" ]]; then
        log "Invalid path after sanitization: $path" "ERROR"
        echo "0"
        return 1
    }

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

    # Sanitize prefix to prevent command injection
    prefix=$(echo "$prefix" | tr -cd 'a-zA-Z0-9_-')

    if [[ -z "$prefix" ]]; then
        prefix="tmp"
    fi

    # Validate permissions parameter
    if ! [[ "$perms" =~ ^[0-7]{3,4}$ ]]; then
        log "Invalid permissions format: $perms, using default (600)" "WARNING"
        perms="600"
    fi

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

    # Safety check for reasonable timeout values
    if (( timeout > 86400 )); then # 24 hours
        log "Timeout value too large (>24h): $timeout" "WARNING"
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

        # Use a temporary file for coordination to avoid race conditions
        local temp_file
        temp_file=$(mktemp) || {
            log "Failed to create temporary file for timeout coordination" "ERROR"
            return 2
        }

        # Start the command in background
        "$@" &
        pid=$!

        # Start watchdog process
        (
            # Wait for specified timeout
            sleep "$timeout"
            # If still running after timeout, kill it
            if kill -0 $pid 2>/dev/null; then
                echo "TIMED_OUT" > "$temp_file"
                kill -TERM $pid 2>/dev/null
                sleep 1
                # Force kill if still running
                if kill -0 $pid 2>/dev/null; then
                    kill -KILL $pid 2>/dev/null
                fi
            fi
        ) &
        watchdog_pid=$!

        # Wait for main process to complete
        wait $pid 2>/dev/null
        ret=$?

        # Kill the watchdog
        kill -KILL $watchdog_pid 2>/dev/null
        wait $watchdog_pid 2>/dev/null

        # Check if timeout occurred
        if [[ -f "$temp_file" && "$(cat "$temp_file")" == "TIMED_OUT" ]]; then
            rm -f "$temp_file"
            return 124  # Standard timeout exit code
        fi

        rm -f "$temp_file"
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
    local result=1

    if [[ -f /proc/meminfo ]]; then
        # Linux
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
        free_mem=$(grep MemAvailable /proc/meminfo 2>/dev/null || grep MemFree /proc/meminfo | awk '{print int($2/1024)}')
        used_mem=$((total_mem - free_mem))
        result=0
    elif command_exists free; then
        # Alternative using free command
        total_mem=$(free -m | grep Mem: | awk '{print $2}')
        free_mem=$(free -m | grep Mem: | awk '{print $7}')
        used_mem=$((total_mem - free_mem))
        result=0
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
            result=0
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
            result=0
        else
            free_mem=0
            used_mem=$total_mem
            result=0
        fi
    else
        # Fallback
        log "Could not determine memory information" "WARNING"
        result=1
    fi

    # Validate results
    if ! is_number "$total_mem" || ! is_number "$free_mem" || ! is_number "$used_mem"; then
        log "Invalid memory values obtained" "WARNING"
        total_mem=0
        free_mem=0
        used_mem=0
        result=1
    fi

    echo "{\"total_mb\":$total_mem,\"used_mb\":$used_mem,\"free_mb\":$free_mem}"
    return $result
}

# Check if system is overloaded
# Arguments:
#   $1 - Load average threshold (optional - defaults to number of CPUs)
#   $2 - Memory threshold percentage (optional - defaults to 90)
#   $3 - Disk threshold percentage (optional - defaults to 90)
# Returns:
#   0 if system load is normal, 1 if overloaded, 2 on error
check_system_load() {
    local cpu_count=1
    local load_threshold="${1:-}"
    local memory_threshold="${2:-90}"
    local disk_threshold="${3:-90}"
    local error_detected=0

    # Get CPU count for default load threshold
    if [[ -z "$load_threshold" ]]; then
        if [[ -f /proc/cpuinfo ]]; then
            cpu_count=$(grep -c "^processor" /proc/cpuinfo)
        elif command_exists nproc; then
            cpu_count=$(nproc)
        elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
            cpu_count=$(sysctl -n hw.ncpu)
        fi
        load_threshold=$cpu_count
    fi

    # Validate thresholds
    if ! is_number "$load_threshold" || ! is_number "$memory_threshold" || ! is_number "$disk_threshold"; then
        log "Invalid threshold values - load: $load_threshold, memory: $memory_threshold, disk: $disk_threshold" "ERROR"
        return 2
    fi

    # Check for reasonable threshold values
    if (( memory_threshold <= 0 || memory_threshold > 100 )); then
        log "Invalid memory threshold value (must be 1-100): $memory_threshold" "ERROR"
        error_detected=1
    fi

    if (( disk_threshold <= 0 || disk_threshold > 100 )); then
        log "Invalid disk threshold value (must be 1-100): $disk_threshold" "ERROR"
        error_detected=1
    fi

    if (( error_detected == 1 )); then
        return 2
    }

    # Check load average
    local load_average
    load_average=$(get_load_average)
    if [[ $? -ne 0 || -z "$load_average" ]]; then
        log "Failed to get system load average" "ERROR"
        return 2
    fi

    # Use bc for floating point comparison if available
    if command_exists bc; then
        if (( $(echo "$load_average > $load_threshold" | bc -l) )); then
            log "System CPU overloaded: $load_average (threshold: $load_threshold)" "WARNING"
            return 1
        fi
    else
        # Fallback integer comparison (less accurate)
        if (( ${load_average%.*} > $load_threshold )); then
            log "System CPU overloaded: $load_average (threshold: $load_threshold)" "WARNING"
            return 1
        fi
    fi

    # Check memory usage
    local memory_info
    local memory_used_percent=0
    memory_info=$(get_memory_info)
    if [[ $? -ne 0 ]]; then
        log "Failed to get memory information" "WARNING"
        # Continue checking other metrics
    fi

    # Parse memory values
    local total_mem=0
    local used_mem=0

    if command_exists jq; then
        total_mem=$(echo "$memory_info" | jq -r '.total_mb' 2>/dev/null)
        used_mem=$(echo "$memory_info" | jq -r '.used_mb' 2>/dev/null)

        # Verify jq output
        if ! is_number "$total_mem" || ! is_number "$used_mem"; then
            # Fallback to grep parsing if jq output is invalid
            total_mem=$(echo "$memory_info" | grep -o '"total_mb":[0-9]*' | cut -d':' -f2)
            used_mem=$(echo "$memory_info" | grep -o '"used_mb":[0-9]*' | cut -d':' -f2)
        fi
    else
        # Simple parsing fallback
        total_mem=$(echo "$memory_info" | grep -o '"total_mb":[0-9]*' | cut -d':' -f2)
        used_mem=$(echo "$memory_info" | grep -o '"used_mb":[0-9]*' | cut -d':' -f2)
    fi

    if [[ "$total_mem" -gt 0 ]]; then
        memory_used_percent=$(( used_mem * 100 / total_mem ))
        if [[ $memory_used_percent -gt $memory_threshold ]]; then
            log "System memory overloaded: ${memory_used_percent}% (threshold: ${memory_threshold}%)" "WARNING"
            return 1
        fi
    else
        log "Invalid total memory value: $total_mem" "WARNING"
        # Continue checking other metrics
    }

    # Check disk usage
    local disk_used_percent=0
    if command_exists df; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            disk_used_percent=$(df -P / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')
        else
            # Linux
            disk_used_percent=$(df -P / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')
        fi

        # Validate disk usage percentage
        if ! is_number "$disk_used_percent"; then
            log "Failed to get valid disk usage percentage: $disk_used_percent" "WARNING"
            # Continue with other checks
        else
            if [[ $disk_used_percent -gt $disk_threshold ]]; then
                log "System disk overloaded: ${disk_used_percent}% (threshold: ${disk_threshold}%)" "WARNING"
                return 1
            fi
        fi
    else
        log "df command not available to check disk usage" "WARNING"
        # Continue with other checks
    fi

    log "System load is within normal parameters" "DEBUG"
    return 0
}

# Export helper functions
export -f command_exists
export -f is_number

# Export System Functions
export -f is_root
export -f get_system_info
export -f check_disk_space
export -f is_port_in_use
export -f get_temp_file
export -f execute_with_timeout
export -f get_load_average
export -f get_memory_info
export -f check_system_load
