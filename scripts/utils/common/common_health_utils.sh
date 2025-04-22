#!/bin/bash
# filepath: scripts/utils/common/common_health_utils.sh
# Health check utility functions for Cloud Infrastructure Platform
# These functions provide system health monitoring capabilities

#######################################
# HEALTH CHECK UTILITIES
#######################################

# Version tracking
HEALTH_UTILS_VERSION="1.0.0"
HEALTH_UTILS_DATE="2024-07-29"

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_health_utils_version() {
    echo "${HEALTH_UTILS_VERSION} (${HEALTH_UTILS_DATE})"
}

# Check if required functions are available
for func in command_exists warn debug; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_utils.sh first." >&2
        exit 1
    fi
done

# Check if a service is running
# Arguments:
#   $1 - Service name
# Returns: 0 if running, 1 if not running, 2 if cannot check
is_service_running() {
    local service="$1"

    if [[ -z "$service" ]]; then
        warn "No service name provided to is_service_running"
        return 2
    fi

    if command_exists systemctl; then
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            debug "Service $service is running (systemctl)"
            return 0
        fi
    elif command_exists service; then
        if service "$service" status &>/dev/null; then
            debug "Service $service is running (service)"
            return 0
        fi
    elif command_exists launchctl; then
        # macOS service check
        if launchctl list | grep -q "$service"; then
            debug "Service $service is running (launchctl)"
            return 0
        fi
    else
        warn "Cannot check service status - no service manager found"
        return 2
    fi

    debug "Service $service is not running"
    return 1
}

# Check disk usage and warn if above threshold
# Arguments:
#   $1 - Path to check
#   $2 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above, 2 if check failed
check_disk_usage_threshold() {
    local path="${1:-/}"
    local threshold="${2:-90}"

    # Validate inputs
    if ! [[ -d "$path" ]]; then
        warn "Path does not exist or is not a directory: $path"
        return 2
    fi

    if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [ "$threshold" -lt 1 ] || [ "$threshold" -gt 100 ]; then
        warn "Invalid threshold value: $threshold (must be 1-100)"
        return 2
    fi

    local usage
    local df_output

    # Get disk usage with error handling
    if ! df_output=$(df -h "$path" 2>/dev/null); then
        warn "Failed to get disk usage for path: $path"
        return 2
    fi

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        usage=$(echo "$df_output" | awk 'NR==2 {sub(/%/, "", $5); print $5}')
    else
        # Linux
        usage=$(echo "$df_output" | awk 'NR==2 {print $5}' | tr -d '%')
    fi

    # Validate that usage is a number
    if ! [[ "$usage" =~ ^[0-9]+$ ]]; then
        warn "Could not parse disk usage from df output"
        return 2
    fi

    if (( usage >= threshold )); then
        warn "Disk usage for $path is at ${usage}%, which exceeds the ${threshold}% threshold"
        return 1
    fi

    debug "Disk usage for $path is at ${usage}%, below the ${threshold}% threshold"
    return 0
}

# Check if a process is running by name
# Arguments:
#   $1 - Process name or pattern to check
# Returns: 0 if running, 1 if not, 2 if check failed
is_process_running() {
    local process_name="$1"

    if [[ -z "$process_name" ]]; then
        warn "No process name provided to is_process_running"
        return 2
    fi

    if command_exists pgrep; then
        if pgrep -f "$process_name" &>/dev/null; then
            debug "Process matching '$process_name' is running (pgrep)"
            return 0
        fi
    elif command_exists ps; then
        if ps -ef | grep -v grep | grep -q "$process_name"; then
            debug "Process matching '$process_name' is running (ps)"
            return 0
        fi
    else
        warn "Cannot check process status - neither pgrep nor ps commands found"
        return 2
    fi

    debug "No process matching '$process_name' is running"
    return 1
}

# Check service health via HTTP endpoint
# Arguments:
#   $1 - URL to health endpoint
#   $2 - Expected status code (optional - defaults to 200)
#   $3 - Timeout in seconds (optional - defaults to 5)
#   $4 - Additional headers (optional - format: "Header1: value1|Header2: value2")
# Returns: 0 if healthy, 1 if unhealthy, 2 if check failed
check_health_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-5}"
    local headers="${4:-}"
    local status_code
    local curl_args=()
    local wget_args=()

    # Validate inputs
    if [[ -z "$url" ]]; then
        warn "No URL provided to check_health_endpoint"
        return 2
    fi

    if ! [[ "$expected_status" =~ ^[0-9]+$ ]]; then
        warn "Invalid expected status code: $expected_status"
        return 2
    fi

    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        warn "Invalid timeout: $timeout"
        return 2
    fi

    # Add headers if provided
    if [[ -n "$headers" ]]; then
        IFS='|' read -ra header_array <<< "$headers"
        for header in "${header_array[@]}"; do
            curl_args+=(-H "$header")
            wget_args+=(--header="$header")
        done
    fi

    if command_exists curl; then
        debug "Checking health endpoint with curl: $url"
        curl_args+=(-s -o /dev/null -w "%{http_code}" --max-time "$timeout")
        status_code=$(curl "${curl_args[@]}" "$url" 2>/dev/null)
        local curl_exit=$?

        if [[ $curl_exit -ne 0 ]]; then
            warn "curl request failed with exit code $curl_exit"
            return 2
        fi
    elif command_exists wget; then
        debug "Checking health endpoint with wget: $url"
        wget_args+=(--spider -q -T "$timeout" -O -)
        local wget_output
        wget_output=$(wget "${wget_args[@]}" "$url" 2>&1)
        local wget_exit=$?

        if [[ $wget_exit -ne 0 && $wget_exit -ne 8 ]]; then
            # Exit code 8 means server error response, which we still want to parse
            warn "wget request failed with exit code $wget_exit"
            return 2
        fi

        status_code=$(echo "$wget_output" | awk '/^  HTTP/{print $2}')

        if [[ -z "$status_code" ]]; then
            warn "Failed to parse HTTP status code from wget output"
            return 2
        fi
    else
        warn "Cannot check health endpoint - neither curl nor wget commands found"
        return 2
    fi

    # Validate status code is a number
    if ! [[ "$status_code" =~ ^[0-9]+$ ]]; then
        warn "Received non-numeric status code: $status_code"
        return 2
    fi

    if [[ "$status_code" == "$expected_status" ]]; then
        debug "Health check for $url succeeded with status $status_code"
        return 0
    else
        warn "Health check for $url failed - expected status $expected_status, got $status_code"
        return 1
    fi
}

# Create a secure temporary directory
# Arguments:
#   $1 - Prefix for directory name (optional)
#   $2 - Parent directory (optional - defaults to system temp)
#   $3 - Permissions (optional - defaults to 700)
# Returns: 0 on success and prints directory path, 1 on failure
create_temp_dir() {
    local prefix="${1:-tmp}"
    local parent_dir="${2:-}"
    local perms="${3:-700}"
    local temp_dir

    # If no parent directory specified, use system temp
    if [[ -z "$parent_dir" ]]; then
        if [[ -d /tmp && -w /tmp ]]; then
            parent_dir="/tmp"
        elif [[ -n "$TMPDIR" && -d "$TMPDIR" && -w "$TMPDIR" ]]; then
            parent_dir="$TMPDIR"
        else
            parent_dir="."
        fi
    fi

    # Ensure parent directory exists and is writable
    if [[ ! -d "$parent_dir" || ! -w "$parent_dir" ]]; then
        warn "Parent directory $parent_dir does not exist or is not writable"
        return 1
    fi

    # Create the temporary directory with mktemp
    if ! temp_dir=$(mktemp -d "${parent_dir}/${prefix}.XXXXXXXXXX" 2>/dev/null); then
        warn "Failed to create temporary directory"
        return 1
    fi

    # Set permissions
    chmod "$perms" "$temp_dir" || {
        warn "Failed to set permissions on temporary directory: $temp_dir"
        rm -rf "$temp_dir" 2>/dev/null
        return 1
    }

    debug "Created temporary directory: $temp_dir with permissions $perms"
    echo "$temp_dir"
    return 0
}

# Clean up temporary resources
# Arguments:
#   $1 - Temporary directory or file to clean up
# Returns: 0 on success, 1 on failure
cleanup_temp_resources() {
    local resource="$1"

    if [[ -z "$resource" ]]; then
        warn "No resource path provided to cleanup_temp_resources"
        return 1
    fi

    if [[ -d "$resource" ]]; then
        debug "Removing temporary directory: $resource"
        rm -rf "$resource" || {
            warn "Failed to remove temporary directory: $resource"
            return 1
        }
    elif [[ -f "$resource" ]]; then
        debug "Removing temporary file: $resource"
        rm -f "$resource" || {
            warn "Failed to remove temporary file: $resource"
            return 1
        }
    else
        warn "Resource does not exist: $resource"
        return 1
    fi

    debug "Successfully removed: $resource"
    return 0
}

# Enforce resource limits for a process
# Arguments:
#   $1 - Command to run with limits enforced
#   $2 - CPU limit percentage (optional - defaults to 50)
#   $3 - Memory limit in MB (optional - defaults to 1024)
#   $4 - Timeout in seconds (optional - defaults to 3600)
# Returns: Command exit code or 126 for limit enforcement failures
run_with_resource_limits() {
    local command="$1"
    local cpu_limit="${2:-50}"
    local memory_limit="${3:-1024}"
    local timeout_seconds="${4:-3600}"

    if [[ -z "$command" ]]; then
        warn "No command provided to run_with_resource_limits"
        return 126
    fi

    if ! [[ "$cpu_limit" =~ ^[0-9]+$ ]] || [ "$cpu_limit" -lt 1 ] || [ "$cpu_limit" -gt 100 ]; then
        warn "Invalid CPU limit: $cpu_limit (must be 1-100)"
        return 126
    fi

    if ! [[ "$memory_limit" =~ ^[0-9]+$ ]] || [ "$memory_limit" -lt 1 ]; then
        warn "Invalid memory limit: $memory_limit (must be positive)"
        return 126
    fi

    if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || [ "$timeout_seconds" -lt 1 ]; then
        warn "Invalid timeout: $timeout_seconds (must be positive)"
        return 126
    fi

    # Check for required tools
    if ! command_exists timeout; then
        warn "Cannot enforce resource limits - timeout command not found"
        # Run command without timeout
        debug "Running command without resource limits: $command"
        eval "$command"
        return $?
    fi

    # Convert memory to KB for cgroups
    local memory_kb=$((memory_limit * 1024))

    debug "Enforcing resource limits: CPU=$cpu_limit%, Memory=${memory_limit}MB, Timeout=${timeout_seconds}s"

    # Check if we can use cgroups
    if command_exists cgcreate && [[ -d "/sys/fs/cgroup" ]] && [[ "$(id -u)" -eq 0 ]]; then
        local cgroup_name="limit_$$"
        debug "Using cgroups to limit resources for command"

        # Create the cgroup
        if ! cgcreate -g cpu,memory:/$cgroup_name; then
            warn "Failed to create cgroup, falling back to nice and timeout"
        else
            # Set CPU and memory limits
            echo "$((cpu_limit * 1024 / 100))" > /sys/fs/cgroup/cpu/$cgroup_name/cpu.shares 2>/dev/null || true
            echo "$memory_kb" > /sys/fs/cgroup/memory/$cgroup_name/memory.limit_in_bytes 2>/dev/null || true

            # Execute with limits
            debug "Running command with cgroups: $command"
            # Use command arrays to avoid eval
            if command_exists nice; then
                cgexec -g cpu,memory:/$cgroup_name nice -n 10 timeout "$timeout_seconds" bash -c "$command"
            else
                cgexec -g cpu,memory:/$cgroup_name timeout "$timeout_seconds" bash -c "$command"
            fi
            local exit_code=$?

            # Clean up
            cgdelete -g cpu,memory:/$cgroup_name 2>/dev/null || true
            debug "Command completed with exit code: $exit_code"
            return $exit_code
        fi
    fi

    # Fallback to nice and ulimit if cgroups not available
    debug "Using nice and timeout to limit resources for command"
    if command_exists ulimit; then
        # Use subshell to avoid affecting parent shell's limits
        (
            # Set ulimit for memory if possible
            ulimit -v "$memory_kb" 2>/dev/null || true
            ulimit -t "$((timeout_seconds * 2))" 2>/dev/null || true

            # Run with nice and timeout
            if command_exists nice; then
                nice -n 10 timeout "$timeout_seconds" bash -c "$command"
            else
                timeout "$timeout_seconds" bash -c "$command"
            fi
        )
        local exit_code=$?
    else
        # Just use timeout without resource limits
        if command_exists nice; then
            nice -n 10 timeout "$timeout_seconds" bash -c "$command"
        else
            timeout "$timeout_seconds" bash -c "$command"
        fi
        local exit_code=$?
    fi

    debug "Command completed with exit code: $exit_code"
    return $exit_code
}

# Check TCP port availability
# Arguments:
#   $1 - Port number to check
#   $2 - Host to check (optional - defaults to localhost)
# Returns: 0 if port is available, 1 if in use, 2 if check failed
is_port_available() {
    local port="$1"
    local host="${2:-localhost}"

    # Validate inputs
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        warn "Invalid port number: $port (must be 1-65535)"
        return 2
    fi

    # Check using nc if available
    if command_exists nc; then
        if nc -z "$host" "$port" &>/dev/null; then
            debug "Port $port on $host is in use (nc)"
            return 1
        else
            debug "Port $port on $host is available (nc)"
            return 0
        fi
    # Check using netstat if available
    elif command_exists netstat; then
        if netstat -tuln | grep -q ":$port "; then
            debug "Port $port is in use (netstat)"
            return 1
        else
            debug "Port $port is available (netstat)"
            return 0
        fi
    # Check using ss if available
    elif command_exists ss; then
        if ss -tuln | grep -q ":$port "; then
            debug "Port $port is in use (ss)"
            return 1
        else
            debug "Port $port is available (ss)"
            return 0
        fi
    else
        warn "Cannot check port availability - no appropriate command found"
        return 2
    fi
}

# Check memory usage and warn if above threshold
# Arguments:
#   $1 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above, 2 if check failed
check_memory_usage_threshold() {
    local threshold="${1:-90}"
    local total_mem=0
    local used_mem=0
    local usage=0

    # Validate inputs
    if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [ "$threshold" -lt 1 ] || [ "$threshold" -gt 100 ]; then
        warn "Invalid threshold value: $threshold (must be 1-100)"
        return 2
    fi

    if [[ "$(uname)" == "Linux" ]]; then
        # Linux - use free command
        if command_exists free; then
            local mem_info
            mem_info=$(free -b 2>/dev/null)
            if [[ $? -ne 0 ]]; then
                warn "Failed to get memory information using free command"
                return 2
            fi

            # Parse total and used memory
            total_mem=$(echo "$mem_info" | awk '/^Mem:/ {print $2}')
            used_mem=$(echo "$mem_info" | awk '/^Mem:/ {print $3}')

            # Calculate percentage
            if [[ "$total_mem" -gt 0 ]]; then
                usage=$(( (used_mem * 100) / total_mem ))
            else
                warn "Invalid total memory value: $total_mem"
                return 2
            fi
        else
            warn "Cannot check memory usage - free command not found"
            return 2
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        # macOS - use vm_stat command
        if command_exists vm_stat; then
            local vm_stat_output
            vm_stat_output=$(vm_stat 2>/dev/null)
            if [[ $? -ne 0 ]]; then
                warn "Failed to get memory information using vm_stat command"
                return 2
            fi

            # Get page size
            local page_size=4096
            if command_exists pagesize; then
                page_size=$(pagesize 2>/dev/null || echo 4096)
            fi

            # Parse memory information
            local pages_free=$(echo "$vm_stat_output" | grep 'Pages free' | awk '{print $3}' | tr -d '.')
            local pages_active=$(echo "$vm_stat_output" | grep 'Pages active' | awk '{print $3}' | tr -d '.')
            local pages_inactive=$(echo "$vm_stat_output" | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')
            local pages_speculative=$(echo "$vm_stat_output" | grep 'Pages speculative' | awk '{print $3}' | tr -d '.' 2>/dev/null || echo 0)
            local pages_wired=$(echo "$vm_stat_output" | grep 'Pages wired' | awk '{print $4}' | tr -d '.')
            local pages_compressed=$(echo "$vm_stat_output" | grep 'Pages stored in compressor' | awk '{print $5}' | tr -d '.' 2>/dev/null || echo 0)

            # Calculate total and used memory
            local used_pages=$((pages_active + pages_wired + pages_compressed))
            local total_pages=$((pages_free + pages_active + pages_inactive + pages_speculative + pages_wired + pages_compressed))

            # Convert to bytes
            used_mem=$((used_pages * page_size))
            total_mem=$((total_pages * page_size))

            # Calculate percentage
            if [[ "$total_mem" -gt 0 ]]; then
                usage=$(( (used_mem * 100) / total_mem ))
            else
                warn "Invalid total memory value: $total_mem"
                return 2
            fi
        else
            warn "Cannot check memory usage - vm_stat command not found"
            return 2
        fi
    else
        warn "Unsupported operating system for memory check: $(uname)"
        return 2
    fi

    if (( usage >= threshold )); then
        warn "Memory usage is at ${usage}%, which exceeds the ${threshold}% threshold"
        return 1
    fi

    debug "Memory usage is at ${usage}%, below the ${threshold}% threshold"
    return 0
}

# Check load average
# Arguments:
#   $1 - Threshold multiplier (optional - defaults to 1.0)
# Returns: 0 if below threshold, 1 if above, 2 if check failed
check_load_average() {
    local threshold="${1:-1.0}"
    local load1=0
    local cores=1

    # Validate threshold
    if ! [[ "$threshold" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        warn "Invalid threshold value: $threshold (must be a number)"
        return 2
    fi

    # Get number of CPU cores
    if command_exists nproc; then
        cores=$(nproc 2>/dev/null)
    elif command_exists sysctl && [[ "$(uname)" == "Darwin" ]]; then
        cores=$(sysctl -n hw.ncpu 2>/dev/null)
    elif [[ -f /proc/cpuinfo ]]; then
        cores=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
    else
        warn "Could not determine number of CPU cores, assuming 1"
    fi

    # Ensure cores is at least 1
    if [[ -z "$cores" || "$cores" -lt 1 ]]; then
        cores=1
    fi

    # Calculate max acceptable load
    local max_load=$(echo "$cores * $threshold" | bc -l)

    # Get current load average
    if command_exists uptime; then
        local uptime_output
        uptime_output=$(uptime 2>/dev/null)
        if [[ "$(uname)" == "Darwin" ]]; then
            load1=$(echo "$uptime_output" | sed 's/.*load averages: \([0-9.]*\).*/\1/g')
        else
            load1=$(echo "$uptime_output" | sed 's/.*load average: \([0-9.]*\).*/\1/g')
        fi
    elif [[ -f /proc/loadavg ]]; then
        load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
    else
        warn "Cannot check load average - no appropriate method found"
        return 2
    fi

    # Validate that load is a number
    if ! [[ "$load1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        warn "Could not parse load average value: $load1"
        return 2
    fi

    # Compare load to threshold
    if (( $(echo "$load1 > $max_load" | bc -l) )); then
        warn "Load average is $load1, which exceeds the threshold of $max_load (${threshold}x $cores cores)"
        return 1
    fi

    debug "Load average is $load1, below the threshold of $max_load (${threshold}x $cores cores)"
    return 0
}

# Export all functions
export -f get_health_utils_version
export -f is_service_running
export -f check_disk_usage_threshold
export -f is_process_running
export -f check_health_endpoint
export -f create_temp_dir
export -f cleanup_temp_resources
export -f run_with_resource_limits
export -f is_port_available
export -f check_memory_usage_threshold
export -f check_load_average
