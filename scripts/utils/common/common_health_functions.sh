#######################################
# HEALTH CHECK UTILITIES
#######################################

# Check if a service is running
# Arguments:
#   $1 - Service name
# Returns: 0 if running, 1 if not
is_service_running() {
    local service="$1"

    if command_exists systemctl; then
        if systemctl is-active --quiet "$service"; then
            return 0
        fi
    elif command_exists service; then
        if service "$service" status &>/dev/null; then
            return 0
        fi
    elif command_exists launchctl; then
        # macOS service check
        if launchctl list | grep -q "$service"; then
            return 0
        fi
    else
        warn "Cannot check service status - no service manager found"
        return 2
    fi

    return 1
}

# Check disk usage and warn if above threshold
# Arguments:
#   $1 - Path to check
#   $2 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above
check_disk_usage_threshold() {
    local path="${1:-/}"
    local threshold="${2:-90}"

    local usage
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        usage=$(df -h "$path" | awk 'NR==2 {sub(/%/, "", $5); print $5}')
    else
        # Linux
        usage=$(df -h "$path" | awk 'NR==2 {print $5}' | tr -d '%')
    fi

    if (( usage >= threshold )); then
        warn "Disk usage for $path is at ${usage}%, which exceeds the ${threshold}% threshold"
        return 1
    fi

    return 0
}

# Check if a process is running by name
# Arguments:
#   $1 - Process name to check
# Returns: 0 if running, 1 if not
is_process_running() {
    local process_name="$1"

    if command_exists pgrep; then
        pgrep -f "$process_name" &>/dev/null
        return $?
    elif command_exists ps; then
        ps -ef | grep -v grep | grep -q "$process_name"
        return $?
    else
        warn "Cannot check process status - neither pgrep nor ps commands found"
        return 2
    fi
}

# Check service health via HTTP endpoint
# Arguments:
#   $1 - URL to health endpoint
#   $2 - Expected status code (optional - defaults to 200)
#   $3 - Timeout in seconds (optional - defaults to 5)
# Returns: 0 if healthy, 1 if unhealthy
check_health_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-5}"
    local status_code

    if command_exists curl; then
        status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url")
    elif command_exists wget; then
        status_code=$(wget --spider -q -T "$timeout" -O - "$url" 2>&1 | awk '/^  HTTP/{print $2}')
    else
        warn "Cannot check health endpoint - neither curl nor wget commands found"
        return 2
    fi

    if [[ "$status_code" == "$expected_status" ]]; then
        return 0
    else
        warn "Health check for $url failed - expected status $expected_status, got $status_code"
        return 1
    fi
}

# Clean up temporary resources
# Arguments:
#   $1 - Temporary directory or file to clean up
# Returns: 0 on success, 1 on failure
cleanup_temp_resources() {
    local resource="$1"

    if [[ -d "$resource" ]]; then
        rm -rf "$resource" || {
            warn "Failed to remove temporary directory: $resource"
            return 1
        }
    elif [[ -f "$resource" ]]; then
        rm -f "$resource" || {
            warn "Failed to remove temporary file: $resource"
            return 1
        }
    else
        warn "Resource does not exist: $resource"
        return 1
    fi

    return 0
}

# Enforce resource limits for a process
# Arguments:
#   $1 - Command to run with limits enforced
#   $2 - CPU limit percentage (optional - defaults to 50)
#   $3 - Memory limit in MB (optional - defaults to 1024)
# Returns: Command exit code
run_with_resource_limits() {
    local command="$1"
    local cpu_limit="${2:-50}"
    local memory_limit="${3:-1024}"

    # Check for required tools
    if ! command_exists nice || ! command_exists timeout; then
        warn "Cannot enforce resource limits - nice or timeout commands not found"
        # Run command without limits
        eval "$command"
        return $?
    fi

    # Convert memory to KB for cgroups
    local memory_kb=$((memory_limit * 1024))

    # Check if we can use cgroups
    if command_exists cgcreate && [[ -d "/sys/fs/cgroup" ]]; then
        cgcreate -g cpu,memory:/$$ || true
        echo "$cpu_limit" > /sys/fs/cgroup/cpu/$$/cpu.shares || true
        echo "$memory_kb" > /sys/fs/cgroup/memory/$$/memory.limit_in_bytes || true
        cgexec -g cpu,memory:/$$ nice -n 10 timeout 3600 "$command"
        local exit_code=$?
        cgdelete -g cpu,memory:/$$ || true
        return $exit_code
    else
        # Fallback to nice and ulimit if cgroups not available
        if command_exists ulimit; then
            # Set ulimit for memory if possible
            ulimit -m "$memory_kb" 2>/dev/null || true
        fi
        nice -n 10 timeout 3600 $command
        return $?
    fi
}

# Export all functions
export -f is_service_running
export -f check_disk_usage_threshold
export -f is_process_running
export -f check_health_endpoint
export -f create_temp_dir
export -f cleanup_temp_resources
export -f run_with_resource_limits
