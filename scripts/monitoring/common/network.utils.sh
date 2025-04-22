#!/bin/bash
# -----------------------------------------------------------------------------
# network_utils.sh - Common network connectivity and testing functions
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# This script provides standardized network utility functions for connectivity
# testing, DNS resolution, latency measurements, and other network operations
# used across monitoring scripts.
#
# Usage: source "$(dirname "$0")/../common/network_utils.sh"
# -----------------------------------------------------------------------------

# Set strict error handling
set -o pipefail
set -o errexit
set -o nounset

# Script version for tracking changes and compatibility
readonly NETWORK_UTILS_VERSION="1.1.0"

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Load common utility functions if available
UTILS_PATH="${PROJECT_ROOT}/scripts/utils/common_functions.sh"
if [[ -f "$UTILS_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$UTILS_PATH"
else
    # Define minimal logging functions if common_functions.sh is not available
    log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$2] $1"; }
    log_info() { log "$1" "INFO"; }
    log_warning() { log "$1" "WARNING" >&2; }
    log_error() { log "$1" "ERROR" >&2; }
    log_debug() { [[ "${VERBOSE:-false}" == "true" ]] && log "$1" "DEBUG"; }
    command_exists() { command -v "$1" &>/dev/null; }
fi

# Load logging utilities if available
LOGGING_PATH="${SCRIPT_DIR}/logging_utils.sh"
if [[ -f "$LOGGING_PATH" ]]; then
    # shellcheck source=/dev/null
    source "$LOGGING_PATH"
fi

# Default settings
DEFAULT_TIMEOUT=5
DEFAULT_RETRY_COUNT=3
DEFAULT_RETRY_DELAY=2
DEFAULT_HISTORY_DIR="${PROJECT_ROOT}/logs/network-history"
CIRCUIT_BREAKER_DIR="/tmp/circuit_breakers"
DEFAULT_USER_AGENT="Cloud-Platform-Monitor"
DEFAULT_DNS_TEST_DOMAIN="google.com"

# Ensure history and circuit breaker directories exist
mkdir -p "$DEFAULT_HISTORY_DIR" 2>/dev/null || true
mkdir -p "$CIRCUIT_BREAKER_DIR" 2>/dev/null || true

# -----------------------------------------------------------------------------
# URL AND ENDPOINT TESTING
# -----------------------------------------------------------------------------

# Check if a URL is reachable and responding as expected
# Arguments:
#   $1 - URL to check (required)
#   $2 - Expected status code (default: 200)
#   $3 - Timeout in seconds (default: 5)
#   $4 - User agent (default: "Cloud-Platform-Monitor")
#   $5 - Additional curl options (optional)
# Returns:
#   0 if successful, 1 if failed
#   Sets global variable HTTP_RESPONSE_TIME, HTTP_STATUS_CODE, HTTP_RESPONSE_SIZE
check_url() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"
    local user_agent="${4:-$DEFAULT_USER_AGENT}"
    local curl_options="${5:-}"
    local retry_count=0
    local max_retries=$DEFAULT_RETRY_COUNT
    local retry_delay=$DEFAULT_RETRY_DELAY

    # Reset global variables
    HTTP_RESPONSE_TIME=""
    HTTP_STATUS_CODE=""
    HTTP_RESPONSE_SIZE=""

    # Validate URL
    if ! is_valid_url "$url"; then
        log_error "Invalid URL format: $url"
        return 1
    fi

    # Check if circuit breaker is tripped for this URL
    local url_safe_name
    url_safe_name=$(url_to_safe_name "$url")
    if is_circuit_breaker_tripped "$url_safe_name"; then
        log_warning "Circuit breaker is tripped for $url, skipping check"
        return 1
    fi

    local success=false
    local curl_result_file
    curl_result_file="$(mktemp)" || {
        log_error "Failed to create temporary file"
        return 1
    }

    # Try with exponential backoff
    while [[ $retry_count -le $max_retries ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log_debug "Retry $retry_count/$max_retries for $url (delay: ${retry_delay}s)"
            sleep "$retry_delay"
            retry_delay=$((retry_delay * 2))  # Exponential backoff
        fi

        if command_exists curl; then
            # Use curl with specified options
            # shellcheck disable=SC2086
            if curl -s -o /dev/null -w "%{http_code},%{time_total},%{size_download}" \
                 -H "User-Agent: $user_agent" \
                 --max-time "$timeout" \
                 --retry 0 \
                 $curl_options \
                 "$url" > "$curl_result_file" 2>/dev/null; then

                IFS=',' read -r HTTP_STATUS_CODE HTTP_RESPONSE_TIME HTTP_RESPONSE_SIZE < "$curl_result_file"
                # Convert response time to milliseconds and ensure it's an integer
                HTTP_RESPONSE_TIME=$(echo "$HTTP_RESPONSE_TIME * 1000" | bc | cut -d'.' -f1)

                if [[ "$HTTP_STATUS_CODE" == "$expected_status" ]]; then
                    success=true
                    break
                fi
                log_debug "Got status code $HTTP_STATUS_CODE, expected $expected_status"
            else
                log_debug "Curl failed with exit code: $?"
            fi
        elif command_exists wget; then
            # Fallback to wget if curl is not available
            local start_time
            local end_time

            start_time=$(date +%s.%N)
            if wget --spider -q --timeout="$timeout" -T "$timeout" -U "$user_agent" "$url" 2>/dev/null; then
                end_time=$(date +%s.%N)
                HTTP_RESPONSE_TIME=$(echo "($end_time - $start_time) * 1000" | bc | cut -d'.' -f1)
                HTTP_STATUS_CODE="200" # Wget doesn't easily provide the status code
                HTTP_RESPONSE_SIZE="0" # Wget spider mode doesn't download content

                if [[ "$expected_status" == "200" ]]; then
                    success=true
                    break
                fi
            fi
        else
            log_error "Neither curl nor wget are available for URL testing"
            rm -f "$curl_result_file"
            return 1
        fi

        retry_count=$((retry_count + 1))
    done

    # Clean up temp file
    rm -f "$curl_result_file"

    if [[ "$success" == "true" ]]; then
        log_debug "URL check succeeded: $url (${HTTP_RESPONSE_TIME}ms, status: $HTTP_STATUS_CODE)"
        return 0
    else
        log_debug "URL check failed after $retry_count retries: $url"
        # Trip circuit breaker after multiple failures
        if [[ $retry_count -ge $max_retries ]]; then
            trip_circuit_breaker "$url_safe_name"
        fi
        return 1
    fi
}

# Check a health endpoint with proper timeout and retry handling
# Arguments:
#   $1 - URL to check (required)
#   $2 - Expected content pattern (optional)
#   $3 - Timeout in seconds (default: 5)
#   $4 - User agent (default: "Cloud-Platform-Monitor")
# Returns:
#   0 if successful, 1 if failed
#   Sets global variables HEALTH_STATUS, HEALTH_MESSAGE
check_health_endpoint() {
    local url="$1"
    local expected_content="${2:-}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"
    local user_agent="${4:-$DEFAULT_USER_AGENT}"

    # Reset global variables
    HEALTH_STATUS=""
    HEALTH_MESSAGE=""

    # First check if URL is reachable
    if ! check_url "$url" 200 "$timeout" "$user_agent"; then
        HEALTH_STATUS="UNREACHABLE"
        HEALTH_MESSAGE="Failed to connect to health endpoint"
        return 1
    fi

    # If we need to check content, download and check
    if [[ -n "$expected_content" ]]; then
        local content=""
        local content_fetched=false

        if command_exists curl; then
            content=$(curl -s -H "User-Agent: $user_agent" --max-time "$timeout" "$url" 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                content_fetched=true
            fi
        fi

        if [[ "$content_fetched" != "true" && $(command_exists wget) ]]; then
            content=$(wget -q -U "$user_agent" -O- --timeout="$timeout" "$url" 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                content_fetched=true
            fi
        fi

        if [[ "$content_fetched" != "true" ]]; then
            HEALTH_STATUS="ERROR"
            HEALTH_MESSAGE="No tools available to check content or content fetch failed"
            return 1
        fi

        # Check if content matches pattern
        if [[ "$content" == *"$expected_content"* || "$content" =~ $expected_content ]]; then
            HEALTH_STATUS="HEALTHY"
            HEALTH_MESSAGE="Health endpoint responded with expected content"
            return 0
        else
            HEALTH_STATUS="UNHEALTHY"
            HEALTH_MESSAGE="Health endpoint response missing expected content"
            return 1
        fi
    fi

    # If no content pattern specified, just checking status code was enough
    HEALTH_STATUS="HEALTHY"
    HEALTH_MESSAGE="Health endpoint responded with status 200"
    return 0
}

# -----------------------------------------------------------------------------
# CONNECTIVITY TESTING
# -----------------------------------------------------------------------------

# Check if a TCP port is open and reachable
# Arguments:
#   $1 - Host to check (required)
#   $2 - Port to check (required)
#   $3 - Timeout in seconds (default: 5)
# Returns:
#   0 if successful, 1 if failed
#   Sets global variable TCP_RESPONSE_TIME
check_tcp_port() {
    local host="$1"
    local port="$2"
    local timeout="${3:-$DEFAULT_TIMEOUT}"

    # Reset global variable
    TCP_RESPONSE_TIME=""

    if [[ -z "$host" || -z "$port" ]]; then
        log_error "Host and port are required for TCP port check"
        return 1
    fi

    # Validate port number
    if ! [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
        log_error "Invalid port number: $port (must be 1-65535)"
        return 1
    fi

    local start_time
    local end_time
    local exit_code=1

    start_time=$(date +%s.%N)

    if command_exists nc; then
        nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
        exit_code=$?
    elif command_exists timeout && command_exists telnet; then
        # Use timeout command with telnet as fallback
        echo -e '\x1dclose\x0d' | timeout "$timeout" telnet "$host" "$port" >/dev/null 2>&1
        exit_code=$?
    else
        log_warning "Neither nc nor telnet available for port checking"
        return 1
    fi

    end_time=$(date +%s.%N)
    TCP_RESPONSE_TIME=$(echo "($end_time - $start_time) * 1000" | bc | cut -d'.' -f1)

    if [[ $exit_code -eq 0 ]]; then
        log_debug "TCP port check succeeded: $host:$port (${TCP_RESPONSE_TIME}ms)"
        return 0
    else
        log_debug "TCP port check failed: $host:$port"
        return 1
    fi
}

# Check if a host responds to ping
# Arguments:
#   $1 - Host to check (required)
#   $2 - Number of packets to send (default: 3)
#   $3 - Timeout in seconds (default: 5)
# Returns:
#   0 if successful, 1 if failed
#   Sets global variables PING_MIN_TIME, PING_AVG_TIME, PING_MAX_TIME, PING_PACKET_LOSS
check_ping() {
    local host="$1"
    local packets="${2:-3}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"

    # Reset global variables
    PING_MIN_TIME=""
    PING_AVG_TIME=""
    PING_MAX_TIME=""
    PING_PACKET_LOSS=""

    if [[ -z "$host" ]]; then
        log_error "Host is required for ping check"
        return 1
    fi

    # Remove http:// or https:// prefix if present
    host="${host#http://}"
    host="${host#https://}"
    # Remove path and query string if present
    host="${host%%/*}"

    # Validate packet count
    if ! [[ "$packets" =~ ^[0-9]+$ && "$packets" -gt 0 ]]; then
        packets=3
        log_warning "Invalid packet count, using default: $packets"
    fi

    local ping_output
    local ping_result=1
    local ping_cmd

    # Set up platform-specific ping command
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS ping
        ping_cmd=(ping -c "$packets" -t "$timeout" "$host")
    else
        # Linux ping
        ping_cmd=(ping -c "$packets" -W "$timeout" "$host")
    fi

    # Execute ping command
    ping_output=$("${ping_cmd[@]}" 2>&1)
    ping_result=$?

    if [[ $ping_result -eq 0 ]]; then
        # Extract statistics using regex
        if [[ "$ping_output" =~ min/avg/max[^=]+= *([0-9.]+)/([0-9.]+)/([0-9.]+) ]]; then
            PING_MIN_TIME="${BASH_REMATCH[1]}"
            PING_AVG_TIME="${BASH_REMATCH[2]}"
            PING_MAX_TIME="${BASH_REMATCH[3]}"
        fi

        if [[ "$ping_output" =~ ([0-9]+)%+ *packet *loss ]]; then
            PING_PACKET_LOSS="${BASH_REMATCH[1]}"
        fi

        log_debug "Ping succeeded: $host (min/avg/max = $PING_MIN_TIME/$PING_AVG_TIME/$PING_MAX_TIME ms, loss = $PING_PACKET_LOSS%)"
        return 0
    else
        log_debug "Ping failed: $host"
        return 1
    fi
}

# Special ping function with simplified return value
# Arguments:
#   $1 - Host to check (required)
#   $2 - Number of packets to send (default: 1)
#   $3 - Timeout in seconds (default: 2)
# Returns:
#   0 if successful, 1 if failed
ping_host() {
    local host="$1"
    local packets="${2:-1}"
    local timeout="${3:-2}"

    if [[ -z "$host" ]]; then
        return 1
    fi

    # Use system ping command with minimal options for speed
    if [[ "$(uname)" == "Darwin" ]]; then
        ping -c "$packets" -t "$timeout" -q "$host" >/dev/null 2>&1
    else
        ping -c "$packets" -W "$timeout" -q "$host" >/dev/null 2>&1
    fi

    return $?
}

# Run traceroute to a host
# Arguments:
#   $1 - Host to trace (required)
#   $2 - Max hops (default: 15)
#   $3 - Timeout in seconds (default: 5)
#   $4 - Output format (text|json) (default: text)
# Returns:
#   0 if traceroute completes, 1 if fails
#   Sets global variable TRACEROUTE_OUTPUT
run_traceroute() {
    local host="$1"
    local max_hops="${2:-15}"
    local timeout="${3:-$DEFAULT_TIMEOUT}"
    local format="${4:-text}"

    # Reset global variable
    TRACEROUTE_OUTPUT=""

    if [[ -z "$host" ]]; then
        log_error "Host is required for traceroute"
        return 1
    fi

    # Remove http:// or https:// prefix if present
    host="${host#http://}"
    host="${host#https://}"
    # Remove path and query string if present
    host="${host%%/*}"

    # Check if traceroute command is available
    if ! command_exists traceroute; then
        log_warning "Traceroute command not available"
        return 1
    fi

    # Run traceroute
    local raw_output
    raw_output=$(traceroute -m "$max_hops" -w "$timeout" "$host" 2>&1)
    local result=$?

    # Process output based on format
    if [[ "$format" == "json" ]]; then
        # Convert traceroute output to JSON format
        TRACEROUTE_OUTPUT="{"
        TRACEROUTE_OUTPUT+="\"host\":\"$host\","
        TRACEROUTE_OUTPUT+="\"hops\":["

        local first_hop=true
        local hop_num=0
        local hop_ip=""
        local hop_name=""
        local hop_time=""

        while read -r line; do
            # Skip the header line
            if [[ "$line" =~ ^traceroute ]]; then
                continue
            fi

            # Extract hop information
            if [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]+(([^[:space:]]+)[[:space:]]+\(([^)]+)\)|([^[:space:]]+))[[:space:]]+(.*)$ ]]; then
                hop_num="${BASH_REMATCH[1]}"

                # Handle different output formats
                if [[ -n "${BASH_REMATCH[3]}" ]]; then
                    hop_name="${BASH_REMATCH[3]}"
                    hop_ip="${BASH_REMATCH[4]}"
                else
                    hop_name=""
                    hop_ip="${BASH_REMATCH[5]}"
                fi

                # Extract the first time value (ms)
                hop_times="${BASH_REMATCH[6]}"
                if [[ "$hop_times" =~ ([0-9.]+)[[:space:]]*ms ]]; then
                    hop_time="${BASH_REMATCH[1]}"
                elif [[ "$hop_times" =~ \* ]]; then
                    hop_time="timeout"
                else
                    hop_time="unknown"
                fi

                if [[ "$first_hop" == "true" ]]; then
                    first_hop=false
                else
                    TRACEROUTE_OUTPUT+=","
                fi

                TRACEROUTE_OUTPUT+="{\"hop\":$hop_num,\"ip\":\"$hop_ip\",\"name\":\"$hop_name\",\"time\":\"$hop_time\"}"
            fi
        done <<< "$raw_output"

        TRACEROUTE_OUTPUT+="]}"
    else
        TRACEROUTE_OUTPUT="$raw_output"
    fi

    if [[ $result -eq 0 ]]; then
        log_debug "Traceroute completed: $host"
        return 0
    else
        log_debug "Traceroute failed: $host"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# DNS FUNCTIONS
# -----------------------------------------------------------------------------

# Resolve hostname to IP address
# Arguments:
#   $1 - Hostname to resolve (required)
#   $2 - Record type (default: A)
#   $3 - Output format (text|json) (default: text)
# Returns:
#   0 if successful, 1 if failed
#   Sets global variable DNS_RESULT
resolve_dns() {
    local hostname="$1"
    local record_type="${2:-A}"
    local format="${3:-text}"

    # Reset global variable
    DNS_RESULT=""

    if [[ -z "$hostname" ]]; then
        log_error "Hostname is required for DNS resolution"
        return 1
    fi

    # Remove http:// or https:// prefix if present
    hostname="${hostname#http://}"
    hostname="${hostname#https://}"
    # Remove path and query string if present
    hostname="${hostname%%/*}"

    local results=""
    local success=false

    if command_exists dig; then
        results=$(dig +short "$record_type" "$hostname" 2>/dev/null)
        if [[ $? -eq 0 && -n "$results" ]]; then
            success=true
        fi
    elif command_exists host; then
        local host_output
        host_output=$(host -t "$record_type" "$hostname" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            if [[ "$record_type" == "A" || "$record_type" == "AAAA" ]]; then
                results=$(echo "$host_output" | awk '/has address/ {print $4}; /has IPv6/ {print $5}')
            else
                results=$(echo "$host_output" | awk '{for (i=5; i<=NF; i++) print $i}')
            fi
            if [[ -n "$results" ]]; then
                success=true
            fi
        fi
    elif command_exists nslookup; then
        local nslookup_output
        nslookup_output=$(nslookup -type="$record_type" "$hostname" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            if [[ "$record_type" == "A" || "$record_type" == "AAAA" ]]; then
                results=$(echo "$nslookup_output" | awk '/^Address/ && !/#/ {print $2}')
            else
                # For other record types, extraction is more complex
                results=$(echo "$nslookup_output" | grep -v '^Address' | awk 'NF>1 {for(i=2;i<=NF;i++) print $i}' | grep -v '^$')
            fi
            if [[ -n "$results" ]]; then
                success=true
            fi
        fi
    else
        log_error "No DNS resolution tools available (dig, host, nslookup)"
        return 1
    fi

    if [[ "$success" == "true" ]]; then
        if [[ "$format" == "json" ]]; then
            # Convert results to JSON format
            DNS_RESULT="{"
            DNS_RESULT+="\"hostname\":\"$hostname\","
            DNS_RESULT+="\"record_type\":\"$record_type\","
            DNS_RESULT+="\"records\":["

            local first=true
            while read -r record; do
                if [[ -n "$record" ]]; then
                    if [[ "$first" == "true" ]]; then
                        first=false
                    else
                        DNS_RESULT+=","
                    fi
                    DNS_RESULT+="\"$record\""
                fi
            done <<< "$results"

            DNS_RESULT+="]}"
        else
            DNS_RESULT="$results"
        fi

        log_debug "DNS resolution succeeded for $hostname ($record_type): $results"
        return 0
    else
        log_debug "DNS resolution failed for $hostname ($record_type)"
        return 1
    fi
}

# Get primary DNS servers
# Arguments:
#   $1 - Output format (text|json) (default: text)
# Returns: List of DNS servers in specified format
get_dns_servers() {
    local format="${1:-text}"
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

    # Format the output
    if [[ "$format" == "json" && -n "$servers" ]]; then
        local json_servers="["
        local first=true
        while read -r server; do
            if [[ -n "$server" ]]; then
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    json_servers+=","
                fi
                json_servers+="\"$server\""
            fi
        done <<< "$servers"
        json_servers+="]"
        echo "{\"dns_servers\":$json_servers}"
    elif [[ -n "$servers" ]]; then
        echo "$servers"
        return 0
    else
        if [[ "$format" == "json" ]]; then
            echo "{\"dns_servers\":[],\"error\":\"No DNS servers found\"}"
        else
            echo "Unknown"
        fi
        return 1
    fi
}

# Check if DNS resolution is working correctly
# Arguments:
#   $1 - Test domain (default: google.com)
# Returns:
#   0 if successful, 1 if failed
check_dns_functioning() {
    local test_domain="${1:-$DEFAULT_DNS_TEST_DOMAIN}"

    if resolve_dns "$test_domain"; then
        log_debug "DNS resolution is functioning properly"
        return 0
    else
        log_warning "DNS resolution appears to be failing"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# CIRCUIT BREAKER PATTERN
# -----------------------------------------------------------------------------

# Generate a safe filename from URL or hostname
# Arguments:
#   $1 - URL or hostname
# Returns: Safe name for use in filenames
url_to_safe_name() {
    local url="$1"
    # Replace non-alphanumeric characters with underscore and collapse multiple underscores
    echo "${url//[^a-zA-Z0-9]/_}" | tr -s '_'
}

# Trip the circuit breaker for an endpoint
# Arguments:
#   $1 - Endpoint identifier (name or safe URL)
#   $2 - Trip duration in seconds (default: 300 seconds / 5 minutes)
# Returns:
#   0 if successful, 1 if failed
trip_circuit_breaker() {
    local endpoint="$1"
    local duration="${2:-300}"

    if [[ -z "$endpoint" ]]; then
        log_error "Endpoint identifier required for circuit breaker"
        return 1
    fi

    # Validate duration
    if ! [[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]]; then
        log_warning "Invalid circuit breaker duration: $duration, using default: 300"
        duration=300
    fi

    local circuit_breaker_file="${CIRCUIT_BREAKER_DIR}/${endpoint}.cb"
    local expiry=$(($(date +%s) + duration))

    echo "$expiry" > "$circuit_breaker_file" || {
        log_error "Failed to create circuit breaker file: $circuit_breaker_file"
        return 1
    }

    log_warning "Circuit breaker tripped for $endpoint (protection active for $duration seconds)"
    return 0
}

# Check if circuit breaker is tripped
# Arguments:
#   $1 - Endpoint identifier (name or safe URL)
# Returns:
#   0 if tripped (open), 1 if not tripped (closed)
is_circuit_breaker_tripped() {
    local endpoint="$1"
    local circuit_breaker_file="${CIRCUIT_BREAKER_DIR}/${endpoint}.cb"

    if [[ -f "$circuit_breaker_file" ]]; then
        # Read expiry time
        local expiry
        expiry=$(cat "$circuit_breaker_file" 2>/dev/null) || {
            log_warning "Failed to read circuit breaker file: $circuit_breaker_file"
            rm -f "$circuit_breaker_file" 2>/dev/null || true
            return 1
        }

        # Validate expiry is a number
        if ! [[ "$expiry" =~ ^[0-9]+$ ]]; then
            log_warning "Invalid expiry time in circuit breaker file: $circuit_breaker_file"
            rm -f "$circuit_breaker_file" 2>/dev/null || true
            return 1
        }

        local current_time
        current_time=$(date +%s)

        if [[ $current_time -lt $expiry ]]; then
            # Calculate remaining time
            local remaining=$((expiry - current_time))
            log_debug "Circuit breaker for $endpoint is open (will reset in ${remaining}s)"
            return 0  # Circuit breaker is tripped (open)
        else
            # Reset circuit breaker
            rm -f "$circuit_breaker_file" 2>/dev/null || true
            log_debug "Circuit breaker for $endpoint reset after expiry"
        fi
    fi

    return 1  # Circuit breaker is not tripped (closed)
}

# Reset circuit breaker
# Arguments:
#   $1 - Endpoint identifier (name or safe URL), or "all" to reset all
# Returns:
#   0 if successful, 1 if no breaker was found or reset failed
reset_circuit_breaker() {
    local endpoint="$1"

    if [[ "$endpoint" == "all" ]]; then
        # Reset all circuit breakers
        local file_count=0
        local removed_count=0

        if [[ -d "$CIRCUIT_BREAKER_DIR" ]]; then
            for cb_file in "${CIRCUIT_BREAKER_DIR}"/*.cb; do
                if [[ -f "$cb_file" ]]; then
                    ((file_count++))
                    if rm -f "$cb_file" 2>/dev/null; then
                        ((removed_count++))
                    fi
                fi
            done
        fi

        if [[ $file_count -eq 0 ]]; then
            log_debug "No circuit breakers found to reset"
            return 1
        elif [[ $removed_count -eq $file_count ]]; then
            log_info "All circuit breakers reset ($removed_count total)"
            return 0
        else
            log_warning "Some circuit breakers could not be reset (removed $removed_count of $file_count)"
            return 1
        fi
    elif [[ -n "$endpoint" ]]; then
        local circuit_breaker_file="${CIRCUIT_BREAKER_DIR}/${endpoint}.cb"
        if [[ -f "$circuit_breaker_file" ]]; then
            if rm -f "$circuit_breaker_file" 2>/dev/null; then
                log_info "Circuit breaker reset for $endpoint"
                return 0
            else
                log_warning "Failed to remove circuit breaker file for $endpoint"
                return 1
            fi
        else
            log_debug "No circuit breaker found for $endpoint"
            return 1
        fi
    else
        log_error "Endpoint identifier required to reset circuit breaker"
        return 1
    fi
}

# List all active circuit breakers
# Arguments:
#   $1 - Output format (text|json) (default: text)
# Returns: List of active circuit breakers with remaining time
list_circuit_breakers() {
    local format="${1:-text}"
    local current_time
    current_time=$(date +%s)

    if [[ "$format" == "json" ]]; then
        echo '{"circuit_breakers":['

        local first=true
        local found=false

        if [[ -d "$CIRCUIT_BREAKER_DIR" ]]; then
            for cb_file in "${CIRCUIT_BREAKER_DIR}"/*.cb; do
                if [[ -f "$cb_file" ]]; then
                    local endpoint=$(basename "$cb_file" .cb)
                    local expiry=$(cat "$cb_file" 2>/dev/null || echo "0")

                    if [[ "$expiry" =~ ^[0-9]+$ && $current_time -lt $expiry ]]; then
                        local remaining=$((expiry - current_time))

                        if [[ "$first" == "true" ]]; then
                            first=false
                        else
                            echo ","
                        fi

                        echo -n "{\"endpoint\":\"$endpoint\",\"remaining_seconds\":$remaining,\"expires_at\":$expiry}"
                        found=true
                    fi
                fi
            done
        fi

        echo ']}'

        if [[ "$found" == "false" ]]; then
            return 1
        else
            return 0
        fi
    else
        local found=false

        if [[ -d "$CIRCUIT_BREAKER_DIR" ]]; then
            for cb_file in "${CIRCUIT_BREAKER_DIR}"/*.cb; do
                if [[ -f "$cb_file" ]]; then
                    local endpoint=$(basename "$cb_file" .cb)
                    local expiry=$(cat "$cb_file" 2>/dev/null || echo "0")

                    if [[ "$expiry" =~ ^[0-9]+$ && $current_time -lt $expiry ]]; then
                        local remaining=$((expiry - current_time))
                        echo "$endpoint: $remaining seconds remaining (expires: $(date -r "$expiry" "+%Y-%m-%d %H:%M:%S"))"
                        found=true
                    fi
                fi
            done
        fi

        if [[ "$found" == "false" ]]; then
            echo "No active circuit breakers found."
            return 1
        fi

        return 0
    fi
}

# -----------------------------------------------------------------------------
# PERFORMANCE TRACKING
# -----------------------------------------------------------------------------

# Record a latency measurement for historical tracking
# Arguments:
#   $1 - Endpoint identifier (name or URL)
#   $2 - Latency in milliseconds
#   $3 - Status (0 for success, non-zero for failure)
#   $4 - History directory (optional)
# Returns:
#   0 if successful, 1 if failed
record_latency() {
    local endpoint="$1"
    local latency="$2"
    local status="${3:-0}"
    local history_dir="${4:-$DEFAULT_HISTORY_DIR}"

    if [[ -z "$endpoint" || -z "$latency" ]]; then
        log_error "Endpoint and latency are required for history tracking"
        return 1
    fi

    # Validate latency is a number
    if ! [[ "$latency" =~ ^[0-9]+$ ]]; then
        log_error "Invalid latency value: $latency"
        return 1
    }

    # Create a safe name for the history file
    local safe_name
    safe_name=$(url_to_safe_name "$endpoint")
    local history_file="${history_dir}/${safe_name}_history.log"

    # Ensure history directory exists
    mkdir -p "$history_dir" 2>/dev/null || {
        log_error "Failed to create history directory: $history_dir"
        return 1
    }

    # Record the measurement with timestamp
    echo "$latency $status $(date +%s)" >> "$history_file" || {
        log_error "Failed to write to history file: $history_file"
        return 1
    }

    # Prevent the history file from growing too large
    local max_lines=1000
    if [[ -f "$history_file" ]]; then
        local line_count
        line_count=$(wc -l < "$history_file")
        if [[ $line_count -gt $max_lines ]]; then
            local lines_to_keep=$((max_lines / 2))
            local temp_file="${history_file}.tmp"
            tail -n "$lines_to_keep" "$history_file" > "$temp_file" && mv "$temp_file" "$history_file"
        fi
    fi

    return 0
}

# Analyze latency trends for an endpoint
# Arguments:
#   $1 - Endpoint identifier (name or URL)
#   $2 - Current latency value
#   $3 - History directory (optional)
#   $4 - Anomaly threshold multiplier (default: 1.5)
# Returns:
#   0 if latency is normal, 1 if abnormal
#   Sets global variables LATENCY_AVG, LATENCY_TREND, LATENCY_ANOMALY
analyze_latency_trend() {
    local endpoint="$1"
    local current_latency="$2"
    local history_dir="${3:-$DEFAULT_HISTORY_DIR}"
    local threshold_multiplier="${4:-1.5}"

    # Reset global variables
    LATENCY_AVG=""
    LATENCY_TREND=""
    LATENCY_ANOMALY="false"

    if [[ -z "$endpoint" || -z "$current_latency" ]]; then
        log_error "Endpoint and current latency are required for trend analysis"
        return 1
    fi

    # Validate latency is a number
    if ! [[ "$current_latency" =~ ^[0-9]+$ ]]; then
        log_error "Invalid latency value: $current_latency"
        return 1
    }

    # Validate threshold multiplier
    if ! [[ "$threshold_multiplier" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        log_warning "Invalid threshold multiplier: $threshold_multiplier, using default: 1.5"
        threshold_multiplier=1.5
    }

    # Create a safe name for the history file
    local safe_name
    safe_name=$(url_to_safe_name "$endpoint")
    local history_file="${history_dir}/${safe_name}_history.log"

    if [[ ! -f "$history_file" ]]; then
        log_debug "No history file found for $endpoint, starting new trend tracking"
        LATENCY_TREND="UNKNOWN"
        return 1
    fi

    # Get last several successful measurements (status=0)
    local history_data
    history_data=$(grep ' 0 ' "$history_file" | tail -n 10)
    local count
    count=$(echo "$history_data" | wc -l | tr -d ' ')

    if [[ $count -lt 5 ]]; then
        log_debug "Insufficient history data for trend analysis of $endpoint ($count samples)"
        LATENCY_TREND="INSUFFICIENT_DATA"
        return 1
    fi

    # Calculate average latency from history
    local total=0
    while read -r latency status timestamp; do
        if [[ "$latency" =~ ^[0-9]+$ ]]; then
            total=$((total + latency))
        fi
    done <<< "$history_data"

    LATENCY_AVG=$((total / count))

    # Determine if current latency is abnormal (> threshold_multiplier * average)
    local threshold
    threshold=$(echo "$LATENCY_AVG * $threshold_multiplier" | bc | cut -d'.' -f1)

    if [[ $current_latency -gt $threshold ]]; then
        LATENCY_TREND="INCREASING"
        LATENCY_ANOMALY="true"
        log_warning "Latency spike detected for $endpoint: current=${current_latency}ms, avg=${LATENCY_AVG}ms, threshold=${threshold}ms"
        return 1
    elif [[ $current_latency -lt $LATENCY_AVG ]]; then
        LATENCY_TREND="DECREASING"
        return 0
    else
        LATENCY_TREND="STABLE"
        return 0
    fi
}

# Get historical latency statistics for an endpoint
# Arguments:
#   $1 - Endpoint identifier (name or URL)
#   $2 - Time period in seconds (default: 86400 - last 24 hours)
#   $3 - History directory (optional)
#   $4 - Output format (text|json) (default: text)
# Returns: Statistics string or JSON with min, max, avg, p95, p99 values
get_latency_stats() {
    local endpoint="$1"
    local period="${2:-86400}"  # Default 24 hours
    local history_dir="${3:-$DEFAULT_HISTORY_DIR}"
    local format="${4:-text}"

    if [[ -z "$endpoint" ]]; then
        if [[ "$format" == "json" ]]; then
            echo "{\"error\":\"Endpoint identifier required\"}"
        else
            echo "Error: Endpoint identifier required"
        fi
        return 1
    fi

    # Create a safe name for the history file
    local safe_name
    safe_name=$(url_to_safe_name "$endpoint")
    local history_file="${history_dir}/${safe_name}_history.log"

    if [[ ! -f "$history_file" ]]; then
        if [[ "$format" == "json" ]]; then
            echo "{\"error\":\"No history data found for $endpoint\"}"
        else
            echo "No history data found for $endpoint"
        fi
        return 1
    fi

    # Filter records from specified time period
    local current_time
    current_time=$(date +%s)
    local cutoff_time=$((current_time - period))

    # Get successful measurements in time period
    local filtered_data
    filtered_data=$(awk -v cutoff="$cutoff_time" '$3 >= cutoff && $2 == 0 {print $1}' "$history_file")
    local count
    count=$(echo "$filtered_data" | wc -l | tr -d ' ')

    if [[ $count -lt 1 ]]; then
        if [[ "$format" == "json" ]]; then
            echo "{\"error\":\"No data points in the specified time period\"}"
        else
            echo "No data points in the specified time period"
        fi
        return 1
    fi

    # Calculate statistics
    local min max sum avg p95 p99

    # Store values in a temporary file for sorting
    local temp_file
    temp_file=$(mktemp)
    echo "$filtered_data" > "$temp_file"

    # Calculate min, max, sum, avg
    min=$(sort -n "$temp_file" | head -n 1)
    max=$(sort -n "$temp_file" | tail -n 1)
    sum=$(awk '{sum+=$1} END {print sum}' "$temp_file")
    avg=$((sum / count))

    # Calculate percentiles
    sorted_file=$(mktemp)
    sort -n "$temp_file" > "$sorted_file"

    local p95_index=$((count * 95 / 100))
    local p99_index=$((count * 99 / 100))

    # Ensure indices are at least 1
    [[ $p95_index -lt 1 ]] && p95_index=1
    [[ $p99_index -lt 1 ]] && p99_index=1

    p95=$(sed -n "${p95_index}p" "$sorted_file")
    p99=$(sed -n "${p99_index}p" "$sorted_file")

    # Clean up temp files
    rm -f "$temp_file" "$sorted_file"

    # Output the results
    if [[ "$format" == "json" ]]; then
        echo "{\"endpoint\":\"$endpoint\",\"period_seconds\":$period,\"samples\":$count,\"min\":$min,\"max\":$max,\"avg\":$avg,\"p95\":$p95,\"p99\":$p99}"
    else
        echo "Latency statistics for $endpoint (last $(( period / 3600 )) hours):"
        echo "  Samples: $count"
        echo "  Min: ${min}ms"
        echo "  Max: ${max}ms"
        echo "  Avg: ${avg}ms"
        echo "  95th percentile: ${p95}ms"
        echo "  99th percentile: ${p99}ms"
    fi

    return 0
}

# -----------------------------------------------------------------------------
# VALIDATION FUNCTIONS
# -----------------------------------------------------------------------------

# Check if a string is a valid URL
# Arguments:
#   $1 - String to validate
# Returns: 0 if valid, 1 if not
is_valid_url() {
    local url="$1"

    if [[ -z "$url" ]]; then
        return 1
    fi

    # Basic URL validation - requires http:// or https:// prefix
    if [[ "$url" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(/[^[:space:]]*)?$ ]]; then
        return 0
    fi

    return 1
}

# Check if a string is a valid hostname
# Arguments:
#   $1 - String to validate
# Returns: 0 if valid, 1 if not
is_valid_hostname() {
    local hostname="$1"

    if [[ -z "$hostname" ]]; then
        return 1
    fi

    # Hostname validation
    # - Allows alphanumeric characters, hyphens
    # - Requires at least one dot
    # - No consecutive dots
    # - No hyphens at start or end of segments
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
        return 0
    fi

    return 1
}

# Check if a string is a valid IP address
# Arguments:
#   $1 - String to validate
#   $2 - Type (4 for IPv4, 6 for IPv6, both if not specified)
# Returns: 0 if valid, 1 if not
is_valid_ip() {
    local ip="$1"
    local type="${2:-both}"

    if [[ -z "$ip" ]]; then
        return 1
    fi

    case "$type" in
        4|ipv4)
            # IPv4 validation
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local IFS='.'
                read -ra ip_array <<< "$ip"

                # Check if we have exactly 4 octets
                if [[ ${#ip_array[@]} -ne 4 ]]; then
                    return 1
                fi

                # Check that each octet is between 0 and 255
                for octet in "${ip_array[@]}"; do
                    if ! [[ "$octet" =~ ^[0-9]+$ ]] || \
                       (( octet < 0 || octet > 255 )); then
                        return 1
                    fi
                done

                return 0
            fi
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (more comprehensive than before)
            if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,7}:$ || \
                  "$ip" =~ ^:((:[0-9a-fA-F]{1,4}){1,7}|:)$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$ || \
                  "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$ || \
                  "$ip" =~ ^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$ || \
                  "$ip" =~ ^:((:[0-9a-fA-F]{1,4}){1,7}|:)$ ]]; then
                return 0
            fi
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            log_error "Invalid IP validation type: $type. Use '4', 'ipv4', '6', 'ipv6', or 'both'."
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# NETWORK INFORMATION FUNCTIONS
# -----------------------------------------------------------------------------

# Get public IP address
# Arguments:
#   $1 - IP version (4 or 6) (default: 4)
#   $2 - Timeout in seconds (default: 5)
# Returns: Public IP address or error message
get_public_ip() {
    local ip_version="${1:-4}"
    local timeout="${2:-$DEFAULT_TIMEOUT}"
    local ip=""

    # Services for IPv4
    local services_ipv4=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )

    # Services for IPv6
    local services_ipv6=(
        "https://api6.ipify.org"
        "https://v6.ident.me"
        "https://ipv6.icanhazip.com"
    )

    # Select appropriate services based on IP version
    local services
    if [[ "$ip_version" == "6" ]]; then
        services=("${services_ipv6[@]}")
    else
        services=("${services_ipv4[@]}")
    fi

    # Try each service until we get a valid IP
    for service in "${services[@]}"; do
        if command_exists curl; then
            ip=$(curl -s --max-time "$timeout" "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout="$timeout" "$service" 2>/dev/null)
        else
            echo "ERROR: Neither curl nor wget are available"
            return 1
        fi

        # Check if we got a valid IP of the requested version
        if [[ -n "$ip" ]] && is_valid_ip "$ip" "$ip_version"; then
            echo "$ip"
            return 0
        fi
    done

    echo "ERROR: Could not determine public IPv$ip_version address"
    return 1
}

# Get default gateway
# Arguments:
#   $1 - IP version (4 or 6) (default: 4)
# Returns: Default gateway IP
get_default_gateway() {
    local ip_version="${1:-4}"
    local gateway=""

    if [[ "$ip_version" != "4" && "$ip_version" != "6" ]]; then
        log_error "Invalid IP version: $ip_version. Use '4' or '6'."
        echo "Unknown"
        return 1
    fi

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if [[ "$ip_version" == "4" ]]; then
            gateway=$(route -n get default 2>/dev/null | awk '/gateway/ {print $2}')
        else
            # IPv6 gateway on macOS
            gateway=$(route -n get -inet6 default 2>/dev/null | awk '/gateway/ {print $2}')
        fi
    else
        # Linux
        if command_exists ip; then
            if [[ "$ip_version" == "4" ]]; then
                gateway=$(ip -4 route | awk '/default/ {print $3}' | head -n1)
            else
                gateway=$(ip -6 route | awk '/default/ {print $3}' | head -n1)
            fi
        elif command_exists route; then
            if [[ "$ip_version" == "4" ]]; then
                gateway=$(route -n | awk '$1=="0.0.0.0" {print $2}' | head -n1)
            else
                # Limited support for IPv6 with route command
                gateway=$(route -A inet6 | awk '$1=="::/0" {print $2}' | head -n1)
            fi
        fi
    fi

    if [[ -n "$gateway" ]]; then
        echo "$gateway"
        return 0
    else
        echo "Unknown"
        return 1
    fi
}

# Check network connectivity status
# Arguments:
#   $1 - Comprehensive check (true/false) (default: false)
# Returns:
#   0 if network appears connected, 1 if disconnected
#   Sets global variable NETWORK_STATUS and NETWORK_DETAILS
check_network_status() {
    local comprehensive="${1:-false}"

    # Reset global variables
    NETWORK_STATUS=""
    NETWORK_DETAILS=""

    # Basic connectivity checks first
    local gateway_result=1
    local dns_result=1
    local public_result=1

    # Try to ping default gateway first
    local gateway
    gateway=$(get_default_gateway)
    if [[ "$gateway" != "Unknown" ]]; then
        ping_host "$gateway" 1 2
        gateway_result=$?
    fi

    # Try DNS resolution
    check_dns_functioning
    dns_result=$?

    # Try a known public IP if comprehensive
    if [[ "$comprehensive" == "true" ]]; then
        ping_host "8.8.8.8" 1 2
        public_result=$?

        # Create detailed report
        NETWORK_DETAILS="{"
        NETWORK_DETAILS+="\"gateway\":{\"ip\":\"$gateway\",\"reachable\":$([[ $gateway_result -eq 0 ]] && echo true || echo false)},"
        NETWORK_DETAILS+="\"dns\":{\"functioning\":$([[ $dns_result -eq 0 ]] && echo true || echo false)"

        if [[ $dns_result -eq 0 ]]; then
            local dns_servers
            dns_servers=$(get_dns_servers)
            NETWORK_DETAILS+=",\"servers\":[\"${dns_servers//$'\n'/\",\"}\"]"
        fi

        NETWORK_DETAILS+="},"
        NETWORK_DETAILS+="\"public_internet\":{\"reachable\":$([[ $public_result -eq 0 ]] && echo true || echo false)}"
        NETWORK_DETAILS+="}"
    fi

    # Determine overall status based on results
    if [[ $gateway_result -eq 0 ]]; then
        NETWORK_STATUS="CONNECTED"
        log_debug "Network is connected (gateway reachable)"
        return 0
    elif [[ $dns_result -eq 0 ]]; then
        NETWORK_STATUS="CONNECTED_DNS_ONLY"
        log_debug "Network is connected (DNS functioning)"
        return 0
    elif [[ $public_result -eq 0 ]]; then
        NETWORK_STATUS="CONNECTED_PUBLIC"
        log_debug "Network is connected (public internet reachable)"
        return 0
    else
        NETWORK_STATUS="DISCONNECTED"
        log_warning "Network appears to be disconnected"
        return 1
    fi
}

# Get network interface information
# Arguments:
#   $1 - Interface name (optional - returns all interfaces if not specified)
#   $2 - Format (text|json) (default: json)
# Returns: Interface information in specified format
get_interface_info() {
    local interface="$1"
    local format="${2:-json}"
    local info=""

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if [[ -n "$interface" ]]; then
            info=$(ifconfig "$interface" 2>/dev/null)
            if [[ $? -ne 0 ]]; then
                if [[ "$format" == "json" ]]; then
                    echo "{\"error\":\"Interface not found\"}"
                else
                    echo "Error: Interface $interface not found"
                fi
                return 1
            fi
        else
            info=$(ifconfig)
        fi
    else
        # Linux
        if command_exists ip; then
            if [[ -n "$interface" ]]; then
                info=$(ip addr show "$interface" 2>/dev/null)
                if [[ $? -ne 0 ]]; then
                    if [[ "$format" == "json" ]]; then
                        echo "{\"error\":\"Interface not found\"}"
                    else
                        echo "Error: Interface $interface not found"
                    fi
                    return 1
                fi
            else
                info=$(ip addr show)
            fi
        elif command_exists ifconfig; then
            if [[ -n "$interface" ]]; then
                info=$(ifconfig "$interface" 2>/dev/null)
                if [[ $? -ne 0 ]]; then
                    if [[ "$format" == "json" ]]; then
                        echo "{\"error\":\"Interface not found\"}"
                    else
                        echo "Error: Interface $interface not found"
                    fi
                    return 1
                fi
            else
                info=$(ifconfig)
            fi
        else
            if [[ "$format" == "json" ]]; then
                echo "{\"error\":\"No network tools available\"}"
            else
                echo "Error: No network tools available (ip or ifconfig required)"
            fi
            return 1
        fi
    fi

    # Return raw info if text format requested
    if [[ "$format" == "text" ]]; then
        echo "$info"
        return 0
    fi

    # Process the output to extract useful information for JSON format
    local result="{"

    # Extract interface names
    local interfaces=()
    if [[ "$(uname)" == "Darwin" ]]; then
        mapfile -t interfaces < <(echo "$info" | grep -E '^[a-z0-9]+:' | cut -d: -f1)
    else
        if command_exists ip; then
            mapfile -t interfaces < <(echo "$info" | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ')
        else
            mapfile -t interfaces < <(echo "$info" | grep -E '^[a-z0-9]+:' | cut -d: -f1)
        fi
    fi

    # Add timestamp to JSON
    result+="\"timestamp\":\"$(date "+%Y-%m-%d %H:%M:%S")\","
    result+="\"interfaces\":["

    local first=true
    for iface in "${interfaces[@]}"; do
        if [[ -z "$iface" ]]; then
            continue
        fi

        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=","
        fi

        local ip_addr=""
        local ipv6_addr=""
        local mac_addr=""
        local status="unknown"
        local mtu=""
        local tx_bytes=0
        local rx_bytes=0

        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS extraction
            # IPv4 address
            ip_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'inet ' | awk '{print $2}')

            # IPv6 address
            ipv6_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'inet6 ' | head -n 1 | awk '{print $2}')

            # MAC address
            mac_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'ether ' | awk '{print $2}')

            # Status
            if echo "$info" | grep -A 3 "^$iface:" | grep -q 'status: active'; then
                status="up"
            else
                status="down"
            fi

            # MTU
            mtu=$(echo "$info" | grep -A 3 "^$iface:" | grep 'mtu' | sed -E 's/.*mtu ([0-9]+).*/\1/')

            # Traffic stats - harder to get consistently on macOS
            if ifconfig "$iface" | grep -q "RX packets"; then
                rx_bytes=$(ifconfig "$iface" | grep "RX bytes" | sed -E 's/.*bytes ([0-9]+).*/\1/')
                tx_bytes=$(ifconfig "$iface" | grep "TX bytes" | sed -E 's/.*bytes ([0-9]+).*/\1/')
            fi
        else
            # Linux extraction
            if command_exists ip; then
                # IPv4 address
                ip_addr=$(echo "$info" | grep -A 3 "inet " | grep -v "inet6" | head -n 1 | awk '{print $2}' | cut -d/ -f1)

                # IPv6 address
                ipv6_addr=$(echo "$info" | grep -A 3 "inet6" | head -n 1 | awk '{print $2}' | cut -d/ -f1)

                # MAC address
                mac_addr=$(echo "$info" | grep -A 3 "link/ether" | head -n 1 | awk '{print $2}')

                # Status
                if echo "$info" | grep -q "state UP"; then
                    status="up"
                else
                    status="down"
                fi

                # MTU
                mtu=$(echo "$info" | grep "mtu" | head -n 1 | sed -E 's/.*mtu ([0-9]+).*/\1/')

                # Traffic stats
                if [[ -f "/sys/class/net/$iface/statistics/rx_bytes" ]]; then
                    rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
                    tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
                fi
            else
                # Using ifconfig on Linux
                ip_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'inet ' | awk '{print $2}' | cut -d: -f2)
                ipv6_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'inet6 ' | head -n 1 | awk '{print $3}')
                mac_addr=$(echo "$info" | grep -A 3 "^$iface:" | grep 'ether ' | awk '{print $2}')

                if echo "$info" | grep -A 3 "^$iface:" | grep -q 'UP'; then
                    status="up"
                else
                    status="down"
                fi

                mtu=$(echo "$info" | grep -A 3 "^$iface:" | grep 'MTU' | sed -E 's/.*MTU:([0-9]+).*/\1/')

                # Traffic stats from ifconfig
                rx_bytes=$(echo "$info" | grep "RX bytes" | sed -E 's/.*bytes:([0-9]+).*/\1/')
                tx_bytes=$(echo "$info" | grep "TX bytes" | sed -E 's/.*bytes:([0-9]+).*/\1/')
            fi
        fi

        # Construct interface JSON object with improved error handling
        result+="{\"name\":\"$iface\","
        result+="\"ipv4\":\"${ip_addr:-none}\","
        result+="\"ipv6\":\"${ipv6_addr:-none}\","
        result+="\"mac\":\"${mac_addr:-none}\","
        result+="\"status\":\"$status\","
        result+="\"mtu\":\"${mtu:-unknown}\","
        result+="\"rx_bytes\":${rx_bytes:-0},"
        result+="\"tx_bytes\":${tx_bytes:-0}"
        result+="}"
    done
    result+="]}"

    echo "$result"
    return 0
}

# Get network usage statistics
# Arguments:
#   $1 - Interface name (optional - returns all interfaces if not specified)
#   $2 - Sample interval in seconds (default: 1)
#   $3 - Format (text|json) (default: json)
# Returns: Network usage statistics in specified format
get_network_usage() {
    local interface="$1"
    local interval="${2:-1}"
    local format="${3:-json}"

    # Validate interval
    if ! [[ "$interval" =~ ^[0-9]+(\.[0-9]+)?$ && $(echo "$interval > 0" | bc -l) -eq 1 ]]; then
        if [[ "$format" == "json" ]]; then
            echo "{\"error\":\"Invalid interval: $interval (must be > 0)\"}"
        else
            echo "Error: Invalid interval: $interval (must be > 0)"
        fi
        return 1
    fi

    # Collect first sample
    local first_sample
    local second_sample

    if [[ -n "$interface" ]]; then
        first_sample=$(get_interface_info "$interface" "json")
        if [[ $? -ne 0 ]]; then
            # Pass through error
            echo "$first_sample"
            return 1
        fi
    else
        first_sample=$(get_interface_info "" "json")
    fi

    # Wait for interval
    sleep "$interval"

    # Collect second sample
    if [[ -n "$interface" ]]; then
        second_sample=$(get_interface_info "$interface" "json")
    else
        second_sample=$(get_interface_info "" "json")
    fi

    # Extract interface data
    local interfaces_1
    local interfaces_2
    interfaces_1=$(echo "$first_sample" | jq -r '.interfaces')
    interfaces_2=$(echo "$second_sample" | jq -r '.interfaces')

    # Check if jq command succeeded
    if [[ $? -ne 0 || -z "$interfaces_1" || -z "$interfaces_2" ]]; then
        if [[ "$format" == "json" ]]; then
            echo "{\"error\":\"Failed to parse interface data. Make sure 'jq' is installed.\"}"
        else
            echo "Error: Failed to parse interface data. Make sure 'jq' is installed."
        fi
        return 1
    fi

    # Calculate bandwidth
    local result
    if [[ "$format" == "json" ]]; then
        result="{\"timestamp\":\"$(date "+%Y-%m-%d %H:%M:%S")\",\"interval\":$interval,\"interfaces\":["

        local first=true
        local iface
        local index=0

        # Iterate through interfaces in second sample
        while read -r iface; do
            # Skip if empty
            if [[ -z "$iface" ]]; then
                continue
            fi

            local name rx_bytes_1 tx_bytes_1 rx_bytes_2 tx_bytes_2

            name=$(echo "$interfaces_2" | jq -r ".[$index].name")
            rx_bytes_2=$(echo "$interfaces_2" | jq -r ".[$index].rx_bytes")
            tx_bytes_2=$(echo "$interfaces_2" | jq -r ".[$index].tx_bytes")

            # Find matching interface in first sample
            rx_bytes_1=0
            tx_bytes_1=0
            for i in $(seq 0 $(echo "$interfaces_1" | jq -r '. | length - 1')); do
                if [[ "$(echo "$interfaces_1" | jq -r ".[$i].name")" == "$name" ]]; then
                    rx_bytes_1=$(echo "$interfaces_1" | jq -r ".[$i].rx_bytes")
                    tx_bytes_1=$(echo "$interfaces_1" | jq -r ".[$i].tx_bytes")
                    break
                fi
            done

            # Calculate bytes per second
            local rx_bps tx_bps
            rx_bps=$(echo "scale=2; ($rx_bytes_2 - $rx_bytes_1) / $interval" | bc)
            tx_bps=$(echo "scale=2; ($tx_bytes_2 - $tx_bytes_1) / $interval" | bc)

            # Add to result
            if [[ "$first" == "true" ]]; then
                first=false
            else
                result+=","
            fi

            result+="{\"name\":\"$name\",\"rx_bytes_per_sec\":$rx_bps,\"tx_bytes_per_sec\":$tx_bps}"
            index=$((index + 1))
        done < <(echo "$interfaces_2" | jq -r '.[].name')

        result+="]}"
        echo "$result"
    else
        # Text format
        echo "Network Usage Statistics (interval: ${interval}s)"
        echo "================================================"

        local iface
        local index=0

        # Iterate through interfaces in second sample
        while read -r iface; do
            # Skip if empty
            if [[ -z "$iface" ]]; then
                continue
            fi

            local name rx_bytes_1 tx_bytes_1 rx_bytes_2 tx_bytes_2

            name=$(echo "$interfaces_2" | jq -r ".[$index].name")
            rx_bytes_2=$(echo "$interfaces_2" | jq -r ".[$index].rx_bytes")
            tx_bytes_2=$(echo "$interfaces_2" | jq -r ".[$index].tx_bytes")

            # Find matching interface in first sample
            rx_bytes_1=0
            tx_bytes_1=0
            for i in $(seq 0 $(echo "$interfaces_1" | jq -r '. | length - 1')); do
                if [[ "$(echo "$interfaces_1" | jq -r ".[$i].name")" == "$name" ]]; then
                    rx_bytes_1=$(echo "$interfaces_1" | jq -r ".[$i].rx_bytes")
                    tx_bytes_1=$(echo "$interfaces_1" | jq -r ".[$i].tx_bytes")
                    break
                fi
            done

            # Calculate bytes per second
            local rx_bps tx_bps rx_kbps tx_kbps rx_mbps tx_mbps
            rx_bps=$(echo "scale=2; ($rx_bytes_2 - $rx_bytes_1) / $interval" | bc)
            tx_bps=$(echo "scale=2; ($tx_bytes_2 - $tx_bytes_1) / $interval" | bc)

            # Convert to more readable formats
            rx_kbps=$(echo "scale=2; $rx_bps / 1024" | bc)
            tx_kbps=$(echo "scale=2; $tx_bps / 1024" | bc)
            rx_mbps=$(echo "scale=2; $rx_kbps / 1024" | bc)
            tx_mbps=$(echo "scale=2; $tx_kbps / 1024" | bc)

            echo "Interface: $name"
            echo "  RX (Download): $rx_bps B/s ($rx_kbps KB/s, $rx_mbps MB/s)"
            echo "  TX (Upload):   $tx_bps B/s ($tx_kbps KB/s, $tx_mbps MB/s)"
            echo "------------------------------------------------"

            index=$((index + 1))
        done < <(echo "$interfaces_2" | jq -r '.[].name')
    fi

    return 0
}

# Check if a port is open on a remote host
# Arguments:
#   $1 - Service name (user-friendly name for the check)
#   $2 - Host to check (required)
#   $3 - Port to check (required)
#   $4 - Timeout in seconds (default: 5)
# Returns:
#   0 if successful, 1 if failed
#   Sets global variable PORT_CHECK_RESULT with detailed result
check_remote_port() {
    local service_name="$1"
    local host="$2"
    local port="$3"
    local timeout="${4:-$DEFAULT_TIMEOUT}"

    # Reset global variable
    PORT_CHECK_RESULT=""

    # Validate inputs
    if [[ -z "$host" || -z "$port" ]]; then
        PORT_CHECK_RESULT="{\"status\":\"ERROR\",\"message\":\"Host and port are required\"}"
        return 1
    fi

    # Validate port number
    if ! [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
        PORT_CHECK_RESULT="{\"status\":\"ERROR\",\"message\":\"Invalid port number: $port (must be 1-65535)\"}"
        return 1
    fi

    # Check if circuit breaker is tripped
    local cb_name="${host}_${port}"
    cb_name=$(url_to_safe_name "$cb_name")

    if is_circuit_breaker_tripped "$cb_name"; then
        PORT_CHECK_RESULT="{\"status\":\"ERROR\",\"message\":\"Circuit breaker is tripped for $host:$port\",\"service\":\"$service_name\"}"
        return 1
    fi

    local start_time
    local end_time
    local response_time
    local exit_code=1

    start_time=$(date +%s.%N)

    if command_exists nc; then
        nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
        exit_code=$?
    elif command_exists timeout && command_exists telnet; then
        echo -e '\x1dclose\x0d' | timeout "$timeout" telnet "$host" "$port" >/dev/null 2>&1
        exit_code=$?
    else
        PORT_CHECK_RESULT="{\"status\":\"ERROR\",\"message\":\"Neither nc nor telnet available for port checking\",\"service\":\"$service_name\"}"
        return 1
    fi

    end_time=$(date +%s.%N)
    response_time=$(echo "($end_time - $start_time) * 1000" | bc | cut -d'.' -f1)

    if [[ $exit_code -eq 0 ]]; then
        PORT_CHECK_RESULT="{\"status\":\"OK\",\"message\":\"Port $port is open on $host\",\"response_time\":$response_time,\"service\":\"$service_name\"}"
        log_debug "Port check succeeded: $host:$port ($service_name) - ${response_time}ms"
        return 0
    else
        PORT_CHECK_RESULT="{\"status\":\"FAILED\",\"message\":\"Port $port is closed on $host\",\"service\":\"$service_name\"}"
        log_debug "Port check failed: $host:$port ($service_name)"

        # Trip circuit breaker after multiple failures
        local failures_file="/tmp/port_check_failures_${cb_name}"
        local failures=1

        if [[ -f "$failures_file" ]]; then
            failures=$(($(cat "$failures_file") + 1))
        fi

        echo "$failures" > "$failures_file"

        if [[ $failures -ge 3 ]]; then
            trip_circuit_breaker "$cb_name" 300  # 5 minutes
            rm -f "$failures_file"
        fi

        return 1
    fi
}

# Scan for open ports on a host
# Arguments:
#   $1 - Host to scan
#   $2 - Port range (start-end) or comma-separated list
#   $3 - Timeout in seconds (default: 2)
#   $4 - Max parallel scans (default: 5)
# Returns: JSON array of open ports
scan_ports() {
    local host="$1"
    local port_range="$2"
    local timeout="${3:-2}"
    local max_parallel="${4:-5}"

    # Validate inputs
    if [[ -z "$host" || -z "$port_range" ]]; then
        echo "{\"error\":\"Host and port range are required\"}"
        return 1
    fi

    # Parse port range
    local ports=()

    if [[ "$port_range" == *-* ]]; then
        # Range specified (e.g., 80-100)
        local start_port="${port_range%-*}"
        local end_port="${port_range#*-}"

        if ! [[ "$start_port" =~ ^[0-9]+$ && "$start_port" -gt 0 && "$start_port" -le 65535 ]]; then
            echo "{\"error\":\"Invalid start port: $start_port\"}"
            return 1
        fi

        if ! [[ "$end_port" =~ ^[0-9]+$ && "$end_port" -gt 0 && "$end_port" -le 65535 ]]; then
            echo "{\"error\":\"Invalid end port: $end_port\"}"
            return 1
        fi

        # Safety check to prevent scanning too many ports
        if (( end_port - start_port > 1000 )); then
            echo "{\"error\":\"Port range too large (>1000 ports). Please specify a smaller range.\"}"
            return 1
        fi

        for (( port = start_port; port <= end_port; port++ )); do
            ports+=($port)
        done
    else
        # Comma-separated list (e.g., 80,443,8080)
        IFS=',' read -ra port_list <<< "$port_range"

        for port in "${port_list[@]}"; do
            if ! [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]]; then
                echo "{\"error\":\"Invalid port: $port\"}"
                return 1
            fi
            ports+=($port)
        done
    fi

    # Check for appropriate tools
    if ! command_exists nc && ! (command_exists timeout && command_exists telnet); then
        echo "{\"error\":\"Neither nc nor telnet available for port scanning\"}"
        return 1
    fi

    # Create temporary directory for results
    local tmp_dir
    tmp_dir=$(mktemp -d) || {
        echo "{\"error\":\"Failed to create temporary directory\"}"
        return 1
    }

    # Track currently running processes
    local running=0
    local open_ports=()

    # Scan ports with parallelism
    for port in "${ports[@]}"; do
        # Wait if we've hit the max parallel scans
        while [[ $running -ge $max_parallel ]]; do
            sleep 0.1
            running=$(find "$tmp_dir" -type f -name "running_*" | wc -l)
        done

        # Start a background scan
        (
            # Mark this scan as running
            touch "$tmp_dir/running_$port"

            local is_open=0

            if command_exists nc; then
                nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
                is_open=$?
            else
                echo -e '\x1dclose\x0d' | timeout "$timeout" telnet "$host" "$port" >/dev/null 2>&1
                is_open=$?
            fi

            if [[ $is_open -eq 0 ]]; then
                echo "$port" > "$tmp_dir/open_$port"
            fi

            # Remove running marker
            rm -f "$tmp_dir/running_$port"
        ) &

        # Increment running counter
        ((running++))
    done

    # Wait for all scans to complete
    wait

    # Collect results
    for result_file in "$tmp_dir"/open_*; do
        if [[ -f "$result_file" ]]; then
            open_ports+=($(cat "$result_file"))
        fi
    done

    # Clean up
    rm -rf "$tmp_dir"

    # Sort the open ports
    IFS=$'\n' open_ports=($(sort -n <<<"${open_ports[*]}"))
    unset IFS

    # Return results as JSON
    local result="{\"host\":\"$host\",\"open_ports\":["

    local first=true
    for port in "${open_ports[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=","
        fi
        result+="$port"
    done

    result+="]}"
    echo "$result"

    return 0
}

# Self-test function
self_test() {
    log_info "Network Utilities Self-Test"
    log_info "-------------------------"
    log_info "Testing URL validation..."
    if is_valid_url "https://example.com"; then
        log_info "✅ URL validation passed"
    else
        log_error "❌ URL validation failed"
    fi

    log_info "Testing hostname validation..."
    if is_valid_hostname "example.com"; then
        log_info "✅ Hostname validation passed"
    else
        log_error "❌ Hostname validation failed"
    fi

    log_info "Testing IP validation..."
    if is_valid_ip "192.168.1.1" "4"; then
        log_info "✅ IPv4 validation passed"
    else
        log_error "❌ IPv4 validation failed"
    fi

    log_info "Testing DNS resolution..."
    if resolve_dns "google.com"; then
        log_info "✅ DNS resolution passed: $DNS_RESULT"
    else
        log_error "❌ DNS resolution failed"
    fi

    log_info "Testing URL connectivity..."
    if check_url "https://www.google.com"; then
        log_info "✅ URL connectivity check passed (${HTTP_RESPONSE_TIME}ms)"
    else
        log_error "❌ URL connectivity check failed (status: ${HTTP_STATUS_CODE:-unknown})"
    fi

    log_info "Testing network status..."
    if check_network_status; then
        log_info "✅ Network status check passed: $NETWORK_STATUS"
    else
        log_warning "⚠️ Network status check indicates: $NETWORK_STATUS"
    fi

    log_info "Testing gateway detection..."
    local gateway
    gateway=$(get_default_gateway)
    log_info "Default gateway: $gateway"

    log_info "Testing public IP detection..."
    local public_ip
    public_ip=$(get_public_ip)
    log_info "Public IP: $public_ip"

    log_info "Testing interface information..."
    if command_exists jq; then
        local interface_info
        interface_info=$(get_interface_info)
        log_info "✅ Interface information retrieved ($(echo "$interface_info" | jq -r '.interfaces | length') interfaces)"
    else
        log_info "Interface information: $(get_interface_info)"
        log_warning "⚠️ Install jq for better formatted output"
    fi

    log_info "Testing port checking..."
    if check_remote_port "Web" "google.com" 443; then
        log_info "✅ Port check passed: $PORT_CHECK_RESULT"
    else
        log_error "❌ Port check failed: $PORT_CHECK_RESULT"
    fi

    log_info "Network Utilities Self-Test Complete"
}

# Export functions
export -f check_url
export -f check_health_endpoint
export -f check_tcp_port
export -f check_ping
export -f ping_host
export -f run_traceroute
export -f resolve_dns
export -f get_dns_servers
export -f check_dns_functioning
export -f url_to_safe_name
export -f trip_circuit_breaker
export -f is_circuit_breaker_tripped
export -f reset_circuit_breaker
export -f list_circuit_breakers
export -f record_latency
export -f analyze_latency_trend
export -f get_latency_stats
export -f is_valid_url
export -f is_valid_hostname
export -f is_valid_ip
export -f get_public_ip
export -f get_default_gateway
export -f check_network_status
export -f get_interface_info
export -f get_network_usage
export -f check_remote_port
export -f scan_ports
export -f self_test

# Run self-test if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    self_test
fi
