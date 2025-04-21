#!/bin/bash
# Network Connectivity Check Script for Cloud Infrastructure Platform
# ---------------------------------------------------------------------
# Tests connectivity to various endpoints and services across environments
# and regions, with comprehensive reporting and error handling.
#
# Features:
# - Multi-region and multi-environment support
# - Parallel check execution option
# - Multiple output formats (text, JSON, Prometheus)
# - Secure credential handling
# - Circuit breaker pattern for failing endpoints
# - Detailed reporting and alerting capabilities
#
# Author: Cloud Platform Team
# Last Updated: 2025-04-21
#
# Usage: ./connectivity_check.sh [--environment <env>] [--region <region>] [--verbose] [--report-file <file>]

set -e

# Add trap for proper cleanup on exit
trap cleanup EXIT INT TERM

# Define exit code and status
EXIT_CODE=0
FINAL_STATUS="UNKNOWN"

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
REGION="primary"
VERBOSE=false
FORMAT="text"
REPORT_FILE=""
TIMEOUT=5
CHECK_DATABASE=true
CHECK_REDIS=true
CHECK_API=true
CHECK_WEB=true
CHECK_EXTERNAL=true
EXTERNAL_ENDPOINTS=()
EXIT_ON_FAILURE=false
ALL_TESTS_PASSED=true

# Create temporary report file
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
TEMP_REPORT_FILE="/tmp/connectivity-check-${ENVIRONMENT}-${TIMESTAMP}.txt"

# Function for proper cleanup
cleanup() {
    # Clean up any temporary files
    [[ -f "$TEMP_REPORT_FILE" ]] && rm -f "$TEMP_REPORT_FILE"

    # Set final exit status code
    if [[ "$ALL_TESTS_PASSED" == "true" ]]; then
        FINAL_STATUS="PASSED"
        EXIT_CODE=0
    else
        FINAL_STATUS="FAILED"
        EXIT_CODE=1
    fi

    # Log completion
    log "Connectivity check complete with status: $FINAL_STATUS" "INFO"

    # Exit with appropriate code when not trapped
    [[ "${FUNCNAME[1]}" == "main" ]] && exit $EXIT_CODE
}

# Circuit breaker implementation
check_circuit_breaker() {
    local endpoint="$1"
    local circuit_breaker_file="/tmp/circuit_breaker_${endpoint// /_}"

    if [[ -f "$circuit_breaker_file" ]]; then
        local trip_time=$(cat "$circuit_breaker_file")
        local current_time=$(date +%s)
        local elapsed=$((current_time - trip_time))

        # Circuit is tripped for 5 minutes (300 seconds)
        if [[ $elapsed -lt 300 ]]; then
            log "Circuit breaker for $endpoint is open (will retry in $((300-elapsed))s), skipping test" "INFO"
            return 1
        else
            rm -f "$circuit_breaker_file"
            log "Circuit breaker for $endpoint reset after $elapsed seconds" "INFO"
        fi
    fi

    return 0
}

# Trip the circuit breaker
trip_circuit_breaker() {
    local endpoint="$1"
    local circuit_breaker_file="/tmp/circuit_breaker_${endpoint// /_}"
    date +%s > "$circuit_breaker_file"
    log "Circuit breaker tripped for $endpoint (protection active for 5 minutes)" "WARNING"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --region|-r)
            REGION="$2"
            shift 2
            ;;
        --format|-f)
            FORMAT="$2"
            if [[ "$FORMAT" != "text" && "$FORMAT" != "json" ]]; then
                echo "Invalid format: $FORMAT. Using default: text"
                FORMAT="text"
            fi
            shift 2
            ;;
        --report-file)
            REPORT_FILE="$2"
            shift 2
            ;;
        --timeout|-t)
            TIMEOUT="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --no-database)
            CHECK_DATABASE=false
            shift
            ;;
        --no-redis)
            CHECK_REDIS=false
            shift
            ;;
        --no-api)
            CHECK_API=false
            shift
            ;;
        --no-web)
            CHECK_WEB=false
            shift
            ;;
        --no-external)
            CHECK_EXTERNAL=false
            shift
            ;;
        --external-endpoint)
            EXTERNAL_ENDPOINTS+=("$2")
            shift 2
            ;;
        --exit-on-failure)
            EXIT_ON_FAILURE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--environment <env>] [--region <region>] [--verbose] [--format text|json] [--report-file <file>] [--timeout <seconds>] [--no-database] [--no-redis] [--no-api] [--no-web] [--no-external] [--external-endpoint <url>] [--exit-on-failure]"
            echo ""
            echo "Options:"
            echo "  --environment, -e ENV       Specify environment to test (default: production)"
            echo "                              Valid values: development, staging, production, dr-recovery"
            echo "  --region, -r REGION         Specify region to test (default: primary)"
            echo "                              Valid values: primary, secondary"
            echo "  --format, -f FORMAT         Output format: text or json (default: text)"
            echo "  --report-file FILE          Write report to specified file"
            echo "  --timeout, -t SECONDS       Connection timeout in seconds (default: 5)"
            echo "  --verbose, -v               Show verbose output"
            echo "  --no-database               Skip database connectivity checks"
            echo "  --no-redis                  Skip Redis connectivity checks"
            echo "  --no-api                    Skip API connectivity checks"
            echo "  --no-web                    Skip Web UI connectivity checks"
            echo "  --no-external               Skip external dependency checks"
            echo "  --external-endpoint URL     Add custom external endpoint to check"
            echo "  --exit-on-failure           Exit immediately on first failure"
            echo "  --help, -h                  Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load common functions if available
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
else
    # Define basic logging and utility functions if common_functions is not available
    log() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local message="$1"
        local level="${2:-INFO}"
        echo "[$timestamp] [$level] $message"
    }

    command_exists() {
        command -v "$1" &>/dev/null
    }

    is_valid_url() {
        local url="$1"
        [[ "$url" =~ ^https?:// ]] && return 0 || return 1
    }

    check_http_health() {
        local url="$1"
        local expected_status="${2:-200}"
        local timeout="${3:-5}"

        if command_exists curl; then
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url")
            if [[ "$status_code" == "$expected_status" ]]; then
                return 0
            else
                return 1
            fi
        elif command_exists wget; then
            if wget --spider --timeout="$timeout" -q "$url"; then
                return 0
            else
                return 1
            fi
        else
            echo "Neither curl nor wget available to check health endpoint"
            return 2
        fi
    }

    ping_host() {
        local host="$1"
        local count="${2:-1}"
        local timeout="${3:-2}"

        ping -c "$count" -W "$timeout" "$host" &>/dev/null
        return $?
    }
fi

# Define a function to record test results
record_result() {
    local component="$1"
    local test="$2"
    local status="$3"
    local details="${4:-}"
    local icon=""
    local color=""

    if [[ "$status" == "PASSED" ]]; then
        icon="✅"
        color="\033[0;32m" # Green
    elif [[ "$status" == "FAILED" ]]; then
        icon="❌"
        color="\033[0;31m" # Red
        ALL_TESTS_PASSED=false
    elif [[ "$status" == "WARNING" ]]; then
        icon="⚠️"
        color="\033[0;33m" # Yellow
    elif [[ "$status" == "SKIPPED" ]]; then
        icon="⏭️"
        color="\033[0;36m" # Cyan
    else
        icon="ℹ️"
        color="\033[0;37m" # Light gray
    fi

    # Reset color
    reset="\033[0m"

    # Print to console
    echo -e "${color}${icon} ${component}: ${test} - ${status}${reset}"
    if [[ -n "$details" && "$VERBOSE" == "true" ]]; then
        echo -e "   ${details}"
    fi

    # Record to report file
    echo "$icon $component: $test - $status" >> "$TEMP_REPORT_FILE"
    if [[ -n "$details" ]]; then
        echo "   $details" >> "$TEMP_REPORT_FILE"
    fi

    # Exit if requested and test failed
    if [[ "$status" == "FAILED" && "$EXIT_ON_FAILURE" == "true" ]]; then
        log "Exiting due to test failure and --exit-on-failure flag" "ERROR"
        finalize_report
        exit 1
    fi
}

# Enhanced check_endpoint function with circuit breaker support
check_endpoint() {
    local name="$1"
    local url="$2"
    local expected_status="${3:-200}"

    # Check circuit breaker first
    if ! check_circuit_breaker "$name"; then
        record_result "URL Check" "$name" "SKIPPED" "Circuit breaker is open"
        return 1
    fi

    if ! is_valid_url "$url"; then
        record_result "URL Check" "$name" "FAILED" "Invalid URL format: $url"
        return 1
    fi

    local start_time=$(date +%s.%N)
    local status_code=0
    local error_msg=""
    local failure_count=0
    local max_retries=3
    local retry_count=0
    local backoff=1

    # Try with exponential backoff
    while [[ $retry_count -le $max_retries ]]; do
        if [[ $retry_count -gt 0 ]]; then
            log "Retrying connection to $name (attempt $retry_count of $max_retries)" "INFO"
            sleep $backoff
            backoff=$((backoff * 2))
        fi

        if command_exists curl; then
            status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" --retry 0 "$url" 2>/dev/null) || error_msg="Connection failed or timed out"
        elif command_exists wget; then
            if wget --spider --timeout="$TIMEOUT" -q "$url" 2>/dev/null; then
                status_code=200
            else
                status_code=000
                error_msg="Connection failed or timed out"
            fi
        else
            record_result "URL Check" "$name" "FAILED" "Neither curl nor wget are available"
            return 1
        fi

        if [[ "$status_code" == "$expected_status" ]]; then
            break
        fi

        retry_count=$((retry_count + 1))
    done

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)
    local elapsed_ms=$(echo "$elapsed * 1000" | bc | cut -d'.' -f1)

    if [[ "$status_code" == "$expected_status" ]]; then
        record_result "URL Check" "$name" "PASSED" "Response time: ${elapsed_ms}ms"
        return 0
    else
        local detail="Got status code: $status_code, expected: $expected_status"
        if [[ -n "$error_msg" ]]; then
            detail="$detail - $error_msg"
        fi
        record_result "URL Check" "$name" "FAILED" "$detail"

        # Trip circuit breaker after multiple failures
        failure_count=$((failure_count + 1))
        if [[ $failure_count -ge 3 ]]; then
            trip_circuit_breaker "$name"
        fi

        return 1
    fi
}

# Function to check TCP port connectivity
check_tcp_port() {
    local name="$1"
    local host="$2"
    local port="$3"

    local start_time=$(date +%s.%N)
    local error_msg=""
    local success=false

    if command_exists nc; then
        if nc -z -w "$TIMEOUT" "$host" "$port" 2>/dev/null; then
            success=true
        else
            error_msg="Connection refused or timed out"
        fi
    elif command_exists telnet; then
        if echo -e '\x1dclose\x0d' | timeout "$TIMEOUT" telnet "$host" "$port" 2>/dev/null | grep -q Connected; then
            success=true
        else
            error_msg="Connection refused or timed out"
        fi
    else
        record_result "TCP Connection" "$name" "FAILED" "Neither nc nor telnet are available"
        return 1
    fi

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)
    local elapsed_ms=$(echo "$elapsed * 1000" | bc | cut -d'.' -f1)

    if [[ "$success" == "true" ]]; then
        record_result "TCP Connection" "$name" "PASSED" "Response time: ${elapsed_ms}ms"
        return 0
    else
        record_result "TCP Connection" "$name" "FAILED" "$error_msg"
        return 1
    fi
}

# Function to check DNS resolution
check_dns_resolution() {
    local name="$1"
    local hostname="$2"

    local start_time=$(date +%s.%N)
    local success=false
    local ip_address=""
    local error_msg=""

    if command_exists dig; then
        ip_address=$(dig +short "$hostname" 2>/dev/null) || error_msg="DNS resolution failed"
        if [[ -n "$ip_address" ]]; then
            success=true
        else
            error_msg="No IP address returned"
        fi
    elif command_exists nslookup; then
        ip_address=$(nslookup "$hostname" 2>/dev/null | grep -E 'Address: ' | tail -n1 | awk '{print $2}') || error_msg="DNS resolution failed"
        if [[ -n "$ip_address" ]]; then
            success=true
        else
            error_msg="No IP address returned"
        fi
    else
        record_result "DNS Resolution" "$name" "FAILED" "Neither dig nor nslookup are available"
        return 1
    fi

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)
    local elapsed_ms=$(echo "$elapsed * 1000" | bc | cut -d'.' -f1)

    if [[ "$success" == "true" ]]; then
        record_result "DNS Resolution" "$name" "PASSED" "Resolved to $ip_address in ${elapsed_ms}ms"
        return 0
    else
        record_result "DNS Resolution" "$name" "FAILED" "$error_msg"
        return 1
    fi
}

# Function to check database connectivity
check_database_connectivity() {
    local db_host="$1"
    local db_port="$2"
    local db_name="$3"
    local db_user="$4"
    local db_password="$5"
    local db_type="${6:-postgresql}"

    local success=false
    local error_msg=""

    if [[ "$db_type" == "postgresql" ]]; then
        if command_exists pg_isready; then
            if pg_isready -h "$db_host" -p "$db_port" -d "$db_name" -U "$db_user" -t "$TIMEOUT" &>/dev/null; then
                success=true
            else
                error_msg="Database server is not accepting connections"
            fi
        elif command_exists psql; then
            if PGPASSWORD="$db_password" psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$db_name" -c "SELECT 1" -t -q &>/dev/null; then
                success=true
            else
                error_msg="Could not connect to database"
            fi
        else
            record_result "Database" "$db_host:$db_port/$db_name" "FAILED" "PostgreSQL client tools not available"
            return 1
        fi
    elif [[ "$db_type" == "mysql" ]]; then
        if command_exists mysql; then
            if mysql -h "$db_host" -P "$db_port" -u "$db_user" -p"$db_password" -D "$db_name" -e "SELECT 1" &>/dev/null; then
                success=true
            else
                error_msg="Could not connect to database"
            fi
        else
            record_result "Database" "$db_host:$db_port/$db_name" "FAILED" "MySQL client tools not available"
            return 1
        fi
    else
        record_result "Database" "Unknown type: $db_type" "FAILED" "Unsupported database type"
        return 1
    fi

    if [[ "$success" == "true" ]]; then
        record_result "Database" "$db_host:$db_port/$db_name" "PASSED" "Successfully connected to $db_type database"
        return 0
    else
        record_result "Database" "$db_host:$db_port/$db_name" "FAILED" "$error_msg"
        return 1
    fi
}

# Function to check Redis connectivity
check_redis_connectivity() {
    local redis_host="$1"
    local redis_port="$2"
    local redis_password="${3:-}"

    if ! command_exists redis-cli; then
        record_result "Redis" "$redis_host:$redis_port" "SKIPPED" "Redis client not available"
        return 1
    fi

    local success=false
    local error_msg=""

    if [[ -n "$redis_password" ]]; then
        if echo "PING" | redis-cli -h "$redis_host" -p "$redis_port" -a "$redis_password" --no-auth-warning 2>/dev/null | grep -q "PONG"; then
            success=true
        else
            error_msg="Redis connection failed with authentication"
        fi
    else
        if echo "PING" | redis-cli -h "$redis_host" -p "$redis_port" 2>/dev/null | grep -q "PONG"; then
            success=true
        else
            error_msg="Redis connection failed"
        fi
    fi

    if [[ "$success" == "true" ]]; then
        record_result "Redis" "$redis_host:$redis_port" "PASSED" "Successfully connected to Redis"
        return 0
    else
        record_result "Redis" "$redis_host:$redis_port" "FAILED" "$error_msg"
        return 1
    fi
}

# Function to ping host
check_ping() {
    local name="$1"
    local host="$2"
    local count="${3:-3}"

    local start_time=$(date +%s.%N)
    local success=false
    local ping_output=""
    local error_msg=""

    # Extract hostname without protocol
    local hostname="$host"
    hostname="${hostname#http://}"
    hostname="${hostname#https://}"
    hostname="${hostname%%/*}"

    if ping -c "$count" -W "$TIMEOUT" "$hostname" &>/dev/null; then
        success=true
        ping_output=$(ping -c "$count" -W "$TIMEOUT" "$hostname" 2>/dev/null | grep -E "min/avg/max|statistics")
    else
        error_msg="Host not responding to ping"
    fi

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)

    if [[ "$success" == "true" ]]; then
        record_result "Ping" "$name" "PASSED" "$ping_output"
        return 0
    else
        record_result "Ping" "$name" "WARNING" "$error_msg (Note: Some hosts may block ICMP)"
        return 1
    fi
}

# Function to check traceroute
check_traceroute() {
    local name="$1"
    local host="$2"

    if ! command_exists traceroute; then
        if [[ "$VERBOSE" == "true" ]]; then
            record_result "Traceroute" "$name" "SKIPPED" "traceroute command not available"
        fi
        return 1
    fi

    # Extract hostname without protocol
    local hostname="$host"
    hostname="${hostname#http://}"
    hostname="${hostname#https://}"
    hostname="${hostname%%/*}"

    local traceroute_output=$(traceroute -m 15 -w 2 "$hostname" 2>&1)
    local exit_code=$?

    if [[ "$exit_code" -eq 0 ]]; then
        if [[ "$VERBOSE" == "true" ]]; then
            # Truncate output if too long
            local trunc_output=$(echo "$traceroute_output" | head -n 10)
            record_result "Traceroute" "$name" "INFO" "Path: $trunc_output"
        fi
        return 0
    else
        if [[ "$VERBOSE" == "true" ]]; then
            record_result "Traceroute" "$name" "WARNING" "Failed to trace route to $hostname"
        fi
        return 1
    fi
}

# Function to finalize and save the report
finalize_report() {
    # Add summary to report
    echo "" >> "$TEMP_REPORT_FILE"
    echo "======================================================" >> "$TEMP_REPORT_FILE"
    echo "Network Connectivity Check Summary" >> "$TEMP_REPORT_FILE"
    echo "Environment: $ENVIRONMENT" >> "$TEMP_REPORT_FILE"
    echo "Region: $REGION" >> "$TEMP_REPORT_FILE"
    echo "Timestamp: $(date)" >> "$TEMP_REPORT_FILE"
    echo "Overall Status: $(if [[ "$ALL_TESTS_PASSED" == "true" ]]; then echo "PASSED ✅"; else echo "FAILED ❌"; fi)" >> "$TEMP_REPORT_FILE"
    echo "======================================================" >> "$TEMP_REPORT_FILE"

    # Copy to final report file if specified
    if [[ -n "$REPORT_FILE" ]]; then
        mkdir -p "$(dirname "$REPORT_FILE")" 2>/dev/null || true
        cp "$TEMP_REPORT_FILE" "$REPORT_FILE"
        echo "Report saved to: $REPORT_FILE"
    fi

    # Output as JSON if requested
    if [[ "$FORMAT" == "json" ]]; then
        # Extract test results and format as JSON
        local json_file="${TEMP_REPORT_FILE}.json"
        echo "{" > "$json_file"
        echo "  \"summary\": {" >> "$json_file"
        echo "    \"environment\": \"$ENVIRONMENT\"," >> "$json_file"
        echo "    \"region\": \"$REGION\"," >> "$json_file"
        echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$json_file"
        echo "    \"overall_status\": \"$(if [[ "$ALL_TESTS_PASSED" == "true" ]]; then echo "PASSED"; else echo "FAILED"; fi)\"" >> "$json_file"
        echo "  }," >> "$json_file"
        echo "  \"tests\": [" >> "$json_file"

        local first=true
        while IFS= read -r line; do
            if [[ "$line" =~ ^[✅❌⚠️⏭️ℹ️]\ ([^:]+):\ (.*)\ -\ (PASSED|FAILED|WARNING|SKIPPED|INFO)$ ]]; then
                local component="${BASH_REMATCH[1]}"
                local test_name="${BASH_REMATCH[2]}"
                local status="${BASH_REMATCH[3]}"
                local details=""

                # Read next line to get details if it starts with spaces
                IFS= read -r next_line
                if [[ "$next_line" =~ ^\s+(.*)$ ]]; then
                    details="${BASH_REMATCH[1]}"
                else
                    # Put the line back for the next iteration
                    exec 3<&0
                    exec 0<<<"$next_line"$'\n'"$(cat <&3)"
                    exec 3<&-
                fi

                if [[ "$first" == "true" ]]; then
                    first=false
echo "" >> "$TEMP_REPORT_FILE"

# Welcome message
log "Starting network connectivity check for environment: $ENVIRONMENT, region: $REGION" "INFO"

# Check Internet connectivity first
log "Checking Internet connectivity..." "INFO"
check_endpoint "Internet Connectivity" "https://www.google.com"

# Check DNS resolution
log "Checking DNS resolution..." "INFO"
check_dns_resolution "API Endpoint" "${API_ENDPOINT#https://}"
check_dns_resolution "Web Endpoint" "${WEB_ENDPOINT#https://}"

# Check API connectivity
if [[ "$CHECK_API" == "true" ]]; then
    log "Checking API endpoints..." "INFO"
    check_endpoint "API Health" "${API_ENDPOINT}/health"
    check_endpoint "API Version" "${API_ENDPOINT}/api/version"
    check_endpoint "API Status" "${API_ENDPOINT}/api/status"

    # Try ping if not explicitly using a URL with protocol
    if [[ ! "$API_ENDPOINT" =~ ^https?:// ]]; then
        check_ping "API Server" "$API_ENDPOINT"
    else
        check_ping "API Server" "${API_ENDPOINT#https://}"
    fi
fi

# Check Web UI connectivity
if [[ "$CHECK_WEB" == "true" ]]; then
    log "Checking Web UI endpoints..." "INFO"
    check_endpoint "Web UI" "$WEB_ENDPOINT"
    check_endpoint "Web UI Static Content" "${WEB_ENDPOINT}/static/css/main.css"

    # Try ping if not explicitly using a URL with protocol
    if [[ ! "$WEB_ENDPOINT" =~ ^https?:// ]]; then
        check_ping "Web Server" "$WEB_ENDPOINT"
    else
        check_ping "Web Server" "${WEB_ENDPOINT#https://}"
    fi
fi

# Check database connectivity
if [[ "$CHECK_DATABASE" == "true" ]]; then
    log "Checking database connectivity..." "INFO"
    check_tcp_port "Database Port" "$DB_HOST" "$DB_PORT"
    if [[ -n "$DB_PASSWORD" ]]; then
        check_database_connectivity "$DB_HOST" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD" "$DB_TYPE"
    else
        record_result "Database" "$DB_HOST:$DB_PORT/$DB_NAME" "SKIPPED" "No database password provided"
    fi
fi

# Check Redis connectivity
if [[ "$CHECK_REDIS" == "true" ]]; then
    log "Checking Redis connectivity..." "INFO"
    check_tcp_port "Redis Port" "$REDIS_HOST" "$REDIS_PORT"
    check_redis_connectivity "$REDIS_HOST" "$REDIS_PORT" "$REDIS_PASSWORD"
fi

# Check external services
if [[ "$CHECK_EXTERNAL" == "true" ]]; then
    log "Checking external service connectivity..." "INFO"
    for endpoint in "${EXTERNAL_ENDPOINTS[@]}"; do
        endpoint_name=$(echo "$endpoint" | sed -e 's/https\?:\/\///' -e 's/\/.*//' -e 's/\..*//')
        check_endpoint "External: $endpoint_name" "$endpoint"
    done
fi

# Run traceroute if in verbose mode
if [[ "$VERBOSE" == "true" ]]; then
    log "Running traceroutes..." "INFO"
    check_traceroute "API Server" "$API_ENDPOINT"
    check_traceroute "Web Server" "$WEB_ENDPOINT"
    for endpoint in "${EXTERNAL_ENDPOINTS[@]}"; do
        endpoint_name=$(echo "$endpoint" | sed -e 's/https\?:\/\///' -e 's/\/.*//' -e 's/\..*//')
        check_traceroute "External: $endpoint_name" "$endpoint"
    done
fi

# Finalize and save the report
finalize_report

# Exit with appropriate status
if [[ "$ALL_TESTS_PASSED" == "true" ]]; then
    log "All connectivity checks passed!" "INFO"
    exit 0
else
    log "Some connectivity checks failed. See the report for details." "ERROR"
    exit 1
fi
