#!/bin/bash
# API Latency Monitoring Script
# Monitors API endpoints for latency issues and reports metrics
# Usage: ./api_latency.sh [environment] [options]

set -e

# Default settings
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
OUTPUT_FORMAT="text"  # text, json, or prometheus
VERBOSE=false
QUIET=false
DR_MODE=false
REGION="primary"
ALERT_THRESHOLD=500  # Alert if P95 latency exceeds this value (ms)
CRITICAL_THRESHOLD=1000  # Critical if P95 latency exceeds this value (ms)
SAMPLES=10  # Number of requests to make to each endpoint
INTERVAL=1  # Seconds between requests
REQUEST_TIMEOUT=10  # Default timeout for requests (seconds)
CONNECTION_REUSE=true  # Enable connection reuse by default
ENDPOINTS_FILE="${PROJECT_ROOT}/config/api_endpoints.json"
CUSTOM_ENDPOINTS=""
METRICS_FILE="/var/lib/node_exporter/textfile_collector/api_latency.prom"
REPORT_FILE=""
API_KEY=""
API_USERNAME=""
API_PASSWORD=""
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Ensure log directory exists
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/api_latency.log"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"

    if [[ "$QUIET" != "true" ]]; then
        echo -e "$message"
    fi

    echo -e "$message" >> "$LOG_FILE"
}

# Function to validate and sanitize configuration
validate_config() {
    # Ensure valid number of samples
    if ! [[ "$SAMPLES" =~ ^[0-9]+$ ]] || [ "$SAMPLES" -lt 1 ]; then
        log "ERROR: Invalid sample count: $SAMPLES. Using default of 10." "ERROR"
        SAMPLES=10
    fi

    # Ensure valid interval
    if ! [[ "$INTERVAL" =~ ^[0-9]+(\.[0-9]+)?$ ]] || [ "$(echo "$INTERVAL < 0" | bc)" -eq 1 ]; then
        log "ERROR: Invalid interval: $INTERVAL. Using default of 1." "ERROR"
        INTERVAL=1
    fi

    # Ensure valid timeout
    if ! [[ "$REQUEST_TIMEOUT" =~ ^[0-9]+$ ]] || [ "$REQUEST_TIMEOUT" -lt 1 ]; then
        log "ERROR: Invalid timeout: $REQUEST_TIMEOUT. Using default of 10." "ERROR"
        REQUEST_TIMEOUT=10
    fi

    # Ensure valid threshold values
    if ! [[ "$ALERT_THRESHOLD" =~ ^[0-9]+$ ]]; then
        log "ERROR: Invalid alert threshold: $ALERT_THRESHOLD. Using default of 500." "ERROR"
        ALERT_THRESHOLD=500
    fi

    if ! [[ "$CRITICAL_THRESHOLD" =~ ^[0-9]+$ ]]; then
        log "ERROR: Invalid critical threshold: $CRITICAL_THRESHOLD. Using default of 1000." "ERROR"
        CRITICAL_THRESHOLD=1000
    fi

    # Check for curl version that supports connection reuse
    if [[ "$CONNECTION_REUSE" == "true" ]]; then
        local curl_version=$(curl --version | head -n 1 | grep -oE "([0-9]+\.[0-9]+\.[0-9]+)")
        if [[ -z "$curl_version" ]]; then
            log "WARNING: Could not determine curl version. Connection reuse may not work properly." "WARNING"
        else
            # Ensure curl version supports keep-alive properly (7.19.7+)
            local major=$(echo "$curl_version" | cut -d. -f1)
            local minor=$(echo "$curl_version" | cut -d. -f2)
            local patch=$(echo "$curl_version" | cut -d. -f3)

            if [[ "$major" -lt 7 || ("$major" -eq 7 && "$minor" -lt 19) ||
                  ("$major" -eq 7 && "$minor" -eq 19 && "$patch" -lt 7) ]]; then
                log "WARNING: Curl version $curl_version may not fully support persistent connections. Consider upgrading curl or using --no-conn-reuse." "WARNING"
                CONNECTION_REUSE=false
            fi
        fi
    fi
}

# Parse command line arguments
shift_count=0
if [[ ! -z "$1" && "$1" != --* ]]; then
    shift_count=1  # Skip the environment parameter in the while loop
fi

while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --region)
            REGION="${2}"
            if [[ "$REGION" != "primary" && "$REGION" != "secondary" ]]; then
                echo "Error: Region must be 'primary' or 'secondary'"
                exit 1
            fi
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="${2}"
            if [[ "$OUTPUT_FORMAT" != "text" && "$OUTPUT_FORMAT" != "json" && "$OUTPUT_FORMAT" != "prometheus" ]]; then
                echo "Error: Format must be 'text', 'json', or 'prometheus'"
                exit 1
            fi
            shift 2
            ;;
        --samples)
            SAMPLES="${2}"
            shift 2
            ;;
        --threshold)
            ALERT_THRESHOLD="${2}"
            shift 2
            ;;
        --interval)
            INTERVAL="${2}"
            shift 2
            ;;
        --timeout)
            REQUEST_TIMEOUT="${2}"
            shift 2
            ;;
        --auth-key)
            API_KEY="${2}"
            shift 2
            ;;
        --auth-user)
            API_USERNAME="${2}"
            shift 2
            ;;
        --auth-pass)
            API_PASSWORD="${2}"
            shift 2
            ;;
        --no-conn-reuse)
            CONNECTION_REUSE=false
            shift
            ;;
        --endpoints)
            CUSTOM_ENDPOINTS="${2}"
            shift 2
            ;;
        --output)
            REPORT_FILE="${2}"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --region primary|secondary   Set region to test"
            echo "  --format text|json|prometheus   Output format"
            echo "  --samples N                  Number of requests per endpoint (default: 10)"
            echo "  --threshold MS               Alert threshold in milliseconds (default: 500)"
            echo "  --interval SEC               Seconds between requests (default: 1)"
            echo "  --timeout SEC                Request timeout in seconds (default: 30)"
            echo "  --auth-key KEY               API authentication key"
            echo "  --auth-user USERNAME         API authentication username"
            echo "  --auth-pass PASSWORD         API authentication password"
            echo "  --no-conn-reuse              Disable connection reuse"
            echo "  --endpoints FILE             Custom endpoints JSON file"
            echo "  --output FILE                Write results to file"
            echo "  --verbose, -v                Enable verbose output"
            echo "  --quiet, -q                  Minimal output"
            echo "  --dr-mode                    Log to DR events system"
            echo "  --help, -h                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Load environment-specific configuration
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Validate configuration
validate_config

# Determine API endpoint based on region
if [[ "$REGION" = "primary" ]]; then
    API_ENDPOINT="${PRIMARY_API_ENDPOINT:-https://api.cloud-platform.example.com}"
else
    API_ENDPOINT="${SECONDARY_API_ENDPOINT:-https://api-dr.cloud-platform.example.com}"
fi

# Use custom endpoints file if specified
if [[ -n "$CUSTOM_ENDPOINTS" ]]; then
    if [[ -f "$CUSTOM_ENDPOINTS" ]]; then
        ENDPOINTS_FILE="$CUSTOM_ENDPOINTS"
    else
        log "ERROR: Custom endpoints file $CUSTOM_ENDPOINTS not found"
        exit 1
    fi
fi

# Check for required commands
for cmd in curl jq bc awk; do
    if ! command -v $cmd &> /dev/null; then
        log "ERROR: Required command '$cmd' not found"
        exit 1
    fi
done

# Function to make a single request and measure latency
measure_latency() {
    local url="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local headers="${4:-}"
    local curl_args=()

    # Build curl command with array for safer execution
    curl_args=(-s -o /dev/null -w '%{time_total},%{http_code}' -X "$method")

    # Add headers if provided
    if [[ -n "$headers" ]]; then
        # Parse headers safely
        IFS=';' read -ra header_array <<< "$headers"
        for header in "${header_array[@]}"; do
            curl_args+=(-H "$header")
        done
    fi

    # Add authentication header if credentials are available
    if [[ -n "$API_KEY" ]]; then
        curl_args+=(-H "Authorization: Bearer $API_KEY")
    elif [[ -n "$API_USERNAME" && -n "$API_PASSWORD" ]]; then
        curl_args+=(-u "$API_USERNAME:$API_PASSWORD")
    fi

    # Add connection reuse option
    if [[ "$CONNECTION_REUSE" == "true" ]]; then
        curl_args+=(--http1.1 --keepalive-time 60)
    else
        curl_args+=(--no-keepalive)
    fi

    # Add max-time option to avoid hanging requests
    curl_args+=(--max-time "$REQUEST_TIMEOUT")

    # Add data if it's a POST/PUT request
    if [[ -n "$data" && ("$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH") ]]; then
        curl_args+=(-d "$data")
    fi

    # Execute the request (no eval needed with array)
    if [[ "$VERBOSE" = true ]]; then
        log "Executing: curl ${curl_args[*]} $url"
    fi

    local result=$(curl "${curl_args[@]}" "$url" 2>/dev/null)
    local curl_exit=$?

    # Handle curl errors
    if [[ $curl_exit -ne 0 ]]; then
        log "Request failed with curl error code $curl_exit" "WARNING"
        echo "0.0,0"
        return $curl_exit
    fi

    local latency=$(echo "$result" | cut -d',' -f1)
    local status=$(echo "$result" | cut -d',' -f2)

    # Convert to milliseconds and return result
    latency=$(echo "$latency * 1000" | bc | awk '{printf "%.1f", $0}')
    echo "$latency,$status"
}

# Function to perform latency test on an endpoint
test_endpoint() {
    local name="$1"
    local path="$2"
    local method="${3:-GET}"
    local data="${4:-}"
    local headers="${5:-}"
    local is_critical="${6:-false}"
    local url="${API_ENDPOINT}${path}"
    local failure_count=0
    local max_failures=3

    log "Testing endpoint: $name ($url)"

    local latencies=()
    local statuses=()
    local success_count=0
    local error_count=0

    # Make multiple requests
    for ((i=1; i<=$SAMPLES; i++)); do
        local result=$(measure_latency "$url" "$method" "$data" "$headers")
        local curl_exit=$?

        # Check for persistent failures
        if [[ $curl_exit -ne 0 ]]; then
            failure_count=$((failure_count + 1))

            if [[ $failure_count -ge $max_failures ]]; then
                log "ERROR: Endpoint $name failed $max_failures consecutive times, skipping remaining tests" "ERROR"
                break
            fi

            # Exponential backoff
            local backoff=$((2 ** (failure_count - 1)))
            if [[ $backoff -gt 30 ]]; then
                backoff=30
            fi

            log "Request failed (attempt $failure_count), retrying in $backoff seconds..."
            sleep $backoff
            continue
        else
            failure_count=0  # Reset on success
        fi

        local latency=$(echo $result | cut -d',' -f1)
        local status=$(echo $result | cut -d',' -f2)

        latencies+=($latency)
        statuses+=($status)

        if [[ "$status" -ge 200 && "$status" -lt 300 ]]; then
            success_count=$((success_count + 1))
        else
            error_count=$((error_count + 1))
            log "  Request returned HTTP status $status"
        fi

        if [[ "$VERBOSE" = true ]]; then
            log "  Request $i: ${latency}ms (status: $status)"
        fi

        # Sleep between requests - adjust interval based on connection reuse
        if [[ $i -lt $SAMPLES ]]; then
            if [[ "$CONNECTION_REUSE" == "true" ]]; then
                # Shorter interval when connection reuse is enabled
                sleep $(echo "scale=2; $INTERVAL / 2" | bc)
            else
                sleep $INTERVAL
            fi
        fi
    done

    # Check if we have any data to analyze
    if [[ ${#latencies[@]} -eq 0 ]]; then
        log "ERROR: No successful responses from endpoint $name"
        return 1
    fi

    # Sort latencies for percentile calculation
    IFS=$'\n' sorted=($(sort -n <<<"${latencies[*]}"))
    unset IFS

    # Calculate statistics
    local total=0
    for latency in "${latencies[@]}"; do
        total=$(echo "$total + $latency" | bc)
    done

    local count=${#latencies[@]}
    local avg=$(echo "scale=1; $total / $count" | bc)
    local min=${sorted[0]}
    local max=${sorted[$((count-1))]}

    # Safe percentile calculations with proper bounds checking
    local p50_idx=$(( count * 50 / 100 ))
    local p95_idx=$(( count * 95 / 100 ))
    local p99_idx=$(( count * 99 / 100 ))

    # Ensure indexes are valid
    [[ $p50_idx -lt $count ]] || p50_idx=$((count-1))
    [[ $p95_idx -lt $count ]] || p95_idx=$((count-1))
    [[ $p99_idx -lt $count ]] || p99_idx=$((count-1))

    local p50=${sorted[$p50_idx]}
    local p95=${sorted[$p95_idx]}
    local p99=${sorted[$p99_idx]}

    # Calculate error rate safely
    local error_rate=0
    if [[ $count -gt 0 ]]; then
        error_rate=$(echo "scale=1; $error_count * 100 / ($success_count + $error_count)" | bc)
    fi

    # Determine status based on thresholds
    local status="OK"
    if (( $(echo "$p95 >= $CRITICAL_THRESHOLD" | bc -l) )) || (( $(echo "$error_rate > 5" | bc -l) )); then
        status="CRITICAL"
    elif (( $(echo "$p95 >= $ALERT_THRESHOLD" | bc -l) )) || (( $(echo "$error_rate > 0" | bc -l) )); then
        status="WARNING"
    fi

    log "Results for $name:"
    log "  Average: ${avg}ms | P50: ${p50}ms | P95: ${p95}ms | P99: ${p99}ms | Error rate: ${error_rate}%"
    log "  Status: $status"

    # Return formatted result
    echo "$name,$path,$method,$avg,$min,$max,$p50,$p95,$p99,$error_rate,$success_count,$error_count,$status,$is_critical"
}

# Function to output results in Prometheus format
output_prometheus() {
    local results="$1"
    local timestamp=$(date +%s)
    local metrics_dir=$(dirname "$METRICS_FILE")

    # Create directory if it doesn't exist
    if [[ ! -d "$metrics_dir" ]]; then
        if ! mkdir -p "$metrics_dir"; then
            log "ERROR: Could not create metrics directory $metrics_dir"
            return 1
        fi
    fi

    # Create or truncate metrics file
    echo "# HELP api_latency_ms API endpoint latency in milliseconds" > "$METRICS_FILE"
    echo "# TYPE api_latency_ms gauge" >> "$METRICS_FILE"
    echo "# HELP api_error_rate API endpoint error rate percentage" >> "$METRICS_FILE"
    echo "# TYPE api_error_rate gauge" >> "$METRICS_FILE"
    echo "# HELP api_latency_p95_ms API endpoint 95th percentile latency in milliseconds" >> "$METRICS_FILE"
    echo "# TYPE api_latency_p95_ms gauge" >> "$METRICS_FILE"
    echo "# HELP api_latency_last_check_timestamp Last check timestamp for API latency" >> "$METRICS_FILE"
    echo "# TYPE api_latency_last_check_timestamp gauge" >> "$METRICS_FILE"

    # Add last check timestamp
    echo "api_latency_last_check_timestamp $timestamp" >> "$METRICS_FILE"

    # Process each endpoint result
    IFS=$'\n'
    for line in $results; do
        IFS=',' read -r name path method avg min max p50 p95 p99 error_rate success_count error_count status is_critical <<< "$line"

        # Clean name for Prometheus (replace non-alphanumeric chars with underscore)
        clean_name=$(echo "$name" | tr -c '[:alnum:]' '_')
        clean_path=$(echo "$path" | tr -c '[:alnum:]' '_')

        # Add metrics
        echo "api_latency_ms{endpoint=\"$name\",path=\"$path\",method=\"$method\",env=\"$ENVIRONMENT\",region=\"$REGION\"} $avg" >> "$METRICS_FILE"
        echo "api_latency_p95_ms{endpoint=\"$name\",path=\"$path\",method=\"$method\",env=\"$ENVIRONMENT\",region=\"$REGION\"} $p95" >> "$METRICS_FILE"
        echo "api_error_rate{endpoint=\"$name\",path=\"$path\",method=\"$method\",env=\"$ENVIRONMENT\",region=\"$REGION\"} $error_rate" >> "$METRICS_FILE"
    done
    unset IFS

    # Set permissions
    chmod 644 "$METRICS_FILE"
    log "Metrics exported to $METRICS_FILE"
}

# Function to output results in JSON format
output_json() {
    local results="$1"
    local output_file="$2"

    if [[ -z "$output_file" ]]; then
        output_file=$(mktemp)
    fi

    # Create JSON structure
    echo "{" > "$output_file"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$output_file"
    echo "  \"environment\": \"$ENVIRONMENT\"," >> "$output_file"
    echo "  \"region\": \"$REGION\"," >> "$output_file"
    echo "  \"api_endpoint\": \"$API_ENDPOINT\"," >> "$output_file"
    echo "  \"sample_size\": $SAMPLES," >> "$output_file"
    echo "  \"endpoints\": [" >> "$output_file"

    # Process each endpoint result
    local first=true
    IFS=$'\n'
    for line in $results; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo "," >> "$output_file"
        fi

        IFS=',' read -r name path method avg min max p50 p95 p99 error_rate success_count error_count status is_critical <<< "$line"

        cat >> "$output_file" << EOF
    {
      "name": "$name",
      "path": "$path",
      "method": "$method",
      "latency": {
        "average_ms": $avg,
        "min_ms": $min,
        "max_ms": $max,
        "p50_ms": $p50,
        "p95_ms": $p95,
        "p99_ms": $p99
      },
      "errors": {
        "rate": $error_rate,
        "success_count": $success_count,
        "error_count": $error_count
      },
      "status": "$status",
      "is_critical": $is_critical
    }
EOF
    done
    unset IFS

    # Close JSON structure
    echo "" >> "$output_file"
    echo "  ]," >> "$output_file"

    # Add system info
    echo "  \"system_info\": {" >> "$output_file"
    echo "    \"hostname\": \"$(hostname)\"," >> "$output_file"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"" >> "$output_file"
    echo "  }" >> "$output_file"
    echo "}" >> "$output_file"

    # Print JSON to stdout if output format is JSON
    if [[ "$OUTPUT_FORMAT" = "json" ]]; then
        cat "$output_file"
    fi

    log "JSON report saved to $output_file"
}

# Function to output results in text format
output_text() {
    local results="$1"
    local output_file="$2"

    if [[ -z "$output_file" ]]; then
        output_file=$(mktemp)
    fi

    # Create header
    cat > "$output_file" << EOF
API LATENCY MONITORING REPORT
============================
Environment: $ENVIRONMENT
Region:      $REGION
API:         $API_ENDPOINT
Timestamp:   $(date)
Samples:     $SAMPLES
Thresholds:  Alert: ${ALERT_THRESHOLD}ms, Critical: ${CRITICAL_THRESHOLD}ms

ENDPOINT LATENCY RESULTS
========================
EOF

    # Process each endpoint result
    IFS=$'\n'
    for line in $results; do
        IFS=',' read -r name path method avg min max p50 p95 p99 error_rate success_count error_count status is_critical <<< "$line"

        local status_symbol="✓"
        if [[ "$status" = "WARNING" ]]; then
            status_symbol="⚠️"
        elif [[ "$status" = "CRITICAL" ]]; then
            status_symbol="⛔"
        fi

        cat >> "$output_file" << EOF

$status_symbol $name ($method $path)
--------------------------------------------------
Latency:     Avg: ${avg}ms, Min: ${min}ms, Max: ${max}ms
Percentiles: P50: ${p50}ms, P95: ${p95}ms, P99: ${p99}ms
Errors:      ${error_rate}% (${error_count}/${success_count})
Status:      $status
Critical:    $is_critical
EOF
    done
    unset IFS

    # Add summary
    cat >> "$output_file" << EOF

SUMMARY
=======
Total endpoints tested: $(echo "$results" | wc -l)
Critical issues:        $(echo "$results" | grep -c "CRITICAL")
Warnings:               $(echo "$results" | grep -c "WARNING")
Healthy endpoints:      $(echo "$results" | grep -c "OK")

Generated: $(date)
EOF

    # Print report to stdout if output format is text
    if [[ "$OUTPUT_FORMAT" = "text" ]]; then
        cat "$output_file"
    fi

    log "Text report saved to $output_file"
}

# Main script execution
log "Starting API latency monitoring for ${ENVIRONMENT} environment in ${REGION} region"
log "Testing API at $API_ENDPOINT"

# Load endpoints from endpoints file
if [[ ! -f "$ENDPOINTS_FILE" ]]; then
    log "ERROR: Endpoints file $ENDPOINTS_FILE not found"
    exit 1
fi

# Parse endpoints from JSON file
ENDPOINTS=$(jq -c '.endpoints[]' "$ENDPOINTS_FILE")
if [[ -z "$ENDPOINTS" ]]; then
    log "ERROR: No endpoints found in $ENDPOINTS_FILE"
    exit 1
fi

# Initialize results array
results=()

# Test each endpoint
for endpoint in $ENDPOINTS; do
    name=$(echo $endpoint | jq -r '.name')
    path=$(echo $endpoint | jq -r '.path')
    method=$(echo $endpoint | jq -r '.method // "GET"')
    data=$(echo $endpoint | jq -r '.data // ""')
    headers=$(echo $endpoint | jq -r '.headers // ""')
    critical=$(echo $endpoint | jq -r '.critical // false')

    # Test the endpoint
    result=$(test_endpoint "$name" "$path" "$method" "$data" "$headers" "$critical")
    results+=("$result")
done

# Combine results
all_results=$(printf '%s\n' "${results[@]}")

# Output results in requested format
if [[ "$OUTPUT_FORMAT" = "json" ]]; then
    output_json "$all_results" "$REPORT_FILE"
elif [[ "$OUTPUT_FORMAT" = "prometheus" ]]; then
    output_prometheus "$all_results"
else
    output_text "$all_results" "$REPORT_FILE"
fi

# Determine final status based on results
if echo "$all_results" | grep -q "CRITICAL"; then
    FINAL_STATUS="CRITICAL"
    EXIT_CODE=2
elif echo "$all_results" | grep -q "WARNING"; then
    FINAL_STATUS="WARNING"
    EXIT_CODE=1
else
    FINAL_STATUS="OK"
    EXIT_CODE=0
fi

# Handle critical endpoints with issues
critical_issues=$(echo "$all_results" | grep -E "CRITICAL.*,true$" || echo "")
if [[ -n "$critical_issues" ]]; then
    log "ALERT: Critical endpoints with performance issues detected!"

    # Create a formatted report of critical issues
    while IFS=',' read -r name path method avg min max p50 p95 p99 error_rate success_count error_count status is_critical; do
        if [[ "$status" == "CRITICAL" && "$is_critical" == "true" ]]; then
            issue_details="P95 latency: ${p95}ms"
            if (( $(echo "$error_rate > 0" | bc -l) )); then
                issue_details+=", Error rate: ${error_rate}%"
            fi
            log "  - $name ($method $path): $issue_details"
        fi
    done <<< "$all_results"

    # Send alert if notification mechanism exists
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" && -n "$EMAIL_RECIPIENT" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority "high" \
            --subject "API Latency Alert: $ENVIRONMENT ($REGION)" \
            --message "Critical API latency issues detected. See report for details." \
            --recipient "$EMAIL_RECIPIENT" \
            --attachment "${REPORT_FILE:-/dev/null}"

        log "Alert notification sent to $EMAIL_RECIPIENT"
    fi
fi

# Log to DR events system if requested
if [[ "$DR_MODE" = true ]]; then
    DR_LOG_DIR="/var/log/cloud-platform"
    DR_LOG_FILE="$DR_LOG_DIR/dr-events.log"

    # Ensure directory exists
    mkdir -p "$DR_LOG_DIR"

    if [[ -d "$DR_LOG_DIR" && -w "$DR_LOG_DIR" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),API_LATENCY,${ENVIRONMENT},${REGION},${FINAL_STATUS}" >> "$DR_LOG_FILE"
        log "API latency monitoring results logged to DR events log"
    else
        log "WARNING: Could not write to DR events log at $DR_LOG_FILE"
    fi
fi

# Summarize results
log "API latency monitoring completed with status: ${FINAL_STATUS}"

# Exit with appropriate code to signal status to calling scripts or cron
exit $EXIT_CODE
