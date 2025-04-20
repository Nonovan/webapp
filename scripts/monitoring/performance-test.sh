#!/bin/bash
# Performance test script for Cloud Infrastructure Platform
# Tests API performance under load and generates reports
# Usage: ./performance-test.sh [environment] [options]

set -e

# Default settings
ENVIRONMENT="development"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORT_DIR="/var/www/reports/performance"
CONCURRENT_USERS=${CONCURRENT_USERS:-10}
DURATION=${DURATION:-30}
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="${REPORT_DIR}/performance-${ENVIRONMENT}-${TIMESTAMP}.html"
JSON_REPORT_FILE="${REPORT_DIR}/performance-${ENVIRONMENT}-${TIMESTAMP}.json"
LOG_FILE="/var/log/cloud-platform/performance-test.log"
OUTPUT_FORMAT=${OUTPUT_FORMAT:-"html"}
AUTO_REFRESH_INTERVAL=300000  # 5 minutes in milliseconds
VERBOSE=false
QUIET=false
NOTIFY=false
DR_MODE=false
EMAIL_RECIPIENT=""
REGION=""
CUSTOM_ENDPOINTS=""
exit_code=0

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    
    if [[ "$QUIET" != "true" ]]; then
        echo "$message"
    fi
    
    echo "$message" >> "$LOG_FILE"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --users|-u)
            CONCURRENT_USERS="$2"
            shift 2
            ;;
        --duration|-d)
            DURATION="$2"
            shift 2
            ;;
        --endpoints|-e)
            CUSTOM_ENDPOINTS="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --notify)
            NOTIFY=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --users, -u NUM       Number of concurrent users (default: 10)"
            echo "  --duration, -d SEC    Test duration in seconds (default: 30)"
            echo "  --endpoints, -e FILE  Custom endpoints file to test"
            echo "  --region              Region to test (primary or secondary)"
            echo "  --notify [EMAIL]      Send notification with results"
            echo "  --dr-mode             Log to DR events system"
            echo "  --output-format       Output format: html or json (default: html)"
            echo "  --verbose, -v         Show detailed output"
            echo "  --quiet, -q           Minimal output"
            echo "  --help, -h            Show this help message"
            exit 0
            ;;
        *)
            # Set the environment if not already set by a named parameter
            if [[ -z "$ENVIRONMENT_SET" ]]; then
                ENVIRONMENT="$1"
                ENVIRONMENT_SET=true
            else
                echo "Unknown parameter: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check required dependencies
check_dependencies() {
    local missing_deps=0
    for cmd in ab curl jq bc; do
        if ! command -v $cmd &>/dev/null; then
            log "ERROR: Required command '$cmd' not found"
            missing_deps=$((missing_deps + 1))
        fi
    done
    
    if [ $missing_deps -gt 0 ]; then
        log "ERROR: Missing dependencies. Please install required tools and try again."
        exit 1
    fi
}

# Call this function early in the script
check_dependencies

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

# Ensure required tools are installed
for cmd in ab curl jq; do
    if ! command -v $cmd &>/dev/null; then
        log "Error: Required command '$cmd' not found. Please install it and try again."
        exit 1
    fi
done

# Add a function to check if the API is reachable
check_api_availability() {
    local url="$1"
    log "Checking availability of $url"
    
    if ! curl -s --head --fail --connect-timeout 10 "$url" > /dev/null; then
        log "ERROR: Cannot connect to $url"
        return 1
    fi
    return 0
}

# Call it before starting tests
if ! check_api_availability "$APP_URL"; then
    log "ERROR: API is not reachable at $APP_URL. Exiting."
    exit 1
fi

log "Starting performance tests for ${ENVIRONMENT} environment"
log "Duration: ${DURATION} seconds, Concurrent Users: ${CONCURRENT_USERS}"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
fi

# Determine endpoints based on region
if [[ -n "$REGION" ]]; then
    log "Using $REGION region endpoints"
    if [ "$REGION" = "primary" ]; then
        APP_URL="${PRIMARY_API_ENDPOINT:-https://api.cloud-platform.example.com}"
    else
        APP_URL="${SECONDARY_API_ENDPOINT:-https://api-dr.cloud-platform.example.com}"
    fi
else
    # Set default URL if not defined in environment file
    APP_URL=${APP_URL:-"http://localhost:5000"}
fi

log "Testing application at $APP_URL"

# Start system monitoring
monitor_system_during_test() {
    local monitor_file="/tmp/perf_monitor_${TIMESTAMP}.txt"
    
    log "Starting system monitoring during test"
    
    # Start monitoring in background
    {
        echo "TIMESTAMP,CPU_USAGE,MEMORY_USAGE,LOAD_AVG" > "$monitor_file"
        
        for i in $(seq 1 "$DURATION"); do
            cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
            mem=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
            load=$(cat /proc/loadavg | awk '{print $1}')
            
            echo "$(date +%s),$cpu,$mem,$load" >> "$monitor_file"
            sleep 1
        done
    } &
    local monitor_pid=$!
    
    # Return the PID so we can wait for it
    echo $monitor_pid
}

# Start monitoring
monitor_pid=$(monitor_system_during_test)

# Function to test an endpoint
test_endpoint() {
    local endpoint=$1
    local description=$2
    local method=${3:-"GET"}
    local data=${4:-""}
    local content_type=${5:-"application/json"}
    
    local full_url="${APP_URL}${endpoint}"
    local output_file="/tmp/ab_results_$(echo $endpoint | sed 's/[^a-zA-Z0-9]/_/g').txt"
    
    log "Testing endpoint: $description ($full_url)"
    
    # Use a timeout to prevent hanging tests
    local timeout_cmd=""
    if command -v timeout &>/dev/null; then
        timeout_cmd="timeout 300"  # 5 minute timeout
    fi
    
    if [[ "$method" == "GET" ]]; then
        # For GET requests
        $timeout_cmd ab -c $CONCURRENT_USERS -t $DURATION -v 2 -m $method $full_url > $output_file 2>&1 || {
            log "WARNING: Error testing $endpoint (GET)"
            return 1
        }
    else
        # For POST/PUT requests with data
        echo "$data" > /tmp/post_data.txt
        $timeout_cmd ab -c $CONCURRENT_USERS -t $DURATION -v 2 -m $method -p /tmp/post_data.txt -T "$content_type" $full_url > $output_file 2>&1 || {
            log "WARNING: Error testing $endpoint ($method)"
            rm -f /tmp/post_data.txt
            return 1
        }
        rm -f /tmp/post_data.txt
    fi
    
    # Extract key metrics with error checking
    if [[ -f "$output_file" ]]; then
        # Check if ab completed properly
        if ! grep -q "Complete requests:" "$output_file"; then
            log "ERROR: Incomplete test for $endpoint"
            return 1
        }

        # Requests per second
        local rps=$(grep "Requests per second" $output_file | awk '{print $4}')
        
        # Response times
        local mean_time=$(grep "Time per request" $output_file | head -1 | awk '{print $4}')
        local p50_time=$(grep "50%" $output_file | awk '{print $2}')
        local p95_time=$(grep "95%" $output_file | awk '{print $2}')
        local p99_time=$(grep "99%" $output_file | awk '{print $2}')
        
        # Error rate
        local total_requests=$(grep "Complete requests" $output_file | awk '{print $3}')
        local failed_requests=$(grep "Failed requests" $output_file | awk '{print $3}')
        local error_rate=0
        if [ "$total_requests" -gt 0 ]; then
            error_rate=$(echo "scale=2; $failed_requests * 100 / $total_requests" | bc)
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            log "Results for $endpoint:"
            log "  Requests per second: $rps"
            log "  Mean response time: $mean_time ms"
            log "  P95 response time: $p95_time ms"
            log "  Error rate: $error_rate%"
        fi
        
        echo "$endpoint,$rps,$mean_time,$p50_time,$p95_time,$p99_time,$error_rate"
    else
        log "ERROR: No output file found for $endpoint"
        return 1
    fi
}

# Safe calculation function
safe_calc() {
    local expr="$1"
    local result=$(echo "$expr" | bc -l 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$result" ]; then
        echo "0"
    else
        echo "$result"
    fi
}

# Then use it like this:
error_rate=$(safe_calc "$failed_requests * 100 / $total_requests")

# Add a function to determine status
determine_status() {
    local error_rate=$1
    local p95=$2
    local rps=$3
    
    if (( $(echo "$error_rate > 5" | bc -l) )); then
        echo "critical"
    elif (( $(echo "$p95 > 500" | bc -l) )); then
        echo "warning"
    elif (( $(echo "$rps < 5" | bc -l) )); then
        echo "warning"
    else
        echo "good"
    fi
}

# Function to add a recommendation based on results
add_recommendation() {
    local endpoint=$1
    local rps=$2
    local p95=$3
    local error_rate=$4
    
    # Define thresholds
    local rps_low=10
    local p95_high=500
    local error_rate_high=1
    
    if (( $(echo "$error_rate > $error_rate_high" | bc -l) )); then
        recommendations+=("Critical: $endpoint has a high error rate ($error_rate%). Investigate error responses and fix API issues.")
    elif (( $(echo "$p95 > $p95_high" | bc -l) )); then
        recommendations+=("Warning: $endpoint has slow P95 response time (${p95}ms). Consider optimizing database queries or caching.")
    elif (( $(echo "$rps < $rps_low" | bc -l) )); then
        recommendations+=("Warning: $endpoint has low throughput ($rps req/s). Verify API implementation efficiency.")
    fi
}

# Initialize recommendations array
recommendations=()

# Test standard endpoints
log "Testing health endpoint"
health_data=$(test_endpoint "/api/health" "Health Check")

log "Testing static endpoint"
static_data=$(test_endpoint "/static/logo.png" "Static Asset")

log "Testing version endpoint"
version_data=$(test_endpoint "/api/version" "Version Info")

log "Testing auth endpoint"
auth_data=$(test_endpoint "/api/auth/status" "Auth Status")

log "Testing resources endpoint"
resources_data=$(test_endpoint "/api/resources" "Resources List")

log "Testing login endpoint"
login_data=$(test_endpoint "/api/auth/login" "Login" "POST" '{"username":"test","password":"test"}' "application/json")

# Test custom endpoints if provided
if [ -n "$CUSTOM_ENDPOINTS" ] && [ -f "$CUSTOM_ENDPOINTS" ]; then
    log "Testing custom endpoints from $CUSTOM_ENDPOINTS"
    
    while IFS=, read -r endpoint method data content_type description; do
        # Skip comments and empty lines
        if [[ "$endpoint" == \#* ]] || [ -z "$endpoint" ]; then
            continue
        fi
        
        # Default values if not provided
        method=${method:-"GET"}
        description=${description:-"Custom endpoint"}
        
        log "Testing custom endpoint: $endpoint ($description)"
        custom_data=$(test_endpoint "$endpoint" "$description" "$method" "$data" "$content_type")
        
        # Process results if needed
        if [ -n "$custom_data" ]; then
            IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$custom_data"
            add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
        fi
    done < "$CUSTOM_ENDPOINTS"
fi

# Wait for monitoring to finish
if [ -n "$monitor_pid" ]; then
    wait $monitor_pid
    log "System monitoring completed"
    
    # Process monitoring data for the report
    monitor_file="/tmp/perf_monitor_${TIMESTAMP}.txt"
    
    if [ -f "$monitor_file" ]; then
        avg_cpu=$(tail -n +2 "$monitor_file" | awk -F, '{sum+=$2} END {print sum/NR}')
        avg_mem=$(tail -n +2 "$monitor_file" | awk -F, '{sum+=$3} END {print sum/NR}')
        max_cpu=$(tail -n +2 "$monitor_file" | awk -F, '{if($2>max) max=$2} END {print max}')
        max_mem=$(tail -n +2 "$monitor_file" | awk -F, '{if($3>max) max=$3} END {print max}')
        
        # Add the data to system info
        system_data="Average CPU: ${avg_cpu}% (Max: ${max_cpu}%)<br>Average Memory: ${avg_mem}% (Max: ${max_mem}%)"
    fi
fi

# Process results to add recommendations
if [ -n "$health_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$health_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

if [ -n "$static_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$static_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

if [ -n "$version_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$version_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

if [ -n "$auth_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$auth_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

if [ -n "$resources_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$resources_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

if [ -n "$login_data" ]; then
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$login_data"
    add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"
fi

# Function to generate a JSON report of test results
generate_json_report() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    log "Generating JSON report at $JSON_REPORT_FILE"
    
    # Create parent directory if it doesn't exist
    mkdir -p "$(dirname "$JSON_REPORT_FILE")"
    
    # Start building JSON with metadata
    cat > "$JSON_REPORT_FILE" <<EOF
{
  "timestamp": "${timestamp}",
  "environment": "${ENVIRONMENT}",
  "region": "${REGION:-"unknown"}",
  "duration": ${DURATION},
  "concurrent_users": ${CONCURRENT_USERS},
  "base_url": "${APP_URL}",
  "endpoints": [
EOF

    # Process each endpoint result
    local first_endpoint=true
    local all_endpoint_data=("$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data")
    
    for endpoint_data in "${all_endpoint_data[@]}"; do
        # Skip empty data entries
        if [ -z "$endpoint_data" ]; then
            continue
        fi
        
        # Parse the comma-separated values
        IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$endpoint_data"
        
        # Add comma separator if not first item
        if [ "$first_endpoint" = true ]; then
            first_endpoint=false
        else
            echo "," >> "$JSON_REPORT_FILE"
        fi
        
        # Add endpoint data to JSON
        cat >> "$JSON_REPORT_FILE" <<EOF
    {
      "endpoint": "${endpoint}",
      "requests_per_second": ${rps},
      "mean_time_ms": ${mean_time},
      "p50_ms": ${p50},
      "p95_ms": ${p95},
      "p99_ms": ${p99},
      "error_rate": ${error_rate}
    }
EOF
    done
    
    # Get system information safely
    local cpu_info=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^ *//' || echo "Unknown")
    local mem_total=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo "Unknown")
    local mem_avail=$(free -h 2>/dev/null | awk '/^Mem:/{print $4}' || echo "Unknown")
    local load_avg=$(uptime 2>/dev/null | awk -F'[a-z]:' '{print $2}' | xargs || echo "Unknown")
    
    # Complete the JSON with system info
    cat >> "$JSON_REPORT_FILE" <<EOF
  ],
  "system_info": {
    "cpu": "$cpu_info",
    "memory_total": "$mem_total",
    "memory_available": "$mem_avail",
    "load_average": "$load_avg"
  },
  "recommendations": [
EOF

    # Add recommendations
    local first_recommendation=true
    for rec in "${recommendations[@]}"; do
        if [ "$first_recommendation" = true ]; then
            first_recommendation=false
        else
            echo "," >> "$JSON_REPORT_FILE"
        fi
        
        # Escape special JSON characters
        local escaped_rec=$(echo "$rec" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        echo "    \"$escaped_rec\"" >> "$JSON_REPORT_FILE"
    done

    # Complete the JSON
    cat >> "$JSON_REPORT_FILE" <<EOF
  ]
}
EOF

    # Validate JSON if jq is available
    if command -v jq &>/dev/null; then
        if ! jq '.' "$JSON_REPORT_FILE" >/dev/null 2>&1; then
            log "WARNING: Generated JSON may be invalid. Please check $JSON_REPORT_FILE"
        else
            log "JSON report validated and saved to $JSON_REPORT_FILE"
        fi
    else
        log "JSON report saved to $JSON_REPORT_FILE (validation skipped - jq not available)"
    fi
}

# Function for comparing with historical results
compare_with_historical() {
    local previous_report=$(find "$REPORT_DIR" -name "performance-${ENVIRONMENT}-*.json" -type f -printf "%T@ %p\n" | sort -nr | head -2 | tail -1 | cut -d' ' -f2)
    
    if [ -z "$previous_report" ] || [ ! -f "$previous_report" ]; then
        log "No previous report found for comparison"
        return
    fi
    
    log "Comparing with previous report: $(basename "$previous_report")"
    
# Add comparison to the report
cat >> "$REPORT_FILE" <<EOF
<div class="section">
    <h2>Historical Comparison</h2>
    <p>Comparing with: $(basename "$previous_report")</p>
    <table>
        <tr>
            <th>Endpoint</th>
            <th>Previous RPS</th>
            <th>Current RPS</th>
            <th>Change</th>
            <th>Previous P95 (ms)</th>
            <th>Current P95 (ms)</th>
            <th>Change</th>
        </tr>
EOF

# Process current results
local all_data=("$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data")

for data in "${all_data[@]}"; do
    # Skip empty data entries
    if [ -z "$data" ]; then
        continue
    fi
    
    # Parse the comma-separated values
    IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$data"
    
    # Default values for previous metrics
    local previous_rps="N/A"
    local previous_p95="N/A"
    
    # Get previous data for this endpoint if jq is available
    if command -v jq &>/dev/null; then
        # Extract previous metrics safely with proper error handling
        previous_rps=$(jq -r ".endpoints[] | select(.endpoint == \"$endpoint\") | .requests_per_second" "$previous_report" 2>/dev/null || echo "N/A")
        previous_p95=$(jq -r ".endpoints[] | select(.endpoint == \"$endpoint\") | .p95_ms" "$previous_report" 2>/dev/null || echo "N/A")
        
        # Validate extracted values
        if [[ "$previous_rps" == "null" || -z "$previous_rps" ]]; then
            previous_rps="N/A"
        fi
        if [[ "$previous_p95" == "null" || -z "$previous_p95" ]]; then
            previous_p95="N/A"
        fi
    else
        # Log the missing dependency
        log "WARNING: jq command not available for JSON processing - skipping historical comparison details"
    fi
    
    # Initialize change variables
    local rps_change="N/A"
    local p95_change="N/A"
        
    if [[ "$previous_rps" != "N/A" && "$previous_rps" != "0" && "$previous_rps" != "null" ]]; then
        rps_change=$(echo "scale=1; ($rps - $previous_rps) / $previous_rps * 100" | bc 2>/dev/null || echo "N/A")
    fi
    
    if [[ "$previous_p95" != "N/A" && "$previous_p95" != "0" && "$previous_p95" != "null" ]]; then
        p95_change=$(echo "scale=1; ($p95 - $previous_p95) / $previous_p95 * 100" | bc 2>/dev/null || echo "N/A")
    fi
    
    # Format change with color and arrow
    local rps_change_class=""
    local p95_change_class=""
    local rps_arrow=""
    local p95_arrow=""
    
    if [[ "$rps_change" != "N/A" ]]; then
        if (( $(echo "$rps_change > 10" | bc -l 2>/dev/null) )); then
            rps_change_class="good"
            rps_arrow="↑"
        elif (( $(echo "$rps_change < -10" | bc -l 2>/dev/null) )); then
            rps_change_class="critical"
            rps_arrow="↓"
        fi
    fi
    
    if [[ "$p95_change" != "N/A" ]]; then
        if (( $(echo "$p95_change > 10" | bc -l 2>/dev/null) )); then
            p95_change_class="critical"
            p95_arrow="↑"
        elif (( $(echo "$p95_change < -10" | bc -l 2>/dev/null) )); then
            p95_change_class="good"
            p95_arrow="↓"
        fi
    fi
    
    # Add row to comparison table
    cat >> "$REPORT_FILE" <<EOF
        <tr>
            <td>${endpoint}</td>
            <td>${previous_rps}</td>
            <td>${rps}</td>
            <td class="${rps_change_class}">${rps_change}% ${rps_arrow}</td>
            <td>${previous_p95}</td>
            <td>${p95}</td>
            <td class="${p95_change_class}">${p95_change}% ${p95_arrow}</td>
        </tr>
EOF
    done
    
    # Close the comparison table
    cat >> "$REPORT_FILE" <<EOF
        </table>
    </div>
EOF
}

# Function to export Prometheus metrics
export_prometheus_metrics() {
    local metrics_file="/var/lib/node_exporter/textfile_collector/performance_test.prom"
    local metrics_dir=$(dirname "$metrics_file")
    
    # Only export if the directory exists (node_exporter is likely installed)
    if [ -d "$metrics_dir" ]; then
        log "Exporting metrics to Prometheus node_exporter"
        
        # Create or truncate the metrics file
        > "$metrics_file"
        
        # Add timestamp metric
        echo "# HELP performance_test_timestamp_seconds Timestamp of the last performance test run" >> "$metrics_file"
        echo "# TYPE performance_test_timestamp_seconds gauge" >> "$metrics_file"
        echo "performance_test_timestamp_seconds $(date +%s)" >> "$metrics_file"
        
        # Process and export each endpoint's metrics
        local all_data=("$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data")
        
        for data in "${all_data[@]}"; do
            if [ -z "$data" ]; then
                continue
            fi
            
            IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$data"
            
            # Clean endpoint name for Prometheus (replace non-alphanumeric with underscore)
            clean_endpoint=$(echo "$endpoint" | sed 's/[^a-zA-Z0-9]/_/g' | sed 's/^_//' | sed 's/_$//')
            
            # Export metrics
            {
                echo "# HELP performance_test_rps_${clean_endpoint} Requests per second for ${endpoint}"
                echo "# TYPE performance_test_rps_${clean_endpoint} gauge"
                echo "performance_test_rps{endpoint=\"${endpoint}\",env=\"${ENVIRONMENT}\"} ${rps}"
                
                echo "# HELP performance_test_latency_${clean_endpoint} Response time for ${endpoint}"
                echo "# TYPE performance_test_latency_${clean_endpoint} gauge"
                echo "performance_test_latency_p50{endpoint=\"${endpoint}\",env=\"${ENVIRONMENT}\"} ${p50}"
                echo "performance_test_latency_p95{endpoint=\"${endpoint}\",env=\"${ENVIRONMENT}\"} ${p95}"
                echo "performance_test_latency_p99{endpoint=\"${endpoint}\",env=\"${ENVIRONMENT}\"} ${p99}"
                
                echo "# HELP performance_test_error_rate_${clean_endpoint} Error rate for ${endpoint}"
                echo "# TYPE performance_test_error_rate_${clean_endpoint} gauge"
                echo "performance_test_error_rate{endpoint=\"${endpoint}\",env=\"${ENVIRONMENT}\"} ${error_rate}"
            } >> "$metrics_file"
        done
        
        chmod 644 "$metrics_file"
        log "Metrics exported to $metrics_file"
    fi
}

# Function for notification
send_notification() {
    if [ "$NOTIFY" = true ] && [ -n "$EMAIL_RECIPIENT" ]; then
        log "Sending notification to $EMAIL_RECIPIENT"
        
        # Use notification script if available
        if [ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]; then
            local priority="low"
            
            # Set priority based on performance issues
            if grep -q "class=\"critical\"" "$REPORT_FILE"; then
                priority="high"
            elif grep -q "class=\"warning\"" "$REPORT_FILE"; then
                priority="medium"
            fi
            
            ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
                --priority "$priority" \
                --subject "Performance Test Report: ${ENVIRONMENT}" \
                --message "Performance test completed. View the report at: ${REPORT_FILE}" \
                --attachment "${REPORT_FILE}" \
                --recipient "$EMAIL_RECIPIENT"
            
            log "Notification sent to $EMAIL_RECIPIENT"
        else
            log "WARNING: Could not send notification, send-notification.sh not found or not executable"
        fi
    fi
}

# Generate HTML report
cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - $ENVIRONMENT</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .summary-item {
            text-align: center;
        }
        .summary-value {
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }
        .section {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .good {
            color: green;
        }
        .warning {
            color: orange;
        }
        .critical {
            color: red;
        }
        .recommendation-list li {
            margin-bottom: 15px;
            padding: 10px;
            border-left: 4px solid #3498db;
            background-color: #f8f9fa;
        }
        .recommendation-list li.critical {
            border-left-color: #e74c3c;
        }
        .recommendation-list li.warning {
            border-left-color: #f39c12;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            font-size: 14px;
            color: #7f8c8d;
        }
        .refresh-controls {
            display: flex;
            align-items: center;
            margin-top: 10px;
        }
        .refresh-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 15px;
        }
        .refresh-btn:hover {
            background-color: #2980b9;
        }
        @media print {
            body {
                background-color: white;
                padding: 0;
            }
            .section {
                box-shadow: none;
                border: 1px solid #ddd;
            }
            .refresh-controls, .actions {
                display: none;
            }
        }
    </style>
</head>
<body>
    <h1>Performance Test Report</h1>
    
    <div class="section">
        <h2>Test Information</h2>
        <p><strong>Environment:</strong> $ENVIRONMENT</p>
        <p><strong>Test Date:</strong> $(date)</p>
        <p><strong>Base URL:</strong> $APP_URL</p>
        <p><strong>Concurrent Users:</strong> $CONCURRENT_USERS</p>
        <p><strong>Duration:</strong> $DURATION seconds</p>
        <p><strong>Region:</strong> ${REGION:-"Default"}</p>
        <div class="refresh-controls">
            <span>Last Update: <span id="lastUpdate">$(date +%H:%M:%S)</span></span>
            <div style="margin-left: auto; display: flex; align-items: center;">
                <button id="refreshData" class="refresh-btn">
                    <span class="spinner-border d-none" role="status" style="width: 1rem; height: 1rem;"></span>
                    <i class="bi-arrow-clockwise"></i> Refresh
                </button>
                <div style="margin-left: 10px;">
                    <input type="checkbox" id="autoRefreshToggle"> 
                    <label for="autoRefreshToggle">Auto refresh (5 min)</label>
                </div>
            </div>
        </div>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <div>Total Endpoints</div>
            <div class="summary-value" id="totalEndpoints">6</div>
        </div>
        <div class="summary-item">
            <div>Avg Response Time</div>
            <div class="summary-value" id="avgResponseTime">
                $(
                    total=0
                    count=0
                    for data in "$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data"; do
                        if [ -n "$data" ]; then
                            mean=$(echo "$data" | cut -d',' -f3)
                            total=$(echo "$total + $mean" | bc)
                            count=$((count+1))
                        fi
                    done
                    if [ $count -gt 0 ]; then
                        echo "scale=1; $total / $count" | bc
                    else
                        echo "N/A"
                    fi
                ) ms
            </div>
        </div>
        <div class="summary-item">
            <div>Avg Error Rate</div>
            <div class="summary-value" id="avgErrorRate">
                $(
                    total=0
                    count=0
                    for data in "$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data"; do
                        if [ -n "$data" ]; then
                            rate=$(echo "$data" | cut -d',' -f7)
                            total=$(echo "$total + $rate" | bc)
                            count=$((count+1))
                        fi
                    done
                    if [ $count -gt 0 ]; then
                        echo "scale=2; $total / $count" | bc
                    else
                        echo "N/A"
                    fi
                )%
            </div>
        </div>
        <div class="summary-item">
            <div>Status</div>
            <div class="summary-value" id="overallStatus">
                $(
                    has_critical=false
                    has_warning=false
                    
                    for data in "$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data"; do
                        if [ -n "$data" ]; then
                            error_rate=$(echo "$data" | cut -d',' -f7)
                            p95=$(echo "$data" | cut -d',' -f5)
                            
                            if (( $(echo "$error_rate > 5" | bc -l) )); then
                                has_critical=true
                            elif (( $(echo "$p95 > 500" | bc -l) )); then
                                has_warning=true
                            fi
                        fi
                    done
                    
                    if [ "$has_critical" = true ]; then
                        echo '<span class="critical">Critical</span>'
                    elif [ "$has_warning" = true ]; then
                        echo '<span class="warning">Warning</span>'
                    else
                        echo '<span class="good">Good</span>'
                    fi
                )
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Endpoint Performance</h2>
        <table>
            <tr>
                <th>Endpoint</th>
                <th>Requests/sec</th>
                <th>Mean (ms)</th>
                <th>P50 (ms)</th>
                <th>P95 (ms)</th>
                <th>P99 (ms)</th>
                <th>Error Rate</th>
                <th>Status</th>
            </tr>
EOF

# Add endpoint data rows
for data in "$health_data" "$static_data" "$version_data" "$auth_data" "$resources_data" "$login_data"; do
    if [ -n "$data" ]; then
        IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$data"
        
        # Determine status based on thresholds
        if (( $(echo "$error_rate > 5" | bc -l) )); then
            status="<span class=\"critical\">Critical</span>"
        elif (( $(echo "$error_rate > 0" | bc -l) )) || (( $(echo "$p95 > 500" | bc -l) )); then
            status="<span class=\"warning\">Warning</span>"
        else
            status="<span class=\"good\">Good</span>"
        fi
        
        cat >> "$REPORT_FILE" << EOF
            <tr>
                <td>$endpoint</td>
                <td>$rps</td>
                <td>$mean_time</td>
                <td>$p50</td>
                <td>$p95</td>
                <td>$p99</td>
                <td>$error_rate%</td>
                <td>$status</td>
            </tr>
EOF
    fi
done

cat >> "$REPORT_FILE" << EOF
        </table>
    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <p><strong>Server:</strong> $(hostname)</p>
        <p><strong>CPU Model:</strong> $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//')</p>
        <p><strong>Memory:</strong> $(free -h | grep Mem | awk '{print $2}')</p>
        <p><strong>Load Average:</strong> $(uptime | awk -F'[a-z]:' '{print $2}' | xargs)</p>
        <p><strong>System Performance:</strong> ${system_data:-"No monitoring data available"}</p>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul class="recommendation-list">
EOF

if [ ${#recommendations[@]} -eq 0 ]; then
    cat >> "$REPORT_FILE" << EOF
            <li class="good">All endpoints are performing within acceptable parameters.</li>
EOF
else
    for rec in "${recommendations[@]}"; do
        # Extract severity from recommendation text
        severity="warning"
        if [[ "$rec" == Critical:* ]]; then
            severity="critical"
        fi
        
        cat >> "$REPORT_FILE" << EOF
            <li class="$severity">$rec</li>
EOF
        
        # Count critical items for exit status
        if [[ "$severity" == "critical" ]]; then
            exit_code=2
        elif [[ "$severity" == "warning" && $exit_code -ne 2 ]]; then
            exit_code=1
        fi
    done
fi

cat >> "$REPORT_FILE" << EOF
        </ul>
    </div>
EOF

# Add historical comparison if available
compare_with_historical

cat >> "$REPORT_FILE" << EOF
    <div class="footer">
        <p>Generated by Cloud Platform Performance Test Suite v1.2</p>
        <p>$(date)</p>
    </div>
    
    <script>
        // Auto-refresh functionality
        let autoRefreshInterval;
        const AUTO_REFRESH_INTERVAL = ${AUTO_REFRESH_INTERVAL};
        
        document.addEventListener('DOMContentLoaded', function() {
            setupRefreshButton();
            setupAutoRefresh();
        });
        
        function setupRefreshButton() {
            const refreshBtn = document.getElementById('refreshData');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', function() {
                    location.reload();
                });
            }
        }
        
        function setupAutoRefresh() {
            const toggle = document.getElementById('autoRefreshToggle');
            if (toggle) {
                toggle.addEventListener('change', function() {
                    if (this.checked) {
                        startAutoRefresh();
                    } else {
                        stopAutoRefresh();
                    }
                });
            }
        }
        
        function startAutoRefresh() {
            stopAutoRefresh(); // Clear any existing interval
            autoRefreshInterval = setInterval(function() {
                location.reload();
            }, AUTO_REFRESH_INTERVAL);
        }
        
        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
            }
        }
    </script>
</body>
</html>
EOF

log "HTML report saved to $REPORT_FILE"

# Generate JSON report
if [ "$OUTPUT_FORMAT" = "json" ]; then
    generate_json_report
fi

# Export metrics to Prometheus if possible
export_prometheus_metrics

# Log to DR events system if requested
if [ "$DR_MODE" = true ]; then
    if [ -d "/var/log/cloud-platform" ]; then
        # Log performance test execution to DR events log
        mkdir -p "/var/log/cloud-platform"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),PERFORMANCE_TEST,${ENVIRONMENT},${APP_URL#*://},$([ $exit_code -eq 0 ] && echo 'SUCCESS' || echo 'WARNING')" >> "/var/log/cloud-platform/dr-events.log"
        log "Performance test result logged to DR events log"
    fi
fi

# Send notification
send_notification

log "Performance tests completed. Report saved to $REPORT_FILE"

# Add temporary files to an array for cleanup
TEMP_FILES=()

cleanup() {
    log "Cleaning up temporary files"
    for file in "${TEMP_FILES[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
        fi
    done
}

# Register cleanup function to run on exit
trap cleanup EXIT

exit $exit_code