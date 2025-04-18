#!/bin/bash
# Performance test script for Cloud Infrastructure Platform
# Tests API performance under load and generates reports
# Usage: ./performance-test.sh [environment]

set -e

# Default settings
ENVIRONMENT=${1:-development}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPORT_DIR="/var/www/reports/performance"
CONCURRENT_USERS=${CONCURRENT_USERS:-10}
DURATION=${DURATION:-30}
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="${REPORT_DIR}/performance-${ENVIRONMENT}-${TIMESTAMP}.html"

# Ensure report directory exists
mkdir -p "$REPORT_DIR"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

# Ensure required tools are installed
for cmd in ab curl jq; do
    if ! command -v $cmd &>/dev/null; then
        log "Error: Required command '$cmd' not found. Please install it and try again."
        exit 1
    fi
done

# Create report directory if it doesn't exist
mkdir -p "$REPORT_DIR"

log "Starting performance tests for ${ENVIRONMENT} environment"
log "Duration: ${DURATION} seconds, Concurrent Users: ${CONCURRENT_USERS}"

# Load environment-specific variables
if [ -f "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env" ]; then
    source "${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
fi

# Set default URL if not defined in environment file
APP_URL=${APP_URL:-"http://localhost:5000"}
log "Testing application at $APP_URL"

# Initialize HTML report
cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - ${ENVIRONMENT} - ${TIMESTAMP}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .section { margin-bottom: 30px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .good { color: green; }
        .warning { color: orange; }
        .critical { color: red; }
    </style>
</head>
<body>
    <h1>Cloud Infrastructure Platform - Performance Test Report</h1>
    <p><strong>Environment:</strong> ${ENVIRONMENT}</p>
    <p><strong>Date:</strong> $(date)</p>
    <p><strong>Duration:</strong> ${DURATION} seconds</p>
    <p><strong>Concurrent Users:</strong> ${CONCURRENT_USERS}</p>
    
    <div class="section">
        <h2>Test Results</h2>
        <table>
            <tr>
                <th>Endpoint</th>
                <th>Requests/sec</th>
                <th>Mean Time (ms)</th>
                <th>P50 (ms)</th>
                <th>P95 (ms)</th>
                <th>P99 (ms)</th>
                <th>Error Rate</th>
            </tr>
EOF

# Function to test an endpoint and return the results
test_endpoint() {
    local endpoint="$1"
    local description="$2"
    local method="${3:-GET}"
    local data="${4:-}"
    local content_type="${5:-}"
    
    local temp_file=$(mktemp)
    local url="${APP_URL}${endpoint}"
    local ab_opts="-c ${CONCURRENT_USERS} -t ${DURATION} -v 2"
    
    log "Testing ${method} ${url} (${description})"
    
    # Add options for POST/PUT requests
    if [ "$method" != "GET" ]; then
        if [ -n "$data" ]; then
            echo "$data" > "${temp_file}"
            ab_opts="${ab_opts} -p ${temp_file}"
            
            if [ -n "$content_type" ]; then
                ab_opts="${ab_opts} -T $content_type"
            fi
        fi
        ab_opts="${ab_opts} -m ${method}"
    fi
    
    # Run Apache Bench
    ab $ab_opts "$url" > "${temp_file}.out" 2>&1
    
    if [ $? -ne 0 ]; then
        log "Warning: ab command failed for ${url}"
        cat "${temp_file}.out"
        rm "${temp_file}"* 2>/dev/null
        echo "${endpoint},0,0,0,0,0,100.0"
        return 1
    fi
    
    # Extract metrics
    reqs_per_sec=$(grep -E "Requests per second" "${temp_file}.out" | awk '{print $4}')
    mean_time=$(grep -E "Time per request" "${temp_file}.out" | head -1 | awk '{print $4}')
    p50_time=$(grep -E "50%" "${temp_file}.out" | awk '{print $2}')
    p95_time=$(grep -E "95%" "${temp_file}.out" | awk '{print $2}')
    p99_time=$(grep -E "99%" "${temp_file}.out" | awk '{print $2}')
    
    # Calculate error rate
    complete_reqs=$(grep -E "Complete requests" "${temp_file}.out" | awk '{print $3}')
    failed_reqs=$(grep -E "Failed requests" "${temp_file}.out" | awk '{print $3}')
    non_2xx_reqs=$(grep -E "Non-2xx responses" "${temp_file}.out" | awk '{print $3}' || echo "0")
    
    if [ -z "$non_2xx_reqs" ]; then
        non_2xx_reqs=0
    fi
    
    total_errors=$((failed_reqs + non_2xx_reqs))
    if [ "$complete_reqs" -gt 0 ]; then
        error_rate=$(echo "scale=1; 100 * $total_errors / $complete_reqs" | bc)
    else
        error_rate="100.0"
    fi
    
    # Add row to HTML report
    cat >> "$REPORT_FILE" <<EOF
            <tr>
                <td>${endpoint}</td>
                <td>${reqs_per_sec}</td>
                <td>${mean_time}</td>
                <td>${p50_time}</td>
                <td>${p95_time}</td>
                <td>${p99_time}</td>
                <td>${error_rate}%</td>
            </tr>
EOF

    # Cleanup
    rm "${temp_file}"* 2>/dev/null
    
    # Return CSV for later analysis
    echo "${endpoint},${reqs_per_sec},${mean_time},${p50_time},${p95_time},${p99_time},${error_rate}"
}

# Test essential endpoints
log "Testing API Health endpoint"
health_data=$(test_endpoint "/api/health" "API Health Check")

log "Testing Static Content"
static_data=$(test_endpoint "/static/css/main.css" "Static Content Delivery")

log "Testing API Version endpoint"
version_data=$(test_endpoint "/api/version" "API Version Information")

log "Testing API Authentication status"
auth_data=$(test_endpoint "/api/auth/status" "Authentication Status Check")

log "Testing API Resources endpoint"
resources_data=$(test_endpoint "/api/resources" "Resources List API")

# Test a POST endpoint if available
log "Testing Login endpoint"
login_data=$(test_endpoint "/api/auth/login" "Authentication API" "POST" '{"username":"test@example.com","password":"password123"}' "application/json")

# Finalize HTML report
cat >> "$REPORT_FILE" <<EOF
        </table>
    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <p><strong>CPU:</strong> $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//')</p>
        <p><strong>Memory:</strong> $(free -h | awk '/^Mem:/{print $2}') total, $(free -h | awk '/^Mem:/{print $4}') available</p>
        <p><strong>Load Average:</strong> $(uptime | awk -F'[a-z]:' '{print $2}')</p>
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        <ul>
EOF

# Add recommendations based on results
add_recommendation() {
    local endpoint="$1"
    local rps="$2"
    local p95="$3"
    local error_rate="$4"
    
    if (( $(echo "$error_rate > 1" | bc -l) )); then
        cat >> "$REPORT_FILE" <<EOF
            <li class="critical">High error rate (${error_rate}%) for endpoint ${endpoint} - investigate errors in application logs</li>
EOF
    fi
    
    if (( $(echo "$p95 > 1000" | bc -l) )); then
        cat >> "$REPORT_FILE" <<EOF
            <li class="warning">Slow response time (P95 = ${p95}ms) for endpoint ${endpoint} - optimize database queries or increase caching</li>
EOF
    fi
    
    if (( $(echo "$rps < 10" | bc -l) )); then
        cat >> "$REPORT_FILE" <<EOF
            <li class="warning">Low throughput (${rps} req/sec) for endpoint ${endpoint} - investigate performance bottlenecks</li>
EOF
    fi
}

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$health_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$static_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$version_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$auth_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$resources_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

IFS=',' read -r endpoint rps mean_time p50 p95 p99 error_rate <<< "$login_data"
add_recommendation "$endpoint" "$rps" "$p95" "$error_rate"

# Default recommendation if none added
grep -q "<li class=" "$REPORT_FILE" || cat >> "$REPORT_FILE" <<EOF
            <li class="good">No performance issues detected</li>
EOF

# Complete the HTML report
cat >> "$REPORT_FILE" <<EOF
        </ul>
    </div>
</body>
</html>
EOF

log "Performance tests completed. Report saved to $REPORT_FILE"