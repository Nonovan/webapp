#!/bin/bash
# Status Reporter for Cloud Infrastructure Platform
# Aggregates monitoring data into comprehensive reports
# Usage: ./status_reporter.sh [environment] [options]

set -e

# Default settings
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
REPORT_DIR="/var/lib/reports"
METRICS_DIR="/var/lib/metrics"
REPORT_FORMAT="html"  # html, json, or text
QUIET=false
VERBOSE=false
EMAIL_RECIPIENT=""
COMPONENTS="all"  # all, system, application, database, network, security
REGION="primary"
HISTORY_DAYS=7
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE=""
SUMMARY_ONLY=false
INCLUDE_RECOMMENDATIONS=true
DR_MODE=false
THRESHOLD_WARNINGS=true
SEND_NOTIFICATION=false

# Source common utilities if available
if [[ -f "${PROJECT_ROOT}/scripts/monitoring/common/logging_utils.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/monitoring/common/logging_utils.sh"
fi

# Function to log messages if not sourced from logging_utils.sh
if ! command -v log_info &> /dev/null; then
    # Define colors for terminal output
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color

    log() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local message="[$timestamp] $1"
        local level="${2:-INFO}"

        if [[ "$QUIET" != "true" || "$level" == "ERROR" || "$level" == "CRITICAL" ]]; then
            case "$level" in
                INFO)     echo -e "${GREEN}${message}${NC}" ;;
                WARNING)  echo -e "${YELLOW}${message}${NC}" ;;
                ERROR)    echo -e "${RED}${message}${NC}" ;;
                CRITICAL) echo -e "${RED}${message}${NC}" ;;
                DEBUG)    if [[ "$VERBOSE" == "true" ]]; then echo -e "${BLUE}${message}${NC}"; fi ;;
                *)        echo "${message}" ;;
            esac
        fi

        # Log to file
        echo "[$timestamp] [$level] $1" >> "${LOG_DIR}/status-reporter.log"
    }
fi

# Parse command line arguments
shift_count=0
if [[ ! -z "$1" && "$1" != --* ]]; then
    shift_count=1  # Skip the environment parameter in the while loop
fi

while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --format)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        --components)
            COMPONENTS="$2"
            shift 2
            ;;
        --output)
            REPORT_FILE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --history)
            HISTORY_DAYS="$2"
            shift 2
            ;;
        --summary-only)
            SUMMARY_ONLY=true
            shift
            ;;
        --no-recommendations)
            INCLUDE_RECOMMENDATIONS=false
            shift
            ;;
        --notify)
            SEND_NOTIFICATION=true
            if [[ ! -z "${2}" && "${2}" != --* ]]; then
                EMAIL_RECIPIENT="${2}"
                shift
            fi
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --no-threshold-warnings)
            THRESHOLD_WARNINGS=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --help)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --format FORMAT          Report format: html, json, or text (default: html)"
            echo "  --components COMPONENTS  Components to include: all, system, application, database, network, security"
            echo "                           Comma-separated for multiple components (default: all)"
            echo "  --output FILE            Output file path (default: auto-generated)"
            echo "  --region REGION          Region to report on: primary or secondary (default: primary)"
            echo "  --history DAYS           Number of days of history to include (default: 7)"
            echo "  --summary-only           Only include summary information"
            echo "  --no-recommendations     Don't include recommendations in the report"
            echo "  --notify [EMAIL]         Send notification with report"
            echo "  --dr-mode                Log to DR events system"
            echo "  --no-threshold-warnings  Don't include threshold warnings"
            echo "  --verbose                Verbose output"
            echo "  --quiet                  Minimal output"
            echo "  --help                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Ensure directories exist
mkdir -p "$LOG_DIR" "$REPORT_DIR" 2>/dev/null || true

# Set default report file if not specified
if [[ -z "$REPORT_FILE" ]]; then
    mkdir -p "$REPORT_DIR/${ENVIRONMENT}" 2>/dev/null || true
    REPORT_FILE="${REPORT_DIR}/${ENVIRONMENT}/status-report-${REGION}-${TIMESTAMP}.${REPORT_FORMAT}"
fi

# Function to run a command and capture output and status
run_command() {
    local cmd="$1"
    local output_file="$2"
    local timeout_seconds="${3:-60}"

    log "Running: $cmd" "DEBUG"

    # Run command with timeout
    timeout $timeout_seconds bash -c "$cmd" > "$output_file" 2>&1
    local status=$?

    if [[ $status -eq 0 ]]; then
        log "Command succeeded" "DEBUG"
        return 0
    elif [[ $status -eq 124 ]]; then
        log "Command timed out after $timeout_seconds seconds" "WARNING"
        echo "COMMAND TIMED OUT AFTER $timeout_seconds SECONDS" >> "$output_file"
        return 124
    else
        log "Command failed with status $status" "WARNING"
        return $status
    fi
}

# Function to collect system metrics
collect_system_metrics() {
    local temp_file="/tmp/system-metrics-${TIMESTAMP}.txt"
    log "Collecting system metrics..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/monitoring/core/metric_collector.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/monitoring/core/metric_collector.sh ${ENVIRONMENT} --output-format json --collect system --quiet" "$temp_file"
        echo "$temp_file"
        return 0
    else
        log "Metric collector script not found or not executable" "WARNING"
        echo "{\"error\": \"Metric collector script not available\"}" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect health check data
collect_health_check() {
    local temp_file="/tmp/health-check-${TIMESTAMP}.json"
    log "Collecting health check data..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/monitoring/core/health-check.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/monitoring/core/health-check.sh ${ENVIRONMENT} --region ${REGION} --format json" "$temp_file"
        echo "$temp_file"
        return 0
    else
        log "Health check script not found or not executable" "WARNING"
        echo "{\"error\": \"Health check script not available\"}" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect resource monitoring data
collect_resource_data() {
    local temp_file="/tmp/resource-data-${TIMESTAMP}.txt"
    log "Collecting resource monitoring data..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/monitoring/core/resource_monitor.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/monitoring/core/resource_monitor.sh --duration 60 --interval 10 --report-file $temp_file --no-log --quiet" "$temp_file"
        echo "$temp_file"
        return 0
    else
        log "Resource monitor script not found" "WARNING"
        echo "Resource monitoring data not available" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect API latency data
collect_api_latency() {
    local temp_file="/tmp/api-latency-${TIMESTAMP}.json"
    log "Collecting API latency data..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/monitoring/core/api_latency.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/monitoring/core/api_latency.sh ${ENVIRONMENT} --region ${REGION} --format json" "$temp_file"
        echo "$temp_file"
        return 0
    else
        log "API latency script not found" "WARNING"
        echo "{\"error\": \"API latency script not available\"}" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect connectivity check data
collect_connectivity_data() {
    local temp_file="/tmp/connectivity-${TIMESTAMP}.json"
    log "Collecting connectivity data..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/monitoring/core/connectivity_check.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/monitoring/core/connectivity_check.sh ${ENVIRONMENT} --region ${REGION} --format json" "$temp_file"
        echo "$temp_file"
        return 0
    else
        log "Connectivity check script not found" "WARNING"
        echo "{\"error\": \"Connectivity check script not available\"}" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect security data
collect_security_data() {
    local temp_file="/tmp/security-${TIMESTAMP}.json"
    log "Collecting security data..." "INFO"

    if [[ -x "${PROJECT_ROOT}/scripts/security/check_permissions.sh" ]]; then
        run_command "${PROJECT_ROOT}/scripts/security/check_permissions.sh --environment ${ENVIRONMENT} --format json --quiet" "$temp_file" 120
        echo "$temp_file"
        return 0
    else
        log "Security check script not found" "WARNING"
        echo "{\"error\": \"Security check script not available\"}" > "$temp_file"
        echo "$temp_file"
        return 1
    fi
}

# Function to collect historical metrics
collect_historical_metrics() {
    local days=$1
    local temp_file="/tmp/historical-metrics-${TIMESTAMP}.json"
    log "Collecting historical metrics for past $days days..." "INFO"

    # Create a JSON structure for historical metrics
    echo "{" > "$temp_file"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$temp_file"
    echo "  \"history_days\": $days," >> "$temp_file"
    echo "  \"metrics\": [" >> "$temp_file"

    # Check if metrics directory exists
    if [[ -d "$METRICS_DIR/$ENVIRONMENT" ]]; then
        # Find metrics files from past N days
        local metric_files=$(find "$METRICS_DIR/$ENVIRONMENT" -type f -name "*.json" -mtime -$days)
        local first=true

        for file in $metric_files; do
            # Skip adding comma for first item
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$temp_file"
            fi

            # Extract content without the outer braces
            cat "$file" | sed '1d;$d' >> "$temp_file"
        done
    else
        log "No historical metrics found in $METRICS_DIR/$ENVIRONMENT" "WARNING"
    fi

    # Close the JSON structure
    echo "" >> "$temp_file"
    echo "  ]" >> "$temp_file"
    echo "}" >> "$temp_file"

    echo "$temp_file"
}

# Function to extract recommendations from monitoring data
extract_recommendations() {
    local health_file="$1"
    local resource_file="$2"
    local api_file="$3"
    local security_file="$4"
    local output_file="/tmp/recommendations-${TIMESTAMP}.json"

    log "Generating recommendations..." "INFO"

    echo "{" > "$output_file"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$output_file"
    echo "  \"recommendations\": [" >> "$output_file"

    local first=true

    # Extract critical issues from health check
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        local health_issues=$(jq -r '.components[] | select(.status == "UNHEALTHY" or .status == "CRITICAL" or .status == "WARNING") | .component + ": " + .status' "$health_file" 2>/dev/null)

        if [[ -n "$health_issues" ]]; then
            while IFS= read -r issue; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo "," >> "$output_file"
                fi

                echo "    {" >> "$output_file"
                echo "      \"source\": \"Health Check\"," >> "$output_file"
                echo "      \"severity\": \"high\"," >> "$output_file"
                echo "      \"issue\": \"$issue\"," >> "$output_file"
                echo "      \"recommendation\": \"Investigate and resolve the health issue with $issue.\"" >> "$output_file"
                echo "    }" >> "$output_file"
            done <<< "$health_issues"
        fi
    fi

    # Extract resource utilization recommendations
    if [[ -f "$resource_file" ]]; then
        # Check for CPU threshold violations
        if grep -q "CPU usage exceeded threshold" "$resource_file"; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            echo "    {" >> "$output_file"
            echo "      \"source\": \"Resource Monitor\"," >> "$output_file"
            echo "      \"severity\": \"medium\"," >> "$output_file"
            echo "      \"issue\": \"High CPU utilization\"," >> "$output_file"
            echo "      \"recommendation\": \"Analyze top processes consuming CPU and consider resource allocation adjustments.\"" >> "$output_file"
            echo "    }" >> "$output_file"
        fi

        # Check for memory threshold violations
        if grep -q "Memory usage exceeded threshold" "$resource_file"; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            echo "    {" >> "$output_file"
            echo "      \"source\": \"Resource Monitor\"," >> "$output_file"
            echo "      \"severity\": \"medium\"," >> "$output_file"
            echo "      \"issue\": \"High memory utilization\"," >> "$output_file"
            echo "      \"recommendation\": \"Check for memory leaks and consider increasing available memory.\"" >> "$output_file"
            echo "    }" >> "$output_file"
        fi

        # Check for disk threshold violations
        if grep -q "Disk usage exceeded threshold" "$resource_file"; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            echo "    {" >> "$output_file"
            echo "      \"source\": \"Resource Monitor\"," >> "$output_file"
            echo "      \"severity\": \"medium\"," >> "$output_file"
            echo "      \"issue\": \"High disk utilization\"," >> "$output_file"
            echo "      \"recommendation\": \"Clean up unnecessary files or expand disk capacity.\"" >> "$output_file"
            echo "    }" >> "$output_file"
        fi
    fi

    # Extract API latency recommendations
    if [[ -f "$api_file" ]] && command -v jq &>/dev/null; then
        local api_issues=$(jq -r '.results[] | select(.status == "CRITICAL" or .status == "WARNING") | .name + " - " + .status + " (P95: " + .p95 + "ms)"' "$api_file" 2>/dev/null)

        if [[ -n "$api_issues" ]]; then
            while IFS= read -r issue; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo "," >> "$output_file"
                fi

                echo "    {" >> "$output_file"
                echo "      \"source\": \"API Latency\"," >> "$output_file"
                echo "      \"severity\": \"high\"," >> "$output_file"
                echo "      \"issue\": \"$issue\"," >> "$output_file"
                echo "      \"recommendation\": \"Optimize the endpoint performance or scale the service.\"" >> "$output_file"
                echo "    }" >> "$output_file"
            done <<< "$api_issues"
        fi
    fi

    # Extract security recommendations
    if [[ -f "$security_file" ]] && command -v jq &>/dev/null; then
        local security_issues=$(jq -r '.results[] | select(.severity == "CRITICAL" or .severity == "HIGH") | .title + " - " + .severity' "$security_file" 2>/dev/null)

        if [[ -n "$security_issues" ]]; then
            while IFS= read -r issue; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo "," >> "$output_file"
                fi

                echo "    {" >> "$output_file"
                echo "      \"source\": \"Security Check\"," >> "$output_file"
                echo "      \"severity\": \"critical\"," >> "$output_file"
                echo "      \"issue\": \"$issue\"," >> "$output_file"
                echo "      \"recommendation\": \"Address the security issue immediately to reduce vulnerability.\"" >> "$output_file"
                echo "    }" >> "$output_file"
            done <<< "$security_issues"
        fi
    fi

    # Close JSON structure
    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"

    echo "$output_file"
}

# Function to generate HTML report
generate_html_report() {
    local system_file="$1"
    local health_file="$2"
    local resource_file="$3"
    local api_file="$4"
    local connectivity_file="$5"
    local security_file="$6"
    local history_file="$7"
    local recommendations_file="$8"

    log "Generating HTML report..." "INFO"

    # Create HTML header
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Infrastructure Platform Status Report - ${ENVIRONMENT}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        header {
            background-color: #0078d4;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2, h3 {
            margin-top: 0;
        }
        .status-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }
        .status-card {
            flex: 1;
            min-width: 250px;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .healthy {
            background-color: #dff0d8;
            border-left: 5px solid #5cb85c;
        }
        .warning {
            background-color: #fcf8e3;
            border-left: 5px solid #f0ad4e;
        }
        .critical {
            background-color: #f2dede;
            border-left: 5px solid #d9534f;
        }
        .unknown {
            background-color: #e8eaed;
            border-left: 5px solid #777;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f5f5f5;
        }
        tr:hover {
            background-color: #f9f9f9;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 10px;
            font-size: 0.9em;
            color: #777;
        }
        .recommendation {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 4px;
        }
        .recommendation.critical {
            background-color: #f2dede;
        }
        .recommendation.high {
            background-color: #fcf8e3;
        }
        .recommendation.medium {
            background-color: #d9edf7;
        }
        .chart {
            height: 300px;
            margin-bottom: 20px;
        }
        .tabs {
            display: flex;
            margin-bottom: 15px;
        }
        .tab {
            padding: 10px 15px;
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-bottom: none;
            margin-right: 5px;
            cursor: pointer;
        }
        .tab.active {
            background-color: white;
            border-bottom: 2px solid #0078d4;
        }
        .tab-content {
            display: none;
            padding: 15px;
            border: 1px solid #ddd;
        }
        .tab-content.active {
            display: block;
        }
        .metric-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        .metric-card {
            flex: 1;
            min-width: 200px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #0078d4;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Cloud Infrastructure Platform Status Report</h1>
            <p>Environment: ${ENVIRONMENT} | Region: ${REGION} | Generated: $(date)</p>
        </header>
EOF

    # Determine overall status based on health check
    local overall_status="unknown"
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        local status=$(jq -r '.overall_status' "$health_file" 2>/dev/null)
        if [[ "$status" == "HEALTHY" ]]; then
            overall_status="healthy"
        elif [[ "$status" == "UNHEALTHY" ]]; then
            overall_status="critical"
        elif [[ "$status" == "WARNING" ]]; then
            overall_status="warning"
        fi
    fi

    # Add status summary
    cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Status Summary</h2>
            <div class="status-summary">
                <div class="status-card ${overall_status}">
                    <h3>Overall Status</h3>
                    <p>Status: ${overall_status^^}</p>
                </div>
EOF

    # Add component statuses
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        # Count components by status
        local healthy_count=$(jq -r '.components[] | select(.status == "HEALTHY") | .component' "$health_file" 2>/dev/null | wc -l)
        local warning_count=$(jq -r '.components[] | select(.status == "WARNING") | .component' "$health_file" 2>/dev/null | wc -l)
        local critical_count=$(jq -r '.components[] | select(.status == "UNHEALTHY" or .status == "CRITICAL") | .component' "$health_file" 2>/dev/null | wc -l)
        local skipped_count=$(jq -r '.components[] | select(.status == "SKIPPED" or .status == "NOT_APPLICABLE") | .component' "$health_file" 2>/dev/null | wc -l)

        cat >> "$REPORT_FILE" << EOF
                <div class="status-card healthy">
                    <h3>Healthy Components</h3>
                    <p>${healthy_count} components</p>
                </div>
                <div class="status-card warning">
                    <h3>Warning Components</h3>
                    <p>${warning_count} components</p>
                </div>
                <div class="status-card critical">
                    <h3>Critical Components</h3>
                    <p>${critical_count} components</p>
                </div>
                <div class="status-card unknown">
                    <h3>Skipped Components</h3>
                    <p>${skipped_count} components</p>
                </div>
EOF
    fi

    cat >> "$REPORT_FILE" << EOF
            </div>
        </div>
EOF

    # Add recommendations section if enabled
    if [[ "$INCLUDE_RECOMMENDATIONS" == "true" && -f "$recommendations_file" ]] && command -v jq &>/dev/null; then
        local rec_count=$(jq '.recommendations | length' "$recommendations_file" 2>/dev/null || echo "0")

        if [[ "$rec_count" -gt 0 ]]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Recommendations</h2>
EOF

            # Add each recommendation
            local recommendations=$(jq -c '.recommendations[]' "$recommendations_file" 2>/dev/null)
            while IFS= read -r rec; do
                local source=$(echo "$rec" | jq -r '.source')
                local severity=$(echo "$rec" | jq -r '.severity')
                local issue=$(echo "$rec" | jq -r '.issue')
                local recommendation=$(echo "$rec" | jq -r '.recommendation')

                cat >> "$REPORT_FILE" << EOF
            <div class="recommendation ${severity}">
                <h4>${source}: ${issue}</h4>
                <p><strong>Recommendation:</strong> ${recommendation}</p>
            </div>
EOF
            done <<< "$recommendations"

            cat >> "$REPORT_FILE" << EOF
        </div>
EOF
        fi
    fi

    # Only include detailed sections if not in summary-only mode
    if [[ "$SUMMARY_ONLY" != "true" ]]; then
        # Add health check section
        if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Health Check</h2>
            <table>
                <tr>
                    <th>Component</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>Critical</th>
                </tr>
EOF

            # Add each component from health check
            local components=$(jq -c '.components[]' "$health_file" 2>/dev/null)
            while IFS= read -r component; do
                local name=$(echo "$component" | jq -r '.component')
                local status=$(echo "$component" | jq -r '.status')
                local time=$(echo "$component" | jq -r '.time')
                local critical=$(echo "$component" | jq -r '.critical')
                local status_class="unknown"

                if [[ "$status" == "HEALTHY" ]]; then
                    status_class="healthy"
                elif [[ "$status" == "WARNING" ]]; then
                    status_class="warning"
                elif [[ "$status" == "UNHEALTHY" || "$status" == "CRITICAL" ]]; then
                    status_class="critical"
                fi

                cat >> "$REPORT_FILE" << EOF
                <tr class="${status_class}">
                    <td>${name}</td>
                    <td>${status}</td>
                    <td>${time}s</td>
                    <td>${critical}</td>
                </tr>
EOF
            done <<< "$components"

            cat >> "$REPORT_FILE" << EOF
            </table>
        </div>
EOF
        fi

        # Add system metrics section
        if [[ -f "$system_file" && "$COMPONENTS" == *"system"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>System Metrics</h2>
            <div class="metric-container">
EOF

            # Extract metrics if jq is available
            if command -v jq &>/dev/null; then
                # CPU usage
                local cpu_usage=$(jq -r '.metrics.cpu_usage_percent // "N/A"' "$system_file" 2>/dev/null)

                cat >> "$REPORT_FILE" << EOF
                <div class="metric-card">
                    <h3>CPU Usage</h3>
                    <div class="metric-value">${cpu_usage}%</div>
                </div>
EOF

                # Memory usage
                local mem_usage=$(jq -r '.metrics.memory_usage_percent // "N/A"' "$system_file" 2>/dev/null)

                cat >> "$REPORT_FILE" << EOF
                <div class="metric-card">
                    <h3>Memory Usage</h3>
                    <div class="metric-value">${mem_usage}%</div>
                </div>
EOF

                # Disk usage
                local disk_usage=$(jq -r '.metrics.disk_usage_percent // "N/A"' "$system_file" 2>/dev/null)

                cat >> "$REPORT_FILE" << EOF
                <div class="metric-card">
                    <h3>Disk Usage</h3>
                    <div class="metric-value">${disk_usage}%</div>
                </div>
EOF

                # Load average
                local load_avg=$(jq -r '.metrics.load_avg_1m // "N/A"' "$system_file" 2>/dev/null)

                cat >> "$REPORT_FILE" << EOF
                <div class="metric-card">
                    <h3>Load Average</h3>
                    <div class="metric-value">${load_avg}</div>
                </div>
EOF
            else
                # Fallback if jq is not available
                cat >> "$REPORT_FILE" << EOF
                <div class="metric-card">
                    <h3>System Metrics</h3>
                    <p>Detailed metrics not available. See raw data for details.</p>
                </div>
EOF
            fi

            cat >> "$REPORT_FILE" << EOF
            </div>

            <h3>Resource Utilization</h3>
            <pre>$(head -n 30 "$resource_file" | grep -v "===" | grep -v "---")</pre>
        </div>
EOF
        fi

        # Add API latency section
        if [[ -f "$api_file" && "$COMPONENTS" == *"application"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>API Performance</h2>
            <table>
                <tr>
                    <th>Endpoint</th>
                    <th>Method</th>
                    <th>Average (ms)</th>
                    <th>P95 (ms)</th>
                    <th>Error Rate</th>
                    <th>Status</th>
                </tr>
EOF

            # Add each API endpoint if jq is available
            if command -v jq &>/dev/null; then
                local endpoints=$(jq -c '.results[]' "$api_file" 2>/dev/null)
                while IFS= read -r endpoint; do
                    local name=$(echo "$endpoint" | jq -r '.name')
                    local path=$(echo "$endpoint" | jq -r '.path')
                    local method=$(echo "$endpoint" | jq -r '.method')
                    local avg=$(echo "$endpoint" | jq -r '.avg')
                    local p95=$(echo "$endpoint" | jq -r '.p95')
                    local error_rate=$(echo "$endpoint" | jq -r '.error_rate')
                    local status=$(echo "$endpoint" | jq -r '.status')
                    local status_class="unknown"

                    if [[ "$status" == "OK" ]]; then
                        status_class="healthy"
                    elif [[ "$status" == "WARNING" ]]; then
                        status_class="warning"
                    elif [[ "$status" == "CRITICAL" ]]; then
                        status_class="critical"
                    fi

                    cat >> "$REPORT_FILE" << EOF
                <tr class="${status_class}">
                    <td>${name} (${path})</td>
                    <td>${method}</td>
                    <td>${avg}</td>
                    <td>${p95}</td>
                    <td>${error_rate}%</td>
                    <td>${status}</td>
                </tr>
EOF
                done <<< "$endpoints"
            else
                # Fallback if jq is not available
                cat >> "$REPORT_FILE" << EOF
                <tr>
                    <td colspan="6">Detailed API metrics not available. See raw data for details.</td>
                </tr>
EOF
            fi

            cat >> "$REPORT_FILE" << EOF
            </table>
        </div>
EOF
        fi

        # Add connectivity section
        if [[ -f "$connectivity_file" && "$COMPONENTS" == *"network"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Network Connectivity</h2>
            <table>
                <tr>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Response Time</th>
                </tr>
EOF

            # Add connectivity test results if jq is available
            if command -v jq &>/dev/null; then
                local tests=$(jq -c '.tests[]' "$connectivity_file" 2>/dev/null)
                while IFS= read -r test; do
                    local component=$(echo "$test" | jq -r '.component')
                    local status=$(echo "$test" | jq -r '.status')
                    local time=$(echo "$test" | jq -r '.time // "N/A"')
                    local status_class="unknown"

                    if [[ "$status" == "PASSED" ]]; then
                        status_class="healthy"
                    elif [[ "$status" == "WARNING" ]]; then
                        status_class="warning"
                    elif [[ "$status" == "FAILED" ]]; then
                        status_class="critical"
                    fi

                    cat >> "$REPORT_FILE" << EOF
                <tr class="${status_class}">
                    <td>${component}</td>
                    <td>${status}</td>
                    <td>${time}</td>
                </tr>
EOF
                done <<< "$tests"
            else
                # Fallback if jq is not available
                cat >> "$REPORT_FILE" << EOF
                <tr>
                    <td colspan="3">Detailed connectivity data not available. See raw data for details.</td>
                </tr>
EOF
            fi

            cat >> "$REPORT_FILE" << EOF
            </table>
        </div>
EOF
        fi

        # Add security section
        if [[ -f "$security_file" && "$COMPONENTS" == *"security"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="section">
            <h2>Security Status</h2>
            <table>
                <tr>
                    <th>Component</th>
                    <th>Issue</th>
                    <th>Severity</th>
                </tr>
EOF

            # Add security issues if jq is available
            if command -v jq &>/dev/null; then
                local issues=$(jq -c '.results[]' "$security_file" 2>/dev/null)
                while IFS= read -r issue; do
                    local component=$(echo "$issue" | jq -r '.component')
                    local title=$(echo "$issue" | jq -r '.title')
                    local severity=$(echo "$issue" | jq -r '.severity')
                    local severity_class="unknown"

                    if [[ "$severity" == "LOW" ]]; then
                        severity_class="healthy"
                    elif [[ "$severity" == "MEDIUM" ]]; then
                        severity_class="warning"
                    elif [[ "$severity" == "HIGH" || "$severity" == "CRITICAL" ]]; then
                        severity_class="critical"
                    fi

                    cat >> "$REPORT_FILE" << EOF
                <tr class="${severity_class}">
                    <td>${component}</td>
                    <td>${title}</td>
                    <td>${severity}</td>
                </tr>
EOF
                done <<< "$issues"
            else
                # Fallback if jq is not available
                cat >> "$REPORT_FILE" << EOF
                <tr>
                    <td colspan="3">Detailed security data not available. See raw data for details.</td>
                </tr>
EOF
            fi

            cat >> "$REPORT_FILE" << EOF
            </table>
        </div>
EOF
        fi
    fi

    # Add footer
    cat >> "$REPORT_FILE" << EOF
        <div class="footer">
            <p>Cloud Infrastructure Platform Status Report - Generated on $(date)</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Function to generate JSON report
generate_json_report() {
    local system_file="$1"
    local health_file="$2"
    local resource_file="$3"
    local api_file="$4"
    local connectivity_file="$5"
    local security_file="$6"
    local history_file="$7"
    local recommendations_file="$8"

    log "Generating JSON report..." "INFO"

    # Create JSON structure
    echo "{" > "$REPORT_FILE"
    echo "  \"metadata\": {" >> "$REPORT_FILE"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
    echo "    \"environment\": \"$ENVIRONMENT\"," >> "$REPORT_FILE"
    echo "    \"region\": \"$REGION\"," >> "$REPORT_FILE"
    echo "    \"hostname\": \"$(hostname)\"" >> "$REPORT_FILE"
    echo "  }," >> "$REPORT_FILE"

    # Add health check data if available
    if [[ -f "$health_file" ]]; then
        echo "  \"health\": $(cat "$health_file")," >> "$REPORT_FILE"
    else
        echo "  \"health\": { \"error\": \"Health check data not available\" }," >> "$REPORT_FILE"
    fi

    # Add system metrics if available and requested
    if [[ -f "$system_file" && "$COMPONENTS" == *"system"* || "$COMPONENTS" == "all" ]]; then
        echo "  \"system\": $(cat "$system_file")," >> "$REPORT_FILE"
    fi

    # Add API metrics if available and requested
    if [[ -f "$api_file" && "$COMPONENTS" == *"application"* || "$COMPONENTS" == "all" ]]; then
        echo "  \"api\": $(cat "$api_file")," >> "$REPORT_FILE"
    fi

    # Add connectivity data if available and requested
    if [[ -f "$connectivity_file" && "$COMPONENTS" == *"network"* || "$COMPONENTS" == "all" ]]; then
        echo "  \"connectivity\": $(cat "$connectivity_file")," >> "$REPORT_FILE"
    fi

    # Add security data if available and requested
    if [[ -f "$security_file" && "$COMPONENTS" == *"security"* || "$COMPONENTS" == "all" ]]; then
        echo "  \"security\": $(cat "$security_file")," >> "$REPORT_FILE"
    fi

    # Add historical data if available
    if [[ -f "$history_file" ]]; then
        echo "  \"history\": $(cat "$history_file")," >> "$REPORT_FILE"
    fi

    # Add recommendations if available and enabled
    if [[ "$INCLUDE_RECOMMENDATIONS" == "true" && -f "$recommendations_file" ]]; then
        echo "  \"recommendations\": $(cat "$recommendations_file")" >> "$REPORT_FILE"
    else
        echo "  \"recommendations\": { \"recommendations\": [] }" >> "$REPORT_FILE"
    fi

    # Close JSON structure
    echo "}" >> "$REPORT_FILE"

    # Validate JSON if jq is available
    if command -v jq &>/dev/null; then
        if ! jq '.' "$REPORT_FILE" >/dev/null 2>&1; then
            log "WARNING: Generated JSON may be invalid" "WARNING"
        else
            log "JSON report validated" "DEBUG"
        fi
    fi
}

# Function to generate text report
generate_text_report() {
    local system_file="$1"
    local health_file="$2"
    local resource_file="$3"
    local api_file="$4"
    local connectivity_file="$5"
    local security_file="$6"
    local history_file="$7"
    local recommendations_file="$8"

    log "Generating text report..." "INFO"

    # Create header
    cat > "$REPORT_FILE" << EOF
CLOUD INFRASTRUCTURE PLATFORM STATUS REPORT
===========================================
Environment: $ENVIRONMENT
Region: $REGION
Generated: $(date)

EOF

    # Add overall status based on health check
    local overall_status="UNKNOWN"
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        overall_status=$(jq -r '.overall_status' "$health_file" 2>/dev/null || echo "UNKNOWN")
    fi

    cat >> "$REPORT_FILE" << EOF
OVERALL STATUS: $overall_status
===========================================

EOF

    # Add recommendations if enabled
    if [[ "$INCLUDE_RECOMMENDATIONS" == "true" && -f "$recommendations_file" ]] && command -v jq &>/dev/null; then
        local rec_count=$(jq '.recommendations | length' "$recommendations_file" 2>/dev/null || echo "0")

        if [[ "$rec_count" -gt 0 ]]; then
            cat >> "$REPORT_FILE" << EOF
RECOMMENDATIONS:
---------------
EOF

            local recommendations=$(jq -c '.recommendations[]' "$recommendations_file" 2>/dev/null)
            while IFS= read -r rec; do
                local source=$(echo "$rec" | jq -r '.source')
                local severity=$(echo "$rec" | jq -r '.severity')
                local issue=$(echo "$rec" | jq -r '.issue')
                local recommendation=$(echo "$rec" | jq -r '.recommendation')

                cat >> "$REPORT_FILE" << EOF
[$source - ${severity^^}] $issue
  Recommendation: $recommendation

EOF
            done <<< "$recommendations"
        fi
    fi

    # Only include detailed sections if not in summary-only mode
    if [[ "$SUMMARY_ONLY" != "true" ]]; then
        # Add health check summary
        if [[ -f "$health_file" ]]; then
            cat >> "$REPORT_FILE" << EOF
HEALTH CHECK:
------------
EOF

            if command -v jq &>/dev/null; then
                local components=$(jq -c '.components[]' "$health_file" 2>/dev/null)
                while IFS= read -r component; do
                    local name=$(echo "$component" | jq -r '.component')
                    local status=$(echo "$component" | jq -r '.status')
                    local time=$(echo "$component" | jq -r '.time')
                    local critical=$(echo "$component" | jq -r '.critical')
                    local critical_str=""

                    if [[ "$critical" == "true" ]]; then
                        critical_str=" (CRITICAL)"
                    fi

                    printf "%-30s %-10s %-10s%s\n" "$name" "$status" "${time}s" "$critical_str" >> "$REPORT_FILE"
                done <<< "$components"
            else
                echo "Detailed health check data not available. See raw JSON for details." >> "$REPORT_FILE"
            fi

            echo "" >> "$REPORT_FILE"
        fi

        # Add system metrics if requested
        if [[ -f "$resource_file" && "$COMPONENTS" == *"system"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
SYSTEM METRICS:
--------------
EOF

            # Extract key metrics from resource monitoring
            grep -E "CPU Usage|Memory Usage|Disk Usage|Load Average" "$resource_file" | head -n 10 >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi

        # Add API metrics if requested
        if [[ -f "$api_file" && "$COMPONENTS" == *"application"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
API PERFORMANCE:
--------------
EOF

            if command -v jq &>/dev/null; then
                local endpoints=$(jq -c '.results[]' "$api_file" 2>/dev/null)
                # Print header
                printf "%-30s %-10s %-10s %-10s %-10s\n" "ENDPOINT" "METHOD" "AVG (ms)" "P95 (ms)" "STATUS" >> "$REPORT_FILE"
                printf "%-30s %-10s %-10s %-10s %-10s\n" "--------" "------" "--------" "--------" "------" >> "$REPORT_FILE"

                while IFS= read -r endpoint; do
                    local name=$(echo "$endpoint" | jq -r '.name')
                    local method=$(echo "$endpoint" | jq -r '.method')
                    local avg=$(echo "$endpoint" | jq -r '.avg')
                    local p95=$(echo "$endpoint" | jq -r '.p95')
                    local status=$(echo "$endpoint" | jq -r '.status')

                    printf "%-30s %-10s %-10s %-10s %-10s\n" "$name" "$method" "$avg" "$p95" "$status" >> "$REPORT_FILE"
                done <<< "$endpoints"
            else
                echo "Detailed API metrics not available. See raw JSON for details." >> "$REPORT_FILE"
            fi

            echo "" >> "$REPORT_FILE"
        fi

        # Add connectivity data if requested
        if [[ -f "$connectivity_file" && "$COMPONENTS" == *"network"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
NETWORK CONNECTIVITY:
------------------
EOF

            if command -v jq &>/dev/null; then
                local tests=$(jq -c '.tests[]' "$connectivity_file" 2>/dev/null)
                # Print header
                printf "%-30s %-10s %-10s\n" "SERVICE" "STATUS" "TIME" >> "$REPORT_FILE"
                printf "%-30s %-10s %-10s\n" "-------" "------" "----" >> "$REPORT_FILE"

                while IFS= read -r test; do
                    local component=$(echo "$test" | jq -r '.component')
                    local status=$(echo "$test" | jq -r '.status')
                    local time=$(echo "$test" | jq -r '.time // "N/A"')

                    printf "%-30s %-10s %-10s\n" "$component" "$status" "$time" >> "$REPORT_FILE"
                done <<< "$tests"
            else
                echo "Detailed connectivity data not available. See raw JSON for details." >> "$REPORT_FILE"
            fi

            echo "" >> "$REPORT_FILE"
        fi

        # Add security status if requested
        if [[ -f "$security_file" && "$COMPONENTS" == *"security"* || "$COMPONENTS" == "all" ]]; then
            cat >> "$REPORT_FILE" << EOF
SECURITY STATUS:
--------------
EOF

            if command -v jq &>/dev/null; then
                # Count issues by severity
                local critical=$(jq '.results[] | select(.severity == "CRITICAL") | .severity' "$security_file" 2>/dev/null | wc -l)
                local high=$(jq '.results[] | select(.severity == "HIGH") | .severity' "$security_file" 2>/dev/null | wc -l)
                local medium=$(jq '.results[] | select(.severity == "MEDIUM") | .severity' "$security_file" 2>/dev/null | wc -l)
                local low=$(jq '.results[] | select(.severity == "LOW") | .severity' "$security_file" 2>/dev/null | wc -l)

                echo "Security Issues Summary:" >> "$REPORT_FILE"
                echo "  Critical: $critical" >> "$REPORT_FILE"
                echo "  High:     $high" >> "$REPORT_FILE"
                echo "  Medium:   $medium" >> "$REPORT_FILE"
                echo "  Low:      $low" >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"

                # List critical and high issues
                if [[ $critical -gt 0 || $high -gt 0 ]]; then
                    echo "Critical and High Priority Issues:" >> "$REPORT_FILE"
                    local issues=$(jq -c '.results[] | select(.severity == "CRITICAL" or .severity == "HIGH")' "$security_file" 2>/dev/null)
                    while IFS= read -r issue; do
                        local component=$(echo "$issue" | jq -r '.component')
                        local title=$(echo "$issue" | jq -r '.title')
                        local severity=$(echo "$issue" | jq -r '.severity')

                        echo "[$severity] $component: $title" >> "$REPORT_FILE"
                    done <<< "$issues"
                    echo "" >> "$REPORT_FILE"
                fi
            else
                echo "Detailed security data not available. See raw JSON for details." >> "$REPORT_FILE"
            fi
        fi
    fi

    # Add footer
    cat >> "$REPORT_FILE" << EOF
===========================================
Cloud Infrastructure Platform Status Report
Generated: $(date)
EOF
}

# Function to send notification
send_notification() {
    if [[ "$SEND_NOTIFICATION" != "true" ]]; then
        return
    fi

    log "Sending notification..." "INFO"

    # Determine severity based on health check
    local severity="low"
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        local status=$(jq -r '.overall_status' "$health_file" 2>/dev/null)
        if [[ "$status" == "UNHEALTHY" ]]; then
            severity="high"
        elif [[ "$status" == "WARNING" ]]; then
            severity="medium"
        fi
    fi

    # Subject line
    local subject="Cloud Platform Status Report - ${ENVIRONMENT} (${REGION})"

    # Message body
    local message="Status report for ${ENVIRONMENT} environment has been generated.\n\n"
    message+="Overall Status: $overall_status\n"

    # Check if notification script exists
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority "$severity" \
            --subject "$subject" \
            --message "$message" \
            --recipient "$EMAIL_RECIPIENT" \
            --attachment "$REPORT_FILE"
        log "Notification sent to $EMAIL_RECIPIENT" "INFO"
    # Fall back to mail command
    elif command -v mail &>/dev/null && [[ -n "$EMAIL_RECIPIENT" ]]; then
        echo -e "$message" | mail -s "$subject" -a "$REPORT_FILE" "$EMAIL_RECIPIENT"
        log "Notification sent to $EMAIL_RECIPIENT using mail command" "INFO"
    else
        log "WARNING: Could not send notification, notification tools not available" "WARNING"
    fi
}

# Log to DR events system
log_to_dr_events() {
    if [[ "$DR_MODE" != "true" ]]; then
        return
    }

    log "Logging to DR events system..." "INFO"

    # Determine status from health check
    local status="UNKNOWN"
    if [[ -f "$health_file" ]] && command -v jq &>/dev/null; then
        status=$(jq -r '.overall_status' "$health_file" 2>/dev/null || echo "UNKNOWN")
    fi

    # Log directory
    local dr_log_dir="/var/log/cloud-platform"
    local dr_log_file="$dr_log_dir/dr-events.log"

    # Ensure directory exists
    mkdir -p "$dr_log_dir" 2>/dev/null || true

    if [[ -d "$dr_log_dir" && -w "$dr_log_dir" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'),STATUS_REPORT,${ENVIRONMENT},${REGION},${status}" >> "$dr_log_file"
        log "Status report logged to DR events log" "INFO"
    else
        log "WARNING: Could not write to DR events log at $dr_log_file" "WARNING"
    fi
}

# Main function
main() {
    log "Starting status report generation for ${ENVIRONMENT} environment in ${REGION} region" "INFO"

    # Ensure directories exist
    mkdir -p "$(dirname "$REPORT_FILE")" 2>/dev/null || {
        log "ERROR: Could not create directory for report file" "ERROR"
        exit 1
    }

    # Collect data
    local system_file=$(collect_system_metrics)
    local health_file=$(collect_health_check)
    local resource_file=$(collect_resource_data)
    local api_file=$(collect_api_latency)
    local connectivity_file=$(collect_connectivity_data)
    local security_file=$(collect_security_data)
    local history_file=$(collect_historical_metrics $HISTORY_DAYS)
    local recommendations_file=$(extract_recommendations "$health_file" "$resource_file" "$api_file" "$security_file")

    # Generate report based on format
    case "$REPORT_FORMAT" in
        html)
            generate_html_report "$system_file" "$health_file" "$resource_file" "$api_file" \
                "$connectivity_file" "$security_file" "$history_file" "$recommendations_file"
            ;;
        json)
            generate_json_report "$system_file" "$health_file" "$resource_file" "$api_file" \
                "$connectivity_file" "$security_file" "$history_file" "$recommendations_file"
            ;;
        text)
            generate_text_report "$system_file" "$health_file" "$resource_file" "$api_file" \
                "$connectivity_file" "$security_file" "$history_file" "$recommendations_file"
            ;;
        *)
            log "ERROR: Unsupported report format: $REPORT_FORMAT" "ERROR"
            exit 1
            ;;
    esac

    log "Report generated successfully: $REPORT_FILE" "INFO"

    # Send notification if requested
    if [[ "$SEND_NOTIFICATION" == "true" ]]; then
        send_notification
    fi

    # Log to DR events system if requested
    if [[ "$DR_MODE" == "true" ]]; then
        log_to_dr_events
    fi

    # Clean up temporary files
    if [[ "$VERBOSE" != "true" ]]; then
        rm -f "/tmp/*-${TIMESTAMP}.*" 2>/dev/null || true
    fi

    log "Status report generation completed" "INFO"
}

# Execute main function
main

exit 0
