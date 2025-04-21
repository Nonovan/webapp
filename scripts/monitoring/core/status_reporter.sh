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
            backgroun
