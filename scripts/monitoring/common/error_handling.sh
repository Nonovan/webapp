#!/bin/bash
# Error Handling and Reporting Utility for Cloud Infrastructure Platform
#
# This script provides standardized error handling and reporting functionality
# that can be sourced by any script in the platform to ensure consistent error
# management, reporting, and recovery strategies.
#
# Usage: source /scripts/monitoring/common/error_handling.sh

# Import common utility functions if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
COMMON_FUNCTIONS="${PROJECT_ROOT}/scripts/utils/common_functions.sh"

if [[ -f "$COMMON_FUNCTIONS" ]]; then
    # shellcheck source=/dev/null
    source "$COMMON_FUNCTIONS"
else
    echo "ERROR: Required common functions not found at $COMMON_FUNCTIONS"
    exit 1
fi

# Configuration
ERROR_LOG_DIR="${DEFAULT_LOG_DIR:-/var/log/cloud-platform}"
ERROR_LOG_FILE="${ERROR_LOG_DIR}/error-tracking.log"
ERROR_REPORT_DIR="${PROJECT_ROOT}/logs/errors"
MAX_RETRIES=3
DEFAULT_RETRY_DELAY=5
DEFAULT_BACKOFF_MULTIPLIER=2
ERROR_DB_FILE="/var/lib/cloud-platform/error_history.db"
PROMETHEUS_METRICS_DIR="/var/lib/node_exporter/textfile_collector"
PROMETHEUS_METRICS_FILE="${PROMETHEUS_METRICS_DIR}/script_errors.prom"

# Ensure error logging directory exists
mkdir -p "$ERROR_LOG_DIR" 2>/dev/null || true
mkdir -p "$ERROR_REPORT_DIR" 2>/dev/null || true
mkdir -p "$(dirname "$ERROR_DB_FILE")" 2>/dev/null || true
mkdir -p "$PROMETHEUS_METRICS_DIR" 2>/dev/null || true

#######################################
# ERROR TRACKING FUNCTIONS
#######################################

# Record an error to the central error tracking system
# Arguments:
#   $1 - Error code/id
#   $2 - Error message
#   $3 - Source script
#   $4 - Severity (CRITICAL, ERROR, WARNING - default: ERROR)
#   $5 - Additional context (JSON string)
# Returns: 0 on success, 1 on failure
track_error() {
    local error_code="$1"
    local error_message="$2"
    local source_script="$3"
    local severity="${4:-ERROR}"
    local context="${5:-{}}"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)
    local pid=$$
    local environment="${ENVIRONMENT:-unknown}"

    # Validate severity
    case "$severity" in
        CRITICAL|ERROR|WARNING)
            # Valid severity
            ;;
        *)
            severity="ERROR"  # Default to ERROR for invalid values
            ;;
    esac

    # Format the error entry as JSON
    local error_json
    error_json=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "error_code": "$error_code",
  "message": "${error_message//\"/\\\"}",
  "source": "$source_script",
  "severity": "$severity",
  "hostname": "$hostname",
  "pid": $pid,
  "environment": "$environment",
  "context": $context
}
EOF
)

    # Log to error tracking file
    echo "$error_json" >> "$ERROR_LOG_FILE"

    # For critical errors, create a separate report file
    if [[ "$severity" == "CRITICAL" ]]; then
        local report_file="${ERROR_REPORT_DIR}/critical_${error_code}_$(date +%Y%m%d%H%M%S).json"
        echo "$error_json" > "$report_file"
        chmod 644 "$report_file"
    fi

    # Update error tracking database if available
    if command_exists sqlite3 && [[ -w "$(dirname "$ERROR_DB_FILE")" ]]; then
        # Create DB if it doesn't exist
        if [[ ! -f "$ERROR_DB_FILE" ]]; then
            sqlite3 "$ERROR_DB_FILE" <<EOF
CREATE TABLE IF NOT EXISTS errors (
  id INTEGER PRIMARY KEY,
  timestamp TEXT,
  error_code TEXT,
  message TEXT,
  source TEXT,
  severity TEXT,
  hostname TEXT,
  pid INTEGER,
  environment TEXT,
  context TEXT
);
CREATE INDEX IF NOT EXISTS idx_error_code ON errors(error_code);
CREATE INDEX IF NOT EXISTS idx_severity ON errors(severity);
CREATE INDEX IF NOT EXISTS idx_timestamp ON errors(timestamp);
EOF
        fi

        # Insert error into database
        sqlite3 "$ERROR_DB_FILE" <<EOF
INSERT INTO errors (timestamp, error_code, message, source, severity, hostname, pid, environment, context)
VALUES ('$timestamp', '$error_code', '${error_message//\'/\'\'}', '$source_script', '$severity', '$hostname', $pid, '$environment', '${context//\'/\'\'}');
EOF
    fi

    # Update Prometheus metrics if directory is writable
    update_error_metrics

    # Log using common functions
    log "Error [$error_code] in $source_script: $error_message" "$severity"

    return 0
}

# Update error metrics for Prometheus
update_error_metrics() {
    if [[ -w "$(dirname "$PROMETHEUS_METRICS_FILE")" ]]; then
        # Current timestamp for metric freshness
        local timestamp
        timestamp=$(date +%s)

        # Calculate error counts (in the last 24 hours) by severity
        local critical_count=0
        local error_count=0
        local warning_count=0

        if command_exists sqlite3 && [[ -f "$ERROR_DB_FILE" ]]; then
            # Get counts from database
            critical_count=$(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE severity='CRITICAL' AND datetime(timestamp) > datetime('now', '-1 day');")
            error_count=$(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE severity='ERROR' AND datetime(timestamp) > datetime('now', '-1 day');")
            warning_count=$(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE severity='WARNING' AND datetime(timestamp) > datetime('now', '-1 day');")
        else
            # Fallback to grep on log file if available
            if [[ -f "$ERROR_LOG_FILE" ]]; then
                local yesterday
                yesterday=$(date -d "yesterday" +"%Y-%m-%d" 2>/dev/null || date -v-1d +"%Y-%m-%d")
                local today
                today=$(date +"%Y-%m-%d")

                critical_count=$(grep -c "\"severity\": \"CRITICAL\"" "$ERROR_LOG_FILE" | grep -e "$yesterday" -e "$today")
                error_count=$(grep -c "\"severity\": \"ERROR\"" "$ERROR_LOG_FILE" | grep -e "$yesterday" -e "$today")
                warning_count=$(grep -c "\"severity\": \"WARNING\"" "$ERROR_LOG_FILE" | grep -e "$yesterday" -e "$today")
            fi
        fi

        # Create the metrics file
        cat > "$PROMETHEUS_METRICS_FILE" <<EOF
# HELP script_errors_total Total number of script errors in the last 24 hours
# TYPE script_errors_total counter
script_errors_total{severity="critical",environment="${ENVIRONMENT:-unknown}"} ${critical_count:-0}
script_errors_total{severity="error",environment="${ENVIRONMENT:-unknown}"} ${error_count:-0}
script_errors_total{severity="warning",environment="${ENVIRONMENT:-unknown}"} ${warning_count:-0}
# HELP script_errors_last_update_timestamp Unix timestamp when the error metrics were last updated
# TYPE script_errors_last_update_timestamp gauge
script_errors_last_update_timestamp ${timestamp}
EOF
        chmod 644 "$PROMETHEUS_METRICS_FILE"
    fi
}

# Check for repeated errors of the same type
# Arguments:
#   $1 - Error code/id
#   $2 - Time window in minutes (default: 60)
# Returns: Number of occurrences
count_recent_errors() {
    local error_code="$1"
    local time_window="${2:-60}"
    local count=0

    if command_exists sqlite3 && [[ -f "$ERROR_DB_FILE" ]]; then
        # Use database for more accurate counting
        count=$(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE error_code='$error_code' AND datetime(timestamp) > datetime('now', '-$time_window minutes');")
    else
        # Fallback to grep on log file
        if [[ -f "$ERROR_LOG_FILE" ]]; then
            # This is a simplistic approach and might not be 100% accurate with the time window
            count=$(grep "\"error_code\": \"$error_code\"" "$ERROR_LOG_FILE" | wc -l)
        fi
    fi

    echo "$count"
}

# Get the most recent error message for a specific error code
# Arguments:
#   $1 - Error code/id
# Returns: Most recent error message or empty if none found
get_last_error_message() {
    local error_code="$1"
    local message=""

    if command_exists sqlite3 && [[ -f "$ERROR_DB_FILE" ]]; then
        message=$(sqlite3 "$ERROR_DB_FILE" "SELECT message FROM errors WHERE error_code='$error_code' ORDER BY timestamp DESC LIMIT 1;")
    else
        # Fallback to grep and parse from log file
        if [[ -f "$ERROR_LOG_FILE" ]]; then
            message=$(grep "\"error_code\": \"$error_code\"" "$ERROR_LOG_FILE" | tail -1 | grep -o '"message": "[^"]*"' | cut -d'"' -f4)
        fi
    fi

    echo "$message"
}

#######################################
# RETRY MECHANISM FUNCTIONS
#######################################

# Execute a command with automatic retries and exponential backoff
# Arguments:
#   $1 - Command to execute (string)
#   $2 - Error code to use if command fails (optional)
#   $3 - Maximum number of retries (optional, default: MAX_RETRIES)
#   $4 - Initial delay between retries in seconds (optional, default: DEFAULT_RETRY_DELAY)
#   $5 - Backoff multiplier (optional, default: DEFAULT_BACKOFF_MULTIPLIER)
# Returns: Exit code of the command (0 on success) or 1 if all retries fail
retry_with_backoff() {
    local cmd="$1"
    local error_code="${2:-CMD_RETRY_FAILED}"
    local max_retries="${3:-$MAX_RETRIES}"
    local delay="${4:-$DEFAULT_RETRY_DELAY}"
    local backoff_multiplier="${5:-$DEFAULT_BACKOFF_MULTIPLIER}"
    local attempt=1
    local exit_code=0
    local source_script
    source_script=$(basename "${BASH_SOURCE[1]}")
    local output_file
    output_file=$(mktemp)

    while (( attempt <= max_retries )); do
        # Execute the command and capture output and exit code
        if (( attempt > 1 )); then
            log "Retry attempt $attempt/$max_retries for command after ${delay}s delay: $cmd" "INFO"
        fi

        # Execute command with output redirection
        eval "$cmd" > "$output_file" 2>&1
        exit_code=$?

        # Check if command succeeded
        if [[ $exit_code -eq 0 ]]; then
            # Success - output the result and return
            cat "$output_file"
            rm -f "$output_file"
            if (( attempt > 1 )); then
                log "Command succeeded on retry $attempt: $cmd" "INFO"
            fi
            return 0
        fi

        # Command failed
        local error_output
        error_output=$(cat "$output_file")

        # Log the failure
        if (( attempt == max_retries )); then
            # This was the last attempt
            track_error "$error_code" "Command failed after $max_retries retries: $cmd - Exit code: $exit_code - Output: ${error_output:0:100}..." "$source_script" "ERROR" "{\"exit_code\":$exit_code,\"attempts\":$attempt,\"command\":\"$cmd\"}"
        else
            # We'll retry
            track_error "$error_code" "Command failed (will retry): $cmd - Exit code: $exit_code - Output: ${error_output:0:100}..." "$source_script" "WARNING" "{\"exit_code\":$exit_code,\"attempt\":$attempt,\"command\":\"$cmd\"}"

            # Wait before retrying with exponential backoff and jitter
            local jitter
            jitter=$(( RANDOM % 1000 ))
            local sleep_time
            sleep_time=$(echo "scale=3; $delay + $jitter/1000" | bc)
            sleep "$sleep_time"

            # Increase the delay for next attempt
            delay=$(echo "$delay * $backoff_multiplier" | bc)
        fi

        (( attempt++ ))
    done

    # All retries failed, output the last failure and return its exit code
    cat "$output_file"
    rm -f "$output_file"
    return $exit_code
}

# Execute a command with circuit breaker protection
# Arguments:
#   $1 - Command to execute (string)
#   $2 - Circuit breaker name (used for tracking state)
#   $3 - Error code to use if command fails (optional)
#   $4 - Circuit breaker trip threshold (number of failures, default: 3)
#   $5 - Circuit breaker reset time in seconds (default: 300 - 5 minutes)
# Returns: Exit code of the command (0 on success) or 1 if circuit open/fail
circuit_breaker_exec() {
    local cmd="$1"
    local breaker_name="$2"
    local error_code="${3:-CIRCUIT_BREAKER_OPEN}"
    local trip_threshold="${4:-3}"
    local reset_time="${5:-300}"
    local source_script
    source_script=$(basename "${BASH_SOURCE[1]}")
    local circuit_file="/tmp/circuit_breaker_${breaker_name// /_}"
    local counter_file="${circuit_file}.count"

    # Check if circuit breaker is open (tripped)
    if [[ -f "$circuit_file" ]]; then
        local trip_time
        trip_time=$(cat "$circuit_file")
        local current_time
        current_time=$(date +%s)
        local elapsed=$((current_time - trip_time))

        # If circuit is open and reset time hasn't elapsed
        if [[ $elapsed -lt $reset_time ]]; then
            local remaining=$((reset_time - elapsed))
            track_error "$error_code" "Circuit breaker for '$breaker_name' is open (will retry in ${remaining}s)" "$source_script" "WARNING" "{\"breaker\":\"$breaker_name\",\"remaining_seconds\":$remaining}"
            return 1
        else
            # Circuit breaker timeout has elapsed, we can try again
            rm -f "$circuit_file"
            rm -f "$counter_file"
            log "Circuit breaker for '$breaker_name' reset after $elapsed seconds" "INFO"
        fi
    fi

    # Execute the command
    local output_file
    output_file=$(mktemp)
    eval "$cmd" > "$output_file" 2>&1
    local exit_code=$?

    # Check result
    if [[ $exit_code -eq 0 ]]; then
        # Success - reset failure counter
        rm -f "$counter_file"
        cat "$output_file"
        rm -f "$output_file"
        return 0
    else
        # Command failed
        local error_output
        error_output=$(cat "$output_file")
        rm -f "$output_file"

        # Update failure counter
        local fail_count=1
        if [[ -f "$counter_file" ]]; then
            fail_count=$(($(cat "$counter_file") + 1))
        fi
        echo "$fail_count" > "$counter_file"

        # Check if we should trip the circuit breaker
        if [[ $fail_count -ge $trip_threshold ]]; then
            # Trip the circuit breaker
            date +%s > "$circuit_file"
            rm -f "$counter_file"
            track_error "$error_code" "Circuit breaker for '$breaker_name' tripped after $fail_count failures. Last error: ${error_output:0:100}..." "$source_script" "ERROR" "{\"breaker\":\"$breaker_name\",\"failures\":$fail_count,\"reset_seconds\":$reset_time}"
            log "Circuit breaker tripped for '$breaker_name' (protection active for $reset_time seconds)" "WARNING"
        else
            # Log the failure but don't trip the breaker yet
            track_error "$error_code" "Operation '$breaker_name' failed ($fail_count/$trip_threshold): ${error_output:0:100}..." "$source_script" "WARNING" "{\"breaker\":\"$breaker_name\",\"failures\":$fail_count,\"threshold\":$trip_threshold}"
        fi

        return $exit_code
    fi
}

#######################################
# ERROR RECOVERY FUNCTIONS
#######################################

# Execute custom error recovery function if available
# Arguments:
#   $1 - Error code
#   $2 - Source script name
#   $3+ - Additional parameters to pass to recovery function
# Returns: 0 on successful recovery, 1 if recovery failed or not available
execute_recovery() {
    local error_code="$1"
    local source_script="$2"
    shift 2  # Remove error code and script name, leaving additional params

    # Check if a recovery function exists for this error code
    local recovery_function="recover_${error_code}"
    if [[ "$(type -t "$recovery_function")" == "function" ]]; then
        log "Executing recovery function for error $error_code" "INFO"

        # Call the recovery function with all additional parameters
        if "$recovery_function" "$@"; then
            log "Recovery successful for error $error_code" "INFO"
            return 0
        else
            track_error "RECOVERY_FAILED" "Recovery function for error $error_code failed" "$source_script" "ERROR" "{\"error_code\":\"$error_code\"}"
            return 1
        fi
    else
        # No recovery function available
        log "No recovery function available for error $error_code" "INFO"
        return 1
    fi
}

# Cleanup function to ensure proper handling of temporary resources
cleanup() {
    # This should be called in the trap of scripts that source this file
    log "Executing error handling cleanup" "DEBUG"

    # Any pending error metrics updates
    update_error_metrics
}

#######################################
# GRACEFUL DEGRADATION FUNCTIONS
#######################################

# Check if a feature should be disabled due to repeated errors
# Arguments:
#   $1 - Feature name
#   $2 - Error threshold (default: 5)
#   $3 - Time window in minutes (default: 60)
# Returns: 0 if feature should remain enabled, 1 if it should be disabled
should_disable_feature() {
    local feature="$1"
    local threshold="${2:-5}"
    local time_window="${3:-60}"
    local feature_error_code="FEATURE_${feature// /_}_ERROR"

    # Count recent errors for this feature
    local error_count
    error_count=$(count_recent_errors "$feature_error_code" "$time_window")

    if [[ $error_count -ge $threshold ]]; then
        log "Feature '$feature' should be disabled due to $error_count errors in the last $time_window minutes" "WARNING"
        return 1
    else
        return 0
    fi
}

# Execute a feature with graceful degradation
# Arguments:
#   $1 - Feature name
#   $2 - Primary command to execute (string)
#   $3 - Fallback command to execute if primary fails (string, optional)
#   $4 - Error threshold for disabling (default: 5)
#   $5 - Time window in minutes for error counting (default: 60)
# Returns: Exit code of the command that executed (primary or fallback)
execute_with_degradation() {
    local feature="$1"
    local primary_cmd="$2"
    local fallback_cmd="$3"
    local threshold="${4:-5}"
    local time_window="${5:-60}"
    local feature_error_code="FEATURE_${feature// /_}_ERROR"
    local source_script
    source_script=$(basename "${BASH_SOURCE[1]}")

    # Check if the feature should be used or is in a degraded state
    if should_disable_feature "$feature" "$threshold" "$time_window"; then
        # Feature should be active - try the primary command
        local output_file
        output_file=$(mktemp)
        eval "$primary_cmd" > "$output_file" 2>&1
        local exit_code=$?

        if [[ $exit_code -eq 0 ]]; then
            # Primary succeeded
            cat "$output_file"
            rm -f "$output_file"
            return 0
        else
            # Primary failed
            local error_output
            error_output=$(cat "$output_file")
            rm -f "$output_file"

            # Record the error
            track_error "$feature_error_code" "Feature '$feature' experienced an error: ${error_output:0:100}..." "$source_script" "WARNING" "{\"feature\":\"$feature\",\"command\":\"$primary_cmd\"}"

            # Try fallback if available
            if [[ -n "$fallback_cmd" ]]; then
                log "Primary command for feature '$feature' failed, trying fallback" "WARNING"
                eval "$fallback_cmd"
                return $?
            else
                return $exit_code
            fi
        fi
    else
        # Feature should be disabled - use fallback immediately
        if [[ -n "$fallback_cmd" ]]; then
            log "Feature '$feature' temporarily disabled due to error threshold, using fallback" "WARNING"
            eval "$fallback_cmd"
            return $?
        else
            log "Feature '$feature' temporarily disabled and no fallback available" "ERROR"
            track_error "$feature_error_code" "Feature '$feature' is disabled due to error threshold and no fallback is available" "$source_script" "ERROR" "{\"feature\":\"$feature\",\"threshold\":$threshold,\"window\":$time_window}"
            return 1
        fi
    fi
}

#######################################
# ERROR REPORTING FUNCTIONS
#######################################

# Generate an error report for a time period
# Arguments:
#   $1 - Start time (YYYY-MM-DD format, defaults to 24 hours ago)
#   $2 - End time (YYYY-MM-DD format, defaults to now)
#   $3 - Output format (text, json, html - default: text)
#   $4 - Output file (optional - defaults to stdout)
# Returns: 0 on success, 1 on failure
generate_error_report() {
    local start_time="${1:-$(date -d "24 hours ago" +"%Y-%m-%d" 2>/dev/null || date -v-1d +"%Y-%m-%d")}"
    local end_time="${2:-$(date +"%Y-%m-%d")}"
    local format="${3:-text}"
    local output_file="$4"
    local report_content=""
    local severity_counts=()
    local error_code_counts=()
    local source_script_counts=()

    # Build the report based on database or log file
    if command_exists sqlite3 && [[ -f "$ERROR_DB_FILE" ]]; then
        # Use the database for reporting
        local db_query=""

        case "$format" in
            json)
                # JSON format report
                db_query="SELECT json_group_array(json_object(
                    'timestamp', timestamp,
                    'error_code', error_code,
                    'message', message,
                    'source', source,
                    'severity', severity,
                    'hostname', hostname,
                    'environment', environment,
                    'context', context
                )) FROM errors
                WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                ORDER BY timestamp DESC;"

                local json_data
                json_data=$(sqlite3 "$ERROR_DB_FILE" "$db_query")

                # Get summary data
                severity_counts=($(sqlite3 "$ERROR_DB_FILE" "SELECT severity, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY severity ORDER BY COUNT(*) DESC;"))

                error_code_counts=($(sqlite3 "$ERROR_DB_FILE" "SELECT error_code, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY error_code ORDER BY COUNT(*) DESC LIMIT 10;"))

                # Build the full JSON report
                report_content="{
  \"report_generated\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",
  \"period\": {
    \"start\": \"$start_time\",
    \"end\": \"$end_time\"
  },
  \"summary\": {
    \"total_errors\": $(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time');"),
    \"severity_breakdown\": {"

                # Add severity counts
                local first_severity=true
                while IFS='|' read -r severity count; do
                    if [[ "$first_severity" == "true" ]]; then
                        first_severity=false
                    else
                        report_content+=","
                    fi
                    report_content+=$'\n      "'$severity'": '$count
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT severity, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY severity ORDER BY COUNT(*) DESC;")

                report_content+=$'\n    },
    "top_error_codes": {'

                # Add top error codes
                local first_code=true
                while IFS='|' read -r code count; do
                    if [[ "$first_code" == "true" ]]; then
                        first_code=false
                    else
                        report_content+=","
                    fi
                    report_content+=$'\n      "'$code'": '$count
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT error_code, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY error_code ORDER BY COUNT(*) DESC LIMIT 10;")

                report_content+=$'\n    },
    "top_error_sources": {'

                # Add top error sources
                local first_source=true
                while IFS='|' read -r source count; do
                    if [[ "$first_source" == "true" ]]; then
                        first_source=false
                    else
                        report_content+=","
                    fi
                    report_content+=$'\n      "'$source'": '$count
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT source, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10;")

                report_content+=$'\n    }
  },
  "errors": '$json_data'
}'
                ;;

            html)
                # HTML format report
                report_content="<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Error Report ($start_time to $end_time)</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            text-align: left;
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .severity-CRITICAL {
            background-color: #ffdddd;
        }
        .severity-ERROR {
            background-color: #fff3cd;
        }
        .severity-WARNING {
            background-color: #e5f5ff;
        }
        .summary-box {
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            background-color: #f8f9fa;
            border-left: 5px solid #3498db;
        }
        .footer {
            margin-top: 30px;
            font-size: 0.8em;
            color: #7f8c8d;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>Error Report</h1>

        <div class=\"summary-box\">
            <h2>Report Summary</h2>
            <p><strong>Period:</strong> $start_time to $end_time</p>
            <p><strong>Total Errors:</strong> $(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time');")</p>
            <p><strong>Generated:</strong> $(date)</p>
        </div>

        <div class=\"summary-box\">
            <h2>Severity Breakdown</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>"

                # Add severity counts
                while IFS='|' read -r severity count; do
                    report_content+="
                <tr>
                    <td>$severity</td>
                    <td>$count</td>
                </tr>"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT severity, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY severity ORDER BY COUNT(*) DESC;")

                report_content+="
            </table>
        </div>

        <div class=\"summary-box\">
            <h2>Top Error Codes</h2>
            <table>
                <tr>
                    <th>Error Code</th>
                    <th>Count</th>
                </tr>"

                # Add error code counts
                while IFS='|' read -r code count; do
                    report_content+="
                <tr>
                    <td>$code</td>
                    <td>$count</td>
                </tr>"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT error_code, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY error_code ORDER BY COUNT(*) DESC LIMIT 10;")

                report_content+="
            </table>
        </div>

        <h2>Error Details</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Error Code</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Message</th>
            </tr>"

                # Add individual error entries
                while IFS='|' read -r timestamp error_code source severity message; do
                    report_content+="
            <tr class=\"severity-$severity\">
                <td>$timestamp</td>
                <td>$error_code</td>
                <td>$source</td>
                <td>$severity</td>
                <td>$message</td>
            </tr>"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT timestamp, error_code, source, severity, message FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    ORDER BY timestamp DESC LIMIT 1000;")

                report_content+="
        </table>

        <div class=\"footer\">
            <p>Generated by Cloud Infrastructure Platform Error Reporting System</p>
        </div>
    </div>
</body>
</html>"
                ;;

            *)
                # Default text format
                report_content="ERROR REPORT: $start_time to $end_time
Generated: $(date)
======================================

SUMMARY
-------
Total Errors: $(sqlite3 "$ERROR_DB_FILE" "SELECT COUNT(*) FROM errors WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time');")

SEVERITY BREAKDOWN
-----------------"

                # Add severity counts
                while IFS='|' read -r severity count; do
                    report_content+=$'\n'"$severity: $count"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT severity, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY severity ORDER BY COUNT(*) DESC;")

                report_content+=$'\n\n'"TOP ERROR CODES
--------------"

                # Add top error codes
                while IFS='|' read -r code count; do
                    report_content+=$'\n'"$code: $count"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT error_code, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY error_code ORDER BY COUNT(*) DESC LIMIT 10;")

                report_content+=$'\n\n'"TOP ERROR SOURCES
----------------"

                # Add top error sources
                while IFS='|' read -r source count; do
                    report_content+=$'\n'"$source: $count"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT source, COUNT(*) FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10;")

                report_content+=$'\n\n'"ERROR DETAILS
-------------"

                # Add individual error entries
                while IFS='|' read -r timestamp error_code severity source message; do
                    report_content+=$'\n\n'"[$timestamp] [$severity] $error_code in $source"
                    report_content+=$'\n'"$message"
                done < <(sqlite3 "$ERROR_DB_FILE" "SELECT timestamp, error_code, severity, source, message FROM errors
                    WHERE date(timestamp) >= date('$start_time') AND date(timestamp) <= date('$end_time')
                    ORDER BY timestamp DESC LIMIT 100;")
                ;;
        esac
    else
        # Fallback to processing the log file directly
        report_content="ERROR REPORT: $start_time to $end_time (Limited functionality - SQLite not available)
Generated: $(date)
======================================

NOTE: This is a simplified report as SQLite is not available for detailed analysis.
Using direct log parsing which may be incomplete.

"

        # Parse the log file if available
        if [[ -f "$ERROR_LOG_FILE" ]]; then
            # Grep for errors in the date range
            # This is a simplified approach
            report_content+="RECENT ERRORS
-------------
"
            grep -E "\"timestamp\": \"($start_time|$end_time)" "$ERROR_LOG_FILE" | tail -n 50 >> "$report_content"
        else
            report_content+="No error log file found at $ERROR_LOG_FILE."
        fi
    fi

    # Output the report
    if [[ -n "$output_file" ]]; then
        echo "$report_content" > "$output_file"
        chmod 644 "$output_file"
        log "Error report generated and saved to $output_file" "INFO"
    else
        echo "$report_content"
    fi

    return 0
}

#######################################
# ERROR NOTIFICATION FUNCTIONS
#######################################

# Send notification for critical errors
# Arguments:
#   $1 - Error code
#   $2 - Error message
#   $3 - Source script
#   $4 - Recipients (comma-separated, optional - uses EMAIL_RECIPIENT from env if not provided)
# Returns: 0 on success, 1 on failure
notify_critical_error() {
    local error_code="$1"
    local error_message="$2"
    local source_script="$3"
    local recipients="${4:-${EMAIL_RECIPIENT:-}}"
    local environment="${ENVIRONMENT:-unknown}"
    local hostname
    hostname=$(hostname -f 2>/dev/null || hostname)

    # If no recipients, try to use a default from environment
    if [[ -z "$recipients" ]]; then
        log "No recipients specified, notification not sent" "WARNING"
        return 1
    fi

    # Create the notification message
    local subject="[CRITICAL ERROR] $error_code in $environment environment"
    local message="Critical error detected in Cloud Infrastructure Platform

Error Code: $error_code
Environment: $environment
Host: $hostname
Script: $source_script
Time: $(date)

Error Message:
$error_message

This is an automated notification. Please investigate immediately.
"

    # Try to send notification
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        "${PROJECT_ROOT}/scripts/utils/send-notification.sh" \
            --priority "high" \
            --subject "$subject" \
            --message "$message" \
            --recipient "$recipients" || {
                log "Failed to send notification using send-notification.sh" "WARNING"
                return 1
            }

        log "Critical error notification sent to $recipients" "INFO"
        return 0
    else
        # Fallback to basic mail command
        if command_exists mail; then
            echo "$message" | mail -s "$subject" "$recipients" || {
                log "Failed to send notification email using mail command" "WARNING"
                return 1
            }

            log "Critical error notification sent to $recipients using mail command" "INFO"
            return 0
        else
            log "Could not send notification, notification utilities not available" "WARNING"
            return 1
        fi
    fi
}

# Function to determine if notification should be throttled
# Arguments:
#   $1 - Error code
#   $2 - Time window in minutes (default: 30)
# Returns: 0 if should send, 1 if should throttle
should_throttle_notification() {
    local error_code="$1"
    local window="${2:-30}"
    local throttle_file="/tmp/error_notify_${error_code// /_}.last"

    # Check if we've sent a notification recently
    if [[ -f "$throttle_file" ]]; then
        local last_time
        last_time=$(cat "$throttle_file")
        local current_time
        current_time=$(date +%s)
        local elapsed=$((current_time - last_time))
        local window_seconds=$((window * 60))

        if [[ $elapsed -lt $window_seconds ]]; then
            # Too recent, should throttle
            return 1
        fi
    fi

    # Update the timestamp
    date +%s > "$throttle_file"
    return 0
}

# Export the functions
export -f track_error
export -f count_recent_errors
export -f get_last_error_message
export -f retry_with_backoff
export -f circuit_breaker_exec
export -f execute_recovery
export -f cleanup
export -f should_disable_feature
export -f execute_with_degradation
export -f generate_error_report
export -f notify_critical_error
export -f should_throttle_notification
export -f update_error_metrics

# Only output if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced by other scripts, not executed directly."
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi
