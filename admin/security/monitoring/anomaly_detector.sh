#!/bin/bash
# Behavioral Anomaly Detection System for Cloud Infrastructure Platform
#
# Detects anomalies in user behavior, system metrics, and network traffic
# based on predefined baselines and detection rules. Designed for security
# operations personnel.

set -eo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
ADMIN_CONFIG_DIR="${PROJECT_ROOT}/admin/security/monitoring/config"
LOG_DIR="/var/log/cloud-platform/security"
REPORT_DIR="/var/www/reports/security"
DEFAULT_BASELINE_DIR="${ADMIN_CONFIG_DIR}/baseline"
DEFAULT_RULES_DIR="${ADMIN_CONFIG_DIR}/detection_rules"
DEFAULT_LOG_FILE="${LOG_DIR}/anomaly_detector.log"
DEFAULT_REPORT_FILE="${REPORT_DIR}/anomaly_report-$(date +%Y%m%d_%H%M%S).json"
DEFAULT_ENV="production"
DEFAULT_HISTORY_DIR="/var/cache/cloud-platform/anomaly_detector/history"
MAX_HISTORY_ENTRIES=100

# Default settings
BASELINE_FILE="" # Determined based on environment
RULES_DIR="$DEFAULT_RULES_DIR"
LOG_FILE="$DEFAULT_LOG_FILE"
REPORT_FILE="$DEFAULT_REPORT_FILE"
HISTORY_DIR="$DEFAULT_HISTORY_DIR"
SCAN_SCOPE="all" # Options: user, system, network, all
TIMEFRAME="24h" # e.g., 1h, 24h, 7d
SENSITIVITY="medium" # Options: low, medium, high
ALERT_ON_ANOMALY=true
VERBOSE=false
QUIET=false
DRY_RUN=false
OUTPUT_FORMAT="json" # Options: json, text, html
ENVIRONMENT="$DEFAULT_ENV"
THRESHOLD_MULTIPLIER=0 # Will be set based on sensitivity
ADDITIONAL_METRICS=() # Can include custom metrics to analyze
CUSTOM_BASELINE_KEYS=() # Used for dynamic baseline key extraction

# --- Ensure Directories Exist ---
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"
mkdir -p "$HISTORY_DIR"

# --- Source Common Utilities ---
COMMON_LOGGING_UTILS="${PROJECT_ROOT}/scripts/utils/common/common_logging_utils.sh"
COMMON_VALIDATION_UTILS="${PROJECT_ROOT}/scripts/monitoring/common/validation.sh"
COMMON_ERROR_UTILS="${PROJECT_ROOT}/scripts/monitoring/common/error_handling.sh"
NETWORK_UTILS="${PROJECT_ROOT}/scripts/monitoring/common/network.utils.sh"
DATE_UTILS="${PROJECT_ROOT}/scripts/utils/common/date_utils.sh"

# Source logging utilities or provide fallbacks
if [[ -f "$COMMON_LOGGING_UTILS" ]]; then
    # shellcheck source=../../scripts/utils/common/common_logging_utils.sh
    source "$COMMON_LOGGING_UTILS"
else
    log() {
        local timestamp
        timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local level="${2:-INFO}"
        if [[ "$QUIET" == "true" && "$level" == "INFO" ]]; then
            return
        fi
        echo "[$timestamp] [$level] $1" | tee -a "$LOG_FILE"
    }
    log_info() { log "$1" "INFO"; }
    log_warn() { log "$1" "WARN"; }
    log_error() { log "$1" "ERROR"; }
    log_debug() { [[ "$VERBOSE" == "true" ]] && log "$1" "DEBUG"; }
    log_script_start() { log_info "Starting $(basename "$0")"; }
    log_script_end() { log_info "$(basename "$0") finished: $1"; }
    log_success() { log "$1" "SUCCESS"; }
fi

# Source validation utilities or provide fallbacks
if [[ -f "$COMMON_VALIDATION_UTILS" ]]; then
    # shellcheck source=../../scripts/monitoring/common/validation.sh
    source "$COMMON_VALIDATION_UTILS"
else
    validate_environment_name() { # Basic fallback
        [[ "$1" =~ ^(development|staging|production|dr-recovery)$ ]]
    }

    validate_timeframe() {
        local timeframe="$1"
        [[ "$timeframe" =~ ^[0-9]+[hdwmy]$ ]]
    }

    validate_file_permissions() {
        local file="$1"
        local required_perms="$2"

        [[ -f "$file" && -r "$file" ]]
    }

    escape_json() {
        local str="$1"
        echo "$str" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\//\\\//g; s/\b/\\b/g; s/\f/\\f/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
    }

    sanitize_filename() {
        local filename="$1"
        echo "$filename" | tr -cd '[:alnum:]_.-'
    }
fi

# Source error utilities if available
if [[ -f "$COMMON_ERROR_UTILS" ]]; then
    # shellcheck source=../../scripts/monitoring/common/error_handling.sh
    source "$COMMON_ERROR_UTILS"
    ERROR_UTILS_AVAILABLE=true
else
    ERROR_UTILS_AVAILABLE=false

    handle_error() {
        local error_msg="$1"
        local error_code="${2:-1}"
        log_error "$error_msg"
        return "$error_code"
    }

    retry_command() {
        local cmd="$1"
        local max_attempts="${2:-3}"
        local wait_time="${3:-5}"
        local attempt=1

        while [[ $attempt -le $max_attempts ]]; do
            if eval "$cmd"; then
                return 0
            fi
            log_warn "Command failed (attempt $attempt/$max_attempts): $cmd"
            sleep "$wait_time"
            ((attempt++))
        done

        return 1
    }
fi

# Source network utilities if available
if [[ -f "$NETWORK_UTILS" ]]; then
    # shellcheck source=../../scripts/monitoring/common/network.utils.sh
    source "$NETWORK_UTILS"
    NETWORK_UTILS_AVAILABLE=true
else
    NETWORK_UTILS_AVAILABLE=false
    log_warn "Network utilities not found at $NETWORK_UTILS. Network anomaly detection may be limited."

    # Basic network utility functions for fallback
    url_to_safe_name() {
        local url="$1"
        echo "$url" | sed 's/[^a-zA-Z0-9]/_/g'
    }

    analyze_latency_trend() {
        local endpoint="$1"
        local current_latency="$2"
        local history_dir="${3:-$HISTORY_DIR}"

        echo "0"  # Simplified fallback
    }

    check_endpoint_connectivity() {
        local endpoint="$1"
        local timeout="${2:-5}"

        curl --connect-timeout "$timeout" -s -o /dev/null -w "%{http_code}" "$endpoint" || echo "000"
    }
fi

# Source date utilities if available
if [[ -f "$DATE_UTILS" ]]; then
    # shellcheck source=../../scripts/utils/common/date_utils.sh
    source "$DATE_UTILS"
    DATE_UTILS_AVAILABLE=true
else
    DATE_UTILS_AVAILABLE=false

    # Parse timeframe string (1h, 2d, 1w, etc.) into seconds
    parse_timeframe() {
        local timeframe="$1"
        local value
        local unit

        value=$(echo "$timeframe" | sed -E 's/([0-9]+)([hdwmy]).*/\1/')
        unit=$(echo "$timeframe" | sed -E 's/([0-9]+)([hdwmy]).*/\2/')

        case "$unit" in
            h) echo $((value * 3600)) ;;
            d) echo $((value * 86400)) ;;
            w) echo $((value * 604800)) ;;
            m) echo $((value * 2592000)) ;; # Approximation: 30 days
            y) echo $((value * 31536000)) ;; # Approximation: 365 days
            *) echo 86400 ;; # Default to 1 day
        esac
    }

    get_start_time() {
        local timeframe="$1"
        local seconds

        seconds=$(parse_timeframe "$timeframe")
        date -d "@$(($(date +%s) - seconds))" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
        date -r "$(($(date +%s) - seconds))" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
        date -v "-${timeframe}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null # macOS variant
    }

    get_current_time() {
        date -u +"%Y-%m-%dT%H:%M:%SZ"
    }
fi

# --- Functions ---

# Display usage information
usage() {
    cat <<EOF
Behavioral Anomaly Detection System

Usage: $(basename "$0") [options]

Options:
  --scope SCOPE        Analysis scope: user, system, network, all (default: all)
  --timeframe TIME     Time window for analysis (e.g., 1h, 24h, 7d) (default: 24h)
  --env ENVIRONMENT    Target environment (default: $DEFAULT_ENV)
  --baseline FILE      Path to a specific baseline JSON file (overrides environment default)
  --rules-dir DIR      Path to the directory containing detection rule files (default: $DEFAULT_RULES_DIR)
  --sensitivity LEVEL  Detection sensitivity: low, medium, high (default: medium)
  --output FILE        Path to the report output file (default: $DEFAULT_REPORT_FILE)
  --format FORMAT      Output report format: json, text, html (default: json)
  --history-dir DIR    Directory to store historical data (default: $DEFAULT_HISTORY_DIR)
  --metric NAME        Additional metric to analyze (can be used multiple times)
  --no-alert           Disable alerting on detected anomalies (default: alerts enabled)
  --log-file FILE      Path to the log file (default: $DEFAULT_LOG_FILE)
  --compare-baseline   Compare current metrics with baseline and report differences
  --export-baseline    Create a new baseline from current metrics
  --verbose, -v        Enable verbose output
  --quiet, -q          Suppress informational output (errors still shown)
  --dry-run            Perform checks but don't save report or send alerts
  --help, -h           Show this help message

Examples:
  $(basename "$0") --scope user --timeframe 1h --sensitivity high
  $(basename "$0") --env staging --output /tmp/staging_anomalies.json
  $(basename "$0") --baseline config/baseline/custom_baseline.json --no-alert
  $(basename "$0") --scope system --metric cpu_iowait --metric memory_cache
EOF
    exit 0
}

# Set sensitivity-based thresholds
set_sensitivity_thresholds() {
    case "$SENSITIVITY" in
        low)
            THRESHOLD_MULTIPLIER=2.0
            log_debug "Set low sensitivity: thresholds will use multiplier $THRESHOLD_MULTIPLIER"
            ;;
        medium)
            THRESHOLD_MULTIPLIER=1.5
            log_debug "Set medium sensitivity: thresholds will use multiplier $THRESHOLD_MULTIPLIER"
            ;;
        high)
            THRESHOLD_MULTIPLIER=1.2
            log_debug "Set high sensitivity: thresholds will use multiplier $THRESHOLD_MULTIPLIER"
            ;;
    esac
}

# Load baseline configuration from JSON file
load_baseline() {
    if [[ -z "$BASELINE_FILE" ]]; then
        BASELINE_FILE="${DEFAULT_BASELINE_DIR}/${ENVIRONMENT}.json"
    fi

    log_info "Loading baseline configuration from $BASELINE_FILE"

    if [[ ! -f "$BASELINE_FILE" ]]; then
        handle_error "Baseline file not found: $BASELINE_FILE" 1
        exit 1
    }

    if ! validate_file_permissions "$BASELINE_FILE" "r"; then
        handle_error "Cannot read baseline file: insufficient permissions" 1
        exit 1
    }

    if ! command -v jq &> /dev/null; then
        handle_error "jq command not found. Cannot parse JSON baseline file." 1
        exit 1
    }

    # Extract specific thresholds using jq
    FAILED_LOGIN_THRESHOLD=$(jq -r '.authentication.failed_login_threshold // 5' "$BASELINE_FILE")
    CPU_ALERT_THRESHOLD=$(jq -r '.system_activity.cpu_baseline.web_servers.alert_threshold // 85' "$BASELINE_FILE")
    NETWORK_CONN_THRESHOLD=$(jq -r '.system_activity.network_baseline.outbound_connections_per_hour.alert_threshold // 10000' "$BASELINE_FILE")

    # Extract custom metrics if specified
    for metric in "${ADDITIONAL_METRICS[@]}"; do
        metric_key=$(echo "$metric" | tr '-' '_')
        CUSTOM_BASELINE_KEYS+=("$metric_key")
        declare -g "THRESHOLD_${metric_key^^}"
        value=$(jq -r ".. | select(has(\"$metric_key\")) | .$metric_key.alert_threshold // \"\"" "$BASELINE_FILE" | grep -v "^$" | head -1)
        if [[ -n "$value" ]]; then
            declare -g "THRESHOLD_${metric_key^^}=$value"
            log_debug "Loaded custom metric threshold: $metric_key = $value"
        else
            log_warn "Custom metric '$metric_key' not found in baseline"
        fi
    done

    log_debug "Baseline thresholds loaded: FailedLogins=$FAILED_LOGIN_THRESHOLD, CPUAlert=$CPU_ALERT_THRESHOLD, NetworkConn=$NETWORK_CONN_THRESHOLD"

    # Store the full baseline content for complex checks
    BASELINE_CONTENT=$(jq -c '.' "$BASELINE_FILE")
}

# Load detection rules
load_detection_rules() {
    log_info "Loading detection rules from $RULES_DIR"

    if [[ ! -d "$RULES_DIR" ]]; then
        log_warn "Detection rules directory not found: $RULES_DIR"
        return 1
    }

    # Initialize rule arrays
    declare -g AUTH_RULES=()
    declare -g SYSTEM_RULES=()
    declare -g NETWORK_RULES=()

    # Process YAML files if available
    local yaml_files=("$RULES_DIR"/*.yml "$RULES_DIR"/*.yaml)

    if command -v python &>/dev/null && [[ -f "${yaml_files[0]}" ]]; then
        log_debug "Using Python to parse YAML files"

        # Load rules using Python for proper YAML parsing
        local rules_json
        rules_json=$(python -c "
import sys, json, yaml, glob
rules = {'auth': [], 'system': [], 'network': []}
try:
    for file in glob.glob('$RULES_DIR/*.y*ml'):
        with open(file, 'r') as f:
            data = yaml.safe_load(f)
            if data and 'rules' in data:
                for rule in data['rules']:
                    category = rule.get('category', 'unknown')
                    if category in rules:
                        rules[category].append(rule)
    print(json.dumps(rules))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" 2>/dev/null)

        if [[ "$rules_json" == *'"error"'* ]]; then
            log_warn "Error parsing YAML files: $(echo "$rules_json" | jq -r '.error')"
        else
            # Store rules by category
            local auth_count system_count network_count
            auth_count=$(echo "$rules_json" | jq -r '.auth | length')
            system_count=$(echo "$rules_json" | jq -r '.system | length')
            network_count=$(echo "$rules_json" | jq -r '.network | length')

            log_debug "Loaded $auth_count auth rules, $system_count system rules, $network_count network rules"

            RULES_JSON="$rules_json"
        fi
    else
        # Fallback to basic rule loading
        local auth_files=("$RULES_DIR"/suspicious_auth.y*ml "$RULES_DIR"/authentication.y*ml)
        local system_files=("$RULES_DIR"/system_*.y*ml "$RULES_DIR"/resource_*.y*ml)
        local network_files=("$RULES_DIR"/network_*.y*ml "$RULES_DIR"/connection_*.y*ml)

        if [[ -f "${auth_files[0]}" ]]; then
            log_debug "Found authentication rule files"
            AUTH_RULES+=("${auth_files[@]}")
        fi

        if [[ -f "${system_files[0]}" ]]; then
            log_debug "Found system rule files"
            SYSTEM_RULES+=("${system_files[@]}")
        fi

        if [[ -f "${network_files[0]}" ]]; then
            log_debug "Found network rule files"
            NETWORK_RULES+=("${network_files[@]}")
        fi
    fi
}

# Parse and convert timeframe to start/end times
parse_time_range() {
    local timeframe="$1"
    local end_time
    local start_time

    # Validate timeframe format
    if ! validate_timeframe "$timeframe"; then
        log_warn "Invalid timeframe format: $timeframe. Using default 24h."
        timeframe="24h"
    }

    # Get current time in ISO format
    end_time=$(get_current_time)

    # Calculate start time
    if [[ "$DATE_UTILS_AVAILABLE" == "true" ]]; then
        start_time=$(get_start_time "$timeframe")
    else
        # Basic calculation for common timeframes
        case "$timeframe" in
            *h)
                local hours="${timeframe%h}"
                start_time=$(date -u -d "-${hours} hours" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null ||
                           date -u -v "-${hours}H" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
                ;;
            *d)
                local days="${timeframe%d}"
                start_time=$(date -u -d "-${days} days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null ||
                           date -u -v "-${days}d" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
                ;;
            *)
                start_time=$(date -u -d "-1 day" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null ||
                           date -u -v "-1d" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
                ;;
        esac
    fi

    echo "$start_time" "$end_time"
}

# Fetch data from various sources
fetch_data() {
    local scope="$1"
    local start_time="$2"
    local end_time="$3"

    log_info "Fetching data for scope '$scope' from $start_time to $end_time"

    # Create temporary directory for fetched data
    local tmp_dir
    tmp_dir=$(mktemp -d "/tmp/anomaly_detector.XXXXXX")
    chmod 700 "$tmp_dir"

    TEMP_DATA_DIR="$tmp_dir"
    trap 'rm -rf "$TEMP_DATA_DIR"' EXIT

    # Data fetch functions for different scopes
    if [[ "$scope" == "user" || "$scope" == "all" ]]; then
        fetch_user_activity_data "$start_time" "$end_time" "$tmp_dir/user_data.json"
    fi

    if [[ "$scope" == "system" || "$scope" == "all" ]]; then
        fetch_system_metrics_data "$start_time" "$end_time" "$tmp_dir/system_data.json"
    fi

    if [[ "$scope" == "network" || "$scope" == "all" ]]; then
        fetch_network_traffic_data "$start_time" "$end_time" "$tmp_dir/network_data.json"
    fi
}

# Fetch user activity data
fetch_user_activity_data() {
    local start_time="$1"
    local end_time="$2"
    local output_file="$3"

    log_debug "Fetching user activity data from $start_time to $end_time"

    # Try various methods to get user activity data

    # 1. Try using core audit utility if available
    if python -c "import importlib.util; print(importlib.util.find_spec('core.security.cs_audit') is not None)" 2>/dev/null | grep -q "True"; then
        log_debug "Using core.security.cs_audit module for user data"

        python -c "
from core.security.cs_audit import get_recent_security_events
import json, sys, datetime
from dateutil import parser

try:
    start_dt = parser.parse('$start_time')
    end_dt = parser.parse('$end_time')

    events = get_recent_security_events(
        start_time=start_dt,
        end_time=end_dt,
        event_types=['auth.login', 'auth.logout', 'auth.failed_login', 'user.action', 'admin.action'],
        limit=1000
    )

    # Convert datetime objects to strings for JSON serialization
    for event in events:
        if 'created_at' in event and isinstance(event['created_at'], datetime.datetime):
            event['created_at'] = event['created_at'].isoformat()

    with open('$output_file', 'w') as f:
        json.dump(events, f)

    print(f'Fetched {len(events)} user activity events')
    sys.exit(0)
except Exception as e:
    print(f'Error fetching user activity: {str(e)}', file=sys.stderr)
    sys.exit(1)
" || log_warn "Failed to fetch user activity data from core audit module"

        if [[ -f "$output_file" && -s "$output_file" ]]; then
            log_debug "Successfully fetched user activity data from core audit module"
            return 0
        fi
    fi

    # 2. Try using admin utils if available
    if [[ -f "${PROJECT_ROOT}/admin/utils/audit_utils.py" ]]; then
        log_debug "Using admin audit utils for user data"

        python "${PROJECT_ROOT}/admin/utils/audit_utils.py" \
            --action get_admin_audit_logs \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --output "$output_file" || log_warn "Failed to fetch user activity data from admin utils"

        if [[ -f "$output_file" && -s "$output_file" ]]; then
            log_debug "Successfully fetched user activity data from admin utils"
            return 0
        fi
    fi

    # 3. Simple fallback - look for auth logs in common locations
    log_debug "Using fallback method for user activity data"

    local auth_logs=("/var/log/auth.log" "/var/log/secure" "/var/log/apache2/access.log" "/var/log/cloud-platform/access.log")
    local combined_log="$output_file.tmp"

    for log_file in "${auth_logs[@]}"; do
        if [[ -f "$log_file" && -r "$log_file" ]]; then
            # Convert timestamps and extract recent entries
            if command -v grep &>/dev/null && command -v awk &>/dev/null; then
                grep -i "login\|auth\|user\|pass\|failed\|session" "$log_file" 2>/dev/null >> "$combined_log" || true
            fi
        fi
    done

    if [[ -f "$combined_log" && -s "$combined_log" ]]; then
        # Convert to simple JSON format
        echo "[" > "$output_file"
        local first=true

        while IFS= read -r line; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo "," >> "$output_file"
            fi

            # Extract timestamp with various formats
            local timestamp
            timestamp=$(echo "$line" | grep -E -o '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})' ||
                       echo "$line" | grep -E -o '[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' ||
                       echo "")

            # Basic sanitization for JSON
            local sanitized_line
            sanitized_line=$(escape_json "$line")

            # Create simple event object
            echo "{\"event_type\": \"log_entry\", \"created_at\": \"$timestamp\", \"message\": \"$sanitized_line\"}" >> "$output_file"
        done < "$combined_log"

        echo "]" >> "$output_file"
        rm "$combined_log"

        log_debug "Created simplified user activity data from system logs"
        return 0
    fi

    # Create empty array if all methods failed
    echo "[]" > "$output_file"
    log_warn "Failed to fetch user activity data, using empty dataset"
    return 1
}

# Fetch system metrics data
fetch_system_metrics_data() {
    local start_time="$1"
    local end_time="$2"
    local output_file="$3"

    log_debug "Fetching system metrics data from $start_time to $end_time"

    # Try various methods to get system metrics

    # 1. Try using a monitoring API if available
    if command -v curl &>/dev/null; then
        local metrics_url="${METRICS_API_URL:-http://localhost:8080/api/metrics}"
        local api_key="${METRICS_API_KEY:-}"

        if [[ -n "$api_key" ]]; then
            log_debug "Attempting to fetch metrics from API: $metrics_url"

            if curl -s -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d "{\"start_time\": \"$start_time\", \"end_time\": \"$end_time\", \"metrics\": [\"cpu\", \"memory\", \"disk\", \"load\"]}" \
                -o "$output_file" "$metrics_url"; then

                if [[ -s "$output_file" && $(cat "$output_file" | grep -c "error") -eq 0 ]]; then
                    log_debug "Successfully fetched metrics from API"
                    return 0
                fi
            fi

            log_warn "Failed to fetch metrics from API"
        fi
    fi

    # 2. Collect current system metrics
    log_debug "Using fallback method to collect current system metrics"

    # Initialize output file with JSON structure
    echo "{\"metrics\": {" > "$output_file"
    local first_metric=true

    # CPU metrics
    if command -v top &>/dev/null; then
        if ! $first_metric; then echo "," >> "$output_file"; fi
        first_metric=false

        echo "\"cpu\": {" >> "$output_file"

        # Get CPU usage using top in batch mode
        cpu_line=$(top -b -n 1 | grep -i "Cpu(s)" | head -n 1)

        # Extract the CPU usage percentages
        user=$(echo "$cpu_line" | grep -o '[0-9.]*%*us' | grep -o '[0-9.]*' || echo "0")
        system=$(echo "$cpu_line" | grep -o '[0-9.]*%*sy' | grep -o '[0-9.]*' || echo "0")
        idle=$(echo "$cpu_line" | grep -o '[0-9.]*%*id' | grep -o '[0-9.]*' || echo "0")
        iowait=$(echo "$cpu_line" | grep -o '[0-9.]*%*wa' | grep -o '[0-9.]*' || echo "0")

        echo "\"user\": $user," >> "$output_file"
        echo "\"system\": $system," >> "$output_file"
        echo "\"idle\": $idle," >> "$output_file"
        echo "\"iowait\": $iowait" >> "$output_file"

        echo "}" >> "$output_file"
    fi

    # Memory metrics
    if command -v free &>/dev/null; then
        if ! $first_metric; then echo "," >> "$output_file"; fi
        first_metric=false

        echo "\"memory\": {" >> "$output_file"

        # Get memory usage using free
        mem_line=$(free -m | grep Mem:)

        # Extract values
        total=$(echo "$mem_line" | awk '{print $2}')
        used=$(echo "$mem_line" | awk '{print $3}')
        free=$(echo "$mem_line" | awk '{print $4}')

        # Calculate usage percentage
        if [[ $total -gt 0 ]]; then
            usage_percent=$(echo "scale=2; $used * 100 / $total" | bc)
        else
            usage_percent="0"
        fi

        echo "\"total_mb\": $total," >> "$output_file"
        echo "\"used_mb\": $used," >> "$output_file"
        echo "\"free_mb\": $free," >> "$output_file"
        echo "\"usage_percent\": $usage_percent" >> "$output_file"

        echo "}" >> "$output_file"
    fi

    # Disk metrics
    if command -v df &>/dev/null; then
        if ! $first_metric; then echo "," >> "$output_file"; fi
        first_metric=false

        echo "\"disk\": {" >> "$output_file"

        # Get disk usage for root filesystem
        disk_line=$(df -h / | grep -v Filesystem)

        # Extract values
        size=$(echo "$disk_line" | awk '{print $2}')
        used=$(echo "$disk_line" | awk '{print $3}')
        avail=$(echo "$disk_line" | awk '{print $4}')
        use_percent=$(echo "$disk_line" | awk '{print $5}' | tr -d '%')

        echo "\"size\": \"$size\"," >> "$output_file"
        echo "\"used\": \"$used\"," >> "$output_file"
        echo "\"available\": \"$avail\"," >> "$output_file"
        echo "\"usage_percent\": $use_percent" >> "$output_file"

        echo "}" >> "$output_file"
    fi

    # Load average
    if [[ -f "/proc/loadavg" ]]; then
        if ! $first_metric; then echo "," >> "$output_file"; fi
        first_metric=false

        echo "\"load\": {" >> "$output_file"

        # Get load averages
        read -r load1 load5 load15 _ < /proc/loadavg

        echo "\"load1\": $load1," >> "$output_file"
        echo "\"load5\": $load5," >> "$output_file"
        echo "\"load15\": $load15" >> "$output_file"

        echo "}" >> "$output_file"
    fi

    # Close the JSON structure
    echo "}, \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" >> "$output_file"

    log_debug "Created system metrics snapshot"
    return 0
}

# Fetch network traffic data
fetch_network_traffic_data() {
    local start_time="$1"
    local end_time="$2"
    local output_file="$3"

    log_debug "Fetching network traffic data from $start_time to $end_time"

    # Try using various methods to get network data

    # 1. Try using a network monitoring API if available
    if command -v curl &>/dev/null; then
        local network_url="${NETWORK_API_URL:-http://localhost:8080/api/network}"
        local api_key="${NETWORK_API_KEY:-}"

        if [[ -n "$api_key" ]]; then
            log_debug "Attempting to fetch network data from API: $network_url"

            if curl -s -H "Authorization: Bearer $api_key" \
                -H "Content-Type: application/json" \
                -d "{\"start_time\": \"$start_time\", \"end_time\": \"$end_time\"}" \
                -o "$output_file" "$network_url"; then

                if [[ -s "$output_file" && $(cat "$output_file" | grep -c "error") -eq 0 ]]; then
                    log_debug "Successfully fetched network data from API"
                    return 0
                fi
            fi

            log_warn "Failed to fetch network data from API"
        fi
    fi

    # 2. Use netstat or ss for current connections
    log_debug "Using fallback method to collect current network data"

    # Initialize output file with JSON structure
    echo "{\"connections\": [" > "$output_file"
    local first_conn=true

    # Get active connections
    local conn_data
    if command -v ss &>/dev/null; then
        conn_data=$(ss -tunaH)
    elif command -v netstat &>/dev/null; then
        conn_data=$(netstat -tunaH)
    else
        conn_data=""
    fi

    # Process each connection
    echo "$conn_data" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        if ! $first_conn; then echo "," >> "$output_file"; fi
        first_conn=false

        # Parse connection details (simplified)
        local proto status local_addr remote_addr
        read -r proto status local_addr remote_addr _ <<< "$line"

        echo "{" >> "$output_file"
        echo "\"protocol\": \"$proto\"," >> "$output_file"
        echo "\"status\": \"$status\"," >> "$output_file"
        echo "\"local_address\": \"$local_addr\"," >> "$output_file"
        echo "\"remote_address\": \"$remote_addr\"" >> "$output_file"
        echo "}" >> "$output_file"
    done

    # Add basic endpoint checks
    if [[ "$NETWORK_UTILS_AVAILABLE" == "true" ]]; then
        echo ", \"endpoints\": [" >> "$output_file"

        # Check some common endpoints
        local endpoints=("google.com" "github.com" "api.example.com")
        local first_endpoint=true

        for endpoint in "${endpoints[@]}"; do
            if ! $first_endpoint; then echo "," >> "$output_file"; fi
            first_endpoint=false

            local url="https://$endpoint"
            local latency_ms=0
            local status_code=0

            # Check endpoint connectivity
            if command -v curl &>/dev/null; then
                local curl_result
                curl_result=$(curl -s -o /dev/null -w "%{time_total},%{http_code}" --connect-timeout 5 "$url")
                latency_ms=$(echo "$curl_result" | cut -d',' -f1)
                latency_ms=$(echo "$latency_ms * 1000" | bc | cut -d'.' -f1)
                status_code=$(echo "$curl_result" | cut -d',' -f2)
            fi

            echo "{" >> "$output_file"
            echo "\"url\": \"$url\"," >> "$output_file"
            echo "\"latency_ms\": $latency_ms," >> "$output_file"
            echo "\"status_code\": $status_code" >> "$output_file"
            echo "}" >> "$output_file"
        done

        echo "]" >> "$output_file"
    fi

    # Close the JSON structure
    echo "], \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" >> "$output_file"

    log_debug "Created network data snapshot"
    return 0
}

# Analyze user activity data for anomalies
analyze_user_activity() {
    local data_file="${TEMP_DATA_DIR}/user_data.json"
    local anomalies_found=()

    log_info "Analyzing user activity for anomalies"

    if [[ ! -f "$data_file" || ! -s "$data_file" ]]; then
        log_warn "No user activity data available for analysis"
        echo "${anomalies_found[@]}"
        return 0
    fi

    # Parse the user data file
    if command -v jq &>/dev/null; then
        # Check for failed login patterns
        local failed_logins
        failed_logins=$(jq -c '[.[] | select(.event_type == "auth.failed_login" or .message | contains("Failed login") or .message | contains("Failed password"))]' "$data_file")
        local failed_count
        failed_count=$(echo "$failed_logins" | jq '. | length')

        if [[ "$failed_count" -gt "$FAILED_LOGIN_THRESHOLD" ]]; then
            local message="Detected $failed_count failed login attempts (threshold: $FAILED_LOGIN_THRESHOLD)"
            anomalies_found+=("$message")
            log_warn "User anomaly: $message"

            # Check for clustering by IP address
            local failed_by_ip
            failed_by_ip=$(echo "$failed_logins" | jq -c 'group_by(.ip_address) | map({ip: .[0].ip_address, count: length}) | sort_by(-.count)')

            local top_ips
            top_ips=$(echo "$failed_by_ip" | jq -c '[.[] | select(.count > 2)]')
            local top_ips_count
            top_ips_count=$(echo "$top_ips" | jq '. | length')

            if [[ "$top_ips_count" -gt 0 ]]; then
                local top_ip
                top_ip=$(echo "$top_ips" | jq -r '.[0].ip')
                local top_count
                top_count=$(echo "$top_ips" | jq -r '.[0].count')

                local ip_message="Potential brute force: $top_count failed logins from IP $top_ip"
                anomalies_found+=("$ip_message")
                log_warn "User anomaly: $ip_message"
            fi
        fi

        # Check for after-hours logins
        local successful_logins
        successful_logins=$(jq -c '[.[] | select(.event_type == "auth.login" or .message | contains("Accepted password"))]' "$data_file")

        echo "$successful_logins" | jq -c '.[]' | while IFS= read -r login; do
            local timestamp
            timestamp=$(echo "$login" | jq -r '.created_at')

            if [[ -n "$timestamp" && "$timestamp" != "null" ]]; then
                # Extract hour (simple heuristic for after-hours check)
                local hour
                hour=$(echo "$timestamp" | grep -o 'T[0-9]\{2\}:' | tr -d 'T:')

                if [[ -n "$hour" && "$hour" -ge 22 || "$hour" -le 5 ]]; then
                    local user
                    user=$(echo "$login" | jq -r '.username // .user_id // "unknown"')
                    local time
                    time=$(echo "$timestamp" | grep -o 'T[0-9]\{2\}:[0-9]\{2\}')

                    local night_message="After-hours login by user $user at $time"
                    anomalies_found+=("$night_message")
                    log_warn "User anomaly: $night_message"
                fi
            fi
        done

        # Check for admin actions frequency
        local admin_actions
        admin_actions=$(jq -c '[.[] | select(.event_type | startswith("admin."))]' "$data_file")
        local admin_count
        admin_count=$(echo "$admin_actions" | jq '. | length')

        if [[ "$admin_count" -gt 10 ]]; then  # Arbitrary threshold
            local admin_message="High frequency of administrative actions: $admin_count"
            anomalies_found+=("$admin_message")
            log_warn "User anomaly: $admin_message"
        fi

        # Check for privilege escalation events
        local priv_escalation
        priv_escalation=$(jq -c '[.[] | select(.event_type | contains("role") or .event_type | contains("permission") or .message | contains("sudo") or .message | contains("root"))]' "$data_file")
        local priv_count
        priv_count=$(echo "$priv_escalation" | jq '. | length')

        if [[ "$priv_count" -gt 3 ]]; then  # Arbitrary threshold
            local priv_message="Potential privilege escalation activity: $priv_count events"
            anomalies_found+=("$priv_message")
            log_warn "User anomaly: $priv_message"
        fi
    else
        # Fallback basic analysis without jq
        local failed_pattern="Failed|failure|invalid"
        local failed_count
        failed_count=$(grep -i "$failed_pattern" "$data_file" | wc -l)

        if [[ "$failed_count" -gt "$FAILED_LOGIN_THRESHOLD" ]]; then
            local message="Detected $failed_count failed login attempts (threshold: $FAILED_LOGIN_THRESHOLD)"
            anomalies_found+=("$message")
            log_warn "User anomaly: $message"
        fi
    fi

    # Return anomalies separated by delimiter for array processing
    local IFS=$'\n'
    echo "${anomalies_found[*]}"
}

# Analyze system metrics data for anomalies
analyze_system_metrics() {
    local data_file="${TEMP_DATA_DIR}/system_data.json"
    local anomalies_found=()

    log_info "Analyzing system metrics for anomalies"

    if [[ ! -f "$data_file" || ! -s "$data_file" ]]; then
        log_warn "No system metrics data available for analysis"
        echo "${anomalies_found[@]}"
        return 0
    fi

    # Parse the system metrics file
    if command -v jq &>/dev/null; then
        # Check CPU usage
        local cpu_usage
        cpu_usage=$(jq -r '.metrics.cpu.user + .metrics.cpu.system' "$data_file" 2>/dev/null || echo "0")

        if [[ -n "$cpu_usage" && "$cpu_usage" != "null" && "$cpu_usage" -gt "$CPU_ALERT_THRESHOLD" ]]; then
            local message="High CPU usage: ${cpu_usage}% (threshold: ${CPU_ALERT_THRESHOLD}%)"
            anomalies_found+=("$message")
            log_warn "System anomaly: $message"
        fi

        # Check Memory usage
        local memory_usage
        memory_usage=$(jq -r '.metrics.memory.usage_percent' "$data_file" 2>/dev/null || echo "0")

        if [[ -n "$memory_usage" && "$memory_usage" != "null" && "$memory_usage" -gt 90 ]]; then
            local message="High memory usage: ${memory_usage}% (threshold: 90%)"
            anomalies_found+=("$message")
            log_warn "System anomaly: $message"
        fi

        # Check Disk usage
        local disk_usage
        disk_usage=$(jq -r '.metrics.disk.usage_percent' "$data_file" 2>/dev/null || echo "0")

        if [[ -n "$disk_usage" && "$disk_usage" != "null" && "$disk_usage" -gt 85 ]]; then
            local message="High disk usage: ${disk_usage}% (threshold: 85%)"
            anomalies_found+=("$message")
            log_warn "System anomaly: $message"
        fi

        # Check load average
        local load_avg
        load_avg=$(jq -r '.metrics.load.load1' "$data_file" 2>/dev/null || echo "0")
        # Simple heuristic: Check if load exceeds number of CPUs
        local cpu_count
        cpu_count=$(grep -c processor /proc/cpuinfo 2>/dev/null || echo 1)

        if [[ -n "$load_avg" && "$load_avg" != "null" && $(echo "$load_avg > $cpu_count * 1.5" | bc -l) -eq 1 ]]; then
            local message="High load average: ${load_avg} (threshold: $(echo "$cpu_count * 1.5" | bc) for ${cpu_count} CPUs)"
            anomalies_found+=("$message")
            log_warn "System anomaly: $message"
        fi

        # Check custom metrics if defined
        for metric in "${CUSTOM_BASELINE_KEYS[@]}"; do
            local metric_path
            metric_path=$(echo "$metric" | tr '_' '.')
            local metric_value
            metric_value=$(jq -r ".metrics.$metric_path // 0" "$data_file" 2>/dev/null || echo "0")

            # Get defined threshold for this metric
            local threshold_var="THRESHOLD_${metric^^}"
            local threshold="${!threshold_var:-0}"

            if [[ -n "$metric_value" && "$metric_value" != "null" && "$metric_value" -gt "$threshold" ]]; then
                local message="High $metric: ${metric_value} (threshold: ${threshold})"
                anomalies_found+=("$message")
                log_warn "System anomaly: $message"
            fi
        done
    else
        # Very basic analysis for system metrics without jq
        if grep -q "cpu" "$data_file"; then
            local cpu_line
            cpu_line=$(grep -A 3 '"cpu"' "$data_file" | grep -o '"user": [0-9.]*' | cut -d' ' -f2)

            if [[ -n "$cpu_line" && "$cpu_line" -gt "$CPU_ALERT_THRESHOLD" ]]; then
                local message="High CPU usage: ${cpu_line}% (threshold: ${CPU_ALERT_THRESHOLD}%)"
                anomalies_found+=("$message")
                log_warn "System anomaly: $message"
            fi
        fi
    fi

    # Return anomalies separated by delimiter for array processing
    local IFS=$'\n'
    echo "${anomalies_found[*]}"
}

# Analyze network traffic data for anomalies
analyze_network_traffic() {
    local data_file="${TEMP_DATA_DIR}/network_data.json"
    local anomalies_found=()

    log_info "Analyzing network traffic for anomalies"

    if [[ ! -f "$data_file" || ! -s "$data_file" ]]; then
        log_warn "No network traffic data available for analysis"
        echo "${anomalies_found[@]}"
        return 0
    fi

    # Parse the network data file
    if command -v jq &>/dev/null; then
        # Count connections
        local total_connections
        total_connections=$(jq '.connections | length' "$data_file" 2>/dev/null || echo "0")

        if [[ -n "$total_connections" && "$total_connections" != "null" && "$total_connections" -gt "$NETWORK_CONN_THRESHOLD" ]]; then
            local message="High connection count: $total_connections (threshold: $NETWORK_CONN_THRESHOLD)"
            anomalies_found+=("$message")
            log_warn "Network anomaly: $message"
        fi

        # Check unusual ports (common targets for scanning/attacks)
        local suspicious_ports=(22 23 3389 5900 6379 9200 27017 28017 6379 11211 8080 4444 4443)
        local open_suspicious=()

        for port in "${suspicious_ports[@]}"; do
            local count
            count=$(jq -c '.connections[] | select(.local_address | test(":'$port'$"))' "$data_file" 2>/dev/null | wc -l)

            if [[ "$count" -gt 0 ]]; then
                open_suspicious+=("$port")
            fi
        done

        if [[ "${#open_suspicious[@]}" -gt 2 ]]; then
            local message="Multiple suspicious ports open: ${open_suspicious[*]}"
            anomalies_found+=("$message")
            log_warn "Network anomaly: $message"
        fi

        # Check endpoint latency if available
        if jq -e '.endpoints' "$data_file" 2>/dev/null; then
            jq -c '.endpoints[]' "$data_file" | while IFS= read -r endpoint; do
                local url
                url=$(echo "$endpoint" | jq -r '.url')
                local latency
                latency=$(echo "$endpoint" | jq -r '.latency_ms')
                local status
                status=$(echo "$endpoint" | jq -r '.status_code')

                # Save historical latency data for trend analysis
                local safe_name
                safe_name=$(url_to_safe_name "$url")
                local history_file="${HISTORY_DIR}/${safe_name}_latency_history.log"

                # Check for latency anomalies
                if [[ "$NETWORK_UTILS_AVAILABLE" == "true" && "$latency" -gt 0 ]]; then
                    # Record current latency with status code and timestamp
                    echo "$latency $status $(date +%s)" >> "$history_file"

                    # Analyze trends if we have enough history
                    if [[ -f "$history_file" && $(wc -l < "$history_file") -gt 5 ]]; then
                        analyze_latency_trend "$url" "$latency" "$HISTORY_DIR" "$THRESHOLD_MULTIPLIER"

                        if [[ "$LATENCY_ANOMALY" == "true" ]]; then
                            local message="Latency spike detected for $url: ${latency}ms ($LATENCY_TREND trend)"
                            anomalies_found+=("$message")
                            log_warn "Network anomaly: $message"
                        fi
                    fi

                    # Trim history file if too large
                    if [[ -f "$history_file" && $(wc -l < "$history_file") -gt "$MAX_HISTORY_ENTRIES" ]]; then
                        tail -n "$MAX_HISTORY_ENTRIES" "$history_file" > "${history_file}.tmp"
                        mv "${history_file}.tmp" "$history_file"
                    fi

                    # Check for error status codes
                    if [[ "$status" -ge 400 ]]; then
                        local message="Error response from $url: HTTP $status"
                        anomalies_found+=("$message")
                        log_warn "Network anomaly: $message"
                    fi
                fi
            done
        fi
    else
        # Very basic analysis for network data without jq
        if grep -q "connections" "$data_file"; then
            local conn_count
            conn_count=$(grep -o '{' "$data_file" | wc -l)

            if [[ "$conn_count" -gt "$NETWORK_CONN_THRESHOLD" ]]; then
                local message="High connection count: $conn_count (threshold: $NETWORK_CONN_THRESHOLD)"
                anomalies_found+=("$message")
                log_warn "Network anomaly: $message"
            fi
        fi
    fi

    # Return anomalies separated by delimiter for array processing
    local IFS=$'\n'
    echo "${anomalies_found[*]}"
}

# Generate report from findings
generate_report() {
    local findings_array=("$@")
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local found_count="${#findings_array[@]}"

    log_info "Generating anomaly report with $found_count findings"

    # Ensure the output directory exists
    mkdir -p "$(dirname "$REPORT_FILE")"

    case "$OUTPUT_FORMAT" in
        json)
            generate_json_report "$timestamp" "${findings_array[@]}"
            ;;
        html)
            generate_html_report "$timestamp" "${findings_array[@]}"
            ;;
        *)
            # Default to text
            generate_text_report "$timestamp" "${findings_array[@]}"
            ;;
    esac

    # Set appropriate permissions for the report file
    chmod 640 "$REPORT_FILE"

    log_info "Report saved to $REPORT_FILE"
}

# Generate JSON format report
generate_json_report() {
    local timestamp="$1"
    shift
    local findings_array=("$@")

    # Start JSON structure
    cat > "$REPORT_FILE" << EOF
{
  "report_metadata": {
    "timestamp": "$timestamp",
    "scope": "$SCAN_SCOPE",
    "timeframe": "$TIMEFRAME",
    "environment": "$ENVIRONMENT",
    "baseline_file": "$BASELINE_FILE",
    "sensitivity": "$SENSITIVITY"
  },
  "anomalies": [
EOF

    # Add findings
    local first=true
    for finding in "${findings_array[@]}"; do
        # Skip empty findings
        [[ -z "$finding" ]] && continue

        if [[ "$first" == "false" ]]; then
            echo "," >> "$REPORT_FILE"
        fi
        first=false

        # Determine category based on content
        local category="unknown"
        if [[ "$finding" == *"User anomaly"* || "$finding" == *"login"* || "$finding" == *"user"* ]]; then
            category="user"
        elif [[ "$finding" == *"System anomaly"* || "$finding" == *"CPU"* || "$finding" == *"memory"* || "$finding" == *"disk"* ]]; then
            category="system"
        elif [[ "$finding" == *"Network anomaly"* || "$finding" == *"connection"* || "$finding" == *"port"* || "$finding" == *"latency"* ]]; then
            category="network"
        fi

        # Determine severity based on content and sensitivity
        local severity="medium"
        if [[ "$finding" == *"Critical"* || "$finding" == *"privilege escalation"* || "$finding" == *"High"* ]]; then
            severity="critical"
        elif [[ "$finding" == *"brute force"* || "$finding" == *"suspicious"* ]]; then
            severity="high"
        elif [[ "$finding" == *"warning"* || "$finding" == *"unusual"* ]]; then
            severity="medium"
        fi

        # Escape JSON special characters
        local escaped_finding
        escaped_finding=$(escape_json "$finding")

        # Create the JSON entry
        cat >> "$REPORT_FILE" << EOF
    {
      "description": "$escaped_finding",
      "category": "$category",
      "severity": "$severity",
      "detection_time": "$timestamp"
    }
EOF
    done

    # Add summary and close JSON
    cat >> "$REPORT_FILE" << EOF
  ],
  "summary": {
    "total_anomalies": ${#findings_array[@]},
    "environment": "$ENVIRONMENT",
    "scan_duration_seconds": $SECONDS
  }
}
EOF
}

# Generate text format report
generate_text_report() {
    local timestamp="$1"
    shift
    local findings_array=("$@")

    # Create the text report
    cat > "$REPORT_FILE" << EOF
======================================================
Anomaly Detection Report - $timestamp
======================================================
Scope: $SCAN_SCOPE
Timeframe: $TIMEFRAME
Environment: $ENVIRONMENT
Baseline: $BASELINE_FILE
Sensitivity: $SENSITIVITY
------------------------------------------------------

EOF

    # Add findings with categories
    if [[ ${#findings_array[@]} -eq 0 ]]; then
        echo "No anomalies detected." >> "$REPORT_FILE"
    else
        echo "Detected Anomalies (${#findings_array[@]}):" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        # Group by categories
        local user_anomalies=()
        local system_anomalies=()
        local network_anomalies=()
        local other_anomalies=()

        for finding in "${findings_array[@]}"; do
            # Skip empty findings
            [[ -z "$finding" ]] && continue

            if [[ "$finding" == *"User anomaly"* || "$finding" == *"login"* || "$finding" == *"user"* ]]; then
                user_anomalies+=("$finding")
            elif [[ "$finding" == *"System anomaly"* || "$finding" == *"CPU"* || "$finding" == *"memory"* || "$finding" == *"disk"* ]]; then
                system_anomalies+=("$finding")
            elif [[ "$finding" == *"Network anomaly"* || "$finding" == *"connection"* || "$finding" == *"port"* || "$finding" == *"latency"* ]]; then
                network_anomalies+=("$finding")
            else
                other_anomalies+=("$finding")
            fi
        done

        # Print user anomalies
        if [[ ${#user_anomalies[@]} -gt 0 ]]; then
            echo "USER ACTIVITY ANOMALIES:" >> "$REPORT_FILE"
            echo "------------------------" >> "$REPORT_FILE"
            for finding in "${user_anomalies[@]}"; do
                echo "  * $finding" >> "$REPORT_FILE"
            done
            echo "" >> "$REPORT_FILE"
        fi

        # Print system anomalies
        if [[ ${#system_anomalies[@]} -gt 0 ]]; then
            echo "SYSTEM METRIC ANOMALIES:" >> "$REPORT_FILE"
            echo "------------------------" >> "$REPORT_FILE"
            for finding in "${system_anomalies[@]}"; do
                echo "  * $finding" >> "$REPORT_FILE"
            done
            echo "" >> "$REPORT_FILE"
        fi

        # Print network anomalies
        if [[ ${#network_anomalies[@]} -gt 0 ]]; then
            echo "NETWORK TRAFFIC ANOMALIES:" >> "$REPORT_FILE"
            echo "--------------------------" >> "$REPORT_FILE"
            for finding in "${network_anomalies[@]}"; do
                echo "  * $finding" >> "$REPORT_FILE"
            done
            echo "" >> "$REPORT_FILE"
        fi

        # Print other anomalies
        if [[ ${#other_anomalies[@]} -gt 0 ]]; then
            echo "OTHER ANOMALIES:" >> "$REPORT_FILE"
            echo "----------------" >> "$REPORT_FILE"
            for finding in "${other_anomalies[@]}"; do
                echo "  * $finding" >> "$REPORT_FILE"
            done
            echo "" >> "$REPORT_FILE"
        fi
    fi

    # Add summary
    cat >> "$REPORT_FILE" << EOF
======================================================
SUMMARY:
  - Total anomalies: ${#findings_array[@]}
  - Scan duration: $SECONDS seconds
  - Environment: $ENVIRONMENT
  - Generated by: $(basename "$0") v1.2
======================================================
EOF
}

# Generate HTML format report
generate_html_report() {
    local timestamp="$1"
    shift
    local findings_array=("$@")

    # Check for custom template
    local template_file="${PROJECT_ROOT}/admin/security/monitoring/templates/anomaly_report.html"
    local use_template=false

    if [[ -f "$template_file" && -r "$template_file" ]]; then
        use_template=true
    fi

    # Group findings by category and severity
    local user_critical=() user_high=() user_medium=() user_low=()
    local system_critical=() system_high=() system_medium=() system_low=()
    local network_critical=() network_high=() network_medium=() network_low=()
    local other_anomalies=()

    for finding in "${findings_array[@]}"; do
        # Skip empty findings
        [[ -z "$finding" ]] && continue

        # Determine category
        local category="other"
        if [[ "$finding" == *"User anomaly"* || "$finding" == *"login"* || "$finding" == *"user"* ]]; then
            category="user"
        elif [[ "$finding" == *"System anomaly"* || "$finding" == *"CPU"* || "$finding" == *"memory"* || "$finding" == *"disk"* ]]; then
            category="system"
        elif [[ "$finding" == *"Network anomaly"* || "$finding" == *"connection"* || "$finding" == *"port"* || "$finding" == *"latency"* ]]; then
            category="network"
        fi

        # Determine severity
        local severity="medium"
        if [[ "$finding" == *"Critical"* || "$finding" == *"privilege escalation"* || "$finding" == *"High"* ]]; then
            severity="critical"
        elif [[ "$finding" == *"brute force"* || "$finding" == *"suspicious"* ]]; then
            severity="high"
        elif [[ "$finding" == *"warning"* || "$finding" == *"unusual"* ]]; then
            severity="medium"
        else
            severity="low"
        fi

        # Add to appropriate array
        case "$category" in
            user)
                case "$severity" in
                    critical) user_critical+=("$finding") ;;
                    high) user_high+=("$finding") ;;
                    medium) user_medium+=("$finding") ;;
                    low) user_low+=("$finding") ;;
                esac
                ;;
            system)
                case "$severity" in
                    critical) system_critical+=("$finding") ;;
                    high) system_high+=("$finding") ;;
                    medium) system_medium+=("$finding") ;;
                    low) system_low+=("$finding") ;;
                esac
                ;;
            network)
                case "$severity" in
                    critical) network_critical+=("$finding") ;;
                    high) network_high+=("$finding") ;;
                    medium) network_medium+=("$finding") ;;
                    low) network_low+=("$finding") ;;
                esac
                ;;
            *)
                other_anomalies+=("$finding")
                ;;
        esac
    done

    # Start HTML content
    if [[ "$use_template" == "true" ]]; then
        # Use the template file as base
        cp "$template_file" "$REPORT_FILE"

        # Replace template placeholders
        # These replacements depend on your template structure
        sed -i'' -e "s|{{TIMESTAMP}}|$timestamp|g" "$REPORT_FILE"
        sed -i'' -e "s|{{ENVIRONMENT}}|$ENVIRONMENT|g" "$REPORT_FILE"
        sed -i'' -e "s|{{SCOPE}}|$SCAN_SCOPE|g" "$REPORT_FILE"
        sed -i'' -e "s|{{TIMEFRAME}}|$TIMEFRAME|g" "$REPORT_FILE"
        sed -i'' -e "s|{{BASELINE}}|$(basename "$BASELINE_FILE")|g" "$REPORT_FILE"
        sed -i'' -e "s|{{SENSITIVITY}}|$SENSITIVITY|g" "$REPORT_FILE"
        sed -i'' -e "s|{{TOTAL_ANOMALIES}}|${#findings_array[@]}|g" "$REPORT_FILE"
    else
        # Create HTML structure from scratch
        cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anomaly Detection Report - $ENVIRONMENT</title>
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
        .timestamp {
            font-size: 0.9em;
            color: #ddd;
        }
        .metadata {
            background-color: #f8f8f8;
            padding: 15px;
            margin-bottom: 20px;
            border-left: 5px solid #0078d4;
        }
        .metadata p {
            margin: 5px 0;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            flex: 1;
            min-width: 200px;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .card h3 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .count {
            font-size: 24px;
            font-weight: bold;
        }
        .critical {
            background-color: #fde0dd;
            border-left: 5px solid #e41a1c;
        }
        .high {
            background-color: #fff3de;
            border-left: 5px solid #ff7f00;
        }
        .medium {
            background-color: #ffffcc;
            border-left: 5px solid #ffcc00;
        }
        .low {
            background-color: #e5f5e0;
            border-left: 5px solid #4daf4a;
        }
        .findings h3 {
            color: #0078d4;
            border-bottom: 1px solid #0078d4;
            padding-bottom: 5px;
        }
        .finding-item {
            padding: 10px;
            border-left: 3px solid #ddd;
            margin-bottom: 10px;
        }
        .finding-item.critical {
            border-left-color: #e41a1c;
        }
        .finding-item.high {
            border-left-color: #ff7f00;
        }
        .finding-item.medium {
            border-left-color: #ffcc00;
        }
        .finding-item.low {
            border-left-color: #4daf4a;
        }
        .footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.9em;
            color: #777;
        }
        @media print {
            body {
                background-color: white;
            }
            .container {
                box-shadow: none;
            }
            .no-print {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Anomaly Detection Report</h1>
            <p class="timestamp">Generated on $timestamp</p>
        </header>

        <div class="metadata">
            <p><strong>Environment:</strong> $ENVIRONMENT</p>
            <p><strong>Scope:</strong> $SCAN_SCOPE</p>
            <p><strong>Timeframe:</strong> $TIMEFRAME</p>
            <p><strong>Baseline:</strong> $(basename "$BASELINE_FILE")</p>
            <p><strong>Sensitivity:</strong> $SENSITIVITY</p>
        </div>

        <div class="summary">
            <div class="card">
                <h3>Total Anomalies</h3>
                <div class="count">${#findings_array[@]}</div>
            </div>
            <div class="card critical">
                <h3>Critical</h3>
                <div class="count">$((${#user_critical[@]} + ${#system_critical[@]} + ${#network_critical[@]}))</div>
            </div>
            <div class="card high">
                <h3>High</h3>
                <div class="count">$((${#user_high[@]} + ${#system_high[@]} + ${#network_high[@]}))</div>
            </div>
            <div class="card medium">
                <h3>Medium</h3>
                <div class="count">$((${#user_medium[@]} + ${#system_medium[@]} + ${#network_medium[@]}))</div>
            </div>
            <div class="card low">
                <h3>Low</h3>
                <div class="count">$((${#user_low[@]} + ${#system_low[@]} + ${#network_low[@]}))</div>
            </div>
        </div>
EOF

        # Add User Activity Findings
        if [ ${#user_critical[@]} -gt 0 ] || [ ${#user_high[@]} -gt 0 ] || [ ${#user_medium[@]} -gt 0 ] || [ ${#user_low[@]} -gt 0 ]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="findings user-findings">
            <h3>User Activity Anomalies</h3>
EOF

            # Critical user findings
            for finding in "${user_critical[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item critical">
                <strong>CRITICAL:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # High user findings
            for finding in "${user_high[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item high">
                <strong>HIGH:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Medium user findings
            for finding in "${user_medium[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item medium">
                <strong>MEDIUM:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Low user findings
            for finding in "${user_low[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item low">
                <strong>LOW:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            cat >> "$REPORT_FILE" << EOF
        </div>
EOF
        fi

        # Add System Metric Findings
        if [ ${#system_critical[@]} -gt 0 ] || [ ${#system_high[@]} -gt 0 ] || [ ${#system_medium[@]} -gt 0 ] || [ ${#system_low[@]} -gt 0 ]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="findings system-findings">
            <h3>System Metric Anomalies</h3>
EOF

            # Critical system findings
            for finding in "${system_critical[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item critical">
                <strong>CRITICAL:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # High system findings
            for finding in "${system_high[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item high">
                <strong>HIGH:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Medium system findings
            for finding in "${system_medium[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item medium">
                <strong>MEDIUM:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Low system findings
            for finding in "${system_low[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item low">
                <strong>LOW:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            cat >> "$REPORT_FILE" << EOF
        </div>
EOF
        fi

        # Add Network Traffic Findings
        if [ ${#network_critical[@]} -gt 0 ] || [ ${#network_high[@]} -gt 0 ] || [ ${#network_medium[@]} -gt 0 ] || [ ${#network_low[@]} -gt 0 ]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="findings network-findings">
            <h3>Network Traffic Anomalies</h3>
EOF

            # Critical network findings
            for finding in "${network_critical[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item critical">
                <strong>CRITICAL:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # High network findings
            for finding in "${network_high[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item high">
                <strong>HIGH:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Medium network findings
            for finding in "${network_medium[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item medium">
                <strong>MEDIUM:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            # Low network findings
            for finding in "${network_low[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item low">
                <strong>LOW:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            cat >> "$REPORT_FILE" << EOF
        </div>
EOF
        fi

        # Add Other Anomalies if any
        if [ ${#other_anomalies[@]} -gt 0 ]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="findings other-findings">
            <h3>Other Anomalies</h3>
EOF

            # Other findings
            for finding in "${other_anomalies[@]}"; do
                cat >> "$REPORT_FILE" << EOF
            <div class="finding-item medium">
                <strong>INFO:</strong> $(escape_html "$finding")
            </div>
EOF
            done

            cat >> "$REPORT_FILE" << EOF
        </div>
EOF
        fi

        # Add Recommendations Section (if we have anomalies)
        if [ ${#findings_array[@]} -gt 0 ]; then
            cat >> "$REPORT_FILE" << EOF
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
EOF

            # Add recommendations based on findings
            if [ $((${#user_critical[@]} + ${#user_high[@]})) -gt 0 ]; then
                cat >> "$REPORT_FILE" << EOF
                <li>Investigate suspicious user activity and consider implementing additional authentication controls.</li>
EOF
            fi

            if [ $((${#system_critical[@]} + ${#system_high[@]})) -gt 0 ]; then
                cat >> "$REPORT_FILE" << EOF
                <li>Check system resource usage and optimize performance or increase resources if necessary.</li>
EOF
            fi

            if [ $((${#network_critical[@]} + ${#network_high[@]})) -gt 0 ]; then
                cat >> "$REPORT_FILE" << EOF
                <li>Review network security policies and monitor suspicious connections.</li>
EOF
            fi

            cat >> "$REPORT_FILE" << EOF
            </ul>
        </div>
EOF
        fi

        # Add Print Button and Close HTML
        cat >> "$REPORT_FILE" << EOF
        <div class="no-print" style="text-align: center; margin: 30px 0;">
            <button onclick="window.print()" style="padding: 10px 20px; background-color: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer;">
                Print Report
            </button>
        </div>

        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Anomaly Detection System</p>
            <p>Scan Duration: $SECONDS seconds</p>
        </div>
    </div>
</body>
</html>
EOF
    fi

    log_debug "HTML report generated successfully"
}

# Helper function to escape special characters for HTML output
escape_html() {
    local string="$1"
    local result="$string"

    # Replace special characters
    result="${result//&/&amp;}"
    result="${result//</&lt;}"
    result="${result//>/&gt;}"
    result="${result//\"/&quot;}"
    result="${result//\'/&#39;}"

    echo "$result"
}
