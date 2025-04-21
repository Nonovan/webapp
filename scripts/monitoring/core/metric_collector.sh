#!/bin/bash
# Metric Collector Script for Cloud Infrastructure Platform
# Collects and processes system and application metrics
# Usage: ./metric_collector.sh [environment] [options]

set -e

# Default settings
ENVIRONMENT=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
METRICS_DIR="/var/lib/metrics"
OUTPUT_FORMAT="text"  # text, json, or prometheus
VERBOSE=false
QUIET=false
COLLECT_SYSTEM=true
COLLECT_APP=true
COLLECT_DB=true
COLLECT_NETWORK=true
COLLECT_CUSTOM=true
METRICS_RETENTION=30 # days
METRICS_FILE="/var/lib/node_exporter/textfile_collector/collected_metrics.prom"
REPORT_FILE=""
STORE_HISTORY=true
EXPORT_METRICS=false
NOTIFY=false
EMAIL_RECIPIENT=""
FREQUENCY="once"  # once, hourly, daily
TIMEOUT=60        # seconds
API_ENDPOINT=""
API_KEY=""

# Create timestamps for filenames
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
DEFAULT_REPORT_FILE="/tmp/metric-collector-${ENVIRONMENT}-${TIMESTAMP}.txt"
JSON_REPORT_FILE="/tmp/metric-collector-${ENVIRONMENT}-${TIMESTAMP}.json"

# Ensure log directory exists
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/metric-collector.log"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"

    if [[ "$QUIET" != "true" ]]; then
        echo -e "$message"
    fi

    echo -e "$message" >> "$LOG_FILE"
}

# Parse command line arguments
shift_count=0
if [[ ! -z "$1" && "$1" != --* ]]; then
    shift_count=1  # Skip the environment parameter in the while loop
fi

while [[ $# -gt $shift_count ]]; do
    key="${1}"
    case $key in
        --api-endpoint)
            API_ENDPOINT="${2}"
            shift 2
            ;;
        --api-key)
            API_KEY="${2}"
            shift 2
            ;;
        --no-system)
            COLLECT_SYSTEM=false
            shift
            ;;
        --no-app)
            COLLECT_APP=false
            shift
            ;;
        --no-db)
            COLLECT_DB=false
            shift
            ;;
        --no-network)
            COLLECT_NETWORK=false
            shift
            ;;
        --no-custom)
            COLLECT_CUSTOM=false
            shift
            ;;
        --format)
            OUTPUT_FORMAT="${2}"
            if [[ "$OUTPUT_FORMAT" != "text" && "$OUTPUT_FORMAT" != "json" && "$OUTPUT_FORMAT" != "prometheus" ]]; then
                echo "Error: Format must be 'text', 'json', or 'prometheus'"
                exit 1
            fi
            shift 2
            ;;
        --report-file)
            REPORT_FILE="${2}"
            shift 2
            ;;
        --metrics-dir)
            METRICS_DIR="${2}"
            shift 2
            ;;
        --metrics-file)
            METRICS_FILE="${2}"
            shift 2
            ;;
        --retention)
            METRICS_RETENTION="${2}"
            shift 2
            ;;
        --export-metrics)
            EXPORT_METRICS=true
            shift
            ;;
        --no-history)
            STORE_HISTORY=false
            shift
            ;;
        --notify)
            NOTIFY=true
            if [[ ! -z "${2}" && "${2}" != --* ]]; then
                EMAIL_RECIPIENT="${2}"
                shift
            fi
            shift
            ;;
        --frequency)
            FREQUENCY="${2}"
            if [[ "$FREQUENCY" != "once" && "$FREQUENCY" != "hourly" && "$FREQUENCY" != "daily" ]]; then
                echo "Error: Frequency must be 'once', 'hourly', or 'daily'"
                exit 1
            fi
            shift 2
            ;;
        --timeout)
            TIMEOUT="${2}"
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
        --help|-h)
            echo "Usage: $0 [environment] [options]"
            echo "Options:"
            echo "  --api-endpoint URL       API endpoint for application metrics"
            echo "  --api-key KEY            API key for authentication"
            echo "  --no-system              Skip system metrics collection"
            echo "  --no-app                 Skip application metrics collection"
            echo "  --no-db                  Skip database metrics collection"
            echo "  --no-network             Skip network metrics collection"
            echo "  --no-custom              Skip custom metrics collection"
            echo "  --format FORMAT          Output format: text, json, or prometheus (default: text)"
            echo "  --report-file FILE       Write report to specified file"
            echo "  --metrics-dir DIR        Directory to store historical metrics (default: /var/lib/metrics)"
            echo "  --metrics-file FILE      File to write Prometheus metrics to"
            echo "  --retention DAYS         Number of days to retain historical metrics (default: 30)"
            echo "  --export-metrics         Export metrics in Prometheus format"
            echo "  --no-history             Don't store metrics history"
            echo "  --notify [EMAIL]         Send notification with metrics report"
            echo "  --frequency FREQ         Frequency: once, hourly, daily (default: once)"
            echo "  --timeout SECONDS        Timeout for API calls in seconds (default: 60)"
            echo "  --verbose, -v            Show detailed output"
            echo "  --quiet, -q              Minimal output"
            echo "  --help, -h               Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set the report file if not specified
if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$DEFAULT_REPORT_FILE"
fi

# Load environment-specific configuration
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Make sure API endpoint is set if needed
if [[ "$COLLECT_APP" == "true" && -z "$API_ENDPOINT" ]]; then
    # Try to determine API endpoint from environment variables
    if [[ -n "$PRIMARY_API_ENDPOINT" ]]; then
        API_ENDPOINT="$PRIMARY_API_ENDPOINT/metrics"
        log "Using API endpoint from environment: $API_ENDPOINT"
    else
        log "WARNING: No API endpoint specified for application metrics collection"
        COLLECT_APP=false
    fi
fi

# Create metrics directory if storing history
if [[ "$STORE_HISTORY" == "true" ]]; then
    mkdir -p "$METRICS_DIR"
fi

# Check required commands
for cmd in jq curl bc; do
    if ! command -v $cmd &> /dev/null; then
        log "WARNING: Required command '$cmd' not found. Some functionality may be limited."
    fi
done

# Function to collect system metrics
collect_system_metrics() {
    log "Collecting system metrics..."
    local system_metrics=()

    # CPU usage
    if command -v top &> /dev/null; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            local cpu_usage=$(top -l 1 | grep "CPU usage" | awk -F': ' '{print $2}' | awk -F'% idle' '{print 100 - $1}')
            system_metrics+=("cpu_usage_percent:$cpu_usage")
        else
            # Linux
            local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
            system_metrics+=("cpu_usage_percent:$cpu_usage")

            # CPU load averages
            if [[ -f "/proc/loadavg" ]]; then
                local load_1m=$(cat /proc/loadavg | awk '{print $1}')
                local load_5m=$(cat /proc/loadavg | awk '{print $2}')
                local load_15m=$(cat /proc/loadavg | awk '{print $3}')
                system_metrics+=("load_avg_1m:$load_1m")
                system_metrics+=("load_avg_5m:$load_5m")
                system_metrics+=("load_avg_15m:$load_15m")
            fi
        fi
    fi

    # Memory usage
    if command -v free &> /dev/null; then
        # Linux
        local mem_total=$(free -m | grep Mem | awk '{print $2}')
        local mem_used=$(free -m | grep Mem | awk '{print $3}')
        local mem_usage_percent=$(echo "scale=1; $mem_used * 100 / $mem_total" | bc)
        system_metrics+=("memory_total_mb:$mem_total")
        system_metrics+=("memory_used_mb:$mem_used")
        system_metrics+=("memory_usage_percent:$mem_usage_percent")

        # Swap usage
        local swap_total=$(free -m | grep Swap | awk '{print $2}')
        if [[ "$swap_total" != "0" ]]; then
            local swap_used=$(free -m | grep Swap | awk '{print $3}')
            local swap_usage_percent=$(echo "scale=1; $swap_used * 100 / $swap_total" | bc)
            system_metrics+=("swap_total_mb:$swap_total")
            system_metrics+=("swap_used_mb:$swap_used")
            system_metrics+=("swap_usage_percent:$swap_usage_percent")
        fi
    elif [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        local mem_total=$(sysctl hw.memsize | awk '{print $2 / 1024 / 1024}')
        local mem_pages=$(vm_stat | grep "Pages active" | awk '{print $3}' | tr -d '.')
        local mem_page_size=4096 # 4KB on macOS
        local mem_used=$(echo "scale=1; $mem_pages * $mem_page_size / 1024 / 1024" | bc)
        local mem_usage_percent=$(echo "scale=1; $mem_used * 100 / $mem_total" | bc)
        system_metrics+=("memory_total_mb:$mem_total")
        system_metrics+=("memory_used_mb:$mem_used")
        system_metrics+=("memory_usage_percent:$mem_usage_percent")
    fi

    # Disk usage
    if command -v df &> /dev/null; then
        local disk_total=$(df -h / | awk 'NR==2 {print $2}')
        local disk_used=$(df -h / | awk 'NR==2 {print $3}')
        local disk_avail=$(df -h / | awk 'NR==2 {print $4}')
        local disk_usage_percent=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
        system_metrics+=("disk_total:$disk_total")
        system_metrics+=("disk_used:$disk_used")
        system_metrics+=("disk_available:$disk_avail")
        system_metrics+=("disk_usage_percent:$disk_usage_percent")
    fi

    # Process count
    if command -v ps &> /dev/null; then
        local process_count=$(ps -e | wc -l | awk '{print $1-1}') # Subtract header
        system_metrics+=("process_count:$process_count")
    fi

    # Uptime
    if command -v uptime &> /dev/null; then
        local uptime_str=$(uptime)
        system_metrics+=("uptime:$(echo "$uptime_str" | sed 's/^.*up *//' | sed 's/,.*//')")
    fi

    # System information if available
    if [[ -f "/etc/os-release" ]]; then
        local os_name=$(grep "PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"')
        system_metrics+=("os:$os_name")
    elif [[ "$(uname)" == "Darwin" ]]; then
        local os_version=$(sw_vers -productVersion)
        system_metrics+=("os:macOS $os_version")
    fi

    echo "${system_metrics[@]}"
}

# Function to collect application metrics from API
collect_app_metrics() {
    log "Collecting application metrics..."
    local app_metrics=()

    if [[ -z "$API_ENDPOINT" ]]; then
        log "WARNING: API endpoint not specified, skipping application metrics collection"
        return
    fi

    local api_url="${API_ENDPOINT}"
    local curl_opts=("-s" "-m" "$TIMEOUT")

    # Add API key if provided
    if [[ -n "$API_KEY" ]]; then
        curl_opts+=("-H" "Authorization: Bearer $API_KEY")
    fi

    # Make API request
    local response
    response=$(curl "${curl_opts[@]}" "$api_url" 2>/dev/null)
    local curl_status=$?

    if [[ $curl_status -ne 0 ]]; then
        log "ERROR: Failed to connect to API endpoint $api_url (curl status: $curl_status)"
        return
    fi

    # Check if response is valid JSON
    if ! echo "$response" | jq -e . >/dev/null 2>&1; then
        log "ERROR: Invalid JSON response from API endpoint"
        if [[ "$VERBOSE" == "true" ]]; then
            log "Response: $response"
        fi
        return
    fi

    # Parse JSON response for metrics
    if command -v jq &> /dev/null; then
        local metrics_count=$(echo "$response" | jq '.metrics | length')

        if [[ "$metrics_count" -eq 0 ]]; then
            log "WARNING: No metrics found in API response"
            return
        fi

        for ((i=0; i<metrics_count; i++)); do
            local name=$(echo "$response" | jq -r ".metrics[$i].name")
            local value=$(echo "$response" | jq -r ".metrics[$i].value")
            local unit=$(echo "$response" | jq -r ".metrics[$i].unit // \"\"")

            if [[ -n "$unit" ]]; then
                app_metrics+=("app_${name}_${unit}:$value")
            else
                app_metrics+=("app_${name}:$value")
            fi
        done

        # Get application status if available
        local status=$(echo "$response" | jq -r ".status // \"\"")
        if [[ -n "$status" && "$status" != "null" ]]; then
            app_metrics+=("app_status:$status")
        fi

        # Get request count if available
        local requests=$(echo "$response" | jq -r ".requests // \"\"")
        if [[ -n "$requests" && "$requests" != "null" ]]; then
            app_metrics+=("app_requests:$requests")
        fi

        # Get error count if available
        local errors=$(echo "$response" | jq -r ".errors // \"\"")
        if [[ -n "$errors" && "$errors" != "null" ]]; then
            app_metrics+=("app_errors:$errors")
        fi
    else
        log "WARNING: jq not available, cannot parse JSON response"
    fi

    echo "${app_metrics[@]}"
}

# Function to collect database metrics
collect_db_metrics() {
    log "Collecting database metrics..."
    local db_metrics=()

    # Database configuration can be loaded from environment file
    local DB_HOST="${DB_HOST:-localhost}"
    local DB_PORT="${DB_PORT:-5432}"
    local DB_USER="${DB_USER:-postgres}"
    local DB_PASSWORD="${DB_PASSWORD:-}"
    local DB_NAME="${DB_NAME:-postgres}"
    local DB_TYPE="${DB_TYPE:-postgresql}"

    # PostgreSQL metrics
    if [[ "$DB_TYPE" == "postgresql" ]] && command -v psql &> /dev/null; then
        log "Collecting PostgreSQL metrics from $DB_HOST:$DB_PORT..."

        # Build connection string
        local psql_cmd="psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c"
        if [[ -n "$DB_PASSWORD" ]]; then
            export PGPASSWORD="$DB_PASSWORD"
        fi

        # Try to connect and execute queries
        if $psql_cmd "SELECT 1;" &>/dev/null; then
            # Database connection count
            local conn_count=$($psql_cmd "SELECT count(*) FROM pg_stat_activity;" | tr -d ' ')
            db_metrics+=("db_connections:$conn_count")

            # Database size
            local db_size=$($psql_cmd "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" | tr -d ' ')
            db_metrics+=("db_size:$db_size")

            # Transactions
            local xact_commit=$($psql_cmd "SELECT sum(xact_commit) FROM pg_stat_database;" | tr -d ' ')
            local xact_rollback=$($psql_cmd "SELECT sum(xact_rollback) FROM pg_stat_database;" | tr -d ' ')
            db_metrics+=("db_commits:$xact_commit")
            db_metrics+=("db_rollbacks:$xact_rollback")

            # Cache hit ratio
            local cache_hit_ratio=$($psql_cmd "SELECT round(sum(blks_hit)*100/sum(blks_hit+blks_read), 2) FROM pg_stat_database;" | tr -d ' ')
            db_metrics+=("db_cache_hit_ratio:$cache_hit_ratio")

            # Locks
            local locks=$($psql_cmd "SELECT count(*) FROM pg_locks;" | tr -d ' ')
            db_metrics+=("db_locks:$locks")

            # Deadlocks
            local deadlocks=$($psql_cmd "SELECT deadlocks FROM pg_stat_database WHERE datname='$DB_NAME';" | tr -d ' ')
            db_metrics+=("db_deadlocks:$deadlocks")

            # Check for long-running queries
            local long_queries=$($psql_cmd "SELECT count(*) FROM pg_stat_activity WHERE state='active' AND query_start < now() - interval '5 minutes';" | tr -d ' ')
            db_metrics+=("db_long_running_queries:$long_queries")
        else
            log "ERROR: Failed to connect to PostgreSQL database"
        fi

        # Clear password from environment
        unset PGPASSWORD

    # MySQL metrics
    elif [[ "$DB_TYPE" == "mysql" ]] && command -v mysql &> /dev/null; then
        log "Collecting MySQL metrics from $DB_HOST:$DB_PORT..."

        # Build command
        local mysql_cmd="mysql -h $DB_HOST -P $DB_PORT -u $DB_USER"
        if [[ -n "$DB_PASSWORD" ]]; then
            mysql_cmd="$mysql_cmd -p$DB_PASSWORD"
        fi
        mysql_cmd="$mysql_cmd -N -e"

        # Try to connect and execute queries
        if $mysql_cmd "SELECT 1;" &>/dev/null; then
            # Get status variables
            local queries=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Questions';" | awk '{print $2}')
            db_metrics+=("db_queries:$queries")

            local connections=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Threads_connected';" | awk '{print $2}')
            db_metrics+=("db_connections:$connections")

            local slow_queries=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Slow_queries';" | awk '{print $2}')
            db_metrics+=("db_slow_queries:$slow_queries")

            local uptime=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Uptime';" | awk '{print $2}')
            db_metrics+=("db_uptime_seconds:$uptime")

            # Key buffer usage
            local key_reads=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Key_reads';" | awk '{print $2}')
            local key_read_requests=$($mysql_cmd "SHOW GLOBAL STATUS LIKE 'Key_read_requests';" | awk '{print $2}')

            if [[ "$key_read_requests" != "0" ]]; then
                local cache_hit_ratio=$(echo "scale=2; (1 - $key_reads / $key_read_requests) * 100" | bc)
                db_metrics+=("db_cache_hit_ratio:$cache_hit_ratio")
            fi

            # Database size
            local db_size=$($mysql_cmd "SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.tables WHERE table_schema='$DB_NAME';" | tr -d ' ')
            db_metrics+=("db_size_mb:$db_size")
        else
            log "ERROR: Failed to connect to MySQL database"
        fi
    else
        log "WARNING: Database client not available or unsupported database type: $DB_TYPE"
    fi

    echo "${db_metrics[@]}"
}

# Function to collect network metrics
collect_network_metrics() {
    log "Collecting network metrics..."
    local network_metrics=()

    # Linux network stats
    if [[ "$(uname)" == "Linux" ]]; then
        if [[ -d "/sys/class/net" ]]; then
            local interfaces=$(ls -1 /sys/class/net | grep -v "lo")
            for iface in $interfaces; do
                if [[ -f "/sys/class/net/$iface/statistics/rx_bytes" ]]; then
                    local rx_bytes=$(cat /sys/class/net/$iface/statistics/rx_bytes)
                    local tx_bytes=$(cat /sys/class/net/$iface/statistics/tx_bytes)
                    local rx_mb=$(echo "scale=2; $rx_bytes / 1024 / 1024" | bc)
                    local tx_mb=$(echo "scale=2; $tx_bytes / 1024 / 1024" | bc)

                    network_metrics+=("net_${iface}_rx_mb:$rx_mb")
                    network_metrics+=("net_${iface}_tx_mb:$tx_mb")
                fi
            done
        fi

        # Check active connections
        if command -v ss &> /dev/null || command -v netstat &> /dev/null; then
            local established=0
            if command -v ss &> /dev/null; then
                established=$(ss -tun state established | wc -l)
                # Subtract header lines
                established=$((established - 1))
            elif command -v netstat &> /dev/null; then
                established=$(netstat -tun | grep ESTABLISHED | wc -l)
            fi
            network_metrics+=("net_connections:$established")
        fi

        # Check for listening ports
        local listening_ports=0
        if command -v ss &> /dev/null; then
            listening_ports=$(ss -tln | grep LISTEN | wc -l)
        elif command -v netstat &> /dev/null; then
            listening_ports=$(netstat -tln | grep LISTEN | wc -l)
        fi
        network_metrics+=("net_listening_ports:$listening_ports")
    # macOS network stats
    elif [[ "$(uname)" == "Darwin" ]]; then
        if command -v netstat &> /dev/null; then
            # Get established connections
            local established=$(netstat -ant | grep ESTABLISHED | wc -l | tr -d ' ')
            network_metrics+=("net_connections:$established")

            # Get listening ports
            local listening_ports=$(netstat -ant | grep LISTEN | wc -l | tr -d ' ')
            network_metrics+=("net_listening_ports:$listening_ports")
        fi
    fi

    # Network latency checks
    if command -v ping &> /dev/null; then
        local targets=("8.8.8.8" "1.1.1.1")
        for target in "${targets[@]}"; do
            local ping_result=$(ping -c 3 $target 2>/dev/null | grep "avg" | awk -F'/' '{print $5}')
            if [[ -n "$ping_result" ]]; then
                network_metrics+=("net_latency_${target}:$ping_result")
            fi
        done
    fi

    echo "${network_metrics[@]}"
}

# Function to collect custom metrics
collect_custom_metrics() {
    log "Collecting custom metrics..."
    local custom_metrics=()

    # Look for custom metrics scripts
    local custom_dir="${PROJECT_ROOT}/scripts/monitoring/custom"
    if [[ -d "$custom_dir" ]]; then
        log "Checking custom metrics directory: $custom_dir"

        # Run each executable script in the custom directory
        for script in "$custom_dir"/*; do
            if [[ -x "$script" ]]; then
                log "Running custom metrics script: $(basename "$script")"
                local output=$("$script" --environment "$ENVIRONMENT" 2>/dev/null)
                local exit_code=$?

                if [[ $exit_code -eq 0 && -n "$output" ]]; then
                    # Process each line of output as a separate metric
                    while IFS= read -r line; do
                        if [[ "$line" =~ ^[a-zA-Z0-9_]+:[a-zA-Z0-9.]+$ ]]; then
                            custom_metrics+=("custom_$line")
                        fi
                    done <<< "$output"
                else
                    log "WARNING: Custom script $(basename "$script") failed with exit code $exit_code"
                fi
            fi
        done
    else
        log "Custom metrics directory not found: $custom_dir"
    fi

    echo "${custom_metrics[@]}"
}

# Function to format metrics for Prometheus
format_prometheus_metrics() {
    local timestamp=$(date +%s)
    local all_metrics=("$@")
    local prom_file="$METRICS_FILE"
    local metrics_dir=$(dirname "$prom_file")

    # Create directory if it doesn't exist
    if [[ ! -d "$metrics_dir" ]]; then
        mkdir -p "$metrics_dir" 2>/dev/null || {
            log "ERROR: Could not create metrics directory: $metrics_dir"
            return 1
        }
    }

    # Clear existing file
    > "$prom_file"

    # Add header
    echo "# HELP cloud_platform_metric_collection_timestamp Unix timestamp of metric collection" >> "$prom_file"
    echo "# TYPE cloud_platform_metric_collection_timestamp gauge" >> "$prom_file"
    echo "cloud_platform_metric_collection_timestamp{environment=\"${ENVIRONMENT}\"} $timestamp" >> "$prom_file"

    # Process all metrics
    for metric in "${all_metrics[@]}"; do
        local name=$(echo "$metric" | cut -d':' -f1)
        local value=$(echo "$metric" | cut -d':' -f2)

        # Skip metrics with non-numeric values
        if ! [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            continue
        fi

        # Convert metric name to Prometheus format
        local prom_name=$(echo "$name" | sed 's/[^a-zA-Z0-9_]/_/g')

        # Add metric definition
        echo "# HELP $prom_name $name metric from cloud platform" >> "$prom_file"
        echo "# TYPE $prom_name gauge" >> "$prom_file"
        echo "${prom_name}{environment=\"${ENVIRONMENT}\"} $value $timestamp" >> "$prom_file"
    done

    # Set appropriate permissions
    chmod 644 "$prom_file" 2>/dev/null || log "WARNING: Could not set permissions on $prom_file"

    log "Metrics exported to Prometheus format: $prom_file"
}

# Function to store metrics history
store_metrics_history() {
    local all_metrics=("$@")
    local history_dir="$METRICS_DIR/$ENVIRONMENT"
    local daily_dir="$history_dir/$(date +%Y-%m-%d)"
    local hourly_file="$daily_dir/$(date +%H).json"

    # Create directories if they don't exist
    mkdir -p "$daily_dir" 2>/dev/null || {
        log "ERROR: Could not create metrics history directory: $daily_dir"
        return 1
    }

    # Create metrics data in JSON format
    local json_content="{"
    json_content+="\"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    json_content+="\"environment\":\"$ENVIRONMENT\","
    json_content+="\"metrics\":{"

    local first=true
    for metric in "${all_metrics[@]}"; do
        local name=$(echo "$metric" | cut -d':' -f1)
        local value=$(echo "$metric" | cut -d':' -f2)

        if [[ "$first" == "true" ]]; then
            first=false
        else
            json_content+=","
        fi

        # Quote the value if it's not a number
        if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            json_content+="\"$name\":$value"
        else
            json_content+="\"$name\":\"$value\""
        fi
    done

    json_content+="}}"

    # Write to hourly file
    echo "$json_content" > "$hourly_file"
    log "Stored metrics history to $hourly_file"

    # Clean up old history files
    if [[ $METRICS_RETENTION -gt 0 ]]; then
        find "$METRICS_DIR" -type d -name "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" -mtime +$METRICS_RETENTION -exec rm -rf {} \; 2>/dev/null
        log "Cleaned up metrics history older than $METRICS_RETENTION days"
    fi
}

# Function to generate a text report
generate_text_report() {
    local all_metrics=("$@")

    log "Generating text report..."

    # Header
    cat > "$REPORT_FILE" << EOF
METRIC COLLECTION REPORT
=======================
Environment: $ENVIRONMENT
Date: $(date)
Hostname: $(hostname)

METRICS SUMMARY
--------------
EOF

    # Group metrics by type
    local system_metrics=()
    local app_metrics=()
    local db_metrics=()
    local network_metrics=()
    local custom_metrics=()

    for metric in "${all_metrics[@]}"; do
        local name=$(echo "$metric" | cut -d':' -f1)

        if [[ "$name" == cpu_* || "$name" == memory_* || "$name" == disk_* || "$name" == load_* || "$name" == process_* || "$name" == uptime || "$name" == os ]]; then
            system_metrics+=("$metric")
        elif [[ "$name" == app_* ]]; then
            app_metrics+=("$metric")
        elif [[ "$name" == db_* ]]; then
            db_metrics+=("$metric")
        elif [[ "$name" == net_* ]]; then
            network_metrics+=("$metric")
        elif [[ "$name" == custom_* ]]; then
            custom_metrics+=("$metric")
        fi
    done

    # Add system metrics
    if [[ ${#system_metrics[@]} -gt 0 ]]; then
        echo -e "\nSYSTEM METRICS" >> "$REPORT_FILE"
        echo "--------------" >> "$REPORT_FILE"
        for metric in "${system_metrics[@]}"; do
            local name=$(echo "$metric" | cut -d':' -f1)
            local value=$(echo "$metric" | cut -d':' -f2)
            printf "%-25s %s\n" "$name:" "$value" >> "$REPORT_FILE"
        done
    fi

    # Add application metrics
    if [[ ${#app_metrics[@]} -gt 0 ]]; then
        echo -e "\nAPPLICATION METRICS" >> "$REPORT_FILE"
        echo "-------------------" >> "$REPORT_FILE"
        for metric in "${app_metrics[@]}"; do
            local name=$(echo "$metric" | cut -d':' -f1)
            local value=$(echo "$metric" | cut -d':' -f2)
            printf "%-25s %s\n" "$name:" "$value" >> "$REPORT_FILE"
        done
    fi

    # Add database metrics
    if [[ ${#db_metrics[@]} -gt 0 ]]; then
        echo -e "\nDATABASE METRICS" >> "$REPORT_FILE"
        echo "----------------" >> "$REPORT_FILE"
        for metric in "${db_metrics[@]}"; do
            local name=$(echo "$metric" | cut -d':' -f1)
            local value=$(echo "$metric" | cut -d':' -f2)
            printf "%-25s %s\n" "$name:" "$value" >> "$REPORT_FILE"
        done
    fi

    # Add network metrics
    if [[ ${#network_metrics[@]} -gt 0 ]]; then
        echo -e "\nNETWORK METRICS" >> "$REPORT_FILE"
        echo "---------------" >> "$REPORT_FILE"
        for metric in "${network_metrics[@]}"; do
            local name=$(echo "$metric" | cut -d':' -f1)
            local value=$(echo "$metric" | cut -d':' -f2)
            printf "%-25s %s\n" "$name:" "$value" >> "$REPORT_FILE"
        done
    fi

    # Add custom metrics
    if [[ ${#custom_metrics[@]} -gt 0 ]]; then
        echo -e "\nCUSTOM METRICS" >> "$REPORT_FILE"
        echo "--------------" >> "$REPORT_FILE"
        for metric in "${custom_metrics[@]}"; do
            local name=$(echo "$metric" | cut -d':' -f1)
            local value=$(echo "$metric" | cut -d':' -f2)
            printf "%-25s %s\n" "$name:" "$value" >> "$REPORT_FILE"
        done
    fi

    # Footer
    echo -e "\nReport generated on $(date)" >> "$REPORT_FILE"

    # Output report if not in quiet mode
    if [[ "$OUTPUT_FORMAT" == "text" && "$QUIET" != "true" ]]; then
        cat "$REPORT_FILE"
    fi

    log "Report saved to $REPORT_FILE"
}

# Function to generate a JSON report
generate_json_report() {
    local all_metrics=("$@")

    log "Generating JSON report..."

    # Start JSON
    echo "{" > "$JSON_REPORT_FILE"
    echo "  \"metadata\": {" >> "$JSON_REPORT_FILE"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$JSON_REPORT_FILE"
    echo "    \"environment\": \"$ENVIRONMENT\"," >> "$JSON_REPORT_FILE"
    echo "    \"hostname\": \"$(hostname)\"" >> "$JSON_REPORT_FILE"
    echo "  }," >> "$JSON_REPORT_FILE"
    echo "  \"metrics\": {" >> "$JSON_REPORT_FILE"

    # Add metrics
    local first=true
    for metric in "${all_metrics[@]}"; do
        local name=$(echo "$metric" | cut -d':' -f1)
        local value=$(echo "$metric" | cut -d':' -f2)

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$JSON_REPORT_FILE"
        fi

        # Quote the value if it's not a number
        if [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            echo "    \"$name\": $value" >> "$JSON_REPORT_FILE"
        else
            echo "    \"$name\": \"$value\"" >> "$JSON_REPORT_FILE"
        fi
    done

    # Close JSON
    echo "" >> "$JSON_REPORT_FILE"
    echo "  }" >> "$JSON_REPORT_FILE"
    echo "}" >> "$JSON_REPORT_FILE"

    # Output JSON report if format is JSON
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        cat "$JSON_REPORT_FILE"
    fi

    log "JSON report saved to $JSON_REPORT_FILE"
}

# Function to send notification
send_notification() {
    local subject="Metric Collection Report - ${ENVIRONMENT}"
    local message="Metric collection report is attached."

    if [[ -z "$EMAIL_RECIPIENT" ]]; then
        log "WARNING: No email recipient specified for notification"
        return 1
    fi

    # Check if notification script exists
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority "low" \
            --subject "$subject" \
            --message "$message" \
            --recipient "$EMAIL_RECIPIENT" \
            --attachment "$REPORT_FILE"
        log "Notification sent to $EMAIL_RECIPIENT"
        return 0
    # Fall back to mail command
    elif command -v mail &>/dev/null; then
        echo "$message" | mail -s "$subject" -a "$REPORT_FILE" "$EMAIL_RECIPIENT"
        log "Notification sent to $EMAIL_RECIPIENT using mail command"
        return 0
    else
        log "WARNING: Could not send notification, notification tools not available"
        return 1
    fi
}

# Main function to collect metrics
collect_metrics() {
    log "Starting metric collection for ${ENVIRONMENT} environment"

    local all_metrics=()

    # Collect system metrics
    if [[ "$COLLECT_SYSTEM" == "true" ]]; then
        local system_results=($(collect_system_metrics))
        all_metrics+=("${system_results[@]}")
    fi

    # Collect application metrics
    if [[ "$COLLECT_APP" == "true" ]]; then
        local app_results=($(collect_app_metrics))
        all_metrics+=("${app_results[@]}")
    fi

    # Collect database metrics
    if [[ "$COLLECT_DB" == "true" ]]; then
        local db_results=($(collect_db_metrics))
        all_metrics+=("${db_results[@]}")
    fi

    # Collect network metrics
    if [[ "$COLLECT_NETWORK" == "true" ]]; then
        local network_results=($(collect_network_metrics))
        all_metrics+=("${network_results[@]}")
    fi

    # Collect custom metrics
    if [[ "$COLLECT_CUSTOM" == "true" ]]; then
        local custom_results=($(collect_custom_metrics))
        all_metrics+=("${custom_results[@]}")
    fi

    log "Collected ${#all_metrics[@]} metrics"

    # Generate report based on format
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        generate_json_report "${all_metrics[@]}"
    else
        generate_text_report "${all_metrics[@]}"
    fi

    # Export metrics to Prometheus format if requested
    if [[ "$EXPORT_METRICS" == "true" ]]; then
        format_prometheus_metrics "${all_metrics[@]}"
    fi

    # Store metrics history
    if [[ "$STORE_HISTORY" == "true" ]]; then
        store_metrics_history "${all_metrics[@]}"
    fi

    # Send notification if requested
    if [[ "$NOTIFY" == "true" ]]; then
        send_notification
    fi

    log "Metric collection completed successfully"
    return 0
}

# Function to set up cron job for scheduled runs
setup_schedule() {
    if [[ "$FREQUENCY" == "once" ]]; then
        return 0
    fi

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log "WARNING: Setting up scheduled runs requires root privileges"
        return 1
    fi

    local cron_file="/etc/cron.d/cloud-platform-metric-collector"
    local cmd_path=$(readlink -f "$0")
    local schedule=""

    case "$FREQUENCY" in
        hourly)
            schedule="0 * * * *"
            ;;
        daily)
            schedule="0 0 * * *"
            ;;
        *)
            log "ERROR: Invalid frequency: $FREQUENCY"
            return 1
            ;;
    esac

    # Create cron file
    cat > "$cron_file" << EOF
# Cloud Platform Metric Collector - $FREQUENCY schedule
$schedule root $cmd_path $ENVIRONMENT --quiet
EOF

    log "Scheduled metric collection ($FREQUENCY) set up in $cron_file"
}

# Main execution
collect_metrics

# Set up scheduled runs if requested
if [[ "$FREQUENCY" != "once" ]]; then
    setup_schedule
fi

exit 0
