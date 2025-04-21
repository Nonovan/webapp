#!/bin/bash
# Resource Monitor Script for Cloud Infrastructure Platform
# Provides real-time monitoring of system resources with alerting capabilities
# Usage: ./resource_monitor.sh [options]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform"
ALERT_DIR="/var/log/cloud-platform/alerts"
CONFIG_FILE="${PROJECT_ROOT}/config/monitoring.ini"
INTERVAL=5               # Check interval in seconds
DURATION=3600            # Total monitoring duration in seconds (default: 1 hour)
CPU_THRESHOLD=80         # CPU usage threshold percentage
MEMORY_THRESHOLD=80      # Memory usage threshold percentage
DISK_THRESHOLD=80        # Disk usage threshold percentage
LOAD_THRESHOLD=4         # Load average threshold (per core)
IO_THRESHOLD=80          # IO wait threshold percentage
VERBOSE=false            # Verbose output
QUIET=false              # Quiet mode
LOG_TO_FILE=true         # Log to file
GENERATE_REPORT=true     # Generate final report
NOTIFY_ON_THRESHOLD=true # Send notification when threshold is exceeded
NOTIFY_AT_END=false      # Send notification with report at end
EMAIL_RECIPIENT=""       # Email recipient for notifications
WATCH_MODE=false         # Interactive watch mode
PLOT_GRAPHS=false        # Generate performance graphs
RESOURCES_TO_MONITOR="cpu,memory,disk,load,network,io" # Resources to monitor
REPORT_FILE=""           # Report file path
LOG_FILE=""              # Log file path
COLLECT_PROCESSES=true   # Collect top processes info
PROCESS_COUNT=5          # Number of top processes to monitor

# Create a timestamp for filenames
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
DEFAULT_REPORT_FILE="/tmp/resource-monitor-${TIMESTAMP}.txt"
DEFAULT_LOG_FILE="${LOG_DIR}/resource-monitor.log"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --interval|-i)
            INTERVAL="$2"
            shift 2
            ;;
        --duration|-d)
            DURATION="$2"
            shift 2
            ;;
        --cpu-threshold)
            CPU_THRESHOLD="$2"
            shift 2
            ;;
        --memory-threshold)
            MEMORY_THRESHOLD="$2"
            shift 2
            ;;
        --disk-threshold)
            DISK_THRESHOLD="$2"
            shift 2
            ;;
        --load-threshold)
            LOAD_THRESHOLD="$2"
            shift 2
            ;;
        --io-threshold)
            IO_THRESHOLD="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --report-file)
            REPORT_FILE="$2"
            shift 2
            ;;
        --resources)
            RESOURCES_TO_MONITOR="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --notify)
            NOTIFY_AT_END=true
            if [[ ! -z "${2}" && "${2}" != --* ]]; then
                EMAIL_RECIPIENT="${2}"
                shift
            fi
            shift
            ;;
        --watch|-w)
            WATCH_MODE=true
            shift
            ;;
        --plot)
            PLOT_GRAPHS=true
            shift
            ;;
        --no-log)
            LOG_TO_FILE=false
            shift
            ;;
        --no-report)
            GENERATE_REPORT=false
            shift
            ;;
        --no-notify-threshold)
            NOTIFY_ON_THRESHOLD=false
            shift
            ;;
        --processes)
            COLLECT_PROCESSES=true
            if [[ ! -z "${2}" && "${2}" != --* && "${2}" =~ ^[0-9]+$ ]]; then
                PROCESS_COUNT="${2}"
                shift
            fi
            shift
            ;;
        --no-processes)
            COLLECT_PROCESSES=false
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
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --interval, -i SECONDS    Check interval in seconds (default: 5)"
            echo "  --duration, -d SECONDS    Total duration to monitor (default: 3600 = 1 hour)"
            echo "  --cpu-threshold PERCENT   CPU usage threshold percentage (default: 80)"
            echo "  --memory-threshold PERCENT Memory usage threshold percentage (default: 80)"
            echo "  --disk-threshold PERCENT  Disk usage threshold percentage (default: 80)"
            echo "  --load-threshold VALUE    Load average threshold per core (default: 4)"
            echo "  --io-threshold PERCENT    IO wait threshold percentage (default: 80)"
            echo "  --resources RESOURCES     Comma-separated list of resources to monitor"
            echo "                             (cpu,memory,disk,load,network,io) (default: all)"
            echo "  --log-file FILE           Log file path"
            echo "  --report-file FILE        Report file path"
            echo "  --config FILE             Configuration file path"
            echo "  --notify [EMAIL]          Send notification with report at end"
            echo "  --watch, -w               Interactive watch mode (updates terminal in real-time)"
            echo "  --plot                    Generate performance graphs (requires gnuplot)"
            echo "  --processes [COUNT]       Monitor top processes (default count: 5)"
            echo "  --no-processes            Don't monitor processes"
            echo "  --no-log                  Don't log to file"
            echo "  --no-report               Don't generate final report"
            echo "  --no-notify-threshold     Don't send notifications on threshold violations"
            echo "  --verbose, -v             Verbose output"
            echo "  --quiet, -q               Minimal output"
            echo "  --help, -h                Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set log and report files if not specified
if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="$DEFAULT_LOG_FILE"
fi

if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$DEFAULT_REPORT_FILE"
fi

# Ensure log directory exists
mkdir -p "$LOG_DIR"
mkdir -p "$ALERT_DIR"

# Define colors for terminal output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    local level="${2:-INFO}"

    if [[ "$QUIET" != "true" || "$level" == "ERROR" || "$level" == "CRITICAL" ]]; then
        # Add color for terminal output
        if [[ "$level" == "ERROR" || "$level" == "CRITICAL" ]]; then
            echo -e "${RED}${message}${NC}"
        elif [[ "$level" == "WARNING" ]]; then
            echo -e "${YELLOW}${message}${NC}"
        elif [[ "$level" == "INFO" ]]; then
            echo "${message}"
        elif [[ "$level" == "DEBUG" ]]; then
            if [[ "$VERBOSE" == "true" ]]; then
                echo -e "${BLUE}${message}${NC}"
            fi
        else
            echo "${message}"
        fi
    fi

    # Log to file if enabled
    if [[ "$LOG_TO_FILE" == "true" ]]; then
        echo "[${level}] ${message}" >> "$LOG_FILE"
    fi
}

# Parse configuration file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    log "Loading configuration from $CONFIG_FILE" "DEBUG"

    # Parse CPU threshold
    if grep -q "^cpu_threshold" "$CONFIG_FILE"; then
        CPU_THRESHOLD=$(grep "^cpu_threshold" "$CONFIG_FILE" | cut -d= -f2 | tr -d ' ')
        log "CPU threshold set to $CPU_THRESHOLD% from config" "DEBUG"
    fi

    # Parse Memory threshold
    if grep -q "^memory_threshold" "$CONFIG_FILE"; then
        MEMORY_THRESHOLD=$(grep "^memory_threshold" "$CONFIG_FILE" | cut -d= -f2 | tr -d ' ')
        log "Memory threshold set to $MEMORY_THRESHOLD% from config" "DEBUG"
    fi

    # Parse Disk threshold
    if grep -q "^disk_threshold" "$CONFIG_FILE"; then
        DISK_THRESHOLD=$(grep "^disk_threshold" "$CONFIG_FILE" | cut -d= -f2 | tr -d ' ')
        log "Disk threshold set to $DISK_THRESHOLD% from config" "DEBUG"
    fi

    # Parse other configuration options
    if grep -q "^notification_email" "$CONFIG_FILE" && [[ -z "$EMAIL_RECIPIENT" ]]; then
        EMAIL_RECIPIENT=$(grep "^notification_email" "$CONFIG_FILE" | cut -d= -f2 | tr -d ' ')
    fi
fi

# Array to store CPU usage history
declare -a cpu_history
# Array to store Memory usage history
declare -a mem_history
# Array to store Disk usage history
declare -a disk_history
# Array to store Load average history
declare -a load_history
# Array to store timestamps
declare -a timestamps

# Function to check if a resource should be monitored
should_monitor() {
    local resource="$1"
    [[ "$RESOURCES_TO_MONITOR" == "all" || "$RESOURCES_TO_MONITOR" =~ $resource ]]
}

# Function to get CPU usage
get_cpu_usage() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        top -l 1 | grep "CPU usage" | awk -F': ' '{print $2}' | awk -F'% idle' '{print 100 - $1}'
    else
        # Linux
        top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}'
    fi
}

# Function to get Memory usage
get_memory_usage() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        top -l 1 | grep "PhysMem" | awk -F', ' '{print $2}' | awk -F'M used' '{print $1}'
    else
        # Linux
        free -m | grep Mem | awk '{printf "%.1f", $3*100/$2}'
    fi
}

# Function to get Disk usage
get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}' | tr -d '%'
}

# Function to get Load average
get_load_average() {
    uptime | awk -F'[a-z]:' '{print $2}' | awk '{print $1}' | tr -d ','
}

# Function to get IO wait percentage
get_io_wait() {
    if [[ "$(uname)" == "Linux" ]]; then
        # Only available on Linux
        top -bn1 | grep "Cpu(s)" | awk '{print $10}'
    else
        # macOS doesn't have IO wait in the same way
        echo "0"
    fi
}

# Function to get top processes by CPU usage
get_top_processes() {
    local count="$1"

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        ps -arcwwxo command,pid,pcpu | head -n $((count+1)) | tail -n $count
    else
        # Linux
        ps -eo cmd,pid,pcpu --sort=-pcpu | head -n $((count+1)) | tail -n $count
    fi
}

# Function to send alert
send_alert() {
    local subject="$1"
    local message="$2"
    local priority="${3:-high}"

    # Skip if no email recipient configured
    if [[ -z "$EMAIL_RECIPIENT" ]]; then
        log "No email recipient configured, skipping alert" "WARNING"
        return
    fi

    # Log the alert
    log "ALERT: $subject - $message" "CRITICAL"

    # Write alert to alerts directory
    local alert_file="${ALERT_DIR}/alert-${TIMESTAMP}.txt"
    echo "ALERT: $subject" > "$alert_file"
    echo "Time: $(date)" >> "$alert_file"
    echo "Priority: $priority" >> "$alert_file"
    echo "Message: $message" >> "$alert_file"

    # Use notification script if available
    if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
        ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
            --priority "$priority" \
            --subject "$subject" \
            --message "$message" \
            --recipient "$EMAIL_RECIPIENT"
        return
    fi

    # Fall back to mail command
    if command -v mail &>/dev/null; then
        echo -e "$message" | mail -s "$subject" "$EMAIL_RECIPIENT"
        log "Alert email sent to $EMAIL_RECIPIENT" "INFO"
    else
        log "Cannot send email alert, mail command not available" "WARNING"
    fi
}

# Function to handle watch mode output
update_watch_display() {
    # Clear the screen
    clear

    # Print header
    echo "===== RESOURCE MONITOR ====="
    echo "Date: $(date)"
    echo "Monitoring interval: ${INTERVAL} seconds"
    echo "Thresholds: CPU ${CPU_THRESHOLD}%, Memory ${MEMORY_THRESHOLD}%, Disk ${DISK_THRESHOLD}%, Load ${LOAD_THRESHOLD}"
    echo "============================="

    # Print current values with color coding
    if should_monitor "cpu"; then
        local cpu_usage="${cpu_history[-1]}"
        if (( $(echo "$cpu_usage >= $CPU_THRESHOLD" | bc -l) )); then
            echo -e "CPU Usage: ${RED}${cpu_usage}%${NC}"
        elif (( $(echo "$cpu_usage >= $(($CPU_THRESHOLD * 8 / 10))" | bc -l) )); then
            echo -e "CPU Usage: ${YELLOW}${cpu_usage}%${NC}"
        else
            echo -e "CPU Usage: ${GREEN}${cpu_usage}%${NC}"
        fi
    fi

    if should_monitor "memory"; then
        local mem_usage="${mem_history[-1]}"
        if (( $(echo "$mem_usage >= $MEMORY_THRESHOLD" | bc -l) )); then
            echo -e "Memory Usage: ${RED}${mem_usage}%${NC}"
        elif (( $(echo "$mem_usage >= $(($MEMORY_THRESHOLD * 8 / 10))" | bc -l) )); then
            echo -e "Memory Usage: ${YELLOW}${mem_usage}%${NC}"
        else
            echo -e "Memory Usage: ${GREEN}${mem_usage}%${NC}"
        fi
    fi

    if should_monitor "disk"; then
        local disk_usage="${disk_history[-1]}"
        if (( $(echo "$disk_usage >= $DISK_THRESHOLD" | bc -l) )); then
            echo -e "Disk Usage: ${RED}${disk_usage}%${NC}"
        elif (( $(echo "$disk_usage >= $(($DISK_THRESHOLD * 8 / 10))" | bc -l) )); then
            echo -e "Disk Usage: ${YELLOW}${disk_usage}%${NC}"
        else
            echo -e "Disk Usage: ${GREEN}${disk_usage}%${NC}"
        fi
    fi

    if should_monitor "load"; then
        local load_avg="${load_history[-1]}"
        local num_cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
        local load_per_core=$(echo "scale=2; $load_avg / $num_cores" | bc)

        if (( $(echo "$load_per_core >= $LOAD_THRESHOLD" | bc -l) )); then
            echo -e "Load Average: ${RED}${load_avg} (${load_per_core}/core)${NC}"
        elif (( $(echo "$load_per_core >= $(($LOAD_THRESHOLD * 8 / 10))" | bc -l) )); then
            echo -e "Load Average: ${YELLOW}${load_avg} (${load_per_core}/core)${NC}"
        else
            echo -e "Load Average: ${GREEN}${load_avg} (${load_per_core}/core)${NC}"
        fi
    fi

    if should_monitor "io" && [[ "$(uname)" == "Linux" ]]; then
        local io_wait=$(get_io_wait)
        if (( $(echo "$io_wait >= $IO_THRESHOLD" | bc -l) )); then
            echo -e "IO Wait: ${RED}${io_wait}%${NC}"
        elif (( $(echo "$io_wait >= $(($IO_THRESHOLD * 8 / 10))" | bc -l) )); then
            echo -e "IO Wait: ${YELLOW}${io_wait}%${NC}"
        else
            echo -e "IO Wait: ${GREEN}${io_wait}%${NC}"
        fi
    fi

    # Print network info
    if should_monitor "network" && command -v netstat &>/dev/null; then
        echo -e "\nNetwork Connections:"
        netstat -ant | grep ESTABLISHED | wc -l | tr -d ' ' | xargs echo "Established connections:"
        netstat -ant | grep LISTEN | wc -l | tr -d ' ' | xargs echo "Listening ports:"
    fi

    # Print top processes
    if [[ "$COLLECT_PROCESSES" == "true" ]]; then
        echo -e "\nTop $PROCESS_COUNT Processes by CPU Usage:"
        get_top_processes $PROCESS_COUNT
    fi

    # Print footer with time remaining
    local elapsed_time=$(($(date +%s) - start_time))
    local remaining_time=$((DURATION - elapsed_time))
    if [[ $remaining_time -gt 0 ]]; then
        echo -e "\nMonitoring for $(format_time $remaining_time) more... (Press Ctrl+C to stop)"
    else
        echo -e "\nMonitoring complete."
    fi

    # Add indication for file output
    if [[ "$LOG_TO_FILE" == "true" ]]; then
        echo "Logging to: $LOG_FILE"
    fi
}

# Function to format seconds to human-readable time
format_time() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local hours=$((minutes / 60))
    local days=$((hours / 24))

    if [[ $days -gt 0 ]]; then
        echo "${days}d ${hours % 24}h ${minutes % 60}m ${seconds % 60}s"
    elif [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes % 60}m ${seconds % 60}s"
    elif [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${seconds % 60}s"
    else
        echo "${seconds}s"
    fi
}

# Function to generate performance graph
generate_graph() {
    if ! command -v gnuplot &>/dev/null; then
        log "Cannot generate graphs, gnuplot not installed" "WARNING"
        return 1
    fi

    log "Generating performance graphs..." "INFO"
    local data_file="/tmp/resource_monitor_data_${TIMESTAMP}.dat"
    local graph_file="${REPORT_FILE%.txt}_graph.png"

    # Create data file for gnuplot
    echo "# Time CPU_Usage Memory_Usage Disk_Usage Load_Average" > "$data_file"
    for ((i=0; i<${#timestamps[@]}; i++)); do
        echo "${timestamps[$i]} ${cpu_history[$i]:-0} ${mem_history[$i]:-0} ${disk_history[$i]:-0} ${load_history[$i]:-0}" >> "$data_file"
    done

    # Create gnuplot script
    local gnuplot_script="/tmp/resource_monitor_plot_${TIMESTAMP}.gp"
    cat > "$gnuplot_script" << EOF
set terminal png size 1200,900
set output '$graph_file'
set title 'System Resource Utilization'
set xlabel 'Time'
set ylabel 'Percentage / Value'
set grid
set key outside
set xdata time
set timefmt '%H:%M:%S'
set format x '%H:%M:%S'
set style data lines
set multiplot layout 2,1
set title 'CPU and Memory Usage'
plot '$data_file' using 1:2 title 'CPU Usage (%)' with lines lw 2 lc rgb 'red', \\
     '$data_file' using 1:3 title 'Memory Usage (%)' with lines lw 2 lc rgb 'blue'
set title 'Disk Usage and Load Average'
plot '$data_file' using 1:4 title 'Disk Usage (%)' with lines lw 2 lc rgb 'green', \\
     '$data_file' using 1:5 title 'Load Average' with lines lw 2 lc rgb 'orange'
unset multiplot
EOF

    # Run gnuplot
    gnuplot "$gnuplot_script"

    # Clean up temporary files
    rm -f "$data_file" "$gnuplot_script"

    log "Performance graph saved to $graph_file" "INFO"
    return 0
}

# Function to generate final report
generate_report() {
    if [[ "$GENERATE_REPORT" != "true" ]]; then
        return
    fi

    log "Generating final report..." "INFO"

    # Calculate statistics
    local cpu_min=$(echo "${cpu_history[@]}" | tr ' ' '\n' | sort -n | head -n1)
    local cpu_max=$(echo "${cpu_history[@]}" | tr ' ' '\n' | sort -n | tail -n1)
    local cpu_avg=$(echo "${cpu_history[@]}" | tr ' ' '\n' | awk '{sum+=$1} END {print sum/NR}')

    local mem_min=$(echo "${mem_history[@]}" | tr ' ' '\n' | sort -n | head -n1)
    local mem_max=$(echo "${mem_history[@]}" | tr ' ' '\n' | sort -n | tail -n1)
    local mem_avg=$(echo "${mem_history[@]}" | tr ' ' '\n' | awk '{sum+=$1} END {print sum/NR}')

    local disk_min=$(echo "${disk_history[@]}" | tr ' ' '\n' | sort -n | head -n1)
    local disk_max=$(echo "${disk_history[@]}" | tr ' ' '\n' | sort -n | tail -n1)
    local disk_avg=$(echo "${disk_history[@]}" | tr ' ' '\n' | awk '{sum+=$1} END {print sum/NR}')

    local load_min=$(echo "${load_history[@]}" | tr ' ' '\n' | sort -n | head -n1)
    local load_max=$(echo "${load_history[@]}" | tr ' ' '\n' | sort -n | tail -n1)
    local load_avg=$(echo "${load_history[@]}" | tr ' ' '\n' | awk '{sum+=$1} END {print sum/NR}')

    # Create report file
    cat > "$REPORT_FILE" << EOF
RESOURCE MONITORING REPORT
=========================
Date: $(date)
Host: $(hostname)
Duration: $(format_time $DURATION)
Interval: ${INTERVAL} seconds
Samples: ${#timestamps[@]}

SYSTEM INFORMATION
-----------------
$(uname -a)
Processors: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")
$(if [[ "$(uname)" == "Linux" && -f /etc/os-release ]]; then cat /etc/os-release | grep "PRETTY_NAME" | cut -d= -f2 | tr -d '"'; else echo "OS: $(uname -s) $(uname -r)"; fi)

RESOURCE USAGE SUMMARY
--------------------
CPU Usage:
  Minimum: ${cpu_min}%
  Maximum: ${cpu_max}%
  Average: ${cpu_avg}%
  Threshold: ${CPU_THRESHOLD}%

Memory Usage:
  Minimum: ${mem_min}%
  Maximum: ${mem_max}%
  Average: ${mem_avg}%
  Threshold: ${MEMORY_THRESHOLD}%

Disk Usage:
  Minimum: ${disk_min}%
  Maximum: ${disk_max}%
  Average: ${disk_avg}%
  Threshold: ${DISK_THRESHOLD}%

Load Average:
  Minimum: ${load_min}
  Maximum: ${load_max}
  Average: ${load_avg}
  Threshold: ${LOAD_THRESHOLD} per core

THRESHOLD VIOLATIONS
------------------
$(cat "$LOG_FILE" 2>/dev/null | grep -i "alert\|critical\|threshold exceeded" | tail -n 20 || echo "No threshold violations detected.")

CURRENT TOP PROCESSES
------------------
$(get_top_processes 10)

CONCLUSION
---------
EOF

    # Add conclusion based on threshold violations
    if (( $(echo "$cpu_max >= $CPU_THRESHOLD" | bc -l) )) || \
       (( $(echo "$mem_max >= $MEMORY_THRESHOLD" | bc -l) )) || \
       (( $(echo "$disk_max >= $DISK_THRESHOLD" | bc -l) )) || \
       (( $(echo "$load_max >= $LOAD_THRESHOLD * $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)" | bc -l) )); then
        cat >> "$REPORT_FILE" << EOF
System resources exceeded threshold during the monitoring period.
Recommend investigation of resource usage patterns and potential optimization.
EOF
    else
        cat >> "$REPORT_FILE" << EOF
All system resources remained within acceptable thresholds during the monitoring period.
System appears to be operating normally.
EOF
    fi

    # Add timestamp to report
    echo -e "\nReport generated: $(date)" >> "$REPORT_FILE"

    log "Report saved to $REPORT_FILE" "INFO"

    # Generate graph if requested
    if [[ "$PLOT_GRAPHS" == "true" ]]; then
        generate_graph
    fi

    # Send notification if requested
    if [[ "$NOTIFY_AT_END" == "true" && -n "$EMAIL_RECIPIENT" ]]; then
        send_alert "Resource Monitoring Report" "Resource monitoring completed. Report attached." "low"
    fi
}

# Trap Ctrl+C to exit gracefully
trap 'log "Monitoring interrupted by user" "INFO"; generate_report; exit 0' INT

# Start monitoring
log "Starting resource monitoring with ${INTERVAL} second interval for $(format_time $DURATION) total duration" "INFO"
log "Alert thresholds: CPU ${CPU_THRESHOLD}%, Memory ${MEMORY_THRESHOLD}%, Disk ${DISK_THRESHOLD}%, Load ${LOAD_THRESHOLD}" "INFO"

start_time=$(date +%s)
end_time=$((start_time + DURATION))

# Main monitoring loop
while [[ $(date +%s) -lt $end_time ]]; do
    # Get current time for this sample
    current_time=$(date +%H:%M:%S)
    timestamps+=("$current_time")

    # Collect CPU usage
    if should_monitor "cpu"; then
        cpu_usage=$(get_cpu_usage)
        cpu_history+=("$cpu_usage")

        # Check for threshold violation
        if (( $(echo "$cpu_usage >= $CPU_THRESHOLD" | bc -l) )) && [[ "$NOTIFY_ON_THRESHOLD" == "true" ]]; then
            send_alert "CPU Threshold Exceeded" "CPU usage is ${cpu_usage}%, which exceeds the threshold of ${CPU_THRESHOLD}%."
        fi

        if [[ "$VERBOSE" == "true" && "$WATCH_MODE" != "true" ]]; then
            log "CPU Usage: ${cpu_usage}%" "INFO"
        fi
    fi

    # Collect Memory usage
    if should_monitor "memory"; then
        mem_usage=$(get_memory_usage)
        mem_history+=("$mem_usage")

        # Check for threshold violation
        if (( $(echo "$mem_usage >= $MEMORY_THRESHOLD" | bc -l) )) && [[ "$NOTIFY_ON_THRESHOLD" == "true" ]]; then
            send_alert "Memory Threshold Exceeded" "Memory usage is ${mem_usage}%, which exceeds the threshold of ${MEMORY_THRESHOLD}%."
        fi

        if [[ "$VERBOSE" == "true" && "$WATCH_MODE" != "true" ]]; then
            log "Memory Usage: ${mem_usage}%" "INFO"
        fi
    fi

    # Collect Disk usage
    if should_monitor "disk"; then
        disk_usage=$(get_disk_usage)
        disk_history+=("$disk_usage")

        # Check for threshold violation
        if (( $(echo "$disk_usage >= $DISK_THRESHOLD" | bc -l) )) && [[ "$NOTIFY_ON_THRESHOLD" == "true" ]]; then
            send_alert "Disk Threshold Exceeded" "Disk usage is ${disk_usage}%, which exceeds the threshold of ${DISK_THRESHOLD}%."
        fi

        if [[ "$VERBOSE" == "true" && "$WATCH_MODE" != "true" ]]; then
            log "Disk Usage: ${disk_usage}%" "INFO"
        fi
    fi

    # Collect Load average
    if should_monitor "load"; then
        load_avg=$(get_load_average)
        load_history+=("$load_avg")

        # Get number of cores
        num_cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
        load_per_core=$(echo "scale=2; $load_avg / $num_cores" | bc)

        # Check for threshold violation
        if (( $(echo "$load_per_core >= $LOAD_THRESHOLD" | bc -l) )) && [[ "$NOTIFY_ON_THRESHOLD" == "true" ]]; then
            send_alert "Load Threshold Exceeded" "Load average is ${load_avg} (${load_per_core}/core), which exceeds the threshold of ${LOAD_THRESHOLD} per core."
        fi

        if [[ "$VERBOSE" == "true" && "$WATCH_MODE" != "true" ]]; then
            log "Load Average: ${load_avg} (${load_per_core}/core)" "INFO"
        fi
    fi

    # Update terminal in watch mode
    if [[ "$WATCH_MODE" == "true" ]]; then
        update_watch_display
    fi

    # Sleep for interval (adjusted to account for processing time)
    processing_time=$(($(date +%s) - start_time - (${#timestamps[@]} - 1) * INTERVAL))
    sleep_time=$((INTERVAL - processing_time))

    if [[ $sleep_time -gt 0 ]]; then
        sleep $sleep_time
    else
        log "Warning: Processing time exceeded interval by $((processing_time - INTERVAL)) seconds" "WARNING"
    fi
done

# Generate final report
generate_report

log "Resource monitoring completed. ${#timestamps[@]} samples collected." "INFO"

exit 0
