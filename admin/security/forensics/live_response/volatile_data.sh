#!/bin/bash
# Volatile Data Collection Script for Live Response Forensics
#
# This script collects volatile system information (processes, network, users, etc.)
# from live systems during incident response, adhering to forensic best practices.

# Load common utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_functions.sh"

# Script version
VOLATILE_DATA_VERSION="1.1.0"
VOLATILE_DATA_DATE="2024-08-25"

# --- Configuration ---
DEFAULT_OUTPUT_DIR="${OUTPUT_DIR:-/tmp/live_response_output_$$/volatile}"
DEFAULT_CATEGORIES="processes,network,users,system_info" # Default categories to collect
DEFAULT_REMOTE_PORT="22"
DEFAULT_PROCESS_ARGS="true"
DEFAULT_PROCESS_ENV="false"
DEFAULT_TIME_ZONE="UTC" # Default time zone for timestamps
DEFAULT_FILE_COPIES="false" # Default option for copying key system files
DEFAULT_INCLUDE_MODULES="true" # Default option for collecting kernel modules
DEFAULT_LOG_FILES_LIMIT="1000" # Max lines to collect from log files
DEFAULT_MAX_COLLECTION_DEPTH=3 # Max depth for recursive collections

# --- Global Variables ---
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
CATEGORIES="$DEFAULT_CATEGORIES"
TARGET_HOST=""
TARGET_USER="$USER"
SSH_KEY=""
SSH_PORT="$DEFAULT_REMOTE_PORT"
PROCESS_ARGS="$DEFAULT_PROCESS_ARGS"
PROCESS_ENV="$DEFAULT_PROCESS_ENV"
INCLUDE_MODULES="$DEFAULT_INCLUDE_MODULES"
COPY_FILES="$DEFAULT_FILE_COPIES"
TIME_ZONE="$DEFAULT_TIME_ZONE"
LOG_FILES_LIMIT="$DEFAULT_LOG_FILES_LIMIT"
MAX_COLLECTION_DEPTH="$DEFAULT_MAX_COLLECTION_DEPTH"
CASE_ID=""
EXAMINER_ID=""
MINIMAL_COLLECTION=false
CUSTOM_COMMANDS=""
CUSTOM_FILTERS=""

# --- Function Definitions ---

# Display usage information
usage() {
    cat << EOF
Volatile Data Collection Script v${VOLATILE_DATA_VERSION} (${VOLATILE_DATA_DATE})

Usage: $(basename "$0") [OPTIONS]

Options:
  -h, --help                 Show this help message
  -o, --output DIR           Output directory for collected data (default: ${DEFAULT_OUTPUT_DIR})
  -c, --collect CATEGORIES   Comma-separated list of categories to collect (default: ${DEFAULT_CATEGORIES})
                             Available: processes, network, users, system_info, services, modules,
                             startup_items, scheduled_tasks, command_history, login_history, open_files,
                             mounted_devices, kernel_modules, loaded_drivers, file_handles
  -t, --target HOST          Remote target hostname or IP address
  -u, --user USER            Remote target user (default: ${TARGET_USER})
  -k, --key FILE             SSH private key file for remote connection
  -p, --port PORT            SSH port for remote connection (default: ${DEFAULT_REMOTE_PORT})
  --process-args             Include process arguments (default: ${DEFAULT_PROCESS_ARGS})
  --no-process-args          Do not include process arguments
  --process-env              Include process environment variables (default: ${DEFAULT_PROCESS_ENV})
  --no-process-env           Do not include process environment variables
  --copy-key-files           Include copies of key system files (default: ${DEFAULT_FILE_COPIES})
  --no-modules               Do not collect kernel modules/drivers info
  --timezone ZONE            Time zone for timestamps (default: ${DEFAULT_TIME_ZONE})
  --log-limit LINES          Maximum number of lines to collect from logs (default: ${DEFAULT_LOG_FILES_LIMIT})
  --minimal                  Perform minimal collection (fewer details, faster)
  --custom-commands FILE     File containing additional commands to execute
  --filter PATTERN           Filter collected data using regex pattern
  --case-id ID               Case identifier for evidence tracking
  --examiner ID              Examiner identifier for chain of custody
  -v, --verbose              Show more detailed output
  -q, --quiet                Suppress non-error output
  --log FILE                 Log file path
  --audit-log FILE           Audit log file path
  --version                  Show version information and exit
EOF
    exit 0
}

# Show version information
show_version() {
    echo "Volatile Data Collection Script v${VOLATILE_DATA_VERSION} (${VOLATILE_DATA_DATE})"
    echo "Using Common Functions v$(get_common_live_response_version)"
    exit 0
}

# Parse command-line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help) usage ;;
            --version) show_version ;;
            -o|--output) shift; OUTPUT_DIR="$1" ;;
            -c|--collect) shift; CATEGORIES="$1" ;;
            -t|--target) shift; TARGET_HOST="$1" ;;
            -u|--user) shift; TARGET_USER="$1" ;;
            -k|--key) shift; SSH_KEY="$1" ;;
            -p|--port) shift; SSH_PORT="$1" ;;
            --process-args) PROCESS_ARGS="true" ;;
            --no-process-args) PROCESS_ARGS="false" ;;
            --process-env) PROCESS_ENV="true" ;;
            --no-process-env) PROCESS_ENV="false" ;;
            --copy-key-files) COPY_FILES="true" ;;
            --no-modules) INCLUDE_MODULES="false" ;;
            --timezone) shift; TIME_ZONE="$1" ;;
            --log-limit) shift; LOG_FILES_LIMIT="$1" ;;
            --minimal) MINIMAL_COLLECTION=true ;;
            --custom-commands) shift; CUSTOM_COMMANDS="$1" ;;
            --filter) shift; CUSTOM_FILTERS="$1" ;;
            --case-id) shift; CASE_ID="$1" ;;
            --examiner) shift; EXAMINER_ID="$1" ;;
            -v|--verbose) VERBOSE=true ;;
            -q|--quiet) QUIET=true ;;
            --log) shift; LOG_FILE="$1" ;;
            --audit-log) shift; AUDIT_LOG_FILE="$1" ;;
            *) log_error "Unknown option: $key"; usage ;;
        esac
        shift
    done
}

# --- Collection Functions ---

collect_processes() {
    local output_subdir="${OUTPUT_DIR}/processes"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting process information..."
    log_coc_event "Start" "Process Collection"

    local ps_path=$(get_tool_path "volatile_data" "ps")
    if [[ -z "$ps_path" ]]; then
        log_error "ps command not found. Cannot collect process information."
        log_coc_event "Fail" "Process Collection" "Tool 'ps' not found"
        return 1
    fi

    local cmd_opts="aux"
    [[ "$PROCESS_ARGS" == "true" ]] && cmd_opts+="ww" # Wide format for full args

    local cmd="$ps_path $cmd_opts"
    local output_file="${output_subdir}/ps_auxww.txt"

    if execute_and_save "$cmd" "$output_file" "Process List (ps auxww)"; then
        # Process relationships (tree view)
        local pstree_path=$(get_tool_path "volatile_data" "pstree")
        if [[ -n "$pstree_path" ]]; then
            execute_and_save "$pstree_path -p" "${output_subdir}/pstree.txt" "Process Tree"
        else
            # Fallback to ps forest view if available
            execute_and_save "$ps_path -ef --forest" "${output_subdir}/ps_forest.txt" "Process Forest View"
        fi

        # Collect process environment if requested
        if [[ "$PROCESS_ENV" == "true" ]]; then
            log_info "Collecting process environment variables..."
            local env_dir="${output_subdir}/environments"
            ensure_output_dir "$env_dir"

            # Get list of PIDs
            local pid_list_file=$(create_temp_file "pid_list")
            $ps_path -eo pid --no-headers > "$pid_list_file"

            # For each PID, try to get its environment
            local env_count=0
            while read -r pid; do
                if [[ -r "/proc/$pid/environ" ]]; then
                    log_debug "Reading environment for PID $pid"
                    tr '\0' '\n' < "/proc/$pid/environ" > "${env_dir}/pid_${pid}_env.txt" 2>/dev/null
                    if [[ $? -eq 0 && -s "${env_dir}/pid_${pid}_env.txt" ]]; then
                        ((env_count++))
                        chmod "$DEFAULT_EVIDENCE_PERMS" "${env_dir}/pid_${pid}_env.txt"
                    else
                        rm -f "${env_dir}/pid_${pid}_env.txt" 2>/dev/null
                    fi
                fi
            done < "$pid_list_file"

            log_info "Collected environment variables for $env_count processes"
        fi

        # Add cmdline content for important processes
        if [[ "$PROCESS_ARGS" == "true" && ! "$MINIMAL_COLLECTION" == "true" ]]; then
            log_info "Collecting detailed command lines..."
            local cmdline_dir="${output_subdir}/cmdlines"
            ensure_output_dir "$cmdline_dir"

            # Get list of PIDs for non-kernel processes
            local pid_list_file=$(create_temp_file "pid_list")
            $ps_path -eo pid,ppid,user,cmd --no-headers | grep -v "\[" | awk '{print $1}' > "$pid_list_file"

            # For each PID, get its cmdline
            local cmd_count=0
            while read -r pid; do
                if [[ -r "/proc/$pid/cmdline" ]]; then
                    log_debug "Reading cmdline for PID $pid"
                    tr '\0' ' ' < "/proc/$pid/cmdline" > "${cmdline_dir}/pid_${pid}_cmdline.txt" 2>/dev/null
                    if [[ $? -eq 0 && -s "${cmdline_dir}/pid_${pid}_cmdline.txt" ]]; then
                        ((cmd_count++))
                        chmod "$DEFAULT_EVIDENCE_PERMS" "${cmdline_dir}/pid_${pid}_cmdline.txt"
                    else
                        rm -f "${cmdline_dir}/pid_${pid}_cmdline.txt" 2>/dev/null
                    fi
                fi
            done < "$pid_list_file"

            log_info "Collected detailed command lines for $cmd_count processes"
        fi

        # Create a process summary file
        local summary_file="${output_subdir}/processes_summary.txt"
        {
            echo "PROCESS SUMMARY"
            echo "==============="
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            # Count processes by user
            echo "PROCESS COUNT BY USER:"
            $ps_path -eo user --no-headers | sort | uniq -c | sort -nr

            echo ""
            echo "TOP 10 CPU CONSUMING PROCESSES:"
            $ps_path aux --sort=-%cpu | head -11

            echo ""
            echo "TOP 10 MEMORY CONSUMING PROCESSES:"
            $ps_path aux --sort=-%mem | head -11

            echo ""
            echo "RECENTLY STARTED PROCESSES (LAST HOUR):"
            # This works on Linux with a readable /proc
            if [[ -d "/proc" ]]; then
                find /proc -maxdepth 1 -type d -name "[0-9]*" -mmin -60 2>/dev/null | while read -r procdir; do
                    pid=$(basename "$procdir")
                    $ps_path -p "$pid" -o pid,ppid,user,start,cmd --no-headers 2>/dev/null
                done | sort -k4
            else
                echo "Could not determine recently started processes - /proc not available"
            fi

        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        log_coc_event "Completed" "Process Collection" "File: $output_file"
    else
        log_coc_event "Fail" "Process Collection" "Command failed: $cmd"
        return 1
    fi
    return 0
}

collect_network_info() {
    local output_subdir="${OUTPUT_DIR}/network"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting network connection information..."
    log_coc_event "Start" "Network Connection Collection"

    local netstat_path=$(get_tool_path "volatile_data" "netstat")
    local ss_path=$(get_tool_path "volatile_data" "ss")
    local success=false

    if [[ -n "$ss_path" ]]; then
        # Collect with ss command (preferred)
        # All connections
        if execute_and_save "$ss_path -tupan" "${output_subdir}/ss_tupan.txt" "All Network Connections (ss)"; then
            success=true
        fi

        # Listening sockets
        if execute_and_save "$ss_path -tulpn" "${output_subdir}/ss_tulpn.txt" "Listening Sockets (ss)"; then
            success=true
        fi

        # Socket statistics
        if execute_and_save "$ss_path -s" "${output_subdir}/ss_stats.txt" "Socket Statistics"; then
            success=true
        fi

        # Get more detailed info if not in minimal mode
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            # Memory information
            if execute_and_save "$ss_path -tme" "${output_subdir}/ss_memory.txt" "Socket Memory Usage"; then
                success=true
            fi

            # Per-process socket details
            if execute_and_save "$ss_path -tpei" "${output_subdir}/ss_process_details.txt" "Process Socket Details"; then
                success=true
            fi
        fi
    elif [[ -n "$netstat_path" ]]; then
        log_warn "ss command not found, falling back to netstat."

        # All connections
        if execute_and_save "$netstat_path -an" "${output_subdir}/netstat_an.txt" "All Network Connections (netstat)"; then
            success=true
        fi

        # With process info (may require root)
        if execute_and_save "$netstat_path -anop" "${output_subdir}/netstat_anop.txt" "Network Connections with Process Info"; then
            success=true
        fi

        # Listening sockets
        if execute_and_save "$netstat_path -tulpn" "${output_subdir}/netstat_tulpn.txt" "Listening Sockets (netstat)"; then
            success=true
        fi

        # Connection statistics
        if execute_and_save "$netstat_path -s" "${output_subdir}/netstat_stats.txt" "Network Statistics"; then
            success=true
        fi
    else
        log_error "Neither ss nor netstat found. Cannot collect network connections."
        log_coc_event "Fail" "Network Connection Collection" "Tools 'ss' and 'netstat' not found"
        return 1
    fi

    # Collect routing table
    local route_path=$(get_tool_path "volatile_data" "route")
    local ip_path=$(get_tool_path "volatile_data" "ip")

    if [[ -n "$ip_path" ]]; then
        if execute_and_save "$ip_path route show" "${output_subdir}/ip_route.txt" "IP Routing Table"; then
            success=true
        fi
    elif [[ -n "$route_path" ]]; then
        if execute_and_save "$route_path -n" "${output_subdir}/route_n.txt" "Routing Table"; then
            success=true
        fi
    fi

    # Collect ARP cache
    local arp_path=$(get_tool_path "volatile_data" "arp")
    if [[ -n "$arp_path" ]]; then
        if execute_and_save "$arp_path -an" "${output_subdir}/arp_an.txt" "ARP Cache"; then
            success=true
        fi
    elif [[ -n "$ip_path" ]]; then
        if execute_and_save "$ip_path neigh show" "${output_subdir}/ip_neigh.txt" "IP Neighbor Table"; then
            success=true
        fi
    fi

    # Collect DNS configuration
    if [[ -f "/etc/resolv.conf" ]]; then
        if execute_and_save "cat /etc/resolv.conf" "${output_subdir}/resolv.conf.txt" "DNS Configuration"; then
            success=true
        fi
    fi

    # Collect interfaces information
    local ifconfig_path=$(get_tool_path "volatile_data" "ifconfig")
    if [[ -n "$ip_path" ]]; then
        if execute_and_save "$ip_path addr show" "${output_subdir}/ip_addr.txt" "Network Interfaces"; then
            success=true
        fi
    elif [[ -n "$ifconfig_path" ]]; then
        if execute_and_save "$ifconfig_path -a" "${output_subdir}/ifconfig_a.txt" "Network Interfaces"; then
            success=true
        fi
    fi

    # Create a summary file
    local summary_file="${output_subdir}/network_summary.txt"
    {
        echo "NETWORK INFORMATION SUMMARY"
        echo "=========================="
        echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
        echo ""

        echo "IP ADDRESSES:"
        if command -v hostname &>/dev/null; then
            hostname -I 2>/dev/null || echo "Could not determine IP addresses"
        elif [[ -n "$ifconfig_path" ]]; then
            $ifconfig_path -a | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*'
        elif [[ -n "$ip_path" ]]; then
            $ip_path -o -4 addr list | awk '{print $4}' | cut -d/ -f1
        else
            echo "Could not determine IP addresses - required tools not found"
        fi

        echo ""
        echo "LISTENING SERVICES:"
        if [[ -n "$ss_path" ]]; then
            $ss_path -tulpn | grep LISTEN | awk '{print $5, $7}' | sort -n | column -t
        elif [[ -n "$netstat_path" ]]; then
            $netstat_path -tulpn | grep LISTEN | awk '{print $4, $7}' | sort -n | column -t
        else
            echo "Could not determine listening services - required tools not found"
        fi

        echo ""
        echo "ESTABLISHED CONNECTIONS:"
        if [[ -n "$ss_path" ]]; then
            $ss_path -tupn | grep ESTAB | wc -l
        elif [[ -n "$netstat_path" ]]; then
            $netstat_path -tupn | grep ESTABLISHED | wc -l
        else
            echo "Could not determine established connections - required tools not found"
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "Network Connection Collection" "Collected network state"
    else
        log_coc_event "Fail" "Network Connection Collection" "Collection command failed"
        return 1
    fi
    return 0
}

collect_users() {
    local output_subdir="${OUTPUT_DIR}/users"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting user information..."
    log_coc_event "Start" "User Information Collection"

    local success=false
    # Collect logged in users (w, who)
    if execute_and_save "w" "${output_subdir}/w.txt" "Logged in users (w)"; then success=true; fi
    if execute_and_save "who" "${output_subdir}/who.txt" "Logged in users (who)"; then success=true; fi

    # Collect last logins (last) - might be large
    local last_count=50
    if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
        last_count=100
    fi
    if execute_and_save "last -n $last_count" "${output_subdir}/last_${last_count}.txt" "Last $last_count logins"; then success=true; fi

    # Get user account information
    if execute_and_save "cat /etc/passwd" "${output_subdir}/passwd.txt" "User accounts"; then success=true; fi
    if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
        # Get only human users (exclude system accounts)
        if execute_and_save "getent passwd | grep -v nologin | grep -v false" "${output_subdir}/human_users.txt" "Human user accounts"; then success=true; fi
    fi

    # Get group information
    if execute_and_save "cat /etc/group" "${output_subdir}/groups.txt" "Group information"; then success=true; fi

    # Get sudo configuration if available
    if [[ -f "/etc/sudoers" ]]; then
        if execute_and_save "cat /etc/sudoers" "${output_subdir}/sudoers.txt" "Sudo configuration"; then success=true; fi
    fi

    # Get currently logged in user ID
    if execute_and_save "id" "${output_subdir}/current_user_id.txt" "Current user ID"; then success=true; fi

    # Get authentication log if available and not in minimal mode
    if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
        if [[ -f "/var/log/auth.log" ]]; then
            if execute_and_save "tail -n $LOG_FILES_LIMIT /var/log/auth.log" "${output_subdir}/auth_log_tail.txt" "Authentication log tail"; then success=true; fi
        fi
        # For RHEL/CentOS systems
        if [[ -f "/var/log/secure" ]]; then
            if execute_and_save "tail -n $LOG_FILES_LIMIT /var/log/secure" "${output_subdir}/secure_log_tail.txt" "Secure log tail"; then success=true; fi
        fi
    fi

    # Create a summary file
    local summary_file="${output_subdir}/users_summary.txt"
    {
        echo "USER ACTIVITY SUMMARY"
        echo "===================="
        echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
        echo ""

        echo "CURRENT ACTIVE USERS:"
        w -h | awk '{print $1, "on", $2, "since", $3, $4}'

        echo ""
        echo "USER LOGIN STATISTICS (LAST 24 HOURS):"
        last -n 1000 | awk '{print $1}' | sort | uniq -c | sort -nr

        echo ""
        echo "SUDO ACTIVITY (LAST 24 HOURS):"
        if [[ -f "/var/log/auth.log" ]]; then
            grep 'sudo:' /var/log/auth.log | tail -n 20
        elif [[ -f "/var/log/secure" ]]; then
            grep 'sudo:' /var/log/secure | tail -n 20
        else
            echo "No sudo logs available"
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "User Information Collection" "Collected user session data"
    else
        log_coc_event "Fail" "User Information Collection" "Failed to collect user data"
        return 1
    fi
    return 0
}

collect_system_info() {
    local output_subdir="${OUTPUT_DIR}/system_info"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting system information..."
    log_coc_event "Start" "System Information Collection"

    local success=false
    # Collect hostname, uname, uptime, date
    if execute_and_save "hostname" "${output_subdir}/hostname.txt" "Hostname"; then success=true; fi
    if execute_and_save "uname -a" "${output_subdir}/uname_a.txt" "System Version (uname -a)"; then success=true; fi
    if execute_and_save "uptime" "${output_subdir}/uptime.txt" "System Uptime"; then success=true; fi
    if execute_and_save "date -u" "${output_subdir}/date_utc.txt" "Current UTC Date"; then success=true; fi

    # Collect timezone information
    if execute_and_save "date" "${output_subdir}/date_local.txt" "Current Local Date"; then success=true; fi
    if execute_and_save "cat /etc/timezone 2>/dev/null || timedatectl 2>/dev/null || ls -la /etc/localtime 2>/dev/null" "${output_subdir}/timezone_info.txt" "Timezone Information"; then success=true; fi

    # Collect memory info (free)
    if execute_and_save "free -m" "${output_subdir}/free_m.txt" "Memory Usage (free -m)"; then success=true; fi
    # Collect disk info (df)
    if execute_and_save "df -h" "${output_subdir}/df_h.txt" "Disk Usage (df -h)"; then success=true; fi

    # Collect detailed hardware info if available
    local lshw_path=$(get_tool_path "volatile_data" "lshw")
    if [[ -n "$lshw_path" && "$MINIMAL_COLLECTION" != "true" ]]; then
        if execute_and_save "$lshw_path -short" "${output_subdir}/lshw_short.txt" "Hardware Summary"; then success=true; fi
    fi

    # Collect CPU information
    if [[ -f "/proc/cpuinfo" ]]; then
        if execute_and_save "cat /proc/cpuinfo" "${output_subdir}/cpuinfo.txt" "CPU Information"; then success=true; fi
    fi

    # Collect memory information
    if [[ -f "/proc/meminfo" ]]; then
        if execute_and_save "cat /proc/meminfo" "${output_subdir}/meminfo.txt" "Memory Information"; then success=true; fi
    fi

    # Collect OS release information
    if [[ -f "/etc/os-release" ]]; then
        if execute_and_save "cat /etc/os-release" "${output_subdir}/os_release.txt" "OS Release Information"; then success=true; fi
    elif [[ -f "/etc/redhat-release" ]]; then
        if execute_and_save "cat /etc/redhat-release" "${output_subdir}/redhat_release.txt" "OS Release Information"; then success=true; fi
    fi

    # Collect kernel parameters
    if execute_and_save "sysctl -a 2>/dev/null" "${output_subdir}/sysctl.txt" "Kernel Parameters"; then success=true; fi

    # Collect system logs if not in minimal mode
    if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
        if [[ -f "/var/log/syslog" ]]; then
            if execute_and_save "tail -n $LOG_FILES_LIMIT /var/log/syslog" "${output_subdir}/syslog_tail.txt" "System Log Tail"; then success=true; fi
        fi
        if [[ -f "/var/log/messages" ]]; then
            if execute_and_save "tail -n $LOG_FILES_LIMIT /var/log/messages" "${output_subdir}/messages_tail.txt" "Messages Log Tail"; then success=true; fi
        fi
    fi

    # Create a summary file with key system information
    local summary_file="${output_subdir}/system_summary.txt"
    {
        echo "SYSTEM INFORMATION SUMMARY"
        echo "========================="
        echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
        echo ""

        echo "SYSTEM IDENTIFICATION:"
        echo "Hostname: $(hostname 2>/dev/null)"
        if [[ -f "/etc/os-release" ]]; then
            echo "OS: $(grep -E "^PRETTY_NAME" /etc/os-release | cut -d= -f2 | tr -d '"')"
            echo "Version: $(grep -E "^VERSION=" /etc/os-release | cut -d= -f2 | tr -d '"')"
        elif [[ -f "/etc/redhat-release" ]]; then
            echo "OS: $(cat /etc/redhat-release)"
        else
            echo "OS: $(uname -s)"
            echo "Version: $(uname -r)"
        fi
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"

        echo ""
        echo "HARDWARE SUMMARY:"
        echo "CPU Info: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')"
        echo "CPU Cores: $(grep -c "processor" /proc/cpuinfo)"
        if free -g &>/dev/null; then
            echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
        fi
        echo "Disk Space: $(df -h / | awk 'NR==2 {print $2}')"
        echo "Free Disk: $(df -h / | awk 'NR==2 {print $4}')"

        echo ""
        echo "UPTIME AND LOAD:"
        uptime

        echo ""
        echo "LAST REBOOT TIMES:"
        last reboot | head -5

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "System Information Collection" "Collected basic system info"
    else
        log_coc_event "Fail" "System Information Collection" "Failed to collect system info"
        return 1
    fi
    return 0
}

collect_services() {
    local output_subdir="${OUTPUT_DIR}/services"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting service information..."
    log_coc_event "Start" "Service Collection"

    local success=false

    # Check for systemctl
    local systemctl_path=$(get_tool_path "volatile_data" "systemctl")
    if [[ -n "$systemctl_path" ]]; then
        # Get all services
        if execute_and_save "$systemctl_path list-units --type=service --all" "${output_subdir}/systemctl_services.txt" "Systemd Services"; then success=true; fi

        # Get running services
        if execute_and_save "$systemctl_path list-units --type=service --state=running" "${output_subdir}/systemctl_running.txt" "Running Systemd Services"; then success=true; fi

        # Get failed services
        if execute_and_save "$systemctl_path --failed" "${output_subdir}/systemctl_failed.txt" "Failed Systemd Services"; then success=true; fi

        # Get service details if not in minimal mode
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            # Create directory for individual service status files
            local services_dir="${output_subdir}/service_details"
            ensure_output_dir "$services_dir"

            # Get list of running services
            local running_services=$($systemctl_path list-units --type=service --state=running --no-legend | awk '{print $1}')

            # For each running service, get its details
            for service in $running_services; do
                # Skip if not a .service
                if [[ ! "$service" == *.service ]]; then
                    continue
                fi

                local service_name=$(echo "$service" | sed 's/\.service$//')
                local output_file="${services_dir}/${service_name}.txt"

                {
                    echo "SERVICE DETAILS: $service"
                    echo "======================$(printf '=%.0s' $(seq 1 ${#service}))"
                    echo ""
                    $systemctl_path status "$service" 2>/dev/null
                    echo ""
                    echo "UNIT FILE PATH:"
                    $systemctl_path show "$service" -p FragmentPath 2>/dev/null | cut -d= -f2
                } > "$output_file"

                chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file"
            done

            # Get timer units (scheduled tasks)
            if execute_and_save "$systemctl_path list-timers" "${output_subdir}/systemctl_timers.txt" "Systemd Timers"; then success=true; fi
        fi
    fi

    # Check for service command
    local service_path=$(get_tool_path "volatile_data" "service")
    if [[ -n "$service_path" ]]; then
        if execute_and_save "$service_path --status-all" "${output_subdir}/service_status_all.txt" "Service Status"; then success=true; fi
    fi

    # Check for chkconfig command
    local chkconfig_path=$(get_tool_path "volatile_data" "chkconfig")
    if [[ -n "$chkconfig_path" ]]; then
        if execute_and_save "$chkconfig_path --list" "${output_subdir}/chkconfig_list.txt" "ChkConfig Services"; then success=true; fi
    fi

    # Create summary file
    local summary_file="${output_subdir}/services_summary.txt"
    {
        echo "SERVICES SUMMARY"
        echo "==============="
        echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
        echo ""

        if [[ -n "$systemctl_path" ]]; then
            echo "RUNNING SERVICES COUNT:"
            $systemctl_path list-units --type=service --state=running --no-legend | wc -l

            echo ""
            echo "FAILED SERVICES:"
            $systemctl_path --failed --no-legend

            echo ""
            echo "RECENTLY STARTED SERVICES:"
            journalctl -b -u "*service" | grep -i "Started" | tail -10

            echo ""
            echo "RECENTLY STOPPED SERVICES:"
            journalctl -b -u "*service" | grep -i "Stopped" | tail -10
        elif [[ -n "$service_path" ]]; then
            echo "SERVICE STATUS SUMMARY:"
            $service_path --status-all | grep -c "\\[ + \\]"
            echo "Running services: $($service_path --status-all | grep -c "\\[ + \\]")"
            echo "Stopped services: $($service_path --status-all | grep -c "\\[ - \\]")"
        fi

    } > "$summary_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

    if [[ "$success" == "true" ]]; then
        log_coc_event "Completed" "Service Collection" "Collected service information"
    else
        log_coc_event "Fail" "Service Collection" "Failed to collect service information"
        return 1
    fi
    return 0
}

collect_modules() {
    # Only run if modules collection is enabled
    if [[ "$INCLUDE_MODULES" != "true" ]]; then
        log_debug "Kernel module collection disabled by user"
        return 0
    fi

    local output_subdir="${OUTPUT_DIR}/modules"
    ensure_output_dir "$output_subdir" || return 1
    log_info "Collecting kernel module information..."
    log_coc_event "Start" "Kernel Module Collection"

    local success=false

    # Get loaded modules
    local lsmod_path=$(get_tool_path "volatile_data" "lsmod")
    if [[ -n "$lsmod_path" ]]; then
        if execute_and_save "$lsmod_path" "${output_subdir}/lsmod.txt" "Loaded Kernel Modules"; then success=true; fi
    fi

        # Get module information if not in minimal mode
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            local modinfo_path=$(get_tool_path "volatile_data" "modinfo")
            if [[ -n "$modinfo_path" && -n "$lsmod_path" ]]; then
                local modules_dir="${output_subdir}/module_details"
                ensure_output_dir "$modules_dir"

                # Get list of loaded modules
                local module_list=$($lsmod_path | awk 'NR>1 {print $1}')

                # Get detailed information for each module
                for module in $module_list; do
                    local output_file="${modules_dir}/${module}.txt"

                    {
                        echo "MODULE DETAILS: $module"
                        echo "======================$(printf '=%.0s' $(seq 1 ${#module}))"
                        echo ""
                        $modinfo_path "$module" 2>/dev/null
                    } > "$output_file"

                    chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file"
                done

                log_info "Collected detailed information for $(echo "$module_list" | wc -w) modules"
            fi

            # Collect module parameters if proc filesystem is available
            if [[ -d "/proc/modules" && -d "/sys/module" ]]; then
                local params_dir="${output_subdir}/module_parameters"
                ensure_output_dir "$params_dir"

                local param_count=0
                for module_dir in /sys/module/*/parameters; do
                    if [[ -d "$module_dir" && "$(ls -A "$module_dir" 2>/dev/null)" ]]; then
                        local module_name=$(echo "$module_dir" | cut -d'/' -f4)
                        local param_file="${params_dir}/${module_name}_parameters.txt"

                        {
                            echo "MODULE PARAMETERS: $module_name"
                            echo "======================$(printf '=%.0s' $(seq 1 ${#module_name}))"
                            echo ""

                            for param_path in "$module_dir"/*; do
                                param_name=$(basename "$param_path")
                                if [[ -r "$param_path" ]]; then
                                    param_value=$(cat "$param_path" 2>/dev/null)
                                    echo "$param_name = $param_value"
                                fi
                            done
                        } > "$param_file"

                        chmod "$DEFAULT_EVIDENCE_PERMS" "$param_file"
                        ((param_count++))
                    fi
                done

                log_info "Collected parameters for $param_count modules"
            fi
        fi

        # Get module dependencies
        if execute_and_save "cat /proc/modules 2>/dev/null" "${output_subdir}/proc_modules.txt" "Kernel Module Dependencies"; then
            success=true
        fi

        # Collect module loading information
        if [[ -f "/etc/modules" ]]; then
            if execute_and_save "cat /etc/modules" "${output_subdir}/etc_modules.txt" "Configured Module Loading"; then
                success=true
            fi
        fi

        # Collect auto-loaded modules configuration
        if [[ -d "/etc/modules-load.d" ]]; then
            if execute_and_save "find /etc/modules-load.d -type f -name '*.conf' -exec cat {} \;" "${output_subdir}/modules_load_conf.txt" "Auto-loaded Modules"; then
                success=true
            fi
        fi

        # Check for blacklisted/disabled modules
        if [[ -d "/etc/modprobe.d" ]]; then
            if execute_and_save "grep -r blacklist /etc/modprobe.d/" "${output_subdir}/blacklisted_modules.txt" "Blacklisted Modules"; then
                success=true
            fi
        fi

        # Create a summary file
        local summary_file="${output_subdir}/modules_summary.txt"
        {
            echo "KERNEL MODULES SUMMARY"
            echo "======================"
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            if [[ -n "$lsmod_path" ]]; then
                echo "LOADED MODULES COUNT: $($lsmod_path | wc -l)"
                echo ""
                echo "TOP 10 LARGEST MODULES:"
                $lsmod_path | sort -k2 -nr | head -10 | awk '{printf "%-20s %10s bytes\n", $1, $2}'

                echo ""
                echo "POTENTIALLY INTERESTING MODULES:"
                # List of potentially interesting modules for security review
                interesting_modules="vboxsf vboxguest nf_ ip_tables iptable_ netfilter nvidia fuse crypto tun tap wireguard openvswitch bridge bonding 8021q vmw_ vmware"
                for pattern in $interesting_modules; do
                    $lsmod_path | grep -i "$pattern" || true
                done

                echo ""
                echo "MODULES WITH EXTERNAL DEPENDENCIES:"
                $lsmod_path | awk '$3 > 0 {print $1, "used by", $3, "modules"}' | sort -k4 -nr
            else
                echo "Could not access module listing tool"
            fi
        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        if [[ "$success" == "true" ]]; then
            log_coc_event "Completed" "Kernel Module Collection" "Collected module information"
        else
            log_coc_event "Fail" "Kernel Module Collection" "Failed to collect kernel module data"
            return 1
        fi
        return 0
    }

    collect_startup_items() {
        local output_subdir="${OUTPUT_DIR}/startup"
        ensure_output_dir "$output_subdir" || return 1
        log_info "Collecting startup items and scheduled tasks..."
        log_coc_event "Start" "Startup Items Collection"

        local success=false

        # Systemd startup items
        local systemctl_path=$(get_tool_path "volatile_data" "systemctl")
        if [[ -n "$systemctl_path" ]]; then
            if execute_and_save "$systemctl_path list-unit-files --state=enabled" "${output_subdir}/enabled_units.txt" "Enabled Units"; then success=true; fi
            if execute_and_save "$systemctl_path list-timers --all" "${output_subdir}/systemd_timers.txt" "Systemd Timers"; then success=true; fi
        fi

        # Init.d startup scripts
        if [[ -d "/etc/init.d" ]]; then
            if execute_and_save "ls -la /etc/init.d/" "${output_subdir}/init.d_scripts.txt" "Init.d Scripts"; then success=true; fi
            if execute_and_save "find /etc/rc*.d -type l -name 'S*' | sort" "${output_subdir}/rc_symlinks.txt" "Runlevel Symlinks"; then success=true; fi
        fi

        # Collect cron information
        if execute_and_save "find /etc/cron* -type f -o -type l 2>/dev/null | sort" "${output_subdir}/cron_files.txt" "Cron Files"; then success=true; fi

        local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
        for dir in "${cron_dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                dir_name=$(basename "$dir")
                if execute_and_save "find $dir -type f -exec cat {} \;" "${output_subdir}/${dir_name}_contents.txt" "$dir Contents"; then success=true; fi
            fi
        done

        # User crontabs if not in minimal mode
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            if execute_and_save "for user in $(cut -f1 -d: /etc/passwd); do echo \"== $user ==\"; crontab -u $user -l 2>/dev/null || echo 'No crontab'; echo; done" "${output_subdir}/user_crontabs.txt" "User Crontabs"; then success=true; fi
        else
            # Just get root's crontab in minimal mode
            if execute_and_save "crontab -l 2>/dev/null || echo 'No crontab'" "${output_subdir}/root_crontab.txt" "Root Crontab"; then success=true; fi
        fi

        # Collect system-wide crontab
        if [[ -f "/etc/crontab" ]]; then
            if execute_and_save "cat /etc/crontab" "${output_subdir}/etc_crontab.txt" "System Crontab"; then success=true; fi
        fi

        # Collect systemd user units if not in minimal mode
        if [[ "$MINIMAL_COLLECTION" != "true" && -n "$systemctl_path" ]]; then
            if execute_and_save "$systemctl_path --user list-unit-files 2>/dev/null" "${output_subdir}/user_unit_files.txt" "User Systemd Units"; then success=true; fi
        fi

        # Create summary file
        local summary_file="${output_subdir}/startup_summary.txt"
        {
            echo "STARTUP ITEMS SUMMARY"
            echo "===================="
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            echo "SYSTEM STARTUP SERVICES:"
            if [[ -n "$systemctl_path" ]]; then
                echo "Enabled systemd services: $($systemctl_path list-unit-files --state=enabled | grep -c "enabled")"
                echo ""
                echo "RECENT SYSTEMD UNIT CHANGES (LAST 24 HOURS):"
                find /etc/systemd/ -type f -mtime -1 2>/dev/null | while read -r unit; do
                    echo "$(stat -c "%y - %n" "$unit")"
                done
            elif [[ -d "/etc/init.d" ]]; then
                echo "Init.d scripts: $(find /etc/init.d/ -type f -executable | wc -l)"
            fi

            echo ""
            echo "SCHEDULED TASKS:"
            echo "System cron jobs: $(find /etc/cron* -type f 2>/dev/null | wc -l)"

            if [[ -n "$systemctl_path" ]]; then
                echo "Systemd timers: $($systemctl_path list-timers --all | grep -v "NEXT\|ACTIVATES" | wc -l)"
            fi

            echo ""
            echo "NOTABLE STARTUP ENTRIES:"
            # Look for unusual or potentially suspicious startup items
            for pattern in "@reboot" "0.0.0.0" "curl -s" "wget" "nc " "netcat" "/dev/tcp/" "socat" "bash -i" ".sh" "bash -c" "eval"; do
                grep -r "$pattern" /etc/cron* /etc/systemd/* 2>/dev/null | grep -v ":#" | head -5
            done
        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        if [[ "$success" == "true" ]]; then
            log_coc_event "Completed" "Startup Items Collection" "Collected startup configuration"
        else
            log_coc_event "Fail" "Startup Items Collection" "Failed to collect startup items"
            return 1
        fi
        return 0
    }

    collect_command_history() {
        local output_subdir="${OUTPUT_DIR}/history"
        ensure_output_dir "$output_subdir" || return 1
        log_info "Collecting command history..."
        log_coc_event "Start" "Command History Collection"

        local success=false

        # Try to get history files for multiple users
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            local history_files=()

            # Look for history files in common user home directories
            while IFS=: read -r username home_dir _; do
                if [[ -d "$home_dir" ]]; then
                    for history_file in ".bash_history" ".zsh_history" ".history"; do
                        if [[ -r "$home_dir/$history_file" ]]; then
                            history_files+=("$home_dir/$history_file")
                            log_debug "Found history file: $home_dir/$history_file"
                        fi
                    done
                fi
            done < /etc/passwd

            # Copy each history file
            local history_count=0
            for history_file in "${history_files[@]}"; do
                local username=$(basename "$(dirname "$history_file")")
                if execute_and_save "cat '$history_file'" "${output_subdir}/${username}_history.txt" "$username History"; then
                    ((history_count++))
                    success=true
                fi
            done

            log_info "Collected $history_count user history files"
        else
            # In minimal mode, just get the current user's history
            if execute_and_save "history 1000" "${output_subdir}/current_history.txt" "Current Shell History"; then success=true; fi
        fi

        # Try to get shell histories from all users
        if execute_and_save "for dir in /root /home/*; do echo \"\n=== \$dir ===\"; cat \"\$dir/.bash_history\" 2>/dev/null; done" "${output_subdir}/all_bash_histories.txt" "All Bash Histories"; then success=true; fi

        # Get command log from journald if available
        local journalctl_path=$(get_tool_path "volatile_data" "journalctl")
        if [[ -n "$journalctl_path" ]]; then
            if execute_and_save "$journalctl_path -o verbose _COMM=sudo -n 1000" "${output_subdir}/sudo_journal.txt" "Sudo Journal Log"; then success=true; fi
            if execute_and_save "$journalctl_path -o verbose -n 1000 | grep -i command" "${output_subdir}/journald_commands.txt" "Journald Command Log"; then success=true; fi
        fi

        # Get auth log entries for commands
        if [[ -f "/var/log/auth.log" ]]; then
            if execute_and_save "grep -i 'COMMAND=' /var/log/auth.log | tail -n 1000" "${output_subdir}/auth_commands.txt" "Auth Log Commands"; then success=true; fi
        elif [[ -f "/var/log/secure" ]]; then
            if execute_and_save "grep -i 'COMMAND=' /var/log/secure | tail -n 1000" "${output_subdir}/secure_commands.txt" "Secure Log Commands"; then success=true; fi
        fi

        # Create a summary file with potentially interesting commands
        local summary_file="${output_subdir}/history_summary.txt"
        {
            echo "COMMAND HISTORY SUMMARY"
            echo "======================"
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            echo "HISTORY FILES FOUND:"
            find /home /root -name ".bash_history" -o -name ".zsh_history" 2>/dev/null | while read -r file; do
                if [[ -s "$file" ]]; then
                    echo "$(stat -c "%y - %s bytes" "$file") - $file"
                fi
            done

            echo ""
            echo "POTENTIALLY INTERESTING COMMANDS:"
            # Define patterns of potentially interesting commands
            local patterns=(
                "wget http"
                "curl http"
                "nc -"
                "chmod +x"
                "chmod 777"
                "rm -rf"
                "ssh -R"
                "ssh -D"
                "base64 -d"
                "python -m SimpleHTTPServer"
                "python3 -m http.server"
            )

            for pattern in "${patterns[@]}"; do
                echo -e "\n--- Commands matching '$pattern' ---"
                for file in "${output_subdir}"/*_history.txt "${output_subdir}"/all_bash_histories.txt; do
                    if [[ -f "$file" ]]; then
                        grep -i "$pattern" "$file" 2>/dev/null | tail -10
                    fi
                done
            done

        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        if [[ "$success" == "true" ]]; then
            log_coc_event "Completed" "Command History Collection" "Collected command history data"
        else
            log_coc_event "Fail" "Command History Collection" "Failed to collect command history"
            return 1
        fi
        return 0
    }

    collect_open_files() {
        local output_subdir="${OUTPUT_DIR}/open_files"
        ensure_output_dir "$output_subdir" || return 1
        log_info "Collecting open file information..."
        log_coc_event "Start" "Open Files Collection"

        local success=false

        # Get open files with lsof
        local lsof_path=$(get_tool_path "volatile_data" "lsof")
        if [[ -n "$lsof_path" ]]; then
            # All open files
            if execute_and_save "$lsof_path" "${output_subdir}/lsof_all.txt" "All Open Files"; then success=true; fi

            # Network connections
            if execute_and_save "$lsof_path -i" "${output_subdir}/lsof_network.txt" "Network Connections"; then success=true; fi

            # Files opened by specific processes if not in minimal mode
            if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
                # Get PIDs of interest
                for proc_name in "sshd" "httpd" "apache2" "nginx" "postgres" "mysql" "mariadb" "mongod" "redis"; do
                    pids=$(pgrep -f "$proc_name" 2>/dev/null)
                    if [[ -n "$pids" ]]; then
                        for pid in $pids; do
                            if execute_and_save "$lsof_path -p $pid" "${output_subdir}/lsof_${proc_name}_${pid}.txt" "Files Opened by $proc_name ($pid)"; then success=true; fi
                        done
                    fi
                done
            fi
        else
            log_warn "lsof command not found, falling back to alternatives"

            # Try to get information about open files from /proc
            if [[ -d "/proc" ]]; then
                if execute_and_save "find /proc/*/fd -type l -ls 2>/dev/null | sort -n" "${output_subdir}/proc_fd_links.txt" "Proc FD Links"; then success=true; fi
            fi
        fi

        # Get file handles from /proc/sys
        if [[ -f "/proc/sys/fs/file-nr" ]]; then
            if execute_and_save "cat /proc/sys/fs/file-nr" "${output_subdir}/file_nr.txt" "File Handle Statistics"; then success=true; fi
        fi

        # Get CPU usage per process (to find most active processes)
        if [[ "$MINIMAL_COLLECTION" != "true" ]]; then
            if execute_and_save "ps aux --sort=-%cpu | head -20" "${output_subdir}/top_cpu_processes.txt" "Top CPU Processes"; then success=true; fi
        fi

        # Create a summary file with statistics
        local summary_file="${output_subdir}/open_files_summary.txt"
        {
            echo "OPEN FILES SUMMARY"
            echo "================="
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            if [[ -n "$lsof_path" ]]; then
                echo "OPEN FILES COUNT: $($lsof_path 2>/dev/null | wc -l)"

                echo ""
                echo "FILES PER USER (TOP 10):"
                $lsof_path 2>/dev/null | awk '{print $3}' | sort | uniq -c | sort -nr | head -10

                echo ""
                echo "FILES PER PROCESS (TOP 10):"
                $lsof_path 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr | head -10

                echo ""
                echo "NETWORK CONNECTIONS:"
                $lsof_path -i 2>/dev/null | grep -v "COMMAND" | awk '{print $1, $9}' | sort | uniq -c | sort -nr
            elif [[ -d "/proc" ]]; then
                echo "TOTAL OPEN FILE DESCRIPTORS: $(find /proc/*/fd -type l 2>/dev/null | wc -l)"

                echo ""
                echo "FILE DESCRIPTORS PER PROCESS (TOP 10):"
                find /proc/*/fd -type l 2>/dev/null | cut -d/ -f3 | sort | uniq -c | sort -nr | head -10 | while read -r count pid; do
                    cmd=$(tr -d '\0' < "/proc/$pid/cmdline" 2>/dev/null | tr -c '[:print:]' ' ' | head -c 50 || echo "unknown")
                    echo "$count - PID $pid ($cmd)"
                done
            fi

            # File handle limits
            if [[ -f "/proc/sys/fs/file-nr" ]]; then
                echo ""
                echo "FILE HANDLE STATS:"
                local file_nr=$(cat /proc/sys/fs/file-nr 2>/dev/null)
                echo "Currently allocated file handles: $(echo "$file_nr" | awk '{print $1}')"
                echo "Currently used file handles: $(echo "$file_nr" | awk '{print $2}')"
                echo "Maximum file handles: $(echo "$file_nr" | awk '{print $3}')"
            fi

        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        if [[ "$success" == "true" ]]; then
            log_coc_event "Completed" "Open Files Collection" "Collected open file information"
        else
            log_coc_event "Fail" "Open Files Collection" "Failed to collect open file data"
            return 1
        fi
        return 0
    }

    collect_mounted_devices() {
        local output_subdir="${OUTPUT_DIR}/mounted_devices"
        ensure_output_dir "$output_subdir" || return 1
        log_info "Collecting mounted device information..."
        log_coc_event "Start" "Mounted Devices Collection"

        local success=false

        # Get mount information
        if execute_and_save "mount" "${output_subdir}/mount.txt" "Mount Information"; then success=true; fi

        # Get more detailed mount information with df
        if execute_and_save "df -h" "${output_subdir}/df_h.txt" "Disk Usage"; then success=true; fi
        if execute_and_save "df -i" "${output_subdir}/df_i.txt" "Inode Usage"; then success=true; fi

        # Get information from /proc/mounts
        if [[ -f "/proc/mounts" ]]; then
            if execute_and_save "cat /proc/mounts" "${output_subdir}/proc_mounts.txt" "Proc Mounts"; then success=true; fi
        fi

        # Get information from /proc/partitions
        if [[ -f "/proc/partitions" ]]; then
            if execute_and_save "cat /proc/partitions" "${output_subdir}/proc_partitions.txt" "Proc Partitions"; then success=true; fi
        fi

        # Get fstab file
        if [[ -f "/etc/fstab" ]]; then
            if execute_and_save "cat /etc/fstab" "${output_subdir}/etc_fstab.txt" "Fstab"; then success=true; fi
        fi

        # Get block device information using lsblk if available
        local lsblk_path=$(get_tool_path "volatile_data" "lsblk")
        if [[ -n "$lsblk_path" ]]; then
            if execute_and_save "$lsblk_path -a" "${output_subdir}/lsblk_a.txt" "Block Devices"; then success=true; fi
            if execute_and_save "$lsblk_path -f" "${output_subdir}/lsblk_f.txt" "Block Devices Filesystems"; then success=true; fi
        fi

        # Get information from blkid if available
        local blkid_path=$(get_tool_path "volatile_data" "blkid")
        if [[ -n "$blkid_path" ]]; then
            if execute_and_save "$blkid_path" "${output_subdir}/blkid.txt" "Block Device IDs"; then success=true; fi
        fi

        # Create a summary file
        local summary_file="${output_subdir}/mounted_devices_summary.txt"
        {
            echo "MOUNTED DEVICES SUMMARY"
            echo "======================"
            echo "Collection Timestamp: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo ""

            echo "MOUNT POINTS OVERVIEW:"
            mount | sort | column -t

            echo ""
            echo "DISK SPACE USAGE:"
            df -h | sort -k 5nr | head -15

            echo ""
            echo "UNUSUAL MOUNT POINTS:"
            # Look for potentially suspicious mount points
            mount | grep -E '/(dev|proc|sys)/|/tmp|uid=0|nosuid|noexec' | grep -v '/proc /proc' | grep -v '/sys /sys' | grep -v '/dev /dev'

            echo ""
            echo "ENCRYPTED VOLUMES:"
            if command -v dmsetup &>/dev/null; then
                dmsetup ls --target crypt || echo "No encrypted volumes found"
            else
                grep -E 'CRYPT|LUKS' /proc/mounts 2>/dev/null || echo "No encrypted volumes found or tool unavailable"
            fi

        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        if [[ "$success" == "true" ]]; then
            log_coc_event "Completed" "Mounted Devices Collection" "Collected mounted device information"
        else
            log_coc_event "Fail" "Mounted Devices Collection" "Failed to collect mounted devices data"
            return 1
        fi
        return 0
    }

    # Execute custom commands defined by the user
    execute_custom_commands() {
        if [[ -z "$CUSTOM_COMMANDS" || ! -f "$CUSTOM_COMMANDS" ]]; then
            log_debug "No custom commands file specified or file not found"
            return 0
        fi

        local output_subdir="${OUTPUT_DIR}/custom"
        ensure_output_dir "$output_subdir" || return 1
        log_info "Executing custom commands from $CUSTOM_COMMANDS..."
        log_coc_event "Start" "Custom Commands Execution"

        local success=false
        local command_count=0

        # Read and execute each command from the file
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
                continue
            fi

            # Split the line into command and description if separator exists
            local cmd
            local description
            if [[ "$line" == *"::"* ]]; then
                cmd=$(echo "$line" | cut -d: -f1 | sed 's/[[:space:]]*$//')
                description=$(echo "$line" | cut -d: -f3- | sed 's/^[[:space:]]*//')
            else
                cmd="$line"
                # Use first 30 chars of command as description
                description="${cmd:0:30}..."
            fi

            # Create a safe filename from the description or command
            local safe_name
            if [[ -n "$description" ]]; then
                safe_name=$(echo "$description" | tr -c '[:alnum:]' '_' | tr -s '_' | cut -c 1-50)
            else
                safe_name=$(echo "$cmd" | tr -c '[:alnum:]' '_' | tr -s '_' | cut -c 1-50)
            fi

            log_info "Executing custom command: $cmd"
            if execute_and_save "$cmd" "${output_subdir}/custom_${safe_name}.txt" "Custom: $description"; then
                ((command_count++))
                success=true
            fi
        done < "$CUSTOM_COMMANDS"

        if [[ "$success" == "true" ]]; then
            log_success "Executed $command_count custom commands successfully"
            log_coc_event "Completed" "Custom Commands" "Executed $command_count commands"
        else
            log_warn "Failed to execute custom commands"
            log_coc_event "Fail" "Custom Commands" "Failed to execute commands"
            return 1
        fi
        return 0
    }

    # --- Main Execution ---
    main() {
        # Parse arguments
        parse_arguments "$@"

        # Initialize common functions (logging, CoC, tool paths)
        # Pass log paths and output dir if overridden by args
        init_common_functions "${LOG_FILE:-}" "${AUDIT_LOG_FILE:-}" "${OUTPUT_DIR:-}"

        log_info "Starting Volatile Data Collection v${VOLATILE_DATA_VERSION}"
        log_audit "Volatile Data Collection Started"

        # Ensure base output directory exists
        ensure_output_dir "$OUTPUT_DIR" || error_exit "Failed to create base output directory: $OUTPUT_DIR"

        # Log parameters
        log_debug "Parameters: Output='$OUTPUT_DIR', Target='$TARGET_HOST', Categories='$CATEGORIES'"
        log_debug "Process Args: $PROCESS_ARGS, Process Env: $PROCESS_ENV"

        # Convert categories string to array
        IFS=',' read -ra CATEGORIES_ARRAY <<< "$CATEGORIES"

        local collection_failed=false
        for category in "${CATEGORIES_ARRAY[@]}"; do
            log_info "--- Collecting category: $category ---"
            case "$category" in
                processes) collect_processes || collection_failed=true ;;
                network) collect_network_info || collection_failed=true ;;
                users) collect_users || collection_failed=true ;;
                system_info) collect_system_info || collection_failed=true ;;
                services) collect_services || collection_failed=true ;;
                modules|kernel_modules|loaded_drivers) collect_modules || collection_failed=true ;;
                startup_items|scheduled_tasks) collect_startup_items || collection_failed=true ;;
                command_history|login_history) collect_command_history || collection_failed=true ;;
                open_files|file_handles) collect_open_files || collection_failed=true ;;
                mounted_devices) collect_mounted_devices || collection_failed=true ;;
                *) log_warn "Unknown or unsupported category: $category" ;;
            esac
        done

        # Execute any custom commands if specified
        if [[ -n "$CUSTOM_COMMANDS" ]]; then
            execute_custom_commands || collection_failed=true
        fi

        # Create an overall summary file
        local summary_file="${OUTPUT_DIR}/collection_summary.txt"
        {
            echo "VOLATILE DATA COLLECTION SUMMARY"
            echo "================================"
            echo "Collection Date: $(date +"$DEFAULT_TIMESTAMP_FORMAT")"
            echo "Host: $(hostname 2>/dev/null || echo 'Unknown')"
            echo "Case ID: ${CASE_ID:-Not Specified}"
            echo "Examiner: ${EXAMINER_ID:-Not Specified}"
            echo ""
            echo "COLLECTED CATEGORIES:"
            for category in "${CATEGORIES_ARRAY[@]}"; do
                if [[ -d "${OUTPUT_DIR}/${category//_*/}" ]]; then
                    echo "- $category: Collected"
                else
                    echo "- $category: Not collected or failed"
                fi
            done

            echo ""
            echo "COLLECTION STATISTICS:"
            echo "Total files collected: $(find "$OUTPUT_DIR" -type f | wc -l)"
            echo "Total data size: $(du -sh "$OUTPUT_DIR" | cut -f1)"

            echo ""
            echo "SYSTEM OVERVIEW:"
            echo "OS: $(grep -i "pretty_name" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)"
            echo "Kernel: $(uname -r 2>/dev/null || echo 'Unknown')"
            echo "Uptime: $(uptime 2>/dev/null || echo 'Unknown')"

        } > "$summary_file"
        chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"

        log_info "Summary report generated: $summary_file"
        log_coc_event "Generated" "Collection Summary" "File: $summary_file"

        if [[ "$collection_failed" == "true" ]]; then
            log_error "One or more volatile data collection categories failed."
            log_audit "Volatile Data Collection Completed with Errors"
            # cleanup_on_exit will handle temporary files
            exit 1
        else
            log_success "Volatile data collection completed successfully."
            log_audit "Volatile Data Collection Completed Successfully"
            exit 0
        fi
    }

    # Execute main function
    main "$@"
