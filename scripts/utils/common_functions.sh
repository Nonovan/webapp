#!/bin/bash
# Common Utility Functions for Cloud Infrastructure Platform
# Usage: source /scripts/utils/common_functions.sh in your scripts
# 
# This file contains shared utility functions for use across multiple scripts,
# including logging, environment management, error handling, validation,
# file operations, and notification utilities.

# Ensure script fails on error when sourced with 'set -e'
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    set -o errexit
    set -o pipefail
    set -o nounset
else
    # Script is being sourced, don't override caller's error settings
    :
fi

# Default configuration
DEFAULT_LOG_DIR="/var/log/cloud-platform"
DEFAULT_BACKUP_DIR="/var/backups/cloud-platform"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")" && pwd)"
ENV_FILE_DIR="${PROJECT_ROOT}/deployment/environments"
DEFAULT_ENVIRONMENT="production"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Text colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Ensure the log directory exists
mkdir -p "$DEFAULT_LOG_DIR"

#######################################
# LOGGING FUNCTIONS
#######################################

# Log a message with timestamp and optional log level
# Arguments:
#   $1 - Message to log
#   $2 - Log level (INFO, WARNING, ERROR, DEBUG) - defaults to INFO
#   $3 - Log file (optional - defaults to stdout)
log() {
    local message="$1"
    local level="${2:-INFO}"
    local log_file="${3:-}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Format based on log level
    case "$level" in
        INFO)
            local colored_level="${GREEN}INFO${NC}"
            ;;
        WARNING)
            local colored_level="${YELLOW}WARNING${NC}"
            ;;
        ERROR)
            local colored_level="${RED}ERROR${NC}"
            ;;
        DEBUG)
            local colored_level="${BLUE}DEBUG${NC}"
            ;;
        *)
            local colored_level="$level"
            ;;
    esac
    
    # Format the log message
    local log_message="[$timestamp] [${colored_level}] $message"
    local plain_message="[$timestamp] [$level] $message"
    
    # Output to console if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo -e "$log_message"
    fi
    
    # Output to log file if specified
    if [[ -n "$log_file" ]]; then
        echo "$plain_message" >> "$log_file"
    fi
}

# Log an error message and exit
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
#   $3 - Log file (optional)
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    local log_file="${3:-}"
    
    log "$message" "ERROR" "$log_file"
    exit "$exit_code"
}

# Log a warning message
# Arguments:
#   $1 - Warning message
#   $2 - Log file (optional)
warn() {
    local message="$1"
    local log_file="${2:-}"
    
    log "$message" "WARNING" "$log_file"
}

# Log a debug message (only when DEBUG=true)
# Arguments:
#   $1 - Debug message
#   $2 - Log file (optional)
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local message="$1"
        local log_file="${2:-}"
        
        log "$message" "DEBUG" "$log_file"
    fi
}

# Log an important message (highlighted)
# Arguments:
#   $1 - Important message
#   $2 - Log file (optional)
important() {
    local message="$1"
    local log_file="${2:-}"
    
    log "${BOLD}${message}${NC}" "INFO" "$log_file"
}

# Log to the disaster recovery events log
# Arguments:
#   $1 - Event type
#   $2 - Environment
#   $3 - Region (optional)
#   $4 - Status (optional)
#   $5 - Details (optional)
log_dr_event() {
    local event_type="$1"
    local environment="$2"
    local region="${3:-all}"
    local status="${4:-COMPLETED}"
    local details="${5:-}"
    local dr_log="${DEFAULT_LOG_DIR}/dr-events.log"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname -f 2>/dev/null || hostname)
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$dr_log")"
    
    # Create log entry
    local log_entry="${timestamp},${event_type},${environment},${region},${status},${hostname}"
    
    # Add details if provided
    if [[ -n "$details" ]]; then
        # Escape commas in details to avoid breaking CSV format
        details="${details//,/;}"
        log_entry="${log_entry},${details}"
    fi
    
    # Append to DR events log
    echo "$log_entry" >> "$dr_log"
    debug "DR event logged: $event_type - $status" "$dr_log"
}

#######################################
# ENVIRONMENT FUNCTIONS
#######################################

# Load environment-specific variables from file
# Arguments:
#   $1 - Environment name (e.g., production, staging)
#   $2 - Custom environment file path (optional)
load_env() {
    local environment="${1:-$DEFAULT_ENVIRONMENT}"
    local custom_env_file="${2:-}"
    local env_file
    
    # Use custom file if provided, otherwise use default location
    if [[ -n "$custom_env_file" && -f "$custom_env_file" ]]; then
        env_file="$custom_env_file"
    else
        env_file="${ENV_FILE_DIR}/${environment}.env"
    fi
    
    # Check if file exists
    if [[ ! -f "$env_file" ]]; then
        warn "Environment file not found: $env_file"
        return 1
    fi
    
    # Source the environment file
    # shellcheck source=/dev/null
    source "$env_file"
    log "Loaded environment configuration from $env_file"
    return 0
}

# Validate if environment is valid
# Arguments:
#   $1 - Environment to validate
#   $2 - Array of valid environments (optional)
validate_environment() {
    local environment="$1"
    shift
    local valid_envs=("${@:-development staging production dr-recovery}")
    
    local valid=false
    for env in "${valid_envs[@]}"; do
        if [[ "$environment" == "$env" ]]; then
            valid=true
            break
        fi
    done
    
    if [[ "$valid" == "false" ]]; then
        log "Invalid environment: $environment" "ERROR"
        log "Valid environments: ${valid_envs[*]}" "ERROR"
        return 1
    fi
    
    return 0
}

# Get the current environment from ENV variable or hostname
# Returns the detected environment
detect_environment() {
    # If ENV is set, use it
    if [[ -n "${ENV:-}" ]]; then
        echo "$ENV"
        return 0
    fi
    
    # Try to detect from hostname
    local hostname=$(hostname -f 2>/dev/null || hostname)
    if [[ "$hostname" =~ (^|[-\.])prod($|[-\.]) || "$hostname" =~ production ]]; then
        echo "production"
    elif [[ "$hostname" =~ (^|[-\.])stg($|[-\.]) || "$hostname" =~ staging ]]; then
        echo "staging"
    elif [[ "$hostname" =~ (^|[-\.])dev($|[-\.]) || "$hostname" =~ development ]]; then
        echo "development"
    elif [[ "$hostname" =~ (^|[-\.])dr($|[-\.]) ]]; then
        echo "dr-recovery"
    elif [[ -f "${ENV_FILE_DIR}/environment_map.txt" ]]; then
        # Try to find in environment mapping file
        grep -i "^$hostname=" "${ENV_FILE_DIR}/environment_map.txt" | cut -d'=' -f2 || echo "$DEFAULT_ENVIRONMENT"
    else
        echo "$DEFAULT_ENVIRONMENT"
    fi
}

#######################################
# VALIDATION FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns: 0 if exists, 1 if not
command_exists() {
    command -v "$1" &>/dev/null
    return $?
}

# Check if a file exists and is readable
# Arguments:
#   $1 - File path
#   $2 - Error message (optional)
# Returns: 0 if exists, 1 if not
file_exists() {
    local file="$1"
    local error_msg="${2:-File does not exist or is not readable: $file}"
    
    if [[ ! -r "$file" ]]; then
        log "$error_msg" "ERROR"
        return 1
    fi
    
    return 0
}

# Validate if a string is a valid IP address
# Arguments:
#   $1 - String to validate
#   $2 - Type (4 for IPv4, 6 for IPv6, both if not specified)
# Returns: 0 if valid, 1 if not
is_valid_ip() {
    local ip="$1"
    local type="${2:-both}"
    
    case "$type" in
        4|ipv4)
            # IPv4 validation
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local IFS='.'
                read -ra ip_array <<< "$ip"
                
                for octet in "${ip_array[@]}"; do
                    if (( octet < 0 || octet > 255 )); then
                        return 1
                    fi
                done
                
                return 0
            fi
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (simplified)
            if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                return 0
            fi
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            log "Invalid IP type specified: $type. Use 4, 6, or both" "ERROR"
            return 1
            ;;
    esac
}

# Check if a value is a number
# Arguments:
#   $1 - Value to check
#   $2 - Allow floating point (true/false, defaults to false)
# Returns: 0 if numeric, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"
    
    if [[ "$allow_float" == "true" ]]; then
        [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
        return $?
    else
        [[ "$value" =~ ^[0-9]+$ ]]
        return $?
    fi
}

# Validate required parameters
# Arguments:
#   Variable number of parameter names to check
# Returns: 0 if all parameters exist, 1 if any are missing
validate_required_params() {
    local missing=0
    
    for param in "$@"; do
        if [[ -z "${!param:-}" ]]; then
            log "Required parameter missing: $param" "ERROR"
            missing=$((missing + 1))
        fi
    done
    
    if (( missing > 0 )); then
        return 1
    fi
    
    return 0
}

# Validate a URL format
# Arguments:
#   $1 - URL to validate
# Returns: 0 if valid, 1 if not
is_valid_url() {
    local url="$1"
    
    # Basic URL validation - requires http:// or https:// prefix
    if [[ "$url" =~ ^https?:// ]]; then
        return 0
    fi
    return 1
}

# Validate email format
# Arguments:
#   $1 - Email to validate
# Returns: 0 if valid, 1 if not
is_valid_email() {
    local email="$1"
    
    # Basic email validation
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

#######################################
# FILE OPERATIONS
#######################################

# Create a backup of a file
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
# Returns: Path to backup file
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${TIMESTAMP}.bak"
    
    # Ensure backup directory exists
    mkdir -p "$backup_dir"
    
    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        warn "Cannot backup file, source does not exist: $file"
        return 1
    fi
    
    # Create backup
    cp -p "$file" "$backup_file" || {
        warn "Failed to create backup of $file"
        return 1
    }
    
    log "Backed up $file to $backup_file" "INFO"
    
    echo "$backup_file"
}

# Create directory if it doesn't exist
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to 755)
# Returns: 0 if created or already exists, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-755}"
    
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            log "Failed to create directory: $dir" "ERROR"
            return 1
        }
        chmod "$perms" "$dir" || {
            log "Failed to set permissions $perms on directory: $dir" "ERROR"
            return 1
        }
        log "Created directory: $dir with permissions $perms" "INFO"
    fi
    
    return 0
}

# Safely write content to a file with error handling
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to 644)
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-644}"
    local temp_file
    
    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || return 1
    
    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        backup_file "$output_file" >/dev/null || {
            log "Failed to back up existing file: $output_file" "WARNING"
        }
    fi
    
    # Write to temporary file first to prevent partial writes
    temp_file=$(mktemp) || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }
    
    echo "$content" > "$temp_file" || {
        log "Failed to write content to temporary file" "ERROR"
        rm -f "$temp_file"
        return 1
    }
    
    # Set permissions on temporary file before moving
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }
    
    # Move temporary file to destination
    mv "$temp_file" "$output_file" || {
        log "Failed to write to $output_file" "ERROR"
        rm -f "$temp_file"
        return 1
    }
    
    log "Successfully wrote to $output_file" "INFO"
    return 0
}

# Get file age in seconds
# Arguments:
#   $1 - File path
# Returns: File age in seconds or -1 if file not found
file_age() {
    local file="$1"
    local file_time
    local current_time
    
    if [[ ! -f "$file" ]]; then
        echo "-1"
        return 1
    fi
    
    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_time=$(stat -f %m "$file")
        else
            # Linux version
            file_time=$(stat -c %Y "$file")
        fi
    else
        # Fallback method using ls
        file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
        if [[ -z "$file_time" ]]; then
            echo "-1"
            return 1
        fi
    fi
    
    current_time=$(date +%s)
    echo $((current_time - file_time))
}

# Find files newer than specified time
# Arguments:
#   $1 - Directory to search
#   $2 - Time in minutes
#   $3 - File pattern (optional)
# Returns: List of files
find_newer_files() {
    local dir="$1"
    local minutes="$2"
    local pattern="${3:-*}"
    
    if [[ ! -d "$dir" ]]; then
        warn "Directory does not exist: $dir"
        return 1
    fi
    
    find "$dir" -type f -name "$pattern" -mmin -"$minutes"
}

# Calculate checksum of a file
# Arguments:
#   $1 - File path
#   $2 - Algorithm (md5, sha1, sha256, defaults to sha256)
# Returns: Checksum of the file
calculate_checksum() {
    local file="$1"
    local algorithm="${2:-sha256}"
    
    if [[ ! -f "$file" ]]; then
        log "File does not exist: $file" "ERROR"
        return 1
    fi
    
    case "$algorithm" in
        md5)
            if command_exists md5sum; then
                md5sum "$file" | awk '{print $1}'
            elif command_exists md5; then
                md5 -q "$file"
            else
                log "No MD5 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        sha1)
            if command_exists sha1sum; then
                sha1sum "$file" | awk '{print $1}'
            elif command_exists shasum; then
                shasum -a 1 "$file" | awk '{print $1}'
            else
                log "No SHA1 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        sha256)
            if command_exists sha256sum; then
                sha256sum "$file" | awk '{print $1}'
            elif command_exists shasum; then
                shasum -a 256 "$file" | awk '{print $1}'
            else
                log "No SHA256 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        *)
            log "Unsupported checksum algorithm: $algorithm" "ERROR"
            return 1
            ;;
    esac
}

#######################################
# SYSTEM OPERATIONS
#######################################

# Check if running as root
# Returns: 0 if root, 1 if not
is_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    fi
    return 0
}

# Get system information
# Returns: JSON string with system information
get_system_info() {
    local os_name
    local kernel
    local hostname
    local uptime
    local cpu_info
    local total_memory
    
    # Get OS name
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    else
        os_name=$(uname -s)
    fi
    
    kernel=$(uname -r)
    hostname=$(hostname -f 2>/dev/null || hostname)
    uptime=$(uptime -p 2>/dev/null || uptime)
    
    # Get CPU info
    if [[ -f /proc/cpuinfo ]]; then
        cpu_info=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
        if [[ -z "$cpu_info" ]]; then
            cpu_info="Unknown"
        fi
    else
        cpu_info="Unknown"
    fi
    
    # Get memory info
    if command_exists free; then
        total_memory=$(free -m | grep Mem: | awk '{print $2}')
        total_memory="${total_memory} MB"
    else
        total_memory="Unknown"
    fi
    
    echo "{\"hostname\":\"$hostname\",\"os\":\"$os_name\",\"kernel\":\"$kernel\",\"uptime\":\"$uptime\",\"cpu\":\"$cpu_info\",\"memory\":\"$total_memory\"}"
}

# Check available disk space on a path (in MB)
# Arguments:
#   $1 - Path to check
# Returns: Available disk space in MB
check_disk_space() {
    local path="${1:-/}"
    local available
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS version
        available=$(df -m "$path" | awk 'NR==2 {print $4}')
    else
        # Linux version
        available=$(df -BM "$path" | awk 'NR==2 {print $4}' | tr -d 'M')
    fi
    
    echo "$available"
}

# Check if a port is in use
# Arguments:
#   $1 - Port number
#   $2 - Protocol (tcp, udp, defaults to tcp)
# Returns: 0 if port is in use, 1 if available
is_port_in_use() {
    local port="$1"
    local protocol="${2:-tcp}"
    
    if ! is_number "$port"; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi
    
    if command_exists netstat; then
        netstat -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists ss; then
        ss -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists lsof; then
        lsof -i "$protocol:$port" &>/dev/null && return 0
    else
        warn "Neither netstat, ss, nor lsof commands available to check port"
        return 2
    fi
    
    return 1
}

# Generate a temporary file with proper permissions
# Arguments:
#   $1 - File prefix
#   $2 - Permissions (optional - defaults to 600)
# Returns: Path to temporary file
get_temp_file() {
    local prefix="${1:-tmp}"
    local perms="${2:-600}"
    local temp_file
    
    temp_file=$(mktemp "/tmp/${prefix}_XXXXXXXX") || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }
    
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }
    
    echo "$temp_file"
}

# Execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2...$n - Command to execute and its arguments
# Returns: Command exit code or 124 for timeout
execute_with_timeout() {
    local timeout="$1"
    shift
    
    if command_exists timeout; then
        timeout "$timeout" "$@"
        return $?
    else
        # Fallback if timeout command doesn't exist
        local pid
        "$@" &
        pid=$!
        
        # Wait for specified time
        (sleep "$timeout" && kill -9 $pid 2>/dev/null) &
        local watchdog=$!
        
        # Wait for process to complete
        wait $pid 2>/dev/null
        local ret=$?
        
        # Kill the watchdog
        kill -9 $watchdog 2>/dev/null
        
        return $ret
    fi
}

# Get system load average
# Returns: Current 1-minute load average
get_load_average() {
    if [[ -f /proc/loadavg ]]; then
        awk '{print $1}' /proc/loadavg
    elif command_exists uptime; then
        uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' '
    else
        echo "0.0"
        return 1
    fi
}

# Get total and available memory in MB
# Returns: JSON with memory information
get_memory_info() {
    local total_mem
    local free_mem
    local used_mem
    
    if [[ -f /proc/meminfo ]]; then
        # Linux
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
        free_mem=$(grep MemAvailable /proc/meminfo 2>/dev/null || grep MemFree /proc/meminfo | awk '{print int($2/1024)}')
        used_mem=$((total_mem - free_mem))
    elif command_exists free; then
        # Alternative using free command
        total_mem=$(free -m | grep Mem: | awk '{print $2}')
        free_mem=$(free -m | grep Mem: | awk '{print $7}')
        used_mem=$((total_mem - free_mem))
    elif command_exists vm_stat; then
        # macOS
        local page_size=$(pagesize 2>/dev/null || echo 4096)
        local pages_free=$(vm_stat | grep 'Pages free' | awk '{print $3}' | tr -d '.')
        local pages_active=$(vm_stat | grep 'Pages active' | awk '{print $3}' | tr -d '.')
        local pages_inactive=$(vm_stat | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')
        local pages_speculative=$(vm_stat | grep 'Pages speculative' | awk '{print $3}' | tr -d '.')
        local pages_wired=$(vm_stat | grep 'Pages wired down' | awk '{print $4}' | tr -d '.')
        
        total_mem=$(( (pages_free + pages_active + pages_inactive + pages_speculative + pages_wired) * page_size / 1024 / 1024 ))
        free_mem=$(( (pages_free + pages_inactive) * page_size / 1024 / 1024 ))
        used_mem=$(( (pages_active + pages_wired) * page_size / 1024 / 1024 ))
    else
        # Fallback
        total_mem=0
        free_mem=0
        used_mem=0
    fi
    
    echo "{\"total_mb\":$total_mem,\"used_mb\":$used_mem,\"free_mb\":$free_mem}"
}

#######################################
# NETWORK OPERATIONS
#######################################

# Check if URL is reachable
# Arguments:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional - defaults to 10)
#   $3 - Additional options for curl/wget (optional)
# Returns: 0 if reachable, 1 if not
is_url_reachable() {
    local url="$1"
    local timeout="${2:-10}"
    local options="${3:-}"
    
    if ! is_valid_url "$url"; then
        log "Invalid URL format: $url" "ERROR"
        return 1
    fi
    
    if command_exists curl; then
        if curl --output /dev/null --silent --head --fail --max-time "$timeout" $options "$url"; then
            return 0
        fi
    elif command_exists wget; then
        if wget --quiet --spider --timeout="$timeout" $options "$url"; then
            return 0
        fi
    else
        log "Neither curl nor wget available to check URL" "WARNING"
        return 2
    fi
    
    return 1
}

# Get public IP address
# Returns: Public IP address or error message
get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )
    
    for service in "${services[@]}"; do
        if command_exists curl; then
            ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout=5 "$service" 2>/dev/null)
        else
            echo "ERROR: Neither curl nor wget are available"
            return 1
        fi
        
        # Check if we got a valid IP
        if [[ -n "$ip" && ( $(is_valid_ip "$ip" 4) || $(is_valid_ip "$ip" 6) ) ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    echo "ERROR: Could not determine public IP address"
    return 1
}

# Check if host is reachable via ping
# Arguments:
#   $1 - Host to ping
#   $2 - Number of packets (optional - defaults to 1)
#   $3 - Timeout in seconds (optional - defaults to 2)
# Returns: 0 if reachable, 1 if not
ping_host() {
    local host="$1"
    local count="${2:-1}"
    local timeout="${3:-2}"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    else
        # Linux
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# Get primary DNS servers
# Returns: List of DNS servers
get_dns_servers() {
    local servers=""
    
    if [[ -f /etc/resolv.conf ]]; then
        servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}')
    fi
    
    # If no servers found, try alternative methods
    if [[ -z "$servers" ]]; then
        if command_exists systemd-resolve; then
            servers=$(systemd-resolve --status | grep 'DNS Servers' | awk '{print $3}')
        elif command_exists scutil && [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            servers=$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u)
        fi
    fi
    
    echo "$servers"
}

# Resolve a hostname to IP address
# Arguments:
#   $1 - Hostname to resolve
#   $2 - Record type (optional, A or AAAA, defaults to A)
# Returns: IP address(es)
resolve_hostname() {
    local hostname="$1"
    local record_type="${2:-A}"
    
    if command_exists dig; then
        dig +short "$record_type" "$hostname" 2>/dev/null
    elif command_exists host; then
        host -t "$record_type" "$hostname" 2>/dev/null | awk '/has address/ {print $4}; /has IPv6/ {print $5}'
    elif command_exists nslookup; then
        nslookup -type="$record_type" "$hostname" 2>/dev/null | awk '/^Address/ && !/#/ {print $2}'
    else
        log "No DNS resolution tools available" "ERROR"
        return 1
    fi
}

#######################################
# NOTIFICATION FUNCTIONS
#######################################

# Send email notification
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Recipient (optional - uses EMAIL_RECIPIENT from env if not provided)
#   $4 - Attachment file (optional)
# Returns: 0 on success, 1 on failure
send_email_notification() {
    local subject="$1"
    local message="$2"
    local recipient="${3:-${EMAIL_RECIPIENT:-}}"
    local attachment="${4:-}"
    
    # Check if recipient is provided
    if [[ -z "$recipient" ]]; then
        warn "No email recipient specified, notification not sent"
        return 1
    fi
    
    # Validate email format
    if ! is_valid_email "$recipient"; then
        warn "Invalid email recipient format: $recipient"
        return 1
    }
    
    # Format subject with hostname for clarity
    local hostname=$(hostname -f 2>/dev/null || hostname)
    subject="[Cloud Platform ${hostname}] $subject"
    
    # Try different mail sending methods
    if command_exists mail; then
        if [[ -n "$attachment" && -f "$attachment" ]]; then
            echo -e "$message" | mail -s "$subject" -a "$attachment" "$recipient"
        else
            echo -e "$message" | mail -s "$subject" "$recipient"
        fi
        log "Email notification sent to $recipient: $subject" "INFO"
        return 0
    elif command_exists sendmail; then
        (
            echo "To: $recipient"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo
            echo -e "$message"
        ) | sendmail -t
        log "Email notification sent to $recipient via sendmail: $subject" "INFO"
        return 0
    elif command_exists aws && [[ -n "${AWS_SES_ENABLED:-}" && "$AWS_SES_ENABLED" == "true" ]]; then
        # AWS SES method
        local ses_region="${AWS_SES_REGION:-us-east-1}"
        local ses_from="${AWS_SES_FROM:-no-reply@example.com}"
        
        aws ses send-email \
            --region "$ses_region" \
            --from "$ses_from" \
            --destination "ToAddresses=$recipient" \
            --message "Subject={Data=$subject},Body={Text={Data=$message}}" \
            &>/dev/null
        
        log "Email notification sent via AWS SES to $recipient: $subject" "INFO"
        return 0
    else
        warn "No email sending method available, cannot send email notification"
        return 1
    fi
}

# Send Slack notification
# Arguments:
#   $1 - Message to send
#   $2 - Webhook URL (optional - uses SLACK_WEBHOOK_URL from env if not provided)
#   $3 - Channel (optional - uses default channel from webhook if not provided)
# Returns: 0 on success, 1 on failure
send_slack_notification() {
    local message="$1"
    local webhook="${2:-${SLACK_WEBHOOK_URL:-}}"
    local channel="${3:-}"
    local hostname=$(hostname -f 2>/dev/null || hostname)
    local environment=$(detect_environment)
    
    # Check if webhook URL is provided
    if [[ -z "$webhook" ]]; then
        warn "No Slack webhook URL specified, notification not sent"
        return 1
    fi
    
    # Check if curl is available
    if ! command_exists curl; then
        warn "curl command not available, cannot send Slack notification"
        return 1
    fi
    
    # Format the JSON payload
    local payload
    if [[ -n "$channel" ]]; then
        payload="{\"text\":\"*[$environment - $hostname]* $message\", \"channel\":\"$channel\"}"
    else
        payload="{\"text\":\"*[$environment - $hostname]* $message\"}"
    fi
    
    # Send the notification
    if curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$webhook" -o /dev/null; then
        log "Slack notification sent: $message" "INFO"
        return 0
    else
        warn "Failed to send Slack notification"
        return 1
    fi
}

# Send notification (tries multiple methods)
# Arguments:
#   $1 - Subject/title
#   $2 - Message body
#   $3 - Priority (low, normal, high - optional, defaults to normal)
#   $4 - Attachment file path (optional)
# Returns: 0 if any method succeeds, 1 if all fail
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-normal}"
    local attachment="${4:-}"
    local success=false
    
    # Add priority emoji based on level
    local emoji=""
    case "$priority" in
        high)
            emoji="🔴 "
            ;;
        normal)
            emoji="🟡 "
            ;;
        low)
            emoji="🟢 "
            ;;
    esac
    
    # Try Slack first if configured
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        if send_slack_notification "${emoji}${subject}\n${message}"; then
            success=true
        fi
    fi
    
    # Try email if configured
    if [[ -n "${EMAIL_RECIPIENT:-}" ]]; then
        if send_email_notification "${emoji}${subject}" "$message" "" "$attachment"; then
            success=true
        fi
    fi
    
    # Try Teams if configured
    if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
        if command_exists curl; then
            local teams_payload="{\"title\":\"${emoji}${subject}\",\"text\":\"$message\"}"
            if curl -s -H "Content-Type: application/json" -d "$teams_payload" "${TEAMS_WEBHOOK_URL}" -o /dev/null; then
                log "Teams notification sent: $subject" "INFO"
                success=true
            fi
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        return 0
    else
        warn "No notification methods succeeded or were configured"
        return 1
    fi
}

#######################################
# STRING OPERATIONS
#######################################

# Generate a random string
# Arguments:
#   $1 - Length (optional - defaults to 16)
#   $2 - Character set (optional - defaults to alnum)
# Returns: Random string
generate_random_string() {
    local length="${1:-16}"
    local char_set="${2:-alnum}"
    local result
    
    # Validate length is a number
    if ! is_number "$length"; then
        log "Invalid length parameter: $length" "ERROR"
        return 1
    fi
    
    case "$char_set" in
        alnum)
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length")
            ;;
        alpha)
            result=$(LC_ALL=C tr -dc 'a-zA-Z' < /dev/urandom | head -c "$length")
            ;;
        hex)
            result=$(LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c "$length")
            ;;
        secure)
            # Complex password with special chars
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9!@#$%^&*()_+?><~' < /dev/urandom | head -c "$length")
            ;;
        *)
            # Custom character set
            result=$(LC_ALL=C tr -dc "$char_set" < /dev/urandom | head -c "$length")
            ;;
    esac
    
    echo "$result"
}

# URL encode a string
# Arguments:
#   $1 - String to encode
# Returns: URL-encoded string
url_encode() {
    local string="$1"
    local encoded=""
    local i
    
    for (( i=0; i<${#string}; i++ )); do
        local c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) printf -v encoded '%s%%%02X' "$encoded" "'$c" ;;
        esac
    done
    
    echo "$encoded"
}

# Parse JSON string to extract a value
# Arguments:
#   $1 - JSON string
#   $2 - Key path (e.g., ".user.name" or ".users[0].email")
# Returns: Value at key path or empty string
parse_json() {
    local json="$1"
    local key_path="$2"
    local result=""
    
    if command_exists jq; then
        result=$(echo "$json" | jq -r "$key_path" 2>/dev/null)
        if [[ "$result" != "null" ]]; then
            echo "$result"
        fi
    else
        warn "jq not available for proper JSON parsing"
        
        # Simple fallback for very basic JSON (not recommended)
        # This will not work with nested objects or arrays
        if [[ "$key_path" =~ ^\. ]]; then
            # Remove leading dot
            key_path="${key_path:1}"
        fi
        
        result=$(echo "$json" | grep -o "\"$key_path\":\"[^\"]*\"" | cut -d'"' -f4)
        echo "$result"
    fi
}

# Parse INI file section
# Arguments:
#   $1 - File path
#   $2 - Section name
#   $3 - Key (optional - if provided returns just this key's value)
# Returns: All key=value pairs in section or specific key value
parse_ini_section() {
    local file="$1"
    local section="$2"
    local key="${3:-}"
    
    if [[ ! -f "$file" ]]; then
        warn "INI file not found: $file"
        return 1
    fi
    
    local section_content
    section_content=$(sed -n "/^\[$section\]/,/^\[/p" "$file" | grep -v "^\[")
    
    if [[ -n "$key" ]]; then
        echo "$section_content" | grep "^$key=" | cut -d= -f2-
    else
        echo "$section_content"
    fi
}

# Convert YAML to JSON
# Arguments:
#   $1 - YAML file path
#   $2 - Output JSON file path (optional)
# Returns: JSON string if output file not provided
yaml_to_json() {
    local yaml_file="$1"
    local json_file="${2:-}"
    
    if [[ ! -f "$yaml_file" ]]; then
        log "YAML file not found: $yaml_file" "ERROR"
        return 1
    fi
    
    if command_exists python3; then
        if [[ -n "$json_file" ]]; then
            python3 -c "import yaml, json, sys; json.dump(yaml.safe_load(open('$yaml_file')), open('$json_file', 'w'), indent=2)" 2>/dev/null
            return $?
        else
            python3 -c "import yaml, json, sys; print(json.dumps(yaml.safe_load(open('$yaml_file')), indent=2))" 2>/dev/null
            return $?
        fi
    elif command_exists python; then
        if [[ -n "$json_file" ]]; then
            python -c "import yaml, json, sys; json.dump(yaml.safe_load(open('$yaml_file')), open('$json_file', 'w'), indent=2)" 2>/dev/null
            return $?
        else
            python -c "import yaml, json, sys; print(json.dumps(yaml.safe_load(open('$yaml_file')), indent=2))" 2>/dev/null
            return $?
        fi
    elif command_exists yq; then
        if [[ -n "$json_file" ]]; then
            yq eval -j "$yaml_file" > "$json_file" 2>/dev/null
            return $?
        else
            yq eval -j "$yaml_file" 2>/dev/null
            return $?
        fi
    else
        log "No YAML parsing tools available (python with yaml module or yq)" "ERROR"
        return 1
    fi
}

# Format JSON string
# Arguments:
#   $1 - JSON string or file
#   $2 - Indent level (optional, defaults to 2)
# Returns: Formatted JSON
format_json() {
    local json="$1"
    local indent="${2:-2}"
    
    # Check if input is a file
    if [[ -f "$json" ]]; then
        json=$(cat "$json")
    fi
    
    if command_exists jq; then
        echo "$json" | jq --indent "$indent" '.'
    elif command_exists python3; then
        echo "$json" | python3 -m json.tool --indent "$indent"
    elif command_exists python; then
        echo "$json" | python -m json.tool
    else
        # If no formatting tools are available, return the original JSON
        echo "$json"
    fi
}

#######################################
# DATABASE UTILITIES
#######################################

# Check PostgreSQL connection
# Arguments:
#   $1 - Host
#   $2 - Port (optional - defaults to 5432)
#   $3 - Database (optional - defaults to postgres)
#   $4 - User (optional - defaults to postgres)
#   $5 - Password (optional)
# Returns: 0 if connection successful, 1 if not
check_postgres_connection() {
    local host="$1"
    local port="${2:-5432}"
    local db="${3:-postgres}"
    local user="${4:-postgres}"
    local password="${5:-}"
    local connection_string="host=$host port=$port dbname=$db user=$user"
    
    # Check if psql command exists
    if ! command_exists psql; then
        log "PostgreSQL client (psql) not installed" "ERROR"
        return 1
    fi
    
    # Build command with proper password handling
    local pg_cmd="psql \"$connection_string\" -t -c \"SELECT 1;\""
    
    if [[ -n "$password" ]]; then
        # Use environment variable for password
        PGPASSWORD="$password" eval "$pg_cmd" &>/dev/null
    else
        # Try without password (might use .pgpass or peer auth)
        eval "$pg_cmd" &>/dev/null
    fi
    
    local result=$?
    
    if [[ $result -eq 0 ]]; then
        log "Successfully connected to PostgreSQL at $host:$port/$db as $user" "DEBUG"
    else
        log "Failed to connect to PostgreSQL at $host:$port/$db as $user" "DEBUG"
    fi
    
    return $result
}

# Check MySQL/MariaDB connection
# Arguments:
#   $1 - Host
#   $2 - Port (optional - defaults to 3306)
#   $3 - Database (optional)
#   $4 - User (optional - defaults to root)
#   $5 - Password (optional)
# Returns: 0 if connection successful, 1 if not
check_mysql_connection() {
    local host="$1"
    local port="${2:-3306}"
    local db="${3:-}"
    local user="${4:-root}"
    local password="${5:-}"
    local mysql_opts="-h $host -P $port -u $user --connect-timeout=10"
    
    # Check if mysql command exists
    if ! command_exists mysql; then
        log "MySQL client not installed" "ERROR"
        return 1
    fi
    
    if [[ -n "$db" ]]; then
        mysql_opts="$mysql_opts -D $db"
    fi
    
    local mysql_cmd="mysql $mysql_opts -e 'SELECT 1;'"
    
    if [[ -n "$password" ]]; then
        mysql_opts="$mysql_opts -p$(printf "%q" "$password")"
        mysql_cmd="mysql $mysql_opts -e 'SELECT 1;'"
    fi
    
    eval "$mysql_cmd" &>/dev/null
    local result=$?
    
    if [[ $result -eq 0 ]]; then
        log "Successfully connected to MySQL at $host:$port${db:+/$db} as $user" "DEBUG"
    else
        log "Failed to connect to MySQL at $host:$port${db:+/$db} as $user" "DEBUG"
    fi
    
    return $result
}

# Execute SQL query on PostgreSQL database
# Arguments:
#   $1 - Query to execute
#   $2 - Host
#   $3 - Database
#   $4 - User
#   $5 - Port (optional - defaults to 5432)
#   $6 - Password (optional)
# Returns: Query result or error message
pg_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-5432}"
    local password="${6:-}"
    local connection_string="host=$host port=$port dbname=$db user=$user"
    
    if ! command_exists psql; then
        echo "ERROR: PostgreSQL client (psql) not installed"
        return 1
    fi
    
    local temp_file=$(get_temp_file "pg_result")
    
    if [[ -n "$password" ]]; then
        PGPASSWORD="$password" psql "$connection_string" -t -c "$query" > "$temp_file" 2>&1
    else
        psql "$connection_string" -t -c "$query" > "$temp_file" 2>&1
    fi
    
    local result=$?
    local output=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi
    
    echo "$output" | sed 's/^ *//' | sed 's/ *$//'
    return 0
}

# Execute SQL query on MySQL database
# Arguments:
#   $1 - Query to execute
#   $2 - Host
#   $3 - Database
#   $4 - User
#   $5 - Port (optional - defaults to 3306)
#   $6 - Password (optional)
# Returns: Query result or error message
mysql_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-3306}"
    local password="${6:-}"
    local mysql_opts="-h $host -P $port -u $user"
    
    if [[ -n "$db" ]]; then
        mysql_opts="$mysql_opts -D $db"
    fi
    
    if ! command_exists mysql; then
        echo "ERROR: MySQL client not installed"
        return 1
    fi
    
    local temp_file=$(get_temp_file "mysql_result")
    
    if [[ -n "$password" ]]; then
        MYSQL_PWD="$password" mysql $mysql_opts -N -e "$query" > "$temp_file" 2>&1
    else
        mysql $mysql_opts -N -e "$query" > "$temp_file" 2>&1
    fi
    
    local result=$?
    local output=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi
    
    echo "$output"
    return 0
}

#######################################
# CLOUD PROVIDER UTILITIES
#######################################

# Check AWS CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_aws_auth() {
    if ! command_exists aws; then
        warn "AWS CLI not installed"
        return 1
    fi
    
    # Attempt to get caller identity
    if aws sts get-caller-identity &>/dev/null; then
        local identity=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
        log "AWS authenticated as: $identity" "DEBUG"
        return 0
    else
        warn "AWS CLI not authenticated"
        return 1
    fi
}

# Check GCP CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_gcp_auth() {
    if ! command_exists gcloud; then
        warn "GCP CLI (gcloud) not installed"
        return 1
    fi
    
    # Check if user is authenticated
    local account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [[ -n "$account" ]]; then
        log "GCP authenticated as: $account" "DEBUG"
        return 0
    else
        warn "GCP CLI not authenticated"
        return 1
    fi
}

# Check Azure CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_azure_auth() {
    if ! command_exists az; then
        warn "Azure CLI not installed"
        return 1
    fi
    
    # Check if user is logged in
    if az account show &>/dev/null; then
        local account=$(az account show --query 'user.name' -o tsv 2>/dev/null)
        log "Azure authenticated as: $account" "DEBUG"
        return 0
    else
        warn "Azure CLI not authenticated"
        return 1
    fi
}

# Get AWS instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance-id, local-hostname)
# Returns: Metadata value
get_aws_metadata() {
    local metadata_key="$1"
    local result
    
    if command_exists curl && curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        result=$(curl -s "http://169.254.169.254/latest/meta-data/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve AWS instance metadata"
        return 1
    fi
}

# Get GCP instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance/id, instance/zone)
# Returns: Metadata value
get_gcp_metadata() {
    local metadata_key="$1"
    local result
    
    if command_exists curl && curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
        result=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve GCP instance metadata"
        return 1
    fi
}

# Detect cloud provider
# Returns: Provider name (aws, gcp, azure, unknown)
detect_cloud_provider() {
    if command_exists curl; then
        # Check for AWS
        if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
            echo "aws"
            return 0
        fi
        
        # Check for GCP
        if curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
            echo "gcp"
            return 0
        fi
        
        # Check for Azure
        if curl -s --connect-timeout 2 http://169.254.169.254/metadata/instance?api-version=2020-09-01 -H "Metadata: true" &>/dev/null; then
            echo "azure"
            return 0
        fi
    fi
    
    # Check for provider-specific files
    if [[ -f /sys/hypervisor/uuid ]] && [[ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]]; then
        echo "aws"
        return 0
    fi
    
    if [[ -f /sys/class/dmi/id/product_name ]] && grep -q "Google Compute Engine" /sys/class/dmi/id/product_name; then
        echo "gcp"
        return 0
    fi
    
    if [[ -f /sys/class/dmi/id/chassis_asset_tag ]] && grep -q "7783-7084-3265-9085-8269-3286-77" /sys/class/dmi/id/chassis_asset_tag; then
        echo "azure"
        return 0
    fi
    
    echo "unknown"
    return 1
}

#######################################
# HEALTH CHECK UTILITIES
#######################################

# Check if a service is running
# Arguments:
#   $1 - Service name
# Returns: 0 if running, 1 if not
is_service_running() {
    local service="$1"
    
    if command_exists systemctl; then
        if systemctl is-active --quiet "$service"; then
            return 0
        fi
    elif command_exists service; then
        if service "$service" status &>/dev/null; then
            return 0
        fi
    elif command_exists launchctl; then
        # macOS service check
        if launchctl list | grep -q "$service"; then
            return 0
        fi
    else
        warn "Cannot check service status - no service manager found"
        return 2
    fi
    
    return 1
}

# Check disk usage and warn if above threshold
# Arguments:
#   $1 - Path to check
#   $2 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above
check_disk_usage_threshold() {
    local path="${1:-/}"
    local threshold="${2:-90}"
    
    local usage
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        usage=$(df -h "$path" | awk 'NR==2 {sub(/%/, "", $5); print $5}')
    else
        # Linux
        usage=$(df -h "$path" | awk 'NR==2 {print $5}' | tr -d '%')
    fi
    
    if (( usage >= threshold )); then
        warn "Disk usage for $path is at ${usage}%, which exceeds the ${threshold}% threshold"
        return 1
    fi
    
    return 0
}

# Check if a process is running by name
# Arguments:
#   $1 - Process name to check
# Returns: 0 if running, 1 if not
is_process_running() {
    local process_name="$1"
    
    if command_exists pgrep; then
        pgrep -f "$process_name" &>/dev/null
        return $?
    elif command_exists ps; then
        ps -ef | grep -v grep | grep -q "$process_name"
        return $?
    else
        warn "Cannot check process status - neither pgrep nor ps commands found"
        return 2
    fi
}

# Check service health via HTTP endpoint
# Arguments:
#   $1 - URL to health endpoint
#   $2 - Expected status code (optional - defaults to 200)
#   $3 - Timeout in seconds (optional - defaults to 5)
# Returns: 0 if healthy, 1 if not
check_http_health() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-5}"
    
    if ! is_valid_url "$url"; then
        log "Invalid health check URL: $url" "ERROR"
        return 1
    fi
    
    local status_code
    
    if command_exists curl; then
        status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url")
    elif command_exists wget; then
        status_code=$(wget --timeout="$timeout" --server-response --spider "$url" 2>&1 | grep "HTTP/" | awk '{print $2}' | tail -1)
    else
        log "Neither curl nor wget available to check health endpoint" "ERROR"
        return 2
    fi
    
    if [[ "$status_code" == "$expected_status" ]]; then
        return 0
    else
        log "Health check failed: $url returned $status_code (expected $expected_status)" "WARNING"
        return 1
    fi
}

# Check CPU usage and warn if above threshold
# Arguments:
#   $1 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above
check_cpu_usage_threshold() {
    local threshold="${1:-90}"
    local cpu_usage
    
    if command_exists top; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            cpu_usage=$(top -l 1 | grep "CPU usage" | awk '{print $3 + $5}' | tr -d '%')
        else
            # Linux
            cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | tr -d '%')
        fi
    elif command_exists mpstat; then
        # Using mpstat
        cpu_usage=$(mpstat 1 1 | awk '/Average:/ {print 100 - $NF}')
    elif [[ -f /proc/stat ]]; then
        # Direct from proc filesystem
        local stats1=$(grep '^cpu ' /proc/stat)
        sleep 1
        local stats2=$(grep '^cpu ' /proc/stat)
        
        # Extract values
        local user1=$(echo "$stats1" | awk '{print $2}')
        local nice1=$(echo "$stats1" | awk '{print $3}')
        local system1=$(echo "$stats1" | awk '{print $4}')
        local idle1=$(echo "$stats1" | awk '{print $5}')
        
        local user2=$(echo "$stats2" | awk '{print $2}')
        local nice2=$(echo "$stats2" | awk '{print $3}')
        local system2=$(echo "$stats2" | awk '{print $4}')
        local idle2=$(echo "$stats2" | awk '{print $5}')
        
        # Calculate deltas
        local total1=$((user1 + nice1 + system1 + idle1))
        local total2=$((user2 + nice2 + system2 + idle2))
        local total_delta=$((total2 - total#!/bin/bash
# Common Utility Functions for Cloud Infrastructure Platform
# Usage: source /scripts/utils/common_functions.sh in your scripts
# 
# This file contains shared utility functions for use across multiple scripts,
# including logging, environment management, error handling, validation,
# file operations, and notification utilities.

# Ensure script fails on error when sourced with 'set -e'
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    set -o errexit
    set -o pipefail
    set -o nounset
else
    # Script is being sourced, don't override caller's error settings
    :
fi

# Default configuration
DEFAULT_LOG_DIR="/var/log/cloud-platform"
DEFAULT_BACKUP_DIR="/var/backups/cloud-platform"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "${BASH_SOURCE[0]}")")")" && pwd)"
ENV_FILE_DIR="${PROJECT_ROOT}/deployment/environments"
DEFAULT_ENVIRONMENT="production"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

# Text colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Ensure the log directory exists
mkdir -p "$DEFAULT_LOG_DIR"

#######################################
# LOGGING FUNCTIONS
#######################################

# Log a message with timestamp and optional log level
# Arguments:
#   $1 - Message to log
#   $2 - Log level (INFO, WARNING, ERROR, DEBUG) - defaults to INFO
#   $3 - Log file (optional - defaults to stdout)
log() {
    local message="$1"
    local level="${2:-INFO}"
    local log_file="${3:-}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Format based on log level
    case "$level" in
        INFO)
            local colored_level="${GREEN}INFO${NC}"
            ;;
        WARNING)
            local colored_level="${YELLOW}WARNING${NC}"
            ;;
        ERROR)
            local colored_level="${RED}ERROR${NC}"
            ;;
        DEBUG)
            local colored_level="${BLUE}DEBUG${NC}"
            ;;
        *)
            local colored_level="$level"
            ;;
    esac
    
    # Format the log message
    local log_message="[$timestamp] [${colored_level}] $message"
    local plain_message="[$timestamp] [$level] $message"
    
    # Output to console if not in quiet mode
    if [[ "${QUIET:-false}" != "true" ]]; then
        echo -e "$log_message"
    fi
    
    # Output to log file if specified
    if [[ -n "$log_file" ]]; then
        echo "$plain_message" >> "$log_file"
    fi
}

# Log an error message and exit
# Arguments:
#   $1 - Error message
#   $2 - Exit code (optional, defaults to 1)
#   $3 - Log file (optional)
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    local log_file="${3:-}"
    
    log "$message" "ERROR" "$log_file"
    exit "$exit_code"
}

# Log a warning message
# Arguments:
#   $1 - Warning message
#   $2 - Log file (optional)
warn() {
    local message="$1"
    local log_file="${2:-}"
    
    log "$message" "WARNING" "$log_file"
}

# Log a debug message (only when DEBUG=true)
# Arguments:
#   $1 - Debug message
#   $2 - Log file (optional)
debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        local message="$1"
        local log_file="${2:-}"
        
        log "$message" "DEBUG" "$log_file"
    fi
}

# Log an important message (highlighted)
# Arguments:
#   $1 - Important message
#   $2 - Log file (optional)
important() {
    local message="$1"
    local log_file="${2:-}"
    
    log "${BOLD}${message}${NC}" "INFO" "$log_file"
}

# Log to the disaster recovery events log
# Arguments:
#   $1 - Event type
#   $2 - Environment
#   $3 - Region (optional)
#   $4 - Status (optional)
#   $5 - Details (optional)
log_dr_event() {
    local event_type="$1"
    local environment="$2"
    local region="${3:-all}"
    local status="${4:-COMPLETED}"
    local details="${5:-}"
    local dr_log="${DEFAULT_LOG_DIR}/dr-events.log"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname -f 2>/dev/null || hostname)
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$dr_log")"
    
    # Create log entry
    local log_entry="${timestamp},${event_type},${environment},${region},${status},${hostname}"
    
    # Add details if provided
    if [[ -n "$details" ]]; then
        # Escape commas in details to avoid breaking CSV format
        details="${details//,/;}"
        log_entry="${log_entry},${details}"
    fi
    
    # Append to DR events log
    echo "$log_entry" >> "$dr_log"
    debug "DR event logged: $event_type - $status" "$dr_log"
}

#######################################
# ENVIRONMENT FUNCTIONS
#######################################

# Load environment-specific variables from file
# Arguments:
#   $1 - Environment name (e.g., production, staging)
#   $2 - Custom environment file path (optional)
load_env() {
    local environment="${1:-$DEFAULT_ENVIRONMENT}"
    local custom_env_file="${2:-}"
    local env_file
    
    # Use custom file if provided, otherwise use default location
    if [[ -n "$custom_env_file" && -f "$custom_env_file" ]]; then
        env_file="$custom_env_file"
    else
        env_file="${ENV_FILE_DIR}/${environment}.env"
    fi
    
    # Check if file exists
    if [[ ! -f "$env_file" ]]; then
        warn "Environment file not found: $env_file"
        return 1
    fi
    
    # Source the environment file
    # shellcheck source=/dev/null
    source "$env_file"
    log "Loaded environment configuration from $env_file"
    return 0
}

# Validate if environment is valid
# Arguments:
#   $1 - Environment to validate
#   $2 - Array of valid environments (optional)
validate_environment() {
    local environment="$1"
    shift
    local valid_envs=("${@:-development staging production dr-recovery}")
    
    local valid=false
    for env in "${valid_envs[@]}"; do
        if [[ "$environment" == "$env" ]]; then
            valid=true
            break
        fi
    done
    
    if [[ "$valid" == "false" ]]; then
        log "Invalid environment: $environment" "ERROR"
        log "Valid environments: ${valid_envs[*]}" "ERROR"
        return 1
    fi
    
    return 0
}

# Get the current environment from ENV variable or hostname
# Returns the detected environment
detect_environment() {
    # If ENV is set, use it
    if [[ -n "${ENV:-}" ]]; then
        echo "$ENV"
        return 0
    fi
    
    # Try to detect from hostname
    local hostname=$(hostname -f 2>/dev/null || hostname)
    if [[ "$hostname" =~ (^|[-\.])prod($|[-\.]) || "$hostname" =~ production ]]; then
        echo "production"
    elif [[ "$hostname" =~ (^|[-\.])stg($|[-\.]) || "$hostname" =~ staging ]]; then
        echo "staging"
    elif [[ "$hostname" =~ (^|[-\.])dev($|[-\.]) || "$hostname" =~ development ]]; then
        echo "development"
    elif [[ "$hostname" =~ (^|[-\.])dr($|[-\.]) ]]; then
        echo "dr-recovery"
    elif [[ -f "${ENV_FILE_DIR}/environment_map.txt" ]]; then
        # Try to find in environment mapping file
        grep -i "^$hostname=" "${ENV_FILE_DIR}/environment_map.txt" | cut -d'=' -f2 || echo "$DEFAULT_ENVIRONMENT"
    else
        echo "$DEFAULT_ENVIRONMENT"
    fi
}

#######################################
# VALIDATION FUNCTIONS
#######################################

# Check if a command exists
# Arguments:
#   $1 - Command to check
# Returns: 0 if exists, 1 if not
command_exists() {
    command -v "$1" &>/dev/null
    return $?
}

# Check if a file exists and is readable
# Arguments:
#   $1 - File path
#   $2 - Error message (optional)
# Returns: 0 if exists, 1 if not
file_exists() {
    local file="$1"
    local error_msg="${2:-File does not exist or is not readable: $file}"
    
    if [[ ! -r "$file" ]]; then
        log "$error_msg" "ERROR"
        return 1
    fi
    
    return 0
}

# Validate if a string is a valid IP address
# Arguments:
#   $1 - String to validate
#   $2 - Type (4 for IPv4, 6 for IPv6, both if not specified)
# Returns: 0 if valid, 1 if not
is_valid_ip() {
    local ip="$1"
    local type="${2:-both}"
    
    case "$type" in
        4|ipv4)
            # IPv4 validation
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local IFS='.'
                read -ra ip_array <<< "$ip"
                
                for octet in "${ip_array[@]}"; do
                    if (( octet < 0 || octet > 255 )); then
                        return 1
                    fi
                done
                
                return 0
            fi
            return 1
            ;;
        6|ipv6)
            # IPv6 validation (simplified)
            if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
                return 0
            fi
            return 1
            ;;
        both)
            if is_valid_ip "$ip" 4 || is_valid_ip "$ip" 6; then
                return 0
            else
                return 1
            fi
            ;;
        *)
            log "Invalid IP type specified: $type. Use 4, 6, or both" "ERROR"
            return 1
            ;;
    esac
}

# Check if a value is a number
# Arguments:
#   $1 - Value to check
#   $2 - Allow floating point (true/false, defaults to false)
# Returns: 0 if numeric, 1 if not
is_number() {
    local value="$1"
    local allow_float="${2:-false}"
    
    if [[ "$allow_float" == "true" ]]; then
        [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]
        return $?
    else
        [[ "$value" =~ ^[0-9]+$ ]]
        return $?
    fi
}

# Validate required parameters
# Arguments:
#   Variable number of parameter names to check
# Returns: 0 if all parameters exist, 1 if any are missing
validate_required_params() {
    local missing=0
    
    for param in "$@"; do
        if [[ -z "${!param:-}" ]]; then
            log "Required parameter missing: $param" "ERROR"
            missing=$((missing + 1))
        fi
    done
    
    if (( missing > 0 )); then
        return 1
    fi
    
    return 0
}

# Validate a URL format
# Arguments:
#   $1 - URL to validate
# Returns: 0 if valid, 1 if not
is_valid_url() {
    local url="$1"
    
    # Basic URL validation - requires http:// or https:// prefix
    if [[ "$url" =~ ^https?:// ]]; then
        return 0
    fi
    return 1
}

# Validate email format
# Arguments:
#   $1 - Email to validate
# Returns: 0 if valid, 1 if not
is_valid_email() {
    local email="$1"
    
    # Basic email validation
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

#######################################
# FILE OPERATIONS
#######################################

# Create a backup of a file
# Arguments:
#   $1 - File to backup
#   $2 - Backup directory (optional - defaults to DEFAULT_BACKUP_DIR)
# Returns: Path to backup file
backup_file() {
    local file="$1"
    local backup_dir="${2:-$DEFAULT_BACKUP_DIR}"
    local filename=$(basename "$file")
    local backup_file="${backup_dir}/${filename}.${TIMESTAMP}.bak"
    
    # Ensure backup directory exists
    mkdir -p "$backup_dir"
    
    # Check if source file exists
    if [[ ! -f "$file" ]]; then
        warn "Cannot backup file, source does not exist: $file"
        return 1
    fi
    
    # Create backup
    cp -p "$file" "$backup_file" || {
        warn "Failed to create backup of $file"
        return 1
    }
    
    log "Backed up $file to $backup_file" "INFO"
    
    echo "$backup_file"
}

# Create directory if it doesn't exist
# Arguments:
#   $1 - Directory path
#   $2 - Permissions (optional - defaults to 755)
# Returns: 0 if created or already exists, 1 on failure
ensure_directory() {
    local dir="$1"
    local perms="${2:-755}"
    
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            log "Failed to create directory: $dir" "ERROR"
            return 1
        }
        chmod "$perms" "$dir" || {
            log "Failed to set permissions $perms on directory: $dir" "ERROR"
            return 1
        }
        log "Created directory: $dir with permissions $perms" "INFO"
    fi
    
    return 0
}

# Safely write content to a file with error handling
# Arguments:
#   $1 - Content to write
#   $2 - Output file
#   $3 - Create backup (true/false, defaults to true)
#   $4 - File permissions (optional, defaults to 644)
# Returns: 0 on success, 1 on failure
safe_write_file() {
    local content="$1"
    local output_file="$2"
    local create_backup="${3:-true}"
    local perms="${4:-644}"
    local temp_file
    
    # Create parent directory if it doesn't exist
    ensure_directory "$(dirname "$output_file")" || return 1
    
    # Backup existing file if requested
    if [[ "$create_backup" == "true" && -f "$output_file" ]]; then
        backup_file "$output_file" >/dev/null || {
            log "Failed to back up existing file: $output_file" "WARNING"
        }
    fi
    
    # Write to temporary file first to prevent partial writes
    temp_file=$(mktemp) || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }
    
    echo "$content" > "$temp_file" || {
        log "Failed to write content to temporary file" "ERROR"
        rm -f "$temp_file"
        return 1
    }
    
    # Set permissions on temporary file before moving
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }
    
    # Move temporary file to destination
    mv "$temp_file" "$output_file" || {
        log "Failed to write to $output_file" "ERROR"
        rm -f "$temp_file"
        return 1
    }
    
    log "Successfully wrote to $output_file" "INFO"
    return 0
}

# Get file age in seconds
# Arguments:
#   $1 - File path
# Returns: File age in seconds or -1 if file not found
file_age() {
    local file="$1"
    local file_time
    local current_time
    
    if [[ ! -f "$file" ]]; then
        echo "-1"
        return 1
    fi
    
    if command_exists stat; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS version
            file_time=$(stat -f %m "$file")
        else
            # Linux version
            file_time=$(stat -c %Y "$file")
        fi
    else
        # Fallback method using ls
        file_time=$(ls -l --time-style=+%s "$file" 2>/dev/null | awk '{print $6}')
        if [[ -z "$file_time" ]]; then
            echo "-1"
            return 1
        fi
    fi
    
    current_time=$(date +%s)
    echo $((current_time - file_time))
}

# Find files newer than specified time
# Arguments:
#   $1 - Directory to search
#   $2 - Time in minutes
#   $3 - File pattern (optional)
# Returns: List of files
find_newer_files() {
    local dir="$1"
    local minutes="$2"
    local pattern="${3:-*}"
    
    if [[ ! -d "$dir" ]]; then
        warn "Directory does not exist: $dir"
        return 1
    fi
    
    find "$dir" -type f -name "$pattern" -mmin -"$minutes"
}

# Calculate checksum of a file
# Arguments:
#   $1 - File path
#   $2 - Algorithm (md5, sha1, sha256, defaults to sha256)
# Returns: Checksum of the file
calculate_checksum() {
    local file="$1"
    local algorithm="${2:-sha256}"
    
    if [[ ! -f "$file" ]]; then
        log "File does not exist: $file" "ERROR"
        return 1
    fi
    
    case "$algorithm" in
        md5)
            if command_exists md5sum; then
                md5sum "$file" | awk '{print $1}'
            elif command_exists md5; then
                md5 -q "$file"
            else
                log "No MD5 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        sha1)
            if command_exists sha1sum; then
                sha1sum "$file" | awk '{print $1}'
            elif command_exists shasum; then
                shasum -a 1 "$file" | awk '{print $1}'
            else
                log "No SHA1 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        sha256)
            if command_exists sha256sum; then
                sha256sum "$file" | awk '{print $1}'
            elif command_exists shasum; then
                shasum -a 256 "$file" | awk '{print $1}'
            else
                log "No SHA256 checksum tool available" "ERROR"
                return 1
            fi
            ;;
        *)
            log "Unsupported checksum algorithm: $algorithm" "ERROR"
            return 1
            ;;
    esac
}

#######################################
# SYSTEM OPERATIONS
#######################################

# Check if running as root
# Returns: 0 if root, 1 if not
is_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    fi
    return 0
}

# Get system information
# Returns: JSON string with system information
get_system_info() {
    local os_name
    local kernel
    local hostname
    local uptime
    local cpu_info
    local total_memory
    
    # Get OS name
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep "PRETTY_NAME" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    else
        os_name=$(uname -s)
    fi
    
    kernel=$(uname -r)
    hostname=$(hostname -f 2>/dev/null || hostname)
    uptime=$(uptime -p 2>/dev/null || uptime)
    
    # Get CPU info
    if [[ -f /proc/cpuinfo ]]; then
        cpu_info=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
        if [[ -z "$cpu_info" ]]; then
            cpu_info="Unknown"
        fi
    else
        cpu_info="Unknown"
    fi
    
    # Get memory info
    if command_exists free; then
        total_memory=$(free -m | grep Mem: | awk '{print $2}')
        total_memory="${total_memory} MB"
    else
        total_memory="Unknown"
    fi
    
    echo "{\"hostname\":\"$hostname\",\"os\":\"$os_name\",\"kernel\":\"$kernel\",\"uptime\":\"$uptime\",\"cpu\":\"$cpu_info\",\"memory\":\"$total_memory\"}"
}

# Check available disk space on a path (in MB)
# Arguments:
#   $1 - Path to check
# Returns: Available disk space in MB
check_disk_space() {
    local path="${1:-/}"
    local available
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS version
        available=$(df -m "$path" | awk 'NR==2 {print $4}')
    else
        # Linux version
        available=$(df -BM "$path" | awk 'NR==2 {print $4}' | tr -d 'M')
    fi
    
    echo "$available"
}

# Check if a port is in use
# Arguments:
#   $1 - Port number
#   $2 - Protocol (tcp, udp, defaults to tcp)
# Returns: 0 if port is in use, 1 if available
is_port_in_use() {
    local port="$1"
    local protocol="${2:-tcp}"
    
    if ! is_number "$port"; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi
    
    if command_exists netstat; then
        netstat -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists ss; then
        ss -tuln | grep -q "$protocol.*:$port " && return 0
    elif command_exists lsof; then
        lsof -i "$protocol:$port" &>/dev/null && return 0
    else
        warn "Neither netstat, ss, nor lsof commands available to check port"
        return 2
    fi
    
    return 1
}

# Generate a temporary file with proper permissions
# Arguments:
#   $1 - File prefix
#   $2 - Permissions (optional - defaults to 600)
# Returns: Path to temporary file
get_temp_file() {
    local prefix="${1:-tmp}"
    local perms="${2:-600}"
    local temp_file
    
    temp_file=$(mktemp "/tmp/${prefix}_XXXXXXXX") || {
        log "Failed to create temporary file" "ERROR"
        return 1
    }
    
    chmod "$perms" "$temp_file" || {
        log "Failed to set permissions on temporary file" "WARNING"
    }
    
    echo "$temp_file"
}

# Execute a command with timeout
# Arguments:
#   $1 - Timeout in seconds
#   $2...$n - Command to execute and its arguments
# Returns: Command exit code or 124 for timeout
execute_with_timeout() {
    local timeout="$1"
    shift
    
    if command_exists timeout; then
        timeout "$timeout" "$@"
        return $?
    else
        # Fallback if timeout command doesn't exist
        local pid
        "$@" &
        pid=$!
        
        # Wait for specified time
        (sleep "$timeout" && kill -9 $pid 2>/dev/null) &
        local watchdog=$!
        
        # Wait for process to complete
        wait $pid 2>/dev/null
        local ret=$?
        
        # Kill the watchdog
        kill -9 $watchdog 2>/dev/null
        
        return $ret
    fi
}

# Get system load average
# Returns: Current 1-minute load average
get_load_average() {
    if [[ -f /proc/loadavg ]]; then
        awk '{print $1}' /proc/loadavg
    elif command_exists uptime; then
        uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' '
    else
        echo "0.0"
        return 1
    fi
}

# Get total and available memory in MB
# Returns: JSON with memory information
get_memory_info() {
    local total_mem
    local free_mem
    local used_mem
    
    if [[ -f /proc/meminfo ]]; then
        # Linux
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
        free_mem=$(grep MemAvailable /proc/meminfo 2>/dev/null || grep MemFree /proc/meminfo | awk '{print int($2/1024)}')
        used_mem=$((total_mem - free_mem))
    elif command_exists free; then
        # Alternative using free command
        total_mem=$(free -m | grep Mem: | awk '{print $2}')
        free_mem=$(free -m | grep Mem: | awk '{print $7}')
        used_mem=$((total_mem - free_mem))
    elif command_exists vm_stat; then
        # macOS
        local page_size=$(pagesize 2>/dev/null || echo 4096)
        local pages_free=$(vm_stat | grep 'Pages free' | awk '{print $3}' | tr -d '.')
        local pages_active=$(vm_stat | grep 'Pages active' | awk '{print $3}' | tr -d '.')
        local pages_inactive=$(vm_stat | grep 'Pages inactive' | awk '{print $3}' | tr -d '.')
        local pages_speculative=$(vm_stat | grep 'Pages speculative' | awk '{print $3}' | tr -d '.')
        local pages_wired=$(vm_stat | grep 'Pages wired down' | awk '{print $4}' | tr -d '.')
        
        total_mem=$(( (pages_free + pages_active + pages_inactive + pages_speculative + pages_wired) * page_size / 1024 / 1024 ))
        free_mem=$(( (pages_free + pages_inactive) * page_size / 1024 / 1024 ))
        used_mem=$(( (pages_active + pages_wired) * page_size / 1024 / 1024 ))
    else
        # Fallback
        total_mem=0
        free_mem=0
        used_mem=0
    fi
    
    echo "{\"total_mb\":$total_mem,\"used_mb\":$used_mem,\"free_mb\":$free_mem}"
}

#######################################
# NETWORK OPERATIONS
#######################################

# Check if URL is reachable
# Arguments:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional - defaults to 10)
#   $3 - Additional options for curl/wget (optional)
# Returns: 0 if reachable, 1 if not
is_url_reachable() {
    local url="$1"
    local timeout="${2:-10}"
    local options="${3:-}"
    
    if ! is_valid_url "$url"; then
        log "Invalid URL format: $url" "ERROR"
        return 1
    fi
    
    if command_exists curl; then
        if curl --output /dev/null --silent --head --fail --max-time "$timeout" $options "$url"; then
            return 0
        fi
    elif command_exists wget; then
        if wget --quiet --spider --timeout="$timeout" $options "$url"; then
            return 0
        fi
    else
        log "Neither curl nor wget available to check URL" "WARNING"
        return 2
    fi
    
    return 1
}

# Get public IP address
# Returns: Public IP address or error message
get_public_ip() {
    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://icanhazip.com"
    )
    
    for service in "${services[@]}"; do
        if command_exists curl; then
            ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
        elif command_exists wget; then
            ip=$(wget -qO- --timeout=5 "$service" 2>/dev/null)
        else
            echo "ERROR: Neither curl nor wget are available"
            return 1
        fi
        
        # Check if we got a valid IP
        if [[ -n "$ip" && ( $(is_valid_ip "$ip" 4) || $(is_valid_ip "$ip" 6) ) ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    echo "ERROR: Could not determine public IP address"
    return 1
}

# Check if host is reachable via ping
# Arguments:
#   $1 - Host to ping
#   $2 - Number of packets (optional - defaults to 1)
#   $3 - Timeout in seconds (optional - defaults to 2)
# Returns: 0 if reachable, 1 if not
ping_host() {
    local host="$1"
    local count="${2:-1}"
    local timeout="${3:-2}"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    else
        # Linux
        if ping -c "$count" -W "$timeout" "$host" &>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# Get primary DNS servers
# Returns: List of DNS servers
get_dns_servers() {
    local servers=""
    
    if [[ -f /etc/resolv.conf ]]; then
        servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}')
    fi
    
    # If no servers found, try alternative methods
    if [[ -z "$servers" ]]; then
        if command_exists systemd-resolve; then
            servers=$(systemd-resolve --status | grep 'DNS Servers' | awk '{print $3}')
        elif command_exists scutil && [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            servers=$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u)
        fi
    fi
    
    echo "$servers"
}

# Resolve a hostname to IP address
# Arguments:
#   $1 - Hostname to resolve
#   $2 - Record type (optional, A or AAAA, defaults to A)
# Returns: IP address(es)
resolve_hostname() {
    local hostname="$1"
    local record_type="${2:-A}"
    
    if command_exists dig; then
        dig +short "$record_type" "$hostname" 2>/dev/null
    elif command_exists host; then
        host -t "$record_type" "$hostname" 2>/dev/null | awk '/has address/ {print $4}; /has IPv6/ {print $5}'
    elif command_exists nslookup; then
        nslookup -type="$record_type" "$hostname" 2>/dev/null | awk '/^Address/ && !/#/ {print $2}'
    else
        log "No DNS resolution tools available" "ERROR"
        return 1
    fi
}

#######################################
# NOTIFICATION FUNCTIONS
#######################################

# Send email notification
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Recipient (optional - uses EMAIL_RECIPIENT from env if not provided)
#   $4 - Attachment file (optional)
# Returns: 0 on success, 1 on failure
send_email_notification() {
    local subject="$1"
    local message="$2"
    local recipient="${3:-${EMAIL_RECIPIENT:-}}"
    local attachment="${4:-}"
    
    # Check if recipient is provided
    if [[ -z "$recipient" ]]; then
        warn "No email recipient specified, notification not sent"
        return 1
    fi
    
    # Validate email format
    if ! is_valid_email "$recipient"; then
        warn "Invalid email recipient format: $recipient"
        return 1
    }
    
    # Format subject with hostname for clarity
    local hostname=$(hostname -f 2>/dev/null || hostname)
    subject="[Cloud Platform ${hostname}] $subject"
    
    # Try different mail sending methods
    if command_exists mail; then
        if [[ -n "$attachment" && -f "$attachment" ]]; then
            echo -e "$message" | mail -s "$subject" -a "$attachment" "$recipient"
        else
            echo -e "$message" | mail -s "$subject" "$recipient"
        fi
        log "Email notification sent to $recipient: $subject" "INFO"
        return 0
    elif command_exists sendmail; then
        (
            echo "To: $recipient"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo
            echo -e "$message"
        ) | sendmail -t
        log "Email notification sent to $recipient via sendmail: $subject" "INFO"
        return 0
    elif command_exists aws && [[ -n "${AWS_SES_ENABLED:-}" && "$AWS_SES_ENABLED" == "true" ]]; then
        # AWS SES method
        local ses_region="${AWS_SES_REGION:-us-east-1}"
        local ses_from="${AWS_SES_FROM:-no-reply@example.com}"
        
        aws ses send-email \
            --region "$ses_region" \
            --from "$ses_from" \
            --destination "ToAddresses=$recipient" \
            --message "Subject={Data=$subject},Body={Text={Data=$message}}" \
            &>/dev/null
        
        log "Email notification sent via AWS SES to $recipient: $subject" "INFO"
        return 0
    else
        warn "No email sending method available, cannot send email notification"
        return 1
    fi
}

# Send Slack notification
# Arguments:
#   $1 - Message to send
#   $2 - Webhook URL (optional - uses SLACK_WEBHOOK_URL from env if not provided)
#   $3 - Channel (optional - uses default channel from webhook if not provided)
# Returns: 0 on success, 1 on failure
send_slack_notification() {
    local message="$1"
    local webhook="${2:-${SLACK_WEBHOOK_URL:-}}"
    local channel="${3:-}"
    local hostname=$(hostname -f 2>/dev/null || hostname)
    local environment=$(detect_environment)
    
    # Check if webhook URL is provided
    if [[ -z "$webhook" ]]; then
        warn "No Slack webhook URL specified, notification not sent"
        return 1
    fi
    
    # Check if curl is available
    if ! command_exists curl; then
        warn "curl command not available, cannot send Slack notification"
        return 1
    fi
    
    # Format the JSON payload
    local payload
    if [[ -n "$channel" ]]; then
        payload="{\"text\":\"*[$environment - $hostname]* $message\", \"channel\":\"$channel\"}"
    else
        payload="{\"text\":\"*[$environment - $hostname]* $message\"}"
    fi
    
    # Send the notification
    if curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$webhook" -o /dev/null; then
        log "Slack notification sent: $message" "INFO"
        return 0
    else
        warn "Failed to send Slack notification"
        return 1
    fi
}

# Send notification (tries multiple methods)
# Arguments:
#   $1 - Subject/title
#   $2 - Message body
#   $3 - Priority (low, normal, high - optional, defaults to normal)
#   $4 - Attachment file path (optional)
# Returns: 0 if any method succeeds, 1 if all fail
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-normal}"
    local attachment="${4:-}"
    local success=false
    
    # Add priority emoji based on level
    local emoji=""
    case "$priority" in
        high)
            emoji="🔴 "
            ;;
        normal)
            emoji="🟡 "
            ;;
        low)
            emoji="🟢 "
            ;;
    esac
    
    # Try Slack first if configured
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        if send_slack_notification "${emoji}${subject}\n${message}"; then
            success=true
        fi
    fi
    
    # Try email if configured
    if [[ -n "${EMAIL_RECIPIENT:-}" ]]; then
        if send_email_notification "${emoji}${subject}" "$message" "" "$attachment"; then
            success=true
        fi
    fi
    
    # Try Teams if configured
    if [[ -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
        if command_exists curl; then
            local teams_payload="{\"title\":\"${emoji}${subject}\",\"text\":\"$message\"}"
            if curl -s -H "Content-Type: application/json" -d "$teams_payload" "${TEAMS_WEBHOOK_URL}" -o /dev/null; then
                log "Teams notification sent: $subject" "INFO"
                success=true
            fi
        fi
    fi
    
    if [[ "$success" == "true" ]]; then
        return 0
    else
        warn "No notification methods succeeded or were configured"
        return 1
    fi
}

#######################################
# STRING OPERATIONS
#######################################

# Generate a random string
# Arguments:
#   $1 - Length (optional - defaults to 16)
#   $2 - Character set (optional - defaults to alnum)
# Returns: Random string
generate_random_string() {
    local length="${1:-16}"
    local char_set="${2:-alnum}"
    local result
    
    # Validate length is a number
    if ! is_number "$length"; then
        log "Invalid length parameter: $length" "ERROR"
        return 1
    fi
    
    case "$char_set" in
        alnum)
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length")
            ;;
        alpha)
            result=$(LC_ALL=C tr -dc 'a-zA-Z' < /dev/urandom | head -c "$length")
            ;;
        hex)
            result=$(LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c "$length")
            ;;
        secure)
            # Complex password with special chars
            result=$(LC_ALL=C tr -dc 'a-zA-Z0-9!@#$%^&*()_+?><~' < /dev/urandom | head -c "$length")
            ;;
        *)
            # Custom character set
            result=$(LC_ALL=C tr -dc "$char_set" < /dev/urandom | head -c "$length")
            ;;
    esac
    
    echo "$result"
}

# URL encode a string
# Arguments:
#   $1 - String to encode
# Returns: URL-encoded string
url_encode() {
    local string="$1"
    local encoded=""
    local i
    
    for (( i=0; i<${#string}; i++ )); do
        local c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) printf -v encoded '%s%%%02X' "$encoded" "'$c" ;;
        esac
    done
    
    echo "$encoded"
}

# Parse JSON string to extract a value
# Arguments:
#   $1 - JSON string
#   $2 - Key path (e.g., ".user.name" or ".users[0].email")
# Returns: Value at key path or empty string
parse_json() {
    local json="$1"
    local key_path="$2"
    local result=""
    
    if command_exists jq; then
        result=$(echo "$json" | jq -r "$key_path" 2>/dev/null)
        if [[ "$result" != "null" ]]; then
            echo "$result"
        fi
    else
        warn "jq not available for proper JSON parsing"
        
        # Simple fallback for very basic JSON (not recommended)
        # This will not work with nested objects or arrays
        if [[ "$key_path" =~ ^\. ]]; then
            # Remove leading dot
            key_path="${key_path:1}"
        fi
        
        result=$(echo "$json" | grep -o "\"$key_path\":\"[^\"]*\"" | cut -d'"' -f4)
        echo "$result"
    fi
}

# Parse INI file section
# Arguments:
#   $1 - File path
#   $2 - Section name
#   $3 - Key (optional - if provided returns just this key's value)
# Returns: All key=value pairs in section or specific key value
parse_ini_section() {
    local file="$1"
    local section="$2"
    local key="${3:-}"
    
    if [[ ! -f "$file" ]]; then
        warn "INI file not found: $file"
        return 1
    fi
    
    local section_content
    section_content=$(sed -n "/^\[$section\]/,/^\[/p" "$file" | grep -v "^\[")
    
    if [[ -n "$key" ]]; then
        echo "$section_content" | grep "^$key=" | cut -d= -f2-
    else
        echo "$section_content"
    fi
}

# Convert YAML to JSON
# Arguments:
#   $1 - YAML file path
#   $2 - Output JSON file path (optional)
# Returns: JSON string if output file not provided
yaml_to_json() {
    local yaml_file="$1"
    local json_file="${2:-}"
    
    if [[ ! -f "$yaml_file" ]]; then
        log "YAML file not found: $yaml_file" "ERROR"
        return 1
    fi
    
    if command_exists python3; then
        if [[ -n "$json_file" ]]; then
            python3 -c "import yaml, json, sys; json.dump(yaml.safe_load(open('$yaml_file')), open('$json_file', 'w'), indent=2)" 2>/dev/null
            return $?
        else
            python3 -c "import yaml, json, sys; print(json.dumps(yaml.safe_load(open('$yaml_file')), indent=2))" 2>/dev/null
            return $?
        fi
    elif command_exists python; then
        if [[ -n "$json_file" ]]; then
            python -c "import yaml, json, sys; json.dump(yaml.safe_load(open('$yaml_file')), open('$json_file', 'w'), indent=2)" 2>/dev/null
            return $?
        else
            python -c "import yaml, json, sys; print(json.dumps(yaml.safe_load(open('$yaml_file')), indent=2))" 2>/dev/null
            return $?
        fi
    elif command_exists yq; then
        if [[ -n "$json_file" ]]; then
            yq eval -j "$yaml_file" > "$json_file" 2>/dev/null
            return $?
        else
            yq eval -j "$yaml_file" 2>/dev/null
            return $?
        fi
    else
        log "No YAML parsing tools available (python with yaml module or yq)" "ERROR"
        return 1
    fi
}

# Format JSON string
# Arguments:
#   $1 - JSON string or file
#   $2 - Indent level (optional, defaults to 2)
# Returns: Formatted JSON
format_json() {
    local json="$1"
    local indent="${2:-2}"
    
    # Check if input is a file
    if [[ -f "$json" ]]; then
        json=$(cat "$json")
    fi
    
    if command_exists jq; then
        echo "$json" | jq --indent "$indent" '.'
    elif command_exists python3; then
        echo "$json" | python3 -m json.tool --indent "$indent"
    elif command_exists python; then
        echo "$json" | python -m json.tool
    else
        # If no formatting tools are available, return the original JSON
        echo "$json"
    fi
}

#######################################
# DATABASE UTILITIES
#######################################

# Check PostgreSQL connection
# Arguments:
#   $1 - Host
#   $2 - Port (optional - defaults to 5432)
#   $3 - Database (optional - defaults to postgres)
#   $4 - User (optional - defaults to postgres)
#   $5 - Password (optional)
# Returns: 0 if connection successful, 1 if not
check_postgres_connection() {
    local host="$1"
    local port="${2:-5432}"
    local db="${3:-postgres}"
    local user="${4:-postgres}"
    local password="${5:-}"
    local connection_string="host=$host port=$port dbname=$db user=$user"
    
    # Check if psql command exists
    if ! command_exists psql; then
        log "PostgreSQL client (psql) not installed" "ERROR"
        return 1
    fi
    
    # Build command with proper password handling
    local pg_cmd="psql \"$connection_string\" -t -c \"SELECT 1;\""
    
    if [[ -n "$password" ]]; then
        # Use environment variable for password
        PGPASSWORD="$password" eval "$pg_cmd" &>/dev/null
    else
        # Try without password (might use .pgpass or peer auth)
        eval "$pg_cmd" &>/dev/null
    fi
    
    local result=$?
    
    if [[ $result -eq 0 ]]; then
        log "Successfully connected to PostgreSQL at $host:$port/$db as $user" "DEBUG"
    else
        log "Failed to connect to PostgreSQL at $host:$port/$db as $user" "DEBUG"
    fi
    
    return $result
}

# Check MySQL/MariaDB connection
# Arguments:
#   $1 - Host
#   $2 - Port (optional - defaults to 3306)
#   $3 - Database (optional)
#   $4 - User (optional - defaults to root)
#   $5 - Password (optional)
# Returns: 0 if connection successful, 1 if not
check_mysql_connection() {
    local host="$1"
    local port="${2:-3306}"
    local db="${3:-}"
    local user="${4:-root}"
    local password="${5:-}"
    local mysql_opts="-h $host -P $port -u $user --connect-timeout=10"
    
    # Check if mysql command exists
    if ! command_exists mysql; then
        log "MySQL client not installed" "ERROR"
        return 1
    fi
    
    if [[ -n "$db" ]]; then
        mysql_opts="$mysql_opts -D $db"
    fi
    
    local mysql_cmd="mysql $mysql_opts -e 'SELECT 1;'"
    
    if [[ -n "$password" ]]; then
        mysql_opts="$mysql_opts -p$(printf "%q" "$password")"
        mysql_cmd="mysql $mysql_opts -e 'SELECT 1;'"
    fi
    
    eval "$mysql_cmd" &>/dev/null
    local result=$?
    
    if [[ $result -eq 0 ]]; then
        log "Successfully connected to MySQL at $host:$port${db:+/$db} as $user" "DEBUG"
    else
        log "Failed to connect to MySQL at $host:$port${db:+/$db} as $user" "DEBUG"
    fi
    
    return $result
}

# Execute SQL query on PostgreSQL database
# Arguments:
#   $1 - Query to execute
#   $2 - Host
#   $3 - Database
#   $4 - User
#   $5 - Port (optional - defaults to 5432)
#   $6 - Password (optional)
# Returns: Query result or error message
pg_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-5432}"
    local password="${6:-}"
    local connection_string="host=$host port=$port dbname=$db user=$user"
    
    if ! command_exists psql; then
        echo "ERROR: PostgreSQL client (psql) not installed"
        return 1
    fi
    
    local temp_file=$(get_temp_file "pg_result")
    
    if [[ -n "$password" ]]; then
        PGPASSWORD="$password" psql "$connection_string" -t -c "$query" > "$temp_file" 2>&1
    else
        psql "$connection_string" -t -c "$query" > "$temp_file" 2>&1
    fi
    
    local result=$?
    local output=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi
    
    echo "$output" | sed 's/^ *//' | sed 's/ *$//'
    return 0
}

# Execute SQL query on MySQL database
# Arguments:
#   $1 - Query to execute
#   $2 - Host
#   $3 - Database
#   $4 - User
#   $5 - Port (optional - defaults to 3306)
#   $6 - Password (optional)
# Returns: Query result or error message
mysql_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-3306}"
    local password="${6:-}"
    local mysql_opts="-h $host -P $port -u $user"
    
    if [[ -n "$db" ]]; then
        mysql_opts="$mysql_opts -D $db"
    fi
    
    if ! command_exists mysql; then
        echo "ERROR: MySQL client not installed"
        return 1
    fi
    
    local temp_file=$(get_temp_file "mysql_result")
    
    if [[ -n "$password" ]]; then
        MYSQL_PWD="$password" mysql $mysql_opts -N -e "$query" > "$temp_file" 2>&1
    else
        mysql $mysql_opts -N -e "$query" > "$temp_file" 2>&1
    fi
    
    local result=$?
    local output=$(cat "$temp_file")
    rm -f "$temp_file"
    
    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi
    
    echo "$output"
    return 0
}

#######################################
# CLOUD PROVIDER UTILITIES
#######################################

# Check AWS CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_aws_auth() {
    if ! command_exists aws; then
        warn "AWS CLI not installed"
        return 1
    fi
    
    # Attempt to get caller identity
    if aws sts get-caller-identity &>/dev/null; then
        local identity=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
        log "AWS authenticated as: $identity" "DEBUG"
        return 0
    else
        warn "AWS CLI not authenticated"
        return 1
    fi
}

# Check GCP CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_gcp_auth() {
    if ! command_exists gcloud; then
        warn "GCP CLI (gcloud) not installed"
        return 1
    fi
    
    # Check if user is authenticated
    local account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [[ -n "$account" ]]; then
        log "GCP authenticated as: $account" "DEBUG"
        return 0
    else
        warn "GCP CLI not authenticated"
        return 1
    fi
}

# Check Azure CLI availability and authentication
# Returns: 0 if authenticated, 1 if not
check_azure_auth() {
    if ! command_exists az; then
        warn "Azure CLI not installed"
        return 1
    fi
    
    # Check if user is logged in
    if az account show &>/dev/null; then
        local account=$(az account show --query 'user.name' -o tsv 2>/dev/null)
        log "Azure authenticated as: $account" "DEBUG"
        return 0
    else
        warn "Azure CLI not authenticated"
        return 1
    fi
}

# Get AWS instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance-id, local-hostname)
# Returns: Metadata value
get_aws_metadata() {
    local metadata_key="$1"
    local result
    
    if command_exists curl && curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
        result=$(curl -s "http://169.254.169.254/latest/meta-data/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve AWS instance metadata"
        return 1
    fi
}

# Get GCP instance metadata
# Arguments:
#   $1 - Metadata key (e.g., instance/id, instance/zone)
# Returns: Metadata value
get_gcp_metadata() {
    local metadata_key="$1"
    local result
    
    if command_exists curl && curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
        result=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$metadata_key")
        echo "$result"
        return 0
    else
        warn "Unable to retrieve GCP instance metadata"
        return 1
    fi
}

# Detect cloud provider
# Returns: Provider name (aws, gcp, azure, unknown)
detect_cloud_provider() {
    if command_exists curl; then
        # Check for AWS
        if curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ &>/dev/null; then
            echo "aws"
            return 0
        fi
        
        # Check for GCP
        if curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 http://metadata.google.internal/computeMetadata/v1/ &>/dev/null; then
            echo "gcp"
            return 0
        fi
        
        # Check for Azure
        if curl -s --connect-timeout 2 http://169.254.169.254/metadata/instance?api-version=2020-09-01 -H "Metadata: true" &>/dev/null; then
            echo "azure"
            return 0
        fi
    fi
    
    # Check for provider-specific files
    if [[ -f /sys/hypervisor/uuid ]] && [[ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]]; then
        echo "aws"
        return 0
    fi
    
    if [[ -f /sys/class/dmi/id/product_name ]] && grep -q "Google Compute Engine" /sys/class/dmi/id/product_name; then
        echo "gcp"
        return 0
    fi
    
    if [[ -f /sys/class/dmi/id/chassis_asset_tag ]] && grep -q "7783-7084-3265-9085-8269-3286-77" /sys/class/dmi/id/chassis_asset_tag; then
        echo "azure"
        return 0
    fi
    
    echo "unknown"
    return 1
}

#######################################
# HEALTH CHECK UTILITIES
#######################################

# Check if a service is running
# Arguments:
#   $1 - Service name
# Returns: 0 if running, 1 if not
is_service_running() {
    local service="$1"
    
    if command_exists systemctl; then
        if systemctl is-active --quiet "$service"; then
            return 0
        fi
    elif command_exists service; then
        if service "$service" status &>/dev/null; then
            return 0
        fi
    elif command_exists launchctl; then
        # macOS service check
        if launchctl list | grep -q "$service"; then
            return 0
        fi
    else
        warn "Cannot check service status - no service manager found"
        return 2
    fi
    
    return 1
}

# Check disk usage and warn if above threshold
# Arguments:
#   $1 - Path to check
#   $2 - Threshold percentage (optional - defaults to 90)
# Returns: 0 if below threshold, 1 if above
check_disk_usage_threshold() {
    local path="${1:-/}"
    local threshold="${2:-90}"
    local usage
    
    # Get disk usage based on operating system
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        usage=$(df -h "$path" | awk 'NR==2 {print $5}' | tr -d '%')
    else
        # Linux
        usage=$(df -h "$path" | awk 'NR==2 {print $5}' | tr -d '%')
    fi
    
    if (( usage >= threshold )); then
        warn "Disk usage for $path is at ${usage}%, which exceeds the ${threshold}% threshold"
        return 1
    fi
    
    return 0
}

# Check if a process is running by name
# Arguments:
#   $1 - Process name to check
# Returns: 0 if running, 1 if not
is_process_running() {
    local process_name="$1"
    
    if command_exists pgrep; then
        pgrep -f "$process_name" &>/dev/null
        return $?
    elif command_exists ps; then
        ps -ef | grep -v grep | grep -q "$process_name"
        return $?
    else
        warn "Cannot check process status - neither pgrep nor ps commands found"
        return 2
    fi
}

# Check service health via HTTP endpoint
# Arguments:
#   $1 - URL to health endpoint
#   $2 - Expected status code (optional - defaults to 200)
#   $3 - Timeout in seconds (optional - defaults to 5)
# Returns: 0 if healthy, 1 if unhealthy
check_health_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    local timeout="${3:-5}"
    local status_code
    
    if command_exists curl; then
        status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url")
    elif command_exists wget; then
        status_code=$(wget --spider -q -T "$timeout" -O - "$url" 2>&1 | awk '/^  HTTP/{print $2}')
    else
        warn "Cannot check health endpoint - neither curl nor wget commands found"
        return 2
    fi
    
    if [[ "$status_code" == "$expected_status" ]]; then
        return 0
    else
        warn "Health check for $url failed - expected status $expected_status, got $status_code"
        return 1
    fi
}

# Check TLS certificate expiration
# Arguments:
#   $1 - Domain name
#   $2 - Warning threshold in days (optional - defaults to 30)
# Returns: 0 if certificate is valid and not expiring soon, 1 otherwise
check_certificate_expiration() {
    local domain="$1"
    local threshold_days="${2:-30}"
    local expiry_date
    local days_remaining
    
    if ! command_exists openssl; then
        warn "OpenSSL not available, cannot check certificate expiration"
        return 2
    fi
    
    # Get certificate expiration date using OpenSSL
    expiry_date=$(echo | openssl s_client -servername "$domain" -connect "$domain":443 2>/dev/null | \
                 openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    
    if [[ -z "$expiry_date" ]]; then
        warn "Failed to retrieve certificate for $domain"
        return 1
    fi
    
    # Calculate days remaining until expiration
    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local seconds_remaining=$((expiry_epoch - current_epoch))
    days_remaining=$((seconds_remaining / 86400))
    
    if (( days_remaining <= 0 )); then
        warn "Certificate for $domain has expired!"
        return 1
    elif (( days_remaining <= threshold_days )); then
        warn "Certificate for $domain will expire in $days_remaining days (threshold: $threshold_days days)"
        return 1
    fi
    
    return 0
}

# Monitor a service and restart if needed
# Arguments:
#   $1 - Service name
#   $2 - Restart command (optional - defaults to systemctl restart)
#   $3 - Health check command (optional - defaults to systemctl is-active)
# Returns: 0 if service is running or was successfully restarted, 1 otherwise
monitor_and_restart_service() {
    local service_name="$1"
    local restart_cmd="${2:-systemctl restart $service_name}"
    local health_check="${3:-systemctl is-active $service_name}"
    
    log "Checking service: $service_name"
    
    # Check if service is running using the provided health check command
    if eval "$health_check" &>/dev/null; then
        debug "Service $service_name is running correctly"
        return 0
    else
        warn "Service $service_name is not running properly, attempting restart"
        
        # Attempt to restart the service
        if eval "$restart_cmd" &>/dev/null; then
            log "Successfully restarted service: $service_name"
            
            # Verify service is now running
            sleep 2
            if eval "$health_check" &>/dev/null; then
                log "Service $service_name is now running properly after restart"
                return 0
            else
                error_exit "Service $service_name failed to restart properly" 1
            fi
        else
            error_exit "Failed to restart service: $service_name" 1
        fi
    fi
}

# Format timestamp for consistent usage
# Arguments:
#   $1 - Format (optional - defaults to "full")
# Returns: Formatted timestamp string
format_timestamp() {
    local format="${1:-full}"
    
    case "$format" in
        full)
            date '+%Y-%m-%d %H:%M:%S'
            ;;
        date)
            date '+%Y-%m-%d'
            ;;
        time)
            date '+%H:%M:%S'
            ;;
        iso8601)
            date -u '+%Y-%m-%dT%H:%M:%SZ'
            ;;
        filename)
            date '+%Y%m%d_%H%M%S'
            ;;
        *)
            date '+%Y-%m-%d %H:%M:%S'
            ;;
    esac
}

# Create a secure temporary directory
# Arguments:
#   $1 - Prefix for directory name (optional)
# Returns: Path to temporary directory
create_temp_dir() {
    local prefix="${1:-cloudplatform}"
    local temp_dir
    
    temp_dir=$(mktemp -d "/tmp/${prefix}_XXXXXX") || {
        error_exit "Failed to create temporary directory" 1
        return 1
    }
    
    # Secure the temporary directory
    chmod 700 "$temp_dir"
    
    echo "$temp_dir"
}

# Clean up temporary resources
# Arguments:
#   $1 - Temporary directory or file to clean up
# Returns: 0 on success, 1 on failure
cleanup_temp_resources() {
    local resource="$1"
    
    if [[ -d "$resource" ]]; then
        rm -rf "$resource" || {
            warn "Failed to remove temporary directory: $resource"
            return 1
        }
    elif [[ -f "$resource" ]]; then
        rm -f "$resource" || {
            warn "Failed to remove temporary file: $resource"
            return 1
        }
    else
        warn "Resource does not exist: $resource"
        return 1
    fi
    
    return 0
}

# Enforce resource limits for a process
# Arguments:
#   $1 - Command to run with limits enforced
#   $2 - CPU limit percentage (optional - defaults to 50)
#   $3 - Memory limit in MB (optional - defaults to 1024)
# Returns: Command exit code
run_with_resource_limits() {
    local command="$1"
    local cpu_limit="${2:-50}"
    local memory_limit="${3:-1024}"
    
    # Check for required tools
    if ! command_exists nice || ! command_exists timeout; then
        warn "Cannot enforce resource limits - nice or timeout commands not found"
        # Run command without limits
        eval "$command"
        return $?
    fi
    
    # Convert memory to KB for cgroups
    local memory_kb=$((memory_limit * 1024))
    
    # Check if we can use cgroups
    if command_exists cgcreate && [[ -d "/sys/fs/cgroup" ]]; then
        cgcreate -g cpu,memory:/$$ || true
        echo "$cpu_limit" > /sys/fs/cgroup/cpu/$$/cpu.shares || true
        echo "$memory_kb" > /sys/fs/cgroup/memory/$$/memory.limit_in_bytes || true
        cgexec -g cpu,memory:/$$ nice -n 10 timeout 3600 "$command"
        local exit_code=$?
        cgdelete -g cpu,memory:/$$ || true
        return $exit_code
    else
        # Fallback to nice and ulimit if cgroups not available
        if command_exists ulimit; then
            # Set ulimit for memory if possible
            ulimit -m "$memory_kb" 2>/dev/null || true
        fi
        nice -n 10 timeout 3600 $command
        return $?
    fi
}

# Export functions to be used in other scripts
export -f log
export -f error_exit
export -f warn
export -f debug
export -f important
export -f log_dr_event
export -f load_env
export -f validate_environment
export -f detect_environment
export -f command_exists
export -f file_exists
export -f is_valid_ip
export -f is_number
export -f validate_required_params
export -f backup_file
export -f ensure_directory
export -f safe_write_file
export -f file_age
export -f is_root
export -f get_system_info
export -f check_disk_space
export -f is_port_in_use
export -f get_temp_file
export -f execute_with_timeout
export -f is_url_reachable
export -f get_public_ip
export -f ping_host
export -f send_email_notification
export -f send_slack_notification
export -f send_notification
export -f generate_random_string
export -f url_encode
export -f parse_json
export -f parse_ini_section
export -f check_postgres_connection
export -f check_mysql_connection
export -f check_aws_auth
export -f check_gcp_auth
export -f check_azure_auth
export -f is_service_running
export -f check_disk_usage_threshold
export -f is_process_running
export -f check_health_endpoint
export -f check_certificate_expiration
export -f monitor_and_restart_service
export -f format_timestamp
export -f create_temp_dir
export -f cleanup_temp_resources
export -f run_with_resource_limits