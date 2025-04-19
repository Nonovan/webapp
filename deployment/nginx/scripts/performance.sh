#!/bin/bash
# Performance optimization script for NGINX
# Usage: ./performance.sh [--apply] [--environment production|staging|development]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
ENVIRONMENT="production"
APPLY=false
DEFAULT_WORKER_CONNECTIONS=1024
DEFAULT_KEEPALIVE_TIMEOUT=65
DEFAULT_KEEPALIVE_REQUESTS=1000
WORKER_PROCESSES="auto"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --apply)
            APPLY=true
            shift
            ;;
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --apply                Apply recommended settings (without this, only shows recommendations)"
            echo "  --environment, -e      Environment (production, staging, development) [default: production]"
            echo "  --help, -h             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "${RED}Invalid environment: $ENVIRONMENT${NC}"
    log "Valid environments: development, staging, production, dr-recovery"
    exit 1
fi

# Check if NGINX is installed
if ! command -v nginx &> /dev/null; then
    log "${RED}ERROR: NGINX is not installed${NC}"
    exit 1
fi

# Function to get total system memory in MB
get_total_memory() {
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    echo $(( $mem_total / 1024 ))  # Convert KB to MB
}

# Function to get CPU cores count
get_cpu_count() {
    grep -c ^processor /proc/cpuinfo
}

# Function to determine optimal worker processes
calculate_worker_processes() {
    local cpu_count=$(get_cpu_count)
    
    # For production, use all cores
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo $cpu_count
    # For staging, use 75% of cores (rounded up)
    elif [[ "$ENVIRONMENT" == "staging" ]]; then
        echo $(( ($cpu_count * 3 + 3) / 4 ))
    # For development, use fewer cores
    else
        echo $(( ($cpu_count + 1) / 2 ))
    fi
}

# Function to determine optimal worker connections
calculate_worker_connections() {
    local mem_total=$(get_total_memory)
    local cpu_count=$(get_cpu_count)
    local worker_processes=$(calculate_worker_processes)
    
    # Each connection uses approximately 2-3KB of memory
    # Reserve 20% of memory for the OS and other processes
    local available_mem=$(( $mem_total * 80 / 100 ))
    local max_conn_by_mem=$(( $available_mem * 1024 / 3 / $worker_processes ))
    
    # Set reasonable limits based on environment
    if [[ "$ENVIRONMENT" == "production" ]]; then
        if [[ $max_conn_by_mem -gt 10000 ]]; then
            echo 10000  # Cap at 10000 connections per worker
        elif [[ $max_conn_by_mem -lt 1024 ]]; then
            echo 1024   # Minimum of 1024 connections
        else
            echo $max_conn_by_mem
        fi
    elif [[ "$ENVIRONMENT" == "staging" ]]; then
        if [[ $max_conn_by_mem -gt 5000 ]]; then
            echo 5000   # Cap at 5000 connections per worker
        elif [[ $max_conn_by_mem -lt 768 ]]; then
            echo 768    # Minimum of 768 connections
        else
            echo $max_conn_by_mem
        fi
    else  # Development
        if [[ $max_conn_by_mem -gt 2048 ]]; then
            echo 2048   # Cap at 2048 connections per worker
        elif [[ $max_conn_by_mem -lt 512 ]]; then
            echo 512    # Minimum of 512 connections
        else
            echo $max_conn_by_mem
        fi
    fi
}

# Function to determine client body buffer size
calculate_client_body_buffer_size() {
    local mem_total=$(get_total_memory)
    
    # Set based on environment and available memory
    if [[ "$ENVIRONMENT" == "production" ]]; then
        if [[ $mem_total -gt 8192 ]]; then  # More than 8GB
            echo "64k"
        elif [[ $mem_total -gt 4096 ]]; then  # 4-8GB
            echo "32k"
        else  # Less than 4GB
            echo "16k"
        fi
    elif [[ "$ENVIRONMENT" == "staging" ]]; then
        if [[ $mem_total -gt 4096 ]]; then  # More than 4GB
            echo "32k"
        else
            echo "16k"
        fi
    else  # Development
        echo "8k"
    fi
}

# Function to calculate keepalive settings based on environment
calculate_keepalive_settings() {
    local env="$1"
    local timeout
    local requests
    
    if [[ "$env" == "production" ]]; then
        timeout=65
        requests=10000
    elif [[ "$env" == "staging" ]]; then
        timeout=65
        requests=5000
    else  # Development
        timeout=75
        requests=1000
    fi
    
    echo "$timeout $requests"
}

# Function to create NGINX performance configuration
generate_performance_config() {
    local worker_processes=$1
    local worker_connections=$2
    local client_body_buffer_size=$3
    local keepalive_timeout=$4
    local keepalive_requests=$5
    
    # Create performance config file
    cat > "${NGINX_ROOT}/conf.d/performance.conf" <<EOF
# Performance Configuration for NGINX
# Environment: ${ENVIRONMENT}
# Generated on: $(date '+%Y-%m-%d %H:%M:%S')
# This file is automatically generated - DO NOT EDIT MANUALLY

# Worker processes and connections
worker_processes ${worker_processes};

events {
    worker_connections ${worker_connections};
    multi_accept on;
    use epoll;
}

http {
    # Buffers and timeouts
    client_body_buffer_size ${client_body_buffer_size};
    client_max_body_size 100m;
    client_body_timeout 60s;
    client_header_buffer_size 2k;
    client_header_timeout 60s;
    large_client_header_buffers 4 8k;
    keepalive_timeout ${keepalive_timeout};
    keepalive_requests ${keepalive_requests};
    send_timeout 60s;

    # TCP optimization
    tcp_nodelay on;
    tcp_nopush on;

    # File IO operations
    sendfile on;
    aio on;
    directio 512;

    # Caching settings
    open_file_cache max=10000 inactive=30s;
    open_file_cache_valid 60s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
}
EOF
    log "${GREEN}Generated performance configuration at ${NGINX_ROOT}/conf.d/performance.conf${NC}"
}

# Function to check current NGINX configuration
check_current_config() {
    log "${BLUE}Checking current NGINX configuration...${NC}"
    
    # Check worker processes
    local current_worker_processes=$(nginx -T 2>/dev/null | grep -m1 "worker_processes" | awk '{print $2}' | tr -d ';')
    log "Current worker_processes: ${current_worker_processes:-"Not set"}"
    
    # Check worker connections
    local current_worker_connections=$(nginx -T 2>/dev/null | grep -m1 "worker_connections" | awk '{print $2}' | tr -d ';')
    log "Current worker_connections: ${current_worker_connections:-$DEFAULT_WORKER_CONNECTIONS}"
    
    # Check client body buffer size
    local current_client_body_buffer_size=$(nginx -T 2>/dev/null | grep -m1 "client_body_buffer_size" | awk '{print $2}' | tr -d ';')
    log "Current client_body_buffer_size: ${current_client_body_buffer_size:-"Not set"}"
    
    # Check keepalive settings
    local current_keepalive_timeout=$(nginx -T 2>/dev/null | grep -m1 "keepalive_timeout" | awk '{print $2}' | tr -d ';')
    log "Current keepalive_timeout: ${current_keepalive_timeout:-$DEFAULT_KEEPALIVE_TIMEOUT}"
    
    local current_keepalive_requests=$(nginx -T 2>/dev/null | grep -m1 "keepalive_requests" | awk '{print $2}' | tr -d ';')
    log "Current keepalive_requests: ${current_keepalive_requests:-$DEFAULT_KEEPALIVE_REQUESTS}"
}

# Main function
main() {
    log "${BLUE}Running NGINX performance optimization for ${ENVIRONMENT} environment${NC}"
    
    # Get system information
    local mem_total=$(get_total_memory)
    local cpu_count=$(get_cpu_count)
    
    log "System information:"
    log "  - Total memory: ${mem_total} MB"
    log "  - CPU cores: ${cpu_count}"
    
    # Check current configuration
    check_current_config
    
    # Calculate optimal settings
    local optimal_worker_processes=$(calculate_worker_processes)
    local optimal_worker_connections=$(calculate_worker_connections)
    local optimal_client_body_buffer_size=$(calculate_client_body_buffer_size)
    
    # Set keepalive settings based on environment
    read optimal_keepalive_timeout optimal_keepalive_requests <<< $(calculate_keepalive_settings "$ENVIRONMENT")
    
    log "${GREEN}Recommended settings:${NC}"
    log "  - worker_processes: $optimal_worker_processes"
    log "  - worker_connections: $optimal_worker_connections"
    log "  - client_body_buffer_size: $optimal_client_body_buffer_size"
    log "  - keepalive_timeout: $optimal_keepalive_timeout"
    log "  - keepalive_requests: $optimal_keepalive_requests"
    
    # Apply settings if requested
    if [[ "$APPLY" == "true" ]]; then
        log "${BLUE}Applying recommended settings...${NC}"
        
        # Create backup of nginx.conf if it exists
        if [ -f "${NGINX_ROOT}/nginx.conf" ]; then
            cp "${NGINX_ROOT}/nginx.conf" "${NGINX_ROOT}/nginx.conf.bak.$(date +%Y%m%d%H%M%S)"
            log "Created backup of nginx.conf"
        fi
        
        # Generate performance configuration
        generate_performance_config "$optimal_worker_processes" "$optimal_worker_connections" \
            "$optimal_client_body_buffer_size" "$optimal_keepalive_timeout" "$optimal_keepalive_requests"
        
        # Test NGINX configuration
        log "Testing NGINX configuration..."
        if nginx -t; then
            log "${GREEN}Configuration test passed${NC}"
            
            # Reload NGINX
            log "Reloading NGINX..."
            systemctl reload nginx
            log "${GREEN}✓ NGINX reloaded successfully with new performance settings${NC}"
        else
            log "${RED}✗ Configuration test failed${NC}"
            log "Reverting changes..."
            
            # Remove generated config if it exists
            if [ -f "${NGINX_ROOT}/conf.d/performance.conf" ]; then
                rm "${NGINX_ROOT}/conf.d/performance.conf"
            fi
            
            log "${YELLOW}Performance optimization failed. No changes were applied.${NC}"
            exit 1
        fi
    else
        log "${YELLOW}To apply these settings, run the script with --apply${NC}"
    fi
}

# Run the main function
main

exit 0