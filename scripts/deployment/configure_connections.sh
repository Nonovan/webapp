#!/bin/bash
# Connection Configuration Script for Cloud Infrastructure Platform
# This script configures connections to external services and databases
# Usage: ./configure_connections.sh [--environment <env>] [--service <service>] [--force]
#
# Copyright (c) 2023-2024 Cloud Infrastructure Platform

# Strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
SERVICES=()
CONFIG_DIR="/etc/cloud-platform/connections"
FORCE=false
DRY_RUN=false
LOG_FILE="/var/log/cloud-platform/connection_config.log"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Load common functions
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
else
    echo "Error: common_functions.sh not found"
    exit 1
fi

# Function to display usage
usage() {
    cat <<EOF
Connection Configuration Script for Cloud Infrastructure Platform

Usage: $(basename "$0") [options]

Options:
  --environment, -e ENV   Specify environment (default: production)
                          Valid values: development, staging, production, dr-recovery
  --service, -s SERVICE   Specify service to configure (can be used multiple times)
                          Valid values: database, cache, messaging, storage, api, auth, monitoring
  --all                   Configure all available services
  --config-dir DIR        Specify configuration directory (default: $CONFIG_DIR)
  --force, -f             Force overwrite existing configurations
  --dry-run               Show what would be configured without making changes
  --log-file FILE         Specify custom log file location
  --help, -h              Show this help message

Examples:
  $(basename "$0") --environment staging --service database --service cache
  $(basename "$0") --environment production --all --force
EOF
    exit 0
}

# Parse command-line arguments
ALL_SERVICES=false

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --service|-s)
            SERVICES+=("$2")
            shift 2
            ;;
        --all)
            ALL_SERVICES=true
            shift
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log "Unknown option: $1" "ERROR" "$LOG_FILE"
            usage
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "Invalid environment: $ENVIRONMENT" "ERROR" "$LOG_FILE"
    log "Valid environments: development, staging, production, dr-recovery" "ERROR" "$LOG_FILE"
    exit 1
fi

# If --all is specified, set all service types
if [[ "$ALL_SERVICES" = true ]]; then
    SERVICES=("database" "cache" "messaging" "storage" "api" "auth" "monitoring")
fi

# If no services specified, show error
if [[ ${#SERVICES[@]} -eq 0 ]]; then
    log "No services specified. Use --service or --all" "ERROR" "$LOG_FILE"
    usage
    exit 1
fi

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE" "INFO" "$LOG_FILE"
else
    log "Environment file not found: $ENV_FILE" "WARNING" "$LOG_FILE"
fi

# Ensure config directory exists
mkdir -p "$CONFIG_DIR" || {
    log "Failed to create configuration directory: $CONFIG_DIR" "ERROR" "$LOG_FILE"
    exit 1
}

# Secure the configuration directory
chmod 750 "$CONFIG_DIR" || log "Warning: Could not set permissions on $CONFIG_DIR" "WARNING" "$LOG_FILE"

# Function to backup an existing configuration file
backup_config_file() {
    local file="$1"
    
    if [[ -f "$file" ]]; then
        local backup_file="${file}.${TIMESTAMP}.bak"
        cp -p "$file" "$backup_file" || {
            log "Failed to create backup of $file" "ERROR" "$LOG_FILE"
            return 1
        }
        log "Backed up existing configuration to $backup_file" "INFO" "$LOG_FILE"
    fi
    return 0
}

# Function to configure database connections
configure_database() {
    log "Configuring database connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_database.json"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Database configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get database configuration details
    # Try to automatically detect from environment variables first
    local db_type="${DB_TYPE:-postgresql}"
    local db_host="${DB_HOST:-}"
    local db_port="${DB_PORT:-}"
    local db_name="${DB_NAME:-}"
    local db_user="${DB_USER:-}"
    local db_password="${DB_PASSWORD:-}"
    
    # If not found in environment, prompt for values
    if [[ -z "$db_host" || "$FORCE" = true ]]; then
        log "Please provide database connection details:" "INFO" "$LOG_FILE"
        read -p "Database type [postgresql]: " input_db_type
        read -p "Database host: " input_db_host
        read -p "Database port [5432]: " input_db_port
        read -p "Database name: " input_db_name
        read -p "Database user: " input_db_user
        read -p "Database password: " -s input_db_password
        echo ""
        
        # Set values, using defaults where appropriate
        db_type="${input_db_type:-postgresql}"
        db_host="${input_db_host}"
        db_port="${input_db_port:-5432}"
        db_name="${input_db_name}"
        db_user="${input_db_user}"
        db_password="${input_db_password}"
    fi
    
    # Validate required inputs
    if [[ -z "$db_host" || -z "$db_name" || -z "$db_user" || -z "$db_password" ]]; then
        log "Missing required database connection parameters" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Set default port based on database type if not specified
    if [[ -z "$db_port" ]]; then
        case "$db_type" in
            postgresql)
                db_port="5432"
                ;;
            mysql)
                db_port="3306"
                ;;
            mongodb)
                db_port="27017"
                ;;
            *)
                db_port="5432"  # Default to PostgreSQL port
                ;;
        esac
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure database connection:" "INFO" "$LOG_FILE"
        log "  - Type: $db_type" "INFO" "$LOG_FILE"
        log "  - Host: $db_host" "INFO" "$LOG_FILE"
        log "  - Port: $db_port" "INFO" "$LOG_FILE"
        log "  - Database: $db_name" "INFO" "$LOG_FILE"
        log "  - User: $db_user" "INFO" "$LOG_FILE"
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    fi
    
    # Test connection if possible
    if [[ "$db_type" == "postgresql" ]] && command_exists psql; then
        log "Testing PostgreSQL connection..." "INFO" "$LOG_FILE"
        if ! PGPASSWORD="$db_password" psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$db_name" -c "SELECT 1;" &>/dev/null; then
            log "Failed to connect to PostgreSQL database" "ERROR" "$LOG_FILE"
            log "Please verify your connection details and try again" "ERROR" "$LOG_FILE"
            return 1
        fi
        log "Database connection test successful" "INFO" "$LOG_FILE"
    elif [[ "$db_type" == "mysql" ]] && command_exists mysql; then
        log "Testing MySQL connection..." "INFO" "$LOG_FILE"
        if ! mysql -h "$db_host" -P "$db_port" -u "$db_user" -p"$db_password" -D "$db_name" -e "SELECT 1;" &>/dev/null; then
            log "Failed to connect to MySQL database" "ERROR" "$LOG_FILE"
            log "Please verify your connection details and try again" "ERROR" "$LOG_FILE"
            return 1
        fi
        log "Database connection test successful" "INFO" "$LOG_FILE"
    else
        log "Skipping connection test - client tools not available" "WARNING" "$LOG_FILE"
    fi
    
    # Create the configuration file
    cat > "$CONFIG_FILE" << EOF
{
    "database": {
        "type": "$db_type",
        "host": "$db_host",
        "port": $db_port,
        "name": "$db_name",
        "user": "$db_user",
        "password": "$db_password",
        "ssl_mode": "require",
        "connection_pool": {
            "max_connections": 20,
            "min_connections": 5,
            "max_idle_time_seconds": 300
        }
    }
}
EOF
    
    # Secure the configuration file
    chmod 640 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "Database connection configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure cache connections
configure_cache() {
    log "Configuring cache connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_cache.ini"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Cache configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get cache configuration details
    # Try to automatically detect from environment variables first
    local cache_host="${CACHE_HOST:-}"
    local cache_port="${CACHE_PORT:-6379}"
    local cache_password="${CACHE_PASSWORD:-}"
    local cache_db="${CACHE_DB:-0}"
    local cache_type="${CACHE_TYPE:-redis}"
    
    # If not found in environment, prompt for values
    if [[ -z "$cache_host" || "$FORCE" = true ]]; then
        log "Please provide cache connection details:" "INFO" "$LOG_FILE"
        read -p "Cache type [redis]: " input_cache_type
        read -p "Cache host: " input_cache_host
        read -p "Cache port [6379]: " input_cache_port
        read -p "Cache password (leave empty if none): " -s input_cache_password
        echo ""
        read -p "Cache DB number [0]: " input_cache_db
        
        # Set values, using defaults where appropriate
        cache_type="${input_cache_type:-redis}"
        cache_host="${input_cache_host}"
        cache_port="${input_cache_port:-6379}"
        cache_password="${input_cache_password}"
        cache_db="${input_cache_db:-0}"
    fi
    
    # Validate required inputs
    if [[ -z "$cache_host" ]]; then
        log "Missing required cache connection parameters" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure cache connection:" "INFO" "$LOG_FILE"
        log "  - Type: $cache_type" "INFO" "$LOG_FILE"
        log "  - Host: $cache_host" "INFO" "$LOG_FILE"
        log "  - Port: $cache_port" "INFO" "$LOG_FILE"
        log "  - DB: $cache_db" "INFO" "$LOG_FILE"
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    fi
    
    # Test connection if possible
    if [[ "$cache_type" == "redis" ]] && command_exists redis-cli; then
        log "Testing Redis connection..." "INFO" "$LOG_FILE"
        local redis_cmd="redis-cli -h $cache_host -p $cache_port"
        
        if [[ -n "$cache_password" ]]; then
            redis_cmd="$redis_cmd -a $cache_password"
        fi
        
        if ! $redis_cmd ping &>/dev/null; then
            log "Failed to connect to Redis cache" "ERROR" "$LOG_FILE"
            log "Please verify your connection details and try again" "ERROR" "$LOG_FILE"
            return 1
        fi
        log "Cache connection test successful" "INFO" "$LOG_FILE"
    else
        log "Skipping connection test - client tools not available" "WARNING" "$LOG_FILE"
    fi
    
    # Create the configuration file
    cat > "$CONFIG_FILE" << EOF
[cache]
type = $cache_type
host = $cache_host
port = $cache_port
EOF

    # Only add password if it's set
    if [[ -n "$cache_password" ]]; then
        echo "password = $cache_password" >> "$CONFIG_FILE"
    fi
    
    # Add remaining configuration
    cat >> "$CONFIG_FILE" << EOF
db = $cache_db
max_connections = 10
timeout = 5
ttl = 3600

[options]
compress_data = true
use_connection_pool = true
EOF
    
    # Secure the configuration file
    chmod 640 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "Cache connection configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure messaging connections
configure_messaging() {
    log "Configuring messaging connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_messaging.json"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Messaging configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get messaging configuration details
    # Try to automatically detect from environment variables first
    local msg_type="${MSG_TYPE:-rabbitmq}"
    local msg_host="${MSG_HOST:-}"
    local msg_port="${MSG_PORT:-5672}"
    local msg_user="${MSG_USER:-}"
    local msg_password="${MSG_PASSWORD:-}"
    local msg_vhost="${MSG_VHOST:-/}"
    
    # If not found in environment, prompt for values
    if [[ -z "$msg_host" || "$FORCE" = true ]]; then
        log "Please provide messaging service connection details:" "INFO" "$LOG_FILE"
        
        # Show available options
        echo "Available messaging types:"
        echo "1) RabbitMQ"
        echo "2) Kafka"
        echo "3) AWS SQS"
        echo "4) Azure Service Bus"
        read -p "Select messaging type [1]: " msg_type_option
        
        case "$msg_type_option" in
            2)
                msg_type="kafka"
                ;;
            3)
                msg_type="aws_sqs"
                ;;
            4)
                msg_type="azure_servicebus"
                ;;
            *)
                msg_type="rabbitmq"
                ;;
        esac
        
        read -p "Host: " input_msg_host
        
        # Ask for service-specific details based on type
        if [[ "$msg_type" == "rabbitmq" ]]; then
            read -p "Port [5672]: " input_msg_port
            read -p "Username: " input_msg_user
            read -p "Password: " -s input_msg_password
            echo ""
            read -p "Virtual host [/]: " input_msg_vhost
            
            msg_port="${input_msg_port:-5672}"
            msg_user="${input_msg_user}"
            msg_password="${input_msg_password}"
            msg_vhost="${input_msg_vhost:-/}"
        elif [[ "$msg_type" == "kafka" ]]; then
            read -p "Port [9092]: " input_msg_port
            read -p "Username (leave empty if not required): " input_msg_user
            read -p "Password (leave empty if not required): " -s input_msg_password
            echo ""
            
            msg_port="${input_msg_port:-9092}"
            msg_user="${input_msg_user}"
            msg_password="${input_msg_password}"
        elif [[ "$msg_type" == "aws_sqs" ]]; then
            read -p "AWS Region [us-west-2]: " input_region
            read -p "Access Key ID: " input_access_key
            read -p "Secret Access Key: " -s input_secret_key
            echo ""
            
            msg_region="${input_region:-us-west-2}"
            msg_access_key="${input_access_key}"
            msg_secret_key="${input_secret_key}"
        elif [[ "$msg_type" == "azure_servicebus" ]]; then
            read -p "Connection String: " -s input_connection_string
            echo ""
            
            msg_connection_string="${input_connection_string}"
        fi
        
        msg_host="${input_msg_host}"
    fi
    
    # Validate required inputs
    if [[ -z "$msg_host" && "$msg_type" != "aws_sqs" && "$msg_type" != "azure_servicebus" ]]; then
        log "Missing required messaging connection parameters" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$msg_type" == "aws_sqs" && ( -z "${msg_access_key:-}" || -z "${msg_secret_key:-}" ) ]]; then
        log "Missing required AWS SQS credentials" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$msg_type" == "azure_servicebus" && -z "${msg_connection_string:-}" ]]; then
        log "Missing required Azure Service Bus connection string" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure messaging connection:" "INFO" "$LOG_FILE"
        log "  - Type: $msg_type" "INFO" "$LOG_FILE"
        
        # Show type-specific configuration
        if [[ "$msg_type" == "rabbitmq" || "$msg_type" == "kafka" ]]; then
            log "  - Host: $msg_host" "INFO" "$LOG_FILE"
            log "  - Port: $msg_port" "INFO" "$LOG_FILE"
            if [[ -n "${msg_user:-}" ]]; then
                log "  - User: $msg_user" "INFO" "$LOG_FILE"
            fi
            if [[ "$msg_type" == "rabbitmq" ]]; then
                log "  - VHost: $msg_vhost" "INFO" "$LOG_FILE"
            fi
        elif [[ "$msg_type" == "aws_sqs" ]]; then
            log "  - Region: ${msg_region:-us-west-2}" "INFO" "$LOG_FILE"
        elif [[ "$msg_type" == "azure_servicebus" ]]; then
            log "  - Connection string: (provided)" "INFO" "$LOG_FILE"
        fi
        
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    }
    
    # Create configuration file based on messaging type
    if [[ "$msg_type" == "rabbitmq" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "messaging": {
        "type": "rabbitmq",
        "host": "$msg_host",
        "port": $msg_port,
        "user": "$msg_user",
        "password": "$msg_password",
        "vhost": "$msg_vhost",
        "ssl": true,
        "connection_options": {
            "heartbeat": 60,
            "blocked_connection_timeout": 300,
            "retry_delay": 5
        }
    }
}
EOF
    elif [[ "$msg_type" == "kafka" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "messaging": {
        "type": "kafka",
        "bootstrap_servers": ["$msg_host:$msg_port"],
        "security": {
EOF

        if [[ -n "${msg_user:-}" && -n "${msg_password:-}" ]]; then
            cat >> "$CONFIG_FILE" << EOF
            "protocol": "SASL_SSL",
            "sasl_mechanism": "PLAIN",
            "sasl_plain_username": "$msg_user",
            "sasl_plain_password": "$msg_password"
EOF
        else
            cat >> "$CONFIG_FILE" << EOF
            "protocol": "PLAINTEXT"
EOF
        fi

        cat >> "$CONFIG_FILE" << EOF
        },
        "client_options": {
            "session_timeout_ms": 10000,
            "auto_offset_reset": "earliest",
            "enable_auto_commit": true,
            "auto_commit_interval_ms": 5000
        }
    }
}
EOF
    elif [[ "$msg_type" == "aws_sqs" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "messaging": {
        "type": "aws_sqs",
        "region": "${msg_region:-us-west-2}",
        "credentials": {
            "access_key_id": "${msg_access_key}",
            "secret_access_key": "${msg_secret_key}"
        },
        "options": {
            "wait_time_seconds": 20,
            "max_number_of_messages": 10,
            "visibility_timeout": 30
        }
    }
}
EOF
    elif [[ "$msg_type" == "azure_servicebus" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "messaging": {
        "type": "azure_servicebus",
        "connection_string": "${msg_connection_string}",
        "options": {
            "retry_total": 3,
            "retry_delay": 5,
            "max_delivery_count": 10
        }
    }
}
EOF
    else
        log "Unsupported messaging type: $msg_type" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Secure the configuration file
    chmod 640 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "Messaging connection configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure storage connections
configure_storage() {
    log "Configuring storage connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_storage.json"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Storage configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get storage configuration details
    # Try to automatically detect from environment variables first
    local storage_type="${STORAGE_TYPE:-s3}"
    local bucket_name="${STORAGE_BUCKET:-}"
    local endpoint="${STORAGE_ENDPOINT:-}"
    local region="${STORAGE_REGION:-us-west-2}"
    local access_key="${STORAGE_ACCESS_KEY:-}"
    local secret_key="${STORAGE_SECRET_KEY:-}"
    
    # If not found in environment, prompt for values
    if [[ -z "$bucket_name" || "$FORCE" = true ]]; then
        log "Please provide storage connection details:" "INFO" "$LOG_FILE"
        
        # Show available options
        echo "Available storage types:"
        echo "1) AWS S3"
        echo "2) Google Cloud Storage"
        echo "3) Azure Blob Storage"
        echo "4) MinIO (S3-compatible)"
        read -p "Select storage type [1]: " storage_type_option
        
        case "$storage_type_option" in
            2)
                storage_type="gcs"
                ;;
            3)
                storage_type="azure_blob"
                ;;
            4)
                storage_type="minio"
                ;;
            *)
                storage_type="s3"
                ;;
        esac
        
        read -p "Bucket/Container name: " input_bucket_name
        
        if [[ "$storage_type" == "s3" ]]; then
            read -p "Region [us-west-2]: " input_region
            read -p "Access Key ID: " input_access_key
            read -p "Secret Access Key: " -s input_secret_key
            echo ""
            
            bucket_name="${input_bucket_name}"
            region="${input_region:-us-west-2}"
            access_key="${input_access_key}"
            secret_key="${input_secret_key}"
            endpoint=""
        elif [[ "$storage_type" == "minio" ]]; then
            read -p "Endpoint URL: " input_endpoint
            read -p "Region [us-west-2]: " input_region
            read -p "Access Key: " input_access_key
            read -p "Secret Key: " -s input_secret_key
            echo ""
            
            bucket_name="${input_bucket_name}"
            endpoint="${input_endpoint}"
            region="${input_region:-us-west-2}"
            access_key="${input_access_key}"
            secret_key="${input_secret_key}"
        elif [[ "$storage_type" == "gcs" ]]; then
            read -p "GCS Project ID: " input_project_id
            read -p "Service Account Key File Path: " input_key_file
            
            bucket_name="${input_bucket_name}"
            project_id="${input_project_id}"
            key_file="${input_key_file}"
        elif [[ "$storage_type" == "azure_blob" ]]; then
            read -p "Connection String: " -s input_connection_string
            echo ""
            
            bucket_name="${input_bucket_name}"
            connection_string="${input_connection_string}"
        fi
    fi
    
    # Validate required inputs
    if [[ -z "$bucket_name" ]]; then
        log "Missing required storage bucket/container name" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$storage_type" == "s3" && ( -z "$access_key" || -z "$secret_key" ) ]]; then
        log "Missing required S3 credentials" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$storage_type" == "minio" && ( -z "$endpoint" || -z "$access_key" || -z "$secret_key" ) ]]; then
        log "Missing required MinIO configuration parameters" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$storage_type" == "gcs" && ( -z "${project_id:-}" || -z "${key_file:-}" ) ]]; then
        log "Missing required GCS configuration parameters" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    if [[ "$storage_type" == "azure_blob" && -z "${connection_string:-}" ]]; then
        log "Missing required Azure Blob Storage connection string" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure storage connection:" "INFO" "$LOG_FILE"
        log "  - Type: $storage_type" "INFO" "$LOG_FILE"
        log "  - Bucket/Container: $bucket_name" "INFO" "$LOG_FILE"
        
        if [[ "$storage_type" == "s3" ]]; then
            log "  - Region: $region" "INFO" "$LOG_FILE"
            log "  - Access Key ID: $access_key" "INFO" "$LOG_FILE"
        elif [[ "$storage_type" == "minio" ]]; then
            log "  - Endpoint: $endpoint" "INFO" "$LOG_FILE"
            log "  - Region: $region" "INFO" "$LOG_FILE"
            log "  - Access Key: $access_key" "INFO" "$LOG_FILE"
        elif [[ "$storage_type" == "gcs" ]]; then
            log "  - Project ID: ${project_id}" "INFO" "$LOG_FILE"
            log "  - Key File: ${key_file}" "INFO" "$LOG_FILE"
        elif [[ "$storage_type" == "azure_blob" ]]; then
            log "  - Connection String: (provided)" "INFO" "$LOG_FILE"
        fi
        
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    }
    
    # Create configuration file based on storage type
    if [[ "$storage_type" == "s3" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "storage": {
        "type": "s3",
        "bucket": "$bucket_name",
        "region": "$region",
        "access_key": "$access_key",
        "secret_key": "$secret_key",
        "options": {
            "signature_version": "s3v4",
            "addressing_style": "virtual"
        },
        "cache_control": "max-age=3600",
        "presigned_url_expiry": 3600
    }
}
EOF
    elif [[ "$storage_type" == "minio" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "storage": {
        "type": "s3",
        "bucket": "$bucket_name",
        "endpoint": "$endpoint",
        "region": "$region",
        "access_key": "$access_key",
        "secret_key": "$secret_key",
        "use_ssl": true,
        "options": {
            "signature_version": "s3v4",
            "addressing_style": "path"
        }
    }
}
EOF
    elif [[ "$storage_type" == "gcs" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "storage": {
        "type": "gcs",
        "bucket": "$bucket_name",
        "project_id": "${project_id}",
        "key_file": "${key_file}",
        "options": {
            "retry_params": {
                "total_timeout_seconds": 120,
                "retry_delay_seconds": 5
            }
        }
    }
}
EOF
    elif [[ "$storage_type" == "azure_blob" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "storage": {
        "type": "azure_blob",
        "container": "$bucket_name",
        "connection_string": "${connection_string}",
        "options": {
            "max_concurrency": 10,
            "retry_total": 3,
            "retry_delay": 5
        }
    }
}
EOF
    else
        log "Unsupported storage type: $storage_type" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Secure the configuration file
    chmod 640 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "Storage connection configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure API connections
configure_api() {
    log "Configuring API connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_api.ini"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "API configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get API configuration details
    # Try to automatically detect from environment variables first
    local api_configs=()
    
    # If not found in environment or forced, prompt for values
    if [[ "$FORCE" = true || ! -f "$CONFIG_FILE" ]]; then
        log "Please provide API endpoint details:" "INFO" "$LOG_FILE"
        
        local continue=true
        local api_count=0
        
        while [[ "$continue" == true && $api_count -lt 10 ]]; do
            api_count=$((api_count + 1))
            
            read -p "API name (e.g., payments, analytics): " api_name
            if [[ -z "$api_name" ]]; then
                api_name="api$api_count"
            fi
            
            read -p "API URL: " api_url
            if [[ -z "$api_url" ]]; then
                log "API URL is required" "ERROR" "$LOG_FILE"
                continue
            fi
            
            read -p "API version (e.g., v1): " api_version
            read -p "Authentication type (none, basic, bearer, apikey): " auth_type
            
            local auth_user=""
            local auth_password=""
            local auth_token=""
            local auth_key=""
            
            case "$auth_type" in
                basic)
                    read -p "Username: " auth_user
                    read -p "Password: " -s auth_password
                    echo ""
                    ;;
                bearer)
                    read -p "Bearer token: " -s auth_token
                    echo ""
                    ;;
                apikey)
                    read -p "API key name (default: x-api-key): " api_key_name
                    if [[ -z "$api_key_name" ]]; then
                        api_key_name="x-api-key"
                    fi
                    read -p "API key value: " -s auth_key
                    echo ""
                    ;;
            esac
            
            read -p "Timeout in seconds [30]: " api_timeout
            if [[ -z "$api_timeout" ]]; then
                api_timeout=30
            fi
            
            # Store API configuration
            api_configs+=("api_name=$api_name")
            api_configs+=("api_url=$api_url")
            api_configs+=("api_version=$api_version")
            api_configs+=("auth_type=$auth_type")
            api_configs+=("auth_user=$auth_user")
            api_configs+=("auth_password=$auth_password")
            api_configs+=("auth_token=$auth_token")
            api_configs+=("auth_key=$auth_key")
            api_configs+=("api_key_name=${api_key_name:-}")
            api_configs+=("api_timeout=$api_timeout")
            
            read -p "Configure another API? (y/n): " another_api
            if [[ ! "$another_api" =~ ^[Yy](es)?$ ]]; then
                continue=false
            fi
        done
    else
        log "Using existing API configuration" "INFO" "$LOG_FILE"
        return 0
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure API connections:" "INFO" "$LOG_FILE"
        
        local i=0
        local total_apis=$((${#api_configs[@]} / 10))
        
        for ((i=0; i<$total_apis; i++)); do
            local base_idx=$((i * 10))
            local api_name=$(echo "${api_configs[$base_idx]}" | cut -d'=' -f2-)
            local api_url=$(echo "${api_configs[$base_idx+1]}" | cut -d'=' -f2-)
            local auth_type=$(echo "${api_configs[$base_idx+3]}" | cut -d'=' -f2-)
            
            log "  - API: $api_name" "INFO" "$LOG_FILE"
            log "    URL: $api_url" "INFO" "$LOG_FILE"
            log "    Auth: $auth_type" "INFO" "$LOG_FILE"
        done
        
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    }
    
    # Create configuration file
    > "$CONFIG_FILE"
    
    local i=0
    local total_apis=$((${#api_configs[@]} / 10))
    
    for ((i=0; i<$total_apis; i++)); do
        local base_idx=$((i * 10))
        local api_name=$(echo "${api_configs[$base_idx]}" | cut -d'=' -f2-)
        local api_url=$(echo "${api_configs[$base_idx+1]}" | cut -d'=' -f2-)
        local api_version=$(echo "${api_configs[$base_idx+2]}" | cut -d'=' -f2-)
        local auth_type=$(echo "${api_configs[$base_idx+3]}" | cut -d'=' -f2-)
        local auth_user=$(echo "${api_configs[$base_idx+4]}" | cut -d'=' -f2-)
        local auth_password=$(echo "${api_configs[$base_idx+5]}" | cut -d'=' -f2-)
        local auth_token=$(echo "${api_configs[$base_idx+6]}" | cut -d'=' -f2-)
        local auth_key=$(echo "${api_configs[$base_idx+7]}" | cut -d'=' -f2-)
        local api_key_name=$(echo "${api_configs[$base_idx+8]}" | cut -d'=' -f2-)
        local api_timeout=$(echo "${api_configs[$base_idx+9]}" | cut -d'=' -f2-)
        
        cat >> "$CONFIG_FILE" << EOF

[$api_name]
url = $api_url
EOF

        # Only add version if provided
        if [[ -n "$api_version" ]]; then
            echo "version = $api_version" >> "$CONFIG_FILE"
        fi
        
        echo "auth_type = $auth_type" >> "$CONFIG_FILE"
        
        # Add authentication details based on type
        case "$auth_type" in
            basic)
                echo "username = $auth_user" >> "$CONFIG_FILE"
                echo "password = $auth_password" >> "$CONFIG_FILE"
                ;;
            bearer)
                echo "token = $auth_token" >> "$CONFIG_FILE"
                ;;
            apikey)
                echo "key_name = $api_key_name" >> "$CONFIG_FILE"
                echo "key_value = $auth_key" >> "$CONFIG_FILE"
                ;;
        esac
        
        echo "timeout = $api_timeout" >> "$CONFIG_FILE"
    done
    
    # Add default configuration section
    cat >> "$CONFIG_FILE" << EOF

[defaults]
retry_attempts = 3
retry_backoff = 2
verify_ssl = true
compress = true
EOF
    
    # Secure the configuration file
    chmod 640 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "API connections configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure authentication services
configure_auth() {
    log "Configuring authentication services..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_auth.json"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Authentication configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get authentication configuration details
    # Try to automatically detect from environment variables first
    local auth_type="${AUTH_TYPE:-oauth2}"
    local auth_provider="${AUTH_PROVIDER:-}"
    local client_id="${AUTH_CLIENT_ID:-}"
    local client_secret="${AUTH_CLIENT_SECRET:-}"
    local auth_url="${AUTH_URL:-}"
    local token_url="${AUTH_TOKEN_URL:-}"
    local redirect_uri="${AUTH_REDIRECT_URI:-}"
    local jwks_uri="${AUTH_JWKS_URI:-}"
    local jwt_secret="${JWT_SECRET:-}"
    
    # If not found in environment, prompt for values
    if [[ -z "$auth_provider" || "$FORCE" = true ]]; then
        log "Please provide authentication service details:" "INFO" "$LOG_FILE"
        
        # Show available options
        echo "Available authentication types:"
        echo "1) OAuth 2.0"
        echo "2) SAML 2.0" 
        echo "3) JWT"
        echo "4) LDAP"
        read -p "Select authentication type [1]: " auth_type_option
        
        case "$auth_type_option" in
            2)
                auth_type="saml"
                ;;
            3)
                auth_type="jwt"
                ;;
            4)
                auth_type="ldap"
                ;;
            *)
                auth_type="oauth2"
                ;;
        esac
        
        if [[ "$auth_type" == "oauth2" ]]; then
            echo "Available OAuth providers:"
            echo "1) Auth0"
            echo "2) Okta"
            echo "3) Azure AD"
            echo "4) Keycloak"
            echo "5) Google"
            echo "6) Custom"
            read -p "Select OAuth provider [1]: " provider_option
            
            case "$provider_option" in
                2)
                    auth_provider="okta"
                    ;;
                3)
                    auth_provider="azure"
                    ;;
                4)
                    auth_provider="keycloak"
                    ;;
                5)
                    auth_provider="google"
                    ;;
                6)
                    auth_provider="custom"
                    ;;
                *)
                    auth_provider="auth0"
                    ;;
            esac
            
            read -p "Client ID: " input_client_id
            read -p "Client Secret: " -s input_client_secret
            echo ""
            read -p "Auth URL: " input_auth_url
            read -p "Token URL: " input_token_url
            read -p "Redirect URI: " input_redirect_uri
            read -p "JWKS URI: " input_jwks_uri
            
            client_id="${input_client_id}"
            client_secret="${input_client_secret}"
            auth_url="${input_auth_url}"
            token_url="${input_token_url}"
            redirect_uri="${input_redirect_uri}"
            jwks_uri="${input_jwks_uri}"
        elif [[ "$auth_type" == "jwt" ]]; then
            read -p "JWT Secret Key: " -s input_jwt_secret
            echo ""
            read -p "JWT Issuer: " input_jwt_issuer
            read -p "JWT Audience: " input_jwt_audience
            read -p "JWT Expiry (seconds) [3600]: " input_jwt_expiry
            
            jwt_secret="${input_jwt_secret}"
            jwt_issuer="${input_jwt_issuer}"
            jwt_audience="${input_jwt_audience}"
            jwt_expiry="${input_jwt_expiry:-3600}"
        elif [[ "$auth_type" == "ldap" ]]; then
            read -p "LDAP Server URL: " input_ldap_url
            read -p "LDAP Bind DN: " input_ldap_bind_dn
            read -p "LDAP Bind Password: " -s input_ldap_bind_password
            echo ""
            read -p "LDAP Search Base: " input_ldap_search_base
            read -p "LDAP User Filter: " input_ldap_user_filter
            
            ldap_url="${input_ldap_url}"
            ldap_bind_dn="${input_ldap_bind_dn}"
            ldap_bind_password="${input_ldap_bind_password}"
            ldap_search_base="${input_ldap_search_base}"
            ldap_user_filter="${input_ldap_user_filter:-(&(objectClass=person)(uid=%s))}"
        elif [[ "$auth_type" == "saml" ]]; then
            read -p "SAML Metadata URL: " input_saml_metadata_url
            read -p "SAML Entity ID: " input_saml_entity_id
            read -p "SAML ACS URL: " input_saml_acs_url
            
            saml_metadata_url="${input_saml_metadata_url}"
            saml_entity_id="${input_saml_entity_id}"
            saml_acs_url="${input_saml_acs_url}"
        fi
    fi
    
    # Validate required inputs based on auth type
    if [[ "$auth_type" == "oauth2" ]]; then
        if [[ -z "$client_id" || -z "$client_secret" || -z "$auth_url" || -z "$token_url" ]]; then
            log "Missing required OAuth2 configuration parameters" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$auth_type" == "jwt" ]]; then
        if [[ -z "$jwt_secret" ]]; then
            log "Missing required JWT secret" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$auth_type" == "ldap" ]]; then
        if [[ -z "${ldap_url:-}" || -z "${ldap_bind_dn:-}" || -z "${ldap_search_base:-}" ]]; then
            log "Missing required LDAP configuration parameters" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$auth_type" == "saml" ]]; then
        if [[ -z "${saml_metadata_url:-}" || -z "${saml_entity_id:-}" || -z "${saml_acs_url:-}" ]]; then
            log "Missing required SAML configuration parameters" "ERROR" "$LOG_FILE"
            return 1
        fi
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure authentication service:" "INFO" "$LOG_FILE"
        log "  - Type: $auth_type" "INFO" "$LOG_FILE"
        
        if [[ "$auth_type" == "oauth2" ]]; then
            log "  - Provider: $auth_provider" "INFO" "$LOG_FILE"
            log "  - Client ID: $client_id" "INFO" "$LOG_FILE"
            log "  - Auth URL: $auth_url" "INFO" "$LOG_FILE"
            log "  - Token URL: $token_url" "INFO" "$LOG_FILE"
            log "  - Redirect URI: $redirect_uri" "INFO" "$LOG_FILE"
        elif [[ "$auth_type" == "jwt" ]]; then
            log "  - JWT Secret: (provided)" "INFO" "$LOG_FILE"
            log "  - JWT Issuer: ${jwt_issuer:-not specified}" "INFO" "$LOG_FILE"
            log "  - JWT Audience: ${jwt_audience:-not specified}" "INFO" "$LOG_FILE"
        elif [[ "$auth_type" == "ldap" ]]; then
            log "  - LDAP URL: ${ldap_url}" "INFO" "$LOG_FILE"
            log "  - LDAP Bind DN: ${ldap_bind_dn}" "INFO" "$LOG_FILE"
            log "  - LDAP Search Base: ${ldap_search_base}" "INFO" "$LOG_FILE"
        elif [[ "$auth_type" == "saml" ]]; then
            log "  - SAML Metadata URL: ${saml_metadata_url}" "INFO" "$LOG_FILE"
            log "  - SAML Entity ID: ${saml_entity_id}" "INFO" "$LOG_FILE"
            log "  - SAML ACS URL: ${saml_acs_url}" "INFO" "$LOG_FILE"
        fi
        
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    }
    
    # Create configuration file based on authentication type
    if [[ "$auth_type" == "oauth2" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "auth": {
        "type": "oauth2",
        "provider": "$auth_provider",
        "client_id": "$client_id",
        "client_secret": "$client_secret",
        "auth_url": "$auth_url",
        "token_url": "$token_url",
        "redirect_uri": "$redirect_uri",
        "jwks_uri": "$jwks_uri",
        "scopes": ["openid", "profile", "email"],
        "response_type": "code",
        "token_endpoint_auth_method": "client_secret_basic",
        "validate_nonce": true,
        "session_timeout_seconds": 28800
    }
}
EOF
    elif [[ "$auth_type" == "jwt" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "auth": {
        "type": "jwt",
        "secret": "$jwt_secret",
        "issuer": "${jwt_issuer:-cloud-platform}",
        "audience": "${jwt_audience:-cloud-platform-api}",
        "expiry_seconds": ${jwt_expiry:-3600},
        "algorithm": "HS256",
        "options": {
            "verify_signature": true,
            "verify_expiry": true,
            "verify_not_before": true,
            "verify_issuer": true,
            "verify_audience": true
        }
    }
}
EOF
    elif [[ "$auth_type" == "ldap" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "auth": {
        "type": "ldap",
        "url": "${ldap_url}",
        "bind_dn": "${ldap_bind_dn}",
        "bind_password": "${ldap_bind_password}",
        "search_base": "${ldap_search_base}",
        "user_filter": "${ldap_user_filter:-(&(objectClass=person)(uid=%s))}",
        "tls": true,
        "timeout_seconds": 5,
        "connection_pool": {
            "max_size": 10,
            "idle_timeout_seconds": 300
        }
    }
}
EOF
    elif [[ "$auth_type" == "saml" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
    "auth": {
        "type": "saml",
        "metadata_url": "${saml_metadata_url}",
        "entity_id": "${saml_entity_id}",
        "acs_url": "${saml_acs_url}",
        "signing": {
            "authn_requests_signed": true,
            "want_assertions_signed": true,
            "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
        },
        "session_timeout_seconds": 28800,
        "attributes": {
            "user_id": "nameID",
            "email": "email",
            "first_name": "firstName",
            "last_name": "lastName"
        }
    }
}
EOF
    else
        log "Unsupported authentication type: $auth_type" "ERROR" "$LOG_FILE"
        return 1
    fi
    
    # Secure the configuration file with restricted permissions
    chmod 600 "$CONFIG_FILE" || log "Warning: Could not set permissions on $CONFIG_FILE" "WARNING" "$LOG_FILE"
    
    log "Authentication services configured successfully: $CONFIG_FILE" "INFO" "$LOG_FILE"
    return 0
}

# Function to configure monitoring connections
configure_monitoring() {
    log "Configuring monitoring connections..." "INFO" "$LOG_FILE"
    
    # Determine configuration file based on environment
    local CONFIG_FILE="${CONFIG_DIR}/${ENVIRONMENT}_monitoring.ini"
    
    # Check if config already exists
    if [[ -f "$CONFIG_FILE" && "$FORCE" != true ]]; then
        log "Monitoring configuration already exists. Use --force to overwrite" "WARNING" "$LOG_FILE"
        return 0
    fi
    
    # Backup existing config if it exists
    backup_config_file "$CONFIG_FILE"
    
    # Get monitoring configuration details
    # Try to automatically detect from environment variables first
    local monitoring_type="${MONITORING_TYPE:-prometheus}"
    local monitoring_host="${MONITORING_HOST:-}"
    local monitoring_port="${MONITORING_PORT:-}"
    local monitoring_path="${MONITORING_PATH:-}"
    local monitoring_interval="${MONITORING_INTERVAL:-15}"
    local monitoring_username="${MONITORING_USERNAME:-}"
    local monitoring_password="${MONITORING_PASSWORD:-}"
    local monitoring_api_key="${MONITORING_API_KEY:-}"
    
    # If not found in environment, prompt for values
    if [[ -z "$monitoring_host" || "$FORCE" = true ]]; then
        log "Please provide monitoring service connection details:" "INFO" "$LOG_FILE"
        
        # Show available options
        echo "Available monitoring types:"
        echo "1) Prometheus"
        echo "2) Datadog"
        echo "3) New Relic"
        echo "4) Grafana Cloud"
        echo "5) CloudWatch"
        read -p "Select monitoring type [1]: " monitoring_type_option
        
        case "$monitoring_type_option" in
            2)
                monitoring_type="datadog"
                ;;
            3)
                monitoring_type="newrelic"
                ;;
            4)
                monitoring_type="grafana"
                ;;
            5)
                monitoring_type="cloudwatch"
                ;;
            *)
                monitoring_type="prometheus"
                ;;
        esac
        
        # Ask for service-specific configuration
        if [[ "$monitoring_type" == "prometheus" ]]; then
            read -p "Prometheus server host: " input_host
            read -p "Prometheus server port [9090]: " input_port
            read -p "Path [/metrics]: " input_path
            read -p "Push interval in seconds [15]: " input_interval
            
            monitoring_host="${input_host}"
            monitoring_port="${input_port:-9090}"
            monitoring_path="${input_path:-/metrics}"
            monitoring_interval="${input_interval:-15}"
        elif [[ "$monitoring_type" == "datadog" ]]; then
            read -p "API key: " -s input_api_key
            echo ""
            read -p "Application key: " -s input_app_key
            echo ""
            read -p "Region (us/eu) [us]: " input_region
            
            monitoring_api_key="${input_api_key}"
            monitoring_app_key="${input_app_key}"
            monitoring_region="${input_region:-us}"
            monitoring_host="${monitoring_region:-us}.datadoghq.com"
        elif [[ "$monitoring_type" == "newrelic" ]]; then
            read -p "API key: " -s input_api_key
            echo ""
            read -p "Account ID: " input_account_id
            read -p "Region (us/eu) [us]: " input_region
            
            monitoring_api_key="${input_api_key}"
            monitoring_account_id="${input_account_id}"
            monitoring_region="${input_region:-us}"
            if [[ "$monitoring_region" == "eu" ]]; then
                monitoring_host="api.eu.newrelic.com"
            else
                monitoring_host="api.newrelic.com"
            fi
        elif [[ "$monitoring_type" == "grafana" ]]; then
            read -p "Grafana Cloud URL: " input_host
            read -p "API key: " -s input_api_key
            echo ""
            read -p "Prometheus remote write URL: " input_remote_write
            
            monitoring_host="${input_host}"
            monitoring_api_key="${input_api_key}"
            monitoring_remote_write="${input_remote_write}"
        elif [[ "$monitoring_type" == "cloudwatch" ]]; then
            read -p "AWS region [us-west-2]: " input_region
            read -p "AWS access key ID: " input_access_key
            read -p "AWS secret access key: " -s input_secret_key
            echo ""
            
            monitoring_region="${input_region:-us-west-2}"
            monitoring_access_key="${input_access_key}"
            monitoring_secret_key="${input_secret_key}"
        fi
    fi
    
    # Validate required inputs based on monitoring type
    if [[ "$monitoring_type" == "prometheus" ]]; then
        if [[ -z "$monitoring_host" ]]; then
            log "Missing required Prometheus server host" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$monitoring_type" == "datadog" ]]; then
        if [[ -z "${monitoring_api_key:-}" ]]; then
            log "Missing required Datadog API key" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$monitoring_type" == "newrelic" ]]; then
        if [[ -z "${monitoring_api_key:-}" || -z "${monitoring_account_id:-}" ]]; then
            log "Missing required New Relic configuration parameters" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$monitoring_type" == "grafana" ]]; then
        if [[ -z "${monitoring_host:-}" || -z "${monitoring_api_key:-}" ]]; then
            log "Missing required Grafana Cloud configuration parameters" "ERROR" "$LOG_FILE"
            return 1
        fi
    elif [[ "$monitoring_type" == "cloudwatch" ]]; then
        if [[ -z "${monitoring_access_key:-}" || -z "${monitoring_secret_key:-}" ]]; then
            log "Missing required AWS CloudWatch credentials" "ERROR" "$LOG_FILE"
            return 1
        fi
    fi
    
    # Show configuration that would be created in dry run mode
    if [[ "$DRY_RUN" = true ]]; then
        log "[DRY RUN] Would configure monitoring service:" "INFO" "$LOG_FILE"
        log "  - Type: $monitoring_type" "INFO" "$LOG_FILE"
        
        if [[ "$monitoring_type" == "prometheus" ]]; then
            log "  - Host: $monitoring_host" "INFO" "$LOG_FILE"
            log "  - Port: $monitoring_port" "INFO" "$LOG_FILE"
            log "  - Path: $monitoring_path" "INFO" "$LOG_FILE"
            log "  - Interval: $monitoring_interval seconds" "INFO" "$LOG_FILE"
        elif [[ "$monitoring_type" == "datadog" ]]; then
            log "  - Host: ${monitoring_host}" "INFO" "$LOG_FILE"
            log "  - API Key: (provided)" "INFO" "$LOG_FILE"
        elif [[ "$monitoring_type" == "newrelic" ]]; then
            log "  - Host: ${monitoring_host}" "INFO" "$LOG_FILE"
            log "  - Account ID: ${monitoring_account_id}" "INFO" "$LOG_FILE"
            log "  - API Key: (provided)" "INFO" "$LOG_FILE"
        elif [[ "$monitoring_type" == "grafana" ]]; then
            log "  - Grafana Cloud URL: ${monitoring_host}" "INFO" "$LOG_FILE"
            log "  - Remote Write URL: ${monitoring_remote_write:-not specified}" "INFO" "$LOG_FILE"
            log "  - API Key: (provided)" "INFO" "$LOG_FILE"
        elif [[ "$monitoring_type" == "cloudwatch" ]]; then
            log "  - Region: ${monitoring_region}" "INFO" "$LOG_FILE"
            log "  - AWS Credentials: (provided)" "INFO" "$LOG_FILE"
        fi
        
        log "  - Config file: $CONFIG_FILE" "INFO" "$LOG_FILE"
        return 0
    }
    
    # Create configuration file based on monitoring type
    if [[ "$monitoring_type" == "prometheus" ]]; then
        cat > "$CONFIG_FILE" << EOF
[prometheus]
type = prometheus
host = $monitoring_host
port = $monitoring_port
path = $monitoring_path
interval = $monitoring_interval
job_name = cloud-platform-${ENVIRONMENT}
instance_label = ${HOSTNAME:-unknown}

[metrics]
enable_process_metrics = true
enable_runtime_metrics = true
enable_memory_metrics = true
enable_database_metrics = true
enable_http_metrics = true
EOF
    elif [[ "$monitoring_type" == "datadog" ]]; then
        cat > "$CONFIG_FILE" << EOF
[datadog]
type = datadog
api_key = $monitoring_api_key
app_key = ${monitoring_app_key}
host = $monitoring_host
tags = environment:${ENVIRONMENT},service:cloud-platform
interval = 15

[metrics]
enable_process_metrics = true
enable_runtime_metrics = true
enable_memory_metrics = true
enable_database_metrics = true
enable_http_metrics = true
EOF
    elif [[ "$monitoring_type" == "newrelic" ]]; then
        cat > "$CONFIG_FILE" << EOF
[newrelic]
type = newrelic
api_key = $monitoring_api_key
account_id = $monitoring_account_id
host = $monitoring_host
app_name = cloud-platform-${ENVIRONMENT}
interval = 15

[metrics]
enable_process_metrics = true
enable_runtime_metrics = true
enable_memory_metrics = true
enable_database_metrics = true
enable_http