#!/bin/bash
# Cloud Infrastructure Platform - Connection Configuration Script
# Usage: ./configure_connections.sh [--environment <env>] [--type <connection_type>] [--host <hostname>] [--port <port>]
#
# This script configures various types of connections and integrations for the Cloud Infrastructure Platform,
# including databases, message queues, monitoring systems, and external services.

# Strict error handling
set -o errexit
set -o pipefail
set -o nounset

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
CONNECTION_TYPE=""
CONNECTION_HOST=""
CONNECTION_PORT=""
CONFIG_DIR="/etc/cloud-platform"
BACKUP_DIR="/var/backups/cloud-platform/configs"
DRY_RUN=false
FORCE=false
LOG_FILE="/var/log/cloud-platform/connections.log"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
QUIET=false
VALIDATE=true
DR_MODE=false

# Ensure script has executable permissions
if [[ ! -x "$0" ]]; then
    chmod +x "$0"
fi

# Create necessary directories with error checking
for dir in "$(dirname "$LOG_FILE")" "$BACKUP_DIR"; do
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            echo "ERROR: Failed to create directory: $dir. Check permissions."
            exit 1
        }
    fi
done

# Load common functions if available
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh"
    COMMON_FUNCTIONS_LOADED=true
else
    COMMON_FUNCTIONS_LOADED=false
    
    # Define basic log function if common functions not available
    log() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local message="$1"
        local level="${2:-INFO}"
        
        if [[ "$QUIET" != "true" ]]; then
            echo -e "[$timestamp] [$level] $message"
        fi
        
        # Check if log file is writable before attempting to write
        if [[ -w "$(dirname "$LOG_FILE")" ]]; then
            echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
        else
            echo "WARNING: Cannot write to log file $LOG_FILE. Check permissions."
        fi
    }
fi

# Function to display usage information
usage() {
    cat <<EOF
Cloud Infrastructure Platform - Connection Configuration Script

Usage: $(basename "$0") [OPTIONS]

Options:
  --environment, -e ENV     Specify environment (default: production)
                            Valid values: development, staging, production, dr-recovery
  --type, -t TYPE           Connection type to configure (required)
                            Valid values: database, redis, rabbitmq, monitoring, aws, azure, gcp, smtp, ldap
  --host, -h HOST           Host/endpoint for the connection
  --port, -p PORT           Port for the connection
  --username, -u USER       Username for authentication
  --password, -w PASS       Password for authentication (or use --password-file)
  --password-file FILE      File containing the password
  --db-name, -d NAME        Database name (for database connections)
  --config-file FILE        Custom configuration file location
  --api-key KEY             API key for external services
  --region REGION           Cloud provider region
  --ssl, -s                 Enable SSL/TLS for the connection
  --dry-run                 Show what would be configured without making changes
  --force, -f               Force configuration overwrite if already exists
  --quiet, -q               Minimal output
  --no-validate             Skip connection validation
  --dr-mode                 Enable disaster recovery mode
  --help                    Show this help message

Examples:
  $(basename "$0") --type database --host db.example.com --port 5432 --username dbuser --password-file /path/to/password.txt --db-name mydb
  $(basename "$0") --type monitoring --host metrics.example.com --api-key ABC123
  $(basename "$0") --environment staging --type redis --host redis.example.com --port 6379

EOF
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --type|-t)
            CONNECTION_TYPE="$2"
            shift 2
            ;;
        --host|-h)
            CONNECTION_HOST="$2"
            shift 2
            ;;
        --port|-p)
            CONNECTION_PORT="$2"
            shift 2
            ;;
        --username|-u)
            CONNECTION_USERNAME="$2"
            shift 2
            ;;
        --password|-w)
            CONNECTION_PASSWORD="$2"
            shift 2
            ;;
        --password-file)
            PASSWORD_FILE="$2"
            if [[ -f "$PASSWORD_FILE" ]]; then
                CONNECTION_PASSWORD=$(cat "$PASSWORD_FILE")
            else
                log "Password file not found: $PASSWORD_FILE" "ERROR"
                exit 1
            fi
            shift 2
            ;;
        --db-name|-d)
            DB_NAME="$2"
            shift 2
            ;;
        --config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --ssl|-s)
            SSL_ENABLED=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --no-validate)
            VALIDATE=false
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            log "Unknown option: $key" "ERROR"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$CONNECTION_TYPE" ]]; then
    log "Missing required parameter: --type" "ERROR"
    usage
fi

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "Invalid environment: $ENVIRONMENT" "ERROR"
    log "Valid environments: development, staging, production, dr-recovery" "ERROR"
    exit 1
fi

# Function to generate a config file path
get_config_path() {
    local conn_type="$1"
    local custom_file="${2:-}"
    
    if [[ -n "$custom_file" ]]; then
        echo "$custom_file"
    else
        echo "${CONFIG_DIR}/${conn_type}-${ENVIRONMENT}.ini"
    fi
}

# Function to create a backup of existing config
backup_config() {
    local config_file="$1"
    
    if [[ -f "$config_file" ]]; then
        local backup_file="${BACKUP_DIR}/$(basename "$config_file").${TIMESTAMP}.bak"
        cp "$config_file" "$backup_file"
        log "Backup created: $backup_file" "INFO"
        return 0
    else
        log "No existing configuration to backup" "INFO"
        return 1
    fi
}

# Function to validate database connection
validate_database_connection() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local db_name="$5"
    local db_type="${6:-postgresql}"
    
    log "Validating $db_type connection to $host:$port/$db_name..." "INFO"
    
    if [[ "$db_type" == "postgresql" ]]; then
        if command -v pg_isready &>/dev/null; then
            if pg_isready -h "$host" -p "$port" -U "$username" -d "$db_name" -t 5; then
                log "PostgreSQL connection successful" "INFO"
                return 0
            else
                log "Failed to connect to PostgreSQL server" "ERROR"
                return 1
            fi
        elif command -v psql &>/dev/null; then
            if PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$username" -d "$db_name" -c "SELECT 1" &>/dev/null; then
                log "PostgreSQL connection successful" "INFO"
                return 0
            else
                log "Failed to connect to PostgreSQL server" "ERROR"
                return 1
            fi
        else
            log "PostgreSQL client tools not installed, skipping validation" "WARNING"
            return 0
        fi
    elif [[ "$db_type" == "mysql" ]]; then
        if command -v mysql &>/dev/null; then
            if mysql -h "$host" -P "$port" -u "$username" -p"$password" -D "$db_name" -e "SELECT 1" &>/dev/null; then
                log "MySQL connection successful" "INFO"
                return 0
            else
                log "Failed to connect to MySQL server" "ERROR"
                return 1
            fi
        else
            log "MySQL client not installed, skipping validation" "WARNING"
            return 0
        fi
    else
        log "Unsupported database type: $db_type" "ERROR"
        return 1
    fi
}

# Function to validate Redis connection
validate_redis_connection() {
    local host="$1"
    local port="$2"
    local password="${3:-}"
    
    log "Validating Redis connection to $host:$port..." "INFO"
    
    if command -v redis-cli &>/dev/null; then
        if [[ -n "$password" ]]; then
            if echo "PING" | redis-cli -h "$host" -p "$port" -a "$password" 2>/dev/null | grep -q "PONG"; then
                log "Redis connection successful" "INFO"
                return 0
            else
                log "Failed to connect to Redis server" "ERROR"
                return 1
            fi
        else
            if echo "PING" | redis-cli -h "$host" -p "$port" 2>/dev/null | grep -q "PONG"; then
                log "Redis connection successful" "INFO"
                return 0
            else
                log "Failed to connect to Redis server" "ERROR"
                return 1
            fi
        fi
    else
        log "Redis client not installed, skipping validation" "WARNING"
        return 0
    fi
}

# Function to validate RabbitMQ connection
validate_rabbitmq_connection() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local vhost="${5:-/}"
    
    log "Validating RabbitMQ connection to $host:$port..." "INFO"
    
    if command -v curl &>/dev/null; then
        if curl -s -u "$username:$password" "http://$host:$((port+10000))/api/vhosts" &>/dev/null; then
            log "RabbitMQ connection successful" "INFO"
            return 0
        else
            log "Failed to connect to RabbitMQ server" "ERROR"
            return 1
        fi
    else
        log "Curl not installed, skipping validation" "WARNING"
        return 0
    fi
}

# Function to validate SMTP connection
validate_smtp_connection() {
    local host="$1"
    local port="$2"
    local username="${3:-}"
    local password="${4:-}"
    
    log "Validating SMTP connection to $host:$port..." "INFO"
    
    if command -v nc &>/dev/null; then
        if echo -e "QUIT\r\n" | nc -w 5 "$host" "$port" | grep -q "220"; then
            log "SMTP connection successful" "INFO"
            return 0
        else
            log "Failed to connect to SMTP server" "ERROR"
            return 1
        fi
    else
        log "Netcat not installed, skipping validation" "WARNING"
        return 0
    fi
}

# Function to validate LDAP connection
validate_ldap_connection() {
    local host="$1"
    local port="$2"
    local bind_dn="${3:-}"
    local bind_password="${4:-}"
    
    log "Validating LDAP connection to $host:$port..." "INFO"
    
    if command -v ldapsearch &>/dev/null; then
        if [[ -n "$bind_dn" && -n "$bind_password" ]]; then
            if ldapsearch -H "ldap://$host:$port" -D "$bind_dn" -w "$bind_password" -b "" -s base &>/dev/null; then
                log "LDAP connection successful" "INFO"
                return 0
            else
                log "Failed to connect to LDAP server" "ERROR"
                return 1
            fi
        else
            if ldapsearch -H "ldap://$host:$port" -x -b "" -s base &>/dev/null; then
                log "LDAP connection successful" "INFO"
                return 0
            else
                log "Failed to connect to LDAP server" "ERROR"
                return 1
            fi
        fi
    else
        log "ldapsearch not installed, skipping validation" "WARNING"
        return 0
    fi
}

# Function to validate monitoring service connection
validate_monitoring_connection() {
    local monitoring_type="$1"
    local host="$2"
    local api_key="$3"
    
    log "Validating $monitoring_type connection to $host..." "INFO"
    
    if command -v curl &>/dev/null; then
        case "$monitoring_type" in
            prometheus)
                if curl -s "$host/metrics" &>/dev/null; then
                    log "Prometheus connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to Prometheus server" "ERROR"
                    return 1
                fi
                ;;
            datadog)
                if curl -s -X GET "https://api.datadoghq.com/api/v1/validate" \
                     -H "Content-Type: application/json" \
                     -H "DD-API-KEY: $api_key" | grep -q "valid"; then
                    log "Datadog connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to Datadog API" "ERROR"
                    return 1
                fi
                ;;
            newrelic)
                if curl -s -X GET "https://api.newrelic.com/v2/applications.json" \
                     -H "X-Api-Key: $api_key" | grep -q "applications"; then
                    log "New Relic connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to New Relic API" "ERROR"
                    return 1
                fi
                ;;
            *)
                log "Unsupported monitoring type: $monitoring_type" "WARNING"
                return 0
                ;;
        esac
    else
        log "Curl not installed, skipping validation" "WARNING"
        return 0
    fi
}

# Function to validate cloud provider connection
validate_cloud_connection() {
    local provider="$1"
    local region="${2:-}"
    
    log "Validating $provider connection..." "INFO"
    
    case "$provider" in
        aws)
            if command -v aws &>/dev/null; then
                if aws sts get-caller-identity &>/dev/null; then
                    log "AWS connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to AWS" "ERROR"
                    return 1
                fi
            else
                log "AWS CLI not installed, skipping validation" "WARNING"
                return 0
            fi
            ;;
        azure)
            if command -v az &>/dev/null; then
                if az account show &>/dev/null; then
                    log "Azure connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to Azure" "ERROR"
                    return 1
                fi
            else
                log "Azure CLI not installed, skipping validation" "WARNING"
                return 0
            fi
            ;;
        gcp)
            if command -v gcloud &>/dev/null; then
                if gcloud auth list &>/dev/null; then
                    log "GCP connection successful" "INFO"
                    return 0
                else
                    log "Failed to connect to GCP" "ERROR"
                    return 1
                fi
            else
                log "GCP CLI not installed, skipping validation" "WARNING"
                return 0
            fi
            ;;
        *)
            log "Unsupported cloud provider: $provider" "ERROR"
            return 1
            ;;
    esac
}

# Function to configure a database connection
configure_database() {
    local db_type="${1:-postgresql}"
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT:-}"
    local username="${CONNECTION_USERNAME:-}"
    local password="${CONNECTION_PASSWORD:-}"
    local db_name="${DB_NAME:-}"
    local ssl_enabled="${SSL_ENABLED:-false}"
    
    # Set default port if not provided
    if [[ -z "$port" ]]; then
        if [[ "$db_type" == "postgresql" ]]; then
            port="5432"
        elif [[ "$db_type" == "mysql" ]]; then
            port="3306"
        fi
    fi
    
    log "Configuring $db_type database connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" || -z "$username" || -z "$password" || -z "$db_name" ]]; then
        log "Missing required parameters for database configuration" "ERROR"
        log "Required: --host, --username, --password (or --password-file), --db-name" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "database" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create database configuration file: $config_file" "INFO"
        log "Connection details: $db_type://$username:***@$host:$port/$db_name" "INFO"
    else
        log "Creating database configuration file: $config_file" "INFO"
        
        cat > "$config_file" << EOF
[database]
type = $db_type
host = $host
port = $port
username = $username
password = $password
database = $db_name
ssl_enabled = $ssl_enabled

[connection]
max_connections = 20
idle_timeout = 300
connect_timeout = 10
retry_interval = 5
retry_attempts = 3
EOF
    
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "Database configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_database_connection "$host" "$port" "$username" "$password" "$db_name" "$db_type"
    fi
    
    return 0
}

# Function to configure a Redis connection
configure_redis() {
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT:-6379}"
    local password="${CONNECTION_PASSWORD:-}"
    local ssl_enabled="${SSL_ENABLED:-false}"
    
    log "Configuring Redis connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" ]]; then
        log "Missing required parameters for Redis configuration" "ERROR"
        log "Required: --host" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "redis" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create Redis configuration file: $config_file" "INFO"
        log "Connection details: redis://$host:$port" "INFO"
    else
        log "Creating Redis configuration file: $config_file" "INFO"
        
        cat > "$config_file" << EOF
[redis]
host = $host
port = $port
EOF

        if [[ -n "$password" ]]; then
            cat >> "$config_file" << EOF
password = $password
EOF
        fi
        
        cat >> "$config_file" << EOF
ssl_enabled = $ssl_enabled
database = 0

[connection]
max_connections = 10
socket_timeout = 5
socket_connect_timeout = 5
retry_on_timeout = true
health_check_interval = 30
EOF
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "Redis configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_redis_connection "$host" "$port" "$password"
    fi
    
    return 0
}

# Function to configure a RabbitMQ connection
configure_rabbitmq() {
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT:-5672}"
    local username="${CONNECTION_USERNAME:-guest}"
    local password="${CONNECTION_PASSWORD:-guest}"
    local vhost="${RABBITMQ_VHOST:-/}"
    local ssl_enabled="${SSL_ENABLED:-false}"
    
    log "Configuring RabbitMQ connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" ]]; then
        log "Missing required parameters for RabbitMQ configuration" "ERROR"
        log "Required: --host" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "rabbitmq" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create RabbitMQ configuration file: $config_file" "INFO"
        log "Connection details: amqp://$username:***@$host:$port/$vhost" "INFO"
    else
        log "Creating RabbitMQ configuration file: $config_file" "INFO"
        
        cat > "$config_file" << EOF
[rabbitmq]
host = $host
port = $port
username = $username
password = $password
vhost = $vhost
ssl_enabled = $ssl_enabled

[connection]
connection_attempts = 3
retry_delay = 5
heartbeat = 60
blocked_connection_timeout = 300
publisher_confirms = true
EOF
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "RabbitMQ configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_rabbitmq_connection "$host" "$port" "$username" "$password" "$vhost"
    fi
    
    return 0
}

# Function to configure a monitoring connection
configure_monitoring() {
    local monitoring_type="${MONITORING_TYPE:-prometheus}"
    local host="${CONNECTION_HOST}"
    local api_key="${API_KEY:-}"
    local app_key="${APP_KEY:-}"
    local monitoring_account_id="${ACCOUNT_ID:-}"
    
    log "Configuring $monitoring_type monitoring connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" ]]; then
        log "Missing required parameters for monitoring configuration" "ERROR"
        log "Required: --host" "ERROR"
        return 1
    fi
    
    # Additional validation for specific monitoring systems
    if [[ "$monitoring_type" == "datadog" && -z "$api_key" ]]; then
        log "Missing API key for Datadog configuration" "ERROR"
        log "Required: --api-key" "ERROR"
        return 1
    elif [[ "$monitoring_type" == "newrelic" && -z "$api_key" ]]; then
        log "Missing API key for New Relic configuration" "ERROR"
        log "Required: --api-key" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "monitoring" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create $monitoring_type monitoring configuration file: $config_file" "INFO"
        log "Connection details: $monitoring_type://$host" "INFO"
    else
        log "Creating $monitoring_type monitoring configuration file: $config_file" "INFO"
        
        if [[ "$monitoring_type" == "prometheus" ]]; then
            cat > "$config_file" << EOF
[prometheus]
type = prometheus
host = $host
push_gateway = ${PUSH_GATEWAY:-}
job_name = cloud-platform-${ENVIRONMENT}
interval = 15

[metrics]
enable_process_metrics = true
enable_runtime_metrics = true
enable_memory_metrics = true
enable_database_metrics = true
enable_http_metrics = true
EOF
        elif [[ "$monitoring_type" == "datadog" ]]; then
            cat > "$config_file" << EOF
[datadog]
type = datadog
api_key = $api_key
app_key = ${app_key:-}
host = $host
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
            cat > "$config_file" << EOF
[newrelic]
type = newrelic
api_key = $api_key
account_id = $monitoring_account_id
host = $host
app_name = cloud-platform-${ENVIRONMENT}
interval = 15

[metrics]
enable_process_metrics = true
enable_runtime_metrics = true
enable_memory_metrics = true
enable_database_metrics = true
enable_http_metrics = true
EOF
        fi
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "$monitoring_type monitoring configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_monitoring_connection "$monitoring_type" "$host" "$api_key"
    fi
    
    return 0
}

# Function to configure a cloud provider connection
configure_cloud_provider() {
    local provider="$1"
    local region="${REGION:-us-west-2}"
    
    log "Configuring $provider cloud provider connection for $ENVIRONMENT environment" "INFO"
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "$provider" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create $provider cloud provider configuration file: $config_file" "INFO"
        log "Provider details: $provider in $region region" "INFO"
    else
        log "Creating $provider cloud provider configuration file: $config_file" "INFO"
        
        case "$provider" in
            aws)
                cat > "$config_file" << EOF
[aws]
region = $region
profile = ${AWS_PROFILE:-default}
access_key_id = ${AWS_ACCESS_KEY_ID:-}
secret_access_key = ${AWS_SECRET_ACCESS_KEY:-}
session_token = ${AWS_SESSION_TOKEN:-}

[s3]
default_bucket = ${AWS_S3_BUCKET:-cloud-platform-${ENVIRONMENT}}
use_path_style = false

[dynamodb]
endpoint = ${DYNAMODB_ENDPOINT:-}
table_prefix = cp_${ENVIRONMENT}_

[sns]
notification_topic = ${SNS_TOPIC:-cloud-platform-${ENVIRONMENT}-notifications}

[sqs]
queue_prefix = cp_${ENVIRONMENT}_
EOF
                ;;
            azure)
                cat > "$config_file" << EOF
[azure]
subscription_id = ${AZURE_SUBSCRIPTION_ID:-}
tenant_id = ${AZURE_TENANT_ID:-}
client_id = ${AZURE_CLIENT_ID:-}
client_secret = ${AZURE_CLIENT_SECRET:-}
region = $region

[storage]
account_name = ${AZURE_STORAGE_ACCOUNT:-cloudplatform${ENVIRONMENT}}
container_name = ${AZURE_CONTAINER:-data}

[cosmos]
endpoint = ${COSMOS_ENDPOINT:-}
key = ${COSMOS_KEY:-}
database = ${COSMOS_DB:-cloudplatform}
EOF
                ;;
            gcp)
                cat > "$config_file" << EOF
[gcp]
project_id = ${GCP_PROJECT_ID:-cloud-platform-${ENVIRONMENT}}
region = $region
zone = ${GCP_ZONE:-${region}-a}
credentials_file = ${GCP_CREDENTIALS_FILE:-}

[storage]
bucket = ${GCP_BUCKET:-cloud-platform-${ENVIRONMENT}-data}

[bigtable]
instance = ${BIGTABLE_INSTANCE:-cloud-platform-${ENVIRONMENT}}
EOF
                ;;
        esac
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "$provider cloud provider configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_cloud_connection "$provider" "$region"
    fi
    
    return 0
}

# Function to configure an SMTP connection
configure_smtp() {
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT:-25}"
    local username="${CONNECTION_USERNAME:-}"
    local password="${CONNECTION_PASSWORD:-}"
    local ssl_enabled="${SSL_ENABLED:-false}"
    local tls_enabled="${TLS_ENABLED:-true}"
    
    log "Configuring SMTP connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" ]]; then
        log "Missing required parameters for SMTP configuration" "ERROR"
        log "Required: --host" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "smtp" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create SMTP configuration file: $config_file" "INFO"
        log "Connection details: smtp://$host:$port" "INFO"
    else
        log "Creating SMTP configuration file: $config_file" "INFO"
        
        cat > "$config_file" << EOF
[smtp]
host = $host
port = $port
EOF

        if [[ -n "$username" && -n "$password" ]]; then
            cat >> "$config_file" << EOF
username = $username
password = $password
EOF
        fi
        
        cat >> "$config_file" << EOF
use_ssl = $ssl_enabled
use_tls = $tls_enabled
timeout = 30
from_address = ${FROM_ADDRESS:-noreply@example.com}
from_name = ${FROM_NAME:-Cloud Platform ${ENVIRONMENT}}

[email]
admin_email = ${ADMIN_EMAIL:-admin@example.com}
error_email = ${ERROR_EMAIL:-errors@example.com}
enable_html_emails = true
EOF
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "SMTP configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_smtp_connection "$host" "$port" "$username" "$password"
    fi
    
    return 0
}

# Function to configure an LDAP connection
configure_ldap() {
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT:-389}"
    local bind_dn="${CONNECTION_USERNAME:-}"
    local bind_password="${CONNECTION_PASSWORD:-}"
    local ssl_enabled="${SSL_ENABLED:-false}"
    local search_base="${LDAP_SEARCH_BASE:-}"
    
    log "Configuring LDAP connection for $ENVIRONMENT environment" "INFO"
    
    # Validate inputs
    if [[ -z "$host" || -z "$search_base" ]]; then
        log "Missing required parameters for LDAP configuration" "ERROR"
        log "Required: --host, --ldap-search-base" "ERROR"
        return 1
    fi
    
    # Configure the connection file
    local config_file
    config_file="$(get_config_path "ldap" "${CONFIG_FILE:-}")"
    
    # Check if the config file already exists and if we should overwrite it
    if [[ -f "$config_file" && "$FORCE" != "true" ]]; then
        log "Configuration file already exists: $config_file" "ERROR"
        log "Use --force to overwrite" "ERROR"
        return 1
    fi
    
    # Create config directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"
    
    # Backup existing configuration
    backup_config "$config_file"
    
    # Generate the configuration file
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would create LDAP configuration file: $config_file" "INFO"
        log "Connection details: ldap://$host:$port" "INFO"
    else
        log "Creating LDAP configuration file: $config_file" "INFO"
        
        cat > "$config_file" << EOF
[ldap]
host = $host
port = $port
use_ssl = $ssl_enabled
search_base = $search_base
EOF

        if [[ -n "$bind_dn" && -n "$bind_password" ]]; then
            cat >> "$config_file" << EOF
bind_dn = $bind_dn
bind_password = $bind_password
EOF
        fi
        
        cat >> "$config_file" << EOF
user_object_class = ${LDAP_USER_OBJECT_CLASS:-person}
user_id_attribute = ${LDAP_USER_ID_ATTRIBUTE:-uid}
group_object_class = ${LDAP_GROUP_OBJECT_CLASS:-groupOfNames}
group_member_attribute = ${LDAP_GROUP_MEMBER_ATTRIBUTE:-member}
timeout = 10

[authentication]
enable_ldap_auth = true
admin_group = ${LDAP_ADMIN_GROUP:-cloud-platform-admins}
EOF
        
        # Set secure permissions
        chmod 640 "$config_file"
        
        log "LDAP configuration created successfully" "INFO"
    fi
    
    # Validate the connection
    if [[ "$VALIDATE" == "true" && "$DRY_RUN" != "true" ]]; then
        validate_ldap_connection "$host" "$port" "$bind_dn" "$bind_password"
    fi
    
    return 0
}

# Function to update app configuration to use the new connection
update_app_config() {
    local connection_type="$1"
    local config_file="$2"
    
    log "Updating application configuration to use $connection_type connection" "INFO"
    
    local app_config="${CONFIG_DIR}/app-${ENVIRONMENT}.ini"
    
    if [[ ! -f "$app_config" ]]; then
        log "Application configuration file not found: $app_config" "WARNING"
        log "Skipping application configuration update" "WARNING"
        return 1
    fi
    
    # Backup existing app configuration
    backup_config "$app_config"
    
    # Update configuration reference
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would update application configuration to use $connection_type connection" "INFO"
    else
        # Check if the connection section already exists
        if grep -q "^\[$connection_type\]" "$app_config"; then
            # Update existing section
            sed -i "/^\[$connection_type\]/,/^\[/ s|config_file = .*|config_file = $config_file|" "$app_config"
        else
            # Add new section
            echo "" >> "$app_config"
            echo "[$connection_type]" >> "$app_config"
            echo "config_file = $config_file" >> "$app_config"
        fi
        
        log "Application configuration updated to use $connection_type connection" "INFO"
    fi
    
    return 0
}

# Generate a connection string from the configuration
generate_connection_string() {
    local connection_type="$1"
    local host="${CONNECTION_HOST}"
    local port="${CONNECTION_PORT}"
    
    # Set default port if not provided
    if [[ -z "$port" ]]; then
        case "$connection_type" in
            database)
                if [[ "${DB_TYPE:-postgresql}" == "postgresql" ]]; then
                    port="5432"
                elif [[ "${DB_TYPE:-postgresql}" == "mysql" ]]; then
                    port="3306"
                fi
                ;;
            redis)
                port="6379"
                ;;
            rabbitmq)
                port="5672"
                ;;
            smtp)
                port="25"
                ;;
            ldap)
                port="389"
                ;;
        esac
    fi
    
    # Generate the connection string
    case "$connection_type" in
        database)
            if [[ "${DB_TYPE:-postgresql}" == "postgresql" ]]; then
                echo "postgresql://${CONNECTION_USERNAME:-}:***@$host:$port/${DB_NAME:-}"
            else
                echo "mysql://${CONNECTION_USERNAME:-}:***@$host:$port/${DB_NAME:-}"
            fi
            ;;
        redis)
            echo "redis://$host:$port"
            ;;
        rabbitmq)
            echo "amqp://${CONNECTION_USERNAME:-guest}:***@$host:$port/${RABBITMQ_VHOST:-/}"
            ;;
        monitoring)
            echo "${MONITORING_TYPE:-prometheus}://$host"
            ;;
        smtp)
            echo "smtp://$host:$port"
            ;;
        ldap)
            echo "ldap://$host:$port"
            ;;
        aws)
            echo "aws:${REGION:-us-west-2}"
            ;;
        azure)
            echo "azure:${REGION:-eastus}"
            ;;
        gcp)
            echo "gcp:${REGION:-us-central1}"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Log connection details to DR events system if enabled
log_dr_event() {
    local connection_type="$1"
    local config_file="$2"
    local status="$3"
    
    if [[ "$DR_MODE" == "true" ]]; then
        log "Logging connection configuration to DR events system" "INFO"
        
        # Create the log directory if it doesn't exist
        DR_LOG_DIR="/var/log/cloud-platform"
        mkdir -p "$DR_LOG_DIR"
        
        # Use ISO-8601 timestamp format for better parsing
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Generate a connection string
        local connection_string
        connection_string=$(generate_connection_string "$connection_type")
        
        # Log the event
        echo "$timestamp,CONNECTION_CONFIG,${ENVIRONMENT},${connection_type},$status,$connection_string" >> "$DR_LOG_DIR/dr-events.log"
        
        log "Connection event logged to DR events system" "INFO"
    fi
}

# Main execution flow based on connection type
main() {
    log "Starting connection configuration for $ENVIRONMENT environment" "INFO"
    log "Connection type: $CONNECTION_TYPE" "INFO"
    
    # Set appropriate config based on connection type
    local config_result=0
    
    case "$CONNECTION_TYPE" in
        database|postgresql|mysql)
            # Determine database type from connection type or default to postgresql
            if [[ "$CONNECTION_TYPE" == "mysql" ]]; then
                DB_TYPE="mysql"
            elif [[ "$CONNECTION_TYPE" == "postgresql" ]]; then
                DB_TYPE="postgresql"
            else
                DB_TYPE="${DB_TYPE:-postgresql}"
            fi
            
            configure_database "$DB_TYPE"
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "database" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "database" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "database" "$config_file" "SUCCESS"
            else
                log_dr_event "database" "$config_file" "FAILED"
            fi
            ;;
        redis)
            configure_redis
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "redis" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "redis" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "redis" "$config_file" "SUCCESS"
            else
                log_dr_event "redis" "$config_file" "FAILED"
            fi
            ;;
        rabbitmq)
            configure_rabbitmq
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "rabbitmq" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "messaging" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "rabbitmq" "$config_file" "SUCCESS"
            else
                log_dr_event "rabbitmq" "$config_file" "FAILED"
            fi
            ;;
        monitoring|prometheus|datadog|newrelic)
            # Determine monitoring type from connection type or default to prometheus
            if [[ "$CONNECTION_TYPE" == "prometheus" ]]; then
                MONITORING_TYPE="prometheus"
            elif [[ "$CONNECTION_TYPE" == "datadog" ]]; then
                MONITORING_TYPE="datadog"
            elif [[ "$CONNECTION_TYPE" == "newrelic" ]]; then
                MONITORING_TYPE="newrelic"
            else
                MONITORING_TYPE="${MONITORING_TYPE:-prometheus}"
            fi
            
            configure_monitoring
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "monitoring" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "monitoring" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "monitoring" "$config_file" "SUCCESS"
            else
                log_dr_event "monitoring" "$config_file" "FAILED"
            fi
            ;;
        aws|azure|gcp)
            configure_cloud_provider "$CONNECTION_TYPE"
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "$CONNECTION_TYPE" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "cloud" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "$CONNECTION_TYPE" "$config_file" "SUCCESS"
            else
                log_dr_event "$CONNECTION_TYPE" "$config_file" "FAILED"
            fi
            ;;
        smtp)
            configure_smtp
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "smtp" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "email" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "smtp" "$config_file" "SUCCESS"
            else
                log_dr_event "smtp" "$config_file" "FAILED"
            fi
            ;;
        ldap)
            configure_ldap
            config_result=$?
            
            # Get the config file path
            local config_file
            config_file="$(get_config_path "ldap" "${CONFIG_FILE:-}")"
            
            # Update app configuration
            if [[ $config_result -eq 0 && "$DRY_RUN" != "true" ]]; then
                update_app_config "authentication" "$config_file"
            fi
            
            # Log to DR events system if enabled
            if [[ $config_result -eq 0 ]]; then
                log_dr_event "ldap" "$config_file" "SUCCESS"
            else
                log_dr_event "ldap" "$config_file" "FAILED"
            fi
            ;;
        *)
            log "Unsupported connection type: $CONNECTION_TYPE" "ERROR"
            log "Valid connection types: database, postgresql, mysql, redis, rabbitmq, monitoring, prometheus, datadog, newrelic, aws, azure, gcp, smtp, ldap" "ERROR"
            exit 1
            ;;
    esac
    
    if [[ $config_result -eq 0 ]]; then
        log "Connection configuration completed successfully" "INFO"
        exit 0
    else
        log "Connection configuration failed" "ERROR"
        exit 1
    fi
}

# Call the main function
main