#!/bin/bash
# Advanced utility functions for Cloud Infrastructure Platform
# These functions provide specialized capabilities for specific use cases

# Check that this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    exit 1
fi

# Check if required variables and functions are defined
if [[ -z "$SCRIPT_DIR" || ! $(type -t log) == "function" ]]; then
    echo "Warning: This module requires core_functions to be loaded first"
    exit 1
fi

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

# Export notification functions
export -f send_email_notification
export -f send_slack_notification
export -f send_notification

# Export string functions
export -f generate_random_string
export -f url_encode
export -f parse_json
export -f parse_ini_section
export -f yaml_to_json
export -f format_json

# Export database functions
export -f check_postgres_connection
export -f check_mysql_connection
export -f pg_execute
export -f mysql_execute
