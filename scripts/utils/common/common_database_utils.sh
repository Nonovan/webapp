#!/bin/bash
# filepath: scripts/utils/common/common_database_utils.sh
# Database utility functions for Cloud Infrastructure Platform
# These functions provide database connectivity and query execution capabilities

# Check that this script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    exit 1
fi

# Script version information
DB_UTILS_VERSION="1.0.0"
DB_UTILS_DATE="2024-07-20"

# Get script version information
# Arguments:
#   None
# Returns:
#   Version string in format "version (date)"
get_db_utils_version() {
    echo "${DB_UTILS_VERSION} (${DB_UTILS_DATE})"
}

# Check if required functions are available
for func in command_exists log get_temp_file; do
    if ! type -t "$func" &>/dev/null; then
        echo "Required function $func not available. Make sure to source common_core_functions.sh first." >&2
        exit 1
    fi
done

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
#   $6 - Connection timeout in seconds (optional - defaults to 10)
# Returns: 0 if connection successful, 1 if not
check_postgres_connection() {
    local host="$1"
    local port="${2:-5432}"
    local db="${3:-postgres}"
    local user="${4:-postgres}"
    local password="${5:-}"
    local timeout="${6:-10}"

    # Validate host parameter
    if [[ -z "$host" ]]; then
        log "Missing required host parameter" "ERROR"
        return 1
    fi

    # Validate numeric parameters
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi

    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 1
    fi

    local connection_string="host=$host port=$port dbname=$db user=$user connect_timeout=$timeout"

    # Check if psql command exists
    if ! command_exists psql; then
        log "PostgreSQL client (psql) not installed" "ERROR"
        return 1
    fi

    # Use timeout command if available for added protection
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout $((timeout + 2))"
    fi

    # Use a more secure approach instead of eval
    if [[ -n "$password" ]]; then
        # Use environment variable for password
        if [[ -n "$timeout_cmd" ]]; then
            PGPASSWORD="$password" $timeout_cmd psql "$connection_string" -t -c "SELECT 1;" &>/dev/null
        else
            PGPASSWORD="$password" psql "$connection_string" -t -c "SELECT 1;" &>/dev/null
        fi
    else
        # Try without password (might use .pgpass or peer auth)
        if [[ -n "$timeout_cmd" ]]; then
            $timeout_cmd psql "$connection_string" -t -c "SELECT 1;" &>/dev/null
        else
            psql "$connection_string" -t -c "SELECT 1;" &>/dev/null
        fi
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
#   $6 - Connection timeout in seconds (optional - defaults to 10)
# Returns: 0 if connection successful, 1 if not
check_mysql_connection() {
    local host="$1"
    local port="${2:-3306}"
    local db="${3:-}"
    local user="${4:-root}"
    local password="${5:-}"
    local timeout="${6:-10}"

    # Validate host parameter
    if [[ -z "$host" ]]; then
        log "Missing required host parameter" "ERROR"
        return 1
    fi

    # Validate numeric parameters
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi

    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 1
    fi

    # Check if mysql command exists
    if ! command_exists mysql; then
        log "MySQL client not installed" "ERROR"
        return 1
    fi

    # Build mysql command with args array for better security
    local mysql_args=()
    mysql_args+=(-h "$host")
    mysql_args+=(-P "$port")
    mysql_args+=(-u "$user")
    mysql_args+=(--connect-timeout="$timeout")

    if [[ -n "$db" ]]; then
        mysql_args+=(-D "$db")
    fi

    # Use timeout command if available for added protection
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout $((timeout + 2))"
    fi

    # Execute mysql command safely without eval
    if [[ -n "$password" ]]; then
        # Use environment variable for password for better security
        if [[ -n "$timeout_cmd" ]]; then
            MYSQL_PWD="$password" $timeout_cmd mysql "${mysql_args[@]}" -e 'SELECT 1;' &>/dev/null
        else
            MYSQL_PWD="$password" mysql "${mysql_args[@]}" -e 'SELECT 1;' &>/dev/null
        fi
    else
        # Try without password
        if [[ -n "$timeout_cmd" ]]; then
            $timeout_cmd mysql "${mysql_args[@]}" -e 'SELECT 1;' &>/dev/null
        else
            mysql "${mysql_args[@]}" -e 'SELECT 1;' &>/dev/null
        fi
    fi

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
#   $7 - Query timeout in seconds (optional - defaults to 30)
# Returns: Query result or error message
pg_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-5432}"
    local password="${6:-}"
    local query_timeout="${7:-30}"

    # Validate required parameters
    if [[ -z "$query" ]]; then
        echo "ERROR: Missing required query parameter"
        return 1
    fi

    if [[ -z "$host" ]]; then
        echo "ERROR: Missing required host parameter"
        return 1
    fi

    if [[ -z "$db" ]]; then
        echo "ERROR: Missing required database parameter"
        return 1
    fi

    if [[ -z "$user" ]]; then
        echo "ERROR: Missing required user parameter"
        return 1
    fi

    # Validate numeric parameters
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Invalid port number: $port"
        return 1
    fi

    if ! [[ "$query_timeout" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Invalid query timeout value: $query_timeout"
        return 1
    fi

    local connection_string="host=$host port=$port dbname=$db user=$user"

    # Check if psql command exists
    if ! command_exists psql; then
        echo "ERROR: PostgreSQL client (psql) not installed"
        return 1
    fi

    # Set statement timeout to prevent long-running queries
    local psql_options="-v statement_timeout=${query_timeout}s"

    # Use temp file for output
    local temp_file
    temp_file=$(get_temp_file "pg_result") || {
        echo "ERROR: Could not create temporary file"
        return 1
    }

    # Use timeout command if available for added protection
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout $((query_timeout + 5))"
    fi

    # Execute query safely
    local result=0
    if [[ -n "$password" ]]; then
        if [[ -n "$timeout_cmd" ]]; then
            PGPASSWORD="$password" $timeout_cmd psql "$connection_string" $psql_options -t -c "$query" > "$temp_file" 2>&1
        else
            PGPASSWORD="$password" psql "$connection_string" $psql_options -t -c "$query" > "$temp_file" 2>&1
        fi
        result=$?
    else
        if [[ -n "$timeout_cmd" ]]; then
            $timeout_cmd psql "$connection_string" $psql_options -t -c "$query" > "$temp_file" 2>&1
        else
            psql "$connection_string" $psql_options -t -c "$query" > "$temp_file" 2>&1
        fi
        result=$?
    fi

    local output
    output=$(cat "$temp_file")
    rm -f "$temp_file"

    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi

    # Trim leading and trailing whitespace
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
#   $7 - Query timeout in seconds (optional - defaults to 30)
# Returns: Query result or error message
mysql_execute() {
    local query="$1"
    local host="$2"
    local db="$3"
    local user="$4"
    local port="${5:-3306}"
    local password="${6:-}"
    local query_timeout="${7:-30}"

    # Validate required parameters
    if [[ -z "$query" ]]; then
        echo "ERROR: Missing required query parameter"
        return 1
    fi

    if [[ -z "$host" ]]; then
        echo "ERROR: Missing required host parameter"
        return 1
    fi

    if [[ -z "$user" ]]; then
        echo "ERROR: Missing required user parameter"
        return 1
    fi

    # Validate numeric parameters
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Invalid port number: $port"
        return 1
    fi

    if ! [[ "$query_timeout" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Invalid query timeout value: $query_timeout"
        return 1
    fi

    # Build mysql command with args array for better security
    local mysql_args=()
    mysql_args+=(-h "$host")
    mysql_args+=(-P "$port")
    mysql_args+=(-u "$user")
    mysql_args+=(--connect-timeout=10)

    # Add timeout-related options
    mysql_args+=(--max-execution-time=$((query_timeout * 1000)))  # Convert to milliseconds

    if [[ -n "$db" ]]; then
        mysql_args+=(-D "$db")
    fi

    # Added -N to suppress column headers
    mysql_args+=(-N)

    # Check if mysql command exists
    if ! command_exists mysql; then
        echo "ERROR: MySQL client not installed"
        return 1
    fi

    # Use temp file for output
    local temp_file
    temp_file=$(get_temp_file "mysql_result") || {
        echo "ERROR: Could not create temporary file"
        return 1
    }

    # Use timeout command if available for added protection
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout $((query_timeout + 5))"
    fi

    # Execute query safely
    local result=0
    if [[ -n "$password" ]]; then
        if [[ -n "$timeout_cmd" ]]; then
            MYSQL_PWD="$password" $timeout_cmd mysql "${mysql_args[@]}" -e "$query" > "$temp_file" 2>&1
        else
            MYSQL_PWD="$password" mysql "${mysql_args[@]}" -e "$query" > "$temp_file" 2>&1
        fi
        result=$?
    else
        if [[ -n "$timeout_cmd" ]]; then
            $timeout_cmd mysql "${mysql_args[@]}" -e "$query" > "$temp_file" 2>&1
        else
            mysql "${mysql_args[@]}" -e "$query" > "$temp_file" 2>&1
        fi
        result=$?
    fi

    local output
    output=$(cat "$temp_file")
    rm -f "$temp_file"

    if [[ $result -ne 0 ]]; then
        echo "ERROR: $output"
        return 1
    fi

    echo "$output"
    return 0
}

# Check MongoDB connection
# Arguments:
#   $1 - Host
#   $2 - Port (optional - defaults to 27017)
#   $3 - Database (optional - defaults to admin)
#   $4 - User (optional)
#   $5 - Password (optional)
#   $6 - Connection timeout in seconds (optional - defaults to 10)
# Returns: 0 if connection successful, 1 if not
check_mongo_connection() {
    local host="$1"
    local port="${2:-27017}"
    local db="${3:-admin}"
    local user="$4"
    local password="$5"
    local timeout="${6:-10}"

    # Validate host parameter
    if [[ -z "$host" ]]; then
        log "Missing required host parameter" "ERROR"
        return 1
    fi

    # Validate numeric parameters
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log "Invalid port number: $port" "ERROR"
        return 1
    fi

    if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
        log "Invalid timeout value: $timeout" "ERROR"
        return 1
    fi

    # Check if mongo command exists
    if ! command_exists mongo && ! command_exists mongosh; then
        log "MongoDB client (mongo/mongosh) not installed" "ERROR"
        return 1
    fi

    # Determine which MongoDB client is available
    local mongo_cmd="mongo"
    if ! command_exists mongo && command_exists mongosh; then
        mongo_cmd="mongosh"
    fi

    # Build connection string
    local connection_string="mongodb://"
    if [[ -n "$user" && -n "$password" ]]; then
        connection_string+="${user}:${password}@"
    fi
    connection_string+="${host}:${port}/${db}"
    connection_string+="?connectTimeoutMS=$((timeout * 1000))"

    # Build command arguments
    local mongo_args=()
    mongo_args+=(--quiet)

    # MongoDB client version check
    if [[ "$mongo_cmd" == "mongosh" ]]; then
        mongo_args+=(--eval "db.serverStatus().ok")
    else
        mongo_args+=(--eval "db.serverStatus().ok" --norc)
    fi

    # Use timeout command if available for added protection
    local timeout_cmd=""
    if command_exists timeout; then
        timeout_cmd="timeout $((timeout + 2))"
    fi

    # Execute mongo command with proper arguments
    local result=0
    local output=""

    if [[ -n "$timeout_cmd" ]]; then
        output=$($timeout_cmd $mongo_cmd "$connection_string" "${mongo_args[@]}" 2>&1) || result=$?
    else
        output=$($mongo_cmd "$connection_string" "${mongo_args[@]}" 2>&1) || result=$?
    fi

    if [[ $result -eq 0 && "$output" == *1* ]]; then
        log "Successfully connected to MongoDB at $host:$port/$db${user:+ as $user}" "DEBUG"
        return 0
    else
        log "Failed to connect to MongoDB at $host:$port/$db${user:+ as $user}: ${output}" "DEBUG"
        return 1
    fi
}

# Export Database Functions
export -f check_postgres_connection
export -f check_mysql_connection
export -f pg_execute
export -f mysql_execute
export -f check_mongo_connection
