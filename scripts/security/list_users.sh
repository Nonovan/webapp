#!/bin/bash
# filepath: scripts/security/list_users.sh
# List Users Script
# Lists system users based on specified criteria, focusing on security aspects like roles and status.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform/security"
LOG_FILE="${LOG_DIR}/list_users.log"
DEFAULT_OUTPUT_FORMAT="table" # Options: table, json, csv
DEFAULT_LIMIT=100
VERBOSE=false
FLASK_CMD="flask" # Assumes 'flask' is in PATH and configured for the project
FALLBACK_TO_SYSTEM=false # Whether to fall back to system users if Flask fails

# --- Ensure Log Directory Exists ---
mkdir -p "$LOG_DIR"

# --- Logging Functions ---
# Source common utilities if available
COMMON_UTILS="${PROJECT_ROOT}/scripts/utils/common/common_logging_utils.sh"
if [[ -f "$COMMON_UTILS" ]]; then
    # shellcheck source=../utils/common/common_logging_utils.sh
    source "$COMMON_UTILS"
else
    # Basic logging functions if common utils are not found
    log() {
        local timestamp
        timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local level="${2:-INFO}"
        echo "[$timestamp] [$level] $1" | tee -a "$LOG_FILE"
    }
    log_info() { log "$1" "INFO"; }
    log_warn() { log "$1" "WARN"; }
    log_error() { log "$1" "ERROR"; }
    log_debug() { if [[ "$VERBOSE" == "true" ]]; then log "$1" "DEBUG"; fi }
fi

# --- Helper Functions ---
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Lists users based on specified criteria using the application's CLI."
    echo "Ensure the Flask environment is properly set up for the CLI to work."
    echo ""
    echo "Options:"
    echo "  --role ROLE           Filter users by role (e.g., admin, operator, user)"
    echo "  --status STATUS       Filter users by status (e.g., active, inactive, suspended)"
    echo "  --admins-only         Shortcut for --role=admin"
    echo "  --limit NUM           Maximum number of users to list (default: $DEFAULT_LIMIT)"
    echo "  --output-format FMT   Output format: table, json, csv (default: $DEFAULT_OUTPUT_FORMAT)"
    echo "  --fallback-to-system  Use system users if Flask CLI fails"
    echo "  --verbose, -v         Enable verbose logging"
    echo "  --help, -h            Display this help message"
    echo ""
    exit 0
}

command_exists() {
    command -v "$1" &> /dev/null
}

# Function to format system users according to the selected output format
format_system_users() {
    local format="$1"
    local filter_role="$2"
    local limit="$3"
    local users_data=""

    log_debug "Formatting system users with format: $format, filter: $filter_role, limit: $limit"

    # Get UID_MIN from /etc/login.defs or use default 1000
    local uid_min=1000
    if [[ -f "/etc/login.defs" ]]; then
        uid_min=$(grep -E "^UID_MIN" /etc/login.defs | awk '{print $2}')
        uid_min=${uid_min:-1000}
    fi

    log_debug "Using UID_MIN: $uid_min"

    # Collect user data based on filter
    # This section focuses on security-relevant users only
    if [[ "$filter_role" == "admin" ]]; then
        # Admin users (members of sudo or admin group, or UID 0)
        users_data=$(awk -F':' -v min="$uid_min" '
            BEGIN {
                # Load sudoers into array for reference
                cmd = "grep -v \"^#\" /etc/sudoers 2>/dev/null | grep -v \"^$\" | grep -E \"^[^%].*ALL\"";
                while ((cmd | getline line) > 0) {
                    if (line !~ /^Defaults/) {
                        split(line, parts, "[ \t]+");
                        if (parts[1]) { sudoers[parts[1]] = 1; }
                    }
                }
                close(cmd);
            }
            # Process password file
            {
                if (($3 == 0) || ($3 >= min && $3 != 65534)) {
                    username = $1;
                    # Check if root
                    if ($3 == 0) { role = "admin"; }
                    else {
                        # Check if user is in sudoers
                        if (username in sudoers) { role = "admin"; }
                        else { role = "user"; }
                    }
                    # Only include admins based on filter
                    if (role == "admin") {
                        uid = $3;
                        # Get last login time
                        cmd = "lastlog -u " username " 2>/dev/null | grep -v \"Never logged in\" | grep -v \"Username\" | awk \"{print \\$4, \\$5, \\$6, \\$7, \\$8}\"";
                        cmd | getline last_login;
                        if (!last_login) { last_login = "Never"; }
                        close(cmd);
                        print username ":" role ":" last_login ":" uid;
                    }
                }
            }
        ' /etc/passwd)
    else
        # All users with UID >= UID_MIN
        users_data=$(awk -F':' -v min="$uid_min" '
            BEGIN {
                # Load sudoers into array for reference
                cmd = "grep -v \"^#\" /etc/sudoers 2>/dev/null | grep -v \"^$\" | grep -E \"^[^%].*ALL\"";
                while ((cmd | getline line) > 0) {
                    if (line !~ /^Defaults/) {
                        split(line, parts, "[ \t]+");
                        if (parts[1]) { sudoers[parts[1]] = 1; }
                    }
                }
                close(cmd);
            }
            # Process password file
            {
                if (($3 == 0) || ($3 >= min && $3 != 65534)) {
                    username = $1;
                    # Check if root or in sudoers
                    if ($3 == 0 || username in sudoers) { role = "admin"; }
                    else { role = "user"; }
                    uid = $3;
                    # Get last login time
                    cmd = "lastlog -u " username " 2>/dev/null | grep -v \"Username\" | awk \"{print \\$4, \\$5, \\$6, \\$7, \\$8}\"";
                    cmd | getline last_login;
                    if (!last_login || last_login ~ /Never logged in/) { last_login = "Never"; }
                    close(cmd);
                    print username ":" role ":" last_login ":" uid;
                }
            }
        ' /etc/passwd)
    fi

    # Apply limit
    users_data=$(echo "$users_data" | head -n "$limit")

    # Format the output
    case "$format" in
        table)
            echo -e "\nSystem User List:"
            echo -e "  Username               Role       Last Login          UID"
            echo -e "  --------------------   --------   -----------------   -----"
            echo "$users_data" | while IFS=':' read -r username role last_login uid; do
                printf "  %-20s   %-8s   %-17s   %s\n" "$username" "$role" "$last_login" "$uid"
            done
            echo -e "\nTotal system users displayed: $(echo "$users_data" | wc -l)"
            ;;

        json)
            echo "{"
            echo "  \"users\": ["
            first=true
            echo "$users_data" | while IFS=':' read -r username role last_login uid; do
                if $first; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    {\"username\": \"$username\", \"role\": \"$role\", \"last_login\": \"$last_login\", \"uid\": $uid}"
            done
            echo ""
            echo "  ]"
            echo "}"
            ;;

        csv)
            echo "Username,Role,LastLogin,UID"
            echo "$users_data" | while IFS=':' read -r username role last_login uid; do
                echo "\"$username\",\"$role\",\"$last_login\",\"$uid\""
            done
            ;;
    esac
}

# --- Argument Parsing ---
FILTER_ROLE=""
FILTER_STATUS=""
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
LIMIT="$DEFAULT_LIMIT"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            shift
            FILTER_ROLE="$1"
            shift
            ;;
        --status)
            shift
            FILTER_STATUS="$1"
            shift
            ;;
        --admins-only)
            FILTER_ROLE="admin" # Override role filter
            shift
            ;;
        --limit)
            shift
            LIMIT="$1"
            shift
            ;;
        --output-format)
            shift
            OUTPUT_FORMAT="$1"
            shift
            ;;
        --fallback-to-system)
            FALLBACK_TO_SYSTEM=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate output format
case "$OUTPUT_FORMAT" in
    table|json|csv)
        ;;
    *)
        log_error "Invalid output format: $OUTPUT_FORMAT. Use 'table', 'json', or 'csv'."
        exit 1
        ;;
esac

# Validate limit
if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
    log_error "Invalid limit: $LIMIT. Must be a positive integer."
    exit 1
fi

# --- Main Logic ---
main() {
    log_info "Starting user listing..."
    log_debug "Role filter: '${FILTER_ROLE:-N/A}', Status filter: '${FILTER_STATUS:-N/A}', Format: $OUTPUT_FORMAT, Limit: $LIMIT"

    # Try Flask CLI first
    if command_exists "$FLASK_CMD"; then
        log_debug "Flask command found, attempting application user list"

        # Construct the Flask CLI command
        local cmd_args=("$FLASK_CMD" user list --limit "$LIMIT" --format "$OUTPUT_FORMAT")

        if [[ -n "$FILTER_ROLE" ]]; then
            cmd_args+=(--role "$FILTER_ROLE")
        fi

        if [[ -n "$FILTER_STATUS" ]]; then
            cmd_args+=(--status "$FILTER_STATUS")
        fi

        log_debug "Executing command: ${cmd_args[*]}"

        # Execute the command with error handling
        if output=$("${cmd_args[@]}" 2>&1); then
            # Success - output the results
            echo "$output"
            log_info "User listing complete."
            exit 0
        else
            log_warn "Failed to execute Flask command: ${cmd_args[*]}"
            log_warn "Error: $output"

            if [[ "$FALLBACK_TO_SYSTEM" != "true" ]]; then
                log_error "Ensure the application context is available and database is reachable."
                log_error "Use --fallback-to-system to fall back to system user listing if Flask fails."
                exit 1
            fi

            log_info "Falling back to system user listing..."
        fi
    else
        if [[ "$FALLBACK_TO_SYSTEM" != "true" ]]; then
            log_error "Flask command '$FLASK_CMD' not found. Ensure the virtual environment is active and Flask is installed."
            log_error "Use --fallback-to-system to fall back to system user listing if Flask is not available."
            exit 1
        fi

        log_info "Flask command not found, falling back to system user listing..."
    fi

    # Fallback: List system users if Flask failed or is not available and fallback is enabled
    if [[ "$FALLBACK_TO_SYSTEM" == "true" ]]; then
        log_info "Listing system users..."

        # Check if the required commands exist
        if ! command_exists "awk" || ! command_exists "lastlog"; then
            log_error "Required commands (awk, lastlog) not found. Cannot list system users."
            exit 1
        fi

        # Format system users according to the selected output format
        format_system_users "$OUTPUT_FORMAT" "$FILTER_ROLE" "$LIMIT"
        log_info "System user listing complete."
    fi

    exit 0
}

# --- Run Script ---
main "$@"
