#!/bin/bash
# filepath: scripts/security/access_review.sh
# Access Review Script
# Performs periodic reviews of user access rights, roles, and permissions
# against defined policies and identifies potential issues like dormant accounts,
# excessive privileges, or policy violations.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform/security"
LOG_FILE="${LOG_DIR}/access_review.log"
REPORT_DIR="${LOG_DIR}/reports"
REPORT_FILE="${REPORT_DIR}/access_review_report_$(date +%Y%m%d%H%M%S).txt"
DEFAULT_INACTIVITY_DAYS=90
DEFAULT_REVIEW_SCOPE="all" # Options: all, privileged, dormant, role, user, mfa, permissions
DEFAULT_OUTPUT_FORMAT="text" # Options: text, json, csv
EMAIL_REPORT=false
EMAIL_RECIPIENT=""
VERBOSE=false
AUTO_DISABLE=false # Flag to automatically disable dormant accounts (use with caution)
AUDIT_LOG_FILE="${REPORT_DIR}/access_review_audit.log"
EXIT_ON_FAIL=false
RISK_ASSESSMENT=false
CONFIG_FILE="${PROJECT_ROOT}/config/security/access_review.conf"
POLICY_FILE="${PROJECT_ROOT}/config/security/user_access_policy.json"
APPROVAL_REQUIRED=false
APPROVER=""
DRY_RUN=false
MFA_CHECK=false
PERMISSION_AUDIT=false
NOTIFICATION_CHANNEL="" # Options: email, slack, webhook

# --- Ensure Directories Exist ---
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

# --- Source Common Utils if Available ---
COMMON_UTILS="${PROJECT_ROOT}/scripts/utils/common/common_logging_utils.sh"
if [[ -f "$COMMON_UTILS" ]]; then
    # shellcheck source=../utils/common/common_logging_utils.sh
    source "$COMMON_UTILS"
else
    # --- Logging Functions ---
    log() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local level="${2:-INFO}"
        echo "[$timestamp] [$level] $1" | tee -a "$LOG_FILE"
    }

    log_verbose() {
        if [[ "$VERBOSE" == "true" ]]; then
            log "$1" "DEBUG"
        fi
    }

    log_error() {
        log "$1" "ERROR"
    }

    log_warn() {
        log "$1" "WARNING"
    }

    log_audit() {
        local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
        local user=$(whoami)
        local action="$1"
        local target="$2"
        local details="${3:-}"
        echo "[$timestamp] AUDIT user=$user action=$action target=$target details=\"$details\"" >> "$AUDIT_LOG_FILE"
    }
fi

# --- Helper Functions ---
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Performs access reviews based on specified criteria."
    echo ""
    echo "Options:"
    echo "  --scope SCOPE         Review scope: all, privileged, dormant, role=<role_name>, user=<username>,"
    echo "                        mfa, permissions (default: $DEFAULT_REVIEW_SCOPE)"
    echo "  --inactive-days DAYS  Define inactivity period in days for dormant check (default: $DEFAULT_INACTIVITY_DAYS)"
    echo "  --output-format FMT   Output format: text, json, csv (default: $DEFAULT_OUTPUT_FORMAT)"
    echo "  --email RECIPIENT     Email the report to the specified recipient"
    echo "  --auto-disable        Automatically disable accounts identified as dormant (USE WITH CAUTION)"
    echo "  --exit-on-fail        Exit with non-zero code if issues found"
    echo "  --approve-action      Require approval for automated actions (requires --approver)"
    echo "  --approver EMAIL      Email of person approving automated actions"
    echo "  --dry-run             Show what would be done without making changes"
    echo "  --check-mfa           Check for users without MFA enabled"
    echo "  --audit-permissions   Perform detailed permission audit against policy"
    echo "  --policy-file FILE    Use specific policy file (default: $POLICY_FILE)"
    echo "  --notify CHANNEL      Send notifications to: email, slack, webhook"
    echo "  --risk-assessment     Include risk assessment in report"
    echo "  --config FILE         Use a specific config file (default: $CONFIG_FILE)"
    echo "  --verbose, -v         Enable verbose logging"
    echo "  --help, -h            Display this help message"
    echo ""
    exit 0
}

# Check if a command exists on the system
command_exists() {
    command -v "$1" &> /dev/null
}

# Load configuration from file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_verbose "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    else
        log_verbose "Config file not found, using default settings"
    fi
}

# Validate email format
validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        return 1
    fi
    return 0
}

# Check user access to API or CLI
check_api_access() {
    log_verbose "Checking API access"

    # Check if authentication credentials are available
    if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
        if FLASK_APP="${PROJECT_ROOT}/app.py" flask auth check-credentials &>/dev/null; then
            log_verbose "API access confirmed"
            return 0
        fi
    fi

    log_warn "No API access available, falling back to local system data"
    return 1
}

# Send notification via configured channel
send_notification() {
    local subject="$1"
    local message="$2"
    local channel="${3:-$NOTIFICATION_CHANNEL}"

    case "$channel" in
        email)
            if [[ -n "$EMAIL_RECIPIENT" ]]; then
                if command_exists mail; then
                    echo "$message" | mail -s "$subject" "$EMAIL_RECIPIENT"
                    log_verbose "Notification email sent to $EMAIL_RECIPIENT"
                    return 0
                else
                    log_error "mail command not found, can't send notification"
                    return 1
                fi
            fi
            ;;
        slack)
            if command_exists curl && [[ -f "${PROJECT_ROOT}/config/slack_webhook.conf" ]]; then
                local webhook_url
                webhook_url=$(grep "^webhook_url=" "${PROJECT_ROOT}/config/slack_webhook.conf" | cut -d= -f2)
                if [[ -n "$webhook_url" ]]; then
                    local payload="{\"text\":\"$subject\n$message\"}"
                    curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$webhook_url" &>/dev/null
                    log_verbose "Slack notification sent"
                    return 0
                fi
            fi
            ;;
        webhook)
            if command_exists curl && [[ -f "${PROJECT_ROOT}/config/notification_webhook.conf" ]]; then
                local webhook_url
                webhook_url=$(grep "^webhook_url=" "${PROJECT_ROOT}/config/notification_webhook.conf" | cut -d= -f2)
                if [[ -n "$webhook_url" ]]; then
                    local payload="{\"subject\":\"$subject\",\"message\":\"$message\"}"
                    curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$webhook_url" &>/dev/null
                    log_verbose "Webhook notification sent"
                    return 0
                fi
            fi
            ;;
    esac

    log_warn "No notification channel configured or notification failed"
    return 1
}

# --- Argument Parsing ---
REVIEW_SCOPE="$DEFAULT_REVIEW_SCOPE"
INACTIVITY_DAYS="$DEFAULT_INACTIVITY_DAYS"
OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
SPECIFIC_TARGET="" # Used for role=<role> or user=<user>

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scope)
            shift
            if [[ "$1" == role=* || "$1" == user=* ]]; then
                REVIEW_SCOPE=$(echo "$1" | cut -d'=' -f1)
                SPECIFIC_TARGET=$(echo "$1" | cut -d'=' -f2)
            else
                REVIEW_SCOPE="$1"
            fi
            shift
            ;;
        --inactive-days)
            shift
            INACTIVITY_DAYS="$1"
            shift
            ;;
        --output-format)
            shift
            OUTPUT_FORMAT="$1"
            shift
            ;;
        --email)
            shift
            EMAIL_REPORT=true
            EMAIL_RECIPIENT="$1"
            shift
            ;;
        --auto-disable)
            AUTO_DISABLE=true
            shift
            ;;
        --exit-on-fail)
            EXIT_ON_FAIL=true
            shift
            ;;
        --approve-action)
            APPROVAL_REQUIRED=true
            shift
            ;;
        --approver)
            shift
            APPROVER="$1"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --check-mfa)
            MFA_CHECK=true
            shift
            ;;
        --audit-permissions)
            PERMISSION_AUDIT=true
            shift
            ;;
        --policy-file)
            shift
            POLICY_FILE="$1"
            shift
            ;;
        --notify)
            shift
            NOTIFICATION_CHANNEL="$1"
            shift
            ;;
        --risk-assessment)
            RISK_ASSESSMENT=true
            shift
            ;;
        --config)
            shift
            CONFIG_FILE="$1"
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

# Load config after parsing args so command line takes precedence
load_config

# --- Validation ---

# Validate scope
case "$REVIEW_SCOPE" in
    all|privileged|dormant|role|user|mfa|permissions)
        ;;
    *)
        log_error "Invalid scope: $REVIEW_SCOPE. Use 'all', 'privileged', 'dormant', 'role=<role_name>', 'user=<username>', 'mfa', or 'permissions'."
        exit 1
        ;;
esac

# Validate output format
case "$OUTPUT_FORMAT" in
    text|json|csv)
        ;;
    *)
        log_error "Invalid output format: $OUTPUT_FORMAT. Use 'text', 'json', or 'csv'."
        exit 1
        ;;
esac

# Validate inactivity days
if ! [[ "$INACTIVITY_DAYS" =~ ^[0-9]+$ ]]; then
    log_error "Invalid inactivity days: $INACTIVITY_DAYS. Must be a positive integer."
    exit 1
fi

# Validate approval requirements
if [[ "$APPROVAL_REQUIRED" == "true" ]]; then
    if [[ -z "$APPROVER" ]]; then
        log_error "Approver required when using --approve-action. Use --approver EMAIL."
        exit 1
    fi
    validate_email "$APPROVER" || exit 1
fi

# Validate email recipient if specified
if [[ "$EMAIL_REPORT" == "true" && -n "$EMAIL_RECIPIENT" ]]; then
    validate_email "$EMAIL_RECIPIENT" || exit 1
fi

# Validate policy file if specified for permissions audit
if [[ "$PERMISSION_AUDIT" == "true" && ! -f "$POLICY_FILE" ]]; then
    log_error "Policy file not found: $POLICY_FILE"
    exit 1
fi

# --- Core Review Functions ---

# Get list of users based on scope
get_user_list() {
    log_verbose "Fetching user list based on scope: $REVIEW_SCOPE, target: $SPECIFIC_TARGET"

    # If API access is available, use it for more complete data
    if check_api_access; then
        # Export user data from the application's CLI interface
        if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
            log_verbose "Using Flask CLI to fetch user data"

            local args=""
            case "$REVIEW_SCOPE" in
                privileged)
                    args="--privileged-only"
                    ;;
                role)
                    args="--role=$SPECIFIC_TARGET"
                    ;;
                user)
                    args="--username=$SPECIFIC_TARGET"
                    ;;
                mfa)
                    args="--mfa-status"
                    ;;
                permissions)
                    args="--with-permissions"
                    ;;
            esac

            # Using process substitution to capture output
            FLASK_APP="${PROJECT_ROOT}/app.py" flask users list --format=csv $args 2>/dev/null | tail -n +2 | \
                awk -F, '{print $1":"$2":"$3":"$4}' || {
                log_warn "Failed to get users from Flask CLI, falling back to system users"
                get_system_users
            }
            return
        fi
    fi

    # Fallback to system users if no API access
    get_system_users
}

# Get users from the local system
get_system_users() {
    log_verbose "Fetching users from local system"

    # Get UID_MIN from login.defs if it exists
    local uid_min=1000
    if [[ -f "/etc/login.defs" ]]; then
        uid_min=$(grep "^UID_MIN" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo 1000)
    fi

    case "$REVIEW_SCOPE" in
        privileged)
            # Filter for root or sudo users
            awk -F':' -v min="$uid_min" '
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
                    if (($3 == 0) || ($3 in sudoers)) {
                        username = $1;
                        # Check if root or in sudoers
                        if ($3 == 0) { role = "admin"; }
                        else if (username in sudoers) { role = "admin"; }
                        else { next; } # Skip non-privileged

                        # Get last login time
                        cmd = "lastlog -u " username " 2>/dev/null | grep -v \"Never logged in\" | grep -v \"Username\" | awk \"{print \\$4, \\$5, \\$6, \\$7, \\$8}\"";
                        cmd | getline last_login;
                        if (!last_login) { last_login = "Never"; }
                        close(cmd);

                        # Get MFA status if possible
                        mfa_status = "unknown";
                        if (system("test -f /home/" username "/.google_authenticator") == 0) {
                            mfa_status = "enabled";
                        } else {
                            mfa_status = "disabled";
                        }
                        print username ":" role ":" last_login ":" mfa_status;
                    }
                }
            ' /etc/passwd
            ;;
        *)
            # All users with UID >= UID_MIN
            awk -F':' -v min="$uid_min" '
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
                        if ($3 == 0) { role = "admin"; }
                        else if (username in sudoers) { role = "admin"; }
                        else { role = "user"; }

                        # Apply user filter if requested
                        if (ENVIRON["REVIEW_SCOPE"] == "user" && username != ENVIRON["SPECIFIC_TARGET"]) {
                            next;
                        }

                        # Apply role filter if requested
                        if (ENVIRON["REVIEW_SCOPE"] == "role") {
                            if ((ENVIRON["SPECIFIC_TARGET"] == "admin" && role != "admin") ||
                                (ENVIRON["SPECIFIC_TARGET"] != "admin" && role == "admin")) {
                                next;
                            }
                        }

                        # Get last login time
                        cmd = "lastlog -u " username " 2>/dev/null | grep -v \"Never logged in\" | grep -v \"Username\" | awk \"{print \\$4, \\$5, \\$6, \\$7, \\$8}\"";
                        cmd | getline last_login;
                        if (!last_login) { last_login = "Never"; }
                        close(cmd);

                        # Get MFA status if possible
                        mfa_status = "unknown";
                        if (system("test -f /home/" username "/.google_authenticator") == 0) {
                            mfa_status = "enabled";
                        } else {
                            mfa_status = "disabled";
                        }
                        print username ":" role ":" last_login ":" mfa_status;
                    }
                }
            ' /etc/passwd
            ;;
    esac
}

# Check if user has privileges beyond the baseline
check_privileges() {
    local user="$1"
    log_verbose "Checking privileges for user: $user"

    # Try to use API for richer data if available
    if check_api_access; then
        if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
            local privilege_level
            privilege_level=$(FLASK_APP="${PROJECT_ROOT}/app.py" flask users check-privileges --username="$user" 2>/dev/null || echo "standard")
            echo "$privilege_level"
            return
        fi
    fi

    # Fallback to checking local system
    if [[ "$user" == "root" ]] || id -nG "$user" 2>/dev/null | grep -qw "sudo"; then
        echo "privileged"
    elif grep -q "^$user" /etc/sudoers 2>/dev/null; then
        echo "privileged"
    else
        echo "standard"
    fi
}

# Check MFA status for a user
check_mfa_status() {
    local user="$1"
    log_verbose "Checking MFA status for user: $user"

    # Try to use API for accurate data if available
    if check_api_access; then
        if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
            local mfa_status
            mfa_status=$(FLASK_APP="${PROJECT_ROOT}/app.py" flask users mfa-status --username="$user" 2>/dev/null || echo "unknown")
            echo "$mfa_status"
            return
        fi
    fi

    # Fallback to checking local system for common MFA indicators
    if [[ -f "/home/$user/.google_authenticator" ]]; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

# Check user permissions against policy
check_permissions() {
    local user="$1"
    local role="$2"
    log_verbose "Checking permissions for user: $user, role: $role"

    # Skip if no policy file specified or it doesn't exist
    if [[ ! -f "$POLICY_FILE" ]]; then
        echo "policy_undefined"
        return
    fi

    # Try to use API for accurate data if available
    if check_api_access; then
        if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
            local permissions_status
            permissions_status=$(FLASK_APP="${PROJECT_ROOT}/app.py" flask users check-policy --username="$user" --policy-file="$POLICY_FILE" 2>/dev/null || echo "unknown")
            echo "$permissions_status"
            return
        fi
    fi

    # Fallback to policy + role check
    if [[ "$role" == "admin" ]]; then
        # Check if admin role is compliant with policy
        if grep -q "\"admin_allowed\": *true" "$POLICY_FILE" 2>/dev/null; then
            echo "compliant"
        else
            echo "non_compliant"
        fi
    else
        # Basic user role is generally compliant
        echo "compliant"
    fi
}

# Disable a user account with proper audit logging
disable_user_account() {
    local user="$1"
    local reason="$2"
    log "Disabling dormant user account: $user" "WARN"

    # Audit logging for the action
    log_audit "disable_account" "$user" "$reason"

    # Skip actual changes in dry run mode
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY-RUN: Would disable user account: $user"
        echo "DRY-RUN: Account $user would be disabled." >> "$REPORT_FILE"
        return 0
    fi

    # Handle approval requirements
    if [[ "$APPROVAL_REQUIRED" == "true" ]]; then
        if ! request_approval "disable user $user" "$APPROVER"; then
            log "Account disable action was not approved for user: $user"
            echo "Account disable action was not approved for user: $user" >> "$REPORT_FILE"
            return 1
        fi
    fi

    # Try to use API if available
    if check_api_access; then
        if command_exists flask && [[ -f "${PROJECT_ROOT}/app.py" ]]; then
            if FLASK_APP="${PROJECT_ROOT}/app.py" flask users disable --username="$user" --reason="$reason" &>/dev/null; then
                log "Successfully disabled account $user using API"
                echo "Account $user disabled." >> "$REPORT_FILE"
                return 0
            fi
        fi
    fi

    # Fallback to system commands
    if passwd -l "$user" &>/dev/null; then
        log "Successfully disabled account $user using passwd command"
        echo "Account $user disabled." >> "$REPORT_FILE"
        return 0
    else
        log_error "Failed to disable account $user"
        echo "Failed to disable account $user." >> "$REPORT_FILE"
        return 1
    fi
}

# Request approval for sensitive actions
request_approval() {
    local action="$1"
    local approver="$2"
    log_verbose "Requesting approval for action: $action from $approver"

    # Generate unique token for this approval request
    local token
    token=$(date +%s | sha256sum | base64 | head -c 12)
    local approval_file="/tmp/approval_request_${token}.json"

    # Create approval request file
    cat > "$approval_file" <<EOF
{
  "action": "$action",
  "requestor": "$(whoami)",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "approver": "$approver",
  "token": "$token",
  "expires": "$(date -d '+1 hour' -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

    # Send approval request notification
    send_notification "Approval Required: $action" "Please approve action: $action\nRequestor: $(whoami)\nTimestamp: $(date)\nApprove by replying with token: $token" "email"

    log "Approval request sent to $approver. Waiting for response..."

    # In a production system, this would integrate with an approval system
    # For this script, we'll simulate manual approval
    read -p "Has approval been granted? (yes/no): " approval_response

    # Remove temp file
    rm -f "$approval_file"

    # Process response
    if [[ "$approval_response" == "yes" ]]; then
        log "Action approved: $action"
        return 0
    else
        log "Action rejected: $action"
        return 1
    fi
}

# Perform risk assessment based on user status
assess_risk() {
    local user="$1"
    local role="$2"
    local last_login="$3"
    local mfa_status="$4"
    log_verbose "Performing risk assessment for user: $user"

    local risk_score=0
    local risk_factors=()

    # Factor 1: Role privilege
    if [[ "$role" == "admin" ]]; then
        ((risk_score+=3))
        risk_factors+=("Administrative privileges")
    fi

    # Factor 2: Login recency
    if [[ "$last_login" == "Never" ]]; then
        ((risk_score+=2))
        risk_factors+=("Account never used")
    elif [[ "$last_login" != "N/A" ]]; then
        # Check if login is older than 30 days but not dormant
        local last_login_sec
        local current_sec
        last_login_sec=$(date -d "$last_login" +%s 2>/dev/null || echo 0)
        current_sec=$(date +%s)

        if [[ "$last_login_sec" -ne 0 ]]; then
            local days_since_login
            days_since_login=$(( (current_sec - last_login_sec) / 86400 ))

            if [[ "$days_since_login" -gt 30 && "$days_since_login" -lt "$INACTIVITY_DAYS" ]]; then
                ((risk_score+=1))
                risk_factors+=("Low login frequency (${days_since_login} days)")
            fi
        fi
    fi

    # Factor 3: MFA Status
    if [[ "$mfa_status" == "disabled" ]]; then
        ((risk_score+=2))
        risk_factors+=("MFA not enabled")
    elif [[ "$mfa_status" == "unknown" ]]; then
        ((risk_score+=1))
        risk_factors+=("MFA status unknown")
    fi

    # Calculate risk level based on score
    local risk_level
    if [[ "$risk_score" -ge 5 ]]; then
        risk_level="HIGH"
    elif [[ "$risk_score" -ge 3 ]]; then
        risk_level="MEDIUM"
    else
        risk_level="LOW"
    fi

    # Return risk assessment data
    echo "$risk_level:$risk_score:${risk_factors[*]}"
}

# --- Report Generation ---
generate_report_header() {
    log_verbose "Generating report header for format: $OUTPUT_FORMAT"
    case "$OUTPUT_FORMAT" in
        text)
            echo "Access Review Report - $(date)" > "$REPORT_FILE"
            echo "Scope: $REVIEW_SCOPE" >> "$REPORT_FILE"
            if [[ -n "$SPECIFIC_TARGET" ]]; then
                echo "Target: $SPECIFIC_TARGET" >> "$REPORT_FILE"
            fi
            echo "Inactivity Threshold: $INACTIVITY_DAYS days" >> "$REPORT_FILE"
            echo "--------------------------------------------------" >> "$REPORT_FILE"

            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                printf "%-20s %-15s %-15s %-15s %-10s %-s\n" "User" "Role" "Last Login" "MFA Status" "Risk" "Notes" >> "$REPORT_FILE"
            else
                printf "%-20s %-15s %-15s %-15s %-s\n" "User" "Role" "Last Login" "Status" "Notes" >> "$REPORT_FILE"
            fi

            echo "--------------------------------------------------" >> "$REPORT_FILE"
            ;;
        json)
            echo "{" > "$REPORT_FILE"
            echo "  \"report_metadata\": {" >> "$REPORT_FILE"
            echo "    \"report_time\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
            echo "    \"scope\": \"$REVIEW_SCOPE\"," >> "$REPORT_FILE"
            if [[ -n "$SPECIFIC_TARGET" ]]; then
                echo "    \"target\": \"$SPECIFIC_TARGET\"," >> "$REPORT_FILE"
            fi
            echo "    \"inactivity_threshold_days\": $INACTIVITY_DAYS," >> "$REPORT_FILE"
            echo "    \"risk_assessment\": $RISK_ASSESSMENT" >> "$REPORT_FILE"
            echo "  }," >> "$REPORT_FILE"
            echo "  \"users\": [" >> "$REPORT_FILE"
            ;;
        csv)
            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                echo "User,Role,LastLogin,MFAStatus,Status,RiskLevel,RiskFactors,Notes" > "$REPORT_FILE"
            else
                echo "User,Role,LastLogin,MFAStatus,Status,Notes" > "$REPORT_FILE"
            fi
            ;;
    esac
}

add_report_entry() {
    local user="$1"
    local role="$2"
    local last_login="$3"
    local mfa_status="$4"
    local status="$5"
    local notes="$6"
    local risk_data="${7:-}"

    log_verbose "Adding report entry for user: $user, status: $status"

    # Parse risk data if available
    local risk_level=""
    local risk_score=""
    local risk_factors=""

    if [[ -n "$risk_data" && "$risk_data" != ":" ]]; then
        IFS=':' read -r risk_level risk_score risk_factors <<< "$risk_data"
    fi

    case "$OUTPUT_FORMAT" in
        text)
            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                printf "%-20s %-15s %-15s %-15s %-10s %-s\n" \
                    "$user" "$role" "$last_login" "$mfa_status" "$risk_level" "$notes" >> "$REPORT_FILE"
            else
                printf "%-20s %-15s %-15s %-15s %-s\n" \
                    "$user" "$role" "$last_login" "$status" "$notes" >> "$REPORT_FILE"
            fi
            ;;
        json)
            # Add comma if not the first entry
            if [[ $(wc -l < "$REPORT_FILE") -gt 7 ]]; then # Check if more than header lines exist
                 # Check if the last line is not the start of the users array
                 if ! tail -n 1 "$REPORT_FILE" | grep -q '\"users\": \['; then
                    sed -i '$ s/$/\,/' "$REPORT_FILE" # Add comma to previous line
                 fi
            fi
            echo "    {" >> "$REPORT_FILE"
            echo "      \"user\": \"$user\"," >> "$REPORT_FILE"
            echo "      \"role\": \"$role\"," >> "$REPORT_FILE"
            echo "      \"last_login\": \"$last_login\"," >> "$REPORT_FILE"
            echo "      \"mfa_status\": \"$mfa_status\"," >> "$REPORT_FILE"
            echo "      \"status\": \"$status\"," >> "$REPORT_FILE"

            if [[ "$RISK_ASSESSMENT" == "true" && -n "$risk_level" ]]; then
                echo "      \"risk\": {" >> "$REPORT_FILE"
                echo "        \"level\": \"$risk_level\"," >> "$REPORT_FILE"
                echo "        \"score\": $risk_score," >> "$REPORT_FILE"
                echo "        \"factors\": \"$risk_factors\"" >> "$REPORT_FILE"
                echo "      }," >> "$REPORT_FILE"
            fi

            echo "      \"notes\": \"$notes\"" >> "$REPORT_FILE"
            echo "    }" >> "$REPORT_FILE"
            ;;
        csv)
            # Escape commas in notes and risk factors if necessary
            notes_escaped=$(echo "$notes" | sed 's/,/;/g')
            risk_factors_escaped=$(echo "$risk_factors" | sed 's/,/;/g')

            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                echo "$user,$role,$last_login,$mfa_status,$status,$risk_level,\"$risk_factors_escaped\",\"$notes_escaped\"" >> "$REPORT_FILE"
            else
                echo "$user,$role,$last_login,$mfa_status,$status,\"$notes_escaped\"" >> "$REPORT_FILE"
            fi
            ;;
    esac
}

add_summary_to_report() {
    local user_count="$1"
    local issue_count="$2"
    local dormant_count="$3"
    local disabled_count="$4"
    local mfa_disabled_count="$5"
    local permission_issues_count="$6"
    local high_risk_count="$7"

    log_verbose "Adding summary to report"

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Summary:" >> "$REPORT_FILE"
            echo "-------------------" >> "$REPORT_FILE"
            echo "Total Users:           $user_count" >> "$REPORT_FILE"
            echo "Total Issues:          $issue_count" >> "$REPORT_FILE"
            echo "Dormant Accounts:      $dormant_count" >> "$REPORT_FILE"
            if [[ "$AUTO_DISABLE" == "true" ]]; then
                echo "Disabled Accounts:     $disabled_count" >> "$REPORT_FILE"
            fi
            if [[ "$MFA_CHECK" == "true" ]]; then
                echo "MFA Disabled:          $mfa_disabled_count" >> "$REPORT_FILE"
            fi
            if [[ "$PERMISSION_AUDIT" == "true" ]]; then
                echo "Permission Issues:     $permission_issues_count" >> "$REPORT_FILE"
            fi
            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                echo "High Risk Accounts:    $high_risk_count" >> "$REPORT_FILE"
            fi
            ;;
        json)
            # First close the users array
            echo "  ]," >> "$REPORT_FILE"
            # Add summary object
            echo "  \"summary\": {" >> "$REPORT_FILE"
            echo "    \"total_users\": $user_count," >> "$REPORT_FILE"
            echo "    \"total_issues\": $issue_count," >> "$REPORT_FILE"
            echo "    \"dormant_accounts\": $dormant_count," >> "$REPORT_FILE"
            if [[ "$AUTO_DISABLE" == "true" ]]; then
                echo "    \"disabled_accounts\": $disabled_count," >> "$REPORT_FILE"
            fi
            if [[ "$MFA_CHECK" == "true" ]]; then
                echo "    \"mfa_disabled\": $mfa_disabled_count," >> "$REPORT_FILE"
            fi
            if [[ "$PERMISSION_AUDIT" == "true" ]]; then
                echo "    \"permission_issues\": $permission_issues_count," >> "$REPORT_FILE"
            fi
            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                echo "    \"high_risk_accounts\": $high_risk_count," >> "$REPORT_FILE"
            fi
            # Remove trailing comma from last item
            sed -i '$ s/,$//' "$REPORT_FILE"
            echo "  }" >> "$REPORT_FILE"
            ;;
        csv)
            echo "" >> "$REPORT_FILE"
            echo "SummaryType,Value" >> "$REPORT_FILE"
            echo "Total Users,$user_count" >> "$REPORT_FILE"
            echo "Total Issues,$issue_count" >> "$REPORT_FILE"
            echo "Dormant Accounts,$dormant_count" >> "$REPORT_FILE"
            if [[ "$AUTO_DISABLE" == "true" ]]; then
                echo "Disabled Accounts,$disabled_count" >> "$REPORT_FILE"
            fi
            if [[ "$MFA_CHECK" == "true" ]]; then
                echo "MFA Disabled,$mfa_disabled_count" >> "$REPORT_FILE"
            fi
            if [[ "$PERMISSION_AUDIT" == "true" ]]; then
                echo "Permission Issues,$permission_issues_count" >> "$REPORT_FILE"
            fi
            if [[ "$RISK_ASSESSMENT" == "true" ]]; then
                echo "High Risk Accounts,$high_risk_count" >> "$REPORT_FILE"
            fi
            ;;
    esac
}

generate_report_footer() {
    log_verbose "Generating report footer for format: $OUTPUT_FORMAT"
    case "$OUTPUT_FORMAT" in
        text)
            echo "--------------------------------------------------" >> "$REPORT_FILE"
            echo "Review Complete: $(date)" >> "$REPORT_FILE"
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "NOTE: This report was generated in dry-run mode. No accounts were actually disabled." >> "$REPORT_FILE"
            fi
            ;;
        json)
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "," >> "$REPORT_FILE"
                echo "  \"dry_run\": true" >> "$REPORT_FILE"
            fi
            echo "}" >> "$REPORT_FILE"
            ;;
        csv)
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "" >> "$REPORT_FILE"
                echo "Note,\"This report was generated in dry-run mode. No accounts were actually disabled.\"" >> "$REPORT_FILE"
            fi
            ;;
    esac
}

# --- Email Report ---
email_report() {
    if [[ "$EMAIL_REPORT" == "true" ]]; then
        if [[ -z "$EMAIL_RECIPIENT" ]]; then
            log_error "Email recipient not specified. Use --email <recipient>."
            return 1
        fi
        log "Emailing report to $EMAIL_RECIPIENT"
        local subject="Access Review Report - $(date)"

        # Add environment info and issue counts to subject
        if [[ "$issue_count" -gt 0 ]]; then
            subject="[ISSUES: $issue_count] $subject"
        fi

        # Check for mail command availability
        if command_exists mail; then
            # Check for attachment capability in mail command
            if mail --help 2>&1 | grep -q -- "-a"; then
                # Support for attachments
                if [[ "$OUTPUT_FORMAT" == "csv" || "$OUTPUT_FORMAT" == "json" ]]; then
                    echo "Please find the access review report attached." | \
                    mail -s "$subject" -a "$REPORT_FILE" "$EMAIL_RECIPIENT"
                else
                    mail -s "$subject" "$EMAIL_RECIPIENT" < "$REPORT_FILE"
                fi
            else
                # No attachment support, send as email body
                mail -s "$subject" "$EMAIL_RECIPIENT" < "$REPORT_FILE"
            fi
            log "Report emailed successfully."
        elif command_exists sendmail; then
            (echo "Subject: $subject"; echo "To: $EMAIL_RECIPIENT"; echo "Content-Type: text/plain"; echo ""; cat "$REPORT_FILE") | sendmail -t
            log "Report emailed successfully using sendmail."
        elif command_exists mutt; then
            echo | mutt -s "$subject" "$EMAIL_RECIPIENT" -a "$REPORT_FILE"
            log "Report emailed successfully using mutt."
        else
            log_error "'mail' command not found. Cannot email report."
            return 1
        fi
    fi
}

# --- Main Logic ---
main() {
    log "Starting access review..."
    log "Scope: $REVIEW_SCOPE, Target: ${SPECIFIC_TARGET:-N/A}, Inactivity Threshold: $INACTIVITY_DAYS days"
    log "Report will be saved to: $REPORT_FILE"

    # Create empty audit log if it doesn't exist
    touch "$AUDIT_LOG_FILE"
    chmod 600 "$AUDIT_LOG_FILE"

    # Log initial audit entry
    log_audit "access_review_started" "$REVIEW_SCOPE" "target=${SPECIFIC_TARGET},inactivity_days=$INACTIVITY_DAYS"

    generate_report_header

    local user_count=0
    local issue_count=0
    local dormant_count=0
    local disabled_count=0
    local mfa_disabled_count=0
    local permission_issues_count=0
    local high_risk_count=0

    # Process users based on scope
    while IFS=: read -r user role last_login mfa_status; do
        ((user_count++))
        log_verbose "Processing user: $user, Role: $role, Last Login: $last_login, MFA: $mfa_status"

        local status="Active"
        local notes=""
        local is_dormant=false
        local is_privileged=$(check_privileges "$user")
        local risk_data=""
        local permission_status=""

        # Default MFA status if not provided in user data
        if [[ -z "$mfa_status" ]]; then
            mfa_status=$(check_mfa_status "$user")
        fi

        # --- Apply Scope Filters ---
        if [[ "$REVIEW_SCOPE" == "privileged" && "$is_privileged" != "privileged" ]]; then
            log_verbose "Skipping non-privileged user: $user"
            continue
        fi

        # --- Dormancy Check ---
        if [[ "$last_login" != "N/A" && "$last_login" != "Never" ]]; then
            local last_login_sec=$(date -d "$last_login" +%s 2>/dev/null || echo 0)
            local current_sec=$(date +%s)
            local inactive_sec=$(( INACTIVITY_DAYS * 24 * 60 * 60 ))

            if [[ "$last_login_sec" -ne 0 && $(( current_sec - last_login_sec )) -gt "$inactive_sec" ]]; then
                status="Dormant"
                notes="Inactive for more than $INACTIVITY_DAYS days."
                is_dormant=true
                ((dormant_count++))
                ((issue_count++))

                # Log dormant account in audit
                log_audit "dormant_detected" "$user" "role=$role,last_login=$last_login"
            fi
        } elif [[ "$last_login" == "Never" ]]; then
            # Never logged in accounts might be problematic too
            status="Unused"
            notes="Account has never been used."
            ((issue_count++))
        } else {
            # Handle users with no login data (e.g., service accounts, newly created)
            notes="No last login data available."
            # Consider if service accounts should be flagged differently
            if [[ "$role" == "service" ]]; then
                 status="Service Account"
                 notes="Service account - dormancy check N/A."
            fi
        }

        # --- Apply Dormant Scope Filter ---
        if [[ "$REVIEW_SCOPE" == "dormant" && "$is_dormant" == "false" ]]; then
             log_verbose "Skipping non-dormant user: $user"
             continue
        fi

        # --- MFA Check ---
        if [[ "$MFA_CHECK" == "true" ]]; then
            # Check if MFA is enabled
            if [[ "$mfa_status" == "disabled" ]]; then
                if [[ -z "$notes" ]]; then
                    notes="MFA not enabled."
                else
                    notes+=" MFA not enabled."
                fi
                ((mfa_disabled_count++))
                ((issue_count++))
            }
        }

        # --- Permission Audit ---
        if [[ "$PERMISSION_AUDIT" == "true" ]]; then
            permission_status=$(check_permissions "$user" "$role")

            if [[ "$permission_status" == "non_compliant" ]]; then
                if [[ -z "$notes" ]]; then
                    notes="Permissions not compliant with policy."
                else
                    notes+=" Permissions not compliant with policy."
                fi
                ((permission_issues_count++))
                ((issue_count++))
            }
        }

        # --- Risk Assessment ---
        if [[ "$RISK_ASSESSMENT" == "true" ]]; then
            risk_data=$(assess_risk "$user" "$role" "$last_login" "$mfa_status")
            local risk_level
            risk_level=$(echo "$risk_data" | cut -d':' -f1)

            if [[ "$risk_level" == "HIGH" ]]; then
                ((high_risk_count++))
            fi
        }

        # --- Auto-Disable Logic ---
        if [[ "$is_dormant" == "true" && "$AUTO_DISABLE" == "true" ]]; then
            # Add extra safety checks here if needed (e.g., don't disable critical service accounts)
            if [[ "$role" != "service" ]]; then # Example safety check
                if disable_user_account "$user" "Dormant account identified by access review"; then
                    status="Disabled (Dormant)"
                    notes+=" Account automatically disabled."
                    ((disabled_count++))
                else
                    notes+=" Failed to disable account automatically."
                }
            } else {
                notes+=" Auto-disable skipped for service account."
            }
        }

        # Add entry to report
        add_report_entry "$user" "$role" "$last_login" "$mfa_status" "$status" "$notes" "$risk_data"

    done < <(get_user_list) # Use process substitution

    # Add summary information
    add_summary_to_report "$user_count" "$issue_count" "$dormant_count" \
        "$disabled_count" "$mfa_disabled_count" "$permission_issues_count" "$high_risk_count"

    # Complete the report
    generate_report_footer

    # Log completion audit entry
    log_audit "access_review_completed" "$REVIEW_SCOPE" "users=$user_count,issues=$issue_count"

    log "Access review complete. Processed $user_count users."
    log "Found $issue_count potential issues."
    if [[ "$dormant_count" -gt 0 ]]; then
        log "Dormant accounts: $dormant_count"
    }
    if [[ "$AUTO_DISABLE" == "true" ]]; then
        log "Automatically disabled $disabled_count dormant accounts."
    }
    if [[ "$MFA_CHECK" == "true" ]]; then
        log "Users without MFA: $mfa_disabled_count"
    }
    if [[ "$PERMISSION_AUDIT" == "true" ]]; then
        log "Users with permission issues: $permission_issues_count"
    }
    if [[ "$RISK_ASSESSMENT" == "true" ]]; then
        log "High risk accounts: $high_risk_count"
    }
    log "Full report saved to: $REPORT_FILE"

    # Email report if requested
    email_report || log_error "Failed to email report."

    # Send notifications if critical issues found
    if [[ "$issue_count" -gt 0 && -n "$NOTIFICATION_CHANNEL" ]]; then
        send_notification "Access Review Issues Detected" \
            "Access review found $issue_count issues. Please check the full report at $REPORT_FILE" \
            "$NOTIFICATION_CHANNEL"
    fi

    # Exit with non-zero code if issues found and configured
    if [[ "$EXIT_ON_FAIL" == "true" && "$issue_count" -gt 0 ]]; then
        exit 1
    }

    exit 0
}

# --- Run Script ---
main "$@"
