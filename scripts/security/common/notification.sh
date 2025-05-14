#!/bin/bash
# filepath: scripts/security/common/notification.sh
#
# Alert and notification capabilities for security scripts
# Part of Cloud Infrastructure Platform security module
#
# This script provides standardized notification functionality across security scripts
# with multiple channels, priority-based routing, rate limiting, and template support.
#
# Usage: source scripts/security/common/notification.sh

# Ensure script is not executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ERROR: This script should be sourced, not executed directly."
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ===== Version information =====
readonly SECURITY_NOTIFICATION_VERSION="1.0.0"
readonly SECURITY_NOTIFICATION_DATE="2024-08-17"

# ===== Import dependencies =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source logging utility if available
if [[ -f "$SCRIPT_DIR/logging.sh" ]]; then
    # shellcheck source=./logging.sh
    source "$SCRIPT_DIR/logging.sh"
else
    # Define minimal logging functions if logging.sh is not available
    log_debug() { [[ "${SECURITY_LOG_LEVEL:-INFO}" == "DEBUG" ]] && echo "[DEBUG] $1" >&2 || true; }
    log_info() { echo "[INFO] $1" >&2; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_critical() { echo "[CRITICAL] $1" >&2; }
fi

# Source validation utility if available
if [[ -f "$SCRIPT_DIR/validation.sh" ]]; then
    # shellcheck source=./validation.sh
    source "$SCRIPT_DIR/validation.sh"
fi

# ===== Configuration =====

# Set default values if not already defined
: "${SECURITY_NOTIFICATION_CHANNELS:=email}"
: "${SECURITY_NOTIFICATION_EMAILS:=}"
: "${SECURITY_NOTIFICATION_SMS:=}"
: "${SECURITY_NOTIFICATION_CHAT_WEBHOOK:=}"
: "${SECURITY_MAX_NOTIFICATIONS:=10}"
: "${SECURITY_NOTIFICATION_RATE_LIMIT_PERIOD:=3600}"  # 1 hour in seconds
: "${SECURITY_NOTIFICATION_TEMPLATE_DIR:=/etc/cloud-platform/security/templates}"
: "${SECURITY_NOTIFICATION_BATCH_INTERVAL:=300}"  # 5 minutes in seconds
: "${SECURITY_NOTIFICATION_LOG_DIR:=/var/log/cloud-platform/security}"
: "${SECURITY_NOTIFICATION_LOG_FILE:=${SECURITY_NOTIFICATION_LOG_DIR}/notifications.log}"
: "${SECURITY_NOTIFICATION_STATE_DIR:=/var/lib/cloud-platform/security/notifications}"
: "${SECURITY_NOTIFICATION_REQUIRE_CONFIRMATION:=false}"

# ===== Internal State =====
NOTIFICATION_COUNT=0
NOTIFICATION_BATCH_MESSAGES=()
NOTIFICATION_BATCH_START_TIME=0
NOTIFICATION_LAST_RESET_TIME=$(date +%s)
NOTIFICATION_STATE_FILE="${SECURITY_NOTIFICATION_STATE_DIR}/notification_state.dat"

# ===== Helper Functions =====

# Initialize notification state directory and files
_initialize_notification_state() {
    # Create state directory if it doesn't exist
    if [[ ! -d "$SECURITY_NOTIFICATION_STATE_DIR" ]]; then
        mkdir -p "$SECURITY_NOTIFICATION_STATE_DIR" 2>/dev/null || {
            log_warning "Failed to create notification state directory: $SECURITY_NOTIFICATION_STATE_DIR"
            # Continue even if we can't create the directory
        }
    fi

    # Set permissions if we can
    if [[ -d "$SECURITY_NOTIFICATION_STATE_DIR" ]]; then
        chmod 750 "$SECURITY_NOTIFICATION_STATE_DIR" 2>/dev/null || true
    fi

    # Create state file if it doesn't exist
    if [[ ! -f "$NOTIFICATION_STATE_FILE" ]]; then
        {
            echo "NOTIFICATION_COUNT=0"
            echo "NOTIFICATION_LAST_RESET_TIME=$(date +%s)"
        } > "$NOTIFICATION_STATE_FILE" 2>/dev/null || {
            log_warning "Failed to create notification state file: $NOTIFICATION_STATE_FILE"
            # Continue even if we can't create the file
        }
    fi

    # Set permissions if we can
    if [[ -f "$NOTIFICATION_STATE_FILE" ]]; then
        chmod 640 "$NOTIFICATION_STATE_FILE" 2>/dev/null || true
    }

    # Load state from file if it exists and is readable
    if [[ -r "$NOTIFICATION_STATE_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$NOTIFICATION_STATE_FILE" 2>/dev/null || {
            log_warning "Failed to load notification state from: $NOTIFICATION_STATE_FILE"
        }
    }
}

# Update notification state in file
_update_notification_state() {
    # Check if state directory exists and is writable
    if [[ ! -d "$SECURITY_NOTIFICATION_STATE_DIR" || ! -w "$SECURITY_NOTIFICATION_STATE_DIR" ]]; then
        log_debug "Notification state directory not writable, skipping state update"
        return 0
    }

    # Write state to file
    {
        echo "NOTIFICATION_COUNT=$NOTIFICATION_COUNT"
        echo "NOTIFICATION_LAST_RESET_TIME=$NOTIFICATION_LAST_RESET_TIME"
    } > "$NOTIFICATION_STATE_FILE" 2>/dev/null || {
        log_warning "Failed to update notification state file: $NOTIFICATION_STATE_FILE"
    }
}

# Check if we've exceeded the maximum number of notifications in the rate limit period
_check_rate_limit() {
    local current_time
    current_time=$(date +%s)

    # Reset counter if we're outside the rate limit period
    if (( current_time - NOTIFICATION_LAST_RESET_TIME >= SECURITY_NOTIFICATION_RATE_LIMIT_PERIOD )); then
        NOTIFICATION_COUNT=0
        NOTIFICATION_LAST_RESET_TIME=$current_time
        _update_notification_state
    fi

    # Check if we've reached the maximum notifications
    if (( NOTIFICATION_COUNT >= SECURITY_MAX_NOTIFICATIONS )); then
        log_warning "Notification rate limit reached ($SECURITY_MAX_NOTIFICATIONS per $SECURITY_NOTIFICATION_RATE_LIMIT_PERIOD seconds)"
        return 1
    }

    return 0
}

# Increment notification counter
_increment_notification_counter() {
    ((NOTIFICATION_COUNT++))
    _update_notification_state
}

# Load template from file
_load_template() {
    local template_name="$1"
    local template_file="${SECURITY_NOTIFICATION_TEMPLATE_DIR}/${template_name}.tmpl"

    # Check if template directory exists
    if [[ ! -d "$SECURITY_NOTIFICATION_TEMPLATE_DIR" ]]; then
        log_debug "Template directory not found: $SECURITY_NOTIFICATION_TEMPLATE_DIR"
        return 1
    }

    # Check if template file exists and is readable
    if [[ ! -f "$template_file" || ! -r "$template_file" ]]; then
        log_debug "Template file not found or not readable: $template_file"
        return 1
    }

    # Load template content
    cat "$template_file"
    return $?
}

# Replace template variables
_replace_template_variables() {
    local template="$1"
    local variables="$2"
    local result="$template"

    # Replace variables in format key=value separated by spaces or commas
    local key value
    for pair in $(echo "$variables" | tr ' ,' '\n'); do
        # Skip empty pairs
        [[ -z "$pair" ]] && continue

        # Extract key and value
        key="${pair%%=*}"
        value="${pair#*=}"

        # Skip if key or value is empty
        [[ -z "$key" || -z "$value" ]] && continue

        # Replace variable in template
        result="${result//\{\{$key\}\}/$value}"
    done

    echo "$result"
}

# Validate email address format
_validate_email() {
    local email="$1"

    # Use validation.sh if available
    if type -t validate_email >/dev/null 2>&1; then
        validate_email "$email"
        return $?
    fi

    # Basic email validation using regex
    [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
    return $?
}

# Validate phone number format
_validate_phone() {
    local phone="$1"

    # Use validation.sh if available
    if type -t validate_phone >/dev/null 2>&1; then
        validate_phone "$phone"
        return $?
    fi

    # Basic phone validation - numbers, spaces, dashes, parentheses, and plus sign
    [[ "$phone" =~ ^[0-9()\-\+\ ]+$ ]]
    return $?
}

# Validate URL format
_validate_url() {
    local url="$1"

    # Use validation.sh if available
    if type -t validate_url >/dev/null 2>&1; then
        validate_url "$url"
        return $?
    fi

    # Basic URL validation
    [[ "$url" =~ ^https?:// ]]
    return $?
}

# Log notification details
_log_notification() {
    local subject="$1"
    local message="$2"
    local channel="$3"
    local priority="$4"
    local recipients="$5"

    log_info "Sending notification: '$subject' via $channel with priority $priority"

    # Log to notification log file if specified and directory exists
    if [[ -n "$SECURITY_NOTIFICATION_LOG_FILE" ]]; then
        local log_dir
        log_dir=$(dirname "$SECURITY_NOTIFICATION_LOG_FILE")

        # Create log directory if it doesn't exist
        if [[ ! -d "$log_dir" ]]; then
            mkdir -p "$log_dir" 2>/dev/null || {
                log_debug "Failed to create notification log directory: $log_dir"
                return
            }
        fi

        # Write to log file
        if [[ -d "$log_dir" && -w "$log_dir" ]]; then
            {
                echo "==========================================="
                echo "Timestamp: $(date "+%Y-%m-%d %H:%M:%S")"
                echo "Subject: $subject"
                echo "Priority: $priority"
                echo "Channel: $channel"
                echo "Recipients: $recipients"
                echo "-------------------------------------------"
                echo "$message"
                echo "==========================================="
                echo ""
            } >> "$SECURITY_NOTIFICATION_LOG_FILE" 2>/dev/null || {
                log_debug "Failed to write to notification log file: $SECURITY_NOTIFICATION_LOG_FILE"
            }
        }
    fi
}

# ===== Notification Channel Functions =====

# Send email notification
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Recipients (comma-separated)
#   $4 - Attachment file (optional)
# Returns:
#   0 on success, 1 on failure
_send_email_notification() {
    local subject="$1"
    local message="$2"
    local recipients="$3"
    local attachment="$4"
    local status=0

    # Check if recipients are provided
    if [[ -z "$recipients" ]]; then
        log_error "No email recipients specified"
        return 1
    fi

    # Check if mail command is available
    if command -v mail >/dev/null 2>&1; then
        # Prepare mail command
        local mail_cmd="mail -s \"$subject\""

        # Add attachment if provided and file exists
        if [[ -n "$attachment" && -f "$attachment" && -r "$attachment" ]]; then
            # Check if mail supports attachments
            if mail --help 2>&1 | grep -q -- "-a"; then
                mail_cmd="$mail_cmd -a \"$attachment\""
            else
                log_warning "Mail command does not support attachments, sending without attachment"
            fi
        fi

        # Add recipients and execute
        mail_cmd="$mail_cmd \"$recipients\""

        # Use echo to pass message to mail
        # shellcheck disable=SC2086
        if ! echo "$message" | eval $mail_cmd >/dev/null 2>&1; then
            log_error "Failed to send email notification"
            status=1
        fi
    # Check if sendmail command is available
    elif command -v sendmail >/dev/null 2>&1; then
        local email_content

        # Prepare email content
        email_content="Subject: $subject"$'\n'
        email_content+="To: $recipients"$'\n'
        email_content+="Content-Type: text/plain; charset=UTF-8"$'\n'
        email_content+=$'\n'
        email_content+="$message"

        # Send email using sendmail
        if ! echo "$email_content" | sendmail -t >/dev/null 2>&1; then
            log_error "Failed to send email notification using sendmail"
            status=1
        }
    # Check if mutt command is available
    elif command -v mutt >/dev/null 2>&1; then
        local mutt_cmd="mutt -s \"$subject\""

        # Add attachment if provided and file exists
        if [[ -n "$attachment" && -f "$attachment" && -r "$attachment" ]]; then
            mutt_cmd="$mutt_cmd -a \"$attachment\""
        fi

        # Add recipients and execute
        mutt_cmd="$mutt_cmd -- \"$recipients\""

        # Use echo to pass message to mutt
        # shellcheck disable=SC2086
        if ! echo "$message" | eval $mutt_cmd >/dev/null 2>&1; then
            log_error "Failed to send email notification using mutt"
            status=1
        }
    else
        log_error "No supported email program found (mail, sendmail, mutt)"
        status=1
    fi

    return $status
}

# Send SMS notification
# Arguments:
#   $1 - Subject (used as prefix)
#   $2 - Message body
#   $3 - Recipients (comma-separated phone numbers)
# Returns:
#   0 on success, 1 on failure
_send_sms_notification() {
    local subject="$1"
    local message="$2"
    local recipients="$3"
    local status=0

    # Check if recipients are provided
    if [[ -z "$recipients" ]]; then
        log_error "No SMS recipients specified"
        return 1
    fi

    # Check for SMS gateway configuration
    if [[ -z "$SECURITY_SMS_GATEWAY_URL" ]]; then
        log_error "SMS gateway URL not configured"
        return 1
    }

    # Prepare message (truncate if needed)
    local sms_message="$subject: $message"
    if [[ ${#sms_message} -gt 160 ]]; then
        sms_message="${sms_message:0:157}..."
    fi

    # Process each recipient
    IFS=',' read -ra phone_numbers <<< "$recipients"
    for phone in "${phone_numbers[@]}"; do
        # Validate phone number
        if ! _validate_phone "$phone"; then
            log_warning "Invalid phone number format: $phone"
            status=1
            continue
        }

        # Send SMS via gateway API - implementation depends on the SMS gateway
        if command -v curl >/dev/null 2>&1; then
            # Example using curl with a generic SMS gateway
            if ! curl -s -X POST \
                -d "phone=$phone" \
                -d "message=$sms_message" \
                -d "api_key=$SECURITY_SMS_API_KEY" \
                "$SECURITY_SMS_GATEWAY_URL" >/dev/null 2>&1; then
                log_error "Failed to send SMS to $phone"
                status=1
            }
        else
            log_error "curl command not found, cannot send SMS"
            status=1
        fi
    done

    return $status
}

# Send chat notification (Slack, Teams, etc.)
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Webhook URL
#   $4 - Priority
# Returns:
#   0 on success, 1 on failure
_send_chat_notification() {
    local subject="$1"
    local message="$2"
    local webhook_url="$3"
    local priority="$4"
    local status=0

    # Check if webhook URL is provided
    if [[ -z "$webhook_url" ]]; then
        log_error "No chat webhook URL specified"
        return 1
    }

    # Validate webhook URL
    if ! _validate_url "$webhook_url"; then
        log_error "Invalid webhook URL format: $webhook_url"
        return 1
    }

    # Determine color based on priority
    local color
    case "$priority" in
        critical) color="#FF0000" ;; # Red
        high) color="#FF9900" ;; # Orange
        medium) color="#FFCC00" ;; # Yellow
        low) color="#36A64F" ;; # Green
        *) color="#808080" ;; # Grey
    esac

    # Send message if curl is available
    if command -v curl >/dev/null 2>&1; then
        # Check if the webhook appears to be for Slack (simple heuristic)
        if [[ "$webhook_url" == *"slack.com"* ]]; then
            # Format payload for Slack
            local payload="{\"attachments\":[{\"color\":\"$color\",\"title\":\"$subject\",\"text\":\"$message\"}]}"

            # Send to Slack
            if ! curl -s -X POST -H "Content-Type: application/json" --data "$payload" "$webhook_url" >/dev/null 2>&1; then
                log_error "Failed to send Slack notification"
                status=1
            }
        # Check if the webhook appears to be for Microsoft Teams
        elif [[ "$webhook_url" == *"office.com"* || "$webhook_url" == *"microsoft.com"* ]]; then
            # Format payload for Teams
            local payload="{\"@type\":\"MessageCard\",\"@context\":\"https://schema.org/extensions\",\"themeColor\":\"${color:1}\",\"title\":\"$subject\",\"text\":\"$message\"}"

            # Send to Microsoft Teams
            if ! curl -s -X POST -H "Content-Type: application/json" --data "$payload" "$webhook_url" >/dev/null 2>&1; then
                log_error "Failed to send Teams notification"
                status=1
            }
        else
            # Generic webhook - use Slack format as default
            local payload="{\"text\":\"*$subject*\n$message\"}"

            # Send to generic webhook
            if ! curl -s -X POST -H "Content-Type: application/json" --data "$payload" "$webhook_url" >/dev/null 2>&1; then
                log_error "Failed to send chat notification"
                status=1
            }
        fi
    else
        log_error "curl command not found, cannot send chat notification"
        status=1
    fi

    return $status
}

# Start notification batching
start_notification_batch() {
    NOTIFICATION_BATCH_MESSAGES=()
    NOTIFICATION_BATCH_START_TIME=$(date +%s)
    log_debug "Starting notification batch"
}

# Add message to batch
# Arguments:
#   $1 - Subject
#   $2 - Message body
# Returns:
#   0 on success
add_to_notification_batch() {
    local subject="$1"
    local message="$2"

    # Add to batch array
    NOTIFICATION_BATCH_MESSAGES+=("Subject: $subject"$'\n'"Message: $message"$'\n')

    log_debug "Added message to notification batch: $subject"
    return 0
}

# Send batched notifications
# Arguments:
#   $1 - Batch subject
#   $2 - Priority (optional, defaults to "info")
#   $3 - Channel (optional, defaults to default channels)
# Returns:
#   0 on success, 1 on failure
send_notification_batch() {
    local batch_subject="$1"
    local priority="${2:-info}"
    local channel="${3:-$SECURITY_NOTIFICATION_CHANNELS}"
    local status=0

    # Check if there are any messages in the batch
    if [[ ${#NOTIFICATION_BATCH_MESSAGES[@]} -eq 0 ]]; then
        log_info "No messages in notification batch, skipping"
        return 0
    }

    # Create batch message
    local batch_message="Batch Notification containing ${#NOTIFICATION_BATCH_MESSAGES[@]} messages:"$'\n\n'

    # Add separator line
    batch_message+="=================================================="$'\n\n'

    # Add all messages
    for msg in "${NOTIFICATION_BATCH_MESSAGES[@]}"; do
        batch_message+="$msg"
        batch_message+="--------------------------------------------------"$'\n\n'
    done

    # Send the batch notification
    send_notification "$batch_subject" "$batch_message" "$priority" "$channel"
    status=$?

    # Clear batch
    NOTIFICATION_BATCH_MESSAGES=()

    return $status
}

# ===== Public Functions =====

# Send notification through configured channels
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Priority (optional, defaults to "info")
#   $4 - Channels (optional, defaults to configured channels)
# Returns:
#   0 on success, 1 on failure
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-info}"
    local channels="${4:-$SECURITY_NOTIFICATION_CHANNELS}"
    local status=0

    # Validate inputs
    if [[ -z "$subject" || -z "$message" ]]; then
        log_error "Subject and message are required for notifications"
        return 1
    }

    # Normalize priority
    priority=$(echo "$priority" | tr '[:upper:]' '[:lower:]')

    # Check valid priority values
    case "$priority" in
        critical|high|medium|low|info) ;;
        *)
            log_warning "Invalid priority: $priority, defaulting to 'info'"
            priority="info"
            ;;
    esac

    # Check rate limiting
    if ! _check_rate_limit; then
        if [[ "$priority" == "critical" ]]; then
            log_warning "Sending critical notification despite rate limiting"
        else
            log_error "Notification suppressed due to rate limiting"
            return 1
        fi
    fi

    # Split channels by comma
    IFS=',' read -ra channel_array <<< "$channels"

    # Process each channel
    for channel in "${channel_array[@]}"; do
        # Normalize channel
        channel=$(echo "$channel" | tr '[:upper:]' '[:lower:]')

        case "$channel" in
            email)
                if [[ -n "$SECURITY_NOTIFICATION_EMAILS" ]]; then
                    _send_email_notification "$subject" "$message" "$SECURITY_NOTIFICATION_EMAILS"
                    [[ $? -ne 0 ]] && status=1
                } else {
                    log_warning "No email recipients configured"
                }
                ;;
            sms)
                if [[ -n "$SECURITY_NOTIFICATION_SMS" ]]; then
                    _send_sms_notification "$subject" "$message" "$SECURITY_NOTIFICATION_SMS"
                    [[ $? -ne 0 ]] && status=1
                } else {
                    log_warning "No SMS recipients configured"
                }
                ;;
            chat|slack|teams)
                if [[ -n "$SECURITY_NOTIFICATION_CHAT_WEBHOOK" ]]; then
                    _send_chat_notification "$subject" "$message" "$SECURITY_NOTIFICATION_CHAT_WEBHOOK" "$priority"
                    [[ $? -ne 0 ]] && status=1
                } else {
                    log_warning "No chat webhook URL configured"
                }
                ;;
            *)
                log_warning "Unknown notification channel: $channel"
                ;;
        esac
    done

    # Log notification
    _log_notification "$subject" "$message" "$channels" "$priority" "$SECURITY_NOTIFICATION_EMAILS,$SECURITY_NOTIFICATION_SMS"

    # Increment notification counter if successful
    if [[ $status -eq 0 ]]; then
        _increment_notification_counter
    }

    # Handle confirmation if required
    if [[ "$SECURITY_NOTIFICATION_REQUIRE_CONFIRMATION" == "true" ]]; then
        # Log a message - in a real implementation this would wait for confirmation
        log_info "Notification sent, waiting for confirmation..."

        # Here we would implement confirmation tracking and timeout handling
    }

    return $status
}

# Send notification with higher priority
# Arguments:
#   $1 - Subject
#   $2 - Message body
# Returns:
#   0 on success, 1 on failure
send_urgent_notification() {
    local subject="$1"
    local message="$2"

    # Prepend "URGENT: " to subject if not already there
    if [[ "$subject" != "URGENT:"* ]]; then
        subject="URGENT: $subject"
    fi

    # Send with high priority to all available channels
    send_notification "$subject" "$message" "high" "email,sms,chat"
    return $?
}

# Send notification using template
# Arguments:
#   $1 - Template name
#   $2 - Variables (key=value pairs separated by spaces or commas)
#   $3 - Priority (optional, defaults to "info")
#   $4 - Channels (optional, defaults to configured channels)
# Returns:
#   0 on success, 1 on failure
send_template_notification() {
    local template_name="$1"
    local variables="$2"
    local priority="${3:-info}"
    local channels="${4:-$SECURITY_NOTIFICATION_CHANNELS}"
    local status=0

    # Load template
    local template_content
    template_content=$(_load_template "$template_name")
    status=$?

    # Check if template was loaded
    if [[ $status -ne 0 || -z "$template_content" ]]; then
        # Try loading a default template or create a simple one
        log_warning "Failed to load template: $template_name, using default"
        template_content="Subject: {{subject}}\n\n{{message}}\n\nTime: {{timestamp}}\nSystem: {{system}}"
    }

    # Add timestamp if not provided in variables
    if [[ "$variables" != *"timestamp="* ]]; then
        variables="$variables,timestamp=$(date '+%Y-%m-%d %H:%M:%S')"
    fi

    # Replace template variables
    local processed_content
    processed_content=$(_replace_template_variables "$template_content" "$variables")

    # Extract subject and message from template
    # Assumes template has a line starting with "Subject: "
    local subject message
    subject=$(echo "$processed_content" | grep -m 1 "^Subject:" | sed "s/^Subject: //")

    # If no subject line found, use template name as subject
    if [[ -z "$subject" ]]; then
        subject="${template_name^} Notification"
    }

    # Remove subject line from message
    message=$(echo "$processed_content" | sed "s/^Subject:.*$//" | sed -e '/./,$!d')

    # Send notification
    send_notification "$subject" "$message" "$priority" "$channels"
    return $?
}

# Send notification with specific priorities and channels based on priority
# Arguments:
#   $1 - Subject
#   $2 - Message body
#   $3 - Channels (comma-separated)
#   $4 - Priority (optional, defaults to "info")
# Returns:
#   0 on success, 1 on failure
send_multi_channel_notification() {
    local subject="$1"
    local message="$2"
    local channels="$3"
    local priority="${4:-info}"

    # Validate inputs
    if [[ -z "$channels" ]]; then
        log_error "Channels must be specified for multi-channel notification"
        return 1
    }

    # Send notification
    send_notification "$subject" "$message" "$priority" "$channels"
    return $?
}

# Get notification system version
# Returns: Version string
get_notification_version() {
    echo "${SECURITY_NOTIFICATION_VERSION} (${SECURITY_NOTIFICATION_DATE})"
}

# Configure notification channels
# Arguments:
#   $1 - Channels (comma-separated: email,sms,chat)
# Returns:
#   0 on success
configure_notification_channels() {
    local channels="$1"

    # Validate and set channels
    SECURITY_NOTIFICATION_CHANNELS="$channels"
    log_debug "Notification channels set to: $channels"

    return 0
}

# Configure email recipients
# Arguments:
#   $1 - Email addresses (comma-separated)
# Returns:
#   0 on success, 1 if invalid
configure_email_recipients() {
    local emails="$1"
    local status=0

    # Validate each email
    IFS=',' read -ra email_array <<< "$emails"
    for email in "${email_array[@]}"; do
        if ! _validate_email "$email"; then
            log_warning "Invalid email address: $email"
            status=1
        }
    done

    # Set even if there are some invalid emails
    SECURITY_NOTIFICATION_EMAILS="$emails"

    return $status
}

# Configure SMS recipients
# Arguments:
#   $1 - Phone numbers (comma-separated)
# Returns:
#   0 on success, 1 if invalid
configure_sms_recipients() {
    local phones="$1"
    local status=0

    # Validate each phone number
    IFS=',' read -ra phone_array <<< "$phones"
    for phone in "${phone_array[@]}"; do
        if ! _validate_phone "$phone"; then
            log_warning "Invalid phone number: $phone"
            status=1
        }
    done

    # Set even if there are some invalid phones
    SECURITY_NOTIFICATION_SMS="$phones"

    return $status
}

# Configure chat webhook URL
# Arguments:
#   $1 - Webhook URL
# Returns:
#   0 on success, 1 if invalid
configure_chat_webhook() {
    local webhook="$1"

    # Validate webhook URL
    if ! _validate_url "$webhook"; then
        log_warning "Invalid webhook URL: $webhook"
        return 1
    }

    SECURITY_NOTIFICATION_CHAT_WEBHOOK="$webhook"
    return 0
}

# Set notification rate limit
# Arguments:
#   $1 - Maximum notifications
#   $2 - Period in seconds
# Returns:
#   0 on success, 1 if invalid
set_notification_rate_limit() {
    local max="$1"
    local period="$2"

    # Validate inputs
    if [[ -z "$max" || -z "$period" ]]; then
        log_error "Maximum and period must be specified"
        return 1
    }

    # Ensure they are numbers
    if ! [[ "$max" =~ ^[0-9]+$ && "$period" =~ ^[0-9]+$ ]]; then
        log_error "Maximum and period must be positive integers"
        return 1
    }

    SECURITY_MAX_NOTIFICATIONS="$max"
    SECURITY_NOTIFICATION_RATE_LIMIT_PERIOD="$period"

    log_debug "Rate limit set to $max notifications per $period seconds"

    return 0
}

# Enable/disable confirmation requirement
# Arguments:
#   $1 - Enable confirmation (true/false)
# Returns:
#   0 on success
set_notification_confirmation() {
    local require_confirmation="$1"

    # Validate input
    if [[ "$require_confirmation" != "true" && "$require_confirmation" != "false" ]]; then
        log_warning "Invalid value for confirmation requirement: $require_confirmation, must be 'true' or 'false'"
        return 1
    }

    SECURITY_NOTIFICATION_REQUIRE_CONFIRMATION="$require_confirmation"

    log_debug "Notification confirmation requirement set to: $require_confirmation"

    return 0
}

# === Initialization ===

# Initialize state directory and load saved state
_initialize_notification_state

# Log initialization
log_debug "Notification utility initialized. Version: $(get_notification_version)"

# Export public functions
export -f send_notification send_urgent_notification send_template_notification
export -f send_multi_channel_notification get_notification_version
export -f configure_notification_channels configure_email_recipients
export -f configure_sms_recipients configure_chat_webhook
export -f set_notification_rate_limit set_notification_confirmation
export -f start_notification_batch add_to_notification_batch send_notification_batch
