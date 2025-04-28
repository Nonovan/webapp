#!/bin/bash
# filepath: scripts/security/check_certificate_expiration.sh
# Certificate Expiration Checker
#
# Monitors SSL/TLS certificates for upcoming expiration and sends notifications
# through configurable channels when certificates are approaching expiration.
# Supports local certificate files and remote domain certificate checking.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform/security"
LOG_FILE="${LOG_DIR}/certificate_check.log"
REPORT_DIR="${LOG_DIR}/reports"
REPORT_FILE="${REPORT_DIR}/certificate_report_$(date +%Y%m%d%H%M%S).txt"
CONFIG_FILE="${PROJECT_ROOT}/config/security/certificate_config.json"
DEFAULT_CERT_DIRS=(
    "/etc/ssl/cloud-platform"
    "/etc/ssl/certs"
    "/etc/nginx/ssl"
    "/etc/letsencrypt/live"
)
WARNING_DAYS=30
CRITICAL_DAYS=7
EMAIL_RECIPIENT=""
SLACK_WEBHOOK=""
VERBOSE=false
EXIT_ON_EXPIRY=false
CHECK_REVOCATION=false
OUTPUT_FORMAT="text"  # Options: text, json, csv
NOTIFICATION_TITLE="Certificate Expiration Alert"
CHECK_EXTERNAL=true
CHECK_LOCAL=true
STATUS_SUCCESS=0
STATUS_WARNING=0
STATUS_ERROR=0

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

    log_info() { log "$1" "INFO"; }
    log_warn() { log "$1" "WARNING"; }
    log_error() { log "$1" "ERROR"; }
    log_debug() { if [[ "$VERBOSE" == "true" ]]; then log "$1" "DEBUG"; fi; }
fi

# --- Helper Functions ---
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Monitors SSL/TLS certificates for upcoming expiration and sends notifications."
    echo ""
    echo "Options:"
    echo "  --cert-dir DIR        Directory to scan for certificates (can be specified multiple times)"
    echo "  --domains DOMAINS     Comma-separated list of domains to check (remote cert check)"
    echo "  --warning-days N      Days before expiry to trigger warning (default: $WARNING_DAYS)"
    echo "  --critical-days N     Days before expiry to trigger critical alert (default: $CRITICAL_DAYS)"
    echo "  --email EMAIL         Email address to send notifications to"
    echo "  --slack-webhook URL   Slack webhook URL for notifications"
    echo "  --output-format FMT   Output format: text, json, csv (default: $OUTPUT_FORMAT)"
    echo "  --config FILE         Path to configuration file (default: $CONFIG_FILE)"
    echo "  --no-external         Skip external domain certificate checks"
    echo "  --no-local            Skip local certificate file checks"
    echo "  --check-revocation    Verify if certificates have been revoked"
    echo "  --exit-on-expiry      Exit with non-zero code if any cert is expiring"
    echo "  --verbose, -v         Enable verbose logging"
    echo "  --help, -h            Display this help message"
    echo ""
    exit 0
}

command_exists() {
    command -v "$1" &> /dev/null
}

validate_domain() {
    local domain="$1"
    # Basic domain validation with regex
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-info}"
    local status=0

    # Email notification
    if [[ -n "$EMAIL_RECIPIENT" ]]; then
        log_debug "Sending email notification to $EMAIL_RECIPIENT"
        if command_exists mail; then
            echo -e "$message" | mail -s "$subject" "$EMAIL_RECIPIENT" || status=$?
            if [[ $status -eq 0 ]]; then
                log_info "Email notification sent to $EMAIL_RECIPIENT"
            else
                log_error "Failed to send email notification"
            fi
        else
            log_warn "Mail command not found. Cannot send email notification."
        fi
    fi

    # Slack notification
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        log_debug "Sending Slack notification"
        if command_exists curl; then
            # Set color based on priority
            local color=""
            case "$priority" in
                critical) color="#FF0000" ;;  # Red
                warning) color="#FFA500" ;;   # Orange
                *) color="#36A64F" ;;         # Green
            esac

            # Create Slack payload
            local payload="{\"attachments\":[{\"color\":\"$color\",\"title\":\"$subject\",\"text\":\"$message\",\"footer\":\"Certificate Monitor | $(hostname)\"}]}"

            # Send to webhook
            curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" &>/dev/null || status=$?
            if [[ $status -eq 0 ]]; then
                log_info "Slack notification sent"
            else
                log_error "Failed to send Slack notification"
            fi
        else
            log_warn "Curl command not found. Cannot send Slack notification."
        fi
    fi

    return $status
}

# Functions for handling different date formats across platforms
parse_expiry_date() {
    local expiry_date="$1"
    local days_remaining=0
    local expiry_epoch=0
    local current_epoch=$(date +%s)

    # Try different date formats based on the OS
    if date --version &>/dev/null 2>&1; then
        # GNU date (Linux)
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
    else
        # BSD date (macOS)
        expiry_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)

        # If that fails, try alternative format
        if [[ -z "$expiry_epoch" ]]; then
            # Convert format - this is a simplification, real implementation would be more robust
            local formatted_date=$(echo "$expiry_date" | sed -E 's/(.{3}) (.{1,2}) (.{2}):(.{2}):(.{2}) (.{4})/\1 \2 \6 \3:\4:\5/')
            expiry_epoch=$(date -j -f "%b %d %Y %H:%M:%S" "$formatted_date" +%s 2>/dev/null)
        fi
    fi

    # Calculate days remaining
    if [[ -n "$expiry_epoch" && $expiry_epoch -gt 0 ]]; then
        days_remaining=$(( (expiry_epoch - current_epoch) / 86400 ))
        echo "$days_remaining"
        return 0
    else
        log_error "Failed to parse expiry date: $expiry_date"
        echo "-1"
        return 1
    fi
}

# Check if certificate has been revoked (requires OCSP)
check_certificate_revocation() {
    local cert_path="$1"
    local status="Unknown"

    log_debug "Checking revocation status for: $cert_path"

    if ! command_exists openssl; then
        log_warn "OpenSSL not found, cannot check revocation status"
        echo "$status"
        return 1
    fi

    # Extract OCSP URI from certificate
    local ocsp_uri=$(openssl x509 -in "$cert_path" -noout -ocsp_uri 2>/dev/null)
    if [[ -z "$ocsp_uri" ]]; then
        log_debug "No OCSP URI found in certificate: $cert_path"
        echo "No OCSP URI"
        return 1
    fi

    # Get issuer certificate - we'd need the actual issuer cert for a real check
    # This is a simplified example - production would require proper certificate chain handling
    log_debug "OCSP URI found: $ocsp_uri. Checking revocation status."

    # Run OCSP check - for illustration, real implementation would be more complex
    local ocsp_output=$(openssl ocsp -issuer "$cert_path" -cert "$cert_path" -text -url "$ocsp_uri" 2>/dev/null || echo "OCSP check failed")

    if echo "$ocsp_output" | grep -q "good"; then
        status="Valid"
    elif echo "$ocsp_output" | grep -q "revoked"; then
        status="Revoked"
        log_error "Certificate has been REVOKED: $cert_path"
    else
        status="Unknown"
        log_warn "Could not determine revocation status for: $cert_path"
    fi

    echo "$status"
    [[ "$status" == "Valid" ]] && return 0 || return 1
}

# Check local certificate file
check_local_certificate() {
    local cert_path="$1"
    local result=0

    if [[ ! -f "$cert_path" ]]; then
        log_error "Certificate file not found: $cert_path"
        return 2
    fi

    log_info "Checking certificate: $(basename "$cert_path")"

    # Extract basic certificate info
    local cert_info=$(openssl x509 -in "$cert_path" -noout -subject -issuer -dates 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        log_error "Failed to read certificate: $cert_path"
        return 2
    }

    log_debug "Certificate details: $cert_info"

    # Extract certificate subject
    local subject=$(echo "$cert_info" | grep "subject" | sed 's/^subject=//g')

    # Extract expiry date
    local expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)

    # Calculate days until expiration
    local days_remaining=$(parse_expiry_date "$expiry_date")
    if [[ $? -ne 0 || "$days_remaining" -eq -1 ]]; then
        log_error "Failed to calculate expiration for: $cert_path"
        return 2
    fi

    # Check if certificate is already expired
    if [[ $days_remaining -le 0 ]]; then
        log_error "CRITICAL: Certificate has EXPIRED: $cert_path"
        send_notification \
            "$NOTIFICATION_TITLE - EXPIRED CERTIFICATE" \
            "Certificate $cert_path has EXPIRED!\n\nSubject: $subject\nExpiry: $expiry_date\nDays since expiry: $((days_remaining * -1))" \
            "critical"
        ((STATUS_ERROR++))
        result=2
    # Check if certificate is approaching critical threshold
    elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then
        log_warn "CRITICAL: Certificate expiring in $days_remaining days: $cert_path"
        send_notification \
            "$NOTIFICATION_TITLE - CRITICAL" \
            "Certificate expiring in $days_remaining days!\n\nPath: $cert_path\nSubject: $subject\nExpiry: $expiry_date" \
            "critical"
        ((STATUS_WARNING++))
        result=1
    # Check if certificate is approaching warning threshold
    elif [[ $days_remaining -le $WARNING_DAYS ]]; then
        log_warn "WARNING: Certificate expiring in $days_remaining days: $cert_path"
        send_notification \
            "$NOTIFICATION_TITLE - WARNING" \
            "Certificate expiring in $days_remaining days\n\nPath: $cert_path\nSubject: $subject\nExpiry: $expiry_date" \
            "warning"
        ((STATUS_WARNING++))
        result=1
    else
        log_info "Certificate valid for $days_remaining days: $cert_path"
        ((STATUS_SUCCESS++))
        result=0
    fi

    # Check revocation status if requested
    local revocation_status="Not checked"
    if [[ "$CHECK_REVOCATION" == "true" ]]; then
        revocation_status=$(check_certificate_revocation "$cert_path")
        if [[ "$revocation_status" == "Revoked" ]]; then
            log_error "CRITICAL: Certificate has been REVOKED: $cert_path"
            send_notification \
                "$NOTIFICATION_TITLE - REVOKED CERTIFICATE" \
                "Certificate $cert_path has been REVOKED!\n\nSubject: $subject\nExpiry: $expiry_date" \
                "critical"
            ((STATUS_ERROR++))
            result=2
        fi
    fi

    # Add to report based on format
    case "$OUTPUT_FORMAT" in
        json)
            echo "  {" >> "$REPORT_FILE"
            echo "    \"file\": \"$cert_path\"," >> "$REPORT_FILE"
            echo "    \"subject\": \"$subject\"," >> "$REPORT_FILE"
            echo "    \"expiry_date\": \"$expiry_date\"," >> "$REPORT_FILE"
            echo "    \"days_remaining\": $days_remaining," >> "$REPORT_FILE"
            echo "    \"status\": \"$(if [[ $days_remaining -le 0 ]]; then echo "expired"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "critical"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "warning"; else echo "ok"; fi)\"," >> "$REPORT_FILE"
            echo "    \"revocation_status\": \"$revocation_status\"" >> "$REPORT_FILE"
            echo "  }," >> "$REPORT_FILE"
            ;;
        csv)
            echo "\"$cert_path\",\"$subject\",\"$expiry_date\",$days_remaining,\"$(if [[ $days_remaining -le 0 ]]; then echo "expired"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "critical"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "warning"; else echo "ok"; fi)\",\"$revocation_status\"" >> "$REPORT_FILE"
            ;;
        *)
            printf "  %-50s  %5d days  %s\n" "$(basename "$cert_path")" "$days_remaining" "$(if [[ $days_remaining -le 0 ]]; then echo "[EXPIRED]"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "[CRITICAL]"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "[WARNING]"; else echo "[OK]"; fi)" >> "$REPORT_FILE"
            ;;
    esac

    return $result
}

# Check remote certificate for a domain
check_remote_certificate() {
    local domain="$1"
    local port="${2:-443}"
    local result=0

    if ! validate_domain "$domain"; then
        log_error "Invalid domain format: $domain"
        return 2
    fi

    log_info "Checking certificate for domain: $domain"

    # Create temporary file for certificate
    local temp_cert=$(mktemp)
    trap 'rm -f "$temp_cert"' EXIT

    # Fetch certificate from remote server
    if ! timeout 10 openssl s_client -servername "$domain" -connect "${domain}:${port}" -verify_hostname "$domain" </dev/null 2>/dev/null | openssl x509 -outform PEM -out "$temp_cert"; then
        log_error "Failed to retrieve certificate for domain: $domain"
        rm -f "$temp_cert"
        ((STATUS_ERROR++))

        # Add to report
        case "$OUTPUT_FORMAT" in
            json)
                echo "  {" >> "$REPORT_FILE"
                echo "    \"domain\": \"$domain\"," >> "$REPORT_FILE"
                echo "    \"status\": \"error\"," >> "$REPORT_FILE"
                echo "    \"message\": \"Failed to retrieve certificate\"" >> "$REPORT_FILE"
                echo "  }," >> "$REPORT_FILE"
                ;;
            csv)
                echo "\"$domain\",\"\",\"\",0,\"error\",\"Failed to retrieve certificate\"" >> "$REPORT_FILE"
                ;;
            *)
                printf "  %-50s  %s\n" "$domain" "[ERROR: Could not retrieve certificate]" >> "$REPORT_FILE"
                ;;
        esac

        return 2
    fi

    # Extract certificate info
    local cert_info=$(openssl x509 -in "$temp_cert" -noout -subject -issuer -dates 2>/dev/null)
    local subject=$(echo "$cert_info" | grep "subject" | sed 's/^subject=//g')
    local expiry_date=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
    local sans=$(openssl x509 -in "$temp_cert" -noout -text | grep -A1 "Subject Alternative Name" | tail -n1)

    # Calculate days until expiration
    local days_remaining=$(parse_expiry_date "$expiry_date")
    if [[ $? -ne 0 || "$days_remaining" -eq -1 ]]; then
        log_error "Failed to calculate expiration for domain: $domain"
        rm -f "$temp_cert"
        return 2
    fi

    # Check certificate validity
    if [[ $days_remaining -le 0 ]]; then
        log_error "CRITICAL: Certificate for $domain has EXPIRED!"
        send_notification \
            "$NOTIFICATION_TITLE - EXPIRED DOMAIN CERTIFICATE" \
            "Certificate for domain $domain has EXPIRED!\n\nSubject: $subject\nExpiry: $expiry_date\nSANs: $sans\nDays since expiry: $((days_remaining * -1))" \
            "critical"
        ((STATUS_ERROR++))
        result=2
    elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then
        log_warn "CRITICAL: Certificate for $domain expiring in $days_remaining days"
        send_notification \
            "$NOTIFICATION_TITLE - CRITICAL" \
            "Certificate for domain $domain expiring in $days_remaining days!\n\nSubject: $subject\nExpiry: $expiry_date\nSANs: $sans" \
            "critical"
        ((STATUS_WARNING++))
        result=1
    elif [[ $days_remaining -le $WARNING_DAYS ]]; then
        log_warn "WARNING: Certificate for $domain expiring in $days_remaining days"
        send_notification \
            "$NOTIFICATION_TITLE - WARNING" \
            "Certificate for domain $domain expiring in $days_remaining days\n\nSubject: $subject\nExpiry: $expiry_date\nSANs: $sans" \
            "warning"
        ((STATUS_WARNING++))
        result=1
    else
        log_info "Certificate for $domain valid for $days_remaining days"
        ((STATUS_SUCCESS++))
        result=0
    fi

    # Check TLS version and cipher
    local tls_version=""
    local cipher=""
    if command_exists openssl; then
        tls_info=$(echo | openssl s_client -servername "$domain" -connect "${domain}:${port}" 2>/dev/null | grep -E "Protocol|Cipher")
        tls_version=$(echo "$tls_info" | grep "Protocol" | awk '{print $2}')
        cipher=$(echo "$tls_info" | grep "Cipher" | awk '{print $3}')
    fi

    # Add to report
    case "$OUTPUT_FORMAT" in
        json)
            echo "  {" >> "$REPORT_FILE"
            echo "    \"domain\": \"$domain\"," >> "$REPORT_FILE"
            echo "    \"subject\": \"$subject\"," >> "$REPORT_FILE"
            echo "    \"expiry_date\": \"$expiry_date\"," >> "$REPORT_FILE"
            echo "    \"days_remaining\": $days_remaining," >> "$REPORT_FILE"
            echo "    \"sans\": \"$sans\"," >> "$REPORT_FILE"
            echo "    \"tls_version\": \"$tls_version\"," >> "$REPORT_FILE"
            echo "    \"cipher\": \"$cipher\"," >> "$REPORT_FILE"
            echo "    \"status\": \"$(if [[ $days_remaining -le 0 ]]; then echo "expired"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "critical"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "warning"; else echo "ok"; fi)\"" >> "$REPORT_FILE"
            echo "  }," >> "$REPORT_FILE"
            ;;
        csv)
            echo "\"$domain\",\"$subject\",\"$expiry_date\",$days_remaining,\"$(if [[ $days_remaining -le 0 ]]; then echo "expired"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "critical"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "warning"; else echo "ok"; fi)\",\"$tls_version\",\"$cipher\"" >> "$REPORT_FILE"
            ;;
        *)
            printf "  %-50s  %5d days  %s\n" "$domain" "$days_remaining" "$(if [[ $days_remaining -le 0 ]]; then echo "[EXPIRED]"; elif [[ $days_remaining -le $CRITICAL_DAYS ]]; then echo "[CRITICAL]"; elif [[ $days_remaining -le $WARNING_DAYS ]]; then echo "[WARNING]"; else echo "[OK]"; fi)" >> "$REPORT_FILE"
            ;;
    esac

    # Clean up
    rm -f "$temp_cert"

    return $result
}

# Load domains from configuration file
load_domains_from_config() {
    local config_file="$1"
    local domains=()

    if [[ ! -f "$config_file" ]]; then
        log_warn "Configuration file not found: $config_file"
        return 1
    fi

    log_debug "Loading domains from configuration file: $config_file"

    if command_exists jq; then
        # Extract domains with jq if available
        mapfile -t domains < <(jq -r '.domains[]?' "$config_file" 2>/dev/null)
    else
        # Fallback to grep
        local domain_lines=$(grep -o '"domains":\s*\[\([^]]*\)\]' "$config_file" 2>/dev/null)
        domain_lines=$(echo "$domain_lines" | sed 's/"domains":\s*\[\(.*\)\]/\1/' | tr -d '[]" ')
        IFS=',' read -ra domains <<< "$domain_lines"
    fi

    echo "${domains[@]}"
}

# Generate summary report
generate_summary() {
    local total_checked=$((STATUS_SUCCESS + STATUS_WARNING + STATUS_ERROR))

    case "$OUTPUT_FORMAT" in
        json)
            # Finalize JSON file (replace last comma with closing brackets)
            sed -i.bak '$ s/},$/}/' "$REPORT_FILE" 2>/dev/null || true

            # Add summary section
            cat >> "$REPORT_FILE" <<EOF
  ],
  "summary": {
    "total_checked": $total_checked,
    "ok": $STATUS_SUCCESS,
    "warning": $STATUS_WARNING,
    "critical": $STATUS_ERROR,
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "hostname": "$(hostname)"
  }
}
EOF
            ;;
        csv)
            # Add empty line and summary section
            echo "" >> "$REPORT_FILE"
            echo "\"SUMMARY\",\"Total: $total_checked\",\"OK: $STATUS_SUCCESS\",\"Warning: $STATUS_WARNING\",\"Critical: $STATUS_ERROR\",\"$(date)\"" >> "$REPORT_FILE"
            ;;
        *)
            # Add summary section
            echo "" >> "$REPORT_FILE"
            echo "Summary:" >> "$REPORT_FILE"
            echo "  Total certificates checked: $total_checked" >> "$REPORT_FILE"
            echo "  OK: $STATUS_SUCCESS" >> "$REPORT_FILE"
            echo "  Warning: $STATUS_WARNING" >> "$REPORT_FILE"
            echo "  Critical: $STATUS_ERROR" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
            echo "Report generated: $(date)" >> "$REPORT_FILE"
            echo "Hostname: $(hostname)" >> "$REPORT_FILE"
            ;;
    esac
}

# --- Argument Parsing ---
CERT_DIRS=()
DOMAINS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cert-dir)
            shift
            CERT_DIRS+=("$1")
            shift
            ;;
        --domains)
            shift
            DOMAINS="$1"
            shift
            ;;
        --warning-days)
            shift
            WARNING_DAYS="$1"
            shift
            ;;
        --critical-days)
            shift
            CRITICAL_DAYS="$1"
            shift
            ;;
        --email)
            shift
            EMAIL_RECIPIENT="$1"
            shift
            ;;
        --slack-webhook)
            shift
            SLACK_WEBHOOK="$1"
            shift
            ;;
        --output-format)
            shift
            OUTPUT_FORMAT="$1"
            shift
            ;;
        --config)
            shift
            CONFIG_FILE="$1"
            shift
            ;;
        --no-external)
            CHECK_EXTERNAL=false
            shift
            ;;
        --no-local)
            CHECK_LOCAL=false
            shift
            ;;
        --check-revocation)
            CHECK_REVOCATION=true
            shift
            ;;
        --exit-on-expiry)
            EXIT_ON_EXPIRY=true
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

# Initialize report file based on output format
case "$OUTPUT_FORMAT" in
    json)
        echo "{" > "$REPORT_FILE"
        echo "  \"certificates\": [" >> "$REPORT_FILE"
        ;;
    csv)
        echo "\"Certificate\",\"Subject\",\"Expiry Date\",\"Days Remaining\",\"Status\",\"Additional Info\"" > "$REPORT_FILE"
        ;;
    *)
        echo "Certificate Expiration Report - $(date)" > "$REPORT_FILE"
        echo "========================================" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        ;;
esac

# --- Main Logic ---
main() {
    log_info "Starting certificate expiration check"

    # Load configuration from file
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE"

        if command_exists jq; then
            # Try to extract configuration with jq
            local config_warning_days=$(jq -r '.warning_days // empty' "$CONFIG_FILE" 2>/dev/null)
            local config_critical_days=$(jq -r '.critical_days // empty' "$CONFIG_FILE" 2>/dev/null)
            local config_email=$(jq -r '.email_recipient // empty' "$CONFIG_FILE" 2>/dev/null)
            local config_slack=$(jq -r '.slack_webhook // empty' "$CONFIG_FILE" 2>/dev/null)

            # Apply configuration if present
            [[ -n "$config_warning_days" ]] && WARNING_DAYS="$config_warning_days"
            [[ -n "$config_critical_days" ]] && CRITICAL_DAYS="$config_critical_days"
            [[ -n "$config_email" && -z "$EMAIL_RECIPIENT" ]] && EMAIL_RECIPIENT="$config_email"
            [[ -n "$config_slack" && -z "$SLACK_WEBHOOK" ]] && SLACK_WEBHOOK="$config_slack"
        else
            # Fallback to grep for basic extraction
            log_debug "jq not found, using basic config extraction"
            local config_warning_days=$(grep -o '"warning_days":\s*[0-9]\+' "$CONFIG_FILE" 2>/dev/null | cut -d: -f2 | tr -d ' ')
            local config_critical_days=$(grep -o '"critical_days":\s*[0-9]\+' "$CONFIG_FILE" 2>/dev/null | cut -d: -f2 | tr -d ' ')

            [[ -n "$config_warning_days" ]] && WARNING_DAYS="$config_warning_days"
            [[ -n "$config_critical_days" ]] && CRITICAL_DAYS="$config_critical_days"
        fi
    fi

    # Validate days are numbers
    if ! [[ "$WARNING_DAYS" =~ ^[0-9]+$ ]]; then
        log_error "Invalid warning days: $WARNING_DAYS. Must be a positive integer."
        exit 1
    fi

    if ! [[ "$CRITICAL_DAYS" =~ ^[0-9]+$ ]]; then
        log_error "Invalid critical days: $CRITICAL_DAYS. Must be a positive integer."
        exit 1
    fi

    log_debug "Using warning threshold: $WARNING_DAYS days, critical threshold: $CRITICAL_DAYS days"

    # Check if OpenSSL is available
    if ! command_exists openssl; then
        log_error "OpenSSL is not installed. Cannot check certificates."
        exit 1
    fi

    # Check external domain certificates
    if [[ "$CHECK_EXTERNAL" == "true" ]]; then
        local domain_list=()

        # Process domains from command line
        if [[ -n "$DOMAINS" ]]; then
            IFS=',' read -ra domain_list <<< "$DOMAINS"
        else
            # Try to load domains from config file
            IFS=' ' read -ra domain_list <<< "$(load_domains_from_config "$CONFIG_FILE")"
        fi

        if [[ ${#domain_list[@]} -gt 0 ]]; then
            case "$OUTPUT_FORMAT" in
                json)
                    # JSON format - entries added in check_remote_certificate
                    ;;
                csv)
                    # CSV format - entries added in check_remote_certificate
                    ;;
                *)
                    echo "External Domain Certificates:" >> "$REPORT_FILE"
                    echo "----------------------------" >> "$REPORT_FILE"
                    ;;
            esac

            for domain in "${domain_list[@]}"; do
                check_remote_certificate "$domain"
            done
        else
            log_info "No external domains specified for checking"
        fi
    fi

    # Check local certificate files
    if [[ "$CHECK_LOCAL" == "true" ]]; then
        # If no cert dirs specified, use the defaults
        if [[ ${#CERT_DIRS[@]} -eq 0 ]]; then
            CERT_DIRS=("${DEFAULT_CERT_DIRS[@]}")
        fi

        local found_certs=false

        case "$OUTPUT_FORMAT" in
            json)
                # JSON format - entries added in check_local_certificate
                ;;
            csv)
                # CSV format - entries added in check_local_certificate
                ;;
            *)
                echo "" >> "$REPORT_FILE"
                echo "Local Certificate Files:" >> "$REPORT_FILE"
                echo "-----------------------" >> "$REPORT_FILE"
                ;;
        esac

        for dir in "${CERT_DIRS[@]}"; do
            if [[ ! -d "$dir" ]]; then
                log_debug "Certificate directory not found: $dir"
                continue
            fi

            log_info "Scanning directory: $dir"

            # Find certificate files with various extensions
            local cert_files=()
            while IFS= read -r -d '' file; do
                cert_files+=("$file")
            done < <(find "$dir" -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.cert" \) -print0 2>/dev/null)

            if [[ ${#cert_files[@]} -gt 0 ]]; then
                found_certs=true

                # Check each certificate
                for cert_file in "${cert_files[@]}"; do
                    if [[ -f "$cert_file" && -r "$cert_file" ]]; then
                        check_local_certificate "$cert_file"
                    fi
                done
            fi
        done

        if [[ "$found_certs" != "true" ]]; then
            log_warn "No certificate files found in specified directories"
            case "$OUTPUT_FORMAT" in
                json)
                    # JSON format
                    echo "  {" >> "$REPORT_FILE"
                    echo "    \"warning\": \"No certificate files found in specified directories\"" >> "$REPORT_FILE"
                    echo "  }," >> "$REPORT_FILE"
                    ;;
                csv)
                    # CSV format
                    echo "\"WARNING\",\"No certificate files found in specified directories\",\"\",\"\",\"warning\",\"\"" >> "$REPORT_FILE"
                    ;;
                *)
                    echo "  No certificate files found in specified directories" >> "$REPORT_FILE"
                    ;;
            esac
        fi
    fi

    # Generate summary report
    generate_summary

    # Display final status
    log_info "Certificate check completed successfully"
    log_info "Total certificates checked: $((STATUS_SUCCESS + STATUS_WARNING + STATUS_ERROR))"
    log_info "OK: $STATUS_SUCCESS, Warning: $STATUS_WARNING, Critical: $STATUS_ERROR"
    log_info "Report file: $REPORT_FILE"

    # Exit with appropriate code if requested
    if [[ "$EXIT_ON_EXPIRY" == "true" && $((STATUS_WARNING + STATUS_ERROR)) -gt 0 ]]; then
        log_warn "Exiting with non-zero code due to expiring certificates"
        exit 1
    fi

    exit 0
}

# --- Run Script ---
main "$@"
