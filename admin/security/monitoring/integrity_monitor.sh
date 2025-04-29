#!/bin/bash
# Enhanced File Integrity Monitoring System for Cloud Infrastructure Platform
#
# Monitors critical files for unauthorized modifications, verifies cryptographic
# signatures, and detects potential tampering or rootkits. Designed for
# administrative security operations.

set -eo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$SCRIPT_DIR")")" && pwd)"
ADMIN_CONFIG_DIR="${PROJECT_ROOT}/admin/security/monitoring/config"
LOG_DIR="/var/log/cloud-platform/security"
REPORT_DIR="/var/www/reports/security"
DEFAULT_BASELINE_FILE="${ADMIN_CONFIG_DIR}/baseline/integrity_baseline.json"
DEFAULT_CONFIG_FILE="${ADMIN_CONFIG_DIR}/integrity_monitor.conf"
DEFAULT_LOG_FILE="${LOG_DIR}/integrity_monitor.log"
DEFAULT_REPORT_FILE="${REPORT_DIR}/integrity_report-$(date +%Y%m%d_%H%M%S).json"

# Default settings
BASELINE_FILE="$DEFAULT_BASELINE_FILE"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"
LOG_FILE="$DEFAULT_LOG_FILE"
REPORT_FILE="$DEFAULT_REPORT_FILE"
SCAN_SCOPE="critical" # Options: critical, config, all, custom path
ALERT_ON_CHANGE=true
VERIFY_SIGNATURES=false
VERBOSE=false
QUIET=false
DRY_RUN=false
OUTPUT_FORMAT="json" # Options: json, text
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
EXCLUDE_PATTERNS=()

# --- Ensure Directories Exist ---
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

# --- Source Common Utilities ---
COMMON_LOGGING_UTILS="${PROJECT_ROOT}/scripts/utils/common/common_logging_utils.sh"
COMMON_FILE_OPS_UTILS="${PROJECT_ROOT}/scripts/utils/common/common_file_ops_utils.sh"
COMMON_VALIDATION_UTILS="${PROJECT_ROOT}/scripts/monitoring/common/validation.sh"

if [[ -f "$COMMON_LOGGING_UTILS" ]]; then
    # shellcheck source=../../scripts/utils/common/common_logging_utils.sh
    source "$COMMON_LOGGING_UTILS"
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
    log_debug() { [[ "$VERBOSE" == "true" ]] && log "$1" "DEBUG"; }
    log_script_start() { log_info "Starting $(basename "$0")"; }
    log_script_end() { log_info "$(basename "$0") finished: $1"; }
fi

if [[ -f "$COMMON_FILE_OPS_UTILS" ]]; then
    # shellcheck source=../../scripts/utils/common/common_file_ops_utils.sh
    source "$COMMON_FILE_OPS_UTILS"
else
    # Fallback secure temp file creation function
    create_secure_temp() {
        local prefix="${1:-temp}"
        local perms="${2:-0600}"
        local temp_file
        temp_file=$(mktemp "/tmp/${prefix}.XXXXXX") || return 1
        chmod "$perms" "$temp_file" 2>/dev/null || true
        echo "$temp_file"
    }
fi

if [[ -f "$COMMON_VALIDATION_UTILS" ]]; then
    # shellcheck source=../../scripts/monitoring/common/validation.sh
    source "$COMMON_VALIDATION_UTILS"
else
    # Simple path validation
    validate_path_safety() {
        local path="$1"
        # Check for path traversal attempts
        if [[ "$path" == *".."* || "$path" == *"~"* ]]; then
            return 1
        fi
        return 0
    }
fi

# --- Functions ---

# Display usage information
usage() {
    cat <<EOF
Enhanced File Integrity Monitoring System

Usage: $(basename "$0") [options]

Options:
  --baseline FILE      Path to the baseline hash file (default: $DEFAULT_BASELINE_FILE)
  --config FILE        Path to the configuration file (default: $DEFAULT_CONFIG_FILE)
  --log-file FILE      Path to the log file (default: $DEFAULT_LOG_FILE)
  --report-file FILE   Path to the report output file (default: $DEFAULT_REPORT_FILE)
  --scope SCOPE        Scan scope: critical, config, all, or a specific path (default: critical)
  --scan-all           Equivalent to --scope all
  --exclude PATTERN    Exclude files matching pattern (can be used multiple times)
  --verify-signatures  Verify cryptographic signatures of binaries (requires GPG setup)
  --no-alert           Disable alerting on changes (default: alerts enabled)
  --format FORMAT      Output report format: json, text (default: json)
  --environment ENV    Target environment (development, staging, production)
  --verbose, -v        Enable verbose output
  --quiet, -q          Suppress informational output (errors still shown)
  --dry-run            Perform checks but don't save report or send alerts
  --help, -h           Show this help message

Examples:
  $(basename "$0") --scope config --alert-on-change
  $(basename "$0") --scan-all --verify-signatures --report-file /tmp/full_integrity_report.json
  $(basename "$0") --scope /etc/nginx/nginx.conf
  $(basename "$0") --scope critical --exclude "*.log" --exclude "*.tmp"
EOF
    exit 0
}

# Load configuration from file
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE"

        # Source the config file if it exists
        if [[ -f "$CONFIG_FILE" ]]; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE" || {
                log_error "Failed to source configuration file: $CONFIG_FILE"
                return 1
            }

            # Load paths from config
            if [[ -v CRITICAL_PATHS_CONFIG && ${#CRITICAL_PATHS_CONFIG[@]} -gt 0 ]]; then
                MONITORED_PATHS_CRITICAL=("${CRITICAL_PATHS_CONFIG[@]}")
            fi

            if [[ -v CONFIG_PATHS_CONFIG && ${#CONFIG_PATHS_CONFIG[@]} -gt 0 ]]; then
                MONITORED_PATHS_CONFIG=("${CONFIG_PATHS_CONFIG[@]}")
            fi

            if [[ -v EXCLUDE_PATTERNS_CONFIG && ${#EXCLUDE_PATTERNS_CONFIG[@]} -gt 0 ]]; then
                EXCLUDE_PATTERNS+=("${EXCLUDE_PATTERNS_CONFIG[@]}")
            fi

            # Load GPG settings
            if [[ -v GPG_KEYRING_CONFIG ]]; then
                GPG_KEYRING="$GPG_KEYRING_CONFIG"
            fi

            log_debug "Loaded configuration settings from $CONFIG_FILE"
        fi
    else
        log_warn "Configuration file not found: $CONFIG_FILE. Using defaults."
    fi

    # Define default paths if not set by config
    if [[ ! -v MONITORED_PATHS_CRITICAL || ${#MONITORED_PATHS_CRITICAL[@]} -eq 0 ]]; then
        MONITORED_PATHS_CRITICAL=(
            "/bin/bash"
            "/usr/sbin/sshd"
            "/etc/passwd"
            "/etc/shadow"
            "/etc/pam.d"
            "/etc/sudoers"
            "/etc/sudoers.d"
            "/etc/ssl/certs/ca-certificates.crt"
        )
    fi

    if [[ ! -v MONITORED_PATHS_CONFIG || ${#MONITORED_PATHS_CONFIG[@]} -eq 0 ]]; then
        MONITORED_PATHS_CONFIG=(
            "/etc/ssh/sshd_config"
            "${ADMIN_CONFIG_DIR}/"
            "/etc/nginx/nginx.conf"
            "/etc/nginx/conf.d"
            "/etc/cloud-platform"
        )
    fi

    log_debug "Using ${#MONITORED_PATHS_CRITICAL[@]} critical paths and ${#MONITORED_PATHS_CONFIG[@]} configuration paths"
}

# Calculate hash of a file
calculate_hash() {
    local file_path="$1"
    local algorithm="${2:-sha256sum}"

    if [[ ! -f "$file_path" ]]; then
        return 1
    fi

    case "$algorithm" in
        md5)
            md5sum "$file_path" 2>/dev/null | awk '{print $1}' || echo ""
            ;;
        sha1)
            sha1sum "$file_path" 2>/dev/null | awk '{print $1}' || echo ""
            ;;
        sha256|*)
            sha256sum "$file_path" 2>/dev/null | awk '{print $1}' || echo ""
            ;;
    esac
}

# Verify signature of a file
verify_signature() {
    local file_path="$1"
    local keyring="${2:-}"

    if [[ ! -f "$file_path" ]]; then
        echo "no_file"
        return 1
    fi

    # Check for .sig or .asc file
    local sig_file=""
    if [[ -f "${file_path}.sig" ]]; then
        sig_file="${file_path}.sig"
    elif [[ -f "${file_path}.asc" ]]; then
        sig_file="${file_path}.asc"
    else
        echo "no_signature"
        return 0
    fi

    # Check if gpg is available
    if ! command -v gpg &>/dev/null; then
        log_warn "GPG not available. Cannot verify signatures."
        echo "unverified"
        return 0
    fi

    local gpg_args=()
    if [[ -n "$keyring" && -f "$keyring" ]]; then
        gpg_args+=("--keyring" "$keyring")
    fi

    # Verify signature
    if gpg "${gpg_args[@]}" --verify "$sig_file" "$file_path" &>/dev/null; then
        echo "verified"
        return 0
    else
        echo "failed"
        return 1
    fi
}

# Check if file should be excluded based on patterns
should_exclude() {
    local file_path="$1"

    if [[ ${#EXCLUDE_PATTERNS[@]} -eq 0 ]]; then
        return 1  # No exclusions, don't exclude
    fi

    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        if [[ "$file_path" == $pattern ]]; then
            return 0  # Exclude exact match
        elif [[ "$file_path" == *"$pattern"* ]]; then
            return 0  # Exclude if pattern is contained
        elif [[ "$(basename "$file_path")" == $pattern ]]; then
            return 0  # Exclude if basename matches
        fi
    done

    return 1  # Don't exclude
}

# Process a data structure for the report
process_findings_for_report() {
    local report_format="$OUTPUT_FORMAT"
    local temp_file

    temp_file=$(create_secure_temp "integrity_report") || {
        log_error "Failed to create temporary file for report generation"
        return 1
    }

    if [[ "$report_format" == "json" ]]; then
        # Create JSON report structure
        cat > "$temp_file" << EOF
{
  "report_metadata": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "scope": "$SCAN_SCOPE",
    "baseline_file": "$BASELINE_FILE",
    "host": "$(hostname)",
    "scan_id": "$TIMESTAMP"
  },
  "findings": [
EOF

        local first_item=true

        # Add modified files to JSON
        for file in "${modified_files[@]}"; do
            if [[ "$first_item" == "false" ]]; then
                echo "," >> "$temp_file"
            fi
            first_item=false

            local expected_hash="${baseline_hashes[$file]}"
            local current_hash="${current_hashes[$file]}"

            cat >> "$temp_file" << EOF
    {
      "file": "$(echo "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')",
      "status": "modified",
      "expected_hash": "$expected_hash",
      "current_hash": "$current_hash",
      "severity": "high"
    }
EOF
        done

        # Add new files to JSON
        for file in "${new_files[@]}"; do
            if [[ "$first_item" == "false" ]]; then
                echo "," >> "$temp_file"
            fi
            first_item=false

            local current_hash="${current_hashes[$file]}"

            cat >> "$temp_file" << EOF
    {
      "file": "$(echo "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')",
      "status": "new",
      "current_hash": "$current_hash",
      "severity": "medium"
    }
EOF
        done

        # Add deleted files to JSON
        for file in "${deleted_files[@]}"; do
            if [[ "$first_item" == "false" ]]; then
                echo "," >> "$temp_file"
            fi
            first_item=false

            local expected_hash="${baseline_hashes[$file]}"

            cat >> "$temp_file" << EOF
    {
      "file": "$(echo "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')",
      "status": "deleted",
      "expected_hash": "$expected_hash",
      "severity": "high"
    }
EOF
        done

        # Add signature failures to JSON
        if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
            for file in "${signature_failures[@]}"; do
                if [[ "$first_item" == "false" ]]; then
                    echo "," >> "$temp_file"
                fi
                first_item=false

                local current_hash="${current_hashes[$file]}"

                cat >> "$temp_file" << EOF
    {
      "file": "$(echo "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')",
      "status": "signature_failed",
      "current_hash": "$current_hash",
      "severity": "critical"
    }
EOF
            done
        fi

        # Close the JSON structure
        cat >> "$temp_file" << EOF
  ],
  "summary": {
    "total_scanned": ${#scanned_files[@]},
    "modified": ${#modified_files[@]},
    "new": ${#new_files[@]},
    "deleted": ${#deleted_files[@]},
    "signature_failures": ${#signature_failures[@]:-0},
    "changes_detected": $([[ "$change_detected" == "true" ]] && echo "true" || echo "false")
  }
}
EOF
    else
        # Create text report
        cat > "$temp_file" << EOF
==================================================
= File Integrity Check Report
= Generated: $(date)
==================================================
Scope: $SCAN_SCOPE
Baseline: $BASELINE_FILE
Host: $(hostname)
Scan ID: $TIMESTAMP
==================================================

EOF

        # Summary section
        cat >> "$temp_file" << EOF
SUMMARY:
--------
Total files scanned: ${#scanned_files[@]}
Modified files: ${#modified_files[@]}
New files: ${#new_files[@]}
Deleted files: ${#deleted_files[@]}
Signature failures: ${#signature_failures[@]:-0}

EOF

        # Only add details if we have findings
        if [[ ${#modified_files[@]} -gt 0 || ${#new_files[@]} -gt 0 || ${#deleted_files[@]} -gt 0 || ${#signature_failures[@]:-0} -gt 0 ]]; then
            cat >> "$temp_file" << EOF
FINDINGS:
---------
EOF

            # Add modified files
            if [[ ${#modified_files[@]} -gt 0 ]]; then
                echo -e "\nMODIFIED FILES:" >> "$temp_file"
                echo "-----------------" >> "$temp_file"
                for file in "${modified_files[@]}"; do
                    local expected_hash="${baseline_hashes[$file]}"
                    local current_hash="${current_hashes[$file]}"
                    echo "  - $file" >> "$temp_file"
                    echo "    Expected: $expected_hash" >> "$temp_file"
                    echo "    Current:  $current_hash" >> "$temp_file"
                    echo >> "$temp_file"
                done
            fi

            # Add new files
            if [[ ${#new_files[@]} -gt 0 ]]; then
                echo -e "\nNEW FILES:" >> "$temp_file"
                echo "-----------" >> "$temp_file"
                for file in "${new_files[@]}"; do
                    local current_hash="${current_hashes[$file]}"
                    echo "  - $file" >> "$temp_file"
                    echo "    Hash: $current_hash" >> "$temp_file"
                    echo >> "$temp_file"
                done
            fi

            # Add deleted files
            if [[ ${#deleted_files[@]} -gt 0 ]]; then
                echo -e "\nDELETED FILES:" >> "$temp_file"
                echo "--------------" >> "$temp_file"
                for file in "${deleted_files[@]}"; do
                    local expected_hash="${baseline_hashes[$file]}"
                    echo "  - $file" >> "$temp_file"
                    echo "    Expected hash: $expected_hash" >> "$temp_file"
                    echo >> "$temp_file"
                done
            fi

            # Add signature failures
            if [[ "$VERIFY_SIGNATURES" == "true" && ${#signature_failures[@]:-0} -gt 0 ]]; then
                echo -e "\nSIGNATURE FAILURES:" >> "$temp_file"
                echo "-------------------" >> "$temp_file"
                for file in "${signature_failures[@]}"; do
                    local current_hash="${current_hashes[$file]}"
                    echo "  - $file" >> "$temp_file"
                    echo "    Hash: $current_hash" >> "$temp_file"
                    echo >> "$temp_file"
                done
            fi
        else
            cat >> "$temp_file" << EOF
No integrity changes detected.
All scanned files match their expected hashes.
EOF
        fi

        # Close the text report
        cat >> "$temp_file" << EOF

==================================================
End of Integrity Check Report
==================================================
EOF
    fi

    # Copy to final report file
    cp "$temp_file" "$REPORT_FILE"
    chmod 600 "$REPORT_FILE"

    # Clean up
    rm -f "$temp_file"

    log_info "Report saved to $REPORT_FILE"
    return 0
}

# Generate integrity report
generate_report() {
    log_info "Generating integrity report..."

    # Process findings into appropriate format
    process_findings_for_report

    return $?
}

# Send alert notification
send_alert() {
    local subject="$1"
    local message="$2"
    local priority="${3:-high}"

    if [[ "$ALERT_ON_CHANGE" != "true" || "$DRY_RUN" == "true" ]]; then
        log_info "Alerting disabled or dry run mode, skipping notification."
        return 0
    fi

    log_warn "ALERT: $subject"

    # Use notification script if available
    local notification_script="${PROJECT_ROOT}/scripts/utils/send-notification.sh"
    if [[ -x "$notification_script" ]]; then
        "$notification_script" \
            --priority "$priority" \
            --subject "$subject" \
            --message "$message" \
            --source "IntegrityMonitor" \
            --attach "$REPORT_FILE" || {
                log_error "Failed to send notification using send-notification.sh"
                return 1
            }
    else
        # Fall back to mail command if available
        if command -v mail &>/dev/null; then
            echo -e "$message\n\nSee attached report for details." | mail -s "$subject" -a "$REPORT_FILE" root@localhost || {
                log_error "Failed to send notification email"
                return 1
            }
            log_info "Alert sent via email to root@localhost"
        else
            log_warn "Notification script not found and mail command not available. Could not send alert."
            return 1
        }
    fi

    return 0
}

# Create a baseline file from current file states
create_baseline() {
    local output_file="$1"

    if [[ -z "$output_file" ]]; then
        output_file="$DEFAULT_BASELINE_FILE"
    fi

    log_info "Creating baseline file from current state..."

    # Create temp file for baseline
    local temp_file
    temp_file=$(create_secure_temp "baseline") || {
        log_error "Failed to create temporary file for baseline generation"
        return 1
    }

    # Start JSON structure
    echo "{" > "$temp_file"

    local first_item=true

    # Add files to baseline
    for file in "${scanned_files[@]}"; do
        local hash="${current_hashes[$file]}"

        # Skip if no hash was calculated
        if [[ -z "$hash" ]]; then
            continue
        fi

        if [[ "$first_item" == "false" ]]; then
            echo "," >> "$temp_file"
        fi
        first_item=false

        # Add file and hash to JSON
        echo "  \"$(echo "$file" | sed 's/\\/\\\\/g; s/"/\\"/g')\": \"$hash\"" >> "$temp_file"
    done

    # Close JSON structure
    echo "}" >> "$temp_file"

    # Copy to final baseline file, creating directories if needed
    mkdir -p "$(dirname "$output_file")"
    cp "$temp_file" "$output_file"
    chmod 600 "$output_file"

    # Clean up
    rm -f "$temp_file"

    log_info "Baseline created with ${#scanned_files[@]} files and saved to $output_file"
    return 0
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --baseline)
            BASELINE_FILE="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --report-file)
            REPORT_FILE="$2"
            shift 2
            ;;
        --scope)
            SCAN_SCOPE="$2"
            shift 2
            ;;
        --scan-all)
            SCAN_SCOPE="all"
            shift
            ;;
        --exclude)
            EXCLUDE_PATTERNS+=("$2")
            shift 2
            ;;
        --verify-signatures)
            VERIFY_SIGNATURES=true
            shift
            ;;
        --no-alert)
            ALERT_ON_CHANGE=false
            shift
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --create-baseline)
            CREATE_BASELINE=true
            shift
            ;;
        --baseline-output)
            BASELINE_OUTPUT="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
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

# --- Main Logic ---
log_script_start

# Validate parameters
if [[ "$OUTPUT_FORMAT" != "json" && "$OUTPUT_FORMAT" != "text" ]]; then
    log_error "Invalid output format: $OUTPUT_FORMAT. Use 'json' or 'text'."
    exit 1
fi

if [[ -n "$ENVIRONMENT" ]]; then
    if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
        log_error "Invalid environment: $ENVIRONMENT. Must be development, staging, production, or dr-recovery."
        exit 1
    fi

    # Adjust baseline file based on environment if not explicitly set
    if [[ "$BASELINE_FILE" == "$DEFAULT_BASELINE_FILE" ]]; then
        BASELINE_FILE="${ADMIN_CONFIG_DIR}/baseline/integrity_baseline_${ENVIRONMENT}.json"
    fi

    log_info "Using environment-specific baseline: $BASELINE_FILE"
fi

# Load configuration
load_config

# Variables for findings
declare -A baseline_hashes=()
declare -A current_hashes=()
declare -A signature_status=()
declare -a modified_files=()
declare -a new_files=()
declare -a deleted_files=()
declare -a signature_failures=()
declare -a scanned_files=()
change_detected=false

# Load baseline file (unless we're just creating a baseline)
if [[ "$CREATE_BASELINE" != "true" ]]; then
    log_info "Loading baseline from $BASELINE_FILE"
    if [[ -f "$BASELINE_FILE" ]]; then
        # Use jq to parse the baseline file into the associative array
        if command -v jq &> /dev/null; then
            while IFS="=" read -r key value; do
                # Remove quotes from key and value
                key="${key%\"}"
                key="${key#\"}"
                value="${value%\"}"
                value="${value#\"}"
                baseline_hashes["$key"]="$value"
            done < <(jq -r 'to_entries|map("\(.key)=\(.value)")|.[]' "$BASELINE_FILE" 2>/dev/null || echo "")
            log_debug "Loaded ${#baseline_hashes[@]} entries from baseline"
        else
            log_error "jq command not found. Cannot parse JSON baseline file."
            exit 1
        fi
    else
        log_error "Baseline file not found: $BASELINE_FILE"
        if [[ "$CREATE_BASELINE" != "true" ]]; then
            exit 1
        fi
    fi
fi

# Determine files to scan based on scope
declare -a files_to_scan
log_info "Determining files to scan based on scope: $SCAN_SCOPE"
case "$SCAN_SCOPE" in
    critical)
        if [[ ${#MONITORED_PATHS_CRITICAL[@]} -eq 0 ]]; then
            log_error "No critical paths defined."
            exit 1
        fi
        files_to_scan=("${MONITORED_PATHS_CRITICAL[@]}")
        ;;
    config)
        if [[ ${#MONITORED_PATHS_CONFIG[@]} -eq 0 ]]; then
            log_error "No configuration paths defined."
            exit 1
        fi
        files_to_scan=("${MONITORED_PATHS_CONFIG[@]}")
        ;;
    all)
        # Combine critical and config, potentially add more broad paths
        files_to_scan=("${MONITORED_PATHS_CRITICAL[@]}" "${MONITORED_PATHS_CONFIG[@]}")
        ;;
    *)
        # Assume custom path or pattern
        if [[ -e "$SCAN_SCOPE" ]]; then
            if [[ -d "$SCAN_SCOPE" ]]; then
                # Validate path for security
                if ! validate_path_safety "$SCAN_SCOPE"; then
                    log_error "Invalid or potentially unsafe path: $SCAN_SCOPE"
                    exit 1
                fi

                # Find files within the directory
                while IFS= read -r file; do
                    files_to_scan+=("$file")
                done < <(find "$SCAN_SCOPE" -type f -follow 2>/dev/null)
            else
                # Validate path for security
                if ! validate_path_safety "$SCAN_SCOPE"; then
                    log_error "Invalid or potentially unsafe path: $SCAN_SCOPE"
                    exit 1
                fi

                files_to_scan=("$SCAN_SCOPE")
            fi
        else
            log_error "Invalid scope or path not found: $SCAN_SCOPE"
            exit 1
        fi
        ;;
esac
log_debug "Found ${#files_to_scan[@]} potential items to scan"

# Perform scan
log_info "Starting integrity scan..."

for item in "${files_to_scan[@]}"; do
    if [[ -d "$item" ]]; then
        # Scan files within the directory
        while IFS= read -r file; do
            # Skip if file should be excluded
            if should_exclude "$file"; then
                log_debug "Skipping excluded file: $file"
                continue
            fi

            # Avoid duplicates if a directory and its contents are listed
            if [[ ! " ${scanned_files[*]} " =~ " ${file} " ]]; then
                log_debug "Scanning file: $file"
                current_hash=$(calculate_hash "$file")

                # Only add if hash was successfully calculated
                if [[ -n "$current_hash" ]]; then
                    current_hashes["$file"]="$current_hash"

                    if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
                        sig_status=$(verify_signature "$file" "$GPG_KEYRING")
                        signature_status["$file"]="$sig_status"

                        if [[ "$sig_status" == "failed" ]]; then
                            signature_failures+=("$file")
                        fi
                    fi

                    scanned_files+=("$file")
                fi
            fi
        done < <(find "$item" -type f -follow 2>/dev/null)
    elif [[ -f "$item" ]]; then
        # Skip if file should be excluded
        if should_exclude "$item"; then
            log_debug "Skipping excluded file: $item"
            continue
        fi

        # Scan a single file
        if [[ ! " ${scanned_files[*]} " =~ " ${item} " ]]; then
            log_debug "Scanning file: $item"
            current_hash=$(calculate_hash "$item")

            # Only add if hash was successfully calculated
            if [[ -n "$current_hash" ]]; then
                current_hashes["$item"]="$current_hash"

                if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
                    sig_status=$(verify_signature "$item" "$GPG_KEYRING")
                    signature_status["$item"]="$sig_status"

                    if [[ "$sig_status" == "failed" ]]; then
                        signature_failures+=("$item")
                    fi
                fi

                scanned_files+=("$item")
            fi
        fi
    else
        log_warn "Path not found or not a file/directory: $item"
    fi
done

log_info "Scan complete. Processed ${#scanned_files[@]} files."

# If creating a baseline, do that and exit
if [[ "$CREATE_BASELINE" == "true" ]]; then
    create_baseline "${BASELINE_OUTPUT:-$BASELINE_FILE}"
    exit_code=$?
    log_script_end "Baseline creation $(if [[ $exit_code -eq 0 ]]; then echo "successful"; else echo "failed"; fi)"
    exit $exit_code
fi

# Compare with baseline
log_info "Comparing current state with baseline..."

# Check for modified and new files
for file in "${!current_hashes[@]}"; do
    current_hash="${current_hashes[$file]}"
    if [[ -v baseline_hashes["$file"] ]]; then
        # File exists in baseline, check hash
        expected_hash="${baseline_hashes[$file]}"
        if [[ "$current_hash" != "$expected_hash" ]]; then
            log_warn "MODIFIED: $file (Expected: $expected_hash, Current: $current_hash)"
            modified_files+=("$file")
            change_detected=true
        fi
    else
        # File does not exist in baseline
        log_warn "NEW: $file (Hash: $current_hash)"
        new_files+=("$file")
        change_detected=true
    fi
done

# Check for deleted files
for file in "${!baseline_hashes[@]}"; do
    if [[ ! -v current_hashes["$file"] ]]; then
        # Check if file should be excluded
        if should_exclude "$file"; then
            log_debug "Skipping excluded deleted file: $file"
            continue
        fi

        # File exists in baseline but not in current scan
        log_warn "DELETED: $file (Was present in baseline)"
        deleted_files+=("$file")
        change_detected=true
    fi
done

# Check signature verification results if enabled
if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
    for file in "${!signature_status[@]}"; do
        status="${signature_status[$file]}"
        if [[ "$status" == "failed" ]]; then
            log_error "SIGNATURE FAILED: $file"
            # Already added to signature_failures array during scanning
            change_detected=true
        elif [[ "$status" != "verified" && "$status" != "unverified" && "$status" != "no_signature" ]]; then
            log_warn "Signature status unknown for $file: $status"
        fi
    done
fi

# Generate report and alert if changes detected
if [[ "$change_detected" == "true" ]]; then
    log_warn "Integrity changes detected!"
    if [[ "$DRY_RUN" != "true" ]]; then
        generate_report

        # Calculate overall severity
        severity="medium"
        if [[ ${#modified_files[@]} -gt 0 || ${#deleted_files[@]} -gt 0 ]]; then
            severity="high"
        fi
        if [[ ${#signature_failures[@]:-0} -gt 0 ]]; then
            severity="critical"
        fi

        send_alert "File Integrity Alert - ${#modified_files[@]} modified, ${#new_files[@]} new, ${#deleted_files[@]} deleted" \
                  "Integrity changes detected in ${ENVIRONMENT:-system}.\n\nModified: ${#modified_files[@]}\nNew: ${#new_files[@]}\nDeleted: ${#deleted_files[@]}\nSignature failures: ${#signature_failures[@]:-0}\n\nCheck report for details: $REPORT_FILE" \
                  "$severity"
    else
        log_info "Dry run: Report generation and alerting skipped."
        # Print findings to stdout in dry run
        echo "--- Dry Run Findings ---"
        [[ ${#modified_files[@]} -gt 0 ]] && echo "Modified (${#modified_files[@]}): ${modified_files[*]}"
        [[ ${#new_files[@]} -gt 0 ]] && echo "New (${#new_files[@]}): ${new_files[*]}"
        [[ ${#deleted_files[@]} -gt 0 ]] && echo "Deleted (${#deleted_files[@]}): ${deleted_files[*]}"
        [[ ${#signature_failures[@]:-0} -gt 0 ]] && echo "Signature failures (${#signature_failures[@]}): ${signature_failures[*]}"
        echo "------------------------"
    fi
    log_script_end "Completed with changes detected"
    exit 1  # Exit with error code if changes found
else
    log_info "No integrity changes detected."
    # Generate a "clean" report if requested
    if [[ "$DRY_RUN" != "true" && "$OUTPUT_FORMAT" == "json" ]]; then
        generate_report
    else
        log_info "Skipping report generation for clean scan in dry run or text mode."
    fi
    log_script_end "Completed successfully - no changes detected"
    exit 0
fi
