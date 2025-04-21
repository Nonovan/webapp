#!/bin/bash
# Configuration Validation Script for Cloud Infrastructure Platform
# Validates configuration files against schemas to ensure compliance standards
# Usage: ./validate_compliance.sh [--environment <env>] [--schema-dir <dir>] [--report <file>] [--strict]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
SCHEMA_DIR="${PROJECT_ROOT}/config/schemas"
CONFIG_DIR="${PROJECT_ROOT}/config"
REPORT_FILE="/var/log/cloud-platform/compliance/validation-$(date +%Y%m%d-%H%M%S).json"
LOG_DIR="/var/log/cloud-platform/compliance"
EXIT_CODE=0
STRICT_MODE=false
NOTIFY=false
EMAIL_RECIPIENT=""
DR_MODE=false
VERBOSE=false

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Log file for detailed output
LOG_FILE="${LOG_DIR}/validation-$(date +%Y%m%d-%H%M%S).log"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    
    echo "$message" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" = true && -n "$2" ]]; then
        echo "[$timestamp] [DEBUG] $2" >> "$LOG_FILE"
    fi
}

# Function to display usage
usage() {
    cat <<EOF
Configuration Validation Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --environment, -e ENV     Specify environment to validate (default: production)
  --schema-dir, -s DIR      Directory containing schema definitions (default: ${PROJECT_ROOT}/config/schemas)
  --config-dir, -c DIR      Directory containing configuration files (default: ${PROJECT_ROOT}/config)
  --report, -r FILE         Output report file (default: ${LOG_DIR}/validation-{timestamp}.json)
  --strict                  Fail on warnings as well as errors
  --notify [EMAIL]          Send notification with results
  --verbose, -v             Enable verbose output
  --help, -h                Show this help message
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --schema-dir|-s)
            SCHEMA_DIR="$2"
            shift 2
            ;;
        --config-dir|-c)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --report|-r)
            REPORT_FILE="$2"
            shift 2
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --notify)
            NOTIFY=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
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
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Function to validate JSON files against schema
validate_json() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    
    log "Validating $config_name against schema $schema_name"
    
    # Ensure jsonschema is installed
    if ! command -v jsonschema &>/dev/null; then
        log "ERROR: jsonschema validator not found. Please install with: pip install jsonschema"
        return 1
    fi
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    if jsonschema -i "$config_file" "$schema_file" 2>"$LOG_DIR/temp_error.log"; then
        log "✅ $config_name: Valid"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
        return 0
    else
        local error_msg=$(cat "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid - $error_msg"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
}

# Function to validate YAML files
validate_yaml() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    
    log "Validating $config_name against schema $schema_name"
    
    # Ensure yamllint and yq are installed
    if ! command -v yamllint &>/dev/null; then
        log "ERROR: yamllint not found. Please install with: pip install yamllint"
        return 1
    fi
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # First check syntax with yamllint
    if ! yamllint -d "{extends: relaxed, rules: {line-length: {max: 120}}}" "$config_file" &>"$LOG_DIR/temp_error.log"; then
        local error_msg=$(cat "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid YAML syntax - $error_msg"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"YAML syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    # Check if python-based validator is available
    if command -v pykwalify &>/dev/null; then
        if pykwalify -d "$config_file" -s "$schema_file" &>"$LOG_DIR/temp_error.log"; then
            log "✅ $config_name: Valid"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
            return 0
        else
            local error_msg=$(cat "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid - $error_msg"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    else
        # Fallback to basic validation
        log "WARNING: pykwalify not installed, performing basic YAML validation only"
        log "✅ $config_name: YAML syntax valid (schema validation skipped)"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Schema validation skipped - install pykwalify for full validation\"}" >> "$REPORT_FILE.tmp"
        return 0
    fi
}

# Function to validate INI files against a schema
validate_ini() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    
    log "Validating $config_name against schema $schema_name"
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # For INI files, use Python to validate
    python3 "${SCRIPT_DIR}/validators/validate_ini.py" "$config_file" "$schema_file" &>"$LOG_DIR/temp_error.log"
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "✅ $config_name: Valid"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
        return 0
    else
        local error_msg=$(cat "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid - $error_msg"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
}

# Function to validate XML files against schema
validate_xml() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    
    log "Validating $config_name against schema $schema_name"
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # Check if xmllint is available
    if command -v xmllint &>/dev/null; then
        if xmllint --schema "$schema_file" --noout "$config_file" &>"$LOG_DIR/temp_error.log"; then
            log "✅ $config_name: Valid"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
            return 0
        else
            local error_msg=$(cat "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid - $error_msg"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    else
        log "WARNING: xmllint not installed, skipping XML validation"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"Validation tool xmllint not available\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
}

# Function to perform compliance checks on files
validate_file_compliance() {
    local file="$1"
    local file_name=$(basename "$file")
    local file_ext="${file_name##*.}"
    local validation_errors=0
    local schema_found=false
    
    # Find matching schema
    case "$file_ext" in
        json)
            for schema_file in "$SCHEMA_DIR"/*.json.schema; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_json "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        yaml|yml)
            for schema_file in "$SCHEMA_DIR"/*.yaml.schema; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_yaml "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        ini|conf)
            for schema_file in "$SCHEMA_DIR"/*.ini.schema; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_ini "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        xml)
            for schema_file in "$SCHEMA_DIR"/*.xsd; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_xml "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        *)
            log "WARNING: No validation method available for $file_ext files"
            echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"No validation method available for $file_ext files\"}" >> "$REPORT_FILE.tmp"
            return 1
            ;;
    esac
    
    if [[ "$schema_found" = false ]]; then
        log "WARNING: No schema found for $file_name"
        echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"No schema found for this file type\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    return $validation_errors
}

# Function to check for security compliance issues
check_security_compliance() {
    log "Checking security compliance requirements..."
    local issues=0
    
    # Check for encryption configuration
    if ! grep -q "encryption_enabled.*=.*true" "$CONFIG_DIR/security.ini" 2>/dev/null; then
        log "❌ Security Compliance: Encryption not enabled in security.ini"
        echo "{\"file\":\"security.ini\",\"valid\":false,\"error\":\"Encryption not enabled\"}" >> "$REPORT_FILE.tmp"
        ((issues++))
    fi
    
    # Check for TLS configuration
    if ! grep -q "min_tls_version.*=.*1.2" "$CONFIG_DIR/security.ini" 2>/dev/null; then
        log "❌ Security Compliance: Minimum TLS version not set to 1.2 or higher"
        echo "{\"file\":\"security.ini\",\"valid\":false,\"error\":\"TLS version below minimum required (1.2)\"}" >> "$REPORT_FILE.tmp"
        ((issues++))
    fi
    
    # Check for password policy in production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        if ! grep -q "password_min_length.*=.*12" "$CONFIG_DIR/security.ini" 2>/dev/null; then
            log "❌ Security Compliance: Password minimum length not set to 12 or higher in production"
            echo "{\"file\":\"security.ini\",\"valid\":false,\"error\":\"Password policy does not meet production requirements\"}" >> "$REPORT_FILE.tmp"
            ((issues++))
        fi
    fi
    
    return $issues
}

# Function to check environment-specific compliance rules
check_environment_compliance() {
    log "Checking environment-specific compliance for $ENVIRONMENT..."
    local issues=0
    
    case "$ENVIRONMENT" in
        production)
            # Production needs stricter settings
            if ! grep -q "debug.*=.*false" "$CONFIG_DIR/app.ini" 2>/dev/null; then
                log "❌ Environment Compliance: Debug mode enabled in production"
                echo "{\"file\":\"app.ini\",\"valid\":false,\"error\":\"Debug mode enabled in production environment\"}" >> "$REPORT_FILE.tmp"
                ((issues++))
            fi
            
            # Check logging level
            if grep -q "log_level.*=.*debug" "$CONFIG_DIR/logging.ini" 2>/dev/null; then
                log "❌ Environment Compliance: Debug logging enabled in production"
                echo "{\"file\":\"logging.ini\",\"valid\":false,\"error\":\"Debug logging enabled in production environment\"}" >> "$REPORT_FILE.tmp"
                ((issues++))
            fi
            ;;
        staging)
            # Staging can have some relaxed settings
            ;;
        development)
            # Development can be more relaxed
            ;;
    esac
    
    return $issues
}

# Function to generate compliance report
generate_report() {
    local total=$1
    local passed=$2
    local failed=$3
    local status=$4
    
    # Finalize the JSON report
    echo "{" > "$REPORT_FILE"
    echo "  \"summary\": {" >> "$REPORT_FILE"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
    echo "    \"environment\": \"$ENVIRONMENT\"," >> "$REPORT_FILE"
    echo "    \"total_files\": $total," >> "$REPORT_FILE"
    echo "    \"passed\": $passed," >> "$REPORT_FILE"
    echo "    \"failed\": $failed," >> "$REPORT_FILE"
    echo "    \"status\": \"$status\"" >> "$REPORT_FILE"
    echo "  }," >> "$REPORT_FILE"
    echo "  \"results\": [" >> "$REPORT_FILE"
    
    # Add all detailed results
    local first=true
    while IFS= read -r line; do
        if [[ "$first" = true ]]; then
            first=false
        else
            echo "," >> "$REPORT_FILE"
        fi
        echo "    $line" >> "$REPORT_FILE"
    done < "$REPORT_FILE.tmp"
    
    echo "" >> "$REPORT_FILE"
    echo "  ]" >> "$REPORT_FILE"
    echo "}" >> "$REPORT_FILE"
    
    # Clean up temporary file
    rm "$REPORT_FILE.tmp"
    
    log "Report generated: $REPORT_FILE"
}

# Function to send email notification
send_notification() {
    local status=$1
    local details=$2
    
    if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
        log "Sending notification email to $EMAIL_RECIPIENT"
        
        local subject="Configuration Compliance Report - ${status}"
        local message="Configuration Compliance Validation Report\n\n"
        message+="Status: ${status}\n"
        message+="Environment: ${ENVIRONMENT}\n"
        message+="Timestamp: $(date)\n\n"
        message+="Summary:\n${details}\n\n"
        message+="See attached report for full details."
        
        # If our standard notification utility exists, use it
        if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
            ${PROJECT_ROOT}/scripts/utils/send-notification.sh \
                --priority $([ "$status" = "PASSED" ] && echo "low" || echo "high") \
                --subject "$subject" \
                --message "$message" \
                --recipient "$EMAIL_RECIPIENT" \
                --attachment "$REPORT_FILE"
        else
            # Fall back to mail command
            if command -v mail &>/dev/null; then
                echo -e "$message" | mail -s "$subject" -a "$REPORT_FILE" "$EMAIL_RECIPIENT"
            else
                log "WARNING: Could not send notification, mail command not available"
            fi
        fi
    fi
}

# Main execution flow
log "Starting configuration validation for ${ENVIRONMENT} environment"
log "Schema directory: $SCHEMA_DIR"
log "Config directory: $CONFIG_DIR"

# Create temporary file for report entries
> "$REPORT_FILE.tmp"

# Check if schema directory exists
if [[ ! -d "$SCHEMA_DIR" ]]; then
    log "ERROR: Schema directory $SCHEMA_DIR not found"
    exit 1
fi

# Check if config directory exists
if [[ ! -d "$CONFIG_DIR" ]]; then
    log "ERROR: Config directory $CONFIG_DIR not found"
    exit 1
fi

# Process all configuration files
TOTAL_FILES=0
PASSED_FILES=0
FAILED_FILES=0

# First validate all files against schemas
for file_pattern in "*.json" "*.yaml" "*.yml" "*.ini" "*.conf" "*.xml"; do
    for config_file in "$CONFIG_DIR"/$file_pattern; do
        if [[ -f "$config_file" ]]; then
            ((TOTAL_FILES++))
            
            if validate_file_compliance "$config_file"; then
                ((PASSED_FILES++))
            else
                ((FAILED_FILES++))
                EXIT_CODE=1
            fi
        fi
    done
done

# Check security compliance
log "Checking security compliance..."
if check_security_compliance; then
    log "✅ Security compliance checks passed"
else
    log "❌ Security compliance issues detected"
    EXIT_CODE=1
fi

# Check environment-specific compliance rules
log "Checking environment-specific compliance..."
if check_environment_compliance; then
    log "✅ Environment-specific compliance checks passed"
else
    log "❌ Environment-specific compliance issues detected"
    EXIT_CODE=1
fi

# If strict mode is enabled, check for warnings too
if [[ "$STRICT_MODE" = true ]]; then
    log "Strict mode enabled - checking for warnings..."
    WARNING_COUNT=$(grep -c "\"warning\":" "${REPORT_FILE}.tmp" || echo "0")
    if [[ $WARNING_COUNT -gt 0 ]]; then
        log "❌ Found $WARNING_COUNT warnings that are treated as failures in strict mode"
        EXIT_CODE=1
    fi
fi

# Determine overall status based on exit code
if [[ $EXIT_CODE -eq 0 ]]; then
    STATUS="PASSED"
else
    STATUS="FAILED"
fi

# Generate the final report
generate_report $TOTAL_FILES $PASSED_FILES $FAILED_FILES $STATUS

# Display summary information
log "==================================================="
log "Validation Summary:"
log "Total files checked: $TOTAL_FILES"
log "Passed: $PASSED_FILES"
log "Failed: $FAILED_FILES"
if [[ "$STRICT_MODE" = true && $WARNING_COUNT -gt 0 ]]; then
    log "Warnings (treated as failures): $WARNING_COUNT"
fi
log "==================================================="
log "Configuration validation completed with status: $STATUS"

# Add validation metadata to the summary
SUMMARY="Files: $TOTAL_FILES, Passed: $PASSED_FILES, Failed: $FAILED_FILES"
if [[ "$STRICT_MODE" = true && $WARNING_COUNT -gt 0 ]]; then
    SUMMARY="$SUMMARY, Warnings: $WARNING_COUNT (treated as failures)"
fi

# Send notification if requested
if [[ "$NOTIFY" = true ]]; then
    log "Sending notification about validation results..."
    send_notification "$STATUS" "$SUMMARY"
fi

# Log to DR events system if enabled
if [[ "$DR_MODE" = true ]]; then
    log "Logging validation result to DR events system..."
    DR_LOG_DIR="/var/log/cloud-platform"
    mkdir -p "$DR_LOG_DIR"
    
    # Use ISO-8601 timestamp format for better parsing
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$TIMESTAMP,CONFIG_VALIDATION,${ENVIRONMENT},all,$STATUS,$FAILED_FILES" >> "$DR_LOG_DIR/dr-events.log"
    log "Validation results logged to DR events log"
fi

# Clean up temporary files
rm -f "${LOG_DIR}/temp_error.log"

# Exit with appropriate status code
exit $EXIT_CODE