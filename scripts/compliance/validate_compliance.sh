#!/bin/bash
# Configuration Compliance Validation Script for Cloud Infrastructure Platform
# Validates configurations and settings against compliance requirements (PCI DSS, HIPAA, etc.)
# Usage: ./validate_compliance.sh [--environment <env>] [--standard <std>] [--report <file>] [--strict]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
COMPLIANCE_STANDARD="all"
CONFIG_DIR="${PROJECT_ROOT}/config"
SCHEMA_DIR="${PROJECT_ROOT}/config/schemas"
LOG_DIR="/var/log/cloud-platform/compliance"
REPORT_FILE="${LOG_DIR}/compliance-validation-$(date +%Y%m%d-%H%M%S).json"
EXIT_CODE=0
STRICT_MODE=false
NOTIFY=false
EMAIL_RECIPIENT=""
DR_MODE=false
VERBOSE=false
FORMAT="json"
REQUIREMENTS_FILE="${SCRIPT_DIR}/compliance_requirements.json"
VALIDATE_SCHEMA=false  # Option to enable schema validation too

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR" || {
    echo "ERROR: Failed to create log directory: $LOG_DIR"
    exit 1
}

# Log file for detailed output
LOG_FILE="${LOG_DIR}/compliance-validation-$(date +%Y%m%d-%H%M%S).log"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    local level="${3:-INFO}"
    
    echo "$message" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" = true && -n "$2" ]]; then
        echo "[$timestamp] [DEBUG] $2" >> "$LOG_FILE"
    fi
}

# Function to display usage
usage() {
    cat <<EOF
Configuration Compliance Validation Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --environment, -e ENV     Specify environment to validate (default: production)
                            Valid values: development, staging, production, dr-recovery
  --standard, -s STD        Compliance standard to validate against (default: all)
                            Valid values: pci-dss, hipaa, gdpr, iso27001, soc2, security, all
  --config-dir, -c DIR      Directory containing configuration files (default: ${PROJECT_ROOT}/config)
  --schema-dir, -d DIR      Directory containing schema definitions (default: ${PROJECT_ROOT}/config/schemas)
  --report, -r FILE         Output report file (default: ${LOG_DIR}/compliance-validation-{timestamp}.json)
  --format, -f FORMAT       Output format: json or html (default: json)
  --strict                  Fail on warnings as well as errors
  --validate-schema         Also validate files against schema definitions
  --notify [EMAIL]          Send notification with results
  --dr-mode                 Enable disaster recovery mode (logs events to DR system)
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
        --standard|-s)
            COMPLIANCE_STANDARD="$2"
            shift 2
            ;;
        --config-dir|-c)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --schema-dir|-d)
            SCHEMA_DIR="$2"
            shift 2
            ;;
        --report|-r)
            REPORT_FILE="$2"
            shift 2
            ;;
        --format|-f)
            FORMAT="$2"
            if [[ "$FORMAT" != "json" && "$FORMAT" != "html" ]]; then
                log "Invalid format: $FORMAT. Using default: json" "ERROR"
                FORMAT="json"
            fi
            shift 2
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --validate-schema)
            VALIDATE_SCHEMA=true
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
        --dr-mode)
            DR_MODE=true
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
            log "Unknown option: $1" "ERROR"
            log "Use --help for usage information" "ERROR"
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "Invalid environment: $ENVIRONMENT" "ERROR"
    log "Valid environments: development, staging, production, dr-recovery" "ERROR"
    exit 1
fi

# Validate compliance standard
VALID_STANDARDS=("pci-dss" "hipaa" "gdpr" "iso27001" "soc2" "security" "all")
STANDARD_VALID=false
for std in "${VALID_STANDARDS[@]}"; do
    if [[ "$COMPLIANCE_STANDARD" == "$std" ]]; then
        STANDARD_VALID=true
        break
    fi
done

if [[ "$STANDARD_VALID" == "false" ]]; then
    log "Invalid compliance standard: $COMPLIANCE_STANDARD" "ERROR"
    log "Valid standards: ${VALID_STANDARDS[*]}" "ERROR"
    exit 1
fi

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Create temporary file for report entries
> "$REPORT_FILE.tmp"

# Check if config directory exists
if [[ ! -d "$CONFIG_DIR" ]]; then
    log "ERROR: Config directory $CONFIG_DIR not found"
    exit 1
fi

# Check if compliance requirements file exists
if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
    log "WARNING: Compliance requirements file not found at $REQUIREMENTS_FILE"
    log "Creating default requirements file"
    
    # Create default requirements file with basic compliance standards
    mkdir -p "$(dirname "$REQUIREMENTS_FILE")"
    cat > "$REQUIREMENTS_FILE" <<EOF
{
  "pci-dss": {
    "requirements": [
      {
        "id": "1.1",
        "description": "Encryption enabled for sensitive data",
        "config_path": "security.ini",
        "check_type": "key_value",
        "key": "encryption_enabled",
        "expected": "true",
        "severity": "critical",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "1.2",
        "description": "Strong TLS version required",
        "config_path": "security.ini",
        "check_type": "key_value_min",
        "key": "min_tls_version",
        "expected": "1.2",
        "severity": "critical",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "1.3",
        "description": "Password complexity requirements",
        "config_path": "security.ini",
        "check_type": "key_value_min",
        "key": "password_min_length",
        "expected": "12",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "1.4",
        "description": "Debug mode disabled in production",
        "config_path": "app.ini",
        "check_type": "key_value",
        "key": "debug",
        "expected": "false",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      }
    ]
  },
  "hipaa": {
    "requirements": [
      {
        "id": "2.1",
        "description": "Audit logging enabled",
        "config_path": "logging.ini",
        "check_type": "key_value",
        "key": "audit_enabled",
        "expected": "true",
        "severity": "critical",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "2.2",
        "description": "Minimum log retention period",
        "config_path": "logging.ini",
        "check_type": "key_value_min",
        "key": "log_retention_days",
        "expected": "365",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      }
    ]
  },
  "gdpr": {
    "requirements": [
      {
        "id": "3.1",
        "description": "Data anonymization enabled",
        "config_path": "privacy.ini",
        "check_type": "key_value",
        "key": "anonymize_logs",
        "expected": "true", 
        "severity": "high",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "3.2",
        "description": "User data export functionality enabled",
        "config_path": "privacy.ini",
        "check_type": "key_value",
        "key": "user_data_export_enabled",
        "expected": "true",
        "severity": "medium",
        "environments": ["production", "staging", "dr-recovery"]
      }
    ]
  },
  "iso27001": {
    "requirements": [
      {
        "id": "4.1",
        "description": "Session timeout configured",
        "config_path": "security.ini",
        "check_type": "key_value_max",
        "key": "session_timeout_minutes",
        "expected": "30",
        "severity": "medium",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "4.2",
        "description": "Failed login attempts before lockout",
        "config_path": "security.ini",
        "check_type": "key_value_max",
        "key": "max_login_attempts",
        "expected": "5",
        "severity": "medium",
        "environments": ["production", "staging", "dr-recovery"]
      }
    ]
  },
  "soc2": {
    "requirements": [
      {
        "id": "5.1",
        "description": "API rate limiting enabled",
        "config_path": "api.ini",
        "check_type": "key_value",
        "key": "rate_limiting_enabled",
        "expected": "true",
        "severity": "medium",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "5.2",
        "description": "Security-related alerts enabled",
        "config_path": "monitoring.ini",
        "check_type": "key_value",
        "key": "security_alerts_enabled",
        "expected": "true",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      }
    ]
  },
  "security": {
    "requirements": [
      {
        "id": "6.1",
        "description": "Encryption enabled for sensitive data",
        "config_path": "security.ini",
        "check_type": "key_value",
        "key": "encryption_enabled",
        "expected": "true",
        "severity": "critical",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "6.2",
        "description": "Minimum TLS version set to 1.2 or higher",
        "config_path": "security.ini",
        "check_type": "key_value_min",
        "key": "min_tls_version",
        "expected": "1.2",
        "severity": "critical",
        "environments": ["production", "staging", "dr-recovery"]
      },
      {
        "id": "6.3",
        "description": "Password minimum length set to 12 or higher",
        "config_path": "security.ini",
        "check_type": "key_value_min",
        "key": "password_min_length",
        "expected": "12",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "6.4",
        "description": "SSL enforcement enabled",
        "config_path": "security.ini",
        "check_type": "key_value",
        "key": "enforce_ssl",
        "expected": "true",
        "severity": "critical",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "6.5",
        "description": "Debug mode disabled",
        "config_path": "app.ini",
        "check_type": "key_value",
        "key": "debug",
        "expected": "false",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "6.6",
        "description": "Debug logging disabled",
        "config_path": "logging.ini",
        "check_type": "key_value_not",
        "key": "log_level",
        "expected": "debug",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      },
      {
        "id": "6.7",
        "description": "Dangerous operations disabled",
        "config_path": "app.ini",
        "check_type": "key_value",
        "key": "allow_dangerous_operations",
        "expected": "false",
        "severity": "high",
        "environments": ["production", "dr-recovery"]
      }
    ]
  }
}
EOF
    log "Created default requirements file at $REQUIREMENTS_FILE"
fi

# Check if schema directory exists when schema validation is requested
if [[ "$VALIDATE_SCHEMA" = true ]]; then
    if [[ ! -d "$SCHEMA_DIR" ]]; then
        log "ERROR: Schema directory $SCHEMA_DIR not found but schema validation requested"
        exit 1
    fi
    
    # Check for dependencies needed for schema validation
    log "Checking for schema validation dependencies..."
    MISSING_DEPS=""
    
    if ! command -v jsonschema &>/dev/null; then
        MISSING_DEPS="${MISSING_DEPS} jsonschema"
    fi
    
    if ! command -v yamllint &>/dev/null; then
        MISSING_DEPS="${MISSING_DEPS} yamllint"
    fi
    
    if [[ -n "$MISSING_DEPS" ]]; then
        log "WARNING: Missing dependencies for schema validation:$MISSING_DEPS"
        log "Some validations may be skipped. Install with pip install$MISSING_DEPS"
    fi
fi

# Load compliance requirements
if ! command -v jq &>/dev/null; then
    log "ERROR: jq is required but not installed" "ERROR"
    exit 1
fi

# Function to validate a single compliance requirement
validate_requirement() {
    local id="$1"
    local description="$2"
    local config_path="$3"
    local check_type="$4"
    local key="$5"
    local expected="$6"
    local severity="$7"
    local full_config_path="${CONFIG_DIR}/${config_path}"
    
    local result="PASSED"
    local details=""

    log "Checking requirement $id: $description" "Checking $config_path for $key"
    
    # Check if config file exists
    if [[ ! -f "$full_config_path" ]]; then
        result="FAILED"
        details="Configuration file not found: $config_path"
        log "❌ $id: $details" "ERROR"
        echo "{\"id\":\"$id\",\"description\":\"$description\",\"result\":\"$result\",\"details\":\"$details\",\"severity\":\"$severity\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    # Perform check based on check type
    case "$check_type" in
        key_value)
            local actual_value=""
            if grep -q "^${key}\s*=" "$full_config_path"; then
                actual_value=$(grep "^${key}\s*=" "$full_config_path" | cut -d'=' -f2 | tr -d ' ')
                
                if [[ "$actual_value" == "$expected" ]]; then
                    result="PASSED"
                    details="Value $key=$actual_value matches expected value"
                else
                    result="FAILED"
                    details="Value $key=$actual_value does not match expected value '$expected'"
                    log "❌ $id: $details" "ERROR"
                fi
            else
                result="FAILED"
                details="Key '$key' not found in configuration file"
                log "❌ $id: $details" "ERROR"
            fi
            ;;
        key_value_min)
            local actual_value=""
            if grep -q "^${key}\s*=" "$full_config_path"; then
                actual_value=$(grep "^${key}\s*=" "$full_config_path" | cut -d'=' -f2 | tr -d ' ')
                
                if [[ "$actual_value" =~ ^[0-9]+(\.[0-9]+)?$ && "$expected" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                    if (( $(echo "$actual_value >= $expected" | bc -l) )); then
                        result="PASSED"
                        details="Value $key=$actual_value meets minimum required value '$expected'"
                    else
                        result="FAILED"
                        details="Value $key=$actual_value is below minimum required value '$expected'"
                        log "❌ $id: $details" "ERROR"
                    fi
                else
                    result="FAILED"
                    details="Non-numeric value found for comparison: $actual_value vs $expected"
                    log "❌ $id: $details" "ERROR"
                fi
            else
                result="FAILED"
                details="Key '$key' not found in configuration file"
                log "❌ $id: $details" "ERROR"
            fi
            ;;
        key_value_max)
            local actual_value=""
            if grep -q "^${key}\s*=" "$full_config_path"; then
                actual_value=$(grep "^${key}\s*=" "$full_config_path" | cut -d'=' -f2 | tr -d ' ')
                
                if [[ "$actual_value" =~ ^[0-9]+(\.[0-9]+)?$ && "$expected" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                    if (( $(echo "$actual_value <= $expected" | bc -l) )); then
                        result="PASSED"
                        details="Value $key=$actual_value is within maximum allowed value '$expected'"
                    else
                        result="FAILED"
                        details="Value $key=$actual_value exceeds maximum allowed value '$expected'"
                        log "❌ $id: $details" "ERROR"
                    fi
                else
                    result="FAILED"
                    details="Non-numeric value found for comparison: $actual_value vs $expected"
                    log "❌ $id: $details" "ERROR"
                fi
            else
                result="FAILED"
                details="Key '$key' not found in configuration file"
                log "❌ $id: $details" "ERROR"
            fi
            ;;
        key_value_not)
            local actual_value=""
            if grep -q "^${key}\s*=" "$full_config_path"; then
                actual_value=$(grep "^${key}\s*=" "$full_config_path" | cut -d'=' -f2 | tr -d ' ')
                
                if [[ "$actual_value" != "$expected" ]]; then
                    result="PASSED"
                    details="Value $key=$actual_value is not the disallowed value '$expected'"
                else
                    result="FAILED"
                    details="Value $key=$actual_value equals disallowed value '$expected'"
                    log "❌ $id: $details" "ERROR"
                fi
            else
                result="FAILED"
                details="Key '$key' not found in configuration file"
                log "❌ $id: $details" "ERROR"
            fi
            ;;
        *)
            result="ERROR"
            details="Unknown check type: $check_type"
            log "❌ $id: $details" "ERROR"
            ;;
    esac
    
    if [[ "$result" == "PASSED" ]]; then
        log "✅ $id: $description - Passed" "SUCCESS"
    fi
    
    echo "{\"id\":\"$id\",\"description\":\"$description\",\"result\":\"$result\",\"details\":\"$details\",\"severity\":\"$severity\"}" >> "$REPORT_FILE.tmp"
    
    if [[ "$result" == "FAILED" || "$result" == "ERROR" ]]; then
        return 1
    fi
    
    return 0
}

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
        log "✅ $config_name: Valid against schema $schema_name"
        echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"PASSED\",\"details\":\"File is valid against schema $schema_name\",\"severity\":\"medium\"}" >> "$REPORT_FILE.tmp"
        return 0
    else
        local error_msg=$(cat "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid - $error_msg"
        echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"FAILED\",\"details\":\"Schema validation error: ${error_msg//\"/\\\"}\",\"severity\":\"high\"}" >> "$REPORT_FILE.tmp"
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
    
    # Ensure yamllint is installed
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
        echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"FAILED\",\"details\":\"YAML syntax error: ${error_msg//\"/\\\"}\",\"severity\":\"high\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    # Check if pykwalify is installed for schema validation
    if command -v pykwalify &>/dev/null; then
        if pykwalify -d "$config_file" -s "$schema_file" &>"$LOG_DIR/temp_error.log"; then
            log "✅ $config_name: Valid against schema $schema_name"
            echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"PASSED\",\"details\":\"File is valid against schema $schema_name\",\"severity\":\"medium\"}" >> "$REPORT_FILE.tmp"
            return 0
        else
            local error_msg=$(cat "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid - $error_msg"
            echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"FAILED\",\"details\":\"Schema validation error: ${error_msg//\"/\\\"}\",\"severity\":\"high\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    else
        # Fallback to basic validation
        log "WARNING: pykwalify not installed, performing basic YAML validation only"
        log "✅ $config_name: YAML syntax valid (schema validation skipped)"
        echo "{\"id\":\"schema-${config_name}\",\"description\":\"Schema validation for $config_name\",\"result\":\"PASSED\",\"details\":\"YAML syntax valid (schema validation skipped)\",\"severity\":\"medium\"}" >> "$REPORT_FILE.tmp"
        return 0
    fi
}

# Function to validate schema for a file
validate_schema_for_file() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local file_ext="${file_name##*.}"
    local validation_errors=0
    local schema_found=false
    
    case "$file_ext" in
        json)
            for schema_file in "$SCHEMA_DIR"/*.json.schema; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_json "$file_path" "$schema_file" || ((validation_errors++))
                    ((TOTAL_CHECKS++))
                    if [[ $validation_errors -eq 0 ]]; then
                        ((PASSED_CHECKS++))
                    else
                        ((FAILED_CHECKS++))
                    fi
                fi
            done
            ;;
        yaml|yml)
            for schema_file in "$SCHEMA_DIR"/*.yaml.schema; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_yaml "$file_path" "$schema_file" || ((validation_errors++))
                    ((TOTAL_CHECKS++))
                    if [[ $validation_errors -eq 0 ]]; then
                        ((PASSED_CHECKS++))
                    else
                        ((FAILED_CHECKS++))
                    fi
                fi
            done
            ;;
        ini|conf)
            # Basic INI syntax check
            if python3 -c "import configparser; configparser.ConfigParser().read('$file_path')" 2>"$LOG_DIR/temp_error.log"; then
                log "✅ $file_name: Basic INI syntax valid"
                echo "{\"id\":\"schema-${file_name}\",\"description\":\"INI syntax check for $file_name\",\"result\":\"PASSED\",\"details\":\"Basic INI syntax is valid\",\"severity\":\"medium\"}" >> "$REPORT_FILE.tmp"
                ((TOTAL_CHECKS++))
                ((PASSED_CHECKS++))
                schema_found=true
            else
                local error_msg=$(cat "$LOG_DIR/temp_error.log")
                log "❌ $file_name: Invalid INI syntax - $error_msg"
                echo "{\"id\":\"schema-${file_name}\",\"description\":\"INI syntax check for $file_name\",\"result\":\"FAILED\",\"details\":\"INI syntax error: ${error_msg//\"/\\\"}\",\"severity\":\"high\"}" >> "$REPORT_FILE.tmp"
                ((TOTAL_CHECKS++))
                ((FAILED_CHECKS++))
                schema_found=true
                ((validation_errors++))
            fi
            ;;
    esac
    
    if [[ "$schema_found" = false ]]; then
        log "WARNING: No schema validation available for $file_name"
        return 0
    fi
    
    return $validation_errors
}

# Function to generate JSON report
generate_json_report() {
    local total_checks=$1
    local passed_checks=$2
    local failed_checks=$3
    local status=$4
    
    # Finalize the JSON report
    echo "{" > "$REPORT_FILE"
    echo "  \"summary\": {" >> "$REPORT_FILE"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
    echo "    \"environment\": \"$ENVIRONMENT\"," >> "$REPORT_FILE"
    echo "    \"compliance_standard\": \"$COMPLIANCE_STANDARD\"," >> "$REPORT_FILE"
    echo "    \"total_checks\": $total_checks," >> "$REPORT_FILE"
    echo "    \"passed\": $passed_checks," >> "$REPORT_FILE"
    echo "    \"failed\": $failed_checks," >> "$REPORT_FILE"
    echo "    \"schema_validation\": $VALIDATE_SCHEMA," >> "$REPORT_FILE"
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
    
    log "JSON report generated: $REPORT_FILE"
}

# Function to generate HTML report
generate_html_report() {
    local total_checks=$1
    local passed_checks=$2
    local failed_checks=$3
    local status=$4
    
    # Create HTML header
    cat > "$REPORT_FILE" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Validation Report - ${ENVIRONMENT}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 20px;
        }
        .status-passed {
            color: #27ae60;
            font-weight: bold;
        }
        .status-failed {
            color: #e74c3c;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .passed {
            color: #27ae60;
        }
        .failed {
            color: #e74c3c;
        }
        .error {
            color: #e67e22;
        }
        .critical {
            background-color: #fdedec;
        }
        .high {
            background-color: #fef9e7;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 14px;
        }
        .schema-section {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Validation Report</h1>
        
        <div class="summary">
            <p><strong>Environment:</strong> ${ENVIRONMENT}</p>
            <p><strong>Compliance Standard:</strong> ${COMPLIANCE_STANDARD}</p>
            <p><strong>Timestamp:</strong> $(date -u "+%Y-%m-%d %H:%M:%S UTC")</p>
            <p><strong>Total Checks:</strong> ${total_checks}</p>
            <p><strong>Pass:</strong> ${passed_checks} / <strong>Fail:</strong> ${failed_checks}</p>
            <p><strong>Schema Validation:</strong> $([[ "$VALIDATE_SCHEMA" = true ]] && echo "Enabled" || echo "Disabled")</p>
            <p><strong>Status:</strong> <span class="status-${status,,}">${status}</span></p>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Description</th>
                    <th>Result</th>
                    <th>Details</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
EOL

    # Process each result
    while IFS= read -r line; do
        # Parse JSON entry
        local id=$(echo "$line" | jq -r '.id')
        local description=$(echo "$line" | jq -r '.description')
        local result=$(echo "$line" | jq -r '.result')
        local details=$(echo "$line" | jq -r '.details')
        local severity=$(echo "$line" | jq -r '.severity')
        
        # Determine CSS classes
        local result_class="${result,,}"
        local severity_class="${severity,,}"
        local row_class=""
        
        # If this is a schema validation check, add a marker
        if [[ "$id" == schema-* ]]; then
            row_class=" class=\"schema-check\""
        fi
        
        # Add table row with appropriate class
        cat >> "$REPORT_FILE" <<EOL
                <tr class="${severity_class}"${row_class}>
                    <td>${id}</td>
                    <td>${description}</td>
                    <td class="${result_class}">${result}</td>
                    <td>${details}</td>
                    <td>${severity}</td>
                </tr>
EOL
    done < "$REPORT_FILE.tmp"
    
    # Complete the HTML
    cat >> "$REPORT_FILE" <<EOL
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Compliance Validator</p>
            <p>$(date)</p>
        </div>
    </div>
</body>
</html>
EOL
    
    log "HTML report generated: $REPORT_FILE"
}

# Function to generate compliance report
generate_report() {
    local total_checks=$1
    local passed_checks=$2
    local failed_checks=$3
    local status=$4
    
    if [[ "$FORMAT" == "html" ]]; then
        generate_html_report "$total_checks" "$passed_checks" "$failed_checks" "$status"
    else
        generate_json_report "$total_checks" "$passed_checks" "$failed_checks" "$status"
    fi
    
    # Clean up temporary file
    rm -f "$REPORT_FILE.tmp"
}

# Function to send email notification
send_notification() {
    local status=$1
    local details=$2
    
    if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
        log "Sending notification email to $EMAIL_RECIPIENT"
        
        local subject="Compliance Validation Report - ${status}"
        local message="Compliance Validation Report for ${COMPLIANCE_STANDARD}\n\n"
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
                --attachment "$REPORT_FILE" || {
                    log "WARNING: Failed to send notification using send-notification.sh"
                }
        else
            # Fall back to mail command
            if command -v mail &>/dev/null; then
                echo -e "$message" | mail -s "$subject" -a "$REPORT_FILE" "$EMAIL_RECIPIENT" || {
                    log "WARNING: Failed to send notification email"
                }
            else
                log "WARNING: Could not send notification, mail command not available"
            fi
        fi
    fi
}

# Main execution flow
log "Starting compliance validation for ${ENVIRONMENT} environment against ${COMPLIANCE_STANDARD} standard"

# Process all compliance requirements
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# First run schema validations if requested
if [[ "$VALIDATE_SCHEMA" = true ]]; then
    log "Running schema validation checks..."
    
    # Validate key configuration files based on their extensions
    for ext in json yaml yml ini conf; do
        for config_file in "$CONFIG_DIR"/*.$ext; do
            if [[ -f "$config_file" ]]; then
                validate_schema_for_file "$config_file" || EXIT_CODE=1
            fi
        done
    done
    
    log "Schema validation completed"
fi

# Determine which compliance standards to check
STANDARDS_TO_CHECK=()
if [[ "$COMPLIANCE_STANDARD" == "all" ]]; then
    STANDARDS_TO_CHECK=("pci-dss" "hipaa" "gdpr" "iso27001" "soc2" "security")
else
    STANDARDS_TO_CHECK=("$COMPLIANCE_STANDARD")
fi

# Check requirements for each selected standard
for standard in "${STANDARDS_TO_CHECK[@]}"; do
    log "Validating compliance with $standard standard..."
    
    # Get requirements for the current standard
    requirements=$(jq -r --arg std "$standard" '.[$std].requirements[] | @json' "$REQUIREMENTS_FILE")
    
    if [[ -z "$requirements" ]]; then
        log "No requirements found for $standard standard" "WARNING"
        continue
    fi
    
    while IFS= read -r req; do
        # Extract requirement details
        id=$(echo "$req" | jq -r '.id')
        description=$(echo "$req" | jq -r '.description')
        config_path=$(echo "$req" | jq -r '.config_path')
        check_type=$(echo "$req" | jq -r '.check_type')
        key=$(echo "$req" | jq -r '.key')
        expected=$(echo "$req" | jq -r '.expected')
        severity=$(echo "$req" | jq -r '.severity')
        
        # Get applicable environments
        applicable_envs=$(echo "$req" | jq -r '.environments[]')
        applies_to_current_env=false
        
        # Check if this requirement applies to the current environment
        for env in $applicable_envs; do
            if [[ "$env" == "$ENVIRONMENT" ]]; then
                applies_to_current_env=true
                break
            fi
        done
        
        if [[ "$applies_to_current_env" == "false" ]]; then
            log "Skipping requirement $id: Not applicable to $ENVIRONMENT environment" "Skipping $id"
            continue
        fi
        
        # Increment total checks
        ((TOTAL_CHECKS++))
        
        # Validate this requirement
        if validate_requirement "$id" "$description" "$config_path" "$check_type" "$key" "$expected" "$severity"; then
            ((PASSED_CHECKS++))
        else
            ((FAILED_CHECKS++))
            EXIT_CODE=1
        fi
    done <<< "$requirements"
done

# Check if no checks were performed
if [[ $TOTAL_CHECKS -eq 0 ]]; then
    log "WARNING: No compliance checks were performed"
    EXIT_CODE=1
fi

# Determine overall status based on exit code
if [[ $EXIT_CODE -eq 0 ]]; then
    STATUS="PASSED"
else
    STATUS="FAILED"
fi

# Generate the final report
generate_report $TOTAL_CHECKS $PASSED_CHECKS $FAILED_CHECKS $STATUS

# Display summary information
log "==================================================="
log "Compliance Validation Summary:"
log "Total checks: $TOTAL_CHECKS"
log "Passed: $PASSED_CHECKS"
log "Failed: $FAILED_CHECKS"
log "==================================================="
log "Compliance validation completed with status: $STATUS"

# Add validation metadata to the summary
SUMMARY="Checks: $TOTAL_CHECKS, Passed: $PASSED_CHECKS, Failed: $FAILED_CHECKS"

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
    echo "$TIMESTAMP,COMPLIANCE_VALIDATION,${ENVIRONMENT},${COMPLIANCE_STANDARD},$STATUS,$FAILED_CHECKS" >> "$DR_LOG_DIR/dr-events.log"
    log "Validation results logged to DR events log"
fi

# Clean up temporary files
rm -f "${LOG_DIR}/temp_error.log" 2>/dev/null

# Exit with appropriate status code
exit $EXIT_CODE