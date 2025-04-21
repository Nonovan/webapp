#!/bin/bash
# Configuration Validator Script for Cloud Infrastructure Platform
# Validates configuration files against schemas and best practices
# Usage: ./config_validator.sh [--environment <env>] [--config-dir <dir>] [--schema-dir <dir>] [--report <file>]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
CONFIG_DIR="${PROJECT_ROOT}/config"
SCHEMA_DIR="${PROJECT_ROOT}/config/schemas"
LOG_DIR="/var/log/cloud-platform/config-validation"
REPORT_FILE="${LOG_DIR}/validation-report-$(date +%Y%m%d-%H%M%S).json"
EXIT_CODE=0
STRICT_MODE=false
VERBOSE=false
FORMAT="json"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR" || {
    echo "ERROR: Failed to create log directory: $LOG_DIR"
    exit 1
}

# Log file for detailed output
LOG_FILE="${LOG_DIR}/validation-$(date +%Y%m%d-%H%M%S).log"

# Function to safely read files to avoid command injection
safe_read_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cat "$file" 2>/dev/null || echo "Error reading file"
    else
        echo "File not found"
    fi
}

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
Configuration Validator Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --environment, -e ENV     Specify environment to validate (default: production)
                            Valid values: development, staging, production, dr-recovery
  --config-dir, -c DIR      Directory containing configuration files (default: ${PROJECT_ROOT}/config)
  --schema-dir, -s DIR      Directory containing schema definitions (default: ${PROJECT_ROOT}/config/schemas)
  --report, -r FILE         Output report file (default: ${LOG_DIR}/validation-report-{timestamp}.json)
  --format, -f FORMAT       Output format: json or html (default: json)
  --strict                  Fail on warnings as well as errors
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
        --config-dir|-c)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --schema-dir|-s)
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
    log "ERROR: Invalid environment: $ENVIRONMENT"
    log "Valid environments: development, staging, production, dr-recovery"
    exit 1
fi

# Check if config directory exists
if [[ ! -d "$CONFIG_DIR" ]]; then
    log "ERROR: Config directory $CONFIG_DIR not found"
    exit 1
fi

# Check if schema directory exists
if [[ ! -d "$SCHEMA_DIR" ]]; then
    log "WARNING: Schema directory $SCHEMA_DIR not found. Creating it."
    mkdir -p "$SCHEMA_DIR" || {
        log "ERROR: Failed to create schema directory $SCHEMA_DIR"
        exit 1
    }
fi

# Create temporary file for report entries
> "$REPORT_FILE.tmp"

# Function to validate JSON files
validate_json() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    
    log "Validating $config_name against schema $schema_name"
    
    # Ensure jsonschema is installed
    if ! command -v jsonschema &>/dev/null; then
        log "ERROR: jsonschema validator not found. Please install with: pip install jsonschema"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"jsonschema validator not installed\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # First check basic JSON syntax with jq if available
    if command -v jq &>/dev/null; then
        if ! jq empty "$config_file" 2>"$LOG_DIR/temp_error.log"; then
            local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid JSON syntax - $error_msg"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"JSON syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    fi
    
    if jsonschema -i "$config_file" "$schema_file" 2>"$LOG_DIR/temp_error.log"; then
        log "✅ $config_name: Valid"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
        return 0
    else
        local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
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
    
    # Ensure yamllint is installed
    if ! command -v yamllint &>/dev/null; then
        log "ERROR: yamllint not found. Please install with: pip install yamllint"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"yamllint validator not installed\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # First check syntax with yamllint
    if ! yamllint -d "{extends: relaxed, rules: {line-length: {max: 120}}}" "$config_file" 2>"$LOG_DIR/temp_error.log"; then
        local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid YAML syntax - $error_msg"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"YAML syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    # Check if pykwalify is installed for schema validation
    if command -v pykwalify &>/dev/null; then
        if pykwalify -d "$config_file" -s "$schema_file" 2>"$LOG_DIR/temp_error.log"; then
            log "✅ $config_name: Valid"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
            return 0
        else
            local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid - $error_msg"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"YAML validation error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    else
        # If pykwalify is not available, we already verified YAML syntax with yamllint
        log "✅ $config_name: Valid (basic syntax only - install pykwalify for schema validation)"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Only basic syntax validation performed - install pykwalify for schema validation\"}" >> "$REPORT_FILE.tmp"
        return 0
    fi
}

# Function to validate INI files
validate_ini() {
    local config_file="$1"
    local schema_file="$2"
    local config_name=$(basename "$config_file")
    local schema_name=$(basename "$schema_file")
    local issues=0
    
    log "Validating $config_name against schema $schema_name"
    
    if [[ "$VERBOSE" = true ]]; then
        log "" "Config file: $config_file"
        log "" "Schema file: $schema_file"
    fi
    
    # Basic syntax check using Python's configparser
    if ! python3 -c "import configparser; configparser.ConfigParser().read('$config_file')" 2>"$LOG_DIR/temp_error.log"; then
        local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
        log "❌ $config_name: Invalid INI syntax - $error_msg"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"INI syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
        return 1
    fi
    
    # Simple schema validation
    if grep -q "^#" "$schema_file" 2>/dev/null; then
        log "✅ $config_name: Basic INI syntax is valid"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
        return 0
    else
        # Advanced validation: Check required sections and keys if specified in a simple schema
        if grep -q "required_sections" "$schema_file" 2>/dev/null; then
            log "Performing basic schema validation for $config_name using $schema_name"
            
            # Extract required sections and keys from schema
            local required_sections=$(grep "required_sections" "$schema_file" | cut -d= -f2- | tr -d ' ')
            
            # Check each required section
            IFS=',' read -ra SECTIONS <<< "$required_sections"
            for section in "${SECTIONS[@]}"; do
                if ! grep -q "^\[${section}\]" "$config_file"; then
                    log "❌ $config_name: Missing required section [$section]"
                    echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"Missing required section [$section]\"}" >> "$REPORT_FILE.tmp"
                    return 1
                fi
                
                # Check required keys in this section if specified
                local section_keys_var="required_keys_${section}"
                local required_keys=$(grep "$section_keys_var" "$schema_file" | cut -d= -f2- | tr -d ' ' 2>/dev/null)
                
                if [[ -n "$required_keys" ]]; then
                    IFS=',' read -ra KEYS <<< "$required_keys"
                    for key in "${KEYS[@]}"; do
                        if ! grep -q -A20 "^\[${section}\]" "$config_file" | grep -q "^${key}\s*="; then
                            log "❌ $config_name: Missing required key '$key' in section [$section]"
                            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"Missing required key '$key' in section [$section]\"}" >> "$REPORT_FILE.tmp"
                            return 1
                        fi
                    done
                fi
            done
        fi
        
        # Add additional checks for environment-specific configuration
        if [[ "$ENVIRONMENT" == "production" || "$ENVIRONMENT" == "dr-recovery" ]]; then
            # Check for debug flag
            if grep -q "^debug\s*=\s*true" "$config_file" || grep -q "^debug_mode\s*=\s*true" "$config_file"; then
                log "⚠️ WARNING: $config_name has debug mode enabled in $ENVIRONMENT environment"
                echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Debug mode should be disabled in production environment\"}" >> "$REPORT_FILE.tmp"
                ((issues++))
            fi
            
            # Check TLS version
            if grep -q "^min_tls_version\s*=" "$config_file"; then
                local tls_version=$(grep "^min_tls_version\s*=" "$config_file" | cut -d= -f2 | tr -d ' ')
                if [[ -n "$tls_version" && "$tls_version" < "1.2" ]]; then
                    log "⚠️ WARNING: $config_name has insecure TLS version: $tls_version"
                    echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Insecure TLS version configured: $tls_version - Recommended: 1.2 or higher\"}" >> "$REPORT_FILE.tmp"
                    ((issues++))
                fi
            fi
        fi
    fi
    
    # Special checks for database.ini
    if [[ "$config_name" == "database.ini" ]]; then
        # Check that database URL doesn't include password
        if grep -q "^database_url\s*=" "$config_file"; then
            local db_url=$(grep "^database_url\s*=" "$config_file" | cut -d= -f2- | tr -d ' ')
            if [[ "$db_url" =~ ://[^:]+:[^@]+@ ]]; then
                log "⚠️ WARNING: $config_name contains password in database URL"
                echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Database URL contains password. Use environment variables instead.\"}" >> "$REPORT_FILE.tmp"
                ((issues++))
            fi
        fi
    fi
    
    # Special checks for security.ini
    if [[ "$config_name" == "security.ini" ]]; then
        # Check for weak password policies
        if grep -q "^password_min_length\s*=" "$config_file"; then
            local min_length=$(grep "^password_min_length\s*=" "$config_file" | cut -d= -f2 | tr -d ' ')
            if [[ -n "$min_length" && "$min_length" -lt 8 ]]; then
                log "⚠️ WARNING: $config_name has weak password policy: min_length=$min_length"
                echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"Weak password policy: minimum length should be at least 8 characters\"}" >> "$REPORT_FILE.tmp"
                ((issues++))
            fi
        fi
    fi
    
    # If we made it here, the file is basically valid
    if [[ $issues -eq 0 ]]; then
        log "✅ $config_name: Valid"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
    else
        # We already wrote warnings to the report file, just don't overwrite them
        log "✅ $config_name: Valid with $issues issues/warnings"
    fi
    
    # Return number of issues for strict mode handling
    return $issues
}

# Function to validate XML files
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
        if xmllint --schema "$schema_file" --noout "$config_file" 2>"$LOG_DIR/temp_error.log"; then
            log "✅ $config_name: Valid"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
            return 0
        else
            local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
            log "❌ $config_name: Invalid - $error_msg"
            echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":false,\"error\":\"${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
            return 1
        fi
    else
        log "WARNING: xmllint not installed, skipping XML validation"
        echo "{\"file\":\"$config_name\",\"schema\":\"$schema_name\",\"valid\":true,\"warning\":\"XML schema validation skipped. Install xmllint for validation.\"}" >> "$REPORT_FILE.tmp"
        return 0
    fi
}

# Function to perform validation on files
validate_file() {
    local file="$1"
    local file_name=$(basename "$file")
    local file_ext="${file_name##*.}"
    local validation_errors=0
    local schema_found=false
    
    # Find matching schema
    case "$file_ext" in
        json)
            for schema_file in "$SCHEMA_DIR"/*.json.schema "$SCHEMA_DIR/${file_name}.schema"; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_json "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        yaml|yml)
            for schema_file in "$SCHEMA_DIR"/*.yaml.schema "$SCHEMA_DIR/${file_name}.schema"; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_yaml "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        ini|conf)
            # First look for specific schema that matches the filename
            specific_schema="${SCHEMA_DIR}/${file_name}.schema"
            if [[ -f "$specific_schema" ]]; then
                schema_found=true
                validate_ini "$file" "$specific_schema" || ((validation_errors++))
            else
                # Look for .ini-specific schema file
                ini_schema="${SCHEMA_DIR}/${file_ext}.schema"
                if [[ -f "$ini_schema" ]]; then
                    schema_found=true
                    validate_ini "$file" "$ini_schema" || ((validation_errors++))
                else
                    # Look for any relevant schema
                    for schema_file in "$SCHEMA_DIR"/*.ini.schema; do
                        if [[ -f "$schema_file" ]]; then
                            schema_found=true
                            validate_ini "$file" "$schema_file" || ((validation_errors++))
                        fi
                    done
                fi
                
                # If no schema found but file is .ini, do basic validation
                if [[ "$schema_found" = false ]]; then
                    schema_found=true
                    log "No specific schema found for $file_name, performing basic validation"
                    # Perform basic syntax validation
                    if python3 -c "import configparser; configparser.ConfigParser().read('$file')" 2>"$LOG_DIR/temp_error.log"; then
                        log "✅ $file_name: Basic INI syntax is valid"
                        echo "{\"file\":\"$file_name\",\"valid\":true,\"warning\":\"Basic syntax check only - no schema available\"}" >> "$REPORT_FILE.tmp"
                    else
                        local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
                        log "❌ $file_name: Invalid INI syntax - $error_msg"
                        echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"INI syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
                        ((validation_errors++))
                    fi
                }
            fi
            ;;
        xml)
            for schema_file in "$SCHEMA_DIR"/*.xsd "$SCHEMA_DIR/${file_name}.xsd"; do
                if [[ -f "$schema_file" ]]; then
                    schema_found=true
                    validate_xml "$file" "$schema_file" || ((validation_errors++))
                fi
            done
            ;;
        py)
            # For Python files, just check syntax
            schema_found=true
            if python3 -m py_compile "$file" 2>"$LOG_DIR/temp_error.log"; then
                log "✅ $file_name: Python syntax valid"
                echo "{\"file\":\"$file_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
            else
                local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
                log "❌ $file_name: Invalid Python syntax - $error_msg"
                echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"Python syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
                ((validation_errors++))
            fi
            ;;
        sh)
            # For shell scripts, use shellcheck if available
            schema_found=true
            if command -v shellcheck &>/dev/null; then
                if shellcheck "$file" 2>"$LOG_DIR/temp_error.log"; then
                    log "✅ $file_name: Shell script valid"
                    echo "{\"file\":\"$file_name\",\"valid\":true}" >> "$REPORT_FILE.tmp"
                else
                    local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
                    log "❌ $file_name: Invalid shell script - $error_msg"
                    echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"Shell script error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
                    ((validation_errors++))
                fi
            else
                # Fallback to basic bash syntax check
                if bash -n "$file" 2>"$LOG_DIR/temp_error.log"; then
                    log "✅ $file_name: Shell syntax valid"
                    echo "{\"file\":\"$file_name\",\"valid\":true,\"warning\":\"Basic syntax check only - install shellcheck for more thorough validation\"}" >> "$REPORT_FILE.tmp"
                else
                    local error_msg=$(safe_read_file "$LOG_DIR/temp_error.log")
                    log "❌ $file_name: Invalid shell syntax - $error_msg"
                    echo "{\"file\":\"$file_name\",\"valid\":false,\"error\":\"Shell syntax error: ${error_msg//\"/\\\"}\"}" >> "$REPORT_FILE.tmp"
                    ((validation_errors++))
                fi
            fi
            ;;
        *)
            # For unknown file types, just log a warning
            log "WARNING: No validation method available for $file_ext files"
            echo "{\"file\":\"$file_name\",\"valid\":true,\"warning\":\"No validation method available for $file_ext files\"}" >> "$REPORT_FILE.tmp"
            return 0
            ;;
    esac
    
    if [[ "$schema_found" = false && "$file_ext" != "py" && "$file_ext" != "sh" ]]; then
        log "WARNING: No schema found for $file_name"
        echo "{\"file\":\"$file_name\",\"valid\":true,\"warning\":\"No schema found for validation\"}" >> "$REPORT_FILE.tmp"
    fi
    
    return $validation_errors
}

# Function to generate JSON report
generate_json_report() {
    local total_files=$1
    local passed_files=$2
    local failed_files=$3
    local warnings=$4
    local status=$5
    
    # Finalize the JSON report
    echo "{" > "$REPORT_FILE"
    echo "  \"summary\": {" >> "$REPORT_FILE"
    echo "    \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
    echo "    \"environment\": \"$ENVIRONMENT\"," >> "$REPORT_FILE"
    echo "    \"total_files\": $total_files," >> "$REPORT_FILE"
    echo "    \"passed\": $passed_files," >> "$REPORT_FILE"
    echo "    \"failed\": $failed_files," >> "$REPORT_FILE"
    echo "    \"warnings\": $warnings," >> "$REPORT_FILE"
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
    local total_files=$1
    local passed_files=$2
    local failed_files=$3
    local warnings=$4
    local status=$5
    
    # Create HTML header
    cat > "$REPORT_FILE" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuration Validation Report - ${ENVIRONMENT}</title>
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
        .valid {
            color: #27ae60;
        }
        .invalid {
            color: #e74c3c;
        }
        .warning {
            color: #f39c12;
        }
        .details {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Configuration Validation Report</h1>
        
        <div class="summary">
            <p><strong>Environment:</strong> ${ENVIRONMENT}</p>
            <p><strong>Timestamp:</strong> $(date -u "+%Y-%m-%d %H:%M:%S UTC")</p>
            <p><strong>Total Files:</strong> ${total_files}</p>
            <p><strong>Passed:</strong> ${passed_files}</p>
            <p><strong>Failed:</strong> ${failed_files}</p>
            <p><strong>Warnings:</strong> ${warnings}</p>
            <p><strong>Status:</strong> <span class="status-${status,,}">${status}</span></p>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Schema</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
EOL

    # Process each result
    while IFS= read -r line; do
        # Parse JSON entry
        local file=$(echo "$line" | jq -r '.file // "Unknown"')
        local schema=$(echo "$line" | jq -r '.schema // "N/A"')
        local valid=$(echo "$line" | jq -r '.valid')
        local error=$(echo "$line" | jq -r '.error // ""')
        local warning=$(echo "$line" | jq -r '.warning // ""')
        
        # Determine status and CSS class
        local status_class="valid"
        local status_text="Valid"
        local details=""
        
        if [[ "$valid" == "false" ]]; then
            status_class="invalid"
            status_text="Invalid"
            details="$error"
        elif [[ -n "$warning" ]]; then
            status_class="warning"
            status_text="Warning"
            details="$warning"
        fi
        
        # Add table row
        cat >> "$REPORT_FILE" <<EOL
                <tr>
                    <td>${file}</td>
                    <td>${schema}</td>
                    <td class="${status_class}">${status_text}</td>
                    <td>
EOL
        
        if [[ -n "$details" ]]; then
            echo "<div class=\"details\">${details}</div>" >> "$REPORT_FILE"
        fi
        
        echo "</td></tr>" >> "$REPORT_FILE"
    done < "$REPORT_FILE.tmp"
    
    # Complete the HTML
    cat >> "$REPORT_FILE" <<EOL
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Config Validator</p>
            <p>$(date)</p>
        </div>
    </div>
</body>
</html>
EOL
    
    log "HTML report generated: $REPORT_FILE"
}

# Function to generate validation report
generate_report() {
    local total_files=$1
    local passed_files=$2
    local failed_files=$3
    local warnings=$4
    local status=$5
    
    if [[ "$FORMAT" == "html" ]]; then
        generate_html_report "$total_files" "$passed_files" "$failed_files" "$warnings" "$status"
    else
        generate_json_report "$total_files" "$passed_files" "$failed_files" "$warnings" "$status"
    fi
    
    # Clean up temporary file
    rm -f "$REPORT_FILE.tmp"
}

# Function to check environment dependencies
check_environment_dependencies() {
    log "Checking environment-specific dependencies..."
    local missing_files=0
    
    # Required files for different environments
    case "$ENVIRONMENT" in
        production|dr-recovery)
            # Critical files for production environments
            local required_files=("security.ini" "logging.ini" "database.ini" "api.ini" "app.ini")
            for file in "${required_files[@]}"; do
                if [[ ! -f "$CONFIG_DIR/$file" ]]; then
                    log "❌ ERROR: Required file $file missing for $ENVIRONMENT environment"
                    ((missing_files++))
                    EXIT_CODE=1
                else
                    log "✅ Required file $file found"
                fi
            done
            ;;
        staging)
            # Less strict for staging
            local required_files=("security.ini" "database.ini" "app.ini")
            for file in "${required_files[@]}"; do
                if [[ ! -f "$CONFIG_DIR/$file" ]]; then
                    log "⚠️ WARNING: Recommended file $file missing for $ENVIRONMENT environment"
                else
                    log "✅ Required file $file found"
                fi
            done
            ;;
    esac
    
    return $missing_files
}

# Function to check security best practices
check_security_best_practices() {
    log "Checking security best practices..."
    local issues=0
    
    # Check file permissions
    for file in "$CONFIG_DIR"/*.{ini,json,conf,yaml,yml}; do
        if [[ -f "$file" ]]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
            if [[ -n "$perms" && "$perms" != "600" && "$perms" != "400" && "$perms" != "640" && "$perms" != "440" ]]; then
                log "⚠️ WARNING: Insecure permissions ($perms) on configuration file $(basename "$file")"
                ((issues++))
            fi
        fi
    done
    
    # Check for sensitive information in config files
    for search_term in "password" "secret" "key" "token" "credential"; do
        local matches=$(grep -l "$search_term" "$CONFIG_DIR"/*.{ini,json,conf,yaml,yml} 2>/dev/null)
        if [[ -n "$matches" ]]; then
            log "⚠️ WARNING: Found potential sensitive information ($search_term) in config files:"
            log "$matches" "Found in: $matches"
            ((issues++))
        fi
    done
    
    # Check if proper .gitignore exists
    if [[ ! -f "$CONFIG_DIR/.gitignore" ]]; then
        log "⚠️ WARNING: No .gitignore found in config directory"
        ((issues++))
    else
        # Check if .gitignore properly ignores sensitive files
        local gitignore_content=$(cat "$CONFIG_DIR/.gitignore" 2>/dev/null)
        for pattern in "*.key" "*.pem" "*secret*" "*.env"; do
            if ! grep -q "$pattern" "$CONFIG_DIR/.gitignore" 2>/dev/null; then
                log "⚠️ WARNING: .gitignore may not be ignoring sensitive files ($pattern)"
                ((issues++))
            fi
        done
    fi
    
    return $issues
}

# Main execution flow
log "Starting configuration validation for environment: $ENVIRONMENT"
log "Config directory: $CONFIG_DIR"
log "Schema directory: $SCHEMA_DIR"

# Check environment dependencies
check_environment_dependencies

# Run security best practices check
if [[ "$ENVIRONMENT" == "production" || "$ENVIRONMENT" == "dr-recovery" || "$STRICT_MODE" = true ]]; then
    check_security_best_practices
    if [[ $? -gt 0 && "$STRICT_MODE" = true ]]; then
        EXIT_CODE=1
    fi
fi

# Track validation statistics
TOTAL_FILES=0
PASSED_FILES=0
FAILED_FILES=0
WARNING_COUNT=0

# Validate files against schemas
log "Validating configuration files..."

# JSON files
for config_file in "$CONFIG_DIR"/*.json; do
    if [[ -f "$config_file" ]]; then
        ((TOTAL_FILES++))
        
        if validate_file "$config_file"; then
            ((PASSED_FILES++))
        else
            ((FAILED_FILES++))
            EXIT_CODE=1
        fi
    fi
done

# YAML files
for ext in yaml yml; do
    for config_file in "$CONFIG_DIR"/*.$ext; do
        if [[ -f "$config_file" ]]; then
            ((TOTAL_FILES++))
            
            if validate_file "$config_file"; then
                ((PASSED_FILES++))
            else
                ((FAILED_FILES++))
                EXIT_CODE=1
            fi
        fi
    done
done

# INI files
for ext in ini conf; do
    for config_file in "$CONFIG_DIR"/*.$ext; do
        if [[ -f "$config_file" ]]; then
            ((TOTAL_FILES++))
            
            if validate_file "$config_file"; then
                ((PASSED_FILES++))
            else
                ((FAILED_FILES++))
                EXIT_CODE=1
            fi
        fi
    done
done

# Python configuration files
for config_file in "$CONFIG_DIR"/*.py; do
    if [[ -f "$config_file" ]]; then
        ((TOTAL_FILES++))
        
        if validate_file "$config_file"; then
            ((PASSED_FILES++))
        else
            ((FAILED_FILES++))
            EXIT_CODE=1
        fi
    fi
done

# Shell script configuration files
for config_file in "$CONFIG_DIR"/*.sh; do
    if [[ -f "$config_file" ]]; then
        ((TOTAL_FILES++))
        
        if validate_file "$config_file"; then
            ((PASSED_FILES++))
        else
            ((FAILED_FILES++))
            EXIT_CODE=1
        fi
    fi
done

# XML files
for config_file in "$CONFIG_DIR"/*.xml; do
    if [[ -f "$config_file" ]]; then
        ((TOTAL_FILES++))
        
        if validate_file "$config_file"; then
            ((PASSED_FILES++))
        else
            ((FAILED_FILES++))
            EXIT_CODE=1
        fi
    fi
done

# Determine overall status
STATUS="PASSED"
if [[ $EXIT_CODE -ne 0 ]]; then
    STATUS="FAILED"
fi

# Count warnings in validation results
if [[ -f "$REPORT_FILE.tmp" ]]; then
    WARNING_COUNT=$(grep -c "\"warning\":" "$REPORT_FILE.tmp" || echo 0)
    
    # In strict mode, warnings cause failure
    if [[ "$STRICT_MODE" = true && $WARNING_COUNT -gt 0 ]]; then
        EXIT_CODE=1
        STATUS="FAILED"
    fi
fi

# Generate the final report
generate_report $TOTAL_FILES $PASSED_FILES $FAILED_FILES $WARNING_COUNT $STATUS

# Display summary information
log "==================================================="
log "Configuration Validation Summary:"
log "Total files checked: $TOTAL_FILES"
log "Passed: $PASSED_FILES"
log "Failed: $FAILED_FILES"
log "Warnings: $WARNING_COUNT"
log "==================================================="
log "Validation completed with status: $STATUS"

# Clean up temporary files
rm -f "${LOG_DIR}/temp_error.log" 2>/dev/null

# Exit with appropriate status code
exit $EXIT_CODE