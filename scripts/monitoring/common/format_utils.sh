#!/bin/bash
# -----------------------------------------------------------------------------
# format_utils.sh - Output formatting for reports and notifications
#
# Part of Cloud Infrastructure Platform - Monitoring System
#
# This script provides standardized formatting functions for generating
# consistent outputs in various formats (text, JSON, CSV, HTML, etc.)
# for monitoring reports and notifications.
#
# Usage: source "$(dirname "$0")/../common/format_utils.sh"
# -----------------------------------------------------------------------------

# Set strict error handling
set -o pipefail

# Script version for tracking changes and compatibility
readonly FORMAT_UTILS_VERSION="1.0.1"

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"

# Load common utility functions if available
if [[ -f "${SCRIPT_DIR}/logging_utils.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/logging_utils.sh"
fi

# Add basic logging if not available from logging_utils.sh
if ! command -v log_info &> /dev/null; then
    log_info() { echo "[INFO] $1"; }
    log_error() { echo "[ERROR] $1" >&2; }
    log_debug() { [[ "${VERBOSE:-false}" == "true" ]] && echo "[DEBUG] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
fi

# -----------------------------------------------------------------------------
# JSON FORMATTING FUNCTIONS
# -----------------------------------------------------------------------------

# Format data as JSON object
# Arguments:
#   $@ - Key-value pairs (key1 value1 key2 value2...)
# Returns:
#   JSON object as string
json_object() {
    local result="{"
    local first=true
    local key=""

    # Process key-value pairs
    for arg in "$@"; do
        if [[ -z "$key" ]]; then
            key="$arg"
        else
            # Format the value properly
            local value="$arg"

            # Check if the value is already a JSON object/array
            if [[ "$value" == \{* || "$value" == \[* ]]; then
                # Already JSON, use as is
                :
            # Check if the value is a number
            elif [[ "$value" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
                # Numeric value, don't quote
                :
            # Check if the value is a boolean
            elif [[ "$value" == "true" || "$value" == "false" || "$value" == "null" ]]; then
                # Boolean or null, use as is
                :
            else
                # String value, escape and quote
                value=$(escape_json_string "$value")
                value="\"$value\""
            fi

            # Add comma if not the first pair
            if [[ "$first" == "true" ]]; then
                first=false
            else
                result+=","
            fi

            # Add the key-value pair
            result+="\"$key\":$value"
            key=""
        fi
    done

    result+="}"
    echo "$result"
}

# Format data as JSON array
# Arguments:
#   $@ - Array items
# Returns:
#   JSON array as string
json_array() {
    local result="["
    local first=true

    for item in "$@"; do
        # Check if the item is already a JSON object/array
        if [[ "$item" == \{* || "$item" == \[* ]]; then
            # Already JSON, use as is
            :
        # Check if the item is a number
        elif [[ "$item" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
            # Numeric value, don't quote
            :
        # Check if the item is a boolean
        elif [[ "$item" == "true" || "$item" == "false" || "$item" == "null" ]]; then
            # Boolean or null, use as is
            :
        else
            # String value, escape and quote
            item=$(escape_json_string "$item")
            item="\"$item\""
        fi

        # Add comma if not the first item
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=","
        fi

        result+="$item"
    done

    result+="]"
    echo "$result"
}

# Escape a string for use in JSON
# Arguments:
#   $1 - String to escape
# Returns:
#   Escaped string
escape_json_string() {
    local string="$1"
    local result=""

    # Replace special characters
    result="${string//\\/\\\\}"  # Backslash
    result="${result//\"/\\\"}"  # Double quote
    result="${result//	/\\t}"    # Tab
    result="${result//$'\n'/\\n}"  # Newline
    result="${result//$'\r'/\\r}"  # Carriage return

    echo "$result"
}

# Validate JSON string
# Arguments:
#   $1 - JSON string to validate
#   $2 - Output format (optional): "silent" or "verbose" (default: silent)
# Returns:
#   0 if JSON is valid, 1 otherwise
validate_json() {
    local json_string="$1"
    local output_format="${2:-silent}"

    # Check if jq is available
    if command -v jq &>/dev/null; then
        if [[ "$output_format" == "silent" ]]; then
            echo "$json_string" | jq '.' >/dev/null 2>&1
            return $?
        else
            local error_output
            error_output=$(echo "$json_string" | jq '.' 2>&1 >/dev/null)
            local result=$?

            if [[ $result -ne 0 ]]; then
                log_error "JSON validation failed: $error_output"
            else
                log_debug "JSON validation succeeded"
            fi

            return $result
        fi
    elif command -v python3 &>/dev/null; then
        # Try with Python as fallback
        if [[ "$output_format" == "silent" ]]; then
            echo "$json_string" | python3 -m json.tool >/dev/null 2>&1
            return $?
        else
            local error_output
            error_output=$(echo "$json_string" | python3 -m json.tool 2>&1 >/dev/null)
            local result=$?

            if [[ $result -ne 0 ]]; then
                log_error "JSON validation failed: $error_output"
            else
                log_debug "JSON validation succeeded"
            fi

            return $result
        fi
    else
        # No validation tools available
        log_warning "Cannot validate JSON: neither jq nor python3 is installed"
        return 0  # Assume valid
    fi
}

# Format data as pretty-printed JSON
# Arguments:
#   $1 - JSON string to format
# Returns:
#   Pretty-printed JSON string or error message
format_json() {
    local json_string="$1"

    # Check if jq is available
    if command -v jq &>/dev/null; then
        echo "$json_string" | jq '.'
    elif command -v python3 &>/dev/null; then
        # Try with Python as fallback
        echo "$json_string" | python3 -m json.tool
    else
        # No formatting tools available
        log_warning "Cannot format JSON: neither jq nor python3 is installed"
        echo "$json_string"
    fi
}

# Create a JSON report structure with standard metadata
# Arguments:
#   $1 - Report title
#   $2 - Environment name
#   $3 - Report content (JSON object)
#   $4 - Report type (default: "status")
# Returns:
#   JSON report structure
create_json_report() {
    local title="$1"
    local environment="$2"
    local content="$3"
    local report_type="${4:-status}"

    # Create metadata
    local metadata
    metadata=$(json_object \
        "timestamp" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "title" "$title" \
        "environment" "$environment" \
        "hostname" "$(hostname)" \
        "report_id" "${report_type}-$(date +%Y%m%d%H%M%S)" \
        "version" "$FORMAT_UTILS_VERSION")

    # Create full report
    local report
    report=$(json_object \
        "metadata" "$metadata" \
        "content" "$content")

    echo "$report"
}

# -----------------------------------------------------------------------------
# CSV FORMATTING FUNCTIONS
# -----------------------------------------------------------------------------

# Convert array to CSV row
# Arguments:
#   $@ - Field values
# Returns:
#   CSV row as string
csv_row() {
    local result=""
    local first=true

    for field in "$@"; do
        # Add comma if not the first field
        if [[ "$first" == "true" ]]; then
            first=false
        else
            result+=","
        fi

        # Escape and quote the field if necessary
        result+=$(escape_csv_field "$field")
    done

    echo "$result"
}

# Escape field for CSV
# Arguments:
#   $1 - Field value
# Returns:
#   Escaped and quoted field value
escape_csv_field() {
    local field="$1"
    local result="$field"

    # Check if the field needs quoting
    if [[ "$field" == *,* || "$field" == *\"* || "$field" == *$'\n'* ]]; then
        # Escape double quotes
        result="${result//\"/\"\"}"
        # Wrap in quotes
        result="\"$result\""
    fi

    echo "$result"
}

# Generate a CSV file from data
# Arguments:
#   $1 - Output file path
#   $2 - Header row (comma-separated fields)
#   $3 - Data rows (newline-separated, comma-separated fields)
#   $4 - Permissions (optional, default: 644)
# Returns:
#   0 if successful, 1 otherwise
generate_csv_file() {
    local output_file="$1"
    local header_row="$2"
    local data_rows="$3"
    local permissions="${4:-644}"

    # Create parent directory if it doesn't exist
    local parent_dir
    parent_dir=$(dirname "$output_file")
    mkdir -p "$parent_dir" || {
        log_error "Unable to create directory: $parent_dir"
        return 1
    }

    # Write header row
    echo "$header_row" > "$output_file" || {
        log_error "Failed to write CSV header to $output_file"
        return 1
    }

    # Write data rows
    echo "$data_rows" >> "$output_file" || {
        log_error "Failed to write CSV data to $output_file"
        return 1
    }

    # Set permissions
    chmod "$permissions" "$output_file" || {
        log_warning "Failed to set permissions on $output_file"
    }

    log_debug "CSV file generated: $output_file"
    return 0
}

# Convert JSON array to CSV
# Arguments:
#   $1 - JSON array
#   $2 - Field names (comma-separated)
#   $3 - Output file (optional)
# Returns:
#   CSV data as string or 0/1 for success/failure if output file specified
json_to_csv() {
    local json_data="$1"
    local field_names="$2"
    local output_file="$3"

    # Check dependencies
    if ! command -v jq &>/dev/null; then
        log_error "jq is required for json_to_csv"
        return 1
    fi

    # Parse field names
    IFS=',' read -r -a fields <<< "$field_names"

    # Create header row
    local header_row=""
    local first=true

    for field in "${fields[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
            header_row="$field"
        else
            header_row="$header_row,$field"
        fi
    done

    # Extract data rows
    local jq_fields=".${fields[0]}"
    for ((i=1; i<${#fields[@]}; i++)); do
        jq_fields+=", .\"${fields[$i]}\""
    done

    local data_rows
    data_rows=$(echo "$json_data" | jq -r ".[] | [$jq_fields] | @csv")

    # Output to file or stdout
    if [[ -n "$output_file" ]]; then
        generate_csv_file "$output_file" "$header_row" "$data_rows"
        return $?
    else
        echo "$header_row"
        echo "$data_rows"
        return 0
    fi
}

# -----------------------------------------------------------------------------
# TEXT FORMATTING FUNCTIONS
# -----------------------------------------------------------------------------

# Format data as a text table
# Arguments:
#   $1 - Header row (pipe-separated fields)
#   $2 - Data rows (newline-separated, pipe-separated fields)
#   $3 - Alignment (optional: "left", "center", "right", default: "left")
# Returns:
#   Text table as string
format_text_table() {
    local header_row="$1"
    local data_rows="$2"
    local alignment="${3:-left}"

    # Parse headers
    IFS='|' read -r -a headers <<< "$header_row"

    # Determine column widths
    local -a widths
    for ((i=0; i<${#headers[@]}; i++)); do
        widths[$i]=${#headers[$i]}
    done

    # Check data rows for wider fields
    while IFS= read -r row; do
        IFS='|' read -r -a fields <<< "$row"
        for ((i=0; i<${#fields[@]} && i<${#widths[@]}; i++)); do
            if (( ${#fields[$i]} > ${widths[$i]} )); then
                widths[$i]=${#fields[$i]}
            fi
        done
    done <<< "$data_rows"

    # Create format string based on alignment
    local format_str=""
    local separator=""

    for width in "${widths[@]}"; do
        case "$alignment" in
            center)
                format_str="$format_str %-${width}s |"
                ;;
            right)
                format_str="$format_str %${width}s |"
                ;;
            *)  # left is default
                format_str="$format_str %-${width}s |"
                ;;
        esac
        separator="$separator-$(printf '%*s' "$width" | tr ' ' '-')-+"
    done

    # Print header
    local header_line
    # shellcheck disable=SC2059 # We need the format to be dynamic
    header_line=$(printf "| $format_str" "${headers[@]}")
    echo "$header_line"
    echo "+$separator"

    # Print data rows
    while IFS= read -r row; do
        IFS='|' read -r -a fields <<< "$row"
        # shellcheck disable=SC2059 # We need the format to be dynamic
        printf "| $format_str\n" "${fields[@]}"
    done <<< "$data_rows"
}

# Create a text report with standard formatting
# Arguments:
#   $1 - Report title
#   $2 - Report content
#   $3 - Environment name
#   $4 - Report type (optional)
# Returns:
#   Formatted text report
create_text_report() {
    local title="$1"
    local content="$2"
    local environment="$3"
    local report_type="${4:-Status Report}"

    # Create header
    local header=""
    header+="================================================================================================\n"
    header+="                              ${title}\n"
    header+="================================================================================================\n"
    header+="Environment: ${environment}                                    Date: $(date)\n"
    header+="Hostname: $(hostname)                                 Report Type: ${report_type}\n"
    header+="------------------------------------------------------------------------------------------------\n\n"

    # Combine header and content
    local report="${header}${content}"

    # Add footer
    local footer="\n------------------------------------------------------------------------------------------------\n"
    footer+="Generated by Cloud Infrastructure Platform Monitoring System v${FORMAT_UTILS_VERSION}\n"
    footer+="================================================================================================\n"

    echo -e "${report}${footer}"
}

# Format section header for text reports
# Arguments:
#   $1 - Section title
#   $2 - Character to use for underlining (default: "-")
# Returns:
#   Formatted section header
format_section_header() {
    local title="$1"
    local char="${2:--}"

    echo -e "\n$title"
    printf '%*s\n' "${#title}" | tr ' ' "$char"
}

# -----------------------------------------------------------------------------
# HTML FORMATTING FUNCTIONS
# -----------------------------------------------------------------------------

# Escape string for HTML
# Arguments:
#   $1 - String to escape
# Returns:
#   HTML-escaped string
escape_html() {
    local string="$1"
    local result="$string"

    # Replace special characters
    result="${result//&/&amp;}"    # Ampersand
    result="${result//</&lt;}"     # Less than
    result="${result//>/&gt;}"     # Greater than
    result="${result//\"/&quot;}"  # Double quote
    result="${result//\'/&#39;}"   # Single quote

    echo "$result"
}

# Create HTML table from data
# Arguments:
#   $1 - Header row (pipe-separated fields)
#   $2 - Data rows (newline-separated, pipe-separated fields)
#   $3 - CSS classes (optional)
#   $4 - ID (optional)
# Returns:
#   HTML table markup
create_html_table() {
    local header_row="$1"
    local data_rows="$2"
    local css_class="${3:-data-table}"
    local id="${4:-}"

    # Parse headers
    IFS='|' read -r -a headers <<< "$header_row"

    # Start table markup
    local html="<table"
    [[ -n "$id" ]] && html+=" id=\"$id\""
    html+=" class=\"$css_class\">\n"

    # Add header row
    html+="  <thead>\n    <tr>\n"
    for header in "${headers[@]}"; do
        html+="      <th>$(escape_html "$header")</th>\n"
    done
    html+="    </tr>\n  </thead>\n  <tbody>\n"

    # Add data rows
    while IFS= read -r row; do
        [[ -z "$row" ]] && continue

        IFS='|' read -r -a fields <<< "$row"
        html+="    <tr>\n"

        for field in "${fields[@]}"; do
            html+="      <td>$(escape_html "$field")</td>\n"
        done

        html+="    </tr>\n"
    done <<< "$data_rows"

    # Close table
    html+="  </tbody>\n</table>"

    echo -e "$html"
}

# Generate a complete HTML report
# Arguments:
#   $1 - Report title
#   $2 - Report content (HTML)
#   $3 - CSS styles (optional)
#   $4 - JavaScript code (optional)
#   $5 - Output file path (optional)
# Returns:
#   HTML document as string or 0/1 for success/failure if output file specified
create_html_report() {
    local title="$1"
    local content="$2"
    local css="${3:-}"
    local js="${4:-}"
    local output_file="${5:-}"

    # Default CSS if not provided
    if [[ -z "$css" ]]; then
        css=$(cat <<'EOF'
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    margin: 0;
    padding: 0;
    background-color: #f5f5f5;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    background-color: #fff;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
}
header {
    background-color: #0078d4;
    color: white;
    padding: 20px;
    margin-bottom: 20px;
}
h1, h2, h3 {
    margin-top: 0;
}
.section {
    margin-bottom: 30px;
    padding: 20px;
    background-color: white;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
}
th, td {
    padding: 12px 15px;
    border: 1px solid #ddd;
    text-align: left;
}
th {
    background-color: #f5f5f5;
}
tr:hover {
    background-color: #f9f9f9;
}
.footer {
    text-align: center;
    margin-top: 30px;
    padding: 10px;
    font-size: 0.9em;
    color: #777;
}
.healthy { background-color: #dff0d8; }
.warning { background-color: #fcf8e3; }
.critical { background-color: #f2dede; }
.unknown { background-color: #e8eaed; }
EOF
        )
    fi

    # Create HTML structure
    local html
    html=$(cat <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$(escape_html "$title")</title>
    <style>
$css
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>$(escape_html "$title")</h1>
            <p>Environment: $(escape_html "${ENVIRONMENT:-production}") | Generated: $(date)</p>
        </header>

$content

        <div class="footer">
            <p>Cloud Infrastructure Platform Monitoring System - Generated on $(date)</p>
        </div>
    </div>
EOF
    )

    # Add JavaScript if provided
    if [[ -n "$js" ]]; then
        html+="
<script>
$js
</script>"
    fi

    # Close HTML
    html+="
</body>
</html>"

    # Output to file or stdout
    if [[ -n "$output_file" ]]; then
        # Create parent directory if it doesn't exist
        local parent_dir
        parent_dir=$(dirname "$output_file")
        mkdir -p "$parent_dir" || {
            log_error "Unable to create directory: $parent_dir"
            return 1
        }

        echo -e "$html" > "$output_file" || {
            log_error "Failed to write HTML report to $output_file"
            return 1
        }

        log_debug "HTML report generated: $output_file"
        return 0
    else
        echo -e "$html"
        return 0
    fi
}

# -----------------------------------------------------------------------------
# EMAIL NOTIFICATION FORMATTING
# -----------------------------------------------------------------------------

# Format an email notification body
# Arguments:
#   $1 - Subject
#   $2 - Message content
#   $3 - Format (plain, html)
#   $4 - Environment name
#   $5 - Severity (info, warning, critical)
# Returns:
#   Formatted email body
format_email_notification() {
    local subject="$1"
    local message="$2"
    local format="${3:-plain}"
    local environment="${4:-production}"
    local severity="${5:-info}"

    # Set color based on severity
    local color
    case "$severity" in
        critical) color="#FF0000" ;; # Red
        warning)  color="#FFA500" ;; # Orange
        *)        color="#0078D4" ;; # Blue (default/info)
    esac

    if [[ "$format" == "html" ]]; then
        # Format as HTML
        cat <<EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$(escape_html "$subject")</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: $color;
            color: white;
            padding: 15px;
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>$(escape_html "$subject")</h2>
        </div>
        <div class="content">
            $(echo -e "$message" | sed 's/$/<br>/g')

            <p><strong>Environment:</strong> $(escape_html "$environment")</p>
            <p><strong>Time:</strong> $(date)</p>
            <p><strong>Host:</strong> $(hostname)</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from Cloud Infrastructure Platform Monitoring System.</p>
        </div>
    </div>
</body>
</html>
EOF
    else
        # Format as plain text
        cat <<EOF
$subject

$(echo -e "$message")

Environment: $environment
Time: $(date)
Host: $(hostname)

--
This is an automated notification from Cloud Infrastructure Platform Monitoring System.
EOF
    fi
}

# Format SMS notification
# Arguments:
#   $1 - Alert message
#   $2 - Environment name
#   $3 - Severity (info, warning, critical)
# Returns:
#   Formatted SMS message
format_sms_notification() {
    local message="$1"
    local environment="${2:-production}"
    local severity="${3:-info}"

    # Create a short prefix based on severity
    local prefix
    case "$severity" in
        critical) prefix="CRITICAL" ;;
        warning)  prefix="WARNING" ;;
        *)        prefix="INFO" ;;
    esac

    # Format the message (keep it concise for SMS)
    echo "[$prefix] $message (Env: $environment, $(date +"%H:%M:%S"))"
}

# -----------------------------------------------------------------------------
# REPORT GENERATION FUNCTIONS
# -----------------------------------------------------------------------------

# Generate report based on format
# Arguments:
#   $1 - Report title
#   $2 - Report data (format depends on $3)
#   $3 - Output format (text, json, html, csv)
#   $4 - Output file (optional)
#   $5 - Environment name (default: production)
# Returns:
#   Formatted report or 0/1 for success/failure if output file is specified
generate_report() {
    local title="$1"
    local data="$2"
    local format="${3:-text}"
    local output_file="$4"
    local environment="${5:-production}"

    case "$format" in
        json)
            # Assume data is a JSON string or raw data to be formatted
            local json_data
            if validate_json "$data" "silent"; then
                json_data="$data"
            else
                # Try to convert to JSON
                json_data=$(format_raw_data_as_json "$data")
            fi

            local report
            report=$(create_json_report "$title" "$environment" "$json_data")

            if [[ -n "$output_file" ]]; then
                # Create parent directory if it doesn't exist
                local parent_dir
                parent_dir=$(dirname "$output_file")
                mkdir -p "$parent_dir" || {
                    log_error "Unable to create directory: $parent_dir"
                    return 1
                }

                echo "$report" > "$output_file" || {
                    log_error "Failed to write JSON report to $output_file"
                    return 1
                }

                log_debug "JSON report generated: $output_file"
                return 0
            else
                echo "$report"
                return 0
            fi
            ;;

        html)
            # Assume data is HTML content or plain text to be formatted
            local html_content
            if [[ "$data" == *"<"*">"* ]]; then
                # Likely already HTML
                html_content="$data"
            else
                # Convert plain text to HTML
                html_content="<pre>$(escape_html "$data")</pre>"
            fi

            create_html_report "$title" "$html_content" "" "" "$output_file"
            return $?
            ;;

        csv)
            # Assume data has header and rows already formatted for CSV
            if [[ -n "$output_file" ]]; then
                echo "$data" > "$output_file" || {
                    log_error "Failed to write CSV report to $output_file"
                    return 1
                }

                log_debug "CSV report generated: $output_file"
                return 0
            else
                echo "$data"
                return 0
            fi
            ;;

        *)  # Default to text
            local text_report
            text_report=$(create_text_report "$title" "$data" "$environment")

            if [[ -n "$output_file" ]]; then
                # Create parent directory if it doesn't exist
                local parent_dir
                parent_dir=$(dirname "$output_file")
                mkdir -p "$parent_dir" || {
                    log_error "Unable to create directory: $parent_dir"
                    return 1
                }

                echo -e "$text_report" > "$output_file" || {
                    log_error "Failed to write text report to $output_file"
                    return 1
                }

                log_debug "Text report generated: $output_file"
                return 0
            else
                echo -e "$text_report"
                return 0
            fi
            ;;
    esac
}

# Convert raw data to JSON format
# Arguments:
#   $1 - Raw data (key-value pairs, one per line)
# Returns:
#   JSON object string
format_raw_data_as_json() {
    local raw_data="$1"
    local json_pairs=()

    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Try to parse as key-value pair (key: value or key = value)
        if [[ "$line" =~ ^([^:=]+)[[:space:]]*[:=][[:space:]]*(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Trim whitespace
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"

            # Escape the value for JSON
            value=$(escape_json_string "$value")

            # Add to JSON object
            json_pairs+=("\"$key\": \"$value\"")
        fi
    done <<< "$raw_data"

    # Create JSON object
    local json_data="{"
    local first=true

    for pair in "${json_pairs[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            json_data+=", "
        fi

        json_data+="$pair"
    done

    json_data+="}"

    echo "$json_data"
}

# -----------------------------------------------------------------------------
# TEMPLATE FUNCTIONS
# -----------------------------------------------------------------------------

# Render a template with variables
# Arguments:
#   $1 - Template content or file path
#   $2+ - Variable values as "key=value" pairs
#   Last parameter can be output file path (optional)
# Returns:
#   Rendered template content or 0/1 for success/failure if output file is specified
render_template() {
    local template="$1"
    shift

    # Check if template is a file path
    if [[ -f "$template" ]]; then
        template=$(cat "$template") || {
            log_error "Failed to read template file: $template"
            return 1
        }
    fi

    # Get output file parameter (if it's the last parameter)
    local output_file=""
    local vars=("$@")
    if [[ "${#vars[@]}" -gt 0 && "${vars[-1]}" == /* ]]; then
        output_file="${vars[-1]}"
        unset 'vars[-1]'
    fi

    # Replace variables
    local rendered="$template"
    for var in "${vars[@]}"; do
        if [[ "$var" =~ ^([^=]+)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Replace {{variable}} with value
            rendered="${rendered//\{\{$key\}\}/$value}"
        fi
    done

    # Output to file or stdout
    if [[ -n "$output_file" ]]; then
        # Create parent directory if it doesn't exist
        local parent_dir
        parent_dir=$(dirname "$output_file")
        mkdir -p "$parent_dir" || {
            log_error "Unable to create directory: $parent_dir"
            return 1
        }

        echo -e "$rendered" > "$output_file" || {
            log_error "Failed to write rendered template to $output_file"
            return 1
        }

        log_debug "Template rendered to: $output_file"
        return 0
    else
        echo -e "$rendered"
        return 0
    fi
}

# Load a template from the templates directory
# Arguments:
#   $1 - Template name (without directory path)
#   $2 - Template type (default: report)
# Returns:
#   Template content or empty string if not found
load_template() {
    local template_name="$1"
    local template_type="${2:-report}"

    # Define template paths to search in order of preference
    local paths=(
        "${SCRIPT_DIR}/../templates/${template_type}/${template_name}"
        "${PROJECT_ROOT}/scripts/monitoring/templates/${template_type}/${template_name}"
        "${PROJECT_ROOT}/templates/${template_type}/${template_name}"
    )

    # Try to find the template
    for path in "${paths[@]}"; do
        if [[ -f "$path" ]]; then
            cat "$path"
            return 0
        fi
    done

    log_warning "Template not found: ${template_name} (type: ${template_type})"
    return 1
}

# -----------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -----------------------------------------------------------------------------

# Convert string to proper case (first letter uppercase, rest lowercase)
# Arguments:
#   $1 - String to convert
# Returns:
#   Proper-cased string
to_proper_case() {
    local string="$1"
    if [[ -z "$string" ]]; then
        echo ""
        return
    fi

    # Convert first character to uppercase and the rest to lowercase
    echo "${string^}"
}

# Convert string to camelCase
# Arguments:
#   $1 - String to convert
# Returns:
#   camelCased string
to_camel_case() {
    local string="$1"
    if [[ -z "$string" ]]; then
        echo ""
        return
    fi

    # Split by non-alphanumeric characters
    local words
    IFS=$' _-' read -r -a words <<< "$string"

    local result=""
    local first=true

    for word in "${words[@]}"; do
        if [[ -z "$word" ]]; then
            continue
        fi

        if [[ "$first" == "true" ]]; then
            result+="${word,,}"
            first=false
        else
            result+="${word^}"
        fi
    done

    echo "$result"
}

# Convert string to snake_case
# Arguments:
#   $1 - String to convert
# Returns:
#   snake_cased string
to_snake_case() {
    local string="$1"
    if [[ -z "$string" ]]; then
        echo ""
        return
    fi

    # Replace non-alphanumeric characters with underscores
    local result="${string//[^a-zA-Z0-9]/_}"

    # Convert to lowercase
    echo "${result,,}"
}

# Truncate string to specified length
# Arguments:
#   $1 - String to truncate
#   $2 - Maximum length
#   $3 - Suffix to add if truncated (default: "...")
# Returns:
#   Truncated string
truncate_string() {
    local string="$1"
    local max_length="$2"
    local suffix="${3:-...}"

    if (( ${#string} <= max_length )); then
        echo "$string"
    else
        local truncated_length=$((max_length - ${#suffix}))
        echo "${string:0:$truncated_length}$suffix"
    fi
}

# Add color to text for terminal output
# Arguments:
#   $1 - Text to colorize
#   $2 - Color name (red, green, yellow, blue, purple, cyan, gray)
# Returns:
#   Colorized text
colorize() {
    local text="$1"
    local color="${2:-}"

    # Define colors
    local red='\033[0;31m'
    local green='\033[0;32m'
    local yellow='\033[0;33m'
    local blue='\033[0;34m'
    local purple='\033[0;35m'
    local cyan='\033[0;36m'
    local gray='\033[0;37m'
    local reset='\033[0m'

    # Apply color if terminal supports it
    if [[ -t 1 ]]; then
        case "$color" in
            red)    echo -e "${red}${text}${reset}" ;;
            green)  echo -e "${green}${text}${reset}" ;;
            yellow) echo -e "${yellow}${text}${reset}" ;;
            blue)   echo -e "${blue}${text}${reset}" ;;
            purple) echo -e "${purple}${text}${reset}" ;;
            cyan)   echo -e "${cyan}${text}${reset}" ;;
            gray)   echo -e "${gray}${text}${reset}" ;;
            *)      echo "$text" ;;
        esac
    else
        echo "$text"
    fi
}

# -----------------------------------------------------------------------------
# EXPORT PUBLIC FUNCTIONS
# -----------------------------------------------------------------------------

# Export JSON functions
export -f json_object
export -f json_array
export -f escape_json_string
export -f validate_json
export -f format_json
export -f create_json_report

# Export CSV functions
export -f csv_row
export -f escape_csv_field
export -f generate_csv_file
export -f json_to_csv

# Export text functions
export -f format_text_table
export -f create_text_report
export -f format_section_header

# Export HTML functions
export -f escape_html
export -f create_html_table
export -f create_html_report

# Export notification functions
export -f format_email_notification
export -f format_sms_notification

# Export report functions
export -f generate_report
export -f format_raw_data_as_json

# Export template functions
export -f render_template
export -f load_template

# Export utility functions
export -f to_proper_case
export -f to_camel_case
export -f to_snake_case
export -f truncate_string
export -f colorize

# -----------------------------------------------------------------------------
# SELF-TEST
# -----------------------------------------------------------------------------

# Self-test function to verify functionality
format_utils_self_test() {
    echo "Format Utils Self-Test"
    echo "---------------------"

    # Test JSON formatting
    echo "Testing JSON formatting..."
    local test_json=$(json_object "name" "Test Server" "status" "active" "uptime" 98.5 "enabled" true)
    echo "JSON Object: $test_json"

    local test_array=$(json_array "value1" "value2" 123 true)
    echo "JSON Array: $test_array"

    # Test CSV formatting
    echo -e "\nTesting CSV formatting..."
    local csv_header=$(csv_row "Name" "Status" "Value")
    local csv_row1=$(csv_row "Server 1" "Active" "123.45")
    local csv_row2=$(csv_row "Server 2" "Inactive, pending restart" "67.8")
    echo "CSV Header: $csv_header"
    echo "CSV Row 1: $csv_row1"
    echo "CSV Row 2: $csv_row2"

    # Test text table
    echo -e "\nTesting text table formatting..."
    local test_headers="Name|Status|Value"
    local test_data="Server 1|Active|123.45\nServer 2|Inactive|67.8"
    echo "Text Table:"
    format_text_table "$test_headers" "$test_data"

    # Test template rendering
    echo -e "\nTesting template rendering..."
    local template="Hello {{name}}! Your status is {{status}}."
    echo "Template: $template"
    echo "Rendered: $(render_template "$template" "name=World" "status=Active")"

    # Test utility functions
    echo -e "\nTesting utility functions..."
    echo "Proper case: $(to_proper_case "hello world")"
    echo "Camel case: $(to_camel_case "hello world")"
    echo "Snake case: $(to_snake_case "Hello World")"
    echo "Truncated: $(truncate_string "This is a very long string that needs to be truncated" 20)"
    echo "Colorized: $(colorize "This text is green" "green")"

    echo -e "\nSelf-test completed successfully."
}

# Run self-test if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    format_utils_self_test
fi
