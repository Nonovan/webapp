#!/bin/bash
# filepath: scripts/security/firewall_check.sh
# Firewall Configuration Check Script
# Verifies firewall rules against a defined security policy and identifies
# potential security gaps or misconfigurations in firewall rules.

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform/security"
LOG_FILE="${LOG_DIR}/firewall_check.log"
REPORT_DIR="${LOG_DIR}/reports"
REPORT_FILE="${REPORT_DIR}/firewall_check_report_$(date +%Y%m%d%H%M%S).txt"
DEFAULT_POLICY_FILE="${PROJECT_ROOT}/docs/security/firewall-policies.md"
DEFAULT_OUTPUT_FORMAT="text" # Options: text, json, csv
EMAIL_REPORT=false
EMAIL_RECIPIENT=""
VERBOSE=false
COMPARE_POLICY=false # Flag to enable comparison against a policy file
SAVE_CURRENT_RULES=false # Flag to save current rules to a file
STRICT_MODE=false # Flag for strict comparison (fails on any deviation)
EXPORT_PATH="" # Path to export current rules
ANALYZE_GAPS=false # Flag to analyze security gaps in the current configuration
INCLUDE_STANDARD_CHECKS=true # Flag to include standard security checks

# --- Ensure Directories Exist ---
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

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
    echo "Checks firewall configuration and optionally compares against a policy."
    echo ""
    echo "Options:"
    echo "  --compare-policy FILE   Compare current rules against the specified policy file"
    echo "                          (default: $DEFAULT_POLICY_FILE if flag is set without file)"
    echo "  --output-format FMT     Output format: text, json, csv (default: $DEFAULT_OUTPUT_FORMAT)"
    echo "  --email RECIPIENT       Email the report to the specified recipient"
    echo "  --verbose, -v           Enable verbose logging"
    echo "  --save-rules PATH       Save current firewall rules to specified file"
    echo "  --strict                Enable strict mode (fails on any policy deviation)"
    echo "  --analyze-gaps          Analyze security gaps in current firewall configuration"
    echo "  --no-standard-checks    Disable standard security best practice checks"
    echo "  --help, -h              Display this help message"
    echo ""
    exit 0
}

command_exists() {
    command -v "$1" &> /dev/null
}

# Check if a command exists and is executable
check_command() {
    local cmd="$1"
    if ! command_exists "$cmd"; then
        if [[ -n "${2:-}" ]]; then
            log_warn "$2"
        else
            log_warn "Command $cmd not found."
        fi
        return 1
    fi
    return 0
}

# --- Argument Parsing ---
POLICY_FILE="" # Will be set if --compare-policy is used

while [[ $# -gt 0 ]]; do
    case "$1" in
        --compare-policy)
            COMPARE_POLICY=true
            # Check if next argument is a file path or another option
            if [[ $# -gt 1 && ! "$2" == --* ]]; then
                shift
                POLICY_FILE="$1"
            else
                POLICY_FILE="$DEFAULT_POLICY_FILE" # Use default if no file specified
            fi
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
        --save-rules)
            shift
            SAVE_CURRENT_RULES=true
            EXPORT_PATH="$1"
            shift
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --analyze-gaps)
            ANALYZE_GAPS=true
            shift
            ;;
        --no-standard-checks)
            INCLUDE_STANDARD_CHECKS=false
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

# Validate policy file if comparison is requested
if [[ "$COMPARE_POLICY" == "true" && ! -f "$POLICY_FILE" ]]; then
    log_error "Policy file not found: $POLICY_FILE"
    exit 1
fi

# Validate output format
case "$OUTPUT_FORMAT" in
    text|json|csv)
        ;;
    *)
        log_error "Invalid output format: $OUTPUT_FORMAT. Use 'text', 'json', or 'csv'."
        exit 1
        ;;
esac

# Check if required commands for JSON output exist
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    if ! command_exists jq; then
        log_warn "jq command not found. JSON output formatting may be limited."
    fi
fi

# --- Firewall Detection and Rule Fetching ---
detect_firewall() {
    log_debug "Detecting firewall type..."
    local fw_types=()

    # Check for multiple firewall systems
    if command_exists ufw && ufw status &>/dev/null; then
        fw_types+=("ufw")
    fi

    if command_exists firewall-cmd && firewall-cmd --state &>/dev/null; then
        fw_types+=("firewalld")
    fi

    if command_exists iptables; then
        fw_types+=("iptables")
    fi

    if command_exists nft && nft list tables &>/dev/null; then
        fw_types+=("nftables")
    fi

    # If multiple firewalls found, prioritize
    if [[ ${#fw_types[@]} -gt 0 ]]; then
        # If UFW is available and active, prefer it
        if [[ " ${fw_types[*]} " =~ " ufw " ]] && ufw status | grep -q "Status: active"; then
            log_debug "Multiple firewalls detected, using UFW as it's active"
            echo "ufw"
            return 0
        fi

        # If firewalld is available and active, prefer it
        if [[ " ${fw_types[*]} " =~ " firewalld " ]] && firewall-cmd --state | grep -q "running"; then
            log_debug "Multiple firewalls detected, using firewalld as it's active"
            echo "firewalld"
            return 0
        fi

        # Otherwise use the first detected
        log_debug "Using ${fw_types[0]} as firewall type"
        echo "${fw_types[0]}"
        return 0
    fi

    log_warn "No common firewall management tool (ufw, firewalld, iptables, nftables) detected."
    echo "none"
}

get_iptables_rules() {
    log_debug "Fetching iptables rules..."
    if ! command_exists iptables; then
        log_error "iptables command not found"
        return 1
    fi

    # Get all tables and chains
    local rules=""
    rules+="# IPv4 rules (iptables)\n"
    rules+=$(iptables-save 2>/dev/null || iptables -L -v -n 2>/dev/null)

    # Also get IPv6 rules if ip6tables is available
    if command_exists ip6tables; then
        rules+="\n\n# IPv6 rules (ip6tables)\n"
        rules+=$(ip6tables-save 2>/dev/null || ip6tables -L -v -n 2>/dev/null)
    fi

    echo -e "$rules"
}

get_ufw_rules() {
    log_debug "Fetching UFW rules..."
    if ! command_exists ufw; then
        log_error "ufw command not found"
        return 1
    fi

    local rules=""
    # Get status and rules
    rules+="# UFW Status\n"
    rules+=$(ufw status verbose 2>/dev/null)

    # Try to get numbered rules if available
    rules+="\n\n# UFW Numbered Rules\n"
    rules+=$(ufw status numbered 2>/dev/null || echo "No numbered rules available")

    echo -e "$rules"
}

get_firewalld_rules() {
    log_debug "Fetching firewalld rules..."
    if ! command_exists firewall-cmd; then
        log_error "firewall-cmd command not found"
        return 1
    fi

    local rules=""
    # Get general status
    rules+="# firewalld status\n"
    rules+="Status: $(firewall-cmd --state 2>/dev/null)\n\n"

    # Get the default zone
    local default_zone
    default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    rules+="# Default zone: $default_zone\n\n"

    # Get detailed information for all zones
    rules+="# Zone details\n"
    rules+=$(firewall-cmd --list-all-zones 2>/dev/null)

    # Get direct rules
    rules+="\n\n# Direct rules\n"
    rules+=$(firewall-cmd --direct --get-all-rules 2>/dev/null || echo "No direct rules")

    echo -e "$rules"
}

get_nftables_rules() {
    log_debug "Fetching nftables rules..."
    if ! command_exists nft; then
        log_error "nft command not found"
        return 1
    fi

    local rules=""
    # Get all ruleset
    rules+="# nftables ruleset\n"
    rules+=$(nft list ruleset 2>/dev/null)

    echo -e "$rules"
}

# --- Policy Parsing and Comparison ---

# Parse policy rules from the specified file
# This implementation is adapted for the markdown format in firewall-policies.md
parse_policy_file() {
    local file="$1"
    local firewall_type="$2"
    log_info "Parsing policy rules from $file for firewall type: $firewall_type..."

    if [[ ! -f "$file" ]]; then
        log_error "Policy file not found: $file"
        return 1
    fi

    # Temporary file to hold extracted rules
    local tmp_rules=$(mktemp)
    trap 'rm -f "$tmp_rules"' EXIT

    # Extract rules from markdown tables
    # This assumes a specific format in the markdown file with tables for rules

    # Look for the table headers first to detect table sections
    log_debug "Extracting rule tables from policy file"

    # Standard patterns for different firewall types
    local rule_patterns=()
    case "$firewall_type" in
        iptables|nftables)
            rule_patterns+=("^\s*\|\s*Any\s*\|\s*" "^\s*\|\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*\|\s*")
            ;;
        ufw)
            rule_patterns+=("^\s*\|\s*[0-9]+/[a-z]+\s*\|\s*" "^\s*\|\s*ALLOW\s*\|\s*" "^\s*\|\s*DENY\s*\|\s*")
            ;;
        firewalld)
            rule_patterns+=("^\s*\|\s*zone\s*\|\s*" "^\s*\|\s*service\s*\|\s*" "^\s*\|\s*port\s*\|\s*")
            ;;
    esac

    # Read the file and extract rules based on patterns
    local in_table=false
    while IFS= read -r line; do
        # Detect table headers
        if [[ "$line" =~ ^\|.*Port/Protocol.*Purpose.*Environment.*\|$ ]]; then
            in_table=true
            echo "# Detected rules table" >> "$tmp_rules"
            continue
        fi

        # End of table
        if [[ "$in_table" == "true" && ! "$line" =~ ^\|.*\|$ ]]; then
            in_table=false
        fi

        # Process table rows
        if [[ "$in_table" == "true" ]]; then
            # Skip table separators
            if [[ "$line" =~ ^\|[-]+\|[-]+\|$ ]]; then
                continue
            fi

            # Extract rule from table cell
            # This is a simplified version - in a real implementation you'd parse
            # the Source, Destination, Port/Protocol columns more accurately
            for pattern in "${rule_patterns[@]}"; do
                if [[ "$line" =~ $pattern ]]; then
                    # Clean up the line and format as a rule
                    local cleaned_line=$(echo "$line" | sed 's/^|//;s/|$//' | sed 's/ *| */|/g')
                    echo "$cleaned_line" >> "$tmp_rules"
                    break
                fi
            done
        fi
    done < "$file"

    # If we found any rules, output them
    if [[ -s "$tmp_rules" ]]; then
        cat "$tmp_rules"
        return 0
    else
        log_warn "No matching rules found in policy file for firewall type: $firewall_type"
        echo "# No rules extracted from policy file"
        return 1
    fi
}

# Load policy rules from the specified file
load_policy_rules() {
    local file="$1"
    local firewall_type="$2"
    log_info "Loading policy rules from $file for firewall type: $firewall_type..."

    local rules
    rules=$(parse_policy_file "$file" "$firewall_type")

    # If parsing failed, try a direct approach based on firewall type
    if [[ $? -ne 0 || -z "$rules" ]]; then
        log_warn "Policy file parsing failed, trying direct extraction..."
        case "$firewall_type" in
            iptables)
                # Look for specific iptables patterns in the file
                rules=$(grep -E '^\s*iptables\s+(-[A-Za-z]+\s+[^ ]+|-[A-Z]\s+[^ ]+)' "$file" || echo "# No direct iptables rules found")
                ;;
            ufw)
                # Look for UFW rule patterns
                rules=$(grep -E '^\s*ufw\s+(allow|deny|reject)' "$file" || echo "# No direct UFW rules found")
                ;;
            firewalld)
                # Look for firewalld rule patterns
                rules=$(grep -E '^\s*firewall-cmd\s+--permanent\s+--zone=' "$file" || echo "# No direct firewalld rules found")
                ;;
            nftables)
                # Look for nftables rule patterns
                rules=$(grep -E '^\s*nft\s+(add|insert|create)' "$file" || echo "# No direct nftables rules found")
                ;;
            *)
                log_error "Unsupported firewall type for direct rule extraction: $firewall_type"
                return 1
                ;;
        esac
    fi

    echo "$rules"
}

# Standard security checks for firewalls
perform_standard_security_checks() {
    local firewall_type="$1"
    local current_rules="$2"
    local issues=()
    local warnings=()

    log_info "Performing standard security checks for $firewall_type firewall..."

    # Define common checks for all firewall types
    # 1. Check for default deny policy
    case "$firewall_type" in
        iptables)
            # Check for default ACCEPT policy on INPUT chain
            if echo "$current_rules" | grep -qE '^:INPUT ACCEPT'; then
                issues+=("Default INPUT chain policy is ACCEPT - should be DROP or REJECT")
            fi
            # Check for default ACCEPT policy on FORWARD chain
            if echo "$current_rules" | grep -qE '^:FORWARD ACCEPT'; then
                issues+=("Default FORWARD chain policy is ACCEPT - should be DROP or REJECT")
            fi
            # Check for rules allowing all traffic
            if echo "$current_rules" | grep -qE -- '-A INPUT .* -j ACCEPT$' | grep -qvE '(-s|--source|--sport|--dport|-p)'; then
                issues+=("Found rule accepting all incoming traffic without restrictions")
            fi
            # Check for rate limiting on SSH
            if echo "$current_rules" | grep -qE -- '-A INPUT .* --dport (22|ssh) .* -j ACCEPT$' | grep -qvE '(-m limit|--limit)'; then
                warnings+=("SSH access not rate-limited - consider adding rate limiting to prevent brute force attacks")
            fi
            ;;
        ufw)
            # Check if UFW is enabled
            if echo "$current_rules" | grep -q "Status: inactive"; then
                issues+=("UFW is installed but not enabled")
            fi
            # Check default policy
            if echo "$current_rules" | grep -q "Default: allow"; then
                issues+=("Default policy is allow - should be deny or reject")
            fi
            # Check for overly permissive rules
            if echo "$current_rules" | grep -qE "ALLOW\s+Anywhere"; then
                warnings+=("Found rule allowing traffic from anywhere - verify if this is intended")
            fi
            ;;
        firewalld)
            # Check if firewalld is running
            if ! echo "$current_rules" | grep -q "Status: running"; then
                issues+=("firewalld is installed but not running")
            fi
            # Check default zone
            local default_zone
            default_zone=$(echo "$current_rules" | grep -A 1 "Default zone:" | tail -1)
            if [[ "$default_zone" == "public" ]]; then
                warnings+=("Default zone is public - consider using a more restrictive zone")
            fi
            # Check if SSH service is enabled in public zone
            if echo "$current_rules" | grep -A20 "public" | grep -qE "services:.*(ssh|SSH)"; then
                warnings+=("SSH service enabled in public zone - consider restricting to specific IPs")
            fi
            ;;
        nftables)
            # Check for base chains with accept policy
            if echo "$current_rules" | grep -qE 'type filter hook input .* policy accept'; then
                issues+=("Input chain has accept policy - should be drop")
            fi
            if echo "$current_rules" | grep -qE 'type filter hook forward .* policy accept'; then
                issues+=("Forward chain has accept policy - should be drop")
            fi
            ;;
        none)
            issues+=("No firewall detected - system is unprotected")
            ;;
    esac

    # Common checks for all firewall types
    # Check for insecure services
    local insecure_ports=("23:telnet" "21:ftp" "137:netbios" "138:netbios" "139:netbios" "445:smb")
    for port_info in "${insecure_ports[@]}"; do
        local port=${port_info%%:*}
        local service=${port_info#*:}

        case "$firewall_type" in
            iptables)
                if echo "$current_rules" | grep -qE -- "-A INPUT.*--dport $port.*-j ACCEPT"; then
                    warnings+=("Port $port ($service) is open - this service is potentially insecure")
                fi
                ;;
            ufw)
                if echo "$current_rules" | grep -qE "$port/(tcp|udp).*ALLOW"; then
                    warnings+=("Port $port ($service) is allowed - this service is potentially insecure")
                fi
                ;;
            firewalld)
                if echo "$current_rules" | grep -qE "port.*$port"; then
                    warnings+=("Port $port ($service) is open - this service is potentially insecure")
                fi
                ;;
            nftables)
                if echo "$current_rules" | grep -qE "dport $port.*accept"; then
                    warnings+=("Port $port ($service) is open - this service is potentially insecure")
                fi
                ;;
        esac
    done

    # Check for exposed database ports
    local database_ports=("3306:MySQL" "5432:PostgreSQL" "27017:MongoDB" "6379:Redis")
    for port_info in "${database_ports[@]}"; do
        local port=${port_info%%:*}
        local service=${port_info#*:}

        case "$firewall_type" in
            iptables)
                if echo "$current_rules" | grep -qE -- "-A INPUT.*--dport $port.*-j ACCEPT" | grep -qvE '(-s|--source) (10\.|172\.16\.|192\.168\.)'; then
                    warnings+=("Port $port ($service) appears to be publicly accessible - database ports should be restricted to internal networks")
                fi
                ;;
            ufw)
                if echo "$current_rules" | grep -qE "$port/(tcp|udp).*ALLOW IN" | grep -qvE 'ALLOW IN.*from (10\.|172\.16\.|192\.168\.)'; then
                    warnings+=("Port $port ($service) appears to be publicly accessible - database ports should be restricted to internal networks")
                fi
                ;;
            firewalld)
                # Simplified check - would need to verify zones in real implementation
                if echo "$current_rules" | grep -qE "port.*port=\"$port\""; then
                    warnings+=("Port $port ($service) appears to be open - verify it's not publicly accessible")
                fi
                ;;
            nftables)
                if echo "$current_rules" | grep -qE "dport $port.*accept"; then
                    warnings+=("Port $port ($service) appears to be open - verify it's not publicly accessible")
                fi
                ;;
        esac
    done

    # Return results in a format that can be easily processed for reporting
    if [[ ${#issues[@]} -gt 0 || ${#warnings[@]} -gt 0 ]]; then
        echo "ISSUES=$(printf "%s|" "${issues[@]}")"
        echo "WARNINGS=$(printf "%s|" "${warnings[@]}")"
        return 1  # Issues found
    else
        echo "No security issues found in current firewall configuration."
        return 0  # No issues
    fi
}

# Analyze security gaps in firewall configuration
analyze_security_gaps() {
    local firewall_type="$1"
    local current_rules="$2"
    local gaps=()

    log_info "Analyzing security gaps in firewall configuration..."

    # Check if basic services are protected
    # These are simplified checks - in a real implementation you'd analyze
    # the rules more thoroughly based on your specific security requirements

    # 1. Check for common web ports protection
    case "$firewall_type" in
        iptables)
            # Check if HTTP/HTTPS are rate limited
            if echo "$current_rules" | grep -qE -- "-A INPUT.*--dport (80|443).*-j ACCEPT" | grep -qvE '(-m limit|--limit)'; then
                gaps+=("Web service ports (80/443) are not rate-limited - consider adding rate limiting to prevent DoS attacks")
            fi

            # Check for connection tracking on common ports
            for port in 80 443 22; do
                if echo "$current_rules" | grep -qE -- "-A INPUT.*--dport $port.*-j ACCEPT" | grep -qvE '(-m conntrack|--ctstate)'; then
                    gaps+=("Port $port lacks connection tracking - add '-m conntrack --ctstate NEW,ESTABLISHED' for better security")
                fi
            done

            # Check for logging of dropped packets
            if ! echo "$current_rules" | grep -qE -- "-A INPUT.*(--log-prefix|LOG)"; then
                gaps+=("No logging rules found for dropped packets - consider adding logging for security monitoring")
            fi

            # Check for ICMP flood protection
            if echo "$current_rules" | grep -qE -- "-A INPUT.*-p icmp.*-j ACCEPT" | grep -qvE '(-m limit|--limit)'; then
                gaps+=("ICMP traffic not rate-limited - consider adding rate limiting to prevent ping floods")
            fi
            ;;
        ufw)
            # Similar checks for UFW
            if echo "$current_rules" | grep -qE "(80|443)/(tcp|udp).*ALLOW" | grep -qvE "limit"; then
                gaps+=("Web service ports (80/443) are not rate-limited in UFW configuration")
            fi

            # Check for logging configuration
            if echo "$current_rules" | grep -q "Logging: off"; then
                gaps+=("UFW logging is disabled - enable logging for security monitoring")
            fi
            ;;
        firewalld)
            # Check public zone configuration
            if echo "$current_rules" | grep -A30 "public" | grep -qE "services:.*(http|https)"; then
                gaps+=("HTTP/HTTPS services enabled in public zone - consider creating a dedicated web zone")
            fi

            # Check rich rules for rate limiting
            if ! echo "$current_rules" | grep -qE "rich.*(limit value)"; then
                gaps+=("No rate limiting rules found in firewalld configuration")
            fi
            ;;
        nftables)
            # Check for rate limiting
            if ! echo "$current_rules" | grep -qE "limit rate"; then
                gaps+=("No rate limiting rules found in nftables configuration")
            fi

            # Check for logging
            if ! echo "$current_rules" | grep -qE "log"; then
                gaps+=("No logging rules found in nftables configuration")
            fi
            ;;
    esac

    # Check for basic protection against common attacks
    # (port scanning, SYN floods, etc.)
    case "$firewall_type" in
        iptables)
            # Check for SYN flood protection
            if ! echo "$current_rules" | grep -qE -- "-A INPUT.*-p tcp.*--syn.*-m limit"; then
                gaps+=("No SYN flood protection detected - consider adding rules to limit new TCP connections")
            fi

            # Check for fragment rules
            if ! echo "$current_rules" | grep -qE -- "-A INPUT.*-f"; then
                gaps+=("No fragmented packet handling rules found - consider adding rules to manage fragmented packets")
            fi
            ;;
        ufw|firewalld|nftables)
            # Simplified checks for other firewalls
            gaps+=("Unable to verify advanced protection features (SYN flood, fragmentation attacks) - manual review recommended")
            ;;
    esac

    # Return gaps in a format that can be easily processed for reporting
    if [[ ${#gaps[@]} -gt 0 ]]; then
        echo "GAPS=$(printf "%s|" "${gaps[@]}")"
        return 1  # Gaps found
    else
        echo "No significant security gaps identified."
        return 0  # No gaps
    fi
}

# Compare current rules with policy rules
compare_rules() {
    local current_rules="$1"
    local policy_rules="$2"
    local firewall_type="$3"
    log_info "Comparing current rules with policy..."

    local compliant_count=0
    local non_compliant_count=0
    local missing_count=0
    local extra_count=0
    local missing_rules=()
    local extra_rules=()

    # This is a simplified implementation - in a real-world scenario,
    # you would need a more sophisticated approach specific to each firewall type

    # For demonstration purposes, we're doing a simple line-based comparison
    # after normalizing both rule sets

    # Create temporary files for comparison
    local tmp_policy=$(mktemp)
    local tmp_current=$(mktemp)
    local tmp_match=$(mktemp)
    trap 'rm -f "$tmp_policy" "$tmp_current" "$tmp_match"' EXIT

    # Pre-process policy rules
    echo "$policy_rules" | grep -v '^#' | sort > "$tmp_policy"

    # Pre-process current rules based on firewall type
    case "$firewall_type" in
        iptables)
            # Extract INPUT, FORWARD chains for comparison
            echo "$current_rules" | grep -E '^-A (INPUT|FORWARD|OUTPUT)' | sort > "$tmp_current"
            ;;
        ufw)
            # Extract numbered rules
            echo "$current_rules" | grep -E '^\[\s*[0-9]+\]' | sort > "$tmp_current"
            ;;
        firewalld)
            # Extract services, ports, and rich rules
            echo "$current_rules" | grep -E '(service|port|rule family)' | sort > "$tmp_current"
            ;;
        nftables)
            echo "$current_rules" | grep -v '^#' | grep -v '^table\|^chain\|^flush\|^}$' | sort > "$tmp_current"
            ;;
    esac

    # Count policy rules (excluding comments and empty lines)
    local policy_count=$(grep -v '^$' "$tmp_policy" | wc -l)

    # Count current rules (excluding comments and empty lines)
    local current_count=$(grep -v '^$' "$tmp_current" | wc -l)

    # Find common rules between policy and current
    comm -12 "$tmp_policy" "$tmp_current" > "$tmp_match"
    local match_count=$(wc -l < "$tmp_match")

    # Calculate counts
    compliant_count=$match_count
    non_compliant_count=$((policy_count - match_count))

    # If there are missing rules, capture them
    if [[ $non_compliant_count -gt 0 ]]; then
        while IFS= read -r line; do
            missing_rules+=("$line")
        done < <(comm -23 "$tmp_policy" "$tmp_current")
        missing_count=${#missing_rules[@]}
    fi

    # Find rules in current but not in policy
    while IFS= read -r line; do
        extra_rules+=("$line")
    done < <(comm -13 "$tmp_policy" "$tmp_current")
    extra_count=${#extra_rules[@]}

    # Output results
    echo "Compliant: $compliant_count"
    echo "Non-Compliant: $non_compliant_count"
    echo "Missing (in current): $missing_count"
    echo "Extra (in current): $extra_count"

    # Output details of missing and extra rules
    if [[ $missing_count -gt 0 ]]; then
        echo -e "\nMissing Rules:"
        printf "  %s\n" "${missing_rules[@]}"
    fi

    if [[ $extra_count -gt 0 ]]; then
        echo -e "\nExtra Rules:"
        printf "  %s\n" "${extra_rules[@]}"
    fi

    # Return non-zero if issues found and strict mode is enabled
    if [[ $STRICT_MODE == "true" && ($non_compliant_count -gt 0 || $missing_count -gt 0) ]]; then
        return 1
    elif [[ $non_compliant_count -gt 0 && $missing_count -gt 0 ]]; then
        # In non-strict mode, return non-zero only if critical deviations exist
        return 1
    else
        return 0
    fi
}

# --- Report Generation ---
generate_report_header() {
    log_debug "Generating report header for format: $OUTPUT_FORMAT"
    case "$OUTPUT_FORMAT" in
        text)
            echo "Firewall Check Report - $(date)" > "$REPORT_FILE"
            echo "========================================" >> "$REPORT_FILE"
            echo "Firewall Type: $FIREWALL_TYPE" >> "$REPORT_FILE"
            echo "Hostname: $(hostname)" >> "$REPORT_FILE"
            echo "Date: $(date)" >> "$REPORT_FILE"
            if [[ "$COMPARE_POLICY" == "true" ]]; then
                echo "Policy File: $POLICY_FILE" >> "$REPORT_FILE"
            fi
            echo "----------------------------------------" >> "$REPORT_FILE"
            ;;
        json)
            echo "{" > "$REPORT_FILE"
            echo "  \"report_metadata\": {" >> "$REPORT_FILE"
            echo "    \"report_time\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$REPORT_FILE"
            echo "    \"firewall_type\": \"$FIREWALL_TYPE\"," >> "$REPORT_FILE"
            echo "    \"hostname\": \"$(hostname)\"," >> "$REPORT_FILE"
            if [[ "$COMPARE_POLICY" == "true" ]]; then
                echo "    \"policy_file\": \"$POLICY_FILE\"," >> "$REPORT_FILE"
            fi
            echo "    \"comparison_enabled\": $COMPARE_POLICY," >> "$REPORT_FILE"
            echo "    \"security_checks_enabled\": $INCLUDE_STANDARD_CHECKS" >> "$REPORT_FILE"
            echo "  }," >> "$REPORT_FILE"
            echo "  \"rules\": {" >> "$REPORT_FILE"
            echo "    \"current\": []," >> "$REPORT_FILE"
            if [[ "$COMPARE_POLICY" == "true" ]]; then
                 echo "    \"policy\": []," >> "$REPORT_FILE"
                 echo "    \"comparison_results\": {}" >> "$REPORT_FILE"
            fi
            echo "  }" >> "$REPORT_FILE" # Close rules object early, will modify later
            echo "}" >> "$REPORT_FILE" # Close main object early
            ;;
        csv)
            # CSV might be less suitable for detailed rule output, better for summary
            echo "CheckType,FirewallType,PolicyFile,Timestamp" > "$REPORT_FILE"
            echo "FirewallCheck,$FIREWALL_TYPE,${POLICY_FILE:-N/A},$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
            echo "RuleSource,RuleDetails" >> "$REPORT_FILE" # Header for rules
            ;;
    esac
}

add_current_rules_to_report() {
    local rules="$1"
    log_debug "Adding current rules to report"

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Current Firewall Rules:" >> "$REPORT_FILE"
            echo "-----------------------" >> "$REPORT_FILE"
            echo "$rules" >> "$REPORT_FILE"
            ;;
        json)
            # Use jq to safely add the rules array if available
            if command_exists jq; then
                local rules_json
                rules_json=$(echo "$rules" | jq -R . | jq -s .)
                jq ".rules.current = $rules_json" "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
            else
                # Fallback if jq is not available
                sed -i.bak 's/"current": \[\],/"current": ["RULES_PLACEHOLDER"],/' "$REPORT_FILE"
                sed -i.bak "s/\"RULES_PLACEHOLDER\"/$(echo "$rules" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g' | sed 's/\n/\\n/g')/" "$REPORT_FILE"
                rm -f "${REPORT_FILE}.bak"
            fi
            ;;
        csv)
            # Add each rule as a row
             while IFS= read -r rule; do
                 # Escape commas and quotes for CSV
                 local escaped_rule
                 escaped_rule=$(echo "$rule" | sed 's/"/""/g')
                 echo "Current,\"$escaped_rule\"" >> "$REPORT_FILE"
             done <<< "$rules"
            ;;
    esac
}

add_policy_rules_to_report() {
    local rules="$1"
    log_debug "Adding policy rules to report"

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Policy Firewall Rules:" >> "$REPORT_FILE"
            echo "----------------------" >> "$REPORT_FILE"
            echo "$rules" >> "$REPORT_FILE"
            ;;
        json)
            if command_exists jq; then
                local rules_json
                rules_json=$(echo "$rules" | jq -R . | jq -s .)
                jq ".rules.policy = $rules_json" "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
            else
                # Fallback if jq is not available
                sed -i.bak 's/"policy": \[\],/"policy": ["POLICY_PLACEHOLDER"],/' "$REPORT_FILE"
                sed -i.bak "s/\"POLICY_PLACEHOLDER\"/$(echo "$rules" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g' | sed 's/\n/\\n/g')/" "$REPORT_FILE"
                rm -f "${REPORT_FILE}.bak"
            fi
            ;;
        csv)
             while IFS= read -r rule; do
                 local escaped_rule
                 escaped_rule=$(echo "$rule" | sed 's/"/""/g')
                 echo "Policy,\"$escaped_rule\"" >> "$REPORT_FILE"
             done <<< "$rules"
            ;;
    esac
}

add_comparison_summary_to_report() {
    local summary="$1" # Expecting multi-line output from compare_rules
    log_debug "Adding comparison summary to report"

    local compliant=$(echo "$summary" | grep "Compliant:" | awk '{print $2}')
    local non_compliant=$(echo "$summary" | grep "Non-Compliant:" | awk '{print $2}')
    local missing=$(echo "$summary" | grep "Missing:" | awk '{print $3}')
    local extra=$(echo "$summary" | grep "Extra:" | awk '{print $3}')

    # Extract details of missing and extra rules if present
    local missing_rules=$(echo "$summary" | sed -n '/Missing Rules:/,/^$/p' | grep -v "^Missing Rules:")
    local extra_rules=$(echo "$summary" | sed -n '/Extra Rules:/,/^$/p' | grep -v "^Extra Rules:")

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Comparison Summary:" >> "$REPORT_FILE"
            echo "-------------------" >> "$REPORT_FILE"
            echo "$summary" >> "$REPORT_FILE"
            ;;
        json)
            if command_exists jq; then
                # Format missing and extra rules as JSON arrays
                local missing_json="[]"
                local extra_json="[]"

                if [[ -n "$missing_rules" ]]; then
                    missing_json=$(echo "$missing_rules" | sed 's/^ *//g' | jq -R . | jq -s .)
                fi

                if [[ -n "$extra_rules" ]]; then
                    extra_json=$(echo "$extra_rules" | sed 's/^ *//g' | jq -R . | jq -s .)
                fi

                local comparison_json="{\"compliant\": $compliant, \"non_compliant\": $non_compliant, \"missing\": $missing, \"extra\": $extra, \"missing_rules\": $missing_json, \"extra_rules\": $extra_json}"
                jq ".rules.comparison_results = $comparison_json" "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
            else
                # Basic fallback if jq is not available
                sed -i.bak 's/"comparison_results": {},/"comparison_results": {"compliant": COMPLIANT, "non_compliant": NON_COMPLIANT, "missing": MISSING, "extra": EXTRA},/' "$REPORT_FILE"
                sed -i.bak "s/COMPLIANT/$compliant/; s/NON_COMPLIANT/$non_compliant/; s/MISSING/$missing/; s/EXTRA/$extra/" "$REPORT_FILE"
                rm -f "${REPORT_FILE}.bak"
            fi
            ;;
        csv)
            echo "" >> "$REPORT_FILE"
            echo "ComparisonSummary,Compliant,NonCompliant,Missing,Extra" >> "$REPORT_FILE"
            echo "Summary,$compliant,$non_compliant,$missing,$extra" >> "$REPORT_FILE"

            # Add missing rules if any
            if [[ -n "$missing_rules" ]]; then
                echo "" >> "$REPORT_FILE"
                echo "MissingRules,Rule" >> "$REPORT_FILE"
                echo "$missing_rules" | while IFS= read -r rule; do
                    [[ -z "$rule" ]] && continue
                    rule=$(echo "$rule" | sed 's/^ *//')
                    echo "Missing,\"$rule\"" >> "$REPORT_FILE"
                done
            fi

            # Add extra rules if any
            if [[ -n "$extra_rules" ]]; then
                echo "" >> "$REPORT_FILE"
                echo "ExtraRules,Rule" >> "$REPORT_FILE"
                echo "$extra_rules" | while IFS= read -r rule; do
                    [[ -z "$rule" ]] && continue
                    rule=$(echo "$rule" | sed 's/^ *//')
                    echo "Extra,\"$rule\"" >> "$REPORT_FILE"
                done
            fi
            ;;
    esac
}

add_security_checks_to_report() {
    local check_results="$1"
    log_debug "Adding security checks to report"

    # Extract issues and warnings
    local issues=$(echo "$check_results" | grep "^ISSUES=" | cut -d= -f2)
    local warnings=$(echo "$check_results" | grep "^WARNINGS=" | cut -d= -f2)

    # Convert pipe-delimited string to array
    IFS='|' read -r -a issues_array <<< "$issues"
    IFS='|' read -r -a warnings_array <<< "$warnings"

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Security Check Results:" >> "$REPORT_FILE"
            echo "----------------------" >> "$REPORT_FILE"

            if [[ ${#issues_array[@]} -gt 0 ]]; then
                echo "" >> "$REPORT_FILE"
                echo "Issues:" >> "$REPORT_FILE"
                for issue in "${issues_array[@]}"; do
                    [[ -z "$issue" ]] && continue
                    echo "  - $issue" >> "$REPORT_FILE"
                done
            fi

            if [[ ${#warnings_array[@]} -gt 0 ]]; then
                echo "" >> "$REPORT_FILE"
                echo "Warnings:" >> "$REPORT_FILE"
                for warning in "${warnings_array[@]}"; do
                    [[ -z "$warning" ]] && continue
                    echo "  - $warning" >> "$REPORT_FILE"
                done
            fi

            if [[ ${#issues_array[@]} -eq 0 && ${#warnings_array[@]} -eq 0 ]]; then
                echo "No security issues found." >> "$REPORT_FILE"
            fi
            ;;
        json)
            if command_exists jq; then
                # Convert issues and warnings to JSON arrays
                local issues_json="[]"
                local warnings_json="[]"

                if [[ ${#issues_array[@]} -gt 0 ]]; then
                    issues_json=$(printf '%s\n' "${issues_array[@]}" | jq -R . | jq -s .)
                fi

                if [[ ${#warnings_array[@]} -gt 0 ]]; then
                    warnings_json=$(printf '%s\n' "${warnings_array[@]}" | jq -R . | jq -s .)
                fi

                # Add security checks section to JSON
                jq '. + {"security_checks": {"issues": ISSUES, "warnings": WARNINGS}}' \
                   --argjson ISSUES "$issues_json" \
                   --argjson WARNINGS "$warnings_json" \
                   "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
            else
                # Basic fallback if jq is not available
                sed -i.bak 's/}$/,"security_checks":{"issues":[],"warnings":[]}}/' "$REPORT_FILE"
                # This is a simplified approach - proper JSON creation without jq would need more careful handling
            fi
            ;;
        csv)
            echo "" >> "$REPORT_FILE"
            echo "SecurityCheck,Type,Description" >> "$REPORT_FILE"

            for issue in "${issues_array[@]}"; do
                [[ -z "$issue" ]] && continue
                echo "Security,Issue,\"$issue\"" >> "$REPORT_FILE"
            done

            for warning in "${warnings_array[@]}"; do
                [[ -z "$warning" ]] && continue
                echo "Security,Warning,\"$warning\"" >> "$REPORT_FILE"
            done
            ;;
    esac
}

add_security_gaps_to_report() {
    local gap_results="$1"
    log_debug "Adding security gaps analysis to report"

    # Extract gaps
    local gaps=$(echo "$gap_results" | grep "^GAPS=" | cut -d= -f2)

    # Convert pipe-delimited string to array
    IFS='|' read -r -a gaps_array <<< "$gaps"

    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "Security Gap Analysis:" >> "$REPORT_FILE"
            echo "---------------------" >> "$REPORT_FILE"

            if [[ ${#gaps_array[@]} -gt 0 ]]; then
                for gap in "${gaps_array[@]}"; do
                    [[ -z "$gap" ]] && continue
                    echo "  - $gap" >> "$REPORT_FILE"
                done
            else
                echo "No significant security gaps identified." >> "$REPORT_FILE"
            fi
            ;;
        json)
            if command_exists jq; then
                # Convert gaps to JSON array
                local gaps_json="[]"

                if [[ ${#gaps_array[@]} -gt 0 ]]; then
                    gaps_json=$(printf '%s\n' "${gaps_array[@]}" | jq -R . | jq -s .)
                fi

                # Add security gaps section to JSON
                jq '. + {"security_gaps": GAPS}' \
                   --argjson GAPS "$gaps_json" \
                   "$REPORT_FILE" > "$REPORT_FILE.tmp" && mv "$REPORT_FILE.tmp" "$REPORT_FILE"
            else
                # Basic fallback if jq is not available
                sed -i.bak 's/}$/,"security_gaps":[]}/' "$REPORT_FILE"
            fi
            ;;
        csv)
            echo "" >> "$REPORT_FILE"
            echo "SecurityGap,Description" >> "$REPORT_FILE"

            for gap in "${gaps_array[@]}"; do
                [[ -z "$gap" ]] && continue
                echo "Gap,\"$gap\"" >> "$REPORT_FILE"
            done
            ;;
    esac
}

generate_report_footer() {
    log_debug "Generating report footer for format: $OUTPUT_FORMAT"
    case "$OUTPUT_FORMAT" in
        text)
            echo "" >> "$REPORT_FILE"
            echo "----------------------------------------" >> "$REPORT_FILE"
            echo "Firewall Check Complete: $(date)" >> "$REPORT_FILE"
            echo "Report generated by: $(whoami)@$(hostname)" >> "$REPORT_FILE"
            ;;
        json)
            # No action needed for JSON - closing braces already added
            ;;
        csv)
            echo "" >> "$REPORT_FILE"
            echo "EndOfReport,$(date)" >> "$REPORT_FILE"
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
        log_info "Emailing report to $EMAIL_RECIPIENT"
        local subject="Firewall Check Report - $(hostname) - $(date)"

        # Check for different mail utilities
        if command_exists mail; then
            mail -s "$subject" "$EMAIL_RECIPIENT" < "$REPORT_FILE"
            log_info "Report emailed successfully using mail."
        elif command_exists sendmail; then
            (echo "Subject: $subject"; echo "To: $EMAIL_RECIPIENT"; echo ""; cat "$REPORT_FILE") | sendmail -t
            log_info "Report emailed successfully using sendmail."
        elif command_exists mutt; then
            echo | mutt -s "$subject" "$EMAIL_RECIPIENT" -a "$REPORT_FILE"
            log_info "Report emailed successfully using mutt."
        else
            log_error "No mail command found (mail, sendmail, mutt). Cannot email report."
            return 1
        fi
    fi
}

# --- Save Current Rules ---
save_current_rules() {
    local rules="$1"
    local path="$2"

    if [[ "$SAVE_CURRENT_RULES" == "true" && -n "$path" ]]; then
        log_info "Saving current firewall rules to $path"

        # Create directory if it doesn't exist
        mkdir -p "$(dirname "$path")"

        # Add header with metadata
        {
            echo "# Firewall rules exported by firewall_check.sh"
            echo "# Date: $(date)"
            echo "# Firewall Type: $FIREWALL_TYPE"
            echo "# Hostname: $(hostname)"
            echo "# User: $(whoami)"
            echo ""
            echo "$rules"
        } > "$path"

        log_info "Rules saved successfully to $path"
        return 0
    fi
}

# --- Main Logic ---
main() {
    log_info "Starting firewall check..."
    if [[ "$COMPARE_POLICY" == "true" ]]; then
        log_info "Policy comparison enabled using file: $POLICY_FILE"
    fi
    log_info "Report will be saved to: $REPORT_FILE"

    # Detect firewall type
    FIREWALL_TYPE=$(detect_firewall)
    if [[ "$FIREWALL_TYPE" == "none" ]]; then
        log_error "Could not determine firewall type or no firewall detected."
        # Still generate a basic report indicating no firewall
        generate_report_header # Generates header with type "none"

        # Add security issue for missing firewall
        if [[ "$INCLUDE_STANDARD_CHECKS" == "true" ]]; then
            add_security_checks_to_report "ISSUES=No firewall detected - system is unprotected|WARNINGS="
        fi

        generate_report_footer
        exit 1
    fi

    generate_report_header

    # Get current rules based on firewall type
    local current_rules=""
    case "$FIREWALL_TYPE" in
        iptables) current_rules=$(get_iptables_rules) ;;
        ufw) current_rules=$(get_ufw_rules) ;;
        firewalld) current_rules=$(get_firewalld_rules) ;;
        nftables) current_rules=$(get_nftables_rules) ;;
    esac

    if [[ -z "$current_rules" ]]; then
        log_error "Failed to retrieve current firewall rules."
        # Update report to indicate failure
        generate_report_footer # Add footer even on error
        exit 1
    fi

    # Save current rules if requested
    if [[ "$SAVE_CURRENT_RULES" == "true" ]]; then
        save_current_rules "$current_rules" "$EXPORT_PATH"
    fi

    # Add current rules to report
    add_current_rules_to_report "$current_rules"

    # Comparison logic
    local comparison_summary=""
    local comparison_status=0
    if [[ "$COMPARE_POLICY" == "true" ]]; then
        local policy_rules
        policy_rules=$(load_policy_rules "$POLICY_FILE" "$FIREWALL_TYPE")
        if [[ -z "$policy_rules" ]]; then
            log_error "Failed to load policy rules from $POLICY_FILE."
            comparison_status=1
        else
            add_policy_rules_to_report "$policy_rules"
            comparison_summary=$(compare_rules "$current_rules" "$policy_rules" "$FIREWALL_TYPE")
            comparison_status=$? # Get exit status of comparison
            add_comparison_summary_to_report "$comparison_summary"
            if [[ $comparison_status -ne 0 ]]; then
                 log_warn "Firewall configuration does not fully match the policy."
            else
                 log_info "Firewall configuration matches the policy."
            fi
        fi
    fi

    # Perform standard security checks if enabled
    local security_check_status=0
    if [[ "$INCLUDE_STANDARD_CHECKS" == "true" ]]; then
        local security_check_results
        security_check_results=$(perform_standard_security_checks "$FIREWALL_TYPE" "$current_rules")
        security_check_status=$?
        if [[ $security_check_status -ne 0 ]]; then
            log_warn "Security checks identified potential issues."
            add_security_checks_to_report "$security_check_results"
        else
            log_info "Security checks passed."
            add_security_checks_to_report "No security issues found."
        fi
    fi

    # Analyze security gaps if requested
    local gap_analysis_status=0
    if [[ "$ANALYZE_GAPS" == "true" ]]; then
        local gap_results
        gap_results=$(analyze_security_gaps "$FIREWALL_TYPE" "$current_rules")
        gap_analysis_status=$?
        if [[ $gap_analysis_status -ne 0 ]]; then
            log_warn "Security gap analysis identified potential improvements."
            add_security_gaps_to_report "$gap_results"
        else
            log_info "Security gap analysis complete, no significant gaps found."
            add_security_gaps_to_report "No significant security gaps identified."
        fi
    fi

    # Complete the report
    generate_report_footer

    log_info "Firewall check complete."
    log_info "Full report saved to: $REPORT_FILE"

    # Email the report if requested
    email_report || log_error "Failed to email report."

    # Determine exit code based on results
    local exit_code=0
    if [[ "$COMPARE_POLICY" == "true" && $comparison_status -ne 0 ]]; then
        exit_code=$((exit_code | 1))  # Policy comparison failed
    fi

    if [[ "$INCLUDE_STANDARD_CHECKS" == "true" && $security_check_status -ne 0 ]]; then
        exit_code=$((exit_code | 2))  # Security checks found issues
    fi

    if [[ "$ANALYZE_GAPS" == "true" && $gap_analysis_status -ne 0 ]]; then
        exit_code=$((exit_code | 4))  # Gap analysis found issues
    fi

    # Exit with appropriate status
    exit $exit_code
}

# --- Run Script ---
main "$@"
