#!/bin/bash
# Security audit script for Cloud Infrastructure Platform
# This script checks for common security issues and configurations

# Configuration
LOG_FILE="/var/log/cloud-platform/security-audit.log"
REPORT_FILE="/var/www/reports/security-audit-$(date +%Y%m%d).html"
EMAIL_RECIPIENT="security@example.com"

# Ensure log directory exists
mkdir -p $(dirname "$LOG_FILE")
mkdir -p $(dirname "$REPORT_FILE")

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Initialize HTML report
init_report() {
    cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .section { margin-bottom: 30px; }
        .issue { margin: 10px 0; padding: 10px; border-left: 4px solid; }
        .critical { border-color: #ff0000; background-color: #ffeeee; }
        .high { border-color: #ff6600; background-color: #fff6ee; }
        .medium { border-color: #ffcc00; background-color: #ffffee; }
        .low { border-color: #00cc00; background-color: #eeffee; }
        .info { border-color: #0066cc; background-color: #eeeeff; }
        table { border-collapse: collapse; width: 100%; }
        th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Cloud Infrastructure Platform Security Audit Report</h1>
    <p>Generated: $(date)</p>
    <p>Server: $(hostname)</p>
    <div id="summary" class="section">
        <h2>Executive Summary</h2>
        <p>This report contains the results of an automated security audit for the Cloud Infrastructure Platform.</p>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>Critical</td>
                <td id="critical-count">0</td>
            </tr>
            <tr>
                <td>High</td>
                <td id="high-count">0</td>
            </tr>
            <tr>
                <td>Medium</td>
                <td id="medium-count">0</td>
            </tr>
            <tr>
                <td>Low</td>
                <td id="low-count">0</td>
            </tr>
            <tr>
                <td>Info</td>
                <td id="info-count">0</td>
            </tr>
        </table>
    </div>
    <div id="findings" class="section">
        <h2>Detailed Findings</h2>
EOF
}

# Add issue to HTML report
add_issue() {
    local severity="$1"
    local title="$2"
    local description="$3"
    local recommendation="$4"

    cat >> "$REPORT_FILE" <<EOF
        <div class="issue ${severity}">
            <h3>${title}</h3>
            <p><strong>Severity:</strong> ${severity}</p>
            <p><strong>Description:</strong> ${description}</p>
            <p><strong>Recommendation:</strong> ${recommendation}</p>
        </div>
EOF

    # Update count
    local count_id="${severity}-count"
    local current_count=$(grep -o "id=\\"${count_id}\\">.*<" "$REPORT_FILE" | sed -E "s/id=\\"${count_id}\\">(.*)</\\1/")
    local new_count=$((current_count + 1))
    sed -i "s/id=\\"${count_id}\\">${current_count}</id=\\"${count_id}\\">${new_count}</" "$REPORT_FILE"
}

# Finalize HTML report
finalize_report() {
    cat >> "$REPORT_FILE" <<EOF
    </div>
    <div class="section">
        <h2>System Information</h2>
        <p><strong>Kernel:</strong> $(uname -a)</p>
        <p><strong>OS:</strong> $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d= -f2 | tr -d '"')</p>
        <p><strong>Audit Date:</strong> $(date)</p>
    </div>
</body>
</html>
EOF
}

# Send email with report
send_report() {
    if command -v mail &> /dev/null; then
        log "Sending report via email to $EMAIL_RECIPIENT"
        echo "Cloud Infrastructure Platform Security Audit Report - $(date +%Y-%m-%d)" | mail -s "Security Audit Report" -a "$REPORT_FILE" "$EMAIL_RECIPIENT"
    else
        log "Mail command not found. Report available at $REPORT_FILE"
    fi
}

# Check OS version and patches
check_os() {
    log "Checking OS version and security patches..."
    local os_version=$(cat /etc/os-release | grep "PRETTY_NAME" | cut -d= -f2 | tr -d '"')
    local kernel_version=$(uname -r)

    echo "OS Version: $os_version" >> "$LOG_FILE"
    echo "Kernel Version: $kernel_version" >> "$LOG_FILE"

    # Check for available security updates
    if command -v apt &> /dev/null; then
        apt update -qq > /dev/null
        local security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)

        if [ $security_updates -gt 0 ]; then
            add_issue "high" "Security updates available" \\
                "There are $security_updates security updates available for installation." \\
                "Run 'apt upgrade' to install security updates."
        else
            add_issue "info" "System up to date" \\
                "No security updates are currently available." \\
                "Continue regular patch management."
        fi
    fi
}

# Check SSL/TLS configuration
check_ssl() {
    log "Checking SSL/TLS configuration..."
    local domain="cloud-platform.example.com"

    if command -v openssl &> /dev/null && command -v curl &> /dev/null; then
        # Check certificate expiry
        local cert_data=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null)
        if [ -n "$cert_data" ]; then
            local expiry_date=$(echo "$cert_data" | cut -d= -f2)
            local expiry_epoch=$(date -d "$expiry_date" +%s)
            local now_epoch=$(date +%s)
            local days_left=$(( ($expiry_epoch - $now_epoch) / 86400 ))

            if [ $days_left -lt 7 ]; then
                add_issue "critical" "SSL certificate expiring soon" \\
                    "The SSL certificate for $domain will expire in $days_left days." \\
                    "Renew the SSL certificate immediately."
            elif [ $days_left -lt 30 ]; then
                add_issue "high" "SSL certificate expiring soon" \\
                    "The SSL certificate for $domain will expire in $days_left days." \\
                    "Plan to renew the SSL certificate within the next week."
            else
                add_issue "info" "SSL certificate valid" \\
                    "The SSL certificate for $domain is valid for $days_left more days." \\
                    "No action required."
            fi
        fi

        # Check TLS protocols
        local protocols=$(curl --insecure -v <https://$domain> 2>&1 | grep "TLSv" | sed 's/.*TLSv/TLSv/')
        if [[ "$protocols" == *"TLSv1.0"* ]] || [[ "$protocols" == *"TLSv1.1"* ]]; then
            add_issue "high" "Insecure TLS protocol versions enabled" \\
                "Server supports deprecated TLS protocols (TLSv1.0/1.1)." \\
                "Configure the server to support only TLSv1.2 and TLSv1.3."
        fi
    fi
}

# Check file permissions
check_permissions() {
    log "Checking file permissions..."

    # Check sensitive configuration files
    local files_to_check=(
        "/etc/nginx/nginx.conf"
        "/etc/cloud-platform/config.ini"
        "/etc/ssl/private/cloud-platform.key"
        "/var/www/.env"
    )

    for file in "${files_to_check[@]}"; do
        if [ -f "$file" ]; then
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")

            # Check for overly permissive settings
            if [[ "$perms" =~ ^[0-7][0-7][67]$ ]] || [[ "$perms" == "777" ]]; then
                add_issue "high" "Insecure file permissions" \\
                    "File $file has overly permissive permissions ($perms)." \\
                    "Change permissions to restrict access (e.g., 600 for private keys, 640 for config files)."
            fi

            # Check ownership
            if [[ "$file" == *"/etc/ssl/private/"* ]] && [[ "$owner" != "root" ]]; then
                add_issue "medium" "Incorrect file ownership" \\
                    "Private key $file is not owned by root." \\
                    "Change ownership to root: chown root:root $file"
            fi
        fi
    done
}

# Check for common security misconfigurations
check_security_config() {
    log "Checking security configurations..."

    # Check NGINX security headers
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        local has_security_headers=false

        if grep -q "Strict-Transport-Security" "/etc/nginx/sites-enabled/default"; then
            has_security_headers=true
        fi

        if [ "$has_security_headers" = false ]; then
            add_issue "medium" "Missing security headers in NGINX" \\
                "NGINX configuration is missing important security headers." \\
                "Add security headers like HSTS, CSP, X-Content-Type-Options, etc."
        fi
    fi

    # Check for ModSecurity
    if ! [ -f "/etc/nginx/modsecurity/modsecurity.conf" ]; then
        add_issue "medium" "ModSecurity not installed" \\
            "ModSecurity WAF is not installed or configured." \\
            "Install and configure ModSecurity with OWASP Core Rule Set."
    fi
}

# Check firewall rules
check_firewall() {
    log "Checking firewall rules..."

    if command -v iptables &> /dev/null; then
        # Check if firewall is enabled
        local rule_count=$(iptables -L -n | grep -v "^Chain" | grep -v "^$" | wc -l)

        if [ $rule_count -eq 0 ]; then
            add_issue "high" "Firewall not configured" \\
                "No firewall rules are currently active." \\
                "Configure firewall rules to restrict access to services."
        fi

        # Check default policies
        local input_policy=$(iptables -L INPUT | head -n 1 | awk '{print $4}')
        if [ "$input_policy" != "DROP" ]; then
            add_issue "medium" "Permissive firewall policy" \\
                "Default INPUT chain policy is not set to DROP." \\
                "Set default policy to DROP and explicitly allow necessary traffic."
        fi
    else
        add_issue "high" "Firewall not installed" \\
            "No firewall (iptables) found on the system." \\
            "Install and configure a firewall to restrict network access."
    fi
}

# Main function
main() {
    log "Starting security audit..."
    init_report

    # Run all checks
    check_os
    check_ssl
    check_permissions
    check_security_config
    check_firewall

    finalize_report
    log "Security audit completed. Report generated at $REPORT_FILE"
    send_report
}

# Execute main function
main
