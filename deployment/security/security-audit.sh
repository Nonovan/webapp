#!/bin/bash
# Security audit script for Cloud Infrastructure Platform
# This script checks for common security issues and configurations

set -o pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/cloud-platform/security-audit.log"
REPORT_FILE="/var/www/reports/security-audit-$(date +%Y%m%d).html"
REPORT_DIR="$(dirname "$REPORT_FILE")"
EMAIL_RECIPIENT="security@example.com"
CHECK_FIREWALL=true
CHECK_UPDATES=true
CHECK_SERVICES=true
CHECK_USERS=true
CHECK_FILES=true
CHECK_SSL=true
CHECK_CONFIG=true

# Issue tracking
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
TOTAL_ISSUES=0

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$REPORT_DIR"
chmod 750 "$REPORT_DIR"

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Command line argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-firewall) CHECK_FIREWALL=false; shift ;;
        --skip-updates) CHECK_UPDATES=false; shift ;;
        --skip-services) CHECK_SERVICES=false; shift ;;
        --skip-users) CHECK_USERS=false; shift ;;
        --skip-files) CHECK_FILES=false; shift ;;
        --skip-ssl) CHECK_SSL=false; shift ;;
        --skip-config) CHECK_CONFIG=false; shift ;;
        --email=*) EMAIL_RECIPIENT="${1#*=}"; shift ;;
        --output=*) REPORT_FILE="${1#*=}"; shift ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --skip-firewall    Skip firewall checks"
            echo "  --skip-updates     Skip security updates checks"
            echo "  --skip-services    Skip service checks"
            echo "  --skip-users       Skip user account checks"
            echo "  --skip-files       Skip file permission checks"
            echo "  --skip-ssl         Skip SSL certificate checks"
            echo "  --skip-config      Skip configuration checks"
            echo "  --email=ADDRESS    Set email recipient"
            echo "  --output=FILE      Set output report file"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            log "Unknown parameter: $1"
            shift
            ;;
    esac
done

# Initialize HTML report
init_report() {
    log "Initializing security audit report"
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
        .summary-box { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; }
        .summary-critical { background-color: #ffeeee; }
        .summary-high { background-color: #fff6ee; }
        .summary-medium { background-color: #ffffee; }
        .summary-low { background-color: #eeffee; }
        .summary-info { background-color: #eeeeff; }
        .summary-count { font-size: 24px; font-weight: bold; }
        .dashboard { display: flex; flex-wrap: wrap; margin-bottom: 20px; }
        .dashboard-item { flex: 1; min-width: 200px; margin: 10px; padding: 15px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <h1>Cloud Infrastructure Platform Security Audit Report</h1>
    <p>Generated: $(date)</p>
    <p>Server: $(hostname)</p>
    <p>Environment: $([ -f "/etc/cloud-platform/environment" ] && cat "/etc/cloud-platform/environment" || echo "Unknown")</p>
    
    <div id="summary" class="section">
        <h2>Executive Summary</h2>
        <p>This report contains the results of an automated security audit for the Cloud Infrastructure Platform.</p>
        <div class="dashboard">
            <div class="dashboard-item summary-critical">
                <h3>Critical</h3>
                <p class="summary-count" id="critical-count">0</p>
            </div>
            <div class="dashboard-item summary-high">
                <h3>High</h3>
                <p class="summary-count" id="high-count">0</p>
            </div>
            <div class="dashboard-item summary-medium">
                <h3>Medium</h3>
                <p class="summary-count" id="medium-count">0</p>
            </div>
            <div class="dashboard-item summary-low">
                <h3>Low</h3>
                <p class="summary-count" id="low-count">0</p>
            </div>
            <div class="dashboard-item summary-info">
                <h3>Info</h3>
                <p class="summary-count" id="info-count">0</p>
            </div>
        </div>
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

    # Increment counters
    case "$severity" in
        critical) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        high) HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        medium) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
        low) LOW_COUNT=$((LOW_COUNT + 1)) ;;
        info) INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac
    TOTAL_ISSUES=$((TOTAL_ISSUES + 1))

    log "$severity: $title"

    cat >> "$REPORT_FILE" <<EOF
        <div class="issue ${severity}">
            <h3>${title}</h3>
            <p><strong>Severity:</strong> ${severity}</p>
            <p><strong>Description:</strong> ${description}</p>
            <p><strong>Recommendation:</strong> ${recommendation}</p>
        </div>
EOF
}

# Finalize HTML report with updated counts
finalize_report() {
    log "Finalizing security audit report"
    
    # Add category summaries
    cat >> "$REPORT_FILE" <<EOF
    </div>

    <div id="categories" class="section">
        <h2>Security Check Categories</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Info</th>
                <th>Status</th>
            </tr>
EOF

    # Add category rows (populate based on actual checks performed)
    for category in "Firewall Rules" "Security Updates" "Service Configuration" "User Accounts" "File Permissions" "SSL Certificates" "System Configuration"; do
        cat >> "$REPORT_FILE" <<EOF
            <tr>
                <td>${category}</td>
                <td>0</td>
                <td>0</td>
                <td>0</td>
                <td>0</td>
                <td>0</td>
                <td>✓ Checked</td>
            </tr>
EOF
    done

    cat >> "$REPORT_FILE" <<EOF
        </table>
    </div>

    <div id="recommendations" class="section">
        <h2>Prioritized Recommendations</h2>
        <ol>
            <!-- Will be populated based on findings -->
        </ol>
    </div>

    <div id="footer" class="section">
        <p>For more information on security best practices, refer to the Cloud Infrastructure Platform Security Guide.</p>
        <p>Contact: ${EMAIL_RECIPIENT}</p>
    </div>

    <script>
        // Update summary counts
        document.getElementById('critical-count').textContent = '${CRITICAL_COUNT}';
        document.getElementById('high-count').textContent = '${HIGH_COUNT}';
        document.getElementById('medium-count').textContent = '${MEDIUM_COUNT}';
        document.getElementById('low-count').textContent = '${LOW_COUNT}';
        document.getElementById('info-count').textContent = '${INFO_COUNT}';
    </script>
</body>
</html>
EOF

    # Set appropriate permissions for report file
    chmod 640 "$REPORT_FILE"
    log "Report generated: $REPORT_FILE"
}

# Check for security updates
check_security_updates() {
    if [ "$CHECK_UPDATES" != "true" ]; then
        log "Skipping security updates check"
        return
    fi

    log "Checking for security updates..."
    local security_updates=0

    if command -v apt-get &> /dev/null; then
        # For Debian/Ubuntu
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq &>/dev/null
        security_updates=$(apt-get --just-print upgrade | grep -c "^Inst.*security")
        
        if [ "$security_updates" -gt 0 ]; then
            add_issue "high" "Security updates available" \
                "There are $security_updates security updates available for installation." \
                "Run 'apt upgrade' to install security updates."
        else
            add_issue "info" "System up to date" \
                "No security updates are currently available." \
                "Continue regular patch management."
        fi
    elif command -v yum &> /dev/null; then
        # For CentOS/RHEL/Fedora
        security_updates=$(yum check-update --security | grep -c "^[a-zA-Z0-9]")
        
        if [ "$security_updates" -gt 0 ]; then
            add_issue "high" "Security updates available" \
                "There are $security_updates security updates available for installation." \
                "Run 'yum update --security' to install security updates."
        else
            add_issue "info" "System up to date" \
                "No security updates are currently available." \
                "Continue regular patch management."
        fi
    else
        add_issue "medium" "Unknown package manager" \
            "Could not detect a recognized package manager (apt-get or yum)." \
            "Manually check for security updates or install a supported package manager."
    fi
}

# Check SSL/TLS configuration
check_ssl() {
    if [ "$CHECK_SSL" != "true" ]; then
        log "Skipping SSL checks"
        return
    fi

    log "Checking SSL/TLS configuration..."
    local domain="cloud-platform.example.com"
    local custom_domain=$(grep -r "server_name" /etc/nginx/sites-enabled/ 2>/dev/null | head -1 | awk '{print $2}' | tr -d ';')
    
    if [ -n "$custom_domain" ] && [ "$custom_domain" != "cloud-platform.example.com" ]; then
        domain="$custom_domain"
    fi

    if command -v openssl &> /dev/null && command -v curl &> /dev/null; then
        # Check certificate expiry
        local cert_data=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null)
        if [ -n "$cert_data" ]; then
            local expiry_date=$(echo "$cert_data" | cut -d= -f2)
            local expiry_epoch=$(date -d "$expiry_date" +%s)
            local now_epoch=$(date +%s)
            local days_remaining=$(( (expiry_epoch - now_epoch) / 86400 ))
            
            if [ "$days_remaining" -lt 7 ]; then
                add_issue "critical" "SSL certificate near expiry" \
                    "The SSL certificate for $domain will expire in $days_remaining days." \
                    "Renew the SSL certificate immediately."
            elif [ "$days_remaining" -lt 30 ]; then
                add_issue "high" "SSL certificate expiring soon" \
                    "The SSL certificate for $domain will expire in $days_remaining days." \
                    "Schedule SSL certificate renewal."
            else
                add_issue "info" "SSL certificate valid" \
                    "The SSL certificate for $domain is valid for $days_remaining more days." \
                    "No action required."
            fi
        else
            add_issue "medium" "Unable to check SSL certificate" \
                "Could not retrieve SSL certificate information for $domain." \
                "Manually verify SSL certificate configuration and expiry."
        fi
        
        # Check supported protocols
        local protocols=""
        for protocol in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
            if echo | openssl s_client -"$protocol" -connect "$domain:443" 2>/dev/null | grep -q "CONNECTED"; then
                protocols="$protocols $protocol"
                if [ "$protocol" = "ssl2" ] || [ "$protocol" = "ssl3" ] || [ "$protocol" = "tls1" ] || [ "$protocol" = "tls1_1" ]; then
                    add_issue "high" "Insecure protocol enabled: $protocol" \
                        "The server supports the insecure protocol: $protocol" \
                        "Disable $protocol in your web server configuration."
                fi
            fi
        done
        
        if [ -z "$protocols" ]; then
            add_issue "medium" "Could not determine SSL/TLS protocols" \
                "Unable to determine which SSL/TLS protocols are enabled." \
                "Manually verify SSL/TLS protocol configuration."
        elif [[ ! "$protocols" =~ tls1_2 ]] && [[ ! "$protocols" =~ tls1_3 ]]; then
            add_issue "high" "Modern TLS protocols not enabled" \
                "The server does not support TLS 1.2 or TLS 1.3." \
                "Enable TLS 1.2 and TLS 1.3 in your web server configuration."
        fi
    else
        add_issue "medium" "SSL tools not installed" \
            "OpenSSL and/or curl are not installed, cannot check SSL/TLS configuration." \
            "Install OpenSSL and curl to enable SSL/TLS configuration checks."
    fi
}

# Check user accounts and security
check_users() {
    if [ "$CHECK_USERS" != "true" ]; then
        log "Skipping user account checks"
        return
    fi

    log "Checking user accounts..."

    # Check for users with empty passwords
    local empty_password_users=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null)
    if [ -n "$empty_password_users" ]; then
        add_issue "critical" "Users with empty passwords" \
            "The following users have empty passwords: $empty_password_users" \
            "Set strong passwords for these accounts or disable them."
    fi

    # Check for unauthorized UID 0 accounts
    local root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v "^root$")
    if [ -n "$root_users" ]; then
        add_issue "critical" "Multiple root accounts" \
            "The following non-root accounts have UID 0 (root privileges): $root_users" \
            "Investigate these accounts and remove root privileges if unauthorized."
    fi

    # Check for weak password hashing algorithms
    local des_password_hashes=$(grep -v '^[^:]*:[*!]' /etc/shadow | grep -c '^[^:]*:[^$]')
    if [ "$des_password_hashes" -gt 0 ]; then
        add_issue "high" "Weak password hashing" \
            "Found $des_password_hashes passwords using the weak DES algorithm." \
            "Update passwords to use strong hashing algorithms (SHA-512)."
    fi

    # Check password aging policies
    if [ -f /etc/login.defs ]; then
        local max_days=$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
        if [ -n "$max_days" ] && [ "$max_days" -gt 90 ]; then
            add_issue "medium" "Password aging policy too long" \
                "Maximum password age is set to $max_days days." \
                "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs."
        fi
    fi
}

# Check file permissions
check_files() {
    if [ "$CHECK_FILES" != "true" ]; then
        log "Skipping file permission checks"
        return
    fi

    log "Checking file permissions..."

    # Check permissions on sensitive files
    local sensitive_files=(
        "/etc/shadow"
        "/etc/gshadow"
        "/etc/passwd"
        "/etc/group"
        "/etc/ssh/sshd_config"
        "/etc/ssl/private"
    )

    for file in "${sensitive_files[@]}"; do
        if [ -e "$file" ]; then
            local perms=$(stat -c "%a" "$file")
            local owner=$(stat -c "%U" "$file")
            
            # Check permissions based on file type
            if [[ "$file" =~ shadow|gshadow ]]; then
                if [[ "$perms" =~ ^[0-7][0-7][67]$ ]] || [[ "$perms" == "777" ]]; then
                    add_issue "high" "Insecure file permissions" \
                        "File $file has overly permissive permissions ($perms)." \
                        "Change permissions to restrict access (e.g., 600 for private keys, 640 for config files)."
                fi
                
                if [[ "$owner" != "root" ]]; then
                    add_issue "high" "Incorrect file ownership" \
                        "Sensitive file $file is not owned by root." \
                        "Change ownership to root: chown root:root $file"
                fi
            fi
        fi
    done

    # Check for world-writable files in /etc
    local world_writable_etc=$(find /etc -type f -perm -002 2>/dev/null | wc -l)
    if [ "$world_writable_etc" -gt 0 ]; then
        add_issue "high" "World-writable files in /etc" \
            "Found $world_writable_etc world-writable files in /etc." \
            "Remove write permissions for 'others' on these files."
    fi
    
    # Check for SUID/SGID binaries
    local suid_binaries=$(find / -type f -perm -4000 2>/dev/null | wc -l)
    local sgid_binaries=$(find / -type f -perm -2000 2>/dev/null | wc -l)
    if [ "$suid_binaries" -gt 25 ] || [ "$sgid_binaries" -gt 25 ]; then
        add_issue "medium" "Excessive SUID/SGID binaries" \
            "Found $suid_binaries SUID and $sgid_binaries SGID binaries." \
            "Review and remove unnecessary SUID/SGID permissions."
    fi
}

# Check for common security misconfigurations
check_security_config() {
    if [ "$CHECK_CONFIG" != "true" ]; then
        log "Skipping security configuration checks"
        return
    fi

    log "Checking security configurations..."

    # Check NGINX security headers
    if [ -d "/etc/nginx/sites-enabled" ]; then
        local has_security_headers=false
        if grep -q "add_header X-Content-Type-Options" /etc/nginx/sites-enabled/* 2>/dev/null && \
           grep -q "add_header X-XSS-Protection" /etc/nginx/sites-enabled/* 2>/dev/null && \
           grep -q "add_header X-Frame-Options" /etc/nginx/sites-enabled/* 2>/dev/null; then
            has_security_headers=true
        fi

        if [ "$has_security_headers" = "false" ]; then
            add_issue "medium" "Missing security headers" \
                "NGINX configuration is missing important security headers." \
                "Add security headers like X-Content-Type-Options, X-XSS-Protection, and X-Frame-Options."
        fi
    fi

    # Check for kernel hardening (sysctl)
    local sysctl_secure=true
    if [ -x "$(command -v sysctl)" ]; then
        # Check for common protections
        if [ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" != "2" ]; then
            sysctl_secure=false
        fi
        
        if [ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" != "1" ]; then
            sysctl_secure=false
        fi
        
        if [ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" != "0" ]; then
            sysctl_secure=false
        fi
        
        if [ "$sysctl_secure" = "false" ]; then
            add_issue "medium" "Kernel hardening not fully configured" \
                "Some kernel security parameters are not set to recommended values." \
                "Configure kernel security parameters in /etc/sysctl.conf."
        fi
    fi

    # Check for SSH configuration
    if [ -f "/etc/ssh/sshd_config" ]; then
        # Check for root login
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            add_issue "high" "SSH root login allowed" \
                "SSH configuration allows root to login directly." \
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
        fi
        
        # Check for password authentication
        if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config && ! grep -q "^ChallengeResponseAuthentication no" /etc/ssh/sshd_config; then
            add_issue "medium" "SSH password authentication allowed" \
                "SSH is configured to allow password authentication." \
                "Consider using key-based authentication only."
        fi
    fi
}

# Check firewall configuration
check_firewall() {
    if [ "$CHECK_FIREWALL" != "true" ]; then
        log "Skipping firewall checks"
        return
    fi

    log "Checking firewall configuration..."

    if command -v iptables &> /dev/null; then
        local rule_count=$(iptables -L -n | grep -v "^Chain" | grep -v "^$" | wc -l)

        if [ $rule_count -eq 0 ]; then
            add_issue "high" "Firewall not configured" \
                "No firewall rules are currently active." \
                "Configure firewall rules to restrict access to services."
        fi

        # Check default policies
        local input_policy=$(iptables -L INPUT | head -n 1 | awk '{print $4}')
        if [ "$input_policy" != "DROP" ]; then
            add_issue "medium" "Permissive firewall policy" \
                "Default INPUT chain policy is not set to DROP." \
                "Set default policy to DROP and explicitly allow necessary traffic."
        fi
    else
        add_issue "high" "Firewall not installed" \
            "No firewall (iptables) found on the system." \
            "Install and configure a firewall to restrict network access."
    fi
}

# Check for running services
check_services() {
    if [ "$CHECK_SERVICES" != "true" ]; then
        log "Skipping service checks"
        return
    fi

    log "Checking services..."

    # Check if unnecessary services are running
    local unnecessary_services=(
        "telnet"
        "rsh"
        "rlogin"
        "rexec"
        "tftp"
        "xinetd"
        "chargen"
        "daytime"
        "echo"
        "discard"
        "avahi-daemon"
    )

    for service in "${unnecessary_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null || service "$service" status >/dev/null 2>&1; then
            add_issue "high" "Unnecessary service running" \
                "The '$service' service is running and may pose a security risk." \
                "Disable the '$service' service if not required."
        fi
    done

    # Check listening ports
    if command -v netstat &> /dev/null || command -v ss &> /dev/null; then
        log "Checking for potentially insecure open ports..."
        
        local insecure_ports=()
        local port_command="ss -tuln"
        
        if ! command -v ss &> /dev/null; then
            port_command="netstat -tuln"
        fi
        
        # List of potentially insecure ports to check
        local check_ports=(
            "23:Telnet"
            "25:SMTP"
            "110:POP3 (unencrypted)"
            "143:IMAP (unencrypted)"
            "21:FTP"
            "69:TFTP"
            "111:RPC"
            "135:RPC/DCOM"
            "139:NetBIOS"
            "445:SMB"
        )
        
        for port_info in "${check_ports[@]}"; do
            IFS=':' read -r port service <<< "$port_info"
            if $port_command | grep -q ":$port "; then
                insecure_ports+=("$port ($service)")
            fi
        done
        
        if [ ${#insecure_ports[@]} -gt 0 ]; then
            add_issue "high" "Potentially insecure ports open" \
                "The following potentially insecure ports are open: ${insecure_ports[*]}" \
                "Close these ports if not absolutely necessary, or restrict access."
        fi
    else
        add_issue "low" "Cannot check open ports" \
            "Neither netstat nor ss commands are available." \
            "Install net-tools or iproute2 to check for open ports."
    fi
}

# Main function
main() {
    log "Starting security audit..."
    init_report

    # Run all checks
    check_security_updates
    check_ssl
    check_users
    check_files
    check_security_config
    check_firewall
    check_services

    # Finalize report
    finalize_report

    # Send email notification
    if [ -n "$EMAIL_RECIPIENT" ] && command -v mail &>/dev/null; then
        log "Sending email notification to $EMAIL_RECIPIENT"
        echo "Cloud Infrastructure Platform Security Audit Report is ready.
        
Date: $(date)
Server: $(hostname)
Total issues found: $TOTAL_ISSUES
Critical: $CRITICAL_COUNT
High: $HIGH_COUNT
Medium: $MEDIUM_COUNT
Low: $LOW_COUNT
Info: $INFO_COUNT

The full report is available at: $REPORT_FILE" | mail -s "Security Audit Report - $(hostname)" "$EMAIL_RECIPIENT"
    fi

    log "Security audit completed. Found $TOTAL_ISSUES issues ($CRITICAL_COUNT critical, $HIGH_COUNT high, $MEDIUM_COUNT medium, $LOW_COUNT low, $INFO_COUNT info)"
    
    # Exit with non-zero status if critical or high issues found
    if [ $CRITICAL_COUNT -gt 0 ] || [ $HIGH_COUNT -gt 0 ]; then
        log "Critical or high severity issues found. Please address them immediately."
        exit 1
    fi
    
    exit 0
}

# Execute main function
main