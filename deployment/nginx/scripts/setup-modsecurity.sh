#!/bin/bash
# ModSecurity WAF Setup for Cloud Infrastructure Platform
# Usage: ./setup-modsecurity.sh [--enable|--disable] [--rules-update]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
MODSEC_DIR="/etc/nginx/modsecurity"
MODSEC_RULES_DIR="/etc/nginx/modsecurity.d"
WAF_RULES_DIR="${MODSEC_RULES_DIR}/waf-rules"
CRS_DIR="${MODSEC_RULES_DIR}/coreruleset"
CRS_VERSION="3.3.5"
ENABLE=false
DISABLE=false
UPDATE_RULES=false
LOG_FILE="/var/log/cloud-platform/modsecurity-setup.log"
BACKUP_DIR="/var/backups/nginx-modsec"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] $1"
    if [ -n "$LOG_FILE" ]; then
        echo "[$timestamp] $1" >> "$LOG_FILE"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --enable)
            ENABLE=true
            shift
            ;;
        --disable)
            DISABLE=true
            shift
            ;;
        --rules-update)
            UPDATE_RULES=true
            shift
            ;;
        --crs-version)
            CRS_VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "ModSecurity WAF Setup for Cloud Infrastructure Platform"
            echo
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --enable          Enable ModSecurity WAF"
            echo "  --disable         Disable ModSecurity WAF"
            echo "  --rules-update    Update OWASP Core Rule Set and custom rules"
            echo "  --crs-version     Specify OWASP CRS version (default: 3.3.5)"
            echo "  --help, -h        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check for mutually exclusive options
if [[ "$ENABLE" == "true" && "$DISABLE" == "true" ]]; then
    log "${RED}ERROR: Cannot specify both --enable and --disable options${NC}"
    exit 1
fi

# Create directories if they don't exist
mkdir -p $(dirname "$LOG_FILE")
mkdir -p "$BACKUP_DIR"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log "${RED}ERROR: This script must be run as root${NC}"
    exit 1
fi

# Check for required tools
log "Checking for required tools..."
for cmd in curl unzip nginx; do
    if ! command -v $cmd &>/dev/null; then
        log "${RED}ERROR: Required command '$cmd' not found${NC}"
        exit 1
    fi
done

# Check if NGINX has ModSecurity enabled
check_modsec_installed() {
    if nginx -V 2>&1 | grep -q "ModSecurity"; then
        return 0  # ModSecurity is installed
    else
        return 1  # ModSecurity is not installed
    fi
}

# Check if ModSecurity is enabled in NGINX config
check_modsec_enabled() {
    if grep -q "modsecurity on" $(find "$NGINX_ROOT" -type f -name "*.conf" 2>/dev/null) 2>/dev/null; then
        return 0  # ModSecurity is enabled
    else
        return 1  # ModSecurity is not enabled
    fi
}

# Function to create backup
backup_configs() {
    log "Backing up existing ModSecurity configurations..."
    local timestamp=$(date "+%Y%m%d%H%M%S")
    local backup_file="${BACKUP_DIR}/modsec-backup-${timestamp}.tar.gz"
    
    if [ -d "$MODSEC_DIR" ]; then
        tar -czf "$backup_file" -C "$(dirname "$MODSEC_DIR")" "$(basename "$MODSEC_DIR")"
        log "${GREEN}✓ Backup created at $backup_file${NC}"
    else
        log "${YELLOW}⚠ No existing ModSecurity directory to backup${NC}"
    fi
    
    # Also backup rules directory if it exists
    if [ -d "$MODSEC_RULES_DIR" ]; then
        local rules_backup="${BACKUP_DIR}/modsec-rules-${timestamp}.tar.gz"
        tar -czf "$rules_backup" -C "$(dirname "$MODSEC_RULES_DIR")" "$(basename "$MODSEC_RULES_DIR")"
        log "${GREEN}✓ Rules backup created at $rules_backup${NC}"
    fi
}

# Function to download and install OWASP CRS
install_owasp_crs() {
    log "${BLUE}Installing OWASP ModSecurity Core Rule Set ${CRS_VERSION}...${NC}"
    
    # Create backup of existing rules
    if [ -d "$CRS_DIR" ]; then
        local backup_file="${BACKUP_DIR}/crs-backup-$(date +%Y%m%d%H%M%S).tar.gz"
        log "Creating backup of existing CRS rules to ${backup_file}"
        tar -czf "$backup_file" -C "$(dirname "$CRS_DIR")" "$(basename "$CRS_DIR")"
    fi
    
    # Create directories if they don't exist
    mkdir -p "$MODSEC_RULES_DIR"
    
    # Download OWASP CRS
    local crs_url="https://github.com/coreruleset/coreruleset/archive/v${CRS_VERSION}.zip"
    local temp_dir=$(mktemp -d)
    
    log "Downloading OWASP CRS from $crs_url"
    curl -s -L "$crs_url" -o "${temp_dir}/crs.zip"
    
    # Extract CRS
    log "Extracting OWASP CRS"
    unzip -q "${temp_dir}/crs.zip" -d "$temp_dir"
    
    # Move to target directory
    if [ -d "$CRS_DIR" ]; then
        rm -rf "$CRS_DIR"
    fi
    
    mkdir -p "$CRS_DIR"
    cp -r "${temp_dir}/coreruleset-${CRS_VERSION}"/* "$CRS_DIR/"
    
    # Create initial CRS configuration
    if [ -f "${CRS_DIR}/crs-setup.conf.example" ]; then
        cp "${CRS_DIR}/crs-setup.conf.example" "${CRS_DIR}/crs-setup.conf"
        log "Created CRS configuration from example"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    
    log "${GREEN}✓ OWASP CRS installation complete${NC}"
}

# Function to install custom WAF rules
install_custom_waf_rules() {
    log "${BLUE}Installing custom WAF rules...${NC}"
    
    # Create WAF rules directory if it doesn't exist
    mkdir -p "$WAF_RULES_DIR"
    
    # Copy custom WAF rules from project
    local custom_rules_src="${PROJECT_ROOT}/deployment/security/waf-rules"
    if [ -d "$custom_rules_src" ]; then
        log "Copying custom WAF rules from ${custom_rules_src}"
        cp -f "${custom_rules_src}"/*.conf "$WAF_RULES_DIR/" 2>/dev/null || true
    else
        log "${YELLOW}⚠ Custom WAF rules directory not found at ${custom_rules_src}${NC}"
        
        # Create basic default rule files
        for rule_type in "sensitive-data" "generic-attacks" "ip-reputation" "ics-protection" "command-injection" "request-limits" "api-protection"; do
            if [ ! -f "${WAF_RULES_DIR}/${rule_type}.conf" ]; then
                log "Creating default ${rule_type}.conf"
                cat > "${WAF_RULES_DIR}/${rule_type}.conf" <<EOF
# ${rule_type} protection rules for Cloud Infrastructure Platform
# ModSecurity Rules - Generated on $(date '+%Y-%m-%d')

# This is a placeholder file. Add your custom rules below.
# See ModSecurity documentation for rule syntax.
EOF
            fi
        done
    fi
    
    # Create specific rules for cloud platform if they don't exist
    if [ ! -f "${WAF_RULES_DIR}/api-protection.conf" ]; then
        cat > "${WAF_RULES_DIR}/api-protection.conf" <<EOF
# API Protection Rules for Cloud Infrastructure Platform
# Generated on $(date '+%Y-%m-%d')

# Block API access with suspicious query parameters
SecRule ARGS_NAMES "@rx (exec|system|eval|select|union|insert|update|delete)" \
    "id:9000,phase:2,t:none,t:lowercase,log,deny,status:403,msg:'Suspicious API parameter detected'"

# JWT token validation (placeholder - specific rules depend on implementation)
SecRule REQUEST_HEADERS:Authorization "!@rx ^Bearer\s+([a-zA-Z0-9\._-]+)$" \
    "id:9001,phase:1,t:none,log,deny,status:401,msg:'Invalid Authorization header format',chain"
    SecRule REQUEST_URI "@rx ^/api/" ""
EOF
    fi
    
    if [ ! -f "${WAF_RULES_DIR}/ics-protection.conf" ]; then
        cat > "${WAF_RULES_DIR}/ics-protection.conf" <<EOF
# ICS/SCADA Protection Rules for Cloud Infrastructure Platform
# Generated on $(date '+%Y-%m-%d')

# Block common ICS protocol keywords that shouldn't appear in web requests
SecRule ARGS|ARGS_NAMES|REQUEST_URI "@rx (modbus|bacnet|dnp3|ethernet/ip|profinet)" \
    "id:9100,phase:2,t:none,t:lowercase,log,deny,status:403,msg:'Potential ICS protocol tampering'"

# Restricted access to ICS endpoints
SecRule REQUEST_URI "@beginsWith /api/ics/" \
    "id:9101,phase:1,t:none,log,pass,id:'9101',msg:'ICS API access'"
EOF
    fi
    
    log "${GREEN}✓ Custom WAF rules installation complete${NC}"
}

# Function to create main ModSecurity configuration
create_modsec_config() {
    log "${BLUE}Creating ModSecurity main configuration...${NC}"
    
    # Create ModSecurity directory if it doesn't exist
    mkdir -p "$MODSEC_DIR"
    mkdir -p "$MODSEC_RULES_DIR"
    
    # Copy modsecurity.conf from deployment if it exists
    local modsec_conf_src="${PROJECT_ROOT}/deployment/security/modsecurity.conf"
    if [ -f "$modsec_conf_src" ]; then
        log "Using ModSecurity configuration from ${modsec_conf_src}"
        cp "$modsec_conf_src" "${MODSEC_DIR}/modsecurity.conf"
    else
        # Create basic configuration
        log "Creating default ModSecurity configuration"
        cat > "${MODSEC_DIR}/modsecurity.conf" <<EOF
# ModSecurity Configuration
# Generated on $(date '+%Y-%m-%d') for Cloud Infrastructure Platform

# -- Rule engine initialization ----------------------------------------------

# Enable ModSecurity, attaching it to every transaction. Use detection
# only to start with, because that minimizes the chances of post-installation
# disruption.
SecRuleEngine On

# -- Request body handling ---------------------------------------------------

# Allow ModSecurity to access request bodies. If you don't, ModSecurity
# won't be able to see any POST parameters, which opens a large security
# hole for attackers to exploit.
SecRequestBodyAccess On

# Enable XML request body parser.
SecRule REQUEST_HEADERS:Content-Type "application/xml" \
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON request body parser.
SecRule REQUEST_HEADERS:Content-Type "application/json" \
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# Maximum request body size we will accept for buffering
SecRequestBodyLimit 13107200

# Store up to 128 KB in memory
SecRequestBodyInMemoryLimit 131072

# -- Response body handling --------------------------------------------------

# Allow ModSecurity to access response bodies. 
SecResponseBodyAccess On

# Which response MIME types do you want to inspect?
SecResponseBodyMimeType text/plain text/html application/json

# Buffer response bodies of up to 512 KB
SecResponseBodyLimit 524288

# -- Filesystem configuration ------------------------------------------------

# The location where ModSecurity stores temporary files (for example, when
# it needs to handle a file upload that is larger than the configured limit).
SecTmpDir /tmp/

# The location where ModSecurity will keep its persistent data.
SecDataDir /tmp/

# -- Audit log configuration -------------------------------------------------

# Log everything we know about a transaction.
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"

# Log all transactions or just the ones that trigger a rule?
SecAuditLogParts ABIJDEFHZ

# Use a single file for logging. This is much easier to look at, but
# assumes that you will use the audit log only for troubleshooting.
SecAuditLogType Serial
SecAuditLog /var/log/cloud-platform/modsec_audit.log

# -- Debug log configuration -------------------------------------------------

# The default debug log configuration is to duplicate the error, warning
# and notice messages from the error log.
#SecDebugLog /var/log/cloud-platform/modsec_debug.log
#SecDebugLogLevel 3

# -- Rule set configuration --------------------------------------------------

# Include the OWASP ModSecurity Core Rule Set
Include ${MODSEC_RULES_DIR}/modsecurity-rules.conf
EOF
    fi
    
    # Create main rule inclusion file
    log "Creating main rule inclusion file"
    cat > "${MODSEC_RULES_DIR}/modsecurity-rules.conf" <<EOF
# ModSecurity Rules Configuration
# Generated on $(date '+%Y-%m-%d') for Cloud Infrastructure Platform

# Include the CRS setup configuration
Include ${CRS_DIR}/crs-setup.conf

# Include CRS rules
Include ${CRS_DIR}/rules/REQUEST-901-INITIALIZATION.conf
Include ${CRS_DIR}/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf
Include ${CRS_DIR}/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf
Include ${CRS_DIR}/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include ${CRS_DIR}/rules/REQUEST-910-IP-REPUTATION.conf
Include ${CRS_DIR}/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include ${CRS_DIR}/rules/REQUEST-912-DOS-PROTECTION.conf
Include ${CRS_DIR}/rules/REQUEST-913-SCANNER-DETECTION.conf
Include ${CRS_DIR}/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include ${CRS_DIR}/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include ${CRS_DIR}/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include ${CRS_DIR}/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include ${CRS_DIR}/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include ${CRS_DIR}/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include ${CRS_DIR}/rules/REQUEST-934-APPLICATION-ATTACK-NODEJS.conf
Include ${CRS_DIR}/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include ${CRS_DIR}/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include ${CRS_DIR}/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include ${CRS_DIR}/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf

# Include custom rules
Include ${WAF_RULES_DIR}/*.conf

# Logging all matched rules
SecRule TX:MONITORING "@eq 1" \
  "id:90001,phase:5,pass,log,msg:'ModSecurity: Alert - %{tx.msg}'"
EOF
    
    # Create directory for log files
    mkdir -p /var/log/cloud-platform
    touch /var/log/cloud-platform/modsec_audit.log
    chmod 640 /var/log/cloud-platform/modsec_audit.log
    
    log "${GREEN}✓ ModSecurity configuration created${NC}"
}

# Function to enable ModSecurity in NGINX
enable_modsecurity() {
    log "${BLUE}Enabling ModSecurity in NGINX...${NC}"
    
    # Check if modsecurity module is loaded in nginx
    if ! check_modsec_installed; then
        log "${RED}ERROR: ModSecurity module not installed in NGINX${NC}"
        log "Please install NGINX with ModSecurity support first. Example installation commands:"
        log "For Ubuntu: apt-get install nginx libnginx-mod-http-modsecurity"
        log "For CentOS: yum install nginx-module-modsecurity"
        log "Or build from source following ModSecurity instructions"
        exit 1
    fi
    
    # Create main configuration if needed
    if [ ! -f "${MODSEC_DIR}/modsecurity.conf" ]; then
        create_modsec_config
    fi
    
    # Create ModSecurity include file for NGINX
    local modsec_nginx_conf="${NGINX_ROOT}/conf.d/modsecurity.conf"
    log "Creating ModSecurity include file at ${modsec_nginx_conf}"
    
    cat > "$modsec_nginx_conf" <<EOF
# ModSecurity configuration for NGINX
# Generated on $(date '+%Y-%m-%d')

modsecurity on;
modsecurity_rules_file ${MODSEC_DIR}/modsecurity.conf;

# Define environment variable for WAF status monitoring
modsecurity_status_variable $modsec_status;
EOF
    
    # Enable ModSecurity in server blocks
    local main_conf_files=("${NGINX_ROOT}/sites-available/cloud-platform.conf" 
                           "${NGINX_ROOT}/sites-available/staging.conf"
                           "${NGINX_ROOT}/sites-available/development.conf")
    
    local changes_made=false
    
    for conf_file in "${main_conf_files[@]}"; do
        if [ -f "$conf_file" ]; then
            log "Checking ModSecurity in ${conf_file}"
            
            # Check if the file already includes ModSecurity
            if ! grep -q "include.*modsecurity.conf" "$conf_file"; then
                log "Enabling ModSecurity in ${conf_file}"
                # Add include directive to server blocks
                sed -i '/server {/a\    include conf.d/modsecurity.conf;' "$conf_file"
                changes_made=true
            fi
            
            # Make sure ModSecurity is on
            if grep -q "modsecurity off" "$conf_file"; then
                log "Switching ModSecurity from off to on in ${conf_file}"
                sed -i 's/modsecurity off/modsecurity on/g' "$conf_file"
                changes_made=true
            fi
        fi
    done
    
    if [ "$changes_made" = true ]; then
        log "${GREEN}✓ ModSecurity enabled in NGINX configurations${NC}"
    else
        log "${YELLOW}⚠ No changes needed - ModSecurity appears to be already enabled${NC}"
    fi
}

# Function to disable ModSecurity in NGINX
disable_modsecurity() {
    log "${YELLOW}Disabling ModSecurity in NGINX...${NC}"
    
    # Option 1: Set modsecurity off in config
    local modsec_nginx_conf="${NGINX_ROOT}/conf.d/modsecurity.conf"
    
    if [ -f "$modsec_nginx_conf" ]; then
        log "Setting ModSecurity to off in ${modsec_nginx_conf}"
        sed -i 's/modsecurity on/modsecurity off/g' "$modsec_nginx_conf"
    fi
    
    # Check for direct modsecurity directives in server blocks
    local main_conf_files=("${NGINX_ROOT}/sites-available/cloud-platform.conf" 
                           "${NGINX_ROOT}/sites-available/staging.conf"
                           "${NGINX_ROOT}/sites-available/development.conf")
    
    for conf_file in "${main_conf_files[@]}"; do
        if [ -f "$conf_file" ] && grep -q "modsecurity on" "$conf_file"; then
            log "Setting ModSecurity to off in ${conf_file}"
            sed -i 's/modsecurity on/modsecurity off/g' "$conf_file"
        fi
    done
    
    log "${YELLOW}✓ ModSecurity disabled in NGINX${NC}"
}

# Test NGINX configuration
test_nginx_config() {
    log "Testing NGINX configuration..."
    if nginx -t; then
        log "${GREEN}✓ NGINX configuration test passed${NC}"
        return 0
    else
        log "${RED}✗ NGINX configuration test failed${NC}"
        return 1
    fi
}

# Reload NGINX
reload_nginx() {
    log "Reloading NGINX..."
    systemctl reload nginx
    if [ $? -eq 0 ]; then
        log "${GREEN}✓ NGINX reloaded successfully${NC}"
        return 0
    else
        log "${RED}✗ Failed to reload NGINX${NC}"
        return 1
    fi
}

# Create ModSecurity status page
create_status_page() {
    log "Creating ModSecurity status endpoint..."
    local status_conf="${NGINX_ROOT}/conf.d/modsec-status.conf"
    
    cat > "$status_conf" <<EOF
# ModSecurity Status Endpoint
# Generated on $(date '+%Y-%m-%d')

# Health check endpoint for WAF status
location = /health/waf {
    allow 127.0.0.1;
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
    
    # Return ModSecurity status
    return 200 "ModSecurity: \$modsec_status";
    add_header Content-Type text/plain;
}
EOF
    
    log "${GREEN}✓ ModSecurity status endpoint created${NC}"
}

# Configure logrotate for ModSecurity
configure_logrotate() {
    log "Configuring log rotation for ModSecurity logs..."
    local logrotate_conf="/etc/logrotate.d/modsecurity"
    
    cat > "$logrotate_conf" <<EOF
/var/log/cloud-platform/modsec_audit.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -s /run/nginx.pid ]; then
            kill -USR1 \$(cat /run/nginx.pid)
        fi
    endscript
}
EOF
    
    log "${GREEN}✓ Log rotation configured for ModSecurity logs${NC}"
}

# Main execution
log "${BLUE}Starting ModSecurity WAF setup for Cloud Infrastructure Platform${NC}"

# Create backup before making changes
backup_configs

# Update rules if requested or as part of enabling
if [[ "$UPDATE_RULES" == "true" || ("$ENABLE" == "true" && ! -d "$CRS_DIR") ]]; then
    install_owasp_crs
    install_custom_waf_rules
    create_modsec_config
fi

# Enable or disable ModSecurity
if [[ "$ENABLE" == "true" ]]; then
    # Make sure CRS is installed
    if [ ! -d "$CRS_DIR" ]; then
        install_owasp_crs
    fi
    
    # Make sure WAF rules are installed
    if [ ! -d "$WAF_RULES_DIR" ] || [ -z "$(ls -A "$WAF_RULES_DIR" 2>/dev/null)" ]; then
        install_custom_waf_rules
    fi
    
    # Create main configuration if needed
    if [ ! -f "${MODSEC_DIR}/modsecurity.conf" ]; then
        create_modsec_config
    fi
    
    enable_modsecurity
    create_status_page
    configure_logrotate
    
elif [[ "$DISABLE" == "true" ]]; then
    disable_modsecurity
else
    # If no action specified, just check status
    if check_modsec_installed; then
        log "${GREEN}ModSecurity module is installed in NGINX${NC}"
        
        if check_modsec_enabled; then
            log "${GREEN}ModSecurity is enabled in NGINX configuration${NC}"
        else
            log "${YELLOW}ModSecurity module is installed but not enabled in NGINX configuration${NC}"
        fi
    else
        log "${RED}ModSecurity module is not installed in NGINX${NC}"
    fi
    
    log "Use --enable to enable ModSecurity or --disable to disable it"
    exit 0
fi

# Test and reload nginx
if test_nginx_config; then
    reload_nginx
    
    # Final status check
    if [[ "$ENABLE" == "true" ]]; then
        if check_modsec_enabled; then
            log "${GREEN}ModSecurity is now enabled and active${NC}"
        else
            log "${YELLOW}ModSecurity configuration is in place but may not be active${NC}"
        fi
    elif [[ "$DISABLE" == "true" ]]; then
        if ! check_modsec_enabled; then
            log "${GREEN}ModSecurity is now disabled${NC}"
        else
            log "${YELLOW}ModSecurity may still be active in some configurations${NC}"
        fi
    fi
    
    # Show next steps
    if [[ "$ENABLE" == "true" ]]; then
        log "${BLUE}Next Steps:${NC}"
        log "1. Review and customize rules in ${WAF_RULES_DIR}"
        log "2. Monitor ModSecurity logs at /var/log/cloud-platform/modsec_audit.log"
        log "3. Check WAF status at /health/waf endpoint from allowed IPs"
    fi
else
    log "${RED}NGINX configuration test failed. Changes may not be applied.${NC}"
    exit 1
fi

log "${GREEN}ModSecurity WAF setup completed successfully${NC}"
exit 0