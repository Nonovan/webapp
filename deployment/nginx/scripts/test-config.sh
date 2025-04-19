#!/bin/bash
# Test NGINX configuration for Cloud Infrastructure Platform
# Usage: ./test-config.sh [nginx_conf_path]

set -e

NGINX_CONF="${1:-/etc/nginx/nginx.conf}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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
}

# Check if NGINX is installed
if ! command -v nginx &> /dev/null; then
    log "${RED}ERROR: NGINX is not installed.${NC}"
    exit 1
fi

log "${BLUE}Testing NGINX configuration: ${NGINX_CONF}${NC}"

# Test basic syntax
log "Checking basic NGINX configuration syntax..."
if nginx -t -c "$NGINX_CONF" &> /dev/null; then
    log "${GREEN}✓ NGINX configuration syntax is valid${NC}"
else
    log "${RED}✗ NGINX configuration syntax is invalid:${NC}"
    nginx -t -c "$NGINX_CONF"
    exit 1
fi

# Check for common security issues
log "Checking for common security issues..."

# Check SSL configuration
if grep -q "ssl_protocols" "$NGINX_CONF" || find /etc/nginx -type f -name "*.conf" -exec grep -l "ssl_protocols" {} \; | grep -q .; then
    if grep -q "TLSv1\.0" "$NGINX_CONF" || find /etc/nginx -type f -name "*.conf" -exec grep -l "TLSv1\.0" {} \; | grep -q .; then
        log "${YELLOW}⚠ WARNING: TLSv1.0 is enabled, which is considered insecure${NC}"
    else
        log "${GREEN}✓ SSL protocol configuration is secure${NC}"
    fi
else
    log "${YELLOW}⚠ WARNING: SSL protocol configuration not found${NC}"
fi

# Check for server tokens
if grep -q "server_tokens off" "$NGINX_CONF" || find /etc/nginx -type f -name "*.conf" -exec grep -l "server_tokens off" {} \; | grep -q .; then
    log "${GREEN}✓ server_tokens is disabled${NC}"
else
    log "${YELLOW}⚠ WARNING: server_tokens should be disabled${NC}"
fi

# Check for important security headers
headers=("X-Content-Type-Options" "X-Frame-Options" "Strict-Transport-Security" "Content-Security-Policy")
missing_headers=()

for header in "${headers[@]}"; do
    if ! find /etc/nginx -type f -name "*.conf" -exec grep -l "$header" {} \; | grep -q .; then
        missing_headers+=("$header")
    fi
done

if [ ${#missing_headers[@]} -eq 0 ]; then
    log "${GREEN}✓ Essential security headers are configured${NC}"
else
    log "${YELLOW}⚠ WARNING: Some security headers are missing:${NC}"
    for header in "${missing_headers[@]}"; do
        log "  - $header"
    done
fi

# Check for rate limiting configuration
if find /etc/nginx -type f -name "*.conf" -exec grep -l "limit_req_zone" {} \; | grep -q .; then
    log "${GREEN}✓ Rate limiting is configured${NC}"
else
    log "${YELLOW}⚠ WARNING: Rate limiting configuration not found${NC}"
fi

# Check for DH parameters
if find /etc/nginx -type f -name "*.conf" -exec grep -l "ssl_dhparam" {} \; | grep -q .; then
    log "${GREEN}✓ Custom DH parameters are configured${NC}"
    
    # Check if the file exists
    dhparam_file=$(find /etc/nginx -type f -name "*.conf" -exec grep "ssl_dhparam" {} \; | head -n1 | awk '{print $2}' | tr -d ';')
    if [ -n "$dhparam_file" ] && [ ! -f "$dhparam_file" ]; then
        log "${YELLOW}⚠ WARNING: DH parameters file ${dhparam_file} not found${NC}"
    fi
else
    log "${YELLOW}⚠ WARNING: Custom DH parameters not configured${NC}"
fi

# Check if client certificate validation is used
if find /etc/nginx -type f -name "*.conf" -exec grep -l "ssl_verify_client" {} \; | grep -q .; then
    log "${GREEN}✓ Client certificate validation is configured${NC}"
fi

# Check if ModSecurity is enabled
if find /etc/nginx -type f -name "*.conf" -exec grep -l "modsecurity on" {} \; | grep -q .; then
    log "${GREEN}✓ ModSecurity WAF is enabled${NC}"
else
    log "${YELLOW}⚠ WARNING: ModSecurity WAF is not enabled${NC}"
fi

# Additional advanced checks
log "${BLUE}Performing advanced checks...${NC}"

# Check for HTTP to HTTPS redirects
if find /etc/nginx -type f -name "*.conf" -exec grep -l "return 301 https://" {} \; | grep -q .; then
    log "${GREEN}✓ HTTP to HTTPS redirect is configured${NC}"
else
    log "${YELLOW}⚠ WARNING: HTTP to HTTPS redirect not found${NC}"
fi

# Check for correct access log format
if find /etc/nginx -type f -name "*.conf" -exec grep -l "log_format" {} \; | grep -q .; then
    log "${GREEN}✓ Custom log format is configured${NC}"
else
    log "${YELLOW}⚠ WARNING: Custom log format not configured${NC}"
fi

# Check for consistent configurations across environments
SITES_AVAILABLE="/etc/nginx/sites-available"
if [ -d "$SITES_AVAILABLE" ]; then
    log "${BLUE}Checking environment configurations...${NC}"
    if [ -f "${SITES_AVAILABLE}/cloud-platform.conf" ]; then
        log "${GREEN}✓ Production configuration exists${NC}"
    else
        log "${YELLOW}⚠ WARNING: Production configuration not found${NC}"
    fi
    
    if [ -f "${SITES_AVAILABLE}/staging.conf" ]; then
        log "${GREEN}✓ Staging configuration exists${NC}"
    fi
    
    if [ -f "${SITES_AVAILABLE}/development.conf" ]; then
        log "${GREEN}✓ Development configuration exists${NC}"
    fi
fi

# Final summary
log "${BLUE}Configuration test complete.${NC}"
if nginx -t -c "$NGINX_CONF" &> /dev/null; then
    log "${GREEN}✓ NGINX configuration is valid and ready to use${NC}"
else
    log "${RED}✗ NGINX configuration has errors${NC}"
    exit 1
fi

exit 0