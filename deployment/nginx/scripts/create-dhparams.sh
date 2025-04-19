#!/bin/bash
# Create Diffie-Hellman parameters for improved SSL security
# Usage: ./create-dhparams.sh [--bits 2048|4096] [--force]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
DH_BITS=2048
FORCE=false
DH_FILE="${NGINX_ROOT}/dhparams.pem"
SSL_PARAMS_CONF="${NGINX_ROOT}/conf.d/ssl-params.conf"

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

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --bits)
            DH_BITS="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --file)
            DH_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Create Diffie-Hellman parameters for improved SSL security"
            echo
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --bits N          Key size in bits (2048 or 4096) [default: 2048]"
            echo "  --file PATH       Output file path [default: /etc/nginx/dhparams.pem]"
            echo "  --force           Force recreation even if file exists"
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

# Validate key size
if [[ "$DH_BITS" != "2048" && "$DH_BITS" != "4096" ]]; then
    log "${RED}Invalid key size: $DH_BITS. Must be 2048 or 4096.${NC}"
    exit 1
fi

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
    log "${RED}This script must be run as root${NC}"
    exit 1
fi

# Check if NGINX is installed
if ! command -v nginx &> /dev/null; then
    log "${RED}ERROR: NGINX is not installed${NC}"
    exit 1
fi

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    log "${RED}ERROR: OpenSSL is not installed${NC}"
    exit 1
fi

# Function to update nginx ssl-params.conf to use the DH params
update_ssl_params() {
    local ssl_params_src="${PROJECT_ROOT}/deployment/security/ssl-params.conf"
    
    # Check if ssl-params.conf already exists
    if [ -f "$SSL_PARAMS_CONF" ]; then
        log "${BLUE}Updating existing SSL parameters configuration...${NC}"
        # Update the dhparam path if it exists in the file
        if grep -q "ssl_dhparam" "$SSL_PARAMS_CONF"; then
            sed -i "s|ssl_dhparam.*|ssl_dhparam $DH_FILE;|" "$SSL_PARAMS_CONF"
        else
            # Add dhparam directive if it doesn't exist
            echo "ssl_dhparam $DH_FILE;" >> "$SSL_PARAMS_CONF"
        fi
    else
        # Check if we have a template to copy from
        if [ -f "$ssl_params_src" ]; then
            log "Using SSL parameters template from ${ssl_params_src}"
            cp "$ssl_params_src" "$SSL_PARAMS_CONF"
            
            # Update the dhparam path if it exists in the template
            if grep -q "ssl_dhparam" "$SSL_PARAMS_CONF"; then
                sed -i "s|ssl_dhparam.*|ssl_dhparam $DH_FILE;|" "$SSL_PARAMS_CONF"
            else
                # Add dhparam directive if it doesn't exist in the template
                echo "ssl_dhparam $DH_FILE;" >> "$SSL_PARAMS_CONF"
            fi
        else
            # Create a basic ssl-params.conf if no template exists
            log "Creating basic SSL parameters configuration"
            mkdir -p "$(dirname "$SSL_PARAMS_CONF")"
            cat > "$SSL_PARAMS_CONF" <<EOF
# SSL Parameters Configuration for Cloud Infrastructure Platform
# Generated on $(date '+%Y-%m-%d')

# SSL protocols and ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# DH parameters
ssl_dhparam $DH_FILE;

# SSL session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOF
        fi
    fi
    
    log "${GREEN}✓ Updated SSL parameters configuration${NC}"
}

# Function to ensure ssl.conf includes ssl-params.conf
update_ssl_conf() {
    local ssl_conf="${NGINX_ROOT}/conf.d/ssl.conf"
    
    # Only modify if the file exists
    if [ -f "$ssl_conf" ]; then
        log "${BLUE}Checking if SSL configuration includes SSL parameters...${NC}"
        
        # Add include directive if it's not already there
        if ! grep -q "include.*ssl-params.conf" "$ssl_conf"; then
            log "Adding SSL parameters include to $ssl_conf"
            sed -i '/^[^#]*ssl_certificate/i include conf.d/ssl-params.conf;' "$ssl_conf"
        fi
        
        log "${GREEN}✓ SSL configuration includes SSL parameters${NC}"
    fi
}

# Main function to generate DH params
generate_dhparams() {
    log "${BLUE}Generating $DH_BITS-bit Diffie-Hellman parameters...${NC}"
    log "This may take a while, especially for 4096-bit keys."
    
    # Display estimated time
    if [ "$DH_BITS" == "4096" ]; then
        log "Estimated time: 25-45 minutes depending on system resources."
    else
        log "Estimated time: 1-3 minutes depending on system resources."
    fi
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$DH_FILE")"
    
    # Generate parameters with progress indicator
    log "Starting generation at $(date '+%H:%M:%S')"
    
    # Use -dsaparam for faster generation (slightly less secure but still very good)
    openssl dhparam -out "$DH_FILE" "$DH_BITS"
    
    # Set proper permissions
    chmod 644 "$DH_FILE"
    
    log "${GREEN}✓ DH parameters generated successfully at $DH_FILE${NC}"
    log "Completed at $(date '+%H:%M:%S')"
    
    # Display file info
    openssl dhparam -in "$DH_FILE" -text -noout | head -1
}

# Display information about current DH params if they exist
check_existing_params() {
    if [ -f "$DH_FILE" ]; then
        log "${BLUE}Checking existing DH parameters...${NC}"
        
        # Check file size to estimate bit length
        local file_size=$(stat -c%s "$DH_FILE")
        local estimated_bits=0
        
        if [ "$file_size" -gt 600 ]; then
            estimated_bits=4096
        elif [ "$file_size" -gt 300 ]; then
            estimated_bits=2048
        else
            estimated_bits=1024
        fi
        
        log "Existing parameters file: $DH_FILE"
        log "File size: $file_size bytes (approximately $estimated_bits bits)"
        
        # Display file info
        openssl dhparam -in "$DH_FILE" -text -noout | head -1
        
        # Check if requested bits are larger than current bits
        if [ "$DH_BITS" -gt "$estimated_bits" ]; then
            log "${YELLOW}Current parameters appear to be weaker than requested ($estimated_bits vs $DH_BITS)${NC}"
            FORCE=true
        fi
    fi
}

# Check if nginx and config directories exist
validate_nginx_installation() {
    if [ ! -d "$NGINX_ROOT" ]; then
        log "${RED}NGINX configuration directory $NGINX_ROOT does not exist${NC}"
        log "Creating directory: $NGINX_ROOT"
        mkdir -p "$NGINX_ROOT/conf.d"
    fi
    
    # Ensure conf.d directory exists
    if [ ! -d "${NGINX_ROOT}/conf.d" ]; then
        log "Creating directory: ${NGINX_ROOT}/conf.d"
        mkdir -p "${NGINX_ROOT}/conf.d"
    fi
}

# Main execution flow
log "${BLUE}Starting Diffie-Hellman parameters setup${NC}"

# Validate NGINX installation
validate_nginx_installation

# Check existing parameters if they exist
check_existing_params

# Check if DH params already exist and we're not forcing recreation
if [ -f "$DH_FILE" ] && [ "$FORCE" = false ]; then
    log "${YELLOW}DH parameters already exist at $DH_FILE${NC}"
    log "Use --force to regenerate"
else
    # Generate new parameters
    generate_dhparams
fi

# Update ssl-params.conf to use this file
update_ssl_params

# Update ssl.conf to include ssl-params.conf
update_ssl_conf

# Test NGINX configuration
log "${BLUE}Testing NGINX configuration...${NC}"
if nginx -t; then
    log "${GREEN}✓ NGINX configuration test passed${NC}"
    
    # Reload NGINX
    log "Reloading NGINX..."
    systemctl reload nginx
    log "${GREEN}✓ NGINX reloaded with new DH parameters${NC}"
else
    log "${RED}✗ NGINX configuration test failed${NC}"
    log "Please fix the configuration errors before reloading NGINX"
    exit 1
fi

log "${GREEN}Diffie-Hellman parameters setup completed${NC}"
exit 0