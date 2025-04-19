#!/bin/bash
# SSL Certificate Setup Script for NGINX in Cloud Infrastructure Platform
# This script automates SSL/TLS certificate installation and configuration

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
CERT_DIR="/etc/ssl/cloud-platform"
SSL_PARAMS_CONF="${NGINX_ROOT}/conf.d/ssl-params.conf"
SSL_CONF="${NGINX_ROOT}/conf.d/ssl.conf"

# Certificate details
DOMAIN=""
ENVIRONMENT="production"
CERT_TYPE="letsencrypt"  # Options: letsencrypt, self-signed, import
EMAIL=""
KEY_SIZE=4096
FORCE=false
DRY_RUN=false
USE_SECURITY_HEADERS=true
CREATE_DHPARAMS=true
DHPARAM_SIZE=2048
NGINX_RELOAD=true

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

# Function to display usage
usage() {
    echo "SSL Certificate Setup Script for NGINX"
    echo 
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --domain, -d DOMAIN       Domain name for certificate"
    echo "  --environment, -e ENV     Environment (production, staging, development)"
    echo "  --email, -m EMAIL         Email for Let's Encrypt registration"
    echo "  --cert-type, -t TYPE      Certificate type (letsencrypt, self-signed, import)"
    echo "  --key-size, -k SIZE       Key size in bits (2048, 4096) [default: 4096]"
    echo "  --cert-dir, -c DIR        Certificate directory [default: /etc/ssl/cloud-platform]"
    echo "  --dhparam-size SIZE       DH parameter size (1024, 2048, 4096) [default: 2048]"
    echo "  --force, -f               Force overwrite of existing certificates"
    echo "  --no-security-headers     Don't configure security headers"
    echo "  --no-dhparams             Don't generate Diffie-Hellman parameters"
    echo "  --no-reload               Don't reload NGINX after installation"
    echo "  --dry-run                 Print actions without executing them"
    echo "  --help, -h                Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain|-d)
            DOMAIN="$2"
            shift 2
            ;;
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --email|-m)
            EMAIL="$2"
            shift 2
            ;;
        --cert-type|-t)
            CERT_TYPE="$2"
            shift 2
            ;;
        --key-size|-k)
            KEY_SIZE="$2"
            shift 2
            ;;
        --cert-dir|-c)
            CERT_DIR="$2"
            shift 2
            ;;
        --dhparam-size)
            DHPARAM_SIZE="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --no-security-headers)
            USE_SECURITY_HEADERS=false
            shift
            ;;
        --no-dhparams)
            CREATE_DHPARAMS=false
            shift
            ;;
        --no-reload)
            NGINX_RELOAD=false
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required parameters
if [[ -z "$DOMAIN" ]]; then
    log "${RED}ERROR: Domain name is required${NC}"
    usage
fi

if [[ "$CERT_TYPE" == "letsencrypt" && -z "$EMAIL" ]]; then
    log "${RED}ERROR: Email address is required for Let's Encrypt certificates${NC}"
    usage
fi

# Check if we're running as root
if [[ $EUID -ne 0 ]]; then
    if [[ "$DRY_RUN" == "false" ]]; then
        log "${RED}ERROR: This script must be run as root${NC}"
        exit 1
    else
        log "${YELLOW}WARNING: Not running as root. In non-dry-run mode, root is required.${NC}"
    fi
fi

# Function to check if certbot is installed
check_certbot() {
    if ! command -v certbot &> /dev/null; then
        log "${RED}ERROR: certbot is not installed. Please install it first.${NC}"
        log "On Ubuntu/Debian: apt-get install certbot python3-certbot-nginx"
        log "On CentOS/RHEL: yum install certbot python3-certbot-nginx"
        exit 1
    fi
}

# Function to create self-signed certificate
create_self_signed_cert() {
    log "${BLUE}Generating self-signed certificate for $DOMAIN${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would generate self-signed certificate in $CERT_DIR"
        return
    fi
    
    # Create certificate directory
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    
    # Generate private key
    log "Generating private key..."
    openssl genrsa -out "$CERT_DIR/privkey.pem" $KEY_SIZE
    chmod 600 "$CERT_DIR/privkey.pem"
    
    # Create CSR configuration file
    cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = $DOMAIN
O = Cloud Infrastructure Platform
OU = $ENVIRONMENT
C = US
ST = California
L = San Francisco

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
EOF
    
    # Create CSR
    log "Creating certificate signing request..."
    openssl req -new -key "$CERT_DIR/privkey.pem" -out "$CERT_DIR/request.csr" -config "$CERT_DIR/openssl.cnf"

    # Create certificate (self-signed)
    log "Self-signing certificate..."
    openssl x509 -req -in "$CERT_DIR/request.csr" -signkey "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/cert.pem" -days 365 -sha256 -extensions req_ext -extfile "$CERT_DIR/openssl.cnf"
    
    # Create chain and fullchain files (for compatibility with Let's Encrypt paths)
    cp "$CERT_DIR/cert.pem" "$CERT_DIR/chain.pem"
    cp "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem"
    
    log "${GREEN}✓ Self-signed certificate generated successfully in $CERT_DIR${NC}"
    
    # Display certificate information
    openssl x509 -in "$CERT_DIR/cert.pem" -text -noout | head -10
}

# Function to request Let's Encrypt certificate using certbot
create_letsencrypt_cert() {
    log "${BLUE}Requesting Let's Encrypt certificate for $DOMAIN${NC}"
    
    # Check if certbot is installed
    check_certbot
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would request Let's Encrypt certificate for $DOMAIN"
        return
    fi
    
    # Create webroot directory if it doesn't exist
    local webroot="/var/www/html"
    mkdir -p "$webroot/.well-known/acme-challenge"
    chmod -R 755 "$webroot/.well-known"
    
    # Create certificate directory
    mkdir -p "$CERT_DIR"
    
    # Build certbot command for webroot authentication
    local certbot_cmd="certbot certonly --webroot -w $webroot -d $DOMAIN -d www.$DOMAIN --email $EMAIL --agree-tos --non-interactive"
    
    # Check if we need to force renewal
    if [[ "$FORCE" == "true" ]]; then
        certbot_cmd="$certbot_cmd --force-renewal"
    fi
    
    # Add staging flag for non-production environments
    if [[ "$ENVIRONMENT" != "production" ]]; then
        certbot_cmd="$certbot_cmd --staging"
    fi
    
    # Run certbot
    log "Running certbot: $certbot_cmd"
    if eval $certbot_cmd; then
        log "${GREEN}✓ Let's Encrypt certificate obtained successfully${NC}"
        
        # Copy certificates to our directory
        local letsencrypt_live_dir="/etc/letsencrypt/live/$DOMAIN"
        if [[ -d "$letsencrypt_live_dir" ]]; then
            log "Copying certificates to $CERT_DIR"
            cp "$letsencrypt_live_dir/privkey.pem" "$CERT_DIR/"
            cp "$letsencrypt_live_dir/cert.pem" "$CERT_DIR/"
            cp "$letsencrypt_live_dir/chain.pem" "$CERT_DIR/"
            cp "$letsencrypt_live_dir/fullchain.pem" "$CERT_DIR/"
            chmod 600 "$CERT_DIR/privkey.pem"
        else
            log "${RED}ERROR: Let's Encrypt directory not found at $letsencrypt_live_dir${NC}"
            exit 1
        fi
    else
        log "${RED}ERROR: Failed to obtain Let's Encrypt certificate${NC}"
        exit 1
    fi
}

# Function to import existing certificates
import_certificates() {
    log "${BLUE}Importing existing certificates for $DOMAIN${NC}"
    
    local source_dir=""
    local source_privkey=""
    local source_fullchain=""
    
    # Prompt for certificate files
    read -p "Enter path to private key file: " source_privkey
    read -p "Enter path to full chain certificate file: " source_fullchain
    
    if [[ ! -f "$source_privkey" ]]; then
        log "${RED}ERROR: Private key file not found: $source_privkey${NC}"
        exit 1
    fi
    
    if [[ ! -f "$source_fullchain" ]]; then
        log "${RED}ERROR: Full chain certificate file not found: $source_fullchain${NC}"
        exit 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would import certificates from $source_privkey and $source_fullchain to $CERT_DIR"
        return
    fi
    
    # Create certificate directory
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    
    # Copy certificate files
    cp "$source_privkey" "$CERT_DIR/privkey.pem"
    cp "$source_fullchain" "$CERT_DIR/fullchain.pem"
    
    # Set proper permissions
    chmod 600 "$CERT_DIR/privkey.pem"
    chmod 644 "$CERT_DIR/fullchain.pem"
    
    log "${GREEN}✓ Certificates imported successfully to $CERT_DIR${NC}"
}

# Function to generate Diffie-Hellman parameters
generate_dhparams() {
    local dhparam_file="${NGINX_ROOT}/dhparams.pem"
    
    if [[ "$CREATE_DHPARAMS" != "true" ]]; then
        log "${YELLOW}Skipping DH parameters generation (--no-dhparams specified)${NC}"
        return
    fi
    
    # Check if DH params already exist and we're not forcing recreation
    if [[ -f "$dhparam_file" && "$FORCE" != "true" ]]; then
        log "${YELLOW}DH parameters already exist at $dhparam_file. Use --force to regenerate.${NC}"
        return
    fi
    
    log "${BLUE}Generating $DHPARAM_SIZE-bit Diffie-Hellman parameters...${NC}"
    log "This may take a while, especially for larger key sizes."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would generate $DHPARAM_SIZE-bit DH parameters at $dhparam_file"
        return
    fi
    
    openssl dhparam -out "$dhparam_file" $DHPARAM_SIZE
    chmod 644 "$dhparam_file"
    
    log "${GREEN}✓ DH parameters generated successfully at $dhparam_file${NC}"
}

# Function to create/update SSL configuration for NGINX
configure_ssl() {
    log "${BLUE}Configuring NGINX for SSL${NC}"
    
    # Create conf.d directory if it doesn't exist
    mkdir -p "${NGINX_ROOT}/conf.d"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would create/update SSL configuration files"
        return
    fi
    
    # Create SSL parameters file
    if [[ ! -f "$SSL_PARAMS_CONF" || "$FORCE" == "true" ]]; then
        log "Creating SSL parameters configuration"
        cat > "$SSL_PARAMS_CONF" <<EOF
# SSL Parameters Configuration for Cloud Infrastructure Platform
# Generated on $(date '+%Y-%m-%d')

# SSL protocols and ciphers
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

# DH parameters
ssl_dhparam ${NGINX_ROOT}/dhparams.pem;

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
    
    # Create main SSL configuration file
    if [[ ! -f "$SSL_CONF" || "$FORCE" == "true" ]]; then
        log "Creating main SSL configuration"
        cat > "$SSL_CONF" <<EOF
# SSL Configuration for Cloud Infrastructure Platform
# This file configures SSL/TLS settings for NGINX servers

# Include the SSL parameters file
include ${NGINX_ROOT}/conf.d/ssl-params.conf;

# SSL certificate paths
ssl_certificate ${CERT_DIR}/fullchain.pem;
ssl_certificate_key ${CERT_DIR}/privkey.pem;

# Diffie-Hellman parameters for improved security
ssl_dhparam ${NGINX_ROOT}/dhparams.pem;

# OCSP Stapling setup
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

# SSL session settings
ssl_session_timeout 24h;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
EOF
    else
        log "Updating certificate paths in SSL configuration"
        sed -i "s|ssl_certificate .*|ssl_certificate ${CERT_DIR}/fullchain.pem;|" "$SSL_CONF"
        sed -i "s|ssl_certificate_key .*|ssl_certificate_key ${CERT_DIR}/privkey.pem;|" "$SSL_CONF"
    fi
    
    # Ensure security headers are set up if requested
    if [[ "$USE_SECURITY_HEADERS" == "true" ]]; then
        local security_headers_conf="${NGINX_ROOT}/conf.d/security-headers.conf"
        local security_headers_src="${PROJECT_ROOT}/deployment/security/security-headers.conf"
        
        if [[ -f "$security_headers_src" ]]; then
            log "Using security headers from $security_headers_src"
            cp "$security_headers_src" "$security_headers_conf"
        elif [[ ! -f "$security_headers_conf" ]]; then
            log "Creating security headers configuration"
            cat > "$security_headers_conf" <<EOF
# Security Headers Configuration for Cloud Infrastructure Platform
# Generated on $(date '+%Y-%m-%d')

# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none';" always;

# HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Prevent clickjacking attacks
add_header X-Frame-Options "DENY" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Configure Cross-site scripting (XSS) Protection
add_header X-XSS-Protection "1; mode=block" always;

# Set referrer policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Set permissions policy
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), accelerometer=(), gyroscope=()" always;

# Hide NGINX version
server_tokens off;
EOF
        fi
    fi
    
    log "${GREEN}✓ SSL configuration completed${NC}"
}

# Function to verify certificate
verify_certificate() {
    if [[ ! -f "${CERT_DIR}/fullchain.pem" ]]; then
        log "${RED}ERROR: Certificate not found at ${CERT_DIR}/fullchain.pem${NC}"
        return 1
    fi
    
    log "${BLUE}Verifying certificate:${NC}"
    
    # Display basic information
    openssl x509 -in "${CERT_DIR}/fullchain.pem" -noout -subject -issuer -dates

    # Calculate and display days until expiry
    local expiry_date=$(openssl x509 -in "${CERT_DIR}/fullchain.pem" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local current_epoch=$(date +%s)
    local days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
    
    log "Certificate will expire in $days_left days"
    
    # Verify the certificate chain if it's not self-signed
    if [[ "$CERT_TYPE" != "self-signed" ]]; then
        log "Verifying certificate chain..."
        if openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "${CERT_DIR}/fullchain.pem" > /dev/null; then
            log "${GREEN}✓ Certificate chain verification successful${NC}"
        else
            log "${RED}✗ Certificate chain verification failed${NC}"
            return 1
        fi
    fi
    
    return 0
}

# Function to reload NGINX
reload_nginx() {
    if [[ "$NGINX_RELOAD" != "true" ]]; then
        log "${YELLOW}Skipping NGINX reload (--no-reload specified)${NC}"
        return
    fi
    
    log "${BLUE}Testing NGINX configuration...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would test and reload NGINX"
        return
    fi
    
    if nginx -t; then
        log "${GREEN}✓ NGINX configuration test passed${NC}"
        log "Reloading NGINX..."
        
        systemctl reload nginx
        if [ $? -eq 0 ]; then
            log "${GREEN}✓ NGINX reloaded successfully${NC}"
        else
            log "${RED}✗ Failed to reload NGINX${NC}"
            return 1
        fi
    else
        log "${RED}✗ NGINX configuration test failed. Not reloading.${NC}"
        return 1
    fi
}

# Function to set up NGINX server block
setup_server_block() {
    local server_block_file="${NGINX_ROOT}/sites-available/${DOMAIN}.conf"
    
    if [[ -f "$server_block_file" && "$FORCE" != "true" ]]; then
        log "${YELLOW}Server block already exists at $server_block_file. Use --force to override.${NC}"
        return
    fi
    
    log "${BLUE}Setting up NGINX server block for $DOMAIN${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY RUN] Would create server block at $server_block_file"
        return
    fi
    
    # Create sites-available and sites-enabled directories if they don't exist
    mkdir -p "${NGINX_ROOT}/sites-available"
    mkdir -p "${NGINX_ROOT}/sites-enabled"
    
    # Create server block configuration
    cat > "$server_block_file" <<EOF
# Server configuration for $DOMAIN
# Generated by setup-ssl.sh on $(date '+%Y-%m-%d')

# HTTP server - redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    
    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
    
    # Allow Let's Encrypt validation
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;
    
    # Root directory
    root /var/www/html;
    index index.html index.htm;
    
    # Include SSL configuration
    include conf.d/ssl.conf;
    
    # Include security headers
    include conf.d/security-headers.conf;
    
    # Other server configuration goes here
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Custom error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    # Additional locations and settings can be added here
}
EOF

    # Create symlink in sites-enabled
    local enabled_link="${NGINX_ROOT}/sites-enabled/${DOMAIN}.conf"
    if [[ ! -L "$enabled_link" ]]; then
        ln -s "$server_block_file" "$enabled_link"
    fi
    
    # Ensure main nginx.conf includes sites-enabled
    if ! grep -q "sites-enabled" "${NGINX_ROOT}/nginx.conf"; then
        log "Adding include directive for sites-enabled to nginx.conf"
        sed -i '/http {/a \    include /etc/nginx/sites-enabled/*.conf;' "${NGINX_ROOT}/nginx.conf"
    fi
    
    log "${GREEN}✓ Server block created at $server_block_file${NC}"
}

# Main execution flow
log "${BLUE}Starting SSL certificate setup for $DOMAIN (Environment: $ENVIRONMENT)${NC}"

# Check if certificate directory exists and if we need to create it
if [[ -d "$CERT_DIR" ]]; then
    if [[ "$FORCE" != "true" ]]; then
        log "${YELLOW}Certificate directory already exists at $CERT_DIR. Use --force to overwrite.${NC}"
        log "To use existing certificates, continue with configuration steps."
        read -p "Continue with configuration? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ && ! $REPLY == "" ]]; then
            log "${RED}Operation cancelled by user${NC}"
            exit 0
        fi
    else
        log "Certificate directory exists. Force flag detected, will overwrite certificates."
        if [[ "$DRY_RUN" != "true" ]]; then
            mkdir -p "${CERT_DIR}.bak"
            cp -a "${CERT_DIR}/"* "${CERT_DIR}.bak/"
            log "Existing certificates backed up to ${CERT_DIR}.bak/"
        else
            log "[DRY RUN] Would backup existing certificates"
        fi
    fi
else
    if [[ "$DRY_RUN" != "true" ]]; then
        mkdir -p "$CERT_DIR"
        chmod 700 "$CERT_DIR"
    else
        log "[DRY RUN] Would create certificate directory: $CERT_DIR"
    fi
fi

# Process based on certificate type
case "$CERT_TYPE" in
    "self-signed")
        create_self_signed_cert
        ;;
    "letsencrypt")
        create_letsencrypt_cert
        ;;
    "import")
        import_certificates
        ;;
    *)
        log "${RED}ERROR: Invalid certificate type: $CERT_TYPE${NC}"
        log "Valid types are: letsencrypt, self-signed, import"
        exit 1
        ;;
esac

# Generate DH parameters
generate_dhparams

# Configure SSL
configure_ssl

# Set up server block
setup_server_block

# Verify certificate
if [[ "$DRY_RUN" != "true" ]]; then
    verify_certificate
fi

# Reload NGINX
reload_nginx

if [[ "$DRY_RUN" == "true" ]]; then
    log "${YELLOW}Dry run completed. No changes were made.${NC}"
else
    log "${GREEN}✓ SSL certificate setup completed successfully for $DOMAIN${NC}"
fi

exit 0