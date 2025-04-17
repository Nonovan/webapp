#!/bin/bash
# SSL Certificate Setup Script for Cloud Infrastructure Platform
# This script automates the process of setting up SSL/TLS certificates

set -e

# Configuration variables
CONFIG_FILE="${1:-/opt/cloud-platform/config/ssl-config.conf}"
DOMAIN=""
EMAIL=""
CERT_DIR="/etc/ssl/cloud-platform"
KEY_SIZE=4096
CERT_TYPE="letsencrypt"  # Options: letsencrypt, self-signed, import
STAGING=false
FORCE_RENEWAL=false
USE_WILDCARD=false
TEST_CERT=false
NGINX_RELOAD=true
LOG_FILE="/var/log/cloud-platform/ssl-setup.log"

# Ensure log directory exists
mkdir -p $(dirname "$LOG_FILE")

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to show usage
usage() {
    echo "SSL Certificate Setup Script for Cloud Infrastructure Platform"
    echo 
    echo "Usage: $0 [config_file] [options]"
    echo
    echo "Options:"
    echo "  --domain DOMAIN     Domain name for the certificate"
    echo "  --email EMAIL       Email address for Let's Encrypt registration"
    echo "  --cert-type TYPE    Certificate type: letsencrypt, self-signed, import"
    echo "  --cert-dir DIR      Directory to store certificates"
    echo "  --key-size SIZE     Key size in bits (default: 4096)"
    echo "  --staging           Use Let's Encrypt staging environment"
    echo "  --force-renewal     Force certificate renewal"
    echo "  --wildcard          Issue wildcard certificate"
    echo "  --test              Generate test certificate"
    echo "  --no-nginx-reload   Skip NGINX reload after certificate installation"
    echo "  --help              Show this help message"
    echo
    echo "Examples:"
    echo "  $0 --domain example.com --email admin@example.com --cert-type letsencrypt"
    echo "  $0 --domain internal.example --cert-type self-signed"
    echo
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --cert-type)
            CERT_TYPE="$2"
            shift 2
            ;;
        --cert-dir)
            CERT_DIR="$2"
            shift 2
            ;;
        --key-size)
            KEY_SIZE="$2"
            shift 2
            ;;
        --staging)
            STAGING=true
            shift
            ;;
        --force-renewal)
            FORCE_RENEWAL=true
            shift
            ;;
        --wildcard)
            USE_WILDCARD=true
            shift
            ;;
        --test)
            TEST_CERT=true
            shift
            ;;
        --no-nginx-reload)
            NGINX_RELOAD=false
            shift
            ;;
        --help)
            usage
            ;;
        *)
            if [[ -f "$1" ]]; then
                CONFIG_FILE="$1"
                shift
            else
                echo "Unknown option: $1"
                usage
            fi
            ;;
    esac
done

# Load configuration from file if provided
if [[ -f "$CONFIG_FILE" ]]; then
    log "Loading configuration from $CONFIG_FILE"
    source "$CONFIG_FILE"
fi

# Validate required parameters
if [[ -z "$DOMAIN" ]]; then
    log "ERROR: Domain name is required"
    usage
fi

if [[ "$CERT_TYPE" == "letsencrypt" && -z "$EMAIL" ]]; then
    log "ERROR: Email address is required for Let's Encrypt certificates"
    usage
fi

# Create certificate directory
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# Function to create self-signed certificate
create_self_signed_cert() {
    log "Generating self-signed certificate for $DOMAIN"
    
    # Create private key
    openssl genrsa -out "$CERT_DIR/privkey.pem" $KEY_SIZE
    chmod 600 "$CERT_DIR/privkey.pem"
    
    # Create CSR config
    cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = $DOMAIN

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
EOF

    if [[ "$USE_WILDCARD" == "true" ]]; then
        echo "DNS.3 = *.$DOMAIN" >> "$CERT_DIR/openssl.cnf"
    fi
    
    # Create CSR
    openssl req -new -key "$CERT_DIR/privkey.pem" -out "$CERT_DIR/cert.csr" -config "$CERT_DIR/openssl.cnf"
    
    # Create self-signed certificate
    openssl x509 -req -days 365 -in "$CERT_DIR/cert.csr" -signkey "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/cert.pem" -extensions req_ext -extfile "$CERT_DIR/openssl.cnf"
    
    # Create fullchain (for self-signed this is the same as cert)
    cp "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem"
    
    log "Self-signed certificate generated successfully"
    
    # Display certificate information
    openssl x509 -in "$CERT_DIR/cert.pem" -text -noout | head -10
}

# Function to create Let's Encrypt certificate using certbot
create_letsencrypt_cert() {
    log "Requesting Let's Encrypt certificate for $DOMAIN"
    
    # Check if certbot is installed
    if ! command -v certbot &> /dev/null; then
        log "ERROR: certbot is not installed. Please install it first."
        exit 1
    fi
    
    # Build certbot command
    certbot_cmd="certbot certonly --webroot -w /var/www/html"
    
    if [[ "$STAGING" == "true" ]]; then
        certbot_cmd="$certbot_cmd --staging"
    fi
    
    if [[ "$FORCE_RENEWAL" == "true" ]]; then
        certbot_cmd="$certbot_cmd --force-renewal"
    fi
    
    if [[ "$USE_WILDCARD" == "true" ]]; then
        # For wildcard certificates we need to use DNS challenge
        certbot_cmd="certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini"
        DOMAIN="*.$DOMAIN"
    fi
    
    # Add domain and email
    certbot_cmd="$certbot_cmd -d $DOMAIN -d www.$DOMAIN --email $EMAIL --agree-tos --non-interactive"
    
    # Run certbot
    log "Running certbot: $certbot_cmd"
    eval $certbot_cmd
    
    # Copy certificates to our directory
    letsencrypt_live_dir="/etc/letsencrypt/live/$DOMAIN"
    if [[ -d "$letsencrypt_live_dir" ]]; then
        cp "$letsencrypt_live_dir/privkey.pem" "$CERT_DIR/"
        cp "$letsencrypt_live_dir/cert.pem" "$CERT_DIR/"
        cp "$letsencrypt_live_dir/chain.pem" "$CERT_DIR/"
        cp "$letsencrypt_live_dir/fullchain.pem" "$CERT_DIR/"
        chmod 600 "$CERT_DIR/privkey.pem"
        log "Let's Encrypt certificate installed successfully"
    else
        log "ERROR: Let's Encrypt certificates not found at $letsencrypt_live_dir"
        exit 1
    fi
}

# Function to import existing certificate
import_certificate() {
    log "Importing existing certificate for $DOMAIN"
    
    # Prompt for certificate files
    read -p "Enter path to private key file: " privkey_path
    read -p "Enter path to certificate file: " cert_path
    read -p "Enter path to certificate chain file (or press Enter to skip): " chain_path
    
    # Validate files
    if [[ ! -f "$privkey_path" ]]; then
        log "ERROR: Private key file not found: $privkey_path"
        exit 1
    fi
    
    if [[ ! -f "$cert_path" ]]; then
        log "ERROR: Certificate file not found: $cert_path"
        exit 1
    fi
    
    # Copy files
    cp "$privkey_path" "$CERT_DIR/privkey.pem"
    cp "$cert_path" "$CERT_DIR/cert.pem"
    chmod 600 "$CERT_DIR/privkey.pem"
    
    if [[ -f "$chain_path" ]]; then
        cp "$chain_path" "$CERT_DIR/chain.pem"
        cat "$cert_path" "$chain_path" > "$CERT_DIR/fullchain.pem"
    else
        cp "$cert_path" "$CERT_DIR/fullchain.pem"
    fi
    
    log "Certificate imported successfully"
    
    # Validate certificate and key match
    cert_modulus=$(openssl x509 -noout -modulus -in "$CERT_DIR/cert.pem")
    key_modulus=$(openssl rsa -noout -modulus -in "$CERT_DIR/privkey.pem")
    
    if [[ "$cert_modulus" != "$key_modulus" ]]; then
        log "ERROR: The certificate and private key do not match"
        exit 1
    else
        log "Certificate and private key match verified"
    fi
}

# Function to create test certificate
create_test_certificate() {
    log "Generating test certificate for $DOMAIN"
    
    # Create private key
    openssl genrsa -out "$CERT_DIR/privkey.pem" 2048
    chmod 600 "$CERT_DIR/privkey.pem"
    
    # Create CSR config
    cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = Test Certificate
O = Cloud Infrastructure Platform
OU = Testing

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Create CSR
    openssl req -new -key "$CERT_DIR/privkey.pem" -out "$CERT_DIR/cert.csr" -config "$CERT_DIR/openssl.cnf"
    
    # Create test certificate valid for 30 days
    openssl x509 -req -days 30 -in "$CERT_DIR/cert.csr" -signkey "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/cert.pem" -extensions req_ext -extfile "$CERT_DIR/openssl.cnf"
    
    # Create fullchain
    cp "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem"
    
    log "Test certificate generated successfully (valid for 30 days)"
}

# Function to configure NGINX
configure_nginx() {
    log "Configuring NGINX with new certificate"
    
    # Check if NGINX is installed
    if ! command -v nginx &> /dev/null; then
        log "NGINX not found, skipping configuration"
        return
    }
    
    # Create SSL parameters configuration if it doesn't exist
    if [[ ! -f "/etc/nginx/conf.d/ssl-params.conf" ]]; then
        cat > "/etc/nginx/conf.d/ssl-params.conf" <<EOF
# SSL parameters for Cloud Infrastructure Platform
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOF
    fi
    
    # Check for existing site configuration
    nginx_conf="/etc/nginx/sites-available/$DOMAIN.conf"
    if [[ ! -f "$nginx_conf" ]]; then
        log "Creating NGINX configuration for $DOMAIN"
        cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    
    # Redirect all HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
    
    # Allow Let's Encrypt validation
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;
    
    # SSL certificate
    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    
    # Include SSL parameters
    include /etc/nginx/conf.d/ssl-params.conf;
    
    # Include security hardening configuration
    include /etc/nginx/conf.d/security-headers.conf;
    
    # Application configuration
    root /var/www/html;
    index index.html;
    
    # API proxy
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    # Static files
    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
    else
        log "Updating NGINX configuration with new certificate paths"
        sed -i "s|ssl_certificate .*|ssl_certificate $CERT_DIR/fullchain.pem;|" "$nginx_conf"
        sed -i "s|ssl_certificate_key .*|ssl_certificate_key $CERT_DIR/privkey.pem;|" "$nginx_conf"
    fi
    
    # Create symlink in sites-enabled if it doesn't exist
    if [[ ! -f "/etc/nginx/sites-enabled/$DOMAIN.conf" ]]; then
        ln -s "$nginx_conf" "/etc/nginx/sites-enabled/$DOMAIN.conf"
    fi
    
    # Test NGINX configuration
    log "Testing NGINX configuration"
    nginx -t
    
    # Reload NGINX if configuration test passes
    if [[ $? -eq 0 && "$NGINX_RELOAD" == "true" ]]; then
        log "Reloading NGINX"
        systemctl reload nginx
    fi
}

# Function to display certificate information
display_cert_info() {
    if [[ -f "$CERT_DIR/cert.pem" ]]; then
        log "Certificate information:"
        openssl x509 -in "$CERT_DIR/cert.pem" -noout -text | grep -E 'Subject:|Issuer:|Not Before:|Not After :|DNS:'
        
        # Calculate days until expiry
        expiry_date=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s)
        current_epoch=$(date +%s)
        days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        log "Certificate will expire in $days_left days"
    else
        log "Certificate not found at $CERT_DIR/cert.pem"
    fi
}

# Main execution
log "Starting SSL certificate setup for $DOMAIN"

# Create certificate based on type
case "$CERT_TYPE" in
    "self-signed")
        create_self_signed_cert
        ;;
    "letsencrypt")
        create_letsencrypt_cert
        ;;
    "import")
        import_certificate
        ;;
    *)
        if [[ "$TEST_CERT" == "true" ]]; then
            create_test_certificate
        else
            log "ERROR: Invalid certificate type: $CERT_TYPE"
            usage
        fi
        ;;
esac

# Configure NGINX
configure_nginx

# Display certificate information
display_cert_info

log "SSL certificate setup completed successfully"
exit 0