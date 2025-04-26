# SSL/TLS Security Configuration for Cloud Infrastructure Platform

This directory contains SSL/TLS security configurations for the Cloud Infrastructure Platform, providing secure communication settings for web servers and API endpoints.

## Contents

- Overview
- Key Components
- Directory Structure
- Configuration Format
- Usage and Integration
- Best Practices & Security
- Certificate Management
- Related Documentation

## Overview

The SSL/TLS security configuration provides standardized settings for establishing secure encrypted connections across the Cloud Infrastructure Platform. These configurations implement industry best practices for cipher selection, protocol versions, and security parameters following NIST guidelines, OWASP recommendations, and Mozilla's modern compatibility profiles. The implementation balances strong security with appropriate compatibility to ensure secure communications across various client types.

## Key Components

- **`ssl-params.conf`**: Core SSL/TLS security parameters configuration
  - Cipher suite selection
  - DH parameters configuration
  - HSTS implementation
  - OCSP stapling settings
  - Protocol version restrictions
  - Session security settings
  - TLS 1.3 optimization

## Directory Structure

```plaintext
deployment/security/ssl/
├── README.md                # This documentation
└── ssl-params.conf          # SSL/TLS security parameters configuration
```

## Configuration Format

The SSL/TLS configuration follows NGINX directive format:

```nginx
# Protocol settings - only allow TLS 1.2 and 1.3 (modern security)
ssl_protocols TLSv1.2 TLSv1.3;

# Cipher suite selection (optimized for security and compatibility)
ssl_prefer_server_ciphers on;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...";

# Additional security settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
```

## Usage and Integration

### Basic NGINX Integration

To integrate SSL/TLS security parameters into an NGINX configuration:

```bash
# Copy the configuration file to NGINX configuration directory
sudo cp ssl-params.conf /etc/nginx/conf.d/

# Include it in your server block
# In /etc/nginx/sites-available/your-site.conf:
server {
    listen 443 ssl http2;
    server_name example.com;

    # Include SSL parameters
    include conf.d/ssl-params.conf;

    # Specify certificate paths (override defaults in ssl-params.conf)
    ssl_certificate /etc/ssl/certs/your-site.crt;
    ssl_certificate_key /etc/ssl/private/your-site.key;

    # Rest of your configuration...
}
```

### Setup Script Integration

The SSL/TLS configuration is automatically integrated when using the `certificate_renew.sh` or setup-ssl.sh scripts:

```bash
# Set up SSL with Let's Encrypt
deployment/security/scripts/certificate_renew.sh --domain example.com --email admin@example.com

# Test the configuration
sudo nginx -t

# Apply changes
sudo systemctl reload nginx
```

## Best Practices & Security

- **Certificate Management**
  - Generate and use 4096-bit RSA keys or ECDSA keys
  - Ensure proper file permissions (600 for private keys)
  - Store private keys securely with restricted access
  - Use automation for certificate renewals
  - Verify certificate chain validity

- **Cipher Selection**
  - Choose strong, modern cipher suites (AES-GCM, ChaCha20)
  - Prioritize authenticated encryption
  - Disable weak ciphers and algorithms
  - Use Forward Secrecy capable key exchange algorithms
  - Balance security with compatibility requirements

- **Protocol Configuration**
  - Enforce TLS 1.2/1.3 only; disable older versions
  - Configure with server preference for cipher selection
  - Use strong Diffie-Hellman parameters (2048+ bits)
  - Enable OCSP stapling with reliable resolver
  - Implement security headers including HSTS

- **Testing & Validation**
  - Run regular SSL/TLS security scans
  - Test with [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
  - Verify full certificate chain trust
  - Check proper certificate naming (CN/SAN)
  - Validate configuration with `nginx -t`

## Certificate Management

### Renewal Process

SSL/TLS certificates are managed using the automated certificate renewal script:

1. Monitor certificate expiration with: `certificate_renew.sh --check-only`
2. Automatic renewal: `certificate_renew.sh`
3. Manual renewal: `certificate_renew.sh --force`

### Certificate Types

The platform supports multiple certificate types:

- **Let's Encrypt**: Automated free certificates with 90-day validity
- **Commercial CA**: Extended validation or organization validation certificates
- **Self-signed**: For development and internal use only

## Related Documentation

- Deployment Scripts Documentation
- ModSecurity WAF Configuration Guide
- NGINX Configuration Guide
- NGINX Security Hardening Guidelines
- SSL Certificate Management Guide
- SSL/TLS Best Practices
- TLS Configuration Testing Guide
- Web Application Security Guide
