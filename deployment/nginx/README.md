# NGINX Configuration for Cloud Infrastructure Platform

This directory contains the NGINX configuration files for the Cloud Infrastructure Platform, providing secure, optimized, and structured web server and reverse proxy configuration.

## Contents

- Overview
- Directory Structure
- Configuration Architecture
- Environment-Specific Configurations
- Security Features
- Performance Optimization
- Usage
- Maintenance
- Related Documentation

## Overview

The NGINX configuration implements a modular, environment-aware approach to web server and reverse proxy configuration for the Cloud Infrastructure Platform. It provides secure defaults with comprehensive security headers, TLS hardening, Web Application Firewall (WAF) protection, and optimized performance settings. The configuration separates concerns into logical modules and supports development, staging, and production environments with appropriate settings for each.

## Directory Structure

```plaintext
deployment/nginx/
├── README.md                # This documentation file
├── conf.d/                  # Configuration modules
│   ├── api.conf             # API endpoint routing
│   ├── location.conf        # Location block definitions
│   ├── monitoring.conf      # Monitoring and health check endpoints
│   ├── proxy-params.conf    # Common proxy parameters
│   ├── README.md            # conf.d documentation
│   ├── security-headers.conf # Security header definitions
│   ├── server.conf          # Main server configuration
│   ├── ssl-params.conf      # SSL parameter optimization
│   ├── ssl.conf             # SSL certificate configuration
│   ├── upstream.conf        # Upstream server definitions
│   └── websocket.conf       # WebSocket support
├── includes/                # Common include files
│   ├── bot-protection.conf  # Bot protection rules
│   ├── cache-control.conf   # Cache control directives
│   ├── cors-headers.conf    # CORS headers configuration
│   ├── logging-format.conf  # Custom logging format definitions
│   ├── proxy-params.conf    # Proxy parameter configuration
│   ├── rate-limiting.conf   # Rate limiting configuration
│   └── README.md            # Includes documentation
├── scripts/                 # Utility scripts
│   ├── create-dhparams.sh   # DH parameters generation
│   ├── generate-config.py   # Environment config generation
│   ├── install-configs.sh   # Config installation script
│   ├── nginx-reload.sh      # Safe config reload script
│   ├── performance.sh       # Performance optimization
│   ├── README.md            # Scripts documentation
│   ├── setup-modsecurity.sh # WAF setup script
│   ├── setup-ssl.sh         # SSL certificate setup
│   └── test-config.sh       # Configuration testing
├── sites-available/         # Server block definitions
│   ├── cloud-platform.conf  # Production environment config
│   ├── development.conf     # Development environment config
│   ├── dr-recovery.conf     # Disaster recovery environment config
│   ├── README.md            # Server blocks documentation
│   └── staging.conf         # Staging environment config
├── sites-enabled/           # Symlinks to enabled configurations
│   ├── README.md            # Symlinks documentation
│   └── cloud-platform.conf  # Symlink to active configuration
└── templates/               # Templates for generating configurations
    ├── api.conf.template    # API configuration template
    ├── location.conf.template # Location block template
    ├── monitoring.conf.template # Monitoring endpoints template
    ├── proxy-params.conf.template # Proxy parameters template
    ├── README.md            # Templates documentation
    ├── server.conf.template # Server block template
    ├── ssl-params.conf.template # SSL parameters template
    ├── ssl.conf.template    # SSL certificate configuration template
    ├── upstream.conf.template # Upstream configuration template
    └── websocket.conf.template # WebSocket connection support template
```

## Configuration Architecture

The NGINX configuration follows a modular approach with the following components:

1. **Configuration Modules**: Common configurations in `conf.d/` that are included in server blocks
2. **Includes**: Reusable configuration snippets in `includes/` for common patterns
3. **Scripts**: Utility scripts in scripts for configuration management
4. **Server Blocks**: Defined in `sites-available/` with environment-specific configurations
5. **Templates**: Template files in `templates/` used to generate environment-specific configurations

## Environment-Specific Configurations

The configuration supports multiple deployment environments:

1. **Development**: Optimized for local development
   - More verbose logging
   - Relaxed security settings
   - Debug headers enabled
   - Auto-reload capabilities

2. **Disaster Recovery**: Specialized configuration for DR scenarios
   - Failover backend settings
   - Minimal feature set for critical operations
   - Emergency access controls
   - Status page configurations

3. **Production**: Full security hardening and performance optimizations
   - Maximum security settings
   - Optimized performance
   - Minimal logging
   - Production backends

4. **Staging**: Similar to production but with debugging capabilities
   - Additional debug endpoints
   - Testing-specific headers
   - Staging-specific backends

## Security Features

This NGINX configuration implements several security best practices:

1. **Access Control**
   - Bot protection rules
   - Connection limiting to prevent resource exhaustion
   - IP-based access restrictions for sensitive endpoints
   - Rate limiting to prevent abuse

2. **HTTP Security Headers**
   - Content-Security-Policy (CSP)
   - Permissions-Policy
   - Referrer-Policy: strict-origin-when-cross-origin
   - Strict-Transport-Security (HSTS)
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block

3. **TLS Configuration**
   - Custom Diffie-Hellman parameters
   - HTTP Strict Transport Security (HSTS)
   - OCSP Stapling for certificate revocation checking
   - Strong cipher suites with Perfect Forward Secrecy (PFS)
   - TLS 1.2 and 1.3 only

4. **Web Application Firewall (WAF)**
   - API protection rules
   - Custom WAF rules for application-specific protections
   - ICS/SCADA-specific protection rules
   - ModSecurity integration with OWASP Core Rule Set (CRS)

## Performance Optimization

The configuration includes performance optimizations tailored to each environment:

1. **Buffer Optimization**
   - Connection keepalive settings
   - File descriptor caching
   - Optimized buffer sizes

2. **Caching and Compression**
   - Browser caching headers
   - Response compression
   - Static asset caching

3. **TCP Optimization**
   - Optimized timeouts
   - TCP keepalive
   - TCP nodelay and nopush

4. **Worker Processes and Connections**
   - Environment-specific worker configuration
   - Multi-worker setup
   - Optimized connection handling

## Usage

### Generating Environment-Specific Configurations

```bash
# Generate configuration for the specified environment
./scripts/generate-config.py --environment production

# Test the generated configuration
./scripts/test-config.sh

# Install the configuration
./scripts/install-configs.sh --environment production
```

### Setting Up ModSecurity WAF

```bash
# Set up ModSecurity with OWASP Core Rule Set
./scripts/setup-modsecurity.sh --install

# Enable ModSecurity
./scripts/setup-modsecurity.sh --enable

# Test WAF configuration
curl http://localhost/health/waf
```

### Optimizing Performance

```bash
# Check current performance settings
./scripts/performance.sh --environment production

# Apply optimized performance settings
./scripts/performance.sh --environment production --apply
```

### SSL Certificate Setup

```bash
# Generate self-signed certificate for development
./scripts/setup-ssl.sh --self-signed --domain dev.example.com

# Set up Let's Encrypt certificate for production
./scripts/setup-ssl.sh --letsencrypt --domain example.com --email admin@example.com
```

## Maintenance

- Health check endpoint is available at `/health` for load balancers and monitoring
- Logs are stored in `/var/log/nginx/` with custom logging formats for easier analysis
- ModSecurity WAF status is available at `/health/waf` (restricted access)
- NGINX status and metrics are available at `/nginx_status` for monitoring systems (restricted access)
- The nginx-reload.sh script ensures safe reloads without service interruption

## Related Documentation

- Let's Encrypt Documentation
- ModSecurity Reference Manual
- NGINX Official Documentation
- NGINX Performance Tuning
- OWASP ModSecurity Core Rule Set (CRS)
- Web Security Headers Guide
