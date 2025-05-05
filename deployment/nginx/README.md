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
- Python Module Integration
- Related Documentation

## Overview

The NGINX configuration implements a modular, environment-aware approach to web server and reverse proxy configuration for the Cloud Infrastructure Platform. It provides secure defaults with comprehensive security headers, TLS hardening, Web Application Firewall (WAF) protection, and optimized performance settings. The configuration separates concerns into logical modules and supports development, staging, production, and disaster recovery environments with appropriate settings for each.

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
│   ├── __init__.py          # Python package initialization
│   ├── create_dhparams.py   # Python impl. for DH parameters generation
│   ├── create-dhparams.sh   # DH parameters generation
│   ├── generate_config.py   # Environment config generation
│   ├── install_configs.py   # Python impl. for config installation
│   ├── install-configs.sh   # Config installation script
│   ├── nginx_constants.py   # Shared NGINX configuration constants
│   ├── nginx_reload.py      # Python impl. for safe config reload
│   ├── nginx-reload.sh      # Safe config reload script
│   ├── performance.py       # Python impl. for performance optimization
│   ├── performance.sh       # Performance optimization
│   ├── README.md            # Scripts documentation
│   ├── setup_modsecurity.py # Python impl. for WAF setup
│   ├── setup-modsecurity.sh # WAF setup script
│   ├── setup_ssl.py         # Python impl. for SSL certificate setup
│   ├── setup-ssl.sh         # SSL certificate setup
│   ├── test_config.py       # Python impl. for configuration testing
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
3. **Scripts**: Utility scripts in scripts for configuration management (both shell and Python)
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
   - Certificate expiration checking
   - File permission verification

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
   - CPU and memory-aware scaling

## Usage

### Generating Environment-Specific Configurations

```bash
# Generate configuration for the specified environment
./scripts/generate_config.py --environment production

# Test the generated configuration
./scripts/test_config.py

# Install the configuration
sudo ./scripts/install_configs.py --environment production
```

### Setting Up ModSecurity WAF

```bash
# Set up ModSecurity with OWASP Core Rule Set
sudo ./scripts/setup_modsecurity.py --install

# Enable ModSecurity
sudo ./scripts/setup_modsecurity.py --enable

# Test WAF configuration
curl http://localhost/health/waf
```

### Optimizing Performance

```bash
# Check current performance settings
sudo ./scripts/performance.py --environment production

# Apply optimized performance settings
sudo ./scripts/performance.py --environment production --apply
```

### Safe Configuration Reload

```bash
# Reload NGINX configuration with change detection
sudo ./scripts/nginx_reload.py --graceful

# Reload with custom timeout value
sudo ./scripts/nginx_reload.py --timeout 60

# Reload with forced restart
sudo ./scripts/nginx_reload.py --restart
```

### SSL Certificate Setup

```bash
# Generate self-signed certificate for development
./scripts/setup_ssl.py --self-signed --domain dev.example.com

# Set up Let's Encrypt certificate for production
./scripts/setup_ssl.py --letsencrypt --domain example.com --email admin@example.com
```

## Maintenance

- Health check endpoint is available at `/health` for load balancers and monitoring
- Logs are stored in `/var/log/nginx/` with custom logging formats for easier analysis
- ModSecurity WAF status is available at `/health/waf` (restricted access)
- NGINX status and metrics are available at `/nginx_status` for monitoring systems (restricted access)
- The `nginx_reload.py` script ensures safe reloads without service interruption
- SSL certificate expiration can be monitored with the `check_ssl_certs` function in `nginx_reload.py`

## Python Module Integration

The scripts directory provides a Python package that can be imported and used programmatically:

```python
from deployment.nginx.scripts import (
    # Core NGINX management
    reload_nginx, restart_nginx, check_nginx_status, verify_nginx_responding,

    # Configuration management
    install_config_files, install_environment_config, generate_config,

    # SSL/TLS utilities
    generate_dhparams, check_ssl_certs, verify_certificate,

    # Security scanning
    check_security_headers, check_security_configs, validate_nginx_installation,

    # Performance optimization
    calculate_worker_processes, calculate_worker_connections,
    generate_performance_config, apply_performance_settings
)

# Examples:
# Reload NGINX gracefully
reload_nginx(graceful=True)

# Install environment-specific configuration
install_environment_config('production', source_dir='/path/to/configs', nginx_root='/etc/nginx')

# Check SSL certificate status
certs_ok = check_ssl_certs(Path('/etc/nginx'))
```

Constants are also available for consistent configuration:

```python
from deployment.nginx.scripts.nginx_constants import (
    ENVIRONMENT_SETTINGS, DEFAULT_SSL_CIPHERS, REQUIRED_SECURITY_HEADERS,
    SECURE_SSL_PROTOCOLS, DEFAULT_RATE_LIMIT
)

# Example: Get recommended rate limit for production
prod_rate_limit = ENVIRONMENT_SETTINGS['production']['RATE_LIMIT']
```

## Related Documentation

- Let's Encrypt Documentation
- ModSecurity Reference Manual
- NGINX Official Documentation
- NGINX Performance Tuning
- OWASP ModSecurity Core Rule Set (CRS)
- Web Security Headers Guide
- Python NGINX Management Library
