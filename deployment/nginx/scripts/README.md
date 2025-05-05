# NGINX Script Utilities

This directory contains utility scripts for managing, configuring, and optimizing NGINX installations for the Cloud Infrastructure Platform. These scripts support environment-specific configurations, security enhancements, and performance tuning.

## Contents

- Overview
- Key Scripts
- Usage Examples
- Best Practices & Security
- Common Features
- Related Documentation

## Overview

The NGINX script utilities provide automation for critical NGINX server management tasks including configuration generation, SSL certificate setup, ModSecurity WAF installation, performance tuning, and safe configuration reloading. These scripts implement best practices for security hardening, performance optimization, and cross-environment compatibility, enabling reliable and consistent NGINX deployments across development, staging, and production environments.

## Key Scripts

- **`create-dhparams.sh`**: Generates secure Diffie-Hellman parameters
  - Configurable key size (2048/4096)
  - Automatic nginx.conf integration
  - Secure file permissions
  - SSL configuration update
  - Configuration testing after changes

- **`generate-config.py`**: Produces environment-specific NGINX configurations
  - Environment-aware template processing
  - Variable substitution
  - Configuration organization
  - Multi-environment support (development/staging/production/dr-recovery)
  - Template validation

- **`install-configs.sh`** / **`install_configs.py`**: Installs and activates NGINX configuration files
  - Configuration backup
  - Environment-specific installations
  - Configuration testing
  - Safe NGINX reloading
  - Dry-run capability
  - Symlink management

- **`nginx-reload.sh`** / **`nginx_reload.py`**: Safely reloads NGINX configuration
  - Change detection
  - Configuration testing
  - Configuration backup
  - Graceful reload
  - Service health verification
  - SSL certificate checking
  - Certificate expiration warning

- **`performance.sh`** / **`performance.py`**: Optimizes NGINX performance settings
  - Environment-specific tuning
  - CPU and memory-aware configuration
  - Worker process optimization
  - Connection handling tuning
  - Buffer size optimization
  - Current configuration analysis

- **`setup-modsecurity.sh`** / **`setup_modsecurity.py`**: Installs and configures ModSecurity WAF
  - OWASP Core Rule Set integration
  - Custom WAF rules installation
  - Rule updates
  - Environment-specific configuration
  - WAF status endpoint
  - Log rotation setup

- **`setup-ssl.sh`**: Configures SSL/TLS certificates for NGINX
  - Let's Encrypt integration
  - Self-signed certificate generation
  - Certificate import capability
  - Security header configuration
  - DH parameter integration
  - Server block generation

- **`test-config.sh`** / **`test_config.py`**: Verifies NGINX configuration correctness and security
  - Syntax validation
  - Security header verification
  - SSL/TLS version checking
  - Certificate validation
  - WAF configuration check
  - Common security issues detection
  - JSON reporting option

## Usage Examples

### Certificate Management

```bash
# Generate secure Diffie-Hellman parameters
sudo ./create-dhparams.sh --bits 4096

# Set up Let's Encrypt certificate
sudo ./setup-ssl.sh --domain example.com --email admin@example.com --cert-type letsencrypt

# Generate self-signed certificate for development
sudo ./setup-ssl.sh --domain dev.example.com --cert-type self-signed --environment development
```

### Configuration Management

```bash
# Generate environment-specific configuration
./generate-config.py --environment production

# Install configuration for production
sudo ./install-configs.sh --environment production

# Install configuration in dry-run mode
sudo ./install-configs.sh --environment staging --dry-run

# Test configuration
sudo ./test-config.sh
```

### ModSecurity WAF Management

```bash
# Set up ModSecurity with OWASP Core Rule Set
sudo ./setup-modsecurity.sh --install

# Enable ModSecurity
sudo ./setup-modsecurity.sh --enable

# Update WAF rules
sudo ./setup-modsecurity.sh --rules-update
```

### Performance Optimization and Maintenance

```bash
# Check recommended performance settings for production
sudo ./performance.sh --environment production

# Apply optimized settings
sudo ./performance.sh --environment production --apply

# Safely reload NGINX
sudo ./nginx-reload.sh --graceful

# Using Python implementation with timeout
sudo python3 nginx_reload.py --graceful --timeout 60
```

### Testing and Validation

```bash
# Test configuration and generate JSON report
sudo ./test_config.py --json --output report.json

# Validate configuration with strict mode
sudo ./test_config.py --strict
```

## Best Practices & Security

- **Backup Management**: All scripts create backups before making changes
- **Certificate Handling**: Proper key storage and secure certificate management
- **Configuration Testing**: Validate configuration before applying changes
- **Environment Awareness**: Apply appropriate settings based on environment
- **Error Handling**: Proper error detection and reporting
- **File Permissions**: Maintain secure file permissions for sensitive files
- **Graceful Operations**: Maintain service availability during changes
- **Isolation**: Environment-specific configurations with appropriate isolation
- **Key Size Selection**: Use appropriate key sizes for different environments
- **WAF Protection**: Implement and test WAF rules to protect applications

## Common Features

These scripts share several common features:

- **Backup Creation**: Automatic backup of configurations before changes
- **Color-Coded Output**: Clear visual distinction in terminal output
- **Comprehensive Logging**: Detailed output for troubleshooting
- **Confirmation Prompts**: User confirmation for potentially breaking changes
- **Dry-Run Mode**: Preview changes without applying them
- **Environment Detection**: Adapt behavior based on environment (development, staging, production, dr-recovery)
- **Error Reporting**: Clear and helpful error messages
- **Force Options**: Override safety checks when necessary
- **Status Reporting**: Report operation status and next steps
- **Testing Integration**: Configuration testing before application

## Related Documentation

- Let's Encrypt Documentation
- ModSecurity Reference Manual
- NGINX Configuration Guide
- NGINX Performance Tuning
- OWASP ModSecurity Core Rule Set Documentation
- SSL/TLS Best Practices
- Web Application Security Guide
