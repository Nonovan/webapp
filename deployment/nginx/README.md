# NGINX Configuration for Cloud Infrastructure Platform

This directory contains the NGINX configuration files for the Cloud Infrastructure Platform, providing secure, optimized, and structured web server and reverse proxy configuration.

## Directory Structure

```
deployment/nginx/
├── README.md                  # This documentation file
├── conf.d/                    # Configuration modules
│   ├── api.conf               # API endpoint routing
│   ├── monitoring.conf        # Monitoring and health check endpoints
│   ├── security-headers.conf  # Symlink to security headers in security/
│   ├── ssl-params.conf        # Symlink to SSL parameters in security/
│   ├── ssl.conf               # SSL configuration
│   └── websocket.conf         # WebSocket support
├── sites-available/           # Server block definitions
│   ├── cloud-platform.conf    # Production environment configuration
│   ├── staging.conf           # Staging environment configuration
│   └── development.conf       # Development environment configuration
├── includes/                  # Common include files
│   ├── proxy-params.conf      # Common proxy parameters
│   ├── cors-headers.conf      # CORS headers
│   ├── rate-limiting.conf     # Rate limiting configuration
│   ├── cache-control.conf     # Cache control directives
│   └── logging-format.conf    # Custom logging format definitions
├── templates/                 # Templates for generating configurations
│   ├── server.conf.template   # Server block template
│   └── location.conf.template # Location block template
└── scripts/                   # Utility scripts
    ├── generate-config.py     # Generate environment-specific configs
    ├── test-config.sh         # Test NGINX configuration
    └── install-configs.sh     # Install NGINX configurations

```

## Configuration Architecture

The NGINX configuration follows a modular approach with the following components:

1. **Server Blocks**: Defined in `sites-available/` with environment-specific configurations
2. **Configuration Modules**: Common configurations in `conf.d/` that are included in server blocks
3. **Includes**: Reusable configuration snippets in `includes/` for common patterns
4. **Security**: Security configurations linked from the central security directory

## Security Features

This NGINX configuration implements several security best practices:

- **HTTP Security Headers**: Using symlinks to the central security headers configuration
- **TLS Hardening**: SSL/TLS configuration following industry best practices
- **Rate Limiting**: Protection against abuse and DDoS attacks
- **IP Restrictions**: Limiting access to sensitive endpoints
- **Content Security Policy**: Preventing XSS attacks
- **WAF Integration**: Configuration for ModSecurity Web Application Firewall

## Usage

### Installing Configuration

To install the NGINX configuration files:

```bash
# Run the installation script
./scripts/install-configs.sh --environment production

```

### Generating Environment-Specific Configurations

To generate configurations for different environments:

```bash
# Generate configuration for a specific environment
./scripts/generate-config.py --environment staging --output-dir /etc/nginx/

```

### Testing Configuration

Before applying changes, test the configuration:

```bash
# Test the configuration
./scripts/test-config.sh /etc/nginx/nginx.conf

```

## Environments

The configuration supports the following environments:

- **Production**: High-performance, strict security settings
- **Staging**: Nearly identical to production for pre-deployment validation
- **Development**: Relaxed settings for local development with debugging enabled

## Integration with Other Components

- **Security**: Works with security configurations for centralized security management
- **SSL Certificates**: Integrates with certificate management from [ssl-setup.sh](http://ssl-setup.sh/)
- **WAF Rules**: Uses ModSecurity rules from modsecurity-rules.conf
- **Application Backend**: Proxies to the Flask application running as a WSGI service

## Maintenance

Regular tasks for maintaining this configuration:

1. **SSL Certificate Renewal**: Automated with Let's Encrypt or manual with [ssl-setup.sh](http://ssl-setup.sh/)
2. **Security Header Updates**: Update the security headers configuration when new best practices emerge
3. **Performance Tuning**: Adjust worker processes, connection limits, and buffer sizes based on traffic
4. **Log Rotation**: Ensure log files are properly rotated to prevent disk space issues

## Troubleshooting

Common issues and resolutions:

- **502 Bad Gateway**: Check if the backend application is running
- **SSL Certificate Errors**: Verify certificate paths and permissions
- **Permission Denied**: Check NGINX user and file ownership/permissions
- **Rate Limiting Too Strict**: Adjust burst and rate settings in rate-limiting.conf

For more detailed information, refer to the Cloud Infrastructure Platform Deployment Documentation.