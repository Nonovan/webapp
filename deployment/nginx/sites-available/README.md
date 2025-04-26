# NGINX Server Blocks Configuration

This directory contains NGINX server block configurations for different environments of the Cloud Infrastructure Platform. These configuration files define virtual hosts, domain mappings, SSL settings, and location-specific routing rules.

## Contents

- Overview
- Environment-Specific Configurations
- File Structure
- Usage
- Best Practices & Security
- Common Patterns
- Related Documentation

## Overview

The server block configurations implement environment-specific virtual hosts for the Cloud Infrastructure Platform, providing proper domain routing, SSL/TLS settings, security headers, and location-specific behavior. Each environment (development, staging, production) maintains its own configuration with appropriate security settings, logging levels, and backend service connections while sharing common patterns for consistency.

## Environment-Specific Configurations

- **`cloud-platform.conf`**: Production environment server block
  - Strict security settings
  - Production backend endpoints
  - Optimized performance settings
  - Minimal logging configuration
  - Full security header implementation
  - Comprehensive WAF protection

- **`development.conf`**: Development environment server block
  - Development-friendly settings
  - Local backend services
  - Enhanced debugging capabilities
  - Verbose logging
  - Relaxed security for development convenience
  - Hot reload support

- **`dr-recovery.conf`**: Disaster recovery environment server block
  - Failover backend configurations
  - High availability settings
  - Minimal feature set for critical operations
  - Emergency access controls
  - Status page configurations
  - Specialized routing for DR mode

- **`staging.conf`**: Pre-production testing environment server block
  - Testing-oriented configuration
  - Staging backend endpoints
  - Enhanced logging for diagnostics
  - Production-like security with testing allowances
  - Testing-specific endpoints
  - Monitoring integration

## File Structure

```plaintext
deployment/nginx/sites_available/
├── README.md               # This documentation
├── cloud-platform.conf     # Production environment server block
├── development.conf        # Development environment server block
├── dr-recovery.conf        # Disaster recovery environment server block
└── staging.conf            # Staging environment server block
```

## Usage

These server block configurations are designed to be installed to NGINX's `sites-available` directory and enabled by creating symlinks in the `sites-enabled` directory using the installation script:

```bash
# Install the appropriate environment configuration
sudo ./scripts/install-configs.sh --environment production

# Install staging environment configuration
sudo ./scripts/install-configs.sh --environment staging

# Install development environment configuration
sudo ./scripts/install-configs.sh --environment development

# Install disaster recovery environment configuration
sudo ./scripts/install-configs.sh --environment dr-recovery
```

After installation, verify the configuration:

```bash
# Test the installed configuration
sudo nginx -t

# Reload NGINX to apply changes
sudo systemctl reload nginx
```

## Best Practices & Security

- **Authentication**: Implement proper authentication for sensitive endpoints
- **Basic Auth**: Use basic auth for maintenance and admin interfaces when appropriate
- **CORS Settings**: Define appropriate CORS headers per domain
- **Diffie-Hellman Parameters**: Use custom DH parameters for improved TLS security
- **Error Pages**: Include custom error pages for consistent user experience
- **HTTP/2 Support**: Enable HTTP/2 for improved performance
- **HSTS Headers**: Include HTTP Strict Transport Security headers
- **HTTPS Redirection**: Always redirect HTTP to HTTPS
- **IP Restrictions**: Apply IP restrictions for sensitive management endpoints
- **ModSecurity WAF**: Include ModSecurity WAF for critical paths
- **Rate Limiting**: Implement rate limiting for login and API endpoints
- **Security Headers**: Include comprehensive security headers
- **TLS Configuration**: Use secure TLS protocols and ciphers

## Common Patterns

### Domain Configuration with SSL

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # Include SSL configuration
    include conf.d/ssl.conf;

    # Include security headers
    include conf.d/security-headers.conf;

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # Main location block
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### API Proxy Configuration

```nginx
# API endpoints
location /api/ {
    # Include proxy settings
    include conf.d/proxy-params.conf;

    # Include CORS headers
    include includes/cors-headers.conf;

    # Rate limiting
    limit_req zone=api burst=10;

    # Proxy to backend
    proxy_pass http://api_backend;
}
```

### Environment-Specific Settings

```nginx
# Development-specific settings
set $environment "development";

# Enhanced logging in development
error_log /var/log/nginx/error.log debug;
access_log /var/log/nginx/access.log detailed;

# Enable auto reload for development
location /livereload/ {
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_pass http://localhost:35729/;
}
```

## Related Documentation

- NGINX Configuration Guide
- NGINX Server Block Documentation
- NGINX SSL Configuration
- NGINX Security Best Practices
- ModSecurity WAF Integration
- NGINX Location Block Reference
