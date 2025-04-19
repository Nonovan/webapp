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
# Generate configuration for development environment
python scripts/generate-config.py --environment development

# Generate configuration for staging environment
python scripts/generate-config.py --environment staging

# Generate configuration for production environment
python scripts/generate-config.py --environment production

```

### Testing Configuration

Before applying changes to your NGINX server, verify the configuration:

```bash
# Test the configuration
./scripts/test-config.sh --environment production

```

## Maintenance

### Updating Security Settings

The security settings can be updated by modifying the appropriate configuration files:

```bash
# Update TLS configuration
vim includes/ssl-params.conf

# Update security headers
vim includes/security-headers.conf

```

### Adding New Domains

To add a new domain:

1. Create a new server block configuration in `sites-available/`
2. Generate the environment-specific configurations
3. Test the configuration
4. Install the updated configuration

```bash
# Example for adding a new domain
cp templates/server.conf.template sites-available/new-domain.conf
vim sites-available/new-domain.conf
python scripts/generate-config.py --environment production --domain new-domain
./scripts/test-config.sh
./scripts/install-configs.sh --environment production

```

## Monitoring and Troubleshooting

### Viewing Logs

Access logs are in a standardized JSON format for easy parsing:

```bash
# View access logs
tail -f /var/log/nginx/access.log | jq

# View error logs
tail -f /var/log/nginx/error.log

```

### Common Issues

1. **403 Forbidden**: Check file permissions and ownership
2. **502 Bad Gateway**: Check upstream server connectivity
3. **Unable to restart NGINX**: Verify configuration syntax

```bash
# Quick syntax check
nginx -t

# Check specific config
nginx -t -c /path/to/nginx.conf

```

## Performance Optimization

The configuration includes several performance optimizations:

- **Caching**: Static content caching with appropriate Cache-Control headers
- **Compression**: GZIP/Brotli compression for text-based resources
- **Connection Pooling**: Optimized keepalive connection settings
- **Worker Processes**: Automatically scaled based on CPU cores

## Contributing

When contributing to the NGINX configuration:

1. Test changes in development environment first
2. Document any non-standard configurations
3. Update this README if adding new features
4. Follow the established naming conventions