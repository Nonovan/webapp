# NGINX Configuration for Cloud Infrastructure Platform

This directory contains the NGINX configuration files for the Cloud Infrastructure Platform, providing secure, optimized, and structured web server and reverse proxy configuration.

## Directory Structure

```

deployment/nginx/
├── [README.md](http://readme.md/)                  # This documentation file
├── conf.d/                    # Configuration modules
│   ├── api.conf               # API endpoint routing
│   ├── monitoring.conf        # Monitoring and health check endpoints
│   ├── proxy-params.conf      # Common proxy parameters
│   ├── security-headers.conf  # Symlink to security headers in security/
│   ├── ssl-params.conf        # Symlink to SSL parameters in security/
│   ├── ssl.conf               # SSL configuration
│   └── websocket.conf         # WebSocket support
├── sites-available/           # Server block definitions
│   ├── cloud-platform.conf    # Production environment configuration
│   ├── staging.conf           # Staging environment configuration
│   └── development.conf       # Development environment configuration
├── sites-enabled/             # Symlinks to enabled configurations
│   └── cloud-platform.conf    # Symlink to the active configuration
├── includes/                  # Common include files
│   ├── cors-headers.conf      # CORS headers
│   ├── rate-limiting.conf     # Rate limiting configuration
│   ├── cache-control.conf     # Cache control directives
│   ├── location.conf          # Common location blocks
│   └── logging-format.conf    # Custom logging format definitions
├── templates/                 # Templates for generating configurations
│   ├── server.conf.template   # Server block template
│   ├── api.conf.template      # API configuration template
│   ├── ssl.conf.template      # SSL configuration template
│   ├── ssl-params.conf.template # SSL parameters template
│   ├── monitoring.conf.template # Monitoring endpoints template
│   ├── proxy-params.conf.template # Proxy parameters template
│   ├── websocket.conf.template # WebSocket configuration template
│   ├── upstream.conf.template  # Upstream configuration template
│   └── location.conf.template # Location block template
├── security/                  # Security-specific configurations
│   ├── modsecurity.conf       # ModSecurity WAF configuration
│   └── waf-rules/             # Custom WAF rules directory
└── scripts/                   # Utility scripts
├── [generate-config.py](http://generate-config.py/)     # Generate environment-specific configs
├── [nginx-reload.sh](http://nginx-reload.sh/)        # Safely reload NGINX configuration
├── [test-config.sh](http://test-config.sh/)         # Test NGINX configuration
├── [setup-modsecurity.sh](http://setup-modsecurity.sh/)   # Set up ModSecurity WAF
└── [install-configs.sh](http://install-configs.sh/)     # Install NGINX configurations

```

## Configuration Architecture

The NGINX configuration follows a modular approach with the following components:

1. **Server Blocks**: Defined in `sites-available/` with environment-specific configurations
2. **Configuration Modules**: Common configurations in `conf.d/` that are included in server blocks
3. **Includes**: Reusable configuration snippets in `includes/` for common patterns
4. **Templates**: Template files in `templates/` used to generate environment-specific configurations
5. **Security**: Security configurations and WAF rules in the `security/` directory

## Security Features

This NGINX configuration implements several security best practices:

1. **TLS Configuration**:
   - TLS 1.2 and 1.3 only
   - Strong cipher suites with PFS (Perfect Forward Secrecy)
   - HSTS (HTTP Strict Transport Security)
   - OCSP Stapling for certificate revocation checking

2. **HTTP Headers**:
   - Content-Security-Policy (CSP)
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Referrer-Policy: strict-origin-when-cross-origin

3. **Access Control**:
   - Rate limiting to prevent abuse
   - IP-based access restrictions for sensitive endpoints
   - Connection limiting to prevent resource exhaustion

4. **WAF Integration**:
   - ModSecurity integration with OWASP Core Rule Set (CRS)
   - Custom WAF rules for application-specific protections

## Deployment Environments

The configuration supports three deployment environments:

1. **Development**: Optimized for local development with more verbose logging and relaxed security
2. **Staging**: Similar to production but with specific staging settings and debugging capabilities
3. **Production**: Full security hardening and performance optimizations

## Using the Configuration

### Generating Environment-Specific Configurations

```bash
# Generate configuration for the specified environment
./scripts/generate-config.py --environment production

# Test the generated configuration
./scripts/test-config.sh

# Install the configuration
./scripts/install-configs.sh

```

### Modifying the Configuration

1. Edit the template files in the `templates/` directory
2. Run the generation script to create updated configurations
3. Test and install the new configurations

## Maintenance and Monitoring

- NGINX status and metrics are available at `/nginx_status` for monitoring systems (restricted access)
- Health check endpoint is available at `/health` for load balancers and monitoring
- Logs are stored in `/var/log/nginx/` with custom logging formats for easier analysis
- The [nginx-reload.sh](http://nginx-reload.sh/) script ensures safe reloads without service interruption

## Contributing

When contributing to the NGINX configuration:

1. Test changes in development environment first
2. Document any non-standard configurations
3. Update this README if adding new features
4. Follow the established naming conventions