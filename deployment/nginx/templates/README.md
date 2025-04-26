# NGINX Template Files

This directory contains template files used to generate environment-specific NGINX configurations for the Cloud Infrastructure Platform, ensuring consistent structure with appropriate environment-specific values.

## Contents

- Overview
- Key Templates
- Directory Structure
- Usage
- Template Variables
- Customization Guidelines
- Best Practices
- Related Files

## Overview

The NGINX template files provide standardized configuration templates that can be dynamically populated with environment-specific values to create tailored NGINX configurations for development, staging, and production environments. These templates implement a modular configuration approach with proper separation of concerns, ensuring security headers, performance optimizations, and environment-appropriate settings are consistently applied across all environments while allowing for necessary customization.

## Key Templates

- **`api.conf.template`**: API endpoint routing configuration template
  - API location blocks with environment-specific backends
  - API rate limiting with variable thresholds
  - JWT authentication settings
  - Backend connection timeouts
  - API versioning support

- **`location.conf.template`**: Location block definitions template
  - Static file serving configuration
  - Environment-specific cache headers
  - Path-based optimization rules
  - Content handling directives
  - Security controls for specific paths

- **`monitoring.conf.template`**: Health check and metrics endpoint template
  - Health check endpoint configuration
  - Environment-specific access restrictions
  - Metrics collection endpoints
  - Status reporting configuration
  - Debug endpoint conditionals

- **`proxy-params.conf.template`**: Proxy parameters template
  - Backend connection parameters
  - Header forwarding rules
  - Timeout configurations
  - Buffer settings
  - Proxy caching directives

- **`server.conf.template`**: Server block definition template
  - Domain configuration
  - Environment labeling
  - SSL/TLS settings inclusion
  - Security headers inclusion
  - Error page definitions

- **`ssl-params.conf.template`**: SSL/TLS security parameters template
  - Protocol version restrictions
  - Cipher suite configuration
  - SSL session settings
  - OCSP stapling setup
  - HTTP Strict Transport Security settings

- **`ssl.conf.template`**: SSL certificate configuration template
  - Certificate path definitions
  - Private key path definitions
  - DH parameters inclusion
  - Trusted certificate configuration
  - Certificate verification settings

- **`upstream.conf.template`**: Backend server definitions template
  - Environment-specific backend server pools
  - Load balancing configuration
  - Health check parameters
  - Connection limits
  - Failover settings

- **`websocket.conf.template`**: WebSocket connection support template
  - WebSocket protocol upgrade handling
  - Connection timeout settings
  - Header forwarding for WebSockets
  - Ping/pong frame configuration
  - Connection upgrade directives

## Directory Structure

```plaintext
deployment/nginx/templates/
├── README.md                   # This documentation
├── api.conf.template           # API endpoint routing template
├── location.conf.template      # Location block definitions template
├── monitoring.conf.template    # Health check and metrics endpoint template
├── proxy-params.conf.template  # Proxy parameters template
├── server.conf.template        # Server block definition template
├── ssl-params.conf.template    # SSL/TLS security parameters template
├── ssl.conf.template           # SSL certificate configuration template
├── upstream.conf.template      # Backend server definitions template
└── websocket.conf.template     # WebSocket connection support template
```

## Usage

These templates are processed by the generate-config.py script, which substitutes variables with environment-specific values to create configuration files in the `sites-available` directory:

```bash
# Generate configuration for production environment
./scripts/generate-config.py --environment production

# Generate configuration for staging environment
./scripts/generate-config.py --environment staging

# Generate configuration for development environment
./scripts/generate-config.py --environment development

# Generate configuration with dry-run (preview only)
./scripts/generate-config.py --environment production --dry-run
```

The generated configurations can then be installed using the install-configs.sh script:

```bash
# Install the generated configurations
./scripts/install-configs.sh --environment production
```

## Template Variables

Templates use the following variable syntax:

- `{{VARIABLE_NAME}}` - Simple variable substitution
- `{{#CONDITION}}...{{/CONDITION}}` - Conditional inclusion based on boolean value
- `{{#LIST_NAME}}...{{.}}...{{/LIST_NAME}}` - List iteration

### Common Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `ENVIRONMENT` | Deployment environment | `production` |
| `DOMAIN_NAME` | Server domain name | `cloud-platform.example.com` |
| `API_UPSTREAM` | API backend server group | `backend_api` |
| `API_TIMEOUT` | API request timeout | `60` |
| `RATE_LIMIT_BURST` | Rate limit burst setting | `20` |
| `CACHE_CONTROL` | Cache-Control header value | `public, max-age=86400` |
| `ICS_RESTRICTED_IPS` | List of IPs allowed to access ICS | `["10.0.0.0/8", "192.168.1.0/24"]` |
| `INTERNAL_HEALTH_CHECK` | Whether to enable detailed health checks | `true` |
| `SSL_CERTIFICATE_PATH` | Path to SSL certificate | `/etc/ssl/certs/cloud-platform.crt` |
| `SSL_KEY_PATH` | Path to SSL private key | `/etc/ssl/private/cloud-platform.key` |

## Customization Guidelines

When modifying these templates:

1. **Use Environment Variables**
   - Use variables for any values that differ between environments
   - Implement conditional sections for environment-specific features
   - Keep environment-specific logic in the templates, not hardcoded

2. **Maintain Modular Structure**
   - Keep templates focused on a specific concern
   - Use includes for shared functionality
   - Preserve separation between server, location, and upstream definitions

3. **Document Changes**
   - Add comments explaining non-obvious configurations
   - Document security implications of changes
   - Include references to relevant documentation

4. **Test All Environments**
   - Verify that templates work for all target environments
   - Test generated configurations with `nginx -t`
   - Check for variable substitution issues

## Best Practices

- **Security First**: Always prioritize security settings regardless of environment
- **Backward Compatibility**: Maintain compatibility with existing configurations
- **Default Values**: Provide safe default values for all variables
- **Error Handling**: Include appropriate error handling and logging directives
- **Performance Balance**: Balance security with performance considerations
- **Readability**: Format templates for readability with proper indentation and comments
- **Variable Safety**: Check that all variables are properly substituted and sanitized
- **Versioning**: Version control all template changes
- **Isolation**: Ensure proper separation between environments
- **Documentation**: Comment all template sections thoroughly

## Related Files

- Generate Config Script: Processes templates to create environment-specific configurations
- Install Configs Script: Installs generated configurations
- Configuration Modules: Include files referenced by templates
- Server Block Definitions: Output location for processed templates
- Environment Variables: Environment-specific variable definitions
