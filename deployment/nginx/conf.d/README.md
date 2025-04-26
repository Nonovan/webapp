# NGINX Configuration Modules

This directory contains modular NGINX configuration files for the Cloud Infrastructure Platform, providing organized and reusable configuration components for various aspects of the web server functionality.

## Contents

- Overview
- Key Components
- File Structure
- Usage
- Configuration Guidelines
- Security Features
- Related Documentation

## Overview

The NGINX configuration modules implement a modular approach to server configuration, separating distinct functionality into individual files. These modules are included in the main server blocks and provide reusable configuration patterns for API routing, security headers, SSL/TLS settings, and other server functionality. The modular approach improves maintainability, promotes reuse, and simplifies environment-specific configurations.

## Key Components

- **`api.conf`**: API endpoint routing configuration
  - RESTful API endpoint definitions
  - API version routing
  - API rate limiting rules
  - API-specific headers
  - Backend proxy configuration for API services

- **`location.conf`**: Location block definitions for static content and applications
  - Static file serving configuration
  - Application routing rules
  - Path-specific optimizations
  - Cache control directives
  - File type handling

- **`monitoring.conf`**: Health check and monitoring endpoint configuration
  - Health check endpoints for load balancers
  - Prometheus metrics exposure
  - Status endpoints for monitoring systems
  - Restricted access controls for monitoring
  - Custom logging for monitoring endpoints

- **`proxy-params.conf`**: Common proxy parameters for backend services
  - Header forwarding configuration
  - Timeout settings
  - Buffer size optimization
  - Connection settings
  - Error handling for proxied requests

- **`security-headers.conf`**: Security-related HTTP headers
  - Content Security Policy (CSP) configuration
  - Cross-Origin Resource Sharing (CORS) settings
  - X-Frame-Options and XSS protection
  - HTTP Strict Transport Security (HSTS)
  - Referrer Policy configuration

- **`server.conf`**: Main server block configuration
  - Server name and listening ports
  - Root directory configuration
  - Default error page settings
  - Log format and location
  - Global server settings

- **`ssl-params.conf`**: SSL/TLS protocol and cipher configuration
  - Protocol version settings
  - Cipher suite configuration
  - OCSP stapling setup
  - SSL session cache settings
  - Diffie-Hellman parameters

- **`ssl.conf`**: SSL certificate and key configuration
  - Certificate file paths
  - Private key file paths
  - Trusted CA certificate chains
  - Certificate verification settings
  - SSL error handling

- **`upstream.conf`**: Backend server pool definitions
  - Application server definitions
  - Load balancing configuration
  - Server health checks
  - Connection limits
  - Failover behavior

- **`websocket.conf`**: WebSocket connection support
  - WebSocket proxy configuration
  - Timeout settings for WebSocket connections
  - Connection upgrade handling
  - WebSocket-specific headers
  - Ping/pong frame configuration

## File Structure

```plaintext
conf.d/
├── api.conf             # API endpoint routing configuration
├── location.conf        # Location block definitions for static content
├── monitoring.conf      # Health check and monitoring endpoints
├── proxy-params.conf    # Common proxy parameters for backend services
├── README.md            # This documentation
├── security-headers.conf # Security-related HTTP header configuration
├── server.conf          # Main server block configuration
├── ssl-params.conf      # SSL/TLS protocol and cipher configuration
├── ssl.conf             # SSL certificate and key configuration
├── upstream.conf        # Backend server pool definitions
└── websocket.conf       # WebSocket connection support
```

## Usage

These configuration modules are imported into the main server configuration files in `sites-available/` using the include directive:

```nginx
# Example of including configuration modules in a server block
server {
    listen 443 ssl http2;
    server_name example.com;

    # Include SSL configuration
    include conf.d/ssl.conf;
    include conf.d/ssl-params.conf;

    # Include security headers
    include conf.d/security-headers.conf;

    # Include API configuration
    include conf.d/api.conf;

    # Include monitoring endpoints
    include conf.d/monitoring.conf;

    # Include WebSocket support for specific paths
    location /ws/ {
        include conf.d/websocket.conf;
    }
}
```

## Configuration Guidelines

When modifying these configuration modules:

1. **Maintain Modularity**
   - Keep related configuration in the appropriate file
   - Avoid duplicating configuration across files
   - Create new modules for distinct functionality

2. **Environment Awareness**
   - Use variables for environment-specific values
   - Keep configuration compatible across environments
   - Document environment-specific considerations

3. **Security First**
   - Follow security best practices
   - Use secure defaults
   - Document security implications of settings

4. **Performance Optimization**
   - Balance security with performance
   - Consider caching implications
   - Optimize buffer and timeout settings

5. **Documentation**
   - Comment complex or non-obvious settings
   - Include references to external documentation
   - Document any dependencies between modules

## Security Features

Each configuration module implements appropriate security controls:

- **API Configuration**: Rate limiting, validation headers, request restrictions
- **Location Configuration**: Directory access controls, symbolic link restrictions
- **Monitoring**: Access restrictions for sensitive endpoints
- **Proxy Parameters**: Header filtering, timeout controls, buffer limitations
- **Security Headers**: CSP, CORS, anti-XSS, and clickjacking protection
- **SSL Parameters**: Modern cipher configuration, secure protocol versions
- **WebSocket**: Origin validation, connection timeout limits

## Related Documentation

- NGINX Core Documentation
- HTTP Security Headers Guide
- Proxy Module Documentation
- SSL Configuration Best Practices
- NGINX Load Balancing Guide
- WebSocket Proxy Configuration
