# NGINX Include Files

This directory contains reusable NGINX configuration includes for the Cloud Infrastructure Platform, providing modular configuration snippets that can be included in multiple server blocks and locations.

## Contents

- Overview
- Key Components
- File Structure
- Usage
- Configuration Guidelines
- Security Considerations
- Related Documentation

## Overview

The NGINX includes directory contains specialized configuration snippets that implement specific functionalities such as bot protection, cache control directives, CORS headers, logging formats, proxy parameters, and rate limiting. These files are designed to be included within server and location blocks across different environment-specific configurations, promoting reuse and consistency while enabling granular control over web server behavior.

## Key Components

- **`bot-protection.conf`**: Rules to identify and manage bot traffic
  - Bot detection patterns
  - Crawler rate limiting
  - User agent filtering
  - Good bot allowlisting
  - Malicious bot blocking rules

- **`cache-control.conf`**: Browser and proxy cache configuration
  - Asset-specific cache policies
  - Cache header management
  - Browser cache directives
  - Cache-control headers
  - ETag and Last-Modified handling

- **`cors-headers.conf`**: Cross-Origin Resource Sharing configuration
  - Access-Control-Allow-Origin settings
  - Allowed HTTP methods
  - Allowed HTTP headers
  - Credentials handling
  - Preflight request configuration

- **`logging-format.conf`**: Enhanced logging format definitions
  - Detailed request logging
  - JSON formatted logs
  - Performance metrics
  - Security-focused logging
  - User tracking information

- **`proxy-params.conf`**: Common reverse proxy parameters
  - Header forwarding configuration
  - Proxy buffer settings
  - Timeout configuration
  - Connection management
  - SSL parameters for proxying

- **`rate-limiting.conf`**: Request rate limiting configuration
  - IP-based rate limiting
  - Endpoint-specific limits
  - Burst handling
  - Rate limit zone definitions
  - Throttling configurations

## File Structure

```plaintext
deployment/nginx/includes/
├── bot-protection.conf  # Bot traffic handling rules
├── cache-control.conf   # Browser and proxy caching directives
├── cors-headers.conf    # Cross-origin resource sharing settings
├── logging-format.conf  # Custom log format definitions
├── proxy-params.conf    # Proxy parameters for backend services
├── rate-limiting.conf   # Request rate limiting configuration
└── README.md            # This documentation
```

## Usage

These include files are designed to be referenced from within server and location blocks in NGINX configurations:

### Bot Protection

```nginx
server {
    # Include bot protection for the entire server
    include includes/bot-protection.conf;

    location /api/ {
        # More restrictive bot rules for API endpoints
        include includes/bot-protection.conf;
        limit_req zone=api_limit burst=10 nodelay;
    }
}
```

### Caching Configuration

```nginx
# For static assets
location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$ {
    include includes/cache-control.conf;
}

# For API responses with different caching strategy
location /api/ {
    include includes/cache-control.conf;
    add_header Cache-Control "private, max-age=0, no-cache";
}
```

### CORS Headers

```nginx
# Allow cross-origin requests to API endpoints
location /api/ {
    include includes/cors-headers.conf;
    # Additional location-specific configuration
}

# Allow specific origins for WebSocket connections
location /ws/ {
    include includes/cors-headers.conf;
    # WebSocket-specific CORS configuration
}
```

### Custom Logging

```nginx
http {
    # Include custom log formats
    include includes/logging-format.conf;

    # Use custom log format for access logs
    access_log /var/log/nginx/access.log json_combined;
}
```

### Proxy Parameters

```nginx
# Apply proxy parameters to backend servers
location /app/ {
    include includes/proxy-params.conf;
    proxy_pass http://app_backend;
}

# With specific overrides for API
location /api/ {
    include includes/proxy-params.conf;
    proxy_read_timeout 60s;  # Override the default from the include
    proxy_pass http://api_backend;
}
```

### Rate Limiting

```nginx
http {
    # Include rate limit zone definitions
    include includes/rate-limiting.conf;

    server {
        # Apply rate limiting to login endpoint
        location /auth/login {
            include includes/rate-limiting.conf;
            limit_req zone=login_limit burst=5 nodelay;
            # Additional location-specific configuration
        }
    }
}
```

## Configuration Guidelines

When working with these include files:

1. **Environment Awareness**
   - Consider environment-specific needs when customizing includes
   - Test includes in each target environment
   - Use variables for environment-specific values

2. **Proper Include Location**
   - Include files at the appropriate context level (http, server, location)
   - Be aware of inheritance and precedence of directives
   - Check for conflicting directives when using multiple includes

3. **Overriding Directives**
   - Include files first, then override specific directives as needed
   - Be careful with duplicate directives which can cause unexpected behavior
   - Document any non-standard overrides

4. **Performance Implications**
   - Consider the performance impact of included directives
   - Test performance with includes enabled
   - Use conditional includes when appropriate

5. **Maintenance**
   - Update all relevant includes when changing behavior
   - Keep includes focused on a single responsibility
   - Document any changes to includes for other developers

## Security Considerations

- **Bot Protection**: Configure appropriate user agent filtering for your application needs
- **Cache-Control**: Ensure sensitive data is not cached inappropriately
- **CORS Headers**: Restrict allowed origins to trusted domains
- **Logging Format**: Do not log sensitive data in access logs
- **Proxy Parameters**: Set appropriate headers to prevent information leakage
- **Rate Limiting**: Set limits appropriate to your application's requirements

## Related Documentation

- NGINX Include Directive Documentation
- Core HTTP Module Documentation
- Headers Module Documentation
- Proxy Module Documentation
- Rate Limiting Configuration Guide
- OWASP Security Headers Guide
- Cross-Origin Resource Sharing (CORS) Specification
