# Web Application Firewall Rules for Cloud Infrastructure Platform

This directory contains custom ModSecurity WAF rules for the Cloud Infrastructure Platform, providing specialized protection against various web-based attacks.

## Contents

- Overview
- Key Rule Files
- Directory Structure
- Rule Structure
- Usage and Integration
- Customization Guidelines
- Best Practices
- Related Documentation

## Overview

The Web Application Firewall (WAF) rules implement attack detection and prevention patterns for ModSecurity. These rules protect the Cloud Infrastructure Platform against common web application attacks, API abuse, and other malicious activities. The rules are organized by attack type or protection category to enable granular deployment and easier maintenance. Each rule set follows ModSecurity best practices with appropriate logging, detection accuracy, and minimal performance impact.

## Key Rule Files

- **`api-protection.conf`**: Rules specific to API endpoint security
  - API method enforcement
  - API versioning validation
  - Authorization header requirements
  - Rate limit enforcement patterns
  - Request validation rules

- **`authentication.conf`**: Authentication-related attack prevention
  - Authentication bypass protection
  - Brute force attempt detection
  - Credential stuffing prevention
  - Session fixation protection
  - Token manipulation detection

- **`command-injection.conf`**: OS command injection prevention
  - Common command pattern detection
  - Escape sequence filtering
  - Parameter sanitization rules
  - Shell metacharacter blocking
  - System command execution prevention

- **`file-upload.conf`**: Secure file upload protection
  - Content-Type verification
  - Extension whitelisting
  - File size limitations
  - MIME type validation
  - Malicious file detection

- **`generic-attacks.conf`**: Common web attack patterns
  - Header injection prevention
  - HTTP method enforcement
  - Protocol abuse protection
  - Request smuggling prevention
  - Server-side request forgery (SSRF) protection

- **`ics-protection.conf`**: Industrial Control System protection
  - Control command validation
  - Control sequence enforcement
  - ICS protocol protection
  - Parameter range validation
  - Safety-critical operation protection

- **`ip-reputation.conf`**: IP-based threat intelligence
  - Bot network detection
  - IP reputation list integration
  - Known attacker identification
  - Threat intelligence feed integration
  - Tor exit node blocking

- **`path-traversal.conf`**: Path traversal attack prevention
  - Directory traversal blocking
  - Encoding evasion detection
  - Filepath normalization rules
  - Path sanitization
  - Special character filtering

- **`request-limits.conf`**: Request control and limiting
  - Content length restrictions
  - Cookie size limitations
  - Header size restrictions
  - Parameter count limits
  - Request timeout settings

- **`sensitive-data.conf`**: Data exposure prevention
  - Credit card number detection
  - PII data leakage prevention
  - Response filtering for sensitive data
  - Social security number pattern matching
  - Token and key exposure prevention

- **`sql-injection.conf`**: SQL injection attack prevention
  - Blind SQL injection patterns
  - Common SQL attack signatures
  - SQL keyword detection
  - SQL operator detection
  - Union-based attack prevention

- **`xss-protection.conf`**: Cross-site scripting prevention
  - DOM-based XSS protection
  - HTML context filtering
  - JavaScript event handler filtering
  - Reflected XSS patterns
  - Script tag filtering

## Directory Structure

```plaintext
deployment/security/filters/waf/
├── README.md                # This documentation
├── api-protection.conf      # API endpoint protection rules
├── authentication.conf      # Authentication attack prevention
├── command-injection.conf   # Command injection prevention
├── file-upload.conf         # File upload protection rules
├── generic-attacks.conf     # Common web attack patterns
├── ics-protection.conf      # Industrial Control System protection
├── ip-reputation.conf       # IP reputation-based filtering
├── path-traversal.conf      # Path traversal attack prevention
├── request-limits.conf      # Request rate and size limiting
├── sensitive-data.conf      # Sensitive data exposure protection
├── sql-injection.conf       # SQL injection prevention
└── xss-protection.conf      # Cross-site scripting prevention
```

## Rule Structure

Each rule file follows a consistent format:

```apache
# Rule file: rule-name.conf
# Description: Short description of the rule's purpose
# Author: Security Team
# Version: 1.0
# Last Updated: YYYY-MM-DD

# ==============================
# INITIALIZATION
# ==============================
# Any initialization code, variables, etc.

# ==============================
# RULES
# ==============================
# Rule 1: Description of what this specific rule does
SecRule [VARIABLES] "@[OPERATOR] [PATTERN]" \
    "id:10001,\
    phase:2,\
    t:none,\
    block,\
    log,\
    msg:'Description of attack',\
    severity:'CRITICAL',\
    tag:'application-multi',\
    tag:'attack-[type]'"

# Additional rules follow the same pattern...

# ==============================
# EXCEPTIONS
# ==============================
# Exceptions for specific URLs or conditions
SecRule REQUEST_URI "@beginsWith /api/allowed-path" \
    "id:10099,\
    phase:1,\
    pass,\
    nolog,\
    skipAfter:END-[RULE-TYPE]"

SecMarker "END-[RULE-TYPE]"
```

## Usage and Integration

### Deploying Rules to ModSecurity

```bash
# Copy WAF rules to the ModSecurity configuration directory
sudo cp *.conf /etc/nginx/modsecurity.d/waf-rules/

# Set appropriate permissions
sudo chmod 644 /etc/nginx/modsecurity.d/waf-rules/*.conf

# Include the rules in the main ModSecurity configuration
sudo nano /etc/nginx/modsecurity.d/modsecurity-rules.conf

# Add include directives for each rule file:
# Include /etc/nginx/modsecurity.d/waf-rules/sql-injection.conf
# Include /etc/nginx/modsecurity.d/waf-rules/xss-protection.conf
# ...

# Test the configuration
sudo nginx -t

# Reload nginx to apply changes
sudo systemctl reload nginx
```

### Testing Rules Before Deployment

```bash
# Test rules against sample traffic
sudo modsecurity-audit-log-test -r ruleset.conf -l sample-traffic.log

# Enable detection-only mode (no blocking) to assess false positives
# Modify rule actions from "block" to "pass" in testing environments
```

## Customization Guidelines

When customizing or creating new WAF rules:

1. **Environment Considerations**
   - Start with detection-only mode in development environments
   - Implement graduated security across environments (dev/staging/production)
   - Add more verbose logging in lower environments
   - Apply stricter rules in production environments

2. **Rule Tuning**
   - Begin with general patterns and refine based on false positives
   - Use phase:1 for early request filtering (headers)
   - Use phase:2 for request body analysis
   - Use appropriate transformation functions (t:lowercase, t:urlDecode)
   - Include proper exception handling for legitimate traffic

3. **Performance Optimization**
   - Place high-confidence, low-impact rules first
   - Use appropriate operators for better performance
   - Create allowlist rules for trusted sources/endpoints
   - Use negated conditions to skip unnecessary processing
   - Implement efficient regular expressions

4. **Rule Management**
   - Assign unique ID ranges to different rule categories
   - Include descriptive comments for complex patterns
   - Document all exceptions and their rationale
   - Maintain version history for all rule changes
   - Test thoroughly before production deployment

## Best Practices

- **Assign Unique IDs**: Use ID ranges 10000-19999 for custom rules
- **Combine Related Rules**: Group logical protections in the same file
- **Document Exceptions**: Document any exceptions and their business justification
- **Log Appropriately**: Include meaningful log messages for investigation
- **Maintain Versioning**: Track rule changes with version numbers and dates
- **Regular Updates**: Review and update rules as attack patterns evolve
- **Test Thoroughly**: Validate rules against both malicious and legitimate traffic
- **Use Tagged Blocks**: Use SecMarker to define logical rule sections

## Related Documentation

- Cloud Platform Security Architecture
- Fail2ban Integration Guide
- ModSecurity Core Rule Set Documentation
- ModSecurity Official Documentation
- OWASP ModSecurity CRS Documentation
- Security Event Monitoring Guide
- Security Incident Response Procedures
- WAF Deployment Guide
