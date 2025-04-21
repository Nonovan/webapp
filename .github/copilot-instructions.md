# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management. The application provides secure management of resources across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

## Code Structure

- `/api/` - RESTful API endpoints and API-related functionality
- `/blueprints/` - Flask blueprints for different application modules
- `/cli/` - Command-line interface tools
- `/config/` - Configuration management
- `/core/` - Core utilities and security functions
- `/deployment/` - Deployment scripts and infrastructure configuration
- `/docs/` - Documentation files
- `/extensions/` - Flask extensions
- `/models/` - Database models
- `/scripts/` - Utility scripts for maintenance, security, compliance, etc.
- `/services/` - Business logic services
- `/static/` - Static assets (CSS, JS, images)
- `/tests/` - Automated tests
- `/views/` - View helpers and template utilities

## Coding Standards

Please follow these standards when generating code:

### Python

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Include docstrings for all functions, classes, and modules
- Handle exceptions appropriately with specific exception types
- Use context managers for resource cleanup when appropriate
- Write unit tests for new functionality
- Prioritize security in all code (input validation, output encoding, etc.)

### JavaScript

- Use modern ES6+ syntax
- Prefer const over let, and avoid var
- Use async/await for asynchronous operations
- Validate user input
- Include CSP nonce in inline scripts
- Implement proper CSRF protection
- Use strict mode ('use strict')

### HTML/Templates

- Follow HTML5 standards
- Include proper ARIA attributes for accessibility
- Use Bootstrap 5 components and utility classes
- Implement responsive designs

## Script Enhancement Case Study

The following case study demonstrates our preferred approach to enhancing shell scripts. This example shows how the `api_latency.sh` monitoring script was improved:

### 1. Assessment Phase

First, identify key areas for improvement:

```
1. Security: Replace `eval` for curl commands with safer alternatives
2. Reliability: Add request timeout settings to prevent hanging processes
3. Error handling: Implement exponential backoff and circuit breakers
4. Authentication: Add built-in support for API authentication methods
5. Performance: Add connection pooling and optimization
```

### 2. Implementation Phase

For each identified area, implement changes following these principles:

- Maintain backward compatibility
- Use defensive programming techniques
- Add proper validation and sanitization
- Organize the code into focused functions
- Implement graceful error handling and cleanup
- Add helpful logging messages

Example improvements:
```bash
# Replace eval for security
# Before:
eval "curl $curl_options -X $method $url"

# After:
curl_args=(-s -o /dev/null -w '%{time_total},%{http_code}' -X "$method")
# Add other arguments to array
curl "${curl_args[@]}" "$url"

# Add circuit breaker pattern
if [[ -f "$circuit_breaker_file" ]]; then
    # Check if circuit is open and handle appropriately
fi
```

### 3. Review and Testing Phase

After implementation:

- Verify all features work as expected
- Test failure scenarios to ensure proper handling
- Document new parameters and features
- Check for any regression issues
- Ensure proper cleanup of resources

### 4. Documentation Updates

Finally, document all changes:

- Update help text with new options
- Document new features in code comments
- Add examples in README files
- Summarize benefits of changes

This process ensures our scripts are robust, secure, and maintainable while preserving functionality and adding new capabilities.

### Security Practices

- Implement strict Content Security Policy
- Validate all user inputs
- Sanitize outputs to prevent XSS
- Use parameterized queries to prevent SQL injection
- Implement proper authentication checks
- Use CSRF tokens for all forms
- Follow the principle of least privilege

## Organization Preferences

- Organize files by feature area and functionality
- Keep related code together when possible
- Prefer smaller, focused functions over large, complex ones
- Use dependency injection for better testability
- Implement proper error handling and logging
- Document complex logic with comments
- Use configuration files for environment-specific settings
- Use lazy formatting for string operations, especially in logging statements
  - Prefer `logger.error("Failed to process %s: %s", item_id, str(e))` over string concatenation
  - Use f-strings only when the string is always evaluated (not in logging statements)

## Specific Guidance

### Scripts Directory

- Place deployment-related scripts in `/scripts/deployment/`
- Put DR (disaster recovery) scripts in `/scripts/deployment/dr/`
- Put security-related scripts in `/scripts/security/`
- Put compliance scripts in `/scripts/compliance/`
- Place monitoring scripts in `/scripts/monitoring/`
- Put core reusable functions in `/scripts/core/`
- Place utility scripts in `/scripts/utils/`

### Documentation

- Include README.md files in each directory explaining its purpose
- Document API endpoints with examples
- Include security considerations in component documentation

### Testing

- Write unit tests for all new functionality
- Include integration tests for critical paths
- Add security tests for authentication and authorization
- Document test coverage requirements

## Architectural Patterns

- Follow a layered architecture (presentation, business logic, data access)
- Use the repository pattern for data access
- Implement service layers for business logic
- Use dependency injection for better testability
- Follow RESTful design principles for APIs

By following these guidelines, you'll help maintain consistency and quality throughout the codebase.
