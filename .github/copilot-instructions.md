# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

## Code Structure

- `/api/` - RESTful API endpoints
  - `/cloud/` - Cloud provider specific API endpoints
  - `/ics/` - Industrial Control Systems endpoints
  - `/monitoring/` - System monitoring endpoints
  - `/security/` - Security-related endpoints

- `/blueprints/` - Flask blueprints for application modules
  - `/auth/` - Authentication and authorization views
  - `/main/` - Core application views
  - `/admin/` - Administrative interface
  - `/monitoring/` - Monitoring dashboard views

- `/cli/` - Command-line interface tools
  - `/app/` - Application CLI commands
  - `/common/` - Shared CLI utilities

- `/config/` - Configuration management
  - `/components/` - Component-specific configurations
  - `/environments/` - Environment-specific settings

- `/core/` - Core utilities and security functions
  - `/security/` - Security implementation
    - `/cs_audit.py` - Security audit logging
    - `/cs_authentication.py` - Authentication services
    - `/cs_authorization.py` - Authorization services
    - `/cs_crypto.py` - Cryptographic operations
    - `/cs_file_integrity.py` - File integrity monitoring
    - `/cs_monitoring.py` - Security monitoring
    - `/cs_session.py` - Session security management
    - `/cs_utils.py` - Security utilities
  - `/templates/` - Core templates for layouts and errors
  - `/factory.py` - Application factory
  - `/middleware.py` - HTTP middleware

- `/deployment/` - Deployment scripts and infrastructure
  - `/security/` - Security configurations and scripts
  - `/config/` - Deployment configurations
  - `/scripts/` - Deployment automation scripts

- `/docs/` - Documentation files
  - `/api/` - API documentation
  - `/development/` - Developer guides
  - `/operations/` - Operations guides
  - `/security/` - Security documentation
  - `/specifications/` - System specifications

- `/extensions/` - Flask extensions
  - Initialization of Flask extensions (db, cache, etc.)

- `/models/` - Database models
  - `/auth/` - Authentication models
    - `/user.py` - User account model
    - `/role.py` - Role model for access control
    - `/permission.py` - Permission model for RBAC
    - `/user_activity.py` - User activity logging
    - `/user_session.py` - Session tracking
  - `/cloud/` - Cloud infrastructure models
  - `/content/` - Content management models
  - `/ics/` - Industrial Control Systems models
  - `/security/` - Security models
    - `/audit_log.py` - Security audit records
    - `/security_incident.py` - Security incident tracking
    - `/system_config.py` - Security configurations
  - `/storage/` - Storage models

- `/scripts/` - Utility scripts
  - `/compliance/` - Compliance checking tools
  - `/core/` - Core reusable functions
    - `/security/` - Security-related functions
    - `/system/` - System operations
  - `/deployment/` - Deployment automation
  - `/dr/` - Disaster recovery
  - `/monitoring/` - System monitoring
    - `/common/` - Shared monitoring utilities
    - `/tests/` - Monitoring tests
  - `/security/` - Security tools
  - `/utils/` - General utilities
    - `/common/` - Common utilities
    - `/dev_tools/` - Developer tools
    - `/modules/` - Modular script components

- `/services/` - Business logic services
  - `/auth/` - Authentication and authorization services
  - `/cloud/` - Cloud provider services
  - `/notification/` - Notification services
  - `/monitoring/` - Monitoring services

- `/static/` - Static assets (CSS, JS, images)
  - `/css/` - Stylesheets
  - `/js/` - JavaScript files
  - `/img/` - Image assets

- `/tests/` - Automated tests
  - `/unit/` - Unit tests
  - `/integration/` - Integration tests
  - `/security/` - Security tests

- `/views/` - View helpers and template utilities

## Coding and Organization Standards

### General Standards

- Organize by feature area and functionality
- Keep related code together
- Use smaller, focused functions
- Use dependency injection for better testability
- Implement proper error handling and logging
- Document complex logic with comments
- Use lazy formatting for logging: `logger.error("Failed: %s", error)`
- Prioritize slim, maintainable code over verbose implementations
- Favor reusable components over duplicate code

### Python

- Follow PEP 8, use type hints, docstrings, proper exception handling
- Use context managers, write unit tests, prioritize security

### Python Import Best Practices

- Use package-level imports for symbols exported in `__init__.py` (e.g., `from models.auth import User`)
- Check `__init__.py` first to identify exported symbols, especially in `__all__` lists
- Use direct module imports only for components not explicitly exported (e.g., `from models.module.internal import InternalClass`)
- Respect the public API boundary defined by packages to maintain code maintainability
- When multiple symbols are needed from the same package, group them in one import statement

### JavaScript

- Use ES6+, use async/await, prefer const over let, and avoid var
- Include CSP nonce, implement CSRF protection, use strict mode, validate inputs

### HTML/Templates

- Follow HTML5 standards with proper ARIA attributes for accessibility
- Use Bootstrap 5 and responsive design

### File Headers

- Use **project-relative paths** only
- Never include personal directory information:

```bash
# CORRECT:
# filepath: scripts/utils/common_functions.sh

# INCORRECT:
# filepath: /Users/username/Workspace/myproject/scripts/utils/common_functions.sh

```

## Security and Testing

### Security Best Practices

- Implement strict Content Security Policy
- Validate all user inputs and sanitize outputs to prevent XSS
- Use parameterized queries to prevent SQL injection
- Implement proper authentication checks with CSRF tokens for all forms
- Follow the principle of least privilege
- Scripts should utilize secure credential handling via environment variables
- Never hardcode API keys and sensitive parameters
- Log all activities for audit purposes
- Require appropriate authentication for sensitive operations

### Testing Requirements

- Write unit tests for all new functionality
- Include integration tests for critical paths
- Add security tests for authentication and authorization
- Document coverage requirements

## Security Standards

### Core Security Principles

- Follow the principle of least privilege
- Validate all inputs, sanitize all outputs
- Never hardcode sensitive data
- Implement defense in depth
- Use secure defaults requiring explicit opt-out
- Apply consistent security controls across all components

### Authentication & Authorization

- Implement multi-factor authentication for admin interfaces
- Use OAuth 2.0 with PKCE for frontend/API authentication flows
- Validate authorization at both client and server sides
- Apply role-based access control with attribute-based constraints
- Implement proper session management with secure refresh mechanisms

### Data Protection

- Use only approved cryptographic libraries and algorithms
- Implement proper key management with rotation mechanisms
- Apply envelope encryption for sensitive data storage
- Use parameterized queries to prevent SQL injection

### API & Interface Security

- Apply consistent security headers across all HTTP responses
- Use structured error responses that don't leak implementation details
- Implement rate limiting at multiple layers
- Use standard security schemes in API documentation

### Security Architecture

- Create reusable security primitives in a central `security` package
- Implement decorator patterns for common security controls
- Use security middleware for consistent enforcement
- Implement circuit breakers for external service calls

### Security Monitoring

- Log all security-relevant events with structured data
- Use correlation IDs across all system components
- Implement real-time alerting for suspicious activities
- Maintain separate audit logs for security events

## Enhanced Security Standards

### Credential Management

- Use a centralized secret management system (e.g., HashiCorp Vault, AWS Secrets Manager)
- Implement credential rotation policies with versioning support
- Apply the principle of short-lived credentials where possible
- Use service accounts with minimal permissions for automated processes
- Implement just-in-time (JIT) access for privileged operations

### Code Security

- Implement function-level permission checks for all sensitive operations
- Use immutable data patterns to prevent unintended modifications
- Apply defensive coding with input validation at all trust boundaries
- Implement circuit breakers for external service calls
- Centralize security control implementation in reusable modules

### Cryptography Standards

- Use only approved cryptographic libraries and algorithms (AES-256-GCM, RSA-2048+, ECDSA P-256+)
- Implement proper key management with separation of duties
- Apply envelope encryption for sensitive data storage
- Use forward secrecy for all TLS connections
- Implement secure key rotation mechanisms with versioning

### Code Structure and Reusability

- Create a central `security` package with reusable security primitives
- Implement decorator patterns for common security controls:

```python
@require_permission('resource:action')
@audit_log
@rate_limit(limit=10, period=60)
def sensitive_operation():
    # Implementation

```

- Use security middleware for consistent enforcement of controls
- Implement security control factories for environment-specific implementations
- Extract repeated security patterns into dedicated libraries

### Default Security Configuration

- Maintain security defaults in versioned configuration files
- Implement secure default configurations that require explicit opt-out
- Use security configuration validation on application startup
- Document all security configuration options with secure default values
- Apply tiered security defaults based on environment (dev/staging/production)

### API Security

- Implement API gateway patterns with centralized security controls
- Use structured error responses that don't leak implementation details
- Apply rate limiting at multiple layers (IP, user, endpoint)
- Implement GraphQL-specific protections (query complexity, depth limiting)
- Use standard security schemes in OpenAPI/Swagger documentation

## Documentation Standards

### README Structure

Every directory should include a [README.md](http://readme.md/) with these sections:

1. **Title & Contents** - Component name and Table of Contents (with links to sections)
2. **Overview** - Component purpose
3. **Key Components** - Main files with descriptions of usage and features
4. **Directory Structure** - List of files and subdirectories with descriptions
5. **Configuration** - Format and examples when applicable
6. **Best Practices & Security** - Implementation guidelines
7. **Common Features** - Shared functionality
8. **Usage Examples** - Command examples with syntax
9. **Related Documentation** - Links to additional resources

### Organization Principles

- **Prioritize Logical Order**: Always organize content in a logical sequence that supports understanding, rather than alphabetically
- **Process Flow**: Arrange operations documentation according to the sequence of execution
- **Complexity Progression**: Structure content from basic to advanced concepts
- **Dependency Order**: List components based on their dependencies (prerequisites first)
- **Functional Grouping**: Group related items based on functionality, not alphabetically
- **Common Operations First**: List frequently used operations before specialized ones
- **Critical Before Optional**: Present critical configuration before optional settings

#### Directory Structure Example

```plaintext
## Directory Structure

/directory/
├── script_a.py            # Description
├── script_b.py            # Description
├── subdirectory/          # Subdirectory description
│   ├── helper_a.py        # Description
│   └── helper_b.py        # Description
└── utils/                 # Utils description
    └── common.py          # Description

```

### Formatting Guidelines

- Use **bold** for file/script names
- Use `backticks` for inline code and function names
- Include language specifiers in code blocks (```plaintext)
- Follow proper heading hierarchy (#, ##, ###)
- Use bullet lists for features and numbered lists for sequential steps
- Set configuration examples in code blocks with comments for documentation:

```plaintext
# Required settings
endpoint=https://api.example.com/v1  # API endpoint URL

# Optional settings
timeout=30  # Request timeout in seconds (default: 10)

```

### Documentation Updates

When modifying code:

1. Update relevant documentation to reflect changes
2. Ensure command examples match current implementation
3. Verify parameter names and defaults are accurate
4. Organize file/directory listings by logical function rather than alphabetically
5. Include security implications of changes

### Template Variables

- Use consistent `{{variable_name}}` format for templates
- Group variables by context (system, environment, metrics)
- Document all template variables with descriptions and examples

## Script Enhancement Approach

When drafting or enhancing code:

### 1. Assessment

Identify improvement areas:

- Security (replace unsafe practices, e.g., replace `eval` for curl commands with safer alternatives)
- Reliability (add timeouts to prevent hanging processes)
- Error handling (implement exponential backoff and circuit breakers)
- Authentication (Add built-in support for API authentication methods)
- Performance (connection pooling and optimization)

For any file type, look for similar areas for improvements. When multiple areas are identified, prioritize based on risk and impact.

### 2. Implementation

Make changes following these principles:

- Maintain backward compatibility (if code is currently in use by other files)
- Use defensive programming
- Add validation and sanitization
- Organize code into focused functions
- Implement graceful error handling and cleanup

Example:

```bash
# Replace eval for security
# Before:
eval "curl $curl_options -X $method $url"

# After:
curl_args=(-s -o /dev/null -w '%{time_total},%{http_code}' -X "$method")
# Add other arguments to array
curl "${curl_args[@]}" "$url"

```

Demonstrate a preference for referencing pre-existing code in other scripts/files before drafting duplicative code. If the code or snippet similar in functionality appears in multiple locations, consider extracting the code to its own separate script/function to be reusable to all files.

### 3. Review and Testing

- Verify all features work as expected
- Test failure scenarios to ensure proper handling
- Check for regression issues
- Ensure proper cleanup of resources

### 4. Documentation

Document all changes:

- Update help text and comments
- Document new features in code comments
- Add examples in README files
- Summarize benefits of changes

## Architectural Patterns

- Use layered architecture (presentation, business logic, data access)
- Follow repository pattern for data and service layers for business logic
- Implement RESTful design for APIs
