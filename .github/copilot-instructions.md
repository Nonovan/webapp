# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

## Code Structure

- `/api/` - RESTful API endpoints
- `/blueprints/` - Flask application modules
- `/cli/` - Command-line tools
- `/config/` - Configuration
- `/core/` - Core utilities and security
- `/deployment/` - Deployment scripts
- `/docs/` - Documentation
- `/extensions/` - Flask extensions
- `/models/` - Database models
- `/scripts/` - Utility scripts
  - `/compliance/` - Compliance checks
  - `/core/` - Core functions
  - `/deployment/` - Deployment automation
  - `/dr/` - Disaster recovery
  - `/monitoring/` - System monitoring
  - `/security/` - Security tools
  - `/utils/` - General utilities
- `/services/` - Business logic
- `/static/` - Static assets
- `/tests/` - Tests
- `/views/` - View helpers

## Coding and Organization Standards

### General Standards
- Organize by feature area and functionality
- Keep related code together
- Use smaller, focused functions
- Implement proper error handling and logging
- Document complex logic
- Use lazy formatting for logging: `logger.error("Failed: %s", error)`

### Python
- Follow PEP 8, use type hints, docstrings, proper exception handling
- Use context managers, write unit tests, prioritize security

### JavaScript
- Use ES6+, prefer const/let, async/await, validate inputs
- Include CSP nonce, implement CSRF protection, use strict mode

### HTML/Templates
- Follow HTML5 standards with ARIA attributes
- Use Bootstrap 5 and responsive design

### File Headers
- Use **project-relative paths** only:
```bash
# CORRECT:
# filepath: scripts/utils/common_functions.sh

# INCORRECT:
# filepath: /Users/username/Workspace/myproject/scripts/utils/common_functions.sh

```

## Security and Testing

### Security Best Practices

- Implement Content Security Policy
- Validate inputs, sanitize outputs
- Use parameterized queries
- Implement CSRF protection
- Follow least privilege principle
- Use environment variables for credentials
- Never hardcode sensitive data
- Log activities for audit
- Require authentication for sensitive operations

### Testing Requirements

- Write unit and integration tests
- Test authentication and failure scenarios
- Document coverage requirements

## Documentation Standards

### Documentation Structure

All directories should include [README.md](http://readme.md/) with:

1. **Title & Overview**: Component name and purpose
2. **Key Components**: Main files with descriptions
3. **Configuration Files**: If applicable
4. **Directory Structure**: Brief listing of contents
5. **Usage**: Examples showing how to use components
6. **Configuration**: Format and examples if applicable
7. **Best Practices & Security**: Guidelines
8. **Common Features**: Shared functionality
9. **Related Docs & Extending**: Links and guidelines

### Documentation Format

- Use markdown formatting:
    - `*bold**` for file/script names
    - Code blocks with language specification
    - Proper heading levels (#, ##, ###)
    - Lists for items and steps

### Template Variables

- Use `{{variable_name}}` format
- Categorize by context (system, environment, metrics)

### Documentation Updates

When changing code:

1. Update affected documentation
2. Revise options and examples
3. Verify command flags match implementation
4. Alphabetize file and directory listings

### Example README Structure

```markdown
# Component Name

## Overview
Brief component description.

## Key Scripts
- **`script_a.py`**: Does X functionality
- **`script_b.py`**: Handles Y processing

## Directory Structure
/directory/
├── script_a.py      # Main script
└── utils/           # Utility functions

## Usage
./script_a.py --option value

## Best Practices
- Validate inputs
- Use logging framework
- Follow least privilege
- Test in staging first

## Security Considerations
- Use environment variables for credentials
- Log for auditing

```

### Configuration Documentation

For config files:

```
[Service]
endpoint=https://api.example.com/status  # Required: API endpoint
timeout=10                               # Optional: Timeout in seconds (default: 5)

```

## Script Enhancement Approach

When enhancing code:

### 1. Assessment

Identify improvement areas:

- Security (replace unsafe practices)
- Reliability (add timeouts)
- Error handling (implement recovery)
- Authentication (improve credential management)

### 2. Implementation

Make changes following these principles:

- Maintain backward compatibility
- Use defensive programming
- Add validation and focused functions

Example:

```bash
# Before: eval "curl $curl_options -X $method $url"
# After: curl "${curl_args[@]}" "$url"

```

### 3. Testing

- Verify functionality
- Test failure scenarios
- Check for regression
- Ensure proper cleanup

### 4. Documentation

- Update help text and comments
- Add examples
- Summarize benefits

## Architectural Patterns

- Use layered architecture (presentation, business logic, data)
- Follow repository pattern and service layers
- Use dependency injection
- Implement RESTful design for APIs
