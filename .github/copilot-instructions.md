# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

## Code Structure

- `/api/` - RESTful API endpoints
- `/blueprints/` - Flask blueprints for application modules
- `/cli/` - Command-line interface tools
- `/config/` - Configuration management
- `/core/` - Core utilities and security functions
- `/deployment/` - Deployment scripts and infrastructure
- `/docs/` - Documentation files
- `/extensions/` - Flask extensions
- `/models/` - Database models
- `/scripts/` - Utility scripts (maintenance, security, compliance)
  - `/compliance/` - Compliance checking tools
  - `/core/` - Core reusable functions
  - `/deployment/` - Deployment automation
  - `/dr/` - Disaster recovery
  - `/monitoring/` - System monitoring
  - `/security/` - Security tools
  - `/utils/` - General utilities
- `/services/` - Business logic services
- `/static/` - Static assets (CSS, JS, images)
- `/tests/` - Automated tests
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

### Python
- Follow PEP 8, use type hints, docstrings, proper exception handling
- Use context managers, write unit tests, prioritize security

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

## Documentation Standards

### Documentation Structure

All directories should include [README.md](http://readme.md/) with:

1. **Title & Overview**: Component name and purpose
2. **Key Components**: Main files with descriptions (decscription, usage, features)
3. **Configuration Files**: If applicable
4. **Directory Structure**: Brief listing of contents including all files and subdirectories
5. **Configuration**: Format and examples if applicable
6. **Best Practices & Security**: Guidelines
7. **Common Features**: Shared functionality
8. **Usage**: Examples showing how to use components with working commands
9. **Related Docs & Extending**: Links and guidelines

### Documentation Format

- Use markdown formatting:
  - `**bold**` for file/script names
  - `backticks` for inline code and `function_naming` references
  - Code blocks with language specification (e.g., ```bash)
  - Proper heading levels (#, ##, ###)
  - Lists for items and steps

### Template Variables

- Use `{{variable_name}}` format
- Categorize by context (system, environment, metrics)
- Provide examples of variable usage

### Documentation Updates

When drafting or changing code:

1. Update affected documentation to reflect new features
2. Revise command-line options and parameters
3. Update usage examples with accurate syntax
4. Verify command flags match implementation
5. Alphabetize all file listings and all directory/subdirectory listings

### Example README Structure

```markdown
# Component Name

## Overview
Brief component description.

## Key Scripts
- **`script_a.py`**: Does X functionality
  - **Usage**: Use this file to implement various functions of X
  - **Features**:
    - Exhibits feature #1
    - Exhibits feature #2
    - Exhibits feature #3

- **`script_b.py`**: Handles Y processing
  - **Usage**: Use this file to handle various processes of Y
  - **Features**:
    - Exhibits feature #1
    - Exhibits feature #2

## Directory Structure
/directory/
├── script_a.py            # Description
├── script_b.py            # Description
├── subdirectory/          # Subdirectory description
│   ├── helper_a.py        # Description
│   └── helper_b.py        # Description
└── utils/                 # Utils description
    └── common.py          # Description

## Best Practices
- Validate inputs
- Use logging framework
- Follow least privilege
- Test in staging first
- Use config files for environment-specific settings

## Security Considerations
- Use environment variables for credentials
- Never hardcode API keys and sensitive parameters
- Log for auditing

## Common Features
- Integration with central monitoring systems
- Historical data collection and trend analysis

## Usage
./script_a.py --option value

```

### Configuration Documentation

1. **List supported environments** alphabetically (development, staging, production)
2. **Document environment-specific behaviors** or configurations
3. **Provide environment-specific examples** where behavior differs
4. **Document configuration sections** with examples:
```ini
[Service]
# Service-specific settings
endpoint=https://api.example.com/status  # Required: API endpoint URL
interval=60                              # Optional: Check interval in seconds (default: 30)
timeout=10                               # Optional: Request timeout in seconds (default: 5)

```
5. **Explain required vs. optional parameters** with default values
6. **Document validation process** and provide troubleshooting tips

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
