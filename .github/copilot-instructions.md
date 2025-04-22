```markdown
# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management providing secure management of resources across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

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
  - `/scripts/compliance/` - Compliance checking tools
  - `/scripts/core/` - Core reusable functions
  - `/scripts/deployment/` - Deployment automation
  - `/scripts/deployment/dr/` - Disaster recovery
  - `/scripts/monitoring/` - System monitoring
  - `/scripts/security/` - Security tools
  - `/scripts/utils/` - General utilities
- `/services/` - Business logic services
- `/static/` - Static assets (CSS, JS, images)
- `/tests/` - Automated tests
- `/views/` - View helpers and template utilities

## Coding and Organization Standards

### General Standards
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

### Python
- Follow PEP 8, use type hints, docstrings, proper exception handling
- Use context managers, write unit tests, prioritize security

### JavaScript
- Use ES6+, prefer const/let, async/await, validate inputs
- Include CSP nonce, implement CSRF protection, use strict mode

### HTML/Templates
- Follow HTML5 standards with proper ARIA attributes for accessibility
- Use Bootstrap 5 components and utility classes
- Implement responsive designs

### File Headers and Paths
- Always use **project-relative paths** in file headers and comments, not absolute paths
- Never include personal directory information (like usernames or home directories)
- Example:
  ```bash
  # CORRECT:
  # filepath: scripts/utils/common_functions.sh

  # INCORRECT:
  # filepath: /Users/username/Workspace/myproject/scripts/utils/common_functions.sh

```

- When referencing files in documentation or comments, use paths relative to the project root
- For import statements, use appropriate relative or absolute imports based on the language's best practices

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
- Document test coverage requirements
- Test failure scenarios to ensure proper handling

## Documentation Standards

### Documentation Structure

All directories should include a [README.md](http://readme.md/) file with these sections (when applicable):

1. **Title**: Name of the module/component
2. **Overview**: Brief description of the purpose and functionality
3. **Key Scripts/Components**: Alphabetical list of main files with descriptions
4. **Configuration Files** (if applicable): List of configuration files with descriptions
5. **Directory Structure**: Complete listing of all files and subdirectories, alphabetically organized
6. **Usage**: Examples showing how to use the scripts or components
7. **Configuration Structure** (if applicable): Format of configuration files with examples
8. **Best Practices**: Guidelines for optimal usage, common patterns, and recommendations
9. **Security Considerations**: Security-related information specific to the component
10. **Common Features**: Shared functionality across the component's scripts/modules
11. **Modifying/Extending**: Guidelines for modifications or extensions
12. **Related Documentation**: Links to related documentation
13. **Contributing**: Guidelines for contributing to this component
14. **Change Log**: Recent changes to track version history
15. **License**: License information if applicable

### Documentation Format

- Use proper markdown formatting:
    - `*bold**` for emphasis, especially for file/script names
    -
    - `backticks` for inline code references
    - Use proper heading levels (# for title, ## for major sections, ### for subsections)
    - Use bullet points for lists of items
    - Use numbered lists for sequential steps or processes

### Template Variable Conventions

- Use `{{variable_name}}` format to denote template variables
- Categorize variables by their context (system, environment, metrics, etc.)
- Provide examples of variable usage

### Documentation Update Process

When making substantial changes to code components:

1. **Identify affected documentation** files (READMEs, API reference, user guides)
2. **Update feature descriptions** to reflect new capabilities
3. **Revise command-line options** and parameters
4. **Update usage examples** with accurate syntax
5. **Ensure consistency** across all documentation
6. **Verify all command flags** match the actual implementation
7. **Ensure file names and directories are listed alphabetically** in documentation sections

### Example README Structure

```markdown
# Component Name

## Overview
Brief description of the component's purpose and functionality.

## Key Scripts
- **`script_a.py`**: Description of script A.
- **`script_b.py`**: Description of script B.

## Directory Structure
/directory/
├── script_a.py            # Description
├── script_b.py            # Description
├── subdirectory/          # Subdirectory description
│   ├── helper_a.py        # Description
│   └── helper_b.py        # Description
└── utils/                 # Utils description
    └── common.py          # Description

## Usage
./script_a.py --option value

## Best Practices
- Always validate inputs before processing
- Use the logging framework instead of print statements
- Follow the principle of least privilege when executing commands
- Test scripts in a staging environment before running in production
- Use configuration files for environment-specific settings

## Security Considerations
- Scripts utilize secure credential handling via environment variables
- API keys and sensitive parameters are never hardcoded
- All activities are logged for audit purposes
- Access to certain capabilities requires appropriate authentication

## Common Features
- Environment-aware configuration
- Standardized logging formats
- Integration with central monitoring systems
- Historical data collection and trend analysis

```

### Environment and Configuration Documentation

For environment-specific and configuration-heavy components:

1. **List supported environments** alphabetically (development, staging, production)
2. **Document environment-specific behaviors** or configurations
3. **Provide environment-specific examples** where behavior differs
4. **Document configuration sections** with examples:

    ```
    [Service]
    # Service-specific settings
    endpoint=https://api.example.com/status  # Required: API endpoint URL
    interval=60                              # Optional: Check interval in seconds (default: 30)
    timeout=10                               # Optional: Request timeout in seconds (default: 5)

    ```

5. **Explain required vs. optional parameters** with default values
6. **Document validation process** and provide troubleshooting tips

## Script Enhancement Case Study

The following case study demonstrates our preferred approach to enhancing code files throughout the project.

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

Example improvements:

```bash
# Replace eval for security
# Before:
eval "curl $curl_options -X $method $url"

# After:
curl_args=(-s -o /dev/null -w '%{time_total},%{http_code}' -X "$method")
# Add other arguments to array
curl "${curl_args[@]}" "$url"

```

### 3. Review and Testing Phase

After implementation:

- Verify all features work as expected
- Test failure scenarios to ensure proper handling
- Check for regression issues
- Ensure proper cleanup of resources

### 4. Documentation Updates

Finally, document all changes:

- Update help text with new options
- Document new features in code comments
- Add examples in README files
- Summarize benefits of changes

## Architectural Patterns

- Follow a layered architecture (presentation, business logic, data access)
- Use the repository pattern for data access
- Implement service layers for business logic
- Use dependency injection for better testability
- Follow RESTful design principles for APIs

By following these guidelines, you'll help maintain consistency and quality throughout the codebase.
