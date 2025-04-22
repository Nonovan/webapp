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

The following case study demonstrates our preferred approach to enhancing code files throughout the project. While this example shows how the `api_latency.sh` monitoring script was improved, **this systematic approach should be applied to most files** in the codebase when improvements are needed, especially when multiple areas require attention.

This approach is applicable to Python modules, JavaScript files, shell scripts, configuration files, and other code assets - with appropriate language-specific adaptations. The goal is to consistently improve code quality across the entire project using a standardized methodology.

### 1. Assessment Phase

First, identify key areas for improvement:

```
1. Security: Replace `eval` for curl commands with safer alternatives
2. Reliability: Add request timeout settings to prevent hanging processes
3. Error handling: Implement exponential backoff and circuit breakers
4. Authentication: Add built-in support for API authentication methods
5. Performance: Add connection pooling and optimization
```

For any file type, look for similar categories of improvements: security, reliability, error handling, authentication, and performance optimizations. When multiple improvement areas are identified, prioritize them based on risk and impact.

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

### Documentation Update Process

When making substantial changes to code components, it's essential to update the related documentation. The following process should be followed:

#### 1. Documentation Assessment

First, identify the affected documentation files:
- README.md files in relevant directories
- API reference documentation
- User guides and tutorials
- Configuration reference docs

#### 2. Documentation Implementation

For each identified document:
- Update feature descriptions to reflect new capabilities
- Revise command-line options and parameters
- Update usage examples with accurate syntax
- Ensure consistency across all documentation

#### 3. Documentation Review

After updating documentation:
- Verify all command flags and options match the actual implementation
- Ensure examples use correct parameter names and syntax
- Check that all new features are properly documented
- Verify related files are also updated for cross-references

#### 4. Documentation Case Study: Monitoring Scripts README

The update to the `scripts/monitoring/core/README.md` after enhancing several monitoring scripts demonstrates our preferred approach:

1. **Maintain the existing structure** for consistency and familiarity
2. **Update technical details** to reflect actual implementation:
```bash
# Before: --auth-token and --retries parameters that do not exist
./api_latency.sh production --endpoints /api/v1/status,/api/v1/users --interval 30 --retries 3 --auth-token $TOKEN
# After: Corrected to use --auth-key as implemented
./api_latency.sh production --endpoints /api/v1/status,/api/v1/users --interval 30 --auth-key $TOKEN
```
3. **Add new features** to the relevant sections
4. **Verify all cross-references** to ensure they point to valid locations
5. **Update usage examples** with actual, working commands
6. **Ensure file names and directories are listed alphabetically** in sections like "Key Scripts" or "Usage Examples", similar to sections "Code Structure" above and "Scripts Directory" below.
7. **Ensure "Directory Structure" includes all files and subdirectories** in the directory.

This systematic approach ensures documentation stays in sync with code changes and provides users with accurate information.

### README Documentation Structure

All directories should include a README.md file with a consistent structure. The following sections should be included when applicable:

1. **Title**: Name of the module/component.
2. **Overview**: Brief description of the purpose and functionality.
3. **Configuration Files** (if applicable): List of configuration files with descriptions.
4. **Key Scripts/Components**: Alphabetical list of main files with descriptions.
5. **Usage**: Examples showing how to use the scripts or components.
6. **Best Practices**: Guidelines for optimal usage, common patterns, and recommendations.
7. **Configuration Structure** (if applicable): Format of configuration files with examples.
8. **Directory Structure**: Complete listing of all files and subdirectories, alphabetically organized.
9. **Modifying/Extending**: Guidelines for modifications or extensions.
10. **Related Documentation**: Links to related documentation.
11. **Change Log**: Recent changes to track version history.

#### Example README Structure

```markdown
# Component Name

## Overview
Brief description of the component's purpose and functionality.

## Key Scripts
- **`script_a.py`**: Description of script A.
- **`script_b.py`**: Description of script B.

## Usage
```bash
./script_a.py --option value
```

## Best Practices
- Always validate inputs before processing
- Use the logging framework instead of print statements
- Follow the principle of least privilege when executing commands
- Test scripts in a staging environment before running in production
- Use configuration files for environment-specific settings

## Directory Structure
```
/directory/
├── script_a.py            # Description
├── script_b.py            # Description
├── subdirectory/          # Subdirectory description
│   ├── helper_a.py        # Description
│   └── helper_b.py        # Description
└── utils/                 # Utils description
    └── common.py          # Description
```

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

- Place compliance scripts in `/scripts/compliance/`
- Put core reusable functions in `/scripts/core/`
- Place deployment-related scripts in `/scripts/deployment/`
- Put DR (disaster recovery) scripts in `/scripts/deployment/dr/`
- Place monitoring scripts in `/scripts/monitoring/`
- Put security-related scripts in `/scripts/security/`
- Place utility scripts in `/scripts/utils/`

### Documentation

- Include README.md files in each directory explaining its purpose
- Document API endpoints with examples
- Include security considerations in component documentation
- Ensure all README files follow the structure outlined in "README Documentation Structure"
- Use markdown syntax consistently for improved readability:
  - Use `**bold**` for emphasis, especially for file/script names
  - Use ``` code blocks with language specification for code examples
  - Use `backticks` for inline code references
  - Use proper heading levels (# for title, ## for major sections, ### for subsections)
  - Use bullet points for lists of items
  - Use numbered lists for sequential steps or processes

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
