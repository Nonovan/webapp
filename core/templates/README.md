# Core Templates

This directory contains reusable template files used by the core components of the Cloud Infrastructure Platform, providing consistent error pages, layout structures, and interface elements.

## Contents

- Overview
- Key Components
- Directory Structure
- Usage Examples
- Template Variables
- Customization Guidelines
- Related Documentation

## Overview

The core templates provide essential layout structures and error pages used throughout the Cloud Infrastructure Platform. These templates implement consistent branding, proper accessibility attributes, security best practices, and responsive design. They serve as the foundation for more specialized templates used in specific application areas while ensuring a unified experience across the platform.

## Key Components

- **`errors/`**: Standard error page templates
  - Consistent error page formatting
  - Custom error messaging
  - Environment-specific debug information
  - Security-conscious error reporting
  - User guidance for common error conditions

- **`layouts/`**: Base layout templates
  - Common header and footer sections
  - Content Security Policy integration
  - Core navigation structure
  - Responsive design framework
  - Theme management

## Directory Structure

```plaintext
core/templates/
├── README.md              # This documentation
├── cs_file_integrity_2.py # File integrity template utility
├── errors/                # Error page templates
│   ├── 400.html           # Bad request error template
│   ├── 401.html           # Unauthorized error template
│   ├── 403.html           # Forbidden error template
│   ├── 404.html           # Not found error template
│   ├── 500.html           # Internal server error template
│   └── base_error.html    # Base template for all error pages
└── layouts/               # Layout templates
    ├── base.html          # Core layout template
    ├── minimal.html       # Minimal layout without navigation
    └── secure.html        # Security-enhanced layout
```

## Usage Examples

### Extending the Base Layout

```html
<!-- In a specific template -->
{% extends "layouts/base.html" %}

{% block title %}Page Title{% endblock %}

{% block content %}
<div class="container my-4">
    <h1>Page Heading</h1>
    <p>Page content goes here.</p>
</div>
{% endblock %}
```

### Using Error Templates

```python
from flask import render_template

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # Log the error
    app.logger.error('Server Error: %s', error)
    return render_template('errors/500.html'), 500
```

### Custom Error Page with Context

```python
def custom_error_handler(error_code, message):
    """Generate a custom error page with context."""
    return render_template(
        'errors/base_error.html',
        error_code=error_code,
        message=message,
        back_url=request.referrer or url_for('main.home')
    ), error_code
```

## Template Variables

The core templates use these common variables:

### Base Layout Template

| Variable | Description | Default |
|----------|-------------|---------|
| `app_name` | Application name | "Cloud Infrastructure Platform" |
| `csp_nonce` | Content Security Policy nonce | Generated per request |
| `current_user` | Current user object | None |
| `debug_mode` | Whether app is in debug mode | app.debug |
| `environment` | Current environment | "production" |
| `page_title` | Page title | None |
| `static_url` | URL for static assets | "/static/" |

### Error Templates

| Variable | Description | Default |
|----------|-------------|---------|
| `error_code` | HTTP error code | "500" |
| `error_title` | Error page title | "Error" |
| `message` | Error message | "An unexpected error occurred." |
| `show_details` | Show technical details | False |
| `back_url` | URL for "go back" link | "/" |
| `support_email` | Support email address | ["support@example.com"](mailto:support@example.com) |

## Customization Guidelines

When customizing these templates:

1. **Maintain Core Structure**
   - Keep standard blocks defined in base templates
   - Preserve security-related elements (CSP nonce usage)
   - Maintain accessibility attributes
   - Keep responsive design elements

2. **Follow Design Standards**
   - Use consistent header hierarchy
   - Apply proper spacing and layout principles
   - Follow color scheme guidelines
   - Use standard button and form styles

3. **Ensure Security**
   - Use provided CSP nonce for inline scripts
   - Follow XSS prevention practices
   - Properly escape dynamic content
   - Use proper authentication checks

4. **Support Accessibility**
   - Maintain ARIA attributes
   - Use proper heading structure
   - Ensure keyboard navigation
   - Keep sufficient color contrast

## Related Documentation

- Base Layout Reference
- Content Security Policy
- Design System Guidelines
- Error Handling Framework
- Template Inheritance Guide
- Theming Documentation
- Template Security Guidelines
