# Main Blueprint

This blueprint provides the primary user interface and core application functionality for the Cloud Infrastructure Platform, implementing responsive, secure, and accessible web pages for essential platform features.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Routes](#routes)
- [Templates](#templates)
- [Security Features](#security-features)
- [Common Patterns](#common-patterns)
- [Related Documentation](#related-documentation)

## Overview

The Main blueprint serves as the central module for end-user interaction with the platform. It delivers the home page, about page, cloud services dashboard, ICS application interface, and user profile pages. The blueprint implements comprehensive security controls, performance monitoring, responsive design, and accessibility features throughout all user interfaces. It follows an MVC pattern with routes handling business logic and templates providing the presentation layer.

The blueprint has several key responsibilities:

1. **User Interface**: Providing responsive, accessible web pages for the platform's core functionality
2. **Security Enforcement**: Implementing robust security measures to protect against common web vulnerabilities
3. **Performance Optimization**: Monitoring and optimizing request/response handling for better user experience
4. **File Integrity Monitoring**: Real-time verification of system integrity to detect potential compromises
5. **Metric Collection**: Gathering and exposing performance and security metrics for monitoring
6. **Content Delivery**: Providing optimized content with proper HTTP headers for caching and security

## Key Components

- **`__init__.py`**: Blueprint initialization and request processing
  - Blueprint registration and configuration
  - Request metrics collection
  - Response header security enhancements
  - Request lifecycle hooks
  - Centralized error handling setup
  - File integrity monitoring implementation
  - Security context establishment

- **`errors.py`**: Error handling functionality
  - Custom error pages for common HTTP status codes
  - Consistent error formatting across the application
  - Security-focused error responses
  - Audit logging for error conditions
  - Structured error response formatting

- **`routes.py`**: Core application endpoints
  - Home page and landing pages
  - Cloud services dashboard implementation
  - ICS application interface
  - Profile management functionality
  - Administrative interface routing
  - Content pages (about, contact, etc.)
  - Security status reporting

- **`templates/`**: User interface templates
  - Base template with common layout elements
  - Page-specific templates with responsive design
  - Secure form implementations
  - Real-time dashboard interfaces
  - User profile and settings interfaces
  - Security visualization components

- **`static/`**: Blueprint-specific static assets
  - Custom CSS styles
  - JavaScript functionality
  - Image assets
  - Font files
  - Security-related icons and graphics

## Directory Structure

```plaintext
blueprints/main/
├── README.md                # This documentation
├── __init__.py              # Blueprint initialization and request hooks
├── errors.py                # Error handling functionality
├── routes.py                # Route definitions and view functions
├── static/                  # Static assets specific to main blueprint
│   ├── css/                 # Custom stylesheet extensions
│   ├── images/              # Blueprint-specific images
│   └── js/                  # Blueprint-specific JavaScript
└── templates/               # HTML templates
    └── main/                # Main blueprint templates
        ├── README.md        # Templates documentation
        ├── about.html       # Company and platform information
        ├── base.html        # Base template with layout structure
        ├── cloud.html       # Cloud services dashboard
        ├── home.html        # Platform landing page
        ├── ics.html         # Industrial control systems interface
        ├── login.html       # User authentication interface
        ├── privacy.html     # Privacy policy page
        ├── profile.html     # User profile management
        ├── register.html    # Account registration interface
        ├── security.html    # Security practices information
        └── terms.html       # Terms of service page
```

## Routes

| Route | Function | Purpose | Security |
|-------|----------|---------|----------|
| `/` | `home()` | Landing page | Rate limited: 60/minute, Cached: 5 minutes |
| `/about` | `about()` | Company information | Rate limited: 30/minute, Cached: 1 hour |
| admin | `admin()` | Administrative panel | Authentication required, Admin role required |
| `/cloud` | `cloud()` | Cloud services dashboard | Authentication required, Standard role required |
| `/contact` | `contact()` | Contact form | Rate limited: 10/minute |
| `/dashboard` | `dashboard()` | User dashboard | Authentication required |
| `/file-integrity-status` | `file_integrity_status()` | File integrity monitor | Admin role required, Rate limited: 10/minute |
| `/ics` | `ics()` | ICS application interface | Authentication required, Operator role required |
| `/ics/environmental` | `environmental_data()` | Environmental monitoring | Authentication required, Operator role required |
| `/privacy` | `privacy()` | Privacy policy | Rate limited: 30/minute, Cached: 24 hours |
| `/profile` | `profile()` | User profile management | Authentication required |
| `/security` | `security()` | Security information | Rate limited: 30/minute, Cached: 12 hours |
| `/terms` | `terms()` | Terms of service | Rate limited: 30/minute, Cached: 24 hours |

**Debug Route** (development environment only):

| Route | Function | Purpose | Security |
|-------|----------|---------|----------|
| `/debug-info` | `debug_info()` | Debug information | Development environment only |

## Templates

The templates implement responsive design using Bootstrap 5, proper accessibility attributes, security best practices, and consistent branding:

- **base.html**: Core template with layout structure, navigation, and security features
  - Common header and footer sections
  - Navigation menu with role-based visibility
  - Security headers and meta tags
  - CSRF protection implementation
  - Theme switching functionality
  - Toast notification system
  - Session management with timeout alerts
  - File integrity status indicators
  - Real-time security alerts

- **Content Pages**:
  - about.html: Company information with contact form
  - home.html: Landing page with feature highlights and security status
  - `privacy.html`: Privacy policy details
  - `terms.html`: Terms of service information
  - `security.html`: Security practices information

- **Application Interfaces**:
  - cloud.html: Real-time cloud infrastructure dashboard
  - `dashboard.html`: User-specific dashboard
  - `ics.html`: Industrial control systems interface
  - `profile.html`: User profile management

- **Authentication Screens** (redirects to auth blueprint):
  - `login.html`: User authentication interface
  - `register.html`: Account registration form

## Security Features

- **AJAX Security**: All AJAX requests include CSRF tokens and proper headers
- **Authentication Controls**: Role-based access control for all routes
- **Content Security Policy**: CSP headers with nonces for inline scripts
- **CSRF Protection**: Token validation for all forms and AJAX requests
- **File Integrity Monitoring**: Continuous monitoring for unauthorized file modifications
- **Input Validation**: Client and server-side validation for user input
- **Pattern Matching**: Detection of suspicious request patterns
- **Rate Limiting**: Configurable request rate limits per endpoint
- **Response Compression**: Automatic response compression for bandwidth optimization
- **Response Headers**: Security headers (X-Frame-Options, CSP, etc.)
- **Secure Cookies**: HTTPOnly, Secure, and SameSite cookie attributes
- **Session Management**: Session timeout monitoring and secure refresh
- **Subresource Integrity**: SRI validation for external resources
- **Suspicious Pattern Detection**: Automated detection of potential attack patterns
- **XSS Prevention**: HTML escaping and output sanitization

### File Integrity Monitoring

The blueprint integrates with the platform's file integrity monitoring system to:

1. Provide admin-accessible status endpoints for monitoring
2. Automatically verify file integrity after system errors
3. Show integrity status indicators in the UI
4. Generate alerts for integrity violations
5. Track integrity metrics for security monitoring

Integrity checking is performed:

- After server errors (5xx status codes) to detect potential attacks
- Through the `/file-integrity-status` endpoint (admin access only)
- On application startup (through separate configuration)

## Common Patterns

### Security-Enhanced Forms

All forms implement these security patterns:

```html
<form method="post" class="needs-validation" novalidate>
    <!-- CSRF Protection -->
    {{ csrf_token() }}

    <div class="mb-3">
        <label for="field-id" class="form-label">Field Label</label>
        <input type="text"
               class="form-control {% if form.field.errors %}is-invalid{% endif %}"
               id="field-id"
               name="field-name"
               required
               pattern="[a-z0-9]+"
               aria-describedby="field-help">

        <div id="field-help" class="form-text">Help text for this field</div>

        {% if form.field.errors %}
            <div class="invalid-feedback">{{ form.field.errors[0] }}</div>
        {% endif %}
    </div>

    <!-- Loading State Button -->
    <button type="submit" class="btn btn-primary">
        <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
        Submit
    </button>
</form>
```

### Secure AJAX Requests

AJAX requests use the secure fetch wrapper:

```javascript
async function performAction() {
    try {
        const response = await secureFetch('/api/endpoint', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
            },
            body: JSON.stringify({ key: 'value' })
        });

        if (response.ok) {
            const data = await response.json();
            // Process successful response
            showToast('Success', 'Operation completed successfully', 'success');
        } else {
            throw new Error('Request failed');
        }
    } catch (error) {
        console.error('Error:', error);
        showToast('Error', 'Failed to complete operation', 'danger');
    }
}
```

### Role-Based Authorization

Routes use the role-based authorization pattern:

```python
from core.security.cs_authorization import require_role

@main_bp.route('/admin')
@login_required
@require_role('admin')
def admin():
    """Admin dashboard requiring admin role."""
    return render_template('main/admin.html')
```

### Security Event Logging

Security-relevant events are logged consistently:

```python
from core.security import log_security_event

# Log the security event
log_security_event(
    event_type='file_integrity_violation',
    description=f"File integrity violation detected: {file_path}",
    severity='critical',
    details={
        'file': file_path,
        'expected_hash': expected_hash,
        'actual_hash': actual_hash,
        'module': module_name
    }
)
```

## Related Documentation

- Authentication Blueprint
- Blueprint Architecture
- Content Security Policy
- CSRF Protection
- Error Handling
- File Integrity Monitoring
- Form Validation Guide
- Rate Limiting
- Response Headers
- Secure AJAX Implementation
- Template Inheritance
