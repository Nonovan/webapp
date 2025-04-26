# Main Blueprint

This blueprint provides the primary user interface and core application functionality for the Cloud Infrastructure Platform, implementing responsive, secure, and accessible web pages for essential platform features.

## Contents

- Overview
- Key Components
- Directory Structure
- Routes
- Templates
- Security Features
- Common Patterns
- Related Documentation

## Overview

The Main blueprint serves as the central module for end-user interaction with the platform. It delivers the home page, about page, cloud services dashboard, ICS application interface, and user profile pages. The blueprint implements comprehensive security controls, performance monitoring, responsive design, and accessibility features throughout all user interfaces. It follows an MVC pattern with routes handling business logic and templates providing the presentation layer.

## Key Components

- **`__init__.py`**: Blueprint initialization and request processing
  - Blueprint registration and configuration
  - Request metrics collection
  - Response header security enhancements
  - Request lifecycle hooks
  - Centralized error handling setup

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

- **`templates/`**: User interface templates
  - Base template with common layout elements
  - Page-specific templates with responsive design
  - Secure form implementations
  - Real-time dashboard interfaces
  - User profile and settings interfaces

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
        └── register.html    # Account registration interface
```

## Routes

| Route | Function | Purpose | Security |
|-------|----------|---------|----------|
| `/` | `home()` | Landing page | Rate limited: 60/minute, Cached: 5 minutes |
| `/about` | `about()` | Company information | Rate limited: 30/minute, Cached: 1 hour |
| admin | `admin()` | Administrative panel | Authentication required, Admin role required |
| `/cloud` | `cloud()` | Cloud services dashboard | Authentication required, Admin role required |
| `/contact` | `contact()` | Contact form | Rate limited: 10/minute |
| `/ics` | `ics()` | ICS application interface | Authentication required, Operator role required |
| `/ics/environmental` | `environmental_data()` | Environmental monitoring | Authentication required, Operator role required |
| `/profile` | `profile()` | User profile management | Authentication required |

## Templates

The templates implement responsive design using Bootstrap 5, proper accessibility attributes, security best practices, and consistent branding:

- **`base.html`**: Core template with layout structure, navigation, and security features
  - Common header and footer sections
  - Navigation menu with role-based visibility
  - Security headers and meta tags
  - CSRF protection implementation
  - Theme switching functionality
  - Toast notification system
  - Session management with timeout alerts

- **Content Pages**:
  - about.html: Company information with contact form
  - home.html: Landing page with feature highlights and security status

- **Application Interfaces**:
  - cloud.html: Real-time cloud infrastructure dashboard
  - ics.html: Industrial control systems interface

- **Authentication Screens**:
  - login.html: User authentication interface
  - register.html: Account registration form

## Security Features

- **AJAX Security**: All AJAX requests include CSRF tokens and proper headers
- **Authentication Controls**: Role-based access control for all routes
- **Content Security Policy**: CSP headers with nonces for inline scripts
- **CSRF Protection**: Token validation for all forms and AJAX requests
- **Input Validation**: Client and server-side validation for user input
- **Rate Limiting**: Configurable request rate limits per endpoint
- **Response Headers**: Security headers (X-Frame-Options, CSP, etc.)
- **Secure Cookies**: HTTPOnly, Secure, and SameSite cookie attributes
- **Session Management**: Session timeout monitoring and secure refresh
- **XSS Prevention**: HTML escaping and output sanitization

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

## Related Documentation

- Authentication Blueprint
- Blueprint Architecture
- Content Security Policy
- CSRF Protection
- Error Handling
- Form Validation Guide
- Rate Limiting
- Response Headers
- Secure AJAX Implementation
- Template Inheritance
