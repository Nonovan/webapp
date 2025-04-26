# Main Templates

This directory contains HTML templates for the main application blueprint, providing user interface components for the Cloud Infrastructure Platform's primary features including home page, about page, cloud dashboard, and ICS application interface.

## Contents

- Overview
- Key Templates
- Directory Structure
- Template Features
- JavaScript Components
- Security Features
- Common Patterns
- Related Documentation

## Overview

The main templates provide the primary user interfaces for the Cloud Infrastructure Platform. These templates implement responsive design using Bootstrap 5, proper accessibility attributes, security best practices, and consistent branding. The templates are organized to maximize code reuse through template inheritance from the base template, which provides the common layout, navigation, footer, and shared JavaScript functionality.

## Key Templates

- **`about.html`**: Company and platform information
  - Company mission and overview
  - Security commitment section
  - Compliance certifications display
  - Contact form with validation
  - Team and architecture information

- **`base.html`**: Base template with layout structure
  - Common header and navigation
  - Footer with site links
  - Security headers and meta tags
  - Theme switcher implementation
  - CSRF protection for AJAX requests
  - Session management features

- **`cloud.html`**: Cloud services dashboard
  - Real-time system metrics
  - Resource utilization gauges
  - Active user monitoring
  - System alerts visualization
  - Auto-refresh functionality
  - AJAX data loading implementation

- **`home.html`**: Platform landing page
  - Feature highlights section
  - Security status overview
  - System metrics visualization
  - Call-to-action components
  - User onboarding guidance

- **`ics.html`**: Industrial control systems interface
  - System control panel
  - Parameter adjustment interface
  - Status monitoring components
  - Visualization of system metrics
  - Real-time data display

- **`login.html`**: User authentication interface
  - Secure login form
  - Multi-factor authentication support
  - Login security notifications
  - Password visibility toggle
  - Error handling and validation

- **`register.html`**: Account registration interface
  - User registration form
  - Password strength meter
  - Form validation with feedback
  - Terms and conditions modal
  - Social registration options

## Directory Structure

```plaintext
blueprints/main/templates/main/
├── README.md        # This documentation
├── about.html       # Company and platform information
├── base.html        # Base template with layout structure
├── cloud.html       # Cloud services dashboard
├── home.html        # Platform landing page
├── ics.html         # Industrial control systems interface
├── login.html       # User authentication interface
└── register.html    # Account registration interface
```

## Template Features

### Accessibility

All templates implement accessibility best practices:

- Appropriate ARIA roles and labels
- Proper heading hierarchy
- Focus management for interactive elements
- Skip links for keyboard navigation
- Visual indicators for interactive states
- Screen reader compatible markup

### Responsive Design

Templates are fully responsive across device sizes:

- Mobile-first approach with Bootstrap
- Appropriate breakpoints for different screen sizes
- Responsive image handling with lazy loading
- Touch-friendly interactive elements
- Content prioritization on small screens

### Security Implementations

Templates incorporate security best practices:

- Content Security Policy nonces for inline scripts
- CSRF token inclusion in all forms
- Input validation with appropriate patterns
- Secure form handling practices
- XSS prevention through output escaping
- User session timeout notifications

## JavaScript Components

### Common Components

- **Authentication Utilities**: Password visibility toggle, strength validation
- **Content Loading**: AJAX data fetch with security headers
- **Form Validation**: Client-side validation with accessibility
- **Security Features**: CSRF protection, brute force prevention
- **Session Management**: Timeout detection and handling
- **Theme Switcher**: Light/dark theme toggle with preference storage
- **Toast Notifications**: User feedback system

### Dashboard Components

- **Data Visualization**: Charts and gauges for metrics
- **Auto-Refresh**: Configurable automatic data refresh
- **Alert Management**: Alert acknowledgment and investigation
- **User Management**: Active user monitoring and management

## Security Features

- **AJAX Security**: All AJAX requests include CSRF tokens and proper security headers
- **Authentication Controls**: Rate limiting notifications, proper error handling
- **Content Security Policy**: Nonces for inline scripts, strict CSP implementation
- **CSRF Protection**: All forms and AJAX requests include CSRF tokens
- **Input Validation**: Client-side validation complements server-side checks
- **Output Sanitization**: All dynamic content is properly escaped
- **Resource Management**: Subresource Integrity (SRI) for external resources
- **Secure Attributes**: Secure cookie attributes, proper security headers

## Common Patterns

### Form Implementation

Forms follow a consistent pattern:

```html
<form method="post" class="needs-validation" novalidate>
    <!-- CSRF Token -->
    {{ form.csrf_token }}

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

    <button type="submit" class="btn btn-primary" id="submitBtn">
        <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
        Submit
    </button>
</form>
```

### AJAX Request Implementation

AJAX requests use the `secureFetch` wrapper:

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

- Authentication Templates
- Bootstrap Framework
- Content Security Policy
- CSRF Protection
- Form Validation
- JavaScript Components
- Template Inheritance
- Theme Implementation
