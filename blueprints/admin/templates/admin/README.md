# Admin Templates

This directory contains HTML templates for the administrative interface of the Cloud Infrastructure Platform, providing secure, responsive, and accessible administrative tools for system management.

## Contents

- [Overview](#overview)
- [Key Templates](#key-templates)
- [Directory Structure](#directory-structure)
- [Template Features](#template-features)
- [Layout Structure](#layout-structure)
- [JavaScript Components](#javascript-components)
- [Security Features](#security-features)
- [Common Patterns](#common-patterns)
- [Related Documentation](#related-documentation)

## Overview

The admin templates provide a secure administrative interface for platform management, allowing administrators to configure system settings, manage users and permissions, monitor security events, and generate compliance reports. These templates implement strict security controls, responsive design, accessibility standards, and comprehensive audit logging throughout all administrative interfaces. The templates follow Bootstrap 5 design patterns with enhanced security features specifically for administrative operations.

## Key Templates

- **`layout.html`**: Primary layout template for admin pages
  - Secure header with security meta tags
  - Responsive navigation structure
  - File integrity status indicators
  - Security alert notifications
  - Content Security Policy implementation
  - Session management controls
  - Toast notification system

- **`base.html`**: Alternative layout with sidebar design
  - Vertical navigation sidebar
  - Collapsible menu groups
  - Security status indicators
  - Session timeout monitoring
  - Mobile-responsive design
  - Theme switching capability

- **`dashboard.html`**: Administrative overview
  - System status widgets
  - Security metrics visualization
  - Active user monitoring
  - Recent activity timeline
  - Quick-access administrative tools
  - Security incident summary
  - System health indicators
  - Usage statistics

- **User Management**
  - `users/list.html`: User accounts listing
  - `users/create.html`: New user creation interface
  - `users/edit.html`: User account editing

- **System Management**
  - `system/settings.html`: Configuration management
  - `system/health.html`: System health monitoring

- **Security Administration**
  - `security/audit_logs.html`: Security audit viewer
  - `security/file_integrity.html`: File integrity monitoring
  - `security/incidents.html`: Security incident management

- **Reports**
  - `reports/compliance.html`: Compliance reporting
  - `reports/security.html`: Security reporting

## Directory Structure

```plaintext
admin/
├── README.md                 # This documentation
├── base.html                 # Base template with sidebar layout
├── dashboard.html            # Admin dashboard
├── layout.html               # Alternative layout template
├── reports/                  # Report generation
│   ├── compliance.html       # Compliance reporting
│   └── security.html         # Security reporting
├── security/                 # Security administration
│   ├── audit_logs.html       # Audit log viewer
│   ├── file_integrity.html   # File integrity dashboard
│   └── incidents.html        # Incident management
├── system/                   # System configuration
│   ├── health.html           # System health monitoring
│   └── settings.html         # System settings interface
└── users/                    # User management
    ├── create.html           # User creation interface
    ├── edit.html             # User editing interface
    └── list.html             # User listing interface
```

## Template Features

### Responsive Design

All admin templates implement responsive design for various device sizes:

- Fluid layouts using Bootstrap 5 grid system
- Responsive sidebar that collapses on small screens
- Touch-friendly controls for mobile devices
- Data tables with horizontal scrolling on small screens
- Appropriate breakpoints for different device categories
- Responsive typography and spacing

### Accessibility

The admin templates follow accessibility best practices:

- Semantic HTML5 markup with proper heading structure
- ARIA roles, labels, and landmarks for screen readers
- Keyboard navigation with visible focus indicators
- Skip navigation links for keyboard users
- Color contrast meeting WCAG AA standards
- Form labels and error states with proper associations
- Alt text for meaningful images and decorative image handling

### Consistent Components

Standard components used across admin templates:

- Card-based content containers with consistent styling
- Contextual alert messages with appropriate icons
- Modal dialogs for confirmations and detail views
- Dropdown menus for action grouping
- Breadcrumb navigation for hierarchy indication
- Standardized form layouts and validation patterns
- Badge indicators for status visualization
- Progress indicators for multi-step operations

## Layout Structure

### Base Layout (`base.html`)

The sidebar layout structure includes these key sections:

```plaintext
+------------------------------------------+
| Skip link (visually hidden until focused)|
+------------------------------------------+
| +-------------+ +----------------------+ |
| | Logo/Title  | | User/Theme controls  | |
| +-------------+ +----------------------+ |
| +-------------+ +----------------------+ |
| |             | |                      | |
| | Sidebar     | |  Header with         | |
| | Navigation  | |  - Breadcrumbs       | |
| | with        | |  - Page title        | |
| | collapsible | |  - Page actions      | |
| | sections    | |  - Flash messages    | |
| |             | |  - Integrity alerts  | |
| |             | |                      | |
| |             | |  Main content area   | |
| |             | |                      | |
| |             | |                      | |
| |             | |                      | |
| +-------------+ +----------------------+ |
| +--------------------------------------+ |
| | Footer with integrity status         | |
| +--------------------------------------+ |
+------------------------------------------+
```

### Alternative Layout (`layout.html`)

The horizontal navigation layout includes:

```plaintext
+------------------------------------------+
| Skip link (visually hidden until focused)|
+------------------------------------------+
| +--------------------------------------+ |
| | Navbar with logo and navigation      | |
| +--------------------------------------+ |
| +--------------------------------------+ |
| | File integrity alerts (if present)   | |
| +--------------------------------------+ |
| +--------------------------------------+ |
| | Header with breadcrumbs and actions  | |
| +--------------------------------------+ |
| +--------------------------------------+ |
| | Flash messages                       | |
| +--------------------------------------+ |
| +--------------------------------------+ |
| |                                      | |
| | Main content area                    | |
| |                                      | |
| |                                      | |
| +--------------------------------------+ |
| +--------------------------------------+ |
| | Footer with integrity status         | |
| +--------------------------------------+ |
+------------------------------------------+
```

## JavaScript Components

### Core Functionality

- **Session Management**: Session timeout detection and prevention
- **Theme Management**: Light/dark theme toggling with persistence
- **Form Validation**: Enhanced client-side validation with accessibility
- **Secure AJAX**: Standardized secure AJAX communication pattern
- **Toast Notifications**: Dynamic notification system
- **Loading Indicators**: Consistent loading state visualization
- **Modal Dialog**: Enhanced modal dialog implementations

### Security Components

- **Session Timeout Warning**: Proactive timeout notification with extension option
- **File Integrity Visualization**: Visual indicators of system integrity status
- **CSRF Protection**: Automatic CSRF token inclusion in requests
- **Error Handling**: Structured error handling with security considerations
- **Secure Form Handling**: Prevention of double submission and proper validation

## Security Features

The admin templates implement comprehensive security measures:

- **Content Security Policy**: Strict CSP rules with nonce-based script execution
- **CSRF Protection**: All forms include CSRF token protection
- **Secure Headers**: Implementation of security-enhancing HTTP headers
- **Input Validation**: Thorough client-side form validation
- **Session Protection**: Enhanced session security with timeout notifications
- **User Activity Tracking**: All actions are logged for audit purposes
- **File Integrity Monitoring**: Real-time integrity status visualization
- **Security Notifications**: Prominent display of security-related alerts
- **Secure Response Handling**: Proper handling of security-sensitive responses
- **Permission Visualization**: Clear indication of required permissions
- **Secure Modal Dialogs**: Security confirmations for sensitive operations
- **Audit Logging Indicators**: Visual feedback for logged administrative actions

## Common Patterns

### Form Implementation

Standard admin form implementation pattern:

```html
<form method="post" class="needs-validation" novalidate id="formId">
    {{ form.csrf_token }}

    <div class="mb-3">
        <label for="fieldId" class="form-label">Field Label</label>
        <div class="input-group has-validation">
            <span class="input-group-text">
                <i class="bi bi-appropriate-icon"></i>
            </span>
            <input type="text"
                   class="form-control {% if form.field.errors %}is-invalid{% endif %}"
                   id="fieldId"
                   name="field"
                   value="{{ form.field.data or '' }}"
                   required>
            <div class="invalid-feedback">
                {% if form.field.errors %}
                {{ form.field.errors[0] }}
                {% else %}
                Please provide a valid input.
                {% endif %}
            </div>
        </div>
        <div class="form-text small">Help text for this field</div>
    </div>

    <!-- Security information notice -->
    <div class="alert alert-info d-flex" role="alert">
        <i class="bi bi-info-circle-fill me-2 flex-shrink-0"></i>
        <div>
            <strong>Security Information:</strong> This action will be logged in the audit trail.
        </div>
    </div>

    <!-- Action buttons with loading state -->
    <div class="d-flex justify-content-between mt-4">
        <a href="{{ url_for('admin.previous_page') }}" class="btn btn-outline-secondary">
            <i class="bi bi-arrow-left me-1"></i> Cancel
        </a>
        <button type="submit" class="btn btn-primary" id="submitBtn">
            <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
            <i class="bi bi-save me-1"></i> Save Changes
        </button>
    </div>
</form>
```

### AJAX Request Implementation

Standard pattern for secure AJAX requests:

```javascript
// Secure fetch with CSRF token and error handling
async function secureFetch(url, options = {}) {
    // Get CSRF token from meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

    // Set default options with security headers
    const defaultOptions = {
        headers: {
            'X-CSRF-Token': csrfToken,
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    };

    // Show loading indicator
    showLoading();

    try {
        // Merge options
        const mergedOptions = { ...defaultOptions, ...options };
        if (options.headers) {
            mergedOptions.headers = { ...defaultOptions.headers, ...options.headers };
        }

        // Make request
        const response = await fetch(url, mergedOptions);

        // Handle 401 Unauthorized (session expired)
        if (response.status === 401) {
            showToast('Session Expired', 'Your session has expired. Please log in again.', 'danger');
            setTimeout(() => {
                window.location.href = "/auth/login";
            }, 2000);
            throw new Error('Session expired');
        }

        // Handle 403 Forbidden (permission denied)
        if (response.status === 403) {
            showToast('Access Denied', 'You do not have permission to perform this action.', 'danger');
            throw new Error('Permission denied');
        }

        return response;
    } finally {
        // Hide loading indicator
        hideLoading();
    }
}
```

### Card Components

Standard admin card pattern:

```html
<div class="card shadow-sm mb-4">
    <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <h5 class="card-title mb-0">Card Title</h5>
        <span class="badge bg-primary">Status</span>
    </div>
    <div class="card-body">
        <!-- Card content -->
    </div>
    <div class="card-footer bg-white d-flex justify-content-between align-items-center">
        <div class="text-muted small">Footer information</div>
        <div>
            <button class="btn btn-sm btn-primary">Action</button>
        </div>
    </div>
</div>
```

## Related Documentation

- Access Control Implementation
- Audit Logging Framework
- [Bootstrap Framework](https://getbootstrap.com/docs/5.3/)
- Content Security Policy
- CSRF Protection
- File Integrity Monitoring
- Form Validation Guide
- Security Controls Implementation
- Template Inheritance
- User Management Guide
