# Flask Blueprints

This directory contains Flask blueprint modules that organize the Cloud Infrastructure Platform application into logical components with isolated routing, templates, and error handling.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Security Features](#security-features)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Blueprint Integrity](#blueprint-integrity)
- [Testing](#testing)
- [Common Patterns](#common-patterns)
- [Related Documentation](#related-documentation)

## Overview

The blueprints package organizes the application's routes and views into modular components using Flask's Blueprint functionality. Each blueprint encapsulates a specific feature area with its own routes, templates, static files, and error handlers. This modular structure improves maintainability through separation of concerns and enables independent testing of components.

The centralized blueprint management system in this package performs:

- Automatic blueprint registration with proper URL prefixes
- Blueprint integrity verification to detect unauthorized code changes
- Dependency tracking between blueprint modules
- Comprehensive error handling for registration failures
- Configuration verification to ensure proper implementation

## Key Components

- **`__init__.py`**: Blueprint registration and initialization
  - Blueprint configuration management
  - Centralized registration function
  - Blueprint dictionary creation
  - Module initialization and exports
  - Blueprint organization utilities
  - File integrity monitoring integration
  - Dependency analysis capabilities

- **`auth/`**: Authentication and authorization blueprint
  - User authentication flows
  - Multi-factor authentication
  - Password management
  - Registration functionality
  - Session management
  - Token handling utilities

- **`main/`**: Primary application interface blueprint
  - Cloud dashboard interface
  - Core application navigation
  - Error handling implementation
  - Home page and landing pages
  - ICS application interface
  - Page templates and layouts

- **`monitoring/`**: System monitoring blueprint
  - Anomaly detection functionality
  - Health check implementations
  - Incident management capabilities
  - Metrics collection and reporting
  - Security monitoring features
  - System status endpoints

- **`admin/`**: Administrative interface blueprint
  - System configuration interface
  - User and permission management
  - Security control administration
  - Audit log analysis interface
  - Compliance reporting tools
  - File integrity monitoring dashboard
  - Security incident management
  - System health monitoring interface
  - User management functionality
  - Role and permission management
  - Compliance reporting features
  - System status dashboard
  - Batch operations interface

## Directory Structure

```plaintext
blueprints/
├── README.md               # This documentation
├── __init__.py             # Blueprint registration and configuration
├── auth/                   # Authentication blueprint
│   ├── README.md           # Authentication documentation
│   ├── __init__.py         # Authentication blueprint initialization
│   ├── decorators.py       # Authentication security decorators
│   ├── routes.py           # Authentication endpoint definitions
│   ├── templates/          # Authentication templates
│   │   └── auth/           # Auth-specific templates
│   │       ├── README.md   # Templates documentation
│   │       ├── change_password.html  # Password change interface
│   │       ├── login.html           # Login interface
│   │       ├── mfa_setup.html       # MFA configuration interface
│   │       ├── register.html        # Registration interface
│   │       └── reset_password.html  # Password reset interface
│   └── utils.py            # Authentication utility functions
├── main/                   # Main application blueprint
│   ├── README.md           # Main blueprint documentation
│   ├── __init__.py         # Main blueprint initialization
│   ├── errors.py           # Error handling implementation
│   ├── routes.py           # Main route definitions
│   ├── static/             # Blueprint-specific static files
│   │   ├── css/            # Blueprint-specific stylesheets
│   │   ├── images/         # Blueprint-specific images
│   │   └── js/             # Blueprint-specific scripts
│   └── templates/          # Blueprint-specific templates
│       └── main/           # Main interface templates
│           ├── README.md   # Templates documentation
│           ├── about.html  # About page template
│           ├── base.html   # Base template with layout
│           ├── cloud.html  # Cloud dashboard template
│           ├── home.html   # Homepage template
│           ├── ics.html    # ICS application template
│           ├── privacy.html     # Privacy policy page
│           ├── profile.html     # User profile management
│           ├── register.html    # Account registration interface
│           ├── security.html    # Security practices information
│           └── terms.html       # Terms of service page
└── monitoring/             # Monitoring blueprint
    ├── README.md           # Monitoring documentation
    ├── __init__.py         # Monitoring blueprint initialization
    ├── metrics.py          # Metrics collection functionality
    └── routes.py           # Monitoring endpoint definitions
```

## Usage

### Blueprint Registration

Blueprints are registered with the Flask application in the main app.py file:

```python
from flask import Flask
from blueprints import register_all_blueprints

app = Flask(__name__)
# Configure the application
register_all_blueprints(app)
```

### Creating a New Blueprint

To create a new blueprint:

```python
from flask import Blueprint, render_template

# Create a new blueprint
new_feature_bp = Blueprint(
    'new_feature',
    __name__,
    url_prefix='/new-feature',
    template_folder='templates',
    static_folder='static'
)

# Define routes for the blueprint
@new_feature_bp.route('/')
def index():
    return render_template('new_feature/index.html')

# Add error handlers specific to this blueprint
@new_feature_bp.errorhandler(404)
def not_found_error(error):
    return render_template('new_feature/errors/404.html'), 404

# Register blueprint with the application
# In blueprints/__init__.py, add to blueprint_configs:
# (new_feature_bp, '/new-feature')
```

### Accessing Blueprint-Specific Templates

```python
from flask import render_template, Blueprint

example_bp = Blueprint('example', __name__, template_folder='templates')

@example_bp.route('/example')
def example():
    # Flask will look for the template in blueprints/example/templates/example.html
    return render_template('example/example.html')
```

### Blueprint Initialization Hook

To initialize a blueprint with application context:

```python
@blueprint_name.record_once
def on_blueprint_init(state):
    """Initialize blueprint with application context."""
    app = state.app

    # Configure blueprint with application settings
    blueprint_name.config = app.config.get('BLUEPRINT_CONFIG', {})

    # Initialize any blueprint-specific extensions
    if hasattr(blueprint_name, 'init_app'):
        blueprint_name.init_app(app)
```

### Dependency Analysis

To analyze blueprint dependencies:

```python
from blueprints import get_blueprint_dependency_graph

def check_dependencies():
    # Get dependency graph showing which blueprints depend on others
    dependencies = get_blueprint_dependency_graph()

    # Check for circular dependencies
    for blueprint, deps in dependencies.items():
        for dep in deps:
            if blueprint in dependencies.get(dep, []):
                print(f"Warning: Circular dependency between {blueprint} and {dep}")
```

## Security Features

- **Access Control**: Role-based access control for sensitive routes
- **Authentication**: Token-based and session-based authentication
- **CSRF Protection**: Cross-site request forgery protection for all forms
- **Error Handling**: Consistent, security-focused error responses
- **File Integrity**: Automatic file integrity monitoring for blueprint code
- **Input Validation**: Thorough validation of all user inputs
- **Output Sanitization**: Proper escaping of rendered content
- **Rate Limiting**: Route-specific rate limiting to prevent abuse
- **Session Management**: Secure session handling with timeout and renewal
- **Secure Headers**: Security headers for XSS, clickjacking protection
- **Subresource Integrity**: SRI hashes for external resources

## File Integrity Monitoring

The blueprint system integrates comprehensive file integrity monitoring to ensure the security and reliability of application code. This functionality is distributed across multiple blueprints:

### Implementation Architecture

The file integrity monitoring system uses a layered approach:

1. **Core Implementation**: Provided by `core.security.cs_file_integrity` module
2. **Admin Interface**: Management dashboard in the admin blueprint
3. **Status Indicators**: Visual indicators in the main blueprint
4. **Metrics Collection**: Monitoring metrics in the monitoring blueprint
5. **Framework Integration**: Automated checks at application startup

### Integrity Monitoring Features

- **Baseline Management**: Creating and verifying integrity baselines
- **Real-time Verification**: On-demand integrity checks
- **Path Filtering**: Include/exclude specific file patterns
- **Automatic Backups**: Versioned baseline backups
- **Security Classification**: Severity-based file categorization
- **Comprehensive Logging**: Detailed audit trail for all operations
- **Integration Points**: Health checks, status monitoring, and alerts

### Blueprint-Specific Implementations

#### Main Blueprint

The main blueprint integrates file integrity status into the user interface:

```python
@main_bp.route('/file-integrity-status')
@login_required
@require_role('admin')
def file_integrity_status():
    """Return file integrity status for monitoring."""
    if not FILE_INTEGRITY_AVAILABLE:
        return jsonify({'status': 'unavailable', 'message': 'File integrity monitoring not available'})

    status = check_integrity()
    return jsonify({
        'status': 'valid' if status['valid'] else 'invalid',
        'timestamp': status['timestamp'],
        'violations': status['violations_count'],
        'message': status['message']
    })
```

The main template `base.html` displays integrity status in non-production environments:

```html
{% if config.ENVIRONMENT != 'production' %}
<div class="integrity-status integrity-status-{{ file_integrity_status|default('valid') }}">
    <i class="bi bi-shield-{{ file_integrity_status == 'valid' ? 'check' : 'exclamation' }}"
       aria-hidden="true"></i>
    File Integrity: {{ file_integrity_status|default('Valid')|capitalize }}
</div>
{% endif %}
```

#### Admin Blueprint

The admin blueprint provides comprehensive management functions:

```python
@admin_bp.route('/security/integrity/update', methods=['POST'])
@login_required
@require_role('admin')
@require_mfa
@audit_log_action('file_integrity_baseline_update')
def update_integrity_baseline():
    """Update file integrity baseline with validation and security checks."""
    form = FileIntegrityForm()

    if form.validate_on_submit():
        try:
            # Update the integrity baseline
            result = update_file_integrity_baseline(
                paths=form.paths.data.split('\n'),
                include_patterns=form.include_patterns.data.split('\n'),
                exclude_patterns=form.exclude_patterns.data.split('\n'),
                reason=form.reason.data
            )

            # Log detailed audit information
            audit_action(
                'file_integrity_baseline_updated',
                f"Updated file integrity baseline: {result['files_processed']} files processed",
                user_id=current_user.id,
                details={
                    'files_processed': result['files_processed'],
                    'files_added': result['files_added'],
                    'files_updated': result['files_updated'],
                    'files_removed': result['files_removed'],
                    'reason': form.reason.data
                }
            )

            flash(f"File integrity baseline updated: {result['files_processed']} files processed", 'success')
            return redirect(url_for('admin.file_integrity'))

        except Exception as e:
            flash(f"Error updating integrity baseline: {str(e)}", 'danger')

    return render_template('admin/security/file_integrity.html', form=form)
```

#### Monitoring Blueprint

The monitoring blueprint tracks integrity violations and exports metrics:

```python
@monitoring_bp.route('/metrics/prometheus')
def prometheus_metrics():
    """Export metrics in Prometheus format."""
    # Other metrics collection...

    # File integrity metrics
    try:
        if FILE_INTEGRITY_AVAILABLE:
            integrity_status = check_integrity()
            metrics.gauge(
                'file_integrity_status',
                1 if integrity_status['valid'] else 0
            )
            metrics.gauge(
                'file_integrity_violations',
                integrity_status['violations_count']
            )
            metrics.gauge(
                'file_integrity_check_timestamp',
                integrity_status['timestamp_epoch']
            )
    except Exception as e:
        logger.warning(f"Error collecting integrity metrics: {e}")

    # Return compiled metrics
    return Response(metrics.export_prometheus(), mimetype='text/plain')
```

### Central Blueprint Registration

The central blueprint registration integrates file integrity checks:

```python
def _update_blueprint_baseline(app: Flask) -> None:
    """Update file integrity baseline for blueprints."""
    if not app.config.get('AUTO_UPDATE_BLUEPRINT_BASELINE', False):
        return

    try:
        # Get all blueprint files
        blueprint_files = []
        for bp_name, bp_module in blueprints.items():
            bp_path = os.path.dirname(sys.modules[bp_module.__module__].__file__)
            for root, _, files in os.walk(bp_path):
                for file in files:
                    if file.endswith('.py'):
                        blueprint_files.append(os.path.join(root, file))

        # Calculate hashes and prepare updates
        updates = []
        for file_path in blueprint_files:
            if os.path.isfile(file_path):
                # Calculate file hash
                current_hash = calculate_file_hash(file_path)

                # Get relative path for the baseline
                rel_path = os.path.relpath(file_path, os.path.dirname(app.root_path))

                # Set severity based on file path and type
                severity = 'medium'  # Default severity
                if '__init__.py' in file_path or 'routes.py' in file_path:
                    severity = 'high'  # Higher severity for route definitions
                if 'auth' in file_path:
                    severity = 'high'  # Security-critical blueprint

                # Add to updates list
                updates.append({
                    'path': rel_path,
                    'current_hash': current_hash,
                    'severity': severity
                })

        # Update baseline with notifications
        if updates and hasattr(app, 'logger'):
            app.logger.info(f"Updating file integrity baseline for {len(updates)} blueprint files")
            update_file_integrity_baseline(updates=updates, source="blueprint_registration")

    except Exception as e:
        if hasattr(app, 'logger'):
            app.logger.error(f"Error updating blueprint baseline: {e}")
```

## Blueprint Integrity

The blueprint system integrates with the platform's file integrity monitoring to:

1. **Verify Code Integrity**: Detects unauthorized changes to blueprint code
2. **Update Baselines**: Automatically updates integrity baselines during development
3. **Security Alerting**: Logs security events when integrity violations are detected
4. **Dependency Tracking**: Monitors blueprint dependencies for security implications
5. **Configuration Verification**: Validates blueprint configuration against standards

The integrity verification process runs:

- During application startup
- After blueprint registration
- When specifically requested by diagnostic tools

Configuration options for integrity monitoring:

- `VERIFY_BLUEPRINT_INTEGRITY`: Enable/disable integrity verification
- `AUTO_UPDATE_BLUEPRINT_BASELINE`: Auto-update baselines in development
- `FILE_BASELINE_PATH`: Path to integrity baseline file

## Testing

Each blueprint includes its own test directory with:

- Route tests ensuring correct access control
- Template rendering tests
- Input validation tests
- Security control tests
- Error handling tests

Run blueprint-specific tests:

```bash
# Test a specific blueprint
pytest tests/blueprints/auth/
pytest tests/blueprints/main/
pytest tests/blueprints/monitoring/
```

## Common Patterns

### Route Protection with Role Requirements

```python
from flask import Blueprint
from decorators import login_required, require_role

bp = Blueprint('example', __name__)

@bp.route('/admin')
@login_required
@require_role('admin')
def admin_route():
    """Protected route requiring admin role."""
    return render_template('admin.html')
```

### Error Handling

```python
from flask import Blueprint, jsonify, render_template, request

bp = Blueprint('example', __name__)

@bp.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors with appropriate format based on request."""
    if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
        return jsonify(error="Not found", code=404), 404
    return render_template('errors/404.html'), 404
```

### Blueprint-Specific Configuration

```python
from flask import Blueprint, current_app

bp = Blueprint('example', __name__)

@bp.before_app_first_request
def setup_blueprint_config():
    """Set up blueprint-specific configuration."""
    config = current_app.config.get('EXAMPLE_BLUEPRINT', {})
    bp.config = config

    # Initialize features based on config
    if config.get('FEATURE_ENABLED'):
        # Set up feature
        pass
```

### Request Preprocessing

```python
from flask import Blueprint, g, request
import uuid

bp = Blueprint('example', __name__)

@bp.before_request
def before_request():
    """Preprocess requests to this blueprint."""
    # Generate request ID for traceability
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.start_time = datetime.utcnow()

    # Add security context
    g.security_context = {
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string
    }
```

### Blueprint-Specific Static Files

```python
from flask import Blueprint, url_for

# Create blueprint with static folder
bp = Blueprint('example', __name__, static_folder='static')

@bp.route('/with-custom-static')
def with_custom_static():
    # Access blueprint-specific static files
    css_url = url_for('example.static', filename='css/style.css')
    js_url = url_for('example.static', filename='js/script.js')
    return render_template('example.html', css_url=css_url, js_url=js_url)
```

## Related Documentation

- Blueprint Architecture
- Authentication Blueprint
- Main Blueprint
- Monitoring Blueprint
- Error Handling Guide
- Blueprint Development Guide
- Template Organization
- Static File Management
- Security Controls Implementation
- Flask Application Structure
- File Integrity Monitoring Guide
