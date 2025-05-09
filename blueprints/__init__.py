"""
Blueprint package for the myproject Flask application.

This package organizes the application's routes and views into logical modules
using Flask's Blueprint functionality. Each blueprint encapsulates a specific
feature area of the application with its own routes, templates, and error handlers,
promoting modular design and separation of concerns.

The package includes the following blueprints:
- auth: Authentication flows including login, registration, and password management
- main: Primary application routes for the core user interface
- monitoring: System health monitoring and performance metrics

Blueprint organization follows best practices:
1. Each blueprint has its own directory with routes, templates, and static files
2. Templates are namespaced to avoid collisions
3. Common functionality is shared through utility modules
4. Each blueprint has specific error handlers for consistent responses

This modular structure enhances maintainability by isolating feature implementations
and enables better testing by allowing components to be tested independently.
"""

import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set, Any

from flask import Flask, Blueprint, current_app

# Initialize package logger
logger = logging.getLogger(__name__)

# Import blueprints - using try/except to handle potential import errors gracefully
try:
    from api import api_bp
except ImportError as e:
    logger.warning(f"Could not import API blueprint: {e}")
    api_bp = None

try:
    from .auth.routes import auth_bp
except ImportError as e:
    logger.warning(f"Could not import Auth blueprint: {e}")
    auth_bp = None

try:
    from .main.routes import main_bp
except ImportError as e:
    logger.warning(f"Could not import Main blueprint: {e}")
    main_bp = None

try:
    from .monitoring.routes import monitoring_bp
except ImportError as e:
    logger.warning(f"Could not import Monitoring blueprint: {e}")
    monitoring_bp = None

try:
    from .admin.routes import admin_bp
except ImportError as e:
    logger.debug(f"Could not import Admin blueprint: {e}")
    admin_bp = None

# Define blueprint configuration - each entry specifies the blueprint object and its URL prefix
blueprint_configs = []

# Only add blueprints that were successfully imported
if auth_bp:
    blueprint_configs.append((auth_bp, '/auth'))

if main_bp:
    blueprint_configs.append((main_bp, '/'))  # Main blueprint at root level

if monitoring_bp:
    blueprint_configs.append((monitoring_bp, '/monitoring'))

if admin_bp:
    blueprint_configs.append((admin_bp, '/admin'))

# Create a dictionary of blueprint objects for reference
blueprints: Dict[str, Blueprint] = {}
if auth_bp:
    blueprints['auth'] = auth_bp
if main_bp:
    blueprints['main'] = main_bp
if monitoring_bp:
    blueprints['monitoring'] = monitoring_bp
if admin_bp:
    blueprints['admin'] = admin_bp

def register_all_blueprints(app: Flask) -> Set[str]:
    """
    Register all application blueprints with the Flask application.

    This function is the central registration point for all blueprints in the application.
    It registers each blueprint with its appropriate URL prefix and applies any
    blueprint-specific configuration.

    Args:
        app (Flask): The Flask application instance

    Returns:
        Set[str]: Set of names of successfully registered blueprints

    Example:
        from flask import Flask
        from blueprints import register_all_blueprints

        app = Flask(__name__)
        registered_blueprints = register_all_blueprints(app)
    """
    start_time = time.time()
    registered_blueprints = set()

    # Track critical blueprint failures separately
    critical_failures = []

    # Register API blueprints if available
    if api_bp:
        try:
            app.register_blueprint(api_bp, url_prefix='/api')
            app.logger.info("Registered API blueprint")
            registered_blueprints.add('api')
        except Exception as e:
            app.logger.error(f"Failed to register API blueprint: {str(e)}")
            critical_failures.append(('api', str(e)))

    # Track registration success count
    success_count = 0

    # Register each blueprint with its configured URL prefix
    for blueprint, url_prefix in blueprint_configs:
        try:
            app.register_blueprint(blueprint, url_prefix=url_prefix)
            blueprint_name = getattr(blueprint, 'name', 'unknown')
            app.logger.info(f"Registered blueprint: {blueprint_name} with prefix: {url_prefix}")
            success_count += 1
            registered_blueprints.add(blueprint_name)

            # Initialize any blueprint-specific configuration
            if hasattr(blueprint, 'init_app'):
                blueprint.init_app(app)

        except Exception as e:
            blueprint_name = getattr(blueprint, 'name', 'unknown')
            app.logger.error(f"Failed to register blueprint {blueprint_name}: {str(e)}")

            # Critical blueprints should be tracked for integrity monitoring
            if blueprint_name in ['auth', 'main']:
                critical_failures.append((blueprint_name, str(e)))

    # Log registration summary with security implications
    duration_ms = (time.time() - start_time) * 1000
    total = len(blueprint_configs)

    if success_count < total:
        app.logger.warning(
            f"Only {success_count}/{total} blueprints registered successfully in {duration_ms:.2f}ms. "
            f"This may impact application functionality."
        )

        # Log critical failures separately for alerting
        if critical_failures:
            critical_failures_str = ", ".join([f"{name}: {error}" for name, error in critical_failures])
            app.logger.error(f"Critical blueprint registration failures: {critical_failures_str}")

            # Log security event for critical failures
            try:
                from core.security import log_security_event
                log_security_event(
                    event_type='blueprint_registration_failure',
                    description="Critical blueprint registration failures detected",
                    severity='high',
                    details={
                        'failures': critical_failures,
                        'registered': list(registered_blueprints)
                    }
                )
            except ImportError:
                # Security module may not be available during app initialization
                app.logger.debug("Security module not available for event logging")
    else:
        app.logger.info(f"All {total} blueprints registered successfully in {duration_ms:.2f}ms")

    # Update file integrity baseline in development mode
    if app.config.get('ENVIRONMENT') == 'development' and app.config.get('AUTO_UPDATE_BLUEPRINT_BASELINE', False):
        try:
            _update_blueprint_baseline(app)
        except Exception as e:
            app.logger.warning(f"Failed to update blueprint baseline: {str(e)}")

    # Check blueprint integrity if configured
    if app.config.get('VERIFY_BLUEPRINT_INTEGRITY', False):
        try:
            _verify_blueprint_integrity(app)
        except Exception as e:
            app.logger.error(f"Blueprint integrity verification failed: {str(e)}")

    return registered_blueprints


def _update_blueprint_baseline(app: Flask) -> None:
    """
    Update the file integrity baseline for blueprint files.

    This function is typically used in development environments to keep
    the baseline in sync with legitimate blueprint changes.

    Args:
        app (Flask): The Flask application instance
    """
    try:
        from services import update_file_integrity_baseline_with_notifications
        from core.security.cs_file_integrity import calculate_file_hash

        # Get blueprints directory path
        blueprints_dir = os.path.dirname(os.path.abspath(__file__))

        # Check if directory exists
        if not os.path.exists(blueprints_dir):
            app.logger.warning("Blueprints directory not found")
            return

        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            app.logger.debug("Baseline path not configured, cannot update blueprint baseline")
            return

        # Collect Python files in directory
        blueprint_files = []
        for root, _, files in os.walk(blueprints_dir):
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
        if updates:
            app.logger.info(f"Updating blueprint baseline with {len(updates)} changes")
            update_file_integrity_baseline_with_notifications(
                updates=updates,
                notify=True,
                message="Blueprint files updated in development environment",
                remove_missing=False
            )

    except ImportError:
        app.logger.debug("File integrity services not available for blueprint baseline update")


def _verify_blueprint_integrity(app: Flask) -> bool:
    """
    Verify the integrity of blueprint files against the baseline.

    Args:
        app (Flask): The Flask application instance

    Returns:
        bool: True if integrity verification passes, False otherwise
    """
    try:
        from core.security.cs_file_integrity import verify_integrity

        app.logger.debug("Verifying blueprint integrity")
        result, violations = verify_integrity(
            file_patterns=['blueprints/*.py', 'blueprints/*/*.py'],
            app=app
        )

        if not result:
            app.logger.warning(f"Blueprint integrity violations detected: {len(violations)} violations")

            # Log security event
            try:
                from core.security import log_security_event
                log_security_event(
                    event_type='blueprint_integrity_violation',
                    description=f"Blueprint integrity violations detected: {len(violations)} violations",
                    severity='high',
                    details={
                        'violations_count': len(violations),
                        'first_violations': violations[:3] if violations else [],
                    }
                )
            except ImportError:
                app.logger.debug("Security module not available for event logging")

        return result

    except ImportError:
        app.logger.debug("File integrity services not available for blueprint verification")
        return True


def get_blueprint_dependency_graph() -> Dict[str, List[str]]:
    """
    Generate a dependency graph of blueprint relationships.

    This function analyzes the codebase to determine which blueprints
    depend on each other. This is useful for understanding impact when
    making changes to blueprint code.

    Returns:
        Dict[str, List[str]]: Dictionary mapping blueprint names to lists of dependent blueprints
    """
    dependency_graph = {name: [] for name in blueprints.keys()}

    # Look for imports between blueprints
    blueprints_dir = os.path.dirname(os.path.abspath(__file__))
    for bp_name, bp in blueprints.items():
        bp_dir = os.path.join(blueprints_dir, bp_name)
        if not os.path.isdir(bp_dir):
            continue

        # Examine Python files in the blueprint
        for root, _, files in os.walk(bp_dir):
            for file in files:
                if not file.endswith('.py'):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()

                    # Check for imports from other blueprints
                    for other_bp_name in blueprints.keys():
                        if bp_name != other_bp_name and f"from blueprints.{other_bp_name}" in content:
                            if other_bp_name not in dependency_graph[bp_name]:
                                dependency_graph[bp_name].append(other_bp_name)
                except Exception as e:
                    logger.debug(f"Error analyzing blueprint dependencies in {file_path}: {str(e)}")

    return dependency_graph


def get_blueprint_info() -> Dict[str, Any]:
    """
    Get information about registered blueprints for diagnostic purposes.

    Returns:
        Dict[str, Any]: Dictionary containing blueprint information
    """
    result = {
        'blueprints': {},
        'total_count': len(blueprints),
        'timestamp': datetime.utcnow().isoformat()
    }

    for name, bp in blueprints.items():
        # Get URL rules for this blueprint
        rules = []
        try:
            if hasattr(current_app, 'url_map'):
                for rule in current_app.url_map.iter_rules():
                    if rule.endpoint.startswith(f"{name}."):
                        rules.append({
                            'rule': str(rule),
                            'endpoint': rule.endpoint,
                            'methods': list(rule.methods)
                        })
        except RuntimeError:
            # No application context
            pass

        # Get blueprint metadata
        result['blueprints'][name] = {
            'routes': rules,
            'route_count': len(rules),
            'static_folder': bp.static_folder,
            'template_folder': bp.template_folder,
            'url_prefix': bp.url_prefix if hasattr(bp, 'url_prefix') else None
        }

    return result


def verify_blueprint_configuration() -> List[Dict[str, str]]:
    """
    Verify that blueprints are properly configured according to standards.

    This function checks that each blueprint has appropriate URL prefixes,
    static folder configurations, error handlers, etc.

    Returns:
        List[Dict[str, str]]: List of issues found, empty if all configurations are valid
    """
    issues = []

    for name, bp in blueprints.items():
        # Ensure blueprints have proper URL prefixes
        if name != 'main' and bp.url_prefix is None:
            issues.append({
                'blueprint': name,
                'issue': 'Missing URL prefix',
                'severity': 'medium'
            })

        # Check for template folder
        if bp.template_folder is None:
            issues.append({
                'blueprint': name,
                'issue': 'Missing template folder',
                'severity': 'low'
            })

        # Check for proper error handlers (if in application context)
        try:
            if current_app:
                has_error_handler = False
                for code in [404, 500]:
                    if bp._has_error_handler(code):
                        has_error_handler = True
                        break

                if not has_error_handler:
                    issues.append({
                        'blueprint': name,
                        'issue': 'No error handlers defined',
                        'severity': 'medium'
                    })
        except RuntimeError:
            # No application context
            pass

    return issues


# Export package members
__all__ = [
    'register_all_blueprints',
    'blueprints',
    'get_blueprint_info',
    'get_blueprint_dependency_graph',
    'verify_blueprint_configuration'
]

# Add blueprint objects to exports only if they exist
for bp_name in ['auth_bp', 'main_bp', 'monitoring_bp', 'admin_bp', 'api_bp']:
    if bp_name.replace('_bp', '') in blueprints:
        __all__.append(bp_name)
