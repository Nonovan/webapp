"""
Blueprint registration module for the myproject application.

This module centralizes the registration of all application blueprints, providing
a clean separation between the core application factory and route definitions.
It serves as the integration point for different functional areas of the application
including authentication, main application routes, and monitoring features.

The blueprint structure enables:
- Modular code organization by feature area
- Isolation of route definitions for better maintainability
- Separate URL prefixes and template folders for each component
- Independent error handling for different application sections
- Security-focused integration with file integrity monitoring

All blueprints are imported here and registered with the application instance
through the register_blueprints function, which is called during app initialization.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from flask import Flask, current_app
from blueprints import register_all_blueprints

# Initialize logger for this package
logger = logging.getLogger(__name__)

# Track registered blueprints for integrity monitoring
REGISTERED_BLUEPRINTS: Set[str] = set()

def register_blueprints(app: Flask) -> None:
    """
    Register application blueprints with the Flask application instance.

    This function attaches all blueprints to the application, organizing routes
    into logical groups with appropriate URL prefixes. The blueprint registration
    process establishes the routing structure of the entire application.

    Blueprint organization:
    - auth_bp: Authentication routes with /auth prefix
    - main_bp: Core application routes at the root level
    - monitoring_bp: System monitoring endpoints with /monitoring prefix
    - admin_bp: Administrative interfaces with /admin prefix
    - api_bp: API endpoints with /api prefix

    Args:
        app (Flask): The Flask application instance to register blueprints with

    Returns:
        None: This function modifies the app instance in-place

    Example:
        from flask import Flask
        from views import register_blueprints

        app = Flask(__name__)
        register_blueprints(app)
    """
    start_time = datetime.now(timezone.utc)

    # Register all blueprints from the blueprints package
    registered = register_all_blueprints(app)

    # Track registered blueprints for integrity monitoring
    if registered:
        REGISTERED_BLUEPRINTS.update(registered)

    # Log registration completion
    duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
    logger.info(f"Registered {len(REGISTERED_BLUEPRINTS)} blueprints in {duration_ms:.2f}ms")

    # Initialize security monitoring for views if available
    if app.config.get('ENABLE_FILE_INTEGRITY_MONITORING', True):
        try:
            from services import check_integrity, update_file_integrity_baseline_with_notifications

            # Only update baseline in development environment
            if app.config.get('ENVIRONMENT') == 'development' and app.config.get('AUTO_UPDATE_VIEWS_BASELINE', False):
                _update_views_baseline(app)
        except ImportError:
            logger.debug("File integrity monitoring services not available for views")


def get_registered_blueprints() -> List[str]:
    """
    Get the list of registered blueprint names.

    Returns:
        List[str]: List of registered blueprint names
    """
    return list(REGISTERED_BLUEPRINTS)


def verify_view_integrity() -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify the integrity of view files.

    This function checks if any view files have been modified since the last baseline update.
    It's useful for detecting unauthorized changes to routing logic.

    Returns:
        Tuple containing:
        - bool: True if all files match the baseline
        - List[Dict]: List of violations if any
    """
    try:
        from services import check_integrity

        # Check integrity with detailed results
        integrity_status, changes = check_integrity()

        # Filter for only view-related files
        view_changes = [
            change for change in changes
            if 'views/' in change.get('path', '') or 'blueprints/' in change.get('path', '')
        ]

        return len(view_changes) == 0, view_changes
    except ImportError:
        logger.warning("Unable to verify view integrity: required services not available")
        return True, []


def _update_views_baseline(app: Flask) -> None:
    """
    Update the file integrity baseline for view files.

    This function is used in development environments to keep the baseline
    in sync with legitimate view changes.

    Args:
        app: Flask application instance
    """
    try:
        from services import update_file_integrity_baseline_with_notifications

        # Get the views directory path
        views_dir = os.path.dirname(os.path.abspath(__file__))
        blueprints_dir = os.path.join(os.path.dirname(views_dir), 'blueprints')

        # Check if directories exist
        if not os.path.exists(views_dir) or not os.path.exists(blueprints_dir):
            logger.warning("Views or blueprints directory not found")
            return

        baseline_path = app.config.get('FILE_BASELINE_PATH')
        if not baseline_path:
            logger.warning("Baseline path not configured, cannot update views baseline")
            return

        # Collect Python files in both directories
        view_files = _collect_python_files(views_dir)
        blueprint_files = _collect_python_files(blueprints_dir)

        # Calculate hashes and prepare updates
        try:
            from services import SecurityService

            changes = []
            for file_path in view_files + blueprint_files:
                if os.path.isfile(file_path):
                    # Get file hash and determine severity
                    current_hash = SecurityService.calculate_file_hash(file_path)

                    # Get relative path for the baseline
                    rel_path = os.path.relpath(file_path, os.path.dirname(app.root_path))

                    # Set severity based on file path and type
                    severity = 'medium'  # Default severity
                    if '__init__.py' in file_path or 'routes.py' in file_path:
                        severity = 'high'  # Higher severity for route definitions

                    # Add to changes list
                    changes.append({
                        'path': rel_path,
                        'current_hash': current_hash,
                        'severity': severity
                    })

            # Update baseline with notifications if changes found
            if changes:
                logger.info(f"Updating views baseline with {len(changes)} changes")

                # Use the enhanced baseline update function with notifications
                success, message, stats = update_file_integrity_baseline_with_notifications(
                    baseline_path=baseline_path,
                    changes=changes,
                    remove_missing=False,  # Don't remove missing files
                    notify=False,          # Don't notify about development updates
                    audit=True,            # Still log to audit trail
                    severity_threshold='high',
                    update_limit=app.config.get('VIEWS_BASELINE_UPDATE_LIMIT', 100)
                )

                if success:
                    logger.info(f"Views baseline updated: {message}")
                else:
                    logger.warning(f"Views baseline update failed: {message}")

        except (ImportError, AttributeError) as e:
            logger.warning(f"Unable to update views baseline: {str(e)}")

    except ImportError:
        logger.debug("File integrity services not available, skipping views baseline update")


def _collect_python_files(directory: str) -> List[str]:
    """
    Collect Python files from a directory recursively.

    Args:
        directory: Directory to search

    Returns:
        List of Python file paths
    """
    python_files = []

    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.py'):
                python_files.append(os.path.join(root, filename))

    return python_files


# Package version
__version__ = '0.1.1'

# Define what is available for import from this package
__all__ = [
    'register_blueprints',
    'get_registered_blueprints',
    'verify_view_integrity',
    '__version__'
]

# Log package initialization
logger.debug(f"Views registration package initialized (version: {__version__})")
