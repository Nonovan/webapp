"""
Services package for the myproject application.

This package contains service classes that implement business logic and coordinate
interactions between different parts of the application. Services encapsulate
complex operations and provide clean APIs for controllers/routes to use.

The services follow a functional core/imperative shell architecture where business
logic is separated from side effects (like database operations). This approach
enhances testability and maintainability by reducing complexity in individual components.

Key services in this package:
- AuthService: User authentication, registration, and session management
- EmailService: Email template rendering and delivery
- NewsletterService: Subscription management and newsletter distribution
- SecurityService: Security operations including file integrity monitoring
"""

import logging
from typing import Dict, List, Any, Optional, Tuple

from .auth_service import AuthService
from .email_service import EmailService, send_email, send_template_email, validate_email_address, test_email_configuration
from .newsletter_service import NewsletterService

# Import SecurityService conditionally to avoid hard dependency
try:
    from .security_service import SecurityService
    SECURITY_SERVICE_AVAILABLE = True
except ImportError:
    SECURITY_SERVICE_AVAILABLE = False
    # Create placeholder for documentation/type hinting
    class SecurityService:
        """Placeholder for SecurityService when the module is not available."""
        @staticmethod
        def check_file_integrity(*args, **kwargs):
            """Placeholder for file integrity checking."""
            raise NotImplementedError("SecurityService is not available")

        @staticmethod
        def update_baseline(*args, **kwargs):
            """Placeholder for baseline update."""
            raise NotImplementedError("SecurityService is not available")

# Initialize logger for service package
logger = logging.getLogger(__name__)

# Export classes and functions to make them available when importing this package
__all__ = [
    # Service classes
    'AuthService',
    'EmailService',
    'NewsletterService',
    'SecurityService',

    # Utility functions
    'send_email',
    'send_template_email',
    'validate_email_address',
    'test_email_configuration',

    # Security functions
    'check_integrity',
    'update_security_baseline',

    # Status constants
    'SECURITY_SERVICE_AVAILABLE',
]

# Version information - incremented to reflect security service addition
__version__ = '1.4.0'

def check_integrity(paths: Optional[List[str]] = None) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Check file integrity for specified paths or critical files.

    This is a convenience function that delegates to SecurityService.

    Args:
        paths: Optional list of file paths to check. If None, checks default critical paths.

    Returns:
        Tuple of (integrity_status, changes)
        - integrity_status: True if all files match baseline, False otherwise
        - changes: List of dictionaries with details about changed files
    """
    if not SECURITY_SERVICE_AVAILABLE:
        logger.warning("SecurityService not available: File integrity check skipped")
        return False, [{"status": "error", "reason": "SecurityService not available"}]

    return SecurityService.check_file_integrity(paths)

def update_security_baseline(paths: Optional[Dict[str, str]] = None,
                           remove_missing: bool = False) -> Tuple[bool, str]:
    """
    Update the security baseline with new file hashes.

    This is a convenience function that delegates to SecurityService.

    Args:
        paths: Optional dictionary of {path: hash} entries to update
        remove_missing: Whether to remove entries for files that no longer exist

    Returns:
        Tuple of (success, message)
    """
    if not SECURITY_SERVICE_AVAILABLE:
        logger.warning("SecurityService not available: Baseline update skipped")
        return False, "SecurityService not available"

    return SecurityService.update_baseline(paths, remove_missing)

# Log initialization status
logger.debug(f"Services package initialized - version {__version__} - "
             f"Security service {'available' if SECURITY_SERVICE_AVAILABLE else 'not available'}")
