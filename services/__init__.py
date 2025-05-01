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
- WebhookService: Management of webhooks, subscriptions, and event delivery
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set, Callable

from .auth_service import AuthService
from .email_service import EmailService, send_email, send_template_email, validate_email_address, test_email_configuration
from .newsletter_service import NewsletterService
from .security_service import SecurityService
from .webhook_service import WebhookService

# Initialize logger for service package
logger = logging.getLogger(__name__)

# Export classes and functions to make them available when importing this package
__all__ = [
    # Service classes
    'AuthService',
    'EmailService',
    'NewsletterService',
    'SecurityService',
    'WebhookService',

    # Utility functions
    'send_email',
    'send_template_email',
    'validate_email_address',
    'test_email_configuration',

    # Security functions
    'check_integrity',
    'update_security_baseline',
    'verify_file_hash',
    'calculate_file_hash',
    'get_integrity_status',
    'schedule_integrity_check',
    'update_file_integrity_baseline',
    'update_file_baseline',

    # Webhook functions
    'trigger_webhook_event',
    'create_webhook_subscription',
    'get_webhook_subscription',
    'update_webhook_subscription',
    'delete_webhook_subscription',
    'check_subscription_health'
]

# Version information - incremented to reflect security service enhancements
__version__ = '0.1.0'

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
    return SecurityService.check_file_integrity(paths)

def update_security_baseline(paths_to_update: Optional[List[str]] = None,
                           remove_missing: bool = False) -> Tuple[bool, str]:
    """
    Update the security baseline with new file hashes.

    This is a convenience function that delegates to SecurityService.

    Args:
        paths_to_update: Optional list of specific file paths to update in the baseline.
                       If None, re-scans all files in the current baseline.
        remove_missing: Whether to remove entries for files that no longer exist

    Returns:
        Tuple of (success, message)
    """
    return SecurityService.update_baseline(paths_to_update, remove_missing)

def verify_file_hash(filepath: str, expected_hash: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify the hash of a specific file against baseline or provided hash.

    Args:
        filepath: Path to the file to verify
        expected_hash: Optional expected hash. If None, uses hash from baseline

    Returns:
        Tuple of (match_status, details)
        - match_status: True if hash matches, False otherwise
        - details: Dictionary with verification details
    """
    return SecurityService.verify_file_hash(filepath, expected_hash)

def calculate_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    Calculate cryptographic hash for a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm to use (sha256, sha512, etc.)

    Returns:
        Calculated hash string or None if file cannot be read
    """
    return SecurityService._calculate_hash(filepath, algorithm)

def get_integrity_status() -> Dict[str, Any]:
    """
    Get the current integrity status of the system.

    Returns:
        Dictionary with integrity status information:
        - last_check_time: DateTime of the last integrity check
        - baseline_status: Status of the baseline file
        - file_count: Number of files monitored
        - changes_detected: Number of changes since last baseline update
        - critical_changes: List of critical file changes
    """
    return SecurityService.get_integrity_status()

def schedule_integrity_check(interval_seconds: int = 3600,
                           callback: Optional[Callable[[bool, List[Dict[str, Any]]], None]] = None) -> bool:
    """
    Schedule periodic integrity checks.

    Args:
        interval_seconds: Time between checks in seconds (default: 1 hour)
        callback: Optional function to call with check results

    Returns:
        Boolean indicating if scheduling was successful
    """
    return SecurityService.schedule_integrity_check(interval_seconds, callback)

def update_file_integrity_baseline(app, baseline_path: str, changes: List[Dict[str, Any]],
                                 auto_update_limit: int = 10) -> Tuple[bool, str]:
    """
    Update the file integrity baseline with changes.

    This function is used to update the baseline when non-critical changes are detected.
    It incorporates new file hashes into the baseline, typically used in development
    or controlled update scenarios.

    Args:
        app: Flask application instance
        baseline_path: Path to the baseline JSON file
        changes: List of change dictionaries from integrity check
        auto_update_limit: Maximum number of files to auto-update (safety limit)

    Returns:
        Tuple containing (success, message)
    """
    try:
        # Import required security functions
        from core.security.cs_file_integrity import update_file_integrity_baseline as core_update_baseline

        # Filter changes to include only those that should be updated
        # Typically exclude critical and high severity changes
        non_critical = [c for c in changes if c.get('severity') not in ('critical', 'high')]

        # Safety check - don't update if too many files changed
        if len(non_critical) > auto_update_limit and not app.config.get('BYPASS_UPDATE_LIMITS', False):
            logger.warning(f"Too many files to update: {len(non_critical)} exceeds limit of {auto_update_limit}")
            return False, f"Too many files to update: {len(non_critical)} exceeds safety limit"

        if not non_critical:
            return True, "No non-critical changes to update"

        # Format the changes for the core function
        # The core function expects updates with 'path' and 'current_hash' keys
        formatted_updates = []
        for change in non_critical:
            if 'path' in change and 'actual_hash' in change:
                formatted_updates.append({
                    'path': change['path'],
                    'current_hash': change['actual_hash']
                })

        if not formatted_updates:
            logger.warning("No valid changes found to update baseline")
            return False, "No valid changes to update"

        # Update the baseline with these non-critical changes
        logger.info(f"Auto-updating baseline for {len(formatted_updates)} non-critical changes")
        result = core_update_baseline(app, baseline_path, formatted_updates)

        if result:
            logger.info("File integrity baseline updated successfully")
            return True, f"Updated baseline with {len(formatted_updates)} changes"
        else:
            logger.error("Failed to update file integrity baseline")
            return False, "Failed to update baseline"

    except ImportError as e:
        logger.warning(f"Could not auto-update baseline: cs_file_integrity module not available - {e}")
        return False, "File integrity module not available"
    except Exception as e:
        logger.error(f"Error auto-updating baseline: {str(e)}")
        return False, f"Error updating baseline: {str(e)}"

def update_file_baseline(baseline_path: str,
                        updates: Dict[str, str],
                        remove_missing: bool = False) -> Tuple[bool, str]:
    """
    Update file integrity baseline with new hashes.

    This function provides a direct way to update the file baseline with explicit
    hash values without requiring a Flask application context.

    Args:
        baseline_path: Path to the baseline JSON file
        updates: Dictionary mapping file paths to new hashes
        remove_missing: Whether to remove entries for files that no longer exist

    Returns:
        Tuple of (success, message)
    """
    try:
        # Try to use the utility from core
        from core.utils import update_file_integrity_baseline as core_update_baseline
        return core_update_baseline(baseline_path, updates, remove_missing)
    except ImportError:
        logger.debug("Core utility not available, using SecurityService directly")

        # Format updates for SecurityService
        paths = list(updates.keys())

        # First update the baseline with the specified paths
        success, message = SecurityService.update_baseline(paths_to_update=paths,
                                                         remove_missing=remove_missing)

        # If successful and we need to verify hashes match exactly what was provided
        if success and paths:
            # Load the baseline again to ensure consistency
            baseline = SecurityService._load_baseline(Path(baseline_path))
            files = baseline.get("files", {})

            # Check if hashes match what was requested
            mismatched = [p for p in paths if p in files and files[p] != updates.get(p)]
            if mismatched:
                logger.warning(f"Hash mismatch after baseline update for: {mismatched}")
                # Could force update here if needed

        return success, message

def trigger_webhook_event(event_type: str, payload: Dict[str, Any],
                        user_id: Optional[int] = None,
                        tags: Optional[List[str]] = None) -> int:
    """
    Trigger a webhook event to be delivered to all relevant subscribers.

    This is a convenience function that delegates to WebhookService.

    Args:
        event_type: The type of event that occurred (e.g., 'resource.created')
        payload: The data associated with the event
        user_id: Optional user ID associated with the event
        tags: Optional list of tags to include with the event

    Returns:
        The number of webhook deliveries initiated
    """
    return WebhookService.trigger_event(event_type, payload, user_id, tags)

def create_webhook_subscription(user_id: int, target_url: str, event_types: List[str],
                              description: Optional[str] = None,
                              headers: Optional[Dict[str, str]] = None,
                              is_active: bool = True,
                              max_retries: int = 3,
                              group_id: Optional[int] = None,
                              rate_limit: Optional[Dict[str, int]] = None) -> Tuple[Optional[Any], Optional[str], Optional[str]]:
    """
    Create a new webhook subscription.

    This is a convenience function that delegates to WebhookService.

    Args:
        user_id: The ID of the user creating the subscription
        target_url: URL where webhook events will be sent
        event_types: List of event types to subscribe to
        description: Optional description for this subscription
        headers: Optional custom HTTP headers to include in requests
        is_active: Whether the subscription is active
        max_retries: Maximum number of delivery attempts
        group_id: Optional ID of a webhook group to associate with
        rate_limit: Optional rate limiting settings

    Returns:
        Tuple containing (subscription object, secret, error message)
    """
    return WebhookService.create_subscription(
        user_id=user_id,
        target_url=target_url,
        event_types=event_types,
        description=description,
        headers=headers,
        is_active=is_active,
        max_retries=max_retries,
        group_id=group_id,
        rate_limit=rate_limit
    )

def get_webhook_subscription(subscription_id: str, user_id: int) -> Optional[Any]:
    """
    Get a webhook subscription by ID.

    This is a convenience function that delegates to WebhookService.

    Args:
        subscription_id: The ID of the subscription
        user_id: The ID of the user requesting the subscription

    Returns:
        The webhook subscription object or None if not found
    """
    return WebhookService.get_subscription_by_id(subscription_id, user_id)

def update_webhook_subscription(subscription_id: str, user_id: int, **kwargs) -> Tuple[Optional[Any], Optional[str]]:
    """
    Update an existing webhook subscription.

    This is a convenience function that delegates to WebhookService.

    Args:
        subscription_id: The ID of the subscription to update
        user_id: The ID of the user requesting the update
        **kwargs: Fields to update (target_url, event_types, description, etc.)

    Returns:
        Tuple containing (updated subscription object, error message)
    """
    return WebhookService.update_subscription(subscription_id, user_id, **kwargs)

def delete_webhook_subscription(subscription_id: str, user_id: int) -> Tuple[bool, Optional[str]]:
    """
    Delete a webhook subscription.

    This is a convenience function that delegates to WebhookService.

    Args:
        subscription_id: The ID of the subscription to delete
        user_id: The ID of the user requesting the deletion

    Returns:
        Tuple containing (success status, error message)
    """
    return WebhookService.delete_subscription(subscription_id, user_id)

def check_subscription_health(subscription_id: str, user_id: int, lookback_hours: int = 24) -> Optional[Dict[str, Any]]:
    """
    Check the health and delivery statistics for a webhook subscription.

    This is a convenience function that delegates to WebhookService.

    Args:
        subscription_id: The ID of the subscription to check
        user_id: The ID of the user requesting the health check
        lookback_hours: Number of hours of history to analyze

    Returns:
        Dictionary with health metrics or None if access denied
    """
    return WebhookService.get_subscription_health(subscription_id, user_id, lookback_hours)

# Determine if security service has all required functionality
try:
    SECURITY_SERVICE_AVAILABLE = hasattr(SecurityService, 'check_file_integrity') and callable(SecurityService.check_file_integrity)
except (ImportError, AttributeError):
    SECURITY_SERVICE_AVAILABLE = False
    logger.warning("SecurityService functionality may be limited or unavailable")

# Log initialization status
logger.debug(f"Services package initialized - version {__version__} - Security service available: {SECURITY_SERVICE_AVAILABLE}")
