"""
Permission utilities for security assessment tools.

This module provides functions for verifying and checking permissions
for security assessment operations. It ensures that all assessment
activities are performed with proper authorization and follows the
principle of least privilege.
"""

import logging
import os
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .assessment_logging import get_assessment_logger, log_security_finding
from .error_handlers import handle_assessment_error, AssessmentException
from .data_types import AssessmentTarget

# Initialize module logger
logger = get_assessment_logger("permission_utils")

# Permission constants
PERMISSION_READ = "assessment:read"
PERMISSION_EXECUTE = "assessment:execute"
PERMISSION_WRITE = "assessment:write"
PERMISSION_ADMIN = "assessment:admin"

# Resource type constants
RESOURCE_TYPE_SYSTEM = "system"
RESOURCE_TYPE_APPLICATION = "application"
RESOURCE_TYPE_NETWORK = "network"
RESOURCE_TYPE_DATABASE = "database"
RESOURCE_TYPE_CLOUD = "cloud"


class PermissionLevel(Enum):
    """Permission levels for assessment operations."""

    READ_ONLY = 1   # Can only read assessment results
    STANDARD = 2    # Can run non-invasive assessments and read results
    ELEVATED = 3    # Can run standard assessments including some invasive tests
    ADMIN = 4       # Full access including critical system assessments


def check_assessment_permission(
    permission: str,
    target: Optional[Union[str, AssessmentTarget]] = None,
    require_mfa: bool = False
) -> bool:
    """
    Check if the current user has the specified permission for the assessment target.

    Args:
        permission: Permission to check (e.g., "assessment:read")
        target: Target system or application to check permissions against
        require_mfa: Whether multi-factor authentication is required

    Returns:
        True if the user has permission, False otherwise
    """
    logger.debug(f"Checking permission '{permission}' for target: {target}")
    try:
        # Get authentication information from environment
        api_key = os.environ.get("ASSESSMENT_TOOLS_API_KEY")
        token = os.environ.get("ASSESSMENT_TOOLS_TOKEN")
        cert_path = os.environ.get("ASSESSMENT_TOOLS_CERT_PATH")

        # First try checking with API key if available
        if api_key:
            return _check_permission_with_api_key(api_key, permission, target)

        # Then try token-based authentication
        if token:
            return _check_permission_with_token(token, permission, target, require_mfa)

        # Finally try certificate-based authentication
        if cert_path and os.path.exists(cert_path):
            return _check_permission_with_certificate(cert_path, permission, target)

        # Check environment-based permissions as fallback
        # This allows use in CI/CD pipelines or trusted environments
        if "ASSESSMENT_TOOLS_ENVIRONMENT" in os.environ:
            env = os.environ["ASSESSMENT_TOOLS_ENVIRONMENT"]

            # Development environment has unrestricted access for testing
            if env.lower() == "development":
                logger.warning(
                    "Using development environment permissions - "
                    "DO NOT USE IN PRODUCTION"
                )
                return True

        # If we reach this point, no valid authentication method was found
        logger.error("No valid authentication method found for permission check")
        return False

    except Exception as e:
        logger.error(f"Error checking permissions: {str(e)}")
        return False


def verify_target_access(target: Union[str, AssessmentTarget], operation: str) -> bool:
    """
    Verify that the current user can access the specified target for the given operation.

    Args:
        target: Target to check access for
        operation: Operation type (read, write, execute)

    Returns:
        True if access is allowed, False otherwise
    """
    logger.debug(f"Verifying target access for '{operation}' on target: {target}")

    # Convert target to string identifier if it's an AssessmentTarget object
    target_id = target.target_id if isinstance(target, AssessmentTarget) else target

    # Map operation to permission
    permission_map = {
        "read": PERMISSION_READ,
        "write": PERMISSION_WRITE,
        "execute": PERMISSION_EXECUTE,
        "admin": PERMISSION_ADMIN
    }

    permission = permission_map.get(operation.lower(), PERMISSION_READ)

    # Check if this is a critical system that requires elevated privileges
    is_critical = _is_critical_target(target_id)
    if is_critical and permission != PERMISSION_READ:
        # Critical systems require MFA for non-read operations
        return check_assessment_permission(permission, target_id, require_mfa=True)

    # Standard permission check for non-critical systems
    return check_assessment_permission(permission, target_id)


def has_required_permissions(
    required_level: PermissionLevel = PermissionLevel.STANDARD
) -> bool:
    """
    Check if the current user has the required permission level.

    Args:
        required_level: Minimum required permission level

    Returns:
        True if the user has the required level, False otherwise
    """
    logger.debug(f"Checking for required permission level: {required_level.name}")

    # Map permission levels to required permissions
    level_permissions = {
        PermissionLevel.READ_ONLY: [PERMISSION_READ],
        PermissionLevel.STANDARD: [PERMISSION_READ, PERMISSION_EXECUTE],
        PermissionLevel.ELEVATED: [PERMISSION_READ, PERMISSION_EXECUTE, PERMISSION_WRITE],
        PermissionLevel.ADMIN: [PERMISSION_READ, PERMISSION_EXECUTE, PERMISSION_WRITE, PERMISSION_ADMIN]
    }

    # Get required permissions for the specified level
    required_permissions = level_permissions[required_level]

    # Check each required permission
    for permission in required_permissions:
        if not check_assessment_permission(permission):
            logger.warning(f"Missing required permission: {permission}")
            return False

    return True


def require_permission(permission: str):
    """
    Decorator to require a specific permission for a function.

    Args:
        permission: Permission required to execute the function

    Returns:
        Decorated function that checks permissions before execution
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract target from arguments if available
            target = None
            if args and hasattr(args[0], 'target'):
                target = args[0].target
            elif 'target' in kwargs:
                target = kwargs['target']

            # Check for required permission
            if not check_assessment_permission(permission, target):
                error_msg = f"Permission denied: {permission} is required"
                logger.error(error_msg)
                raise AssessmentException(error_msg)

            # Execute the function if permission check passes
            return func(*args, **kwargs)

        return wrapper

    return decorator


def secure_operation(permission: str, audit_name: str = None, require_mfa: bool = False):
    """
    Enhanced decorator that detects targets and handles all permission checks.

    Args:
        permission: Permission required for the operation
        audit_name: Name to use in audit logs (defaults to function name)
        require_mfa: Whether MFA is required for this operation

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract target from arguments
            target = None
            target_id = None

            # Try to find target in args and kwargs
            if args and hasattr(args[0], 'target'):
                target = args[0].target
            elif 'target' in kwargs:
                target = kwargs['target']

            if isinstance(target, AssessmentTarget):
                target_id = target.target_id
            elif isinstance(target, str):
                target_id = target

            # Get operation name for audit
            operation = audit_name or func.__name__

            # Check for cached permission result first
            cached_result = get_cached_permission(permission, target)
            if cached_result is not None:
                if not cached_result:
                    error_msg = f"Permission denied (cached): {permission} for {target_id or 'global'}"
                    logger.warning(error_msg)
                    raise AssessmentException(error_msg)
            else:
                # Check for required permission
                granted = check_assessment_permission(permission, target, require_mfa)

                # Cache the result
                cache_permission_result(permission, target, granted)

                if not granted:
                    error_msg = f"Permission denied: {permission} for {target_id or 'global'}"
                    logger.warning(error_msg)
                    raise AssessmentException(error_msg)

            # Audit the permission usage
            audit_permission_usage(
                permission,
                target,
                True,  # Permission granted if we reached here
                operation,
                details={"args": str(args), "kwargs": str(kwargs)}
            )

            try:
                # Execute the function
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                # Audit failures
                audit_permission_usage(
                    permission,
                    target,
                    True,  # Permission was granted
                    operation,
                    details={"error": str(e), "error_type": type(e).__name__}
                )
                raise  # Re-raise the exception

        return wrapper
    return decorator


def get_user_permissions() -> Dict[str, List[str]]:
    """
    Get the current user's permissions.

    Returns:
        Dictionary of resource types to permissions
    """
    # Initialize with an empty permission set
    permissions: Dict[str, List[str]] = {
        RESOURCE_TYPE_SYSTEM: [],
        RESOURCE_TYPE_APPLICATION: [],
        RESOURCE_TYPE_NETWORK: [],
        RESOURCE_TYPE_DATABASE: [],
        RESOURCE_TYPE_CLOUD: []
    }

    try:
        # Try to load permissions from environment or authentication
        api_key = os.environ.get("ASSESSMENT_TOOLS_API_KEY")
        token = os.environ.get("ASSESSMENT_TOOLS_TOKEN")
        cert_path = os.environ.get("ASSESSMENT_TOOLS_CERT_PATH")

        if api_key:
            # Get permissions using API key
            permissions = _get_permissions_with_api_key(api_key)
        elif token:
            # Get permissions using token
            permissions = _get_permissions_with_token(token)
        elif cert_path and os.path.exists(cert_path):
            # Get permissions using certificate
            permissions = _get_permissions_with_certificate(cert_path)
        else:
            # Fallback to environment-based permissions
            env = os.environ.get("ASSESSMENT_TOOLS_ENVIRONMENT", "").lower()
            if env == "development":
                # Development environment gets full permissions for testing
                for resource_type in permissions:
                    permissions[resource_type] = [
                        PERMISSION_READ,
                        PERMISSION_EXECUTE,
                        PERMISSION_WRITE,
                        PERMISSION_ADMIN
                    ]

    except Exception as e:
        logger.error(f"Error retrieving permissions: {str(e)}")

    return permissions


def load_restricted_targets() -> Set[str]:
    """
    Load the list of restricted targets that require elevated permissions.

    Returns:
        Set of target identifiers that are restricted
    """
    restricted_targets = set()

    try:
        # Path to restricted targets configuration
        config_path = os.environ.get("ASSESSMENT_RESTRICTED_TARGETS_PATH")

        if not config_path:
            # Use default path relative to project root
            project_root = Path(__file__).parent.parent.parent.parent.parent
            config_path = project_root / "admin" / "security" / "assessment_tools" / "config_files" / "restricted_targets.txt"

        # Load restricted targets from file if it exists
        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        restricted_targets.add(line)

        logger.debug(f"Loaded {len(restricted_targets)} restricted targets")

    except Exception as e:
        logger.error(f"Error loading restricted targets: {str(e)}")

    return restricted_targets


def verify_role_permission(role: str, operation: str) -> bool:
    """
    Verify if the specified role has permission for the operation.

    Args:
        role: Role name (e.g., "security_analyst", "security_admin")
        operation: Operation to check (read, write, execute)

    Returns:
        True if the role has permission, False otherwise
    """
    # Define role permissions
    role_permissions = {
        "security_admin": [PERMISSION_READ, PERMISSION_EXECUTE, PERMISSION_WRITE, PERMISSION_ADMIN],
        "security_engineer": [PERMISSION_READ, PERMISSION_EXECUTE, PERMISSION_WRITE],
        "security_analyst": [PERMISSION_READ, PERMISSION_EXECUTE],
        "auditor": [PERMISSION_READ]
    }

    # Default to empty list if role not found
    permissions = role_permissions.get(role.lower(), [])

    # Map operation to required permission
    permission_map = {
        "read": PERMISSION_READ,
        "execute": PERMISSION_EXECUTE,
        "write": PERMISSION_WRITE,
        "admin": PERMISSION_ADMIN
    }

    required_permission = permission_map.get(operation.lower(), PERMISSION_ADMIN)

    # Check if the required permission is in the role's permissions
    return required_permission in permissions


def check_delegated_permission(
    username: str,
    permission: str,
    target: Optional[Union[str, AssessmentTarget]] = None
) -> bool:
    """
    Check if a user has a permission that has been delegated to them.

    Args:
        username: The user to check delegated permissions for
        permission: The permission to check for
        target: Optional target to check permission against

    Returns:
        True if the user has the delegated permission, False otherwise
    """
    logger.debug(f"Checking delegated permission '{permission}' for user {username}")

    try:
        # Look for delegation environment variables
        delegations_file = os.environ.get("ASSESSMENT_DELEGATIONS_FILE")
        if not delegations_file:
            # Use default path relative to project root
            project_root = Path(__file__).parent.parent.parent.parent.parent
            delegations_file = project_root / "admin" / "security" / "assessment_tools" / "config_files" / "delegations.json"

        if not Path(delegations_file).exists():
            logger.debug(f"Delegations file not found: {delegations_file}")
            return False

        # Read delegations from file
        import json
        with open(delegations_file, 'r') as f:
            delegations = json.load(f)

        # Get current time for expiration check
        from datetime import datetime
        now = datetime.now().isoformat()

        # Check for valid delegation
        if username in delegations:
            for delegation in delegations[username]:
                if (delegation["permission"] == permission and
                    delegation["valid_until"] > now and
                    delegation["is_active"]):

                    # Check target restriction if applicable
                    if "target_id" in delegation and target:
                        target_id = target.target_id if isinstance(target, AssessmentTarget) else target
                        if delegation["target_id"] != target_id:
                            continue

                    logger.debug(f"Found valid delegation for {username}: {permission}")
                    return True

        return False

    except Exception as e:
        logger.error(f"Error checking delegated permissions: {str(e)}")
        return False


def elevate_permissions_temporarily(
    reason: str,
    duration_minutes: int = 60,
    require_approval: bool = True
) -> Dict[str, Any]:
    """
    Temporarily elevate permissions for emergency scenarios.

    Args:
        reason: Reason for requesting elevated permissions
        duration_minutes: Duration in minutes for elevated access
        require_approval: Whether approval is required for elevation

    Returns:
        Dictionary with elevation status and token if successful
    """
    logger.info(f"Requesting temporary permission elevation: {reason}")

    try:
        # Generate a unique request ID
        import uuid
        import time
        from datetime import datetime, timedelta

        request_id = str(uuid.uuid4())
        elevation_token = None

        # Calculate expiration
        expiration = datetime.now() + timedelta(minutes=duration_minutes)

        # Record elevation request
        elevation_request = {
            "request_id": request_id,
            "reason": reason,
            "requested_at": datetime.now().isoformat(),
            "expiration": expiration.isoformat(),
            "approved": not require_approval,
            "approver": None
        }

        # Log audit event for the elevation request
        log_security_finding(
            severity="medium",
            finding_type="permission_elevation_request",
            description=f"Temporary permission elevation requested: {reason}",
            details=elevation_request
        )

        # If approval is required, wait for it or use approval API
        if require_approval:
            # Implementation would depend on your approval workflow
            # This is a simplified example that could be expanded
            approval_env = os.environ.get("ASSESSMENT_AUTO_APPROVE")
            if approval_env == "true":
                elevation_request["approved"] = True
                elevation_request["approver"] = "auto_approval"
            else:
                # In a real implementation, this might wait for an approval API response
                # or check an approval queue
                logger.info(f"Elevation request {request_id} waiting for approval")
                return {
                    "status": "pending_approval",
                    "request_id": request_id,
                    "expiration": expiration.isoformat()
                }

        # If approved, generate an elevation token
        if elevation_request["approved"]:
            # In a real implementation, this would generate a secure token
            # with appropriate claims and signatures
            elevation_token = f"elevation_{request_id}_{int(time.time())}"

            # Set the token in environment for other functions to use
            os.environ["ASSESSMENT_ELEVATION_TOKEN"] = elevation_token
            os.environ["ASSESSMENT_ELEVATION_EXPIRY"] = elevation_request["expiration"]

            logger.info(f"Permission elevation granted until {elevation_request['expiration']}")

            return {
                "status": "approved",
                "request_id": request_id,
                "token": elevation_token,
                "expiration": elevation_request["expiration"]
            }

        return {
            "status": "rejected",
            "request_id": request_id
        }

    except Exception as e:
        logger.error(f"Error during permission elevation request: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }


def batch_check_permissions(
    permissions: List[str],
    targets: Optional[List[Union[str, AssessmentTarget]]] = None
) -> Dict[str, Dict[str, bool]]:
    """
    Check multiple permissions against multiple targets efficiently.

    Args:
        permissions: List of permissions to check
        targets: Optional list of targets to check against

    Returns:
        Dictionary mapping permissions to targets with boolean results
    """
    logger.debug(f"Batch checking {len(permissions)} permissions against {len(targets) if targets else 0} targets")

    results = {}

    try:
        # If no targets specified, use None for all permission checks
        if not targets:
            targets = [None]

        # Process each permission
        for permission in permissions:
            results[permission] = {}

            # Check against each target
            for target in targets:
                target_id = target.target_id if isinstance(target, AssessmentTarget) else target
                target_key = str(target_id) if target_id else "global"

                # Check permission
                results[permission][target_key] = check_assessment_permission(permission, target)

        return results

    except Exception as e:
        logger.error(f"Error during batch permission check: {str(e)}")
        return {}


def get_cached_permission(
    permission: str,
    target: Optional[Union[str, AssessmentTarget]] = None,
    max_cache_age_seconds: int = 300
) -> Optional[bool]:
    """
    Get a cached permission result if available and not expired.

    Args:
        permission: Permission to check
        target: Target to check permission against
        max_cache_age_seconds: Maximum age of cache entry in seconds

    Returns:
        Cached result if available, None otherwise
    """
    import time

    # Generate a cache key
    target_id = target.target_id if isinstance(target, AssessmentTarget) else target
    cache_key = f"{permission}:{target_id if target_id else 'global'}"

    # Check for cached result in environment variable
    cache_var = f"ASSESSMENT_PERMISSION_CACHE_{hash(cache_key) & 0xffffffff:x}"
    cached_data = os.environ.get(cache_var)

    if cached_data:
        try:
            timestamp, result = cached_data.split(":", 1)
            timestamp = float(timestamp)

            # Check if cache is still valid
            if time.time() - timestamp <= max_cache_age_seconds:
                return result.lower() == "true"

        except (ValueError, TypeError):
            # Invalid cache format, ignore
            pass

    return None

def cache_permission_result(
    permission: str,
    target: Optional[Union[str, AssessmentTarget]],
    result: bool
) -> None:
    """
    Cache a permission check result for future use.

    Args:
        permission: Permission that was checked
        target: Target that was checked
        result: Result of the permission check
    """
    import time

    # Generate a cache key
    target_id = target.target_id if isinstance(target, AssessmentTarget) else target
    cache_key = f"{permission}:{target_id if target_id else 'global'}"

    # Store in environment variable
    cache_var = f"ASSESSMENT_PERMISSION_CACHE_{hash(cache_key) & 0xffffffff:x}"
    os.environ[cache_var] = f"{time.time()}:{result}"


def sync_with_admin_permissions() -> bool:
    """
    Synchronize assessment tool permissions with the main admin permission framework.

    Returns:
        True if synchronization was successful, False otherwise
    """
    logger.debug("Synchronizing with admin permission framework")

    try:
        # Check if admin CLI is available
        admin_cli_path = os.environ.get("ADMIN_CLI_PATH")
        if not admin_cli_path:
            project_root = Path(__file__).parent.parent.parent.parent.parent
            admin_cli_path = project_root / "admin" / "cli" / "grant_permissions.py"

        if not Path(admin_cli_path).exists():
            logger.warning(f"Admin CLI not found at {admin_cli_path}")
            return False

        # Import the admin permissions module dynamically
        import sys
        import importlib.util

        spec = importlib.util.spec_from_file_location("grant_permissions", admin_cli_path)
        admin_perms = importlib.util.module_from_spec(spec)
        sys.modules["grant_permissions"] = admin_perms
        spec.loader.exec_module(admin_perms)

        # Get current user and check permissions using admin framework
        import getpass
        current_user = getpass.getuser()

        # Map assessment permissions to admin permissions
        permission_map = {
            PERMISSION_READ: "assessment:read",
            PERMISSION_EXECUTE: "assessment:execute",
            PERMISSION_WRITE: "assessment:write",
            PERMISSION_ADMIN: "assessment:admin"
        }

        # Check each permission using admin framework
        synced_permissions = {}
        for assessment_perm, admin_perm in permission_map.items():
            try:
                result = admin_perms.check_user_permission(current_user, admin_perm)
                synced_permissions[assessment_perm] = result["has_permission"]
            except Exception as e:
                logger.error(f"Error checking admin permission {admin_perm}: {str(e)}")

        # Store synced permissions in environment
        os.environ["ASSESSMENT_SYNCED_PERMISSIONS"] = ",".join(
            [p for p, has in synced_permissions.items() if has]
        )

        logger.info(f"Successfully synced permissions with admin framework")
        return True

    except Exception as e:
        logger.error(f"Error synchronizing with admin permissions: {str(e)}")
        return False


def audit_permission_usage(
    permission: str,
    target: Optional[Union[str, AssessmentTarget]],
    granted: bool,
    operation: str,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Audit permission usage for security analysis and compliance.

    Args:
        permission: Permission that was checked
        target: Target that was checked
        granted: Whether the permission was granted
        operation: Operation being performed
        details: Additional operation details
    """
    try:
        # Create audit record
        import time
        import getpass
        from datetime import datetime

        target_id = target.target_id if isinstance(target, AssessmentTarget) else target

        audit_record = {
            "timestamp": datetime.now().isoformat(),
            "permission": permission,
            "target": target_id,
            "granted": granted,
            "operation": operation,
            "user": getpass.getuser(),
            "process_id": os.getpid(),
            "details": details or {}
        }

        # Log to assessment security log
        if granted:
            log_level = "debug" if permission == PERMISSION_READ else "info"
            getattr(logger, log_level)(
                f"Permission granted: {permission} for {target_id or 'global'}"
            )
        else:
            logger.warning(
                f"Permission denied: {permission} for {target_id or 'global'}"
            )

        # Record security event for non-read operations or denied permissions
        if permission != PERMISSION_READ or not granted:
            log_security_finding(
                severity="low" if granted else "medium",
                finding_type="permission_audit",
                description=f"Permission {'granted' if granted else 'denied'}: {permission}",
                details=audit_record
            )

    except Exception as e:
        logger.error(f"Error auditing permission usage: {str(e)}")


# ---- Helper functions ----

def _check_permission_with_api_key(
    api_key: str,
    permission: str,
    target: Optional[Union[str, AssessmentTarget]]
) -> bool:
    """Check permissions using API key authentication."""
    logger.debug("Checking permissions with API key")

    # Extract target_id if target is an AssessmentTarget object
    target_id = None
    if isinstance(target, AssessmentTarget):
        target_id = target.target_id
    elif isinstance(target, str):
        target_id = target

    try:
        # TODO: Implement API-based permission check when API is available
        # This is a simplified implementation for the current version

        # For now, validate that the API key follows the expected format
        # Real implementation would validate with an authentication service
        if not api_key.startswith("assessment_") or len(api_key) < 32:
            logger.warning("Invalid API key format")
            return False

        # Check if this is a restricted target requiring elevated permissions
        if target_id and _is_critical_target(target_id):
            # Critical targets require admin permission
            if permission != PERMISSION_READ and permission != PERMISSION_ADMIN:
                logger.warning(f"Critical target {target_id} requires admin permission")
                return False

        # Allow the operation for valid API keys
        # In a real implementation, this would check with an authorization service
        logger.debug(f"Permission {permission} granted via API key")
        return True

    except Exception as e:
        logger.error(f"API key permission check failed: {str(e)}")
        return False


def _check_permission_with_token(
    token: str,
    permission: str,
    target: Optional[Union[str, AssessmentTarget]],
    require_mfa: bool
) -> bool:
    """Check permissions using token-based authentication."""
    logger.debug("Checking permissions with authentication token")

    try:
        # Extract target_id if target is an AssessmentTarget object
        target_id = None
        if isinstance(target, AssessmentTarget):
            target_id = target.target_id
        elif isinstance(target, str):
            target_id = target

        # TODO: Implement token validation with a proper JWT validation
        # This is a simplified check for the current version

        # Validate token format (simplified)
        parts = token.split('.')
        if len(parts) != 3:
            logger.warning("Invalid token format")
            return False

        # Check MFA requirement
        if require_mfa and not _token_has_mfa(token):
            logger.warning("MFA required but not present in token")
            return False

        # Check if this is a restricted target requiring elevated permissions
        if target_id and _is_critical_target(target_id):
            # Critical targets require admin permission for non-read operations
            if permission != PERMISSION_READ and permission != PERMISSION_ADMIN:
                logger.warning(f"Critical target {target_id} requires admin permission")
                return False

        # Allow the operation for valid tokens
        # In a real implementation, this would decode and validate the token
        logger.debug(f"Permission {permission} granted via token")
        return True

    except Exception as e:
        logger.error(f"Token permission check failed: {str(e)}")
        return False


def _check_permission_with_certificate(
    cert_path: str,
    permission: str,
    target: Optional[Union[str, AssessmentTarget]]
) -> bool:
    """Check permissions using certificate-based authentication."""
    logger.debug(f"Checking permissions with certificate at {cert_path}")

    try:
        # Extract target_id if target is an AssessmentTarget object
        target_id = None
        if isinstance(target, AssessmentTarget):
            target_id = target.target_id
        elif isinstance(target, str):
            target_id = target

        # Validate certificate exists
        if not os.path.isfile(cert_path):
            logger.warning(f"Certificate file not found at {cert_path}")
            return False

        # TODO: Implement proper certificate validation
        # This would validate the certificate against trusted CAs and check revocation

        # Check if this is a restricted target requiring elevated permissions
        if target_id and _is_critical_target(target_id):
            # Critical targets require admin permission for non-read operations
            if permission != PERMISSION_READ and permission != PERMISSION_ADMIN:
                logger.warning(f"Critical target {target_id} requires admin permission")
                return False

        # Allow the operation for valid certificates
        logger.debug(f"Permission {permission} granted via certificate")
        return True

    except Exception as e:
        logger.error(f"Certificate permission check failed: {str(e)}")
        return False


def _is_critical_target(target_id: str) -> bool:
    """
    Check if the target is a critical system requiring elevated permissions.

    Args:
        target_id: Target identifier to check

    Returns:
        True if the target is critical, False otherwise
    """
    if not target_id:
        return False

    # Load restricted targets
    restricted_targets = load_restricted_targets()

    # Check if target is directly in the restricted list
    if target_id in restricted_targets:
        return True

    # Check for pattern matches (e.g., "prod-*" would match "prod-db1")
    for pattern in restricted_targets:
        if pattern.endswith('*') and target_id.startswith(pattern[:-1]):
            return True

    return False


def _token_has_mfa(token: str) -> bool:
    """
    Check if the token has MFA verification.

    Args:
        token: Authentication token to check

    Returns:
        True if the token has MFA verification, False otherwise
    """
    # TODO: Implement proper JWT parsing and validation
    # This is a simplified implementation for the current version

    # For now, just check for an MFA indicator in the token
    # Real implementation would decode and validate the token claims
    return "mfa=true" in token or "mfa:true" in token


def _get_permissions_with_api_key(api_key: str) -> Dict[str, List[str]]:
    """Get permissions using API key authentication."""
    # Initialize with empty permission sets
    permissions: Dict[str, List[str]] = {
        RESOURCE_TYPE_SYSTEM: [],
        RESOURCE_TYPE_APPLICATION: [],
        RESOURCE_TYPE_NETWORK: [],
        RESOURCE_TYPE_DATABASE: [],
        RESOURCE_TYPE_CLOUD: []
    }

    try:
        # TODO: Implement API-based permission retrieval when API is available
        # This is a simplified implementation for the current version

        # For valid API keys, provide some default permissions
        # In a real implementation, this would retrieve from an API
        if api_key and api_key.startswith("assessment_"):
            for resource_type in permissions:
                permissions[resource_type] = [PERMISSION_READ, PERMISSION_EXECUTE]

            # If this looks like an admin API key, add admin permissions
            if "admin" in api_key:
                for resource_type in permissions:
                    permissions[resource_type].extend([PERMISSION_WRITE, PERMISSION_ADMIN])

    except Exception as e:
        logger.error(f"Error retrieving permissions with API key: {str(e)}")

    return permissions


def _get_permissions_with_token(token: str) -> Dict[str, List[str]]:
    """Get permissions using token authentication."""
    # Initialize with empty permission sets
    permissions: Dict[str, List[str]] = {
        RESOURCE_TYPE_SYSTEM: [],
        RESOURCE_TYPE_APPLICATION: [],
        RESOURCE_TYPE_NETWORK: [],
        RESOURCE_TYPE_DATABASE: [],
        RESOURCE_TYPE_CLOUD: []
    }

    try:
        # TODO: Implement token-based permission retrieval
        # This is a simplified implementation for the current version

        # For valid tokens, provide some default permissions
        # In a real implementation, this would decode and validate the token
        parts = token.split('.')
        if len(parts) == 3:
            for resource_type in permissions:
                permissions[resource_type] = [PERMISSION_READ, PERMISSION_EXECUTE]

            # If token contains admin indicator, add admin permissions
            if "role=admin" in token or "role:admin" in token:
                for resource_type in permissions:
                    permissions[resource_type].extend([PERMISSION_WRITE, PERMISSION_ADMIN])

    except Exception as e:
        logger.error(f"Error retrieving permissions with token: {str(e)}")

    return permissions


def _get_permissions_with_certificate(cert_path: str) -> Dict[str, List[str]]:
    """Get permissions using certificate authentication."""
    # Initialize with empty permission sets
    permissions: Dict[str, List[str]] = {
        RESOURCE_TYPE_SYSTEM: [],
        RESOURCE_TYPE_APPLICATION: [],
        RESOURCE_TYPE_NETWORK: [],
        RESOURCE_TYPE_DATABASE: [],
        RESOURCE_TYPE_CLOUD: []
    }

    try:
        # TODO: Implement certificate-based permission retrieval
        # This is a simplified implementation for the current version

        # For valid certificates, provide some default permissions
        # In a real implementation, this would validate the certificate and extract roles
        if os.path.isfile(cert_path):
            for resource_type in permissions:
                permissions[resource_type] = [PERMISSION_READ, PERMISSION_EXECUTE]

            # For service account certificates, add write permission
            if "service" in cert_path:
                for resource_type in permissions:
                    permissions[resource_type].append(PERMISSION_WRITE)

    except Exception as e:
        logger.error(f"Error retrieving permissions with certificate: {str(e)}")

    return permissions
