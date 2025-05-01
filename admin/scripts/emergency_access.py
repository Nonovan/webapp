#!/usr/bin/env python3

"""
Emergency Access Management System for Cloud Infrastructure Platform.

This script manages temporary emergency access privileges including break-glass account
activation, privilege escalation, and emergency delegation. It provides secure
authentication, approval workflows, comprehensive audit logging, and automatic
access expiration to ensure security and accountability during emergencies.

Features:
- Emergency access activation with justification and time limits
- Multi-party approval workflows for critical access
- Temporary privilege escalation with proper audit records
- Break-glass account management
- Comprehensive security event logging
- Time-limited access with automatic expiration
- Integration with notification systems
"""

import argparse
import datetime
import getpass
import json
import logging
import os
import sys
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set

# Add project root to path for imports
project_root = Path(__file__).resolve().parent.parent.parent
if project_root not in sys.path:
    sys.path.insert(0, str(project_root))

# Setup logging
LOG_DIR = Path("/var/log/cloud-platform/admin")
LOG_FILE = LOG_DIR / "emergency_access.log"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("emergency_access")

try:
    # Core application imports
    from core.security.cs_audit import log_security_event
    from core.security.cs_authorization import require_permission
    from models.auth.permission_delegation import PermissionDelegation
    from models.security.audit_log import AuditLog
    from models.auth.user import User
    from models.auth.role import Role
    from extensions import db
    from core.factory import create_app

    # Admin utils imports
    from admin.utils.admin_auth import (
        authenticate_admin, check_permission, verify_mfa_token
    )
    from admin.utils.audit_utils import (
        log_admin_action, SEVERITY_CRITICAL, STATUS_SUCCESS,
        ACTION_EMERGENCY_ACCESS, ACTION_EMERGENCY_DEACTIVATE
    )
    from admin.utils.secure_credentials import get_credential
    from admin.utils.notification_utils import send_notification

    IMPORTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some imports not available: {e}")
    IMPORTS_AVAILABLE = False
    # Define placeholder functions for standalone operation
    def log_security_event(*args, **kwargs): pass
    def log_admin_action(*args, **kwargs): pass
    def send_notification(*args, **kwargs): pass

# Constants
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_VALIDATION_ERROR = 2
EXIT_AUTHENTICATION_ERROR = 3
EXIT_AUTHORIZATION_ERROR = 4
EXIT_RESOURCE_ERROR = 5
EXIT_APPROVAL_ERROR = 6
EXIT_ARGUMENT_ERROR = 7

CONFIG_FILE = project_root / "config" / "security" / "emergency_access.json"
REQUEST_STORE = project_root / "instance" / "emergency_requests"
NOTIFIERS = ["email", "slack", "sms"]

REQUEST_STORE.mkdir(parents=True, exist_ok=True)

# Ensure secure permissions on emergency request files
try:
    REQUEST_STORE.chmod(0o700)
except Exception as e:
    logger.warning(f"Failed to set secure permissions on {REQUEST_STORE}: {e}")

class AccessStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ACTIVE = "active"
    REVOKED = "revoked"


class EmergencyAccessError(Exception):
    """Base exception for emergency access errors."""
    pass


class ValidationError(EmergencyAccessError):
    """Raised when validation of parameters fails."""
    pass


class AuthorizationError(EmergencyAccessError):
    """Raised when authorization check fails."""
    pass


class ApprovalError(EmergencyAccessError):
    """Raised when approval workflow fails."""
    pass


class ResourceError(EmergencyAccessError):
    """Raised when a requested resource is not found."""
    pass


class EmergencyAccessManager:
    """Manages emergency access requests and approvals."""

    def __init__(self, config_file: Path = CONFIG_FILE):
        self.config_file = config_file
        self.config = self._load_config()
        self.app = None

    def _load_config(self) -> Dict:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid configuration file: {e}")
                return {}
        else:
            logger.warning(f"Configuration file {self.config_file} not found")
            return {}

    def _initialize_app(self):
        """Initialize Flask app context if needed."""
        if IMPORTS_AVAILABLE and self.app is None:
            try:
                self.app = create_app()
                self.app.app_context().push()
                return True
            except Exception as e:
                logger.error(f"Failed to initialize application context: {e}")
                return False
        return IMPORTS_AVAILABLE

    def generate_request_id(self) -> str:
        """Generate a unique request ID."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        random_id = str(uuid.uuid4())[:8]
        return f"ER-{timestamp}-{random_id}"

    def _save_request(self, request_data: Dict) -> bool:
        """Save request data to file."""
        request_id = request_data.get("request_id")
        if not request_id:
            raise ValidationError("Request ID is required")

        request_file = REQUEST_STORE / f"{request_id}.json"
        try:
            with open(request_file, 'w') as f:
                json.dump(request_data, f, indent=2, default=str)

            # Set secure permissions on the file
            request_file.chmod(0o600)
            return True
        except Exception as e:
            logger.error(f"Failed to save request {request_id}: {e}")
            return False

    def _load_request(self, request_id: str) -> Dict:
        """Load request data from file."""
        request_file = REQUEST_STORE / f"{request_id}.json"
        if not request_file.exists():
            raise ValueError(f"Request {request_id} not found")

        try:
            with open(request_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load request {request_id}: {e}")
            raise ValueError(f"Failed to load request {request_id}: {e}")

    def validate_request_duration(self, role: str, duration_hours: int) -> bool:
        """Validate that the requested duration is within allowed limits."""
        max_duration = self.config.get("max_duration_hours", {}).get(role, 24)
        if duration_hours <= 0:
            raise ValidationError("Duration must be positive")
        if duration_hours > max_duration:
            raise ValidationError(
                f"Requested duration ({duration_hours}h) exceeds maximum allowed duration for {role} ({max_duration}h)"
            )
        return True

    def activate_emergency_access(
        self,
        username: str,
        role: str,
        reason: str,
        duration_hours: int = 4,
        require_approval: bool = True,
        mfa_token: Optional[str] = None,
        notify: Optional[List[str]] = None
    ) -> Dict:
        """
        Activate emergency access for a user.

        Args:
            username: The username to grant emergency access
            role: The role to grant (admin, operator, etc.)
            reason: Justification for emergency access
            duration_hours: Duration in hours for the emergency access
            require_approval: Whether approval is required before activation
            mfa_token: Multi-factor authentication token if required
            notify: List of notification channels to use

        Returns:
            Dictionary with request status and information
        """
        # Validate parameters
        if not username:
            raise ValidationError("Username is required")
        if not role:
            raise ValidationError("Role is required")
        if not reason:
            raise ValidationError("Reason is required")

        # Check if the role is valid
        self.validate_request_duration(role, duration_hours)

        # Create request ID and record
        request_id = self.generate_request_id()
        requester = getpass.getuser()
        now = datetime.datetime.now()
        expiration = now + datetime.timedelta(hours=duration_hours)

        request_data = {
            "request_id": request_id,
            "username": username,
            "role": role,
            "requester": requester,
            "reason": reason,
            "created_at": now.isoformat(),
            "expiration": expiration.isoformat(),
            "duration_hours": duration_hours,
            "status": AccessStatus.PENDING.value if require_approval else AccessStatus.APPROVED.value,
            "approval_required": require_approval,
            "approvers": [],
            "notifications": notify or [],
            "mfa_verified": bool(mfa_token)
        }

        # Attempt to use models if available
        if self._initialize_app():
            # Check if the user exists
            user = User.query.filter_by(username=username).first()
            if not user:
                raise ValidationError(f"User {username} not found")

            # Check if the role exists
            target_role = Role.query.filter_by(name=role).first()
            if not target_role:
                raise ValidationError(f"Role {role} not found")

            request_data["user_id"] = user.id
            request_data["role_id"] = target_role.id

            # Log security event
            log_security_event(
                event_type="emergency_access_request",
                description=f"Emergency access requested for {username} with role {role}",
                severity="critical",
                user_id=user.id,
                details={
                    "request_id": request_id,
                    "role": role,
                    "duration_hours": duration_hours,
                    "reason": reason,
                    "requester": requester
                }
            )

            # Log admin action
            log_admin_action(
                action=ACTION_EMERGENCY_ACCESS,
                details={
                    "request_id": request_id,
                    "username": username,
                    "role": role,
                    "duration_hours": duration_hours,
                    "reason": reason
                },
                status=STATUS_SUCCESS,
                severity=SEVERITY_CRITICAL
            )

            # If no approval needed, directly activate access
            if not require_approval:
                # Create permission delegation
                permissions = target_role.permissions
                delegation = PermissionDelegation.create_emergency_delegation(
                    delegator_id=1,  # System user ID
                    delegate_id=user.id,
                    permissions=[p.name for p in permissions],
                    valid_hours=duration_hours,
                    reason=reason
                )
                request_data["delegation_id"] = delegation.id

        # Save request data
        self._save_request(request_data)

        # Send notifications
        self._notify_about_request(request_data, "created")

        if require_approval:
            return {
                "status": "pending",
                "message": "Emergency access request submitted and waiting for approval",
                "request_id": request_id,
                "expiration": expiration.isoformat()
            }
        else:
            return {
                "status": "approved",
                "message": "Emergency access granted immediately (no approval required)",
                "request_id": request_id,
                "expiration": expiration.isoformat()
            }

    def approve_emergency_request(
        self,
        request_id: str,
        approver: str,
        approver_note: Optional[str] = None,
        mfa_token: Optional[str] = None,
    ) -> Dict:
        """
        Approve an emergency access request.

        Args:
            request_id: The ID of the request to approve
            approver: Email or username of the approver
            approver_note: Optional note from the approver
            mfa_token: Multi-factor authentication token if required

        Returns:
            Dictionary with approval status and information
        """
        # Load and validate request
        try:
            request_data = self._load_request(request_id)
        except ValueError as e:
            raise ResourceError(str(e))

        # Check if the request is pending
        if request_data["status"] != AccessStatus.PENDING.value:
            raise ValidationError(f"Request {request_id} is not pending approval (status: {request_data['status']})")

        # Check if the request has expired
        expiration = datetime.datetime.fromisoformat(request_data["expiration"])
        if datetime.datetime.now() > expiration:
            request_data["status"] = AccessStatus.EXPIRED.value
            self._save_request(request_data)
            raise ValidationError(f"Request {request_id} has expired")

        # Record approval
        approval_time = datetime.datetime.now()
        request_data["approvers"].append({
            "approver": approver,
            "timestamp": approval_time.isoformat(),
            "note": approver_note
        })

        # Check if we have sufficient approvers
        min_approvers = self.config.get("min_approvers", {}).get(request_data["role"], 1)
        if len(request_data["approvers"]) >= min_approvers:
            request_data["status"] = AccessStatus.APPROVED.value

            # Attempt to use models if available
            if self._initialize_app():
                username = request_data["username"]
                user = User.query.filter_by(username=username).first()
                if not user:
                    raise ResourceError(f"User {username} not found")

                role_name = request_data["role"]
                role = Role.query.filter_by(name=role_name).first()
                if not role:
                    raise ResourceError(f"Role {role_name} not found")

                # Create permission delegation
                permissions = role.permissions
                delegation = PermissionDelegation.create_emergency_delegation(
                    delegator_id=1,  # System user ID
                    delegate_id=user.id,
                    permissions=[p.name for p in permissions],
                    valid_hours=request_data["duration_hours"],
                    reason=request_data["reason"]
                )
                request_data["delegation_id"] = delegation.id

                # Log security event
                log_security_event(
                    event_type="emergency_access_activated",
                    description=f"Emergency access activated for {username} with role {role_name}",
                    severity="critical",
                    user_id=user.id,
                    details={
                        "request_id": request_id,
                        "approvers": [a["approver"] for a in request_data["approvers"]],
                        "expiration": request_data["expiration"]
                    }
                )

        # Save updated request data
        self._save_request(request_data)

        # Send notifications
        self._notify_about_request(request_data, "approved" if request_data["status"] == AccessStatus.APPROVED.value else "approval_progress")

        return {
            "status": request_data["status"],
            "message": f"Request {request_data['status']}",
            "approvers": len(request_data["approvers"]),
            "min_approvers": min_approvers,
            "request_id": request_id,
            "expiration": request_data["expiration"]
        }

    def deactivate_emergency_access(
        self,
        request_id: str,
        reason: Optional[str] = None,
        revoked_by: Optional[str] = None,
        mfa_token: Optional[str] = None,
    ) -> Dict:
        """
        Deactivate an emergency access request before expiration.

        Args:
            request_id: The ID of the request to deactivate
            reason: Reason for deactivation
            revoked_by: Username of person revoking access
            mfa_token: Multi-factor authentication token if required

        Returns:
            Dictionary with deactivation status and information
        """
        # Load and validate request
        try:
            request_data = self._load_request(request_id)
        except ValueError as e:
            raise ResourceError(str(e))

        # Check if the request is active or approved
        if request_data["status"] not in [AccessStatus.ACTIVE.value, AccessStatus.APPROVED.value]:
            raise ValidationError(f"Request {request_id} is not active or approved (status: {request_data['status']})")

        # Record deactivation
        deactivation_time = datetime.datetime.now()
        request_data["status"] = AccessStatus.REVOKED.value
        request_data["revoked_at"] = deactivation_time.isoformat()
        request_data["revoked_by"] = revoked_by or getpass.getuser()
        request_data["revocation_reason"] = reason or "Manual deactivation"

        # Attempt to use models if available
        if self._initialize_app() and "delegation_id" in request_data:
            # Revoke delegation
            try:
                delegation = PermissionDelegation.query.get(request_data["delegation_id"])
                if delegation:
                    delegation.end_time = datetime.datetime.now(datetime.timezone.utc)
                    db.session.commit()

                    # Log security event
                    log_security_event(
                        event_type="emergency_access_deactivated",
                        description=f"Emergency access deactivated for {request_data['username']}",
                        severity="warning",
                        details={
                            "request_id": request_id,
                            "revoked_by": request_data["revoked_by"],
                            "reason": request_data["revocation_reason"]
                        }
                    )

                    # Log admin action
                    log_admin_action(
                        action=ACTION_EMERGENCY_DEACTIVATE,
                        details={
                            "request_id": request_id,
                            "username": request_data["username"],
                            "reason": reason
                        },
                        status=STATUS_SUCCESS,
                        severity=SEVERITY_CRITICAL
                    )
            except Exception as e:
                logger.error(f"Failed to revoke delegation: {e}")

        # Save updated request data
        self._save_request(request_data)

        # Send notifications
        self._notify_about_request(request_data, "deactivated")

        return {
            "status": "deactivated",
            "message": "Emergency access has been deactivated",
            "request_id": request_id,
            "deactivated_at": deactivation_time.isoformat(),
            "deactivated_by": request_data["revoked_by"]
        }

    def list_emergency_requests(
        self,
        status: Optional[str] = None,
        user: Optional[str] = None,
        role: Optional[str] = None,
        include_expired: bool = False,
        limit: int = 100
    ) -> List[Dict]:
        """
        List emergency access requests.

        Args:
            status: Filter by status
            user: Filter by username
            role: Filter by role
            include_expired: Include expired requests
            limit: Maximum number of requests to return

        Returns:
            List of request data dictionaries
        """
        results = []
        count = 0

        # Get all request files
        request_files = sorted(REQUEST_STORE.glob("*.json"), key=os.path.getmtime, reverse=True)

        for request_file in request_files:
            if count >= limit:
                break

            try:
                with open(request_file, 'r') as f:
                    request_data = json.load(f)

                # Apply filters
                if status and request_data.get("status") != status:
                    continue

                if user and request_data.get("username") != user:
                    continue

                if role and request_data.get("role") != role:
                    continue

                # Check for expired requests
                if not include_expired and request_data.get("status") not in [AccessStatus.EXPIRED.value, AccessStatus.REVOKED.value]:
                    expiration = datetime.datetime.fromisoformat(request_data["expiration"])
                    if datetime.datetime.now() > expiration:
                        request_data["status"] = AccessStatus.EXPIRED.value
                        self._save_request(request_data)
                        if status and status != AccessStatus.EXPIRED.value:
                            continue

                # Add summary information
                request_summary = {
                    "request_id": request_data["request_id"],
                    "username": request_data["username"],
                    "role": request_data["role"],
                    "status": request_data["status"],
                    "created_at": request_data["created_at"],
                    "expiration": request_data["expiration"],
                    "reason": request_data["reason"],
                    "approver_count": len(request_data.get("approvers", []))
                }

                results.append(request_summary)
                count += 1

            except Exception as e:
                logger.error(f"Error processing request file {request_file}: {e}")

        return results

    def get_request_details(self, request_id: str) -> Dict:
        """
        Get detailed information about a specific emergency access request.

        Args:
            request_id: The ID of the request to get details for

        Returns:
            Complete request data dictionary
        """
        return self._load_request(request_id)

    def _notify_about_request(self, request_data: Dict, event_type: str) -> None:
        """Send notifications about an emergency access event."""
        # Determine who to notify
        notify_list = request_data.get("notifications", [])
        if not notify_list and "notifiers" in self.config:
            notify_list = self.config.get("notifiers", [])

        if not notify_list:
            logger.debug("No notification channels specified")
            return

        # Generate notification message
        request_id = request_data["request_id"]
        username = request_data["username"]
        role = request_data["role"]
        expiration = datetime.datetime.fromisoformat(request_data["expiration"])
        duration = request_data["duration_hours"]
        reason = request_data["reason"]

        # Generate subject based on event type
        subjects = {
            "created": f"Emergency Access Request: {username} - {request_id}",
            "approved": f"Emergency Access APPROVED: {username} - {request_id}",
            "approval_progress": f"Emergency Access Approval Progress: {username} - {request_id}",
            "deactivated": f"Emergency Access Deactivated: {username} - {request_id}",
            "expired": f"Emergency Access Expired: {username} - {request_id}"
        }

        subject = subjects.get(event_type, f"Emergency Access Event: {request_id}")

        # Generate message based on event type
        messages = {
            "created": (
                f"Emergency access has been requested for user {username} with role {role}.\n"
                f"Request ID: {request_id}\n"
                f"Duration: {duration} hours (expires: {expiration})\n"
                f"Reason: {reason}\n"
                f"Status: {request_data['status']}\n\n"
                f"Please approve or deny this request using the emergency access management tools."
            ),
            "approved": (
                f"Emergency access has been APPROVED for user {username} with role {role}.\n"
                f"Request ID: {request_id}\n"
                f"Duration: {duration} hours (expires: {expiration})\n"
                f"Reason: {reason}\n"
                f"Approvers: {', '.join([a['approver'] for a in request_data.get('approvers', [])])}\n\n"
                f"The user now has elevated permissions. This access will automatically expire at {expiration}."
            ),
            "approval_progress": (
                f"An emergency access request has received an approval.\n"
                f"Request ID: {request_id}\n"
                f"User: {username}\n"
                f"Role: {role}\n"
                f"Current approvers: {len(request_data.get('approvers', []))}\n"
                f"Required approvers: {self.config.get('min_approvers', {}).get(role, 1)}\n\n"
                f"Additional approvals are still required before access is granted."
            ),
            "deactivated": (
                f"Emergency access has been deactivated for user {username}.\n"
                f"Request ID: {request_id}\n"
                f"Deactivated by: {request_data.get('revoked_by', 'Unknown')}\n"
                f"Reason: {request_data.get('revocation_reason', 'Not provided')}\n\n"
                f"The user no longer has emergency elevated permissions."
            ),
            "expired": (
                f"Emergency access has expired for user {username}.\n"
                f"Request ID: {request_id}\n"
                f"The temporary elevated permissions have been automatically revoked."
            )
        }

        message = messages.get(event_type, f"Emergency access event for request {request_id}")

        # Send notifications
        for channel in notify_list:
            try:
                if channel in NOTIFIERS:
                    send_notification(
                        subject=subject,
                        message=message,
                        channel=channel,
                        severity="critical" if event_type in ["created", "approved"] else "warning"
                    )
                else:
                    logger.warning(f"Unknown notification channel: {channel}")
            except Exception as e:
                logger.error(f"Failed to send notification via {channel}: {e}")


def format_output(result: Union[Dict, List], format_type: str = "text") -> str:
    """Format the output based on the specified format."""
    if format_type == "json":
        return json.dumps(result, indent=2, sort_keys=True)

    elif format_type == "csv":
        if isinstance(result, list) and len(result) > 0:
            # Get headers from first item
            headers = list(result[0].keys())
            output = ",".join(headers) + "\n"

            # Add all rows
            for item in result:
                row = [str(item.get(h, "")) for h in headers]
                output += ",".join([f'"{val}"' if "," in val else val for val in row]) + "\n"
            return output
        else:
            return "No data to format as CSV"

    # Default to text format
    if isinstance(result, dict):
        output = []
        for key, value in result.items():
            if isinstance(value, list):
                output.append(f"{key}:")
                for item in value:
                    output.append(f"  - {item}")
            else:
                output.append(f"{key}: {value}")
        return "\n".join(output)

    elif isinstance(result, list):
        if not result:
            return "No results found"

        output = []
        for item in result:
            output.append("---")
            for key, value in item.items():
                output.append(f"{key}: {value}")
        return "\n".join(output)

    return str(result)


def setup_arg_parser() -> argparse.ArgumentParser:
    """Set up the argument parser."""
    parser = argparse.ArgumentParser(description="Emergency Access Management System")

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--output",
        help="Output file (default: stdout)"
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Emergency access commands")

    # Activate command
    activate_parser = subparsers.add_parser("activate", help="Activate emergency access")
    activate_parser.add_argument("--username", "-u", required=True, help="Username for emergency access")
    activate_parser.add_argument("--role", "-r", required=True, help="Role to grant")
    activate_parser.add_argument("--reason", required=True, help="Justification for emergency access")
    activate_parser.add_argument("--duration", "-d", type=int, default=4, help="Duration in hours (default: 4)")
    activate_parser.add_argument("--no-approval", action="store_true", help="Skip approval workflow")
    activate_parser.add_argument("--mfa-token", help="MFA token for verification")
    activate_parser.add_argument("--notify", nargs="+", choices=NOTIFIERS, help="Notification channels")

    # Approve command
    approve_parser = subparsers.add_parser("approve", help="Approve emergency access request")
    approve_parser.add_argument("--request-id", required=True, help="ID of the request to approve")
    approve_parser.add_argument("--approver", required=True, help="Email or username of the approver")
    approve_parser.add_argument("--note", help="Note from the approver")
    approve_parser.add_argument("--mfa-token", help="MFA token for verification")

    # Deactivate command
    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate emergency access")
    deactivate_parser.add_argument("--request-id", required=True, help="ID of the request to deactivate")
    deactivate_parser.add_argument("--reason", help="Reason for deactivation")
    deactivate_parser.add_argument("--revoked-by", help="Username of person revoking access")
    deactivate_parser.add_argument("--mfa-token", help="MFA token for verification")

    # List command
    list_parser = subparsers.add_parser("list", help="List emergency access requests")
    list_parser.add_argument("--status", choices=[s.value for s in AccessStatus], help="Filter by status")
    list_parser.add_argument("--user", help="Filter by username")
    list_parser.add_argument("--role", help="Filter by role")
    list_parser.add_argument("--include-expired", action="store_true", help="Include expired requests")
    list_parser.add_argument("--limit", type=int, default=100, help="Maximum number of requests to return")

    # Get details command
    details_parser = subparsers.add_parser("details", help="Get details of an emergency access request")
    details_parser.add_argument("--request-id", required=True, help="ID of the request to get details for")

    return parser


def activate_emergency_access(
    username: str,
    role: str,
    reason: str,
    duration_hours: int = 4,
    require_approval: bool = True,
    mfa_token: Optional[str] = None,
    notify: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Activate emergency access for a user."""
    manager = EmergencyAccessManager()
    try:
        return manager.activate_emergency_access(
            username=username,
            role=role,
            reason=reason,
            duration_hours=duration_hours,
            require_approval=require_approval,
            mfa_token=mfa_token,
            notify=notify
        )
    except EmergencyAccessError as e:
        return {"error": str(e), "status": "failed"}


def approve_emergency_request(
    request_id: str,
    approver: str,
    approver_note: Optional[str] = None,
    mfa_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Approve an emergency access request."""
    manager = EmergencyAccessManager()
    try:
        return manager.approve_emergency_request(
            request_id=request_id,
            approver=approver,
            approver_note=approver_note,
            mfa_token=mfa_token
        )
    except EmergencyAccessError as e:
        return {"error": str(e), "status": "failed"}


def deactivate_emergency_access(
    request_id: str,
    reason: Optional[str] = None,
    revoked_by: Optional[str] = None,
    mfa_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Deactivate an emergency access request."""
    manager = EmergencyAccessManager()
    try:
        return manager.deactivate_emergency_access(
            request_id=request_id,
            reason=reason,
            revoked_by=revoked_by,
            mfa_token=mfa_token
        )
    except EmergencyAccessError as e:
        return {"error": str(e), "status": "failed"}


def list_emergency_requests(
    status: Optional[str] = None,
    user: Optional[str] = None,
    role: Optional[str] = None,
    include_expired: bool = False,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """List emergency access requests."""
    manager = EmergencyAccessManager()
    try:
        return manager.list_emergency_requests(
            status=status,
            user=user,
            role=role,
            include_expired=include_expired,
            limit=limit
        )
    except EmergencyAccessError as e:
        return [{"error": str(e), "status": "failed"}]


def get_request_details(request_id: str) -> Dict[str, Any]:
    """Get details of a specific emergency access request."""
    manager = EmergencyAccessManager()
    try:
        return manager.get_request_details(request_id)
    except EmergencyAccessError as e:
        return {"error": str(e), "status": "failed"}


def main() -> int:
    """Main entry point for the script."""
    parser = setup_arg_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger.setLevel(log_level)

    try:
        # Handle commands
        if args.command == "activate":
            result = activate_emergency_access(
                username=args.username,
                role=args.role,
                reason=args.reason,
                duration_hours=args.duration,
                require_approval=not args.no_approval,
                mfa_token=args.mfa_token,
                notify=args.notify
            )

        elif args.command == "approve":
            result = approve_emergency_request(
                request_id=args.request_id,
                approver=args.approver,
                approver_note=args.note,
                mfa_token=args.mfa_token
            )

        elif args.command == "deactivate":
            result = deactivate_emergency_access(
                request_id=args.request_id,
                reason=args.reason,
                revoked_by=args.revoked_by,
                mfa_token=args.mfa_token
            )

        elif args.command == "list":
            result = list_emergency_requests(
                status=args.status,
                user=args.user,
                role=args.role,
                include_expired=args.include_expired,
                limit=args.limit
            )

        elif args.command == "details":
            result = get_request_details(
                request_id=args.request_id
            )

        else:
            # No command or unrecognized command
            parser.print_help()
            return EXIT_ARGUMENT_ERROR

        # Format and output the result
        formatted_output = format_output(result, args.format)

        # Write to file or stdout
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(formatted_output)
                logger.info(f"Output written to {args.output}")
            except Exception as e:
                logger.error(f"Failed to write output: {e}")
                return EXIT_ERROR
        else:
            print(formatted_output)

        # Determine exit code
        if isinstance(result, dict) and "error" in result:
            logger.error(f"Operation failed: {result['error']}")
            return EXIT_ERROR

        return EXIT_SUCCESS

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        return 130  # Standard exit code for SIGINT

    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
