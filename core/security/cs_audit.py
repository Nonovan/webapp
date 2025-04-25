import logging
from typing import List, Dict, Any, Optional, Tuple, Union, Set, TypeVar, cast
from datetime import datetime, timedelta, timezone

# SQLAlchemy imports
from sqlalchemy.exc import SQLAlchemyError

# Flask imports
from flask import current_app, request, g, has_request_context, session, has_app_context

# Internal imports
from .cs_constants import SECURITY_CONFIG
from models.audit_log import AuditLog
from extensions import db, metrics


# Set up module-level logger
logger = logging.getLogger(__name__)
# Initialize security logger for security events
security_logger = logging.getLogger('security')


def log_security_event(
    event_type: str,
    description: str,
    severity: str = 'info',
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[Union[str, Dict[str, Any]]] = None
) -> bool:
    """
    Log a security event to both application logs and audit log.

    This function serves as the central point for all security event logging
    in the application. It logs to both the application logs and the database
    audit log for comprehensive security event tracking.

    Args:
        event_type: Type of security event (e.g., 'login_failed', 'file_integrity')
        description: Human-readable description of the event
        severity: Severity level ('info', 'warning', 'error', 'critical')
        user_id: ID of the user associated with the event, if any
        ip_address: IP address associated with the event, if any
        details: Additional details about the event

    Returns:
        bool: True if logging was successful, False otherwise
    """
    # Try to get user_id from flask.g if not provided
    if user_id is None and has_request_context() and hasattr(g, 'user_id'):
        user_id = g.user_id

    # Try to get IP address from request if not provided
    if ip_address is None and has_request_context():
        ip_address = request.remote_addr

    # Get proper forwarded IP if behind proxy
    if ip_address is None and has_request_context() and request.headers.get('X-Forwarded-For'):
        # Use the leftmost IP which is the client's IP
        ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()

    # Map severity to logging levels
    severity_levels = {
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    log_level = severity_levels.get(severity.lower(), logging.INFO)

    # Map severity to AuditLog severity constants
    audit_severity = {
        'info': AuditLog.SEVERITY_INFO,
        'warning': AuditLog.SEVERITY_WARNING,
        'error': AuditLog.SEVERITY_ERROR,
        'critical': AuditLog.SEVERITY_CRITICAL
    }
    db_severity = audit_severity.get(severity.lower(), AuditLog.SEVERITY_INFO)

    # Prepare details for logging
    log_details = None
    if details:
        if isinstance(details, dict):
            # Format dict as JSON string
            import json
            try:
                log_details = json.dumps(details)
            except (TypeError, ValueError):
                log_details = str(details)
        else:
            log_details = str(details)

    # Log to application log
    try:
        # Create extra data dictionary for structured logging
        extra_data = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity
        }

        if log_details:
            extra_data['details'] = log_details

        # Log to security logger
        security_logger.log(
            log_level,
            description,
            extra=extra_data
        )
    except Exception as e:
        # Use a separate logger to avoid potential recursion
        logger.error(f"Error writing to security log: {e}")

    # Record in audit log
    try:
        # Use the AuditLog model
        audit_log = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=log_details,
            severity=db_severity,
            user_agent=request.user_agent.string if has_request_context() else None,
            created_at=datetime.now(timezone.utc)
        )

        db.session.add(audit_log)
        db.session.commit()

        # Track the security event
        metrics.increment(f'security.event.{event_type}')

        return True

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to record audit log: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in audit logging: {e}")
        return False
