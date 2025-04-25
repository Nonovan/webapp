"""
Security audit logging functionality.

This module provides functions for security event logging, ensuring that
security-relevant events are properly recorded in both application logs
and the database audit log for compliance and investigation purposes.
"""

import json
import logging
from typing import Dict, Any, Optional, Union
from datetime import datetime, timezone, timedelta

# SQLAlchemy imports
from sqlalchemy.exc import SQLAlchemyError

# Flask imports
from flask import request, g, has_request_context, current_app, has_app_context

# Internal imports
from .cs_constants import SECURITY_CONFIG
from models.audit_log import AuditLog
from extensions import db, metrics, redis_client


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
    try:
        # Try to get user_id from flask.g if not provided
        if user_id is None and has_request_context() and hasattr(g, 'user_id'):
            user_id = g.user_id

        # Try to get IP address from request if not provided
        if ip_address is None and has_request_context():
            ip_address = request.remote_addr

            # Get proper forwarded IP if behind proxy
            if ip_address is None and request.headers.get('X-Forwarded-For'):
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
        log_details = _prepare_log_details(details)

        # Log to application log
        _log_to_application_log(description, log_level, event_type, user_id, ip_address, severity, log_details)

        # Record in audit log
        _record_in_audit_log(event_type, description, user_id, ip_address, log_details, db_severity)

        # Track the security event in metrics
        metrics.increment(f'security.event.{event_type}')

        # Optional: Cache high criticality events for real-time monitoring
        if severity in ('error', 'critical'):
            _cache_critical_event(event_type, description, user_id, ip_address, severity)

        return True
    except Exception as e:
        # Use a separate logger to avoid potential recursion
        logger.error(f"Fatal error in security logging: {e}")
        return False


def _prepare_log_details(details: Optional[Union[str, Dict[str, Any]]]) -> Optional[str]:
    """
    Prepare details for logging by converting to a string format.

    Args:
        details: Event details as string or dictionary

    Returns:
        str: Formatted details string or None
    """
    if not details:
        return None

    if isinstance(details, dict):
        try:
            return json.dumps(details)
        except (TypeError, ValueError):
            return str(details)

    return str(details)


def _log_to_application_log(
    description: str,
    log_level: int,
    event_type: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    severity: str,
    log_details: Optional[str]
) -> None:
    """
    Log security event to the application log.

    Args:
        description: Event description
        log_level: Logging level
        event_type: Type of security event
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
        log_details: Formatted event details
    """
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
        logger.error(f"Error writing to security log: {e}")


def _record_in_audit_log(
    event_type: str,
    description: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    log_details: Optional[str],
    db_severity: str
) -> None:
    """
    Record security event in the database audit log.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        log_details: Formatted event details
        db_severity: Database severity level

    Raises:
        SQLAlchemyError: Database error
    """
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

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to record audit log: {e}")
        raise


def _cache_critical_event(
    event_type: str,
    description: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    severity: str
) -> None:
    """
    Cache critical security events for real-time monitoring.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
    """
    if not redis_client:
        return

    try:
        # Create a simple event summary
        event_summary = {
            'event_type': event_type,
            'description': description,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Add to recent critical events list (capped at 100 items)
        key = 'security:recent_critical_events'
        redis_client.lpush(key, json.dumps(event_summary))
        redis_client.ltrim(key, 0, 99)

        # Set expiration on the key if not already set
        if not redis_client.ttl(key) > 0:
            # Store for the retention period (default 7 days)
            retention_days = SECURITY_CONFIG.get('CRITICAL_EVENTS_RETENTION_DAYS', 7)
            redis_client.expire(key, retention_days * 86400)
    except Exception as e:
        logger.error(f"Failed to cache critical event: {e}")


def get_recent_security_events(limit: int = 50, severity: Optional[str] = None) -> list:
    """
    Get recent security events from the database.

    Args:
        limit: Maximum number of events to return
        severity: Filter by severity level

    Returns:
        list: List of security events
    """
    try:
        query = AuditLog.query.order_by(AuditLog.created_at.desc())

        if severity:
            severity_map = {
                'info': AuditLog.SEVERITY_INFO,
                'warning': AuditLog.SEVERITY_WARNING,
                'error': AuditLog.SEVERITY_ERROR,
                'critical': AuditLog.SEVERITY_CRITICAL
            }
            db_severity = severity_map.get(severity.lower())
            if db_severity:
                query = query.filter(AuditLog.severity == db_severity)

        events = query.limit(limit).all()
        return [event.to_dict() for event in events]
    except SQLAlchemyError as e:
        logger.error(f"Failed to retrieve recent security events: {e}")
        return []


def clear_old_security_logs(days: int = None) -> int:
    """
    Clear security logs older than the specified number of days.

    Args:
        days: Number of days to keep logs (uses configured retention period if None)

    Returns:
        int: Number of logs deleted
    """
    if not has_app_context():
        logger.warning("Cannot clear security logs outside application context")
        return 0

    try:
        # Use configured retention period if not specified
        if days is None:
            days = SECURITY_CONFIG.get('AUDIT_LOG_RETENTION_DAYS', 180)

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        result = AuditLog.query.filter(AuditLog.created_at < cutoff_date).delete()
        db.session.commit()

        logger.info(f"Cleared {result} security logs older than {days} days")
        return result
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to clear old security logs: {e}")
        return 0
