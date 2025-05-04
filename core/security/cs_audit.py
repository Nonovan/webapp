"""
Security audit logging functionality.

This module provides functions for security event logging, ensuring that
security-relevant events are properly recorded in both application logs
and the database audit log for compliance and investigation purposes.
"""

import json
import logging
from typing import Dict, Any, Optional, Union, List, Tuple
import os
from datetime import datetime, timezone, timedelta

# SQLAlchemy imports
from sqlalchemy import func, desc, and_
from sqlalchemy.exc import SQLAlchemyError

# Flask imports
from flask import request, g, has_request_context, current_app, has_app_context, session

# Internal imports
from .cs_constants import SECURITY_CONFIG
from models.security import AuditLog
from extensions import db, metrics, get_redis_client

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
    details: Optional[Union[str, Dict[str, Any]]] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> bool:
    """
    Log a security event to both application logs and the audit log database.

    This function provides comprehensive security event logging, recording events
    in both the application logs (for real-time monitoring) and the audit log
    database (for compliance and investigation).

    Args:
        event_type: Type of security event
        description: Human-readable description of the event
        severity: Severity level (info, warning, error, critical)
        user_id: ID of the user associated with the event
        ip_address: IP address associated with the event
        details: Additional details about the event
        object_type: Type of object affected by the event
        object_id: ID of the object affected by the event

    Returns:
        bool: True if the event was successfully logged, False otherwise
    """
    try:
        # Determine user ID from context if not provided
        if user_id is None and has_request_context() and hasattr(g, 'user_id'):
            user_id = g.user_id

        # Determine IP address from request if not provided
        if has_request_context():
            if ip_address is None or ip_address == '127.0.0.1':
                forwarded_for = request.headers.get('X-Forwarded-For')
                if forwarded_for:
                    # Use the leftmost IP which is the client's IP
                    ip_address = forwarded_for.split(',')[0].strip()

            # Check for proxy headers in different formats
            if ip_address is None:
                # Try other common headers
                for header in ['X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP']:
                    if request.headers.get(header):
                        ip_address = request.headers.get(header)
                        break

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

        # Add session ID if available
        session_id = None
        if has_request_context() and session:
            session_id = session.get('id')

        # Log to application log
        _log_to_application_log(
            description, log_level, event_type, user_id,
            ip_address, severity, log_details, object_type, object_id
        )

        # Record in audit log
        audit_log_id = _record_in_audit_log(
            event_type, description, user_id, ip_address,
            log_details, db_severity, object_type, object_id, session_id
        )

        # Track the security event in metrics
        metrics.increment(f'security.event.{event_type}')
        metrics.increment(f'security.severity.{severity.lower()}')

        # Optional: Cache high criticality events for real-time monitoring
        if severity in ('error', 'critical'):
            _cache_critical_event(
                event_type, description, user_id, ip_address,
                severity, audit_log_id, object_type, object_id
            )

        # Add to event correlation database for pattern detection
        if SECURITY_CONFIG.get('ENABLE_EVENT_CORRELATION', False):
            _add_to_event_correlation(event_type, user_id, ip_address, severity)

        return True
    except Exception as e:
        # Use a separate logger to avoid potential recursion
        logger.error(f"Fatal error in security logging: {e}")
        return False


def log_security_event_as_audit_log(
    category: str,
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    severity: str = 'info',
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> bool:
    """
    Log an audit event with standardized formatting.

    This function provides a simplified interface to log_security_event that is
    more suitable for CLI tools and other non-HTTP contexts. It constructs
    a standardized event type from the category and event type.

    Args:
        category: Category of the audit event (e.g., 'user_management', 'configuration')
        event_type: Specific event type (e.g., 'user_created', 'role_changed')
        details: Additional details about the event
        severity: Severity level ('info', 'warning', 'error', 'critical')
        user_id: ID of the user who performed the action
        ip_address: IP address where the action originated
        object_type: Type of object being modified
        object_id: ID of the object being modified

    Returns:
        bool: True if logging succeeded, False otherwise
    """
    # Format the event type in a standard way: category.event_type
    formatted_event_type = f"{category}.{event_type}"

    # Create a standard description
    description = f"{category.replace('_', ' ').title()}: {event_type.replace('_', ' ').title()}"

    # Call the core security event logging function
    return log_security_event(
        event_type=formatted_event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        ip_address=ip_address,
        details=details,
        object_type=object_type,
        object_id=object_id
    )

# Create an alias for backward compatibility and to match the import in user.py
log_audit_event = log_security_event_as_audit_log

# Create the desired function name that's being imported
audit_log = log_security_event_as_audit_log


def log_model_event(
    model_name: str,
    event_type: str,
    object_id: Optional[Union[int, str]] = None,
    details: Optional[Union[Dict[str, Any], str]] = None,
    severity: str = 'info',
    user_id: Optional[int] = None
) -> bool:
    """
    Log a model-specific event to the security audit log.

    This is a specialized wrapper around log_security_event for model-related events
    like creation, modification, or deletion of model instances.

    Args:
        model_name: Name of the model (e.g., 'User', 'SecurityConfig')
        event_type: Type of event (e.g., 'create', 'update', 'delete')
        object_id: ID of the affected object
        details: Additional details about the event
        severity: Event severity (info, warning, error, critical)
        user_id: ID of the user who performed the action (if applicable)

    Returns:
        bool: True if the event was successfully logged, False otherwise
    """
    # Format event type if not already prefixed
    if '.' not in event_type:
        event_type = f"model.{event_type}"

    # Create user-friendly description
    action_verbs = {
        'create': 'created',
        'update': 'updated',
        'delete': 'deleted',
        'read': 'accessed',
    }

    # Get appropriate verb or default to the event type itself
    verb = action_verbs.get(event_type.split('.')[-1], event_type.split('.')[-1])
    description = f"{model_name} {verb}"

    if object_id:
        description = f"{description} (ID: {object_id})"

    # Log the event
    return log_security_event(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        details=details,
        object_type=model_name,
        object_id=object_id
    )


def get_security_events(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    per_page: int = 50
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Get security events from the audit log with filtering capabilities.

    This function retrieves security-related events from the audit log with
    various filtering options and pagination support, intended for administrative
    interfaces and reporting tools.

    Args:
        start_date: ISO format date string for filtering events after this date
        end_date: ISO format date string for filtering events before this date
        severity: Filter by severity level (info, warning, error, critical)
        event_type: Filter by specific event type
        page: Page number for pagination (starting at 1)
        per_page: Number of results per page

    Returns:
        Tuple containing:
            - List of security events as dictionaries
            - Total count of matching records
            - Total number of pages
    """
    try:
        query = AuditLog.query

        # Convert ISO date strings to datetime if provided
        start_dt = None
        end_dt = None

        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                logger.warning(f"Invalid start_date format: {start_date}")

        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                logger.warning(f"Invalid end_date format: {end_date}")

        # Apply date filters
        if start_dt:
            query = query.filter(AuditLog.created_at >= start_dt)

        if end_dt:
            query = query.filter(AuditLog.created_at <= end_dt)

        # Apply severity filter if specified
        if severity:
            # Map the severity string to the constant
            severity_map = {
                'info': AuditLog.SEVERITY_INFO,
                'warning': AuditLog.SEVERITY_WARNING,
                'error': AuditLog.SEVERITY_ERROR,
                'critical': AuditLog.SEVERITY_CRITICAL
            }
            db_severity = severity_map.get(severity.lower(), severity)
            query = query.filter(AuditLog.severity == db_severity)

        # Apply event type filter if specified
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)

        # Get total count before pagination
        total_count = query.count()

        # Calculate total pages
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1

        # Apply pagination and ordering
        query = query.order_by(AuditLog.severity.desc(), AuditLog.created_at.desc())
        query = query.offset((page - 1) * per_page).limit(per_page)

        # Execute query
        events = query.all()

        # Format logs for response
        result = []
        for event in events:
            event_entry = {
                'id': event.id,
                'event_type': event.event_type,
                'description': event.description,
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'severity': event.severity,
                'timestamp': event.created_at.isoformat() if event.created_at else None,
                'details': event.details,
                'object_type': event.object_type,
                'object_id': event.object_id
            }

            # Fetch username for display if available
            if event.user_id:
                try:
                    from models.auth.user import User
                    user = User.query.get(event.user_id)
                    if user:
                        event_entry['username'] = user.username
                except (ImportError, Exception):
                    # Silently handle if User model is not available
                    pass

            result.append(event_entry)

        return result, total_count, total_pages

    except SQLAlchemyError as e:
        logger.error(f"Database error in get_security_events: {str(e)}")
        raise ValueError("A database error occurred while retrieving security events")
    except Exception as e:
        logger.error(f"Unexpected error in get_security_events: {str(e)}")
        raise ValueError(f"Failed to retrieve security events: {str(e)}")


def log_error(message: str) -> None:
    """
    Log an error message to security logger.

    Args:
        message: Error message to log
    """
    try:
        security_logger.error(message)
        if has_app_context():
            # If in app context, log to audit log with appropriate severity
            log_security_event(
                event_type="system.error",
                description=message,
                severity="error"
            )
    except Exception as e:
        # Use standard logger as fallback
        logger.error(f"Failed to log security error: {e}")
        logger.error(message)


def log_warning(message: str) -> None:
    """
    Log a warning message to security logger.

    Args:
        message: Warning message to log
    """
    try:
        security_logger.warning(message)
        if has_app_context():
            # If in app context, log to audit log with appropriate severity
            log_security_event(
                event_type="system.warning",
                description=message,
                severity="warning"
            )
    except Exception as e:
        # Use standard logger as fallback
        logger.error(f"Failed to log security warning: {e}")
        logger.warning(message)


def log_info(message: str) -> None:
    """
    Log an info message to security logger.

    Args:
        message: Info message to log
    """
    try:
        security_logger.info(message)
        # Note: We don't log info messages to audit log to avoid noise
    except Exception as e:
        # Use standard logger as fallback
        logger.error(f"Failed to log security info: {e}")
        logger.info(message)


def log_debug(message: str) -> None:
    """
    Log a debug message to security logger.

    Args:
        message: Debug message to log
    """
    try:
        security_logger.debug(message)
        # Note: We don't log debug messages to audit log to avoid noise
    except Exception as e:
        # Use standard logger as fallback
        logger.error(f"Failed to log security debug: {e}")
        logger.debug(message)


def detect_security_anomalies(hours: int = 24) -> List[Dict[str, Any]]:
    """
    Detect security anomalies by analyzing recent security events.

    This function analyzes audit logs to identify patterns that may indicate
    security risks or unusual behavior warranting investigation.

    Args:
        hours: Number of hours to look back for event analysis

    Returns:
        List[Dict[str, Any]]: List of detected anomalies with details
    """
    anomalies = []

    try:
        MODELS_AVAILABLE = 'AuditLog' in globals()
        if not MODELS_AVAILABLE or not hasattr(AuditLog, 'query'):
            return []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Detect failed login clusters (potential brute force)
        login_attempts = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.created_at >= cutoff
        ).group_by(AuditLog.ip_address).having(
            func.count(AuditLog.id) >= 5  # Threshold for suspicious activity
        ).all()

        for ip_address, count in login_attempts:
            severity = 'medium' if count >= 10 else 'low'
            if count >= 20:
                severity = 'high'

            anomalies.append({
                'type': 'login_failure_cluster',
                'subtype': 'potential_brute_force',
                'ip_address': ip_address,
                'count': count,
                'severity': severity,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"Multiple failed login attempts ({count}) from {ip_address}"
            })

        # Detect unusual permission denied events
        permission_denied = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == 'permission_denied',
            AuditLog.created_at >= cutoff
        ).group_by(AuditLog.user_id).having(
            func.count(AuditLog.id) >= 3  # Threshold for suspicious activity
        ).all()

        for user_id, count in permission_denied:
            severity = 'medium' if count >= 5 else 'low'
            if count >= 10:
                severity = 'high'

            anomalies.append({
                'type': 'permission_denied_cluster',
                'subtype': 'potential_privilege_escalation',
                'user_id': user_id,
                'count': count,
                'severity': severity,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"Multiple permission denied events ({count}) for user {user_id}"
            })

        # Detect file integrity violations
        integrity_violations = db.session.query(
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == 'file_integrity',
            AuditLog.severity.in_(['error', 'critical']),
            AuditLog.created_at >= cutoff
        ).scalar() or 0

        if integrity_violations > 0:
            anomalies.append({
                'type': 'file_integrity_violations',
                'subtype': 'potential_unauthorized_changes',
                'count': integrity_violations,
                'severity': 'high',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"Multiple file integrity violations detected ({integrity_violations})"
            })

        # Track metrics for detected anomalies if metrics is available
        if anomalies and 'metrics' in globals():
            try:
                metrics.gauge('security.anomalies_detected', len(anomalies))
                high_severity = sum(1 for a in anomalies if a.get('severity') == 'high')
                metrics.gauge('security.high_severity_anomalies', high_severity)
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Error detecting security anomalies: {e}")

    return anomalies


def _prepare_log_details(details: Optional[Union[str, Dict[str, Any]]]) -> Optional[str]:
    """
    Prepare details for logging by converting to JSON if needed.

    Args:
        details: Details as string or dictionary

    Returns:
        str: JSON string representation of details
    """
    if details is None:
        return None

    if isinstance(details, str):
        return details

    try:
        return json.dumps(details)
    except Exception as e:
        logger.error(f"Error converting details to JSON: {e}")
        return json.dumps({"error": "Failed to serialize details", "raw": str(details)[:500]})

def _log_to_application_log(
    description: str,
    log_level: int,
    event_type: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    severity: str,
    log_details: Optional[str],
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> None:
    """
    Log security event to application log.

    Args:
        description: Event description
        log_level: Log level (INFO, WARNING, etc.)
        event_type: Type of security event
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
        log_details: JSON string of event details
        object_type: Type of object affected
        object_id: ID of object affected
    """
    try:
        # Create extra data for structured logging
        extra_data = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity
        }

        if object_type:
            extra_data['object_type'] = object_type

        if object_id:
            extra_data['object_id'] = object_id

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
    db_severity: str,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None,
    session_id: Optional[str] = None
) -> Optional[int]:
    """
    Record security event in the audit log database.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        log_details: JSON string of event details
        db_severity: Database severity constant
        object_type: Type of object affected
        object_id: ID of object affected
        session_id: Session identifier

    Returns:
        Optional[int]: ID of the created audit log entry, or None on error
    """
    try:
        # Get request data if available
        request_data = None
        if has_request_context():
            request_data = {
                'path': request.path,
                'method': request.method,
                'referrer': request.referrer,
            }

        # Use the AuditLog model
        audit_log = AuditLog(
            event_type=event_type,
            description=description,
            user_id=user_id,
            ip_address=ip_address,
            details=log_details,
            severity=db_severity,
            user_agent=request.user_agent.string if has_request_context() else None,
            session_id=session_id,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
            request_data=json.dumps(request_data) if request_data else None,
            created_at=datetime.now(timezone.utc)
        )

        db.session.add(audit_log)
        db.session.commit()

        return audit_log.id

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to record audit log: {e}")

        # Try to log to Redis as fallback if database is unavailable
        if SECURITY_CONFIG.get('FALLBACK_TO_REDIS', True):
            _fallback_log_to_redis(event_type, description, user_id, ip_address, log_details, db_severity)

        return None

def _fallback_log_to_redis(
    event_type: str,
    description: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    log_details: Optional[str],
    severity: str
) -> bool:
    """
    Fallback logging to Redis when database is unavailable.

    This function stores audit events in Redis temporarily until they can be
    processed into the main audit log database.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        log_details: JSON string of event details
        severity: Event severity level

    Returns:
        bool: True if successfully logged to Redis, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        return False

    try:
        # Create an event summary with all relevant info
        event_summary = {
            'event_type': event_type,
            'description': description,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': log_details,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Store in Redis list for later processing
        key = 'security:fallback_logs'
        redis_client.lpush(key, json.dumps(event_summary))

        # Cap the list to prevent memory issues (store last 1000 events)
        redis_client.ltrim(key, 0, 999)

        # Set expiration if not already set
        if not redis_client.ttl(key) > 0:
            # Retain for 7 days
            redis_client.expire(key, 7 * 86400)

        return True
    except Exception as e:
        logger.error(f"Redis fallback logging failed: {e}")
        return False

def _cache_critical_event(
    event_type: str,
    description: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    severity: str,
    audit_log_id: Optional[int] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Union[int, str]] = None
) -> None:
    """
    Cache critical security events for real-time monitoring.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
        audit_log_id: Database ID of the audit log entry
        object_type: Type of object affected
        object_id: ID of the affected object
    """
    redis_client = get_redis_client()
    if not redis_client:
        return

    try:
        # Create an event summary with all relevant info
        event_summary = {
            'event_type': event_type,
            'description': description,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'audit_log_id': audit_log_id
        }

        if object_type:
            event_summary['object_type'] = object_type

        if object_id:
            event_summary['object_id'] = str(object_id)

        # Add to recent critical events list (capped at 100 items)
        key = 'security:recent_critical_events'
        redis_client.lpush(key, json.dumps(event_summary))
        redis_client.ltrim(key, 0, 99)

        # Set expiration on the key if not already set
        if not redis_client.ttl(key) > 0:
            # Store for the retention period (default 7 days)
            retention_days = SECURITY_CONFIG.get('CRITICAL_EVENTS_RETENTION_DAYS', 7)
            redis_client.expire(key, retention_days * 86400)

        # Also increment a counter for this event type (for rate monitoring)
        counter_key = f'security:event_count:{event_type}'
        window_seconds = SECURITY_CONFIG.get('EVENT_COUNT_WINDOW', 3600)  # Default 1 hour

        # Use Redis sorted set for time-based counters
        redis_client.zadd(counter_key, {str(datetime.now(timezone.utc).timestamp()): 1})

        # Remove entries outside the window
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        redis_client.zremrangebyscore(counter_key, 0, cutoff.timestamp())

        # Set expiration on counter
        redis_client.expire(counter_key, window_seconds * 2)  # Double window for safety
    except Exception as e:
        logger.error(f"Failed to cache critical event: {e}")

def _add_to_event_correlation(
    event_type: str,
    user_id: Optional[int],
    ip_address: Optional[str],
    severity: str
) -> None:
    """
    Add security event to correlation tracking for pattern detection.

    Args:
        event_type: Type of security event
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
    """
    redis_client = get_redis_client()
    if not redis_client:
        return

    try:
        now = datetime.now(timezone.utc)
        timestamp = now.timestamp()

        # Get correlation window from config
        window = SECURITY_CONFIG.get('EVENT_CORRELATION_WINDOW', 3600)  # Default 1 hour

        # If user ID exists, track events by user
        if user_id:
            user_key = f'security:correlation:user:{user_id}'
            redis_client.zadd(user_key, {f"{event_type}:{timestamp}": timestamp})
            # Expire old entries
            redis_client.zremrangebyscore(user_key, 0, now.timestamp() - window)
            # Set key expiration
            redis_client.expire(user_key, window * 2)

        # If IP exists, track events by IP
        if ip_address:
            ip_key = f'security:correlation:ip:{ip_address}'
            redis_client.zadd(ip_key, {f"{event_type}:{timestamp}": timestamp})
            # Expire old entries
            redis_client.zremrangebyscore(ip_key, 0, now.timestamp() - window)
            # Set key expiration
            redis_client.expire(ip_key, window * 2)

        # Track high severity events globally
        if severity in ('error', 'critical'):
            global_key = 'security:correlation:global_high_severity'
            redis_client.zadd(global_key, {f"{event_type}:{user_id or 'anonymous'}:{timestamp}": timestamp})
            # Expire old entries
            redis_client.zremrangebyscore(global_key, 0, now.timestamp() - window)
            # Set key expiration
            redis_client.expire(global_key, window * 2)
    except Exception as e:
        logger.error(f"Failed to add event to correlation tracking: {e}")

def register_event_handlers():
    """
    Register event handlers for audit logging on model events.

    Returns:
        bool: True if handlers were registered successfully, False otherwise
    """
    try:
        from sqlalchemy import event
        from models.auth.login_attempt import LoginAttempt
        from models.security.session import Session

        # Register handlers for login attempts
        event.listen(LoginAttempt, 'after_insert', _handle_login_attempt)

        # Register handlers for session events
        event.listen(Session, 'after_insert', _handle_session_created)
        event.listen(Session, 'after_update', _handle_session_updated)
        event.listen(Session, 'after_delete', _handle_session_terminated)

        # These will be triggered by the respective operations in the auth module

        logger.info("Authentication event handlers registered successfully")
        return True

    except ImportError as e:
        logger.error(f"Failed to import necessary components for auth event handlers: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to register authentication event handlers: {e}")
        return False

def _handle_login_attempt(mapper, connection, login_attempt):
    """Handle login attempt events for security audit."""
    try:
        # Extract relevant information
        success = login_attempt.success
        event_type = AuditLog.EVENT_LOGIN_SUCCESS if success else AuditLog.EVENT_LOGIN_FAILED
        severity = 'info' if success else 'warning'

        # Log the security event
        log_security_event(
            event_type=event_type,
            description=f"User login {'succeeded' if success else 'failed'} for {login_attempt.username}",
            severity=severity,
            user_id=login_attempt.user_id if hasattr(login_attempt, 'user_id') else None,
            ip_address=login_attempt.ip_address,
            details={
                'username': login_attempt.username,
                'success': success,
                'user_agent': login_attempt.user_agent if hasattr(login_attempt, 'user_agent') else None,
                'location': login_attempt.location if hasattr(login_attempt, 'location') else None,
                'failure_reason': login_attempt.failure_reason if hasattr(login_attempt, 'failure_reason') and not success else None
            }
        )
    except Exception as e:
        logger.error(f"Error handling login attempt event: {e}")

def _handle_session_created(mapper, connection, session):
    """Handle session creation events for security audit."""
    try:
        log_security_event(
            event_type="session_created",
            description=f"User session created for user ID {session.user_id}",
            severity='info',
            user_id=session.user_id,
            ip_address=session.ip_address if hasattr(session, 'ip_address') else None,
            details={
                'session_id': session.session_id if hasattr(session, 'session_id') else None,
                'user_agent': session.user_agent if hasattr(session, 'user_agent') else None,
                'expires_at': session.expires_at.isoformat() if hasattr(session, 'expires_at') else None
            }
        )
    except Exception as e:
        logger.error(f"Error handling session created event: {e}")

def _handle_session_updated(mapper, connection, session):
    """Handle session update events for security audit."""
    try:
        if hasattr(session, 'is_extended') and session.is_extended:
            log_security_event(
                event_type="session_extended",
                description=f"User session extended for user ID {session.user_id}",
                severity='info',
                user_id=session.user_id,
                ip_address=session.ip_address if hasattr(session, 'ip_address') else None,
                details={
                    'session_id': session.session_id if hasattr(session, 'session_id') else None,
                    'new_expiry': session.expires_at.isoformat() if hasattr(session, 'expires_at') else None
                }
            )
    except Exception as e:
        logger.error(f"Error handling session updated event: {e}")

def _handle_session_terminated(mapper, connection, session):
    """Handle session termination events for security audit."""
    try:
        log_security_event(
            event_type="session_terminated",
            description=f"User session terminated for user ID {session.user_id}",
            severity='info',
            user_id=session.user_id,
            ip_address=session.ip_address if hasattr(session, 'ip_address') else None,
            details={
                'session_id': session.session_id if hasattr(session, 'session_id') else None,
                'reason': session.termination_reason if hasattr(session, 'termination_reason') else 'logout'
            }
        )
    except Exception as e:
        logger.error(f"Error handling session terminated event: {e}")

def get_recent_security_events(
    limit: int = 50,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """
    Get recent security events from the audit log.

    Args:
        limit: Maximum number of events to return
        severity: Filter by severity level
        event_type: Filter by event type
        user_id: Filter by user ID
        ip_address: Filter by IP address
        start_time: Filter by start time
        end_time: Filter by end time

    Returns:
        List[Dict[str, Any]]: List of security events
    """
    try:
        query = AuditLog.query

        # Apply severity filter if specified
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

        if event_type:
            query = query.filter(AuditLog.event_type == event_type)

        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        if ip_address:
            query = query.filter(AuditLog.ip_address == ip_address)

        if start_time:
            query = query.filter(AuditLog.created_at >= start_time)

        if end_time:
            query = query.filter(AuditLog.created_at <= end_time)

        # Get events sorted by time (most recent first)
        events = query.order_by(AuditLog.created_at.desc()).limit(limit).all()

        # Convert to dictionaries
        return [event.to_dict() for event in events]

    except Exception as e:
        logger.error(f"Error retrieving recent security events: {e}")
        return []

def get_audit_logs(**filters) -> List[Dict[str, Any]]:
    """
    Retrieve audit logs with flexible filtering.

    This function is intended to be used by the admin.utils.audit_utils module
    but provides more generalized filtering capabilities.

    Args:
        **filters: Arbitrary filters to apply to the query
            - start_time (datetime): Start time for logs
            - end_time (datetime): End time for logs
            - user_id (int): Filter by user ID
            - event_types (List[str]): Filter by event types
            - severity (str): Filter by severity
            - category (str): Filter by category
            - object_type (str): Filter by object type
            - object_id (str/int): Filter by object ID
            - limit (int): Maximum number of logs to return
            - offset (int): Number of logs to skip (for pagination)

    Returns:
        List[Dict[str, Any]]: List of audit logs
    """
    try:
        query = AuditLog.query

        # Apply time filters
        start_time = filters.get('start_time')
        end_time = filters.get('end_time')

        if start_time:
            query = query.filter(AuditLog.created_at >= start_time)
        if end_time:
            query = query.filter(AuditLog.created_at <= end_time)

        # Apply identity filters
        user_id = filters.get('user_id')
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)

        # Apply event type filters
        event_types = filters.get('event_types')
        if event_types:
            query = query.filter(AuditLog.event_type.in_(event_types))

        # Apply severity filter
        severity = filters.get('severity')
        if severity:
            # Map string severity to DB constant if needed
            severity_map = {
                'info': AuditLog.SEVERITY_INFO,
                'warning': AuditLog.SEVERITY_WARNING,
                'error': AuditLog.SEVERITY_ERROR,
                'critical': AuditLog.SEVERITY_CRITICAL
            }
            db_severity = severity_map.get(severity.lower(), severity)
            query = query.filter(AuditLog.severity == db_severity)

        # Apply category filter
        category = filters.get('category')
        if category:
            query = query.filter(AuditLog.category == category)

        # Apply object filters
        object_type = filters.get('object_type')
        if object_type:
            query = query.filter(AuditLog.object_type == object_type)

        object_id = filters.get('object_id')
        if object_id:
            query = query.filter(AuditLog.object_id == str(object_id))

        # Apply pagination
        limit = filters.get('limit', 50)
        offset = filters.get('offset', 0)

        # Execute query
        query = query.order_by(AuditLog.created_at.desc())
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)

        logs = query.all()

        # Convert to dictionaries if needed
        return logs

    except Exception as e:
        logger.error(f"Error retrieving audit logs: {e}")
        return []

def process_fallback_logs() -> int:
    """
    Process logs stored in Redis fallback mechanism into the database.

    This function retrieves audit events stored in Redis and inserts them
    into the main audit log database. It should be called periodically
    (e.g., by a scheduled task) to ensure logs are properly recorded.

    Returns:
        int: Number of logs processed
    """
    redis_client = get_redis_client()
    if not redis_client:
        return 0

    key = 'security:fallback_logs'

    try:
        # Get all fallback logs
        fallback_logs = redis_client.lrange(key, 0, -1)
        if not fallback_logs:
            return 0

        processed_count = 0

        for log_entry in fallback_logs:
            try:
                # Parse the event data
                event_data = json.loads(log_entry)

                # Create audit log entry
                audit_log = AuditLog(
                    event_type=event_data.get('event_type'),
                    description=event_data.get('description'),
                    user_id=event_data.get('user_id'),
                    ip_address=event_data.get('ip_address'),
                    details=event_data.get('details'),
                    severity=event_data.get('severity'),
                    created_at=datetime.fromisoformat(event_data.get('timestamp'))
                )

                db.session.add(audit_log)
                processed_count += 1

            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.error(f"Failed to process fallback event: {e}")

        # Commit all processed events
        db.session.commit()

        # Clear processed events from Redis
        if processed_count > 0:
            redis_client.delete(key)

        logger.info(f"Processed {processed_count} fallback security events")
        return processed_count

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error processing fallback logs: {e}")
        return 0
    except Exception as e:
        logger.error(f"Error processing fallback logs: {e}")
        return 0

def get_critical_event_categories() -> List[str]:
    """
    Get list of event categories considered critical for security monitoring.

    Returns:
        List[str]: List of critical event categories
    """
    try:
        # Get from config if available, otherwise use defaults
        return SECURITY_CONFIG.get('CRITICAL_EVENT_CATEGORIES', [
            'security',
            'authentication',
            'access_control'
        ])
    except Exception as e:
        logger.error(f"Error retrieving critical event categories: {e}", exc_info=True)
        # Return safe defaults on error
        return ['security', 'authentication', 'admin']

def initialize_audit_logging(app) -> None:
    """
    Initialize audit logging configuration for the application.

    Args:
        app: Flask application instance
    """
    try:
        # Set up logging directory
        log_dir = app.config.get('SECURITY_LOG_DIR', 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, 'security_audit.log')
        log_level_name = app.config.get('SECURITY_LOG_LEVEL', 'INFO')

        # Map log level name to logging constant
        log_level = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }.get(log_level_name.upper(), logging.INFO)

        # Configure logging
        logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'detailed': {
                    'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s\nDetails: %(event_type)s User: %(user_id)s IP: %(ip_address)s',
                },
            },
            'handlers': {
                'security_file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': log_file,
                    'formatter': 'detailed',
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 10
                },
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'detailed',
                    'level': log_level
                }
            },
            'loggers': {
                'security': {
                    'level': log_level,
                    'handlers': ['security_file', 'console'],
                    'propagate': False,
                }
            }
        })

        logger.info(f"Security audit logging initialized (level: {log_level})")
    except Exception as e:
        logger.error(f"Failed to initialize audit logging: {e}")

def get_security_event_counts(
    days: int = 7,
    event_types: Optional[List[str]] = None
) -> Dict[str, Dict[str, int]]:
    """
    Get counts of security events grouped by type and severity.

    Args:
        days: Number of days to look back
        event_types: Optional list of specific event types to count

    Returns:
        Dict with event types as keys and counts by severity as values
    """
    try:
        if not has_app_context():
            logger.warning("App context not available for security event counts")
            return {}

        # Calculate cutoff date
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Base query
        query = db.session.query(
            AuditLog.event_type,
            AuditLog.severity,
            func.count(AuditLog.id).label('count')
        ).filter(AuditLog.created_at >= cutoff)

        # Filter by event types if specified
        if event_types:
            query = query.filter(AuditLog.event_type.in_(event_types))

        # Group by event type and severity, and get counts
        query = query.group_by(AuditLog.event_type, AuditLog.severity)

        # Execute query
        results = query.all()

        # Format results
        event_counts = {}
        for event_type, severity, count in results:
            if event_type not in event_counts:
                event_counts[event_type] = {'info': 0, 'warning': 0, 'error': 0, 'critical': 0, 'total': 0}

            # Map DB severity to string representation
            severity_str = {
                AuditLog.SEVERITY_INFO: 'info',
                AuditLog.SEVERITY_WARNING: 'warning',
                AuditLog.SEVERITY_ERROR: 'error',
                AuditLog.SEVERITY_CRITICAL: 'critical'
            }.get(severity, 'info')

            event_counts[event_type][severity_str] = count
            event_counts[event_type]['total'] += count

        return event_counts

    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving security event counts: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error retrieving security event counts: {e}")
        return {}

def get_critical_security_events(
    limit: int = 20,
    hours: int = 24
) -> List[Dict[str, Any]]:
    """
    Get recent critical and error-level security events.

    This function retrieves high-severity security events that may require
    immediate attention for security monitoring and incident response.

    Args:
        limit: Maximum number of events to return
        hours: Number of hours to look back

    Returns:
        List of critical and error security events
    """
    try:
        # Try to get events from Redis cache first for better performance
        redis_client = get_redis_client()
        if redis_client:
            try:
                key = 'security:recent_critical_events'
                cached_events = redis_client.lrange(key, 0, limit - 1)
                if cached_events:
                    events = []
                    for event_json in cached_events:
                        try:
                            event = json.loads(event_json)
                            # Only include events within the time window
                            event_time = datetime.fromisoformat(event.get('timestamp', ''))
                            if datetime.now(timezone.utc) - event_time <= timedelta(hours=hours):
                                events.append(event)
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.debug(f"Could not parse cached event: {e}")

                    if events:
                        return events[:limit]
            except Exception as e:
                logger.debug(f"Redis cache access error: {e}")

        # Fall back to database query if cache is not available or empty
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query for critical and error events
        query = AuditLog.query.filter(
            AuditLog.created_at >= cutoff,
            AuditLog.severity.in_([AuditLog.SEVERITY_CRITICAL, AuditLog.SEVERITY_ERROR])
        ).order_by(AuditLog.created_at.desc()).limit(limit)

        events = query.all()

        # Format results as dictionaries
        return [
            {
                'id': event.id,
                'event_type': event.event_type,
                'description': event.description,
                'severity': event.severity,
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'timestamp': event.created_at.isoformat() if event.created_at else None,
                'details': event.details
            }
            for event in events
        ]

    except SQLAlchemyError as e:
        logger.error(f"Database error retrieving critical security events: {e}")
        return []
    except Exception as e:
        logger.error(f"Error retrieving critical security events: {e}")
        return []
