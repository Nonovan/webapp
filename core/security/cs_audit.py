"""
Security audit logging functionality.

This module provides functions for security event logging, ensuring that
security-relevant events are properly recorded in both application logs
and the database audit log for compliance and investigation purposes.
"""

import json
import logging
from typing import Dict, Any, Optional, Union, List, Tuple
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
        object_type: Type of object affected (e.g., 'User', 'Configuration')
        object_id: ID of the affected object

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


def log_model_event(
    model_name: str,
    event_type: str,
    object_id: Optional[Union[int, str]] = None,
    user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: str = 'info'
) -> bool:
    """
    Log an event related to a model object.

    This is a convenience wrapper around log_security_event that provides
    standardized formatting for model-related events.

    Args:
        model_name: Name of the model being logged
        event_type: Type of event (e.g., 'status_change', 'permission_update')
        object_id: ID of the object being acted upon
        user_id: ID of the user performing the action (optional)
        details: Additional details about the event
        severity: Event severity (info, warning, error, critical)

    Returns:
        bool: True if logging was successful, False otherwise
    """
    # Automatically detect user ID from context if not provided
    if user_id is None and has_request_context() and hasattr(g, 'user_id'):
        user_id = g.user_id

    # Create a standardized event_type format
    full_event_type = f"{model_name.lower()}_{event_type}"

    # Generate a descriptive message
    description = f"{model_name} {event_type}"
    if object_id is not None:
        description = f"{model_name} {event_type} for ID {object_id}"

    # Pass to the main security event logging function
    return log_security_event(
        event_type=full_event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        details=details,
        object_type=model_name,
        object_id=object_id
    )


def log_error(message: str) -> None:
    """
    Log an error message using the security logger.

    Args:
        message: Error message to log
    """
    if has_app_context():
        security_logger.error(message)
    else:
        logger.error(message)


def log_warning(message: str) -> None:
    """
    Log a warning message using the security logger.

    Args:
        message: Warning message to log
    """
    if has_app_context():
        security_logger.warning(message)
    else:
        logger.warning(message)


def log_info(message: str) -> None:
    """
    Log an info message using the security logger.

    Args:
        message: Info message to log
    """
    if has_app_context():
        security_logger.info(message)
    else:
        logger.info(message)


def log_debug(message: str) -> None:
    """
    Log a debug message using the security logger.

    Args:
        message: Debug message to log
    """
    if has_app_context():
        security_logger.debug(message)
    else:
        logger.debug(message)


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
            # Remove any sensitive keys before serializing
            sanitized_details = details.copy()
            for sensitive_key in ['password', 'secret', 'token', 'key', 'credential']:
                if sensitive_key in sanitized_details:
                    sanitized_details[sensitive_key] = '[REDACTED]'

            # Try with default encoder first
            try:
                return json.dumps(sanitized_details)
            except (TypeError, ValueError):
                # Fall back to custom encoding with str() for non-serializable values
                for key, value in sanitized_details.items():
                    if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                        sanitized_details[key] = str(value)
                return json.dumps(sanitized_details)
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to JSON encode details: {e}")
            return str(details)

    return str(details)


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
    Log security event to the application log.

    Args:
        description: Event description
        log_level: Logging level
        event_type: Type of security event
        user_id: Associated user ID
        ip_address: Associated IP address
        severity: Event severity
        log_details: Formatted event details
        object_type: Type of object affected
        object_id: ID of the affected object
    """
    try:
        # Create extra data dictionary for structured logging
        extra_data = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat()
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
    Record security event in the database audit log.

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        log_details: Formatted event details
        db_severity: Database severity level
        object_type: Type of object affected
        object_id: ID of the affected object
        session_id: User session ID if available

    Returns:
        Optional[int]: ID of the created audit log entry or None on error

    Raises:
        SQLAlchemyError: Database error
    """
    try:
        # Add request path and method if available
        request_data = {}
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

    Args:
        event_type: Type of security event
        description: Event description
        user_id: Associated user ID
        ip_address: Associated IP address
        log_details: Formatted event details
        severity: Event severity

    Returns:
        bool: True if success, False otherwise
    """
    redis_client = get_redis_client()
    if not redis_client:
        return False

    try:
        # Create a simple event summary
        event_summary = {
            'event_type': event_type,
            'description': description,
            'user_id': user_id,
            'ip_address': ip_address,
            'severity': severity,
            'details': log_details,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Add to fallback events list
        key = 'security:fallback_events'
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
    Add event to correlation database for pattern detection.

    This function records events for later pattern analysis to detect
    potential security threats based on event correlation.

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
        # Current timestamp
        now = datetime.now(timezone.utc)
        timestamp = now.timestamp()

        # Store in correlation window
        window = SECURITY_CONFIG.get('EVENT_CORRELATION_WINDOW', 300)  # Default 5 minutes

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
            redis_client.zadd(global_key, {f"{event_type}:{user_id or 'none'}:{ip_address or 'none'}:{timestamp}": timestamp})
            # Expire old entries
            redis_client.zremrangebyscore(global_key, 0, now.timestamp() - window)
            # Set key expiration
            redis_client.expire(global_key, window * 2)
    except Exception as e:
        logger.error(f"Failed to add event to correlation database: {e}")


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
    Get recent security events from the database with flexible filtering.

    Args:
        limit: Maximum number of events to return
        severity: Filter by severity level
        event_type: Filter by event type
        user_id: Filter by user ID
        ip_address: Filter by IP address
        start_time: Filter events after this time
        end_time: Filter events before this time

    Returns:
        List[Dict[str, Any]]: List of security events as dictionaries
    """
    try:
        query = AuditLog.query.order_by(AuditLog.created_at.desc())

        # Apply filters
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

        events = query.limit(limit).all()
        return [event.to_dict() for event in events]
    except SQLAlchemyError as e:
        logger.error(f"Failed to retrieve recent security events: {e}")
        return []


def get_critical_security_events() -> List[Dict[str, Any]]:
    """
    Get cached critical security events from Redis.

    Returns:
        List[Dict[str, Any]]: List of critical security events
    """
    redis_client = get_redis_client()
    if not redis_client:
        return []

    try:
        key = 'security:recent_critical_events'
        event_jsons = redis_client.lrange(key, 0, 99)

        events = []
        for event_json in event_jsons:
            try:
                event = json.loads(event_json)
                events.append(event)
            except json.JSONDecodeError:
                # Skip invalid entries
                continue

        return events
    except Exception as e:
        logger.error(f"Failed to retrieve critical security events from Redis: {e}")
        return []


def get_security_event_counts(hours: int = 24) -> Dict[str, int]:
    """
    Get counts of security events by type for a given time period.

    Args:
        hours: Number of hours to look back

    Returns:
        Dict[str, int]: Mapping of event types to counts
    """
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query the database for event counts grouped by event type
        results = db.session.query(
            AuditLog.event_type,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at >= cutoff_time
        ).group_by(
            AuditLog.event_type
        ).all()

        # Convert to dictionary
        counts = {event_type: count for event_type, count in results}

        return counts
    except SQLAlchemyError as e:
        logger.error(f"Failed to retrieve security event counts: {e}")
        return {}


def get_security_event_severity_distribution(hours: int = 24) -> Dict[str, int]:
    """
    Get distribution of security events by severity for a given time period.

    Args:
        hours: Number of hours to look back

    Returns:
        Dict[str, int]: Mapping of severities to counts
    """
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Query the database for counts grouped by severity
        results = db.session.query(
            AuditLog.severity,
            func.count(AuditLog.id)
        ).filter(
            AuditLog.created_at >= cutoff_time
        ).group_by(
            AuditLog.severity
        ).all()

        # Map database severity values to readable names
        severity_map = {
            AuditLog.SEVERITY_INFO: 'info',
            AuditLog.SEVERITY_WARNING: 'warning',
            AuditLog.SEVERITY_ERROR: 'error',
            AuditLog.SEVERITY_CRITICAL: 'critical'
        }

        # Convert to dictionary with readable names
        counts = {severity_map.get(severity, severity): count for severity, count in results}

        # Ensure all severities are represented
        for severity_name in ['info', 'warning', 'error', 'critical']:
            if severity_name not in counts:
                counts[severity_name] = 0

        return counts
    except SQLAlchemyError as e:
        logger.error(f"Failed to retrieve security event severity distribution: {e}")
        return {'info': 0, 'warning': 0, 'error': 0, 'critical': 0}


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

        # Archive logs before deletion if archiving is enabled
        if SECURITY_CONFIG.get('ARCHIVE_LOGS_BEFORE_DELETE', False):
            _archive_old_logs(cutoff_date)

        # Delete logs older than the cutoff date
        result = AuditLog.query.filter(AuditLog.created_at < cutoff_date).delete()
        db.session.commit()

        logger.info(f"Cleared {result} security logs older than {days} days")
        metrics.gauge('security.logs_deleted', result)

        return result
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Failed to clear old security logs: {e}")
        return 0


def _archive_old_logs(cutoff_date: datetime) -> bool:
    """
    Archive logs before deletion.

    Args:
        cutoff_date: Archive logs older than this date

    Returns:
        bool: True if archiving was successful
    """
    try:
        # This is a placeholder for actual archiving logic
        # In a real implementation, this would export logs to a file or external system
        logger.info(f"Archiving logs older than {cutoff_date.isoformat()}")
        return True
    except Exception as e:
        logger.error(f"Failed to archive old logs: {e}")
        return False


def detect_security_anomalies() -> List[Dict[str, Any]]:
    """
    Detect anomalies in recent security events.

    Returns:
        List[Dict[str, Any]]: List of detected anomalies
    """
    anomalies = []

    try:
        # Check for multiple failed login attempts from the same IP
        login_failures = _check_login_anomalies()
        if login_failures:
            anomalies.extend(login_failures)

        # Check for unusual access patterns
        access_anomalies = _check_access_anomalies()
        if access_anomalies:
            anomalies.extend(access_anomalies)

        # Check for permission violations
        permission_anomalies = _check_permission_anomalies()
        if permission_anomalies:
            anomalies.extend(permission_anomalies)

        # Add additional anomaly checks here

        return anomalies
    except Exception as e:
        logger.error(f"Error detecting security anomalies: {e}")
        return []


def _check_login_anomalies() -> List[Dict[str, Any]]:
    """
    Check for login-related anomalies.

    Returns:
        List[Dict[str, Any]]: List of login anomalies
    """
    anomalies = []

    try:
        # Look back 1 hour for login failures
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)

        # Get IPs with multiple failed logins
        results = db.session.query(
            AuditLog.ip_address,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.created_at >= cutoff,
            AuditLog.ip_address.isnot(None)
        ).group_by(
            AuditLog.ip_address
        ).having(
            func.count(AuditLog.id) >= 5  # Threshold for anomaly
        ).all()

        for ip, count in results:
            anomalies.append({
                'type': 'multiple_failed_logins',
                'ip_address': ip,
                'count': count,
                'severity': 'high' if count >= 10 else 'medium',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"{count} failed login attempts from IP {ip} in the last hour"
            })

        # Check for distributed login attempts (many IPs for same username)
        username_results = db.session.query(
            func.json_extract(AuditLog.details, '$.username').label('username'),
            func.count(func.distinct(AuditLog.ip_address)).label('ip_count')
        ).filter(
            AuditLog.event_type == 'login_failed',
            AuditLog.created_at >= cutoff,
            AuditLog.details.like('%username%')
        ).group_by(
            'username'
        ).having(
            func.count(func.distinct(AuditLog.ip_address)) >= 3  # Threshold for anomaly
        ).all()

        for username, ip_count in username_results:
            if username:  # Ensure username is not None
                anomalies.append({
                    'type': 'distributed_login_attempts',
                    'username': username,
                    'ip_count': ip_count,
                    'severity': 'high',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': f"Login attempts for user '{username}' from {ip_count} different IPs in the last hour"
                })

        return anomalies
    except Exception as e:
        logger.error(f"Error checking login anomalies: {e}")
        return []


def _check_access_anomalies() -> List[Dict[str, Any]]:
    """
    Check for unusual access patterns.

    Returns:
        List[Dict[str, Any]]: List of access anomalies
    """
    anomalies = []

    try:
        # Look back 24 hours
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        # Check for unusual API access patterns
        # This is a placeholder for more specific implementation
        # In a real system, this would check for unusual API access times, volumes, etc.

        # For now, we'll just check for high volume of access to sensitive endpoints
        sensitive_endpoints = ['/api/admin/', '/api/users/', '/api/config/']

        for endpoint in sensitive_endpoints:
            # Count accesses to this endpoint by IP
            results = db.session.query(
                AuditLog.ip_address,
                func.count(AuditLog.id).label('count')
            ).filter(
                AuditLog.created_at >= cutoff,
                AuditLog.ip_address.isnot(None),
                AuditLog.request_data.like(f'%"path": "{endpoint}%')
            ).group_by(
                AuditLog.ip_address
            ).having(
                func.count(AuditLog.id) >= 50  # Threshold for anomaly
            ).all()

            for ip, count in results:
                anomalies.append({
                    'type': 'high_volume_sensitive_access',
                    'ip_address': ip,
                    'endpoint': endpoint,
                    'count': count,
                    'severity': 'medium',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'description': f"High volume of access ({count}) to sensitive endpoint {endpoint} from IP {ip}"
                })

        return anomalies
    except Exception as e:
        logger.error(f"Error checking access anomalies: {e}")
        return []


def _check_permission_anomalies() -> List[Dict[str, Any]]:
    """
    Check for unusual permission violation patterns.

    Returns:
        List[Dict[str, Any]]: List of permission anomalies
    """
    anomalies = []

    try:
        # Look back 24 hours
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        # Find users with multiple permission denied events
        results = db.session.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.event_type == 'permission_denied',
            AuditLog.created_at >= cutoff,
            AuditLog.user_id.isnot(None)
        ).group_by(
            AuditLog.user_id
        ).having(
            func.count(AuditLog.id) >= 5  # Threshold for anomaly
        ).all()

        for user_id, count in results:
            anomalies.append({
                'type': 'multiple_permission_violations',
                'user_id': user_id,
                'count': count,
                'severity': 'high' if count >= 10 else 'medium',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'description': f"User {user_id} had {count} permission violations in the last 24 hours"
            })

        return anomalies
    except Exception as e:
        logger.error(f"Error checking permission anomalies: {e}")
        return []


def process_fallback_logs() -> int:
    """
    Process security events that were logged to Redis when the database was unavailable.

    Returns:
        int: Number of events processed
    """
    redis_client = get_redis_client()
    if not redis_client:
        return 0

    try:
        key = 'security:fallback_events'
        processed_count = 0

        # Get all events from Redis
        event_jsons = redis_client.lrange(key, 0, -1)

        if not event_jsons:
            return 0

        # Process each event
        for event_json in event_jsons:
            try:
                event = json.loads(event_json)

                # Create audit log entry
                audit_log = AuditLog(
                    event_type=event.get('event_type', 'unknown'),
                    description=event.get('description', ''),
                    user_id=event.get('user_id'),
                    ip_address=event.get('ip_address'),
                    details=event.get('details'),
                    severity=event.get('severity', AuditLog.SEVERITY_INFO),
                    created_at=datetime.fromisoformat(event.get('timestamp', datetime.now(timezone.utc).isoformat()))
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


def initialize_audit_logging(app) -> None:
    """
    Initialize audit logging components.

    Args:
        app: Flask application
    """
    if not app:
        logger.error("Cannot initialize audit logging: No app provided")
        return

    logger.info("Initializing security audit logging")

    try:
        # Set up security logger based on app config
        from logging.config import dictConfig

        # Get log level from config or default to INFO
        log_level = app.config.get('SECURITY_LOG_LEVEL', 'INFO')
        log_file = app.config.get('SECURITY_LOG_FILE', 'logs/security.log')

        # Create logs directory if it doesn't exist
        import os
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Configure security logger
        dictConfig({
            'version': 1,
            'formatters': {
                'default': {
                    'format': '[%(asctime)s] %(levelname)s: %(message)s',
                },
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


def get_critical_event_categories() -> List[str]:
    """
    Get a list of event categories that are considered critical for security metrics.

    This function returns a list of audit log categories that are considered critical
    for security monitoring and metrics calculation. It first tries to get the list
    from application configuration, and falls back to sensible defaults if not configured.

    Returns:
        List[str]: List of critical event category names
    """
    try:
        # Try to get critical categories from configuration
        if has_app_context() and current_app.config:
            # Try application config first
            config_categories = current_app.config.get('AUDIT_CRITICAL_EVENT_CATEGORIES')
            if config_categories and isinstance(config_categories, list):
                return config_categories

            # Try security config from constants
            security_config_categories = SECURITY_CONFIG.get('CRITICAL_EVENT_CATEGORIES')
            if security_config_categories and isinstance(security_config_categories, list):
                return security_config_categories

        # Default categories if not configured
        return [
            'security',
            'authentication',
            'authorization',
            'admin',
            'audit',
            'compliance',
            'access_control'
        ]
    except Exception as e:
        logger.error(f"Error retrieving critical event categories: {e}", exc_info=True)
        # Return safe defaults on error
        return ['security', 'authentication', 'admin']
