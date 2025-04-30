"""
Audit Service for Cloud Infrastructure Platform.

This service provides functionalities for logging and retrieving audit trail
information for significant events and actions within the application.
It ensures that security-relevant activities are recorded for compliance,
debugging, and security analysis purposes.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple

# Attempt to import core components and models
try:
    from flask import current_app, has_app_context
    from extensions import db
    from models.security.audit_log import AuditLog
    from models.user import User # Assuming a User model exists
    CORE_AVAILABLE = True
except ImportError as e:
    CORE_AVAILABLE = False
    # Define dummy classes/functions if core components are missing
    db = None
    AuditLog = None
    User = None
    current_app = None
    has_app_context = lambda: False
    logging.warning(f"Core components not available for AuditService: {e}")

logger = logging.getLogger(__name__)

class AuditService:
    """
    Provides methods for managing audit logs.
    """

    @staticmethod
    def log_event(
        user_id: Optional[int],
        action: str,
        target_resource: Optional[str] = None,
        target_id: Optional[str] = None,
        status: str = "success",
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info"
    ) -> bool:
        """
        Logs an audit event to the database.

        Args:
            user_id: The ID of the user performing the action (None for system actions).
            action: A string identifier for the action performed (e.g., 'user.login', 'config.update').
            target_resource: The type of resource affected (e.g., 'user', 'firewall_rule').
            target_id: The specific ID of the resource affected.
            status: The outcome of the action ('success', 'failure', 'attempted').
            ip_address: The IP address from which the action originated.
            details: A dictionary containing additional context about the event.
            severity: The severity level of the event ('info', 'warning', 'error', 'critical').

        Returns:
            True if the event was logged successfully, False otherwise.
        """
        if not CORE_AVAILABLE or not AuditLog or not db:
            logger.error("Cannot log audit event: Core components or AuditLog model not available.")
            return False

        if not has_app_context():
            logger.error("Cannot log audit event: Application context not available.")
            # In a real scenario, you might queue this or handle it differently
            return False

        try:
            log_entry = AuditLog(
                user_id=user_id,
                action=action,
                target_resource=target_resource,
                target_id=target_id,
                status=status,
                ip_address=ip_address,
                details=details,
                severity=severity,
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(log_entry)
            db.session.commit()
            logger.debug(f"Audit event logged: Action={action}, UserID={user_id}, Status={status}")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to log audit event: {e}", exc_info=True)
            return False

    @staticmethod
    def get_logs(
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[int] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        ip_address: Optional[str] = None,
        target_resource: Optional[str] = None,
        target_id: Optional[str] = None,
        order_by: str = "timestamp",
        order_direction: str = "desc"
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Retrieves audit logs based on specified filter criteria.

        Args:
            limit: Maximum number of logs to return.
            offset: Number of logs to skip (for pagination).
            user_id: Filter by user ID.
            action: Filter by action string (can use wildcards like 'user.%').
            start_time: Filter logs after this timestamp.
            end_time: Filter logs before this timestamp.
            status: Filter by status ('success', 'failure', 'attempted').
            severity: Filter by severity level.
            ip_address: Filter by IP address.
            target_resource: Filter by target resource type.
            target_id: Filter by target resource ID.
            order_by: Field to order results by (default: 'timestamp').
            order_direction: 'asc' or 'desc' (default: 'desc').

        Returns:
            A tuple containing:
            - A list of audit log entries (as dictionaries).
            - The total count of matching log entries (before limit/offset).
        """
        if not CORE_AVAILABLE or not AuditLog:
            logger.error("Cannot get audit logs: Core components or AuditLog model not available.")
            return [], 0

        if not has_app_context():
            logger.error("Cannot get audit logs: Application context not available.")
            return [], 0

        try:
            query = AuditLog.query

            # Apply filters
            if user_id is not None:
                query = query.filter(AuditLog.user_id == user_id)
            if action:
                if '%' in action:
                    query = query.filter(AuditLog.action.like(action))
                else:
                    query = query.filter(AuditLog.action == action)
            if start_time:
                query = query.filter(AuditLog.timestamp >= start_time)
            if end_time:
                query = query.filter(AuditLog.timestamp <= end_time)
            if status:
                query = query.filter(AuditLog.status == status)
            if severity:
                query = query.filter(AuditLog.severity == severity)
            if ip_address:
                query = query.filter(AuditLog.ip_address == ip_address)
            if target_resource:
                query = query.filter(AuditLog.target_resource == target_resource)
            if target_id:
                query = query.filter(AuditLog.target_id == target_id)

            # Get total count before pagination
            total_count = query.count()

            # Apply ordering
            order_column = getattr(AuditLog, order_by, AuditLog.timestamp)
            if order_direction.lower() == "asc":
                query = query.order_by(order_column.asc())
            else:
                query = query.order_by(order_column.desc())

            # Apply pagination
            logs = query.limit(limit).offset(offset).all()

            # Convert logs to dictionaries (or use a serialization schema)
            log_list = [log.to_dict() for log in logs] # Assuming AuditLog has a to_dict() method

            return log_list, total_count

        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}", exc_info=True)
            return [], 0

    # Potential future methods:
    # - get_log_by_id(log_id: int) -> Optional[Dict[str, Any]]
    # - get_recent_failures(limit: int = 10) -> List[Dict[str, Any]]
    # - analyze_log_patterns(...) -> Dict[str, Any]
