"""
Audit Service for Cloud Infrastructure Platform.

This service provides functionalities for logging and retrieving audit trail
information for significant events and actions within the application.
It ensures that security-relevant activities are recorded for compliance,
debugging, and security analysis purposes.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple, Set
import re

# Attempt to import core components and models
try:
    from flask import current_app, has_app_context, request
    from extensions import db, cache
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

    # Common event types constants for consistent usage
    EVENT_USER_LOGIN = "user.login"
    EVENT_USER_LOGOUT = "user.logout"
    EVENT_USER_CREATE = "user.create"
    EVENT_USER_UPDATE = "user.update"
    EVENT_USER_DELETE = "user.delete"
    EVENT_PASSWORD_CHANGE = "user.password.change"
    EVENT_PASSWORD_RESET = "user.password.reset"
    EVENT_MFA_CHANGE = "user.mfa.change"
    EVENT_ACCESS_DENIED = "access.denied"
    EVENT_CONFIG_CHANGE = "config.change"
    EVENT_FILE_ACCESS = "file.access"
    EVENT_FILE_CHANGE = "file.change"
    EVENT_SECURITY_ALERT = "security.alert"
    EVENT_API_KEY_CREATE = "api_key.create"
    EVENT_API_KEY_REVOKE = "api_key.revoke"

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

        # Auto-detect IP address if not provided but request is available
        if ip_address is None and request:
            ip_address = request.remote_addr

        # Add timestamp to details if not present
        if details is None:
            details = {}
        if not details.get('timestamp'):
            details['timestamp'] = datetime.now(timezone.utc).isoformat()

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
            log_list = [log.to_dict() for log in logs]  # Assuming AuditLog has a to_dict() method

            # Log this retrieval for audit trail meta-logging
            AuditService.log_event(
                user_id=None if not has_app_context() else getattr(getattr(current_app, 'auth', None), 'current_user_id', None),
                action="audit.log.access",
                target_resource="audit_log",
                status="success",
                details={
                    "filters": {
                        "limit": limit,
                        "offset": offset,
                        "user_id": user_id,
                        "action": action,
                        "start_time": start_time.isoformat() if start_time else None,
                        "end_time": end_time.isoformat() if end_time else None,
                        "status": status,
                        "severity": severity,
                        "target_resource": target_resource
                    },
                    "results_count": len(log_list)
                }
            )

            return log_list, total_count

        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}", exc_info=True)
            return [], 0

    @staticmethod
    def get_log_by_id(log_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific audit log entry by ID.

        Args:
            log_id: The ID of the audit log entry to retrieve.

        Returns:
            The audit log entry as a dictionary, or None if not found.
        """
        if not CORE_AVAILABLE or not AuditLog or not has_app_context():
            logger.error("Cannot get audit log: Core components or application context not available.")
            return None

        try:
            log_entry = AuditLog.query.get(log_id)
            if log_entry:
                # Log this access for audit trail
                AuditService.log_event(
                    user_id=getattr(getattr(current_app, 'auth', None), 'current_user_id', None),
                    action="audit.log.detail_access",
                    target_resource="audit_log",
                    target_id=str(log_id),
                    status="success"
                )
                return log_entry.to_dict()
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve audit log by ID {log_id}: {e}", exc_info=True)
            return None

    @staticmethod
    def get_recent_failures(limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent failed actions across the system.

        Args:
            limit: Maximum number of failure records to return.

        Returns:
            A list of recent failure audit logs.
        """
        logs, _ = AuditService.get_logs(
            limit=limit,
            status="failure",
            order_by="timestamp",
            order_direction="desc"
        )
        return logs

    @staticmethod
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def get_security_metrics(start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Calculate security metrics based on audit logs.

        Args:
            start_time: Start time for the metric calculation period.
            end_time: End time for the metric calculation period.

        Returns:
            Dictionary containing security metrics.
        """
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(days=7)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        if not CORE_AVAILABLE or not AuditLog or not has_app_context():
            logger.error("Cannot calculate security metrics: Core components or application context not available.")
            return {
                "error": "Service unavailable",
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat()
            }

        try:
            metrics = {
                "period_start": start_time.isoformat(),
                "period_end": end_time.isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat()
            }

            # Get basic counts by severity
            for severity in ["info", "warning", "error", "critical"]:
                count = AuditLog.query.filter(
                    AuditLog.severity == severity,
                    AuditLog.timestamp.between(start_time, end_time)
                ).count()
                metrics[f"{severity}_count"] = count

            # Get failure counts
            failure_count = AuditLog.query.filter(
                AuditLog.status == "failure",
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["failure_count"] = failure_count

            # Get authentication failure counts
            auth_failure_count = AuditLog.query.filter(
                AuditLog.action.like("user.login%"),
                AuditLog.status == "failure",
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["auth_failure_count"] = auth_failure_count

            # Get security-related event counts
            security_event_count = AuditLog.query.filter(
                AuditLog.action.like("security.%"),
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["security_event_count"] = security_event_count

            return metrics

        except Exception as e:
            logger.error(f"Failed to generate security metrics: {e}", exc_info=True)
            return {
                "error": "Failed to generate metrics",
                "reason": str(e)
            }

    @staticmethod
    def analyze_login_anomalies(
        threshold_percent: int = 30,
        lookback_days: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Analyze authentication logs for anomalies based on IP addresses, times, and failures.

        Args:
            threshold_percent: Percent deviation to flag as anomalous.
            lookback_days: Number of days to analyze for baseline.

        Returns:
            List of detected anomalies with details.
        """
        if not CORE_AVAILABLE or not AuditLog or not has_app_context():
            logger.error("Cannot analyze login anomalies: Core components or application context not available.")
            return []

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=lookback_days)

            anomalies = []

            # Query login events
            login_events = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_USER_LOGIN,
                AuditLog.timestamp.between(start_time, end_time)
            ).all()

            if not login_events:
                logger.info("No login events found for anomaly analysis.")
                return []

            # Analyze by user
            user_logins = {}
            user_ips = {}

            for event in login_events:
                user_id = event.user_id
                if user_id is None:
                    continue

                # Track login frequency by user
                if user_id not in user_logins:
                    user_logins[user_id] = []
                user_logins[user_id].append(event.timestamp)

                # Track IP addresses by user
                if user_id not in user_ips:
                    user_ips[user_id] = set()
                if event.ip_address:
                    user_ips[user_id].add(event.ip_address)

            # Check for new IPs
            for user_id, ip_set in user_ips.items():
                if len(ip_set) > 1:
                    # Get historical IPs (lookback further)
                    historical_ips = set()
                    historical_events = AuditLog.query.filter(
                        AuditLog.user_id == user_id,
                        AuditLog.timestamp < start_time,
                        AuditLog.timestamp > start_time - timedelta(days=30)
                    ).all()

                    for event in historical_events:
                        if event.ip_address:
                            historical_ips.add(event.ip_address)

                    # Find new IPs
                    new_ips = ip_set - historical_ips
                    if new_ips and historical_ips:
                        user = User.query.get(user_id) if User else None
                        username = user.username if user else f"User #{user_id}"

                        anomalies.append({
                            "type": "new_login_location",
                            "user_id": user_id,
                            "username": username,
                            "new_ips": list(new_ips),
                            "historical_ips": list(historical_ips),
                            "severity": "medium"
                        })

            # Check for unusual login times
            for user_id, timestamps in user_logins.items():
                if len(timestamps) < 3:
                    continue

                # Analyze hour distribution
                hour_counts = [0] * 24
                for ts in timestamps:
                    hour_counts[ts.hour] += 1

                # Check for unusual hours
                avg_count = sum(hour_counts) / 24
                unusual_hours = []

                for hour, count in enumerate(hour_counts):
                    if count > 0 and avg_count > 0:
                        if hour < 6 or hour > 22:  # Late night/early morning (adjust based on business hours)
                            unusual_hours.append(hour)

                if unusual_hours:
                    user = User.query.get(user_id) if User else None
                    username = user.username if user else f"User #{user_id}"

                    anomalies.append({
                        "type": "unusual_login_time",
                        "user_id": user_id,
                        "username": username,
                        "unusual_hours": unusual_hours,
                        "severity": "low"
                    })

            return anomalies

        except Exception as e:
            logger.error(f"Failed to analyze login anomalies: {e}", exc_info=True)
            return []

    @staticmethod
    def generate_compliance_report(
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        compliance_type: str = "general"
    ) -> Dict[str, Any]:
        """
        Generate a compliance report based on audit logs.

        Args:
            start_time: Start of reporting period.
            end_time: End of reporting period.
            compliance_type: Type of compliance report (general, security, access, etc.).

        Returns:
            A dictionary with the compliance report data.
        """
        if not start_time:
            # Default to last 30 days
            start_time = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        if not CORE_AVAILABLE or not AuditLog or not has_app_context():
            logger.error("Cannot generate compliance report: Core components or application context not available.")
            return {
                "error": "Service unavailable",
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat()
            }

        try:
            report = {
                "title": f"{compliance_type.capitalize()} Compliance Report",
                "period_start": start_time.isoformat(),
                "period_end": end_time.isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "compliance_type": compliance_type
            }

            # Get event counts by action type
            action_counts = {}
            actions = db.session.query(
                AuditLog.action, db.func.count(AuditLog.id)
            ).filter(
                AuditLog.timestamp.between(start_time, end_time)
            ).group_by(AuditLog.action).all()

            for action, count in actions:
                action_counts[action] = count

            report["action_counts"] = action_counts

            # Get failure analysis
            failures = AuditLog.query.filter(
                AuditLog.status == "failure",
                AuditLog.timestamp.between(start_time, end_time)
            ).all()

            failure_analysis = {
                "total_count": len(failures),
                "by_action": {},
                "by_severity": {}
            }

            for failure in failures:
                # Count by action
                if failure.action not in failure_analysis["by_action"]:
                    failure_analysis["by_action"][failure.action] = 0
                failure_analysis["by_action"][failure.action] += 1

                # Count by severity
                if failure.severity not in failure_analysis["by_severity"]:
                    failure_analysis["by_severity"][failure.severity] = 0
                failure_analysis["by_severity"][failure.severity] += 1

            report["failure_analysis"] = failure_analysis

            # Get user activity summary
            user_activity = {}
            users = db.session.query(
                AuditLog.user_id, db.func.count(AuditLog.id)
            ).filter(
                AuditLog.user_id.isnot(None),
                AuditLog.timestamp.between(start_time, end_time)
            ).group_by(AuditLog.user_id).all()

            for user_id, count in users:
                if User:
                    user = User.query.get(user_id)
                    username = user.username if user else f"User #{user_id}"
                else:
                    username = f"User #{user_id}"

                user_activity[username] = count

            report["user_activity"] = user_activity

            # Add compliance-specific sections
            if compliance_type == "security":
                # Add security-focused metrics
                security_events = AuditLog.query.filter(
                    AuditLog.action.like("security.%"),
                    AuditLog.timestamp.between(start_time, end_time)
                ).all()

                report["security_events"] = {
                    "total": len(security_events),
                    "by_severity": {
                        "critical": sum(1 for e in security_events if e.severity == "critical"),
                        "error": sum(1 for e in security_events if e.severity == "error"),
                        "warning": sum(1 for e in security_events if e.severity == "warning"),
                        "info": sum(1 for e in security_events if e.severity == "info")
                    }
                }

            elif compliance_type == "access":
                # Add access control metrics
                access_events = AuditLog.query.filter(
                    db.or_(
                        AuditLog.action.like("access.%"),
                        AuditLog.action == "user.login"
                    ),
                    AuditLog.timestamp.between(start_time, end_time)
                ).all()

                report["access_events"] = {
                    "total": len(access_events),
                    "denied_access": sum(1 for e in access_events if e.action == "access.denied"),
                    "successful_logins": sum(1 for e in access_events if e.action == "user.login" and e.status == "success"),
                    "failed_logins": sum(1 for e in access_events if e.action == "user.login" and e.status == "failure")
                }

            # Log this report generation for audit trail
            AuditService.log_event(
                user_id=getattr(getattr(current_app, 'auth', None), 'current_user_id', None),
                action="audit.report.generated",
                target_resource="compliance_report",
                target_id=compliance_type,
                details={
                    "report_type": compliance_type,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat()
                }
            )

            return report

        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}", exc_info=True)
            return {
                "error": "Failed to generate compliance report",
                "reason": str(e),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat()
            }

    @staticmethod
    def purge_old_logs(retention_days: int = 365, dry_run: bool = True) -> Dict[str, Any]:
        """
        Purge audit logs older than the specified retention period.

        Args:
            retention_days: Number of days to retain logs.
            dry_run: If True, only report what would be deleted without actually deleting.

        Returns:
            A dictionary with operation results and statistics.
        """
        if not CORE_AVAILABLE or not AuditLog or not has_app_context() or not db:
            logger.error("Cannot purge old logs: Core components or application context not available.")
            return {"error": "Service unavailable"}

        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

            # Count logs that would be deleted
            logs_to_delete = AuditLog.query.filter(AuditLog.timestamp < cutoff_date).count()

            result = {
                "retention_days": retention_days,
                "cutoff_date": cutoff_date.isoformat(),
                "logs_to_delete": logs_to_delete,
                "dry_run": dry_run
            }

            if logs_to_delete == 0:
                result["message"] = "No logs found to delete."
                return result

            if not dry_run:
                # Actually delete the logs
                AuditLog.query.filter(AuditLog.timestamp < cutoff_date).delete(synchronize_session=False)
                db.session.commit()
                result["message"] = f"Successfully purged {logs_to_delete} logs older than {retention_days} days."

                # Log this purge operation
                AuditService.log_event(
                    user_id=getattr(getattr(current_app, 'auth', None), 'current_user_id', None),
                    action="audit.logs.purged",
                    severity="warning",
                    details={
                        "retention_days": retention_days,
                        "cutoff_date": cutoff_date.isoformat(),
                        "logs_deleted": logs_to_delete
                    }
                )
            else:
                result["message"] = f"Would purge {logs_to_delete} logs older than {retention_days} days (dry run)."

            return result

        except Exception as e:
            logger.error(f"Failed to purge old logs: {e}", exc_info=True)
            return {
                "error": "Failed to purge old logs",
                "reason": str(e)
            }
