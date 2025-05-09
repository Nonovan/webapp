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
    from models import User
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

# Check for availability of security-related components
try:
    from services import SECURITY_SERVICE_AVAILABLE, SCANNING_SERVICE_AVAILABLE
    from services import (
        check_integrity,
        update_security_baseline,
        verify_baseline_consistency
    )
    SECURITY_INTEGRATION_AVAILABLE = True
except ImportError:
    SECURITY_INTEGRATION_AVAILABLE = False
    SECURITY_SERVICE_AVAILABLE = False
    SCANNING_SERVICE_AVAILABLE = False

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

    # Security specific event types
    EVENT_FILE_INTEGRITY_CHECK = "security.file_integrity.check"
    EVENT_FILE_INTEGRITY_VIOLATION = "security.file_integrity.violation"
    EVENT_BASELINE_UPDATE = "security.baseline.update"
    EVENT_SECURITY_SCAN_START = "security.scan.start"
    EVENT_SECURITY_SCAN_COMPLETE = "security.scan.complete"
    EVENT_SECURITY_SCAN_FINDING = "security.scan.finding"
    EVENT_SECURITY_CONFIG_CHANGE = "security.config.change"

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

        # Add source for system-generated events
        if user_id is None and not details.get('source'):
            details['source'] = 'system'
            # Detect component source if possible
            if action.startswith('security.'):
                details['component'] = 'security'
            elif action.startswith('user.'):
                details['component'] = 'auth'
            elif action.startswith('audit.'):
                details['component'] = 'audit'
            elif action.startswith('file.'):
                details['component'] = 'filesystem'
            elif action.startswith('api.'):
                details['component'] = 'api'
            elif action.startswith('scan.'):
                details['component'] = 'scanner'

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
    def get_security_events(
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        severity: Optional[str] = None,
        type_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get security-specific events from the audit log.

        Args:
            start_time: Start time for filtering events
            end_time: End time for filtering events
            limit: Maximum number of events to return
            severity: Filter by severity level
            type_filter: Filter by security event type (file_integrity, scan, etc.)

        Returns:
            List of security events as dictionaries
        """
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(days=7)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        # Build the query filter
        action_filter = "security.%"
        if type_filter:
            if type_filter == "file_integrity":
                action_filter = "security.file_integrity.%"
            elif type_filter == "scan":
                action_filter = "security.scan.%"
            elif type_filter == "baseline":
                action_filter = "security.baseline.%"
            elif type_filter == "alert":
                action_filter = "security.alert.%"

        # Get the logs
        logs, _ = AuditService.get_logs(
            limit=limit,
            action=action_filter,
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            order_by="timestamp",
            order_direction="desc"
        )

        return logs

    @staticmethod
    def get_file_integrity_events(
        days: int = 7,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get file integrity monitoring events.

        Args:
            days: Number of days to look back
            status: Optional status filter ('success', 'failure')

        Returns:
            List of file integrity events
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        logs, _ = AuditService.get_logs(
            action="security.file_integrity.%",
            start_time=start_time,
            end_time=end_time,
            status=status,
            order_by="timestamp",
            order_direction="desc"
        )

        return logs

    @staticmethod
    def get_scanning_events(
        days: int = 7,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get security scanning events.

        Args:
            days: Number of days to look back
            status: Optional status filter ('success', 'failure')

        Returns:
            List of security scanning events
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        logs, _ = AuditService.get_logs(
            action="security.scan.%",
            start_time=start_time,
            end_time=end_time,
            status=status,
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

            # Get file integrity-specific metrics
            file_integrity_check_count = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_FILE_INTEGRITY_CHECK,
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["file_integrity_check_count"] = file_integrity_check_count

            file_integrity_violation_count = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_FILE_INTEGRITY_VIOLATION,
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["file_integrity_violation_count"] = file_integrity_violation_count

            # Get scanning metrics
            scan_count = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_SECURITY_SCAN_START,
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["security_scan_count"] = scan_count

            scan_finding_count = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_SECURITY_SCAN_FINDING,
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["security_scan_finding_count"] = scan_finding_count

            # Get baseline update metrics
            baseline_update_count = AuditLog.query.filter(
                AuditLog.action == AuditService.EVENT_BASELINE_UPDATE,
                AuditLog.timestamp.between(start_time, end_time)
            ).count()
            metrics["baseline_update_count"] = baseline_update_count

            # Add security service and scanning service availability
            if SECURITY_INTEGRATION_AVAILABLE:
                metrics["security_service_available"] = SECURITY_SERVICE_AVAILABLE
                metrics["scanning_service_available"] = SCANNING_SERVICE_AVAILABLE

                # If SecurityService is available, get more metrics
                if SECURITY_SERVICE_AVAILABLE:
                    try:
                        from services import get_integrity_status
                        integrity_status = get_integrity_status()
                        metrics["file_integrity_monitoring"] = {
                            "enabled": integrity_status.get("monitoring_enabled", False),
                            "baseline_status": integrity_status.get("baseline_status", "unknown"),
                            "file_count": integrity_status.get("file_count", 0),
                            "changes_detected": integrity_status.get("changes_detected", 0)
                        }
                    except Exception as e:
                        logger.warning(f"Could not get integrity status: {e}")
                        metrics["file_integrity_monitoring"] = {"error": "Failed to get status"}

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
    def generate_security_compliance_report(
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Generate a security compliance report focusing on file integrity, scanning, and other security events.

        Args:
            start_time: Start of reporting period
            end_time: End of reporting period

        Returns:
            Dictionary with security compliance report data
        """
        # Get general compliance report first
        report = AuditService.generate_compliance_report(
            start_time=start_time,
            end_time=end_time,
            compliance_type="security"
        )

        # Early return on error
        if "error" in report:
            return report

        if SECURITY_INTEGRATION_AVAILABLE:
            # Add file integrity metrics
            file_integrity_events = AuditService.get_file_integrity_events(
                days=(end_time - start_time).days if start_time and end_time else 30
            )

            file_integrity_metrics = {
                "total_events": len(file_integrity_events),
                "checks_performed": sum(1 for e in file_integrity_events if e.get('action') == AuditService.EVENT_FILE_INTEGRITY_CHECK),
                "violations_detected": sum(1 for e in file_integrity_events if e.get('action') == AuditService.EVENT_FILE_INTEGRITY_VIOLATION),
                "baseline_updates": sum(1 for e in file_integrity_events if e.get('action') == AuditService.EVENT_BASELINE_UPDATE),
            }

            report["file_integrity"] = file_integrity_metrics

            # Add scanning metrics
            scan_events = AuditService.get_scanning_events(
                days=(end_time - start_time).days if start_time and end_time else 30
            )

            scan_metrics = {
                "total_events": len(scan_events),
                "scans_started": sum(1 for e in scan_events if e.get('action') == AuditService.EVENT_SECURITY_SCAN_START),
                "scans_completed": sum(1 for e in scan_events if e.get('action') == AuditService.EVENT_SECURITY_SCAN_COMPLETE),
                "findings_detected": sum(1 for e in scan_events if e.get('action') == AuditService.EVENT_SECURITY_SCAN_FINDING),
            }

            report["security_scans"] = scan_metrics

            # Get baseline consistency status if available
            if SECURITY_SERVICE_AVAILABLE:
                try:
                    # Get baseline consistency status
                    is_consistent, details = verify_baseline_consistency()
                    report["baseline_consistency"] = {
                        "is_consistent": is_consistent,
                        "file_count": details.get("file_count", 0),
                        "last_modified": details.get("last_modified"),
                        "has_metadata": details.get("has_metadata", False),
                        "errors": details.get("errors", [])
                    }
                except Exception as e:
                    logger.warning(f"Could not verify baseline consistency: {e}")

        return report

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
            # If this is a security compliance report and we have security integration,
            # use the specialized function instead
            if compliance_type == "security" and SECURITY_INTEGRATION_AVAILABLE and SECURITY_SERVICE_AVAILABLE:
                return AuditService.generate_security_compliance_report(start_time, end_time)

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

    @staticmethod
    def log_file_integrity_event(
        status: str,
        action: str,
        changes: Optional[List[Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        severity: str = "info"
    ) -> bool:
        """
        Log a file integrity event to the audit trail.

        Args:
            status: 'success', 'failure', or 'violation'
            action: The specific action ('check', 'violation', 'update')
            changes: Optional list of file changes
            details: Optional additional details
            user_id: User ID if action was initiated by a user, else None for system
            severity: Event severity ('info', 'warning', 'error', 'critical')

        Returns:
            True if logging succeeded, False otherwise
        """
        # Determine appropriate action string
        event_type = AuditService.EVENT_FILE_INTEGRITY_CHECK
        if action == 'violation':
            event_type = AuditService.EVENT_FILE_INTEGRITY_VIOLATION
            if severity == 'info':
                severity = 'warning'  # Violations should be at least warning level
        elif action == 'update':
            event_type = AuditService.EVENT_BASELINE_UPDATE

        # Create event details
        event_details = details or {}
        if changes:
            # Only include first 5 changes to avoid excessive log size
            event_details['changes_summary'] = changes[:5]
            event_details['changes_count'] = len(changes)

            # Check for critical changes
            critical_changes = [c for c in changes if c.get('severity') == 'critical']
            if critical_changes:
                event_details['critical_changes'] = len(critical_changes)
                # Critical changes should elevate the event severity
                if severity in ('info', 'warning'):
                    severity = 'error'

        # Log the event
        return AuditService.log_event(
            user_id=user_id,
            action=event_type,
            target_resource='file_integrity',
            status=status,
            details=event_details,
            severity=severity
        )

    @staticmethod
    def log_security_scan_event(
        scan_id: str,
        action: str,
        scan_type: str,
        status: str = 'success',
        findings: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
        severity: str = 'info'
    ) -> bool:
        """
        Log a security scanning event to the audit trail.

        Args:
            scan_id: ID of the scan
            action: Specific action ('start', 'complete', 'finding')
            scan_type: Type of scan performed
            status: Operation status ('success', 'failure')
            findings: Optional scan findings
            user_id: User ID if initiated by a user, else None
            severity: Event severity level

        Returns:
            True if logging succeeded, False otherwise
        """
        # Determine appropriate event type
        event_type = AuditService.EVENT_SECURITY_SCAN_START
        if action == 'complete':
            event_type = AuditService.EVENT_SECURITY_SCAN_COMPLETE
        elif action == 'finding':
            event_type = AuditService.EVENT_SECURITY_SCAN_FINDING
            # Findings should have higher severity
            if severity == 'info':
                severity = 'warning'

        # Create event details
        details = {
            'scan_id': scan_id,
            'scan_type': scan_type
        }

        # Add findings information if available
        if findings:
            # Include finding counts by severity
            if isinstance(findings, dict):
                details['findings'] = findings
            else:
                details['findings_count'] = len(findings)

            # Check for critical findings
            if isinstance(findings, dict) and findings.get('critical', 0) > 0:
                # Critical findings should elevate severity
                if severity in ('info', 'warning'):
                    severity = 'error'

        # Log the event
        return AuditService.log_event(
            user_id=user_id,
            action=event_type,
            target_resource='security_scan',
            target_id=scan_id,
            status=status,
            details=details,
            severity=severity
        )


# Add custom audit integration for file integrity and scanning
if SECURITY_INTEGRATION_AVAILABLE:
    from functools import wraps

    def audit_integrity_check(func):
        """
        Decorator to audit file integrity checks.

        Usage:
            @audit_integrity_check
            def check_integrity(paths):
                # Normal integrity check code
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Capture start time
            start_time = datetime.now(timezone.utc)

            # Call the original function
            try:
                result = func(*args, **kwargs)
                integrity_status, changes = result

                # Log the event
                AuditService.log_file_integrity_event(
                    status='success' if integrity_status else 'violation',
                    action='check' if integrity_status else 'violation',
                    changes=changes if not integrity_status else None,
                    details={
                        'timestamp': start_time.isoformat(),
                        'duration_ms': (datetime.now(timezone.utc) - start_time).total_seconds() * 1000,
                        'files_checked': len(changes) if changes else 0
                    },
                    severity='info' if integrity_status else 'warning'
                )
                return result
            except Exception as e:
                # Log failure
                AuditService.log_file_integrity_event(
                    status='failure',
                    action='check',
                    details={
                        'timestamp': start_time.isoformat(),
                        'error': str(e)
                    },
                    severity='error'
                )
                raise
        return wrapper


def audit_action(
    action: str,
    description: str,
    user_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: str = "info"
) -> bool:
    """
    Log an administrative action to the audit trail.

    This function serves as a convenience wrapper around AuditService.log_event,
    specifically designed for administrative actions.

    Args:
        action: The action type/name to log (e.g., 'user_created', 'config_updated')
        description: Human-readable description of the action
        user_id: ID of the user performing the action
        target_user_id: ID of the user affected by the action (if applicable)
        details: A dictionary containing additional context about the action
        severity: The severity level of the action ('info', 'warning', 'error', 'critical')

    Returns:
        bool: True if the action was logged successfully, False otherwise
    """
    # Ensure details is a dictionary
    if details is None:
        details = {}

    # Add target_user_id to details if provided
    if target_user_id is not None:
        details['target_user_id'] = target_user_id

    # Determine target_resource and target_id based on action
    target_resource = None
    target_id = None

    # Extract resource type from action if possible
    if '_' in action:
        parts = action.split('_', 1)
        if len(parts) > 1:
            resource_type = parts[0]
            if resource_type in ['user', 'role', 'permission', 'config', 'file']:
                target_resource = resource_type
                # If target_user_id is provided and resource is user, use it as target_id
                if target_resource == 'user' and target_user_id is not None:
                    target_id = str(target_user_id)

    # Log the event using AuditService
    return AuditService.log_event(
        user_id=user_id,
        action=f"admin.{action}",
        target_resource=target_resource,
        target_id=target_id,
        status="success",
        details=details,
        severity=severity
    )

def export_audit_data(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_types: Optional[List[str]] = None,
    user_id: Optional[int] = None,
    severity: Optional[str] = None,
    format_type: str = 'csv',
    max_records: int = 10000
) -> Tuple[bool, str, Optional[str]]:
    """
    Export audit log data to a specified format.

    Args:
        start_time: Start date/time for filtering logs
        end_time: End date/time for filtering logs
        event_types: List of event types to include
        user_id: Filter by specific user ID
        severity: Filter by severity level
        format_type: Export format ('csv', 'json')
        max_records: Maximum number of records to export

    Returns:
        Tuple containing:
        - Success flag (bool)
        - Message describing the result
        - Path to the generated file (if successful)
    """
    import os
    import csv
    import json
    import tempfile
    from datetime import datetime, timezone

    try:
        # Build query based on filters
        query = None

        if hasattr(AuditService, 'get_logs'):
            # If get_logs method exists, use it
            logs, total_count = AuditService.get_logs(
                limit=max_records,
                user_id=user_id,
                action=event_types[0] if event_types and len(event_types) == 1 else None,
                start_time=start_time,
                end_time=end_time,
                severity=severity,
                order_by="timestamp",
                order_direction="desc"
            )

            if total_count == 0:
                return False, "No audit logs found matching the criteria", None
        else:
            # Fallback to direct model query if we don't have access to get_logs
            logger.error("AuditService.get_logs method not available")
            return False, "Export functionality unavailable", None

        # Create temporary directory if it doesn't exist
        temp_dir = tempfile.gettempdir()
        export_dir = os.path.join(temp_dir, 'audit_exports')
        os.makedirs(export_dir, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"audit_export_{timestamp}.{format_type}"
        filepath = os.path.join(export_dir, filename)

        # Export in the requested format
        if format_type == 'csv':
            with open(filepath, 'w', newline='') as f:
                # Define CSV fields based on log structure
                fieldnames = ['timestamp', 'action', 'user_id', 'status', 'severity',
                              'target_resource', 'target_id', 'ip_address']

                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for log in logs:
                    # Convert log to dict if it's not already
                    if not isinstance(log, dict):
                        if hasattr(log, 'to_dict'):
                            log = log.to_dict()
                        else:
                            # Skip if we can't convert
                            continue

                    # Write the log as a row
                    row = {
                        'timestamp': log.get('timestamp', ''),
                        'action': log.get('action', ''),
                        'user_id': log.get('user_id', ''),
                        'status': log.get('status', ''),
                        'severity': log.get('severity', ''),
                        'target_resource': log.get('target_resource', ''),
                        'target_id': log.get('target_id', ''),
                        'ip_address': log.get('ip_address', '')
                    }
                    writer.writerow(row)

        elif format_type == 'json':
            # For JSON format, we export the entire log objects
            export_data = {
                'metadata': {
                    'exported_at': datetime.now(timezone.utc).isoformat(),
                    'record_count': len(logs),
                    'filters': {
                        'start_time': start_time.isoformat() if start_time else None,
                        'end_time': end_time.isoformat() if end_time else None,
                        'event_types': event_types,
                        'user_id': user_id,
                        'severity': severity
                    }
                },
                'logs': logs
            }

            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        else:
            return False, f"Unsupported export format: {format_type}", None

        # Log the export action
        AuditService.log_event(
            user_id=user_id,
            action="audit.logs.exported",
            target_resource="audit_logs",
            status="success",
            details={
                'format': format_type,
                'record_count': len(logs),
                'filters': {
                    'start_time': start_time.isoformat() if start_time else None,
                    'end_time': end_time.isoformat() if end_time else None,
                    'event_types': event_types,
                    'user_id': user_id,
                    'severity': severity
                }
            },
            severity="info"
        )

        return True, f"Successfully exported {len(logs)} audit logs", filepath

    except Exception as e:
        logger.error(f"Error exporting audit data: {str(e)}", exc_info=True)
        return False, f"Error exporting audit data: {str(e)}", None
