"""
Administrative Audit Logging Utilities.

This module provides specialized audit logging functionality for administrative
tools and scripts, ensuring comprehensive logging of all administrative actions
for security, compliance, and troubleshooting purposes. It integrates with the
core audit logging infrastructure while providing admin-specific formatting,
categorization, and convenience functions.
"""

import json
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Try to import core logging
try:
    from core.loggings import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback basic logger if core logging is unavailable
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.warning("Core logging module not found, using basic logging.")

# Try to import core security audit functionality
try:
    from core.security.cs_audit import (
        log_security_event,
        get_audit_logs as core_get_audit_logs,
        AuditLog
    )
    CORE_AUDIT_AVAILABLE = True
except ImportError:
    logger.warning("Core audit logging not available, using basic audit logging.")
    CORE_AUDIT_AVAILABLE = False
    AuditLog = None

# Constants for admin audit logging
ADMIN_ACTION_CATEGORY = "admin"
ADMIN_EVENT_PREFIX = "admin."

# Severity levels
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"

# Common admin action types
ACTION_USER_CREATE = "user.create"
ACTION_USER_UPDATE = "user.update"
ACTION_USER_DELETE = "user.delete"
ACTION_ROLE_ASSIGN = "role.assign"
ACTION_ROLE_REVOKE = "role.revoke"
ACTION_PERMISSION_GRANT = "permission.grant"
ACTION_PERMISSION_REVOKE = "permission.revoke"
ACTION_CONFIG_CHANGE = "config.change"
ACTION_SYSTEM_CHANGE = "system.change"
ACTION_SECURITY_CHANGE = "security.change"
ACTION_EMERGENCY_ACCESS = "emergency.access"
ACTION_EMERGENCY_DEACTIVATE = "emergency.deactivate"
ACTION_DATA_EXPORT = "data.export"
ACTION_AUDIT_ACCESS = "audit.access"
ACTION_API_KEY_CREATE = "api_key.create"
ACTION_API_KEY_REVOKE = "api_key.revoke"

# Common admin action statuses
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_ATTEMPTED = "attempted"
STATUS_CANCELLED = "cancelled"


def log_admin_action(
    action: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    status: str = STATUS_SUCCESS,
    severity: str = SEVERITY_INFO,
    related_resource_id: Optional[str] = None,
    related_resource_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    session_id: Optional[str] = None
) -> bool:
    """
    Logs an administrative action for audit purposes.

    Creates a comprehensive audit log entry for an administrative action,
    ensuring proper categorization and attribution. Takes care of integrating
    with the core audit logging system when available.

    Args:
        action: The specific admin action being performed (e.g., "user.create")
        details: Dictionary containing additional details about the action
        user_id: ID of the user performing the action
        username: Username of the user performing the action (as alternative to user_id)
        status: Outcome of the action (success, failure, etc.)
        severity: Importance level of the action (info, warning, error, critical)
        related_resource_id: ID of the resource being acted upon
        related_resource_type: Type of resource being acted upon
        source_ip: IP address where the action originated
        session_id: Session identifier for the admin session

    Returns:
        True if log entry was successfully created, False otherwise
    """
    if not action:
        logger.error("Cannot log admin action with empty action type")
        return False

    # Normalize details dictionary
    if details is None:
        details = {}

    # Add the basic event information
    log_details = {
        "action": action,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        **details
    }

    # Add source information if available
    if source_ip:
        log_details["source_ip"] = source_ip

    # Add session information if available
    if session_id:
        log_details["session_id"] = session_id

    # Determine user information to include
    if user_id:
        log_details["user_id"] = user_id
    if username:
        log_details["username"] = username

    # Add resource information if available
    if related_resource_type:
        log_details["resource_type"] = related_resource_type
    if related_resource_id:
        log_details["resource_id"] = related_resource_id

    # Construct a descriptive message
    message = f"Admin action: {action}"
    if status != STATUS_SUCCESS:
        message += f" ({status})"

    # Prefix with appropriate admin namespace if not already present
    if not action.startswith(ADMIN_EVENT_PREFIX):
        event_type = f"{ADMIN_EVENT_PREFIX}{action}"
    else:
        event_type = action

    # Use core audit logging if available
    if CORE_AUDIT_AVAILABLE:
        try:
            log_security_event(
                event_type=event_type,
                description=message,
                severity=severity,
                user_id=user_id,
                details=log_details,
                category=ADMIN_ACTION_CATEGORY,
                object_type=related_resource_type,
                object_id=related_resource_id
            )
            return True
        except Exception as e:
            logger.error(f"Failed to log admin action using core audit logging: {e}")
            # Fall through to basic logging as backup

    # Basic logging as fallback
    try:
        # Convert log level string to logging level
        log_level = {
            SEVERITY_INFO: logging.INFO,
            SEVERITY_WARNING: logging.WARNING,
            SEVERITY_ERROR: logging.ERROR,
            SEVERITY_CRITICAL: logging.CRITICAL
        }.get(severity.lower(), logging.INFO)

        # Format the log message
        log_message = f"{message} | Details: {json.dumps(log_details)}"
        logger.log(log_level, log_message)

        # Also write to audit log file if configured
        audit_log_file = os.environ.get("ADMIN_AUDIT_LOG_FILE")
        if audit_log_file:
            try:
                with open(audit_log_file, 'a') as f:
                    log_entry = f"[{datetime.now(timezone.utc).isoformat()}] {severity.upper()}: {log_message}\n"
                    f.write(log_entry)
            except Exception as file_err:
                logger.error(f"Failed to write to audit log file: {file_err}")

        return True
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")
        return False


def get_admin_audit_logs(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    action_types: Optional[List[str]] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Retrieves administrative audit logs based on filtering criteria.

    Args:
        start_time: Start time for log filtering
        end_time: End time for log filtering
        user_id: Filter by specific user ID
        username: Filter by specific username
        action_types: List of action types to include
        severity: Filter by severity level
        status: Filter by action status
        resource_type: Filter by resource type
        resource_id: Filter by resource ID
        limit: Maximum number of logs to return
        offset: Number of logs to skip for pagination

    Returns:
        List of audit log entries as dictionaries
    """
    # Default to last 24 hours if no time range specified
    if start_time is None:
        start_time = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    if end_time is None:
        end_time = datetime.now(timezone.utc)

    # Helper function to filter by admin category/prefix
    def is_admin_log(log_entry):
        if isinstance(log_entry, dict):
            event_type = log_entry.get('event_type', '')
            category = log_entry.get('category', '')
        else:
            # Assume AuditLog model
            event_type = getattr(log_entry, 'event_type', '')
            category = getattr(log_entry, 'category', '')

        return (category == ADMIN_ACTION_CATEGORY or
                event_type.startswith(ADMIN_EVENT_PREFIX))

    # Use core audit logging if available
    if CORE_AUDIT_AVAILABLE and AuditLog is not None:
        try:
            # Create filters for core audit logs
            filters = {
                'start_time': start_time,
                'end_time': end_time,
                'limit': limit,
                'offset': offset
            }

            # Add optional filters
            if user_id:
                filters['user_id'] = user_id
            if severity:
                filters['severity'] = severity
            if resource_type:
                filters['object_type'] = resource_type
            if resource_id:
                filters['object_id'] = resource_id

            # Filter by event types if specified
            if action_types:
                # Add admin prefix if not already present
                prefixed_actions = []
                for action in action_types:
                    if not action.startswith(ADMIN_EVENT_PREFIX):
                        prefixed_actions.append(f"{ADMIN_EVENT_PREFIX}{action}")
                    else:
                        prefixed_actions.append(action)
                filters['event_types'] = prefixed_actions
            else:
                # Only get admin logs
                filters['category'] = ADMIN_ACTION_CATEGORY

            # Get logs from core system
            logs = core_get_audit_logs(**filters)

            # Filter further by status and username if needed since these might
            # be in the details field that core audit might not filter on
            filtered_logs = []
            for log in logs:
                log_dict = log.to_dict() if hasattr(log, 'to_dict') else log

                # Check if it's an admin log
                if not is_admin_log(log_dict):
                    continue

                # Apply status filter if specified
                if status and log_dict.get('details', {}).get('status') != status:
                    continue

                # Apply username filter if specified
                if username:
                    log_username = log_dict.get('details', {}).get('username')
                    if log_username != username:
                        continue

                filtered_logs.append(log_dict)

            return filtered_logs

        except Exception as e:
            logger.error(f"Failed to retrieve admin audit logs from core: {e}")
            # Fall through to basic retrieval

    # Basic retrieval from files as fallback
    logs = []
    audit_log_file = os.environ.get("ADMIN_AUDIT_LOG_FILE")

    if not audit_log_file or not os.path.exists(audit_log_file):
        logger.error(f"Audit log file not found: {audit_log_file}")
        return []

    try:
        with open(audit_log_file, 'r') as f:
            for line in f:
                try:
                    # Parse log line
                    parts = line.strip().split(' ', 3)
                    if len(parts) < 4:
                        continue

                    timestamp_str, level, message = parts[0][1:-1], parts[1][:-1], parts[3]

                    # Extract details JSON
                    details_start = message.find("Details: ")
                    if details_start == -1:
                        continue

                    details_json = message[details_start + 9:]
                    details = json.loads(details_json)

                    # Convert timestamp
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                    except ValueError:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                        timestamp = timestamp.replace(tzinfo=timezone.utc)

                    # Apply time filters
                    if timestamp < start_time or timestamp > end_time:
                        continue

                    # Create log entry
                    log_entry = {
                        'timestamp': timestamp.isoformat(),
                        'severity': level.lower(),
                        'event_type': details.get('action', ''),
                        'details': details,
                        'user_id': details.get('user_id'),
                        'username': details.get('username'),
                        'resource_type': details.get('resource_type'),
                        'resource_id': details.get('resource_id'),
                        'status': details.get('status')
                    }

                    # Apply filters
                    if user_id and log_entry['user_id'] != user_id:
                        continue

                    if username and log_entry['username'] != username:
                        continue

                    if action_types and log_entry['event_type'] not in action_types:
                        # Try with admin prefix
                        prefixed = f"{ADMIN_EVENT_PREFIX}{log_entry['event_type']}"
                        if prefixed not in action_types:
                            continue

                    if severity and log_entry['severity'] != severity:
                        continue

                    if status and log_entry['status'] != status:
                        continue

                    if resource_type and log_entry['resource_type'] != resource_type:
                        continue

                    if resource_id and log_entry['resource_id'] != resource_id:
                        continue

                    logs.append(log_entry)

                    # Apply limit and offset
                    if len(logs) >= limit + offset:
                        break

                except Exception as parse_error:
                    logger.debug(f"Could not parse log line: {parse_error}")
                    continue

        # Apply offset
        logs = logs[offset:offset + limit]
        return logs

    except Exception as e:
        logger.error(f"Failed to retrieve admin audit logs from file: {e}")
        return []


def export_admin_audit_logs(
    start_time: datetime,
    end_time: datetime,
    output_format: str = 'json',
    output_file: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None
) -> Union[str, bool]:
    """
    Exports administrative audit logs to a file or returns them as a string.

    Args:
        start_time: Start time for logs to export
        end_time: End time for logs to export
        output_format: Format for export ('json', 'csv', or 'text')
        output_file: File path to write output to (if None, returns as string)
        filters: Additional filters to apply (user_id, action_types, etc.)

    Returns:
        If output_file is specified, returns True on success or False on failure
        If output_file is None, returns the formatted logs as a string
    """
    if filters is None:
        filters = {}

    # Get logs with filters
    logs = get_admin_audit_logs(
        start_time=start_time,
        end_time=end_time,
        user_id=filters.get('user_id'),
        username=filters.get('username'),
        action_types=filters.get('action_types'),
        severity=filters.get('severity'),
        status=filters.get('status'),
        resource_type=filters.get('resource_type'),
        resource_id=filters.get('resource_id'),
        limit=filters.get('limit', 10000),  # Higher limit for exports
        offset=filters.get('offset', 0)
    )

    if not logs:
        logger.warning("No logs found for export")
        return "" if output_file is None else False

    # Format the logs
    if output_format == 'json':
        output = json.dumps(logs, indent=2, default=str)
    elif output_format == 'csv':
        import csv
        import io

        # Determine fields for CSV
        fields = set()
        for log in logs:
            fields.update(log.keys())
            if 'details' in log and isinstance(log['details'], dict):
                fields.update(f"details.{k}" for k in log['details'].keys())

        fields = sorted(fields)

        # Create CSV
        output_io = io.StringIO()
        writer = csv.writer(output_io)

        # Write header
        writer.writerow(fields)

        # Write data
        for log in logs:
            row = []
            for field in fields:
                if '.' in field and field.startswith('details.'):
                    # Handle nested fields
                    nested_key = field.split('.', 1)[1]
                    value = log.get('details', {}).get(nested_key, '')
                else:
                    value = log.get(field, '')

                # Convert non-string values
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)

                row.append(value)

            writer.writerow(row)

        output = output_io.getvalue()

    elif output_format == 'text':
        lines = []
        for log in logs:
            timestamp = log.get('timestamp', '')
            event_type = log.get('event_type', '')
            severity = log.get('severity', '').upper()
            user = log.get('username', log.get('user_id', 'unknown'))
            status = log.get('status', '')

            details = log.get('details', {})
            resource_info = ''
            if 'resource_type' in log and 'resource_id' in log:
                resource_info = f"{log['resource_type']}:{log['resource_id']}"
            elif 'resource_type' in details and 'resource_id' in details:
                resource_info = f"{details['resource_type']}:{details['resource_id']}"

            line = f"[{timestamp}] {severity}: {event_type} by {user} - {status}"
            if resource_info:
                line += f" | Resource: {resource_info}"

            lines.append(line)

        output = '\n'.join(lines)
    else:
        logger.error(f"Unsupported output format: {output_format}")
        return False

    # Write to file or return as string
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output)

            logger.info(f"Exported {len(logs)} admin audit logs to {output_file}")

            # Log this export for audit purposes
            log_admin_action(
                action=ACTION_AUDIT_ACCESS,
                details={
                    "export_format": output_format,
                    "log_count": len(logs),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "filters": filters
                },
                status=STATUS_SUCCESS
            )

            return True
        except Exception as e:
            logger.error(f"Failed to write audit logs to file: {e}")

            # Log failed export attempt
            log_admin_action(
                action=ACTION_AUDIT_ACCESS,
                details={
                    "export_format": output_format,
                    "error": str(e),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "filters": filters
                },
                status=STATUS_FAILURE,
                severity=SEVERITY_ERROR
            )

            return False
    else:
        # Log this export for audit purposes
        log_admin_action(
            action=ACTION_AUDIT_ACCESS,
            details={
                "export_format": output_format,
                "log_count": len(logs),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "filters": filters,
                "exported_to": "memory"
            },
            status=STATUS_SUCCESS
        )

        return output


def detect_admin_anomalies(
    start_time: datetime,
    end_time: datetime,
    threshold: str = 'medium',
    output_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Detects anomalies in administrative actions.

    Identifies patterns that may indicate suspicious or unusual administrative
    behavior such as unusual timing, high frequencies of certain actions,
    rare actions, or actions from unusual sources.

    Args:
        start_time: Start of time period to analyze
        end_time: End of time period to analyze
        threshold: Sensitivity threshold ('low', 'medium', 'high')
        output_file: Optional file to write results to

    Returns:
        List of detected anomalies with details
    """
    # Get all admin logs for the period
    logs = get_admin_audit_logs(
        start_time=start_time,
        end_time=end_time,
        limit=10000  # Large limit to get comprehensive data for analysis
    )

    if not logs:
        logger.warning("No logs found for anomaly detection")
        return []

    # Set thresholds based on sensitivity
    thresholds = {
        'low': {
            'action_frequency': 30,  # Actions per hour by same user
            'failed_attempts': 5,    # Failed attempts in a row
            'time_window': 60,       # Seconds between related actions
            'unusual_hour_factor': 3 # Factor more actions than usual for the hour
        },
        'medium': {
            'action_frequency': 20,
            'failed_attempts': 3,
            'time_window': 120,
            'unusual_hour_factor': 2
        },
        'high': {
            'action_frequency': 10,
            'failed_attempts': 2,
            'time_window': 300,
            'unusual_hour_factor': 1.5
        }
    }

    # Use medium if invalid threshold provided
    if threshold not in thresholds:
        threshold = 'medium'

    current_thresholds = thresholds[threshold]
    anomalies = []

    # Group logs by user
    user_logs = {}
    for log in logs:
        user = log.get('username', log.get('user_id', 'unknown'))
        if user not in user_logs:
            user_logs[user] = []
        user_logs[user].append(log)

    # Check for anomalies

    # 1. High frequency of actions by a single user
    for user, user_log_entries in user_logs.items():
        # Group by hour
        hour_buckets = {}
        for log in user_log_entries:
            try:
                if isinstance(log.get('timestamp'), str):
                    timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                else:
                    timestamp = log['timestamp']

                hour_key = timestamp.strftime('%Y-%m-%d-%H')
                if hour_key not in hour_buckets:
                    hour_buckets[hour_key] = []

                hour_buckets[hour_key].append(log)
            except Exception:
                continue

        # Check each hour
        for hour, hour_logs in hour_buckets.items():
            if len(hour_logs) > current_thresholds['action_frequency']:
                anomalies.append({
                    'type': 'high_frequency',
                    'user': user,
                    'hour': hour,
                    'count': len(hour_logs),
                    'threshold': current_thresholds['action_frequency'],
                    'actions': [log.get('event_type') for log in hour_logs[:10]],
                    'severity': 'medium'
                })

    # 2. Multiple failed attempts
    for user, user_log_entries in user_logs.items():
        # Sort by timestamp
        sorted_logs = sorted(user_log_entries,
                            key=lambda x: x.get('timestamp', ''))

        # Check for sequences of failures
        failure_count = 0
        failure_sequence = []

        for log in sorted_logs:
            status = log.get('status', log.get('details', {}).get('status', ''))

            if status == STATUS_FAILURE:
                failure_count += 1
                failure_sequence.append(log)
            else:
                # Reset on success
                if failure_count >= current_thresholds['failed_attempts']:
                    anomalies.append({
                        'type': 'multiple_failures',
                        'user': user,
                        'count': failure_count,
                        'threshold': current_thresholds['failed_attempts'],
                        'actions': [log.get('event_type') for log in failure_sequence],
                        'timestamps': [log.get('timestamp') for log in failure_sequence],
                        'severity': 'high'
                    })

                failure_count = 0
                failure_sequence = []

        # Check remaining sequence at the end
        if failure_count >= current_thresholds['failed_attempts']:
            anomalies.append({
                'type': 'multiple_failures',
                'user': user,
                'count': failure_count,
                'threshold': current_thresholds['failed_attempts'],
                'actions': [log.get('event_type') for log in failure_sequence],
                'timestamps': [log.get('timestamp') for log in failure_sequence],
                'severity': 'high'
            })

    # 3. Unusual action timing (outside business hours, weekends)
    for log in logs:
        try:
            if isinstance(log.get('timestamp'), str):
                timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
            else:
                timestamp = log['timestamp']

            hour = timestamp.hour
            weekday = timestamp.weekday()  # 0-6, Monday-Sunday

            # Check for weekend activity (5=Sat, 6=Sun)
            is_weekend = weekday >= 5

            # Check for after-hours activity (before 7am or after 7pm)
            is_after_hours = hour < 7 or hour >= 19

            if is_weekend or is_after_hours:
                user = log.get('username', log.get('user_id', 'unknown'))
                event_type = log.get('event_type', '')

                if any(critical in event_type for critical in ['security', 'emergency', 'config']):
                    anomalies.append({
                        'type': 'unusual_timing',
                        'user': user,
                        'action': event_type,
                        'timestamp': log.get('timestamp'),
                        'is_weekend': is_weekend,
                        'is_after_hours': is_after_hours,
                        'severity': 'medium'
                    })
        except Exception:
            continue

    # 4. Unusual sequences (e.g., creation immediately followed by deletion)
    action_sequences = {}
    for log in logs:
        user = log.get('username', log.get('user_id', 'unknown'))
        resource_type = log.get('resource_type', log.get('details', {}).get('resource_type', ''))
        resource_id = log.get('resource_id', log.get('details', {}).get('resource_id', ''))

        if not resource_type or not resource_id:
            continue

        key = f"{resource_type}:{resource_id}"
        if key not in action_sequences:
            action_sequences[key] = []

        action_sequences[key].append({
            'timestamp': log.get('timestamp'),
            'user': user,
            'action': log.get('event_type', ''),
            'status': log.get('status', log.get('details', {}).get('status', ''))
        })

    # Look for create-delete pairs
    for resource, actions in action_sequences.items():
        # Sort by timestamp
        sorted_actions = sorted(actions, key=lambda x: x['timestamp'])

        for i in range(len(sorted_actions) - 1):
            current = sorted_actions[i]
            next_action = sorted_actions[i + 1]

            # Check if this is a create followed by delete
            if ('create' in current['action'] and 'delete' in next_action['action']) or \
               ('add' in current['action'] and 'remove' in next_action['action']):

                # Calculate time difference
                try:
                    if isinstance(current['timestamp'], str):
                        current_time = datetime.fromisoformat(current['timestamp'].replace('Z', '+00:00'))
                    else:
                        current_time = current['timestamp']

                    if isinstance(next_action['timestamp'], str):
                        next_time = datetime.fromisoformat(next_action['timestamp'].replace('Z', '+00:00'))
                    else:
                        next_time = next_action['timestamp']

                    time_diff = (next_time - current_time).total_seconds()

                    # If create-delete happened within the threshold time window
                    if time_diff < current_thresholds['time_window']:
                        anomalies.append({
                            'type': 'suspicious_sequence',
                            'resource': resource,
                            'first_action': current['action'],
                            'second_action': next_action['action'],
                            'first_user': current['user'],
                            'second_user': next_action['user'],
                            'time_diff_seconds': time_diff,
                            'threshold': current_thresholds['time_window'],
                            'severity': 'high'
                        })
                except Exception:
                    continue

    # Write report to file if requested
    if output_file and anomalies:
        try:
            with open(output_file, 'w') as f:
                json.dump(anomalies, f, indent=2, default=str)

            logger.info(f"Wrote {len(anomalies)} anomalies to {output_file}")

            # Log this for audit purposes
            log_admin_action(
                action="anomaly.detection",
                details={
                    "anomaly_count": len(anomalies),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "threshold": threshold
                },
                status=STATUS_SUCCESS
            )
        except Exception as e:
            logger.error(f"Failed to write anomalies to file: {e}")

    # Return the anomalies
    return anomalies


def verify_audit_log_integrity(
    start_time: datetime,
    end_time: datetime
) -> Dict[str, Any]:
    """
    Verifies the integrity of audit logs, checking for gaps or inconsistencies.

    Args:
        start_time: Start of time period to analyze
        end_time: End of time period to analyze

    Returns:
        Dictionary with integrity verification results
    """
    # Get all admin logs for the period
    logs = get_admin_audit_logs(
        start_time=start_time,
        end_time=end_time,
        limit=10000  # Large limit to get comprehensive data
    )

    if not logs:
        return {
            'status': 'unknown',
            'message': 'No logs found for the specified period',
            'issues': []
        }

    issues = []

    # Sort logs by timestamp
    sorted_logs = sorted(logs, key=lambda x: x.get('timestamp', ''))

    # Check for time gaps
    for i in range(1, len(sorted_logs)):
        prev_log = sorted_logs[i-1]
        curr_log = sorted_logs[i]

        try:
            if isinstance(prev_log.get('timestamp'), str):
                prev_time = datetime.fromisoformat(prev_log['timestamp'].replace('Z', '+00:00'))
            else:
                prev_time = prev_log['timestamp']

            if isinstance(curr_log.get('timestamp'), str):
                curr_time = datetime.fromisoformat(curr_log['timestamp'].replace('Z', '+00:00'))
            else:
                curr_time = curr_log['timestamp']

            time_gap = (curr_time - prev_time).total_seconds() / 60  # Gap in minutes

            # Flag gaps over 60 minutes during business hours
            if time_gap > 60:
                # Check if this is during business hours on a weekday
                is_business_hours = (
                    prev_time.weekday() < 5 and  # Weekday
                    prev_time.hour >= 9 and prev_time.hour < 17  # 9am-5pm
                )

                if is_business_hours:
                    issues.append({
                        'type': 'time_gap',
                        'gap_minutes': time_gap,
                        'start_time': prev_time.isoformat(),
                        'end_time': curr_time.isoformat(),
                        'severity': 'medium'
                    })
        except Exception:
            continue

    # Check for sequence issues (based on IDs if available)
    if all('id' in log for log in logs):
        # Sort by ID
        id_sorted_logs = sorted(logs, key=lambda x: int(x.get('id', 0)))

        # Check for gaps in ID sequence
        for i in range(1, len(id_sorted_logs)):
            prev_id = int(id_sorted_logs[i-1].get('id', 0))
            curr_id = int(id_sorted_logs[i].get('id', 0))

            if prev_id > 0 and curr_id > 0 and curr_id - prev_id > 1:
                issues.append({
                    'type': 'id_sequence_gap',
                    'gap_size': curr_id - prev_id - 1,
                    'start_id': prev_id,
                    'end_id': curr_id,
                    'severity': 'high'
                })

    # Overall status
    status = 'valid'
    message = 'Audit logs appear valid'

    if issues:
        if any(issue['severity'] == 'high' for issue in issues):
            status = 'invalid'
            message = 'Audit logs show signs of tampering or corruption'
        else:
            status = 'warning'
            message = 'Audit logs have potential inconsistencies'

    return {
        'status': status,
        'message': message,
        'logs_analyzed': len(logs),
        'time_range': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat()
        },
        'issues': issues
    }


if __name__ == "__main__":
    # Example/testing code
    print("Admin Audit Utils - Test Mode")

    # Test logging an admin action
    success = log_admin_action(
        action="test.action",
        details={"purpose": "testing"},
        username="test_user",
        status=STATUS_SUCCESS
    )
    print(f"Log action result: {success}")

    # Get current time
    now = datetime.now(timezone.utc)

    # Test retrieving logs
    logs = get_admin_audit_logs(
        start_time=now - timedelta(hours=1),
        end_time=now
    )
    print(f"Found {len(logs)} recent logs")
