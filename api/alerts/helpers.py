"""
Helper functions for the Alerts API.

This module provides utility functions for alert management operations,
including priority calculations, notification formatting, alert correlation,
and aggregation logic.

These helper functions support the routes.py module and ensure consistent
business logic across all alert-related operations.
"""

import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from flask import current_app, g

from models.alerts import Alert
from core.utils.validation import is_valid_ip_address, sanitize_html
from core.security import log_security_event

# Initialize logger for module
logger = logging.getLogger(__name__)

# Alert severity score mapping (for calculations)
SEVERITY_SCORES = {
    'critical': 100,
    'high': 70,
    'warning': 40,
    'info': 10
}

# Time thresholds for auto-escalation (in hours)
ESCALATION_THRESHOLDS = {
    'critical': 1,  # 1 hour
    'high': 4,      # 4 hours
    'warning': 24,  # 24 hours
    'info': 72      # 72 hours
}


def calculate_alert_priority(severity: str, environment: str, service_name: str) -> int:
    """
    Calculate the numerical priority of an alert based on its attributes.

    Higher numbers indicate higher priority.

    Args:
        severity: Alert severity level
        environment: Environment where the alert was triggered
        service_name: Service that generated the alert

    Returns:
        Integer priority score (higher means more important)
    """
    # Base score from severity
    base_score = SEVERITY_SCORES.get(severity.lower(), 10)

    # Environment multiplier
    env_multiplier = 1.0
    if environment == 'production':
        env_multiplier = 2.0
    elif environment == 'staging':
        env_multiplier = 1.5
    elif environment == 'dr-recovery':
        env_multiplier = 1.8

    # Service criticality boost (from configuration)
    service_boost = 1.0
    critical_services = current_app.config.get('CRITICAL_SERVICES', [])
    if service_name in critical_services:
        service_boost = 1.5

    # Calculate final score
    priority = int(base_score * env_multiplier * service_boost)

    return priority


def format_alert_notification(alert: Alert, channel: str = 'email') -> Dict[str, Any]:
    """
    Format an alert for notification delivery based on the channel.

    Args:
        alert: Alert instance to format
        channel: Notification channel (email, slack, webhook)

    Returns:
        Formatted notification content for the specified channel
    """
    # Common notification data
    notification = {
        'id': alert.id,
        'severity': alert.severity,
        'title': f"[{alert.severity.upper()}] {alert.message}",
        'timestamp': alert.created_at.isoformat(),
        'environment': alert.environment,
        'message': alert.message,
    }

    # Add service name if available
    if alert.service_name:
        notification['service'] = alert.service_name

    # Add resource ID if available
    if alert.resource_id:
        notification['resource'] = alert.resource_id

    # Add region if available
    if alert.region:
        notification['region'] = alert.region

    # Format alert details based on channel
    if channel == 'email':
        notification['subject'] = f"[{alert.severity.upper()}] Alert: {alert.message}"
        notification['html_body'] = _format_email_body(alert)

    elif channel == 'slack':
        notification['blocks'] = _format_slack_blocks(alert)
        notification['color'] = _get_severity_color(alert.severity)

    elif channel == 'webhook':
        # For webhooks, include full details
        notification['details'] = alert.details
        notification['status'] = alert.status
        notification['event_type'] = f"alert.{alert.status}"

    return notification


def correlate_alerts(alert: Alert) -> List[int]:
    """
    Find correlated alerts for a given alert.

    Correlation is based on similar services, resources, timing, and alert types.

    Args:
        alert: Alert to find correlations for

    Returns:
        List of correlated alert IDs
    """
    correlated_ids = []
    correlation_window = current_app.config.get('ALERT_CORRELATION_WINDOW_MINUTES', 30)

    # Define time window for correlation
    time_threshold = alert.created_at - timedelta(minutes=correlation_window)

    try:
        # Basic query for alerts in the time window
        candidates = Alert.query.filter(
            Alert.created_at >= time_threshold,
            Alert.id != alert.id,
            Alert.environment == alert.environment
        ).all()

        # Score each candidate for correlation
        for candidate in candidates:
            correlation_score = 0

            # Same service increases correlation
            if candidate.service_name == alert.service_name:
                correlation_score += 30

            # Same resource increases correlation
            if candidate.resource_id and candidate.resource_id == alert.resource_id:
                correlation_score += 40

            # Same alert type increases correlation
            if candidate.alert_type == alert.alert_type:
                correlation_score += 20

            # Same region increases correlation
            if candidate.region and candidate.region == alert.region:
                correlation_score += 10

            # Closer in time increases correlation
            time_diff = abs((candidate.created_at - alert.created_at).total_seconds())
            time_factor = max(0, 1 - (time_diff / (correlation_window * 60)))
            correlation_score += int(time_factor * 20)

            # If correlation score is high enough, consider it related
            if correlation_score >= 50:
                correlated_ids.append(candidate.id)

    except Exception as e:
        logger.error(f"Error correlating alerts: {str(e)}")

    return correlated_ids


def group_alerts_by_resource(alerts: List[Alert]) -> Dict[str, List[Alert]]:
    """
    Group alerts by affected resource.

    Args:
        alerts: List of alert objects to group

    Returns:
        Dictionary of resource IDs to lists of alerts
    """
    resource_groups = {}

    for alert in alerts:
        if not alert.resource_id:
            continue

        if alert.resource_id not in resource_groups:
            resource_groups[alert.resource_id] = []

        resource_groups[alert.resource_id].append(alert)

    return resource_groups


def check_alert_sla(alert: Alert) -> Dict[str, Any]:
    """
    Check if an alert is meeting its SLA based on severity.

    Args:
        alert: Alert to check

    Returns:
        Dictionary with SLA information including deadline and compliance
    """
    # Get SLA response times from config or use defaults
    sla_hours = current_app.config.get('INCIDENT_SLA_HOURS', ESCALATION_THRESHOLDS)

    # Get SLA for this severity level
    severity = alert.severity.lower()
    hours_to_respond = sla_hours.get(severity, ESCALATION_THRESHOLDS[severity])

    # Calculate deadline
    deadline = alert.created_at + timedelta(hours=hours_to_respond)
    now = datetime.utcnow()

    # Calculate time remaining
    if alert.status == 'active':
        time_remaining = (deadline - now).total_seconds()
        overdue = time_remaining < 0
        sla_met = not overdue
    elif alert.status == 'acknowledged':
        if alert.acknowledged_at:
            time_to_ack = (alert.acknowledged_at - alert.created_at).total_seconds() / 3600
            sla_met = time_to_ack <= hours_to_respond
        else:
            sla_met = False
        overdue = False
        time_remaining = 0
    else:  # Resolved
        if alert.resolved_at and alert.created_at:
            time_to_resolve = (alert.resolved_at - alert.created_at).total_seconds() / 3600
            sla_met = time_to_resolve <= hours_to_respond
        else:
            sla_met = False
        overdue = False
        time_remaining = 0

    return {
        'deadline': deadline.isoformat() if alert.status == 'active' else None,
        'sla_hours': hours_to_respond,
        'time_remaining_seconds': time_remaining if alert.status == 'active' else 0,
        'overdue': overdue,
        'sla_met': sla_met
    }


def check_sla_compliance(alert: Alert, check_type: str = 'both',
                        custom_sla_hours: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """
    Perform comprehensive SLA compliance check for an alert with detailed metrics.

    This function evaluates if an alert has been acknowledged and/or resolved within
    the required SLA time frames based on severity. It supports different check types
    and custom SLA definitions.

    Args:
        alert: Alert to check for SLA compliance
        check_type: Type of SLA check ('acknowledgement', 'resolution', or 'both')
        custom_sla_hours: Optional custom SLA hours that override system defaults

    Returns:
        Dictionary with comprehensive SLA compliance information, including:
        - Deadlines for acknowledgement and resolution
        - Time metrics (elapsed time, remaining time)
        - Compliance status for both acknowledgement and resolution
        - Historical compliance data
    """
    # Get configured SLA response times or use defaults
    system_sla_hours = current_app.config.get('INCIDENT_SLA_HOURS', ESCALATION_THRESHOLDS)

    # Use custom SLAs if provided, otherwise use system defaults
    sla_hours = custom_sla_hours or system_sla_hours

    # Get specific SLA for this alert's severity
    severity = alert.severity.lower()
    hours_to_respond = sla_hours.get(severity, ESCALATION_THRESHOLDS[severity])

    # Base response with alert info
    now = datetime.utcnow()
    response = {
        'alert_id': alert.id,
        'severity': alert.severity,
        'status': alert.status,
        'created_at': alert.created_at.isoformat(),
        'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None,
        'sla_hours': hours_to_respond,
        'compliance': {}
    }

    # Calculate acknowledgement SLA metrics if requested
    if check_type in ('acknowledgement', 'both'):
        ack_deadline = alert.created_at + timedelta(hours=hours_to_respond)
        response['compliance']['acknowledgement'] = {
            'deadline': ack_deadline.isoformat(),
        }

        # If alert has been acknowledged, calculate actual time taken
        if alert.acknowledged_at:
            time_to_ack_seconds = (alert.acknowledged_at - alert.created_at).total_seconds()
            time_to_ack_hours = time_to_ack_seconds / 3600
            response['compliance']['acknowledgement'].update({
                'time_taken_seconds': int(time_to_ack_seconds),
                'time_taken_hours': round(time_to_ack_hours, 2),
                'sla_met': time_to_ack_hours <= hours_to_respond,
                'overdue': time_to_ack_hours > hours_to_respond,
                'overdue_by_hours': round(time_to_ack_hours - hours_to_respond, 2) if time_to_ack_hours > hours_to_respond else 0
            })
        # If alert is still active, calculate remaining time
        elif alert.status == 'active':
            time_remaining = (ack_deadline - now).total_seconds()
            response['compliance']['acknowledgement'].update({
                'time_remaining_seconds': int(time_remaining),
                'time_remaining_hours': round(time_remaining / 3600, 2),
                'sla_met': time_remaining > 0,
                'overdue': time_remaining < 0,
                'overdue_by_hours': round(abs(time_remaining) / 3600, 2) if time_remaining < 0 else 0
            })
        # Alert is in an invalid state for acknowledgement SLA checking
        else:
            response['compliance']['acknowledgement'].update({
                'sla_met': False,
                'error': "Alert is not active but hasn't been acknowledged"
            })

    # Calculate resolution SLA metrics if requested
    if check_type in ('resolution', 'both'):
        # For resolution, we typically allow more time than acknowledgement
        resolution_multiplier = current_app.config.get('RESOLUTION_SLA_MULTIPLIER', 2.0)
        resolution_hours = hours_to_respond * resolution_multiplier

        res_deadline = alert.created_at + timedelta(hours=resolution_hours)
        response['compliance']['resolution'] = {
            'deadline': res_deadline.isoformat(),
            'sla_hours': resolution_hours
        }

        # If alert has been resolved, calculate actual time taken
        if alert.resolved_at:
            time_to_resolve_seconds = (alert.resolved_at - alert.created_at).total_seconds()
            time_to_resolve_hours = time_to_resolve_seconds / 3600
            response['compliance']['resolution'].update({
                'time_taken_seconds': int(time_to_resolve_seconds),
                'time_taken_hours': round(time_to_resolve_hours, 2),
                'sla_met': time_to_resolve_hours <= resolution_hours,
                'overdue': time_to_resolve_hours > resolution_hours,
                'overdue_by_hours': round(time_to_resolve_hours - resolution_hours, 2) if time_to_resolve_hours > resolution_hours else 0
            })
        # If alert is still open (active or acknowledged), calculate remaining time
        elif alert.status in ('active', 'acknowledged'):
            time_remaining = (res_deadline - now).total_seconds()
            response['compliance']['resolution'].update({
                'time_remaining_seconds': int(time_remaining),
                'time_remaining_hours': round(time_remaining / 3600, 2),
                'sla_met': time_remaining > 0,
                'overdue': time_remaining < 0,
                'overdue_by_hours': round(abs(time_remaining) / 3600, 2) if time_remaining < 0 else 0
            })

    # Determine overall SLA compliance based on check type
    if check_type == 'both':
        ack_met = response['compliance'].get('acknowledgement', {}).get('sla_met', False)
        res_met = response['compliance'].get('resolution', {}).get('sla_met', False)
        response['sla_met'] = ack_met and res_met
    elif check_type == 'acknowledgement':
        response['sla_met'] = response['compliance'].get('acknowledgement', {}).get('sla_met', False)
    else:  # resolution
        response['sla_met'] = response['compliance'].get('resolution', {}).get('sla_met', False)

    # Calculate overall compliance metrics
    response['overall_health'] = _calculate_sla_health_score(response)

    # Add SLA history if available in alert.details
    if alert.details and 'sla_history' in alert.details:
        response['history'] = alert.details['sla_history']

    return response


def should_auto_escalate(alert: Alert) -> bool:
    """
    Determine if an alert should be auto-escalated based on time thresholds.

    Args:
        alert: Alert to check

    Returns:
        True if the alert should be escalated, False otherwise
    """
    # Only active alerts can be escalated
    if alert.status != 'active':
        return False

    # Get time thresholds from config
    thresholds = current_app.config.get('ALERT_AUTO_ESCALATION_HOURS', ESCALATION_THRESHOLDS)

    # Get threshold for this severity
    severity = alert.severity.lower()
    hours_threshold = thresholds.get(severity, ESCALATION_THRESHOLDS.get(severity, 24))

    # Calculate time since alert was created
    now = datetime.utcnow()
    alert_age_hours = (now - alert.created_at).total_seconds() / 3600

    # Check if alert has exceeded its threshold
    return alert_age_hours >= hours_threshold


def build_alert_filter_query(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    service_name: Optional[str] = None,
    environment: Optional[str] = None,
    resource_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Build a standardized filter query dictionary for alerts.

    Args:
        status: Alert status to filter by
        severity: Alert severity to filter by
        service_name: Service name to filter by
        environment: Environment to filter by
        resource_id: Resource ID to filter by
        start_date: Start date for time range filtering
        end_date: End date for time range filtering

    Returns:
        Filter query dictionary
    """
    filters = {}

    if status and status != 'all':
        filters['status'] = status

    if severity and severity != 'all':
        filters['severity'] = severity

    if service_name:
        filters['service_name'] = service_name

    if environment and environment != 'all':
        filters['environment'] = environment

    if resource_id:
        filters['resource_id'] = resource_id

    if start_date:
        filters['start_date'] = start_date

    if end_date:
        filters['end_date'] = end_date

    return filters


def log_alert_action(alert: Alert, action: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log an alert action with proper security event tracking and auditing.

    Args:
        alert: Alert being acted on
        action: Action being performed
        details: Optional additional details
    """
    if not details:
        details = {}

    # Build basic event details
    event_details = {
        'alert_id': alert.id,
        'alert_type': alert.alert_type,
        'severity': alert.severity,
        'service_name': alert.service_name,
        'environment': alert.environment
    }

    # Add any additional details
    event_details.update(details)

    # Determine appropriate event type
    event_type = f"alert_{action}"

    # Log security event
    log_security_event(
        event_type=event_type,
        description=f"Alert {action}: ID {alert.id}",
        severity=alert.severity.lower(),
        user_id=g.get('user_id'),
        details=event_details
    )

    # Log to application logs as well
    logger.info(f"Alert {action}: ID {alert.id}")


def update_sla_compliance_history(alert: Alert, compliance_data: Dict[str, Any]) -> bool:
    """
    Update an alert with SLA compliance history.

    Args:
        alert: Alert to update
        compliance_data: The compliance data to record

    Returns:
        Boolean indicating if the update was successful
    """
    try:
        # Get current details or initialize empty dict
        details = alert.details or {}

        # Initialize SLA history if not present
        if 'sla_history' not in details:
            details['sla_history'] = []

        # Create a history entry with timestamp
        history_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': alert.status,
            'sla_met': compliance_data.get('sla_met', False),
            'check_type': compliance_data.get('check_type', 'both'),
            'user_id': g.get('user_id', 'system')
        }

        # Add compliance details
        if 'compliance' in compliance_data:
            for check_type, check_data in compliance_data['compliance'].items():
                history_entry[check_type] = {
                    'sla_met': check_data.get('sla_met', False),
                    'overdue': check_data.get('overdue', False),
                    'overdue_by_hours': check_data.get('overdue_by_hours', 0)
                }

        # Append to history and limit to 20 entries
        details['sla_history'].append(history_entry)
        details['sla_history'] = details['sla_history'][-20:]

        # Update alert with latest compliance status
        details['last_sla_check'] = {
            'timestamp': datetime.utcnow().isoformat(),
            'sla_met': compliance_data.get('sla_met', False),
            'overall_health': compliance_data.get('overall_health', 0)
        }

        # Update the alert details
        return alert.update_details(details)

    except Exception as e:
        logger.error(f"Error updating SLA compliance history for alert {alert.id}: {str(e)}")
        return False


def sanitize_alert_message(message: str) -> str:
    """
    Sanitize an alert message to prevent potential XSS attacks.

    Args:
        message: Raw alert message

    Returns:
        Sanitized alert message
    """
    if not message:
        return ""

    # Remove HTML tags if present (using core utility)
    sanitized = sanitize_html(message)

    # Additional filtering for potentially dangerous content
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)

    # Limit length
    max_length = current_app.config.get('MAX_ALERT_MESSAGE_LENGTH', 500)
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized


def validate_alert_details(details: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate alert details structure and content.

    Args:
        details: Alert details dictionary

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not details:
        return True, None

    # Check size to prevent DoS
    import json
    try:
        json_data = json.dumps(details)
        if len(json_data) > 10000:  # 10KB limit
            return False, "Details object too large (max 10KB)"
    except (TypeError, OverflowError):
        return False, "Invalid details structure"

    # Check nesting level (prevent DoS via deeply nested objects)
    try:
        _check_nesting_depth(details)
    except Exception as e:
        return False, str(e)

    return True, None


def _calculate_sla_health_score(compliance_data: Dict[str, Any]) -> float:
    """
    Calculate an overall SLA health score from compliance data.

    Args:
        compliance_data: The SLA compliance data

    Returns:
        A score between 0.0 and 1.0 representing the overall SLA health
    """
    # Start with base score
    score = 1.0

    # Check acknowledgement compliance
    if 'compliance' in compliance_data and 'acknowledgement' in compliance_data['compliance']:
        ack_data = compliance_data['compliance']['acknowledgement']
        if not ack_data.get('sla_met', True):
            # Reduce score based on how overdue
            overdue_hours = ack_data.get('overdue_by_hours', 0)
            if overdue_hours > 0:
                # More reduction for acknowledgement than resolution
                reduction = min(0.6, overdue_hours * 0.1)
                score -= reduction

    # Check resolution compliance
    if 'compliance' in compliance_data and 'resolution' in compliance_data['compliance']:
        res_data = compliance_data['compliance']['resolution']
        if not res_data.get('sla_met', True):
            # Reduce score based on how overdue
            overdue_hours = res_data.get('overdue_by_hours', 0)
            if overdue_hours > 0:
                reduction = min(0.4, overdue_hours * 0.05)
                score -= reduction

    # Ensure score is between 0 and 1
    return max(0.0, min(1.0, score))


def _check_nesting_depth(obj: Any, current_depth: int = 0, max_depth: int = 5) -> None:
    """
    Check for excessive nesting in dictionaries/lists.

    Args:
        obj: Object to check
        current_depth: Current nesting depth
        max_depth: Maximum allowed nesting depth

    Raises:
        ValueError: If nesting is too deep or structure is invalid
    """
    if current_depth > max_depth:
        raise ValueError("Details structure too deeply nested")

    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ValueError("Dictionary keys must be strings")
            _check_nesting_depth(value, current_depth + 1, max_depth)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_nesting_depth(item, current_depth + 1, max_depth)


def _format_email_body(alert: Alert) -> str:
    """
    Format an alert for email notification with HTML.

    Args:
        alert: Alert to format

    Returns:
        HTML content for email
    """
    severity_color = _get_severity_color(alert.severity)

    # Format details if present
    details_html = ""
    if alert.details:
        details_html = "<h3>Details:</h3><ul>"
        for key, value in alert.details.items():
            details_html += f"<li><strong>{key}:</strong> {value}</li>"
        details_html += "</ul>"

    # Build HTML body
    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #{severity_color}; color: white; padding: 10px; text-align: center;">
            <h2>{alert.severity.upper()} Alert</h2>
        </div>
        <div style="padding: 15px; border: 1px solid #ddd;">
            <p><strong>Message:</strong> {alert.message}</p>
            <p><strong>Service:</strong> {alert.service_name or 'N/A'}</p>
            <p><strong>Environment:</strong> {alert.environment}</p>
            <p><strong>Resource:</strong> {alert.resource_id or 'N/A'}</p>
            <p><strong>Region:</strong> {alert.region or 'N/A'}</p>
            <p><strong>Created at:</strong> {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            {details_html}
            <div style="margin-top: 20px; text-align: center;">
                <a href="{current_app.config.get('APP_URL', '')}/alerts/{alert.id}"
                   style="background-color: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; border-radius: 4px;">
                   View Alert
                </a>
            </div>
        </div>
        <div style="text-align: center; margin-top: 15px; color: #777; font-size: 12px;">
            This is an automated message from the Cloud Infrastructure Platform.
        </div>
    </div>
    """


def _format_slack_blocks(alert: Alert) -> List[Dict[str, Any]]:
    """
    Format an alert for Slack notification using blocks.

    Args:
        alert: Alert to format

    Returns:
        List of Slack blocks
    """
    color = _get_severity_color(alert.severity)

    # Build blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{alert.severity.upper()} Alert: {alert.message}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Service:*\n{alert.service_name or 'N/A'}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Environment:*\n{alert.environment}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Resource:*\n{alert.resource_id or 'N/A'}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Region:*\n{alert.region or 'N/A'}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Created at:* {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            }
        }
    ]

    # Add details if present
    if alert.details:
        details_text = "*Details:*\n"
        for key, value in alert.details.items():
            details_text += f"• *{key}:* {value}\n"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": details_text
            }
        })

    # Add button to view alert
    app_url = current_app.config.get('APP_URL', '')
    if app_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Alert"
                    },
                    "url": f"{app_url}/alerts/{alert.id}"
                }
            ]
        })

    return blocks


def _get_severity_color(severity: str) -> str:
    """
    Get color hex code for alert severity.

    Args:
        severity: Alert severity

    Returns:
        Color hex code without the # prefix
    """
    colors = {
        'critical': 'FF0000',  # Red
        'high': 'FF9900',      # Orange
        'warning': 'FFCC00',   # Amber
        'info': '0099CC'       # Blue
    }

    return colors.get(severity.lower(), '777777')  # Default gray
