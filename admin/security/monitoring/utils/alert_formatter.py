"""
Security Alert Formatting Utilities

This module provides functions for formatting security alerts in various output formats
(HTML, JSON, text) with appropriate styling based on severity. It ensures consistent
alert presentation across the security monitoring tools while properly handling
sensitive information.

Key functionality includes:
- Formatting individual and batched security alerts
- Applying appropriate styling and icons based on severity
- Sanitizing alert data to prevent data leakage
- Template-based formatting with customization options
- Support for multiple output formats (HTML, JSON, plain text)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import re
import html

# Try importing Jinja2 for template rendering if available
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# Try importing the monitoring constants if available
try:
    from ..monitoring_constants import SEVERITY
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False

# Try importing core security components if available
try:
    from core.utils import sanitize_html as core_sanitize_html
    CORE_SANITIZE_AVAILABLE = True
except ImportError:
    CORE_SANITIZE_AVAILABLE = False

# Set up module logger
logger = logging.getLogger(__name__)

# Flag for determining if module is properly initialized
ALERT_FORMATTER_AVAILABLE = True

# Default templates directory
TEMPLATES_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / ".." / "templates"

# Default severity colors map
SEVERITY_COLORS = {
    "critical": "#e41a1c",  # Red
    "high": "#ff7f00",      # Orange
    "medium": "#ffcc00",    # Yellow
    "low": "#4daf4a",       # Green
    "info": "#377eb8",      # Blue
    "unknown": "#999999"    # Gray
}

# Default severity icons map
SEVERITY_ICONS = {
    "critical": "exclamation-triangle-fill",
    "high": "exclamation-triangle",
    "medium": "exclamation",
    "low": "info-circle",
    "info": "info",
    "unknown": "question-circle"
}

def format_security_alert(
    event: Dict[str, Any],
    matches: Optional[List[Dict[str, Any]]] = None,
    severity: str = "medium",
    format: str = "html",
    template: Optional[str] = None,
    include_remediation: bool = False,
    environment: str = "production"
) -> str:
    """
    Format a security alert based on an event and optional indicator matches.

    Args:
        event: The security event data to format
        matches: Optional list of threat indicator matches
        severity: Alert severity level (critical, high, medium, low, info)
        format: Output format (html, json, text)
        template: Optional template name to use for formatting
        include_remediation: Whether to include remediation guidance
        environment: Environment name (production, staging, development)

    Returns:
        Formatted alert as a string in the specified format
    """
    # Normalize severity
    severity = severity.lower() if severity else "unknown"
    if severity not in SEVERITY_COLORS:
        severity = "unknown"

    # Basic alert structure
    alert_data = {
        "timestamp": event.get("timestamp", datetime.now().isoformat()),
        "title": event.get("title", f"Security alert: {event.get('alert_type', 'unknown')}"),
        "message": event.get("message", "Security event detected"),
        "severity": severity,
        "event_data": event,
        "matches": matches or [],
        "environment": environment,
        "source": event.get("source", "security_monitoring")
    }

    # Add remediation if requested
    if include_remediation:
        alert_data["remediation"] = _generate_remediation_guidance(event, severity)

    # Format based on requested output
    if format.lower() == "json":
        return _format_json_alert(alert_data)
    elif format.lower() == "text":
        return _format_text_alert(alert_data)
    else:  # Default to HTML
        return _format_html_alert(alert_data, template)

def format_batch_alerts(
    alerts: List[Dict[str, Any]],
    format: str = "html",
    template: Optional[str] = None,
    max_alerts: int = 10,
    environment: str = "production"
) -> str:
    """
    Format a batch of security alerts.

    Args:
        alerts: List of alert data to format
        format: Output format (html, json, text)
        template: Optional template name to use for formatting
        max_alerts: Maximum number of alerts to include (for HTML/text formats)
        environment: Environment name

    Returns:
        Formatted batch of alerts as a string
    """
    # Limit number of alerts if needed
    limited_alerts = alerts[:max_alerts]
    has_more = len(alerts) > max_alerts

    # Basic structure for batch formatting
    batch_data = {
        "alerts": limited_alerts,
        "total_count": len(alerts),
        "displayed_count": len(limited_alerts),
        "has_more": has_more,
        "timestamp": datetime.now().isoformat(),
        "environment": environment
    }

    # Count alerts by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for alert in alerts:
        severity = alert.get("severity", "unknown").lower()
        if severity not in severity_counts:
            severity = "unknown"
        severity_counts[severity] += 1

    batch_data["severity_counts"] = severity_counts

    # Format based on requested output
    if format.lower() == "json":
        return json.dumps(batch_data, default=str)
    elif format.lower() == "text":
        return _format_text_batch(batch_data)
    else:  # Default to HTML
        return _format_html_batch(batch_data, template)

def get_alert_template(template_name: str) -> Optional[str]:
    """
    Get the content of an alert template by name.

    Args:
        template_name: Name of the template to retrieve

    Returns:
        Template content as string, or None if not found
    """
    template_path = TEMPLATES_DIR / f"{template_name}.html"
    try:
        if template_path.exists():
            with open(template_path, "r") as f:
                return f.read()
        else:
            logger.warning(f"Template not found: {template_name}")
            return None
    except Exception as e:
        logger.error(f"Error reading template {template_name}: {str(e)}")
        return None

def get_severity_color(severity: str) -> str:
    """
    Get the color code associated with a severity level.

    Args:
        severity: Severity level string

    Returns:
        Color hex code for the severity level
    """
    severity = severity.lower() if severity else "unknown"
    return SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

def get_severity_icon(severity: str) -> str:
    """
    Get the icon name associated with a severity level.

    Args:
        severity: Severity level string

    Returns:
        Icon identifier for the severity level
    """
    severity = severity.lower() if severity else "unknown"
    return SEVERITY_ICONS.get(severity, SEVERITY_ICONS["unknown"])

def sanitize_alert_data(data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """
    Sanitize potentially sensitive data from alert information.

    Args:
        data: Alert data to sanitize
        **kwargs: Additional options for sanitization

    Returns:
        Sanitized alert data
    """
    # Create a deep copy to avoid modifying the original
    sanitized = _deep_copy_dict(data)

    # Fields to completely redact
    redact_fields = [
        "password", "token", "api_key", "secret", "credential", "private",
        "auth", "access_key", "key", "cert"
    ]

    # Fields to partially redact (keep partial information)
    partial_redact_fields = ["ip", "email", "address", "phone", "user"]

    # Function to recursively sanitize dictionaries
    def _sanitize_dict(d, current_path=""):
        if not isinstance(d, dict):
            return d

        for key, value in list(d.items()):
            # Track the path to this field
            field_path = f"{current_path}.{key}" if current_path else key

            # Check if this field should be redacted
            should_redact = any(rf in key.lower() for rf in redact_fields)
            should_partial_redact = any(rf in key.lower() for rf in partial_redact_fields)

            if should_redact:
                # Completely redact sensitive fields
                d[key] = "[REDACTED]"
            elif should_partial_redact and isinstance(value, str):
                # Partially redact identifiable information
                d[key] = _partial_redact(value, key)
            elif isinstance(value, dict):
                # Recurse into nested dictionaries
                d[key] = _sanitize_dict(value, field_path)
            elif isinstance(value, list):
                # Sanitize each item in a list
                d[key] = [
                    _sanitize_dict(item, f"{field_path}[{i}]") if isinstance(item, dict)
                    else item for i, item in enumerate(value)
                ]

        return d

    # Sanitize the data
    return _sanitize_dict(sanitized)

def render_alert_template(
    template_content: str,
    alert_data: Dict[str, Any],
    default_template: Optional[str] = None
) -> str:
    """
    Render an alert template with the provided data.

    Args:
        template_content: Template content as string
        alert_data: Data to use for template rendering
        default_template: Optional fallback template if primary fails

    Returns:
        Rendered template as string
    """
    if not template_content and default_template:
        template_content = get_alert_template(default_template)

    if not template_content:
        # If no template content provided or found, use basic formatting
        return _format_html_alert(alert_data)

    try:
        if JINJA2_AVAILABLE:
            # Use Jinja2 if available
            env = Environment(
                loader=FileSystemLoader(TEMPLATES_DIR),
                autoescape=select_autoescape(['html'])
            )
            template = env.from_string(template_content)

            # Add helper functions to template context
            context = {
                "get_severity_color": get_severity_color,
                "get_severity_icon": get_severity_icon,
                "format_timestamp": _format_timestamp,
                **alert_data
            }

            return template.render(**context)
        else:
            # Simple template substitution if Jinja2 not available
            result = template_content
            for key, value in alert_data.items():
                if isinstance(value, str):
                    placeholder = f"{{{{{key}}}}}"
                    result = result.replace(placeholder, value)

            return result

    except Exception as e:
        logger.error(f"Error rendering alert template: {str(e)}")
        # Fall back to basic formatting on error
        return _format_html_alert(alert_data)

# --- Private Helper Functions ---

def _format_json_alert(alert_data: Dict[str, Any]) -> str:
    """Format alert as JSON."""
    return json.dumps(alert_data, indent=2, default=str)

def _format_text_alert(alert_data: Dict[str, Any]) -> str:
    """Format alert as plain text."""
    severity = alert_data.get("severity", "unknown").upper()
    title = alert_data.get("title", "Security Alert")
    message = alert_data.get("message", "")
    timestamp = _format_timestamp(alert_data.get("timestamp", datetime.now().isoformat()))

    text = [
        f"[{severity}] {title}",
        f"Time: {timestamp}",
        f"Environment: {alert_data.get('environment', 'production')}",
        "",
        message,
        ""
    ]

    # Add matches if available
    matches = alert_data.get("matches", [])
    if matches:
        text.append("Matched Indicators:")
        for i, match in enumerate(matches):
            text.append(f"  {i+1}. {match.get('indicator_type', 'unknown')}: {match.get('value', '')}")
        text.append("")

    # Add remediation if available
    if "remediation" in alert_data:
        text.append("Recommended Action:")
        text.append(alert_data["remediation"])

    return "\n".join(text)

def _format_html_alert(alert_data: Dict[str, Any], template: Optional[str] = None) -> str:
    """Format alert as HTML."""
    if template:
        template_content = get_alert_template(template)
        if template_content:
            return render_alert_template(template_content, alert_data)

    # Basic HTML formatting if no template provided or found
    severity = alert_data.get("severity", "unknown")
    title = _escape_html(alert_data.get("title", "Security Alert"))
    message = _escape_html(alert_data.get("message", ""))
    timestamp = _format_timestamp(alert_data.get("timestamp", datetime.now().isoformat()))
    color = get_severity_color(severity)
    icon = get_severity_icon(severity)

    html_content = f"""
    <div class="security-alert severity-{severity}" style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0; background-color: #f8f9fa;">
        <div class="alert-header" style="font-weight: bold; color: {color};">
            <span class="alert-icon"><i class="bi bi-{icon}"></i></span>
            <span class="alert-title">{title}</span>
        </div>
        <div class="alert-timestamp" style="color: #666; font-size: 0.9em;">
            {timestamp} | {_escape_html(alert_data.get('environment', 'production'))}
        </div>
        <div class="alert-message" style="margin-top: 8px;">
            {message}
        </div>
    """

    # Add matches if available
    matches = alert_data.get("matches", [])
    if matches:
        html_content += '<div class="alert-matches" style="margin-top: 8px; font-size: 0.9em;">'
        html_content += '<div style="font-weight: bold;">Matched Indicators:</div>'
        html_content += '<ul style="margin-top: 4px; padding-left: 20px;">'

        for match in matches:
            indicator_type = _escape_html(match.get("indicator_type", "unknown"))
            value = _escape_html(match.get("value", ""))
            html_content += f'<li>{indicator_type}: {value}</li>'

        html_content += '</ul></div>'

    # Add remediation if available
    if "remediation" in alert_data:
        remediation = _escape_html(alert_data["remediation"])
        html_content += f'''
        <div class="alert-remediation" style="margin-top: 8px; border-top: 1px solid #ddd; padding-top: 8px;">
            <div style="font-weight: bold;">Recommended Action:</div>
            <div>{remediation}</div>
        </div>
        '''

    html_content += '</div>'
    return html_content

def _format_text_batch(batch_data: Dict[str, Any]) -> str:
    """Format a batch of alerts as plain text."""
    alerts = batch_data.get("alerts", [])
    severity_counts = batch_data.get("severity_counts", {})
    timestamp = _format_timestamp(batch_data.get("timestamp", datetime.now().isoformat()))

    text = [
        f"Security Alerts Summary - {timestamp}",
        f"Environment: {batch_data.get('environment', 'production')}",
        "",
        "Alert Count by Severity:",
    ]

    # Add severity counts
    for severity, count in severity_counts.items():
        if count > 0:
            text.append(f"  {severity.upper()}: {count}")

    text.append("")
    text.append(f"Showing {len(alerts)} of {batch_data.get('total_count', len(alerts))} alerts")
    text.append("")

    # Add individual alerts
    for i, alert in enumerate(alerts):
        severity = alert.get("severity", "unknown").upper()
        title = alert.get("title", "Security Alert")
        message = alert.get("message", "")
        alert_time = _format_timestamp(alert.get("timestamp", ""))

        text.append(f"{i+1}. [{severity}] {title}")
        text.append(f"   Time: {alert_time}")
        text.append(f"   Message: {message}")
        text.append("")

    # Add note about additional alerts
    if batch_data.get("has_more", False):
        remaining = batch_data.get("total_count", 0) - len(alerts)
        text.append(f"... and {remaining} more alerts not shown")

    return "\n".join(text)

def _format_html_batch(batch_data: Dict[str, Any], template: Optional[str] = None) -> str:
    """Format a batch of alerts as HTML."""
    if template:
        template_content = get_alert_template(template)
        if template_content:
            return render_alert_template(template_content, batch_data)

    # Basic HTML formatting if no template provided or found
    alerts = batch_data.get("alerts", [])
    severity_counts = batch_data.get("severity_counts", {})
    timestamp = _format_timestamp(batch_data.get("timestamp", datetime.now().isoformat()))
    environment = _escape_html(batch_data.get("environment", "production"))

    html_content = f"""
    <div class="security-alerts-summary" style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
        <h2 style="color: #333;">Security Alerts Summary</h2>
        <div style="color: #666; margin-bottom: 15px;">
            <span>Environment: {environment}</span> | <span>Generated: {timestamp}</span>
        </div>

        <div class="severity-summary" style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px;">
    """

    # Add severity count cards
    for severity, count in severity_counts.items():
        if count > 0:
            color = get_severity_color(severity)
            html_content += f"""
            <div class="severity-card" style="flex: 1; min-width: 100px; padding: 10px; background-color: #f8f9fa; border-left: 4px solid {color}; text-align: center;">
                <div style="font-weight: bold; color: {color};">{severity.upper()}</div>
                <div style="font-size: 1.5em;">{count}</div>
            </div>
            """

    html_content += f"""
        </div>

        <div style="margin-bottom: 15px;">
            Showing {len(alerts)} of {batch_data.get('total_count', len(alerts))} alerts
        </div>

        <div class="alerts-list">
    """

    # Add individual alerts
    for alert in alerts:
        severity = alert.get("severity", "unknown")
        title = _escape_html(alert.get("title", "Security Alert"))
        message = _escape_html(alert.get("message", ""))
        alert_time = _format_timestamp(alert.get("timestamp", ""))
        color = get_severity_color(severity)
        icon = get_severity_icon(severity)

        html_content += f"""
        <div class="alert-item" style="border-left: 4px solid {color}; padding: 10px; margin-bottom: 10px; background-color: #f8f9fa;">
            <div style="font-weight: bold; color: {color};">
                <i class="bi bi-{icon}"></i> {title}
            </div>
            <div style="color: #666; font-size: 0.9em;">{alert_time}</div>
            <div style="margin-top: 5px;">{message}</div>
        </div>
        """

    # Add note about additional alerts
    if batch_data.get("has_more", False):
        remaining = batch_data.get("total_count", 0) - len(alerts)
        html_content += f"""
        <div style="font-style: italic; text-align: center; margin-top: 10px; color: #666;">
            ... and {remaining} more alerts not shown
        </div>
        """

    html_content += """
        </div>
    </div>
    """

    return html_content

def _generate_remediation_guidance(event: Dict[str, Any], severity: str) -> str:
    """Generate remediation guidance based on the event type and severity."""
    event_type = event.get("event_type", "").lower()

    # Generic remediations based on event type
    remediation_map = {
        "authentication_failure": "Review authentication logs and consider implementing MFA.",
        "malware_detected": "Isolate the affected system and perform a full scan.",
        "permission_change": "Verify that the permission change was authorized.",
        "network_scan": "Investigate the source IP and consider blocking if malicious.",
        "data_access": "Verify that the data access was authorized and appropriate.",
        "configuration_change": "Verify that the configuration change was authorized.",
        "api_abuse": "Consider implementing rate limiting and reviewing API authentication."
    }

    # Get basic remediation based on event type
    remediation = remediation_map.get(event_type, "Investigate this security alert further.")

    # Add severity-specific actions
    if severity == "critical":
        remediation += " This is a CRITICAL alert requiring immediate attention."
    elif severity == "high":
        remediation += " This is a HIGH severity alert requiring prompt investigation."

    return remediation

def _escape_html(text: str) -> str:
    """Safely escape HTML characters to prevent XSS."""
    if CORE_SANITIZE_AVAILABLE:
        return core_sanitize_html(text)
    else:
        # Simple fallback if core utility not available
        return html.escape(text)

def _partial_redact(value: str, field_name: str) -> str:
    """Partially redact a value while maintaining some context."""
    if not value:
        return value

    # Email addresses - show domain only
    if "email" in field_name.lower() and "@" in value:
        username, domain = value.split("@", 1)
        return f"****@{domain}"

    # IP addresses - show first octet only
    if "ip" in field_name.lower() and re.match(r'\d+\.\d+\.\d+\.\d+', value):
        parts = value.split(".")
        return f"{parts[0]}.***.***.*"

    # Other identifiers - show first and last character only
    if len(value) > 4:
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
    else:
        return "****"  # Too short to partially redact meaningfully

def _format_timestamp(timestamp: str) -> str:
    """Format a timestamp string for display."""
    if not timestamp:
        return ""

    try:
        # Try parsing ISO format
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        # Return as-is if parsing fails
        return str(timestamp)

def _deep_copy_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a deep copy of a dictionary."""
    try:
        return json.loads(json.dumps(data, default=str))
    except (TypeError, ValueError):
        # Fallback for non-serializable objects
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = _deep_copy_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    _deep_copy_dict(item) if isinstance(item, dict)
                    else item for item in value
                ]
            else:
                result[key] = value
        return result
