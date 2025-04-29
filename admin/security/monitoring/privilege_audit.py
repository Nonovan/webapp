#!/usr/bin/env python3
"""
Privilege Audit Tool

This script monitors and audits the usage of administrative privileges
within the Cloud Infrastructure Platform. It checks for unusual privilege
assignments, escalations, and usage patterns based on audit logs.

Usage:
    python admin/security/monitoring/privilege_audit.py [options]

Options:
    --hours <N>         Analyze logs from the last N hours.
    --days <N>          Analyze logs from the last N days (default: 1). Overrides --hours.
    --start-date <dt>   Start date (YYYY-MM-DD or ISO format). Overrides --days/--hours.
    --end-date <dt>     End date (YYYY-MM-DD or ISO format). Defaults to now.
    --user <username>   Filter by specific administrator username.
    --role <role>       Filter by specific role (e.g., 'admin', 'superuser').
    --output <file>     Path to the output report file (json or html format).
    --format <fmt>      Output format (json, html). Default: json. HTML provides visualization.
    --threshold <level> Alert threshold (low, medium, high). Default: medium.
    --verbose           Enable verbose logging.
    --env <env>         Application environment (default: production).
    --no-alert          Disable automatic alerting for high-severity issues.
"""

import argparse
import json
import logging
import os
import sys
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Set, Union
from pathlib import Path

# Adjust path to import application components
# Assumes the script is run from the project root or the path is adjusted externally
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Import Core Components ---
try:
    from flask import Flask, render_template_string
    from core.factory import create_app # Assuming create_app exists for context
    # Use admin utils for consistency if they exist and provide necessary functions
    from admin.utils.audit_utils import (
        get_admin_audit_logs, log_admin_action, detect_admin_anomalies,
        verify_audit_log_integrity,
        SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR, SEVERITY_CRITICAL,
        STATUS_SUCCESS, STATUS_FAILURE, STATUS_ATTEMPTED,
        ACTION_AUDIT_ACCESS, ADMIN_EVENT_PREFIX
    )
    # Assume notification service is available
    from services.notification import send_notification
    # For time utility functions
    from models.security.audit_log import AuditLog # For event type constants
    CORE_AVAILABLE = True
    NOTIFICATION_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Error importing application modules: {e}", file=sys.stderr)
    print("Core application context or utils may not be available. Functionality might be limited.", file=sys.stderr)
    CORE_AVAILABLE = False
    NOTIFICATION_AVAILABLE = False
    # Define dummy functions for basic operation
    def get_admin_audit_logs(*args, **kwargs) -> List[Dict[str, Any]]: return []
    def log_admin_action(*args, **kwargs) -> bool: return False
    def detect_admin_anomalies(*args, **kwargs) -> List[Dict[str, Any]]: return []
    def verify_audit_log_integrity(*args, **kwargs) -> Dict[str, Any]: return {"status": "unknown", "issues": []}
    def send_notification(*args, **kwargs) -> bool: return False

    # Dummy AuditLog class with constants
    class AuditLog:
        EVENT_ROLE_ASSIGNED = 'role_assigned'
        EVENT_ROLE_REMOVED = 'role_removed'
        EVENT_PERMISSION_GRANTED = 'permission_granted'
        EVENT_PERMISSION_REVOKED = 'permission_revoked'
        EVENT_ADMIN_ACTION = 'admin_action' # Generic admin action
        EVENT_EMERGENCY_ACCESS = 'emergency_access'
        EVENT_EMERGENCY_DEACTIVATE = 'emergency_deactivate'

    # Constants for this script's operation
    SEVERITY_INFO = "info"
    SEVERITY_WARNING = "warning"
    SEVERITY_ERROR = "error"
    SEVERITY_CRITICAL = "critical"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    STATUS_ATTEMPTED = "attempted"
    STATUS_WARNING = "warning"
    ACTION_AUDIT_ACCESS = "audit.access"
    ADMIN_EVENT_PREFIX = "admin."

# --- Logging Setup ---
LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "privilege_audit.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE)
    ]
)
logger = logging.getLogger(__name__)

# --- Constants ---
# Define privilege-related event types using constants if available
PRIVILEGE_EVENTS = [
    f"{ADMIN_EVENT_PREFIX}role.assign", f"{ADMIN_EVENT_PREFIX}role.revoke",
    f"{ADMIN_EVENT_PREFIX}permission.grant", f"{ADMIN_EVENT_PREFIX}permission.revoke",
    f"{ADMIN_EVENT_PREFIX}emergency.access", f"{ADMIN_EVENT_PREFIX}emergency.deactivate",
    f"{ADMIN_EVENT_PREFIX}sudo.exec", f"{ADMIN_EVENT_PREFIX}sudo.auth",
    AuditLog.EVENT_ROLE_ASSIGNED, AuditLog.EVENT_ROLE_REMOVED,
    AuditLog.EVENT_PERMISSION_GRANTED, AuditLog.EVENT_PERMISSION_REVOKED,
    AuditLog.EVENT_EMERGENCY_ACCESS, AuditLog.EVENT_EMERGENCY_DEACTIVATE,
    # Add other relevant event types if necessary
]
# Remove duplicates that might exist if admin utils redefine core constants
PRIVILEGE_EVENTS = sorted(list(set(PRIVILEGE_EVENTS)))

# Default thresholds for anomaly detection
DEFAULT_THRESHOLDS = {
    "low": {
        "after_hours_changes": 1,
        "weekend_changes": 1,
        "emergency_access": 1,
        "consecutive_changes": 5,
        "privilege_escalation": 1
    },
    "medium": {
        "after_hours_changes": 2,
        "weekend_changes": 2,
        "emergency_access": 1,
        "consecutive_changes": 10,
        "privilege_escalation": 2
    },
    "high": {
        "after_hours_changes": 5,
        "weekend_changes": 3,
        "emergency_access": 2,
        "consecutive_changes": 15,
        "privilege_escalation": 3
    }
}

# --- Helper Functions ---
def parse_datetime(dt_str: str) -> Optional[datetime]:
    """Parses YYYY-MM-DD or ISO format datetime strings."""
    if not dt_str:
        return None
    try:
        # Try ISO format first
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except ValueError:
        try:
            # Try YYYY-MM-DD format
            dt = datetime.strptime(dt_str, '%Y-%m-%d')
            return dt.replace(tzinfo=timezone.utc) # Assume UTC if only date is given
        except ValueError:
            try:
                # Try MM/DD/YYYY format
                dt = datetime.strptime(dt_str, '%m/%d/%Y')
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.error(f"Invalid date format: {dt_str}. Use YYYY-MM-DD, MM/DD/YYYY, or ISO format.")
                return None

def get_time_range_from_args(args: argparse.Namespace) -> Tuple[datetime, datetime]:
    """Determines the start and end datetime from command line arguments."""
    now = datetime.now(timezone.utc)
    end_dt = parse_datetime(args.end_date) if args.end_date else now

    if args.start_date:
        start_dt = parse_datetime(args.start_date)
        if not start_dt:
            raise ValueError("Invalid start date format.")
    elif args.hours:
        start_dt = end_dt - timedelta(hours=args.hours)
    elif args.days:
        start_dt = end_dt - timedelta(days=args.days)
    else:
        # Default to last 1 day if nothing else specified
        start_dt = end_dt - timedelta(days=1)

    # Ensure end_dt is after start_dt
    if end_dt < start_dt:
        raise ValueError("End date cannot be before start date.")

    return start_dt, end_dt

def is_business_hours(timestamp: datetime) -> bool:
    """Determines if timestamp is during standard business hours (Mon-Fri, 9am-5pm UTC)."""
    return (timestamp.weekday() < 5 and  # Weekday (Mon-Fri)
            9 <= timestamp.hour < 17)    # 9am-5pm

def get_threshold_config(threshold_level: str) -> Dict[str, int]:
    """Get threshold configuration based on specified level."""
    level = threshold_level.lower()
    if level in DEFAULT_THRESHOLDS:
        return DEFAULT_THRESHOLDS[level]
    logger.warning(f"Unknown threshold level: {level}. Using 'medium'.")
    return DEFAULT_THRESHOLDS["medium"]

def analyze_privilege_logs(logs: List[Dict[str, Any]], threshold_level: str = "medium") -> Dict[str, Any]:
    """Analyzes audit logs for privilege-related activities."""
    analysis = {
        "total_privilege_events": 0,
        "grants_assignments": [],
        "revocations_removals": [],
        "emergency_access_events": [],
        "potential_issues": []
    }

    # Get threshold configuration
    thresholds = get_threshold_config(threshold_level)

    # Track user activity for sequence detection
    user_activities = {}
    privilege_escalations = {}

    # Organize logs by timestamp
    sorted_logs = sorted(logs, key=lambda x: datetime.fromisoformat(
        x.get('timestamp', '').replace('Z', '+00:00')) if x.get('timestamp') else datetime.min)

    for log in sorted_logs:
        analysis["total_privilege_events"] += 1
        event_type = log.get('event_type', '')
        details = log.get('details', {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {'raw_details': details}

        timestamp_str = log.get('timestamp')
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')) if timestamp_str else None
        user = log.get('username', log.get('user_id', 'Unknown'))
        target_user = details.get('target_user', details.get('affected_user'))
        target_role = details.get('role', details.get('role_name'))

        # Track user activity for sequence detection
        if user not in user_activities:
            user_activities[user] = []

        user_activities[user].append({
            'timestamp': timestamp,
            'event_type': event_type,
            'details': details,
            'log_id': log.get('id')
        })

        # Categorize events
        if "grant" in event_type or "assign" in event_type:
            analysis["grants_assignments"].append(log)

            # Check for self-privilege escalation
            if target_user and user == target_user and target_role:
                if user not in privilege_escalations:
                    privilege_escalations[user] = []
                privilege_escalations[user].append({
                    'timestamp': timestamp,
                    'role': target_role,
                    'log_id': log.get('id')
                })

        elif "revoke" in event_type or "remove" in event_type:
            analysis["revocations_removals"].append(log)
        elif "emergency" in event_type:
            analysis["emergency_access_events"].append(log)

        # --- Identify Potential Issues ---

        # Issue 1: Non-business hours activity
        if timestamp and ("grant" in event_type or "assign" in event_type or "emergency" in event_type):
            if timestamp.weekday() >= 5:  # Weekend (Sat-Sun)
                analysis["potential_issues"].append({
                    "type": "weekend_privilege_change",
                    "severity": SEVERITY_WARNING,
                    "log_id": log.get('id'),
                    "timestamp": timestamp_str,
                    "user": user,
                    "event_type": event_type,
                    "details": f"Privilege change performed on weekend by {user}"
                })
            elif timestamp.hour < 9 or timestamp.hour >= 17:  # Outside 9am-5pm
                analysis["potential_issues"].append({
                    "type": "after_hours_privilege_change",
                    "severity": SEVERITY_INFO,
                    "log_id": log.get('id'),
                    "timestamp": timestamp_str,
                    "user": user,
                    "event_type": event_type,
                    "details": f"Privilege change performed outside business hours by {user}"
                })

        # Issue 2: Emergency access
        if "emergency" in event_type:
            severity = SEVERITY_CRITICAL if ".access" in event_type else SEVERITY_WARNING
            issue_type = "emergency_access_activated" if ".access" in event_type else "emergency_access_deactivated"

            analysis["potential_issues"].append({
                "type": issue_type,
                "severity": severity,
                "log_id": log.get('id'),
                "timestamp": timestamp_str,
                "user": user,
                "details": f"{'Emergency access activated' if '.access' in event_type else 'Emergency access deactivated'} by {user}"
            })

    # --- Process multi-event patterns ---

    # Issue 3: Check for rapid sequence of privilege changes by same user
    for user, activities in user_activities.items():
        if len(activities) < thresholds["consecutive_changes"]:
            continue

        # Check for rapid changes in time windows
        window_size = timedelta(minutes=15)
        for i in range(len(activities)):
            window_start = activities[i]['timestamp']
            window_end = window_start + window_size
            changes_in_window = [
                act for act in activities[i:]
                if act['timestamp'] <= window_end
            ]

            if len(changes_in_window) >= thresholds["consecutive_changes"]:
                analysis["potential_issues"].append({
                    "type": "rapid_privilege_changes",
                    "severity": SEVERITY_WARNING,
                    "user": user,
                    "timestamp": window_start.isoformat(),
                    "count": len(changes_in_window),
                    "event_ids": [act['log_id'] for act in changes_in_window],
                    "details": f"User {user} made {len(changes_in_window)} privilege changes in {window_size.total_seconds()/60} minutes"
                })
                break  # Only report once per user

    # Issue 4: Self-privilege escalation
    for user, escalations in privilege_escalations.items():
        if len(escalations) >= thresholds["privilege_escalation"]:
            analysis["potential_issues"].append({
                "type": "self_privilege_escalation",
                "severity": SEVERITY_CRITICAL,
                "user": user,
                "roles": [esc['role'] for esc in escalations],
                "event_ids": [esc['log_id'] for esc in escalations],
                "details": f"User {user} escalated their own privileges {len(escalations)} times"
            })

    # --- Final processing ---

    # Remove duplicate issues
    seen_issues = set()
    unique_issues = []

    for issue in analysis["potential_issues"]:
        # Create a key for deduplication
        issue_key = f"{issue['type']}:{issue.get('user', '')}:{issue.get('log_id', '')}"

        if issue_key not in seen_issues:
            seen_issues.add(issue_key)
            unique_issues.append(issue)

    analysis["potential_issues"] = unique_issues

    # Sort issues by severity
    severity_order = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_ERROR: 1,
        SEVERITY_WARNING: 2,
        SEVERITY_INFO: 3
    }

    analysis["potential_issues"].sort(
        key=lambda x: (severity_order.get(x.get('severity', SEVERITY_INFO), 4),
                       x.get('timestamp', ''))
    )

    logger.info(f"Analyzed {analysis['total_privilege_events']} privilege-related events.")
    logger.info(f"Found {len(analysis['potential_issues'])} potential issues.")
    return analysis

def generate_json_report(analysis_results: Dict[str, Any], output_file: Optional[str],
                        start_dt: datetime, end_dt: datetime) -> str:
    """Generates a JSON report of the privilege audit findings."""
    report_data = {
        "report_metadata": {
            "report_type": "Privilege Audit",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range_start": start_dt.isoformat(),
            "time_range_end": end_dt.isoformat(),
            "version": "1.1.0"
        },
        "summary": {
            "total_privilege_events": analysis_results["total_privilege_events"],
            "total_grants_assignments": len(analysis_results["grants_assignments"]),
            "total_revocations_removals": len(analysis_results["revocations_removals"]),
            "total_emergency_access_events": len(analysis_results["emergency_access_events"]),
            "potential_issues_count": len(analysis_results["potential_issues"]),
        },
        "potential_issues": analysis_results["potential_issues"],
        # Optional detailed data - can be included if needed
        # "grants_assignments_sample": analysis_results["grants_assignments"][:10],
        # "revocations_removals_sample": analysis_results["revocations_removals"][:10],
        # "emergency_access_events": analysis_results["emergency_access_events"],
    }

    # Add severity counts
    severity_counts = {SEVERITY_CRITICAL: 0, SEVERITY_ERROR: 0, SEVERITY_WARNING: 0, SEVERITY_INFO: 0}
    for issue in analysis_results["potential_issues"]:
        severity = issue.get('severity', SEVERITY_INFO)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    report_data["summary"]["severity_counts"] = severity_counts

    # Add issue types summary
    issue_types = {}
    for issue in analysis_results["potential_issues"]:
        issue_type = issue.get('type', 'unknown')
        issue_types[issue_type] = issue_types.get(issue_type, 0) + 1

    report_data["summary"]["issue_types"] = issue_types

    # Convert to JSON
    report_json = json.dumps(report_data, indent=2, default=str)

    # If output_file is provided, write to file
    if output_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(report_json)
            logger.info(f"Privilege audit report saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to write report to {output_file}: {e}")

    return report_json

def generate_html_report(analysis_results: Dict[str, Any], output_file: Optional[str],
                        start_dt: datetime, end_dt: datetime) -> str:
    """Generates an HTML report of the privilege audit findings with visualizations."""
    # First generate JSON data
    json_data = json.loads(generate_json_report(analysis_results, None, start_dt, end_dt))

    # Get directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(script_dir, "templates")

    # Try to load the template
    template_path = os.path.join(template_dir, "privilege_audit_report.html")
    template_content = None

    try:
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                template_content = f.read()
    except IOError as e:
        logger.warning(f"Could not load template file: {e}")

    # If template not available, use a basic built-in template
    if not template_content:
        template_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Privilege Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
                .container { max-width: 1200px; margin: 0 auto; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #2c3e50; margin-top: 30px; }
                .summary { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }
                .summary-box { border: 1px solid #ddd; padding: 15px; flex: 1; min-width: 150px; }
                .severity-critical { background-color: #ffdddd; border-left: 5px solid #ff0000; }
                .severity-error { background-color: #ffe0cc; border-left: 5px solid #ff6600; }
                .severity-warning { background-color: #ffffcc; border-left: 5px solid #ffcc00; }
                .severity-info { background-color: #d4edda; border-left: 5px solid #28a745; }
                .count { font-size: 24px; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f5f5f5; }
                tr:hover { background-color: #f9f9f9; }
                .chart-container { width: 100%; height: 300px; margin: 20px 0; }
                .footer { margin-top: 40px; font-size: 12px; color: #777; }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <div class="container">
                <h1>Privilege Audit Report</h1>
                <p><strong>Time Range:</strong> {{ report.report_metadata.time_range_start }} to {{ report.report_metadata.time_range_end }}</p>
                <p><strong>Generated:</strong> {{ report.report_metadata.generated_at }}</p>

                <h2>Summary</h2>
                <div class="summary">
                    <div class="summary-box">
                        <h3>Total Events</h3>
                        <div class="count">{{ report.summary.total_privilege_events }}</div>
                    </div>
                    <div class="summary-box">
                        <h3>Grants/Assignments</h3>
                        <div class="count">{{ report.summary.total_grants_assignments }}</div>
                    </div>
                    <div class="summary-box">
                        <h3>Revocations</h3>
                        <div class="count">{{ report.summary.total_revocations_removals }}</div>
                    </div>
                    <div class="summary-box">
                        <h3>Emergency Access</h3>
                        <div class="count">{{ report.summary.total_emergency_access_events }}</div>
                    </div>
                </div>

                <h2>Issue Severity Distribution</h2>
                <div class="summary">
                    <div class="summary-box severity-critical">
                        <h3>Critical</h3>
                        <div class="count">{{ report.summary.severity_counts.critical }}</div>
                    </div>
                    <div class="summary-box severity-error">
                        <h3>Error</h3>
                        <div class="count">{{ report.summary.severity_counts.error }}</div>
                    </div>
                    <div class="summary-box severity-warning">
                        <h3>Warning</h3>
                        <div class="count">{{ report.summary.severity_counts.warning }}</div>
                    </div>
                    <div class="summary-box severity-info">
                        <h3>Info</h3>
                        <div class="count">{{ report.summary.severity_counts.info }}</div>
                    </div>
                </div>

                <h2>Issue Types</h2>
                <div class="chart-container">
                    <canvas id="issueTypeChart"></canvas>
                </div>

                <h2>Potential Issues ({{ report.summary.potential_issues_count }})</h2>
                {% if report.potential_issues %}
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>User</th>
                            <th>Timestamp</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for issue in report.potential_issues %}
                        <tr class="severity-{{ issue.severity }}">
                            <td>{{ issue.type }}</td>
                            <td>{{ issue.severity }}</td>
                            <td>{{ issue.user }}</td>
                            <td>{{ issue.timestamp }}</td>
                            <td>{{ issue.details }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No issues detected.</p>
                {% endif %}

                <div class="footer">
                    <p>Generated by Privilege Audit Tool v{{ report.report_metadata.version }}</p>
                </div>
            </div>

            <script>
                // Setup issue type chart
                const issueTypes = {{ report.summary.issue_types|tojson }};
                const issueTypeLabels = Object.keys(issueTypes);
                const issueTypeCounts = Object.values(issueTypes);

                new Chart(document.getElementById('issueTypeChart'), {
                    type: 'bar',
                    data: {
                        labels: issueTypeLabels,
                        datasets: [{
                            label: 'Count',
                            data: issueTypeCounts,
                            backgroundColor: 'rgba(54, 162, 235, 0.6)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            </script>
        </body>
        </html>
        """

    # Try to use Flask's render_template_string if available
    try:
        html_content = render_template_string(
            template_content,
            report=json_data
        )
    except Exception as e:
        # Fall back to basic string substitution
        logger.warning(f"Could not render template with Flask: {e}")
        # Very basic templating fallback - just replace simple variables
        html_content = template_content

        # Replace basic variables
        html_content = html_content.replace("{{ report.report_metadata.time_range_start }}", json_data["report_metadata"]["time_range_start"])
        html_content = html_content.replace("{{ report.report_metadata.time_range_end }}", json_data["report_metadata"]["time_range_end"])
        html_content = html_content.replace("{{ report.report_metadata.generated_at }}", json_data["report_metadata"]["generated_at"])
        html_content = html_content.replace("{{ report.report_metadata.version }}", json_data["report_metadata"]["version"])

        html_content = html_content.replace("{{ report.summary.total_privilege_events }}", str(json_data["summary"]["total_privilege_events"]))
        html_content = html_content.replace("{{ report.summary.total_grants_assignments }}", str(json_data["summary"]["total_grants_assignments"]))
        html_content = html_content.replace("{{ report.summary.total_revocations_removals }}", str(json_data["summary"]["total_revocations_removals"]))
        html_content = html_content.replace("{{ report.summary.total_emergency_access_events }}", str(json_data["summary"]["total_emergency_access_events"]))

        # Replace severity counts
        html_content = html_content.replace("{{ report.summary.severity_counts.critical }}", str(json_data["summary"]["severity_counts"].get("critical", 0)))
        html_content = html_content.replace("{{ report.summary.severity_counts.error }}", str(json_data["summary"]["severity_counts"].get("error", 0)))
        html_content = html_content.replace("{{ report.summary.severity_counts.warning }}", str(json_data["summary"]["severity_counts"].get("warning", 0)))
        html_content = html_content.replace("{{ report.summary.severity_counts.info }}", str(json_data["summary"]["severity_counts"].get("info", 0)))

        # Add issue types chart data
        html_content = html_content.replace("{{ report.summary.issue_types|tojson }}", json.dumps(json_data["summary"]["issue_types"]))

        # Replace potential issues count
        html_content = html_content.replace("{{ report.summary.potential_issues_count }}", str(json_data["summary"]["potential_issues_count"]))

        # Handle conditional for issues table
        if json_data["potential_issues"]:
            # Replace {% if report.potential_issues %} ... {% else %} ... {% endif %}
            pattern = r"{% if report\.potential_issues %}(.*?){% else %}.*?{% endif %}"
            table_content = re.search(pattern, html_content, re.DOTALL).group(1)

            # Handle for loop for issues
            issue_rows = ""
            for issue in json_data["potential_issues"]:
                issue_row = """
                <tr class="severity-{severity}">
                    <td>{type}</td>
                    <td>{severity}</td>
                    <td>{user}</td>
                    <td>{timestamp}</td>
                    <td>{details}</td>
                </tr>
                """.format(
                    type=issue.get("type", ""),
                    severity=issue.get("severity", ""),
                    user=issue.get("user", ""),
                    timestamp=issue.get("timestamp", ""),
                    details=issue.get("details", "")
                )
                issue_rows += issue_row

            # Replace loop template with actual rows
            table_content = re.sub(
                r"{% for issue in report\.potential_issues %}.*?{% endfor %}",
                issue_rows,
                table_content,
                flags=re.DOTALL
            )

            # Replace conditional with table content
            html_content = re.sub(
                r"{% if report\.potential_issues %}.*?{% endif %}",
                table_content,
                html_content,
                flags=re.DOTALL
            )
        else:
            # Replace with "no issues" message
            html_content = re.sub(
                r"{% if report\.potential_issues %}.*?{% else %}(.*?){% endif %}",
                r"\1",
                html_content,
                flags=re.DOTALL
            )

    # Write to file if output_file is provided
    if output_file:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(html_content)
            logger.info(f"HTML privilege audit report saved to {output_file}")
        except IOError as e:
            logger.error(f"Failed to write HTML report to {output_file}: {e}")

    return html_content

def send_alert_for_findings(analysis_results: Dict[str, Any], threshold_level: str = "medium") -> bool:
    """Send alert notifications for critical and high severity findings."""
    if not NOTIFICATION_AVAILABLE:
        logger.warning("Notification service not available. Skipping alerts.")
        return False

    # Skip if no issues
    if not analysis_results["potential_issues"]:
        return True

    # Filter critical and error issues
    critical_issues = [issue for issue in analysis_results["potential_issues"]
                      if issue.get("severity") == SEVERITY_CRITICAL]
    error_issues = [issue for issue in analysis_results["potential_issues"]
                   if issue.get("severity") == SEVERITY_ERROR]

    # Only send alerts for critical/error based on threshold
    if threshold_level == "high" and not critical_issues:
        return True

    if threshold_level == "medium" and not (critical_issues or error_issues):
        return True

    # Prepare alert message
    subject = f"ALERT: {len(critical_issues)} Critical, {len(error_issues)} Error privilege issues detected"

    message = f"""
    Privilege Audit Alert
    ---------------------
    Time: {datetime.now(timezone.utc).isoformat()}

    Critical Issues: {len(critical_issues)}
    Error Issues: {len(error_issues)}

    Details:
    """

    # Add critical issues
    if critical_issues:
        message += "\n--- CRITICAL ISSUES ---\n"
        for idx, issue in enumerate(critical_issues[:5], 1):
            message += f"{idx}. {issue.get('type')}: {issue.get('details')}\n"
        if len(critical_issues) > 5:
            message += f"... and {len(critical_issues) - 5} more critical issues\n"

    # Add error issues
    if error_issues:
        message += "\n--- ERROR ISSUES ---\n"
        for idx, issue in enumerate(error_issues[:5], 1):
            message += f"{idx}. {issue.get('type')}: {issue.get('details')}\n"
        if len(error_issues) > 5:
            message += f"... and {len(error_issues) - 5} more error issues\n"

    try:
        # Send notification using the service
        notification_sent = send_notification(
            channel="security",
            subject=subject,
            message=message,
            priority="high"
        )

        if notification_sent:
            logger.info(f"Alert sent for {len(critical_issues)} critical and {len(error_issues)} error issues")
        else:
            logger.warning("Failed to send alert notification")

        return notification_sent
    except Exception as e:
        logger.error(f"Error sending alert notification: {e}")
        return False

# --- Main Execution ---
def main(app: Optional[Flask] = None):
    parser = argparse.ArgumentParser(description="Privilege Audit Tool")
    parser.add_argument("--hours", type=int, help="Analyze logs from the last N hours.")
    parser.add_argument("--days", type=int, help="Analyze logs from the last N days. Overrides --hours.")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD or ISO format). Overrides --days/--hours.")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD or ISO format). Defaults to now.")
    parser.add_argument("--user", help="Filter by specific administrator username.")
    parser.add_argument("--role", help="Filter by specific role (e.g., 'admin'). Requires log details support.")
    parser.add_argument("--output", help="Path to the output report file (format determined by --format).")
    parser.add_argument("--format", choices=["json", "html"], default="json", help="Output format (default: json)")
    parser.add_argument("--threshold", choices=["low", "medium", "high"], default="medium",
                        help="Alert threshold level (default: medium)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--env", default=os.environ.get('FLASK_ENV', 'production'), help="Application environment.")
    parser.add_argument("--no-alert", action="store_true", help="Disable automatic alerting for high-severity issues.")
    parser.add_argument("--integrity-check", action="store_true",
                       help="Perform integrity check on audit logs (experimental).")
    parser.add_argument("--detect-anomalies", action="store_true",
                       help="Use advanced anomaly detection algorithms.")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # Determine time range
    try:
        start_dt, end_dt = get_time_range_from_args(args)
        logger.info(f"Analyzing privilege events from {start_dt.isoformat()} to {end_dt.isoformat()}")
    except ValueError as e:
        logger.error(f"Error determining time range: {e}")
        sys.exit(1)

    # --- Fetch Audit Logs ---
    logger.info("Fetching relevant audit logs...")
    filters = {
        "start_time": start_dt,
        "end_time": end_dt,
        "action_types": PRIVILEGE_EVENTS,
        "limit": 10000, # Consider making this configurable or implementing pagination
    }
    if args.user:
        filters["username"] = args.user
    if args.role:
        # Role filtering depends on how roles are logged
        logger.warning("Filtering by role is informational; effectiveness depends on log details structure.")
        # Try to add role filter if supported
        try:
            filters["details_contain"] = {"role": args.role}
        except (TypeError, ValueError):
            logger.warning("Role filtering not supported by get_admin_audit_logs.")

    audit_logs = []
    try:
        # Use admin util if available
        audit_logs = get_admin_audit_logs(**filters)
        logger.info(f"Retrieved {len(audit_logs)} potential privilege-related audit logs.")

        # Log the audit access itself
        log_admin_action(
            action=ACTION_AUDIT_ACCESS,
            details={
                "audit_type": "privilege",
                "filters_applied": {k: str(v) for k, v in filters.items() if k != 'limit'},
                "logs_retrieved": len(audit_logs)
            },
            severity=SEVERITY_INFO,
            status=STATUS_SUCCESS
        )

    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}", exc_info=args.verbose)
        # Log the failure
        log_admin_action(
            action=ACTION_AUDIT_ACCESS,
            details={"audit_type": "privilege", "error": str(e)},
            severity=SEVERITY_ERROR,
            status=STATUS_FAILURE
        )
        sys.exit(1)

    # --- Perform Integrity Check (if requested) ---
    if args.integrity_check and CORE_AVAILABLE:
        logger.info("Performing audit log integrity check...")
        try:
            integrity_result = verify_audit_log_integrity(start_dt, end_dt)

            if integrity_result["status"] != "valid":
                logger.warning(f"Audit log integrity check: {integrity_result['status']}")
                logger.warning(f"Found {len(integrity_result.get('issues', []))} potential integrity issues")

                # Add integrity warning to logs
                log_admin_action(
                    action="audit.integrity",
                    details={
                        "status": integrity_result["status"],
                        "message": integrity_result.get("message", ""),
                        "issue_count": len(integrity_result.get("issues", []))
                    },
                    severity=SEVERITY_WARNING,
                    status=STATUS_WARNING
                )
            else:
                logger.info("Audit log integrity check passed.")
        except Exception as e:
            logger.error(f"Error performing integrity check: {e}", exc_info=args.verbose)

    # --- Analyze Logs ---
    logger.info(f"Analyzing logs for privilege activities with threshold level: {args.threshold}...")
    try:
        # Use standard analysis
        analysis_results = analyze_privilege_logs(audit_logs, args.threshold)

        # If advanced anomaly detection requested and available, enhance results
        if args.detect_anomalies and CORE_AVAILABLE:
            try:
                logger.info("Running advanced anomaly detection...")
                anomalies = detect_admin_anomalies(start_dt, end_dt, args.threshold)

                # Add anomalies to our results if not already present
                existing_ids = {issue.get('log_id') for issue in analysis_results["potential_issues"]
                               if issue.get('log_id') is not None}

                for anomaly in anomalies:
                    anomaly_id = anomaly.get('log_id')
                    if anomaly_id is not None and anomaly_id not in existing_ids:
                        # Transform to our format
                        analysis_results["potential_issues"].append({
                            "type": f"anomaly_{anomaly.get('type', 'unknown')}",
                            "severity": anomaly.get('severity', SEVERITY_WARNING),
                            "log_id": anomaly_id,
                            "timestamp": anomaly.get('timestamp'),
                            "user": anomaly.get('user'),
                            "details": anomaly.get('description', "Advanced anomaly detected")
                        })
                        existing_ids.add(anomaly_id)

                logger.info(f"Added {len(anomalies)} advanced anomalies to analysis.")
            except Exception as e:
                logger.error(f"Error in advanced anomaly detection: {e}", exc_info=args.verbose)
    except Exception as e:
        logger.error(f"Failed during log analysis: {e}", exc_info=args.verbose)
        sys.exit(1)

    # --- Send alerts if critical/high severity issues detected (and not disabled) ---
    if not args.no_alert and (analysis_results["potential_issues"]):
        try:
            alert_sent = send_alert_for_findings(analysis_results, args.threshold)
            if not alert_sent:
                logger.warning("Failed to send alerts for critical findings.")
        except Exception as e:
            logger.error(f"Error sending alerts: {e}", exc_info=args.verbose)

    # --- Generate Report ---
    logger.info(f"Generating {args.format} privilege audit report...")
    try:
        if args.format == "html":
            generate_html_report(analysis_results, args.output, start_dt, end_dt)
        else:
            # Default to JSON
            generate_json_report(analysis_results, args.output, start_dt, end_dt)
    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=args.verbose)
        sys.exit(1)

    logger.info("Privilege audit finished successfully.")

if __name__ == "__main__":
    flask_app = None
    if CORE_AVAILABLE:
        try:
            # Create app using the factory, pass environment from args or ENV
            env_name = os.environ.get('FLASK_ENV') or 'production'
            flask_app = create_app(env_name)
        except Exception as e:
            logger.warning(f"Could not create Flask app context: {e}. Running without app context.")

    if flask_app:
        with flask_app.app_context():
            main(app=flask_app)
    else:
        # Run without app context if core components are unavailable or app creation failed
        main()
