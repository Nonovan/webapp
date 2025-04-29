"""
Security Event Correlation Engine for Cloud Infrastructure Platform

This tool analyzes security events from various sources to detect complex attack
patterns and correlated security threats based on predefined rules.
"""

import argparse
import json
import logging
import os
import sys
import yaml
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union, Set

# Adjust path to import application components
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Import Core & Admin Components ---
try:
    from flask import Flask
    # Use core security functions for event fetching and logging
    from core.security.cs_audit import get_recent_security_events, log_security_event
    from core.security.cs_constants import SECURITY_CONFIG
    from models.audit_log import AuditLog
    from extensions import db, metrics, get_redis_client # If needed for direct access
    # Use admin utils if available
    from admin.utils.audit_utils import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_INFO
    # Import monitoring utils
    from admin.security.monitoring.utils.event_normalizer import normalize_event, EVENT_NORMALIZER_AVAILABLE
    from admin.security.monitoring.utils.indicator_matcher import match_indicators, INDICATOR_MATCHER_AVAILABLE
    from admin.security.monitoring.utils.alert_formatter import format_security_alert, ALERT_FORMATTER_AVAILABLE, sanitize_alert_data
    # Import notification service if available
    from services.notification import send_notification
    CORE_AVAILABLE = True
    NOTIFICATION_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Error importing application modules: {e}", file=sys.stderr)
    print("Core application context or utils may not be available. Functionality might be limited.", file=sys.stderr)
    CORE_AVAILABLE = False
    NOTIFICATION_AVAILABLE = False
    # Define dummy functions/classes if needed
    def get_recent_security_events(*args, **kwargs) -> List[Dict[str, Any]]: return []
    def log_security_event(*args, **kwargs): pass
    def normalize_event(event, **kwargs): return event
    def match_indicators(event, **kwargs): return []
    def format_security_alert(**kwargs): return "Alert: " + kwargs.get('description', 'Unknown issue')
    def sanitize_alert_data(data): return data
    def send_notification(*args, **kwargs): pass
    EVENT_NORMALIZER_AVAILABLE = False
    INDICATOR_MATCHER_AVAILABLE = False
    ALERT_FORMATTER_AVAILABLE = False
    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_INFO = "info"
    class AuditLog:
        SEVERITY_CRITICAL = "critical"
        SEVERITY_HIGH = "high"
        SEVERITY_MEDIUM = "medium"
        SEVERITY_INFO = "info"


# --- Configuration ---
ADMIN_CONFIG_DIR = os.path.join(project_root, "admin", "security", "monitoring", "config")
DEFAULT_RULES_DIR = os.path.join(ADMIN_CONFIG_DIR, "detection_rules")
LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
DEFAULT_LOG_FILE = LOG_DIR / "security_event_correlator.log"
DEFAULT_REPORT_DIR = Path(os.environ.get("SECURITY_REPORT_DIR", "/var/www/reports/security"))
DEFAULT_CORRELATION_WINDOW = SECURITY_CONFIG.get('EVENT_CORRELATION_WINDOW', 300) if CORE_AVAILABLE else 300 # seconds
DEFAULT_TEMPLATE_DIR = Path(os.path.join(os.path.dirname(__file__), "templates"))
VERSION = "1.2.0"

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=DEFAULT_LOG_FILE,
    filemode='a'
)
logger = logging.getLogger(__name__)
# Add console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)


# --- Helper Functions ---

def load_detection_rules(rules_dir: str) -> List[Dict[str, Any]]:
    """Loads detection rules from YAML files in the specified directory."""
    rules = []
    logger.info(f"Loading detection rules from: {rules_dir}")
    if not os.path.isdir(rules_dir):
        logger.error(f"Rules directory not found: {rules_dir}")
        return []

    for filename in os.listdir(rules_dir):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    if rule_data and 'rules' in rule_data:
                        loaded_count = len(rule_data['rules'])
                        rules.extend(rule_data['rules'])
                        logger.debug(f"Loaded {loaded_count} rules from {filename}")
                    else:
                        logger.warning(f"No 'rules' key found or empty file: {filename}")
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML file {filename}: {e}")
            except Exception as e:
                logger.error(f"Error reading file {filename}: {e}")
    logger.info(f"Total detection rules loaded: {len(rules)}")
    return rules

def fetch_security_events(start_time: datetime, end_time: datetime, user_id: Optional[int] = None,
                          ip_address: Optional[str] = None, event_types: Optional[List[str]] = None,
                          severity: Optional[str] = None,
                          limit: int = 10000) -> List[Dict[str, Any]]:
    """Fetches security events within the specified time range."""
    logger.info(f"Fetching security events from {start_time.isoformat()} to {end_time.isoformat()}")
    if not CORE_AVAILABLE:
        logger.warning("Core components not available. Cannot fetch events from database.")
        return []

    try:
        # Build filter parameters
        params = {
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit
        }

        # Add optional filters if provided
        if user_id:
            params["user_id"] = user_id
            logger.debug(f"Filtering events for user ID: {user_id}")

        if ip_address:
            params["ip_address"] = ip_address
            logger.debug(f"Filtering events for IP address: {ip_address}")

        if event_types:
            params["event_type"] = event_types
            logger.debug(f"Filtering events for event types: {', '.join(event_types)}")

        if severity:
            params["severity"] = severity
            logger.debug(f"Filtering events for severity: {severity}")

        # Fetch events using the core audit function
        events = get_recent_security_events(**params)
        logger.info(f"Fetched {len(events)} security events.")
        return events
    except Exception as e:
        logger.error(f"Failed to fetch security events: {e}")
        return []

def evaluate_condition(event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Evaluates if an event matches a rule's condition."""
    # Basic property matching
    if 'event_type' in condition and event.get('event_type') != condition['event_type']:
        return False

    if 'properties' in condition:
        for key, value in condition['properties'].items():
            # Handle nested properties if necessary (e.g., details.username)
            event_value = event
            for part in key.split('.'):
                if isinstance(event_value, dict):
                    event_value = event_value.get(part)
                else:
                    event_value = None
                    break
            if event_value != value:
                return False

    # Handle 'not' conditions
    if 'not' in condition:
        for key, value in condition['not'].items():
            event_value = event.get(key) # Simplified, add nesting if needed
            if event_value == value:
                return False

    # Handle regex pattern matching
    if 'patterns' in condition:
        for key, pattern in condition['patterns'].items():
            try:
                event_value = event.get(key, '')
                if isinstance(event_value, (str, bytes)):
                    if not re.search(pattern, str(event_value)):
                        return False
                else:
                    # Convert non-string values to string for pattern matching
                    if not re.search(pattern, str(event_value)):
                        return False
            except re.error:
                logger.warning(f"Invalid regex pattern in condition: '{pattern}'")
                return False
            except Exception as e:
                logger.warning(f"Error evaluating pattern '{pattern}' on field '{key}': {e}")
                return False

    # Handle range conditions (e.g., for numeric values)
    if 'range' in condition:
        for key, range_spec in condition['range'].items():
            try:
                event_value = event.get(key)
                if event_value is None:
                    return False

                # Convert to numeric if needed
                if not isinstance(event_value, (int, float)):
                    try:
                        event_value = float(event_value)
                    except (ValueError, TypeError):
                        return False

                # Check min bound if specified
                if 'min' in range_spec and event_value < range_spec['min']:
                    return False

                # Check max bound if specified
                if 'max' in range_spec and event_value > range_spec['max']:
                    return False
            except Exception as e:
                logger.warning(f"Error evaluating range condition on field '{key}': {e}")
                return False

    return True

def correlate_events(events: List[Dict[str, Any]], rules: List[Dict[str, Any]],
                    window_seconds: int) -> List[Dict[str, Any]]:
    """Correlates events based on detection rules."""
    findings = []
    logger.info(f"Starting event correlation for {len(events)} events using {len(rules)} rules.")

    # Sort events by timestamp for sequential analysis
    events.sort(key=lambda x: x.get('created_at', datetime.min.replace(tzinfo=timezone.utc)))

    for rule in rules:
        rule_id = rule.get('id', 'UNKNOWN_RULE')
        rule_name = rule.get('name', 'Unnamed Rule')
        condition = rule.get('condition', {})
        severity = rule.get('severity', SEVERITY_INFO)
        actions = rule.get('actions', [])
        threshold = condition.get('threshold', {})
        count_threshold = threshold.get('count', 1)
        timeframe = threshold.get('timeframe', window_seconds) # Use rule timeframe or default
        group_by = condition.get('group_by', None) # Optional grouping field

        logger.debug(f"Evaluating rule: {rule_id} ({rule_name})")

        # Group events by a relevant key if specified
        if group_by:
            # Dictionary to hold groups of potential matches
            grouped_matches = {}

            # Find all potential matches
            for event in events:
                if evaluate_condition(event, condition):
                    # Extract group key value from the event
                    if group_by == "user_id":
                        group_key = event.get('user_id', 'unknown_user')
                    elif group_by == "ip_address":
                        group_key = event.get('ip_address', 'unknown_ip')
                    else:
                        # Try to extract nested properties
                        parts = group_by.split('.')
                        group_key = event
                        for part in parts:
                            if isinstance(group_key, dict):
                                group_key = group_key.get(part)
                            else:
                                group_key = None
                                break

                        if group_key is None:
                            group_key = 'unknown'

                    # Add to the group
                    if group_key not in grouped_matches:
                        grouped_matches[group_key] = []
                    grouped_matches[group_key].append(event)

            # Process each group separately
            for group_key, group_events in grouped_matches.items():
                if len(group_events) < count_threshold:
                    continue  # Not enough events in this group

                # Sort events by timestamp
                group_events.sort(key=lambda x: x.get('created_at', datetime.min.replace(tzinfo=timezone.utc)))

                # Check for threshold count within the timeframe
                for i in range(len(group_events)):
                    window_start_time = group_events[i]['created_at']
                    window_end_time = window_start_time + timedelta(seconds=timeframe)
                    events_in_current_window = [group_events[i]]

                    for j in range(i + 1, len(group_events)):
                        if group_events[j]['created_at'] <= window_end_time:
                            events_in_current_window.append(group_events[j])
                        else:
                            break  # Events are sorted, no need to check further

                    if len(events_in_current_window) >= count_threshold:
                        # Correlation found for this group!
                        finding = {
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "description": rule.get('description', 'Correlation detected'),
                            "severity": severity,
                            "timestamp": events_in_current_window[-1]['created_at'],  # Last event's timestamp
                            "correlated_events": [e['id'] for e in events_in_current_window],
                            "details": {
                                "count": len(events_in_current_window),
                                "timeframe_seconds": timeframe,
                                "group_by": group_by,
                                "group_value": group_key,
                                # Add relevant common fields
                                "user_id": events_in_current_window[0].get('user_id'),
                                "ip_address": events_in_current_window[0].get('ip_address'),
                            }
                        }
                        findings.append(finding)
                        logger.warning(f"Correlation detected: Rule '{rule_id}' triggered by {len(events_in_current_window)} events for {group_by}={group_key}.")
                        break  # Found a correlation for this group, move to the next group
        else:
            # Global correlation (no grouping)
            potential_matches = [event for event in events if evaluate_condition(event, condition)]

            if len(potential_matches) < count_threshold:
                continue # Not enough potential matches for this rule

            # Check for threshold count within the timeframe
            for i in range(len(potential_matches)):
                window_start_time = potential_matches[i]['created_at']
                window_end_time = window_start_time + timedelta(seconds=timeframe)
                events_in_current_window = [potential_matches[i]]

                for j in range(i + 1, len(potential_matches)):
                    if potential_matches[j]['created_at'] <= window_end_time:
                        events_in_current_window.append(potential_matches[j])
                    else:
                        break # Events are sorted, no need to check further

                if len(events_in_current_window) >= count_threshold:
                    # Correlation found!
                    finding = {
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "description": rule.get('description', 'Correlation detected'),
                        "severity": severity,
                        "timestamp": events_in_current_window[-1]['created_at'], # Timestamp of the last event in sequence
                        "correlated_events": [e['id'] for e in events_in_current_window], # Log IDs or full events
                        "details": {
                            "count": len(events_in_current_window),
                            "timeframe_seconds": timeframe,
                            # Add relevant common fields like user_id, ip_address if consistent
                            "user_id": events_in_current_window[0].get('user_id'),
                            "ip_address": events_in_current_window[0].get('ip_address'),
                        }
                    }
                    findings.append(finding)
                    logger.warning(f"Correlation detected: Rule '{rule_id}' triggered by {len(events_in_current_window)} events.")
                    # Avoid redundant findings for the same set of events (more complex logic needed for robust de-duplication)
                    break # Move to the next rule once a correlation is found for this rule

    logger.info(f"Correlation analysis completed. Found {len(findings)} potential correlations.")

    # Deduplication - avoid alerting on the same events multiple times
    deduplicated_findings = []
    seen_event_sets = set()

    for finding in findings:
        # Create a frozen set of the correlated event IDs for deduplication
        events_set = frozenset(finding['correlated_events'])
        if events_set not in seen_event_sets:
            seen_event_sets.add(events_set)
            deduplicated_findings.append(finding)

    if len(findings) > len(deduplicated_findings):
        logger.info(f"Removed {len(findings) - len(deduplicated_findings)} duplicate findings.")

    return deduplicated_findings

def report_findings(findings: List[Dict[str, Any]], output_file: str, output_format: str,
                    start_time: datetime, end_time: datetime):
    """Reports the correlation findings."""
    if not findings:
        logger.info("No correlations found to report.")
        return

    logger.info(f"Reporting {len(findings)} correlations to {output_file} in {output_format} format.")

    try:
        if output_format == 'json':
            # Convert datetime objects to ISO strings for JSON serialization
            serializable_findings = []
            for finding in findings:
                finding_copy = finding.copy()
                if isinstance(finding_copy.get('timestamp'), datetime):
                    finding_copy['timestamp'] = finding_copy['timestamp'].isoformat()
                serializable_findings.append(finding_copy)

            report_data = {
                "metadata": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "time_range": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat()
                    },
                    "version": VERSION
                },
                "findings": serializable_findings,
                "summary": {
                    "total": len(findings),
                    "by_severity": count_findings_by_severity(findings),
                    "by_rule": count_findings_by_rule(findings)
                }
            }

            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)

        elif output_format == 'text':
            with open(output_file, 'w') as f:
                f.write("Security Event Correlation Report\n")
                f.write("=================================\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Time Range: {start_time.isoformat()} to {end_time.isoformat()}\n\n")

                # Add summary information
                severity_counts = count_findings_by_severity(findings)
                f.write("Summary:\n")
                f.write("---------\n")
                f.write(f"Total correlations: {len(findings)}\n")
                for severity, count in severity_counts.items():
                    f.write(f"  {severity.upper()}: {count}\n")
                f.write("\n")

                # Add detailed findings
                for finding in findings:
                    f.write(f"Rule ID: {finding['rule_id']} ({finding['rule_name']})\n")
                    f.write(f"Severity: {finding['severity'].upper()}\n")
                    f.write(f"Timestamp: {finding['timestamp'].isoformat() if isinstance(finding.get('timestamp'), datetime) else finding.get('timestamp')}\n")
                    f.write(f"Description: {finding['description']}\n")
                    f.write(f"Details: {json.dumps(finding.get('details', {}))}\n")
                    f.write(f"Correlated Event IDs: {', '.join(map(str, finding.get('correlated_events', [])))}\n")
                    f.write("---------------------------------\n\n")

        elif output_format == 'html':
            generate_html_report(findings, output_file, start_time, end_time)

        else:
            logger.error(f"Unsupported output format: {output_format}")
            return

        logger.info(f"Report successfully saved to {output_file}")

    except Exception as e:
        logger.error(f"Failed to write report file {output_file}: {e}")
        raise

def generate_html_report(findings: List[Dict[str, Any]], output_file: str,
                        start_time: datetime, end_time: datetime):
    """Generates an HTML report for security event correlations."""
    try:
        # Check for custom template
        template_file = DEFAULT_TEMPLATE_DIR / "correlation_report.html"
        custom_template = template_file.exists()

        # Basic HTML structure if no custom template
        if not custom_template:
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Event Correlation Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        header {{
            background-color: #0078d4;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h1, h2, h3 {{
            margin-top: 0;
        }}
        .timestamp {{
            font-size: 0.9em;
            color: #ddd;
        }}
        .metadata {{
            background-color: #f8f8f8;
            padding: 15px;
            margin-bottom: 20px;
            border-left: 5px solid #0078d4;
        }}
        .metadata p {{
            margin: 5px 0;
        }}
        .summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            flex: 1;
            min-width: 200px;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }}
        .count {{
            font-size: 24px;
            font-weight: bold;
        }}
        .critical {{
            background-color: #fde0dd;
            border-left: 5px solid #e41a1c;
        }}
        .high {{
            background-color: #fff3de;
            border-left: 5px solid #ff7f00;
        }}
        .medium {{
            background-color: #ffffcc;
            border-left: 5px solid #ffcc00;
        }}
        .low, .info {{
            background-color: #e5f5e0;
            border-left: 5px solid #4daf4a;
        }}
        .findings h3 {{
            color: #0078d4;
            border-bottom: 1px solid #0078d4;
            padding-bottom: 5px;
        }}
        .finding-item {{
            padding: 10px;
            margin-bottom: 15px;
            border-left: 3px solid #ddd;
            background-color: #f9f9f9;
        }}
        .finding-item.critical {{
            border-left-color: #e41a1c;
        }}
        .finding-item.high {{
            border-left-color: #ff7f00;
        }}
        .finding-item.medium {{
            border-left-color: #ffcc00;
        }}
        .finding-item.low, .finding-item.info {{
            border-left-color: #4daf4a;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.9em;
            color: #777;
        }}
        .detail-toggle {{
            cursor: pointer;
            color: #0078d4;
            text-decoration: underline;
            display: inline-block;
            margin-top: 10px;
        }}
        .details-content {{
            display: none;
            padding: 10px;
            background-color: #f0f0f0;
            margin-top: 10px;
            border-radius: 4px;
        }}
        @media print {{
            body {{
                background-color: white;
            }}
            .container {{
                box-shadow: none;
            }}
            .no-print {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Event Correlation Report</h1>
            <p class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="metadata">
            <p><strong>Analysis Period:</strong> {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Report Version:</strong> {VERSION}</p>
        </div>

        <div class="summary">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="count">{len(findings)}</div>
            </div>
"""

            # Add severity counts
            severity_counts = count_findings_by_severity(findings)
            for severity, count in severity_counts.items():
                if count > 0:
                    html_content += f"""
            <div class="card {severity.lower()}">
                <h3>{severity.capitalize()}</h3>
                <div class="count">{count}</div>
            </div>"""

            html_content += """
        </div>

        <div class="findings">
            <h2>Correlation Findings</h2>
"""

            # Group findings by severity for better organization
            grouped_findings = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }

            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                if severity in grouped_findings:
                    grouped_findings[severity].append(finding)
                else:
                    grouped_findings['info'].append(finding)

            # Order severities from highest to lowest
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if grouped_findings[severity]:
                    html_content += f"""
            <h3>{severity.capitalize()} Severity Findings ({len(grouped_findings[severity])})</h3>
"""

                    # Add each finding in this severity group
                    for idx, finding in enumerate(grouped_findings[severity]):
                        # Sanitize finding details for HTML display
                        safe_finding = sanitize_alert_data(finding) if ALERT_FORMATTER_AVAILABLE else finding

                        # Format timestamp
                        timestamp = finding.get('timestamp')
                        if isinstance(timestamp, datetime):
                            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            timestamp_str = str(timestamp)

                        html_content += f"""
            <div class="finding-item {severity}">
                <h4>{safe_finding['rule_name']}</h4>
                <p><strong>Rule ID:</strong> {safe_finding['rule_id']}</p>
                <p><strong>Timestamp:</strong> {timestamp_str}</p>
                <p><strong>Description:</strong> {safe_finding['description']}</p>
                <p><strong>Event Count:</strong> {safe_finding.get('details', {}).get('count', 'Unknown')}</p>
"""

                        # Add user and IP if available
                        details = safe_finding.get('details', {})
                        if details.get('user_id'):
                            html_content += f"""                <p><strong>User ID:</strong> {details['user_id']}</p>\n"""
                        if details.get('ip_address'):
                            html_content += f"""                <p><strong>IP Address:</strong> {details['ip_address']}</p>\n"""

                        # Add details toggle
                        html_content += f"""
                <div class="detail-toggle" onclick="toggleDetails('finding-{idx}')">Show Details</div>
                <div class="details-content" id="finding-{idx}">
                    <p><strong>Correlated Events:</strong> {', '.join(map(str, safe_finding.get('correlated_events', [])))}</p>
                    <p><strong>Details:</strong> <pre>{json.dumps(safe_finding.get('details', {}), indent=2)}</pre></p>
                </div>
            </div>
"""

            # Close the HTML content
            html_content += """
        </div>

        <div class="no-print" style="text-align: center; margin: 30px 0;">
            <button onclick="window.print()" style="padding: 10px 20px; background-color: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer;">
                Print Report
            </button>
        </div>

        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Security Event Correlator</p>
            <p>Version {VERSION}</p>
        </div>
    </div>

    <script>
        function toggleDetails(id) {
            const detailsElem = document.getElementById(id);
            const toggle = detailsElem.previousElementSibling;

            if (detailsElem.style.display === 'block') {
                detailsElem.style.display = 'none';
                toggle.textContent = 'Show Details';
            } else {
                detailsElem.style.display = 'block';
                toggle.textContent = 'Hide Details';
            }
        }
    </script>
</body>
</html>
"""
        else:
            # Use the custom template file
            with open(template_file, 'r') as f:
                html_content = f.read()

            # Replace template variables with actual content
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            html_content = html_content.replace('{{generated_timestamp}}', timestamp)
            html_content = html_content.replace('{{start_time}}', start_time.strftime('%Y-%m-%d %H:%M:%S'))
            html_content = html_content.replace('{{end_time}}', end_time.strftime('%Y-%m-%d %H:%M:%S'))
            html_content = html_content.replace('{{version}}', VERSION)
            html_content = html_content.replace('{{findings_count}}', str(len(findings)))

            # Replace severity counts
            severity_counts = count_findings_by_severity(findings)
            for severity, count in severity_counts.items():
                html_content = html_content.replace(f'{{{{count_{severity}}}}}', str(count))

            # Build the findings content
            findings_html = ""
            for idx, finding in enumerate(findings):
                # Sanitize finding details for HTML display
                safe_finding = sanitize_alert_data(finding) if ALERT_FORMATTER_AVAILABLE else finding

                # Format timestamp
                timestamp = finding.get('timestamp')
                if isinstance(timestamp, datetime):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = str(timestamp)

                severity = finding.get('severity', 'info').lower()
                details = safe_finding.get('details', {})

                findings_html += f"""
                <div class="finding-item {severity}">
                    <h4>{safe_finding['rule_name']}</h4>
                    <p><strong>Rule ID:</strong> {safe_finding['rule_id']}</p>
                    <p><strong>Timestamp:</strong> {timestamp_str}</p>
                    <p><strong>Severity:</strong> {severity.upper()}</p>
                    <p><strong>Description:</strong> {safe_finding['description']}</p>
                """

                if details.get('user_id'):
                    findings_html += f"""<p><strong>User ID:</strong> {details['user_id']}</p>\n"""
                if details.get('ip_address'):
                    findings_html += f"""<p><strong>IP Address:</strong> {details['ip_address']}</p>\n"""

                findings_html += f"""
                    <p><strong>Event Count:</strong> {details.get('count', 'Unknown')}</p>
                    <div class="detail-toggle" onclick="toggleDetails('finding-{idx}')">Show Details</div>
                    <div class="details-content" id="finding-{idx}">
                        <p><strong>Correlated Events:</strong> {', '.join(map(str, safe_finding.get('correlated_events', [])))}</p>
                        <p><strong>Details:</strong> <pre>{json.dumps(safe_finding.get('details', {}), indent=2)}</pre></p>
                    </div>
                </div>
                """

            # Replace findings placeholder
            html_content = html_content.replace('{{findings_content}}', findings_html)

        # Write the HTML to file
        with open(output_file, 'w') as f:
            f.write(html_content)

        logger.info(f"HTML report generated successfully at {output_file}")

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        raise

def count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1

    return counts

def count_findings_by_rule(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts findings by rule ID."""
    counts = {}

    for finding in findings:
        rule_id = finding.get('rule_id', 'unknown')
        if rule_id in counts:
            counts[rule_id] += 1
        else:
            counts[rule_id] = 1

    return counts

def trigger_alerts(findings: List[Dict[str, Any]], threshold: str = "medium"):
    """Triggers alerts based on high/critical severity findings."""
    if not CORE_AVAILABLE or not ALERT_FORMATTER_AVAILABLE:
        logger.warning("Alerting disabled: Core components or Alert Formatter not available.")
        return

    # Filter findings based on threshold
    alert_findings = []
    if threshold.lower() == "low":
        # Alert on all findings
        alert_findings = findings
    elif threshold.lower() == "medium":
        # Alert on medium, high, and critical findings
        alert_findings = [f for f in findings if f.get('severity') in [SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]]
    elif threshold.lower() == "high":
        # Alert only on high and critical findings
        alert_findings = [f for f in findings if f.get('severity') in [SEVERITY_HIGH, SEVERITY_CRITICAL]]
    else:
        # Default to medium
        alert_findings = [f for f in findings if f.get('severity') in [SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]]

    if not alert_findings:
        logger.info(f"No findings met the {threshold} threshold for alerting.")
        return

    logger.info(f"Triggering alerts for {len(alert_findings)} findings that met the {threshold} threshold.")

    for finding in alert_findings:
        severity = finding.get('severity', SEVERITY_INFO)
        logger.info(f"Processing alert for finding: {finding['rule_id']} (severity: {severity})")

        try:
            # Log a security event for the correlation itself
            log_security_event(
                event_type=f"correlation.{finding['rule_id']}",
                description=f"Correlation Detected: {finding['rule_name']}",
                severity=severity,
                details=finding, # Include full finding details
                # Potentially add user/IP if consistent across correlated events
                user_id=finding.get('details', {}).get('user_id'),
                ip_address=finding.get('details', {}).get('ip_address')
            )

            # Format the alert content
            alert_content = format_security_alert(
                rule_id=finding['rule_id'],
                rule_name=finding['rule_name'],
                description=finding['description'],
                severity=severity,
                timestamp=finding['timestamp'],
                details=finding.get('details'),
                correlated_events=finding.get('correlated_events'),
                format='json' # Or desired format for alert system
            )

            # Send notification if service is available
            if NOTIFICATION_AVAILABLE:
                notification_sent = send_notification(
                    channel="security_alerts",
                    subject=f"Security Correlation Alert: {finding['rule_name']}",
                    message=alert_content,
                    priority=severity
                )

                if notification_sent:
                    logger.info(f"Alert notification sent for rule '{finding['rule_id']}'")
                else:
                    logger.warning(f"Failed to send notification for rule '{finding['rule_id']}'")
            else:
                logger.info(f"Alert content ready but notification service not available: {alert_content}")

        except Exception as e:
            logger.error(f"Failed to trigger alert for rule '{finding['rule_id']}': {e}")


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Security Event Correlation Engine")
    parser.add_argument(
        "--hours", type=int, default=24,
        help="Number of hours of past events to analyze (default: 24)"
    )
    parser.add_argument(
        "--rules-dir", default=DEFAULT_RULES_DIR,
        help=f"Directory containing detection rule YAML files (default: {DEFAULT_RULES_DIR})"
    )
    parser.add_argument(
        "--window", type=int, default=DEFAULT_CORRELATION_WINDOW,
        help=f"Default correlation time window in seconds (default: {DEFAULT_CORRELATION_WINDOW})"
    )
    parser.add_argument(
        "--output-file",
        help="Path to save the correlation report file. (default: auto-generated path)"
    )
    parser.add_argument(
        "--output-format", choices=['json', 'text', 'html'], default='json',
        help="Format for the output report (default: json)."
    )
    parser.add_argument(
        "--limit", type=int, default=10000,
        help="Maximum number of events to fetch (default: 10000)"
    )
    parser.add_argument(
        "--user-id", type=int,
        help="Filter events for a specific user ID."
    )
    parser.add_argument(
        "--ip-address",
        help="Filter events for a specific IP address."
    )
    parser.add_argument(
        "--event-types",
        help="Comma-separated list of event types to include."
    )
    parser.add_argument(
        "--severity", choices=['info', 'medium', 'high', 'critical'],
        help="Filter events by minimum severity level."
    )
    parser.add_argument(
        "--alert-threshold", choices=['low', 'medium', 'high'], default='medium',
        help="Threshold for triggering alerts (default: medium)."
    )
    parser.add_argument(
        "--trigger-alerts", action='store_true',
        help="Trigger alerts for findings that meet the alert threshold (requires core components)."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging."
    )
    parser.add_argument(
        "--version", action='version',
        version=f'Security Event Correlator {VERSION}',
        help="Show the version and exit."
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # Determine time range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=args.hours)

    # Set default output file if not specified
    if not args.output_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extension = ".html" if args.output_format == 'html' else ".json" if args.output_format == 'json' else ".txt"
        args.output_file = os.path.join(DEFAULT_REPORT_DIR, f"correlation_report_{timestamp}{extension}")

    logger.info("Starting Security Event Correlator...")
    logger.info(f"Time range: {start_time.isoformat()} to {end_time.isoformat()}")
    logger.info(f"Rules directory: {args.rules_dir}")
    logger.info(f"Output file: {args.output_file} (Format: {args.output_format})")

    # 1. Load Rules
    rules = load_detection_rules(args.rules_dir)
    if not rules:
        logger.error("No detection rules loaded. Exiting.")
        sys.exit(1)

    # 2. Fetch Events
    # Parse event_types into list if provided
    event_types = None
    if args.event_types:
        event_types = [t.strip() for t in args.event_types.split(',')]
        logger.info(f"Filtering for event types: {', '.join(event_types)}")

    events = fetch_security_events(
        start_time=start_time,
        end_time=end_time,
        user_id=args.user_id,
        ip_address=args.ip_address,
        event_types=event_types,
        severity=args.severity,
        limit=args.limit
    )

    if not events:
        logger.warning("No security events fetched for the specified time range.")
        # Decide whether to exit or continue (maybe rules don't need events?)
        # For correlation, we need events.
        logger.info("Exiting due to lack of events.")
        sys.exit(0)

    # Optional: Normalize events if needed by rules
    if EVENT_NORMALIZER_AVAILABLE:
        logger.debug("Normalizing fetched events...")
        normalized_events = [normalize_event(e, source_type='audit_log') for e in events] # Assuming audit log format
        events = normalized_events
    else:
        logger.debug("Event normalizer not available, using raw events.")


    # 3. Correlate Events
    findings = correlate_events(events, rules, args.window)

    # 4. Report Findings
    report_findings(findings, args.output_file, args.output_format, start_time, end_time)

    # 5. Trigger Alerts (Optional)
    if args.trigger_alerts:
        trigger_alerts(findings, args.alert_threshold)

    logger.info(f"Security Event Correlator finished. Found {len(findings)} correlations.")

    # Return success code
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)
