"""
Administrative Action Auditing Utility

This script provides tools for reviewing, filtering, and reporting on administrative
actions recorded in the system's audit log. It supports filtering by user,
time range, action type, and generating reports in various formats. It can also
perform basic anomaly detection and integrity checks.

Usage:
    python admin/scripts/admin_audit.py <command> [options]

Commands:
    review      Review administrative audit logs with filters.
    report      Generate an audit report based on filters.
    anomalies   Detect potential anomalies in administrative actions.
    integrity   Perform basic integrity checks on the audit log (experimental).

Examples:
    # Review admin actions from the last 24 hours
    python admin/scripts/admin_audit.py review --hours 24

    # Generate a CSV report of config changes by user 'admin.user' in the last 7 days
    python admin/scripts/admin_audit.py report --format csv --output config_changes.csv --user admin.user --days 7 --action-type config_change

    # Detect anomalies in admin actions over the last 30 days
    python admin/scripts/admin_audit.py anomalies --days 30 --threshold medium --output anomalies.json

    # Review logs between specific dates
    python admin/scripts/admin_audit.py review --start-date 2023-11-01 --end-date 2023-11-30 --user-id 5

Options:
    --output <file>     Path to the output file for reports.
    --format <fmt>      Report format (json, csv, text). Default: text.
    --hours <N>         Filter logs from the last N hours.
    --days <N>          Filter logs from the last N days. Overrides --hours.
    --start-date <dt>   Start date (YYYY-MM-DD). Overrides --days/--hours.
    --end-date <dt>     End date (YYYY-MM-DD). Defaults to now.
    --user <username>   Filter by administrator username.
    --user-id <id>      Filter by administrator user ID.
    --action-type <type> Filter by specific action/event type (e.g., 'config_change', 'user_created').
    --severity <level>  Filter by severity (info, warning, error, critical).
    --limit <N>         Maximum number of entries to fetch/display (default: 1000).
    --verbose           Enable verbose logging.
    --env <env>         Application environment (default: production).
    --threshold <level> Threshold level for anomaly detection (low, medium, high).
"""

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

# Adjust path to import application components
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from flask import Flask
    from extensions import db
    from models.security.audit_log import AuditLog
    from models.auth.user import User
    from core.factory import create_app
    from core.security.cs_audit import detect_security_anomalies

    # Import admin audit utilities
    from admin.utils.audit_utils import (
        get_admin_audit_logs,
        export_admin_audit_logs,
        detect_admin_anomalies,
        verify_audit_log_integrity,
        log_admin_action,
        ADMIN_ACTION_CATEGORY,
        ADMIN_EVENT_PREFIX,
        ACTION_AUDIT_ACCESS,
        SEVERITY_INFO,
        STATUS_SUCCESS
    )
    AUDIT_UTILS_AVAILABLE = True
except ImportError as e:
    print(f"Error importing application modules: {e}", file=sys.stderr)
    print("Please ensure the script is run within the project environment or PYTHONPATH is set correctly.", file=sys.stderr)
    AUDIT_UTILS_AVAILABLE = False
    sys.exit(1)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ['json', 'csv', 'text']
DEFAULT_LIMIT = 1000

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Administrative Action Auditing Utility.")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Command to execute')

    # Common arguments for filtering and environment
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--hours", type=int, help="Filter logs from the last N hours.")
    common_parser.add_argument("--days", type=int, help="Filter logs from the last N days. Overrides --hours.")
    common_parser.add_argument("--start-date", help="Start date (YYYY-MM-DD). Overrides --days/--hours.")
    common_parser.add_argument("--end-date", help="End date (YYYY-MM-DD). Defaults to now.")
    common_parser.add_argument("--user", help="Filter by administrator username.")
    common_parser.add_argument("--user-id", type=int, help="Filter by administrator user ID.")
    common_parser.add_argument("--action-type", help="Filter by specific action/event type (e.g., 'config_change').")
    common_parser.add_argument("--severity", choices=['info', 'warning', 'error', 'critical'],
                               help="Filter by severity level.")
    common_parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum number of entries (default: {DEFAULT_LIMIT}).")
    common_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    common_parser.add_argument("--env", default="production", help="Application environment (default: production).")

    # Subparser for 'review'
    review_parser = subparsers.add_parser('review', parents=[common_parser], help='Review administrative audit logs.')
    review_parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format (default: text).")

    # Subparser for 'report'
    report_parser = subparsers.add_parser('report', parents=[common_parser], help='Generate an audit report.')
    report_parser.add_argument("--output", required=True, help="Path to the output file for the report.")
    report_parser.add_argument("--format", choices=SUPPORTED_FORMATS, required=True, help="Report format (json, csv, text).")

    # Subparser for 'anomalies'
    anomalies_parser = subparsers.add_parser('anomalies', parents=[common_parser], help='Detect potential anomalies in administrative actions.')
    anomalies_parser.add_argument("--threshold", choices=['low', 'medium', 'high'], default='medium',
                                 help="Anomaly detection sensitivity threshold.")
    anomalies_parser.add_argument("--output", help="Optional output file for anomaly report (JSON format).")

    # Subparser for 'integrity'
    integrity_parser = subparsers.add_parser('integrity', parents=[common_parser], help='Perform basic integrity checks (experimental).')
    integrity_parser.add_argument("--check-gaps", action="store_true", help="Check for potential time gaps in logs.")
    integrity_parser.add_argument("--check-sequence", action="store_true", help="Check for sequence inconsistencies.")
    integrity_parser.add_argument("--output", help="Output file for integrity check results (JSON format).")

    return parser.parse_args()

def get_time_range(args: argparse.Namespace) -> Tuple[datetime, datetime]:
    """Calculate the start and end datetime based on arguments."""
    end_dt = datetime.now(timezone.utc)
    if args.end_date:
        try:
            end_dt = datetime.strptime(args.end_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            end_dt = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        except ValueError:
            logger.error("Invalid end date format. Please use YYYY-MM-DD.")
            sys.exit(1)

    start_dt = None
    if args.start_date:
        try:
            start_dt = datetime.strptime(args.start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        except ValueError:
            logger.error("Invalid start date format. Please use YYYY-MM-DD.")
            sys.exit(1)
    elif args.days:
        start_dt = end_dt - timedelta(days=args.days)
    elif args.hours:
        start_dt = end_dt - timedelta(hours=args.hours)
    else:
        # Default to last 24 hours if no range specified for review/anomaly
        if args.command in ['review', 'anomalies']:
             start_dt = end_dt - timedelta(hours=24)
             logger.info("No time range specified. Defaulting to the last 24 hours.")
        else: # Require explicit range for reports/integrity
             logger.error("Time range must be specified using --days, --hours, or --start-date for this command.")
             sys.exit(1)

    return start_dt, end_dt

def fetch_admin_logs(app: Flask, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Fetch administrative audit logs based on filters."""
    start_dt, end_dt = get_time_range(args)

    with app.app_context():
        if AUDIT_UTILS_AVAILABLE:
            # Use the advanced admin audit utils when available
            try:
                filters = {
                    "start_time": start_dt,
                    "end_time": end_dt,
                    "limit": args.limit,
                    "offset": 0
                }

                if args.user_id is not None:
                    filters["user_id"] = args.user_id

                if args.user:
                    filters["username"] = args.user

                if args.action_type:
                    filters["action_types"] = [args.action_type]

                if args.severity:
                    filters["severity"] = args.severity

                logger.debug(f"Fetching admin logs with filters: {filters}")
                logs = get_admin_audit_logs(**filters)

                # Log the audit access
                log_admin_action(
                    action=ACTION_AUDIT_ACCESS,
                    details={
                        "command": args.command,
                        "filters": {k: str(v) for k, v in filters.items()},
                        "count": len(logs)
                    },
                    severity=SEVERITY_INFO,
                    status=STATUS_SUCCESS
                )

                return logs

            except Exception as e:
                logger.error(f"Failed to retrieve logs using audit_utils: {e}")
                # Fall back to direct querying if the utils method fails

        # Fallback when audit utils are unavailable or failed
        logger.debug("Falling back to direct database query for admin logs")
        query = AuditLog.query

        # Filter primarily for administrative actions
        admin_categories = [AuditLog.EVENT_CATEGORY_ADMIN, AuditLog.EVENT_CATEGORY_SECURITY]
        admin_event_types = [
            AuditLog.EVENT_ADMIN_ACTION, AuditLog.EVENT_CONFIG_CHANGE,
            AuditLog.EVENT_ROLE_ASSIGNED, AuditLog.EVENT_ROLE_REMOVED,
            AuditLog.EVENT_PERMISSION_GRANTED, AuditLog.EVENT_PERMISSION_REVOKED,
        ]

        if args.action_type:
             query = query.filter(AuditLog.event_type == args.action_type)
        else:
             query = query.filter(
                 (AuditLog.category.in_(admin_categories)) |
                 (AuditLog.event_type.in_(admin_event_types))
             )

        query = query.filter(AuditLog.created_at.between(start_dt, end_dt))

        # User filtering
        user_id_to_filter = args.user_id
        if args.user:
            user = User.query.filter_by(username=args.user).first()
            if user:
                user_id_to_filter = user.id
            else:
                logger.warning(f"Username '{args.user}' not found. No logs will be returned for this user filter.")
                return []

        if user_id_to_filter is not None:
            query = query.filter(AuditLog.user_id == user_id_to_filter)

        # Severity filtering
        if args.severity:
            query = query.filter(AuditLog.severity == args.severity)

        # Order by timestamp and apply limit
        logs = query.order_by(AuditLog.created_at.asc()).limit(args.limit).all()

        # Convert to dictionaries for consistency
        return [log.to_dict() if hasattr(log, 'to_dict') else {
            'id': log.id,
            'created_at': log.created_at.isoformat() if log.created_at else None,
            'event_type': log.event_type,
            'severity': log.severity,
            'description': log.description,
            'user_id': log.user_id,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'details': log.details,
            'category': log.category,
            'object_type': log.object_type,
            'object_id': log.object_id,
            'related_type': log.related_type,
            'related_id': log.related_id,
            'username': User.query.get(log.user_id).username if log.user_id and User.query.get(log.user_id) else None
        } for log in logs]

def format_report_data(logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Formats log data into a list of dictionaries and determines headers."""
    if not logs:
        # Define default headers even if no logs
        headers = ['id', 'created_at', 'event_type', 'severity', 'category', 'user_id', 'username', 'ip_address', 'description', 'details']
        return [], headers

    log_dicts = []
    all_keys = set()

    for log in logs:
        log_dict = log.copy()  # Work with a copy to avoid modifying original

        # Convert complex types (like dict/list) to JSON strings
        for key, value in log_dict.items():
            if isinstance(value, (dict, list)):
                try:
                    log_dict[key] = json.dumps(value)
                except TypeError:
                    log_dict[key] = str(value)  # Fallback
            elif isinstance(value, datetime):
                log_dict[key] = value.isoformat()

        log_dicts.append(log_dict)
        all_keys.update(log_dict.keys())

    # Define a consistent header order
    ordered_keys = sorted(list(all_keys), key=lambda x: (
        0 if x == 'id' else
        1 if x == 'created_at' else
        2 if x == 'event_type' else
        3 if x == 'severity' else
        4 if x == 'category' else
        5 if x == 'user_id' else
        6 if x == 'username' else
        7 if x == 'ip_address' else
        8 if x == 'description' else
        9 if x == 'details' else
        10  # Put others at the end
    ))

    return log_dicts, ordered_keys

def write_output(data: List[Dict[str, Any]], headers: List[str], output_file: str, format_type: str):
    """Write the formatted data to the output file."""
    try:
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if format_type == 'json':
                json.dump(data, f, indent=2, default=str)
            elif format_type == 'csv':
                writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
            elif format_type == 'text':
                # Simple text format, one log per line
                for log_dict in data:
                    f.write(f"[{log_dict.get('created_at', '')}] {log_dict.get('severity', '').upper()}: "
                            f"User={log_dict.get('username', log_dict.get('user_id', 'N/A'))} "
                            f"IP={log_dict.get('ip_address', 'N/A')} "
                            f"Event={log_dict.get('event_type', '')} - {log_dict.get('description', '')}\n")
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        logger.info(f"Successfully wrote {len(data)} entries to {output_file} in {format_type} format.")
    except IOError as e:
        logger.error(f"Failed to write to output file {output_file}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during file writing: {e}")
        sys.exit(1)

def display_review(logs: List[Dict[str, Any]]):
    """Display logs to the console in a readable text format."""
    if not logs:
        print("No administrative logs found matching the criteria.")
        return

    print("\n--- Administrative Audit Log Review ---")
    for log in logs:
        timestamp = log.get('created_at', '')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass

        severity = log.get('severity', '').upper()
        username = log.get('username', log.get('user_id', 'System'))
        ip_address = log.get('ip_address', 'N/A')
        event_type = log.get('event_type', '')
        description = log.get('description', '')

        details = log.get('details', '')
        details_str = f" Details={details}" if details else ""

        print(f"[{timestamp}] {severity:<8} User={username:<25} IP={ip_address:<20} "
              f"Event={event_type:<20} - {description}{details_str}")
    print(f"--- Displayed {len(logs)} log entries ---\n")

def run_anomaly_detection(app: Flask, args: argparse.Namespace):
    """Run anomaly detection checks."""
    logger.info("Running anomaly detection...")
    start_dt, end_dt = get_time_range(args)
    anomalies = []

    with app.app_context():
        try:
            # Use the specialized admin anomaly detection if available
            if AUDIT_UTILS_AVAILABLE:
                logger.info("Using admin-specific anomaly detection...")
                admin_anomalies = detect_admin_anomalies(
                    start_time=start_dt,
                    end_time=end_dt,
                    threshold=args.threshold,
                    output_file=None  # We'll handle the output ourselves
                )
                logger.info(f"Admin anomaly detection found {len(admin_anomalies)} potential anomalies.")
                anomalies.extend(admin_anomalies)

            # Also use the core security anomaly detection for more comprehensive results
            logger.info("Using core security anomaly detection...")
            security_anomalies = detect_security_anomalies()

            # Filter for admin-related anomalies only
            admin_related_anomalies = [
                a for a in security_anomalies
                if a.get('category') == 'admin' or 'admin' in a.get('type', '').lower()
            ]
            logger.info(f"Core security anomaly detection found {len(admin_related_anomalies)} additional admin-related anomalies.")

            # Add to our results, avoid duplicates
            existing_ids = {a.get('id') for a in anomalies if a.get('id') is not None}
            for anomaly in admin_related_anomalies:
                if anomaly.get('id') not in existing_ids:
                    anomalies.append(anomaly)

            # Log the successful anomaly detection
            if AUDIT_UTILS_AVAILABLE:
                log_admin_action(
                    action="anomaly.detection",
                    details={
                        "anomaly_count": len(anomalies),
                        "start_time": start_dt.isoformat(),
                        "end_time": end_dt.isoformat(),
                        "threshold": args.threshold
                    },
                    status=STATUS_SUCCESS
                )

        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            sys.exit(1)

    if not anomalies:
        logger.info("No significant anomalies detected in administrative actions for the specified period.")
        if args.output:
            write_output([], [], args.output, 'json')  # Write empty list if requested
        return

    logger.warning(f"Detected {len(anomalies)} potential anomalies.")

    # Normalize results for output
    serializable_anomalies = []
    for anomaly in anomalies:
        serializable_anomaly = {}
        for k, v in anomaly.items():
            if isinstance(v, datetime):
                serializable_anomaly[k] = v.isoformat()
            elif isinstance(v, (int, str, float, bool, list, dict)) or v is None:
                serializable_anomaly[k] = v
            else:
                serializable_anomaly[k] = str(v)  # Fallback for other types
        serializable_anomalies.append(serializable_anomaly)

    if args.output:
        headers = list(serializable_anomalies[0].keys()) if serializable_anomalies else []
        write_output(serializable_anomalies, headers, args.output, 'json')
    else:
        print("\n--- Detected Anomalies ---")
        for anomaly in serializable_anomalies:
            print(json.dumps(anomaly, indent=2))
        print("--- End of Anomalies ---")

def run_integrity_checks(app: Flask, args: argparse.Namespace):
    """Run basic integrity checks on audit logs."""
    logger.info("Running integrity checks...")
    start_dt, end_dt = get_time_range(args)
    integrity_issues = []

    with app.app_context():
        # Use the audit utils integrity check if available
        if AUDIT_UTILS_AVAILABLE:
            try:
                logger.info("Using audit utilities for integrity checking...")
                integrity_result = verify_audit_log_integrity(start_dt, end_dt)

                if integrity_result["status"] != "valid":
                    logger.warning(f"Audit log integrity check: {integrity_result['status']}")
                    logger.warning(f"Found {len(integrity_result.get('issues', []))} potential integrity issues")
                    integrity_issues.extend(integrity_result.get('issues', []))
                else:
                    logger.info("Audit log integrity check passed.")

                # Log the integrity check
                log_admin_action(
                    action="audit.integrity",
                    details={
                        "status": integrity_result["status"],
                        "issue_count": len(integrity_result.get('issues', [])),
                        "start_time": start_dt.isoformat(),
                        "end_time": end_dt.isoformat()
                    },
                    severity=SEVERITY_INFO,
                    status=STATUS_SUCCESS
                )
            except Exception as e:
                logger.error(f"Error performing integrity check with audit utilities: {e}")
                # Continue with basic checks

        # Perform basic gap check if requested or no issues found yet
        if args.check_gaps or not integrity_issues:
            logger.info("Checking for time gaps in logs...")
            logs = fetch_admin_logs(app, args)

            if len(logs) > 1:
                # Sort by timestamp
                logs.sort(key=lambda x: x.get('created_at', '') if isinstance(x.get('created_at'), str)
                          else x.get('created_at', datetime.min))

                max_gap = timedelta(minutes=60)  # Example threshold: 1 hour
                potential_gaps = []

                for i in range(len(logs) - 1):
                    # Convert timestamps to datetime objects if they're strings
                    curr_time = logs[i].get('created_at')
                    next_time = logs[i+1].get('created_at')

                    if isinstance(curr_time, str):
                        curr_time = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
                    if isinstance(next_time, str):
                        next_time = datetime.fromisoformat(next_time.replace('Z', '+00:00'))

                    gap = next_time - curr_time

                    # Business hours check (9am-5pm on weekdays)
                    is_business_hours = (
                        curr_time.weekday() < 5 and  # Weekday
                        curr_time.hour >= 9 and curr_time.hour < 17  # 9am-5pm
                    )

                    if gap > max_gap and is_business_hours:
                        logger.warning(f"Potential time gap detected: {gap} between logs at {curr_time} and {next_time}")
                        potential_gaps.append({
                            'type': 'time_gap',
                            'start_time': curr_time.isoformat() if isinstance(curr_time, datetime) else curr_time,
                            'end_time': next_time.isoformat() if isinstance(next_time, datetime) else next_time,
                            'gap_minutes': gap.total_seconds() / 60,
                            'first_log_id': logs[i].get('id'),
                            'second_log_id': logs[i+1].get('id')
                        })

                if potential_gaps:
                    logger.warning(f"Found {len(potential_gaps)} potential time gaps during business hours.")
                    integrity_issues.extend(potential_gaps)
                else:
                    logger.info("No significant time gaps detected during business hours.")
            else:
                logger.info("Not enough logs in the period to check for gaps.")

        # Perform sequence checking if requested
        if args.check_sequence:
            logger.info("Checking for sequence consistency...")
            logs = fetch_admin_logs(app, args)

            if len(logs) > 1:
                # Sort by ID
                logs.sort(key=lambda x: x.get('id', 0))

                sequence_issues = []
                for i in range(len(logs) - 1):
                    curr_id = logs[i].get('id', 0)
                    next_id = logs[i+1].get('id', 0)

                    # Check for gaps in ID sequence
                    if next_id > curr_id + 1:
                        logger.warning(f"Potential sequence gap detected: {next_id - curr_id - 1} missing IDs between {curr_id} and {next_id}")
                        sequence_issues.append({
                            'type': 'sequence_gap',
                            'first_id': curr_id,
                            'second_id': next_id,
                            'missing_count': next_id - curr_id - 1
                        })

                if sequence_issues:
                    logger.warning(f"Found {len(sequence_issues)} sequence gaps in the log IDs.")
                    integrity_issues.extend(sequence_issues)
                else:
                    logger.info("No sequence gaps detected in the log IDs.")
            else:
                logger.info("Not enough logs in the period to check sequence.")

    # Output integrity issues if any were found
    if integrity_issues:
        if args.output:
            # Normalize for JSON output
            serializable_issues = []
            for issue in integrity_issues:
                serializable_issue = {}
                for k, v in issue.items():
                    if isinstance(v, datetime):
                        serializable_issue[k] = v.isoformat()
                    elif isinstance(v, (int, str, float, bool, list, dict)) or v is None:
                        serializable_issue[k] = v
                    else:
                        serializable_issue[k] = str(v)
                serializable_issues.append(serializable_issue)

            headers = list(serializable_issues[0].keys()) if serializable_issues else []
            write_output(serializable_issues, headers, args.output, 'json')
        else:
            print("\n--- Integrity Issues ---")
            for issue in integrity_issues:
                print(json.dumps(issue, indent=2, default=str))
            print("--- End of Integrity Issues ---")
    else:
        logger.info("No integrity issues found.")
        if args.output:
            write_output([], [], args.output, 'json')

def main():
    """Main execution function."""
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")
        logger.debug(f"Arguments: {args}")

    # Create Flask app context
    try:
        app = create_app(env=args.env)
    except Exception as e:
        logger.error(f"Failed to create Flask app context for environment '{args.env}': {e}")
        sys.exit(1)

    if args.command == 'review':
        logger.info("Fetching logs for review...")
        logs = fetch_admin_logs(app, args)
        if args.format == 'json':
             print(json.dumps(logs, indent=2, default=str))
        else:
             display_review(logs)
    elif args.command == 'report':
        logger.info("Fetching logs for report generation...")
        logs = fetch_admin_logs(app, args)

        # If export utility is available, use it for better integration
        if AUDIT_UTILS_AVAILABLE and args.output:
            start_dt, end_dt = get_time_range(args)
            try:
                # Build filters
                filters = {}
                if args.user_id:
                    filters['user_id'] = args.user_id
                if args.user:
                    filters['username'] = args.user
                if args.action_type:
                    filters['action_types'] = [args.action_type]
                if args.severity:
                    filters['severity'] = args.severity

                # Use the specialized export function
                result = export_admin_audit_logs(
                    start_time=start_dt,
                    end_time=end_dt,
                    output_format=args.format,
                    output_file=args.output,
                    filters=filters
                )

                if result is True:
                    logger.info(f"Successfully exported logs to {args.output}")
                else:
                    logger.warning("Export function returned a string instead of writing to file.")
                    # Write the returned string to the output file
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(result)
                    logger.info(f"Manually wrote export result to {args.output}")
            except Exception as e:
                logger.error(f"Failed to use export_admin_audit_logs: {e}")
                # Fall back to manual formatting and export
                report_data, headers = format_report_data(logs)
                write_output(report_data, headers, args.output, args.format)
        else:
            # Use the standard formatting and export
            if not logs:
                logger.info("No logs found matching criteria. Generating empty report.")
                report_data, headers = format_report_data([])
            else:
                logger.info(f"Formatting {len(logs)} logs for {args.format} report...")
                report_data, headers = format_report_data(logs)
            write_output(report_data, headers, args.output, args.format)

    elif args.command == 'anomalies':
        run_anomaly_detection(app, args)
    elif args.command == 'integrity':
        run_integrity_checks(app, args)
    else:
        logger.error(f"Unknown command: {args.command}")
        sys.exit(1)

    logger.info("Administrative audit script finished.")

if __name__ == "__main__":
    main()
