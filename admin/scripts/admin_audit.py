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
    python admin/scripts/admin_audit.py anomalies --days 30

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
    from core.security.cs_audit import detect_security_anomalies # Use existing anomaly detection if suitable
    # Consider importing admin.utils.audit_utils if it exists and is relevant
except ImportError as e:
    print(f"Error importing application modules: {e}", file=sys.stderr)
    print("Please ensure the script is run within the project environment or PYTHONPATH is set correctly.", file=sys.stderr)
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
    common_parser.add_argument("--severity", choices=AuditLog.VALID_SEVERITIES, help="Filter by severity level.")
    common_parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum number of entries (default: {DEFAULT_LIMIT}).")
    common_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    common_parser.add_argument("--env", default="production", help="Application environment (default: production).")

    # Subparser for 'review'
    review_parser = subparsers.add_parser('review', parents=[common_parser], help='Review administrative audit logs.')
    review_parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format (default: text).") # Limited formats for review

    # Subparser for 'report'
    report_parser = subparsers.add_parser('report', parents=[common_parser], help='Generate an audit report.')
    report_parser.add_argument("--output", required=True, help="Path to the output file for the report.")
    report_parser.add_argument("--format", choices=SUPPORTED_FORMATS, required=True, help="Report format (json, csv, text).")

    # Subparser for 'anomalies'
    anomalies_parser = subparsers.add_parser('anomalies', parents=[common_parser], help='Detect potential anomalies in administrative actions.')
    anomalies_parser.add_argument("--threshold", choices=['low', 'medium', 'high'], default='medium', help="Anomaly detection sensitivity threshold.")
    anomalies_parser.add_argument("--output", help="Optional output file for anomaly report (JSON format).")

    # Subparser for 'integrity'
    integrity_parser = subparsers.add_parser('integrity', parents=[common_parser], help='Perform basic integrity checks (experimental).')
    integrity_parser.add_argument("--check-gaps", action="store_true", help="Check for potential time gaps in logs.")
    integrity_parser.add_argument("--check-sequence", action="store_true", help="Check for sequence inconsistencies (if applicable).")

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

def fetch_admin_logs(app: Flask, args: argparse.Namespace) -> List[AuditLog]:
    """Fetch administrative audit logs based on filters."""
    with app.app_context():
        query = AuditLog.query

        # Filter primarily for administrative actions
        # Adjust category/event_types based on actual usage in models/security/audit_log.py
        admin_categories = [AuditLog.EVENT_CATEGORY_ADMIN, AuditLog.EVENT_CATEGORY_SECURITY] # Example categories
        admin_event_types = [
            AuditLog.EVENT_ADMIN_ACTION, AuditLog.EVENT_CONFIG_CHANGE,
            AuditLog.EVENT_ROLE_ASSIGNED, AuditLog.EVENT_ROLE_REMOVED,
            AuditLog.EVENT_PERMISSION_GRANTED, AuditLog.EVENT_PERMISSION_REVOKED,
            # Add other relevant event types
        ]
        # Allow overriding with specific action type if provided
        if args.action_type:
             query = query.filter(AuditLog.event_type == args.action_type)
        else:
             # Default filter for admin-related categories/types
             query = query.filter(
                 (AuditLog.category.in_(admin_categories)) |
                 (AuditLog.event_type.in_(admin_event_types))
             )

        # Time range filtering
        start_dt, end_dt = get_time_range(args)
        query = query.filter(AuditLog.created_at.between(start_dt, end_dt))

        # User filtering
        user_id_to_filter = args.user_id
        if args.user:
            user = User.query.filter_by(username=args.user).first()
            if user:
                user_id_to_filter = user.id
            else:
                logger.warning(f"Username '{args.user}' not found. No logs will be returned for this user filter.")
                return [] # Return empty list if user not found
        if user_id_to_filter is not None:
            query = query.filter(AuditLog.user_id == user_id_to_filter)

        # Severity filtering
        if args.severity:
            query = query.filter(AuditLog.severity == args.severity)

        # Order by timestamp and apply limit
        logs = query.order_by(AuditLog.created_at.asc()).limit(args.limit).all()

        if len(logs) >= args.limit:
             logger.warning(f"Reached fetch limit of {args.limit}. Results may be truncated.")

        return logs

def format_report_data(logs: List[AuditLog]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Formats log data into a list of dictionaries and determines headers."""
    if not logs:
        # Define default headers even if no logs
        headers = ['id', 'created_at', 'event_type', 'severity', 'category', 'user_id', 'username', 'ip_address', 'description', 'details']
        return [], headers

    log_dicts: List[Dict[str, Any]] = []
    all_keys = set()

    # Cache user info to avoid repeated DB lookups
    user_cache: Dict[int, Optional[str]] = {}

    for log in logs:
        log_dict = log.to_dict() if hasattr(log, 'to_dict') else {
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
        }

        # Add username if user_id exists
        username = None
        if log.user_id:
            if log.user_id not in user_cache:
                 # Fetch user only if not cached
                 user = User.query.get(log.user_id)
                 user_cache[log.user_id] = user.username if user else None
            username = user_cache[log.user_id]
        log_dict['username'] = username

        # Convert complex types (like dict/list in 'details') to JSON strings
        for key, value in log_dict.items():
             if isinstance(value, (dict, list)):
                 try:
                     log_dict[key] = json.dumps(value)
                 except TypeError:
                     log_dict[key] = str(value) # Fallback
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
        10 # Put others at the end
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
                json.dump(data, f, indent=2)
            elif format_type == 'csv':
                writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(data)
            elif format_type == 'text':
                 # Simple text format, one log per line (customize as needed)
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

def display_review(logs: List[AuditLog]):
    """Display logs to the console in a readable text format."""
    if not logs:
        print("No administrative logs found matching the criteria.")
        return

    print("\n--- Administrative Audit Log Review ---")
    for log in logs:
        user_info = f"User={log.user.username if log.user else log.user_id or 'System'}"
        ip_info = f"IP={log.ip_address or 'N/A'}"
        details_str = f" Details={log.details}" if log.details else ""
        print(f"[{log.created_at.strftime('%Y-%m-%d %H:%M:%S')}] {log.severity.upper():<8} "
              f"{user_info:<25} {ip_info:<20} Event={log.event_type:<20} - {log.description}{details_str}")
    print(f"--- Displayed {len(logs)} log entries ---\n")


def run_anomaly_detection(app: Flask, args: argparse.Namespace):
    """Run anomaly detection checks."""
    logger.info("Running anomaly detection...")
    anomalies = []
    with app.app_context():
        try:
            # Utilize core anomaly detection if it suits admin actions
            # Pass relevant filters if the function supports them
            detected = detect_security_anomalies() # This might need adjustment
            # Filter detected anomalies for relevance to admin actions if necessary
            admin_related_anomalies = [
                a for a in detected if a.get('category') == 'admin' or 'admin' in a.get('type', '').lower()
                # Add more filtering logic based on the structure of anomalies
            ]
            anomalies.extend(admin_related_anomalies)
            logger.info(f"Core anomaly detection found {len(admin_related_anomalies)} potentially relevant anomalies.")

            # Add custom admin-specific anomaly checks here if needed
            # Example: Check for high frequency of specific admin actions
            # start_dt, end_dt = get_time_range(args)
            # high_freq_actions = db.session.query(...) # Query for frequent admin actions

        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            sys.exit(1)

    if not anomalies:
        logger.info("No significant anomalies detected in administrative actions for the specified period.")
        if args.output:
             write_output([], [], args.output, 'json') # Write empty list if requested
        return

    logger.warning(f"Detected {len(anomalies)} potential anomalies.")
    if args.output:
        # Ensure data is serializable for JSON
        serializable_anomalies = []
        for anomaly in anomalies:
            serializable_anomaly = {}
            for k, v in anomaly.items():
                if isinstance(v, datetime):
                    serializable_anomaly[k] = v.isoformat()
                elif isinstance(v, (int, str, float, bool, list, dict)) or v is None:
                    serializable_anomaly[k] = v
                else:
                    serializable_anomaly[k] = str(v) # Fallback for other types
            serializable_anomalies.append(serializable_anomaly)
        write_output(serializable_anomalies, list(serializable_anomalies[0].keys()) if serializable_anomalies else [], args.output, 'json')
    else:
        print("\n--- Detected Anomalies ---")
        for anomaly in anomalies:
            print(json.dumps(anomaly, indent=2, default=str)) # Print JSON to console
        print("--- End of Anomalies ---")


def run_integrity_checks(app: Flask, args: argparse.Namespace):
    """Run basic integrity checks on audit logs."""
    logger.info("Running integrity checks (experimental)...")
    # This is a placeholder for more complex integrity checks.
    # Real integrity checks might involve checksums, blockchain, or external validation.

    if args.check_gaps:
        logger.info("Checking for time gaps...")
        # Basic gap check: Fetch logs ordered by time and look for large time differences.
        # This is very basic and might yield false positives.
        with app.app_context():
            start_dt, end_dt = get_time_range(args)
            logs = AuditLog.query.filter(AuditLog.created_at.between(start_dt, end_dt))\
                                 .order_by(AuditLog.created_at.asc()).limit(args.limit * 2).all() # Fetch more to check gaps

            if len(logs) > 1:
                max_gap = timedelta(minutes=60) # Example threshold: 1 hour
                potential_gaps = 0
                for i in range(len(logs) - 1):
                    gap = logs[i+1].created_at - logs[i].created_at
                    if gap > max_gap:
                        logger.warning(f"Potential time gap detected: {gap} between log ID {logs[i].id} and {logs[i+1].id}")
                        potential_gaps += 1
                if potential_gaps == 0:
                    logger.info("No significant time gaps detected.")
                else:
                     logger.warning(f"Found {potential_gaps} potential time gaps exceeding {max_gap}.")
            else:
                logger.info("Not enough logs in the period to check for gaps.")

    if args.check_sequence:
         logger.warning("Sequence checking is not implemented in this basic version.")
         # Placeholder: Check if log IDs are sequential or if there's a sequence field.

    logger.info("Integrity checks complete.")


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
             log_dicts, _ = format_report_data(logs)
             print(json.dumps(log_dicts, indent=2))
        else:
             display_review(logs)
    elif args.command == 'report':
        logger.info("Fetching logs for report generation...")
        logs = fetch_admin_logs(app, args)
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
