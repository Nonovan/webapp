"""
Audit Log Exporter Script

This script exports audit logs from the database to various formats (JSON, CSV).
It allows filtering by time range, event type, severity, category, and user ID.

Usage:
    python admin/scripts/audit_log_exporter.py --output <file_path> --format <json|csv> [filters]

Examples:
    # Export last 7 days of critical security events to JSON
    python admin/scripts/audit_log_exporter.py --output critical_events.json --format json --days 7 --severity critical --category security

    # Export all logs from a specific user to CSV, limiting to 5000 entries
    python admin/scripts/audit_log_exporter.py --output user_logs.csv --format csv --user-id 123 --limit 5000

    # Export logs between two specific dates
    python admin/scripts/audit_log_exporter.py --output date_range.json --format json --start-date 2023-10-01 --end-date 2023-10-31
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
# This assumes the script is run from the project root or the path is adjusted externally
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from flask import Flask
    # Need to create a minimal Flask app context to use SQLAlchemy models/extensions
    from extensions import db
    from models.security.audit_log import AuditLog
    from core.factory import create_app # Assuming create_app exists for context
    from core.security.cs_audit import log_security_event # For logging the export action
except ImportError as e:
    print(f"Error importing application modules: {e}", file=sys.stderr)
    print("Please ensure the script is run within the project environment or PYTHONPATH is set correctly.", file=sys.stderr)
    sys.exit(1)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define available export formats
SUPPORTED_FORMATS = ['json', 'csv']

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Export audit logs from the database.")

    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output file."
    )
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        required=True,
        help="Output format for the exported logs."
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Export logs from the last N days."
    )
    parser.add_argument(
        "--start-date",
        help="Start date for export (YYYY-MM-DD). Overrides --days."
    )
    parser.add_argument(
        "--end-date",
        help="End date for export (YYYY-MM-DD). Defaults to today."
    )
    parser.add_argument(
        "--event-type",
        help="Filter logs by event type (e.g., 'login_failed')."
    )
    parser.add_argument(
        "--severity",
        choices=AuditLog.VALID_SEVERITIES,
        help="Filter logs by severity level."
    )
    parser.add_argument(
        "--category",
        help="Filter logs by category (e.g., 'auth', 'security', 'system')."
    )
    parser.add_argument(
        "--user-id",
        type=int,
        help="Filter logs by user ID."
    )
    parser.add_argument(
        "--ip-address",
        help="Filter logs by IP address."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10000, # Default limit to prevent excessive memory usage
        help="Maximum number of log entries to export (default: 10000)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )
    parser.add_argument(
        "--env",
        default="production",
        help="Application environment to load configuration (default: production)."
    )

    return parser.parse_args()

def fetch_audit_logs(app: Flask, args: argparse.Namespace) -> List[AuditLog]:
    """Fetch audit logs from the database based on filters."""
    with app.app_context():
        query = AuditLog.query

        # Time range filtering
        end_dt = datetime.now(timezone.utc)
        if args.end_date:
            try:
                end_dt = datetime.strptime(args.end_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                # Include the whole end day
                end_dt = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            except ValueError:
                logger.error("Invalid end date format. Please use YYYY-MM-DD.")
                sys.exit(1)
        query = query.filter(AuditLog.created_at <= end_dt)

        if args.start_date:
            try:
                start_dt = datetime.strptime(args.start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                query = query.filter(AuditLog.created_at >= start_dt)
            except ValueError:
                logger.error("Invalid start date format. Please use YYYY-MM-DD.")
                sys.exit(1)
        elif args.days:
            start_dt = end_dt - timedelta(days=args.days)
            query = query.filter(AuditLog.created_at >= start_dt)
        else:
            # Default to last 30 days if no time range specified
            start_dt = end_dt - timedelta(days=30)
            query = query.filter(AuditLog.created_at >= start_dt)
            logger.info("No time range specified. Defaulting to logs from the last 30 days.")

        # Apply other filters
        if args.event_type:
            query = query.filter(AuditLog.event_type == args.event_type)
        if args.severity:
            query = query.filter(AuditLog.severity == args.severity)
        if args.category:
            query = query.filter(AuditLog.category == args.category)
        if args.user_id is not None: # Check for None explicitly as user_id 0 might be valid
            query = query.filter(AuditLog.user_id == args.user_id)
        if args.ip_address:
            query = query.filter(AuditLog.ip_address == args.ip_address)

        # Order by timestamp and apply limit
        logs = query.order_by(AuditLog.created_at.asc()).limit(args.limit).all()

        if len(logs) == args.limit:
             logger.warning(f"Reached export limit of {args.limit} logs. Results may be truncated.")

        return logs

def format_logs(logs: List[AuditLog], format_type: str) -> Tuple[Any, Optional[List[str]]]:
    """
    Format logs into the specified output format.

    Returns:
        A tuple containing the formatted data and an optional list of headers (for CSV).
    """
    if not logs:
        return ([], None) if format_type == 'json' else ("", None)

    # Use the to_dict method from the AuditLog model if available, otherwise build manually
    log_dicts: List[Dict[str, Any]] = []
    if hasattr(AuditLog, 'to_dict') and callable(getattr(AuditLog, 'to_dict')):
        log_dicts = [log.to_dict() for log in logs]
    else:
        logger.warning("AuditLog.to_dict() method not found. Manually constructing dictionaries.")
        for log in logs:
            log_dicts.append({
                'id': log.id,
                'created_at': log.created_at,
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
            })


    if format_type == 'json':
        # Convert datetime objects to ISO format strings for JSON serialization
        for log_dict in log_dicts:
            for key, value in log_dict.items():
                if isinstance(value, datetime):
                    log_dict[key] = value.isoformat()
        return log_dicts, None

    elif format_type == 'csv':
        if not log_dicts:
            return [], [] # Return empty list and empty list for headers

        # Get all possible keys from all dictionaries to handle variations
        all_keys = set()
        for log_dict in log_dicts:
            all_keys.update(log_dict.keys())

        # Define a consistent header order (prioritize common fields)
        ordered_keys = sorted(list(all_keys), key=lambda x: (
            0 if x == 'id' else
            1 if x == 'created_at' else
            2 if x == 'event_type' else
            3 if x == 'severity' else
            4 if x == 'category' else
            5 if x == 'user_id' else
            6 if x == 'ip_address' else
            7 if x == 'description' else
            8 if x == 'details' else
            9 if x == 'object_type' else
            10 if x == 'object_id' else
            11 if x == 'related_type' else
            12 if x == 'related_id' else
            13 if x == 'user_agent' else
            20 # Put others at the end
        ))

        return log_dicts, ordered_keys # Return list of dicts and headers for CSV writer

    else:
        raise ValueError(f"Unsupported format: {format_type}")


def write_output(data: Any, headers: Optional[List[str]], output_file: str, format_type: str):
    """Write the formatted data to the output file."""
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if format_type == 'json':
                json.dump(data, f, indent=2)
                count = len(data)
            elif format_type == 'csv':
                if not data or not headers:
                    logger.info("No data to write to CSV.")
                    # Write header even if no data
                    if headers:
                        writer = csv.writer(f)
                        writer.writerow(headers)
                    count = 0
                else:
                    writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                    writer.writeheader()
                    for row in data:
                        # Convert complex types (like dict/list in 'details') to JSON strings for CSV
                        processed_row = {}
                        for key, value in row.items():
                             if isinstance(value, (dict, list)):
                                 try:
                                     processed_row[key] = json.dumps(value)
                                 except TypeError:
                                     processed_row[key] = str(value) # Fallback for non-serializable
                             elif isinstance(value, datetime):
                                 processed_row[key] = value.isoformat()
                             else:
                                 processed_row[key] = value
                        writer.writerow(processed_row)
                    count = len(data)
            else:
                 raise ValueError(f"Cannot write unsupported format: {format_type}")
        logger.info(f"Successfully exported {count} audit logs to {output_file} in {format_type} format.")
    except IOError as e:
        logger.error(f"Failed to write to output file {output_file}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during file writing: {e}")
        sys.exit(1)


def main():
    """Main execution function."""
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")
        logger.debug(f"Arguments: {args}")

    # Create a Flask app instance for context
    try:
        app = create_app(env=args.env)
    except Exception as e:
        logger.error(f"Failed to create Flask app context for environment '{args.env}': {e}")
        sys.exit(1)

    logger.info(f"Fetching audit logs with specified filters...")
    try:
        logs = fetch_audit_logs(app, args)
    except Exception as e:
        logger.error(f"Failed to fetch audit logs from database: {e}")
        sys.exit(1)

    if not logs:
        logger.info("No audit logs found matching the criteria.")
        # Create an empty file as requested
        headers = None
        data = []
        if args.format == 'csv':
            # Need headers even for empty CSV
            # Attempt to get headers from the model definition or use a default set
            try:
                # Use a default set if model introspection is too complex here
                headers = ['id', 'created_at', 'event_type', 'severity', 'category', 'user_id', 'ip_address', 'description', 'details']
                logger.debug("Using default headers for empty CSV.")
            except Exception:
                logger.warning("Could not determine headers for empty CSV.")
        try:
            write_output(data, headers, args.output, args.format)
            logger.info(f"Created empty output file: {args.output}")
        except Exception as e:
             logger.error(f"Failed to create empty output file {args.output}: {e}")
        sys.exit(0)

    logger.info(f"Found {len(logs)} log entries. Formatting for {args.format} output...")

    headers = None
    try:
        formatted_data, headers = format_logs(logs, args.format)
    except ValueError as e:
        logger.error(f"Error formatting logs: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during formatting: {e}")
        sys.exit(1)

    logger.info(f"Writing formatted logs to {args.output}...")
    write_output(formatted_data, headers, args.output, args.format)

    # Log the export action itself to the audit log
    try:
        with app.app_context():
            # Construct filter dictionary safely
            filters_used = {
                key: val for key, val in vars(args).items()
                if key in ['days', 'start_date', 'end_date', 'event_type', 'severity', 'category', 'user_id', 'ip_address', 'limit'] and val is not None
            }
            log_security_event(
                event_type='audit_log_export',
                description=f'Exported {len(logs)} audit logs to {os.path.basename(args.output)}',
                severity='info',
                details={
                    'output_file': args.output,
                    'format': args.format,
                    'count': len(logs),
                    'filters': filters_used
                },
                # Identify the script user/process if possible. Using None for now.
                user_id=None
            )
            logger.debug("Logged audit log export action.")
    except Exception as e:
        logger.warning(f"Could not log the export action to the audit log: {e}")


if __name__ == "__main__":
    main()
