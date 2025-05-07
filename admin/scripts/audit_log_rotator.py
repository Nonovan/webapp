#!/usr/bin/env python3
"""
Audit Log Rotation and Archival Utility

This script handles the rotation, archival, and optionally deletion of old audit logs.
It supports keeping logs in the database for a configurable period while archiving older
logs to files for long-term storage, helping to maintain database performance.

Usage:
    python admin/scripts/audit_log_rotator.py [options]

Examples:
    # Archive all audit logs older than 90 days with default settings
    python admin/scripts/audit_log_rotator.py

    # Archive logs older than 30 days but keep them in the database
    python admin/scripts/audit_log_rotator.py --archive-days 30 --no-delete

    # Archive and delete logs older than 180 days, with specific formats and paths
    python admin/scripts/audit_log_rotator.py --archive-days 180 --format json --output-dir /secure/archives
"""

import argparse
import csv
import json
import logging
import os
import sys
import shutil
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

# Adjust path to import application components
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from flask import Flask
    from sqlalchemy import func
    from extensions import db
    from models.security.audit_log import AuditLog
    from core.factory import create_app
    from core.security.cs_audit import log_security_event
except ImportError as e:
    print(f"Error importing application modules: {e}", file=sys.stderr)
    print("Please ensure the script is run within the project environment or PYTHONPATH is set correctly.", file=sys.stderr)
    sys.exit(1)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define available export formats
SUPPORTED_FORMATS = ['json', 'csv']


__all__ = [
    # Core functions


    # Helper functions


    # Classes


    # Constants


    # Main entry point
    "main"
]


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Rotate and archive old audit logs.")

    parser.add_argument(
        "--archive-days",
        type=int,
        default=90,
        help="Archive logs older than this many days (default: 90)."
    )
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="json",
        help="Format for archived logs (default: json)."
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join(project_root, "archives", "audit"),
        help="Directory to store archived logs (default: PROJECT_ROOT/archives/audit)."
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Compress archived logs using gzip."
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Don't delete logs from database after archiving."
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="Number of logs to process in each batch (default: 5000)."
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=365,
        help="Days to keep archived logs before deletion (default: 365)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without making any changes."
    )
    parser.add_argument(
        "--env",
        default="production",
        help="Application environment to load configuration (default: production)."
    )

    return parser.parse_args()

def get_batch_count(app: Flask, cutoff_date: datetime) -> int:
    """Get the total number of logs to be archived."""
    with app.app_context():
        return AuditLog.query.filter(AuditLog.created_at < cutoff_date).count()

def fetch_log_batch(app: Flask, cutoff_date: datetime, batch_size: int, offset: int) -> List[AuditLog]:
    """Fetch a batch of audit logs to be archived."""
    with app.app_context():
        return AuditLog.query.filter(
            AuditLog.created_at < cutoff_date
        ).order_by(
            AuditLog.created_at
        ).limit(batch_size).offset(offset).all()

def format_logs(logs: List[AuditLog], format_type: str) -> Tuple[Any, Optional[List[str]]]:
    """Format logs into the specified output format."""
    if not logs:
        return [], None

    # Use the to_dict method from the AuditLog model if available, otherwise build manually
    log_dicts = []
    if hasattr(logs[0], 'to_dict') and callable(getattr(logs[0], 'to_dict')):
        log_dicts = [log.to_dict() for log in logs]
    else:
        for log in logs:
            log_dict = {
                'id': log.id,
                'created_at': log.created_at.isoformat() if hasattr(log.created_at, 'isoformat') else str(log.created_at),
                'event_type': log.event_type,
                'severity': log.severity,
                'description': log.description,
                'user_id': log.user_id,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'details': log.details,
                'category': log.category
            }
            # Add optional fields if they exist
            for field in ['object_type', 'object_id', 'related_type', 'related_id']:
                if hasattr(log, field):
                    log_dict[field] = getattr(log, field)

            log_dicts.append(log_dict)

    if format_type == 'json':
        # Datetimes are already ISO formatted above
        return log_dicts, None

    elif format_type == 'csv':
        # Get all column names from the first log
        all_keys = set()
        for log_dict in log_dicts:
            all_keys.update(log_dict.keys())

        # Define a consistent header order
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
            9
        ))

        return log_dicts, ordered_keys

    else:
        raise ValueError(f"Unsupported format: {format_type}")

def write_archive(logs: List[Dict[str, Any]], headers: Optional[List[str]],
                 output_file: str, format_type: str, compress: bool = False) -> str:
    """Write logs to archive file and optionally compress."""
    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, mode=0o750, exist_ok=True)

    temp_output = output_file

    try:
        with open(temp_output, 'w', newline='', encoding='utf-8') as f:
            if format_type == 'json':
                json.dump(logs, f, indent=2)
            elif format_type == 'csv':
                writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                for row in logs:
                    # Convert complex data to strings for CSV
                    processed_row = {}
                    for key, value in row.items():
                        if isinstance(value, (dict, list)):
                            try:
                                processed_row[key] = json.dumps(value)
                            except (TypeError, ValueError):
                                processed_row[key] = str(value)
                        else:
                            processed_row[key] = value
                    writer.writerow(processed_row)
    except Exception as e:
        logger.error(f"Failed to write archive file: {e}")
        raise

    # Set secure permissions
    os.chmod(temp_output, 0o640)

    # Compress if requested
    if compress:
        import gzip
        compressed_output = f"{output_file}.gz"
        with open(temp_output, 'rb') as f_in:
            with gzip.open(compressed_output, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(temp_output)  # Remove uncompressed file
        os.chmod(compressed_output, 0o640)
        return compressed_output

    return temp_output

def delete_old_archives(archive_dir: str, retention_days: int, dry_run: bool = False) -> int:
    """Delete archive files older than retention period."""
    if not os.path.exists(archive_dir):
        return 0

    count = 0
    cutoff_time = datetime.now() - timedelta(days=retention_days)

    for filename in os.listdir(archive_dir):
        filepath = os.path.join(archive_dir, filename)
        if not os.path.isfile(filepath):
            continue

        file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
        if file_mtime < cutoff_time:
            if dry_run:
                logger.info(f"Would delete archive: {filepath}")
            else:
                try:
                    os.remove(filepath)
                    logger.debug(f"Deleted old archive: {filepath}")
                    count += 1
                except OSError as e:
                    logger.error(f"Failed to delete {filepath}: {e}")

    return count

def delete_logs_from_database(app: Flask, logs: List[AuditLog], dry_run: bool = False) -> int:
    """Delete archived logs from the database."""
    if dry_run:
        return len(logs)

    with app.app_context():
        try:
            log_ids = [log.id for log in logs]
            result = AuditLog.query.filter(AuditLog.id.in_(log_ids)).delete(synchronize_session=False)
            db.session.commit()
            return result
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to delete logs from database: {e}")
            raise

def main():
    args = parse_arguments()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Calculate cutoff date
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=args.archive_days)

    # Create Flask app instance for database access
    try:
        app = create_app(env=args.env)
    except Exception as e:
        logger.error(f"Failed to create Flask app context: {e}")
        sys.exit(1)

    # Get total logs to archive
    try:
        total_logs = get_batch_count(app, cutoff_date)
        logger.info(f"Found {total_logs} logs older than {args.archive_days} days to process")

        if total_logs == 0:
            logger.info("No logs to archive. Exiting.")
            return

        if args.dry_run:
            logger.info("DRY RUN: No changes will be made")
    except Exception as e:
        logger.error(f"Failed to count logs: {e}")
        sys.exit(1)

    # Ensure output directory exists
    try:
        os.makedirs(args.output_dir, exist_ok=True)
        os.chmod(args.output_dir, 0o750)  # Secure permissions
    except OSError as e:
        logger.error(f"Failed to create output directory {args.output_dir}: {e}")
        sys.exit(1)

    # Generate timestamp for archive files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Process in batches
    processed_count = 0
    batch_num = 0
    total_deleted = 0
    archived_files = []

    while processed_count < total_logs:
        batch_num += 1
        offset = processed_count

        try:
            # Fetch next batch of logs
            batch = fetch_log_batch(app, cutoff_date, args.batch_size, offset)
            if not batch:
                break

            batch_size = len(batch)
            logger.info(f"Processing batch {batch_num}: {batch_size} logs")

            # Format logs based on selected format
            formatted_data, headers = format_logs(batch, args.format)

            # Generate archive filename
            file_ext = args.format
            output_filename = f"audit_logs_{timestamp}_batch{batch_num:04d}.{file_ext}"
            output_path = os.path.join(args.output_dir, output_filename)

            # Write to archive file
            if not args.dry_run:
                try:
                    archive_file = write_archive(
                        formatted_data, headers, output_path,
                        args.format, args.compress
                    )
                    archived_files.append(archive_file)
                    logger.info(f"Archived {batch_size} logs to {archive_file}")
                except Exception as e:
                    logger.error(f"Failed to write archive file: {e}")
                    sys.exit(1)
            else:
                logger.info(f"Would archive {batch_size} logs to {output_path}")

            # Delete from database if requested
            if not args.no_delete and not args.dry_run:
                try:
                    deleted = delete_logs_from_database(app, batch)
                    total_deleted += deleted
                    logger.info(f"Deleted {deleted} logs from database")
                except Exception as e:
                    logger.error(f"Failed to delete logs batch from database: {e}")
            elif not args.no_delete and args.dry_run:
                logger.info(f"Would delete {batch_size} logs from database")
                total_deleted += batch_size

            processed_count += batch_size
            logger.info(f"Progress: {processed_count}/{total_logs} logs processed")

        except Exception as e:
            logger.error(f"Error processing batch {batch_num}: {e}")
            sys.exit(1)

    # Clean up old archives if needed
    if args.retention_days > 0:
        try:
            deleted_archives = delete_old_archives(args.output_dir, args.retention_days, args.dry_run)
            if deleted_archives > 0:
                logger.info(f"Deleted {deleted_archives} archives older than {args.retention_days} days")
        except Exception as e:
            logger.error(f"Error cleaning up old archives: {e}")

    # Log the rotation activity
    summary = {
        "logs_processed": processed_count,
        "logs_deleted": total_deleted if not args.no_delete else 0,
        "archive_files_created": len(archived_files),
        "archive_format": args.format,
        "archive_directory": args.output_dir,
        "cutoff_date": cutoff_date.isoformat()
    }

    if not args.dry_run:
        try:
            with app.app_context():
                log_security_event(
                    event_type='audit_log_rotation',
                    description=f"Rotated {processed_count} audit logs older than {args.archive_days} days",
                    severity='info',
                    details=summary
                )
        except Exception as e:
            logger.warning(f"Could not log rotation event: {e}")

    logger.info("Audit log rotation completed successfully")
    logger.info(f"Summary: Processed {processed_count} logs, " +
                f"created {len(archived_files)} archive files" +
                (f", deleted {total_deleted} logs from database" if not args.no_delete else ""))

if __name__ == "__main__":
    main()
