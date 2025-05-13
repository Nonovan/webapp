#!/usr/bin/env python3
"""
Seed data script for Cloud Infrastructure Platform database.

This script populates the database with initial data and optionally adds
development test data when the '--dev' flag is provided. It safely handles
different environments and includes options for forcing recreation of data.

Usage:
    ./seed_data.py                     # Seeds basic data only
    ./seed_data.py --dev               # Seeds basic and development data
    ./seed_data.py --dev --force       # Seeds data, overwriting existing records
    ./seed_data.py --env production    # Seeds data for production environment
    ./seed_data.py --skip-basic --dev  # Seeds only development data
    ./seed_data.py --help              # Shows usage information
"""

import os
import sys
import argparse
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

# Add project root to path to enable imports
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Try importing the application and seeder module
try:
    from app import create_app
    from core.seeder import (
        seed_database,
        seed_development_data,
        seed_test_data,
        is_database_seeded
    )
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the script.

    Args:
        verbose: If True, enables debug level logging

    Returns:
        Configured logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format
    )
    return logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='Seed database with initial and/or development data.',
        epilog='Example: ./seed_data.py --dev --force --verbose'
    )
    parser.add_argument('--dev', action='store_true',
                      help='Include development test data')
    parser.add_argument('--test', action='store_true',
                      help='Include minimal test data (less than dev data)')
    parser.add_argument('--env', default='development',
                      choices=['development', 'staging', 'production', 'testing'],
                      help='Target environment (default: development)')
    parser.add_argument('--force', action='store_true',
                      help='Force overwrite of existing data')
    parser.add_argument('--verbose', action='store_true',
                      help='Show detailed output during seeding')
    parser.add_argument('--skip-basic', action='store_true',
                      help='Skip basic data seeding (only valid with --dev or --test)')
    parser.add_argument('--timeout', type=int, default=300,
                      help='Timeout in seconds for long operations (default: 300)')
    parser.add_argument('--file-integrity', action='store_true',
                      help='Include file integrity monitoring test data')
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace, logger: logging.Logger) -> bool:
    """Validate command-line argument combinations.

    Args:
        args: Command-line arguments
        logger: Logger instance

    Returns:
        True if arguments are valid, False otherwise
    """
    # Cannot skip basic data unless also seeding dev or test data
    if args.skip_basic and not (args.dev or args.test):
        logger.error("--skip-basic can only be used with --dev or --test")
        return False

    # Warn about forcing data in production
    if args.force and args.env == 'production':
        logger.warning("Using --force in production will overwrite existing data")
        logger.warning("Press Ctrl+C within 5 seconds to cancel...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Operation cancelled by user")
            return False

    # Cannot use both --dev and --test
    if args.dev and args.test:
        logger.error("Cannot use both --dev and --test flags together")
        return False

    return True


def seed_data(args: argparse.Namespace, logger: logging.Logger) -> bool:
    """Seed database based on provided arguments.

    Args:
        args: Command-line arguments
        logger: Logger instance

    Returns:
        True if seeding was successful, False otherwise
    """
    start_time = time.time()
    success = True

    try:
        # Initialize Flask application
        logger.info(f"Initializing application for {args.env} environment")
        os.environ['FLASK_ENV'] = args.env
        app = create_app()

        # Execute seeding within application context
        with app.app_context():
            # Check if database is already seeded
            if is_database_seeded() and not args.force:
                logger.warning("Database appears to be already seeded")
                logger.warning("Use --force to overwrite existing data")
                return True

            # Step 1: Seed basic data unless skipped
            if not args.skip_basic:
                logger.info("Seeding database with initial data...")
                if seed_database(force=args.force, verbose=args.verbose):
                    logger.info("✅ Initial data seeding completed successfully")
                else:
                    logger.error("❌ Failed to seed initial data")
                    success = False

            # Step 2: Seed development data if requested
            if args.dev and success:
                logger.info("Adding development test data...")
                if seed_development_data(force=args.force, verbose=args.verbose):
                    logger.info("✅ Development data seeding completed successfully")
                else:
                    logger.error("❌ Failed to seed development data")
                    success = False

            # Step 3: Seed minimal test data if requested
            if args.test and success:
                logger.info("Adding minimal test data...")
                if seed_test_data(force=args.force, verbose=args.verbose):
                    logger.info("✅ Test data seeding completed successfully")
                else:
                    logger.error("❌ Failed to seed test data")
                    success = False

            # Log completion
            elapsed = time.time() - start_time
            if success:
                logger.info(f"All seeding operations completed successfully in {elapsed:.2f} seconds")

                # Log seed completion metrics if metrics module is available
                try:
                    from core.metrics import track_event
                    track_event("database_seed_completed", {
                        "environment": args.env,
                        "dev_data": args.dev,
                        "test_data": args.test,
                        "duration_seconds": int(elapsed),
                        "timestamp": datetime.now().isoformat()
                    })
                except ImportError:
                    # Metrics module not available, continue without it
                    pass
            else:
                logger.warning(f"Some seeding operations failed after {elapsed:.2f} seconds")

            return success

    except Exception as e:
        logger.exception(f"Unexpected error during data seeding: {e}")
        return False


def main() -> int:
    """Main function to execute the data seeding process.

    Returns:
        int: 0 for success, 1 for failure
    """
    args = parse_arguments()
    logger = setup_logging(args.verbose)

    # Record script execution for audit purposes
    logger.info(f"Database seeding started by {os.getlogin()} for environment: {args.env}")

    # Validate arguments
    if not validate_arguments(args, logger):
        return 1

    # Measure execution time
    start_time = time.time()

    # Execute seeding operation
    try:
        success = seed_data(args, logger)

        # Log completion
        elapsed = time.time() - start_time
        if success:
            logger.info(f"✅ Database seeding completed successfully in {elapsed:.2f} seconds")
            # Try to log audit event
            try:
                from core.security import log_security_event
                with create_app().app_context():
                    log_security_event(
                        event_type="database_seed",
                        severity="info",
                        description=f"Database seeded for {args.env} environment",
                        details={
                            "environment": args.env,
                            "dev_data": args.dev,
                            "test_data": args.test,
                            "user": os.getlogin(),
                            "duration_seconds": int(elapsed)
                        }
                    )
            except ImportError:
                # Security module not available, continue without audit logging
                pass
            return 0
        else:
            logger.error(f"❌ Database seeding failed after {elapsed:.2f} seconds")
            return 1

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


# Allow importing this module
if __name__ == "__main__":
    sys.exit(main())
