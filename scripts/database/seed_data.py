#!/usr/bin/env python3
"""
Seed data script for Cloud Infrastructure Platform database.

This script populates the database with initial data and optionally adds
development test data when the '--dev' flag is provided.

Usage:
    ./seed_data.py                   # Seeds basic data only
    ./seed_data.py --dev             # Seeds basic and development data
    ./seed_data.py --dev --force     # Seeds data, overwriting existing records
    ./seed_data.py --help            # Shows usage information
"""
import sys
import argparse
import logging
from app import create_app
from core.seeder import seed_database, seed_development_data


def setup_logging(verbose=False):
    """Configure logging for the script.
    
    Args:
        verbose: If True, enables debug level logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='Seed database with initial and/or development data.',
        epilog='Example: ./seed_data.py --dev --force --verbose'
    )
    parser.add_argument('--dev', action='store_true', help='Include development test data')
    parser.add_argument('--force', action='store_true', help='Force overwrite of existing data')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output during seeding')
    parser.add_argument('--skip-basic', action='store_true', help='Skip basic data seeding (only valid with --dev)')
    return parser.parse_args()


def main():
    """Main function to execute the data seeding process.
    
    Returns:
        int: 0 for success, 1 for failure
    """
    args = parse_arguments()
    logger = setup_logging(args.verbose)
    
    # Validate argument combination
    if args.skip_basic and not args.dev:
        logger.error("--skip-basic can only be used with --dev")
        return 1
    
    try:
        # Initialize the application context
        logger.info("Initializing application context")
        app = create_app()
        
        success = True
        with app.app_context():
            # Seed basic data unless skipped
            if not args.skip_basic:
                logger.info("Seeding database with initial data...")
                if not seed_database(force=args.force, verbose=args.verbose):
                    logger.error("Failed to seed initial data")
                    success = False
                else:
                    logger.info("Initial data seeding completed successfully")
            
            # Seed development data if requested
            if args.dev:
                logger.info("Adding development test data...")
                if not seed_development_data(force=args.force, verbose=args.verbose):
                    logger.error("Failed to seed development data")
                    success = False
                else:
                    logger.info("Development data seeding completed successfully")
        
        if success:
            logger.info("✅ All seeding operations completed successfully")
            return 0
        else:
            logger.warning("❌ Some seeding operations failed")
            return 1
            
    except Exception as e:
        logger.exception("Unexpected error during data seeding: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())