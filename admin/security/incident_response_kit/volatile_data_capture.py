#!/usr/bin/env python3
# filepath: admin/security/incident_response_kit/volatile_data_capture.py
"""
Volatile Data Capture Tool

This script provides functionality to capture volatile system data during security incident
response. It captures process information, network connections, user sessions, loaded modules,
and other volatile artifacts that would be lost after system shutdown.

The tool follows forensic best practices for evidence collection, ensuring data integrity
through proper hashing, chain of custody documentation, and minimal system impact.

This is a wrapper around the forensics/live_response toolkit's volatile_data.sh script,
providing an easy-to-use Python interface for incident responders.
"""

import os
import sys
import logging
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Set, Union

# Configure logging
logger = logging.getLogger(__name__)

# Determine module path
MODULE_PATH = Path(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = MODULE_PATH.parent.parent.parent

# Ensure forensics module is in path
sys.path.insert(0, str(PROJECT_ROOT))

# Import necessary modules
try:
    # Import constants and configuration
    from admin.security.incident_response_kit import (
        response_config, tool_paths, CONFIG_AVAILABLE, ValidationError,
        EvidenceCollectionError, sanitize_incident_id, create_evidence_directory
    )

    # Import forensics live response module
    from admin.security.forensics.live_response import (
        get_collector, LiveResponseConfig, VolatileDataCollector,
        update_evidence_integrity_baseline, verify_evidence_integrity
    )

    LIVE_RESPONSE_AVAILABLE = True

except ImportError as e:
    logger.error(f"Required modules not available: {e}")
    LIVE_RESPONSE_AVAILABLE = False


class VolatileDataCapture:
    """Class for capturing volatile data from target systems"""

    def __init__(self,
                incident_id: Optional[str] = None,
                output_dir: Optional[str] = None,
                analyst: Optional[str] = None):
        """
        Initialize the volatile data capture tool.

        Args:
            incident_id: Optional incident identifier
            output_dir: Directory to store collected evidence
            analyst: Name of the analyst performing the collection
        """
        self.incident_id = incident_id
        self.analyst = analyst or os.environ.get('USER', 'unknown')

        # Determine output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        elif incident_id:
            self.output_dir = create_evidence_directory(incident_id) / "volatile"
        else:
            default_dir = response_config.get("evidence_collection", {}).get("base_dir", "/secure/evidence")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path(default_dir) / f"volatile_{timestamp}"

        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"Output directory set to: {self.output_dir}")

    def capture(self,
               target: Optional[str] = None,
               categories: Optional[List[str]] = None,
               minimal: bool = False,
               process_args: bool = True,
               process_env: bool = False,
               include_modules: bool = True,
               verify_integrity: bool = True,
               user: Optional[str] = None,
               key_file: Optional[str] = None,
               port: int = 22) -> Tuple[bool, str]:
        """
        Capture volatile data from the target system.

        Args:
            target: Target hostname or IP address (None for local system)
            categories: List of data categories to collect
                        (processes, network, users, services, system_info, etc.)
            minimal: Perform minimal collection (faster but less comprehensive)
            process_args: Include process command line arguments
            process_env: Include process environment variables
            include_modules: Collect kernel module information
            verify_integrity: Create and verify integrity baseline after collection
            user: SSH username for remote collection
            key_file: SSH key file for remote collection
            port: SSH port for remote collection

        Returns:
            Tuple of (success, output_directory)

        Raises:
            EvidenceCollectionError: If the collection fails
            ValidationError: If required tools are not available
        """
        if not LIVE_RESPONSE_AVAILABLE:
            raise ValidationError("Forensic live response tools not available")

        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

        # Create a live response config
        config = LiveResponseConfig(
            output_dir=str(self.output_dir),
            case_id=self.incident_id,
            examiner=self.analyst,
            target=target,
            target_user=user,
            target_key=key_file,
            target_port=port
        )

        # Get a volatile data collector
        collector = get_collector('volatile_data', config)
        if not isinstance(collector, VolatileDataCollector):
            raise ValidationError("Failed to initialize volatile data collector")

        # Start the collection
        logger.info(f"Starting volatile data collection on {'local system' if not target else target}")
        success, output_path = collector.collect(
            categories=categories,
            minimal=minimal,
            process_args=process_args,
            process_env=process_env,
            include_modules=include_modules
        )

        if not success:
            error_msg = f"Volatile data collection failed on {'local system' if not target else target}"
            logger.error(error_msg)
            raise EvidenceCollectionError(error_msg)

        # Create integrity baseline if requested
        if verify_integrity and success:
            try:
                baseline_success, baseline_path = update_evidence_integrity_baseline(
                    evidence_dir=output_path,
                    case_id=self.incident_id,
                    examiner=self.analyst
                )

                if baseline_success:
                    logger.info(f"Created integrity baseline at {baseline_path}")
                else:
                    logger.warning("Failed to create integrity baseline")

            except Exception as e:
                logger.error(f"Error creating integrity baseline: {e}")

        logger.info(f"Volatile data collection completed successfully. Evidence stored in {output_path}")
        return success, output_path

    @staticmethod
    def available_categories() -> List[str]:
        """Return a list of available data collection categories"""
        return [
            "processes", "network", "users", "services", "modules",
            "startup_items", "scheduled_tasks", "command_history",
            "login_history", "open_files", "system_info", "environment_variables"
        ]


def main() -> int:
    """Command-line entry point for volatile data capture"""
    parser = argparse.ArgumentParser(description="Capture volatile system data for incident response")

    # Basic arguments
    parser.add_argument("--incident-id", help="Incident identifier")
    parser.add_argument("--output", help="Directory to store collected evidence")
    parser.add_argument("--analyst", help="Name of the analyst performing the collection")

    # Collection parameters
    parser.add_argument("--target", help="Target hostname or IP address (default: local system)")
    parser.add_argument("--categories", help="Comma-separated list of data categories to collect")
    parser.add_argument("--minimal", action="store_true", help="Perform minimal collection")
    parser.add_argument("--no-process-args", action="store_true",
                      help="Don't collect process command line arguments")
    parser.add_argument("--process-env", action="store_true",
                      help="Collect process environment variables")
    parser.add_argument("--no-modules", action="store_true",
                      help="Skip kernel module collection")
    parser.add_argument("--no-verify", action="store_true",
                      help="Skip integrity verification")

    # Remote connection options
    parser.add_argument("--user", help="SSH username for remote collection")
    parser.add_argument("--key-file", help="SSH key file for remote collection")
    parser.add_argument("--port", type=int, default=22, help="SSH port for remote collection")

    # Utility options
    parser.add_argument("--list-categories", action="store_true",
                      help="List available data categories")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Show categories if requested
    if args.list_categories:
        categories = VolatileDataCapture.available_categories()
        print("Available data collection categories:")
        for category in categories:
            print(f"  - {category}")
        return 0

    try:
        # Create the volatile data capture instance
        capture = VolatileDataCapture(
            incident_id=args.incident_id,
            output_dir=args.output,
            analyst=args.analyst
        )

        # Parse categories if provided
        categories = None
        if args.categories:
            categories = [c.strip() for c in args.categories.split(',')]

        # Perform the collection
        success, output_path = capture.capture(
            target=args.target,
            categories=categories,
            minimal=args.minimal,
            process_args=not args.no_process_args,
            process_env=args.process_env,
            include_modules=not args.no_modules,
            verify_integrity=not args.no_verify,
            user=args.user,
            key_file=args.key_file,
            port=args.port
        )

        print(f"Volatile data collection {'successful' if success else 'failed'}!")
        print(f"Output directory: {output_path}")
        return 0 if success else 1

    except ValidationError as e:
        logger.error(f"Validation error: {str(e)}")
        return 1
    except EvidenceCollectionError as e:
        logger.error(f"Evidence collection error: {str(e)}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return 1


# Module exports
__all__ = [
    'VolatileDataCapture',
    'main'
]

if __name__ == "__main__":
    sys.exit(main())
