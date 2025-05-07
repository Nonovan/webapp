"""
File Integrity Monitoring Module

This module provides a Python interface to the integrity_monitor.sh bash script,
allowing for programmatic initialization, configuration, and execution of file
integrity monitoring.

It enables verification of file integrity against established baselines,
detection of unauthorized modifications, and alerting on potential security incidents.
"""

import os
import subprocess
import logging
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple

# Import constants if available
try:
    from .monitoring_constants import INTEGRITY_MONITORING, VERSION
    CONSTANTS_AVAILABLE = True
except ImportError:
    CONSTANTS_AVAILABLE = False

# Configure module logger
logger = logging.getLogger(__name__)

# Constants
SCRIPT_PATH = Path(__file__).parent / "integrity_monitor.sh"
DEFAULT_CONFIG_DIR = Path(__file__).parent / "config"
DEFAULT_BASELINE_DIR = DEFAULT_CONFIG_DIR / "baseline"

def initialize_monitoring(config_path: Optional[str] = None) -> bool:
    """
    Initialize file integrity monitoring with optional custom configuration.

    Args:
        config_path: Optional path to a custom configuration file

    Returns:
        bool: True if initialization was successful
    """
    logger.debug("Initializing file integrity monitoring")

    # Check if the shell script exists
    if not SCRIPT_PATH.exists():
        logger.error(f"Integrity monitoring script not found at {SCRIPT_PATH}")
        return False

    # Make sure script is executable
    try:
        SCRIPT_PATH.chmod(SCRIPT_PATH.stat().st_mode | 0o100)
    except Exception as e:
        logger.error(f"Failed to set executable permissions on script: {e}")
        return False

    # Check or create default directories
    try:
        DEFAULT_BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create baseline directory: {e}")
        return False

    # Test script with --help to verify it works
    try:
        result = subprocess.run(
            [str(SCRIPT_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            logger.error(f"Script test failed with exit code {result.returncode}: {result.stderr}")
            return False
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to execute integrity script: {e}")
        return False

    logger.info("File integrity monitoring initialized successfully")
    return True

def run_integrity_check(
    baseline_path: Optional[str] = None,
    scan_scope: str = "critical",
    output_format: str = "json",
    report_file: Optional[str] = None,
    verify_signatures: bool = False,
    alert_on_change: bool = True
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Run a file integrity check using the integrity monitoring script.

    Args:
        baseline_path: Path to baseline file (uses default if None)
        scan_scope: Scope of files to scan ("critical", "config", "all", or custom path)
        output_format: Output format ("json" or "text")
        report_file: Path to save the report (auto-generated if None)
        verify_signatures: Whether to verify file signatures if available
        alert_on_change: Whether to send alerts on detected changes

    Returns:
        Tuple containing:
        - bool: True if no integrity issues found
        - Optional[str]: Path to the report file if generated
        - Optional[Dict[str, Any]]: JSON report data if available
    """
    if not SCRIPT_PATH.exists():
        logger.error(f"Integrity monitoring script not found at {SCRIPT_PATH}")
        return False, None, None

    cmd = [str(SCRIPT_PATH)]

    # Add arguments
    if baseline_path:
        cmd.extend(["--baseline", baseline_path])

    cmd.extend(["--scope", scan_scope])
    cmd.extend(["--output-format", output_format])

    if report_file:
        cmd.extend(["--report-file", report_file])

    if verify_signatures:
        cmd.append("--verify-signatures")

    if not alert_on_change:
        cmd.append("--no-alert")

    # Run the command
    try:
        logger.debug(f"Running integrity check: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        # The script returns non-zero if changes are detected
        success = result.returncode == 0

        # Find report file path from output if not specified
        if not report_file and "Report saved to" in result.stdout:
            for line in result.stdout.splitlines():
                if "Report saved to" in line:
                    report_file = line.split("Report saved to")[-1].strip()
                    break

        # Parse report if it's JSON and file exists
        report_data = None
        if report_file and os.path.exists(report_file) and output_format == "json":
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON report: {e}")

        # Log appropriate message based on result
        if success:
            logger.info("File integrity check completed, no changes detected")
        else:
            logger.warning("File integrity check detected changes")

        return success, report_file, report_data

    except subprocess.SubprocessError as e:
        logger.error(f"Failed to execute integrity check: {e}")
        return False, None, None

def create_baseline(
    directory_path: str,
    output_file: Optional[str] = None,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Create a new file integrity baseline.

    Args:
        directory_path: Directory to generate baseline for
        output_file: Path to save the baseline (uses default if None)
        include_patterns: List of file patterns to include
        exclude_patterns: List of file patterns to exclude

    Returns:
        Tuple containing:
        - bool: True if baseline creation was successful
        - Optional[str]: Path to the created baseline file if successful
    """
    if not SCRIPT_PATH.exists():
        logger.error(f"Integrity monitoring script not found at {SCRIPT_PATH}")
        return False, None

    cmd = [str(SCRIPT_PATH), "--create-baseline"]

    # Add arguments
    cmd.extend(["--scope", directory_path])

    if output_file:
        cmd.extend(["--baseline-output", output_file])

    if include_patterns:
        for pattern in include_patterns:
            cmd.extend(["--include", pattern])

    if exclude_patterns:
        for pattern in exclude_patterns:
            cmd.extend(["--exclude", pattern])

    # Run the command
    try:
        logger.debug(f"Creating baseline: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        success = result.returncode == 0

        # Extract baseline file path from output
        baseline_file = None
        if success:
            for line in result.stdout.splitlines():
                if "Baseline saved to" in line:
                    baseline_file = line.split("Baseline saved to")[-1].strip()
                    break

        if success:
            logger.info(f"Baseline created successfully: {baseline_file}")
        else:
            logger.error(f"Baseline creation failed: {result.stderr}")

        return success, baseline_file

    except subprocess.SubprocessError as e:
        logger.error(f"Failed to create baseline: {e}")
        return False, None

def get_integrity_status() -> Dict[str, Any]:
    """
    Get current file integrity monitoring status.

    Returns:
        Dict with status information including:
        - enabled: Whether monitoring is enabled
        - last_check: Timestamp of last check
        - baseline_exists: Whether baseline exists
        - changes_detected: Whether changes were detected
    """
    status = {
        "enabled": SCRIPT_PATH.exists(),
        "last_check": None,
        "baseline_exists": False,
        "changes_detected": False,
        "monitored_files_count": 0,
        "version": getattr(VERSION, "__version__", "1.0.0") if CONSTANTS_AVAILABLE else "1.0.0"
    }

    # Check if baseline exists
    baseline_path = DEFAULT_BASELINE_DIR / "integrity_baseline.json"
    if baseline_path.exists():
        status["baseline_exists"] = True
        try:
            # Get baseline statistics
            with open(baseline_path, 'r') as f:
                baseline_data = json.load(f)
                if isinstance(baseline_data, dict):
                    status["monitored_files_count"] = len(baseline_data)
                    status["baseline_created"] = os.path.getctime(baseline_path)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read baseline file: {e}")

    # Check for recent reports to determine last check time and status
    try:
        report_dir = Path(os.environ.get("SECURITY_REPORT_DIR", "/var/www/reports/security"))
        if report_dir.exists():
            reports = sorted(report_dir.glob("integrity_report-*.json"), key=os.path.getmtime, reverse=True)
            if reports:
                last_report = reports[0]
                status["last_check"] = os.path.getmtime(last_report)

                # Check if changes were detected in the most recent report
                try:
                    with open(last_report, 'r') as f:
                        report_data = json.load(f)
                        status["changes_detected"] = report_data.get("summary", {}).get("changes_detected", False)
                        status["findings_count"] = len(report_data.get("findings", []))
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Failed to read report file: {e}")
    except Exception as e:
        logger.warning(f"Failed to get integrity status: {e}")

    return status

# Export public API
__all__ = [
    "initialize_monitoring",
    "run_integrity_check",
    "create_baseline",
    "get_integrity_status",
]

if __name__ == "__main__":
    # Setup logging for direct execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Test integrity monitoring initialization
    print(f"Initializing file integrity monitoring: {initialize_monitoring()}")

    # Show status
    print(f"Current status: {json.dumps(get_integrity_status(), indent=2, default=str)}")
