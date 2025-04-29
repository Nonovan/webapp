#!/usr/bin/env python3
"""
Security Dashboard Generator for Cloud Infrastructure Platform

Generates an HTML dashboard summarizing the current security posture,
including metrics, active alerts, incidents, and threat intelligence updates.
Designed for security operations personnel.

Usage:
    python admin/security/monitoring/security_dashboard.py [options]

Options:
    --environment <env>   Target environment (e.g., production, staging). Default: production.
    --output <file>       Path to the output HTML file. Default: /var/www/security/dashboard.html
    --template <file>     Path to the Jinja2 template file. Default: templates/dashboard.html
    --hours <N>           Time window in hours for recent data (e.g., alerts). Default: 24.
    --log-file <file>     Path to the log file.
    --verbose, -v         Enable verbose logging.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- Project Setup ---
# Assuming the script is run from the project root or its path is correctly handled
try:
    # Try adding the project root to the path for module imports
    PROJECT_ROOT = Path(__file__).resolve().parents[3]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.append(str(PROJECT_ROOT))

    # --- Import Core & Admin Components ---
    from flask import Flask
    from core.factory import create_app # For app context if needed
    from core.security.cs_audit import get_recent_security_events, log_security_event
    from core.security.cs_metrics import get_security_metrics_summary
    from core.security.cs_monitoring import get_threat_summary, get_security_anomalies
    from core.security.cs_utils import get_security_status_summary
    # Import admin utils if available and needed
    from admin.utils.audit_utils import (
        log_admin_action, SEVERITY_INFO, SEVERITY_ERROR, STATUS_SUCCESS, STATUS_FAILURE,
        ACTION_REPORT_GENERATION
    )
    # Import monitoring utils
    from admin.security.monitoring.utils.alert_formatter import sanitize_alert_data # Example utility
    CORE_AVAILABLE = True
    ADMIN_UTILS_AVAILABLE = True
    MONITORING_UTILS_AVAILABLE = True

except ImportError as e:
    print(f"Warning: Error importing application modules: {e}", file=sys.stderr)
    print("Core application context or utils may not be available. Functionality might be limited.", file=sys.stderr)
    CORE_AVAILABLE = False
    ADMIN_UTILS_AVAILABLE = False
    MONITORING_UTILS_AVAILABLE = False
    # Define dummy functions/classes if needed for basic operation
    def get_recent_security_events(*args, **kwargs) -> List[Dict[str, Any]]: return []
    def log_security_event(*args, **kwargs): pass
    def get_security_metrics_summary(*args, **kwargs) -> Dict[str, Any]: return {}
    def get_threat_summary(*args, **kwargs) -> Dict[str, Any]: return {}
    def get_security_anomalies(*args, **kwargs) -> List[Dict[str, Any]]: return []
    def get_security_status_summary(*args, **kwargs) -> Dict[str, Any]: return {'status': 'unknown'}
    def log_admin_action(*args, **kwargs): pass
    def sanitize_alert_data(data, **kwargs): return data # Passthrough if util unavailable
    SEVERITY_INFO = "info"
    SEVERITY_ERROR = "error"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    ACTION_REPORT_GENERATION = "report.generate.security_dashboard"

# --- Configuration ---
ADMIN_MONITORING_DIR = Path(__file__).parent.resolve()
DEFAULT_TEMPLATE_DIR = ADMIN_MONITORING_DIR / "templates"
DEFAULT_TEMPLATE_FILE = DEFAULT_TEMPLATE_DIR / "dashboard.html"
DEFAULT_LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "security_dashboard.log"
DEFAULT_OUTPUT_DIR = Path(os.environ.get("SECURITY_REPORT_DIR", "/var/www/reports/security"))
DEFAULT_OUTPUT_FILE = DEFAULT_OUTPUT_DIR / "dashboard.html"
DEFAULT_ENV = "production"
DEFAULT_HOURS = 24

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ensure directories exist
DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Helper Functions ---

def get_cached_data(cache_file: Path, ttl: int) -> Optional[Dict[str, Any]]:
    """Retrieve data from cache if it exists and is within TTL."""
    if not cache_file.exists():
        return None

    try:
        # Check file modification time
        mtime = cache_file.stat().st_mtime
        if (time.time() - mtime) > ttl:
            logger.debug(f"Cache expired (TTL: {ttl}s)")
            return None

        # Read and parse cache file
        with open(cache_file, 'r') as f:
            data = json.load(f)
            logger.info(f"Using cached data from {cache_file}")
            return data
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Error reading cache: {e}")
        return None

def save_to_cache(data: Dict[str, Any], cache_file: Path) -> bool:
    """Save data to cache file."""
    try:
        with open(cache_file, 'w') as f:
            json.dump(data, f, default=str)
        logger.debug(f"Data cached to {cache_file}")
        return True
    except IOError as e:
        logger.warning(f"Failed to cache data: {e}")
        return False

def set_secure_permissions(file_path: Path) -> None:
    """Set secure permissions on the generated file."""
    try:
        # Set 0640 permissions (owner read/write, group read, no permissions for others)
        os.chmod(file_path, 0o640)
        logger.debug(f"Set secure permissions on {file_path}")
    except OSError as e:
        logger.warning(f"Failed to set permissions on {file_path}: {e}")

def fetch_dashboard_data(hours: int, environment: str, min_severity: str = "all") -> Dict[str, Any]:
    """Fetches all necessary data for the dashboard."""
    logger.info(f"Fetching dashboard data for the last {hours} hours (Environment: {environment}, Min Severity: {min_severity})...")
    data = {}
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)

    try:
        # Overall Status
        data['overall_status'] = get_security_status_summary()

        # Security Metrics
        data['security_metrics'] = get_security_metrics_summary(hours=hours)

        # Threat Summary (includes anomalies, threat IPs, file integrity etc.)
        data['threat_summary'] = get_threat_summary() # Assumes this function gets recent relevant threats

        # Determine severity levels based on min_severity
        severity_levels = []
        if min_severity == "critical":
            severity_levels = ["critical"]
        elif min_severity == "high":
            severity_levels = ["critical", "high"]
        elif min_severity == "medium":
            severity_levels = ["critical", "high", "medium"]
        elif min_severity == "low":
            severity_levels = ["critical", "high", "medium", "low"]
        elif min_severity == "info" or min_severity == "all":
            severity_levels = ["critical", "high", "medium", "low", "info"]

        # Recent Alerts (Filtered by severity)
        critical_alerts = get_recent_security_events(
            start_time=start_time,
            end_time=end_time,
            severity_levels=severity_levels,
            limit=20 # Limit the number of alerts shown
        )
        # Sanitize alert data before passing to template
        data['critical_alerts'] = [sanitize_alert_data(alert, format='html') for alert in critical_alerts] if MONITORING_UTILS_AVAILABLE else critical_alerts

        # Incident Count (Placeholder - requires incident management integration)
        data['incident_count'] = data['security_metrics'].get('incidents_active', 0) # Example from metrics

        # Threat Intel Updates (Placeholder - requires threat_intelligence.py integration)
        # Could read a summary file or call a function from threat_intelligence.py
        data['threat_intel_updates'] = {"last_update": "N/A", "new_indicators": 0} # Dummy data

        logger.info("Successfully fetched dashboard data.")
    except Exception as e:
        logger.error(f"Failed to fetch dashboard data: {e}", exc_info=True)
        # Return partial data or defaults
        data.setdefault('overall_status', {'status': 'error', 'details': str(e)})
        data.setdefault('security_metrics', {})
        data.setdefault('threat_summary', {})
        data.setdefault('critical_alerts', [])
        data.setdefault('incident_count', 'N/A')
        data.setdefault('threat_intel_updates', {})

    return data

def render_dashboard(data: Dict[str, Any], template_file: str, output_file: str) -> None:
    """Renders the dashboard using Jinja2 template."""
    logger.info(f"Rendering dashboard to {output_file} using template {template_file}...")
    try:
        env = Environment(
            loader=FileSystemLoader(str(DEFAULT_TEMPLATE_DIR)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template(template_file)
        output = template.render(data)

        with open(output_file, 'w') as f:
            f.write(output)

        # Set secure permissions on the output file
        set_secure_permissions(Path(output_file))

        logger.info("Dashboard rendered successfully.")
    except Exception as e:
        logger.error(f"Failed to render dashboard: {e}", exc_info=True)
        raise
    # Log the action
    log_admin_action(
        action=ACTION_REPORT_GENERATION,
        status=STATUS_SUCCESS,
        severity=SEVERITY_INFO,
        message=f"Dashboard generated successfully at {output_file}",
        details=data
    )

def main() -> int:
    """Main entry point for security dashboard generator."""
    parser = argparse.ArgumentParser(description="Security Dashboard Generator")
    parser.add_argument(
        "--environment", "-e",
        default=DEFAULT_ENV,
        help=f"Target environment (production, staging, development). Default: {DEFAULT_ENV}"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path to the output HTML file. Default: {DEFAULT_OUTPUT_FILE}"
    )
    parser.add_argument(
        "--template", "-t",
        type=str,
        default="dashboard.html",
        help="Template file name to use (from templates directory). Default: dashboard.html"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=DEFAULT_HOURS,
        help=f"Time window in hours for recent data. Default: {DEFAULT_HOURS}"
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help=f"Path to the log file. Default: {DEFAULT_LOG_FILE}"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info", "all"],
        default="all",
        help="Filter alerts by minimum severity level. Default: all"
    )
    parser.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Output format (default: html)"
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Use cached data if available and not expired"
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=300,  # 5 minutes
        help="Cache time-to-live in seconds. Default: 300"
    )

    args = parser.parse_args()

    # Configure file logging
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    # Set log level if verbose
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    logger.info(f"Starting Security Dashboard Generator (Environment: {args.environment}, Hours: {args.hours})")

    # Create parent directories for the output file if needed
    args.output.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Check for cached data if requested
        dashboard_data = None
        cache_file = Path(f"{args.output}.cache.json")

        if args.cache:
            dashboard_data = get_cached_data(cache_file, args.cache_ttl)

        if not dashboard_data:
            # Fetch security data
            dashboard_data = fetch_dashboard_data(args.hours, args.environment)

            # Add metadata
            dashboard_data['metadata'] = {
                'generated_at': datetime.now().isoformat(),
                'environment': args.environment,
                'time_window_hours': args.hours
            }

            # Cache the data
            if args.cache:
                save_to_cache(dashboard_data, cache_file)

        if args.format == "json":
            # Output JSON format
            with open(args.output, 'w') as f:
                json.dump(dashboard_data, f, indent=2, default=str)
            set_secure_permissions(args.output)
            logger.info(f"Security dashboard JSON data written to {args.output}")
        else:
            # Render HTML dashboard
            render_dashboard(dashboard_data, args.template, args.output)
            logger.info(f"Security dashboard HTML successfully generated at {args.output}")

        return 0
    except Exception as e:
        logger.error(f"Failed to generate security dashboard: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    # If run as a script, execute main
    sys.exit(main())
