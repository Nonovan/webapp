#!/usr/bin/env python3
"""
Security Log Analyzer for Cloud Infrastructure Platform.

Analyzes various system and application logs to detect suspicious activities,
potential security incidents, and anomalies based on predefined patterns
and thresholds.

Usage: python log_analyzer.py [--log-files <file1> <file2>...] [--last-hours N]
                             [--detect-threats] [--output-format <format>] [--verbose]
"""

import argparse
import enum
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Pattern

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
LOG_DIR = Path("/var/log/cloud-platform/security")
LOG_FILE = LOG_DIR / "log_analyzer.log"
DEFAULT_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",  # CentOS/RHEL equivalent of auth.log
    "/var/log/syslog",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/cloud-platform/app.log", # Assuming application log path
]
DEFAULT_LAST_HOURS = 24
DEFAULT_OUTPUT_FORMAT = "text" # Options: text, json

# Ensure log directory exists
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    print(f"Warning: Could not create log directory {LOG_DIR}. Logging to stderr.", file=sys.stderr)
    LOG_FILE = None # Disable file logging if directory creation fails
except Exception as e:
    print(f"Warning: Error setting up log directory {LOG_DIR}: {e}. Logging to stderr.", file=sys.stderr)
    LOG_FILE = None

# Setup logging
log_handlers: List[logging.Handler] = [logging.StreamHandler()]
if LOG_FILE:
    log_handlers.append(logging.FileHandler(str(LOG_FILE)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("log_analyzer")

# --- Severity Enum ---
class Severity(enum.Enum):
    """Enumeration of severity levels for findings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# --- Suspicious Patterns ---
# Regex patterns to detect potential security issues
# Using compiled regex for performance
SUSPICIOUS_PATTERNS: Dict[str, Tuple[Pattern[str], Severity, str]] = {
    "failed_login": (
        re.compile(r'(fail|error|invalid).*login|authentication failure|failed password', re.IGNORECASE),
        Severity.MEDIUM,
        "Multiple failed login attempts detected."
    ),
    "ssh_root_login_attempt": (
        re.compile(r'sshd.*invalid user root|sshd.*failed password for root', re.IGNORECASE),
        Severity.HIGH,
        "Attempted root login via SSH."
    ),
    "sudo_failure": (
        re.compile(r'sudo.*incorrect password attempt|sudo.*authentication failure', re.IGNORECASE),
        Severity.MEDIUM,
        "Failed sudo attempts detected."
    ),
    "possible_sqli": (
        re.compile(r'(\%27)|(\')|(\-\-)|(\%23)|(#)', re.IGNORECASE), # Basic SQLi detection
        Severity.HIGH,
        "Potential SQL injection attempt detected in web logs."
    ),
    "possible_xss": (
        re.compile(r'(<script>|%3Cscript%3E|javascript:)', re.IGNORECASE), # Basic XSS detection
        Severity.MEDIUM,
        "Potential Cross-Site Scripting (XSS) attempt detected in web logs."
    ),
    "error_spike": (
        re.compile(r'error|exception|critical|fatal', re.IGNORECASE),
        Severity.INFO, # Severity raised based on count/frequency
        "Spike in error messages detected."
    ),
}

# --- Log Parsing Regex ---
# Generic syslog format: "MMM DD HH:MM:SS hostname process[pid]: message"
# More modern format (RFC 5424): "YYYY-MM-DDTHH:MM:SS.msZ hostname process[pid]: message"
LOG_LINE_REGEX = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# --- Argument Parser ---
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument(
        "--log-files",
        nargs="+",
        help=f"List of log files to analyze (default: {' '.join(DEFAULT_LOG_FILES)})",
        default=None # Use default later if None
    )
    parser.add_argument(
        "--last-hours",
        type=int,
        default=DEFAULT_LAST_HOURS,
        help="Analyze logs from the last N hours (default: %(default)s)"
    )
    parser.add_argument(
        "--detect-threats",
        action="store_true",
        help="Enable pattern-based threat detection (default: False)"
    )
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format for the report (default: %(default)s)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    return parser.parse_args()

# --- Log Analyzer Class ---
class LogAnalyzer:
    """Analyzes log files for security events and anomalies."""

    def __init__(self, config: argparse.Namespace):
        """Initialize the LogAnalyzer."""
        self.config = config
        self.findings: List[Dict[str, Any]] = []
        self.start_time = datetime.now(timezone.utc) - timedelta(hours=config.last_hours)
        self.log_files = config.log_files if config.log_files else DEFAULT_LOG_FILES

        # Counters for anomaly detection
        self.event_counters: Dict[str, Counter] = defaultdict(Counter)
        self.line_count = 0
        self.error_count = 0

        logger.info("Log Analyzer initialized. Analyzing logs since %s", self.start_time.isoformat())
        logger.debug("Configuration: %s", config)
        logger.debug("Log files to analyze: %s", self.log_files)

    def add_finding(self, severity: Severity, title: str, description: str, details: Optional[Dict] = None) -> None:
        """Add a finding to the list."""
        finding = {
            "severity": severity.value,
            "title": title,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        self.findings.append(finding)
        logger.log(
            logging.WARNING if severity in [Severity.HIGH, Severity.CRITICAL] else logging.INFO,
            f"Finding [{severity.value}]: {title} - {description}"
        )

    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse a log line using common formats."""
        match = LOG_LINE_REGEX.match(line)
        if match:
            data = match.groupdict()
            # Attempt to parse timestamp (basic formats)
            try:
                # Try ISO format first
                ts_str = data['timestamp'].replace('Z', '+00:00')
                timestamp = datetime.fromisoformat(ts_str)
            except ValueError:
                try:
                    # Try syslog format (requires year context, assume current year)
                    current_year = datetime.now().year
                    ts_str = f"{data['timestamp']} {current_year}"
                    timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc) # Assume UTC if no tz
                except ValueError:
                    timestamp = None # Cannot parse timestamp

            data['parsed_timestamp'] = timestamp
            return data
        return None

    def _check_patterns(self, message: str, line_data: Dict[str, Any]) -> None:
        """Check the log message against predefined suspicious patterns."""
        if not self.config.detect_threats:
            return

        for key, (pattern, severity, title) in SUSPICIOUS_PATTERNS.items():
            if pattern.search(message):
                # Increment counter for anomaly detection
                self.event_counters[key].update([line_data.get('hostname', 'unknown')])

                # Add finding immediately for high/critical patterns
                if severity in [Severity.HIGH, Severity.CRITICAL]:
                     self.add_finding(severity, title, f"Pattern '{key}' matched.", details={"log_line": line_data.get('raw_line', message)})

    def _detect_anomalies(self) -> None:
        """Analyze collected counters to detect anomalies."""
        logger.info("Analyzing collected event counts for anomalies...")

        # Example: Failed Logins Anomaly
        failed_login_counts = self.event_counters.get("failed_login")
        if failed_login_counts:
            total_failed = sum(failed_login_counts.values())
            if total_failed > 10: # Arbitrary threshold
                severity = Severity.HIGH if total_failed > 50 else Severity.MEDIUM
                self.add_finding(
                    severity,
                    "Multiple Failed Logins Detected",
                    f"Detected {total_failed} failed login attempts across hosts.",
                    details={"counts_per_host": dict(failed_login_counts)}
                )

        # Example: Error Spike Anomaly
        error_counts = self.event_counters.get("error_spike")
        if error_counts:
            total_errors = sum(error_counts.values())
            if self.line_count > 0 and (total_errors / self.line_count) > 0.1: # If > 10% lines are errors
                 self.add_finding(
                    Severity.MEDIUM,
                    "High Error Rate Detected",
                    f"Detected {total_errors} errors ({total_errors * 100 / self.line_count:.1f}%) in {self.line_count} lines.",
                    details={"error_counts_per_host": dict(error_counts)}
                )

        # Add more anomaly detection rules here (e.g., time-based anomalies, frequency changes)

    def analyze_log_file(self, file_path: Path) -> None:
        """Analyze a single log file."""
        logger.info("Analyzing log file: %s", file_path)
        try:
            with file_path.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    self.line_count += 1
                    line = line.strip()
                    if not line:
                        continue

                    parsed_data = self._parse_log_line(line)

                    if parsed_data:
                        # Check if line is within the time window
                        if parsed_data['parsed_timestamp'] and parsed_data['parsed_timestamp'] < self.start_time:
                            continue # Skip lines older than the window

                        parsed_data['raw_line'] = line # Keep raw line for context
                        message = parsed_data.get('message', '')
                        self._check_patterns(message, parsed_data)
                    else:
                        # If parsing fails, check raw line against patterns
                         self._check_patterns(line, {"raw_line": line})

        except FileNotFoundError:
            logger.warning("Log file not found: %s", file_path)
        except PermissionError:
            logger.error("Permission denied when reading log file: %s", file_path)
            self.add_finding(Severity.LOW, "Permission Denied", f"Cannot read log file: {file_path}", details={"file": str(file_path)})
        except Exception as e:
            logger.error("Error reading log file %s: %s", file_path, e)
            self.add_finding(Severity.LOW, "File Read Error", f"Error reading log file: {file_path}", details={"file": str(file_path), "error": str(e)})

    def analyze(self) -> None:
        """Orchestrate the analysis of specified log files."""
        for file_str in self.log_files:
            file_path = Path(file_str)
            if file_path.is_dir():
                logger.warning("Path %s is a directory, skipping.", file_path)
                continue
            self.analyze_log_file(file_path)

        # Perform anomaly detection based on aggregated counts
        self._detect_anomalies()

        logger.info(
            "Analysis complete. Processed %d lines. Found %d potential issues.",
            self.line_count, len(self.findings)
        )

    def generate_report(self) -> str:
        """Generate a report based on the findings."""
        if self.config.output_format == "json":
            import json
            report_data = {
                "analysis_start_time": self.start_time.isoformat(),
                "analysis_end_time": datetime.now(timezone.utc).isoformat(),
                "total_lines_processed": self.line_count,
                "findings": sorted(self.findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])),
            }
            return json.dumps(report_data, indent=2)
        else: # Text format
            report = f"Security Log Analysis Report ({self.start_time.isoformat()} to {datetime.now(timezone.utc).isoformat()})\n"
            report += f"======================================================================\n"
            report += f"Processed {self.line_count} log lines from {len(self.log_files)} files.\n"
            report += f"Found {len(self.findings)} potential issues.\n\n"

            if not self.findings:
                report += "No significant issues detected.\n"
                return report

            report += "Findings (sorted by severity):\n"
            report += "-----------------------------\n"
            # Sort findings by severity
            sorted_findings = sorted(self.findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"]))

            for finding in sorted_findings:
                report += f"\n[{finding['severity']}] {finding['title']}\n"
                report += f"  Description: {finding['description']}\n"
                if finding.get('details'):
                    details_str = str(finding['details'])
                    # Truncate long details in text report
                    if len(details_str) > 200:
                         details_str = details_str[:200] + "..."
                    report += f"  Details: {details_str}\n"
                report += f"  Detected At: {finding['timestamp']}\n"

            return report

# --- Main Execution ---
def main() -> int:
    """Main entry point for the log analyzer script."""
    args = parse_arguments()

    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting Log Analyzer...")

    analyzer = LogAnalyzer(args)
    analyzer.analyze()
    report = analyzer.generate_report()

    print(report)

    # Exit code based on highest severity finding
    highest_severity = Severity.INFO
    for finding in analyzer.findings:
        severity = Severity(finding['severity'])
        if ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(severity.value) < \
           ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(highest_severity.value):
            highest_severity = severity

    if highest_severity == Severity.CRITICAL:
        return 2
    elif highest_severity == Severity.HIGH:
        return 1
    else:
        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Log analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.critical("An unexpected error occurred: %s", e, exc_info=True)
        sys.exit(3)
