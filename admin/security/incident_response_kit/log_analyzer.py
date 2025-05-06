#!/usr/bin/env python3
"""
Log Analyzer for Security Incident Response

This tool analyzes various system and application logs to detect suspicious activities,
potential security incidents, and anomalies based on predefined patterns and thresholds.
It's integrated with the Incident Response Kit for automated detection and analysis.

The tool supports multiple log formats, customizable detection patterns, and outputs
findings in various formats suitable for incident reports and further analysis.
"""

import argparse
import enum
import json
import logging
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Pattern, Union, Set

# Add parent path to import path if running as script
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
if str(SCRIPT_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR.parent.parent))

# Try to import from incident response kit
try:
    from admin.security.incident_response_kit import (
        EvidenceType, IncidentType, IncidentResponseError,
        DEFAULT_LOG_DIR, DEFAULT_EVIDENCE_DIR,
        create_evidence_directory, sanitize_incident_id
    )
    from admin.security.incident_response_kit.incident_constants import (
        IncidentSeverity
    )
    IR_KIT_IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Error importing incident response kit modules: {e}", file=sys.stderr)
    print("Running in standalone mode with limited functionality", file=sys.stderr)
    IR_KIT_IMPORTS_AVAILABLE = False
    # Define fallbacks for required constants
    DEFAULT_LOG_DIR = Path("/var/log")
    DEFAULT_EVIDENCE_DIR = Path("/tmp/evidence")

    class IncidentSeverity:
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

    class EvidenceType:
        LOG_FILE = "log_file"

    class IncidentType:
        UNAUTHORIZED_ACCESS = "unauthorized_access"
        MALWARE = "malware"

    class IncidentResponseError(Exception):
        """Base exception for all incident response errors."""
        pass

    def create_evidence_directory(incident_id):
        """Create evidence directory fallback."""
        dir_path = Path(DEFAULT_EVIDENCE_DIR) / incident_id
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def sanitize_incident_id(incident_id):
        """Sanitize incident ID fallback."""
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', incident_id)

# Try to import core security utilities
try:
    from core.security.cs_audit import log_security_event
    from core.security.cs_file_integrity import calculate_file_hash
    CORE_SECURITY_AVAILABLE = True
except ImportError:
    CORE_SECURITY_AVAILABLE = False
    # Define fallbacks
    def log_security_event(event_type, description, severity="info", **kwargs):
        """Fallback logging function."""
        logger.info(f"[{severity.upper()}] {event_type}: {description}")
        if kwargs:
            logger.debug(f"Additional details: {kwargs}")

    def calculate_file_hash(file_path, algorithm='sha256'):
        """Calculate file hash fallback."""
        import hashlib
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

# Configuration
LOG_DIR = Path(os.environ.get("IR_LOG_DIR", DEFAULT_LOG_DIR))
LOG_FILE = LOG_DIR / "log_analyzer.log"
OUTPUT_DIR = Path(os.environ.get("IR_OUTPUT_DIR", str(DEFAULT_EVIDENCE_DIR / "log_analysis")))
DEFAULT_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",  # CentOS/RHEL equivalent of auth.log
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/cloud-platform/app.log",
    "/var/log/cloud-platform/security.log",
    "/var/log/cloud-platform/audit.log",
]
DEFAULT_LAST_HOURS = 24
DEFAULT_OUTPUT_FORMAT = "text"  # Options: text, json
MAX_SCAN_SIZE_MB = 500  # Maximum log file size to scan in MB

# Ensure log directory exists
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    print(f"Warning: Could not create log directory {LOG_DIR}. Logging to stderr.", file=sys.stderr)
    LOG_FILE = None  # Disable file logging if directory creation fails
except Exception as e:
    print(f"Warning: Error setting up log directory {LOG_DIR}: {e}. Logging to stderr.", file=sys.stderr)
    LOG_FILE = None

# Setup logging
log_handlers = [logging.StreamHandler()]
if LOG_FILE:
    try:
        log_handlers.append(logging.FileHandler(str(LOG_FILE)))
    except (PermissionError, IOError) as e:
        print(f"Warning: Could not create log file {LOG_FILE}: {e}. Logging to stderr only.", file=sys.stderr)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=log_handlers,
)
logger = logging.getLogger("log_analyzer")


# --- Severity Enum ---
class Severity(enum.Enum):
    """Enumeration of severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# --- Risk Rating ---
class RiskRating:
    """Risk rating calculation based on multiple factors."""

    @staticmethod
    def calculate(severity: Severity, count: int, timeframe_hours: int = 24) -> float:
        """
        Calculate risk rating based on severity, count, and timeframe.

        Args:
            severity: Severity level
            count: Number of occurrences
            timeframe_hours: Timeframe in hours

        Returns:
            Risk score from 0.0 to 1.0
        """
        # Base score by severity
        severity_scores = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.4,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1
        }

        base_score = severity_scores.get(severity, 0.1)

        # Adjust for frequency (count/timeframe)
        frequency_factor = min(1.0, count / (timeframe_hours * 2))

        # Calculate final score (max 1.0)
        return min(1.0, base_score + (frequency_factor * 0.3))


# --- Suspicious Patterns ---
# Regex patterns to detect potential security issues
# Using compiled regex for performance
SUSPICIOUS_PATTERNS: Dict[str, Tuple[Pattern[str], Severity, str]] = {
    "failed_login": (
        re.compile(r'(fail|error|invalid).*login|authentication failure|failed password|Login failed|Failed to authorize', re.IGNORECASE),
        Severity.MEDIUM,
        "Multiple failed login attempts detected"
    ),
    "ssh_root_login_attempt": (
        re.compile(r'sshd.*invalid user root|sshd.*failed password for root', re.IGNORECASE),
        Severity.HIGH,
        "Attempted root login via SSH"
    ),
    "sudo_failure": (
        re.compile(r'sudo.*incorrect password attempt|sudo.*authentication failure', re.IGNORECASE),
        Severity.MEDIUM,
        "Failed sudo attempts detected"
    ),
    "possible_sqli": (
        re.compile(r'(\%27)|(\')|(\-\-)|(\%23)|(#).*\b(select|insert|update|delete|union|into|from|where)\b', re.IGNORECASE),
        Severity.HIGH,
        "Potential SQL injection attempt detected in web logs"
    ),
    "possible_xss": (
        re.compile(r'(<script>|%3Cscript%3E|javascript:)|(on\w+\s*=)', re.IGNORECASE),
        Severity.MEDIUM,
        "Potential Cross-Site Scripting (XSS) attempt detected in web logs"
    ),
    "suspicious_file_access": (
        re.compile(r'(passwd|shadow|\.ssh/|authorized_keys|id_rsa).*(?:read|access|open|write)', re.IGNORECASE),
        Severity.HIGH,
        "Suspicious access to sensitive files detected"
    ),
    "unexpected_privilege_escalation": (
        re.compile(r'(new privileges|granted .* privileges|effective uid changed|NOPASSWD|added to sudoers)', re.IGNORECASE),
        Severity.HIGH,
        "Potential privilege escalation activity detected"
    ),
    "error_spike": (
        re.compile(r'error|exception|critical|fatal|failure', re.IGNORECASE),
        Severity.INFO,  # Severity raised based on count/frequency
        "Spike in error messages detected"
    ),
    "system_modification": (
        re.compile(r'(modified|changed|edited|updated) (system|config|boot|startup|init|cron)', re.IGNORECASE),
        Severity.MEDIUM,
        "System configuration modification detected"
    ),
    "suspicious_process": (
        re.compile(r'(fork bomb|killed process|fork\(\) bomb|abnormal behavior|excessive cpu|excessive memory)', re.IGNORECASE),
        Severity.HIGH,
        "Suspicious process behavior detected"
    ),
    "sensitive_data_access": (
        re.compile(r'(credit card|ssn|social security|password|credentials|token) (exposure|leak|disclosed)', re.IGNORECASE),
        Severity.CRITICAL,
        "Potential sensitive data exposure detected"
    ),
    "web_attack": (
        re.compile(r'(directory traversal|path traversal|\.\.\/|\.\.%2f|\/etc\/passwd|\/var\/www|\/bin\/sh|\/bin\/bash|\bcmd\.exe|\bpowershell\.exe)', re.IGNORECASE),
        Severity.HIGH,
        "Potential directory traversal or web attack detected"
    ),
    "command_injection": (
        re.compile(r'(\;|\||\`|\$\(|\&\&|\|\||system\(|exec\(|eval\(|os\.)', re.IGNORECASE),
        Severity.HIGH,
        "Potential command injection attempt detected"
    ),
    "brute_force": (
        re.compile(r'(multiple login failures|excessive login attempts|possible brute force|authentication flood)', re.IGNORECASE),
        Severity.MEDIUM,
        "Potential brute force attack detected"
    )
}

# --- Additional Pattern Categories ---
WEB_ATTACK_PATTERNS = {
    "lfi_rfi": (
        re.compile(r'(include|require)(_once)?\s*\(?[\'"](https?|ftp|php|data|expect):', re.IGNORECASE),
        Severity.HIGH,
        "Potential Local/Remote File Inclusion attack"
    ),
    "code_execution": (
        re.compile(r'(eval|system|exec|passthru|shell_exec|assert|str_rot13|base64_decode)\s*\(', re.IGNORECASE),
        Severity.HIGH,
        "Potential code execution attempt"
    ),
    "xxe": (
        re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']', re.IGNORECASE),
        Severity.HIGH,
        "Potential XML External Entity (XXE) attack"
    )
}

SYSTEM_COMPROMISE_PATTERNS = {
    "rootkit": (
        re.compile(r'(hidden process|rootkit|lkm|loadable kernel module|syscall table|hidden file|hidden directory)', re.IGNORECASE),
        Severity.CRITICAL,
        "Potential rootkit or system compromise indicators"
    ),
    "backdoor": (
        re.compile(r'(backdoor|reverse shell|bind shell|remote access|covert channel|beacon|c2|command and control)', re.IGNORECASE),
        Severity.CRITICAL,
        "Potential backdoor or unauthorized remote access"
    )
}

API_ABUSE_PATTERNS = {
    "rate_limiting": (
        re.compile(r'(rate limit exceeded|too many requests|429 Too Many Requests)', re.IGNORECASE),
        Severity.MEDIUM,
        "API rate limiting triggered - possible API abuse"
    ),
    "api_key_misuse": (
        re.compile(r'(invalid api key|unauthorized api|token revoked|api authentication failure)', re.IGNORECASE),
        Severity.HIGH,
        "Potential API key misuse or unauthorized access attempt"
    )
}

# Merge all detection patterns
DETECTION_PATTERNS = {**SUSPICIOUS_PATTERNS, **WEB_ATTACK_PATTERNS, **SYSTEM_COMPROMISE_PATTERNS, **API_ABUSE_PATTERNS}

# --- Log Format Parsers ---

# Generic syslog format: "MMM DD HH:MM:SS hostname process[pid]: message"
# More modern format (RFC 5424): "YYYY-MM-DDTHH:MM:SS.msZ hostname process[pid]: message"
LOG_LINE_REGEX = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Web server access log format
ACCESS_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[\w:/]+\s[+\-]\d{4})\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

# JSON log format (many modern applications)
def parse_json_log(line: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON formatted log line."""
    try:
        data = json.loads(line)
        # Extract common fields and normalize
        if isinstance(data, dict):
            result = {"raw_data": data}

            # Try to get timestamp
            for ts_field in ["timestamp", "time", "@timestamp", "date", "datetime", "created_at"]:
                if ts_field in data:
                    result["timestamp"] = str(data[ts_field])
                    break

            # Try to get message
            for msg_field in ["message", "msg", "log", "event", "description"]:
                if msg_field in data and data[msg_field]:
                    result["message"] = str(data[msg_field])
                    break

            # Try to get level/severity
            for lvl_field in ["level", "severity", "loglevel", "log_level"]:
                if lvl_field in data:
                    result["level"] = str(data[lvl_field])
                    break

            return result
        return None
    except (json.JSONDecodeError, ValueError):
        return None


# --- Log Parser Functions ---
def detect_log_format(file_path: Path) -> str:
    """
    Detect the format of the log file.

    Args:
        file_path: Path to the log file

    Returns:
        String indicating log format: 'syslog', 'apache', 'json', 'unknown'
    """
    try:
        with file_path.open('r', encoding='utf-8', errors='ignore') as f:
            for _ in range(5):  # Check first 5 lines
                line = f.readline().strip()
                if not line:
                    continue

                if line.startswith('{') and line.endswith('}'):
                    try:
                        json.loads(line)
                        return 'json'
                    except json.JSONDecodeError:
                        pass

                if LOG_LINE_REGEX.match(line):
                    return 'syslog'

                if ACCESS_LOG_REGEX.match(line):
                    return 'apache'

        return 'unknown'
    except Exception as e:
        logger.error(f"Error detecting log format: {e}")
        return 'unknown'


def parse_log_line(line: str, log_format: str = 'auto') -> Optional[Dict[str, Any]]:
    """
    Parse a log line using the appropriate format parser.

    Args:
        line: Log line to parse
        log_format: Format to use ('auto', 'syslog', 'apache', 'json')

    Returns:
        Parsed log data or None if parsing fails
    """
    if not line or not line.strip():
        return None

    # Auto-detect format if not specified
    if log_format == 'auto':
        if line.startswith('{') and line.endswith('}'):
            log_format = 'json'
        elif ACCESS_LOG_REGEX.match(line):
            log_format = 'apache'
        else:
            log_format = 'syslog'

    # Apply the appropriate parser
    if log_format == 'json':
        return parse_json_log(line)

    elif log_format == 'apache':
        match = ACCESS_LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            # Convert apache timestamp format
            try:
                timestamp_str = data['timestamp']
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                data['parsed_timestamp'] = timestamp
            except (ValueError, KeyError):
                data['parsed_timestamp'] = None

            # Add raw line for reference
            data['raw_line'] = line
            return data

    elif log_format == 'syslog':
        match = LOG_LINE_REGEX.match(line)
        if match:
            data = match.groupdict()
            # Convert syslog timestamp format
            try:
                # Try ISO format first
                ts_str = data['timestamp']
                if 'T' in ts_str:  # ISO format
                    timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                else:  # Syslog format
                    current_year = datetime.now().year
                    ts_str = f"{data['timestamp']} {current_year}"
                    timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                data['parsed_timestamp'] = timestamp
            except (ValueError, KeyError):
                data['parsed_timestamp'] = None

            # Add raw line for reference
            data['raw_line'] = line
            return data

    # Fallback to simply storing the raw line
    return {'raw_line': line, 'parsed_timestamp': None, 'message': line}


# --- Argument Parser ---
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze logs for security incidents and anomalies as part of incident response.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--log-files",
        nargs="+",
        default=None,
        help="Log file paths to analyze. If not specified, default system logs will be used."
    )

    parser.add_argument(
        "--last-hours",
        type=int,
        default=DEFAULT_LAST_HOURS,
        help="Analyze logs from the last N hours"
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path for analysis results"
    )

    parser.add_argument(
        "--output-format",
        choices=["text", "json", "csv"],
        default=DEFAULT_OUTPUT_FORMAT,
        help="Format for output results"
    )

    parser.add_argument(
        "--incident-id",
        type=str,
        help="Incident ID for tracking and evidence association"
    )

    parser.add_argument(
        "--detect-threats",
        action="store_true",
        default=True,
        help="Enable threat detection patterns (default: enabled)"
    )

    parser.add_argument(
        "--no-detect-threats",
        action="store_false",
        dest="detect_threats",
        help="Disable threat detection patterns"
    )

    parser.add_argument(
        "--detect-anomalies",
        action="store_true",
        default=True,
        help="Enable anomaly detection (default: enabled)"
    )

    parser.add_argument(
        "--no-detect-anomalies",
        action="store_false",
        dest="detect_anomalies",
        help="Disable anomaly detection"
    )

    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only output summary information, not detailed findings"
    )

    parser.add_argument(
        "--evidence-dir",
        type=str,
        help="Directory to store evidence files"
    )

    parser.add_argument(
        "--pattern-file",
        type=str,
        help="Path to additional custom detection patterns JSON file"
    )

    parser.add_argument(
        "--max-scan-size-mb",
        type=int,
        default=MAX_SCAN_SIZE_MB,
        help="Maximum size of log file to scan in MB"
    )

    parser.add_argument(
        "--report-categories",
        nargs="+",
        choices=["web_attacks", "system_compromise", "api_abuse", "authentication", "all"],
        default=["all"],
        help="Categories of patterns to include in report"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


# --- Log Analyzer Class ---
class LogAnalyzer:
    """Analyzes log files for security events and anomalies."""

    def __init__(self, config: argparse.Namespace):
        """Initialize the LogAnalyzer.

        Args:
            config: Configuration namespace from argparse
        """
        self.config = config
        self.findings: List[Dict[str, Any]] = []
        self.start_time = datetime.now(timezone.utc) - timedelta(hours=config.last_hours)
        self.log_files = config.log_files if config.log_files else DEFAULT_LOG_FILES
        self.evidence_dir = self._setup_evidence_dir()

        # Load custom patterns if specified
        self.patterns = DETECTION_PATTERNS.copy()
        if config.pattern_file and os.path.exists(config.pattern_file):
            self._load_custom_patterns()

        # If categories specified, filter patterns
        if "all" not in config.report_categories:
            self._filter_patterns_by_category()

        # Analysis counters and stats
        self.line_count = 0
        self.analyzed_count = 0
        self.skipped_count = 0
        self.invalid_count = 0
        self.files_processed = 0
        self.start_analysis_time = datetime.now(timezone.utc)

        # Counters for anomaly detection
        self.event_counters = defaultdict(Counter)
        self.host_counters = defaultdict(Counter)
        self.ip_counters = defaultdict(Counter)
        self.process_counters = defaultdict(Counter)
        self.status_counters = defaultdict(Counter)
        self.user_counters = defaultdict(Counter)

        # Ratio counters for anomaly detection
        self.error_ratios = {}  # host -> error ratio
        self.failure_ratios = {}  # host -> failure ratio
        self.login_failure_ratios = {}  # user -> login failure ratio

        # Format detection
        self.format_counts = Counter()

        # Set logging level
        self._configure_logging()

        logger.info("Log Analyzer initialized")
        logger.info(f"Analysis timeframe: {self.start_time.isoformat()} to present")
        if not self.config.quiet:
            logger.info(f"Log files to analyze: {', '.join(str(f) for f in self.log_files)}")

    def _configure_logging(self) -> None:
        """Configure logging based on command line options."""
        if self.config.verbose:
            logger.setLevel(logging.DEBUG)
        elif self.config.quiet:
            logger.setLevel(logging.WARNING)
        else:
            logger.setLevel(logging.INFO)

    def _setup_evidence_dir(self) -> Path:
        """Set up evidence directory for findings.

        Returns:
            Path to evidence directory
        """
        if self.config.evidence_dir:
            evidence_dir = Path(self.config.evidence_dir)
        elif self.config.incident_id and IR_KIT_IMPORTS_AVAILABLE:
            try:
                evidence_dir = create_evidence_directory(self.config.incident_id) / "log_analysis"
            except Exception as e:
                logger.warning(f"Could not create incident evidence directory: {e}")
                evidence_dir = OUTPUT_DIR / sanitize_incident_id(self.config.incident_id)
        else:
            evidence_dir = OUTPUT_DIR

        try:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Evidence directory set to {evidence_dir}")
        except Exception as e:
            logger.warning(f"Could not create evidence directory {evidence_dir}: {e}")

        return evidence_dir

    def _load_custom_patterns(self) -> None:
        """Load custom detection patterns from JSON file."""
        try:
            with open(self.config.pattern_file, 'r') as f:
                custom_patterns = json.load(f)

            for pattern_name, pattern_data in custom_patterns.items():
                if not all(k in pattern_data for k in ["regex", "severity", "description"]):
                    logger.warning(f"Skipping invalid pattern {pattern_name}: missing required fields")
                    continue

                try:
                    severity = Severity(pattern_data["severity"].upper())
                    regex = re.compile(pattern_data["regex"], re.IGNORECASE)
                    description = pattern_data["description"]

                    self.patterns[pattern_name] = (regex, severity, description)
                    logger.debug(f"Added custom pattern: {pattern_name}")
                except (re.error, ValueError) as e:
                    logger.warning(f"Error in custom pattern {pattern_name}: {e}")

            logger.info(f"Loaded {len(custom_patterns)} custom detection patterns")
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error loading custom patterns file: {e}")

    def _filter_patterns_by_category(self) -> None:
        """Filter patterns based on selected categories."""
        selected_patterns = {}
        categories = self.config.report_categories

        category_mappings = {
            "web_attacks": WEB_ATTACK_PATTERNS,
            "system_compromise": SYSTEM_COMPROMISE_PATTERNS,
            "api_abuse": API_ABUSE_PATTERNS,
            "authentication": {k: v for k, v in SUSPICIOUS_PATTERNS.items()
                             if "login" in k or "authentication" in k or "sudo" in k}
        }

        # Add patterns from each selected category
        for category in categories:
            if category in category_mappings:
                selected_patterns.update(category_mappings[category])

        # Only use selected patterns if any were found
        if selected_patterns:
            self.patterns = selected_patterns
        else:
            logger.warning("No patterns found for selected categories, using all patterns")

    def add_finding(self,
                   severity: Severity,
                   title: str,
                   description: str,
                   details: Optional[Dict] = None,
                   log_data: Optional[Dict] = None,
                   pattern: Optional[str] = None) -> None:
        """Add a finding to the list.

        Args:
            severity: Severity level
            title: Finding title
            description: Finding description
            details: Additional details
            log_data: Original log data
            pattern: Pattern that triggered the finding
        """
        finding = {
            "severity": severity.value,
            "title": title,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }

        # Add pattern information if available
        if pattern:
            finding["pattern"] = pattern

        # Add log data if available (always include source file)
        if log_data:
            source_file = log_data.get("source_file", "unknown")
            finding["source"] = source_file

            # Add timestamp from log if available
            if "parsed_timestamp" in log_data and log_data["parsed_timestamp"]:
                finding["log_timestamp"] = log_data["parsed_timestamp"].isoformat()

            # Add other useful fields
            for field in ["hostname", "process", "ip", "user", "pid"]:
                if field in log_data and log_data[field]:
                    finding["details"][field] = log_data[field]

        self.findings.append(finding)

        # Log finding
        log_level = logging.WARNING if severity in [Severity.HIGH, Severity.CRITICAL] else logging.INFO
        logger.log(
            log_level,
            f"Finding [{severity.value}]: {title} - {description}"
        )

        # Log to security event system if available
        if CORE_SECURITY_AVAILABLE and severity in [Severity.HIGH, Severity.CRITICAL]:
            security_severity = "high" if severity == Severity.HIGH else "critical"

            incident_type = None
            if "web attack" in title.lower() or "injection" in title.lower():
                incident_type = IncidentType.WEB_APPLICATION_ATTACK
            elif "unauthorized" in title.lower() or "access" in title.lower():
                incident_type = IncidentType.UNAUTHORIZED_ACCESS
            elif "malware" in title.lower() or "backdoor" in title.lower():
                incident_type = IncidentType.MALWARE

            log_security_event(
                event_type="log_analyzer_finding",
                description=f"Log Analyzer: {title}",
                severity=security_severity,
                details={
                    "finding": finding,
                    "incident_id": self.config.incident_id,
                    "incident_type": incident_type
                }
            )

    def _check_patterns(self, message: str, line_data: Dict[str, Any]) -> None:
        """Check the log message against predefined suspicious patterns.

        Args:
            message: Log message to check
            line_data: Full parsed log data
        """
        if not self.config.detect_threats or not message:
            return

        for key, (pattern, severity, title) in self.patterns.items():
            if pattern.search(message):
                # Increment counter for anomaly detection
                hostname = line_data.get('hostname', line_data.get('ip', 'unknown'))
                self.event_counters[key].update([hostname])

                # Add finding immediately for high/critical patterns
                if severity in [Severity.HIGH, Severity.CRITICAL]:
                    self.add_finding(
                        severity,
                        title,
                        f"Pattern '{key}' matched in log message",
                        details={"matched_pattern": key},
                        log_data=line_data,
                        pattern=key
                    )

    def _detect_anomalies(self) -> None:
        """Analyze collected counters to detect anomalies."""
        if not self.config.detect_anomalies:
            return

        logger.info("Analyzing collected metrics for anomalies...")

        # Analyze failed logins
        self._detect_login_anomalies()

        # Analyze error rates
        self._detect_error_anomalies()

        # Analyze 4xx/5xx status code anomalies in web logs
        self._detect_status_code_anomalies()

        # Analyze process anomalies
        self._detect_process_anomalies()

        # Analyze IP address anomalies
        self._detect_ip_anomalies()

    def _detect_login_anomalies(self) -> None:
        """Detect login-related anomalies."""
        # Failed login anomalies
        failed_login_counts = self.event_counters.get("failed_login", Counter())
        if failed_login_counts:
            total_failed = sum(failed_login_counts.values())
            if total_failed > 10:  # Arbitrary threshold
                severity = Severity.HIGH if total_failed > 50 else Severity.MEDIUM
                self.add_finding(
                    severity,
                    "Multiple Failed Login Attempts",
                    f"Detected {total_failed} failed login attempts across hosts",
                    details={"counts_per_host": dict(failed_login_counts)}
                )

        # Check for high failure ratios per user
        for user, counters in self.user_counters.items():
            success = counters.get("success", 0)
            failure = counters.get("failure", 0)
            total = success + failure

            if total > 5 and failure > 0:  # Only consider users with some activity
                failure_ratio = failure / total
                if failure_ratio > 0.5:  # Over 50% failure rate
                    severity = Severity.HIGH if failure_ratio > 0.8 else Severity.MEDIUM
                    self.add_finding(
                        severity,
                        "High Login Failure Rate Per User",
                        f"User {user} has a {failure_ratio:.1%} login failure rate ({failure}/{total})",
                        details={
                            "user": user,
                            "success_count": success,
                            "failure_count": failure,
                            "failure_ratio": failure_ratio
                        }
                    )

    def _detect_error_anomalies(self) -> None:
        """Detect error-related anomalies."""
        # Error spike anomaly
        error_counts = self.event_counters.get("error_spike", Counter())
        if error_counts and self.line_count > 0:
            total_errors = sum(error_counts.values())
            error_ratio = total_errors / self.line_count

            # Alert if more than 10% of lines contain errors
            if error_ratio > 0.1:
                severity = Severity.HIGH if error_ratio > 0.3 else Severity.MEDIUM
                self.add_finding(
                    severity,
                    "High Error Rate Detected",
                    f"Detected {total_errors} errors ({error_ratio:.1%}) in {self.line_count} lines",
                    details={
                        "error_counts_by_host": dict(error_counts),
                        "error_ratio": error_ratio
                    }
                )

        # Per-host error ratio anomalies
        for hostname, error_ratio in self.error_ratios.items():
            if error_ratio > 0.2:  # More than 20% errors
                severity = Severity.MEDIUM
                if error_ratio > 0.5:  # More than 50% errors
                    severity = Severity.HIGH

                self.add_finding(
                    severity,
                    "Host with High Error Rate",
                    f"Host {hostname} has {error_ratio:.1%} error rate",
                    details={
                        "hostname": hostname,
                        "error_ratio": error_ratio
                    }
                )

    def _detect_status_code_anomalies(self) -> None:
        """Detect HTTP status code anomalies."""
        # Process status code counters for web logs
        for hostname, status_counts in self.status_counters.items():
            total_requests = sum(status_counts.values())
            if total_requests < 10:  # Skip hosts with minimal traffic
                continue

            # Count types of status codes
            status_4xx = sum(count for status, count in status_counts.items() if status.startswith('4'))
            status_5xx = sum(count for status, count in status_counts.items() if status.startswith('5'))

            # Calculate ratios
            ratio_4xx = status_4xx / total_requests if total_requests > 0 else 0
            ratio_5xx = status_5xx / total_requests if total_requests > 0 else 0

            # Alert on high 4xx rates
            if status_4xx > 10 and ratio_4xx > 0.2:  # More than 20% 4xx status codes
                severity = Severity.MEDIUM if ratio_4xx < 0.5 else Severity.HIGH
                self.add_finding(
                    severity,
                    "High Rate of 4xx Client Errors",
                    f"Host {hostname} has {ratio_4xx:.1%} client error rate ({status_4xx}/{total_requests})",
                    details={
                        "hostname": hostname,
                        "total_requests": total_requests,
                        "client_errors": status_4xx,
                        "error_ratio": ratio_4xx
                    }
                )

            # Alert on high 5xx rates (more severe)
            if status_5xx > 5 and ratio_5xx > 0.05:  # More than 5% 5xx status codes
                severity = Severity.MEDIUM if ratio_5xx < 0.2 else Severity.HIGH
                self.add_finding(
                    severity,
                    "High Rate of 5xx Server Errors",
                    f"Host {hostname} has {ratio_5xx:.1%} server error rate ({status_5xx}/{total_requests})",
                    details={
                        "hostname": hostname,
                        "total_requests": total_requests,
                        "server_errors": status_5xx,
                        "error_ratio": ratio_5xx
                    }
                )

    def _detect_process_anomalies(self) -> None:
        """Detect anomalies related to processes."""
        # Check for unusual process behavior or excessive activity
        process_thresholds = {
            "cron": 1000,  # Lots of cron activity could be suspicious
            "sudo": 20,    # High number of sudo commands
            "su": 10,      # High number of user switching
            "ssh": 100,    # High number of SSH operations
            "sshd": 100    # High number of SSH daemon events
        }

        for process, count in self.process_counters.items():
            threshold = process_thresholds.get(process, 500)  # Default threshold

            if count > threshold:
                self.add_finding(
                    Severity.MEDIUM,
                    "Unusual Process Activity",
                    f"Process {process} has unusually high activity count: {count}",
                    details={
                        "process": process,
                        "count": count,
                        "threshold": threshold
                    }
                )

    def _detect_ip_anomalies(self) -> None:
        """Detect anomalies related to IP addresses."""
        # Check for IP addresses with high error or failure rates
        for ip, counters in self.ip_counters.items():
            if '.' not in ip and ':' not in ip:  # Skip non-IPs
                continue

            total_requests = sum(counters.values())
            if total_requests < 10:  # Skip IPs with minimal traffic
                continue

            # Get error counts
            errors = counters.get("error", 0) + counters.get("failure", 0)
            error_ratio = errors / total_requests if total_requests > 0 else 0

            # Alert on high error IPs
            if errors > 5 and error_ratio > 0.5:  # More than 50% errors
                severity = Severity.MEDIUM if error_ratio < 0.8 else Severity.HIGH
                self.add_finding(
                    severity,
                    "IP Address with High Error Rate",
                    f"IP {ip} has {error_ratio:.1%} error rate ({errors}/{total_requests})",
                    details={
                        "ip": ip,
                        "total_requests": total_requests,
                        "errors": errors,
                        "error_ratio": error_ratio
                    }
                )

    def analyze_log_file(self, file_path: Union[str, Path]) -> None:
        """Analyze a single log file.

        Args:
            file_path: Path to log file
        """
        file_path = Path(file_path)
        try:
            if not file_path.exists():
                logger.warning(f"Log file not found: {file_path}")
                return

            # Check file size against maximum
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.config.max_scan_size_mb:
                logger.warning(
                    f"File {file_path} exceeds maximum scan size ({file_size_mb:.1f} MB > {self.config.max_scan_size_mb} MB). "
                    f"Use --max-scan-size-mb to increase limit."
                )
                return

            logger.info(f"Analyzing log file: {file_path}")

            # Detect log format
            log_format = detect_log_format(file_path)
            self.format_counts[log_format] += 1
            logger.debug(f"Detected log format: {log_format}")

            # Process the file
            file_line_count = 0
            analyzed_lines = 0

            with file_path.open('r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    file_line_count += 1
                    self.line_count += 1

                    line = line.strip()
                    if not line:  # Skip empty lines
                        self.skipped_count += 1
                        continue

                    # Parse the line according to detected format
                    parsed_data = parse_log_line(line, log_format)
                    if not parsed_data:
                        self.invalid_count += 1
                        continue

                    # Add source file information
                    parsed_data["source_file"] = str(file_path)

                    # Check if line is within the time window (if timestamp available)
                    if (parsed_data.get('parsed_timestamp') and
                            parsed_data['parsed_timestamp'] < self.start_time):
                        self.skipped_count += 1
                        continue

                    # Analyze the line
                    analyzed_lines += 1
                    self.analyzed_count += 1

                    # Update counters
                    hostname = parsed_data.get('hostname', parsed_data.get('ip', 'unknown'))
                    self.host_counters[hostname] += 1

                    # Update IP counters (for web logs)
                    if 'ip' in parsed_data:
                        ip = parsed_data['ip']
                        self.ip_counters[ip]["total"] = self.ip_counters[ip].get("total", 0) + 1

                        # Check for error status codes
                        if 'status' in parsed_data:
                            status = parsed_data['status']
                            if status.startswith('4') or status.startswith('5'):
                                self.ip_counters[ip]["error"] = self.ip_counters[ip].get("error", 0) + 1
                                self.status_counters[hostname][status] = self.status_counters[hostname].get(status, 0) + 1

                    # Update process counters
                    if 'process' in parsed_data and parsed_data['process']:
                        process = parsed_data['process']
                        self.process_counters[process] += 1

                    # Extract and check message
                    message = parsed_data.get('message', '')
                    if not message and 'request' in parsed_data:  # For web logs
                        message = parsed_data['request']

                    # Check for login success/failure
                    if 'user' in parsed_data and parsed_data['user']:
                        user = parsed_data['user']
                        if 'fail' in message.lower() or 'invalid' in message.lower():
                            self.user_counters[user]["failure"] = self.user_counters[user].get("failure", 0) + 1
                        elif 'success' in message.lower() or 'accepted' in message.lower():
                            self.user_counters[user]["success"] = self.user_counters[user].get("success", 0) + 1

                    # Run pattern checks
                    self._check_patterns(message, parsed_data)

                    # Check for errors/warnings
                    if ('error' in message.lower() or 'critical' in message.lower() or
                            'fatal' in message.lower()):
                        self.host_counters[hostname + "_error"] += 1

            # Update file error ratios
            host_error_count = self.host_counters.get(file_path.name + "_error", 0)
            if host_error_count and file_line_count:
                self.error_ratios[file_path.name] = host_error_count / file_line_count

            self.files_processed += 1

            logger.info(f"Processed {file_line_count} lines in {file_path}, analyzed {analyzed_lines}")

        except PermissionError:
            logger.error(f"Permission denied when reading log file: {file_path}")
            self.add_finding(
                Severity.LOW,
                "Permission Denied",
                f"Cannot read log file: {file_path}",
                details={"file": str(file_path)}
            )
        except (UnicodeDecodeError, IOError) as e:
            logger.error(f"Error decoding log file {file_path}: {e}")
            self.add_finding(
                Severity.LOW,
                "File Read Error",
                f"Error reading log file: {file_path}",
                details={"file": str(file_path), "error": str(e)}
            )
        except Exception as e:
            logger.error(f"Error analyzing log file {file_path}: {e}", exc_info=True)
            self.add_finding(
                Severity.LOW,
                "Analysis Error",
                f"Error analyzing log file: {file_path}",
                details={"file": str(file_path), "error": str(e)}
            )

    def analyze(self) -> None:
        """Orchestrate the analysis of specified log files."""
        self.start_analysis_time = datetime.now(timezone.utc)

        # Process each specified log file
        for file_str in self.log_files:
            file_path = Path(file_str)

            # Skip non-existent files with warning
            if not file_path.exists():
                logger.warning(f"Log file not found: {file_path}")
                continue

            # Handle directories by recursively finding log files
            if file_path.is_dir():
                logger.info(f"Searching for log files in directory: {file_path}")
                try:
                    for root, _, files in os.walk(file_path):
                        for filename in files:
                            # Skip very large files
                            full_path = Path(root) / filename
                            try:
                                if full_path.stat().st_size > (self.config.max_scan_size_mb * 1024 * 1024):
                                    logger.debug(f"Skipping large file: {full_path}")
                                    continue

                                # Skip non-log files
                                if not any(filename.endswith(ext) for ext in ['.log', '.txt', '.json']):
                                    logger.debug(f"Skipping non-log file: {full_path}")
                                    continue

                                self.analyze_log_file(full_path)
                            except Exception as e:
                                logger.warning(f"Error checking file {full_path}: {e}")
                except PermissionError:
                    logger.error(f"Permission denied when accessing directory: {file_path}")
                    continue
            else:
                # Analyze the file directly
                self.analyze_log_file(file_path)

        # Perform anomaly detection based on aggregated counts
        if self.config.detect_anomalies:
            self._detect_anomalies()

        # Calculate analysis duration
        duration = datetime.now(timezone.utc) - self.start_analysis_time

        logger.info(
            f"Analysis complete in {duration.total_seconds():.1f}s. Processed {self.line_count} lines, "
            f"analyzed {self.analyzed_count} lines, found {len(self.findings)} issues."
        )

    def save_findings(self) -> Tuple[str, bool]:
        """Save findings to a file.

        Returns:
            Tuple of (output_file_path, success_flag)
        """
        # Determine output file path
        if self.config.output:
            output_file = Path(self.config.output)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_analysis_{timestamp}.{self.config.output_format}"
            if self.config.incident_id:
                # Use incident ID in filename if available
                output_file = self.evidence_dir / f"{self.config.incident_id}_{filename}"
            else:
                output_file = self.evidence_dir / filename

        try:
            # Create parent directory if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)

            # Generate report content
            content = self.generate_report()

            # Write to file
            with output_file.open('w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"Analysis results saved to: {output_file}")

            # Generate evidence hash if used in IR context
            if CORE_SECURITY_AVAILABLE and self.config.incident_id:
                try:
                    file_hash = calculate_file_hash(str(output_file))
                    hash_file = output_file.with_suffix(output_file.suffix + '.sha256')

                    with hash_file.open('w') as f:
                        f.write(f"{file_hash}  {output_file.name}\n")

                    logger.debug(f"Evidence hash saved to: {hash_file}")

                except Exception as e:
                    logger.warning(f"Could not generate evidence hash: {e}")

            return str(output_file), True

        except Exception as e:
            logger.error(f"Error saving findings: {e}")
            return "", False

    def generate_report(self) -> str:
        """Generate a report based on the findings.

        Returns:
            Report content as string in the selected format
        """
        # Add findings to results
        sorted_findings = sorted(
            self.findings,
            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])
        )

        # Create summary data
        report_data = {
            "summary": {
                "analysis_start_time": self.start_time.isoformat(),
                "analysis_end_time": datetime.now(timezone.utc).isoformat(),
                "scan_duration_seconds": (datetime.now(timezone.utc) - self.start_analysis_time).total_seconds(),
                "total_lines_processed": self.line_count,
                "lines_analyzed": self.analyzed_count,
                "lines_skipped": self.skipped_count,
                "lines_invalid": self.invalid_count,
                "files_processed": self.files_processed,
                "log_formats": dict(self.format_counts),
                "findings_count": len(self.findings),
                "findings_by_severity": {
                    "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                    "high": len([f for f in self.findings if f["severity"] == "HIGH"]),
                    "medium": len([f for f in self.findings if f["severity"] == "MEDIUM"]),
                    "low": len([f for f in self.findings if f["severity"] == "LOW"]),
                    "info": len([f for f in self.findings if f["severity"] == "INFO"])
                },
                "patterns_used": len(self.patterns),
            },
            "findings": sorted_findings if not self.config.summary_only else []
        }

        # Format according to specified output format
        if self.config.output_format == "json":
            return json.dumps(report_data, indent=2, default=str)

        elif self.config.output_format == "csv":
            import csv
            from io import StringIO

            output = StringIO()

            # Write summary as key-value pairs
            writer = csv.writer(output)
            writer.writerow(["Summary Key", "Summary Value"])
            for key, value in report_data["summary"].items():
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        writer.writerow([f"{key}.{subkey}", subvalue])
                else:
                    writer.writerow([key, value])

            if not self.config.summary_only:
                # Add empty row as separator
                writer.writerow([])

                # Write findings if not summary only
                if self.findings:
                    # Get all possible columns from all findings
                    columns = {"severity", "title", "description", "timestamp"}
                    for finding in self.findings:
                        columns.update(finding.keys())
                        if "details" in finding and isinstance(finding["details"], dict):
                            columns.update(f"details.{k}" for k in finding["details"].keys())

                    # Write header
                    writer.writerow(sorted(columns))

                    # Write each finding
                    for finding in sorted_findings:
                        row = []
                        for col in sorted(columns):
                            if "details." in col and "details" in finding:
                                # Extract from nested details
                                detail_key = col.split(".", 1)[1]
                                value = finding["details"].get(detail_key, "")
                            else:
                                value = finding.get(col, "")
                            row.append(value)
                        writer.writerow(row)

            return output.getvalue()

        else:  # Text format
            # Format as readable text report
            report = f"Security Log Analysis Report\n"
            report += f"==========================\n\n"
            report += f"Analysis Period: {self.start_time.isoformat()} to {datetime.now(timezone.utc).isoformat()}\n"
            report += f"Duration: {(datetime.now(timezone.utc) - self.start_analysis_time).total_seconds():.1f} seconds\n"
            report += f"Files Processed: {self.files_processed}\n"
            report += f"Total Lines: {self.line_count}\n"
            report += f"Lines Analyzed: {self.analyzed_count}\n"
            report += f"Lines Skipped: {self.skipped_count}\n"
            report += f"Lines Invalid: {self.invalid_count}\n\n"

            # Format counts
            report += f"Log Formats Detected:\n"
            for fmt, count in self.format_counts.items():
                report += f"  - {fmt}: {count}\n"
            report += "\n"

            # Format finding summary
            report += f"Findings Summary:\n"
            report += f"  Critical: {report_data['summary']['findings_by_severity']['critical']}\n"
            report += f"  High:     {report_data['summary']['findings_by_severity']['high']}\n"
            report += f"  Medium:   {report_data['summary']['findings_by_severity']['medium']}\n"
            report += f"  Low:      {report_data['summary']['findings_by_severity']['low']}\n"
            report += f"  Info:     {report_data['summary']['findings_by_severity']['info']}\n"
            report += f"  Total:    {len(self.findings)}\n\n"

            if not self.findings:
                report += "No significant issues detected.\n"
                return report

            # Skip detailed findings if summary only
            if self.config.summary_only:
                return report

            # Format detailed findings
            report += "Findings (sorted by severity):\n"
            report += "-----------------------------\n"

            for finding in sorted_findings:
                report += f"\n[{finding['severity']}] {finding['title']}\n"
                report += f"  Description: {finding['description']}\n"
                report += f"  Timestamp: {finding['timestamp']}\n"

                if "source" in finding:
                    report += f"  Source: {finding['source']}\n"

                if "log_timestamp" in finding:
                    report += f"  Log Timestamp: {finding['log_timestamp']}\n"

                if "pattern" in finding:
                    report += f"  Matched Pattern: {finding['pattern']}\n"

                if finding.get('details'):
                    # Format details, handling nested dictionaries
                    report += "  Details:\n"
                    for k, v in finding['details'].items():
                        if isinstance(v, dict):
                            report += f"    {k}:\n"
                            for sk, sv in v.items():
                                report += f"      {sk}: {sv}\n"
                        else:
                            # Truncate long values
                            v_str = str(v)
                            if len(v_str) > 100:
                                v_str = v_str[:97] + "..."
                            report += f"    {k}: {v_str}\n"

            return report


# --- Main Execution ---
def collect_evidence(*args, **kwargs) -> Dict[str, Any]:
    """Main entry point for the log analyzer.

    This function signature matches the toolkit's expected function pattern
    and is used for integration with the incident response toolkit.

    Args:
        incident_id: (str) Incident identifier
        output_dir: (str) Directory to store evidence/findings
        log_files: (List[str]) Log files to analyze
        last_hours: (int) Hours of logs to analyze
        detect_threats: (bool) Whether to detect threats
        detect_anomalies: (bool) Whether to detect anomalies
        format: (str) Output format (text, json, csv)
        summary_only: (bool) Only include summary in output
        pattern_file: (str) Path to custom pattern file

    Returns:
        Dict containing analysis results and status
    """
    # Parse arguments from kwargs
    incident_id = kwargs.get("incident_id")
    output_dir = kwargs.get("output_dir")
    log_files = kwargs.get("log_files", [])
    last_hours = kwargs.get("last_hours", DEFAULT_LAST_HOURS)
    detect_threats = kwargs.get("detect_threats", True)
    detect_anomalies = kwargs.get("detect_anomalies", True)
    output_format = kwargs.get("format", DEFAULT_OUTPUT_FORMAT)
    summary_only = kwargs.get("summary_only", False)
    pattern_file = kwargs.get("pattern_file")
    verbose = kwargs.get("verbose", False)
    quiet = kwargs.get("quiet", False)
    max_scan_size_mb = kwargs.get("max_scan_size_mb", MAX_SCAN_SIZE_MB)

    # Create namespace for configuration
    config = argparse.Namespace(
        log_files=log_files if log_files else None,
        last_hours=last_hours,
        output=None,  # Will determine dynamically
        output_format=output_format,
        incident_id=incident_id,
        detect_threats=detect_threats,
        detect_anomalies=detect_anomalies,
        summary_only=summary_only,
        evidence_dir=output_dir,
        pattern_file=pattern_file,
        max_scan_size_mb=max_scan_size_mb,
        report_categories=["all"],
        quiet=quiet,
        verbose=verbose
    )

    try:
        # Initialize and run analyzer
        analyzer = LogAnalyzer(config)
        analyzer.analyze()

        # Save findings to file
        output_file, success = analyzer.save_findings()

        # Return results
        result = {
            "status": "success" if success else "error",
            "findings_count": len(analyzer.findings),
            "output_file": output_file if success else None,
            "lines_processed": analyzer.line_count,
            "analysis_timeframe": {
                "start": analyzer.start_time.isoformat(),
                "end": datetime.now(timezone.utc).isoformat()
            },
            "findings_by_severity": {
                "critical": len([f for f in analyzer.findings if f["severity"] == "CRITICAL"]),
                "high": len([f for f in analyzer.findings if f["severity"] == "HIGH"]),
                "medium": len([f for f in analyzer.findings if f["severity"] == "MEDIUM"]),
                "low": len([f for f in analyzer.findings if f["severity"] == "LOW"]),
                "info": len([f for f in analyzer.findings if f["severity"] == "INFO"])
            }
        }

        if not success:
            result["error"] = "Failed to save analysis results to file"

        # Register with evidence tracking if available
        if IR_KIT_IMPORTS_AVAILABLE and CORE_SECURITY_AVAILABLE and success and incident_id:
            try:
                # Calculate hash for integrity verification
                file_hash = calculate_file_hash(output_file)

                # Create an evidence entry for the analysis report
                from admin.security.forensics.utils.evidence_tracker import register_evidence
                evidence_id = register_evidence(
                    case_id=incident_id,
                    evidence_description="Log Analysis Report",
                    evidence_type=EvidenceType.LOG_FILE,
                    source_identifier=','.join(log_files) if log_files else "default_logs",
                    acquisition_method="log_analyzer",
                    acquisition_tool="incident_response_kit.log_analyzer",
                    analyst=os.environ.get("USER", "system"),
                    file_path=output_file,
                    initial_hash_algorithm="sha256"
                )

                if evidence_id:
                    result["evidence_id"] = evidence_id
                    logger.info(f"Registered analysis report as evidence: {evidence_id}")
            except Exception as e:
                logger.warning(f"Failed to register analysis report as evidence: {e}")

        return result

    except Exception as e:
        logger.error(f"Error during log analysis: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def main() -> int:
    """Command-line entry point."""
    args = parse_arguments()

    # Configure logging based on args
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)

    try:
        # Call main analysis function
        result = collect_evidence(
            incident_id=args.incident_id,
            output_dir=args.evidence_dir,
            log_files=args.log_files,
            last_hours=args.last_hours,
            detect_threats=args.detect_threats,
            detect_anomalies=args.detect_anomalies,
            format=args.output_format,
            summary_only=args.summary_only,
            pattern_file=args.pattern_file,
            verbose=args.verbose,
            quiet=args.quiet
        )

        # Print results summary to console
        if result["status"] == "success":
            print(f"\nLog Analysis Complete")
            print(f"--------------------")
            print(f"Processed {result['lines_processed']} log lines")
            print(f"Found {result['findings_count']} potential issues:")
            print(f"  Critical: {result['findings_by_severity']['critical']}")
            print(f"  High:     {result['findings_by_severity']['high']}")
            print(f"  Medium:   {result['findings_by_severity']['medium']}")
            print(f"  Low:      {result['findings_by_severity']['low']}")
            print(f"  Info:     {result['findings_by_severity']['info']}")

            if result.get("output_file"):
                print(f"\nResults saved to: {result['output_file']}")

            if result.get("evidence_id"):
                print(f"Registered as evidence ID: {result['evidence_id']}")

            # Return appropriate exit code based on findings
            if result['findings_by_severity']['critical'] > 0:
                print("\nCRITICAL issues found! Immediate investigation recommended.")
                return 2
            elif result['findings_by_severity']['high'] > 0:
                print("\nHIGH severity issues found! Investigation recommended.")
                return 1
            return 0
        else:
            print(f"Analysis failed: {result.get('error', 'Unknown error')}")
            return 3

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        return 130
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1


# Allow running as standalone script
if __name__ == "__main__":
    sys.exit(main())
