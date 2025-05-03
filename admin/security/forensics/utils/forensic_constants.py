"""
Common Constants for the Forensic Analysis Toolkit Utilities.

This module defines shared constants used across the forensic utility modules
(`crypto.py`, `evidence_tracker.py`, `file_utils.py`, etc.) to ensure
consistency and ease of configuration.

Constants are organized by functional area and are intended to provide a single
source of truth for configuration values across the forensic toolkit.
"""

import os
from datetime import timedelta
from typing import Dict, Final, FrozenSet, List, Tuple, Union

# Try to load core security constants first if available
try:
    from core.security.cs_constants import (
        FILE_HASH_ALGORITHM as CORE_HASH_ALGORITHM
    )

    # Use the core security constant as default if available
    DEFAULT_CORE_HASH = CORE_HASH_ALGORITHM
except ImportError:
    DEFAULT_CORE_HASH = "sha256"  # Fallback if core security not available

# --- Hashing Constants ---

#: Default hash algorithm used for integrity checks and evidence verification.
#: Aligns with core security settings where possible.
DEFAULT_HASH_ALGORITHM: Final[str] = DEFAULT_CORE_HASH

#: List of supported cryptographic hash algorithms for forensic operations.
#: Listed in order of preference (strongest first)
SUPPORTED_HASH_ALGORITHMS: Final[List[str]] = [
    "sha512", "sha384", "sha256", "sha1", "md5"
]

#: Hash algorithms REQUIRED for evidence hashing (all must be calculated)
REQUIRED_HASH_ALGORITHMS: Final[List[str]] = ["sha256", "sha1"]

#: Weak hash algorithms that should generate warnings when used alone
WEAK_HASH_ALGORITHMS: Final[FrozenSet[str]] = frozenset(["md5", "sha1"])

#: Chunk size (in bytes) for reading files during hashing operations.
#: Optimizes memory usage for large files.
CHUNK_SIZE: Final[int] = 65536  # 64KB

# --- Evidence Management Constants ---

#: Base directory for storing forensic evidence metadata files.
#: Should be a secure location with restricted access.
EVIDENCE_METADATA_DIR: Final[str] = os.environ.get(
    "FORENSIC_EVIDENCE_METADATA_DIR",
    "/secure/forensics/metadata"
)

#: Default storage location for actual evidence files (separate from metadata)
EVIDENCE_STORAGE_DIR: str = os.environ.get(
    "FORENSIC_EVIDENCE_FILES_DIR",
    "/secure/forensics/evidence"
)

#: Standard filename for the chain of custody log within a case directory.
#: Using JSON Lines format (.jsonl) for append-friendly logging.
CHAIN_OF_CUSTODY_FILENAME: Final[str] = "chain_of_custody.jsonl"

#: Valid evidence states used by the evidence_tracker module
VALID_EVIDENCE_STATES: Final[FrozenSet[str]] = frozenset([
    "active", "archived", "disposed", "transferred", "in_review", "sealed", "destroyed"
])

#: Evidence classifications in order of sensitivity (low to high)
EVIDENCE_CLASSIFICATIONS: Final[List[str]] = [
    "unclassified", "confidential", "sensitive", "restricted"
]

#: Maximum size for evidence metadata files to prevent abuse
MAX_METADATA_SIZE_BYTES: Final[int] = 10 * 1024 * 1024  # 10MB

# --- Cryptography Constants ---

#: Name/Identifier used to retrieve the dedicated forensic encryption key
#: from secure credential storage (e.g., Vault, environment variable).
FORENSIC_ENCRYPTION_KEY_NAME: Final[str] = "forensic_evidence_encryption_key"

#: Name for the HMAC signing key for integrity validation
FORENSIC_HMAC_KEY_NAME: Final[str] = "forensic_hmac_key"

#: Key cache duration in seconds (5 minutes)
KEY_CACHE_DURATION: Final[int] = 300

#: Maximum key retrieval attempts before failing
MAX_KEY_RETRIEVAL_ATTEMPTS: Final[int] = 3

#: The cipher to use for evidence encryption
DEFAULT_ENCRYPTION_ALGORITHM: Final[str] = "AES-256-GCM"

#: Default initialization vector length in bytes for encryption
IV_LENGTH_BYTES: Final[int] = 12

#: Whether to auto-encrypt sensitive evidence files by default
DEFAULT_ENCRYPT_SENSITIVE: Final[bool] = True

# --- File System Constants ---

#: Default file permissions (octal) for newly created secure files (e.g., metadata, temp files).
#: 0o600 restricts access to the owner only (Read/Write).
DEFAULT_SECURE_FILE_PERMS: Final[int] = 0o600

#: Read-only permissions for evidence files (Read-only for owner)
DEFAULT_READ_ONLY_FILE_PERMS: Final[int] = 0o400

#: Default directory permissions that restrict access to the owner
DEFAULT_SECURE_DIR_PERMS: Final[int] = 0o700

#: Designated directory for storing temporary files generated during forensic analysis.
#: Should be on a filesystem with sufficient space and appropriate security controls.
TEMP_DIR_FORENSICS: str = os.environ.get(
    "FORENSIC_TEMP_DIR",
    "/tmp/forensics"
)

#: Maximum allowed size for secure temporary files to prevent disk space abuse
MAX_TEMP_FILE_SIZE_BYTES: Final[int] = 500 * 1024 * 1024  # 500MB

#: Dictionary mapping file extensions to their MIME types for common forensic artifacts
EVIDENCE_TYPE_MAPPINGS: Final[Dict[str, str]] = {
    ".mem": "application/octet-stream;forensic-type=memory-dump",
    ".raw": "application/octet-stream;forensic-type=disk-image",
    ".dd": "application/octet-stream;forensic-type=disk-image",
    ".img": "application/octet-stream;forensic-type=disk-image",
    ".e01": "application/octet-stream;forensic-type=encase-image",
    ".aff": "application/octet-stream;forensic-type=aff-image",
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/vnd.tcpdump.pcap",
    ".evt": "application/x-windows-event",
    ".evtx": "application/x-windows-event",
    ".log": "text/plain;forensic-type=log",
    ".xml": "text/xml",
    ".json": "application/json",
    ".html": "text/html",
    ".htm": "text/html",
    ".txt": "text/plain",
    ".pdf": "application/pdf",
}

#: Default file exporter "safe output" permissions
DEFAULT_EXPORT_FILE_PERMS: Final[int] = 0o644

# --- Logging Constants ---

#: Prefix for forensic-specific log operations recorded by logging_utils.
FORENSIC_LOG_OPERATION_PREFIX: Final[str] = "ForensicOperation"

#: Default log directory for forensic operations
FORENSIC_LOG_DIR: str = os.environ.get(
    "FORENSIC_LOG_DIR",
    "/var/log/forensics"
)

#: The directory for high-security forensic logs (may be on write-once media)
FORENSIC_SECURE_LOG_DIR: Final[str] = os.environ.get(
    "FORENSIC_SECURE_LOG_DIR",
    "/secure/forensics/logs"
)

#: Default log file name for forensic operations
FORENSIC_LOG_FILE: Final[str] = "forensic_operations.log"

#: Maximum size for rotating forensic logs
MAX_LOG_SIZE: Final[int] = 10 * 1024 * 1024  # 10MB

#: Number of backup log files to keep
LOG_BACKUP_COUNT: Final[int] = 10

# --- Timestamp Constants ---

#: Default timezone for forensic operations if not otherwise specified. UTC is standard.
DEFAULT_TIMEZONE: Final[str] = "UTC"

#: Standard ISO 8601 format for timestamps in logs and metadata.
DEFAULT_TIMESTAMP_FORMAT: Final[str] = "iso8601"  # Corresponds to datetime.isoformat()

#: Maximum allowed time skew (for timestamp validation)
MAX_TIMESTAMP_SKEW: Final[timedelta] = timedelta(minutes=10)

#: Common timestamp formats to try when parsing ambiguous timestamps
COMMON_TIMESTAMP_FORMATS: Final[List[str]] = [
    "%Y-%m-%dT%H:%M:%S.%fZ",         # ISO 8601 with microseconds
    "%Y-%m-%dT%H:%M:%SZ",            # ISO 8601
    "%Y-%m-%d %H:%M:%S.%f%z",        # ISO with space and timezone
    "%Y-%m-%d %H:%M:%S",             # Common YYYY-MM-DD HH:MM:SS
    "%d/%b/%Y:%H:%M:%S %z",          # Apache/nginx log format
    "%b %d %H:%M:%S",                # Syslog format
    "%m/%d/%Y %I:%M:%S %p",          # US format with AM/PM
]

# --- Sanitization Constants ---

#: Default redaction placeholder for sanitized content
DEFAULT_REDACTION_PLACEHOLDER: Final[str] = "[REDACTED]"

#: Common credential keywords to detect and redact in data
CREDENTIAL_KEYWORDS: Final[List[str]] = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "api-key",
    "token", "access_key", "access-key", "credential", "auth", "key"
]

#: Common patterns for sensitive data that should be redacted
SENSITIVE_DATA_PATTERNS: Final[Dict[str, str]] = {
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "api_key": r"\b(?:key|api|token|secret)[-_]?[0-9a-zA-Z]{16,}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "private_key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
}

# --- Network Constants ---

#: Default packet capture size for network forensics
DEFAULT_PACKET_CAPTURE_SIZE: Final[int] = 65535

#: Default network timeout in seconds
DEFAULT_NETWORK_TIMEOUT: Final[int] = 15

#: Default ports for common forensic-relevant services
DEFAULT_PORTS: Final[Dict[str, int]] = {
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "http": 80,
    "https": 443,
    "smb": 445,
    "rdp": 3389,
}

# --- Report Generation Constants ---

#: Default report templates directory
REPORT_TEMPLATES_DIR: Final[str] = "admin/security/forensics/templates/reports"

#: Default evidence report template
DEFAULT_REPORT_TEMPLATE: Final[str] = "standard_report.html"

#: Maximum report generation time (timeout) in seconds
MAX_REPORT_GENERATION_TIME: Final[int] = 300  # 5 minutes

#: Valid report formats
VALID_REPORT_FORMATS: Final[Tuple[str, ...]] = ("html", "pdf", "json", "text")

# --- Static Analysis Constants ---

#: Safe file extensions that are considered low risk for execution
SAFE_FILE_EXTENSIONS: Final[FrozenSet[str]] = frozenset([
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".pdf",
    ".md", ".yaml", ".yml", ".ini", ".conf", ".cfg"
])

#: Allowed MIME types for file processing
ALLOWED_MIME_TYPES: Final[FrozenSet[str]] = frozenset([
    "text/plain", "text/html", "text/csv", "text/xml",
    "application/json", "application/xml", "application/pdf"
])

#: Maximum file size for analysis in bytes
MAX_FILE_SIZE_BYTES: Final[int] = 100 * 1024 * 1024  # 100MB

#: Maximum length for filenames
MAX_FILENAME_LENGTH: Final[int] = 255

#: Default minimum string length for extraction during analysis
DEFAULT_MIN_STRING_LENGTH: Final[int] = 6

#: Hash comparison threshold for similarity
HASH_COMPARISON_THRESHOLD: Final[float] = 1.0

#: Fuzzy hash threshold for similarity
FUZZY_HASH_THRESHOLD: Final[int] = 70

# --- Environment-specific configuration ---
# Check environment for operational mode
ENV_TYPE = os.environ.get("APP_ENV", "production").lower()

# Adjust behavior based on environment
if ENV_TYPE == "development":
    # Use less strict settings for development
    TEMP_DIR_FORENSICS = "/tmp/forensic_dev"
    DEV_MAX_TEMP_FILE_SIZE_BYTES = 1024 * 1024 * 1024  # 1GB for development
    DEV_EXPORT_FILE_PERMS = 0o644  # More permissive in dev
    # Force use of localhost for development
    DEV_EVIDENCE_METADATA_DIR = "/tmp/forensic_dev/metadata"
    EVIDENCE_STORAGE_DIR = "/tmp/forensic_dev/evidence"
elif ENV_TYPE == "testing":
    # Test-specific paths
    TEMP_DIR_FORENSICS = "/tmp/forensic_test"
    TEST_EVIDENCE_METADATA_DIR = "/tmp/forensic_test/metadata"
    EVIDENCE_STORAGE_DIR = "/tmp/forensic_test/evidence"
    FORENSIC_LOG_DIR = "/tmp/forensic_test/logs"
