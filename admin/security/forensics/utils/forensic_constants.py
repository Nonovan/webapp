"""
Common Constants for the Forensic Analysis Toolkit Utilities.

This module defines shared constants used across the forensic utility modules
(`crypto.py`, `evidence_tracker.py`, `file_utils.py`, etc.) to ensure
consistency and ease of configuration.
"""

from typing import List, Final

# --- Hashing Constants ---

#: Default hash algorithm used for integrity checks and evidence verification.
#: Aligns with core security settings where possible.
DEFAULT_HASH_ALGORITHM: Final[str] = "sha256"

#: List of supported cryptographic hash algorithms for forensic operations.
SUPPORTED_HASH_ALGORITHMS: Final[List[str]] = ["md5", "sha1", "sha256", "sha512"]

#: Chunk size (in bytes) for reading files during hashing operations.
#: Optimizes memory usage for large files. 64KB is a common default.
CHUNK_SIZE: Final[int] = 65536  # 64KB

# --- Evidence Management Constants ---

#: Base directory for storing forensic evidence metadata files.
#: Should be a secure location with restricted access.
EVIDENCE_METADATA_DIR: Final[str] = "/secure/forensics/metadata" # Example: Use a configurable path in production

#: Standard filename for the chain of custody log within a case directory.
#: Using JSON Lines format (.jsonl) for append-friendly logging.
CHAIN_OF_CUSTODY_FILENAME: Final[str] = "chain_of_custody.jsonl"

# --- Cryptography Constants ---

#: Name/Identifier used to retrieve the dedicated forensic encryption key
#: from secure credential storage (e.g., Vault, environment variable).
FORENSIC_ENCRYPTION_KEY_NAME: Final[str] = "forensic_evidence_encryption_key"

# --- File System Constants ---

#: Default file permissions (octal) for newly created secure files (e.g., metadata, temp files).
#: 0o600 restricts access to the owner only (Read/Write).
DEFAULT_SECURE_FILE_PERMS: Final[int] = 0o600

#: Designated directory for storing temporary files generated during forensic analysis.
#: Should be on a filesystem with sufficient space and appropriate security controls.
TEMP_DIR_FORENSICS: Final[str] = "/tmp/forensics" # Example: Use a configurable, secured path

# --- Logging Constants ---

#: Prefix for forensic-specific log operations recorded by logging_utils.
FORENSIC_LOG_OPERATION_PREFIX: Final[str] = "ForensicOperation"

# --- Timestamp Constants ---

#: Default timezone for forensic operations if not otherwise specified. UTC is standard.
DEFAULT_TIMEZONE: Final[str] = "UTC"

#: Standard ISO 8601 format for timestamps in logs and metadata.
DEFAULT_TIMESTAMP_FORMAT: Final[str] = "iso8601" # Corresponds to datetime.isoformat()
