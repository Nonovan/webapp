"""
Common components for static analysis in the Forensic Analysis Toolkit.

This package provides shared utilities and core components used by the static analysis
tools within the Forensic Analysis Toolkit. It includes file handling utilities, hash
computation functions, signature database systems, and YARA rule integration.

These components ensure consistent behavior across the toolkit while maintaining proper
security controls and providing optimized implementations of frequently used operations.
"""

import logging
import importlib.util
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple, Union
from datetime import datetime, timezone

# Initialize package-level logger
logger = logging.getLogger(__name__)

# Package version information
__version__ = '1.0.0'

# Package metadata
__author__ = 'Security Team'
__email__ = 'security@example.com'
__status__ = 'Production'

# Package path utilities
PACKAGE_PATH = Path(__file__).parent
YARA_RULES_PATH = PACKAGE_PATH / 'yara_rules'
SIGNATURE_DB_PATH = PACKAGE_PATH / 'signature_db'

# Initialize feature flags and availability trackers
INITIALIZATION_SUCCESS = False
SIGNATURE_DB_AVAILABLE = False
YARA_SCANNER_AVAILABLE = False
SSDEEP_AVAILABLE = False
TLSH_AVAILABLE = False
PEFILE_AVAILABLE = False
EMBEDDED_EXTRACTION_AVAILABLE = False
FORENSIC_CORE_AVAILABLE = False

# Try importing forensic core utilities first, as other components may need them
try:
    from admin.security.forensics.utils.logging_utils import log_forensic_operation, setup_forensic_logger
    from admin.security.forensics.utils.validation_utils import validate_path, validate_file_format
    from admin.security.forensics.utils.crypto import calculate_file_hash, verify_file_hash
    FORENSIC_CORE_AVAILABLE = True
except ImportError:
    logger.warning("Forensic core utilities not available, using fallback implementations")
    FORENSIC_CORE_AVAILABLE = False

    # Simple fallback for logging if forensic utilities are not available
    def log_forensic_operation(operation: str, success: bool, details: Dict[str, Any] = None,
                              level: int = logging.INFO) -> None:
        """Simple fallback for forensic logging."""
        msg = f"Forensic operation: {operation}, Success: {success}"
        if details:
            msg += f", Details: {str(details)}"
        logger.log(level=level, msg=msg)

    # Fallback for hash calculation
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash using standard library."""
        import hashlib
        if not os.path.isfile(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.new(algorithm)
                for chunk in iter(lambda: f.read(65536), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            return None

    # Fallback for hash verification
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify file hash using standard library."""
        actual_hash = calculate_file_hash(file_path, algorithm)
        if not actual_hash:
            return False
        return actual_hash.lower() == expected_hash.lower()

    # Fallback for path validation
    def validate_path(path: str, **kwargs) -> Tuple[bool, str]:
        """Simple path validation function."""
        if not path:
            return False, "Empty path"
        try:
            path_obj = Path(path)
            if kwargs.get("must_exist", False) and not path_obj.exists():
                return False, f"Path does not exist: {path}"
            return True, ""
        except Exception as e:
            return False, f"Invalid path: {str(e)}"

    # Fallback for file format validation
    def validate_file_format(file_path: str, allowed_formats: Optional[List[str]] = None) -> bool:
        """Simple file format validation."""
        if not os.path.isfile(file_path):
            return False
        if not allowed_formats:
            return True
        extension = os.path.splitext(file_path)[1].lower()
        return extension in allowed_formats

# Import and expose core utilities for direct package-level imports
try:
    from .file_utils import (
        # Core file operations
        safe_analyze_file,
        isolated_file_access,
        identify_file_type,
        extract_embedded_files,
        extract_file_strings,
        calculate_file_entropy,

        # Analysis functions
        extract_metadata_by_format,
        analyze_script_file,
        detect_file_obfuscation,
        compare_files_forensically,
        save_analysis_report
    )

    from .hash_utils import (
        # Basic hash functions
        calculate_hash,
        calculate_multiple_hashes,
        calculate_fuzzy_hash,
        verify_hash,

        # Advanced hash functions
        compare_fuzzy_hashes,
        create_hash_database,
        check_hash_against_database,
        hash_directory,
        find_similar_files
    )

    # Check for optional dependencies first
    # Check for fuzzy hashing libraries
    try:
        import ssdeep
        SSDEEP_AVAILABLE = True
        logger.debug("ssdeep library available")
    except ImportError:
        logger.debug("ssdeep library not available")
        SSDEEP_AVAILABLE = False

    try:
        import tlsh
        TLSH_AVAILABLE = True
        logger.debug("tlsh library available")
    except ImportError:
        logger.debug("tlsh library not available")
        TLSH_AVAILABLE = False

    # Check for YARA
    try:
        import yara
        YARA_AVAILABLE = True
        logger.debug("yara-python library available")
    except ImportError:
        logger.debug("yara-python library not available")
        YARA_AVAILABLE = False

    # Check for PE file parsing
    try:
        import pefile
        PEFILE_AVAILABLE = True
        logger.debug("pefile library available")
    except ImportError:
        logger.debug("pefile library not available")
        PEFILE_AVAILABLE = False

    # Check for additional extraction tools
    try:
        # Check for common extraction libraries like python-magic, etc.
        magic_spec = importlib.util.find_spec("magic")
        EMBEDDED_EXTRACTION_AVAILABLE = magic_spec is not None
        if EMBEDDED_EXTRACTION_AVAILABLE:
            logger.debug("python-magic library available for enhanced file type detection")
    except ImportError:
        logger.debug("python-magic library not available")
        EMBEDDED_EXTRACTION_AVAILABLE = False

    # Core module initialization success
    INITIALIZATION_SUCCESS = True
    logger.debug("Static analysis common components initialized successfully")

except ImportError as e:
    logger.warning(f"Error importing static analysis common components: {e}")
    INITIALIZATION_SUCCESS = False


class SignatureVerificationStatus:
    """
    Represents the results of a code signature verification operation.
    """
    def __init__(
        self,
        verified: bool = False,
        verification_attempted: bool = False,
        signer_name: str = "",
        signer_id: str = "",
        issuer: str = "",
        reason: str = "",
        signature_timestamp: Optional[datetime] = None,
        valid_from: Optional[datetime] = None,
        valid_to: Optional[datetime] = None,
        certificate_chain_valid: bool = False,
        revocation_checked: bool = False,
        revoked: bool = False,
        extensions: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SignatureVerificationStatus with verification results.

        Args:
            verified: Whether the signature is valid
            verification_attempted: Whether verification was attempted
            signer_name: Name of the signer (e.g. company name)
            signer_id: Identifier for the signer (e.g. certificate subject)
            issuer: Certificate issuer information
            reason: Reason for verification failure if not verified
            signature_timestamp: When the file was signed
            valid_from: Start of certificate validity period
            valid_to: End of certificate validity period
            certificate_chain_valid: Whether the certificate chain is valid
            revocation_checked: Whether revocation status was checked
            revoked: Whether the certificate was revoked
            extensions: Additional certificate extension information
        """
        self.verified = verified
        self.verification_attempted = verification_attempted
        self.signer_name = signer_name
        self.signer_id = signer_id
        self.issuer = issuer
        self.reason = reason
        self.timestamp = signature_timestamp or datetime.now()
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.certificate_chain_valid = certificate_chain_valid
        self.revocation_checked = revocation_checked
        self.revoked = revoked
        self.extensions = extensions or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert verification status to a dictionary representation."""
        return {
            "verified": self.verified,
            "verification_attempted": self.verification_attempted,
            "signer_name": self.signer_name,
            "signer_id": self.signer_id,
            "issuer": self.issuer,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "certificate_chain_valid": self.certificate_chain_valid,
            "revocation_checked": self.revocation_checked,
            "revoked": self.revoked,
            "extensions": self.extensions
        }


class SignatureDBManager:
    """
    Manager class for accessing and querying signature databases.

    This class provides a unified interface to the various signature databases
    used for static analysis, including code signing certificates, malware
    signatures, and file type identification.
    """

    def __init__(self, db_root: Optional[str] = None):
        """
        Initialize the signature database manager.

        Args:
            db_root: Root directory for signature databases (optional)
        """
        # Set the database root directory
        if db_root:
            self.db_root = Path(db_root)
        else:
            # Default to module's directory
            self.db_root = SIGNATURE_DB_PATH

        # Set up paths for the different databases
        self.code_signing_path = self.db_root / "code_signing"
        self.malware_path = self.db_root / "malware"
        self.file_types_path = self.db_root / "file_types"

        # Load database status
        self.initialized = False
        self._db_status = self._initialize_databases()

        logger.info(f"SignatureDBManager initialized with root: {self.db_root}")

    def _initialize_databases(self) -> Dict[str, bool]:
        """Initialize and check status of all signature databases."""
        status = {
            "code_signing": False,
            "malware": False,
            "file_types": False
        }

        # Check for code signing database
        if self.code_signing_path.exists():
            trusted_certs_path = self.code_signing_path / "trusted_certs.json"
            if trusted_certs_path.exists():
                status["code_signing"] = True
                logger.debug(f"Code signing database found at {self.code_signing_path}")

        # Check for malware database
        if self.malware_path.exists():
            hash_db_path = self.malware_path / "hash_database.bin"
            yara_index_path = self.malware_path / "yara_index.json"
            if hash_db_path.exists() or yara_index_path.exists():
                status["malware"] = True
                logger.debug(f"Malware database found at {self.malware_path}")

        # Check for file types database
        if self.file_types_path.exists():
            magic_bytes_path = self.file_types_path / "magic_bytes.bin"
            if magic_bytes_path.exists():
                status["file_types"] = True
                logger.debug(f"File types database found at {self.file_types_path}")

        self.initialized = any(status.values())
        return status

    def verify_code_signature(self, file_path: str) -> SignatureVerificationStatus:
        """
        Verify the code signature of a file.

        Args:
            file_path: Path to the file to verify

        Returns:
            SignatureVerificationStatus object with verification results
        """
        logger.debug(f"Verifying code signature for {file_path}")

        if not self.initialized or not self._db_status["code_signing"]:
            logger.warning("Code signing database not available")
            return SignatureVerificationStatus(
                verified=False,
                verification_attempted=False,
                reason="Code signing database not available"
            )

        # This is a stub implementation
        # In a real implementation, this would use platform-specific tools
        # or libraries to verify the code signature

        # For the purpose of this stub, we'll just check if the file exists
        if not os.path.exists(file_path):
            return SignatureVerificationStatus(
                verified=False,
                verification_attempted=True,
                reason=f"File not found: {file_path}"
            )

        # Mock verification based on file extension for testing
        # In a real implementation, this would perform actual verification
        if file_path.lower().endswith(('.exe', '.dll', '.sys')):
            # For testing purposes, assuming executables are not verified
            return SignatureVerificationStatus(
                verified=False,
                verification_attempted=True,
                reason="Signature could not be verified",
                signer_name="Unknown",
                signature_timestamp=datetime.now()
            )
        elif file_path.lower().endswith(('.pdf', '.docx')):
            # For testing purposes, assuming documents are verified
            return SignatureVerificationStatus(
                verified=True,
                verification_attempted=True,
                signer_name="Example Corporation",
                signer_id="CN=Example Corporation, O=Example Inc., C=US",
                issuer="CN=Trusted CA, O=Certificate Authority, C=US",
                signature_timestamp=datetime.now(),
                valid_from=datetime(2023, 1, 1),
                valid_to=datetime(2025, 1, 1),
                certificate_chain_valid=True,
                revocation_checked=True,
                revoked=False
            )
        else:
            # For other files, assuming no signature found
            return SignatureVerificationStatus(
                verified=False,
                verification_attempted=True,
                reason="No signature found"
            )

    def check_malware_signatures(
        self,
        file_path: str,
        file_hash: Optional[str] = None,
        check_patterns: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Check a file against known malware signatures.

        Args:
            file_path: Path to the file to check
            file_hash: Optional pre-calculated hash of the file (SHA-256)
            check_patterns: Whether to check binary patterns (slower)

        Returns:
            List of dictionaries with signature match information
        """
        logger.debug(f"Checking malware signatures for {file_path}")

        if not self.initialized or not self._db_status["malware"]:
            logger.warning("Malware signature database not available")
            return []

        # This is a stub implementation
        # In a real implementation, this would check the file against
        # hash databases, binary patterns, and YARA rules

        # For the purpose of this stub, just check if the file exists
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []

        # Mock detection based on filename for testing
        # In a real implementation, this would perform actual signature checks
        matches = []

        filename = os.path.basename(file_path).lower()
        if "malware" in filename or "virus" in filename:
            # For testing, generate a sample match
            matches.append({
                "signature_id": "TEST-001",
                "name": "Test Malware",
                "type": "trojan",
                "family": "TestFamily",
                "variant": "A",
                "risk_level": "high",
                "description": "This is a test malware detection",
                "source": "test",
                "confidence": 0.95,
                "match_type": "filename"
            })

        return matches

    def identify_file_type(self, file_path: str) -> Dict[str, str]:
        """
        Identify the type of a file using signature database.

        Args:
            file_path: Path to the file to identify

        Returns:
            Dictionary with file type information
        """
        logger.debug(f"Identifying file type for {file_path}")

        if not self.initialized or not self._db_status["file_types"]:
            logger.warning("File types database not available")
            return {"type": "unknown", "mime_type": "application/octet-stream"}

        # This is a stub implementation
        # In a real implementation, this would check magic bytes and file extensions

        # For simplicity, we'll just use the file extension for now
        _, ext = os.path.splitext(file_path.lower())

        mime_types = {
            ".txt": "text/plain",
            ".html": "text/html",
            ".htm": "text/html",
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt": "application/vnd.ms-powerpoint",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".exe": "application/x-dosexec",
            ".dll": "application/x-dosexec",
            ".sys": "application/x-dosexec",
            ".elf": "application/x-executable",
            ".so": "application/x-sharedlib",
            ".py": "text/x-python",
            ".js": "text/javascript",
            ".java": "text/x-java",
            ".jar": "application/java-archive",
            ".json": "application/json",
            ".xml": "application/xml",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
            ".wav": "audio/wav",
            ".avi": "video/x-msvideo",
            ".mov": "video/quicktime"
        }

        mime_type = mime_types.get(ext, "application/octet-stream")

        return {
            "type": ext[1:] if ext else "unknown",
            "mime_type": mime_type,
            "extension": ext,
            "category": self._get_file_category(mime_type)
        }

    def _get_file_category(self, mime_type: str) -> str:
        """Helper method to categorize files based on MIME type."""
        if mime_type.startswith("text/"):
            return "text"
        elif mime_type.startswith("image/"):
            return "image"
        elif mime_type.startswith("audio/"):
            return "audio"
        elif mime_type.startswith("video/"):
            return "video"
        elif mime_type == "application/pdf":
            return "document"
        elif "document" in mime_type or "sheet" in mime_type or "presentation" in mime_type:
            return "document"
        elif "executable" in mime_type or mime_type == "application/x-dosexec":
            return "executable"
        elif "archive" in mime_type or mime_type in ["application/zip", "application/x-tar", "application/gzip"]:
            return "archive"
        else:
            return "binary"

    def update_database(self, db_type: str, source_path: str) -> bool:
        """
        Update a specific signature database from a source.

        Args:
            db_type: Type of database to update ('code_signing', 'malware', or 'file_types')
            source_path: Path to the source database files

        Returns:
            True if the update was successful, False otherwise
        """
        logger.info(f"Updating {db_type} database from {source_path}")

        if db_type not in ["code_signing", "malware", "file_types"]:
            logger.error(f"Invalid database type: {db_type}")
            return False

        # This is a stub implementation
        # In a real implementation, this would verify and update the database

        try:
            # Validate source
            if not os.path.exists(source_path):
                logger.error(f"Source path does not exist: {source_path}")
                return False

            # Verify source integrity
            if FORENSIC_CORE_AVAILABLE:
                valid, _ = validate_path(source_path, must_exist=True)
                if not valid:
                    logger.error(f"Source path validation failed: {source_path}")
                    return False

            # Log the update operation
            details = {
                "db_type": db_type,
                "source_path": source_path
            }

            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation(
                    f"update_{db_type}_database",
                    True,
                    details,
                    level=logging.INFO
                )

            # In a real implementation, would perform the actual update
            # ...

            # Update status
            self._db_status[db_type] = True
            return True

        except Exception as e:
            logger.error(f"Error updating {db_type} database: {str(e)}")

            if FORENSIC_CORE_AVAILABLE:
                log_forensic_operation(
                    f"update_{db_type}_database",
                    False,
                    {"db_type": db_type, "error": str(e)},
                    level=logging.ERROR
                )

            return False

    def get_database_info(self) -> Dict[str, Any]:
        """
        Get information about the signature databases.

        Returns:
            Dictionary with database status and metadata
        """
        return {
            "initialized": self.initialized,
            "status": self._db_status,
            "paths": {
                "root": str(self.db_root),
                "code_signing": str(self.code_signing_path),
                "malware": str(self.malware_path),
                "file_types": str(self.file_types_path)
            },
            "version": __version__
        }

    def verify_database_integrity(self) -> Dict[str, bool]:
        """
        Verify the integrity of signature databases.

        Returns:
            Dictionary with verification results for each database
        """
        results = {
            "code_signing": False,
            "malware": False,
            "file_types": False
        }

        # This is a stub implementation
        # In a real implementation, this would check database integrity

        # For now, just check if the directories exist
        results["code_signing"] = self.code_signing_path.exists()
        results["malware"] = self.malware_path.exists()
        results["file_types"] = self.file_types_path.exists()

        return results


class YaraScanner:
    """
    Wrapper for YARA scanning capabilities.

    This class provides an interface to the YARA scanning functionality,
    including rule compilation and scanning files and memory for matches.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize the YARA scanner.

        Args:
            rules_dir: Directory containing YARA rule files (optional)
        """
        self.rules = None
        self.rules_dir = Path(rules_dir) if rules_dir else YARA_RULES_PATH
        self.initialized = False

        # Check if YARA is available
        if not YARA_AVAILABLE:
            logger.warning("YARA library not available, scanner cannot be initialized")
            return

        try:
            self._load_rules()
            self.initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize YARA scanner: {e}")

    def _load_rules(self) -> None:
        """Load YARA rules from the rules directory."""
        if not os.path.isdir(self.rules_dir):
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return

        try:
            # Find all .yar/.yara files in the rules directory and subdirectories
            rule_files = []
            for root, _, files in os.walk(self.rules_dir):
                for filename in files:
                    if filename.endswith(('.yar', '.yara')):
                        rule_files.append(os.path.join(root, filename))

            if not rule_files:
                logger.warning("No YARA rule files found")
                return

            # Compile all rules
            import yara
            rules_dict = {}
            for rule_file in rule_files:
                try:
                    namespace = os.path.basename(rule_file).split('.')[0]
                    rules_dict[namespace] = rule_file
                except Exception as e:
                    logger.warning(f"Failed to load YARA rule file {rule_file}: {e}")

            if rules_dict:
                self.rules = yara.compile(filepaths=rules_dict)
                logger.info(f"Loaded {len(rules_dict)} YARA rule files")
            else:
                logger.warning("No valid YARA rules found")

        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
            raise

    def scan_file(self, file_path: str, timeout: int = 60) -> List[Dict[str, Any]]:
        """
        Scan a file with YARA rules.

        Args:
            file_path: Path to the file to scan
            timeout: Timeout for scanning in seconds

        Returns:
            List of dictionaries with match information
        """
        if not self.initialized or not self.rules:
            logger.warning("YARA scanner not initialized")
            return []

        if not os.path.isfile(file_path):
            logger.warning(f"File not found: {file_path}")
            return []

        try:
            matches = self.rules.match(file_path, timeout=timeout)
            return self._format_matches(matches)
        except Exception as e:
            logger.error(f"Error scanning file with YARA: {e}")
            return []

    def scan_data(self, data: bytes, timeout: int = 60) -> List[Dict[str, Any]]:
        """
        Scan data with YARA rules.

        Args:
            data: Bytes to scan
            timeout: Timeout for scanning in seconds

        Returns:
            List of dictionaries with match information
        """
        if not self.initialized or not self.rules:
            logger.warning("YARA scanner not initialized")
            return []

        try:
            matches = self.rules.match(data=data, timeout=timeout)
            return self._format_matches(matches)
        except Exception as e:
            logger.error(f"Error scanning data with YARA: {e}")
            return []

    def _format_matches(self, matches) -> List[Dict[str, Any]]:
        """Format YARA matches as dictionaries."""
        results = []
        for match in matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "strings": []
            }

            # Include matched strings if available
            for string in match.strings:
                match_info["strings"].append({
                    "identifier": string[1],
                    "data": string[2].hex() if isinstance(string[2], bytes) else str(string[2]),
                    "offset": string[0]
                })

            results.append(match_info)

        return results

    def get_scanner_info(self) -> Dict[str, Any]:
        """Get information about the YARA scanner configuration."""
        return {
            "initialized": self.initialized,
            "rules_dir": str(self.rules_dir),
            "rules_loaded": bool(self.rules),
            "yara_available": YARA_AVAILABLE
        }


# Define public API
__all__ = [
    # File utilities
    'safe_analyze_file',
    'isolated_file_access',
    'identify_file_type',
    'extract_embedded_files',
    'extract_file_strings',
    'calculate_file_entropy',
    'extract_metadata_by_format',
    'analyze_script_file',
    'detect_file_obfuscation',
    'compare_files_forensically',
    'save_analysis_report',

    # Hash utilities
    'calculate_hash',
    'calculate_multiple_hashes',
    'calculate_fuzzy_hash',
    'verify_hash',
    'compare_fuzzy_hashes',
    'create_hash_database',
    'check_hash_against_database',
    'hash_directory',
    'find_similar_files',

    # Signature DB
    'SignatureDBManager',
    'SignatureVerificationStatus',

    # YARA scanning
    'YaraScanner',

    # Package constants
    'PACKAGE_PATH',
    'YARA_RULES_PATH',
    'SIGNATURE_DB_PATH',
    'SSDEEP_AVAILABLE',
    'TLSH_AVAILABLE',
    'YARA_AVAILABLE',
    'PEFILE_AVAILABLE',
    'EMBEDDED_EXTRACTION_AVAILABLE',
    'FORENSIC_CORE_AVAILABLE',
    'INITIALIZATION_SUCCESS',

    # Information functions
    'get_package_info',
    'check_dependencies',
    'get_component_status',

    # Version info
    '__version__',
    '__author__',
    '__email__',
    '__status__'
]

# Make SignatureDBManager and YaraScanner available at the package level
SIGNATURE_DB_AVAILABLE = True
YARA_SCANNER_AVAILABLE = True

def get_package_info() -> Dict[str, Any]:
    """
    Return package information and status.

    Returns:
        Dictionary with package version, initialization status,
        and component availability.
    """
    return {
        'version': __version__,
        'initialized': INITIALIZATION_SUCCESS,
        'components': {
            'file_utils': True,
            'hash_utils': True,
            'signature_db': SIGNATURE_DB_AVAILABLE,
            'yara_scanner': YARA_SCANNER_AVAILABLE,
            'ssdeep': SSDEEP_AVAILABLE,
            'tlsh': TLSH_AVAILABLE,
            'pefile': PEFILE_AVAILABLE,
            'embedded_extraction': EMBEDDED_EXTRACTION_AVAILABLE,
            'forensic_core': FORENSIC_CORE_AVAILABLE
        },
        'paths': {
            'package': str(PACKAGE_PATH),
            'yara_rules': str(YARA_RULES_PATH),
            'signature_db': str(SIGNATURE_DB_PATH)
        }
    }

def check_dependencies() -> Dict[str, bool]:
    """
    Check availability of optional dependencies.

    Returns:
        Dictionary with dependency status.
    """
    dependencies = {
        'ssdeep': SSDEEP_AVAILABLE,
        'tlsh': TLSH_AVAILABLE,
        'yara': YARA_AVAILABLE,
        'pefile': PEFILE_AVAILABLE,
        'python-magic': EMBEDDED_EXTRACTION_AVAILABLE,
        'forensic_core': FORENSIC_CORE_AVAILABLE
    }

    # Check for additional parsing libraries
    try:
        import olefile
        dependencies['olefile'] = True
    except ImportError:
        dependencies['olefile'] = False

    try:
        import PyPDF2
        dependencies['pypdf2'] = True
    except ImportError:
        dependencies['pypdf2'] = False

    try:
        import zipfile
        dependencies['zipfile'] = True
    except ImportError:
        dependencies['zipfile'] = False

    try:
        import tarfile
        dependencies['tarfile'] = True
    except ImportError:
        dependencies['tarfile'] = False

    return dependencies

def get_component_status() -> Dict[str, Dict[str, Any]]:
    """
    Get detailed status of each component including dependency information.

    Returns:
        Dictionary with detailed component status
    """
    status = {}

    # File utility component
    status["file_utils"] = {
        "available": True,
        "functions": [
            "safe_analyze_file", "isolated_file_access", "identify_file_type",
            "extract_embedded_files", "extract_file_strings", "calculate_file_entropy",
            "extract_metadata_by_format", "analyze_script_file",
            "detect_file_obfuscation", "compare_files_forensically", "save_analysis_report"
        ],
        "dependencies": {
            "pefile": PEFILE_AVAILABLE,
            "python-magic": EMBEDDED_EXTRACTION_AVAILABLE
        }
    }

    # Hash utility component
    status["hash_utils"] = {
        "available": True,
        "functions": [
            "calculate_hash", "calculate_multiple_hashes", "calculate_fuzzy_hash",
            "verify_hash", "compare_fuzzy_hashes", "create_hash_database",
            "check_hash_against_database", "hash_directory", "find_similar_files"
        ],
        "dependencies": {
            "ssdeep": SSDEEP_AVAILABLE,
            "tlsh": TLSH_AVAILABLE
        }
    }

    # Signature DB component
    status["signature_db"] = {
        "available": SIGNATURE_DB_AVAILABLE,
        "path": str(SIGNATURE_DB_PATH),
        "exists": SIGNATURE_DB_PATH.exists(),
        "classes": ["SignatureDBManager", "SignatureVerificationStatus"]
    }

    # YARA scanner component
    status["yara_scanner"] = {
        "available": YARA_SCANNER_AVAILABLE,
        "path": str(YARA_RULES_PATH),
        "exists": YARA_RULES_PATH.exists(),
        "dependencies": {
            "yara": YARA_AVAILABLE
        }
    }

    return status

# Initialize required directories if they don't exist
def _ensure_directories():
    """Ensure required directories exist."""
    try:
        # Create YARA rules directory if it doesn't exist
        if not YARA_RULES_PATH.exists():
            YARA_RULES_PATH.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created YARA rules directory at {YARA_RULES_PATH}")

        # Create signature database directory if it doesn't exist
        if not SIGNATURE_DB_PATH.exists():
            SIGNATURE_DB_PATH.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created signature database directory at {SIGNATURE_DB_PATH}")

            # Create subdirectories for different databases
            (SIGNATURE_DB_PATH / "code_signing").mkdir(exist_ok=True)
            (SIGNATURE_DB_PATH / "malware").mkdir(exist_ok=True)
            (SIGNATURE_DB_PATH / "file_types").mkdir(exist_ok=True)
            logger.info(f"Created signature database subdirectories")

    except (OSError, PermissionError) as e:
        logger.warning(f"Could not create required directories: {e}")
        if FORENSIC_CORE_AVAILABLE:
            log_forensic_operation("create_directory", False, {
                "dir": str(SIGNATURE_DB_PATH),
                "error": str(e)
            })

# Run directory initialization
_ensure_directories()

# Log initialization status
logger.info(f"Static analysis common module initialized - version {__version__}")
if FORENSIC_CORE_AVAILABLE:
    log_forensic_operation("module_init", True, {
        "module": "static_analysis.common",
        "version": __version__,
        "dependencies": check_dependencies()
    })
