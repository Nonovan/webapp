"""
Core utility functions for the Cloud Infrastructure Platform.

This module provides utility functions used throughout the application for
common tasks such as:
- File integrity verification through SRI hash generation
- Security operations like hash comparison and file integrity checking
- Date and time handling with proper timezone support
- Data formatting and conversion utilities
- Metrics collection helpers
- System resource monitoring

These utilities are designed to be stateless, reusable components that
encapsulate common operations to reduce code duplication and ensure
consistent behavior throughout the application.
"""

import base64
import glob
import hashlib
import logging
import os
import pwd
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import psutil
from flask import current_app, has_app_context

# Type definitions
FileMetadata = Dict[str, Any]
ResourceMetrics = Dict[str, Any]
FileChangeInfo = Dict[str, Any]

# Constants
DEFAULT_HASH_ALGORITHM = 'sha256'
SMALL_FILE_THRESHOLD = 10240  # 10KB
EXECUTABLE_PATTERNS = ['*.so', '*.dll', '*.exe', '*.bin']
CRITICAL_FILE_PATTERNS = ['*.py', 'config.*', '.env*', '*.ini', 'requirements.txt']
ALLOWED_HIDDEN_FILES = ['.env', '.gitignore', '.dockerignore']
DEFAULT_READ_CHUNK_SIZE = 4096  # 4KB chunks for file reading

# Setup module-level logger
logger = logging.getLogger(__name__)


def generate_sri_hash(file_path: str) -> str:
    """
    Generate a Subresource Integrity hash for a file.

    Creates a base64-encoded SHA-384 hash suitable for use in SRI attributes
    in HTML to verify resource integrity.

    Args:
        file_path: Path to the file

    Returns:
        SRI hash string in the format "sha384-{hash}"

    Raises:
        FileNotFoundError: If the specified file does not exist
        IOError: If the file cannot be read
    """
    try:
        with open(file_path, 'rb') as f:
            file_contents = f.read()

        digest = hashlib.sha384(file_contents).digest()
        b64_hash = base64.b64encode(digest).decode('utf-8')
        return f"sha384-{b64_hash}"
    except FileNotFoundError:
        log_error(f"SRI hash generation failed: File not found: {file_path}")
        raise
    except IOError as e:
        log_error(f"SRI hash generation failed: I/O error: {str(e)}")
        raise


def calculate_file_hash(file_path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """
    Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Hexadecimal hash string

    Raises:
        FileNotFoundError: If the specified file does not exist
        ValueError: If an unsupported algorithm is specified
        IOError: If the file cannot be read
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    hash_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }

    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    hash_func = hash_algorithms[algorithm]()

    try:
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks for memory efficiency
            for chunk in iter(lambda: f.read(DEFAULT_READ_CHUNK_SIZE), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()
    except IOError as e:
        log_error(f"Failed to read file for hashing: {file_path} - {str(e)}")
        raise


def get_critical_file_hashes(files: List[str], algorithm: str = DEFAULT_HASH_ALGORITHM) -> Dict[str, str]:
    """
    Generate hash dictionary for critical application files.

    Used to create reference hashes for integrity checking.

    Args:
        files: List of file paths to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Dictionary mapping file paths to their hash values
    """
    from models.audit_log import AuditLog
    from core.security_utils import log_security_event

    hashes = {}

    for file_path in files:
        # Normalize the path for consistency
        normalized_path = os.path.normpath(file_path)

        if not os.path.exists(normalized_path):
            log_warning(f"File not found for hashing: {normalized_path}")
            continue

        try:
            file_hash = calculate_file_hash(normalized_path, algorithm)
            hashes[normalized_path] = file_hash

            # Check if this is a security-critical file
            if has_app_context() and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
                critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
                if normalized_path in critical_files:
                    # Log the hash calculation for audit purposes
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Integrity hash calculated for critical file: {normalized_path}",
                        severity=AuditLog.SEVERITY_INFO,
                        details=f"Algorithm: {algorithm}, Hash: {file_hash[:8]}..."
                    )
        except (IOError, ValueError, PermissionError) as e:
            log_error(f"Failed to hash {normalized_path}: {str(e)}")
            hashes[normalized_path] = None

            # Log file access errors for security-critical files
            if has_app_context() and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
                critical_files = current_app.config.get('SECURITY_CRITICAL_FILES', [])
                if normalized_path in critical_files:
                    log_security_event(
                        event_type=AuditLog.EVENT_FILE_INTEGRITY,
                        description=f"Failed to verify integrity of critical file: {normalized_path}",
                        severity=AuditLog.SEVERITY_WARNING,
                        details=f"Error: {str(e)}"
                    )

    return hashes


def generate_request_id() -> str:
    """
    Generate a unique request ID for tracking and security monitoring.

    This function creates a unique identifier that combines:
    - UUID v4 for global uniqueness
    - Timestamp component for chronological sorting
    - Process ID to differentiate between application instances
    - Host identifier to track across distributed systems

    The resulting ID is useful for:
    - Request tracing across microservices
    - Security event correlation
    - Log analysis and filtering
    - Performance monitoring
    - Distributed tracing in cloud environments

    Returns:
        str: Unique request ID in format: 'req-{timestamp}-{uuid}-{host}-{pid}'
    """
    timestamp = int(time.time() * 1000)  # Millisecond precision
    unique_id = uuid.uuid4().hex[:12]    # Use first 12 chars of UUID for brevity
    process_id = os.getpid() % 10000     # Include process ID (truncated)

    # Get a host identifier (first 4 chars of hostname hash)
    try:
        import socket
        hostname = socket.gethostname()
        host_id = hashlib.md5(hostname.encode()).hexdigest()[:4]
    except (OSError, ImportError):
        host_id = "0000"  # Fallback if hostname can't be retrieved

    # Format: req-{timestamp}-{uuid}-{host}-{pid}
    # Example: req-1635789042513-a7de31f8b4c2-1a2b-3478
    request_id = f"req-{timestamp}-{unique_id}-{host_id}-{process_id}"

    return request_id


def now_utc() -> datetime:
    """
    Get current UTC timestamp with timezone information.

    Returns:
        datetime: Current time in UTC with timezone info
    """
    return datetime.now(timezone.utc)


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format datetime as ISO 8601 string.

    Args:
        dt: Datetime to format (default: current time)

    Returns:
        ISO 8601 formatted timestamp string
    """
    if dt is None:
        dt = now_utc()

    # Ensure it has timezone info
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.isoformat()


def safe_json_serialize(obj: Any) -> Any:
    """
    Convert object to JSON-serializable format.

    Handles datetime objects, sets, and other common non-serializable types.

    Args:
        obj: Object to serialize

    Returns:
        JSON-serializable representation of the object
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return str(obj)
    elif hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
        return obj.to_dict()
    else:
        # Let the JSON serializer handle the type error
        return str(obj)


@contextmanager
def measure_execution_time() -> Generator[None, None, float]:
    """
    Context manager to measure execution time of a code block.

    Returns:
        float: Execution time in seconds

    Example:
        with measure_execution_time() as elapsed:
            # Code to measure
            time.sleep(1)
        print(f"Operation took {elapsed} seconds")
    """
    start_time = time.time()
    try:
        yield
    finally:
        execution_time = time.time() - start_time

    return execution_time


def get_system_resources() -> ResourceMetrics:
    """
    Get current system resource usage.

    Returns:
        Dictionary containing CPU, memory, and disk usage information

    Example:
        {
            'cpu': {'percent': 12.5, 'count': 8},
            'memory': {'total': 16777216, 'available': 8388608, 'percent': 50.0},
            'disk': {'total': 1073741824, 'used': 536870912, 'percent': 50.0},
            'timestamp': '2023-01-01T12:00:00+00:00'
        }
    """
    try:
        return {
            'cpu': {
                'percent': psutil.cpu_percent(interval=0.5),
                'count': psutil.cpu_count(),
                'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            },
            'network': {
                'connections': len(psutil.net_connections()),
                'interfaces': list(psutil.net_if_addrs().keys())
            },
            'timestamp': format_timestamp()
        }
    except (psutil.Error, OSError) as e:
        log_error(f"Error collecting system resources: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def get_process_info() -> Dict[str, Any]:
    """
    Get information about the current process.

    Returns:
        Dictionary containing process memory usage, threads, and connections

    Example:
        {
            'memory_mb': 120.5,
            'threads': 4,
            'connections': 8,
            'open_files': 15,
            'start_time': '2023-01-01T12:00:00+00:00',
            'timestamp': '2023-01-01T12:30:00+00:00'
        }
    """
    try:
        process = psutil.Process()

        # Calculate memory in different formats for better visibility
        memory_bytes = process.memory_info().rss
        memory_mb = memory_bytes / (1024 * 1024)
        memory_percent = process.memory_percent()

        # Get file and connection information safely
        try:
            open_files = len(process.open_files())
        except (psutil.AccessDenied, psutil.Error):
            open_files = -1

        try:
            connections = len(process.connections())
        except (psutil.AccessDenied, psutil.Error):
            connections = -1

        # Get CPU usage with a small interval for accuracy
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
        except (psutil.AccessDenied, psutil.Error):
            cpu_percent = None

        return {
            'pid': process.pid,
            'memory': {
                'bytes': memory_bytes,
                'mb': memory_mb,
                'percent': memory_percent
            },
            'cpu_percent': cpu_percent,
            'threads': process.num_threads(),
            'connections': connections,
            'open_files': open_files,
            'username': process.username(),
            'status': process.status(),
            'start_time': datetime.fromtimestamp(
                process.create_time(), tz=timezone.utc
            ).isoformat(),
            'timestamp': format_timestamp()
        }
    except (psutil.Error, OSError) as e:
        log_error(f"Error collecting process info: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def detect_file_changes(
        basedir: str,
        reference_hashes: Dict[str, str],
        critical_patterns: Optional[List[str]] = None,
        detect_permissions: bool = True,
        check_signatures: bool = False) -> List[FileChangeInfo]:
    """
    Detect changes in critical files by comparing current hashes with reference hashes.

    This function performs comprehensive file integrity monitoring by:
    1. Checking hash values against known good reference hashes
    2. Detecting recently modified files matching critical patterns
    3. Optionally checking for permission changes on critical files
    4. Optionally verifying digital signatures on executable files

    Args:
        basedir: Base directory to check files in
        reference_hashes: Dictionary mapping paths to expected hash values
        critical_patterns: List of glob patterns to match critical files
        detect_permissions: Whether to check for permission changes
        check_signatures: Whether to verify digital signatures on executables

    Returns:
        List of dictionaries containing information about modified files

    Example:
        changes = detect_file_changes('/app', config['CRITICAL_FILE_HASHES'])
        if changes:
            log_security_event('file_integrity_violation', f"Detected {len(changes)} modified files")
    """
    if not os.path.isdir(basedir):
        log_error(f"Base directory does not exist or is not a directory: {basedir}")
        return [{'error': 'Invalid base directory', 'path': basedir, 'timestamp': format_timestamp()}]

    critical_patterns = critical_patterns or CRITICAL_FILE_PATTERNS
    modified_files = []
    permission_cache = {}

    # Check files with known hashes
    _check_known_files(reference_hashes, modified_files, permission_cache, detect_permissions)

    # Check modification times of critical files
    _check_critical_files(basedir, critical_patterns, reference_hashes, modified_files)

    # Check digital signatures if requested
    if check_signatures:
        _check_file_signatures(basedir, modified_files)

    return modified_files


def _check_known_files(
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]],
        permission_cache: Dict[str, int],
        detect_permissions: bool) -> None:
    """
    Check known files against their reference hashes and permissions.

    Args:
        reference_hashes: Dictionary mapping paths to expected hash values
        modified_files: List to add detected changes to
        permission_cache: Dictionary to store file permissions
        detect_permissions: Whether to check for permission changes
    """
    for filepath, expected_hash in reference_hashes.items():
        if not os.path.exists(filepath):
            modified_files.append({
                'path': filepath,
                'status': 'missing',
                'severity': 'high',
                'timestamp': format_timestamp()
            })
            continue

        try:
            current_hash = calculate_file_hash(filepath)
            if current_hash != expected_hash:
                modified_files.append({
                    'path': filepath,
                    'status': 'modified',
                    'severity': 'high',
                    'old_hash': expected_hash,
                    'new_hash': current_hash,
                    'timestamp': format_timestamp()
                })

            # Check for permission changes if requested
            if detect_permissions:
                _check_file_permissions(filepath, permission_cache, modified_files)

        except (IOError, ValueError, OSError) as e:
            modified_files.append({
                'path': filepath,
                'status': 'access_error',
                'severity': 'medium',
                'error': str(e),
                'timestamp': format_timestamp()
            })


def _check_file_permissions(
        filepath: str,
        permission_cache: Dict[str, int],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check file permissions for security issues.

    Args:
        filepath: Path to check
        permission_cache: Dictionary to store file permissions
        modified_files: List to add detected issues to
    """
    try:
        current_mode = os.stat(filepath).st_mode
        # Store permission mode to track changes
        permission_cache[filepath] = current_mode

        # Check if file has unusual permissions
        is_executable = bool(current_mode & stat.S_IXUSR)
        is_world_writable = bool(current_mode & stat.S_IWOTH)
        is_world_readable = bool(current_mode & stat.S_IROTH)
        is_setuid = bool(current_mode & stat.S_ISUID)
        is_setgid = bool(current_mode & stat.S_ISGID)

        # Check for Python scripts with execute permissions
        if filepath.endswith('.py') and is_executable:
            modified_files.append({
                'path': filepath,
                'status': 'executable_script',
                'severity': 'medium',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for world-writable files (severe security risk)
        if is_world_writable:
            modified_files.append({
                'path': filepath,
                'status': 'world_writable',
                'severity': 'critical',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for setuid/setgid binaries
        if is_setuid or is_setgid:
            modified_files.append({
                'path': filepath,
                'status': 'setuid_setgid',
                'severity': 'high',
                'setuid': is_setuid,
                'setgid': is_setgid,
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

        # Check for sensitive files that are world-readable
        sensitive_extensions = ['.key', '.pem', '.p12', '.pfx', '.keystore', '.jks', '.env']
        if any(filepath.endswith(ext) for ext in sensitive_extensions) and is_world_readable:
            modified_files.append({
                'path': filepath,
                'status': 'world_readable_sensitive',
                'severity': 'high',
                'current_mode': oct(current_mode),
                'timestamp': format_timestamp()
            })

    except (IOError, OSError) as e:
        log_error(f"Error checking file permissions for {filepath}: {e}")
        # No need to add to modified_files as the calling function will handle this


def _check_critical_files(
        basedir: str,
        critical_patterns: List[str],
        reference_hashes: Dict[str, str],
        modified_files: List[Dict[str, Any]]) -> None:
    """
    Check critical files for modifications.

    Args:
        basedir: Base directory to check
        critical_patterns: List of glob patterns to match critical files
        reference_hashes: Dictionary of known file hashes
        modified_files: List to add detected changes to
    """
    for pattern in critical_patterns:
        try:
            # Safely join paths and handle path traversal attempts
            pattern_path = os.path.normpath(os.path.join(basedir, pattern))
            if not pattern_path.startswith(os.path.normpath(basedir)):
                log_warning(f"Skipping potentially dangerous path pattern: {pattern}")
                continue

            for filepath in glob.glob(pattern_path):
                if filepath not in reference_hashes and os.path.isfile(filepath):
                    _check_critical_file(filepath, modified_files)
        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking critical files with pattern {pattern}: {e}")


def _check_critical_file(filepath: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check a single critical file for security concerns.

    Args:
        filepath: Path to the file to check
        modified_files: List to add detected issues to
    """
    try:
        mtime = os.path.getmtime(filepath)
        mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)

        # Check if modified in last 24 hours
        if (now_utc() - mtime_dt).total_seconds() < 86400:
            # Calculate hash for new/changed file
            current_hash = calculate_file_hash(filepath)

            modified_files.append({
                'path': filepath,
                'status': 'recent_change',
                'severity': 'medium',
                'modified_time': mtime_dt.isoformat(),
                'current_hash': current_hash,
                'timestamp': format_timestamp()
            })

        # Check for hidden files that match our patterns
        basename = os.path.basename(filepath)
        if basename.startswith('.') and basename not in ALLOWED_HIDDEN_FILES:
            modified_files.append({
                'path': filepath,
                'status': 'hidden_file',
                'severity': 'medium',
                'modified_time': mtime_dt.isoformat(),
                'timestamp': format_timestamp()
            })

        # Check for unusual file ownership
        _check_file_ownership(filepath, modified_files)

    except (IOError, ValueError, OSError) as e:
        modified_files.append({
            'path': filepath,
            'status': 'access_error',
            'error': str(e),
            'timestamp': format_timestamp()
        })


def _check_file_ownership(filepath: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check file ownership for security concerns.

    Args:
        filepath: Path to the file to check
        modified_files: List to add detected issues to
    """
    try:
        stat_info = os.stat(filepath)
        try:
            # Try to get the owner name (Unix-specific)
            owner = pwd.getpwuid(stat_info.st_uid).pw_name

            # Get expected owner from environment or config
            expected_owner = None
            if has_app_context():
                expected_owner = current_app.config.get('EXPECTED_FILE_OWNER')
            if not expected_owner:
                expected_owner = os.environ.get('EXPECTED_FILE_OWNER')

            # Check for unexpected ownership on security-sensitive files
            security_sensitive = filepath.endswith(('.py', '.env', 'config.py', '.sh', '.key', '.pem'))
            if expected_owner and owner != expected_owner and security_sensitive:
                modified_files.append({
                    'path': filepath,
                    'status': 'unexpected_owner',
                    'severity': 'medium',
                    'owner': owner,
                    'expected_owner': expected_owner,
                    'timestamp': format_timestamp()
                })
        except (KeyError, ImportError):
            # pwd module not available or owner lookup failed
            pass

    except (IOError, OSError) as e:
        log_error(f"Error checking file ownership for {filepath}: {e}")


def _check_file_signatures(basedir: str, modified_files: List[Dict[str, Any]]) -> None:
    """
    Check digital signatures of executable files.

    Args:
        basedir: Base directory to check
        modified_files: List to add detected issues to
    """
    for pattern in EXECUTABLE_PATTERNS:
        try:
            for filepath in glob.glob(os.path.join(basedir, '**', pattern), recursive=True):
                if not verify_file_signature(filepath):
                    modified_files.append({
                        'path': filepath,
                        'status': 'invalid_signature',
                        'severity': 'critical',
                        'timestamp': format_timestamp()
                    })
        except (IOError, ValueError, OSError) as e:
            log_error(f"Error checking file signatures for pattern {pattern}: {e}")


def verify_file_signature(filepath: str) -> bool:
    """
    Verify the digital signature of a file if supported on the platform.

    This is a placeholder implementation that should be replaced with
    platform-specific signature verification code.

    Args:
        filepath: Path to the file to verify

    Returns:
        bool: True if signature is valid or verification not supported,
              False if signature is invalid
    """
    log_info(f"Verifying file signature for: {filepath}")

    # This is a stub implementation. In production code, you would implement
    # platform-specific signature verification:
    # - On Windows, using WinVerifyTrust
    # - On macOS, using Security framework
    # - On Linux, using GPG or other verification methods

    # Example implementation using a hypothetical platform-specific module:
    try:
        # Platform-specific signature checking would go here
        import platform
        if platform.system() == 'Windows':
            # Windows signature verification - would use ctypes to call WinVerifyTrust
            # return win_verify.check_signature(filepath)
            return True
        elif platform.system() == 'Darwin':  # macOS
            # macOS signature verification - would use Security framework
            # return mac_verify.verify_code_signature(filepath)
            return True
        else:  # Linux or other platforms
            # Could use GPG or other verification methods
            return True
    except (OSError, ValueError, ImportError):
        # If verification fails or is not supported, assume valid
        # to prevent false positives in environments without signature verification
        return True


def log_file_integrity_event(changes: List[Dict[str, Any]]) -> None:
    """
    Log file integrity violations to both the application log and audit log.

    Args:
        changes: List of detected file changes from detect_file_changes()
    """
    if not changes:
        return

    from models.audit_log import AuditLog
    from core.cs_audit import log_security_event

    # Group changes by severity
    critical = [c for c in changes if c.get('severity') == 'critical']
    high = [c for c in changes if c.get('severity') == 'high']
    medium = [c for c in changes if c.get('severity') == 'medium']
    low = [c for c in changes if c.get('severity', '').lower() not in ('critical', 'high', 'medium')]

    # Determine overall severity
    if critical:
        severity = AuditLog.SEVERITY_CRITICAL
        log_level = 'critical'
    elif high:
        severity = AuditLog.SEVERITY_ERROR
        log_level = 'error'
    elif medium:
        severity = AuditLog.SEVERITY_WARNING
        log_level = 'warning'
    else:
        severity = AuditLog.SEVERITY_INFO
        log_level = 'info'

    # Create summary
    summary = f"File integrity violations detected: {len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(low)} low"

    # Log to application log
    if log_level == 'critical':
        log_critical(summary)
    elif log_level == 'error':
        log_error(summary)
    elif log_level == 'warning':
        log_warning(summary)
    else:
        log_info(summary)

    # Log detailed information for each changed file
    for change in changes:
        path = change.get('path', 'unknown')
        status = change.get('status', 'unknown')
        change_severity = change.get('severity', 'unknown')

        # Create audit log entry
        try:
            log_security_event(
                event_type=AuditLog.EVENT_FILE_INTEGRITY,
                description=f"File integrity violation: {path} ({status})",
                severity=severity,
                details={
                    "file": path,
                    "status": status,
                    "severity": change_severity,
                    "timestamp": change.get('timestamp', format_timestamp())
                }
            )
        except Exception as e:
            log_error(f"Failed to create audit log for file integrity event: {e}")


def get_file_metadata(file_path: str) -> FileMetadata:
    """
    Get metadata about a file for security and integrity checks.

    This function collects detailed metadata about a file that can be used
    for security analysis, integrity monitoring, and compliance purposes.
    Particularly useful for ICS and critical infrastructure files.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing file metadata including:
        - size: File size in bytes
        - created_at: Creation timestamp
        - modified_at: Last modification timestamp
        - accessed_at: Last access timestamp
        - owner: File owner username
        - permissions: File permissions as octal string
        - hash: SHA-256 hash of the file content

    Raises:
        FileNotFoundError: If the specified file does not exist
        IOError: If the file cannot be read
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_info = os.stat(file_path)

    try:
        # Get owner name (Unix-specific)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
    except (KeyError, ImportError):
        # Fallback for Windows or if user lookup fails
        owner = str(stat_info.st_uid)

    try:
        # Generate hash for content verification
        file_hash = calculate_file_hash(file_path)
    except IOError as e:
        log_error(f"Failed to hash file {file_path}: {e}")
        file_hash = None

    try:
        # Get file type using file command if available
        file_type = None
        if os.path.exists('/usr/bin/file'):
            import subprocess
            result = subprocess.run(
                ['/usr/bin/file', '-b', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
                check=False
            )
            if result.returncode == 0:
                file_type = result.stdout.decode('utf-8', 'replace').strip()
    except (subprocess.SubprocessError, OSError):
        file_type = None

    metadata = {
        'path': os.path.abspath(file_path),
        'size': stat_info.st_size,
        'created_at': datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc),
        'modified_at': datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc),
        'accessed_at': datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc),
        'owner': owner,
        'permissions': oct(stat_info.st_mode & 0o777),
        'is_executable': bool(stat_info.st_mode & stat.S_IXUSR),
        'is_world_writable': bool(stat_info.st_mode & stat.S_IWOTH),
        'hash': file_hash,
        'file_type': file_type
    }

    return metadata


def setup_logging(log_file: Optional[str] = None, level: str = 'INFO') -> None:
    """
    Set up application logging to a specified file with a given log level.

    Args:
        log_file: Path to the log file (if None, logs to console only)
        level: Logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Create a formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear any existing handlers to avoid duplicate logging
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            root_logger.addHandler(file_handler)
        except (IOError, OSError) as e:
            logger.error(f"Failed to set up file logging: {e}")


def sanitize_path(path: str, base_dir: str) -> Optional[str]:
    """
    Sanitize and validate a file path to prevent path traversal attacks.

    Args:
        path: The file path to sanitize
        base_dir: The base directory that the path should be within

    Returns:
        Sanitized absolute path or None if path is invalid or outside base_dir
    """
    if not path or not isinstance(path, str):
        return None

    # Normalize the path to resolve '..' and '.'
    norm_path = os.path.normpath(os.path.join(base_dir, path))
    norm_base = os.path.normpath(base_dir)

    # Check if path is within the base directory
    if not norm_path.startswith(norm_base):
        return None

    # Check if path exists
    if not os.path.exists(norm_path):
        return None

    return norm_path


def is_within_directory(file_path: str, directory: str) -> bool:
    """
    Check if a file is within a specified directory.

    Args:
        file_path: Path to the file to check
        directory: Base directory to check against

    Returns:
        True if file is within the directory, False otherwise
    """
    # Normalize both paths
    norm_file = os.path.abspath(file_path)
    norm_dir = os.path.abspath(directory)

    # Check if the normalized file path starts with the normalized directory
    return norm_file.startswith(norm_dir)


def is_safe_file_operation(operation: str, file_path: str, safe_dirs: List[str]) -> bool:
    """
    Check if a file operation is considered safe.

    Args:
        operation: The operation to be performed ('read', 'write', 'delete')
        file_path: Path to the file to check
        safe_dirs: List of directories where operations are allowed

    Returns:
        True if operation is safe, False otherwise
    """
    # Validate inputs
    if not operation or not file_path:
        return False

    # Convert to lowercase for consistent checking
    operation = operation.lower()

    # Check if operation is supported
    if operation not in ('read', 'write', 'delete', 'append'):
        return False

    # Check if the file is in a safe directory
    for safe_dir in safe_dirs:
        if is_within_directory(file_path, safe_dir):
            return True

    return False


def log_critical(message: str) -> None:
    """Log a critical message using the appropriate logger."""
    if has_app_context():
        current_app.logger.critical(message)
    else:
        logger.critical(message)


def log_error(message: str) -> None:
    """Log an error message using the appropriate logger."""
    if has_app_context():
        current_app.logger.error(message)
    else:
        logger.error(message)


def log_warning(message: str) -> None:
    """Log a warning message using the appropriate logger."""
    if has_app_context():
        current_app.logger.warning(message)
    else:
        logger.warning(message)


def log_info(message: str) -> None:
    """Log an info message using the appropriate logger."""
    if has_app_context():
        current_app.logger.info(message)
    else:
        logger.info(message)


def log_debug(message: str) -> None:
    """Log a debug message using the appropriate logger."""
    if has_app_context():
        current_app.logger.debug(message)
    else:
        logger.debug(message)
