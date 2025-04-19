"""
Core utility functions for the myproject application.

This module provides utility functions used throughout the application for
common tasks such as:
- File integrity verification through SRI hash generation
- Security operations like hash comparison and file integrity checking
- Date and time handling with proper timezone support
- Data formatting and conversion utilities
- Metrics collection helpers

These utilities are designed to be stateless, reusable components that
encapsulate common operations to reduce code duplication and ensure
consistent behavior throughout the application.
"""

import logging
import hashlib
import base64
import os
import uuid
import glob
import stat
import time
import pwd
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from flask import current_app
import psutil
from models.audit_log import AuditLog
from core.security_utils import log_security_event


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
        current_app.logger.error(f"SRI hash generation failed: File not found: {file_path}")
        raise
    except IOError as e:
        current_app.logger.error(f"SRI hash generation failed: I/O error: {str(e)}")
        raise


def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
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
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

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

    with open(file_path, 'rb') as f:
        # Read and update hash in chunks for memory efficiency
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()

def get_critical_file_hashes(files: List[str], 
                             algorithm: str = 'sha256') -> Dict[str, str]:
    """
    Generate hash dictionary for critical application files.
    
    Used to create reference hashes for integrity checking.
    
    Args:
        files: List of file paths to hash
        algorithm: Hash algorithm to use (default: sha256)
        
    Returns:
        Dictionary mapping file paths to their hash values
    """
    hashes = {}
    for file_path in files:
        # Normalize the path for consistency
        normalized_path = os.path.normpath(file_path)

        if os.path.exists(normalized_path):
            try:
                file_hash = calculate_file_hash(normalized_path, algorithm)
                hashes[normalized_path] = file_hash

                # Check if this is a security-critical file
                if current_app and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
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
                current_app.logger.error(f"Failed to hash {normalized_path}: {e}")
                hashes[normalized_path] = None

                # Log file access errors for security-critical files
                if current_app and current_app.config.get('SECURITY_CHECK_FILE_INTEGRITY'):
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

def get_system_resources() -> Dict[str, Any]:
    """
    Get current system resource usage.
    
    Returns:
        Dictionary containing CPU, memory, and disk usage information
    """
    try:
        return {
            'cpu': {
                'percent': psutil.cpu_percent(interval=0.5),
                'count': psutil.cpu_count()
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
            'timestamp': format_timestamp()
        }
    except (psutil.Error, OSError) as e:
        current_app.logger.error(f"Error collecting system resources: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def get_process_info() -> Dict[str, Any]:
    """
    Get information about the current process.
    
    Returns:
        Dictionary containing process memory usage, threads, and connections
    """
    try:
        process = psutil.Process()
        return {
            'memory_mb': process.memory_info().rss / (1024 * 1024),
            'threads': process.num_threads(),
            'connections': len(process.connections()),
            'open_files': len(process.open_files()),
            'start_time': datetime.fromtimestamp(
                process.create_time(), tz=timezone.utc
            ).isoformat(),
            'timestamp': format_timestamp()
        }
    except (psutil.Error, OSError) as e:
        current_app.logger.error(f"Error collecting process info: {e}")
        return {'error': str(e), 'timestamp': format_timestamp()}


def detect_file_changes(basedir: str, 
                        reference_hashes: Dict[str, str], 
                        critical_patterns: Optional[List[str]] = None,
                        detect_permissions: bool = True,
                        check_signatures: bool = False) -> List[Dict[str, str]]:
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


    if critical_patterns is None:
        critical_patterns = ['*.py', 'config.*', '.env*', '*.ini', 'requirements.txt']

    modified_files = []
    permission_cache = {}

    # Check files with known hashes
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
                current_mode = os.stat(filepath).st_mode
                # Store permission mode to track changes
                permission_cache[filepath] = current_mode

                # Check if file has unusual permissions
                is_executable = bool(current_mode & stat.S_IXUSR)
                is_world_writable = bool(current_mode & stat.S_IWOTH)

                if filepath.endswith('.py') and is_executable:
                    modified_files.append({
                        'path': filepath,
                        'status': 'executable_script',
                        'severity': 'medium',
                        'current_mode': oct(current_mode),
                        'timestamp': format_timestamp()
                    })

                if is_world_writable:
                    modified_files.append({
                        'path': filepath,
                        'status': 'world_writable',
                        'severity': 'critical',
                        'current_mode': oct(current_mode),
                        'timestamp': format_timestamp()
                    })

        except (IOError, ValueError, OSError) as e:
            modified_files.append({
                'path': filepath,
                'status': 'access_error',
                'severity': 'medium',
                'error': str(e),
                'timestamp': format_timestamp()
            })

    # Check modification times of critical files
    for pattern in critical_patterns:
        for filepath in glob.glob(os.path.join(basedir, pattern)):
            if filepath not in reference_hashes and os.path.isfile(filepath):
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
                    if basename.startswith('.') and not basename in ['.env', '.gitignore']:
                        modified_files.append({
                            'path': filepath,
                            'status': 'hidden_file',
                            'severity': 'medium',
                            'modified_time': mtime_dt.isoformat(),
                            'timestamp': format_timestamp()
                        })

                    # Check for unusual file ownership
                    try:
                        stat_info = os.stat(filepath)
                        owner = pwd.getpwuid(stat_info.st_uid).pw_name

                        # Detection logic depends on deployment environment
                        # This example assumes files should be owned by 'www-data'
                        expected_owner = os.environ.get('EXPECTED_FILE_OWNER', 'www-data')
                        if owner != expected_owner and filepath.endswith(('.py', '.env', 'config.py')):
                            modified_files.append({
                                'path': filepath,
                                'status': 'unexpected_owner',
                                'severity': 'medium',
                                'owner': owner,
                                'expected_owner': expected_owner,
                                'timestamp': format_timestamp()
                            })
                    except (ImportError, KeyError):
                        # pwd module not available or owner lookup failed
                        pass

                except (IOError, ValueError, OSError) as e:
                    modified_files.append({
                        'path': filepath,
                        'status': 'access_error',
                        'error': str(e),
                        'timestamp': format_timestamp()
                    })

    # Check digital signatures if requested
    if check_signatures:
        executable_patterns = ['*.so', '*.dll', '*.exe', '*.bin']
        for pattern in executable_patterns:
            for filepath in glob.glob(os.path.join(basedir, '**', pattern), recursive=True):
                if not verify_file_signature(filepath):
                    modified_files.append({
                        'path': filepath,
                        'status': 'invalid_signature',
                        'severity': 'critical',
                        'timestamp': format_timestamp()
                    })

    return modified_files


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
    # Use the filepath argument to log the file being checked
    current_app.logger.info(f"Verifying file signature for: {filepath}")

    # This is a stub implementation. In production code, you would implement
    # platform-specific signature verification:
    # - On Windows, using WinVerifyTrust
    # - On macOS, using Security framework
    # - On Linux, using GPG or other verification methods

    # Example implementation using a hypothetical platform-specific module:
    try:
        # Platform-specific signature checking would go here
        # if platform.system() == 'Windows':
        #    import win_verify
        #    return win_verify.check_signature(filepath)
        # elif platform.system() == 'Darwin':  # macOS
        #    import mac_verify
        #    return mac_verify.verify_code_signature(filepath)

        # For now, just return True to avoid false positives
        return True
    except (OSError, ValueError):
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

    # Group changes by severity
    critical = [c for c in changes if c.get('severity') == 'critical']
    high = [c for c in changes if c.get('severity') == 'high']
    medium = [c for c in changes if c.get('severity') == 'medium']

    # Determine overall severity
    if critical:
        severity = AuditLog.SEVERITY_CRITICAL
    elif high:
        severity = AuditLog.SEVERITY_ERROR
    elif medium:
        severity = AuditLog.SEVERITY_WARNING
    else:
        severity = AuditLog.SEVERITY_INFO

    # Create summary
    summary = f"File integrity violations detected: {len(critical)} critical, {len(high)} high, {len(medium)} medium"

    # Log to application log
    if critical or high:
        current_app.logger.error(summary)
    else:
        current_app.logger.warning(summary)

    # Log detailed information for each changed file
    for change in changes:
        path = change.get('path', 'unknown')
        status = change.get('status', 'unknown')

        # Create audit log entry
        try:
            log_security_event(
                event_type=AuditLog.EVENT_FILE_INTEGRITY,
                description=f"File integrity violation: {path} ({status})",
                 severity=severity
            )
        except (psutil.Error, OSError, ValueError) as e:
            current_app.logger.error(f"Failed to create audit log for file integrity event: {e}")


def get_file_metadata(file_path: str) -> Dict[str, Any]:
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

    metadata = {
        'path': os.path.abspath(file_path),
        'size': stat_info.st_size,
        'created_at': datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc),
        'modified_at': datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc),
        'accessed_at': datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc),
        'owner': owner,
        'permissions': oct(stat_info.st_mode & 0o777),
        'hash': calculate_file_hash(file_path)
    }

    return metadata

def setup_logging(log_file: str, level: str = 'INFO') -> None:
    """
    Set up application logging to a specified file with a given log level.

    Args:
        log_file: Path to the log file
        level: Logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    """

    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        filename=log_file,
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.getLogger().addHandler(logging.StreamHandler())
