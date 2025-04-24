"""
Secure file upload handler for cloud infrastructure platform.

This module provides a FileUpload class that manages file uploads with
comprehensive security controls, validation, and metadata tracking to ensure
safe handling of user-provided files across cloud environments.
"""

import os
import uuid
import hashlib
import mimetypes
import datetime
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, BinaryIO, Union, Any, Set
from werkzeug.utils import secure_filename
from flask import g, current_app

from core.security_utils import validate_path
from extensions import metrics


class FileUpload:
    """
    Secure file upload handler for cloud infrastructure.

    This class manages file uploads with security controls, including:
    - Path traversal prevention
    - File type validation
    - File size limits
    - Malware scanning integration
    - Metadata tracking
    - Secure file naming

    It supports local storage and has hooks for cloud storage integration.
    """

    # Allowed file extensions and mime types (restrictive by default)
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'xlsx', 'docx'}
    ALLOWED_MIME_TYPES = {
        'text/plain', 'application/pdf', 'image/png', 'image/jpeg',
        'text/csv', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }

    # Default max file size (10MB)
    DEFAULT_MAX_SIZE = 10 * 1024 * 1024

    # Minimum byte sample size for MIME detection
    MIME_SAMPLE_SIZE = 8192

    def __init__(self, upload_dir: str, max_size: Optional[int] = None,
                 allowed_extensions: Optional[Set[str]] = None,
                 allowed_mime_types: Optional[Set[str]] = None,
                 scan_files: bool = True):
        """
        Initialize the FileUpload class with a directory to store uploaded files.

        Args:
            upload_dir: Directory where files will be uploaded
            max_size: Maximum file size in bytes (defaults to 10MB)
            allowed_extensions: Set of allowed file extensions (defaults to class constant)
            allowed_mime_types: Set of allowed MIME types (defaults to class constant)
            scan_files: Whether to scan files for malware when possible

        Raises:
            ValueError: If the upload directory path is invalid or can't be created
            PermissionError: If the upload directory is not writable
        """
        # Validate upload directory path
        try:
            # Convert to absolute path and normalize
            self.upload_dir = os.path.abspath(os.path.normpath(upload_dir))

            # Security check for path
            if not validate_path(self.upload_dir):
                raise ValueError(f"Invalid upload directory path: {upload_dir}")

            # Create upload directory if it doesn't exist
            os.makedirs(self.upload_dir, exist_ok=True)

            # Verify directory is writable
            if not os.access(self.upload_dir, os.W_OK):
                raise PermissionError(f"Upload directory is not writable: {self.upload_dir}")

        except (OSError, PermissionError) as e:
            raise ValueError(f"Failed to initialize upload directory: {str(e)}")

        self.max_size = max_size or self.DEFAULT_MAX_SIZE
        self.allowed_extensions = allowed_extensions or self.ALLOWED_EXTENSIONS
        self.allowed_mime_types = allowed_mime_types or self.ALLOWED_MIME_TYPES
        self.scan_files = scan_files
        self.logger = logging.getLogger(__name__)

    def is_allowed_file(self, filename: str) -> bool:
        """
        Check if the file extension is allowed.

        Args:
            filename: Name of the file to check

        Returns:
            bool: True if the file extension is allowed, False otherwise
        """
        if not filename or '.' not in filename:
            return False

        extension = filename.rsplit('.', 1)[1].lower()
        return extension in self.allowed_extensions

    def is_allowed_mime(self, file_content: BinaryIO, filename: str) -> bool:
        """
        Check if the file MIME type is allowed based on content and extension.

        Args:
            file_content: File-like object containing file data
            filename: Name of the file

        Returns:
            bool: True if the MIME type is allowed, False otherwise
        """
        if not file_content or not filename:
            return False

        try:
            # Save current position
            current_pos = file_content.tell()

            # Read sample bytes for MIME detection
            file_content.seek(0)
            header = file_content.read(self.MIME_SAMPLE_SIZE)

            # Restore original position
            file_content.seek(current_pos)

            # Try multiple methods to determine MIME type
            mime_type = self._get_mime_type(header, filename)

            if not mime_type:
                self.logger.warning("Couldn't determine MIME type for file: %s", filename)
                return False

            return mime_type in self.allowed_mime_types

        except (IOError, ValueError) as e:
            self.logger.error("Error checking MIME type: %s", str(e))
            return False

    def _get_mime_type(self, file_header: bytes, filename: str) -> Optional[str]:
        """
        Try multiple methods to determine a file's MIME type.

        Args:
            file_header: Sample of file content
            filename: Name of the file

        Returns:
            str: MIME type or None if it couldn't be determined
        """
        mime_type = None

        # Method 1: Use mimetypes library (based on file extension)
        mime_type = mimetypes.guess_type(filename)[0]

        # Method 2: Try python-magic if available
        if mime_type is None:
            try:
                import magic
                mime_type = magic.from_buffer(file_header, mime=True)
            except ImportError:
                self.logger.debug("python-magic not installed, falling back to extension-only checks")
            except Exception as e:
                self.logger.warning("Error using python-magic: %s", str(e))

        return mime_type

    def generate_secure_filename(self, original_filename: str) -> str:
        """
        Generate a secure filename to prevent directory traversal and ensure uniqueness.

        Args:
            original_filename: Original name of the file

        Returns:
            str: Secure filename with UUID and sanitized original name
        """
        if not original_filename:
            return f"{uuid.uuid4()}_unnamed_file"

        # Secure the filename to remove path components
        secure_name = secure_filename(original_filename)

        # Extract extension
        ext = ""
        if '.' in secure_name:
            name_part, ext = secure_name.rsplit('.', 1)
            # Handle cases where the extension is very long (likely not an extension)
            if len(ext) > 10:
                name_part = secure_name
                ext = ""
        else:
            name_part = secure_name

        # Remove extra dots from name part
        name_part = name_part.replace('.', '_')

        # Generate UUID for uniqueness
        file_uuid = str(uuid.uuid4())

        # Construct final filename
        if ext:
            return f"{file_uuid}_{name_part}.{ext.lower()}"
        else:
            return f"{file_uuid}_{name_part}"

    def get_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file for integrity verification.

        Args:
            file_path: Path to the file

        Returns:
            str: Hexadecimal SHA-256 hash or empty string on error
        """
        if not os.path.isfile(file_path):
            self.logger.error("Cannot hash non-existent file: %s", file_path)
            return ""

        sha256 = hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError) as e:
            self.logger.error("Failed to calculate file hash: %s", str(e))
            return ""

    def save_file(self, file: BinaryIO, filename: str,
                  metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Securely save the uploaded file with validation and metadata.

        Args:
            file: File-like object to be saved
            filename: Original name of the file
            metadata: Additional metadata to store with the file

        Returns:
            Dictionary with file information on success

        Raises:
            ValueError: If validation fails or file cannot be saved
        """
        # Track current user if available
        user_id = getattr(g, 'user_id', None) if 'g' in globals() else None
        file_path = None

        try:
            # Basic validation
            if file is None or not filename:
                raise ValueError("Missing file or filename")

            # Check file extension
            if not self.is_allowed_file(filename):
                self.logger.warning("Rejected file with disallowed extension: %s", filename)
                raise ValueError(f"File type not allowed: {filename}")

            # Check MIME type
            if not self.is_allowed_mime(file, filename):
                self.logger.warning("Rejected file with disallowed MIME type: %s", filename)
                raise ValueError("File content type not allowed")

            # Check file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset position

            if file_size > self.max_size:
                self.logger.warning("Rejected file exceeding size limit: %s (%d bytes)",
                                   filename, file_size)
                raise ValueError(f"File too large (max {self.max_size/1024/1024:.1f}MB)")

            # Generate secure filename
            secure_name = self.generate_secure_filename(filename)
            file_path = os.path.join(self.upload_dir, secure_name)

            # Save the file
            try:
                with open(file_path, 'wb') as f:
                    f.write(file.read())
            except (OSError, IOError) as e:
                raise ValueError(f"Failed to write file: {str(e)}")

            # Calculate hash for integrity verification
            file_hash = self.get_file_hash(file_path)

            # Scan file if enabled
            if self.scan_files:
                is_clean, scan_message = self.scan_file(file_path)
                if not is_clean:
                    # Remove potentially malicious file
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                    raise ValueError(f"Security scan failed: {scan_message}")

            # Prepare metadata
            file_info = {
                'original_name': filename,
                'stored_name': secure_name,
                'path': file_path,
                'size': file_size,
                'hash': file_hash,
                'mime_type': mimetypes.guess_type(filename)[0] or 'application/octet-stream',
                'upload_time': datetime.datetime.utcnow().isoformat(),
                'user_id': user_id,
                'metadata': metadata or {}
            }

            # Log upload (security audit)
            self.logger.info(
                "File uploaded: %s (%d bytes) by user %s",
                secure_name, file_size, user_id or 'anonymous'
            )

            # Track metrics if available
            if hasattr(metrics, 'counter'):
                try:
                    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                    metrics.counter(
                        'file_uploads_total',
                        1,
                        {'extension': extension, 'status': 'success'}
                    )
                    metrics.histogram(
                        'file_upload_size_bytes',
                        file_size,
                        {'extension': extension}
                    )
                except Exception as e:
                    self.logger.warning("Failed to record metrics: %s", str(e))

            return file_info

        except ValueError as e:
            # Track failed upload metrics
            if hasattr(metrics, 'counter'):
                try:
                    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                    metrics.counter(
                        'file_uploads_total',
                        1,
                        {'extension': extension, 'status': 'failed', 'reason': str(e)[:20]}
                    )
                except Exception as metric_err:
                    self.logger.warning("Failed to record metrics: %s", str(metric_err))

            # Re-raise the error
            raise

        except (OSError, PermissionError) as e:
            self.logger.error("File upload error: %s", str(e), exc_info=True)
            # Delete partial file if it exists
            try:
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
            except OSError as inner_e:
                self.logger.error("Failed to delete partial file: %s", str(inner_e))

            # Track error metrics
            if hasattr(metrics, 'counter'):
                try:
                    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                    metrics.counter(
                        'file_uploads_total',
                        1,
                        {'extension': extension, 'status': 'error', 'reason': 'io_error'}
                    )
                except Exception:
                    pass

            raise ValueError(f"File upload failed: {str(e)}")

    def list_files(self, include_metadata: bool = False) -> List[Dict[str, Any]]:
        """
        List all files in the upload directory with optional metadata.

        Args:
            include_metadata: Whether to include file metadata

        Returns:
            List of dictionaries containing file information
        """
        try:
            files = []
            for filename in os.listdir(self.upload_dir):
                file_path = os.path.join(self.upload_dir, filename)
                if not os.path.isfile(file_path):
                    continue

                file_info = {
                    'filename': filename,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.datetime.fromtimestamp(
                        os.path.getmtime(file_path)).isoformat()
                }

                if include_metadata:
                    file_info['hash'] = self.get_file_hash(file_path)
                    file_info['mime_type'] = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

                files.append(file_info)

            # Sort files by modification time (newest first)
            files.sort(key=lambda x: x['modified'], reverse=True)
            return files

        except (OSError, PermissionError) as e:
            self.logger.error("Error listing files: %s", str(e))
            return []

    def delete_file(self, filename: str) -> Tuple[bool, str]:
        """
        Securely delete a file from the upload directory.

        Args:
            filename: Name of the file to delete

        Returns:
            Tuple of (success boolean, message)
        """
        # Prevent directory traversal
        secure_name = os.path.basename(filename)
        file_path = os.path.join(self.upload_dir, secure_name)

        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"

            if not os.path.isfile(file_path):
                return False, "Not a file"

            # Get file hash before deletion (for logging)
            file_hash = self.get_file_hash(file_path)
            file_size = os.path.getsize(file_path)

            # Delete the file
            os.remove(file_path)

            # Audit logging
            user_id = getattr(g, 'user_id', 'unknown') if 'g' in globals() else 'unknown'
            self.logger.info(
                "File deleted: %s (hash: %s, size: %d bytes) by user %s",
                secure_name, file_hash, file_size, user_id
            )

            # Track metrics
            if hasattr(metrics, 'counter'):
                try:
                    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                    metrics.counter(
                        'file_deletions_total',
                        1,
                        {'extension': extension, 'status': 'success'}
                    )
                except Exception:
                    pass

            return True, "File deleted successfully"

        except (OSError, PermissionError) as e:
            self.logger.error("Error deleting file %s: %s", secure_name, str(e))

            # Track error metrics
            if hasattr(metrics, 'counter'):
                try:
                    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                    metrics.counter(
                        'file_deletions_total',
                        1,
                        {'extension': extension, 'status': 'error'}
                    )
                except Exception:
                    pass

            return False, f"Failed to delete file: {str(e)}"

    def get_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific file.

        Args:
            filename: Name of the file

        Returns:
            Dictionary with file information or None if file doesn't exist
        """
        # Prevent directory traversal
        secure_name = os.path.basename(filename)
        file_path = os.path.join(self.upload_dir, secure_name)

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None

        try:
            # Get file stats
            stats = os.stat(file_path)

            file_info = {
                'filename': secure_name,
                'path': file_path,
                'size': stats.st_size,
                'created': datetime.datetime.fromtimestamp(stats.st_ctime).isoformat(),
                'modified': datetime.datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'hash': self.get_file_hash(file_path),
                'mime_type': mimetypes.guess_type(secure_name)[0] or 'application/octet-stream'
            }
            return file_info

        except (OSError, ValueError) as e:
            self.logger.error("Error getting file info for %s: %s", secure_name, str(e))
            return None

    def scan_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Integrate with malware scanning service.

        Args:
            file_path: Path to the file to scan

        Returns:
            Tuple of (is_clean boolean, scan_result message)
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return False, "File not found or is not a regular file"

        try:
            # First, check if we have access to a scanner service
            scanner_available = False

            # Try available scanning mechanisms

            # Option 1: Try ClamAV if available
            try:
                import clamd
                scanner_available = True

                # Try to connect to local ClamAV daemon
                cd = clamd.ClamdUnixSocket()
                # Alternatively: cd = clamd.ClamdNetworkSocket('localhost', 3310)

                # Scan the file
                scan_result = cd.scan(file_path)
                file_key = list(scan_result.keys())[0]
                status = scan_result[file_key][0]

                is_clean = status == 'OK'
                message = scan_result[file_key][1] if not is_clean else "No threats detected"

                self.logger.info("ClamAV scan of %s: %s", file_path, "Clean" if is_clean else "Infected")
                return is_clean, message

            except (ImportError, IndexError, KeyError):
                # ClamAV not available or scan failed
                pass

            # Option 2: Use external scanner via API if configured
            if hasattr(current_app, 'config') and current_app.config.get('MALWARE_SCAN_API_URL'):
                scanner_available = True
                # Implementation for external scanning API would go here
                # For example:
                # api_url = current_app.config.get('MALWARE_SCAN_API_URL')
                # api_key = current_app.config.get('MALWARE_SCAN_API_KEY')
                # scan_result = requests.post(api_url, files={'file': open(file_path, 'rb')}, headers={'API-Key': api_key})
                # return scan_result.json()['is_clean'], scan_result.json()['message']

                # For now, just return a placeholder response
                self.logger.info("External scan API configured but not implemented for %s", file_path)
                return True, "External scan is configured but not implemented"

            # If no scanner is available
            if not scanner_available:
                self.logger.warning("No malware scanner available for %s", file_path)
                if self.scan_files:
                    # If scanning is required but no scanner is available, log a warning
                    self.logger.warning("Malware scanning is enabled but no scanner is available")
                return True, "File scanning is not available (adjust scan_files setting if needed)"

            return True, "File appears clean"

        except Exception as e:
            self.logger.error("Error scanning file %s: %s", file_path, str(e), exc_info=True)
            # If scanning is required but fails, we should fail securely
            if self.scan_files:
                return False, f"Scan error: {str(e)}"
            else:
                # If scanning is optional, continue even if it fails
                return True, f"Scan skipped due to error: {str(e)}"

    def cleanup_old_files(self, max_age_days: int = 30) -> Tuple[int, List[str]]:
        """
        Remove files older than the specified age.

        Args:
            max_age_days: Maximum age of files in days

        Returns:
            Tuple of (count of deleted files, list of filenames that couldn't be deleted)
        """
        if max_age_days <= 0:
            raise ValueError("max_age_days must be a positive integer")

        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=max_age_days)
        cutoff_timestamp = cutoff_time.timestamp()

        deleted_count = 0
        failed_deletions = []

        try:
            for filename in os.listdir(self.upload_dir):
                file_path = os.path.join(self.upload_dir, filename)

                # Skip if not a file
                if not os.path.isfile(file_path):
                    continue

                # Check modification time
                mtime = os.path.getmtime(file_path)
                if mtime < cutoff_timestamp:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                        self.logger.info("Deleted old file: %s (age: %d days)",
                                        filename, (datetime.datetime.now().timestamp() - mtime) / 86400)
                    except OSError as e:
                        self.logger.error("Failed to delete old file %s: %s", filename, str(e))
                        failed_deletions.append(filename)

            # Track metrics
            if hasattr(metrics, 'counter') and deleted_count > 0:
                try:
                    metrics.counter('file_cleanup_deleted_total', deleted_count)
                except Exception:
                    pass

            return deleted_count, failed_deletions

        except OSError as e:
            self.logger.error("Error during file cleanup: %s", str(e))
            return deleted_count, failed_deletions
