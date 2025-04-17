import os
import uuid
import hashlib
import mimetypes
import datetime
import logging
from typing import Dict, List, Optional, Tuple, BinaryIO, Union, Any
from werkzeug.utils import secure_filename
from flask import g

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

    def __init__(self, upload_dir: str, max_size: Optional[int] = None, 
                 allowed_extensions: Optional[set] = None, allowed_mime_types: Optional[set] = None):
        """
        Initialize the FileUpload class with a directory to store uploaded files.
        
        Args:
            upload_dir: Directory where files will be uploaded
            max_size: Maximum file size in bytes (defaults to 10MB)
            allowed_extensions: Set of allowed file extensions (defaults to class constant)
            allowed_mime_types: Set of allowed MIME types (defaults to class constant)
        """
        self.upload_dir = os.path.abspath(upload_dir)
        self.max_size = max_size or self.DEFAULT_MAX_SIZE
        self.allowed_extensions = allowed_extensions or self.ALLOWED_EXTENSIONS
        self.allowed_mime_types = allowed_mime_types or self.ALLOWED_MIME_TYPES
        self.logger = logging.getLogger(__name__)

        # Create upload directory if it doesn't exist
        os.makedirs(self.upload_dir, exist_ok=True)

    def is_allowed_file(self, filename: str) -> bool:
        """
        Check if the file extension is allowed.
        
        Args:
            filename: Name of the file to check
        
        Returns:
            bool: True if the file extension is allowed, False otherwise
        """
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in self.allowed_extensions

    def is_allowed_mime(self, file_content: BinaryIO, filename: str) -> bool:
        """
        Check if the file MIME type is allowed based on content and extension.
        
        Args:
            file_content: File-like object containing file data
            filename: Name of the file
            
        Returns:
            bool: True if the MIME type is allowed, False otherwise
        """
        # Save current position
        current_pos = file_content.tell()

        # Read the first 2048 bytes for MIME detection
        file_content.seek(0)
        header = file_content.read(2048)
        file_content.seek(current_pos)  # Return to original position

        # Get MIME type from file header and extension
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type is None:
            # If standard library fails, attempt content-based detection
            try:
                import magic
                mime_type = magic.from_buffer(header, mime=True)
            except ImportError:
                # Fall back to extension-only check if python-magic isn't available
                pass

        return mime_type in self.allowed_mime_types if mime_type else False

    def generate_secure_filename(self, original_filename: str) -> str:
        """
        Generate a secure filename to prevent directory traversal and ensure uniqueness.
        
        Args:
            original_filename: Original name of the file
            
        Returns:
            str: Secure filename with UUID and sanitized original name
        """
        # Secure the filename to remove path components
        secure_name = secure_filename(original_filename)

        # Extract extension
        if '.' in secure_name:
            ext = secure_name.rsplit('.', 1)[1].lower()
        else:
            ext = ""

        # Generate UUID for uniqueness
        file_uuid = str(uuid.uuid4())

        # Construct final filename
        if ext:
            return f"{file_uuid}_{secure_name}"
        else:
            return f"{file_uuid}_{secure_name}"

    def get_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file for integrity verification.
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: Hexadecimal SHA-256 hash
        """
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
                  metadata: Optional[Dict] = None) -> Union[Dict[str, Any], Tuple[None, str]]:
        """
        Securely save the uploaded file with validation and metadata.
        
        Args:
            file: File-like object to be saved
            filename: Original name of the file
            metadata: Additional metadata to store with the file
            
        Returns:
            Dictionary with file information or (None, error_message) on failure
        """
        # Track current user if available
        user_id = getattr(g, 'user_id', None) if 'g' in globals() else None

        file_path = None  # Initialize file_path to avoid unbound variable error
        try:
            # Basic validation
            if file is None or filename is None:
                return None, "Missing file or filename"

            # Check file extension
            if not self.is_allowed_file(filename):
                self.logger.warning("Rejected file with disallowed extension: %s", filename)
                return None, "File type not allowed"

            # Check MIME type
            if not self.is_allowed_mime(file, filename):
                self.logger.warning("Rejected file with disallowed MIME type: %s", filename)
                return None, "File content type not allowed"

            # Check file size (peek at content length if available)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset position

            if file_size > self.max_size:
                self.logger.warning("Rejected file exceeding size limit: %s (%d bytes)", filename, file_size)
                return None, f"File too large (max {self.max_size/1024/1024:.1f}MB)"

            # Generate secure filename
            secure_name = self.generate_secure_filename(filename)
            file_path = os.path.join(self.upload_dir, secure_name)

            # Save the file
            with open(file_path, 'wb') as f:
                f.write(file.read())

            # Calculate hash for integrity verification
            file_hash = self.get_file_hash(file_path)

            # Prepare metadata
            file_info = {
                'original_name': filename,
                'stored_name': secure_name,
                'path': file_path,
                'size': file_size,
                'hash': file_hash,
                'mime_type': mimetypes.guess_type(filename)[0],
                'upload_time': datetime.datetime.utcnow().isoformat(),
                'user_id': user_id,
                'metadata': metadata or {}
            }

            # Log upload (security audit)
            self.logger.info(
                "File uploaded: %s (%d bytes) by user %s", secure_name, file_size, user_id
            )

            return file_info

        except (OSError, PermissionError) as e:
            self.logger.error("File upload error: %s", str(e), exc_info=True)
            # Delete partial file if it exists
            try:
                if 'file_path' in locals() and file_path is not None and os.path.exists(file_path):
                    if file_path:
                        os.remove(file_path)
            except OSError as inner_e:
                self.logger.error("Failed to delete partial file: %s", str(inner_e))
            return None, f"File upload failed: {str(e)}"

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
                if os.path.isfile(file_path):
                    file_info = {
                        'filename': filename,
                        'size': os.path.getsize(file_path),
                        'modified': datetime.datetime.fromtimestamp(
                            os.path.getmtime(file_path)).isoformat()
                    }

                    if include_metadata:
                        file_info['hash'] = self.get_file_hash(file_path)
                        file_info['mime_type'] = mimetypes.guess_type(filename)[0]

                    files.append(file_info)
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
            if os.path.exists(file_path):
                os.remove(file_path)
                self.logger.info("File deleted: %s by user %s", secure_name, getattr(g, 'user_id', 'unknown'))
                return True, "File deleted successfully"
            return False, "File does not exist"
        except (OSError, RuntimeError) as e:
            self.logger.error("Error deleting file %s: %s", secure_name, str(e))
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

        if not os.path.exists(file_path):
            return None

        try:
            file_info = {
                'filename': secure_name,
                'path': file_path,
                'size': os.path.getsize(file_path),
                'created': datetime.datetime.fromtimestamp(
                    os.path.getctime(file_path)).isoformat(),
                'modified': datetime.datetime.fromtimestamp(
                    os.path.getmtime(file_path)).isoformat(),
                'hash': self.get_file_hash(file_path),
                'mime_type': mimetypes.guess_type(secure_name)[0]
            }
            return file_info
        except (OSError, ValueError) as e:
            self.logger.error("Error getting file info for %s: %s", secure_name, str(e))
            return None

    def scan_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Integrate with malware scanning service (placeholder for integration).
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Tuple of (is_clean boolean, scan_result message)
        """
        # In a real implementation, this would connect to your malware scanning service
        # For now, we'll just validate the file exists
        if not os.path.exists(file_path):
            return False, "File not found"

        # Placeholder for actual virus scan integration
        try:
            # Example integration point - in production, replace with actual scan service
            # scan_result = virus_scanner.scan_file(file_path)
            # return scan_result.is_clean, scan_result.message

            # For now, we'll assume the file is clean
            return True, "File appears clean (Note: actual scan not implemented)"
        except (OSError, RuntimeError) as e:
            self.logger.error("Error scanning file %s: %s", file_path, str(e))
            return False, f"Scan error: {str(e)}"
