"""
Storage models package for the Cloud Infrastructure Platform.

This package contains models related to file storage and management including:
- FileUpload: For tracking and managing uploaded files including security scanning
  and validation
- FileMetadata: For storing and managing detailed metadata about uploaded files,
  supporting security analysis, integrity verification, and content management

These models provide the foundation for secure file management within the platform,
enabling file uploads, downloads, validation, security scanning, and comprehensive
metadata tracking.
"""

from .file_upload import FileUpload
from .file_metadata import FileMetadata

# Define exports explicitly to control the public API
__all__ = [
    "FileUpload",
    "FileMetadata"
]

# Package version
__version__ = '0.1.1'
