"""
Storage models package for the Cloud Infrastructure Platform.

This package contains models related to file storage and management including:
- FileUpload: For tracking and managing uploaded files including security scanning
  and validation

These models provide the foundation for secure file management within the platform,
enabling file uploads, downloads, validation, and security scanning.
"""

from .file_upload import FileUpload

# Define exports explicitly to control the public API
__all__ = [
    "FileUpload"
]
