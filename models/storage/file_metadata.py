"""
File metadata model for storing and managing metadata about uploaded files.

This module defines the FileMetadata model which captures detailed information
about files uploaded to the system, supporting security analysis, integrity
verification, and content management use cases.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set, Union
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import validates
from flask import current_app, g, has_request_context

from models.base import BaseModel, AuditableMixin
from extensions import db, metrics
from core.security.cs_audit import log_security_event


class FileMetadata(BaseModel, AuditableMixin):
    """
    Model for storing detailed metadata about uploaded files.

    Captures comprehensive file information to support security analysis,
    integrity verification, and content management.

    Attributes:
        id: Primary key
        file_id: Reference to the file in storage system
        filename: Original filename
        mime_type: Detected MIME type
        file_size: Size in bytes
        file_hash: Cryptographic hash of file contents
        created_at: When the metadata record was created
        updated_at: When the metadata record was last updated
        user_id: ID of the user who uploaded the file
        path: Storage path of the file
        extension: File extension (without dot)
        media_type: General classification of the file type
        is_encrypted: Whether the file content is encrypted
        metadata: Additional file-specific metadata as JSON
    """

    __tablename__ = 'file_metadata'

    # Security critical fields that trigger enhanced auditing
    SECURITY_CRITICAL_FIELDS = ['is_sensitive', 'security_scan_result', 'metadata']
    AUDIT_ACCESS = True

    # Media type constants
    TYPE_IMAGE = 'image'
    TYPE_DOCUMENT = 'document'
    TYPE_VIDEO = 'video'
    TYPE_AUDIO = 'audio'
    TYPE_ARCHIVE = 'archive'
    TYPE_EXECUTABLE = 'executable'
    TYPE_OTHER = 'other'

    VALID_MEDIA_TYPES = [
        TYPE_IMAGE, TYPE_DOCUMENT, TYPE_VIDEO,
        TYPE_AUDIO, TYPE_ARCHIVE, TYPE_EXECUTABLE, TYPE_OTHER
    ]

    # Security scan result constants
    SCAN_RESULT_CLEAN = 'clean'
    SCAN_RESULT_SUSPICIOUS = 'suspicious'
    SCAN_RESULT_INFECTED = 'infected'
    SCAN_RESULT_ERROR = 'error'
    SCAN_RESULT_PENDING = 'pending'

    VALID_SCAN_RESULTS = [
        SCAN_RESULT_CLEAN, SCAN_RESULT_SUSPICIOUS,
        SCAN_RESULT_INFECTED, SCAN_RESULT_ERROR, SCAN_RESULT_PENDING
    ]

    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False, index=True)
    file_size = db.Column(db.BigInteger, nullable=False)
    file_hash = db.Column(db.String(128), nullable=True, index=True)

    # File attributes
    path = db.Column(db.String(512), nullable=False)
    extension = db.Column(db.String(20), nullable=True, index=True)
    media_type = db.Column(db.String(20), nullable=False, index=True)

    # Ownership and permissions
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Security attributes
    is_encrypted = db.Column(db.Boolean, default=False)
    is_sensitive = db.Column(db.Boolean, default=False)
    security_scan_result = db.Column(db.String(20), default=SCAN_RESULT_PENDING)
    security_scanned_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Detailed metadata (format-specific details, EXIF data, etc.)
    metadata = db.Column(JSONB, nullable=True)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('file_metadata', lazy='dynamic'))

    def __init__(self, file_id: str, filename: str, mime_type: str, file_size: int, path: str,
                 user_id: Optional[int] = None, file_hash: Optional[str] = None, extension: Optional[str] = None,
                 media_type: Optional[str] = None, is_public: bool = False, is_encrypted: bool = False,
                 is_sensitive: bool = False, metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a new file metadata record.

        Args:
            file_id: Unique identifier for the file
            filename: Original filename
            mime_type: MIME type of the file
            file_size: Size of the file in bytes
            path: Storage path where the file is located
            user_id: ID of the user who uploaded the file
            file_hash: Hash of the file content for integrity verification
            extension: File extension (without dot)
            media_type: General classification of file type
            is_public: Whether the file is publicly accessible
            is_encrypted: Whether the file content is encrypted
            is_sensitive: Whether the file contains sensitive data
            metadata: Additional file-specific metadata
        """
        super().__init__()
        self.file_id = file_id
        self.filename = filename
        self.mime_type = mime_type
        self.file_size = file_size
        self.path = path
        self.user_id = user_id
        self.file_hash = file_hash
        self.is_public = is_public
        self.is_encrypted = is_encrypted
        self.is_sensitive = is_sensitive
        self.metadata = metadata or {}

        # Extract extension from filename if not provided
        if extension is None and '.' in filename:
            extension = filename.rsplit('.', 1)[1].lower()
        self.extension = extension

        # Determine media type from MIME type if not provided
        if media_type is None:
            if mime_type.startswith('image/'):
                media_type = self.TYPE_IMAGE
            elif mime_type.startswith('video/'):
                media_type = self.TYPE_VIDEO
            elif mime_type.startswith('audio/'):
                media_type = self.TYPE_AUDIO
            elif mime_type in ['application/pdf', 'application/msword',
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                media_type = self.TYPE_DOCUMENT
            elif mime_type in ['application/zip', 'application/x-rar-compressed',
                              'application/x-tar', 'application/x-gzip']:
                media_type = self.TYPE_ARCHIVE
            elif mime_type in ['application/x-msdownload', 'application/x-executable',
                              'application/x-dosexec']:
                media_type = self.TYPE_EXECUTABLE
            else:
                media_type = self.TYPE_OTHER

        # Ensure valid media type
        if media_type not in self.VALID_MEDIA_TYPES:
            media_type = self.TYPE_OTHER

        self.media_type = media_type

    @validates('security_scan_result')
    def validate_scan_result(self, key: str, value: str) -> str:
        """Validate security scan result is one of the allowed values."""
        if value not in self.VALID_SCAN_RESULTS:
            raise ValueError(f"Invalid scan result: {value}")
        return value

    @validates('media_type')
    def validate_media_type(self, key: str, media_type: str) -> str:
        """Validate media type is one of the allowed values."""
        if media_type not in self.VALID_MEDIA_TYPES:
            raise ValueError(f"Invalid media type: {media_type}")
        return media_type

    def update_security_scan(self, result: str, scan_details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the security scan results for this file.

        Args:
            result: The scan result (clean, suspicious, infected, error)
            scan_details: Additional details about the scan result

        Returns:
            bool: Whether the update was successful
        """
        try:
            if result not in self.VALID_SCAN_RESULTS:
                raise ValueError(f"Invalid scan result: {result}")

            self.security_scan_result = result
            self.security_scanned_at = datetime.now(timezone.utc)

            # Add scan details to metadata
            if scan_details:
                if 'security_scans' not in self.metadata:
                    self.metadata['security_scans'] = []

                scan_record = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'result': result,
                    'details': scan_details
                }
                self.metadata['security_scans'].append(scan_record)

            db.session.commit()

            # Log security event for suspicious/infected files
            if result in [self.SCAN_RESULT_SUSPICIOUS, self.SCAN_RESULT_INFECTED]:
                log_security_event(
                    event_type='malware_detected',
                    description=f"Security scan detected {result} file: {self.filename}",
                    severity='warning' if result == self.SCAN_RESULT_SUSPICIOUS else 'critical',
                    user_id=self.user_id,
                    details={
                        'file_id': self.file_id,
                        'filename': self.filename,
                        'scan_result': result,
                        'scan_details': scan_details
                    }
                )

            # Track metrics
            if hasattr(metrics, 'counter'):
                try:
                    metrics.counter(
                        'file_scans_total',
                        1,
                        {'result': result, 'media_type': self.media_type}
                    )
                except Exception as e:
                    if current_app:
                        current_app.logger.warning(f"Failed to record metrics: {str(e)}")

            return True

        except (SQLAlchemyError, ValueError) as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error updating security scan: {str(e)}")
            return False

    def update_metadata(self, new_metadata: Dict[str, Any]) -> bool:
        """
        Update file metadata with new information.

        Args:
            new_metadata: New metadata to merge with existing metadata

        Returns:
            bool: Whether the update was successful
        """
        try:
            # Merge new metadata with existing metadata
            if self.metadata is None:
                self.metadata = {}

            self.metadata.update(new_metadata)
            db.session.commit()
            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error updating file metadata: {str(e)}")
            return False

    def verify_integrity(self, hash_value: str) -> bool:
        """
        Verify file integrity by comparing hash values.

        Args:
            hash_value: The hash to compare against stored hash

        Returns:
            bool: Whether the hash matches
        """
        if not self.file_hash:
            return False
        return self.file_hash == hash_value

    def mark_sensitive(self, is_sensitive: bool = True, reason: Optional[str] = None) -> bool:
        """
        Mark file as sensitive or not sensitive.

        Args:
            is_sensitive: Whether the file contains sensitive data
            reason: Reason for marking the file as sensitive

        Returns:
            bool: Whether the update was successful
        """
        try:
            # Record previous state for audit logging
            previous_state = self.is_sensitive

            self.is_sensitive = is_sensitive

            # Record reason in metadata if provided
            if reason and is_sensitive:
                if 'sensitivity' not in self.metadata:
                    self.metadata['sensitivity'] = {}

                self.metadata['sensitivity']['reason'] = reason
                self.metadata['sensitivity']['marked_at'] = datetime.now(timezone.utc).isoformat()

                if hasattr(g, 'user_id'):
                    self.metadata['sensitivity']['marked_by'] = g.user_id

            db.session.commit()

            # Log change for security auditing
            if previous_state != is_sensitive:
                event_type = 'file_marked_sensitive' if is_sensitive else 'file_marked_not_sensitive'
                log_security_event(
                    event_type=event_type,
                    description=f"File {self.filename} marked as {'sensitive' if is_sensitive else 'not sensitive'}",
                    severity='info',
                    user_id=getattr(g, 'user_id', None) if has_request_context() else None,
                    details={
                        'file_id': self.file_id,
                        'filename': self.filename,
                        'reason': reason
                    }
                )

            return True

        except SQLAlchemyError as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Error marking file sensitivity: {str(e)}")
            return False

    @classmethod
    def get_by_file_id(cls, file_id: str) -> Optional['FileMetadata']:
        """
        Get file metadata by file ID.

        Args:
            file_id: Unique identifier for the file

        Returns:
            FileMetadata object if found, None otherwise
        """
        return cls.query.filter_by(file_id=file_id).first()

    @classmethod
    def get_by_hash(cls, file_hash: str) -> List['FileMetadata']:
        """
        Get file metadata records by file hash.

        Args:
            file_hash: Hash of the file content

        Returns:
            List of FileMetadata objects with matching hash
        """
        return cls.query.filter_by(file_hash=file_hash).all()

    @classmethod
    def find_duplicates(cls) -> Dict[str, List['FileMetadata']]:
        """
        Find duplicate files based on hash values.

        Returns:
            Dictionary mapping file hashes to lists of FileMetadata objects
        """
        duplicates = {}
        # Find hashes with more than one file
        duplicate_hashes = db.session.query(cls.file_hash) \
            .filter(cls.file_hash.isnot(None)) \
            .group_by(cls.file_hash) \
            .having(db.func.count(cls.id) > 1).all()

        for (hash_value,) in duplicate_hashes:
            duplicates[hash_value] = cls.query.filter_by(file_hash=hash_value).all()

        return duplicates

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the file metadata to a dictionary.

        Returns:
            Dictionary representation of file metadata
        """
        result = {
            'id': self.id,
            'file_id': self.file_id,
            'filename': self.filename,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'path': self.path,
            'extension': self.extension,
            'media_type': self.media_type,
            'user_id': self.user_id,
            'is_public': self.is_public,
            'is_encrypted': self.is_encrypted,
            'is_sensitive': self.is_sensitive,
            'security_scan_result': self.security_scan_result,
            'security_scanned_at': self.security_scanned_at.isoformat() if self.security_scanned_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

        # Include safe metadata fields
        if self.metadata:
            # Filter out any internal metadata that shouldn't be exposed
            safe_metadata = {k: v for k, v in self.metadata.items() if not k.startswith('_')}
            result['metadata'] = safe_metadata

        return result
