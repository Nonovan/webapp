"""
File Integrity Baseline Model for Cloud Infrastructure Platform.

This module defines the data model for storing file integrity baselines,
which are used to detect unauthorized modifications to critical system files.
The model supports versioning, metadata tracking, and integration with the
file integrity monitoring system.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict

from models.base import BaseModel
from models.security.audit_log import AuditLog
from extensions import db
from core.security import log_security_event


class FileIntegrityBaseline(BaseModel):
    """
    Model for storing file integrity baseline data.

    A baseline represents a known-good state of files in the system,
    containing file paths and their cryptographic hashes. The baseline
    is used to detect unauthorized modifications to critical system files.

    Attributes:
        id (int): Primary key
        name (str): Descriptive name for the baseline
        description (str): Detailed description of the baseline's purpose
        baseline_type (str): Type of baseline (system, application, custom)
        file_path (str): Path to the baseline file on disk
        is_active (bool): Whether this baseline is currently active
        file_count (int): Number of files in the baseline
        hash_algorithm (str): Algorithm used for file hashing (sha256, etc.)
        creation_date (datetime): When the baseline was created
        last_verified (datetime): When the baseline was last verified
        last_updated (datetime): When the baseline was last modified
        created_by (int): User ID who created the baseline
        updated_by (int): User ID who last updated the baseline
        baseline_data (dict): JSON data containing file paths and hashes
        metadata (dict): Additional metadata for the baseline
    """

    # Status constants
    STATUS_ACTIVE = 'active'
    STATUS_ARCHIVED = 'archived'
    STATUS_PENDING = 'pending'
    STATUS_INVALID = 'invalid'

    # Valid status values
    STATUSES = [STATUS_ACTIVE, STATUS_ARCHIVED, STATUS_PENDING, STATUS_INVALID]

    # Baseline types
    TYPE_SYSTEM = 'system'
    TYPE_APPLICATION = 'application'
    TYPE_CRITICAL = 'critical'
    TYPE_CUSTOM = 'custom'

    # Valid baseline types
    BASELINE_TYPES = [TYPE_SYSTEM, TYPE_APPLICATION, TYPE_CRITICAL, TYPE_CUSTOM]

    # Hash algorithms
    ALGORITHM_SHA256 = 'sha256'
    ALGORITHM_SHA512 = 'sha512'
    ALGORITHM_SHA3_256 = 'sha3_256'

    # Valid hash algorithms
    HASH_ALGORITHMS = [ALGORITHM_SHA256, ALGORITHM_SHA512, ALGORITHM_SHA3_256]

    # Column definitions
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(255))
    baseline_type = db.Column(db.String(32), nullable=False, default=TYPE_CUSTOM)
    file_path = db.Column(db.String(255))
    status = db.Column(db.String(32), default=STATUS_PENDING, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    file_count = db.Column(db.Integer, default=0)
    hash_algorithm = db.Column(db.String(32), default=ALGORITHM_SHA256, nullable=False)

    # Timestamps
    creation_date = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    last_verified = db.Column(db.DateTime(timezone=True))
    last_updated = db.Column(db.DateTime(timezone=True))

    # User tracking
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # JSON data fields
    baseline_data = db.Column(MutableDict.as_mutable(JSONB), default=dict)
    metadata = db.Column(MutableDict.as_mutable(JSONB), default=dict)

    def __init__(self, name: str, baseline_type: str, hash_algorithm: str = ALGORITHM_SHA256,
                description: Optional[str] = None, file_path: Optional[str] = None,
                created_by: Optional[int] = None, baseline_data: Optional[Dict[str, Any]] = None,
                metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a new file integrity baseline.

        Args:
            name: Descriptive name for the baseline
            baseline_type: Type of baseline (system, application, custom)
            hash_algorithm: Algorithm used for file hashing
            description: Optional detailed description
            file_path: Optional path to baseline file on disk
            created_by: User ID who created the baseline
            baseline_data: Optional initial baseline data
            metadata: Optional additional metadata
        """
        if baseline_type not in self.BASELINE_TYPES:
            raise ValueError(f"Invalid baseline type: {baseline_type}. Must be one of: {', '.join(self.BASELINE_TYPES)}")

        if hash_algorithm not in self.HASH_ALGORITHMS:
            raise ValueError(f"Invalid hash algorithm: {hash_algorithm}. Must be one of: {', '.join(self.HASH_ALGORITHMS)}")

        super().__init__()
        self.name = name
        self.description = description
        self.baseline_type = baseline_type
        self.file_path = file_path
        self.hash_algorithm = hash_algorithm
        self.created_by = created_by
        self.creation_date = datetime.now(timezone.utc)

        # Initialize JSON fields
        self.baseline_data = baseline_data or {"files": {}, "metadata": {}}
        self.metadata = metadata or {}

        # Update file count if baseline data was provided
        if baseline_data and "files" in baseline_data:
            self.file_count = len(baseline_data["files"])

    def update_baseline(self, file_hashes: Dict[str, str], user_id: int) -> Tuple[bool, str]:
        """
        Update baseline with new file hashes.

        Args:
            file_hashes: Dictionary mapping file paths to their hash values
            user_id: ID of user performing the update

        Returns:
            Tuple containing (success, message)
        """
        try:
            # Create backup of current data
            backup = self.baseline_data.copy()

            # Track changes
            added = 0
            updated = 0
            unchanged = 0

            # Get current files or initialize if not present
            if "files" not in self.baseline_data:
                self.baseline_data["files"] = {}

            current_files = self.baseline_data["files"]

            # Update file entries
            for path, file_hash in file_hashes.items():
                if path in current_files:
                    if current_files[path] != file_hash:
                        current_files[path] = file_hash
                        updated += 1
                    else:
                        unchanged += 1
                else:
                    current_files[path] = file_hash
                    added += 1

            # Update metadata
            self.baseline_data["metadata"] = self.baseline_data.get("metadata", {})
            self.baseline_data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
            self.baseline_data["metadata"]["hash_algorithm"] = self.hash_algorithm
            self.baseline_data["metadata"]["updated_by"] = user_id

            # Update model fields
            self.file_count = len(current_files)
            self.last_updated = datetime.now(timezone.utc)
            self.updated_by = user_id

            # Log security event
            log_security_event(
                event_type='file_integrity_baseline_updated',
                description=f"File integrity baseline '{self.name}' updated",
                severity='info',
                user_id=user_id,
                details={
                    'baseline_id': self.id,
                    'name': self.name,
                    'added': added,
                    'updated': updated,
                    'unchanged': unchanged,
                    'file_count': self.file_count
                }
            )

            return True, f"Baseline updated successfully: {added} added, {updated} updated, {unchanged} unchanged"

        except Exception as e:
            # Restore from backup on error
            self.baseline_data = backup
            return False, f"Error updating baseline: {str(e)}"

    def verify_file(self, file_path: str, current_hash: str) -> bool:
        """
        Verify if a file matches its baseline hash.

        Args:
            file_path: Path to the file
            current_hash: Current hash of the file

        Returns:
            True if file hash matches baseline, False otherwise
        """
        if "files" not in self.baseline_data:
            return False

        baseline_hash = self.baseline_data["files"].get(file_path)
        if not baseline_hash:
            return False

        return baseline_hash == current_hash

    def detect_changes(self, current_hashes: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Detect changes between current hashes and baseline.

        Args:
            current_hashes: Dictionary mapping file paths to current hash values

        Returns:
            List of changes with details
        """
        changes = []

        if "files" not in self.baseline_data:
            return changes

        baseline_files = self.baseline_data["files"]

        # Check for modified or missing files
        for path, baseline_hash in baseline_files.items():
            if path in current_hashes:
                current_hash = current_hashes[path]
                if current_hash != baseline_hash:
                    changes.append({
                        'path': path,
                        'status': 'modified',
                        'baseline_hash': baseline_hash,
                        'current_hash': current_hash,
                        'severity': self._get_path_severity(path)
                    })
            else:
                changes.append({
                    'path': path,
                    'status': 'missing',
                    'baseline_hash': baseline_hash,
                    'current_hash': None,
                    'severity': self._get_path_severity(path)
                })

        # Check for new files
        for path, current_hash in current_hashes.items():
            if path not in baseline_files:
                changes.append({
                    'path': path,
                    'status': 'new',
                    'baseline_hash': None,
                    'current_hash': current_hash,
                    'severity': self._get_path_severity(path)
                })

        return changes

    def activate(self, user_id: int) -> bool:
        """
        Activate this baseline for integrity monitoring.

        Args:
            user_id: ID of user performing the activation

        Returns:
            bool: True if activation was successful
        """
        try:
            # Check if file count is reasonable
            if self.file_count == 0:
                return False

            # Deactivate any other active baselines of the same type
            if self.baseline_type:
                active_baselines = FileIntegrityBaseline.query.filter_by(
                    baseline_type=self.baseline_type,
                    is_active=True
                ).all()

                for baseline in active_baselines:
                    baseline.is_active = False
                    baseline.status = self.STATUS_ARCHIVED

            # Activate this baseline
            self.is_active = True
            self.status = self.STATUS_ACTIVE
            self.last_updated = datetime.now(timezone.utc)
            self.updated_by = user_id

            # Save to database
            db.session.commit()

            # Log activation
            log_security_event(
                event_type='file_integrity_baseline_activated',
                description=f"File integrity baseline '{self.name}' activated",
                severity='medium',
                user_id=user_id,
                details={
                    'baseline_id': self.id,
                    'name': self.name,
                    'file_count': self.file_count
                }
            )

            return True

        except Exception as e:
            db.session.rollback()
            return False

    def export_to_file(self, export_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Export baseline data to a JSON file.

        Args:
            export_path: Path to export file, uses self.file_path if None

        Returns:
            Tuple containing (success, message)
        """
        try:
            path = export_path or self.file_path
            if not path:
                return False, "No export path specified"

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(path), exist_ok=True)

            # Write to file
            with open(path, 'w') as f:
                json.dump(self.baseline_data, f, indent=2)

            # Update file path if changed
            if export_path and export_path != self.file_path:
                self.file_path = export_path

            return True, f"Baseline exported successfully to {path}"

        except Exception as e:
            return False, f"Error exporting baseline: {str(e)}"

    def import_from_file(self, import_path: str, user_id: int) -> Tuple[bool, str]:
        """
        Import baseline data from a JSON file.

        Args:
            import_path: Path to import file
            user_id: ID of user performing the import

        Returns:
            Tuple containing (success, message)
        """
        try:
            if not os.path.exists(import_path):
                return False, f"Import file not found: {import_path}"

            # Read from file
            with open(import_path, 'r') as f:
                data = json.load(f)

            # Validate structure
            if not isinstance(data, dict):
                return False, "Invalid baseline format: root must be a dictionary"

            if "files" not in data:
                return False, "Invalid baseline format: missing 'files' key"

            # Update baseline data
            self.baseline_data = data
            self.file_count = len(data.get("files", {}))
            self.last_updated = datetime.now(timezone.utc)
            self.updated_by = user_id

            # Update file path
            self.file_path = import_path

            # Log import
            log_security_event(
                event_type='file_integrity_baseline_imported',
                description=f"File integrity baseline '{self.name}' imported from file",
                severity='medium',
                user_id=user_id,
                details={
                    'baseline_id': self.id,
                    'name': self.name,
                    'file_count': self.file_count,
                    'import_path': import_path
                }
            )

            return True, f"Baseline imported successfully with {self.file_count} files"

        except json.JSONDecodeError:
            return False, "Invalid JSON format in import file"
        except Exception as e:
            return False, f"Error importing baseline: {str(e)}"

    def _get_path_severity(self, path: str) -> str:
        """
        Determine severity level for a given file path.

        Args:
            path: File path to evaluate

        Returns:
            Severity level: critical, high, medium, or low
        """
        # Check for critical system files
        if any(crit in path for crit in [
            'core/security',
            'models/security',
            'services/security',
            'api/security',
            'config/security'
        ]):
            return 'critical'

        # Check for high severity files
        if any(high in path for high in [
            'config/',
            'models/',
            'core/',
            'services/',
            'extensions/',
            'app.py',
            'cli.py',
            'wsgi.py',
            '__init__.py'
        ]):
            return 'high'

        # Check for medium severity files
        if any(med in path for med in [
            'blueprints/',
            'views/',
            'api/',
            'admin/',
            'tests/security'
        ]):
            return 'medium'

        # Default to low severity
        return 'low'

    def __repr__(self) -> str:
        """String representation of the baseline."""
        return f"<FileIntegrityBaseline {self.id}: {self.name} ({self.baseline_type})>"
