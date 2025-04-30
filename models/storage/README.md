# Storage Models

## Overview

This directory contains database models for the Cloud Infrastructure Platform's file storage system. These models provide a robust foundation for managing file uploads, media content, and storage operations while ensuring proper security controls, validation, and integrity verification.

The storage models enable secure file management across the platform, supporting features like file uploads, metadata tracking, storage policy enforcement, quota management, file versioning, and secure sharing.

## Key Components

- **`FileUpload`**: Manages uploaded file information and processing
  - Tracks files throughout their lifecycle
  - Validates file content and enforces security controls
  - Integrates with scanning systems for security verification
  - Handles file storage locations and access permissions
  - Associates metadata with uploaded content

- **`FileMetadata`**: Manages detailed information about stored files
  - Stores comprehensive file attributes and properties
  - Tracks file hashes for integrity verification
  - Manages security classification of content
  - Records scan results and security assessments
  - Provides file categorization and organization

- **`StoragePolicy`**: Defines retention and lifecycle policies
  - Manages data retention requirements
  - Implements tiered storage strategies
  - Enforces compliance-based retention rules
  - Schedules archival and deletion operations
  - Supports legal hold functionality

- **`StorageQuota`**: Tracks and enforces storage limits
  - Monitors storage usage per user/organization
  - Implements quota enforcement mechanisms
  - Provides usage statistics and alerts
  - Enforces file size limitations
  - Manages quota allocation and adjustment

- **`FileVersion`**: Tracks file version history
  - Maintains chronological version history
  - Supports rollback to previous versions
  - Records modification metadata
  - Provides differential storage optimization
  - Implements version comparison capabilities

- **`FileShare`**: Manages access permissions for shared files
  - Controls file sharing and permissions
  - Implements time-limited sharing capabilities
  - Tracks access history for shared content
  - Provides granular access control mechanisms
  - Supports secure external sharing

## Directory Structure

```plaintext
models/storage/
├── __init__.py           # Package exports
├── file_upload.py        # File upload tracking and management
├── file_metadata.py      # File metadata management
├── storage_policy.py     # Retention and lifecycle policies
├── storage_quota.py      # Storage quota management
├── file_version.py       # File version tracking
├── file_share.py         # File sharing and permissions
└── README.md             # This documentation
```

## Implementation Notes

All storage models inherit from the `BaseModel` class, providing:

- Common CRUD operations (save, update, delete)
- Timestamp tracking (created_at, updated_at)
- Type annotations for better IDE support
- Common query methods and validation

Storage models are designed with these principles:

- **Security-first approach**: All file operations include security validation
- **Metadata separation**: Clear separation between files and their metadata
- **Lifecycle management**: Complete tracking from upload through deletion
- **Integration capabilities**: Hooks for scanning and verification services
- **Compliance support**: Retention and legal hold capabilities
- **Quota enforcement**: Resource limitation at multiple granularity levels
- **Version control**: Historical tracking with rollback capabilities
- **Audit capabilities**: Changes tracked for compliance requirements

## Features

- **Secure File Upload**: Security-validated file uploads with scanning
- **File Integrity**: Hash-based integrity verification
- **Metadata Management**: Comprehensive file property tracking
- **Content Security**: File scanning and classification
- **Access Control**: Integration with the platform RBAC system
- **Quota Management**: Storage limitations and enforcement
- **Version Control**: File history with rollback capabilities
- **Sharing Controls**: Secure file sharing with permissions
- **Retention Policies**: Compliance-based storage lifecycles
- **Audit Logging**: Change tracking for compliance
- **Legal Hold**: Support for compliance and eDiscovery
- **Format Conversion**: File format transformation capabilities

## Usage Examples

### File Upload and Processing

```python
from models.storage import FileUpload
from flask import request

# Handle file upload from a request
uploaded_file = request.files['document']

# Create the file upload record
file_upload = FileUpload(
    filename=uploaded_file.filename,
    content_type=uploaded_file.content_type,
    size=len(uploaded_file.read()),
    user_id=current_user.id,
    upload_source=FileUpload.SOURCE_WEB_UPLOAD
)
uploaded_file.seek(0)  # Reset file pointer

# Save the file physically
storage_path = file_upload.generate_storage_path()
file_upload.storage_path = storage_path
uploaded_file.save(storage_path)

# Create file upload record
file_upload.save()

# Trigger security scanning
file_upload.schedule_security_scan()

# Generate metadata
file_upload.extract_metadata()

# Check quota before committing
if not current_user.check_storage_quota(file_upload.size):
    file_upload.delete_file()  # Clean up file
    return {"error": "Storage quota exceeded"}, 403

# Complete upload process
file_upload.status = FileUpload.STATUS_COMPLETE
file_upload.save()
```

### Working with File Metadata

```python
from models.storage import FileMetadata

# Create file metadata
metadata = FileMetadata(
    file_id=file_upload.id,
    filename=file_upload.filename,
    mime_type=file_upload.content_type,
    file_size=file_upload.size,
    path=file_upload.storage_path,
    user_id=current_user.id,
    media_type=FileMetadata.TYPE_DOCUMENT
)

# Calculate hash for integrity
import hashlib
with open(file_upload.storage_path, 'rb') as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
metadata.file_hash = file_hash

metadata.save()

# Update security scan results
metadata.update_security_scan(
    result=FileMetadata.SCAN_RESULT_CLEAN,
    scan_details={
        "scanner": "MalwareScanner v3.4",
        "definitions_date": "2024-07-10",
        "scan_id": "scan-20240710-123456"
    }
)

# Mark file as sensitive if needed
if sensitive_content_detected:
    metadata.mark_sensitive(
        is_sensitive=True,
        reason="Contains personally identifiable information"
    )

# Find duplicate files
duplicates = FileMetadata.find_duplicates()
for file_hash, files in duplicates.items():
    print(f"Found {len(files)} duplicates with hash {file_hash}")
```

### Managing File Versions

```python
from models.storage import FileVersion, FileUpload, FileMetadata
import os
import shutil

# Get the existing file
existing_file = FileUpload.query.get(file_id)
existing_metadata = FileMetadata.get_by_file_id(existing_file.id)

# Create a new version
version = FileVersion(
    file_id=existing_file.id,
    version_number=FileVersion.get_next_version_number(existing_file.id),
    created_by=current_user.id,
    file_size=len(new_content),
    change_summary="Updated content with latest information"
)

# Store the previous version
previous_version_path = version.generate_version_path(existing_file.storage_path)
shutil.copy2(existing_file.storage_path, previous_version_path)
version.storage_path = previous_version_path
version.save()

# Update the current file
with open(existing_file.storage_path, 'wb') as f:
    f.write(new_content)

# Update file metadata
existing_metadata.file_size = len(new_content)

# Calculate new hash
with open(existing_file.storage_path, 'rb') as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
existing_metadata.file_hash = file_hash
existing_metadata.save()

# Record the version update
existing_file.current_version = version.version_number
existing_file.save()
```

### File Sharing Management

```python
from models.storage import FileShare
from datetime import datetime, timedelta, timezone

# Create a new file share
share = FileShare(
    file_id=file_id,
    created_by=current_user.id,
    access_level=FileShare.ACCESS_LEVEL_READ,
    expiration_date=datetime.now(timezone.utc) + timedelta(days=7),
    share_type=FileShare.SHARE_TYPE_LINK
)

# Set sharing options
share.password_protected = True
share.password = "secure_password_hash"  # Store hashed password
share.allow_downloads = True
share.max_access_count = 10

# Generate share key
share.generate_share_key()
share.save()

# Get sharing URL
share_url = share.get_share_url()

# Validate access to shared file
def access_shared_file(share_key, password=None):
    share = FileShare.get_by_share_key(share_key)

    if not share:
        return {"error": "Share not found"}, 404

    if share.is_expired():
        return {"error": "Share has expired"}, 403

    if share.access_count >= share.max_access_count and share.max_access_count > 0:
        return {"error": "Maximum access limit reached"}, 403

    if share.password_protected and not share.verify_password(password):
        return {"error": "Invalid password"}, 403

    # Record access
    share.record_access(request.remote_addr)

    # Return file data
    return share.get_file_data()
```

### Storage Quota Management

```python
from models.storage import StorageQuota

# Create user quota
quota = StorageQuota(
    user_id=user.id,
    max_bytes=10 * 1024 * 1024 * 1024,  # 10GB
    quota_type=StorageQuota.TYPE_USER
)
quota.save()

# Check quota before upload
def check_quota(user_id, file_size):
    quota = StorageQuota.get_for_user(user_id)

    if not quota:
        # Use default quota
        quota = StorageQuota.get_default_quota()

    current_usage = quota.get_current_usage()
    remaining = quota.max_bytes - current_usage

    if file_size > remaining:
        return False, remaining

    return True, remaining

# Update quota usage after file operations
def update_quota_usage(user_id, bytes_change):
    quota = StorageQuota.get_for_user(user_id)
    if quota:
        quota.update_usage(bytes_change)
```

### Storage Policy Implementation

```python
from models.storage import StoragePolicy, FileUpload

# Create a compliance-based storage policy
policy = StoragePolicy(
    name="Financial Records",
    retention_period=365 * 7,  # 7 years
    policy_type=StoragePolicy.TYPE_COMPLIANCE,
    auto_archive_days=365,  # Archive after 1 year
    auto_delete=False,  # Never auto-delete compliance documents
)
policy.save()

# Apply policy to files
policy.apply_to_category("financial_documents")

# Check if a file can be deleted
def can_delete_file(file_id):
    file = FileUpload.query.get(file_id)
    policy = StoragePolicy.get_for_file(file_id)

    if policy and policy.has_legal_hold():
        return False, "File is under legal hold"

    if policy and not policy.deletion_allowed(file):
        retention_days = policy.get_remaining_retention_days(file)
        return False, f"Retention policy prevents deletion for {retention_days} more days"

    return True, None

# Process scheduled operations (archival, deletion)
def process_policy_operations():
    # Get files to archive
    files_to_archive = StoragePolicy.get_files_for_archival()
    for file in files_to_archive:
        file.archive()

    # Get files eligible for deletion
    files_to_delete = StoragePolicy.get_files_for_deletion()
    for file in files_to_delete:
        file.delete()
```

## Security Considerations

- **Access Control**: All file operations are restricted through the RBAC system
- **File Validation**: Files are validated for type, size, and content safety
- **Malware Scanning**: Security scanning integration for all uploads
- **Content Classification**: Files can be marked as sensitive with restricted access
- **Hash Verification**: SHA-256 file hashes verify file integrity
- **Safe Storage Paths**: Storage paths prevent directory traversal attacks
- **Secure Downloads**: Download requests verify permissions and track access
- **Password Protection**: Optional password protection for shared files
- **Expiring Links**: Shares can have expiration dates and access limits
- **Audit Trails**: All file operations are logged for compliance and security
- **Legal Hold**: Support for preventing deletion during legal proceedings
- **Quota Enforcement**: Resource limitations prevent storage exhaustion attacks
- **Metadata Sanitization**: Automatic removal of sensitive metadata from files

## Best Practices

- Always use the `FileUpload` model's methods for secure file handling
- Validate file types and content before accepting uploads
- Apply appropriate retention policies based on content type
- Implement proper quota management to prevent resource exhaustion
- Use version control for important documents
- Set appropriate access permissions when sharing files
- Regularly scan stored files for security threats
- Remove sensitive metadata before storing files
- Implement appropriate backup strategies for critical files
- Use strong randomization for share keys and download tokens
- Set expirations on shared links to minimize exposure
- Apply proper classification to files containing sensitive information

## Related Documentation

- File Handling API Reference
- Storage Service Architecture
- Upload Security Guidelines
- Content Security Policy
- RBAC Implementation Guide
- File Integrity Verification
- Quota Management System
- Retention Policy Framework
- Compliance Requirements
- Storage Backup System
- Legal Hold Procedures
- Media Processing Pipeline
