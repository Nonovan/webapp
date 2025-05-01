# Models Package

The models package provides the data model layer for the Cloud Infrastructure Platform using SQLAlchemy ORM. It implements a structured domain-driven design approach to organize database models.

## Overview

This package defines the application's data model layer with a focus on:

- Domain separation through subdirectories
- Common base functionality through inheritance
- Comprehensive type annotations and documentation
- Security and audit features
- Automated logging for security-critical operations
- Bulk operations for efficient data manipulation
- Advanced query capabilities with pagination and filtering

The models implement the Active Record pattern through SQLAlchemy, where each model instance represents a row in the database and provides methods for CRUD operations. This approach encapsulates database operations within the models themselves, promoting code organization and reusability.

## Directory Structure

```plaintext
models/
├── __init__.py              # Package exports and event listeners
├── base.py                  # Base model classes and mixins
├── README.md                # This documentation
├── auth/                    # Authentication and user management
│   ├── __init__.py          # Auth module exports
│   ├── api_key.py           # API key model for programmatic authentication
│   ├── login_attempt.py     # Login attempt tracking and brute force protection
│   ├── mfa_backup_code.py   # Backup codes for multi-factor authentication
│   ├── mfa_method.py        # Multi-factor authentication methods
│   ├── mfa_verification.py  # MFA verification attempt tracking
│   ├── oath_provider.py     # OAuth provider and connection models
│   ├── permission.py        # Permission model for RBAC
│   ├── permission_context.py # Context-based permission evaluation rules
│   ├── permission_delegation.py # Temporary permission delegation
│   ├── README.md            # Auth module documentation
│   ├── role.py              # Role model for access control
│   ├── role_assignment.py   # Role assignment and management
│   ├── user.py              # User account model
│   ├── user_activity.py     # User activity logging
│   └── user_session.py      # User session tracking
├── cloud/                   # Cloud infrastructure models
│   ├── __init__.py          # Cloud module exports
│   ├── cloud_alert.py       # Alert configurations
│   ├── cloud_metric.py      # Resource metrics and monitoring
│   ├── cloud_provider.py    # Cloud provider configurations
│   └── cloud_resource.py    # Infrastructure resources
├── communication/           # Communication-related models
│   ├── __init__.py          # Communication module exports
│   ├── comm_channel.py      # Channel configuration model
│   ├── comm_log.py          # Communication logging model
│   ├── comm_scheduler.py    # Communication scheduling model
│   ├── newsletter.py        # Newsletter subscribers and lists
│   ├── notification.py      # User notifications
│   ├── subscriber.py        # Subscriber management
│   └── webhook.py           # Webhook subscriptions and delivery
├── content/                 # Content management models
│   ├── __init__.py          # Content module exports
│   ├── category.py          # Content categorization
│   ├── comment.py           # User feedback and interactions
│   ├── content_revision.py  # Version history tracking
│   ├── media.py             # Media file management
│   ├── menu.py              # Navigation structure
│   ├── post.py              # Blog/news post content
│   ├── post_media.py        # Media associations for posts
│   ├── README.md            # Content module documentation
│   └── tag.py               # Content tagging
├── ics/                     # Industrial Control Systems
│   ├── __init__.py          # ICS module exports
│   ├── ics_control_log.py   # Control operation logging
│   ├── ics_device.py        # ICS device inventory
│   └── ics_reading.py       # Sensor readings and telemetry
├── security/                # Security-related models
│   ├── __init__.py          # Security module exports
│   ├── audit_log.py         # Security audit records
│   ├── compliance_check.py  # Compliance verification
│   ├── login_attempt.py     # Authentication attempt tracking
│   ├── README.md            # Security module documentation
│   ├── security_baseline.py # Security standards definition
│   ├── security_incident.py # Security incident management
│   ├── security_scan.py     # Security scan results
│   ├── system_config.py     # Security configurations
│   ├── threat_intelligence.py # Threat intelligence data
│   └── vulnerability_record.py # Vulnerability management
└── storage/                 # Storage-related models
    ├── __init__.py          # Storage module exports
    ├── file_metadata.py     # File metadata management
    ├── file_share.py        # File sharing permissions
    ├── file_upload.py       # File upload tracking
    ├── file_version.py      # File version history tracking
    ├── README.md            # Storage module documentation
    ├── storage_policy.py    # Retention and lifecycle policies
    └── storage_quota.py     # Storage quota management
```

## Key Components

1. **Base Classes (`base.py`)**:
    - `BaseModel`: Core base class that all models inherit from
    - `TimestampMixin`: Provides automatic timestamp tracking
    - `AuditableMixin`: Adds security auditing capabilities
2. **Authentication (`auth/`)**:
    - User management and authentication
    - Role-based access control (RBAC)
    - Permission management
    - Session tracking and management
    - User activity logging
    - Multi-factor authentication
    - OAuth integration
    - API key management
    - Temporary permission delegation
3. **Cloud Infrastructure (`cloud/`)**:
    - Cloud provider configurations (AWS, Azure, GCP)
    - Resource management (VMs, storage, etc.)
    - Metrics collection and alerting
    - Cost tracking and monitoring
4. **Communication (`communication/`)**:
    - Newsletter management
    - User notification systems
    - Subscriber management
    - Webhook integrations
5. **Content Management (`content/`)**:
    - Blog posts and content articles
    - Content categorization
    - Hierarchical category structure
    - Content tagging
    - Media management
    - Revision history tracking
    - Comment systems
    - Navigation menus
6. **Industrial Control Systems (`ics/`)**:
    - Device inventory management
    - Sensor reading collection
    - Control operation logging
7. **Security (`security/`)**:
    - Security incident tracking
    - Comprehensive audit logging
    - System configuration management
    - Security controls
    - Vulnerability management
    - Compliance verification
    - Threat intelligence
    - Security baseline definitions
    - Security scanning
8. **Storage (`storage/`)**:
    - File upload tracking and management
    - Comprehensive file metadata management
    - File security scanning and classification
    - File integrity verification through hashing
    - Version control for files
    - Secure file sharing with access controls
    - Storage quota management and enforcement
    - File retention and lifecycle policies
9. **Alerts (`alerts/`)**:
    - Alert lifecycle management from creation to resolution
    - Severity-based prioritization and routing
    - Multi-channel notification delivery (email, SMS, webhook, Slack, Teams)
    - Alert correlation to identify related issues
    - Auto-acknowledgement for stale alerts
    - Time-based severity escalation
    - Alert suppression for maintenance periods and throttling
    - Alert metrics and trend analysis
    - Environment and service-specific alerting
    - SLA compliance tracking

## Notable Files

- **`__init__.py`**: Main package initialization with event listeners for audit logging
- **`base.py`**: Contains the core base classes and mixins with bulk operations support
- **`auth/permission.py`**: Fine-grained permission model for RBAC
- **`auth/role.py`**: Role model with permission inheritance
- **`auth/permission_delegation.py`**: Temporary permission transfers between users
- **`auth/mfa_method.py`**: Multi-factor authentication implementation
- **`security/audit_log.py`**: Comprehensive security auditing system
- **`security/vulnerability_record.py`**: Vulnerability tracking and lifecycle management
- **`content/content_revision.py`**: Version history tracking for content
- **`cloud/cloud_resource.py`**: Cloud resource management with cost tracking
- **`security/system_config.py`**: System-wide configuration storage
- **`storage/file_metadata.py`**: File metadata and classification management
- **`storage/file_upload.py`**: File upload processing and security validation

## Implementation Notes

- All models inherit from `BaseModel` which provides common CRUD operations
- Security-sensitive models also use the `AuditableMixin` for automatic audit logging
- Most models implement a `to_dict()` method for serialization
- Many models include comprehensive validation and error handling
- Several domains implement specialized features:
  - Cloud models include cost and security monitoring
  - Security models have built-in alerting and incident management
  - Content models support hierarchical structures
  - Storage models include file validation and security scanning
  - Auth models implement full RBAC with permission inheritance
- Bulk operations provide efficient data manipulation for large datasets
- Advanced query methods support pagination, filtering, and contextual operations

## Key Features

- **Structured Organization**: Models are grouped by domain for better maintainability
- **Common Base Model**: All models inherit from `BaseModel` for consistent behavior
- **Type Annotations**: Comprehensive typing for IDE support and type checking
- **Audit Tracking**: `AuditableMixin` provides security audit capabilities
- **Serialization**: Standard `to_dict()` methods for API responses
- **Event Listeners**: Automatic timestamp tracking and audit logging
- **Role-Based Access Control**: Complete RBAC implementation with roles and permissions
- **Multi-Factor Authentication**: Support for multiple MFA methods
- **Content Versioning**: Revision history for content changes
- **Security Incident Management**: Full workflow for security incidents
- **Vulnerability Management**: Comprehensive vulnerability lifecycle handling
- **Threat Intelligence**: Tracking of security threats and indicators
- **Sanitization**: Automatic removal of sensitive data from logs
- **File Integrity**: Cryptographic hash verification for uploaded files
- **Security Scanning**: Malware and threat scanning for file uploads
- **Bulk Operations**: Efficient creation, updating, and deletion of multiple records
- **Advanced Queries**: Pagination, date range filtering, and contextual lookups
- **Get-or-Create Pattern**: Simplified retrieval with fallback to creation

## RBAC System

The Role-Based Access Control system implemented in the `auth/` module provides sophisticated access control capabilities:

1. **Hierarchical Permission Inheritance**: Roles can inherit permissions from parent roles, creating organizational structures.
2. **Resource-Action Permission Model**: Permissions follow a `resource:action` naming pattern (e.g., `cloud_resources:read`).
3. **Context-Based Permission Evaluation**: Permissions can be evaluated with contextual data for attribute-based access control.
4. **System vs. Custom Roles/Permissions**: Distinction between core system components and user-defined components.
5. **Time-Limited Permission Assignments**: Support for temporary access elevation without permanent permission changes.
6. **Permission Delegation**: Temporary transfer of permissions between users with approval workflows.

## Base Model Structure

All models inherit from the `BaseModel` class, which provides:

- Core CRUD operations (save, update, delete)
- Timestamp tracking (created_at, updated_at)
- Type annotations for better IDE support
- Common query methods
- JSON serialization via `to_dict()`
- Bulk operations for efficient data manipulation
- Pagination and filtering capabilities

```python
from models.base import BaseModel

class MyModel(BaseModel):
    __tablename__ = 'my_model'

    # Define fields...

    # Define relationships...
```

## Usage Examples

### Basic Model Operations

```python
from models import User, Post, CloudResource

# Create a new user
user = User(username="username", email="user@example.com")
user.save()

# Query resources by type
resources = CloudResource.get_by_type("vm", active_only=True)

# Update an existing model
post = Post.query.filter_by(slug="welcome-post").first()
post.title = "Updated Title"
post.save()

# Delete a model instance
user_session = UserSession.query.get(session_id)
user_session.delete()
```

### Working with Relationships

```python
# Create related objects
category = Category(name="Technology")
category.save()

post = Post(title="New Tech Post", category_id=category.id)
post.save()

# Query with joins
tech_posts = Post.query.join(Category).filter(
    Category.name == "Technology"
).all()

# Using relationship properties
for subscriber in newsletter_list.subscribers:
    print(f"Sending to: {subscriber.email}")
```

### Role-Based Access Control

```python
# Create a permission
view_reports = Permission(name="reports:view", description="View system reports")
view_reports.save()

# Create a role with permissions
analyst_role = Role(name="Analyst", description="Data analyst")
analyst_role.add_permission(view_reports)
analyst_role.save()

# Assign role to user
user = User.query.filter_by(email="analyst@example.com").first()
user.assign_role(analyst_role)

# Check permissions
if user.has_permission("reports:view"):
    print("User can view reports")

# Context-based permission check
context = {
    "owner_id": resource.owner_id,
    "resource_type": "vm",
    "cloud_provider": "aws",
    "region": "us-west-2"
}
if user.has_permission_with_context("resources:modify", context):
    # Allow modification
    pass
```

### User Activity and Session Management

```python
# Log user activity
UserActivity.log_activity(
    activity_type=UserActivity.ACTIVITY_RESOURCE_ACCESS,
    user_id=current_user.id,
    resource_type="cloud_instance",
    resource_id=instance_id,
    action=UserActivity.ACTION_UPDATE,
    data={"changes": changes_dict}
)

# Create and track user session
session = UserSession(
    user_id=user.id,
    ip_address=request.remote_addr,
    user_agent=request.user_agent.string,
    client_type=UserSession.SESSION_CLIENT_TYPE_WEB
)
db.session.add(session)
db.session.commit()

# Check for suspicious sessions
suspicious_sessions = UserSession.detect_suspicious_sessions(user_id)
for session in suspicious_sessions:
    session.flag_as_suspicious("Unusual access pattern detected")
```

### Security-Enhanced Models

The `SecurityIncident` model provides a comprehensive incident lifecycle management system for handling security events:

```python
# Create a new security incident
incident = SecurityIncident(
    title="Unauthorized Access Attempt",
    incident_type="brute_force",
    description="Multiple failed login attempts detected",
    severity=SecurityIncident.SEVERITY_HIGH,
    details="10 failed login attempts from IP 192.168.1.100 within 2 minutes",
    ip_address="192.168.1.100",
    source=SecurityIncident.SOURCE_SECURITY_SCAN
)
incident.save()  # Automatically logs the creation event

# Assign the incident to a security analyst
incident.assign_to(user_id=5, assigned_by=1)  # Changes status to INVESTIGATING

# Add investigation notes
incident.add_note("Analyzing login patterns and comparing with known attack signatures")

# If the incident is more severe than initially thought, escalate it
incident.escalate(
    new_severity=SecurityIncident.SEVERITY_CRITICAL,
    reason="Found indicators of targeted attack against admin accounts",
    user_id=5
)

# After implementing countermeasures, resolve the incident
incident.resolve(
    resolution="Blocked originating IP address, reset affected user passwords, " +
               "and enabled additional monitoring",
    user_id=5
)

# If new related activity is detected, reopen the incident
incident.reopen(
    reason="Similar attack pattern detected from new IP range",
    user_id=5
)

# When fully addressed, permanently close the incident
incident.close(
    reason="All countermeasures validated and no further suspicious activity detected",
    user_id=5
)
```

### Working with Audit Logs

The platform automatically captures audit logs for security-sensitive operations, but you can also review and analyze them:

```python
from models.security import AuditLog

# Get recent security events for a specific user
user_events = AuditLog.get_events_by_user(
    user_id=5,
    limit=50,
    severity=AuditLog.SEVERITY_WARNING
)

# Get audit trail for a specific incident
incident_logs = AuditLog.get_events_by_object(
    object_type="SecurityIncident",
    object_id=123
)

# Analyze failed login attempts in the last 24 hours
from datetime import datetime, timedelta
yesterday = datetime.now() - timedelta(days=1)
failed_logins = AuditLog.query.filter(
    AuditLog.event_type == AuditLog.EVENT_LOGIN_FAILED,
    AuditLog.created_at >= yesterday
).order_by(AuditLog.created_at.desc()).all()

# Generate security report by event types
from collections import Counter
from sqlalchemy import func

event_counts = db.session.query(
    AuditLog.event_type,
    func.count(AuditLog.id)
).group_by(AuditLog.event_type).all()

summary = {event_type: count for event_type, count in event_counts}
print(f"Found {summary.get(AuditLog.EVENT_LOGIN_FAILED, 0)} failed login attempts")
```

### Multi-Factor Authentication

```python
# Set up TOTP-based MFA for a user
mfa_method = MFAMethod(
    user_id=user.id,
    method_type=MFAMethod.METHOD_TYPE_TOTP,
    is_primary=True
)

# Generate secret and save
totp_secret = pyotp.random_base32()
mfa_method.set_secret(totp_secret)
db.session.add(mfa_method)
db.session.commit()

# Generate backup codes
backup_codes = MFABackupCode.generate_codes(user.id)

# Verify a TOTP code during login
if mfa_method.verify_code(submitted_code):
    # Log successful verification
    MFAVerification.log_verification(
        user_id=user.id,
        verification_type="totp",
        success=True,
        mfa_method_id=mfa_method.id
    )
    # Complete login process
else:
    # Log failed attempt
    MFAVerification.log_verification(
        user_id=user.id,
        verification_type="totp",
        success=False,
        mfa_method_id=mfa_method.id
    )
```

### File Storage Management

```python
from models.storage import FileUpload, FileMetadata
import hashlib

# Create a file upload record
file_upload = FileUpload(
    filename="security_whitepaper.pdf",
    original_filename="CompanyName-Security-Whitepaper-2023.pdf",
    file_size=1024 * 1024,  # 1MB
    mime_type="application/pdf",
    user_id=current_user.id,
    storage_path="uploads/2023/07/security_whitepaper.pdf"
)
file_upload.save()

# Create detailed file metadata
metadata = FileMetadata(
    file_id=file_upload.id,
    filename=file_upload.filename,
    mime_type=file_upload.mime_type,
    file_size=file_upload.file_size,
    path=file_upload.storage_path,
    user_id=current_user.id,
    media_type=FileMetadata.TYPE_DOCUMENT
)

# Calculate hash for integrity verification
with open(file_upload.storage_path, 'rb') as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
metadata.file_hash = file_hash

metadata.save()

# Run security scan on the file
metadata.update_security_scan(
    result=FileMetadata.SCAN_RESULT_CLEAN,
    scan_details={
        "scanner": "MalwareScanner v3.4",
        "definitions_date": "2023-07-15",
        "scan_id": "scan-20230715-123456"
    }
)

# Mark file as sensitive if it contains confidential information
if contains_sensitive_data(file_upload.storage_path):
    metadata.mark_sensitive(
        is_sensitive=True,
        reason="Contains personally identifiable information"
    )

# Find duplicate files based on hash
duplicates = FileMetadata.find_duplicates()
for hash_value, files in duplicates.items():
    print(f"Found {len(files)} duplicate files with hash {hash_value}")
```

### Vulnerability Management

```python
from models.security import VulnerabilityRecord

# Record a new vulnerability
vuln = VulnerabilityRecord(
    title="SQL Injection in Search Function",
    description="The search API endpoint is vulnerable to SQL injection attacks",
    severity=VulnerabilityRecord.SEVERITY_HIGH,
    cvss_score=8.5,
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    vulnerability_type=VulnerabilityRecord.TYPE_CODE,
    affected_resources=[
        {"type": "api", "id": "search-endpoint"}
    ],
    status=VulnerabilityRecord.STATUS_OPEN
)
vuln.save()

# Add affected resources
vuln.add_affected_resource({
    "type": "server",
    "id": "web-server-01"
})

# Create remediation plan
vuln.remediation_steps = """
1. Apply input validation to the search parameter
2. Use parameterized queries
3. Update API documentation
4. Add security tests
"""
vuln.remediation_deadline = datetime.now(timezone.utc) + timedelta(days=7)
vuln.assign_to(user_id=5, assigned_by_id=1)
vuln.save()

# Mark as resolved
vuln.resolve(
    resolution_summary="Implemented parameterized queries and input validation",
    user_id=5
)

# Verify the fix
vuln.verify(user_id=security_team_id)
```

### Permission Delegation

```python
# Delegate a permission temporarily to another user
delegation = PermissionDelegation.create_standard_delegation(
    delegator_id=manager.id,
    delegate_id=substitute.id,
    permissions=["invoices:approve", "payments:view"],
    valid_days=14,
    reason="Vacation coverage",
    context_constraints={"department_id": 42}
)

# Check if user has delegated permissions
delegated_permissions = PermissionDelegation.get_active_for_user(user.id)
for delegation in delegated_permissions:
    print(f"Delegated: {delegation.permissions} (until {delegation.end_time})")

# Revoke a delegation early
delegation.revoke(
    revoker_id=manager.id,
    reason="Returned from vacation early"
)
```

### Bulk Operations

```python
from models import User, Role, Post

# Create multiple users at once
new_users = [
    {"username": "user1", "email": "user1@example.com", "status": User.STATUS_ACTIVE},
    {"username": "user2", "email": "user2@example.com", "status": User.STATUS_ACTIVE},
    {"username": "user3", "email": "user3@example.com", "status": User.STATUS_PENDING}
]

# Create all users in a single transaction
created_count = User.bulk_create(new_users, return_instances=False)
print(f"Created {created_count} users")

# Update multiple records with the same attributes
post_ids = [1, 2, 3, 4, 5]
update_result = Post.bulk_update({
    post_id: {"status": Post.STATUS_PUBLISHED, "published_at": datetime.now(timezone.utc)}
    for post_id in post_ids
})
print(f"Updated {update_result['updated_count']} posts")

# Delete multiple records efficiently
delete_result = Role.bulk_delete([5, 6, 7])
print(f"Deleted {delete_result['deleted_count']} roles, skipped {len(delete_result['skipped_ids'])}")

# Use the generic model updater for flexibility
from models import bulk_update_models

result = bulk_update_models(
    User,
    [10, 11, 12],
    {"is_active": True, "last_login_reminder": datetime.now(timezone.utc)}
)
```

### Advanced Query Methods

```python
from models import Post, User

# Get paginated results with filtering and sorting
page_result = Post.paginate(
    page=2,
    per_page=15,
    filters={"status": Post.STATUS_PUBLISHED, "category_id": 5},
    order_by="published_at",
    order_direction="desc"
)

# Access paginated data
posts = page_result["items"]
metadata = page_result["meta"]
print(f"Showing page {metadata['page']} of {metadata['total_pages']} ({metadata['total_items']} total posts)")

# Filter records by date range
recent_users = User.filter_by_date_range(
    start_date=datetime.now(timezone.utc) - timedelta(days=7),
    end_date=datetime.now(timezone.utc),
    date_column="created_at"
)

# Get a record or create it if it doesn't exist
tag, created = Tag.get_or_create(
    name="security",
    defaults={"description": "Security-related content"}
)
if created:
    print(f"Created new tag: {tag.name}")
else:
    print(f"Found existing tag: {tag.name}")
```

## Security Considerations

- **Encrypted Fields**: Sensitive fields are encrypted at rest using AES-256
- **Password Protection**: Password fields use Argon2 hashing with appropriate work factors
- **Audit Logging**: Security-critical operations are automatically logged
- **Access Control**: Model access is controlled through the `AuditableMixin`
- **Input Validation**: Field validations prevent invalid or harmful data
- **SQL Injection Prevention**: All queries use parameterized statements
- **Session Management**: Secure session handling with proper timeout and rotation
- **Permission Model**: Fine-grained permission system with resource:action pattern
- **Role Hierarchy**: Supports role inheritance for complex permission structures
- **MFA Support**: Multiple authentication factors for sensitive operations
- **Delegated Access**: Temporary, auditable permission transfers between users
- **Sensitive Data Protection**: Automatic redaction of sensitive data in logs
- **Vulnerability Management**: Full vulnerability lifecycle tracking and remediation
- **Threat Intelligence**: Storage and processing of threat indicators
- **File Integrity**: Cryptographic hashing to verify file integrity
- **Content Security**: Security scanning for uploaded files with flagging capabilities
- **Metadata Sanitization**: Removal of sensitive metadata from uploaded files
- **Bulk Operation Auditing**: Security logging for bulk operations to track mass changes
- **Transaction Management**: Proper transaction handling with automatic rollbacks on errors

## Contributing New Models

When adding new models:

1. Determine the appropriate domain subdirectory
2. Inherit from appropriate base classes
3. Include comprehensive docstrings
4. Add type annotations for all fields and methods
5. Implement required validation logic
6. Add the model to **init**.py exports
7. Consider security implications and add to audit listeners if needed
8. Write unit tests for the model's functionality
9. Implement bulk operations for models that require batch processing
10. Add pagination support for models with potentially large result sets

## Related Documentation

- Database Migration Guide
- Security Controls Documentation
- API Documentation
- Authentication Guide
- RBAC Implementation Guide
- Content Management System Guide
- Multi-Factor Authentication Setup Guide
- OAuth Integration Guide
- API Key Management
- Security Monitoring and Auditing
- Vulnerability Management Policy
- Threat Intelligence Integration Guide
- File Storage Management Guide
- Secure File Handling Best Practices
- Bulk Operations Guide
- Query Performance Optimization
- Pagination Implementation
