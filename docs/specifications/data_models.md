# Data Models Specification

## Overview

This document details the data models used in the Cloud Infrastructure Platform. These models define the structure and relationships of the core entities managed by the system, ensuring data integrity and consistency across all platform components.

## Core Entities

### User

Represents an authenticated user of the platform.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| email | String | User's email address | Unique, Required |
| first_name | String | User's first name | Required |
| last_name | String | User's last name | Required |
| password_hash | String | Hashed password | Required |
| company | String | User's organization | Optional |
| phone | String | Contact phone number | Optional |
| role | String | User role (admin, user, etc.) | Required, Default: 'user' |
| status | Enum | Account status | Required, Values: active, inactive, locked, pending |
| mfa_enabled | Boolean | Multi-factor authentication status | Default: false |
| mfa_secret | String | Encrypted MFA secret | Optional |
| last_login | DateTime | Last login timestamp | Optional |
| preferences | JSON | User preferences | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- One-to-many with UserSession
- One-to-many with CloudResource (as created_by)
- One-to-many with UserActivity
- One-to-many with FileUpload

### UserSession

Tracks user authentication sessions.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Session identifier | Primary Key |
| user_id | UUID | Associated user | Foreign Key |
| token | String | Session token | Required |
| ip_address | String | Client IP address | Required |
| user_agent | String | Client user agent | Required |
| expires_at | DateTime | Expiration timestamp | Required |
| is_active | Boolean | Session status | Default: true |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with User

### CloudProvider

Represents a cloud service provider configuration.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | Integer | Unique identifier | Primary Key |
| name | String | Provider name | Required, Unique with provider_type |
| provider_type | String | Provider type | Required, Values: aws, azure, gcp, custom |
| is_active | Boolean | Provider status | Default: true |
| credentials | Text | Encrypted credentials | Optional |
| config | JSON | Provider configuration | Default: {} |
| default_region | String | Default region | Optional |
| api_endpoint | String | Custom API endpoint | Optional |
| monitoring_enabled | Boolean | Monitoring status | Default: true |
| quota | JSON | Resource quotas | Default: {} |
| created_by_id | UUID | User who created | Foreign Key |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- One-to-many with CloudResource
- Many-to-one with User (created_by)

### CloudResource

Represents an infrastructure resource in a cloud provider.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| name | String | Resource name | Required |
| resource_id | String | Provider's resource ID | Required |
| provider_id | Integer | Associated provider | Foreign Key |
| resource_type | String | Resource type (vm, storage, etc.) | Required |
| region | String | Resource region | Required |
| status | String | Resource status | Required, Default: 'pending' |
| is_active | Boolean | Resource active status | Default: true |
| created_by_id | UUID | User who created | Foreign Key |
| metadata | JSON | Resource metadata | Default: {} |
| config | JSON | Resource configuration | Default: {} |
| tags | JSON | Resource tags | Default: {} |
| monthly_cost | Decimal | Estimated monthly cost | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with CloudProvider
- Many-to-one with User (created_by)
- One-to-many with CloudMetric
- One-to-many with CloudAlert

### CloudMetric

Stores metrics for cloud resources.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| resource_id | UUID | Associated resource | Foreign Key |
| metric_type | String | Type of metric | Required |
| value | Float | Metric value | Required |
| unit | String | Measurement unit | Required |
| timestamp | DateTime | Measurement time | Required |
| created_at | DateTime | Creation timestamp | Required |

**Relationships:**
- Many-to-one with CloudResource

### CloudAlert

Represents alerts for cloud resources.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| resource_id | UUID | Associated resource | Foreign Key |
| title | String | Alert title | Required |
| message | String | Alert message | Required |
| severity | String | Alert severity | Required, Values: critical, high, medium, low, info |
| status | String | Alert status | Required, Values: open, acknowledged, resolved |
| metadata | JSON | Additional alert data | Default: {} |
| acknowledged_by_id | UUID | User who acknowledged | Foreign Key |
| acknowledged_at | DateTime | Acknowledgment time | Optional |
| resolved_by_id | UUID | User who resolved | Foreign Key |
| resolved_at | DateTime | Resolution time | Optional |
| resolution_note | String | Resolution details | Optional |
| resolution_type | String | Resolution type | Optional, Values: fixed, false_positive, expected_behavior, other |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with CloudResource
- Many-to-one with User (acknowledged_by)
- Many-to-one with User (resolved_by)

### ICSDevice

Represents an Industrial Control System device.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| name | String | Device name | Required |
| device_type | String | Type of device | Required |
| status | String | Device status | Required, Values: online, offline, maintenance, error |
| location | String | Physical location | Optional |
| manufacturer | String | Device manufacturer | Optional |
| model | String | Device model | Optional |
| serial_number | String | Device serial number | Optional |
| firmware_version | String | Current firmware | Optional |
| installation_date | Date | Installation date | Optional |
| metadata | JSON | Additional device data | Default: {} |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- One-to-many with ICSReading
- One-to-many with ICSControlLog

### ICSReading

Stores sensor readings from ICS devices.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| device_id | UUID | Associated device | Foreign Key |
| reading_type | String | Type of reading | Required |
| value | Float | Reading value | Required |
| unit | String | Measurement unit | Required |
| timestamp | DateTime | Reading time | Required |
| status | String | Reading status | Default: 'normal' |
| created_at | DateTime | Creation timestamp | Required |

**Relationships:**
- Many-to-one with ICSDevice

### ICSControlLog

Records control actions performed on ICS devices.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Unique identifier | Primary Key |
| device_id | UUID | Associated device | Foreign Key |
| user_id | UUID | User who performed action | Foreign Key |
| action | String | Control action taken | Required |
| parameters | JSON | Action parameters | Default: {} |
| result | String | Action result | Required |
| timestamp | DateTime | Action time | Required |
| created_at | DateTime | Creation timestamp | Required |

**Relationships:**
- Many-to-one with ICSDevice
- Many-to-one with User

### SystemConfig

Stores system-wide configuration settings.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | Integer | Unique identifier | Primary Key |
| key | String | Configuration key | Unique, Required |
| value | Text | Configuration value | Optional |
| description | String | Setting description | Optional |
| category | String | Setting category | Default: 'security' |
| security_level | String | Access restriction level | Default: 'restricted' |
| is_encrypted | Boolean | Encryption status | Default: false |
| validation_rules | JSON | Validation constraints | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

### AuditLog

Records security-relevant actions within the system.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Log entry identifier | Primary Key |
| user_id | UUID | User who performed action | Foreign Key, Optional |
| event_type | String | Type of event | Required |
| resource_type | String | Type of affected resource | Optional |
| resource_id | String | ID of affected resource | Optional |
| action | String | Action performed | Required |
| status | String | Action status | Required, Values: success, failure, warning |
| ip_address | String | Client IP address | Optional |
| user_agent | String | Client user agent | Optional |
| details | JSON | Additional event details | Optional |
| severity | String | Event severity | Default: 'info', Values: info, warning, error, critical |
| created_at | DateTime | Event timestamp | Required |

**Relationships:**
- Many-to-one with User

### UserActivity

Tracks user activities for analytics and usability.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | Integer | Activity identifier | Primary Key |
| user_id | UUID | Associated user | Foreign Key |
| activity_type | String | Type of activity | Required |
| resource_type | String | Type of resource | Optional |
| resource_id | String | Resource identifier | Optional |
| details | JSON | Activity details | Optional |
| ip_address | String | Client IP address | Optional |
| user_agent | String | Client user agent | Optional |
| created_at | DateTime | Activity timestamp | Required |

**Relationships:**
- Many-to-one with User

### FileUpload

Records files uploaded to the system.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | Integer | Upload identifier | Primary Key |
| user_id | UUID | User who uploaded | Foreign Key |
| filename | String | System filename | Required |
| original_filename | String | Original filename | Required |
| file_size | Integer | Size in bytes | Required |
| mime_type | String | File type | Required |
| file_hash | String | File checksum | Required |
| storage_path | String | File location | Required |
| public_url | String | Public access URL | Optional |
| is_public | Boolean | Public access flag | Default: false |
| metadata | JSON | File metadata | Optional |
| scanned_at | DateTime | Security scan time | Optional |
| scan_result | String | Security scan result | Optional, Values: clean, suspicious, infected |
| created_at | DateTime | Upload timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with User

### WebhookSubscription

Manages webhook subscriptions for event notifications.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Subscription identifier | Primary Key |
| user_id | UUID | Subscribing user | Foreign Key |
| url | String | Webhook endpoint URL | Required |
| description | String | Subscription description | Required |
| status | String | Subscription status | Required, Values: active, paused, error |
| event_types | Array | Types of events to receive | Required |
| headers | JSON | Custom HTTP headers | Optional |
| secret | String | Signature verification secret | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with User
- One-to-many with WebhookDelivery

### WebhookDelivery

Tracks webhook notification deliveries.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Delivery identifier | Primary Key |
| webhook_id | UUID | Associated webhook | Foreign Key |
| event_type | String | Event type | Required |
| payload | JSON | Event payload | Required |
| status | String | Delivery status | Required, Values: success, failed |
| status_code | Integer | HTTP status code | Optional |
| response_body | Text | Response content | Optional |
| attempt_count | Integer | Delivery attempts | Default: 1 |
| next_retry | DateTime | Next retry time | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with WebhookSubscription

### SecurityScan

Records security scans performed on resources.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | UUID | Scan identifier | Primary Key |
| scan_type | String | Type of scan | Required, Values: vulnerability, compliance, configuration, full |
| status | String | Scan status | Required, Values: queued, in_progress, completed, failed |
| resources | JSON | Scanned resources | Required |
| initiated_by_id | UUID | User who initiated | Foreign Key |
| start_time | DateTime | Scan start time | Optional |
| end_time | DateTime | Scan completion time | Optional |
| findings | JSON | Scan results | Optional |
| summary | JSON | Result summary | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

**Relationships:**
- Many-to-one with User (initiated_by)

### Subscriber

Manages newsletter subscribers.

| Attribute | Type | Description | Constraints |
|-----------|------|-------------|------------|
| id | Integer | Subscriber identifier | Primary Key |
| email | String | Email address | Unique, Required |
| status | String | Subscription status | Required, Values: active, unsubscribed, bounced, pending |
| preferences | JSON | Subscription preferences | Default: {} |
| confirmation_token | String | Email confirmation token | Optional |
| confirmed_at | DateTime | Confirmation timestamp | Optional |
| unsubscribed_at | DateTime | Unsubscribe timestamp | Optional |
| created_at | DateTime | Creation timestamp | Required |
| updated_at | DateTime | Last update timestamp | Required |

## Object Inheritance

Several models implement inheritance patterns to share common attributes:

### Base Model

All models inherit from a base model that provides:
- Standard CRUD operations
- Serialization methods
- Validation functionality
- Timestamps for creation and update events

### Auditable Mixin

Models that require audit trail functionality implement the Auditable mixin, which:
- Automatically creates audit log entries for create, update, and delete operations
- Tracks the user who made changes
- Records the changed attributes
- Ensures compliance with security and regulatory requirements

### TimestampMixin

All models include the TimestampMixin which:
- Automatically sets created_at on record creation
- Updates updated_at on record modification
- Provides methods for time-based queries and filtering

## Database Schema Diagram

```

┌──────────────┐       ┌───────────────┐       ┌────────────────┐
│    User      │       │ CloudProvider │       │ CloudResource  │
├──────────────┤       ├───────────────┤       ├────────────────┤
│ id           │       │ id            │       │ id             │
│ email        │       │ name          │       │ name           │
│ first_name   │       │ provider_type │       │ resource_id    │
│ last_name    │◄──────┤ created_by_id │◄──────┤ provider_id    │
│ password_hash│       │ credentials   │       │ created_by_id  │
│ ...          │       │ ...           │       │ ...            │
└──────┬───────┘       └───────────────┘       └────────┬───────┘
│                                                │
│                                                │
┌──────▼───────┐                                ┌───────▼────────┐
│ UserSession  │                                │   CloudMetric  │
├──────────────┤                                ├────────────────┤
│ id           │                                │ id             │
│ user_id      │                                │ resource_id    │
│ token        │                                │ metric_type    │
│ ip_address   │                                │ value          │
│ ...          │                                │ ...            │
└──────────────┘                                └────────────────┘
▲                                                ▲
│                                                │
│                                                │
┌──────┴───────┐                                ┌───────┴────────┐
│ UserActivity │                                │   CloudAlert   │
├──────────────┤                                ├────────────────┤
│ id           │                                │ id             │
│ user_id      │                                │ resource_id    │
│ activity_type│                                │ title          │
│ ...          │                                │ severity       │
└──────────────┘                                │ ...            │
└────────────────┘
┌──────────────┐       ┌───────────────┐       ┌────────────────┐
│  ICSDevice   │       │  ICSReading   │       │ ICSControlLog  │
├──────────────┤       ├───────────────┤       ├────────────────┤
│ id           │       │ id            │       │ id             │
│ name         ├──────►│ device_id     │       │ device_id      │◄─┐
│ device_type  │       │ reading_type  │       │ user_id        │  │
│ status       │       │ value         │       │ action         │  │
│ ...          │       │ ...           │       │ ...            │  │
└──────────────┘       └───────────────┘       └────────────────┘  │
△                                                            │
└────────────────────────────────────────────────────────────┘

```

## Schema Evolution

### Version Control

The database schema is version controlled using migrations to ensure:
- Backward compatibility
- Safe schema changes
- Rollback capabilities
- Audit trail of schema changes

### Migration Strategy

Schema changes follow this process:
1. Create a migration file defining the changes
2. Test the migration in development environment
3. Apply the migration to staging for validation
4. Deploy the migration to production during maintenance windows
5. Verify database integrity after migration

### Data Integrity

To maintain data integrity during schema changes:
- Foreign key constraints enforce referential integrity
- Default values ensure consistency
- Database transactions ensure atomicity
- Validation rules prevent invalid data

## Security Considerations

### Sensitive Data

Sensitive data in the models is protected by:
- Encryption for credentials, secrets, and sensitive configuration
- Password hashing using strong algorithms (bcrypt/Argon2)
- Data masking in logs and error reports
- Column-level encryption for PII and sensitive fields

### Access Control

Database access follows the principle of least privilege:
- Application service accounts have limited permissions
- Direct database access is restricted to authorized personnel
- Row-level security controls access to specific records
- Column-level encryption protects sensitive fields

## Performance Considerations

### Indexing Strategy

The following indexes are defined for performance optimization:
- Primary keys on all tables
- Foreign key indexes for relationship fields
- Composite indexes for frequently filtered fields
- Full-text indexes for search functionality

### Partitioning Strategy

Large tables employ partitioning strategies:
- CloudMetric: Time-based partitioning by month
- AuditLog: Time-based partitioning by month
- ICSReading: Time-based partitioning by month

## Version History

| Version | Date | Description | Author |
|---------|------|-------------|--------|
| 1.0 | 2023-06-15 | Initial data model specification | Data Architecture Team |
| 1.1 | 2023-08-22 | Added ICS device models | Platform Engineering |
| 1.2 | 2023-11-10 | Added webhook subscription models | API Team |
| 1.3 | 2024-02-05 | Added security scan model | Security Team |
| 1.4 | 2024-04-20 | Updated cloud resource model with cost tracking | Data Architecture Team |
| 1.5 | 2024-05-15 | Added ICSControlLog model and enhanced security attributes | Platform Engineering |