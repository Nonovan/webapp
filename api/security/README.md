# Security API

The Security API module provides RESTful endpoints for security incident management, vulnerability tracking, security scanning, and threat intelligence within the Cloud Infrastructure Platform.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Usage Examples
- Integration with Platform Services
- Related Documentation
- File Integrity Monitoring API

## Overview

The Security API implements RESTful endpoints following security best practices including input validation, audit logging, authorization checks, and proper error handling. It provides programmatic access to security-related functionality including security incident management, vulnerability tracking, security scan configuration, and threat detection capabilities.

This module serves as the central interface for all security operations in the Cloud Infrastructure Platform, enabling automated security workflows, integration with monitoring systems, and comprehensive security visibility.

## Key Components

- **`routes.py`**: Implements RESTful API endpoints for security operations
  - Security incident management
  - Vulnerability tracking and reporting
  - Security scan configuration and control
  - Threat detection and response
  - Security policy management

- **`incidents.py`**: Security incident management functionality
  - Incident creation and tracking
  - Incident prioritization and categorization
  - Automated incident response workflows
  - Incident correlation engine
  - Reporting and metrics generation
  - SLA compliance tracking
  - File integrity violation handling
  - Incident state lifecycle management

- **`vulnerabilities.py`**: Vulnerability management capabilities
  - Vulnerability tracking and lifecycle management
  - CVSS-based risk scoring and prioritization
  - Remediation planning and tracking
  - Remediation deadline calculation
  - Integration with security scanners
  - Compliance status reporting
  - Threat correlation and intelligence

- **`scanning.py`**: Security scanning configuration and control
  - Scan scheduling and management
  - Scan configuration templates and profiles
  - Scan result aggregation and analysis
  - Scan metrics collection and reporting
  - Integration with multiple scanning engines
  - Compliance reporting
  - Finding-to-vulnerability conversion
  - Scan health monitoring

- **`threats.py`**: Threat detection and intelligence
  - Threat detection rules
  - IOC management
  - Threat intelligence integration
  - Suspicious activity detection
  - Alert correlation
  - Threat intelligence feeds
  - Detection metrics
  - Integration with the `SecurityIncident` model

- **`baseline.py`**: File integrity baseline management
  - Baseline status reporting
  - Secure baseline updating
  - Integrity verification
  - Change validation
  - Baseline versioning
  - Approved update workflow

- **`schemas.py`**: Data validation and serialization schemas
  - Security event validation
  - CVE field validation with standard format enforcement
  - File integrity baseline validation
  - Vulnerability data validation and serialization
  - Security scan request/response validation
  - Security incident schema validation
  - Security configuration validation
  - DoS protection with size and nesting limits
  - Comprehensive input validation

- **`__init__.py`**: Module initialization and configuration
  - Blueprint registration
  - Security metrics integration
  - Event handler registration
  - Rate limit configuration
  - Security headers enforcement
  - Security monitoring setup
  - File integrity baseline management

## Directory Structure

```plaintext
api/security/
├── __init__.py         # Module initialization and exports
├── README.md           # This documentation
├── routes.py           # API endpoint implementations
├── incidents.py        # Security incident management
├── vulnerabilities.py  # Vulnerability tracking functionality
├── scanning.py         # Security scanning configuration
├── threats.py          # Threat detection and intelligence
├── baseline.py         # File integrity baseline management
└── schemas.py          # Data validation schemas
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/security/incidents` | GET | List security incidents | Security Analyst, Admin |
| `/api/security/incidents` | POST | Create a security incident | Security Analyst, Admin |
| `/api/security/incidents/{id}` | GET | Get incident details | Security Analyst, Admin |
| `/api/security/incidents/{id}` | PATCH | Update incident status | Security Analyst, Admin |
| `/api/security/incidents/{id}/status` | POST | Change incident status | Security Analyst, Admin |
| `/api/security/incidents/{id}/phase` | POST | Change incident phase | Security Analyst, Admin |
| `/api/security/incidents/{id}/comments` | POST | Add comment to incident | Security Analyst, Admin |
| `/api/security/incidents/{id}/escalate` | POST | Escalate an incident | Security Analyst, Admin |
| `/api/security/incidents/{id}/assign` | POST | Assign incident to user | Security Analyst, Admin |
| `/api/security/incidents/{id}/resolve` | POST | Resolve an incident | Security Analyst, Admin |
| `/api/security/incidents/{id}/reopen` | POST | Reopen a resolved incident | Security Analyst, Admin |
| `/api/security/incidents/{id}/close` | POST | Close an incident | Security Analyst, Admin |
| `/api/security/incidents/{id}/merge` | POST | Merge with another incident | Security Analyst, Admin |
| `/api/security/incidents/stats` | GET | Get incident statistics | Security Analyst, Admin |
| `/api/security/incidents/file-integrity-violations` | GET | List file integrity incidents | Security Analyst, Admin |
| `/api/security/incidents/create-from-integrity` | POST | Create incident from integrity check | Security Analyst, Admin |
| `/api/security/vulnerabilities` | GET | List vulnerabilities | Security Analyst, Admin |
| `/api/security/vulnerabilities/{id}` | GET | Get vulnerability details | Security Analyst, Admin |
| `/api/security/vulnerabilities/{id}` | PATCH | Update vulnerability | Security Analyst, Admin |
| `/api/security/vulnerabilities/check-cve/{cve_id}` | GET | Check if CVE exists | Security Analyst, Admin |
| `/api/security/vulnerabilities/statistics` | GET | Get vulnerability metrics | Security Analyst, Admin |
| `/api/security/scan` | GET | List security scans | Security Analyst, Admin |
| `/api/security/scan` | POST | Trigger security scan | Security Admin |
| `/api/security/scan/{id}` | GET | Get scan details | Security Analyst, Admin |
| `/api/security/scan/{id}` | PATCH | Update scan (e.g. cancel) | Security Admin |
| `/api/security/scan/{id}/findings` | GET | Get scan findings | Security Analyst, Admin |
| `/api/security/scan/{id}/results` | POST | Update scan results | Security Admin |
| `/api/security/scan/profiles` | GET | List scan profiles | Security Analyst, Admin |
| `/api/security/scan/metrics` | GET | Get scan statistics | Security Analyst, Admin |
| `/api/security/scan/convert-to-vulnerabilities` | POST | Convert findings to vulnerabilities | Security Admin |
| `/api/security/threats/ioc` | POST | Create threat indicator | Security Admin |
| `/api/security/threats/ioc/{id}` | DELETE | Remove threat indicator | Security Admin |
| `/api/security/threats/detection` | GET | List threat detections | Security Analyst, Admin |
| `/api/security/threats/integrity` | GET | Get file integrity status | Security Analyst, Admin |
| `/api/security/threats/status` | GET | Get threat status summary | Security Analyst, Admin |
| `/api/security/baseline` | GET | Get file integrity baseline status | Security Analyst, Admin |
| `/api/security/baseline` | PUT | Update file integrity baseline | Security Admin |
| `/api/security/baseline/verify` | POST | Verify files against integrity baseline | Security Analyst, Admin |

## Configuration

The security API system uses several configuration settings that can be adjusted in the application config:

```python
# Security API settings
'SECURITY_INCIDENT_AUTO_ASSIGN': True,    # Auto-assign incidents based on type
'SECURITY_SCAN_CONCURRENCY': 3,           # Maximum concurrent security scans
'SECURITY_INCIDENT_RETENTION_DAYS': 365,  # How long to keep incidents in the database
'VULNERABILITY_AUTO_PRIORITIZE': True,    # Auto-prioritize vulnerabilities by CVSS
'THREAT_INTEL_SOURCES': ['internal', 'mitre', 'alienvault'],  # Threat intelligence sources
'SECURITY_API_ADMINS_GROUP': 'security_administrators',  # Group for security admins
'SECURITY_METRIC_COLLECTION_INTERVAL': 300, # Metrics collection interval in seconds
'FILE_INTEGRITY_CHECK_ENABLED': True,     # Enable file integrity monitoring
'FILE_INTEGRITY_CRITICAL_PATHS': ['/etc/config', '/var/lib/app'], # Critical paths to monitor
'VULNERABILITY_DEFAULT_DEADLINE_DAYS': 90, # Default remediation deadline in days
'SCAN_RESULT_RETENTION_DAYS': 365,        # How long to keep scan results
'INCIDENT_SLA_HOURS': {                   # SLA response times
    'critical': 1,                         # Critical incidents: 1 hour
    'high': 4,                             # High severity: 4 hours
    'medium': 24,                          # Medium severity: 24 hours
    'low': 72                              # Low severity: 72 hours
},
'FILE_INTEGRITY_BASELINE_PATH': 'instance/file_baseline.json',  # Path to integrity baseline
'FILE_INTEGRITY_AUTO_UPDATE_LIMIT': 10,    # Maximum files to auto-update in baseline
'FILE_INTEGRITY_AUTO_NOTIFICATION': True,  # Auto-notify on integrity violations
'FILE_HASH_ALGORITHM': 'sha256',          # Algorithm used for file hashing
'FILE_INTEGRITY_CHECK_INTERVAL': 3600,    # Seconds between automated checks
'FILE_INTEGRITY_CHECK_PERMISSIONS': True, # Check for unsafe file permissions
'BASELINE_MAX_CHANGES_PER_UPDATE': 100,   # Maximum changes allowed in one update
'BASELINE_BACKUP_ENABLED': True,          # Enable baseline backups before updates

# Rate limiting settings
'RATELIMIT_SECURITY_DEFAULT': "60 per minute",
'RATELIMIT_SECURITY_SCAN': "10 per hour",
'RATELIMIT_SECURITY_INCIDENT_CREATE': "30 per minute",
'RATELIMIT_SECURITY_BASELINE_UPDATE': "5 per hour",
'RATELIMIT_SECURITY_BASELINE_CHECK': "30 per minute",
```

## Security Features

- **Strict Access Controls**: All endpoints require appropriate security role permissions
- **Audit Logging**: Comprehensive logging of all security operations for compliance
- **Input Validation**: Thorough validation of all input parameters
- **Rate Limiting**: Prevents API abuse with endpoint-specific rate limits
- **Correlation Engine**: Links related security incidents and vulnerabilities
- **Workflow Enforcement**: Ensures proper security incident handling procedures
- **Real-time Alerting**: Generates alerts for critical security incidents
- **Secure Error Handling**: Prevents information leakage in error responses
- **Forensic Data Preservation**: Ensures security incident evidence is properly preserved
- **File Integrity Monitoring**: Integration with system integrity monitoring
- **Security Metrics**: Collection and reporting of security posture metrics
- **Progressive SLAs**: Severity-based response time requirements
- **State Management**: Proper handling of security incident lifecycle states
- **Customizable Scan Profiles**: Template-based security scan configurations
- **File Integrity Baseline Management**: Maintain and verify file integrity baselines
- **Exception Handling**: Robust error management with appropriate logging
- **Schema Validation**: Strong schema-based validation for all API inputs
- **Data Sanitization**: Automatic sanitization of untrusted input
- **Deep Object Validation**: Protection against nested object attacks
- **Size Limitation**: Enforcement of size limits to prevent DoS
- **Baseline Versioning**: Track and manage baseline versions with rollback capability
- **Integrity Verification**: Verify the integrity of the baseline itself
- **Security Headers**: Comprehensive set of HTTP security headers

## Usage Examples

### List Security Incidents

```http
GET /api/security/incidents?severity=high&status=open
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 42,
      "title": "Unusual login pattern detected",
      "description": "Multiple failed login attempts followed by successful login from unusual location",
      "severity": "high",
      "status": "open",
      "created_at": "2023-06-14T23:15:42Z",
      "created_by": "security_monitoring",
      "affected_resources": [
        {
          "type": "user",
          "id": 5,
          "name": "john.doe"
        }
      ]
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 1
  }
}
```

### Create Security Incident

```http
POST /api/security/incidents
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "title": "Possible file integrity violation",
  "description": "Checksum mismatch detected on system files",
  "severity": "high",
  "affected_resources": [
    {
      "type": "system",
      "id": "file-system",
      "details": {
        "path": "/etc/config",
        "files_affected": 3
      }
    }
  ],
  "evidence": [
    {
      "type": "log",
      "content": "File integrity check failed at 2023-06-15 16:42:15"
    }
  ]
}
```

Response:

```json
{
  "id": 43,
  "title": "Possible file integrity violation",
  "severity": "high",
  "status": "open",
  "phase": "identification",
  "created_at": "2023-06-15T17:10:22Z",
  "created_by": {
    "id": 1,
    "username": "admin"
  },
  "triage_by": "2023-06-15T19:10:22Z",
  "tracking_id": "SEC-2023-06-15-043"
}
```

### Change Incident Status

```http
POST /api/security/incidents/43/status
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "status": "investigating",
  "reason": "Beginning investigation of affected files"
}
```

Response:

```json
{
  "id": 43,
  "title": "Possible file integrity violation",
  "severity": "high",
  "status": "investigating",
  "phase": "identification",
  "updated_at": "2023-06-15T17:30:45Z"
}
```

### Trigger Security Scan

```http
POST /api/security/scan
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "scan_type": "vulnerability",
  "targets": ["web-server-01", "api-server-02"],
  "profile": "full",
  "schedule": "immediate",
  "notify_email": "security@example.com"
}
```

Response:

```json
{
  "scan_id": "scan-20230615-001",
  "status": "scheduled",
  "estimated_duration_minutes": 45,
  "targets": ["web-server-01", "api-server-02"],
  "scheduled_start": "2023-06-15T17:15:00Z"
}
```

### Get Scan Findings

```http
GET /api/security/scan/scan-20230615-001/findings
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "scan_id": "scan-20230615-001",
  "findings": [
    {
      "id": "finding-001",
      "title": "Outdated OpenSSL Version",
      "description": "The system is running an outdated version of OpenSSL with known vulnerabilities",
      "severity": "high",
      "cve_id": "CVE-2023-1234",
      "affected_resource": "web-server-01",
      "remediation": "Update OpenSSL to version 1.1.1t or later"
    },
    {
      "id": "finding-002",
      "title": "SSH Weak Ciphers Enabled",
      "description": "SSH server configured to allow weak cipher algorithms",
      "severity": "medium",
      "affected_resource": "api-server-02",
      "remediation": "Update SSH configuration to only allow strong ciphers"
    }
  ],
  "findings_count": 2,
  "severity_counts": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "page": 1,
  "per_page": 25
}
```

### Convert Scan Findings to Vulnerabilities

```http
POST /api/security/scan/convert-to-vulnerabilities
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "scan_id": "scan-20230615-001",
  "finding_ids": ["finding-001", "finding-002"]
}
```

Response:

```json
{
  "message": "Processed 2 findings",
  "created_count": 1,
  "updated_count": 1,
  "skipped_count": 0,
  "errors": null
}
```

### Create Incident from File Integrity Violation

```http
POST /api/security/incidents/create-from-integrity
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "message": "Created 1 incidents from file integrity violations",
  "created_incidents": [
    {
      "id": 44,
      "title": "File Integrity Violation: /etc/passwd",
      "severity": "critical",
      "status": "open",
      "phase": "identification"
    }
  ],
  "violations_processed": 1,
  "total_violations": 2
}
```

### Get File Integrity Status

```http
GET /api/security/threats/integrity
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "status": "compromised",
  "last_check": "2024-08-15T13:45:22Z",
  "changes_detected": 3,
  "critical_violations": 1,
  "high_violations": 1,
  "other_violations": 1,
  "violations": {
    "critical": [
      {
        "path": "/etc/passwd",
        "status": "modified",
        "expected_hash": "a1b2c3...",
        "current_hash": "d4e5f6..."
      }
    ],
    "high": [
      {
        "path": "/etc/shadow",
        "status": "modified",
        "expected_hash": "g7h8i9...",
        "current_hash": "j0k1l2..."
      }
    ],
    "other": [
      {
        "path": "/var/log/auth.log",
        "status": "modified",
        "expected_hash": "m3n4o5...",
        "current_hash": "p6q7r8..."
      }
    ]
  }
}
```

### Update File Integrity Baseline

```http
PUT /api/security/baseline
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "changes": [
    {
      "path": "/etc/config/app.conf",
      "current_hash": "a1b2c3d4e5f6...",
      "expected_hash": null,
      "status": "modified"
    }
  ],
  "remove_missing": false,
  "auto_update_limit": 5
}
```

Response:

```json
{
  "message": "Baseline updated successfully",
  "updated_files": 1,
  "removed_files": 0,
  "baseline_version": "2024-08-15T14:30:00Z"
}
```

## Integration with Platform Services

The Security API integrates with several platform services:

1. **File Integrity Monitoring**: Automatically creates security incidents when critical file integrity violations are detected by system monitoring

2. **Vulnerability Management**: Converts security scan findings into tracked vulnerabilities with prioritization and remediation tracking

3. **Metrics Collection**: Reports security metrics to the platform's monitoring systems for dashboards and alerts

4. **Notification System**: Sends alerts for critical security events requiring immediate attention

5. **Audit System**: Logs all security operations for compliance and accountability

6. **CMDB Integration**: Links security incidents and vulnerabilities to affected configuration items

7. **Authentication/Authorization**: Enforces strict access controls based on security roles

8. **File Baseline Management**: Updates and maintains file integrity baseline definitions with proper security controls

9. **Threat Intelligence Integration**: Correlates security incidents with known threat indicators

10. **Schema Validation**: Uses centralized schemas for consistent data validation across all security endpoints

## Related Documentation

- Security Architecture Overview
- Security Incident Response
- Vulnerability Management Process
- Security Scanning Framework
- File Integrity Monitoring
- Security API Reference
- Threat Intelligence Framework
- File Baseline Management
- Incident Lifecycle Management
- Schema Validation Guide

## File Integrity Monitoring API

The File Integrity Monitoring API provides specialized endpoints for maintaining and verifying the integrity of critical system files.

### Available Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/security/threats/integrity` | GET | Get current file integrity status | Security Analyst, Admin |
| `/api/security/baseline` | GET | Get file integrity baseline status | Security Analyst, Admin |
| `/api/security/baseline` | PUT | Update file integrity baseline | Security Admin |
| `/api/security/baseline/verify` | POST | Verify files against integrity baseline | Security Analyst, Admin |
| `/api/security/incidents/create-from-integrity` | POST | Create incident from integrity violations | Security Analyst, Admin |

### Key Features

- **Real-time Integrity Verification**: Detect unauthorized file modifications
- **Baseline Management**: Securely maintain and update file integrity baselines
- **Automatic Incident Creation**: Convert integrity violations to security incidents
- **Granular Permission Controls**: Role-based access to integrity operations
- **Change Classification**: Categorize changes by severity (critical, high, medium)
- **Comprehensive Reporting**: Generate reports on file integrity status
- **Secure Baseline Updates**: Validation of baseline modifications with backups

### Usage Example: Verify Files Against Baseline

```http
POST /api/security/baseline/verify
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "paths": ["/etc/nginx/", "/etc/config/app.conf"]
}
```

Response:

```json
{
  "timestamp": "2024-08-16T09:45:22Z",
  "status": "failed",
  "baseline_path": "instance/file_baseline.json",
  "changes_detected": 1,
  "changes": [
    {
      "path": "/etc/config/app.conf",
      "status": "modified",
      "severity": "high",
      "expected_hash": "a1b2c3d4e5f6...",
      "current_hash": "f6e5d4c3b2a1..."
    }
  ]
}
```

### Configuration Options

```python
# File Integrity Monitoring settings
'FILE_INTEGRITY_CHECK_ENABLED': True,     # Enable file integrity monitoring
'FILE_INTEGRITY_CRITICAL_PATHS': ['/etc/config', '/var/lib/app'], # Critical paths to monitor
'FILE_INTEGRITY_BASELINE_PATH': 'instance/file_baseline.json',  # Path to integrity baseline
'FILE_INTEGRITY_AUTO_UPDATE_LIMIT': 10,    # Maximum files to auto-update in baseline
'FILE_INTEGRITY_AUTO_NOTIFICATION': True,  # Auto-notify on integrity violations
'FILE_HASH_ALGORITHM': 'sha256',          # Algorithm used for file hashing
'FILE_INTEGRITY_CHECK_INTERVAL': 3600,    # Seconds between automated checks
'FILE_INTEGRITY_CHECK_PERMISSIONS': True, # Check for unsafe file permissions
'FILE_INTEGRITY_CHECK_SIGNATURES': False, # Verify digital signatures on executables
'BASELINE_CHECK_LIMIT': "30 per minute",  # Rate limiting for baseline verification
```

### Integration Points

The File Integrity Monitoring API integrates with these platform components:

- **Monitoring System**: Produces metrics for dashboards
- **Alerting Framework**: Generates alerts on critical file changes
- **Incident Management**: Creates incidents from integrity violations
- **Audit Logging**: Records all baseline modifications
- **Redis Cache**: Caches integrity status for performance
